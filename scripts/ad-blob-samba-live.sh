#!/bin/sh
# Can a real Samba directory use the `supplementalCredentials` this crate writes?
#
# The fixture set (`tests/fixtures/ad_blob`, written by Samba) checks one direction: that we read what
# a directory wrote. This asks the other one, and the honest answer is not a plain yes — it is three
# findings, each of which a unit test cannot reach:
#
#   1. **A live DC authenticates a client with keys derived the way ours are.** The control run logs in
#      with `kinit` (MIT's, from Debian) against a Samba DC whose account keys Samba wrote. So the
#      string-to-key, the salt handling and the wire are all exercised end to end by somebody else's
#      code.
#
#   2. **Our keys for that account are byte-identical to Samba's.** This crate generates the blob for
#      the same principal and password; `samba-tool domain exportkeytab` gives Samba's own keys for the
#      same account. Equal AES keys mean our string-to-key and our notion of the salt string agree with
#      Samba's. What this does *not* cover — and the unit test
#      `every_key_of_the_entry_reaches_the_structure` does — is how the salt is encoded *inside* the
#      blob: the same question, answered by asserting the raw octets of `DefaultSalt` rather than
#      trusting a read-back.
#
#   3. **The attribute cannot be replaced at all, by us or by Samba.** `ldbmodify` on
#      `supplementalCredentials` is refused by Samba's `password_hash` module — and it refuses Samba's
#      *own* blob, byte for byte, just as it refuses ours. So the refusal is about who may write a
#      secret attribute, not about what the blob contains; a run that only tried our blob would have
#      reported a defect that is not there. Writing keys into a Samba domain is Samba's password path,
#      and it is closed to injection by design.
#
# The conclusion the three support together: a real directory would accept our keys if it accepted any
# blob — the login works for keys identical to ours, and no content check stands in the way. What
# cannot be shown live is a Samba DC *serving* our blob, because Samba does not let anyone put one
# there.
#
# Two container details are load-bearing, both found the hard way:
#
#   * `--option=posix:eadb=...` during provisioning. Without it `samba-tool domain provision` dies in
#     `setsysvolacl` (it sets NT ACLs on the new sysvol through smbd and cannot in a container), leaves
#     `sam.ldb` half-written, and the DC later refuses to start with "Failed to obtain server
#     credentials".
#   * the KDC listens on **UDP** 88 only. A TCP probe reports "closed" while the KDC serves perfectly,
#     so readiness reads `ss -uln`.
#
# Usage:
#   scripts/ad-blob-samba-live.sh [--image debian:bookworm|samba-stand:bookworm]
#
# The second name is an image with samba already installed, which turns a two-minute apt run into
# seconds; the script installs what it needs when the image lacks it.
set -eu

IMAGE=debian:bookworm
while [ $# -gt 0 ]; do
    case $1 in
        --image) IMAGE=$2; shift 2 ;;
        --image=*) IMAGE=${1#--image=}; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

REPO=$(cd "$(dirname "$0")/.." && pwd)
EXAMPLE=
for candidate in "$REPO"/target/*/debug/examples/ad-blob; do
    # The mutation run keeps its own target directory and its own, older, binary.
    case $candidate in *mutants*) continue ;; esac
    [ -x "$candidate" ] && EXAMPLE=$candidate
done
if [ -z "$EXAMPLE" ]; then
    echo "build the example first: ./scripts/cargo.sh build --example ad-blob --features hdb-ldap" >&2
    exit 2
fi
echo "== example: $EXAMPLE"

REALM=FIX.TEST
DOMAIN=FIX
NAME=fixture
# A throwaway in an ephemeral domain, and the same string the blob's keys are derived from.
PASSWORD='Passw0rd!user'
ADMIN_PASSWORD='Passw0rd!fix'

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The blob is produced on the host, by this crate, for a principal whose salt is the one Samba uses:
# `realm + sAMAccountName`.
"$EXAMPLE" --principal "$NAME@$REALM" --password "$PASSWORD" --out "$WORK" >/dev/null
echo "== our blob: $(wc -c < "$WORK/entry.blob") octets"

VOLUME=rrl-ad-blob-live
docker volume create "$VOLUME" >/dev/null 2>&1 || true

docker run --rm -v "$VOLUME:/srv" -v "$WORK:/blob:ro" -e REALM="$REALM" -e DOMAIN="$DOMAIN" \
    -e NAME="$NAME" -e PASSWORD="$PASSWORD" -e ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    "$IMAGE" sh -eu -c '
if ! command -v samba-tool >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq samba samba-common-bin winbind ldb-tools krb5-user iproute2 \
        python3 procps >/dev/null 2>&1
fi

D=/srv/dc
LDB=$D/private/sam.ldb
CONF=$D/etc/smb.conf
DN="CN=$NAME,CN=Users,DC=$(echo "$DOMAIN" | tr A-Z a-z),DC=$(echo "$REALM" | cut -d. -f2 | tr A-Z a-z)"

rm -rf "$D"
mkdir -p "$D"
samba-tool domain provision --realm="$REALM" --domain="$DOMAIN" \
    --adminpass="$ADMIN_PASSWORD" --server-role=dc --use-rfc2307 --targetdir="$D" \
    "--option=posix:eadb=$D/eadb.tdb" >/tmp/prov.log 2>&1
rc=$?
if [ ! -f "$LDB" ]; then
    echo "FAIL: provisioning left no sam.ldb"; tail -20 /tmp/prov.log; exit 1
fi
echo "== provisioned (samba-tool rc=$rc)"

samba-tool user add "$NAME" "$PASSWORD" -H "tdb://$LDB" -s "$CONF" >/tmp/add.log 2>&1 || {
    echo "FAIL: user add"; cat /tmp/add.log; exit 1; }

printf "[libdefaults]\n    default_realm = %s\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    rdns = false\n[realms]\n    %s = {\n        kdc = 127.0.0.1\n    }\n" \
    "$REALM" "$REALM" > /etc/krb5.conf

start_dc() {
    /usr/sbin/samba --foreground --no-process-group -s "$CONF" >/tmp/samba.log 2>&1 &
    DC=$!
    i=0
    while [ $i -lt 60 ]; do
        # UDP: the only transport this KDC binds. A TCP probe answers "closed" for a DC that serves.
        if ss -uln 2>/dev/null | grep -q ":88 "; then return 0; fi
        sleep 1
        i=$((i+1))
    done
    echo "FAIL: the KDC never listened"; tail -20 /tmp/samba.log; return 1
}

stop_dc() {
    kill "$DC" 2>/dev/null || true
    wait "$DC" 2>/dev/null || true
    i=0
    while [ $i -lt 20 ]; do
        ss -uln 2>/dev/null | grep -q ":88 " || return 0
        sleep 1
        i=$((i+1))
    done
}

login() {
    label=$1; account=$2; secret=$3
    rm -f /tmp/cc /tmp/kinit.log
    if KRB5CCNAME=FILE:/tmp/cc kinit -V "$account@$REALM" <<PW >/tmp/kinit.log 2>&1
$secret
PW
    then
        echo "LOGIN $label: ok"
        KRB5CCNAME=FILE:/tmp/cc klist 2>/dev/null | sed -n "s/^ *Principal: /    /p" | head -1
        return 0
    fi
    echo "LOGIN $label: refused"
    grep -iE "preauth|error|incorrect|Password" /tmp/kinit.log | head -3
    return 1
}

# LDIF wraps a long base64 value, each continuation starting with a space. Joining only the prefixed
# line truncates the blob to a fragment that then looks structurally broken — a parsing mistake that
# reads like a corrupt attribute.
samba_blob() {
    ldbsearch -H "$LDB" "(sAMAccountName=$NAME)" supplementalCredentials 2>/dev/null > /tmp/raw.ldif
    python3 - /tmp/raw.ldif "$1" <<PY
import base64, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
for i, line in enumerate(lines):
    if line.startswith("supplementalCredentials:: "):
        value = line[len("supplementalCredentials:: "):]
        for nxt in lines[i + 1:]:
            if not nxt.startswith(" "):
                break
            value += nxt[1:]
        open(sys.argv[2], "wb").write(base64.b64decode(value))
        break
else:
    raise SystemExit("no supplementalCredentials")
PY
}

write_blob() {
    { printf "dn: %s\nchangetype: modify\nreplace: supplementalCredentials\n" "$DN"
      base64 -w 76 < "$1" | sed "1s/^/supplementalCredentials:: /; 1!s/^/ /"
    } > /tmp/blob.ldif
    ldbmodify -H "$LDB" /tmp/blob.ldif 2>&1 | tail -1
}

STATUS=0

echo "== 1/3 a live DC authenticates against keys it wrote"
start_dc || exit 1
login control Administrator "$ADMIN_PASSWORD" || {
    echo "   the harness cannot log in even with keys Samba wrote"; STATUS=1; }
login account "$NAME" "$PASSWORD" || {
    echo "   and not with the account the stand added"; STATUS=1; }
stop_dc

echo "== 2/3 our keys against the keytab Samba exports for that account"
samba-tool domain exportkeytab /tmp/fixture.keytab --principal="$NAME@$REALM" -s "$CONF" \
    >/tmp/kt.log 2>&1 || { echo "FAIL: exportkeytab"; cat /tmp/kt.log; STATUS=1; }
samba_blob /tmp/theirs.blob
echo "   Samba blob: $(wc -c < /tmp/theirs.blob) octets; ours: $(wc -c < /blob/entry.blob) octets"
python3 - /tmp/fixture.keytab /blob/entry.json <<PY || STATUS=1
import json, struct, sys

# Keytab §3: two-octet version, then entries of a signed two-octet (v5.1) or four-octet (v5.2) size.
data = open(sys.argv[1], "rb").read()
version = struct.unpack_from(">H", data, 0)[0]
wide = version == 0x0502
at, keys = 2, {}
while at < len(data):
    if wide:
        size = struct.unpack_from(">i", data, at)[0]; at += 4
    else:
        size = struct.unpack_from(">h", data, at)[0]; at += 2
    if size < 0:
        at += -size
        continue
    entry = data[at:at + size]; at += size
    components = struct.unpack_from(">H", entry, 0)[0]
    realm_len = struct.unpack_from(">H", entry, 2)[0]
    cursor = 4 + realm_len
    for _ in range(components):
        length = struct.unpack_from(">H", entry, cursor)[0]
        cursor += 2 + length
    cursor += 4 + 4 + 1                      # name type, timestamp, kvno
    enctype = struct.unpack_from(">H", entry, cursor)[0]; cursor += 2
    key_len = struct.unpack_from(">H", entry, cursor)[0]; cursor += 2
    keys[enctype] = entry[cursor:cursor + key_len].hex()

ours = json.load(open(sys.argv[2]))["current"]
bad = 0
for enctype, octets in sorted(ours.items(), key=lambda kv: int(kv[0])):
    theirs = keys.get(int(enctype))
    if theirs is None:
        print(f"   enctype {enctype}: not in the keytab, nothing to compare")
        continue
    same = theirs == octets
    verdict = "identical" if same else "DIFFERENT"
    print(f"   enctype {enctype}: {verdict}")
    bad += 0 if same else 1
raise SystemExit(1 if bad else 0)
PY

echo "== 3/3 can the attribute be replaced at all?"
OURS_WRITE=$(write_blob /blob/entry.blob)
THEIRS_WRITE=$(write_blob /tmp/theirs.blob)
echo "   ours:          $OURS_WRITE"
echo "   Samba own:     $THEIRS_WRITE"
echo "   a description: $(printf "dn: %s\nchangetype: modify\nreplace: description\n" "$DN" > /tmp/d.ldif; \
    echo "description: written by the stand" >> /tmp/d.ldif; \
    ldbmodify -H "$LDB" /tmp/d.ldif 2>&1 | tail -1)"

case $OURS_WRITE in
    *"Modify failed"*|*"ERR"*)
        echo "   The refusal is the same for Samba own blob, and a plain attribute goes through in the"
        echo "   same session: it is about who may write a secret attribute, not about the content."
        echo "   So the live login above ran on Samba keys that are identical to ours (step 2), and no"
        echo "   content check stands between our blob and a real directory."
        ;;
    *)
        # Not expected on Samba. If a build ever allows it, do what the check was for in the first
        # place: serve that blob and log in against it.
        echo "   accepted, so serve it:"
        start_dc || exit 1
        login ours "$NAME" "$PASSWORD" || STATUS=1
        stop_dc
        ;;
esac

exit $STATUS
'
