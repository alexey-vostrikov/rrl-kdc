#!/bin/sh
# A real propagation: Heimdal's `hprop` reads a **Heimdal** HDB, and this crate's `hpropd` installs it.
#
# The stand next door (`hprop-stand.sh`) stops one step short, on purpose: Heimdal's `hprop` needs an
# HDB to read from, and that HDB's keys are sealed under *its* master key. It proves the refusal is
# honest and that the sealing construction agrees in both directions, but it never installs an entry.
#
# This script closes that gap by not fighting the master key:
#
#   1. create the master side with Heimdal's own `kadmin -l init`, so the realm has a Heimdal HDB and
#      a Heimdal stash (`heimdal.mkey`, a keytab with `K/M@REALM` — which this crate's
#      `MasterKeys::from_keytab` reads as-is);
#   2. add the principals here with the **same passwords** the other side uses, so the long-term keys
#      agree (same enctype, same default salt) and one keytab authenticates on both;
#   3. serve that realm from this crate's KDC — `hprop` does `kinit -k` and needs a KDC to talk to;
#   4. run `hpropd` with `HPROR_MKEY` pointing at **Heimdal's stash**, so the entries it receives open;
#   5. push with Heimdal's `hprop` and dump what arrived.
#
# What this proves that a self-test cannot: the octets Heimdal writes are read by code that did not
# write them, all the way through to a database this crate serves tickets from.
#
# Usage: scripts/hprop-heimdal-master.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-rust:1.99.1-bullseye}"
TAG=$(printf '%s' "$IMAGE" | sed 's/.*://')

"$ROOT/scripts/cargo.sh" build -q --example hprop-stand --features hdb-redb

docker run --rm \
    -v "$ROOT:/w:ro" -v "$ROOT/target/$TAG/debug/examples:/ours:ro" \
    "$IMAGE" sh -ec '
set -eu
apt-get update -qq -o Acquire::Retries=3 -o Acquire::http::Timeout=20 >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq heimdal-clients heimdal-kdc >/dev/null 2>&1
PATH=/usr/sbin:$PATH
export PATH

# Debian renames Heimdal programs to avoid colliding with MIT; pick whichever spelling exists.
for prog in kadmin hprop; do
    if command -v "$prog" >/dev/null 2>&1; then
        eval "HAVE_$(echo "$prog" | tr a-z A-Z)=$prog"
    elif command -v "$prog.heimdal" >/dev/null 2>&1; then
        eval "HAVE_$(echo "$prog" | tr a-z A-Z)=$prog.heimdal"
    else
        echo "no $prog in this image"; exit 1
    fi
done

STAND=/ours/hprop-stand
REALM=HPR.OP.EXAMPLE
HOST=localhost
# The passwords the seeded side uses. Spelled out because the whole point is that both sides derive
# the same key from them; a mismatch fails as "the client did not decrypt its ticket", which reads
# like a protocol problem rather than a configuration one.
CLIENT_PW="the masters propagation password"
SERVICE_PW="the hprop service password"
ALICE_PW="alices password"

OURS=$(mktemp -d)

# `kadmin -l init` writes where its own configuration says and ignores `[hdb] db-dir` from
# `krb5.conf`; the default is this directory, and it is the one path `kadmin -l` and `hprop` agree
# on without a `kdc.conf` of our own.
HM=/var/lib/heimdal-kdc
rm -f "$HM/heimdal.db" "$HM/m-key" "$HM"/heimdal.mkey "$HM/heimdal.log"
cd "$HM"

# The default master key set in Heimdal includes `des3-cbc-sha1`, and this crate refuses an enctype it
# does not implement — loudly, which is right, but it means a default Heimdal realm produces a stash
# this KDC cannot load. That is a finding about the *master key set*, not about propagation, and it
# deserves its own decision; here the stash is restricted to the enctype both sides share so that the
# propagation itself is what the stand measures.
# The knob lives in `[kadmin]`, not `[libdefaults]`: Heimdal documents `default_keys` there, and a
# value in the wrong section is silently ignored — which shows up as a stash full of `des3` again.
printf "[libdefaults]\n    default_realm = %s\n[kadmin]\n    default_keys = aes256-cts:pw-salt\n" \
    "$REALM" > "$HM/krb5.conf"
export KRB5_CONFIG="$HM/krb5.conf"

echo "== the master side: a Heimdal HDB with a Heimdal stash"
# Explicit lifetimes, so the two questions with defaults are not answered from stdin: the input here
# is the master key passphrase, and feeding it to a lifetime prompt created no database at all —
# silently, because `init` exits 0 after printing usage.
printf "master-pw\nmaster-pw\n" | \
    "$HAVE_KADMIN" -l --realm="$REALM" init \
        --realm-max-ticket-life=1d --realm-max-renewable-life=7d "$REALM" > init.log 2>&1 || {
    echo "kadmin -l init failed:"; cat init.log; exit 1
}
# `init` writes the database but not the stash: the master key file comes from `kstash`, and with a
# random key it needs no terminal — which is the only reason this stand can run in a container. The
# file it writes is `m-key`, not `<realm>.mkey`: the name is fixed, and looking for the wrong one is
# how a stand concludes "init failed" while a perfectly good database sits next to it.
"$HAVE_KADMIN" -l --realm="$REALM" list "*" >/dev/null 2>&1 || true
kstash --random-key > stash.log 2>&1 || { echo "kstash failed:"; cat stash.log; exit 1; }
STASH=$(ls "$HM"/m-key "$HM"/*.mkey 2>/dev/null | head -1)
[ -f "$HM/heimdal.db" ] && [ -n "${STASH:-}" ] || {
    echo "no database or no stash behind:"; ls -l "$HM"; cat init.log stash.log; exit 1
}
echo "   db: $HM/heimdal.db"
echo "   stash: $STASH"

echo "== the same principals, with the passwords the other side uses"
for spec in "alice:$ALICE_PW" "kadmin/hprop:$CLIENT_PW" "hprop/$HOST:$SERVICE_PW"; do
    name=${spec%%:*}
    pw=${spec#*:}
    # Idempotent: `kadmin -l init` on this version leaves principals behind from its own setup, and
    # an `add` that fails on an existing name would stop the stand at the second principal for a
    # reason that has nothing to do with propagation.
    "$HAVE_KADMIN" -l --realm="$REALM" del "$name@$REALM" >/dev/null 2>&1 || true
    "$HAVE_KADMIN" -l --realm="$REALM" add --use-defaults --password="$pw" "$name@$REALM" \
        > add.log 2>&1 || { echo "adding $name failed:"; cat add.log; exit 1; }
done
"$HAVE_KADMIN" -l --realm="$REALM" get "alice@$REALM" 2>/dev/null \
    | grep -E "Principal:|Keytypes" | sed "s/^/   /"

echo "== this crate serves the same realm, so hprop can kinit"
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" seed "$OURS" >/dev/null
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" kdc "$OURS" 127.0.0.1:18888 > kdc.log 2>&1 &
KDC_PID=$!
# `set -u` and a trap that runs before the second daemon starts: an unset variable there turns every
# later failure into "parameter not set" instead of the failure itself.
HPROP_PID=
trap "kill $KDC_PID ${HPROP_PID:-} 2>/dev/null || true" EXIT
for i in $(seq 1 200); do
    (exec 3<>/dev/tcp/127.0.0.1/18888) 2>/dev/null && break
    kill -0 $KDC_PID 2>/dev/null || { echo "the KDC exited:"; cat kdc.log; exit 1; }
    sleep 0.1
done

cat > "$OURS/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false

[realms]
    $REALM = {
        kdc = 127.0.0.1:18888
    }
EOF
export KRB5_CONFIG="$OURS/krb5.conf"
export KRB5_KTNAME="$OURS/hprop.keytab"

echo "== checking that hprop can log in to this KDC with its keytab"
kinit -k -t "$OURS/hprop.keytab" "kadmin/hprop@$REALM" || { echo "kinit failed"; cat kdc.log; exit 1; }
klist | sed -n "2,3p" | sed "s/^/   /"

echo "== hpropd accepts into an empty database, sealing with the Heimdal stash"
KDC_REALM=$REALM KDC_HOST=$HOST HPROR_MKEY="$STASH" \
    "$STAND" hpropd "$OURS/slave.db" 127.0.0.1:17544 > hpropd.log 2>&1 &
HPROP_PID=$!
for i in $(seq 1 100); do
    kill -0 $HPROP_PID 2>/dev/null || { echo "hpropd exited:"; cat hpropd.log; exit 1; }
    (exec 3<>/dev/tcp/127.0.0.1/17544) 2>/dev/null && break
    sleep 0.1
done

echo "== pushing with Heimdal hprop"
set +e
timeout 90 "$HAVE_PROP" -k "FILE:$OURS/hprop.keytab" -R "$REALM" -v "localhost:17544" > hprop.out 2>&1
RC=$?
set -e
echo "   hprop exit: $RC"
sed "s/^/   hprop: /" hprop.out | head -10
sed "s/^/   hpropd: /" hpropd.log | head -10
[ "$RC" -eq 0 ] || { echo "PUSH FAILED"; exit 1; }

echo "== what the slave holds"
KDC_REALM=$REALM KDC_HOST=$HOST HPROR_MKEY="$STASH" "$STAND" dump "$OURS/slave.db" > dump.txt 2>&1 || {
    echo "the database does not open:"; cat dump.txt; exit 1
}
sed "s/^/   /" dump.txt

for who in "alice@$REALM" "krbtgt/$REALM@$REALM"; do
    grep -q "$who" dump.txt || { echo "MISSING: $who did not arrive"; exit 1; }
done
echo "OK: Heimdal pushed a database this crate installed"
'
