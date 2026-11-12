#!/bin/sh
# Check the `krb5Key` layout against Heimdal, in both directions.
#
# The claim being tested is narrow and checkable: a value this crate writes must mean the same thing to
# Heimdal that it means to us. `hdb-ldap.c` writes `ASN1_MALLOC_ENCODE(Key, …)` and reads `decode_Key`,
# so one small program compiled against Debian's Heimdal settles it — no guesswork from the ASN.1 text,
# and no trust in our own reader agreeing with our own writer.
#
# Both directions:
#   * our value, decoded by Heimdal — `mkvno` absent, the enctype and the salt as we meant them;
#   * Heimdal's value, decoded by us — the same fields back.
#
# Usage: scripts/heimdal-key-layout.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-rust:1.99.1-bullseye}"
TAG=$(printf '%s' "$IMAGE" | sed 's/.*://')

"$ROOT/scripts/cargo.sh" build -q --example key-value --features hdb-ldap

docker run --rm \
    -v "$ROOT:/w:ro" \
    -v "$ROOT/target/$TAG/debug/examples:/ours:ro" \
    "$IMAGE" sh -ec '
set -eu
apt-get update -qq -o Acquire::Retries=3 -o Acquire::http::Timeout=20 >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq heimdal-dev >/dev/null 2>&1
cc -O1 -o /tmp/key /w/docker/heimdal-key.c -I/usr/include/heimdal \
   -L/usr/lib/x86_64-linux-gnu/heimdal -lkrb5 -lhdb -lasn1 -lroken -lhcrypto -lwind -lcom_err

OURS=/ours/key-value
KEY=$(printf "5a%.0s" $(seq 1 32))
SALT="EXAMPLE.COMalice"

echo "== 1. a value this crate writes, decoded by Heimdal"
HEX=$("$OURS" encode aes256-cts-hmac-sha1-96 "$KEY" "$SALT")
echo "ours:      $HEX"
/tmp/key decode "$HEX" | sed "s/^/heimdal: /"

echo
echo "== 2. a value Heimdal writes, decoded by us"
THEIRS=$(/tmp/key encode 18 "$KEY" "$SALT" | sed "s/.*: //")
echo "heimdal:   $THEIRS"
"$OURS" decode "$THEIRS" | sed "s/^/ours:     /"

echo
echo "== 3. a sealed value: mkvno is where Heimdal keeps it"
SEALED=$("$OURS" encode-sealed aes256-cts-hmac-sha1-96 "$KEY" "$SALT" 4)
echo "ours:      $SEALED"
/tmp/key decode "$SEALED" | sed "s/^/heimdal: /"

echo
echo "== 4. Heimdal writes mkvno too, and we read it"
THEIRS_SEALED=$(/tmp/key encode 18 "$KEY" "$SALT" 7 | sed "s/.*: //")
echo "heimdal:   $THEIRS_SEALED"
"$OURS" decode "$THEIRS_SEALED" | sed "s/^/ours:     /"
'
