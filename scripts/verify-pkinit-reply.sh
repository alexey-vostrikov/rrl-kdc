#!/bin/sh
# Judges a PA-PK-AS-REP by OpenSSL.
#
# The KDC signs the client's DH nonce in CMS `SignedData`; if the envelope is wrong, a client
# built by somebody else cannot read it, and a reply this crate both produced and verified
# would prove only that it agrees with itself. So the signature is checked by `openssl cms
# -verify`, which knows nothing about this code.
#
# Usage:
#   examples/pkinit — written by `cargo run --features pkinit --example pkinit-reply`
#   scripts/verify-pkinit-reply.sh [dir]
#
# It checks, in order:
#   1. the SignedData verifies against the test CA and carries id-pkinit-DHKeyData;
#   2. the content parses as KDCDHKeyInfo with the nonce that was signed;
#   3. the outer structure is PA-PK-AS-REP ::= [0] DHRepInfo { [0] SignedData }.
set -eu

DIR=${1:-tests/pkinit}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

SIGNED="$DIR/dh-signed-data.der"
REP="$DIR/pk-as-rep.der"

for f in "$SIGNED" "$REP" "$DIR/ca.pem"; do
    [ -f "$f" ] || { echo "missing $f — run: cargo run --features pkinit --example pkinit-reply -- $DIR"; exit 1; }
done

echo "== 1. the CMS signature, checked by openssl"
openssl cms -verify -inform DER -in "$SIGNED" -CAfile "$DIR/ca.pem" \
    -purpose any -out "$WORK/content.der" 2>"$WORK/cms.err" \
    || { cat "$WORK/cms.err"; echo "FAIL: openssl refused the SignedData"; exit 1; }
echo "   signature verifies against $DIR/ca.pem"

# The content type must be id-pkinit-DHKeyData (1.3.6.1.5.2.3.2): a signature over some
# other content would verify and mean nothing. It sits in EncapsulatedContentInfo, past the
# digest algorithms, so the whole parse is searched rather than its first lines.
openssl asn1parse -inform DER -in "$SIGNED" > "$WORK/asn1.txt"
if grep -q "1\.3\.6\.1\.5\.2\.3\.2" "$WORK/asn1.txt"; then
    echo "   content type is id-pkinit-DHKeyData (1.3.6.1.5.2.3.2)"
else
    echo "FAIL: the signed content is not id-pkinit-DHKeyData:"
    grep -i "OBJECT" "$WORK/asn1.txt" | sed 's/^/     /'
    exit 1
fi

echo "== 2. KDCDHKeyInfo carries the signed nonce"
openssl asn1parse -inform DER -in "$WORK/content.der" -i | sed 's/^/   /' | head -8
# `openssl asn1parse` prints an INTEGER past 32 bits in hexadecimal, so the comparison is
# in hex: 0x51501234 is the nonce the example signed.
NONCE=$(openssl asn1parse -inform DER -in "$WORK/content.der" \
    | awk -F'INTEGER *:' '/INTEGER/{print $2; exit}' | tr -d ' ' | tr 'A-Z' 'a-z')
[ "$NONCE" = "51501234" ] \
    || { echo "FAIL: the nonce is ${NONCE:-none}, expected 51501234 (0x51501234)"; exit 1; }
echo "   nonce 0x${NONCE} — the value the client signed"

echo "== 3. the outer PA-PK-AS-REP is [0] DHRepInfo { [0] SignedData }"
FIRST=$(openssl asn1parse -inform DER -in "$REP" | head -1)
case "$FIRST" in
    *"cont [ 0 ]"*) echo "   dhInfo [0] present" ;;
    *) echo "FAIL: the outer tag is not [0]: $FIRST"; exit 1 ;;
esac
openssl asn1parse -inform DER -in "$REP" | sed -n '2,5p' | sed 's/^/   /'

echo
echo "OK: PA-PK-AS-REP verified by openssl"
