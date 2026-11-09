#!/bin/bash
# Regenerates the PKINIT fixtures under tests/pkinit/.
#
# The certificates and the CMS signatures in these files come from OpenSSL, not from this
# crate: a request this KDC both builds and verifies proves only that it agrees with
# itself, which is exactly the mistake the FAST work was spoiled by. `openssl cms -sign`
# is a third-party encoder, so a parser that reads its output reads what a real client
# sends.
#
# The `AuthPack` inside is built by this crate's own example, because its ASN.1 is what
# the KDC must understand; only the CMS envelope around it is foreign.
#
#     ./tests/pkinit/make-fixtures.sh
#
# Requires: openssl 3.x, python3. Deterministic apart from the RSA keys, so the fixtures
# are committed rather than built in CI — a test that needs openssl to run would skip
# wherever it is missing, and a skipped test proves nothing.
set -euo pipefail
cd "$(dirname "$0")"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# DER for `subjectAltName` holding one `id-pkinit-san` otherName:
#
#   GeneralNames ::= SEQUENCE OF GeneralName
#   GeneralName  ::= [0] otherName { OID 1.3.6.1.5.2.2, [0] EXPLICIT KRB5PrincipalName }
#   KRB5PrincipalName ::= SEQUENCE { [0] Realm, [1] PrincipalName { [0] type, [1] SEQUENCE OF } }
san_der() {
    python3 - "$1" "$2" <<'PY'
import sys

def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        head = bytes([tag, n])
    elif n < 0x100:
        head = bytes([tag, 0x81, n])
    else:
        head = bytes([tag, 0x82, n >> 8, n & 0xFF])
    return head + content

def oid(text):
    parts = [int(p) for p in text.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, out)

name, realm = sys.argv[1], sys.argv[2]
principal_name = tlv(0x30, tlv(0xa0, tlv(0x02, b"\x01"))          # name-type: NT-PRINCIPAL
                         + tlv(0xa1, tlv(0x30, tlv(0x1b, name.encode()))))  # one component
krb5 = tlv(0x30, tlv(0xa0, tlv(0x1b, realm.encode())) + tlv(0xa1, principal_name))
# `GeneralName ::= CHOICE { otherName [0] OtherName }` with IMPLICIT tags, so the
# `[0]` replaces OtherName's SEQUENCE tag: its content is the OID and the value.
# An extra SEQUENCE here is accepted by OpenSSL's own printer and rejected by
# every parser that follows RFC 5280, x509-parser included.
other = tlv(0xa0, oid("1.3.6.1.5.2.2") + tlv(0xa0, krb5))
general_names = tlv(0x30, other)
sys.stdout.write(general_names.hex())
PY
}

# The trust anchor of the test realm.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out ca.pem \
    -not_before 20200101000000Z -not_after 20460101000000Z \
    -subj "/CN=EXAMPLE.COM Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# A second CA this realm does not trust, used to show that a certificate for the right
# name from the wrong issuer is still nobody.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/other-ca.key" -out other-ca.pem \
    -not_before 20200101000000Z -not_after 20460101000000Z \
    -subj "/CN=Unrelated CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# $1 name, $2 principal component, $3 CA basename, $4 days or empty, $5 output
issue() {
    local name=$1 principal=$2 ca=$3 days=$4 out=$5
    openssl req -newkey rsa:2048 -nodes -keyout "$WORK/$name.key" \
        -out "$WORK/$name.csr" -subj "/CN=$principal" 2>/dev/null
    cat > "$WORK/$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectAltName=DER:$(san_der "$principal" EXAMPLE.COM)
EOF
    if [ -n "$days" ]; then
        openssl x509 -req -in "$WORK/$name.csr" -CA "$ca.pem" -CAkey "$WORK/$ca.key" \
            -CAcreateserial -days "$days" -extfile "$WORK/$name.ext" -out "$out" 2>/dev/null
    else
        # A window in the past: valid for one day in 2020, expired ever since.
        openssl x509 -req -in "$WORK/$name.csr" -CA "$ca.pem" -CAkey "$WORK/$ca.key" \
            -CAcreateserial -not_before 20200101000000Z -not_after 20200102000000Z \
            -extfile "$WORK/$name.ext" -out "$out" 2>/dev/null
    fi
    cp "$WORK/$name.key" "${out%.pem}-key.pem"
}

issue alice alice ca 7300 alice.pem
issue bob bob ca 7300 bob.pem
# The right name from a CA nobody here trusts.
issue mallory alice other-ca 7300 untrusted-alice.pem
# Expired: the same identity as alice, outside its validity window.
issue expired alice ca "" expired.pem

# A certificate whose SAN names no principal at all: issued by the right CA, but naming
# nobody, which must not become "somebody" by default.
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/nosan.key" \
    -out "$WORK/nosan.csr" -subj "/CN=alice" 2>/dev/null
cat > "$WORK/nosan.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectAltName=DNS:alice.example.com
EOF
openssl x509 -req -in "$WORK/nosan.csr" -CA ca.pem -CAkey "$WORK/ca.key" -CAcreateserial \
    -days 7300 -extfile "$WORK/nosan.ext" -out no-pkinit-san.pem 2>/dev/null
cp "$WORK/nosan.key" no-pkinit-san-key.pem

# A certificate for a TLS server: the right name, the right issuer, the wrong purpose.
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/serverauth.key" \
    -out "$WORK/serverauth.csr" -subj "/CN=alice" 2>/dev/null
cat > "$WORK/serverauth.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DER:$(san_der alice EXAMPLE.COM)
EOF
openssl x509 -req -in "$WORK/serverauth.csr" -CA ca.pem -CAkey "$WORK/ca.key" -CAcreateserial \
    -days 7300 -extfile "$WORK/serverauth.ext" -out wrong-purpose.pem 2>/dev/null
cp "$WORK/serverauth.key" wrong-purpose-key.pem

echo "certificates written. Next: build the signed requests with"
echo "  cargo run --features pkinit --example pkinit-fixture"
