#!/bin/sh
# Can MIT's own kinit do client-side SPAKE at all?
#
# The question this answers is not about this crate: it is whether the client in the image has a
# working SPAKE preauth module. Run against MIT's own KDC, which supports SPAKE, a client that can
# do SPAKE will answer the challenge; one that cannot will fall back to `PA-ENC-TIMESTAMP` and the
# login still succeeds — which is exactly the trap a plain "kinit worked" check falls into.
set -eu

REALM=MITSPAKE.TEST
PASSWORD=alice-password-1
DIR=/tmp/mit-spake
mkdir -p "$DIR"
cd "$DIR"

cat > krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    spake_preauth_groups = edwards25519
    default_ccache_name = FILE:$DIR/ccache

[realms]
    $REALM = {
        kdc = 127.0.0.1:18899
        admin_server = 127.0.0.1:18749
    }

[dbmodules]
    $REALM = {
        db_library = db2
        database_name = $DIR/principal
    }
EOF
export KRB5_CONFIG="$DIR/krb5.conf"
export KRB5_KDC_PROFILE="$DIR/kdc.conf"

cat > kdc.conf <<EOF
[kdcdefaults]
    kdc_ports = 18899
    kdc_tcp_ports = 18899
    spake_preauth_groups = edwards25519

[realms]
    $REALM = {
        database_name = $DIR/principal
        key_stash_file = $DIR/stash
        acl_file = $DIR/kadm5.acl
        admin_keytab = $DIR/kadm5.keytab
        max_life = 1d
        max_renewable_life = 7d
    }
EOF

echo "master-password" | kdb5_util create -s -r "$REALM" -P master-password >/dev/null
kadmin.local -q "addprinc -pw $PASSWORD alice" >/dev/null 2>&1
# `addprinc -requires_preauth` did not take effect on this kadmin (attributes came back empty), and
# `modprinc +requires_preauth` does. Without it the MIT KDC answers the first AS-REQ with a ticket
# and no preauthentication runs at all — which would make this probe say "no SPAKE module" for a
# reason that has nothing to do with SPAKE.
kadmin.local -q "modprinc +requires_preauth alice" >/dev/null 2>&1
kadmin.local -q "getprinc alice" 2>/dev/null | grep -i attributes | sed 's/^/   /'
echo "*/admin@$REALM *" > "$DIR/kadm5.acl"

krb5kdc -n > kdc.log 2>&1 &
KDC_PID=$!
trap "kill $KDC_PID 2>/dev/null || true" EXIT
for i in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/18899) 2>/dev/null && break; sleep 0.1; done

echo "== MIT kinit against MIT kdc, spake_preauth_groups = edwards25519"
printf "%s\n" "$PASSWORD" | KRB5_TRACE="$DIR/trace.txt" kinit "alice@$REALM" 2>/dev/null || {
    echo "login failed:"; tail -20 "$DIR/trace.txt"; exit 1
}
klist | sed -n '2,3p'

echo "-- what the client says it used:"
grep -E "Preauth module|Produced preauth for next request|SPAKE" "$DIR/trace.txt" | sed 's/^/   /' | head -12

if grep -q "Preauth module spake" "$DIR/trace.txt"; then
    echo "RESULT: the client has a working SPAKE module"
else
    echo "RESULT: the client has NO working SPAKE module (it fell back to another preauth)"
fi
