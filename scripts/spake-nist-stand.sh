#!/bin/sh
# Log in to this crate's KDC with MIT's own `kinit`, over each SPAKE group MIT has.
#
# Why: `tests/spake_live.rs` uses this crate's client, and a client of one's own agrees with the
# KDC by construction. MIT's `kinit` does not — it derives `w`, the masks and the transcript hash
# from the registry's definitions, and if our arithmetic differs by one reduction the login fails
# at the second factor with nothing to point at. That is the check this script runs.
#
# The groups are MIT's, not ours: `kinit` is told which to offer through
# `spake_preauth_groups`, and a client that is told `P-256` will refuse the realm's answer if the
# KDC picks anything else. So a login that succeeds says three things at once — the group was
# chosen as asked, the challenge named it, and both sides derived the same key.
#
# MIT 1.18 (the version in the image) knows edwards25519, P-256 and P-384. The registry's fourth
# group, P-521, arrived in MIT 1.20 and is not exercised here; this script says so rather than
# leaving the gap to be inferred.
#
# Usage: scripts/spake-nist-stand.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-rust:1.99.1-bullseye}"
TAG=$(printf '%s' "$IMAGE" | sed 's/.*://')

"$ROOT/scripts/cargo.sh" build -q --example spake-stand --features spake

docker run --rm \
    -v "$ROOT/target/$TAG/debug/examples:/ours:ro" \
    "$IMAGE" sh -ec '
set -eu
apt-get update -qq -o Acquire::Retries=3 -o Acquire::http::Timeout=20 >/dev/null 2>&1
# `krb5-user` is the client: kinit and klist. The libraries are already in the image.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq krb5-user >/dev/null 2>&1

REALM=SPAKE.TEST
PASSWORD="correct horse battery staple"
PORT=18888
DIR=$(mktemp -d)
cd "$DIR"

# Only TCP is configured: this crate serves both, and pinning one transport removes a variable
# that has nothing to do with SPAKE.
cat > krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    udp_preference_limit = 1
    default_ccache_name = FILE:$DIR/ccache

[realms]
    $REALM = {
        kdc = 127.0.0.1:$PORT
    }
EOF
export KRB5_CONFIG="$DIR/krb5.conf"
export KRB5CCNAME="FILE:$DIR/ccache"

/ours/spake-stand 127.0.0.1:$PORT > kdc.log 2>&1 &
KDC_PID=$!
trap "kill $KDC_PID 2>/dev/null || true" EXIT

# Wait for the port, not for a ticket: a `klist` here answers a different question and a stand
# that asks it goes on to report "unable to reach any KDC" when the process is a moment behind.
for i in $(seq 1 200); do
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then break; fi
    if ! kill -0 $KDC_PID 2>/dev/null; then
        echo "the KDC exited during start-up:"; cat kdc.log; exit 1
    fi
    sleep 0.1
done

# `kinit` with a password from stdin: no terminal, no keytab, exactly what the script needs.
login() {
    group=$1
    expected=$2
    kdestroy -A 2>/dev/null || true
    # `spake_preauth_groups` is read from the profile, so each group gets its own config line
    # rather than its own file.
    sed -i "/spake_preauth_groups/d" krb5.conf
    sed -i "/default_realm/a\\    spake_preauth_groups = $group" krb5.conf
    echo "== $group"
    # The trace is the proof, not decoration: a successful `kinit` alone would also be produced by
    # a KDC that never offered SPAKE and a client that fell back to `PA-ENC-TIMESTAMP`. The client
    # itself says which mechanism ran and which group it answered, so the log is where the claim is
    # checked rather than assumed.
    if printf "%s\n" "$PASSWORD" | KRB5_TRACE="$DIR/trace.$group" kinit "alice@$REALM" 2> kinit.err; then
        klist | sed -n "2,3p"
        if ! grep -q "SPAKE challenge received with group $expected" "trace.$group"; then
            echo "   $group: a ticket, but the client did not answer a SPAKE challenge of group $expected:"
            grep -i "spake" "trace.$group" | sed "s/^/   /" || echo "   (no SPAKE in the trace at all)"
            return 1
        fi
        echo "   $group: ticket issued, and the client answered SPAKE group $expected"
        return 0
    fi
    echo "   $group: FAILED"
    sed "s/^/   /" kinit.err
    return 1
}

failed=0
# Every group MIT 1.18 knows, with the registry id our KDC must name in its challenge. P-521 is not
# here: this `kinit` has no such group, and asking for it would test MIT'"'"'s version rather than
# this crate.
for pair in edwards25519:1 P-256:2 P-384:3; do
    login "${pair%%:*}" "${pair##*:}" || failed=1
done

echo "== a wrong password must be refused"
kdestroy -A 2>/dev/null || true
sed -i "/spake_preauth_groups/d" krb5.conf
sed -i "/default_realm/a\\    spake_preauth_groups = P-256" krb5.conf
if printf "%s\n" "not the password" | kinit "alice@$REALM" 2> wrong.err; then
    echo "   FAILED: a wrong password produced a ticket"
    failed=1
else
    echo "   refused: $(head -1 wrong.err)"
fi

echo "== what the KDC said"
grep -iE "spake|group" kdc.log | head -20 || true

exit $failed
'
