#!/bin/bash
# MIT's `kadmin` against this crate's `kadmind` — the client every operator has.
#
#   scripts/kadmin-mit-stand.sh
#
# Why this exists at all. `tests/kadmin_live.rs` drives the admin protocol with the `krb5` crate,
# which is the right judge for the wire format but is still a Rust client that this project builds
# against. MIT's `kadmin` is a different implementation of the same protocol, written by the people
# who wrote the protocol, and it will complain about things a lenient client does not: an XDR count
# that is off by one, a privilege word that does not match, a GSS token with the wrong usage number.
#
# Two runs, because they catch different faults:
#
#   * an administrator with every right: connect, handshake, list, read, create, change a password,
#     delete. A green here means the answers are the shape MIT unmarshals.
#   * the same administrator with **no** rights: every call must come back as MIT's `AUTH_*`
#     message. A server that answered success, or a bare failure, would be invisible to a Rust
#     client that does not print the code.
#
# Requires: `kadmin` (Debian: krb5-user), cargo, and a free port pair. Run inside
# `docker/kadmin-stand.Dockerfile`, or anywhere with the toolchain and the client.
#
# STATUS: the first scenario fails, and that is the finding, not a bug in the script. MIT's `kadmin`
# gets a ticket, completes the GSS handshake (`kadmind: data: context established` / `MIC verified` /
# `wrap opened` under `RRL_KADMIN_DIAG=1`), sends `kadm5_init` — and then reports
# `Communication failure with server`, so it does not accept this server's *reply*. Three defects on
# the way to that point are fixed (see the commit that added this file); the reply's framing is not.
# The script exits non-zero until it is, deliberately: a stand that swallowed this would say the
# interop works.
set -u

cd "$(dirname "$0")/.." || exit 1
PATH=/usr/local/cargo/bin:$PATH
export PATH

REALM=${STAND_REALM:-EXAMPLE.COM}
ADMIN=kadmin/admin
ADMIN_PASSWORD=${STAND_ADMIN_PASSWORD:-admin-Password-1}
KDC_PORT=${KDC_PORT:-18088}
ADMIN_PORT=${ADMIN_PORT:-18749}
OUT=/tmp/kadmin-stand
CCACHE=FILE:/tmp/krb5cc_stand

command -v kadmin >/dev/null || {
    echo "kadmin is missing (Debian: krb5-user)" >&2
    exit 1
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# A realm in a directory of its own, and a `krb5.conf` the client reads from the environment.
start_stand() {
    local deny=$1
    rm -rf "$OUT"
    mkdir -p "$OUT"
    KRB5CCNAME=$CCACHE kdestroy -A >/dev/null 2>&1

    STAND_REALM=$REALM \
    STAND_ADMIN_PASSWORD=$ADMIN_PASSWORD \
    STAND_DENY=$deny \
        cargo run --features kadmin --example kadmin-stand -- \
        "127.0.0.1:$KDC_PORT" "127.0.0.1:$ADMIN_PORT" "$OUT" \
        > "$OUT/stand.log" 2>&1 &
    STAND_PID=$!

    # Ready when `krb5.conf` exists and the admin port accepts a connection: the file is written
    # before either listener binds, so its presence alone proves nothing.
    for _ in $(seq 1 120); do
        if [ -f "$OUT/krb5.conf" ] && (exec 3<>"/dev/tcp/127.0.0.1/$ADMIN_PORT") 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$STAND_PID" 2>/dev/null; then
            echo "the stand exited before it was ready:" >&2
            cat "$OUT/stand.log" >&2
            exit 1
        fi
        sleep 0.5
    done
    echo "the stand never became reachable; its log:" >&2
    cat "$OUT/stand.log" >&2
    exit 1
}

stop_stand() {
    if [ -n "${STAND_PID:-}" ]; then
        kill "$STAND_PID" 2>/dev/null
        wait "$STAND_PID" 2>/dev/null
    fi
}
trap stop_stand EXIT

# One `kadmin` call, with the client reading this stand's configuration.
kadmin_call() {
    KRB5_CONFIG=$OUT/krb5.conf KRB5CCNAME=$CCACHE \
        kadmin -p "$ADMIN@$REALM" -w "$ADMIN_PASSWORD" -r "$REALM" "$@"
}

echo "=== an administrator with every right"
start_stand 0

kadmin_call -q "getprincs" || fail "getprincs was refused by an administrator holding every right"

# A create, a read of what was created, and a delete: the three answers a client unmarshals most
# strictly, because each carries a principal entry rather than a bare status.
kadmin_call -q "addprinc -pw alice-Password-1 alice" || fail "addprinc"
kadmin_call -q "getprinc alice" | grep -q "Principal: alice@$REALM" || fail "getprinc did not name the entry"
# A password change goes through its own procedure and its own right.
kadmin_call -q "cpw -pw another-Password-1 alice" || fail "cpw"
kadmin_call -q "delprinc -force alice" || fail "delprinc"
kadmin_call -q "getprinc alice" >/dev/null 2>&1 && fail "getprinc found a principal that was deleted"
echo "PASS: an administrator with every right could list, add, read, change and delete"
stop_stand

echo "=== the same administrator with no rights"
start_stand 1

# The connection itself must still work: the handshake is authentication, and refusing it here would
# test the wrong thing. What must fail is every operation after it, with MIT's own message.
for query in "getprincs" "addprinc -pw x y" "getprinc alice"; do
    out=$(kadmin_call -q "$query" 2>&1)
    status=$?
    if [ $status -eq 0 ]; then
        echo "the stand refused nothing; $query was answered with success:" >&2
        echo "$out" >&2
        fail "$query"
    fi
    echo "$out" | grep -qi "insufficient privileges\|requires .* privilege\|Operation requires" || {
        echo "$query was refused, but not with a privilege message:" >&2
        echo "$out" >&2
        fail "$query"
    }
done
echo "PASS: every call was refused with a privilege message"
stop_stand
