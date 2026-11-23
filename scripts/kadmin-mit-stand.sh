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
# Assertions are made on the **text** of the answer, not on the exit status: MIT's `kadmin -q` returns
# 0 whatever the operation did. Measured, not assumed — a `getprinc` for a principal that does not
# exist prints "Principal does not exist" and still exits 0, and so does a duplicate `addprinc`. A
# stand that trusted `$?` would pass while the server refused everything.
#
# Four defects were found here and fixed, each invisible to this crate's own client because both
# ends shared the mistake: the acceptor numbered its reply tokens from zero instead of continuing
# the sequence its AP-REP announced (MIT answers "Communication failure"); `mod_name` was sent as
# NULL, which MIT's `kadmin` unparses without a NULL check and kills `getprinc` with a parse error
# that blames the principal; and two privilege answers, below.
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
        # The stand is *supposed* to die here, so its status is 143 — and `wait` would hand that to
        # `set -e`-less callers as the script's own result. A clean run has to look clean.
        wait "$STAND_PID" 2>/dev/null
        STAND_PID=
    fi
    return 0
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

# A principal of the stand's own, so that a realm the example seeded is not the thing under test.
NEW=mitprobe

# A create, a read of what was created, and a delete: the three answers a client unmarshals most
# strictly, because each carries a principal entry rather than a bare status. Every expectation is
# on the text; see the note about exit statuses at the top.
kadmin_call -q "addprinc -pw $NEW-Password-1 $NEW" 2>&1 | grep -q "already exists" \
    && fail "addprinc found an entry that should not exist"
kadmin_call -q "getprinc $NEW" 2>&1 | grep -q "Principal: $NEW@$REALM" \
    || fail "getprinc did not name the entry it had just created"
# Who changed it, and when: `mod_name`/`mod_date` of the entry record. MIT prints them as
# "Last modified: <date> (<principal>)". This is the field that used to be the entry's own name
# because nothing recorded a modifier — so a stand that only checked the name of the entry would
# pass with the wrong person in it.
kadmin_call -q "getprinc $NEW" 2>&1 \
    | grep -qE "Last modified: .*\\($ADMIN@$REALM\\)" \
    || fail "getprinc did not name the administrator who created the entry"
# A password change goes through its own procedure and its own right.
kadmin_call -q "cpw -pw another-Password-1 $NEW" 2>&1 | grep -q "Password for .* changed" \
    || fail "cpw did not report the change"
kadmin_call -q "delprinc -force $NEW" 2>&1 | grep -q "deleted" \
    || fail "delprinc did not report the delete"
# `kadmin` writes its errors to stderr, so a check that reads only stdout sees an empty answer and
# calls a correct refusal a failure.
kadmin_call -q "getprinc $NEW" 2>&1 | grep -q "does not exist" \
    || fail "getprinc still found a principal that was deleted"
echo "PASS: an administrator with every right could list, add, read, change and delete"
stop_stand

echo "=== the same administrator with no rights"
start_stand 1

# The connection itself must still work: the handshake is authentication, and refusing it here would
# test the wrong thing. What must fail is every operation after it, with MIT's own message.
for query in "getprincs" "addprinc -pw x y" "getprinc alice"; do
    out=$(kadmin_call -q "$query" 2>&1)
    # The exit status is 0 either way, so a refusal is recognised by its message alone — and a call
    # that *silently* succeeded would show up as that message's absence, not as a status.

    echo "$out" | grep -qi "insufficient privileges\|requires .* privilege\|Operation requires" || {
        echo "$query was refused, but not with a privilege message:" >&2
        echo "$out" >&2
        fail "$query"
    }
done
echo "PASS: every call was refused with a privilege message"
stop_stand
exit 0
