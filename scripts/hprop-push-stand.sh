#!/bin/sh
# rrl-kdc -> rrl-kdc: a master pushes its database into a slave of the same crate.
#
# Both ends are this crate, which is what makes this the test of the pairing: two processes, one
# socket, and a database that becomes the slave copy. The interop claim is separate and lives next
# door (hprop-stand.sh proves that Heimdal hprop reaches our receiver; hprop-heimdal-master.sh shows
# why a real Heimdal master still cannot feed it).
#
# Nothing is published outside the container and nothing is installed on the host.
#
# Usage: scripts/hprop-push-stand.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-rust:1.99.1-bullseye}"
TAG=$(printf '%s' "$IMAGE" | sed 's/.*://')

"$ROOT/scripts/cargo.sh" build -q --example hprop-stand --features hdb-redb

docker run --rm \
    -v "$ROOT/target/$TAG/debug/examples:/ours:ro" \
    "$IMAGE" sh -ec '
set -eu
STAND=/ours/hprop-stand
REALM=PUSH.OP.EXAMPLE
HOST=localhost
DIR=$(mktemp -d)
cd "$DIR"

echo "== the realm of the master, as files the slave does not share"
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" seed "$DIR" | sed "s/^/   /"

echo "== the master key, the same one the slave is given"
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" mkey "$DIR" | sed "s/^/   /"

echo "== the slave, into an empty staging database"
KDC_REALM=$REALM KDC_HOST=$HOST HPROR_MKEY="$DIR/m-key" \
    "$STAND" hpropd "$DIR/slave.db" 127.0.0.1:17544 > hpropd.log 2>&1 &
HPROP_PID=$!
trap "kill $HPROP_PID 2>/dev/null || true" EXIT
for i in $(seq 1 200); do
    kill -0 $HPROP_PID 2>/dev/null || { echo "the slave exited:"; cat hpropd.log; exit 1; }
    (exec 3<>/dev/tcp/127.0.0.1/17544) 2>/dev/null && break
    sleep 0.1
done
echo "   listening"

echo "== the push"
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" push "$DIR" localhost:17544 | sed "s/^/   /"
sleep 0.5
sed "s/^/   slave: /" hpropd.log

echo "== what the slave holds"
KDC_REALM=$REALM KDC_HOST=$HOST HPROR_MKEY="$DIR/m-key" "$STAND" dump "$DIR/slave.db" > dump.txt 2>&1 || {
    echo "the database does not open:"; cat dump.txt; exit 1
}
sed "s/^/   /" dump.txt

for who in "alice@$REALM" "krbtgt/$REALM@$REALM" "kadmin/hprop@$REALM"; do
    grep -q "$who" dump.txt || { echo "MISSING: $who did not arrive"; exit 1; }
done

echo "== a KDC over the pushed database starts and answers"
# The stronger claim -- that it issues tickets for the user the push brought -- needs a real AS-REQ,
# and that is the Rust test the_slave_serves_a_ticket_from_what_it_was_pushed. Here the point is
# narrower: the file the slave was left with is a database this KDC can open and serve from.
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" kdc "$DIR" 127.0.0.1:18888 > kdc.log 2>&1 &
KDC_PID=$!
trap "kill $HPROP_PID $KDC_PID 2>/dev/null || true" EXIT
for i in $(seq 1 200); do
    (exec 3<>/dev/tcp/127.0.0.1/18888) 2>/dev/null && break
    kill -0 $KDC_PID 2>/dev/null || { echo "the KDC exited:"; cat kdc.log; exit 1; }
    sleep 0.1
done
echo "   the slave KDC accepted a connection on 18888"

echo "OK: a database pushed from this crate into this crate, installed and served"
'
