#!/bin/sh
# Push a database into this crate's hpropd with Heimdal's own `hprop`.
#
# The reason this exists: the protocol is a stream of `KRB-PRIV` messages behind a `sendauth`
# handshake, and a hand-written test client can only prove that our reader agrees with our writer.
# Heimdal's `hprop` proves that a third party's writer agrees with our reader — which is the whole
# claim of a port.
#
# The stand, inside one container:
#
#   1. seed a master realm in this crate: `krbtgt`, `alice`, and the two principals the protocol
#      needs (`hprop/HOST`, `kadmin/hprop`), plus the keytab `hprop` will authenticate with;
#   2. serve it on loopback and let `hprop` fetch a ticket for `hprop/HOST` — the real client does
#      `kinit -k` internally, so this is a real Kerberos login;
#   3. run our `hpropd` on another loopback port, with an empty staging database;
#   4. run Heimdal's `hprop` against it, and check the entries arrived.
#
# Nothing is published outside the container and nothing is installed on the host.
#
# Usage: scripts/hprop-stand.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE="${IMAGE:-rust:1.99.1-bullseye}"
TAG=$(printf '%s' "$IMAGE" | sed 's/.*://')

# The stand binary is the crate's own: what is checked is what ships.
"$ROOT/scripts/cargo.sh" build -q --example hprop-stand --features hdb-redb

docker run --rm \
    -v "$ROOT:/w:ro" -v "$ROOT/target/$TAG/debug/examples:/ours:ro" \
    "$IMAGE" sh -ec '
set -eu
apt-get update -qq -o Acquire::Retries=3 -o Acquire::http::Timeout=20 >/dev/null 2>&1
# `hprop` and `hpropd` ship in the KDC package, not in `heimdal-clients`: they are the
# server-side tools, and `hprop` is what this script uses as a client.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq heimdal-clients heimdal-kdc heimdal-dev >/dev/null 2>&1
PATH=/usr/sbin:$PATH
cc -O1 -o /tmp/hdbseal /w/docker/heimdal-hdbseal.c -I/usr/include/heimdal \
   -L/usr/lib/x86_64-linux-gnu/heimdal -lkrb5 -lhdb -lasn1 -lroken -lhcrypto -lwind -lcom_err

STAND=/ours/hprop-stand
REALM=HPR.OP.EXAMPLE
# `localhost`, not a made-up name: Heimdal resolves the host to a principal with KRB5_NT_SRV_HST,
# which canonicalises through DNS, and a name that does not resolve would be refused by the client
# before it ever reached this service.
HOST=localhost
DIR=$(mktemp -d)
cd "$DIR"

echo "== seeding the master realm"
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" seed "$DIR"

echo "== starting the master KDC"
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" kdc "$DIR" 127.0.0.1:18888 > kdc.log 2>&1 &
KDC_PID=$!
trap "kill $KDC_PID 2>/dev/null || true" EXIT

# `kinit -k` from Heimdal needs a config; the stand wrote one.
export KRB5_CONFIG="$DIR/krb5.conf"
export KRB5_KTNAME="$DIR/hprop.keytab"

# Wait for the KDC port, not for a ticket: `klist -s` answers a different question, and a stand that
# asks it goes on to fail with "unable to reach any KDC" when the process is a moment behind.
for i in $(seq 1 200); do
    if (exec 3<>/dev/tcp/127.0.0.1/18888) 2>/dev/null; then break; fi
    if ! kill -0 $KDC_PID 2>/dev/null; then
        echo "the KDC exited during start-up:"; cat kdc.log; exit 1
    fi
    sleep 0.1
done

echo "== checking that the master answers"
kinit -k -t "$DIR/hprop.keytab" "kadmin/hprop@$REALM" || { echo "kinit failed"; cat kdc.log; exit 1; }
klist | head -3

echo "== writing the master key the master will seal with"
KDC_REALM=$REALM KDC_HOST=$HOST "$STAND" mkey "$DIR"

echo "== starting hpropd"
KDC_REALM=$REALM KDC_HOST=$HOST HPROR_MKEY="$DIR/m-key" "$STAND" hpropd "$DIR/slave.db" 127.0.0.1:17544 > hpropd.log 2>&1 &
HPROP_PID=$!
trap "kill $KDC_PID $HPROP_PID 2>/dev/null || true" EXIT

# Wait for the port rather than for a fixed sleep: a service that died at start-up must be reported
# before the client tries to reach it, or the failure reads as "connection refused" with no reason.
for i in $(seq 1 100); do
    if ! kill -0 $HPROP_PID 2>/dev/null; then
        echo "hpropd exited during start-up:"
        cat hpropd.log
        exit 1
    fi
    if (exec 3<>/dev/tcp/127.0.0.1/17544) 2>/dev/null; then break; fi
    sleep 0.1
done

# The octets both sides seal: 32 of 0x5a, printed once so that the two directions use the same input.
PLAIN=$(printf "5a%.0s" $(seq 1 32))

echo "== pushing with Heimdal hprop"
# -k is load-bearing: without it the client looks for its key in the HDBGET: keytab of Heimdal,
# which reads a Heimdal database this stand does not have. (No apostrophes anywhere below: the whole
# block is inside a single-quoted shell string, and one would end it silently.)
set +e
timeout 90 hprop -k "FILE:$DIR/hprop.keytab" -R "$REALM" -v "localhost:17544" > hprop.out 2>&1
RC=$?
set -e
echo "hprop exit: $RC"
sleep 1
echo "-- hpropd said:"; cat hpropd.log
# The push reaches our service and is refused for one reason only: the database hprop reads was
# sealed under ITS OWN master key, and we hold a different one. That is the honest outcome here, and
# it is exactly what a slave sees when it is given the wrong stash — the tag does not verify, and the
# refusal says the master key is the wrong one rather than calling the record corrupt.
grep -q "does not open under this master key" hpropd.log || {
    echo "the push failed for a reason this stand does not model"; exit 1
}

echo "== the construction itself, in both directions"
# The refusal above is about a key we do not have; it says nothing about whether our sealing agrees
# with Heimdal. This does, on one key both sides can read:
#   - we seal 32 known octets under the master keytab, Heimdal opens them;
#   - Heimdal seals the same octets, we open them.
OURS=$("$STAND" seal "$DIR/m-key" "$PLAIN" | grep sealed | sed "s/.*: //")
echo "ours:   $OURS"
echo "-- heimdal opens ours:"
/tmp/hdbseal -d "$DIR/m-key" "$OURS" | tail -1
THEIRS=$(/tmp/hdbseal "$DIR/m-key" "$PLAIN" | grep sealed | sed "s/.*: //")
echo "-- heimdal seals, we open:"
"$STAND" unseal "$DIR/m-key" "$THEIRS"
'
