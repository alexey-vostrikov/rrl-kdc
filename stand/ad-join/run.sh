#!/bin/sh
# Runs the AD-join stand: one container, both servers, four steps, the first failure
# printed raw.
#
# Nothing is published to the host and nothing is installed there: the container is
# the stand. What it needs from this machine is two binaries and a shell.
#
#   ./run.sh                 # every step, stop at the first failure
#   ./run.sh join            # one step
#   KEEP=1 ./run.sh          # leave the container running to poke at it
#
# The image is built on first use and cached; it carries the client tools the check
# needs (krb5, samba, dnsmasq, ldap-utils) and no Rust, because both servers are
# built outside it — this crate's by `scripts/cargo.sh`, the directory's by its own
# wrapper.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
KDC_ROOT=$(cd "$HERE/../.." && pwd)
# Where the consumer keeps its release build. Overridable because the checkout is a
# local detail, and a missing binary should say so rather than run an old one.
RRD_ROOT="${RRD_ROOT:-$KDC_ROOT/../3part/rust-rest-ldap}"
RRD_TARGET="${RRD_TARGET:-$HOME/.cache/rrl/target/release}"
KDC_BIN="${KDC_BIN:-$KDC_ROOT/target/debug/examples/kdc-stand}"
RRD_BIN="${RRD_BIN:-$RRD_TARGET/rust-rest-ldap}"

for bin in "$KDC_BIN" "$RRD_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "missing $bin" >&2
        echo "  $KDC_BIN  <- scripts/cargo.sh build --example kdc-stand --features hdb-redb" >&2
        echo "  $RRD_BIN  <- (cd $RRD_ROOT && ./scripts/cargo.sh build --release)" >&2
        exit 2
    fi
done

IMAGE="${STAND_IMAGE:-rust-rest-ldap-ad-join-stand}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "== building $IMAGE (once)"
    docker build -q -t "$IMAGE" "$HERE"
fi

docker rm -f ad-join-stand >/dev/null 2>&1 || true

exec docker run --rm --name ad-join-stand \
    --hostname samba.ad.example.com \
    -v "$KDC_BIN:/usr/local/bin/kdc-stand:ro" \
    -v "$RRD_BIN:/usr/local/bin/rust-rest-ldap:ro" \
    -v "$HERE/stand.sh:/usr/local/bin/stand.sh:ro" \
    -v "$HERE/rrd.yaml:/shared/rrd.yaml:ro" \
    -e RRD_ADMIN_PASSWORD="admin-Password-1" \
    "$IMAGE" /usr/local/bin/stand.sh "${1:-all}"
