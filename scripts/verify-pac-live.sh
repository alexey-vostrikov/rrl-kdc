#!/bin/sh
# Starts a KDC that issues PACs, has impacket ask it for a TGT, and reads the PAC out
# of the ticket the KDC actually handed over.
#
# Why this exists next to `verify-pac.sh`: that one hands impacket bytes this crate
# produced, so it proves the encoder and nothing about the engine. This one proves
# the engine — the ticket here is one the KDC built in answer to a real AS-REQ, and
# the PAC inside it was signed with the key the KDC holds.
#
# The KDC runs on port `PAC_LIVE_PORT` (default 8888) because port 88 needs root; the
# verifier points impacket at that port instead of 88 and changes nothing else.
#
#   scripts/verify-pac-live.sh
#
# `PAC_LIVE_VENV` overrides the virtualenv; the default is created on first use.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK_REL="${PAC_LIVE_WORK:-target/pac-live}"
WORK="$ROOT/$WORK_REL"
PORT="${PAC_LIVE_PORT:-8888}"
VENV="${PAC_LIVE_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/rrl-kdc/ad-blob-venv}"
CONTAINER="pac-live-stand-$$"
CACHE="${KDC_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rrl-kdc}"

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "== building the stand"
"$ROOT/scripts/cargo.sh" build --example kdc-stand >/dev/null

rm -rf "$WORK"
mkdir -p "$WORK" "$CACHE/cargo" "$CACHE/rustup"

echo "== starting the KDC on 127.0.0.1:$PORT with PACs enabled"
# `--network host` so the client reaches the port the stand bound, and the image is
# the same one the gates use, so the binary's glibc matches.
docker run -d --name "$CONTAINER" --network host \
    -u "$(id -u):$(id -g)" \
    -v "$ROOT:/w" \
    -v "$CACHE/cargo:/cargo" \
    -v "$CACHE/rustup:/rustup" \
    -e KDC_PAC=1 \
    -e KDC_REALM="${PAC_REALM:-AD.EXAMPLE.COM}" \
    -e KDC_HOST="${PAC_KDC_HOST:-samba.ad.example.com}" \
    -e KDC_DOMAIN_SID="${PAC_EXPECT_DOMAIN_SID:-S-1-5-21-100-200-300}" \
    rust:1.99.1-bullseye \
    /w/target/debug/examples/kdc-stand "127.0.0.1:$PORT" "/w/$WORK_REL" >/dev/null

# The stand prints "serving on" once the socket is bound, and a client that arrived a
# moment early would only see a dropped datagram. Poll the port rather than sleeping a
# guessed interval.
python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 30
while time.time() < deadline:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.settimeout(0.5)
    try:
        # An empty datagram: the KDC answers with a KRB-ERROR, which proves the socket
        # is bound and reading. The reply is not parsed here.
        probe.sendto(b"", ("127.0.0.1", port))
        probe.recvfrom(4096)
        sys.exit(0)
    except Exception:
        time.sleep(0.3)
    finally:
        probe.close()
print("the KDC never answered on port %d" % port)
sys.exit(1)
PY

if [ ! -s "$WORK/krbtgt.key" ]; then
    echo "the stand wrote no krbtgt key; its log follows"
    docker logs "$CONTAINER" 2>&1 | tail -20
    exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
    echo "   creating $VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check impacket
fi

echo "== impacket, against the running KDC"
PAC_HOST=127.0.0.1 \
PAC_PORT="$PORT" \
PAC_REALM="${PAC_REALM:-AD.EXAMPLE.COM}" \
PAC_KEY_FILE="$WORK/krbtgt.key" \
PAC_EXPECT_DOMAIN_SID="${PAC_EXPECT_DOMAIN_SID:-S-1-5-21-100-200-300}" \
    "$VENV/bin/python" "$ROOT/scripts/verify-pac-live.py"
