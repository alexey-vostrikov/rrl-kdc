#!/bin/sh
# Seals a PAC with this crate and has impacket verify both signatures, so that the
# evidence is somebody else's implementation of [MS-PAC] §2.8.1 and not this
# crate agreeing with itself.
#
# Why a script and not a test: impacket is a Python package this crate does not
# depend on, and a test would either skip silently — indistinguishable from
# passing — or fail on a machine without it for reasons that are not about the
# code.
#
#   scripts/verify-pac.sh
#
# `PAC_VENV` overrides the virtualenv; the default is created on first use.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK_REL="${PAC_WORK:-target/pac}"
WORK="$ROOT/$WORK_REL"
VENV="${PAC_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/rust-heimdal-kdc/ad-blob-venv}"

echo "== sealing a PAC"
mkdir -p "$WORK"
"$ROOT/scripts/cargo.sh" run --quiet --example pac-blob > "$WORK/pac.hex"

if [ ! -x "$VENV/bin/python" ]; then
    echo "   creating $VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check impacket
fi

echo "== impacket"
"$VENV/bin/python" "$ROOT/scripts/verify-pac.py" "$WORK/pac.hex"
