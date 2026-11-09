#!/bin/sh
# Encodes KERB_VALIDATION_INFO and a PAC carrying it, then has impacket read both
# back — the acceptance for the one part of a PAC whose correctness cannot be read
# off the code, because NDR pointer arithmetic looks right either way.
#
# Why a script and not a test: impacket is a Python package this crate does not
# depend on, and a test would either skip silently — indistinguishable from
# passing — or fail on a machine without it for reasons that are not about the code.
#
#   scripts/verify-logon-info.sh
#
# `LOGON_INFO_VENV` overrides the virtualenv; the default is created on first use.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK_REL="${LOGON_INFO_WORK:-target/logon-info}"
WORK="$ROOT/$WORK_REL"
VENV="${LOGON_INFO_VENV:-${XDG_CONFIG_HOME:-$HOME/.cache}/rust-heimdal-kdc/ad-blob-venv}"

echo "== encoding a logon info"
mkdir -p "$WORK"
"$ROOT/scripts/cargo.sh" run --quiet --example logon-info > "$WORK/logon-info.txt"

if [ ! -x "$VENV/bin/python" ]; then
    echo "   creating $VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check impacket
fi

echo "== impacket"
"$VENV/bin/python" "$ROOT/scripts/verify-logon-info.py" "$WORK/logon-info.txt"
