#!/bin/sh
# Generates `supplementalCredentials` blobs with this crate and reads them back
# with impacket, which is somebody else's implementation of [MS-SAMR] §2.2.10.
#
# Why a script and not a test: the check needs Python and a PyPI package this crate
# does not depend on. A test would either skip silently — which is indistinguishable
# from passing — or fail on a machine without impacket for a reason that has nothing
# to do with the code. A script that says what it is missing is honest about the
# boundary.
#
#   scripts/verify-ad-blob.sh
#
# `AD_BLOB_VENV` overrides the virtualenv; the default is created on first use.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# A path relative to the tree, because the generator runs in the build container
# where the tree is mounted at /w: an absolute host path means nothing there, and the
# container's own /tmp is not where the host can read the result.
WORK_REL="${AD_BLOB_WORK:-target/ad-blob}"
WORK="$ROOT/$WORK_REL"
VENV="${AD_BLOB_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/rust-heimdal-kdc/ad-blob-venv}"

echo "== writing blobs"
"$ROOT/scripts/cargo.sh" run --quiet --example ad-blob --features hdb-ldap -- "$WORK_REL"

echo "== impacket"
# The generator ran in the container as the build user, so the files are already
# this user's; nothing to copy out.

if [ ! -x "$VENV/bin/python" ]; then
    echo "   creating $VENV"
    python3 -m venv "$VENV"
    "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check impacket
fi

"$VENV/bin/python" "$ROOT/scripts/verify-ad-blob.py" "$WORK"
