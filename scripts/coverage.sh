#!/bin/sh
# Line coverage for the crate, measured inside the same container every other
# gate uses.
#
# Why a separate script and not a `cargo` alias: `cargo-llvm-cov` has to be
# installed (a one-off, cached in the mounted CARGO_HOME) and the toolchain needs
# `llvm-tools-preview` (a one-off, cached in the mounted RUSTUP_HOME). Doing that
# inside the same `docker run` keeps the measurement in the image the tests run in,
# so a number cannot come from a different compiler.
#
# Usage:
#   scripts/coverage.sh            # print the summary
#   scripts/coverage.sh --check    # fail below COVERAGE_MIN (default 85)
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/rust-kdc"
IMAGE="${KDC_IMAGE:-rust:1.99.1-bookworm}"
# The floor is a regression alarm, not a target: coverage was 89.8% when this was
# written, and the number that matters is that it does not fall. Set below the
# current figure so an unrelated refactor is not blocked, high enough that a new
# module with no tests is.
MIN="${COVERAGE_MIN:-88}"

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

mkdir -p "$CACHE/cargo" "$CACHE/rustup"

docker run --rm -u "$(id -u):$(id -g)" \
    -v "$ROOT:/w" -v "$CACHE/cargo:/cargo" -v "$CACHE/rustup:/rustup" \
    -e CARGO_HOME=/cargo -e RUSTUP_HOME=/rustup -e CARGO_TERM_COLOR=never \
    -e COVERAGE_MIN="$MIN" -e CHECK="$CHECK" \
    -w /w "$IMAGE" sh -c '
set -eu
PATH=/usr/local/cargo/bin:$PATH

# One-off, cached in the mounted volumes.
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    rustup component add llvm-tools-preview >/dev/null
    cargo install cargo-llvm-cov --locked --quiet
fi

# `--all-features` because a line behind a feature flag that no test compiles is
# uncovered for a reason worth seeing.
cargo llvm-cov --all-features --workspace --summary-only --ignore-filename-regex "(^|/)tests/|(^|/)examples/" > /tmp/cov.txt 2>&1 || {
    cat /tmp/cov.txt
    exit 1
}
grep -vE "^\s*$" /tmp/cov.txt
total=$(grep -E "^TOTAL" /tmp/cov.txt | tail -1 || true)
lines=$(printf "%s" "$total" | awk "{print \$10}" | tr -d "%")
echo "lines covered: ${lines:-unknown}%"

if [ "$CHECK" = "1" ]; then
    awk -v min="$COVERAGE_MIN" -v got="${lines:-0}" "BEGIN { if (got+0 < min+0) { printf \"below the floor: %s%% < %s%%\n\", got, min; exit 1 } }"
fi
'
