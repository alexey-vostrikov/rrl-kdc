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
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/rrl-kdc"
. "$ROOT/scripts/image.sh"
# The floor is a regression alarm, not a target: coverage was 89.8% when this was
# written, and the number that matters is that it does not fall. Set below the
# current figure so an unrelated refactor is not blocked, high enough that a new
# module with no tests is.
MIN="${COVERAGE_MIN:-88}"

CHECK=0
CRAP=0
case "${1:-}" in
--check) CHECK=1 ;;
--crap) CRAP=1 ;;
esac

mkdir -p "$CACHE/rustup" "$CACHE/coverage"
ensure_cargo_home
ensure_image


docker run --rm -u "$(id -u):$(id -g)" \
    -v "$ROOT:/w" -v "$CARGO_HOME_SRC:/cargo" -v "$CACHE/rustup:/rustup" \
    -v "$CACHE/coverage:/coverage" \
    -e CARGO_HOME=/cargo -e RUSTUP_HOME=/rustup -e CARGO_TERM_COLOR=never \
    -e COVERAGE_MIN="$MIN" -e CHECK="$CHECK" -e CARGO_TARGET_DIR=/w/target/$TAG \
    -w /w "$IMAGE" sh -c '
set -eu
PATH=/usr/local/cargo/bin:$PATH

# The tool comes from the image and never from the mounted CARGO_HOME.
#
# Installing it here was a trap: `/cargo/bin` is shared between image tags, cargo resolves a
# subcommand through `$CARGO_HOME/bin` first, and a `cargo-llvm-cov` left there by a bookworm
# run dies on bullseye with "version GLIBC_2.34 not found". The same trap is written up in
# the provider projects, where it cost a build. Missing means the image is wrong, which is a
# failure worth seeing at once rather than a silent `cargo install` of a binary the base
# cannot run.
command -v cargo-llvm-cov >/dev/null 2>&1 || {
    echo "cargo-llvm-cov is missing from $IMAGE; it is installed by docker/toolchain.Dockerfile" >&2
    exit 1
}

# `--all-features` because a line behind a feature flag that no test compiles is
# uncovered for a reason worth seeing.
# The LCOV is what CRAP needs: coverage and complexity have to come from the same run, or the
# report attributes uncovered lines to functions that have moved since the LCOV was written.
# `report` re-renders from the profraw the run just left behind, so the table below costs nothing
# extra; writing the LCOV does not cost a second test run either.
cargo llvm-cov --all-features --workspace --lcov --output-path /coverage/lcov.info > /tmp/cov.txt 2>&1 || {
    cat /tmp/cov.txt
    exit 1
}
cargo llvm-cov report --summary-only --ignore-filename-regex "(^|/)tests/|(^|/)examples/" > /tmp/cov.txt 2>&1 || {
    cat /tmp/cov.txt
    exit 1
}
grep -vE "^\s*$" /tmp/cov.txt
total=$(grep -E "^TOTAL" /tmp/cov.txt | tail -1 || true)
lines=$(printf "%s" "$total" | awk "{print \$10}" | tr -d "%")
echo "lines covered: ${lines:-unknown}%"
echo "lcov: /coverage/lcov.info"

if [ "$CHECK" = "1" ]; then
    awk -v min="$COVERAGE_MIN" -v got="${lines:-0}" "BEGIN { if (got+0 < min+0) { printf \"below the floor: %s%% < %s%%\n\", got, min; exit 1 } }"
fi
'

# CRAP over the LCOV the run above just wrote. Not part of the default run: hundreds of functions
# sit above the threshold, and a wall of findings on every coverage check is a wall nobody reads.
# The floor above is the regression alarm; this is the report you read when you decide what to fix.
if [ "$CRAP" = "1" ]; then
    docker run --rm -u "$(id -u):$(id -g)" \
        -v "$ROOT:/w" -w /w -v "$CACHE/coverage:/coverage" -v "$CARGO_HOME_SRC:/cargo" \
        -e CARGO_HOME=/cargo -e CARGO_TERM_COLOR=never "$IMAGE" \
        sh -c 'PATH=/usr/local/cargo/bin:$PATH; cargo crap --lcov /coverage/lcov.info --threshold 10 || true'
fi
