#!/bin/sh
# ub-mode measurement, in the order the methodology requires: coverage, then CRAP over that
# coverage, then duplicates. Mutations last and separately — they need the coverage file too.
#
# Why one script: the three numbers are only comparable when taken from the same tree with the
# same compiler, and running them by hand invites the classic mistake — CRAP over a stale or
# missing lcov, which does not fail, it silently scores every function at 0% coverage and
# produces a plausible, wildly inflated report.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/rrl-kdc"
. "$ROOT/scripts/image.sh"

mkdir -p "$CACHE/rustup" "$ROOT/target/ub"
ensure_cargo_home
ensure_image

docker run --rm -u "$(id -u):$(id -g)" \
    -v "$ROOT:/w" -v "$CARGO_HOME_SRC:/cargo" -v "$CACHE/rustup:/rustup" \
    -e CARGO_HOME=/cargo -e RUSTUP_HOME=/rustup -e CARGO_TERM_COLOR=never \
    -e CARGO_TARGET_DIR=/w/target/$TAG-metrics \
    -w /w "$IMAGE" sh -c '
set -eu
PATH=/usr/local/cargo/bin:$PATH

# `--no-cfg-coverage` is not optional: without it llvm-cov compiles with `--cfg coverage`, and a
# dependency that gates a nightly feature on that cfg fails the whole build on stable.
mkdir -p /w/target/coverage/rust
cargo llvm-cov --lcov --no-cfg-coverage --all-features --workspace \
    --ignore-filename-regex "(^|/)tests/|(^|/)examples/" \
    --output-path /w/target/coverage/rust/lcov.info.long --no-fail-fast >/w/target/ub/cov.log 2>&1

# Paths are rewritten once, before anything reads the file: the tools expect paths from the
# project root, and a leftover `/w/` prefix makes a mutator report every site as uncovered.
sed "s|^SF:/w/|SF:|" /w/target/coverage/rust/lcov.info.long > /w/target/coverage/rust/lcov.info
rm -f /w/target/coverage/rust/lcov.info.long

cargo crap --lcov /w/target/coverage/rust/lcov.info --path /w > /w/target/ub/crap.txt 2>&1 || true
cargo dupes report > /w/target/ub/dupes.txt 2>&1 || true
cargo dupes stats > /w/target/ub/dupes-stats.txt 2>&1 || true
'
echo "written: target/ub/{cov.log,crap.txt,dupes.txt,dupes-stats.txt}"
