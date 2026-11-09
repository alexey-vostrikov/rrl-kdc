#!/bin/sh
# Mutation testing for this crate, run inside the same image every other gate uses.
#
# Why `cargo-mutants` and not the mutator the provider projects use: unclebob's `mutator`
# needs python >= 3.11, and bullseye ships 3.9, so that project keeps a second, bookworm-based
# measurement image. Its own notes say why that is a compromise — "the toolchain must be the
# same, otherwise the measurement and the build compile the code with different compilers, and
# the kill count depends on the image". `cargo-mutants` is a Rust binary and runs on the same
# 1.99.1-on-bullseye toolchain that builds the crate, so a mutation is measured against the
# compiler and libc that ship.
#
# Usage:
#   scripts/mutate.sh                      # the whole crate (slow: one build per mutant)
#   scripts/mutate.sh --file src/kdc/fast.rs
#   scripts/mutate.sh --in-place --file src/kdc/pkinit/reply.rs --baseline=ignore
#
# The target directory is per-image **and separate from the one `cargo.sh` uses**. Cargo decides
# what to rebuild by timestamp, and `cargo-mutants` builds mutated sources into
# `CARGO_TARGET_DIR`: sharing it means a `cargo test` run beside a measurement picks up a test
# binary compiled from a mutated file, and the failure looks like a regression in the code just
# written. Observed exactly that — a test that had passed for months failed with `left: [1]`
# until the source was touched. Two directories make the two unable to see each other's work.
#
# `mutants.out/` is the first place to look when a mutant is reported killed but no test ran;
# it must not be deleted while a run is in flight, because the run appends its per-mutant logs
# there and dies with `reopen … for append`.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/rust-kdc"
. "$ROOT/scripts/image.sh"

mkdir -p "$CACHE/rustup" "$ROOT/target"
ensure_cargo_home
ensure_image

exec docker run --rm -u "$(id -u):$(id -g)" \
    -v "$ROOT:/w" -v "$CARGO_HOME_SRC:/cargo" -v "$CACHE/rustup:/rustup" \
    -e CARGO_HOME=/cargo -e RUSTUP_HOME=/rustup -e CARGO_TERM_COLOR=always \
    -e CARGO_TARGET_DIR=/w/target/$TAG-mutants -e TIMEOUT="${KDC_MUTANT_TIMEOUT:-120}" \
    -e JOBS="${KDC_MUTANT_JOBS:-}" \
    -w /w "$IMAGE" \
    sh -c 'PATH=/usr/local/cargo/bin:$PATH
if [ -n "$JOBS" ]; then exec cargo mutants --timeout "$TIMEOUT" --jobs "$JOBS" "$@"; fi
exec cargo mutants --timeout "$TIMEOUT" "$@"' sh "$@"
