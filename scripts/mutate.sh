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
# The output directory is per-image, like `target/`, and `.cargo/mutants/` is the first place
# to look when a mutant is reported killed but the test never ran.
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
    -e CARGO_TARGET_DIR=/w/target/$TAG -e TIMEOUT="${KDC_MUTANT_TIMEOUT:-120}" \
    -w /w "$IMAGE" \
    sh -c 'PATH=/usr/local/cargo/bin:$PATH; exec cargo mutants --timeout "$TIMEOUT" "$@"' sh "$@"
