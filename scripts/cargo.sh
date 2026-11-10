#!/bin/sh
# Run a cargo command for this repository inside the pinned toolchain image.
#
# The host has no Rust and should not: the compiler is the image tag, which is
# the same thing CI uses (`rust:1.99.1-bullseye`), so a build that works here
# works there and a version drift is impossible rather than unlikely.
#
# Usage:
#   scripts/cargo.sh test
#   scripts/cargo.sh clippy --all-targets --features crypto-rskrb5 -- -D warnings
#
# Two details that are load-bearing:
#
# * `-u $(id -u):$(id -g)` — without it the container writes `target/` as root
#   and the next run on the host cannot clean it up.
# * `CARGO_HOME` and `RUSTUP_HOME` inside a writable mount — the image's homes
#   are root-owned, and a user cannot write the registry cache into them.
# * `CARGO_TARGET_DIR` keyed by the image tag. Cargo decides what to rebuild from
#   timestamps, not from libc: switching the base from bookworm to bullseye reuses
#   objects linked against glibc 2.36 and produces binaries that die on the stand
#   with "version `GLIBC_2.34' not found" — or, worse, a green test run against a
#   binary the repository does not build. A separate directory per image makes the
#   two bases unable to see each other's work.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CACHE="${KDC_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rust-kdc}"
. "$ROOT/scripts/image.sh"

# `CARGO_HOME` per image tag as well as `CARGO_TARGET_DIR`. A shared home mixes
# `$CARGO_HOME/bin` between bases, and cargo resolves a subcommand through that directory
# first: a `cargo-llvm-cov` installed on bookworm shadows the image's own and dies on bullseye
# with "version `GLIBC_2.34' not found". The registry cache costs a second download once.
mkdir -p "$CACHE/rustup" "$ROOT/target"
ensure_cargo_home
ensure_image

exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$ROOT:/w" \
  -v "$CARGO_HOME_SRC:/cargo" \
  -v "$CACHE/rustup:/rustup" \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR=/w/target/$TAG \
  -e RUSTUP_HOME=/rustup \
  -e CARGO_TERM_COLOR=always \
  -w /w \
  "$IMAGE" \
  sh -c 'PATH=/usr/local/cargo/bin:$PATH; exec cargo "$@"' sh "$@"
