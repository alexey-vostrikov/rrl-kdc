#!/bin/sh
# Run a cargo command for this repository inside the pinned toolchain image.
#
# The host has no Rust and should not: the compiler is the image tag, which is
# the same thing CI uses (`rust:1.99.1-bookworm`), so a build that works here
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
set -eu

IMAGE="${KDC_IMAGE:-rust:1.99.1-bookworm}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CACHE="${KDC_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rust-heimdal-kdc}"

mkdir -p "$CACHE/cargo" "$CACHE/rustup" "$ROOT/target"

exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$ROOT:/w" \
  -v "$CACHE/cargo:/cargo" \
  -v "$CACHE/rustup:/rustup" \
  -e CARGO_HOME=/cargo \
  -e RUSTUP_HOME=/rustup \
  -e CARGO_TERM_COLOR=always \
  -w /w \
  "$IMAGE" \
  sh -c 'PATH=/usr/local/cargo/bin:$PATH; exec cargo "$@"' sh "$@"
