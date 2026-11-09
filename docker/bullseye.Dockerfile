# The toolchain image this repository builds and tests in: Rust 1.99.1 on Debian 11 (bullseye).
#
# Why a local image rather than a tag. `rust:1.99.1-bullseye` does not exist: the official
# project stopped publishing bullseye variants after 1.90, and the tag that *does* exist,
# `rust:1.99.1-bookworm`, carries glibc 2.36. A binary linked there will not start on the
# stands this KDC is meant to run on — Debian 11 and Astra Linux both ship glibc 2.31 — so
# the image has to be assembled, and assembling it by hand on one machine and calling it a
# tag is how a build starts depending on somebody's laptop.
#
# The assembly is the one already used for the provider projects: the toolchain is *copied*
# out of the official slim-bookworm image rather than installed with rustup. Official Rust
# builds link against glibc 2.17, so a bullseye base runs them unchanged, and the libc that
# ends up in our binaries comes from the base — 2.31. Copying also avoids pulling ~200 MB
# from static.rust-lang.org on a network where that has stalled for tens of minutes.
#
# `scripts/cargo.sh` builds this file when the image is absent, so a fresh checkout either
# has the toolchain or says why it does not; it never silently falls back to another base,
# because a green build on the wrong glibc is worse than a red one.
FROM rust:1.99.1-slim-bookworm AS toolchain

# The official slim image ships `cargo` and `rustc` and nothing else; `rustfmt` and `clippy`
# are rustup components and have to be named. They are added **here**, in the bookworm stage,
# because the component tarballs are what get copied — they are libc-agnostic, while the
# `cargo-llvm-cov` *binary* built here would not be, which is why that one is built later.
RUN rustup component add rustfmt clippy

FROM rust:1.90-bullseye

ARG RUST_TOOLCHAIN=1.99.1

# The rustup and cargo trees from the bookworm stage: 1.99.1 becomes the default toolchain,
# and the 1.90 that ships with the base is shadowed rather than removed — the base's own
# `/usr/local/bin/cargo` is a symlink into that tree, which is why both directories come over
# whole instead of file by file.
COPY --from=toolchain /usr/local/rustup /usr/local/rustup
COPY --from=toolchain /usr/local/cargo /usr/local/cargo
ENV RUSTUP_TOOLCHAIN=${RUST_TOOLCHAIN} \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Bullseye left LTS and moved to the archive: `deb.debian.org/debian-security` answers 404
# for its own package versions and every `apt-get install` fails with code 100. The archive
# works but is signed with an expired date, hence `Check-Valid-Until=false`.
RUN printf '%s\n' \
      'deb http://archive.debian.org/debian bullseye main' \
      'deb http://archive.debian.org/debian-security bullseye-security main' \
      > /etc/apt/sources.list

# `build-essential` for the link step, `pkg-config` for the TLS and SQLite crates behind
# optional features, `python3` for the impacket and MIT verification scripts.
RUN apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config ca-certificates curl git python3 \
 && rm -rf /var/lib/apt/lists/*

# `cargo-llvm-cov` is built **here**, not copied from the bookworm stage: the published
# binary and the one built there need glibc 2.34 and die on bullseye with
# "version `GLIBC_2.34' not found". The version is pinned so that a coverage figure does not
# move because somebody else published a release.
RUN cargo install cargo-llvm-cov --locked --version 0.6.18 \
 && cargo llvm-cov --version

# The mutator. Basis-provider's measurement image uses unclebob's `mutator`, which needs
# python >= 3.11 — bullseye ships 3.9, so it lives in a separate bookworm image there. That
# image measures a *different* compiler's build than the one shipped, which is the one thing
# basis itself says must not differ between a build and a measurement. `cargo-mutants` is a
# Rust binary and runs on the same toolchain, so measurement and build stay one image and one
# compiler. Pinned, so a kill count does not move because somebody published a release.
RUN cargo install cargo-mutants --locked --version 27.1.0 \
 && cargo mutants --version

# The gates assert their tools exist rather than discovering at report time that `rustfmt`
# was missing and the check silently did nothing.
RUN rustc --version && cargo --version && rustfmt --version && cargo clippy --version
