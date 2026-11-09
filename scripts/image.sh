#!/bin/sh
# The one place that says where the toolchain image comes from.
#
# Meant to be sourced by `cargo.sh`, `coverage.sh` and `mutate.sh` after each has computed
# `ROOT`; it sets `IMAGE` and `TAG` and defines `ensure_image`.
#
# Why an image built from `docker/toolchain.Dockerfile` rather than a tag: `rust:1.99.1-bullseye`
# is not published. The official project stopped shipping bullseye variants after 1.90, and the
# tag that does exist, `rust:1.99.1-bookworm`, links against glibc 2.36 — a binary built there
# will not start on the Debian 11 and Astra stands this KDC targets, which ship glibc 2.31. The
# base of the image is therefore part of what the repository says about itself, and it lives in
# a file that a reviewer can diff.
#
# Building it on demand rather than refusing: every gate would otherwise start with "pull an
# image that is not on the hub", and a contributor's first command would be a message about a
# missing tag. The build is printed, not silent, so nobody mistakes it for a cached image.
#
# Taken from the sibling `rust-smb-server` project, where the same problem was solved once for
# the same reason and the ub-mode measurement tools (`cargo-crap`, `cargo-dupes`) were added to
# the image: measurement and build must share one compiler, or the numbers mean nothing.

IMAGE="${KDC_IMAGE:-rust:1.99.1-bullseye}"
# `rust:1.99.1-bullseye` -> `bullseye`, for the per-image cache and target directories.
TAG=$(printf '%s' "$IMAGE" | sed 's/.*://')

# Where `$CARGO_HOME` lives. Either a directory on the host, or a docker volume — the sibling
# projects keep their registries in volumes (`rrl-cargo-bullseye`), and re-downloading the whole
# registry per project is minutes of network for bytes that are already on the disk.
#
# A volume rather than a path matters because `-v` treats a bare name and an absolute path the
# same way; only the caller knows which one was meant, so it is named explicitly.
CARGO_HOME_SRC="${KDC_CARGO_VOLUME:-$CACHE/cargo-$TAG}"

ensure_cargo_home() {
    if [ -z "${KDC_CARGO_VOLUME:-}" ]; then
        mkdir -p "$CARGO_HOME_SRC"
    fi
}

ensure_image() {
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        return 0
    fi
    echo "building $IMAGE from docker/toolchain.Dockerfile (first run only)" >&2
    docker build -t "$IMAGE" -f "$ROOT/docker/toolchain.Dockerfile" "$ROOT" >&2 || {
        echo "could not build $IMAGE; the gates cannot run without it" >&2
        exit 1
    }
}
