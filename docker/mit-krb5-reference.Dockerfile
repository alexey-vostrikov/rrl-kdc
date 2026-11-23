# MIT krb5 built from source, so that `kadmind` in this image really serves the admin RPC port.
#
# Why not the distribution package: `krb5-admin-server` 1.18 was measured listening on 464 only —
# that is kadmind's own kpasswd port, so the daemon runs and the *admin* listener never comes up.
# Without one there is no ground truth for what a `kadm5` reply looks like on the wire, and the
# interop failure against MIT's `kadmin` cannot be told apart from a broken reference.
#
# Why the base is `rust:1.99.1-bullseye`: it is already on this machine, and the Docker daemon here
# cannot resolve `registry-1.docker.io` (the host can), so a fresh base image cannot be pulled.
# Build it with `--network=host`.
FROM rust:1.99.1-bullseye

ENV DEBIAN_FRONTEND=noninteractive
ARG KRB5_VERSION=1.21.3

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bison \
        flex \
        perl \
        python3 \
        curl \
        ca-certificates \
        libdb-dev \
        libssl-dev \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl -fsSLO "https://kerberos.org/dist/krb5/1.21/krb5-${KRB5_VERSION}.tar.gz" \
    && tar xzf "krb5-${KRB5_VERSION}.tar.gz" \
    # The tarball keeps everything under `src/`: `krb5-1.21.3/src/configure` is the entry point, and
    # `./configure` at the top level is a "not found" that reads as a broken download.
    && cd "krb5-${KRB5_VERSION}/src" \
    && ./configure --prefix=/opt/krb5 > /tmp/configure.log 2>&1 \
    && make -j6 > /tmp/make.log 2>&1 \
    && make install > /tmp/install.log 2>&1 \
    && cd / && rm -rf /src

# Checked at build time rather than assumed: a build that produced no `kadmind` would send every
# later run down the same dead end this image exists to escape.
RUN test -x /opt/krb5/sbin/kadmind \
    && test -x /opt/krb5/sbin/krb5kdc \
    && test -x /opt/krb5/bin/kadmin \
    && test -x /opt/krb5/bin/kinit \
    && /opt/krb5/sbin/kadmind -h 2>&1 | head -3

ENV PATH=/opt/krb5/sbin:/opt/krb5/bin:$PATH

WORKDIR /w
CMD ["bash"]
