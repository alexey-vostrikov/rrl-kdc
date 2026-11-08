# The client side of the stand: what a machine that wants to join a domain has.
#
# Deliberately not a Rust image. The two servers are built outside it and mounted in,
# so this carries only the tools whose behaviour the check is about — Samba's `net`,
# MIT's `kinit`, dnsmasq and `ldapsearch` — and rebuilding them never invalidates the
# binaries under test.
FROM debian:bookworm-slim

# krb5-user: kinit and a real client library, so step 1 is Samba's dependency and
# not ours. samba: `net ads` is the client whose refusal this stand is built to
# provoke. winbind comes with it and is what the join actually configures. dnsmasq:
# SRV records, without which Samba finds no domain controller at all.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        krb5-user \
        samba \
        winbind \
        dnsmasq \
        ldap-utils \
        # The SASL mechanism itself: `ldapsearch -Y GSSAPI` finds no mechanism at
        # all without it, and the error names SASL rather than the missing package.
        libsasl2-modules-gssapi-mit \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Samba refuses to run a join with a default smb.conf that has no workgroup.
RUN printf '%s\n' \
    '[global]' \
    '   workgroup = AD' \
    '   realm = AD.EXAMPLE.COM' \
    '   security = ADS' \
    '   kerberos method = secrets and keytab' \
    '   dns proxy = no' \
    '   log level = 3' \
    > /etc/samba/smb.conf

# A realm that is never contacted: krb5-user's postinst wants one, and the stand
# replaces this file at startup with what the KDC wrote.
RUN printf '%s\n' \
    '[libdefaults]' \
    '   default_realm = AD.EXAMPLE.COM' \
    '   dns_lookup_realm = false' \
    '   dns_lookup_kdc = false' \
    > /etc/krb5.conf

WORKDIR /shared
