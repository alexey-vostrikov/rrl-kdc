#!/bin/bash
# bash, not sh: the port check below uses /dev/tcp, which dash does not have.
# One stand, one question: at which step does a stock Samba refuse to join a realm
# whose KDC is this crate's and whose directory is rust-rest-ldap?
#
# The script does not try to make the join succeed. It runs the four things a join
# does, in order, and stops at the first one that fails, printing the raw error. The
# value of the exercise is that failing step, not a green run: every assumption
# about what "AD mode" needs is either confirmed here or shown to be wrong by a
# message from Samba itself.
#
#   ./stand.sh            # all four steps
#   ./stand.sh kinit      # one step, for iterating
set -u
# A pipeline reports the status of its last command, so `net ads join | tail` reported
# `tail`'s success and the script announced a join that had failed. That is the same
# class of mistake as a test that passes because it asserts nothing.
set -o pipefail

REALM="${REALM:-AD.EXAMPLE.COM}"
DOMAIN="${DOMAIN:-ad.example.com}"
HOST="${HOST:-samba.${DOMAIN}}"
NETBIOS="${NETBIOS:-AD}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin-Password-1}"
BASE_DN="${BASE_DN:-dc=ad,dc=example,dc=com}"

export KRB5_CONFIG=/shared/krb5.conf
export KRB5_KTNAME=/shared/service.keytab
export KRB5CCNAME=FILE:/tmp/krb5cc_stand

say() { printf '\n== %s\n' "$*"; }
fail() {
    printf 'FAIL at %s\n' "$*" >&2
    exit 1
}

wait_for_port() {
    # Up to 10 seconds: the servers are threads inside two processes, and a stand
    # that sleeps a fixed second either wastes time or races.
    host=$1
    port=$2
    i=0
    while [ "$i" -lt 100 ]; do
        if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
            exec 3<&- 2>/dev/null
            return 0
        fi
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

bootstrap() {
    say "starting dnsmasq, kdc-stand, rust-rest-ldap"

    # DNS: Samba finds a domain controller only through SRV records, and it will not
    # fall back to anything else. `_ldap._tcp.dc._msdcs` is the one it asks first.
    cat >/etc/dnsmasq.conf <<EOF
port=53
no-resolv
no-hosts
log-queries
address=/${DOMAIN}/127.0.0.1
address=/${REALM}/127.0.0.1
srv-host=_ldap._tcp.${DOMAIN},${HOST},389,0,100
srv-host=_kerberos._tcp.${DOMAIN},${HOST},88,0,100
srv-host=_kerberos._udp.${DOMAIN},${HOST},88,0,100
srv-host=_kpasswd._udp.${DOMAIN},${HOST},464,0,100
srv-host=_ldap._tcp.dc._msdcs.${DOMAIN},${HOST},389,0,100
srv-host=_kerberos._tcp.dc._msdcs.${DOMAIN},${HOST},88,0,100
EOF
    printf '127.0.0.1 localhost\n127.0.0.1 %s %s\n' "$HOST" "$DOMAIN" >/etc/hosts.stand
    cat /etc/hosts.stand >>/etc/hosts
    printf 'nameserver 127.0.0.1\nsearch %s\n' "$DOMAIN" >/etc/resolv.conf
    dnsmasq --conf-file=/etc/dnsmasq.conf || fail "dnsmasq"

    KDC_REALM="$REALM" KDC_HOST="$HOST" \
        KDC_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
        kdc-stand 0.0.0.0:88 /shared >/tmp/kdc.log 2>&1 &
    wait_for_port 127.0.0.1 88 || {
        cat /tmp/kdc.log
        fail "the KDC did not start"
    }

    rust-rest-ldap --config /shared/rrd.yaml >/tmp/rrd.log 2>&1 &
    wait_for_port 127.0.0.1 389 || {
        cat /tmp/rrd.log
        fail "the directory did not start"
    }
    sleep 1
}

step_kinit() {
    say "1. kinit administrator: does the KDC issue a TGT at all"
    if ! kinit -V "administrator@${REALM}" <<EOF
${ADMIN_PASSWORD}
EOF
    then
        cat /tmp/kdc.log
        fail "kinit (the KDC did not issue a TGT)"
    fi
    klist || fail "klist after a successful kinit"
}

step_ldap() {
    say "2. SASL GSSAPI bind: does the directory accept the ticket"
    # The directory does not implement the SASL security layer — its own
    # documentation says TLS is where the encryption belongs — so the client has to
    # ask for none. Which spelling a given OpenLDAP accepts varies, and the wrong one
    # produces a complaint about an unwrapped Wrap token that reads like a server
    # bug, so all three are tried and the one that works is reported.
    attempt=""
    for opt in "-O maxssf=0" "-O none" "-O minssf=0,maxssf=0" ""; do
        # shellcheck disable=SC2086
        if out=$(ldapsearch -H ldap://127.0.0.1:389 -Y GSSAPI $opt -b "$BASE_DN" -s base dn 2>&1); then
            attempt="$opt"
            printf '%s\n' "$out" | tail -6
            printf 'accepted with: ldapsearch -Y GSSAPI %s\n' "${opt:-(no option)}"
            return 0
        fi
        printf 'rejected with %s: %s\n' "${opt:-(no option)}" "$(printf '%s' "$out" | tail -1)"
    done
    echo "no spelling worked" >&2
    cat /tmp/rrd.log
    fail "ldapsearch -Y GSSAPI"
}

step_discovery() {
    say "3. net ads info: can Samba find a domain controller over DNS and CLDAP"
    if ! net ads info -S "$HOST" 2>&1 | tail -20; then
        fail "net ads info (DC discovery)"
    fi
}

step_join() {
    say "4. net ads join: the step this stand exists for"
    # `-k` uses the ticket from step 1 rather than a password prompt, which is what
    # a machine image does; the account is created by Samba in the directory.
    # The output is captured rather than piped, so the exit status is `net`'s and not
    # `tail`'s — the difference between reporting a join and reporting a print.
    status=0
    out=$(net ads join -k -S "$HOST" 2>&1) || status=$?
    if [ "$status" -eq 0 ]; then
        printf '%s\n' "$out" | tail -20
        printf '\nJOIN SUCCEEDED\n'
        net ads testjoin 2>&1 | tail -5 || true
    else
        printf '%s\n' "$out" | tail -20
        printf '\nJOIN FAILED (exit %s), last line above\n' "$status"
        exit 1
    fi
}

bootstrap

case "${1:-all}" in
kinit) step_kinit ;;
# Every step after the first needs a ticket, and a step that skipped kinit would
# fail with "no Kerberos credentials" — its own fault, not the server's.
ldap) step_kinit && step_ldap ;;
discovery) step_kinit && step_discovery ;;
join) step_kinit && step_join ;;
all)
    step_kinit
    step_ldap
    step_discovery
    step_join
    ;;
*)
    echo "unknown step: $1" >&2
    exit 2
    ;;
esac
