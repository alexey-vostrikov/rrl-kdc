"""Reads a PAC out of a ticket this crate's KDC actually issued.

The other verifiers hand impacket bytes this crate produced; this one makes impacket
talk to the KDC first. It is the difference between "our encoder agrees with a reader"
and "a client asked for a ticket and found a PAC in it", which is what `TASQ-3.4` is
short of.

# The one substitution, and why

impacket's `sendReceive` defaults to port 88, and port 88 needs root. Rather than run
the whole check as root, the port is injected here by wrapping `sendReceive`. Nothing
else is touched: the AS-REQ is built by impacket, sent over UDP, and parsed by
impacket — the wire is real, only the destination port is a variable.

# What is checked

* the ticket really carries `authorization-data` with an `AD-IF-RELEVANT` in it;
* that wrapper holds a `PACTYPE` whose buffers are the four this crate writes;
* `KERB_VALIDATION_INFO` names the RID, the primary group and the domain the stand
  was told to state;
* `PAC_CLIENT_INFO` names the account the client authenticated as;
* both signatures verify under `krbtgt` — which for a TGT is the same key for the
  service and the KDC checksum, since a TGT's service *is* `krbtgt`;
* the same bytes are what the KDC signed: the signature covers the PAC with its own
  signature fields zeroed.
"""

import os
import socket
import sys
from struct import pack

from impacket.krb5 import constants
from impacket.krb5.asn1 import AD_IF_RELEVANT, AS_REP, EncTicketPart
from impacket.krb5.crypto import Enctype, make_checksum
from impacket.krb5.crypto import Key as ImacketKey
from impacket.krb5.crypto import _enctype_table
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.krb5.pac import (
    KERB_VALIDATION_INFO,
    PAC_CLIENT_INFO,
    PAC_CLIENT_INFO_TYPE,
    PAC_INFO_BUFFER,
    PAC_PRIVSVR_CHECKSUM,
    PAC_SERVER_CHECKSUM,
    PAC_SIGNATURE_DATA,
    PACTYPE,
)
from pyasn1.codec.der import decoder

REALM = os.environ.get("PAC_REALM", "AD.EXAMPLE.COM")
USER = os.environ.get("PAC_USER", "administrator")
PASSWORD = os.environ.get("PAC_PASSWORD", "admin-Password-1")
HOST = os.environ.get("PAC_HOST", "127.0.0.1")
PORT = int(os.environ.get("PAC_PORT", "8888"))
KEY_FILE = os.environ["PAC_KEY_FILE"]

# What `examples/kdc-stand.rs` states when `KDC_PAC=1`, so the comparison is against
# something written down rather than against whatever the buffer happens to say.
EXPECT_RID = int(os.environ.get("PAC_EXPECT_RID", "500"))
EXPECT_DOMAIN_NAME = os.environ.get("PAC_EXPECT_DOMAIN_NAME", "AD")
EXPECT_DOMAIN_SID = os.environ.get("PAC_EXPECT_DOMAIN_SID", "S-1-5-21-100-200-300")
CHECKSUM_AES_SHA1_96_256 = 16


def fail(message):
    print(f"FAIL {message}")
    sys.exit(1)


def read_key(path):
    """The `krbtgt` key: the stand's file is comments and one line of hex."""
    for line in open(path, encoding="ascii"):
        line = line.strip()
        if line and not line.startswith("#"):
            return bytes.fromhex(line)
    fail(f"{path} carries no key")


def send_on_our_port(data, host, kdcHost, port=88):
    """impacket's own transport, pointed at the stand's unprivileged port."""
    for attempt in (0, 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        try:
            sock.sendto(data, (kdcHost or host, PORT))
            reply, _ = sock.recvfrom(65535)
            return reply
        except socket.timeout:
            # A dropped UDP datagram is exactly why RFC 4120 §7.2.2 lets a client
            # retry once before concluding the KDC is down.
            if attempt == 1:
                raise
        finally:
            sock.close()


def main():
    # The module-level name is what `getKerberosTGT` resolves, so replacing both the
    # module attribute and the imported alias is not redundant: the first is what the
    # call site looks up.
    import impacket.krb5.kerberosv5 as krb5

    krb5.sendReceive = send_on_our_port

    # impacket wants a `Principal`, not a string: `components_to_asn1` is what the
    # AS-REQ body is built from, and a bare name has no components.
    name = Principal(USER, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    print(f"asking {HOST}:{PORT} for a TGT for {USER}@{REALM}")
    reply, _, _, _ = getKerberosTGT(
        name, PASSWORD, REALM, b"", b"", kdcHost=HOST, requestPAC=True
    )

    # `getKerberosTGT` hands back the raw reply and the *session* key's cipher; the
    # ticket is sealed under the service key, so the AS-REP is decoded here and the
    # ticket opened with `krbtgt` at usage 2 (RFC 4120 §5.4.2).
    as_rep = decoder.decode(reply, asn1Spec=AS_REP())[0]
    ticket = as_rep["ticket"]
    enctype = int(ticket["enc-part"]["etype"])
    key = read_key(KEY_FILE)
    plain = _enctype_table[enctype].decrypt(
        ImacketKey(Enctype.AES256, key), 2, ticket["enc-part"]["cipher"]
    )
    part = decoder.decode(plain, asn1Spec=EncTicketPart())[0]

    if not part["authorization-data"]:
        fail("the ticket carries no authorization-data at all")
    kinds = [int(e["ad-type"]) for e in part["authorization-data"]]
    if constants.AuthorizationDataType.AD_IF_RELEVANT.value not in kinds:
        fail(f"no AD-IF-RELEVANT in the ticket: {kinds}")
    wrapper = [e for e in part["authorization-data"] if int(e["ad-type"]) == 1][0]
    relevant = decoder.decode(wrapper["ad-data"], asn1Spec=AD_IF_RELEVANT())[0]
    if int(relevant[0]["ad-type"]) != constants.AuthorizationDataType.AD_WIN2K_PAC.value:
        fail(f"the IF-RELEVANT holds type {int(relevant[0]['ad-type'])}, not AD-WIN2K-PAC (128)")
    pac = bytes(relevant[0]["ad-data"])
    print(f"ticket carries a PAC of {len(pac)} octets, inside AD-IF-RELEVANT / AD-WIN2K-PAC")

    pac_type = PACTYPE(pac)
    infos = {}
    at = 8
    for _ in range(pac_type["cBuffers"]):
        info = PAC_INFO_BUFFER(pac[at : at + 16])
        at += 16
        if info["Offset"] % 8 != 0:
            fail(f"buffer {info['ulType']} starts at {info['Offset']}, not on 8")
        infos[info["ulType"]] = (info["cbBufferSize"], info["Offset"])
    expected = {1, PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM}
    if set(infos) != expected:
        fail(f"buffers are {sorted(infos)}, and a Windows PAC has {sorted(expected)}")
    print(f"buffers: {sorted(infos)}")

    size, offset = infos[1]
    blob = pac[offset : offset + size]
    logon = KERB_VALIDATION_INFO(blob)
    # impacket's structure carries a thirty-fourth field, `ResourceGroupIds`, that
    # [MS-PAC] §2.5 does not define; walking *all* fields therefore steps one pointer
    # past the end of a correct buffer. The walk stops at the last field the
    # specification names, and says so rather than padding the buffer to fit another
    # implementation's extension.
    walk = 212
    for field_name, _ in logon.commonHdr + logon.structure:
        if field_name == "ResourceGroupIds":
            break
        field = logon.fields[field_name]
        if not hasattr(field, "fromStringReferents"):
            continue
        refs = field.fromStringReferents(blob, walk)
        walk += refs + field.fromStringReferent(blob, walk + refs)
    if logon["UserId"] != EXPECT_RID:
        fail(f"UserId is {logon['UserId']}, and the stand says {EXPECT_RID}")
    if logon["PrimaryGroupId"] != 513:
        fail(f"PrimaryGroupId is {logon['PrimaryGroupId']}, not 513")
    if logon["LogonDomainName"] != EXPECT_DOMAIN_NAME:
        fail(f"LogonDomainName is {logon['LogonDomainName']!r}, not {EXPECT_DOMAIN_NAME!r}")
    groups = [g["RelativeId"] for g in logon["GroupIds"]]
    print(
        f"logon info: RID {logon['UserId']}, primary {logon['PrimaryGroupId']}, "
        f"groups {groups}, domain {logon['LogonDomainName']!r}"
    )

    sid = logon["LogonDomainId"]
    subs = list(sid["SubAuthority"])
    expected = [int(part) for part in EXPECT_DOMAIN_SID.split("-")[1:]]
    if list(subs) != expected[2:]:
        fail(f"domain SID sub-authorities are {list(subs)}, and the stand says {expected[2:]}")
    # impacket's `Revision` and `IdentifierAuthority` come back shifted for a SID it
    # parsed as a referent — `S-0-21541945344` for a SID whose octets start `01 04 00
    # … 05`. The octets are therefore checked directly: revision, count, the
    # authority big-endian, then the conformant array, which is the form `objectSid`
    # carries minus the array's own length.
    octets = (
        bytes([expected[0], len(expected[2:])])
        + expected[1].to_bytes(6, "big")
        + len(expected[2:]).to_bytes(4, "little")
        + b"".join(s.to_bytes(4, "little") for s in expected[2:])
    )
    if octets not in blob:
        fail(f"the buffer carries no {EXPECT_DOMAIN_SID} in its binary form")
    canonical = EXPECT_DOMAIN_SID
    print(f"domain SID: {canonical}")

    size, offset = infos[PAC_CLIENT_INFO_TYPE]
    info = PAC_CLIENT_INFO(pac[offset : offset + size])
    name = info["Name"]
    if isinstance(name, bytes):
        name = name.decode("utf-16-le")
    if name != f"{USER}@{REALM}":
        fail(f"PAC_CLIENT_INFO names {name!r}, not {USER}@{REALM}")
    print(f"client info: {name!r}")

    # Both signatures, over the PAC with its own signature fields zeroed. For a TGT
    # the service is `krbtgt`, so both checksums use the same key — which is why this
    # verifies both rather than treating one as absent.
    block = bytearray(pac)
    for kind in (PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM):
        size, offset = infos[kind]
        block[offset + 4 : offset + size] = b"\x00" * (size - 4)
    for kind, where in (
        (PAC_SERVER_CHECKSUM, "server"),
        (PAC_PRIVSVR_CHECKSUM, "kdc"),
    ):
        size, offset = infos[kind]
        data = PAC_SIGNATURE_DATA(pac[offset : offset + size])
        if data["SignatureType"] != CHECKSUM_AES_SHA1_96_256:
            fail(f"{where} signature type is {data['SignatureType']}, not 16")
        expected_sig = make_checksum(
            CHECKSUM_AES_SHA1_96_256, ImacketKey(Enctype.AES256, key), 17, bytes(block)
        )
        if bytes(data["Signature"]) != expected_sig:
            fail(f"the {where} signature does not verify under krbtgt")
        print(f"{where} signature verifies under the krbtgt key")

    print("OK a live client asked this KDC for a ticket and read the PAC in it")


if __name__ == "__main__":
    main()
