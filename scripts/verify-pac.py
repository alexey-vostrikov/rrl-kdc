"""Verifies this crate's PAC with impacket, somebody else's [MS-PAC] reader.

Two independent claims, both of which a self-test cannot make:

1. impacket's `PACTYPE` / `PAC_INFO_BUFFER` parse the envelope this crate writes —
   the buffer count, the sizes, and the offsets that point into the buffer.
2. Both signatures recompute to the bytes written, under their own keys. The
   recomputation is impacket's `make_checksum`, whose AES-SHA1 profile derives the
   checksum key with the RFC 3961 simplification and HMACs the whole PAC — code
   this crate never calls.

A third thing is asserted because it is the point of the whole module: the server
signature verifies under the *service* key and the private one under the `krbtgt`
key, and neither verifies under the other. A PAC where both were computed with one
key would pass a naive check and be worth nothing.

The keys are the ones `examples/pac-blob.rs` uses: 0x07 for the service, 0x09 for
the KDC.
"""

import sys

from impacket.krb5 import crypto
from impacket.krb5.crypto import Enctype as E
from impacket.krb5.pac import (
    PAC_INFO_BUFFER,
    PAC_PRIVSVR_CHECKSUM,
    PAC_SERVER_CHECKSUM,
    PAC_SIGNATURE_DATA,
    PACTYPE,
)

SERVER_KEY = b"\x07" * 32
KDC_KEY = b"\x09" * 32
CHECKSUM_AES_SHA1_96_256 = 16


def fail(message):
    print(f"FAIL {message}")
    sys.exit(1)


def main(path):
    pac = bytes.fromhex(open(path, encoding="ascii").read().strip())
    pac_type = PACTYPE(pac)
    count = pac_type["cBuffers"]
    if pac_type["Version"] != 0:
        fail(f"Version is {pac_type['Version']}, and the specification says zero")

    infos = {}
    at = 8
    for _ in range(count):
        info = PAC_INFO_BUFFER(pac[at : at + 16])
        at += 16
        kind, size, offset = info["ulType"], info["cbBufferSize"], info["Offset"]
        if offset % 8 != 0:
            fail(f"buffer {kind} starts at {offset}, which is not an eight-octet boundary")
        if offset + size > len(pac):
            fail(f"buffer {kind} runs past the end: {offset} + {size} > {len(pac)}")
        infos[kind] = (size, offset)
    print(f"envelope: {count} buffers, offsets inside {len(pac)} octets")

    # impacket zeroes the Signature field and leaves SignatureType as written;
    # that is the region the signature covers.
    block = bytearray(pac)
    for kind in (PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM):
        if kind not in infos:
            fail(f"no buffer {kind}")
        size, offset = infos[kind]
        block[offset + 4 : offset + size] = b"\x00" * (size - 4)

    def signature(kind):
        size, offset = infos[kind]
        data = PAC_SIGNATURE_DATA(pac[offset : offset + size])
        return data["SignatureType"], bytes(data["Signature"])

    def recompute(key):
        return crypto.make_checksum(
            CHECKSUM_AES_SHA1_96_256, crypto.Key(E.AES256, key), 17, bytes(block)
        )

    for kind, key, name in (
        (PAC_SERVER_CHECKSUM, SERVER_KEY, "server"),
        (PAC_PRIVSVR_CHECKSUM, KDC_KEY, "kdc"),
    ):
        sigtype, sig = signature(kind)
        if sigtype != CHECKSUM_AES_SHA1_96_256:
            fail(f"{name} signature type is {sigtype}, not HMAC-SHA1-96-AES256")
        if sig != recompute(key):
            fail(f"{name} signature does not verify under its own key")
        other = KDC_KEY if key is SERVER_KEY else SERVER_KEY
        if sig == recompute(other):
            fail(f"{name} signature also verifies under the other key, so they are one key")
        print(f"{name} signature verifies under its own key, and not under the other")

    print("OK impacket parsed the envelope and verified both signatures")


if __name__ == "__main__":
    main(sys.argv[1])
