#!/usr/bin/env python3
"""Reads the blobs this crate writes with impacket, and compares.

impacket's `samr.USER_PROPERTIES` and `samr.KERB_STORED_CREDENTIAL_NEW` are an
independent implementation of [MS-SAMR] §2.2.10, written by somebody else and used
by `secretsdump`. A blob that parses here and yields the keys we put in is a blob
`secretsdump` can read; a blob this crate merely re-reads with its own decoder
proves only that the decoder and the encoder agree with each other.

The comparison is per generation — current, old, older — because putting the
previous keys where the current ones belong still parses and still holds every key,
and would hand an auditor yesterday's key as the account's current one.

Exit code 0 means every case matched. Anything else prints what differed.
"""

import binascii
import json
import pathlib
import struct
import sys

try:
    from impacket.dcerpc.v5 import samr
except ImportError:  # pragma: no cover - the caller reports this
    print("impacket is not importable; install it (see scripts/verify-ad-blob.sh)")
    sys.exit(2)

PROPERTY_NAME = "Primary:Kerberos-Newer-Keys"


def parse_property(blob_path, blob):
    """The single property's value, as octets."""
    properties, count, tail = samr.unpack_user_properties(blob)
    if properties["PropertySignature"] != 0x50:
        raise SystemExit(
            f"{blob_path.name}: PropertySignature is "
            f"{properties['PropertySignature']:#x}, not 0x50"
        )
    if count != 1:
        raise SystemExit(f"{blob_path.name}: expected 1 property, impacket found {count}")

    at = 0
    name_len, value_len, reserved = struct.unpack_from("<HHH", tail, at)
    at += 6
    name = tail[at : at + name_len].decode("utf-16le")
    at += name_len
    value_hex = tail[at : at + value_len].decode("ascii")
    at += value_len
    if reserved != 0:
        raise SystemExit(f"{blob_path.name}: USER_PROPERTY.Reserved is {reserved}, not 0")
    if name != PROPERTY_NAME:
        raise SystemExit(f"{blob_path.name}: property is {name!r}, not {PROPERTY_NAME!r}")
    return binascii.unhexlify(value_hex)


def check_length(blob_path, blob):
    """`Length` must be the value Windows writes, which is what impacket's boundary uses.

    impacket computes `properties_end = 12 + Length` and then reads `Reserved5` from that
    offset, so a blob whose `Length` counted `Reserved5` — the literal reading of
    §2.2.10.1 — would be rejected by it as missing its final octet. This crate reads either
    reading but must write this one.
    """
    length = struct.unpack_from("<L", blob, 4)[0]
    if 12 + length != len(blob) - 1:
        raise SystemExit(
            f"{blob_path.name}: Length {length} puts the end of the structure at "
            f"{12 + length}, but Reserved5 is the octet at {len(blob) - 1}"
        )


def read_case(blob_path):
    blob = blob_path.read_bytes()
    manifest = json.loads(blob_path.with_suffix(".json").read_text())
    check_length(blob_path, blob)

    if manifest["properties"] == 0:
        # The odd shape: no PropertyCount field at all, and no trailing property.
        _, count, tail = samr.unpack_user_properties(blob)
        if count != 0:
            raise SystemExit(f"{blob_path.name}: expected 0 properties, got {count}")
        if tail:
            raise SystemExit(f"{blob_path.name}: {len(tail)} octets after the header")
        if len(blob) != 111:
            raise SystemExit(f"{blob_path.name}: {len(blob)} octets, expected 111")
        return None, 0

    payload = parse_property(blob_path, blob)
    credential = samr.KERB_STORED_CREDENTIAL_NEW(payload)
    if credential["Revision"] != 4:
        raise SystemExit(f"{blob_path.name}: revision {credential['Revision']}, not 4")
    if credential["ServiceCredentialCount"] != 0:
        raise SystemExit(f"{blob_path.name}: service credentials are not written")

    counts = [
        credential["CredentialCount"],
        credential["OldCredentialCount"],
        credential["OlderCredentialCount"],
    ]
    buffer = credential["Buffer"]
    index = 0
    for generation, count in zip(["current", "old", "older"], counts):
        found = {}
        for _ in range(count):
            # 24 octets each: `KERB_KEY_DATA_NEW`.
            key_data = samr.KERB_KEY_DATA_NEW(buffer[index * 24 :])
            index += 1
            key_bytes = payload[key_data["KeyOffset"] :][: key_data["KeyLength"]]
            found[str(key_data["KeyType"])] = binascii.hexlify(key_bytes).decode()
        expect = manifest[generation]
        if found != expect:
            raise SystemExit(
                f"{blob_path.name}: {generation} differs\n"
                f"  expected {expect}\n  impacket {found}"
            )

    return manifest["principal"], sum(counts)


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/ad-blob")
    blobs = sorted(root.glob("*.blob"))
    if not blobs:
        print(f"no blobs in {root}; run the example first")
        return 2

    total_keys = 0
    for blob in blobs:
        principal, keys = read_case(blob)
        total_keys += keys
        if principal is None:
            print(f"  {blob.stem:20} {'(no properties)':34} {len(blob.read_bytes())} octets")
        else:
            print(f"  {blob.stem:20} {principal:34} {keys} key(s), all matched")
    print(
        f"{len(blobs)} blob(s) read by impacket, {total_keys} key(s) compared generation by "
        f"generation"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
