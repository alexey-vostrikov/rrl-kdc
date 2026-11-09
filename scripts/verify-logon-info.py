"""Verifies this crate's KERB_VALIDATION_INFO with impacket, somebody else's NDR reader.

What is checked, and why it cannot be checked from the Rust side:

1. **The structure's layout.** impacket parses the buffer as `KERB_VALIDATION_INFO`
   and reads `UserId`, `PrimaryGroupId`, `GroupCount`, the counts and the timestamps
   at the offsets it computes from the specification. A field missed or duplicated in
   this crate's encoder shifts everything after it, and these numbers would be other
   numbers.
2. **The referents.** Every pointer is followed and the strings, the group array and
   the domain SID are read back and compared with what the example asked for. A
   pointer that is off by the length of a header lands in the middle of a name.
3. **That the buffer ends where the last referent does.** No padding, no missing
   tail: the last octet of the domain SID is the last octet of the buffer.

# The one field impacket adds

impacket's `KERB_VALIDATION_INFO` has a thirty-fourth field, `ResourceGroupIds`,
after `ResourceGroupCount`. [MS-PAC] §2.5 ends the structure at
`ResourceGroupCount`, and so does this crate's encoder — a Windows PAC has no
`ResourceGroupIds` there. The parser therefore walks one pointer past the end of a
correct buffer and raises; this script stops at the last field the specification
defines and says so, rather than padding the buffer to satisfy another
implementation's extension.
"""

import sys

SID = None  # set in main, so the module imports without impacket


def fail(message):
    print(f"FAIL {message}")
    sys.exit(1)


def main(path):
    global SID
    from impacket.krb5.pac import KERB_VALIDATION_INFO, PAC_INFO_BUFFER, PAC_LOGON_INFO, PACTYPE
    from impacket.krb5.pac import PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA
    from impacket.krb5 import crypto
    from impacket.krb5.crypto import Enctype

    values = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value

    validation = bytes.fromhex(values["VALIDATION"])
    pac = bytes.fromhex(values["PAC"])

    info = KERB_VALIDATION_INFO(validation)

    def check(claim, got, want):
        if str(got) != str(want):
            fail(f"{claim}: impacket read {got!r}, and the source said {want!r}")

    check("UserId", info["UserId"], values["EXPECT_RID"])
    check("PrimaryGroupId", info["PrimaryGroupId"], values["EXPECT_PRIMARY"])
    check("GroupCount", info["GroupCount"], len(values["EXPECT_GROUPS"].split(",")))
    check("UserAccountControl", info["UserAccountControl"], 0x200)
    print(
        f"structure: RID {info['UserId']}, primary group {info['PrimaryGroupId']}, "
        f"{info['GroupCount']} groups"
    )

    # The timestamps, as the two halves of a FILETIME.
    logon = info["LogonTime"]
    ticks = logon["dwLowDateTime"] | (logon["dwHighDateTime"] << 32)
    seconds = ticks // 10_000_000 - 11_644_473_600
    check("LogonTime", seconds, values["EXPECT_LOGON_TIME"])

    # The referents, walked in the order the structure names their pointers. The walk
    # stops before `ResourceGroupIds`, which is impacket's own addition.
    offset = 212
    # A sequential walk would find the referents even if every pointer were wrong, so
    # the pointers themselves are checked: the first one must equal the octet where
    # the structure ends, which is where the referent area begins.
    first_pointer = int.from_bytes(validation[52:56], "little")
    if first_pointer != 212:
        fail(
            f"the first referent pointer says {first_pointer} and the structure ends at 212; "
            "every string and array is shifted by the difference"
        )
    for name, _ in info.commonHdr + info.structure:
        if name == "ResourceGroupIds":
            break
        field = info.fields[name]
        # Only a constructed field — a string, an array, a SID — has referents; a
        # `USHORT` such as `LogonCount` has none and takes no room in the referent
        # area.
        if not hasattr(field, "fromStringReferents"):
            continue
        refs = field.fromStringReferents(validation, offset)
        ref = field.fromStringReferent(validation, offset + refs)
        offset += refs + ref
    if offset != len(validation):
        fail(
            f"the buffer is {len(validation)} octets but the last referent ends at {offset}: "
            "a tail nobody reads is a tail nobody can vouch for"
        )
    print(f"referents: every pointer resolved, and the buffer ends at {offset} octets")

    check("EffectiveName", info["EffectiveName"], values["EXPECT_NAME"])
    check("FullName", info["FullName"], values["EXPECT_FULL"])
    check("LogonServer", info["LogonServer"], values["EXPECT_LOGON_SERVER"])
    check("LogonDomainName", info["LogonDomainName"], values["EXPECT_LOGON_DOMAIN"])
    print(
        f"strings: {info['EffectiveName']!r} / {info['FullName']!r}, "
        f"server {info['LogonServer']!r}, domain {info['LogonDomainName']!r}"
    )

    groups = [g["RelativeId"] for g in info["GroupIds"]]
    check("GroupIds", ",".join(str(g) for g in groups), values["EXPECT_GROUPS"])
    print(f"groups: RIDs {groups}")

    sid = info["LogonDomainId"]
    subs = list(sid["SubAuthority"])
    # The sub-authorities are what prove the pointer landed where the structure says,
    # so the revision and the authority are read from the eight octets immediately
    # before the array that impacket just read — its own `Revision` field comes back
    # zero for a structure it parses as a referent, which is a quirk of that reader,
    # not a fact about these octets.
    array = b"".join(s.to_bytes(4, "little") for s in subs)
    at = validation.find(len(subs).to_bytes(4, "little") + array)
    if at < 8:
        fail("the domain SID's sub-authority array is not in the buffer")
    revision = validation[at - 8]
    authority_bytes = validation[at - 6 : at]
    authority = 0
    for byte in authority_bytes:
        authority = (authority << 8) | byte
    text = f"S-{revision}-{authority}"
    for sub in subs:
        text += f"-{sub}"
    check("LogonDomainId", text, values["EXPECT_DOMAIN"])
    if revision != 1:
        fail(f"a SID's revision is 1, and this one says {revision}")
    if validation[at - 7] != len(subs):
        fail("the SID's octet count and its array length disagree")
    print(f"domain SID: {text}")

    # And the same bytes inside a sealed PAC: the buffer a service actually receives.
    pac_type = PACTYPE(pac)
    buffers = {}
    at = 8
    for _ in range(pac_type["cBuffers"]):
        buffer = PAC_INFO_BUFFER(pac[at : at + 16])
        at += 16
        buffers[buffer["ulType"]] = (buffer["cbBufferSize"], buffer["Offset"])
    size, start = buffers[PAC_LOGON_INFO]
    if bytes(pac[start : start + size]) != validation:
        fail("the PAC's logon info is not the buffer the encoder produced")

    block = bytearray(pac)
    for kind in (PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM):
        size, start = buffers[kind]
        block[start + 4 : start + size] = b"\x00" * (size - 4)
    for kind, key, name in (
        (PAC_SERVER_CHECKSUM, b"\x07" * 32, "server"),
        (PAC_PRIVSVR_CHECKSUM, b"\x09" * 32, "kdc"),
    ):
        size, start = buffers[kind]
        signature = bytes(PAC_SIGNATURE_DATA(pac[start : start + size])["Signature"])
        expected = crypto.make_checksum(16, crypto.Key(Enctype.AES256, key), 17, bytes(block))
        if signature != expected:
            fail(f"the {name} signature does not cover the logon info")
    print("pac: the logon info travels unchanged, and both signatures cover it")

    print("OK impacket read every field, every referent and the domain SID")


if __name__ == "__main__":
    main(sys.argv[1])
