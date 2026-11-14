#!/usr/bin/env python3
"""Writes `supplementalCredentials` fixtures from a real Samba, checked against Samba's own keytab.

Why this is a script and not a test: producing a fixture needs a provisioned Samba domain and
`ldbsearch`, and neither belongs in `cargo test`. A test that silently skipped when they are missing
would be indistinguishable from a passing one.

# Why the expected values are not computed from the blob alone

A codec checked against itself always agrees with itself. So the fixture's expectation comes from a
second path: **Samba's own string-to-key**, through `samba-tool domain exportkeytab`. The keys in the
keytab are what Samba computed for that account from its password; the keys in
`supplementalCredentials` are what Samba wrote into the directory. If the two sets agree — and the
generator refuses to write a fixture where they do not — then the blob genuinely carries the account's
keys, and our decoder reading those octets is checked against Samba's arithmetic rather than ours.

The layout is also re-implemented here in `struct`, straight from [MS-SAMR] §2.2.10, rather than read
with impacket's structures: impacket gives the header fields but leaves the key array as raw `Buffer`,
so using it would mean repeating the same logic a second time in another language with no independent
opinion about where a key starts.

    scripts/ad-blob-fixtures.py --out tests/fixtures/ad_blob
"""

import argparse
import base64
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

FIXTURES = "tests/fixtures/ad_blob"
REALM = "FIX.TEST"
DOMAIN = "FIX"
ADMIN_PASSWORD = "Passw0rd!fix"
USER = "fixture"
USER_PASSWORD = "Passw0rd!user"

# [MS-SAMR] §2.2.10.1: the fixed part of `KERB_STORED_CREDENTIAL_NEW`, and §2.2.10.2 for one
# `KERB_KEY_DATA_NEW`.
CREDENTIAL_HEADER = 24
KEY_DATA_NEW = 24
PROPERTY_SIGNATURE = 0x0050
# `Reserved1` (4) + `Length` (4) + `Reserved2` (2) + `Reserved3` (2) + `Reserved4` (96).
PROPERTY_SIGNATURE_OFFSET = 108
PROPERTY_COUNT_OFFSET = 110
WANTED_PROPERTY = "Primary:Kerberos-Newer-Keys"


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


def provision(target):
    """A fresh Samba domain in `target`; returns the path of its `sam.ldb`."""
    if os.path.isdir(target):
        shutil.rmtree(target)
    os.makedirs(target)
    result = run([
        "samba-tool", "domain", "provision",
        f"--realm={REALM}", f"--domain={DOMAIN}", f"--adminpass={ADMIN_PASSWORD}",
        "--server-role=dc", "--use-rfc2307", f"--targetdir={target}",
    ])
    # Provisioning finishes by setting ACLs on the new databases, which needs a filesystem carrying
    # POSIX ACLs. A container's overlayfs may not, and that failure arrives as a traceback *after*
    # the directory is written — so the attribute decides, below, not this exit code.
    if result.returncode != 0:
        print(f"note: samba-tool provision exited {result.returncode}", file=sys.stderr)
    ldb = os.path.join(target, "private", "sam.ldb")
    if not os.path.exists(ldb):
        print(result.stdout, result.stderr, file=sys.stderr)
        raise SystemExit("provisioning left no sam.ldb")
    return ldb


def add_user(target, ldb, name, password):
    """An account with a password, so Samba writes keys for an ordinary user as well.

    `samba-tool` is pointed at the database by URL and at the configuration separately: `-s` takes the
    `smb.conf`, and handing it the `sam.ldb` (the obvious-looking `--configfile=<ldb>`) makes every
    command fall back to `/var/lib/samba` and fail with "unable to open tdb".
    """
    result = run([
        "samba-tool", "user", "add", name, password,
        "-H", f"tdb://{ldb}", "-s", os.path.join(target, "etc", "smb.conf"),
    ])
    if result.returncode != 0:
        print(result.stdout, result.stderr, file=sys.stderr)
        raise SystemExit(f"adding {name} failed")


def attribute(ldb, sam, attribute="supplementalCredentials"):
    """The attribute's bytes, from LDIF.

    LDIF wraps a long base64 value over several lines, each continuation starting with a space.
    Splitting on whitespace — the obvious reading — drops those breaks and yields a value that
    decodes to nothing, which looks like a corrupt blob rather than a parsing mistake.
    """
    out = run(["ldbsearch", "-H", ldb, f"(sAMAccountName={sam})", attribute])
    if out.returncode != 0:
        print(out.stdout, out.stderr, file=sys.stderr)
        raise SystemExit(f"ldbsearch failed for {sam}")
    lines = out.stdout.splitlines()
    for i, line in enumerate(lines):
        prefix = f"{attribute}:: "
        if line.startswith(prefix):
            value = line[len(prefix):]
            j = i + 1
            while j < len(lines) and lines[j].startswith(" "):
                value += lines[j][1:]
                j += 1
            return base64.b64decode(value)
    raise SystemExit(f"no {attribute} on {sam}")


def properties(blob):
    """`USER_PROPERTIES` as `{name: value}`, with values decoded from hex text.

    The layout is [MS-SAMR] §2.2.10.1 and is **not** the intuitive one: after `Reserved1` and
    `Length` come two 16-bit reserved fields and a **96-octet** `Reserved4`, so the
    `PropertySignature` sits at offset 108 and `PropertyCount` at 110. Reading the signature at
    offset 0 answers 0x0000 and looks like a corrupt blob.

    `PropertyValue` is a string holding the **hexadecimal text** of the value, which every consumer
    unhexes. Both readings of `Length` are tolerated — `len-13` (Windows, impacket, mimikatz) and
    `len-12` (§2.2.10.1 counts from `Reserved4`) — because the count is found from
    `PropertySignature` here, not from `Length`.
    """
    if len(blob) < 112:
        raise SystemExit("blob shorter than USER_PROPERTIES' fixed header")
    signature = struct.unpack_from("<H", blob, PROPERTY_SIGNATURE_OFFSET)[0]
    if signature != PROPERTY_SIGNATURE:
        raise SystemExit(f"PropertySignature is {signature:#x}, not 0x50")
    count = struct.unpack_from("<H", blob, PROPERTY_COUNT_OFFSET)[0]
    at = PROPERTY_COUNT_OFFSET + 2
    found = {}
    for _ in range(count):
        name_len, value_len, _reserved = struct.unpack_from("<HHH", blob, at)
        at += 6
        name = blob[at:at + name_len].decode("utf-16le")
        at += name_len
        value = blob[at:at + value_len].decode("ascii")
        at += value_len
        found[name] = bytes.fromhex(value)
    return found


def _wchar(raw):
    """A WCHAR string's octets as text, trailing NUL padding removed."""
    text = raw.decode("utf-16le")
    return text.rstrip("\x00")


def credentials(blob):
    """The keys `credential_count` entries name, as `[{enctype, key, salt}]`.

    Read per [MS-SAMR] §2.2.10.2: four counts, one salt, then a table of fixed-size descriptors whose
    `KeyOffset`/`KeyLength` point into the same buffer.
    """
    inner = properties(blob)[WANTED_PROPERTY]
    if len(inner) < CREDENTIAL_HEADER:
        raise SystemExit("KERB_STORED_CREDENTIAL_NEW shorter than its header")
    revision = struct.unpack_from("<H", inner, 0)[0]
    if revision != 4:
        raise SystemExit(f"revision {revision}, and only 4 has these fields")
    counts = struct.unpack_from("<HHHH", inner, 4)
    total = sum(counts)
    salt_len = struct.unpack_from("<H", inner, 12)[0]
    salt_at = struct.unpack_from("<I", inner, 16)[0]
    # `DefaultSalt` is a WCHAR string: the blob holds `F\0I\0X\0…`, and the value string-to-key
    # was given is `FIX.TEST…`. Decoded here so the fixture states the salt rather than its encoding —
    # the encoding is what the reader has to get right, and a fixture that stored the raw octets would
    # leave the test comparing two encodings instead of checking the decoding.
    salt = _wchar(inner[salt_at:salt_at + salt_len])
    out = []
    for i in range(total):
        at = CREDENTIAL_HEADER + i * KEY_DATA_NEW
        key_type = struct.unpack_from("<I", inner, at + 12)[0]
        key_len = struct.unpack_from("<I", inner, at + 16)[0]
        key_at = struct.unpack_from("<I", inner, at + 20)[0]
        out.append({
            "enctype": key_type,
            "key": inner[key_at:key_at + key_len].hex(),
            "salt": salt,
        })
    return out


def keytab_credentials(target, account):
    """The keys Samba computed for `account`, out of a keytab it exported.

    This is the second path the fixture rests on. `exportkeytab` runs Samba's string-to-key for the
    account; the blob is what Samba wrote from the same computation. A fixture whose two halves
    disagreed would be describing a directory Samba itself cannot use.
    """
    path = os.path.join(target, "fixture.keytab")
    result = run([
        "samba-tool", "domain", "exportkeytab", path,
        f"--principal={account}@{REALM}",
        # No `-H`: `exportkeytab` reads the database the configuration names, unlike the commands
        # that take a URL.
        "-s", os.path.join(target, "etc", "smb.conf"),
    ])
    if result.returncode != 0:
        print(result.stdout, result.stderr, file=sys.stderr)
        raise SystemExit(f"exportkeytab failed for {account}")
    with open(path, "rb") as handle:
        data = handle.read()
    # Keytab §3: a two-octet version, then entries of `size` octets (four-octet sizes in v5.2).
    version = struct.unpack_from(">H", data, 0)[0]
    wide = version == 0x0502
    at = 2
    out = {}
    while at < len(data):
        if wide:
            size = struct.unpack_from(">i", data, at)[0]
            at += 4
        else:
            size = struct.unpack_from(">h", data, at)[0]
            at += 2
        if size < 0:
            at += -size
            continue
        entry = data[at:at + size]
        at += size
        components = struct.unpack_from(">H", entry, 0)[0]
        cursor = 2
        realm_len = struct.unpack_from(">H", entry, cursor)[0]
        cursor += 2 + realm_len
        for _ in range(components):
            length = struct.unpack_from(">H", entry, cursor)[0]
            cursor += 2 + length
        cursor += 4  # name type
        cursor += 4  # timestamp
        cursor += 1  # kvno
        enctype = struct.unpack_from(">H", entry, cursor)[0]
        cursor += 2
        key_len = struct.unpack_from(">H", entry, cursor)[0]
        cursor += 2
        out[enctype] = entry[cursor:cursor + key_len].hex()
    return out


# The enctypes this crate implements (`rrl-crypto::Enctype`): 17, 18, 19, 20 and 23. A blob written
# by Samba or Windows also carries 1 and 3 — `des-cbc-crc` and `des-cbc-md5` — in the same generation,
# and those are recorded in the fixture as unreadable rather than dropped: a fixture that only ever
# contained what the reader understands would not show that the reader copes with what it does not.
READABLE_ENCTYPES = {17, 18, 19, 20, 23}


def fixture(name, sam, password, ldb, target, note):
    blob = attribute(ldb, sam)
    from_blob = credentials(blob)
    from_keytab = keytab_credentials(target, sam)

    # Only what both halves have can be compared: Samba's `exportkeytab` writes the current keys it
    # considers usable, and the DES pair in the blob is legacy material it does not export. The
    # comparison is therefore over the intersection, and the fixture records what was compared.
    checked = []
    for credential in from_blob:
        expected = from_keytab.get(credential["enctype"])
        if expected is None:
            continue
        if expected != credential["key"]:
            raise SystemExit(
                f"{sam}: enctype {credential['enctype']} differs between the blob and the keytab — "
                f"the two halves of this fixture disagree"
            )
        checked.append(credential["enctype"])

    if not checked:
        raise SystemExit(f"{sam}: the keytab confirms none of the blob's keys")

    readable = [c for c in from_blob if c["enctype"] in READABLE_ENCTYPES]
    if not readable:
        raise SystemExit(f"{sam}: no key this crate implements")
    # The readable keys are the ones the Rust test compares against, and each has to be confirmed by
    # the keytab — otherwise the fixture would pin a value only the blob's own arithmetic produced.
    for credential in readable:
        if credential["enctype"] not in checked:
            raise SystemExit(
                f"{sam}: enctype {credential['enctype']} is readable by this crate and the keytab "
                f"does not confirm it, so the fixture has nothing independent to check it against"
            )

    return {
        "name": name,
        "source": f"Samba {samba_version()}: `samba-tool domain provision` + `samba-tool user add`",
        "note": note,
        "account": sam,
        # Published on purpose: it is a throwaway account in an ephemeral domain, and the Rust test
        # derives the keys from it. Password → salt → key is the loop that proves the salt was
        # decoded the way the directory encoded it: a salt with a NUL after every character derives
        # a key that matches nothing.
        "password": password,
        "blob": blob.hex(),
        "credentials": readable,
        "skipped_enctypes": sorted(
            {c["enctype"] for c in from_blob if c["enctype"] not in READABLE_ENCTYPES}
        ),
        "verified_against": "Samba's own `domain exportkeytab` for the same account: the keys were "
                            "computed by Samba's string-to-key and confirm the octets the blob "
                            "carries",
    }


def samba_version():
    out = run(["samba-tool", "--version"])
    return out.stdout.strip().splitlines()[0] if out.stdout else "unknown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=FIXTURES)
    parser.add_argument("--keep", default=None, help="provision here instead of a temporary directory")
    args = parser.parse_args()

    target = args.keep or tempfile.mkdtemp(prefix="samba-fixture-")
    ldb = provision(target)
    add_user(target, ldb, USER, USER_PASSWORD)

    fixtures = [
        fixture("administrator", "Administrator", ADMIN_PASSWORD, ldb, target,
                "the account provisioning creates; Samba writes the current generation and may write "
                "older ones"),
        fixture("user", USER, USER_PASSWORD, ldb, target,
                "an account `samba-tool user add` created, so the fixture is not only a provisioned "
                "one"),
    ]

    os.makedirs(args.out, exist_ok=True)
    for one in fixtures:
        path = os.path.join(args.out, f"{one['name']}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(one, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote {path}: {len(one['credentials'])} credentials "
              f"({sorted({c['enctype'] for c in one['credentials']})}), "
              f"{len(bytes.fromhex(one['blob']))} octets")


if __name__ == "__main__":
    main()
