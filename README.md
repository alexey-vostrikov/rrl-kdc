# rust-heimdal-kdc

A Kerberos KDC core in Rust, written from scratch, with **Heimdal's behaviour as
the specification**.

This is a **library**, not a daemon. The protocol engine is sans-io: sockets,
clocks, randomness and storage are supplied by the caller, so the same code
serves a standalone KDC, an in-process KDC inside a directory server, and a
deterministic test that replays recorded requests.

Not a fork of anything. Not a client. The client it is judged by is somebody
else's implementation — a KDC that only agrees with itself agrees with nothing.

## Who checks this crate

1. **`krb5` 1.0 (ddalton) — the primary client.** Every acceptance test goes
   through it: it asks this KDC for a ticket the way MIT's `kinit` does and
   refuses replies MIT would refuse, so a reply it accepts is a reply another
   implementation accepts too.
2. **`rskrb5` 0.2 — secondary, crypto only.** Behind the `crypto-rskrb5`
   feature, used to run the same known-answer vectors through a second
   implementation of RFC 3961/3962/8009. A disagreement is worth knowing about,
   but it does not define this KDC's behaviour — `krb5` does.

## Status

The protocol engine is in place and green: AS and TGS exchanges, the
change-password service, user-to-user tickets, keytab files, a redb store, the
administrator's API over it, and a PAC in the tickets it issues. The `krb5` crate
drives the acceptance tests; impacket checks the PAC and the AD key projection, and
`scripts/verify-pac-live.sh` has it ask this KDC for a ticket and read the PAC out.

| Layer | State |
|---|---|
| `der` — strict DER for RFC 4120 | done: minimal lengths, minimal INTEGERs, refuses non-DER |
| `crypto` — RFC 3961 §5.1/§5.3, RFC 3962, RFC 8009 | done: enctypes 17/18/19/20 |
| `crypto::nfold` — RFC 3961 §5.1 n-fold | done |
| `time` — `KerberosTime` | done |
| `msg` — KDC-REQ decode, KDC-REP / EncASRepPart / EncTGSRepPart encode | done |
| `hdb` — principal records after Heimdal's `lib/hdb/hdb.asn1` | done: memory and redb backends, keytab read/write |
| `kdc` — AS-REQ → AS-REP, TGS-REQ → TGS-REP | done, including user-to-user tickets |
| `kdc::kpasswd` — RFC 3244 change-password | done: set-password, with a pluggable authorization policy |
| `acl` — who may change whose password | done: rules in a store, not a file |
| `admin` — create, delete, modify, re-key, export a keytab | done |
| `admin::wire` — the operations as values, with the authorization in one place | done |
| `admin::json` — the JSON form (feature `admin-json`) | done, for a REST front end to wrap |
| `hdb::ldap` — an entry as directory attributes (feature `hdb-ldap`) | done: Heimdal's schema, plus the Microsoft spellings |
| `kadmin` — MIT's `kadm5` protocol over ONC RPC (feature `kadmin`) | done: init, get_privs, get/get_principals, create, delete, chpass, chrand |
| `hdb::ad_blob` — `supplementalCredentials` (feature `hdb-ldap`) | done both ways: written as a projection, read back when `krb5Key` is absent |
| `kdc::pac` — the privilege attribute certificate | done: envelope, `PAC_CLIENT_INFO`, `KERB_VALIDATION_INFO`, both signatures |
| `kdc::logon_info` — NDR for `KERB_VALIDATION_INFO` | done: encoded by hand, checked by impacket and by a live client |

### Managing a realm without inventing an API

`admin::wire` exists so that a transport carries operations rather than calling
`Admin`'s methods one by one: every operation is a value, `Admin::handle` runs it,
and **the authorization is inside `handle`**. A REST route, a CLI and an in-process
caller therefore cannot forget the check — there is no other entry point that
performs an operation.

Rights are finer than "administrator": listing a realm, reading an entry and
exporting a keytab are three different rights, because only the last one hands over
password-equivalent material. Nothing is granted by default (`DenyAll`), so a
deployment that forgets to configure authorization serves nobody rather than
everybody.

With the `admin-json` feature a front end is a one-liner:

```rust
let reply = admin.handle(serde_json::from_str(&body)?)?;   // -> serde_json::to_value
```

with three properties worth relying on: binary fields travel as base64 rather than
as arrays of octets, a misspelled field is an error rather than silently dropped,
and an error carries a stable `kind` (`not_found`, `already_exists`, `forbidden`,
`bad_request`, …) for the status code so nobody has to parse prose.

### A PAC, and where the identity comes from

Tickets carry a privilege attribute certificate when the realm is told to issue one:
`Kdc::with_pac(Arc<dyn PacIdentities>)`. The trait is the seam, not an implementation
detail — the RID, the group list and the domain SID belong to a directory, and this
crate does not own one. A realm without it issues plain Kerberos tickets, which is
correct when no Windows service reads them, and an account the directory does not
know gets a ticket without a PAC rather than a refusal.

The PAC is rebuilt for every ticket rather than copied out of the TGT: its service
signature is keyed by *that* service's key, and the signature type follows the key's
enctype (15/16 for the AES-SHA1 enctypes, −138 for RC4).

Three things are checked by somebody else's code, because a self-test would agree
with whatever the encoder did: `scripts/verify-pac.sh` (envelope and signatures),
`scripts/verify-logon-info.sh` (every NDR field and referent), and
`scripts/verify-pac-live.sh`, which starts a KDC, has impacket request a TGT and
reads the PAC out of the reply.

### A service is found by the name it publishes

A client asks for `cifs/host.example.com`; a Windows directory holds that account as
`HOST$` and keeps the requested name in `servicePrincipalName`. `Hdb::fetch` answers
the first question only, so `Hdb::fetch_for_service` is the one the TGS asks — by
default it is `fetch`, and a backend that can see SPNs overrides it. `LdapHdb` does:
name first, then `Directory::get_by_spn`, and the entry it finds must itself publish
the requested name, or the lookup fails instead of handing out one account's ticket
under another's name.

The ticket and the reply then state the name the **client** asked for, which is what
Active Directory does and what a client checks: a reply naming `HOST$` is refused with
`KRB5_KDCREP_MODIFIED`.

## Enctypes

Only the AES four: 17/18 (RFC 3962) and 19/20 (RFC 8009). DES3 and RC4 are
refused rather than silently downgraded — a configuration naming `rc4-hmac`
fails at startup instead of being quietly given AES.

## Two crypto backends

`OwnCipher` is this crate's implementation, and it is the one that ships. With
the optional `crypto-rskrb5` feature a second backend over
[`rskrb5::crypto`](https://github.com/clelange/rskrb5) joins it, and **every**
known-answer vector runs against both:

```sh
cargo test                                    # the default configuration
cargo test --features crypto-rskrb5           # both, compared
```

That turns the vectors from a self-test into a differential test: a
disagreement names the construction that differs instead of surfacing as
"`kinit` cannot log in". The feature is off by default and the backend is
secondary: it is a cross-check on the crypto, not a second definition of what
this KDC does.

## Evidence

Vectors are transcribed from the sources, not invented:

- `tests/fixtures/mit-crypto.json` — MIT krb5's `crypto_tests` known answers
  (decrypt, checksum, derive, string-to-key).
- `tests/fixtures/heimdal.json` — Heimdal 7.99.1 `n-fold-test.c`,
  `derived-key-test.c`, `aes-test.c`.

Three real bugs were caught by them during step 0 and are worth knowing:

1. **n-fold needs end-around carry.** Dropping the carry out of the top octet
   changes only the last octet — close enough to look like a typo in the
   vectors, wrong enough that every derived key is wrong.
2. **PBKDF2 is not the key.** The enctype's own KDF with the constant
   `"kerberos"` turns the PBKDF2 output into the protocol key (RFC 3962 §A.2).
3. **RFC 8009 sizes `Ki` and `Kc` separately from `Ke`.** For
   `aes256-cts-hmac-sha384-192` they are 192-bit, while `Ke` is 256-bit;
   deriving 32 octets and truncating the MAC yields a tag no peer accepts.
   RFC 8009 §4 also prefixes the salt with the enctype name and a NUL.

### A realm in a directory

`hdb-ldap` is a **mapping**, not an LDAP client: `to_attributes` writes an entry as
the attributes Heimdal's `lib/hdb/hdb.schema` defines, `from_attributes` reads one
back, and `Directory` is the four operations a KDC needs from whatever holds them.
`LdapHdb` is then an `Hdb` over any such directory, so an embedder that already has
a database implements that trait in a few dozen lines instead of running an LDAP
client against itself.

The Microsoft attributes (`msDS-KeyVersionNumber`, `msDS-SupportedEncryptionTypes`,
`userAccountControl`, `servicePrincipalName`) are written, never required: an entry
with only the Heimdal attributes is complete, and an entry with only Microsoft's
reads too. Where the two vocabularies state one fact and disagree, the mapping
refuses rather than picking a winner — a KDC that silently preferred one would end
up with an account enabled in the directory and disabled in the realm.

### `kadmin`

`kadmin` speaks MIT's `kadm5` protocol over ONC RPC with RPCSEC_GSS privacy, and
this crate answers it: the acceptance tests drive a real `krb5` 1.0
`AdminClient` — connect, handshake, `get_principals`, create, delete, `chpass`,
`chrand`, and then log in with an ordinary client using the password that was just
set. Authorization is the same `Policy` the in-process and JSON front ends use, so
a `kadmin` user without rights gets MIT's `KADM5_AUTH_*` and no data.

Not implemented, and answered with an error rather than a fabricated success:
policies, string attributes, `extract_keys`.

## Building

```sh
cargo build
cargo test                          # the default configuration
cargo test --all-features           # + redb, + the JSON form, + the crypto cross-check
cargo clippy --all-targets --all-features -- -D warnings
```

Coverage is measured with `cargo llvm-cov` and held to a floor, so a module that
arrives without tests fails the build rather than lowering a number nobody reads:

```sh
scripts/coverage.sh --check         # COVERAGE_MIN=88 by default
```

Edition 2024, MSRV 1.99.1 — the same toolchain the in-process consumer
(`rust-rest-ldap`) pins in `rust-toolchain.toml`, so one workspace does not need
two.

## Layout

```
src/der.rs        strict DER: encode, Reader, Fields, typed accessors
src/error.rs      one error type and its mapping to KRB-ERROR codes
src/time.rs       GeneralizedTime without a date dependency
src/crypto/       enctypes, Key, Cipher trait, OwnCipher
  nfold.rs        RFC 3961 §5.1 n-fold
  kdf.rs          DR/DK, KDF-HMAC-SHA2, PBKDF2 string-to-key, usage constants
  aes_cts.rs      AES-CBC-CTS (RFC 3962 §5 / RFC 8009 §1)
  rskrb5_backend.rs  second backend, feature-gated
tests/vectors.rs  every vector, run against every backend
```

## Licence

MIT.
