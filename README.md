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
change-password service, user-to-user tickets, keytab files, a redb store, and
the administrator's API over it. The `krb5` crate drives the acceptance tests.

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

## Building

```sh
cargo build
cargo test
cargo test --features crypto-rskrb5
cargo clippy --all-targets --features crypto-rskrb5
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
