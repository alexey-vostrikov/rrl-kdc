# rrl-kdc

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
| `crypto` — RFC 3961 §5.1/§5.3, RFC 3962, RFC 8009 | done: enctypes 17/18/19/20, in the `rrl-crypto` crate, re-exported here so every path keeps working |
| `crypto::nfold` — RFC 3961 §5.1 n-fold | done, in `rrl-crypto` |
| `time` — `KerberosTime` | done |
| `msg` — KDC-REQ decode, KDC-REP / EncASRepPart / EncTGSRepPart encode | done |
| `hdb` — principal records after Heimdal's `lib/hdb/hdb.asn1` | done: memory and redb backends, keytab read/write, every `HDBFlags` bit from `initial` to `do-not-store` (including the jump from 24 to 30), and the `allowed-to-delegate-to` and `aliases` extensions |
| `hdb::aliases` — `HDB-Ext-Aliases` | done: one account under several names, `case-insensitive` included; an alias resolves to the entry and its keys, the TGS reply names the alias as asked (RFC 6806 §6), and `force-canonicalize` on the service returns the entry's own name |
| `kdc` — AS-REQ → AS-REP, TGS-REQ → TGS-REP | done, including user-to-user tickets |
| `kdc::pac` policy — `require-pac`, `disable-pac`, `auth-data-reqd` | done: Heimdal's `_kdc_include_pac_p` order (root TGT always, then `no-auth-data-reqd`, then `auth-data-reqd`, then `disable-pac`, then the client's `PA-PAC-REQUEST`), and a TGT without a PAC refused as `KDC_ERR_TGT_REVOKED` when the realm requires one |
| `kdc::keys` — the four "strongest" options | done: the three session-key options (`tgt-`, `svc-`, `preauth-use-strongest-session-key`) are off by default, which means the *client's* enctype order decides; `use-strongest-server-key` is on by default, which means this KDC's order picks the key that seals a ticket. `strict-nametypes` (off by default) refuses a `krbtgt` name under any type but `NT-SRV-INST`/`NT-UNKNOWN` |
| `kdc::times` — postdating and `renewable-ok` | done: `may-postdate` needs both entries and is refused with `KDC_ERR_POLICY` otherwise; a postdated ticket starts at `from` and carries `invalid`; `renewable-ok` yields a renewable ticket only where the lifetime had to be cut |
| `transport` — RFC 4120 §7.2, UDP and TCP | done: four-octet framing, and `max-kdc-datagram-reply-length` (Heimdal's 1400 by default) deciding when a reply goes to TCP with `KDC_ERR_RESPONSE_TOO_BIG`; an explicit port that cannot be bound fails with the address rather than retrying |
| `kdc::kpasswd` — RFC 3244 change-password | done: set-password, with a pluggable authorization policy |
| `acl` — who may change whose password | done: rules in a store, not a file |
| `admin` — create, delete, modify, re-key, export a keytab | done |
| `admin::wire` — the operations as values, with the authorization in one place | done |
| `admin::json` — the JSON form (feature `admin-json`) | done, for a REST front end to wrap |
| `hdb::ldap` — an entry as directory attributes (feature `hdb-ldap`) | done: Heimdal's schema, plus the Microsoft spellings |
| `kdc::pkinit` — certificate logins (feature `pkinit`) | done: DH (2048/4096), ECDH (P-256/384/521, RFC 5349), RSA key transport, anonymous (RFC 8062), a `PkinitSource` seam for the identity, and `pkinit_dh_min_bits` answered with `KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED` + `TD-DH-PARAMETERS` so a client retries with a stronger group |
| `kdc::ca` + `kdc::kx509` — a certificate for a ticket (feature `pkinit`) | done: PKCS#10 parsed with its possession proof (RSA/ECDSA), `CertificateAuthority` and `CsrAuthorizer` seams, `kx509` on the KDC port with RFC 6717's MAC. A bare public key is refused: no proof, no certificate |
| `kdc::gss_preauth` — GSS tokens as pre-authentication | done: the mechanism, its cookie state and its policy (`enable-gss-preauth`, `gss-mechanisms-allowed`, `gss-cross-realm-mechanisms-allowed`, `gss-require-bound-request`), over a `GssAcceptor` seam. PA type 655 — Heimdal's, and absent from the IANA registry |
| `kdc::gss_hdb` — the acceptor for that mechanism (feature `gss-preauth`) | done: the realm's own `HDB` is the keytab, and the credential is `krbtgt/REALM@REALM` — the one key only the KDC holds. Ticket lifetime capped at the context's, initiator checked against the request's client |
| `hprop` — database propagation (`kdc/hprop.c`, `kdc/hpropd.c`) | done: `sendauth` in, one `KRB-PRIV` per entry, all-or-nothing install (`PropagationTarget`), `StagedHdb` and a `<path>~`→rename `FileTarget`, `kadmin/hprop` as the only client allowed to push. Entries arrive in Heimdal's `HDB_entry` DER (`hdb::value`), sealed keys open with the realm's master key (`hdb::mkey`) |
| `hdb::mkey` — the master key (KRB-3.2) | done: `K/M@REALM` keytab as `kstash` writes it, seal/unseal at Heimdal's `HDB_KU_MKEY` (0x484442), several versions by `mkvno`, `reseal` for a roll |
| `hdb::redb_store` — keys at rest | done: `open_sealed` writes every key as `encrypt(master_key, HDB_KU_MKEY, …)` and every record names its `mkvno`; a read opens them, so a handle always holds plaintext. A walk reads names only and needs no master key. `reseal` rolls the key; a plaintext file is readable through a sealed handle and re-sealed on the next write |
| `hdb::ldap` — sealed `krb5Key` (feature `hdb-ldap`) | done: `LdapHdb::with_master_keys` seals what it writes and opens what it reads, as Heimdal's `hdb-ldap.c` does — `krb5Key` is an attribute, so a read-only account holding it holds the keys it can see |
| `hdb::ldap` — Heimdal's `Key` layout (feature `hdb-ldap`) | done: `mkvno[0] OPTIONAL, key[1], salt[2] Salt`, with the version in `krb5KeyVersionNumber`; values in this crate's old layout still read, and `LdapHdb::migrate_key_layout` rewrites them |
| `kadmin` — MIT's `kadm5` protocol over ONC RPC (feature `kadmin`) | done: init, get_privs, get/get_principals, create, delete, modify, rename, chpass, chrand, get/set/del string attributes, extract_keys, and the five policy procedures |
| `hdb::ad_blob` — `supplementalCredentials` (feature `hdb-ldap`) | done both ways: written as a projection with `Packages`, read back when `krb5Key` is absent — and refused without a declared version, because the blob cannot carry one. `Primary:Kerberos` is not written: it holds two DES keys by definition (§2.2.10.4/§2.2.10.5) and this crate has no DES, so filling it would put AES material under a DES key type |
| `hdb::ad_blob` — why not `Primary:Kerberos` | done: `Packages` is written as `Kerberos-Newer-Keys` in the table's spelling; the cost is named — Samba still refuses the blob without `Primary:Kerberos`, impacket/dissect/mimikatz/`secretsdump` read it |
| NT hash (`NTOWFv1`) | done: recorded when a password is set (`add_password_key`), `set_nt_hash_utf16` for a caller holding UTF-16LE octets, sealed at rest in the record (`[17]` with `mkvno`, `encode_with`) and in redb; written to a directory as Samba's `sambaNTPassword`, thirty-two upper-case hexadecimal digits, unsealed there because that is what the tools that read it expect |
| `kdc::pac` — the privilege attribute certificate | done: envelope, `PAC_CLIENT_INFO`, `KERB_VALIDATION_INFO`, both signatures |
| `kdc::logon_info` — NDR for `KERB_VALIDATION_INFO` | done: encoded by hand, checked by impacket and by a live client |
| `kdc::names` — RFC 6806 §6 enterprise names | done: `NT-ENTERPRISE` client names resolve to the principal they name when the request sets `canonicalize`, and are refused when it does not |
| `kdc::fast` — RFC 6113 FAST | done: armored AS exchange, the implicit armor of a TGS request, `hide-client-names`, `PA-ENCRYPTED-CHALLENGE` instead of a plain timestamp inside the armor, and the reply key strengthened by a secret that travels only in the armor |
| `kdc::pkinit` — RFC 4556 certificate login | done for both key-establishment forms and both reply forms: CMS verification and signing, the chain to a configured anchor, `id-pkinit-san` for the principal, `PA-PK-AS-REQ` → `PA-PK-AS-REP`, reply key per RFC 8636, `KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED` with the groups this realm accepts. Judged by `openssl cms -verify` and by tests that derive the key the client would, for DH and for each curve |
| `kdc::pkinit::anonymous` — RFC 8062 anonymous PKINIT | done: an unsigned `PA-PK-AS-REQ`, `WELLKNOWN/ANONYMOUS` in `WELLKNOWN:ANONYMOUS` with name type 11 and the anonymous flag, no authorization data, and the session key taken from `cf2` over the KDC's contribution in `PA-PKINIT-KX` so neither side picks it alone. Off unless a realm enables it; a build without the `pkinit` feature answers `KDC_ERR_NULL_KEY` |
| `kdc::s4u` — MS-SFU delegation | done: `PA-FOR-USER` with the checksum over the non-DER blob Heimdal and MIT both use, `PA-S4U-X509-USER`, and a constrained-delegation ACL read from the entry or from `msDS-AllowedToDelegateTo` |
| `kdc::req_enc_pa_rep` — RFC 6806 §11 | done: the request checksum in the *encrypted* part of the reply, the `enc-pa-rep` flag, and `PA-FX-FAST` beside it — which is how a client learns from FAST that S4U exists |
| `kdc::cookie` — RFC 6113 §5.4.2.3 `PA-FX-COOKIE` | done: opaque realm state, sealed under a key of its own; an expired, foreign or altered cookie is ignored rather than refused, because refusing would let a rewritten request break a legitimate login |
| `kdc::preauth` — the multi-round framework | done: `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED` (91), a mechanism trait that returns the reply key itself, and nothing advertised by a realm that configured nothing |
| `kdc::spake` — RFC 9588 SPAKE (feature `spake`) | done for `edwards25519`: the mask, the transcript, `K'[n]`, and the second factor that proves the password. Checked against the published vectors and accepted by `krb5` |
| `kdc::hwauth` — `require-hwauth` (`_kdc_hwauth_policy`) | done: the flag is now enforced, checked before any credential is validated so it cannot serve as a password oracle. Default policy is Heimdal's: a certificate admits (`PA_HARDWARE_AUTH` is set on the two PKINIT entries and nowhere else), everything else is refused with `KDC_ERR_POLICY`. `HwAuthPolicy` is the seam; `AllowList` is the configuration-shaped one. The flag *alone* does not force pre-authentication — Heimdal's check sits inside the pre-authentication loop — so it is meaningful together with `require-preauth`, and that is pinned by a test rather than left to be discovered |
| `kdc::audit` — the trail (`kdc/kdc-plugin.c`'s `audit` hook) | done: one `Record` per request, emitted by `Kdc::handle_from` — the only place that answers one — so an undecodable request is recorded too; the subject comes from the **reply** when a ticket is issued (after an alias, a canonicalization or `PA-FOR-USER`) and from the request when it is refused (a `KRB-ERROR` carries no client); the code is the one the client received. `Audit` cannot fail, so a full disk cannot refuse a login. Three layers: `Record` (the decision as data), `Audit` (takes records — batch, sign, ship), `AuditDriver` (takes the **record**, because an OTLP log record carries attributes and a rendered line has already thrown them away); a closure is a driver. For OpenTelemetry the mapping is part of the contract, not the exporter's invention: `Record::attributes` (`kerberos.*`, plus `client.address` where the semantic conventions define one), `Record::severity_number` (9 `INFO`, 13 `WARN` — a refusal is the KDC working, not a fault), body `Record::to_line`. `Collector`, `DriverAudit` over any driver, and `ToWriter` (flushes every line) ship |
| `kdc::otp` — RFC 6560 OTP (feature `otp`) | done for the `must-encrypt-nonce`-clear variant: `PA-OTP-CHALLENGE` → `PA-OTP-REQUEST` inside FAST armor, the nonce carried in a cookie and compared in constant time, and the reply key left as the armor key. Who judges a one-time value is the caller's `Verifier` |

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

## What Heimdal's KDC has and this one does not

The target is behavioural parity with Heimdal's `kdc/`, so the gaps are worth stating rather
than leaving to be discovered. Measured against `kdc/*.c` of the Heimdal tree and `src/` of
this crate.

Planned:

* **Replication** — see below; `hprop`/`hpropd` are written, a second domain controller is a
  decision rather than a task.
* **OTP's `must-encrypt-nonce` variant** (RFC 6560 §3.3) — where the one-time value never travels
  and generates the reply key instead. It needs the KDC to hold every token's current value, which
  this crate has no store for; the variant that asks a verifier is written.
* **SPAKE over the NIST groups** (RFC 9588 §12.2.2) — the exchange is written and accepted by
  `krb5`, for `edwards25519` only, which is the group that client asks for.
* **The rest of `kdc-plugin.c`'s hooks** — `check_access`, `referral_policy`, `finalize_reply`
  exist as behaviour but not as seams a deployment can replace; `pac_generate`/`pac_verify` are the
  `PacIdentities` seam.
* **Replication** (`kdc/hprop.c`, `hpropd.c`) — a second domain controller. Not planned work
  in the sense of "next": a decision was taken that one HDB is enough, so this sits at
  `deferred` rather than `todo`.

Done since an earlier version of this section listed them as absent, because a parity table
that does not move reads as a claim about the code:

* **S4U2Self / S4U2Proxy** (MS-SFU) — `src/kdc/s4u.rs`, with the delegation ACL read from a
  directory (`msDS-AllowedToDelegateTo`) or from the record backend.
* **`PA-FX-COOKIE`** (RFC 6113 §5.4.2.3) — `src/kdc/cookie.rs`. It was needed the moment SPAKE
  arrived, which is the only thing that makes an exchange multi-round.
* **`forwarded` and `proxy`** `kdc-options` — honoured in the TGS, including the refusal of a
  proxied TGT.
* **Enterprise names** (`NT-ENTERPRISE`, RFC 6806 §6), **anonymous PKINIT** (RFC 8062),
  **`PA-REQ-ENC-PA-REP`** (RFC 6806 §11), **SPAKE** (RFC 9588, `edwards25519`) and
  **OTP** (RFC 6560, FAST OTP).

Outside the intent: the Heimdal CA and its issuance protocols (`kdc/ca.c`, `kx509.c`,
`bx509.c`, `httpkadmind`), JWT and token validators, `mit_dump`, and `announce`. These serve
"Kerberos as a certificate authority", which is not what this crate is for. Of the seven,
only two are worth revisiting: **PKINIT key transport** and **PKINIT with elliptic curves**
(`lib/krb5/pkinit-ec.c`) are refused today by name, and a client is entitled to ask for
either.

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

- `rrl-crypto/tests/fixtures/mit-crypto.json` — MIT krb5's `crypto_tests` known answers
  (decrypt, checksum, derive, string-to-key).
- `tests/fixtures/nfold.json` — Heimdal 7.99.1 `n-fold-test.c`,
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
`AdminClient` — connect, handshake, `get_principals`, create, delete, `modprinc`,
`renprinc`, `chpass`, `chrand`, `getstr`/`setstr`/`delstr`, `extract_keys`, and then
log in with an ordinary client using the password that was just set or the keytab
the extracted keys built. Authorization is the same `Policy` the in-process and JSON
front ends use, so a `kadmin` user without rights gets MIT's `KADM5_AUTH_*` and no
data; `extract_keys` needs a right of its own, because handing out keys in the clear
is a stronger thing to be allowed than writing a keytab.

String attributes live in `HDB-Ext-Strings [16]`, an extension of this crate's own:
Heimdal has none (`setstr` is MIT's), and its `HDB-extension` CHOICE ends with `...`,
so a Heimdal KDC reading such an entry skips what it does not know.

**Policies** are `kadm5_policy_ent_rec` records, stored in the same database as the principals and
cited by name from an entry (`policy [12]`, Heimdal's own extension number). `addpol`, `getpol`,
`listpols`, `modpol` and `delpol` all answer a stock client, `modprinc -policy` puts an entry under
one, `getprinc` shows which, and a policy an entry cites cannot be deleted (`KADM5_POLICY_REF`) —
counted at the delete, not kept as a number that could drift.

What a policy *enforces* here is the password: length and character classes, checked before the keys
are derived and reported as `KADM5_PASS_Q_TOOSHORT` / `KADM5_PASS_Q_CLASS`, which are two different
fixes and therefore two different codes. What it does not yet enforce: `pw_min_life`, history
(`pw_history_num` is stored and reported, and nothing reads it), the failed-authentication lock-out,
and the ticket lifetimes (`max_life`, `max_renewable_life`), which the KDC still takes from the entry
and its own configuration. Those are named here rather than implied by a field that is accepted and
ignored.

Not implemented in the exchanges either, and refused by name rather than half-done:

| Missing | What a caller sees |
|---|---|
| PKINIT RSA key transport (`encKeyPack`) | `Unsupported`; MIT's own client rejects the mode too |
| PKINIT elliptic-curve ECDH | `Unsupported`, with the offered algorithm named |
| SPAKE over P-256 / P-384 / P-521 | `KDC_ERR_PREAUTH_FAILED` naming the groups asked for, and the client falls back |
| OTP outside FAST armor | `PA-OTP-CHALLENGE` is not offered at all, and a bare `PA-OTP-REQUEST` is refused by name |
| cross-realm (a `krbtgt` of another realm) | no ticket |

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
src/crypto         re-export of the `rrl-crypto` crate: enctypes, Key, Cipher, OwnCipher
  nfold.rs        RFC 3961 §5.1 n-fold
  kdf.rs          DR/DK, KDF-HMAC-SHA2, PBKDF2 string-to-key, usage constants
  aes_cts.rs      AES-CBC-CTS (RFC 3962 §5 / RFC 8009 §1)
  rskrb5_backend.rs  second backend, feature-gated
tests/vectors.rs  every vector, run against every backend
```

## Licence

MIT.
