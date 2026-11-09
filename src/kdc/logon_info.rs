//! `KERB_VALIDATION_INFO`: the structure that says who the client is and which
//! groups it holds ([MS-PAC] §2.5).
//!
//! This is the buffer a Windows service reads to decide what the client may do,
//! and it is the only part of a PAC that cannot be built from anything the KDC
//! knows by itself: the RID, the primary group and the group list belong to the
//! directory. So [`LogonInfo`] is data and [`encode`] is the encoder — nothing here
//! invents an identity.
//!
//! # Why a hand-rolled NDR encoder
//!
//! The structure is [C706] NDR, 32-bit transfer syntax: the fixed part, then the
//! referents its pointers point at, in the order the pointers appear.
//!
//! A PAC buffer holds this structure **from its first octet** — no
//! `TypeSerialization1` common header, no private header, and no leading pointer to
//! the structure. That form is what a marshalled RPC parameter carries, and writing
//! it here is the defect this module was first written with: the scalars then read
//! correctly and every string and array comes back empty, because each pointer is
//! short by the header's length. impacket reported exactly that, and it is the
//! reason the encoder is judged by somebody else's reader.
//!
//! Every pointer is an offset **from the first octet of the buffer**, which is the
//! structure's first octet. A reader follows it; land four octets early and the name
//! it prints belongs to nobody.
//!
//! # What is not written
//!
//! `UserSessionKey`, `LMKey` and the four password timestamps carry nothing a
//! modern realm has: they exist for NTLM fallback and for an account-policy UI.
//! They are written as zero rather than filled with something plausible, because a
//! service that read a fabricated NTLM key would try to authenticate with it.
//!
//! # Reference
//!
//! [MS-PAC] §2.5 for the fields and the buffer form, [C706] §14 for the encoding.

use crate::error::{Error, Result};

/// Seconds from the `FILETIME` epoch (1601-01-01) to the Unix one.
pub(crate) const FILETIME_UNIX_EPOCH_SECONDS: i64 = 11_644_473_600;

/// `FILETIME` ticks per second: one hundred nanoseconds each.
pub(crate) const FILETIME_TICKS_PER_SECOND: i64 = 10_000_000;

/// A security identifier, the form a directory keeps in `objectSid`.
///
/// Kept here as data with no allocation policy: this crate never decides which SID
/// an account gets. It has to be able to read one and to write it in NDR, which is
/// all [`Sid`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    /// Always 1 in practice; kept because the wire has a field for it.
    pub revision: u8,
    /// The identifier authority, six octets, big-endian in the text form.
    pub authority: [u8; 6],
    /// The sub-authorities: for a domain SID these are the three random words, and
    /// the last one of an account SID is its RID.
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// `S-1-5-21-a-b-c-rid`, the form a directory publishes and an operator types.
    pub fn parse(text: &str) -> Result<Self> {
        let mut parts = text.split('-');
        if parts.next() != Some("S") {
            return Err(Error::Protocol(format!(
                "{text} is not a SID: a SID starts with S-"
            )));
        }
        let revision: u8 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Protocol(format!("{text} is not a SID: no revision")))?;
        let authority: u64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Protocol(format!("{text} is not a SID: no authority")))?;
        if authority > 0xffff_ffff_ffff {
            return Err(Error::Protocol(format!(
                "{text}: the authority is six octets at most"
            )));
        }
        let mut sub_authorities = Vec::new();
        for part in parts {
            sub_authorities.push(part.parse::<u32>().map_err(|_| {
                Error::Protocol(format!(
                    "{text} is not a SID: {part} is not a sub-authority"
                ))
            })?);
        }
        if sub_authorities.len() > 15 {
            return Err(Error::Protocol(format!(
                "{text}: a SID has at most fifteen sub-authorities"
            )));
        }
        let mut octets = [0u8; 6];
        octets.copy_from_slice(&authority.to_be_bytes()[2..]);
        Ok(Sid {
            revision,
            authority: octets,
            sub_authorities,
        })
    }

    /// The binary form a directory stores: the same layout NDR writes, without the
    /// NDR array length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::Protocol(format!(
                "a SID of {} octets is shorter than its fixed part",
                bytes.len()
            )));
        }
        let count = bytes[1] as usize;
        if bytes.len() != 8 + count * 4 {
            return Err(Error::Protocol(format!(
                "a SID claims {count} sub-authorities but carries {} octets",
                bytes.len()
            )));
        }
        let mut authority = [0u8; 6];
        authority.copy_from_slice(&bytes[2..8]);
        let sub_authorities = bytes[8..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        Ok(Sid {
            revision: bytes[0],
            authority,
            sub_authorities,
        })
    }

    /// The last sub-authority, which is the RID of an account SID.
    pub fn rid(&self) -> Option<u32> {
        self.sub_authorities.last().copied()
    }

    /// The binary form, as `objectSid` holds it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.sub_authorities.len() * 4);
        out.push(self.revision);
        out.push(self.sub_authorities.len() as u8);
        out.extend_from_slice(&self.authority);
        for sub in &self.sub_authorities {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }

    /// The text form an operator types.
    pub fn to_text(&self) -> String {
        let authority = self
            .authority
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        let mut out = format!("S-{}-{authority}", self.revision);
        for sub in &self.sub_authorities {
            out.push_str(&format!("-{sub}"));
        }
        out
    }
}

/// Everything `KERB_VALIDATION_INFO` states about one logon.
///
/// Times are Unix seconds; the encoder converts them to `FILETIME`. The RIDs and the
/// SIDs come from the directory — nothing here is derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonInfo {
    /// When the logon happened.
    pub logon_time: i64,
    /// When it stops being valid; `i64::MAX / FILETIME_TICKS_PER_SECOND` for never.
    pub logoff_time: i64,
    /// When the session is cut; same convention.
    pub kick_off_time: i64,
    /// The account's name as the directory spells it.
    pub effective_name: String,
    /// A display name, empty when the directory has none.
    pub full_name: String,
    /// RID of the account, in the domain's SID space.
    pub user_id: u32,
    /// RID of the primary group — 513 for `Domain Users`.
    pub primary_group_id: u32,
    /// The groups the account holds, as `(RID, attributes)`. Each RID is relative to
    /// [`LogonInfo::logon_domain_id`].
    pub group_ids: Vec<(u32, u32)>,
    /// `userAccountControl` as the directory holds it.
    pub user_account_control: u32,
    /// `UserFlags`: a collection of `LOGON_*` bits, zero for an ordinary logon.
    pub user_flags: u32,
    /// The DC that authenticated the client.
    pub logon_server: String,
    /// The domain's own name, as NetBIOS spells it — `EXAMPLE`, not `EXAMPLE.COM`.
    pub logon_domain_name: String,
    /// The domain SID: the prefix every RID above is relative to.
    pub logon_domain_id: Sid,
    /// SIDs from other domains the account holds, with their attributes.
    pub extra_sids: Vec<(Sid, u32)>,
    /// `ResourceGroupDomainSid`; `None` writes a null pointer, which is what a
    /// realm without resource groups has.
    pub resource_group_domain_sid: Option<Sid>,
}

impl LogonInfo {
    /// The structure for `name` with a domain `Sid` and one RID, and everything
    /// else zero: the shape a realm has before anybody fills in a display name or a
    /// logon script.
    pub fn minimal(
        effective_name: impl Into<String>,
        user_id: u32,
        domain: Sid,
        logon_time: i64,
    ) -> Self {
        LogonInfo {
            logon_time,
            logoff_time: NO_EXPIRY,
            kick_off_time: NO_EXPIRY,
            effective_name: effective_name.into(),
            full_name: String::new(),
            user_id,
            primary_group_id: 513,
            group_ids: Vec::new(),
            user_account_control: 0x200,
            user_flags: 0,
            logon_server: String::new(),
            logon_domain_name: String::new(),
            logon_domain_id: domain,
            extra_sids: Vec::new(),
            resource_group_domain_sid: None,
        }
    }
}

/// The "never" value AD writes into `LogoffTime` and `KickOffTime`: the largest
/// `FILETIME` representable in a signed 64-bit field, in Unix seconds.
pub const NO_EXPIRY: i64 = i64::MAX / FILETIME_TICKS_PER_SECOND - FILETIME_UNIX_EPOCH_SECONDS;

/// An account's identity as a directory holds it: everything a PAC states that this
/// crate cannot derive.
///
/// Separate from [`LogonInfo`] because the two differ in who fills them in: the
/// directory knows the RID, the group list and the domain SID, and the KDC knows the
/// instant of the logon. Splitting them means an implementer cannot accidentally
/// invent a logon time, and this crate cannot accidentally invent a RID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The domain SID every RID below is relative to.
    pub domain: Sid,
    /// The domain's name as NetBIOS writes it — `EXAMPLE`, not `EXAMPLE.COM`. A
    /// reader compares it with the `LogonDomainName` a service already knows, and a
    /// DNS name there breaks that comparison.
    pub domain_name: String,
    /// The DC that authenticated the client, for `LogonServer`.
    pub logon_server: String,
    /// The account's RID, which is the last sub-authority of its `objectSid`.
    pub user_rid: u32,
    /// The RID of the account's primary group — 513 (`Domain Users`) by default in a
    /// realm, and whatever the directory says otherwise.
    pub primary_group: u32,
    /// The groups the account holds, as `(RID, attributes)` relative to [`Self::domain`].
    /// An empty list is a null pointer, which is what an account in no groups has.
    pub groups: Vec<(u32, u32)>,
    /// A display name; empty when the directory has none.
    pub full_name: String,
    /// `userAccountControl` as the directory holds it.
    pub user_account_control: u32,
    /// SIDs from other domains the account holds.
    pub extra_sids: Vec<(Sid, u32)>,
}

impl Identity {
    /// The logon information for a logon of `effective_name` at `logon_time`.
    ///
    /// `effective_name` is the name the ticket was issued for, which is not
    /// necessarily the directory's spelling of it: the ticket says `alice@REALM`, and
    /// an account whose `EffectiveName` disagreed with its `cname` would be two
    /// identities in one ticket.
    pub fn logon_info(&self, effective_name: impl Into<String>, logon_time: i64) -> LogonInfo {
        LogonInfo {
            logon_time,
            logoff_time: NO_EXPIRY,
            kick_off_time: NO_EXPIRY,
            effective_name: effective_name.into(),
            full_name: self.full_name.clone(),
            user_id: self.user_rid,
            primary_group_id: self.primary_group,
            group_ids: self.groups.clone(),
            user_account_control: self.user_account_control,
            user_flags: 0,
            logon_server: self.logon_server.clone(),
            logon_domain_name: self.domain_name.clone(),
            logon_domain_id: self.domain.clone(),
            extra_sids: self.extra_sids.clone(),
            resource_group_domain_sid: None,
        }
    }

    /// The account's own SID: the domain SID with the RID appended.
    pub fn user_sid(&self) -> Sid {
        let mut sid = self.domain.clone();
        sid.sub_authorities.push(self.user_rid);
        sid
    }
}

/// Where a PAC's identity comes from.
///
/// A trait rather than a field in the entry, because the answer lives in the
/// directory and this crate does not own directories: the server that embeds the KDC
/// has the `objectSid`, the group list and the domain SID already, and asking it is
/// the only way to get an answer that is not invented. The pattern is the same as
/// [`crate::kdc::ChangePolicy`] — a KDC with no directory returns `None` here and
/// issues tickets without a PAC, which is what a Kerberos-only realm does.
pub trait PacIdentities: Send + Sync {
    /// The identity behind `principal`, or `None` when the directory does not know
    /// it — in which case the ticket is issued without a PAC rather than with an
    /// empty one.
    fn identity(&self, principal: &crate::name::Principal) -> Result<Option<Identity>>;
}

/// The structure's fixed part, octet for octet: six `FILETIME`s, six
/// `RPC_UNICODE_STRING`s, then the counts, the SIDs and the pointers.
///
/// A PAC's `PAC_LOGON_INFO` is this structure at the very start of the buffer, with
/// the referents after it and every pointer an offset from octet zero — not the
/// `TypeSerialization1` form (a common header, a private header and a leading
/// pointer to the structure) that a marshalled RPC parameter would carry. Getting
/// that wrong is silent: the scalars still read correctly and only the strings and
/// the group array come back empty, which is exactly what impacket showed when this
/// encoder wrote the wrapped form.
const STRUCT_LEN: usize = 212;

/// `KERB_VALIDATION_INFO` for `info`, ready to be a `PAC_LOGON_INFO` buffer.
///
/// Deterministic: the same `LogonInfo` produces the same octets, so a test can
/// compare two encodings and an operator can compare two dumps.
pub fn encode(info: &LogonInfo) -> Result<Vec<u8>> {
    // Referents begin right after the structure, and every pointer is an offset
    // from the start of the buffer — the structure's first octet is offset zero.
    const DEEPEST: usize = STRUCT_LEN;
    let mut referents = Referents::new(DEEPEST);

    // The order of these calls is the order of the pointers in the structure, and
    // both the offsets and the byte order of the referent area depend on it.
    let effective_name = referents.string(&info.effective_name);
    let full_name = referents.string(&info.full_name);
    // AD writes these three as null pointers when it has nothing to say, and a
    // reader distinguishes "absent" from "empty" the same way.
    let logon_script = referents.null_pointer();
    let profile_path = referents.null_pointer();
    let home_directory = referents.null_pointer();
    let home_directory_drive = referents.null_pointer();
    let group_ids = referents.group_memberships(&info.group_ids);
    let logon_server = referents.string(&info.logon_server);
    let logon_domain_name = referents.string(&info.logon_domain_name);
    let logon_domain_id = referents.sid(&info.logon_domain_id);
    let extra_sids = referents.extra_sids(&info.extra_sids);
    let resource_group_domain_sid = match &info.resource_group_domain_sid {
        Some(sid) => referents.sid(sid),
        None => referents.null_pointer(),
    };

    let mut out = Vec::with_capacity(DEEPEST + referents.len());
    let start = out.len();
    // Six `FILETIME`s.
    for seconds in [
        info.logon_time,
        info.logoff_time,
        info.kick_off_time,
        // Nothing in a Kerberos realm records these three, and a service that read a
        // fabricated password age would show an account age nobody can explain.
        0,
        0,
        0,
    ] {
        out.extend_from_slice(&filetime(seconds)?.to_le_bytes());
    }
    for (length, pointer) in [
        (units(&info.effective_name), effective_name),
        (units(&info.full_name), full_name),
        (0, logon_script),
        (0, profile_path),
        (0, home_directory),
        (0, home_directory_drive),
    ] {
        let octets = (length * 2) as u16;
        out.extend_from_slice(&octets.to_le_bytes()); // Length
        out.extend_from_slice(&octets.to_le_bytes()); // MaximumLength
        out.extend_from_slice(&pointer.to_le_bytes());
    }
    out.extend_from_slice(&1u16.to_le_bytes()); // LogonCount
    out.extend_from_slice(&0u16.to_le_bytes()); // BadPasswordCount
    out.extend_from_slice(&info.user_id.to_le_bytes());
    out.extend_from_slice(&info.primary_group_id.to_le_bytes());
    out.extend_from_slice(&(info.group_ids.len() as u32).to_le_bytes()); // GroupCount
    out.extend_from_slice(&group_ids.to_le_bytes()); // GroupIds
    out.extend_from_slice(&info.user_flags.to_le_bytes());
    // `UserSessionKey`: zero, because this realm has no NTLM key to put there and a
    // plausible-looking one would be used.
    out.extend_from_slice(&[0u8; 16]);
    for (length, pointer) in [
        (units(&info.logon_server), logon_server),
        (units(&info.logon_domain_name), logon_domain_name),
    ] {
        let octets = (length * 2) as u16;
        out.extend_from_slice(&octets.to_le_bytes());
        out.extend_from_slice(&octets.to_le_bytes());
        out.extend_from_slice(&pointer.to_le_bytes());
    }
    out.extend_from_slice(&logon_domain_id.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]); // LMKey: zero, as `UserSessionKey` is
    out.extend_from_slice(&info.user_account_control.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // SubAuthStatus
    out.extend_from_slice(&0i64.to_le_bytes()); // LastSuccessfulILogon
    out.extend_from_slice(&0i64.to_le_bytes()); // LastFailedILogon
    out.extend_from_slice(&0u32.to_le_bytes()); // FailedILogonCount
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
    out.extend_from_slice(&(info.extra_sids.len() as u32).to_le_bytes()); // SidCount
    out.extend_from_slice(&extra_sids.to_le_bytes());
    out.extend_from_slice(&resource_group_domain_sid.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // ResourceGroupCount

    if out.len() != start + STRUCT_LEN {
        return Err(Error::Protocol(format!(
            "KERB_VALIDATION_INFO is {} octets, and the layout says {STRUCT_LEN}",
            out.len() - start
        )));
    }
    out.extend_from_slice(referents.as_slice());
    Ok(out)
}

/// A Unix time in `FILETIME` ticks, refusing what cannot be represented instead of
/// silently wrapping into a date in 1601.
pub(crate) fn filetime(seconds: i64) -> Result<i64> {
    seconds
        .checked_mul(FILETIME_TICKS_PER_SECOND)
        .and_then(|t| t.checked_add(FILETIME_UNIX_EPOCH_SECONDS * FILETIME_TICKS_PER_SECOND))
        .ok_or_else(|| Error::Protocol(format!("{seconds} is not representable as a FILETIME")))
}

/// The number of UTF-16 units a string occupies, which is what `Length` counts (in
/// octets, so twice this).
fn units(text: &str) -> usize {
    text.encode_utf16().count()
}

/// The referent area: the things the structure's pointers point at.
///
/// Built by appending, with each append returning the absolute offset it landed on.
/// Keeping the offset arithmetic in one place is what makes the "absolute from the
/// header" rule hold for every referent instead of for the first one only.
struct Referents {
    deep: usize,
    bytes: Vec<u8>,
}

impl Referents {
    fn new(deep: usize) -> Self {
        Referents {
            deep,
            bytes: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// The absolute offset the next referent will start at.
    fn here(&self) -> usize {
        self.deep + self.bytes.len()
    }

    /// Pads to the four-octet alignment every NDR referent starts on.
    fn align(&mut self) {
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
    }

    fn null_pointer(&mut self) -> u32 {
        0
    }

    /// A `[size_is][length_is] WCHAR *`: the maximum count, the offset, the actual
    /// count, then the characters.
    fn string(&mut self, text: &str) -> u32 {
        if text.is_empty() {
            return 0;
        }
        self.align();
        let pointer = self.here() as u32;
        let count = units(text) as u32;
        self.bytes.extend_from_slice(&count.to_le_bytes()); // MaximumCount
        self.bytes.extend_from_slice(&0u32.to_le_bytes()); // Offset
        self.bytes.extend_from_slice(&count.to_le_bytes()); // ActualCount
        for unit in text.encode_utf16() {
            self.bytes.extend_from_slice(&unit.to_le_bytes());
        }
        pointer
    }

    /// A conformant array of `GROUP_MEMBERSHIP { RelativeId, Attributes }`.
    fn group_memberships(&mut self, groups: &[(u32, u32)]) -> u32 {
        if groups.is_empty() {
            return 0;
        }
        self.align();
        let pointer = self.here() as u32;
        self.bytes
            .extend_from_slice(&(groups.len() as u32).to_le_bytes());
        for (rid, attributes) in groups {
            self.bytes.extend_from_slice(&rid.to_le_bytes());
            self.bytes.extend_from_slice(&attributes.to_le_bytes());
        }
        pointer
    }

    /// An `RPC_SID`: the revision, the count, the authority, then a conformant array
    /// of sub-authorities — the array's own length included, which is why this is
    /// four octets longer than `objectSid`.
    fn sid(&mut self, sid: &Sid) -> u32 {
        self.align();
        let pointer = self.here() as u32;
        self.bytes.push(sid.revision);
        self.bytes.push(sid.sub_authorities.len() as u8);
        self.bytes.extend_from_slice(&sid.authority);
        self.bytes
            .extend_from_slice(&(sid.sub_authorities.len() as u32).to_le_bytes());
        for sub in &sid.sub_authorities {
            self.bytes.extend_from_slice(&sub.to_le_bytes());
        }
        pointer
    }

    /// A conformant array of `KERB_SID_AND_ATTRIBUTES { Sid, Attributes }`, whose
    /// SIDs are referents of their own and therefore come after the array.
    fn extra_sids(&mut self, sids: &[(Sid, u32)]) -> u32 {
        if sids.is_empty() {
            return 0;
        }
        self.align();
        let pointer = self.here() as u32;
        self.bytes
            .extend_from_slice(&(sids.len() as u32).to_le_bytes());
        // The array is written first with its pointers left for the second pass,
        // because the SIDs it points at start only after the array ends.
        let array_at = self.bytes.len();
        self.bytes.resize(array_at + sids.len() * 8, 0);
        for (i, (sid, attributes)) in sids.iter().enumerate() {
            let referent = self.sid(sid);
            let at = array_at + i * 8;
            self.bytes[at..at + 4].copy_from_slice(&referent.to_le_bytes());
            self.bytes[at + 4..at + 8].copy_from_slice(&attributes.to_le_bytes());
        }
        pointer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> Sid {
        Sid::parse("S-1-5-21-100-200-300").unwrap()
    }

    fn info() -> LogonInfo {
        let mut info = LogonInfo::minimal("alice", 1105, domain(), 1_794_182_400);
        info.full_name = "Alice Example".into();
        info.group_ids = vec![(513, 7), (512, 7), (1106, 7)];
        info.logon_server = "DC1".into();
        info.logon_domain_name = "EXAMPLE".into();
        info
    }

    #[test]
    fn a_sid_round_trips_through_text_and_octets() {
        for text in [
            "S-1-5-21-100-200-300-1105",
            "S-1-5-18",
            "S-1-0-0",
            "S-1-5-32-544",
        ] {
            let sid = Sid::parse(text).unwrap();
            assert_eq!(sid.to_text(), text);
            assert_eq!(Sid::from_bytes(&sid.to_bytes()).unwrap(), sid);
        }
    }

    #[test]
    fn the_rid_is_the_last_sub_authority() {
        assert_eq!(
            Sid::parse("S-1-5-21-100-200-300-1105").unwrap().rid(),
            Some(1105)
        );
        assert_eq!(Sid::parse("S-1-5-21-100-200-300").unwrap().rid(), Some(300));
    }

    #[test]
    fn a_sid_that_is_not_one_is_refused_with_the_reason() {
        // The last one is 2^48, one more than six octets hold.
        for text in ["1-5-21-1", "S-x-5", "S-1-5-21-x", "S-1-281474976710656-1"] {
            let err = Sid::parse(text);
            assert!(err.is_err(), "{text} must be refused");
            let message = format!("{}", err.unwrap_err());
            assert!(
                message.contains("SID") || message.contains("authority"),
                "{text}: {message}"
            );
        }
        // Sixteen sub-authorities is one more than a SID holds.
        let long = format!("S-1-5-{}", vec!["1"; 16].join("-"));
        assert!(Sid::parse(&long).is_err());
    }

    #[test]
    fn a_sid_from_a_directory_is_read_suspiciously() {
        let good = domain().to_bytes();
        // A count that does not match the octets is a SID whose remainder would be
        // read as part of the next structure.
        let mut wrong = good.clone();
        wrong[1] = 9;
        assert!(Sid::from_bytes(&wrong).is_err());
        assert!(Sid::from_bytes(&good[..7]).is_err());
    }

    #[test]
    fn the_buffer_starts_with_the_structure_and_not_with_a_serialization_header() {
        // A `TypeSerialization1` wrapper — a common header, a private header and a
        // leading pointer — parses as a structure whose scalars are right and whose
        // strings are all empty, because every pointer then misses by the header's
        // length. That is what impacket showed, and this is the fact it pinned.
        let bytes = encode(&info()).unwrap();
        assert_eq!(
            u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
            0,
            "LogonCount is the first thing after the six FILETIMEs, not a version octet"
        );
        assert_eq!(
            i64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            filetime(1_794_182_400).unwrap(),
            "the buffer opens with LogonTime"
        );
    }

    #[test]
    fn the_structure_is_the_length_the_layout_says() {
        // The one number a hand-built encoder gets wrong: miss a field and every
        // referent after it points four octets into whatever follows.
        let bytes = encode(&info()).unwrap();
        assert!(bytes.len() > STRUCT_LEN);
        // The first referent starts exactly where the structure ends, and the
        // pointer to it says so.
        let effective_name_at =
            u32::from_le_bytes(bytes[48 + 4..48 + 8].try_into().unwrap()) as usize;
        assert_eq!(
            effective_name_at, STRUCT_LEN,
            "the first referent follows the structure, counted from octet zero"
        );
    }

    #[test]
    fn the_rid_and_the_primary_group_are_where_a_reader_looks() {
        let bytes = encode(&info()).unwrap();
        let user_id_at = 48 + 48 + 4;
        assert_eq!(
            u32::from_le_bytes(bytes[user_id_at..user_id_at + 4].try_into().unwrap()),
            1105,
            "UserId"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[user_id_at + 4..user_id_at + 8].try_into().unwrap()),
            513,
            "PrimaryGroupId"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[user_id_at + 8..user_id_at + 12].try_into().unwrap()),
            3,
            "GroupCount"
        );
    }

    #[test]
    fn a_name_of_different_length_moves_the_referents_by_the_same_amount() {
        // The check that would catch an encoder that counts characters instead of
        // UTF-16 units, or forgets the four-octet alignment between referents.
        let short = encode(&info()).unwrap();
        let mut longer = info();
        longer.full_name = "Alice Example With A Rather Long Display Name".into();
        let long = encode(&longer).unwrap();
        let difference = long.len() - short.len();
        let name_difference = (units(&longer.full_name) - units(&info().full_name)) * 2;
        assert_eq!(
            difference, name_difference,
            "only the name's own octets may change"
        );
    }

    #[test]
    fn the_encoding_is_the_same_octets_on_every_call() {
        assert_eq!(encode(&info()).unwrap(), encode(&info()).unwrap());
    }

    #[test]
    fn no_expiry_lands_on_the_largest_filetime_a_signed_field_holds() {
        let bytes = encode(&info()).unwrap();
        let logoff = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(
            logoff,
            i64::MAX / FILETIME_TICKS_PER_SECOND * FILETIME_TICKS_PER_SECOND
        );
        assert!(logoff > 0);
    }

    #[test]
    fn a_time_before_1601_is_refused() {
        let mut impossible = info();
        impossible.logon_time = i64::MIN;
        assert!(encode(&impossible).is_err());
    }

    #[test]
    fn an_account_with_no_groups_writes_a_null_group_array() {
        let mut bare = info();
        bare.group_ids.clear();
        let bytes = encode(&bare).unwrap();
        let group_ids_at = 48 + 48 + 4 + 8 + 4;
        assert_eq!(
            u32::from_le_bytes(bytes[group_ids_at..group_ids_at + 4].try_into().unwrap()),
            0,
            "an empty group list is a null pointer, not a pointer to an empty array"
        );
    }

    #[test]
    fn the_domain_sid_carries_its_own_array_length() {
        // `RPC_SID` writes the sub-authority count twice: once as an octet in the
        // fixed part and once as the conformant array's maximum count. A reader that
        // takes only the first finds the second where the first sub-authority is.
        let bytes = encode(&info()).unwrap();
        // `LogonDomainId`'s pointer: six FILETIMEs, six strings, then the counts and
        // the other pointers up to it.
        let pointer_at = 48 + 48 + 4 + 8 + 4 + 4 + 4 + 16 + 16;
        let sid_at =
            u32::from_le_bytes(bytes[pointer_at..pointer_at + 4].try_into().unwrap()) as usize;
        assert_eq!(bytes[sid_at], 1, "Revision");
        assert_eq!(bytes[sid_at + 1], 4, "S-1-5-21-100-200-300 has four");
        assert_eq!(
            u32::from_le_bytes(bytes[sid_at + 8..sid_at + 12].try_into().unwrap()),
            4,
            "and the array's maximum count says the same"
        );
    }
}
