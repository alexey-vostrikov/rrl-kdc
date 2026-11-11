//! The JSON form of [`crate::admin::wire`], for a transport that speaks HTTP.
//!
//! # What a transport needs, and nothing more
//!
//! `serde_json::from_str::<AdminRequest>()` in, `serde_json::to_value(&Reply)`
//! out, and `serde_json::to_value(&Error)` when it fails. That is the whole
//! contract, and it is why the conversions live here rather than in the embedder:
//! two HTTP front ends that each invented their own spelling of "set password"
//! would be two APIs.
//!
//! # Three decisions worth naming
//!
//! * **Binary travels as base64, never as an array of numbers.** A bare `Vec<u8>`
//!   serializes to `[115,101,99,...]`: valid JSON, twice the size, and legible in
//!   whatever log it passes through. base64 hides nothing — the transport still
//!   has to be TLS — but it stops the password from being printed as octets.
//! * **A misspelled field is an error.** `deny_unknown_fields`, because
//!   `{"invalidat": true}` silently dropped leaves an operator believing they
//!   disabled an account.
//! * **`null` means "clear", absent means "leave alone".** With a plain
//!   `Option`, both arrive as `None` and a modify that meant to change one field
//!   clears the others.

use std::result::Result as StdResult;

use serde::de::Error as _;
use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::admin::wire::{AdminRequest, EntryView, Operation, Reply};
use crate::admin::{Modify, Role};

impl Serialize for Role {
    fn serialize<S: Serializer>(&self, serializer: S) -> StdResult<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Role::Client => "client",
            Role::Server => "server",
            Role::Both => "both",
        })
    }
}

impl<'de> Deserialize<'de> for Role {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> StdResult<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "client" => Ok(Role::Client),
            "server" => Ok(Role::Server),
            "both" => Ok(Role::Both),
            other => Err(D::Error::custom(format!(
                "{other:?} is not a role: expected client, server or both"
            ))),
        }
    }
}

/// `Option<Option<T>>` where an explicit `null` means "clear the field".
///
/// `serde` maps `null` to the outer `None`, which makes "clear" and "do not
/// touch" indistinguishable. Here the field is only deserialized when it is
/// present, so presence with `null` becomes `Some(None)`.
/// Reading half of the double option. The writing half is not here: `Modify`
/// serializes by hand, because `skip_serializing_if` on a derived struct would
/// need one attribute per field and this file already has the list.
mod double_option {
    use super::{Deserialize, Deserializer, StdResult};

    pub fn deserialize<'de, D, T>(deserializer: D) -> StdResult<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Ok(Some(Option::<T>::deserialize(deserializer)?))
    }
}

impl Serialize for Modify {
    fn serialize<S: Serializer>(&self, serializer: S) -> StdResult<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Modify", 6)?;
        if let Some(v) = self.invalid {
            out.serialize_field("invalid", &v)?;
        }
        if let Some(v) = self.locked_out {
            out.serialize_field("locked_out", &v)?;
        }
        if let Some(v) = self.valid_end {
            out.serialize_field("valid_end", &v)?;
        }
        if let Some(v) = self.pw_end {
            out.serialize_field("pw_end", &v)?;
        }
        if let Some(v) = self.max_life {
            out.serialize_field("max_life", &v)?;
        }
        if let Some(v) = self.ok_as_delegate {
            out.serialize_field("ok_as_delegate", &v)?;
        }
        out.end()
    }
}

impl<'de> Deserialize<'de> for Modify {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> StdResult<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                with = "double_option"
            )]
            valid_end: Option<Option<i64>>,
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                with = "double_option"
            )]
            pw_end: Option<Option<i64>>,
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                with = "double_option"
            )]
            max_life: Option<Option<i64>>,
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                with = "double_option"
            )]
            max_renew: Option<Option<i64>>,
            #[serde(default)]
            invalid: Option<bool>,
            #[serde(default)]
            locked_out: Option<bool>,
            #[serde(default)]
            ok_as_delegate: Option<bool>,
            #[serde(default)]
            require_preauth: Option<bool>,
            #[serde(default)]
            require_hwauth: Option<bool>,
            #[serde(default)]
            allow_server: Option<bool>,
            #[serde(default)]
            change_password_service: Option<bool>,
            #[serde(default)]
            forwardable: Option<bool>,
            #[serde(default)]
            proxiable: Option<bool>,
            #[serde(default)]
            renewable: Option<bool>,
            #[serde(default)]
            postdated: Option<bool>,
            #[serde(default)]
            kvno: Option<u32>,
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                with = "double_option"
            )]
            policy: Option<Option<String>>,
        }
        let fields = Fields::deserialize(deserializer)?;
        Ok(Modify {
            policy: fields.policy,
            invalid: fields.invalid,
            locked_out: fields.locked_out,
            valid_end: fields.valid_end,
            pw_end: fields.pw_end,
            max_life: fields.max_life,
            max_renew: fields.max_renew,
            ok_as_delegate: fields.ok_as_delegate,
            require_preauth: fields.require_preauth,
            require_hwauth: fields.require_hwauth,
            allow_server: fields.allow_server,
            change_password_service: fields.change_password_service,
            forwardable: fields.forwardable,
            proxiable: fields.proxiable,
            renewable: fields.renewable,
            postdated: fields.postdated,
            kvno: fields.kvno,
        })
    }
}

impl Serialize for Operation {
    fn serialize<S: Serializer>(&self, serializer: S) -> StdResult<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Operation", 5)?;
        match self {
            Operation::List => out.serialize_field("operation", "list")?,
            Operation::Get { principal } => {
                out.serialize_field("operation", "get")?;
                out.serialize_field("principal", principal)?;
            }
            Operation::Create {
                principal,
                password,
                enctypes,
                role,
            } => {
                out.serialize_field("operation", "create")?;
                out.serialize_field("principal", principal)?;
                out.serialize_field("password", &Base64(password))?;
                out.serialize_field("enctypes", enctypes)?;
                out.serialize_field("role", role)?;
            }
            Operation::Modify { principal, change } => {
                out.serialize_field("operation", "modify")?;
                out.serialize_field("principal", principal)?;
                out.serialize_field("change", change)?;
            }
            Operation::Rename { from, to } => {
                out.serialize_field("operation", "rename")?;
                out.serialize_field("from", from)?;
                out.serialize_field("to", to)?;
            }
            Operation::Delete { principal } => {
                out.serialize_field("operation", "delete")?;
                out.serialize_field("principal", principal)?;
            }
            Operation::SetPassword {
                principal,
                password,
            } => {
                out.serialize_field("operation", "set_password")?;
                out.serialize_field("principal", principal)?;
                out.serialize_field("password", &Base64(password))?;
            }
            Operation::CreatePolicy { policy } => {
                out.serialize_field("operation", "create_policy")?;
                out.serialize_field("policy", policy)?;
            }
            Operation::ModifyPolicy { policy } => {
                out.serialize_field("operation", "modify_policy")?;
                out.serialize_field("policy", policy)?;
            }
            Operation::DeletePolicy { name } => {
                out.serialize_field("operation", "delete_policy")?;
                out.serialize_field("name", name)?;
            }
            Operation::Policy { name } => {
                out.serialize_field("operation", "policy")?;
                out.serialize_field("name", name)?;
            }
            Operation::Policies => {
                out.serialize_field("operation", "policies")?;
            }
            Operation::Strings { principal } => {
                out.serialize_field("operation", "strings")?;
                out.serialize_field("principal", principal)?;
            }
            Operation::SetString {
                principal,
                key,
                value,
            } => {
                out.serialize_field("operation", "set_string")?;
                out.serialize_field("principal", principal)?;
                out.serialize_field("key", key)?;
                // `delstr` is the same operation with no value, and JSON's `null` is how a caller
                // spells it.
                out.serialize_field("value", value)?;
            }
            Operation::PruneOldKeys { principal } => {
                out.serialize_field("operation", "prune_old_keys")?;
                out.serialize_field("principal", principal)?;
            }
            Operation::Keytab { principals } => {
                out.serialize_field("operation", "keytab")?;
                out.serialize_field("principals", principals)?;
            }
        }
        out.end()
    }
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> StdResult<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            List,
            Get {
                principal: crate::name::Principal,
            },
            Create {
                principal: crate::name::Principal,
                #[serde(with = "base64_option")]
                password: Option<Vec<u8>>,
                #[serde(default)]
                enctypes: Vec<crate::crypto::Enctype>,
                role: Role,
            },
            Modify {
                principal: crate::name::Principal,
                change: Modify,
            },
            Rename {
                from: crate::name::Principal,
                to: crate::name::Principal,
            },
            CreatePolicy {
                policy: crate::hdb::Policy,
            },
            ModifyPolicy {
                policy: crate::hdb::Policy,
            },
            DeletePolicy {
                name: String,
            },
            Policy {
                name: String,
            },
            Policies,
            Strings {
                principal: crate::name::Principal,
            },
            SetString {
                principal: crate::name::Principal,
                key: String,
                #[serde(default)]
                value: Option<String>,
            },
            Delete {
                principal: crate::name::Principal,
            },
            SetPassword {
                principal: crate::name::Principal,
                #[serde(with = "base64_option")]
                password: Option<Vec<u8>>,
            },
            PruneOldKeys {
                principal: crate::name::Principal,
            },
            Keytab {
                principals: Vec<crate::name::Principal>,
            },
        }

        Ok(match Wire::deserialize(deserializer)? {
            Wire::List => Operation::List,
            Wire::Get { principal } => Operation::Get { principal },
            Wire::Create {
                principal,
                password,
                enctypes,
                role,
            } => Operation::Create {
                principal,
                password: require::<D::Error>(password, "create")?,
                enctypes,
                role,
            },
            Wire::Modify { principal, change } => Operation::Modify { principal, change },
            Wire::Rename { from, to } => Operation::Rename { from, to },
            Wire::CreatePolicy { policy } => Operation::CreatePolicy { policy },
            Wire::ModifyPolicy { policy } => Operation::ModifyPolicy { policy },
            Wire::DeletePolicy { name } => Operation::DeletePolicy { name },
            Wire::Policy { name } => Operation::Policy { name },
            Wire::Policies => Operation::Policies,
            Wire::Strings { principal } => Operation::Strings { principal },
            Wire::SetString {
                principal,
                key,
                value,
            } => Operation::SetString {
                principal,
                key,
                value,
            },
            Wire::Delete { principal } => Operation::Delete { principal },
            Wire::SetPassword {
                principal,
                password,
            } => Operation::SetPassword {
                principal,
                password: require::<D::Error>(password, "set_password")?,
            },
            Wire::PruneOldKeys { principal } => Operation::PruneOldKeys { principal },
            Wire::Keytab { principals } => Operation::Keytab { principals },
        })
    }
}

/// A password the request did not carry is a mistake, not an empty password.
///
/// The distinction matters: an absent field defaulted to `""` would reach
/// `set_password`, which refuses an empty password anyway — but with a message
/// about the password being empty rather than about it being missing.
fn require<E: serde::de::Error>(
    password: Option<Vec<u8>>,
    operation: &str,
) -> StdResult<Vec<u8>, E> {
    password.ok_or_else(|| E::custom(format!("{operation} needs a `password` field")))
}

impl Serialize for AdminRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> StdResult<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("AdminRequest", 2)?;
        out.serialize_field("actor", &self.actor)?;
        out.serialize_field("operation", &self.operation)?;
        out.end()
    }
}

impl<'de> Deserialize<'de> for AdminRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> StdResult<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            actor: crate::name::Principal,
            operation: Operation,
        }
        let fields = Fields::deserialize(deserializer)?;
        Ok(AdminRequest {
            actor: fields.actor,
            operation: fields.operation,
        })
    }
}

impl Serialize for EntryView {
    fn serialize<S: Serializer>(&self, serializer: S) -> StdResult<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("EntryView", 9)?;
        out.serialize_field("principal", &self.principal)?;
        out.serialize_field("kvno", &self.kvno)?;
        out.serialize_field("flags", &self.flags)?;
        out.serialize_field("key_count", &self.key_count)?;
        out.serialize_field("enctypes", &self.enctypes)?;
        out.serialize_field("valid_start", &self.valid_start)?;
        out.serialize_field("valid_end", &self.valid_end)?;
        out.serialize_field("pw_end", &self.pw_end)?;
        out.serialize_field("max_life", &self.max_life)?;
        out.end()
    }
}

impl Serialize for Reply {
    /// A tagged object: `{"reply": "created", "entry": {...}}`.
    ///
    /// Written by hand rather than derived because an internally tagged enum in
    /// `serde` cannot hold a newtype variant around a sequence, and flattening the
    /// variants until it can would have made `Message::Principals(Vec<_>)` into a
    /// struct the caller has to destructure for no reason.
    fn serialize<S: Serializer>(&self, serializer: S) -> StdResult<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        match self {
            Reply::Principals { principals } => {
                map.serialize_entry("reply", "principals")?;
                map.serialize_entry("principals", principals)?;
            }
            Reply::Entry { entry } => {
                map.serialize_entry("reply", "entry")?;
                map.serialize_entry("entry", entry)?;
            }
            Reply::Created { entry } => {
                map.serialize_entry("reply", "created")?;
                map.serialize_entry("entry", entry)?;
            }
            Reply::Modified { entry } => {
                map.serialize_entry("reply", "modified")?;
                map.serialize_entry("entry", entry)?;
            }
            Reply::Policy { policy } => {
                map.serialize_entry("reply", "policy")?;
                map.serialize_entry("policy", policy)?;
            }
            Reply::Policies { names } => {
                map.serialize_entry("reply", "policies")?;
                map.serialize_entry("names", names)?;
            }
            Reply::Strings { strings } => {
                map.serialize_entry("reply", "strings")?;
                map.serialize_entry("strings", strings)?;
            }
            Reply::Renamed { from, to } => {
                map.serialize_entry("reply", "renamed")?;
                map.serialize_entry("from", from)?;
                map.serialize_entry("to", to)?;
            }
            Reply::PasswordSet { kvno } => {
                map.serialize_entry("reply", "password_set")?;
                map.serialize_entry("kvno", kvno)?;
            }
            Reply::Pruned { removed } => {
                map.serialize_entry("reply", "pruned")?;
                map.serialize_entry("removed", removed)?;
            }
            Reply::Deleted { existed } => {
                map.serialize_entry("reply", "deleted")?;
                map.serialize_entry("existed", existed)?;
            }
            Reply::Keytab { bytes } => {
                map.serialize_entry("reply", "keytab")?;
                map.serialize_entry("keytab", &Base64(bytes))?;
            }
        }
        map.end()
    }
}

/// Bytes as a base64 string.
struct Base64<'a>(&'a [u8]);

impl Serialize for Base64<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> StdResult<S::Ok, S::Error> {
        serializer.serialize_str(&base64_encode(self.0))
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Reading half of a base64 field: absent stays absent, present must decode.
mod base64_option {
    use super::StdResult;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> StdResult<Option<Vec<u8>>, D::Error> {
        let text = Option::<String>::deserialize(deserializer)?;
        match text {
            None => Ok(None),
            Some(text) => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(text.as_bytes())
                    .map(Some)
                    .map_err(serde::de::Error::custom)
            }
        }
    }
}
