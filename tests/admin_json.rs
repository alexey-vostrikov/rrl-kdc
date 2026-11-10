//! The JSON form of the administrator's vocabulary.
//!
//! A REST layer built on this crate has to be able to write
//!
//! ```text
//! router.route("/admin", post(|body| admin.handle(serde_json::from_str(&body)?)))
//! ```
//!
//! and nothing else. So the types carry their own `Serialize`/`Deserialize`, the
//! error carries a machine-readable `kind` for the status code, and the two kinds
//! of binary the operations move — a password and a keytab — have a textual form,
//! because JSON has no octets.
//!
//! What this file deliberately does *not* test is that base64 hides anything. It
//! does not: a password in a request body is a password in a request body, and
//! the transport is expected to be TLS.
#![cfg(feature = "admin-json")]

use std::sync::Arc;

use rrl_kdc::admin::wire::{AdminRequest, Grants, Operation, Rights};
use rrl_kdc::admin::{Admin, Modify, Role};
use rrl_kdc::crypto::{Enctype, OwnCipher};
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";

fn p(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

fn realm() -> Admin {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();
    Admin::with_defaults(REALM, Arc::new(db) as Arc<dyn Hdb>, Arc::new(cipher))
        .with_policy(Arc::new(Grants::new().grant(&p("admin"), Rights::ALL)))
}

#[test]
fn a_request_survives_json() {
    let original = AdminRequest {
        actor: p("admin"),
        operation: Operation::SetPassword {
            principal: p("alice"),
            password: b"correct horse battery staple".to_vec(),
        },
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: AdminRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, original);
}

#[test]
fn the_password_travels_as_a_base64_string_and_never_as_an_int_array() {
    // An array of numbers is what a bare `Vec<u8>` gives you: valid JSON, twice
    // the size, and readable in a log as the password's octets.
    let request = AdminRequest {
        actor: p("admin"),
        operation: Operation::SetPassword {
            principal: p("alice"),
            password: b"secret".to_vec(),
        },
    };
    let json = serde_json::to_string(&request).unwrap();
    assert!(
        !json.contains("[115,101,99,114,101,116]"),
        "the password must not be serialized as an array of octets: {json}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let password = parsed["operation"]["password"]
        .as_str()
        .expect("the password must be a string");
    assert_eq!(password, "c2VjcmV0");
}

#[test]
fn a_reply_survives_json_and_carries_the_shape_the_transport_needs() {
    let admin = realm();
    let reply = admin
        .handle(AdminRequest {
            actor: p("admin"),
            operation: Operation::Create {
                principal: p("alice"),
                password: b"a password".to_vec(),
                enctypes: Vec::new(),
                role: Role::Client,
            },
        })
        .unwrap();
    let json = serde_json::to_value(&reply).unwrap();
    assert_eq!(json["reply"], "created");
    assert_eq!(json["entry"]["principal"], "alice@EXAMPLE.COM");
    assert_eq!(json["entry"]["kvno"], 1);

    let listed = admin
        .handle(AdminRequest {
            actor: p("admin"),
            operation: Operation::List,
        })
        .unwrap();
    let json = serde_json::to_value(&listed).unwrap();
    assert_eq!(json["reply"], "principals");
    let listed: Vec<&str> = json["principals"]
        .as_array()
        .expect("principals must be an array")
        .iter()
        .map(|p| p.as_str().expect("each principal must be a string"))
        .collect();
    assert!(
        listed.contains(&"alice@EXAMPLE.COM"),
        "the realm's accounts and its krbtgt are both listed, in the backend's order: {listed:?}"
    );
}

#[test]
fn a_keytab_comes_back_as_base64_and_parses_back_into_a_keytab() {
    use rrl_kdc::hdb::Keytab;
    let admin = realm();
    admin
        .handle(AdminRequest {
            actor: p("admin"),
            operation: Operation::Create {
                principal: p("host/h"),
                password: b"service key".to_vec(),
                enctypes: Vec::new(),
                role: Role::Server,
            },
        })
        .unwrap();
    let reply = admin
        .handle(AdminRequest {
            actor: p("admin"),
            operation: Operation::Keytab {
                principals: vec![p("host/h")],
            },
        })
        .unwrap();
    let json = serde_json::to_value(&reply).unwrap();
    let encoded = json["keytab"]
        .as_str()
        .expect("the keytab must be a base64 string");
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .expect("it must decode");
    let keytab = Keytab::parse(&bytes).expect("and it must still be a keytab file");
    assert_eq!(keytab.entries().len(), 4);
}

#[test]
fn an_error_is_a_kind_the_transport_can_map_to_a_status() {
    let admin = realm();
    let err = admin
        .handle(AdminRequest {
            actor: p("admin"),
            operation: Operation::Get {
                principal: p("nobody"),
            },
        })
        .unwrap_err();
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["kind"], "not_found");
    assert!(
        json["message"]
            .as_str()
            .is_some_and(|m| m.contains("nobody")),
        "the message must name what was missing: {json}"
    );
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    // A typo in `{"change": {"invalid": true}}` silently ignored would have an
    // operator believe they disabled an account. The parse has to fail instead.
    let json = r#"{"actor":"admin@EXAMPLE.COM","operation":{"operation":"modify",
        "principal":"alice@EXAMPLE.COM","change":{"invalidat":true}}}"#;
    assert!(
        serde_json::from_str::<AdminRequest>(json).is_err(),
        "a misspelled field must not be dropped"
    );
}

#[test]
fn a_modify_can_clear_a_field_and_distinguish_that_from_not_touching_it() {
    // `null` means "clear", absent means "leave alone". With `Option<Option<_>>`
    // that distinction survives a round trip; with a plain `Option` it does not,
    // and every request would silently clear what it did not mention.
    let json = r#"{"actor":"admin@EXAMPLE.COM","operation":{"operation":"modify",
        "principal":"alice@EXAMPLE.COM","change":{"valid_end":null}}}"#;
    let request: AdminRequest = serde_json::from_str(json).unwrap();
    let Operation::Modify { ref change, .. } = request.operation else {
        panic!("expected a modify");
    };
    assert_eq!(change.valid_end, Some(None), "null must mean clear");
    assert_eq!(change.pw_end, None, "absent must mean leave alone");

    let round = serde_json::to_string(&request).unwrap();
    let back: AdminRequest = serde_json::from_str(&round).unwrap();
    assert_eq!(back, request);
    let _ = Modify::default();
}

#[test]
fn the_request_never_serializes_a_field_the_operation_does_not_use() {
    // A `Get` that also carries `password` and `role` invites a transport to
    // start reading fields that are not part of the operation.
    let json = serde_json::to_value(AdminRequest {
        actor: p("admin"),
        operation: Operation::Get {
            principal: p("alice"),
        },
    })
    .unwrap();
    let operation = json["operation"].as_object().unwrap();
    assert_eq!(
        operation.keys().collect::<Vec<_>>(),
        vec!["operation", "principal"],
        "got {operation:?}"
    );
}

// ---------------------------------------------------------------------------
// Every operation, in both directions
// ---------------------------------------------------------------------------

/// One request per [`Operation`] variant.
fn every_operation() -> Vec<AdminRequest> {
    let actor = p("admin");
    vec![
        AdminRequest {
            actor: actor.clone(),
            operation: Operation::List,
        },
        AdminRequest {
            actor: actor.clone(),
            operation: Operation::Get {
                principal: p("alice"),
            },
        },
        AdminRequest {
            actor: actor.clone(),
            operation: Operation::Create {
                principal: p("alice"),
                password: b"a password".to_vec(),
                enctypes: vec![Enctype::Aes256Sha1, Enctype::Aes128Sha256],
                role: Role::Both,
            },
        },
        AdminRequest {
            actor: actor.clone(),
            operation: Operation::Create {
                principal: p("host/h"),
                password: Vec::new(),
                enctypes: Vec::new(),
                role: Role::Server,
            },
        },
        AdminRequest {
            actor: actor.clone(),
            operation: Operation::Modify {
                principal: p("alice"),
                change: Modify {
                    invalid: Some(true),
                    locked_out: Some(false),
                    valid_end: Some(Some(1_700_000_000)),
                    pw_end: Some(None),
                    max_life: Some(Some(86_400)),
                    ok_as_delegate: Some(true),
                },
            },
        },
        AdminRequest {
            actor: actor.clone(),
            operation: Operation::Delete {
                principal: p("alice"),
            },
        },
        AdminRequest {
            actor: actor.clone(),
            operation: Operation::SetPassword {
                principal: p("alice"),
                password: b"a new password".to_vec(),
            },
        },
        AdminRequest {
            actor: actor.clone(),
            operation: Operation::PruneOldKeys {
                principal: p("alice"),
            },
        },
        AdminRequest {
            actor,
            operation: Operation::Keytab {
                principals: vec![p("host/h"), Principal::krbtgt(REALM)],
            },
        },
    ]
}

#[test]
fn every_operation_survives_json_in_both_directions() {
    // A variant whose serializer was written but never read back is a variant
    // whose spelling disagrees with itself, and the REST client is the one who
    // finds out.
    for request in every_operation() {
        let json = serde_json::to_string(&request).expect("every operation must serialize");
        let back: AdminRequest =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}\nfor {json}"));
        assert_eq!(back, request, "round trip changed the request: {json}");
    }
}

#[test]
fn every_operation_tags_itself_with_a_stable_name() {
    // The tag is the wire contract: renaming one breaks a client, so the list is
    // written out rather than derived in the test as well.
    let expected = [
        "list",
        "get",
        "create",
        "create",
        "modify",
        "delete",
        "set_password",
        "prune_old_keys",
        "keytab",
    ];
    for (request, want) in every_operation().into_iter().zip(expected) {
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["operation"]["operation"], want);
    }
}

#[test]
fn an_empty_password_survives_as_an_empty_string_not_as_a_missing_field() {
    // An entry keyed only from a keytab has no password, and `create` must accept
    // that. Absent and empty are different fields on the wire: one is an error
    // for `set_password`, the other is how a service is made without a password.
    let request = AdminRequest {
        actor: p("admin"),
        operation: Operation::Create {
            principal: p("host/h"),
            password: Vec::new(),
            enctypes: Vec::new(),
            role: Role::Server,
        },
    };
    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["operation"]["password"], "");
    let back: AdminRequest = serde_json::from_value(json).unwrap();
    assert_eq!(back, request);
}

#[test]
fn a_missing_password_is_refused_with_a_message_that_says_so() {
    let json = r#"{"actor":"admin@EXAMPLE.COM",
        "operation":{"operation":"set_password","principal":"alice@EXAMPLE.COM"}}"#;
    let err = serde_json::from_str::<AdminRequest>(json)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("password"),
        "the message must name the missing field, got: {err}"
    );
}

#[test]
fn a_password_that_is_not_base64_is_refused() {
    let json = r#"{"actor":"admin@EXAMPLE.COM",
        "operation":{"operation":"set_password","principal":"alice@EXAMPLE.COM","password":"!!!"}}"#;
    assert!(
        serde_json::from_str::<AdminRequest>(json).is_err(),
        "garbage in the password field must not decode to garbage keys"
    );
}

#[test]
fn an_unknown_role_is_refused() {
    let json = r#"{"actor":"admin@EXAMPLE.COM","operation":{"operation":"create",
        "principal":"alice@EXAMPLE.COM","password":"cHc=","role":"superuser"}}"#;
    let err = serde_json::from_str::<AdminRequest>(json)
        .unwrap_err()
        .to_string();
    assert!(err.contains("role") || err.contains("superuser"), "{err}");
}

#[test]
fn an_unknown_operation_is_refused() {
    let json = r#"{"actor":"admin@EXAMPLE.COM","operation":{"operation":"destroy_realm"}}"#;
    assert!(
        serde_json::from_str::<AdminRequest>(json).is_err(),
        "an operation the server does not implement must not be ignored"
    );
}

#[test]
fn a_field_the_operation_does_not_have_is_refused() {
    // `set_password` with a `role` is a client that meant `create`, or a version
    // mismatch. Either way, dropping the field silently is worse than a 400.
    let json = r#"{"actor":"admin@EXAMPLE.COM","operation":{"operation":"set_password",
        "principal":"alice@EXAMPLE.COM","password":"cHc=","role":"client"}}"#;
    assert!(serde_json::from_str::<AdminRequest>(json).is_err());
}

#[test]
fn every_reply_serializes_with_its_own_tag_and_payload() {
    use rrl_kdc::admin::wire::{EntryView, Reply};

    let view = EntryView {
        principal: p("alice"),
        kvno: 2,
        flags: 0x40,
        key_count: 4,
        enctypes: vec![Enctype::Aes256Sha1],
        valid_start: None,
        valid_end: Some(1_700_000_000),
        pw_end: None,
        max_life: Some(86_400),
    };
    let cases: Vec<(Reply, &str, &str)> = vec![
        (
            Reply::Principals {
                principals: vec![p("alice")],
            },
            "principals",
            "principals",
        ),
        (
            Reply::Entry {
                entry: view.clone(),
            },
            "entry",
            "entry",
        ),
        (
            Reply::Created {
                entry: view.clone(),
            },
            "created",
            "entry",
        ),
        (
            Reply::Modified {
                entry: view.clone(),
            },
            "modified",
            "entry",
        ),
        (Reply::PasswordSet { kvno: 3 }, "password_set", "kvno"),
        (Reply::Pruned { removed: 2 }, "pruned", "removed"),
        (Reply::Deleted { existed: false }, "deleted", "existed"),
        (
            Reply::Keytab {
                bytes: b"file".to_vec(),
            },
            "keytab",
            "keytab",
        ),
    ];
    for (reply, tag, payload) in cases {
        let json = serde_json::to_value(&reply).unwrap();
        assert_eq!(json["reply"], tag, "wrong tag for {reply:?}");
        assert!(
            !json[payload].is_null(),
            "{tag} must carry `{payload}`: {json}"
        );
        assert_eq!(
            json.as_object().unwrap().len(),
            2,
            "a reply carries its tag and one payload, got: {json}"
        );
    }
}

#[test]
fn an_entry_view_serializes_every_field_a_caller_may_read() {
    let admin = realm();
    admin
        .handle(AdminRequest {
            actor: p("admin"),
            operation: Operation::Create {
                principal: p("alice"),
                password: b"pw".to_vec(),
                enctypes: Vec::new(),
                role: Role::Client,
            },
        })
        .unwrap();
    let reply = admin
        .handle(AdminRequest {
            actor: p("admin"),
            operation: Operation::Get {
                principal: p("alice"),
            },
        })
        .unwrap();
    let json = serde_json::to_value(&reply).unwrap();
    let entry = json["entry"].as_object().expect("an object");
    for field in [
        "principal",
        "kvno",
        "flags",
        "key_count",
        "enctypes",
        "valid_start",
        "valid_end",
        "pw_end",
        "max_life",
    ] {
        assert!(
            entry.contains_key(field),
            "the view must carry {field}: {entry:?}"
        );
    }
    assert_eq!(entry["enctypes"], serde_json::json!([20, 18, 19, 17]));
}
