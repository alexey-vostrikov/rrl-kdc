//! The administrator's operations as values, and the rights that gate them.
//!
//! Two questions this answers, and they are not the same:
//!
//! * Does the vocabulary cover every operation a transport needs, without the
//!   transport reaching into `Admin`'s internals?
//! * Can a transport forget the authorization? It must not be able to: the check
//!   lives in `Admin::handle`, so an HTTP route that calls it and turns the reply
//!   into JSON cannot be missing anything.
//!
//! The rights are deliberately finer than "administrator". Listing a realm and
//! exporting a keytab are both reads, and only one of them hands over
//! password-equivalent material.

use std::sync::Arc;

use rrl_kdc::acl::Targets;
use rrl_kdc::admin::wire::{
    AdminRequest, DenyAll, Grants, Operation, Policy, Reply, Right, Rights,
};
use rrl_kdc::admin::{Admin, Modify, Role};
use rrl_kdc::crypto::{Cipher, Enctype, OwnCipher};
// `Policy` in this file's other import is the authorization trait; a policy record is `PolicyRec`.
use rrl_kdc::hdb::{Hdb, HdbEntry, Keytab, MemoryHdb, Policy as PolicyRec, flags as entry_flags};
use rrl_kdc::name::Principal;

const REALM: &str = "EXAMPLE.COM";

fn p(name: &str) -> Principal {
    Principal::parse(&format!("{name}@{REALM}")).unwrap()
}

/// The realm's `krbtgt`, and an administrator over the database.
fn realm() -> (Arc<MemoryHdb>, Admin) {
    let cipher = OwnCipher;
    let db = MemoryHdb::new();
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    for e in [Enctype::Aes256Sha1, Enctype::Aes128Sha1] {
        krbtgt
            .add_password_key(&cipher, e, b"master-key-of-the-realm", 1)
            .unwrap();
    }
    db.insert(krbtgt).unwrap();
    let db = Arc::new(db);
    let admin = Admin::with_defaults(REALM, Arc::clone(&db) as Arc<dyn Hdb>, Arc::new(cipher));
    (db, admin)
}

fn as_owner(admin: &Admin) -> Admin {
    admin
        .clone()
        .with_policy(Arc::new(Grants::new().grant(&p("admin"), Rights::ALL)))
}

fn request(actor: &str, operation: Operation) -> AdminRequest {
    AdminRequest {
        actor: p(actor),
        operation,
    }
}

fn create(principal: &str, role: Role) -> Operation {
    Operation::Create {
        principal: p(principal),
        password: b"a password".to_vec(),
        enctypes: Vec::new(),
        role,
    }
}

#[test]
fn nothing_is_permitted_without_a_granted_right() {
    // A transport that installs no policy must deny, not allow: the failure mode
    // of "forgot to configure authorization" has to be a closed door.
    let (_db, admin) = realm();
    let err = admin
        .handle(request("alice", Operation::List))
        .expect_err("a fresh administrator grants nothing");
    assert_eq!(err.kind(), "forbidden");
}

#[test]
fn the_default_policy_is_deny_all() {
    assert!(!DenyAll.may(&p("admin"), Right::List, None));
    assert!(!DenyAll.may(&p("admin"), Right::ExportKeytab, Some(&p("host/h"))));
    assert!(!DenyAll.may(&p("admin"), Right::SetPassword, Some(&p("alice"))));
}

#[test]
fn a_granted_right_lets_one_actor_do_one_thing() {
    let (_db, admin) = realm();
    let admin = admin.with_policy(Arc::new(Grants::new().grant(&p("admin"), Rights::LIST)));

    let listed = admin
        .handle(request("admin", Operation::List))
        .expect("the granted right must work");
    assert!(matches!(listed, Reply::Principals { .. }));

    // The same actor, a different right: refused, and not silently allowed
    // because one right happened to be granted.
    let err = admin
        .handle(request(
            "admin",
            Operation::Get {
                principal: p("admin"),
            },
        ))
        .expect_err("listing a realm is not reading its entries");
    assert_eq!(err.kind(), "forbidden");
}

#[test]
fn exporting_a_keytab_needs_its_own_right() {
    // The point of separate rights: an operator allowed to look at the realm must
    // not thereby walk away with every service's long-term key.
    let (_db, admin) = realm();
    let owner = as_owner(&admin);
    owner
        .handle(request("admin", create("host/h", Role::Server)))
        .unwrap();

    let auditor = admin.with_policy(Arc::new(
        Grants::new().grant(&p("auditor"), Rights::LIST | Rights::READ),
    ));
    // Reading the entry is allowed...
    assert!(matches!(
        auditor
            .handle(request(
                "auditor",
                Operation::Get {
                    principal: p("host/h")
                }
            ))
            .unwrap(),
        Reply::Entry { .. }
    ));
    // ...exporting its keys is not.
    let err = auditor
        .handle(request(
            "auditor",
            Operation::Keytab {
                principals: vec![p("host/h")],
            },
        ))
        .expect_err("reading entries is not exporting their keys");
    assert_eq!(err.kind(), "forbidden");
}

#[test]
fn the_whole_lifecycle_over_the_wire_vocabulary() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);

    let created = admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    let Reply::Created { entry: view } = created else {
        panic!("a create must answer with the entry it made, got {created:?}");
    };
    assert_eq!(view.principal, p("alice"));
    assert_eq!(view.kvno, 1);
    assert_eq!(view.key_count, 4);

    let fetched = admin
        .handle(request(
            "admin",
            Operation::Get {
                principal: p("alice"),
            },
        ))
        .unwrap();
    assert!(matches!(fetched, Reply::Entry { .. }));

    let modified = admin
        .handle(request(
            "admin",
            Operation::Modify {
                principal: p("alice"),
                change: Modify {
                    locked_out: Some(true),
                    ..Modify::default()
                },
            },
        ))
        .unwrap();
    let Reply::Modified { entry: view } = modified else {
        panic!("a modify must answer with the entry");
    };
    assert_ne!(view.flags & entry_flags::LOCKED_OUT, 0);

    let rotated = admin
        .handle(request(
            "admin",
            Operation::SetPassword {
                principal: p("alice"),
                password: b"a new password".to_vec(),
            },
        ))
        .unwrap();
    let Reply::PasswordSet { kvno } = rotated else {
        panic!("a password change must answer with the kvno");
    };
    assert_eq!(kvno, 2);

    let pruned = admin
        .handle(request(
            "admin",
            Operation::PruneOldKeys {
                principal: p("alice"),
            },
        ))
        .unwrap();
    assert!(matches!(pruned, Reply::Pruned { .. }));

    let deleted = admin
        .handle(request(
            "admin",
            Operation::Delete {
                principal: p("alice"),
            },
        ))
        .unwrap();
    assert_eq!(deleted, Reply::Deleted { existed: true });
    let again = admin
        .handle(request(
            "admin",
            Operation::Delete {
                principal: p("alice"),
            },
        ))
        .unwrap();
    assert_eq!(
        again,
        Reply::Deleted { existed: false },
        "deleting what is not there is not an error, but it must say so"
    );
}

/// A rename over the wire vocabulary: the keys and the kvno travel with the name, and the old
/// name stops resolving.
#[test]
fn a_rename_takes_the_keys_and_the_kvno_with_it() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    let before = admin
        .handle(request(
            "admin",
            Operation::Get {
                principal: p("alice"),
            },
        ))
        .unwrap();
    let Reply::Entry { entry: before } = before else {
        panic!("a get must answer with an entry");
    };

    let renamed = admin
        .handle(request(
            "admin",
            Operation::Rename {
                from: p("alice"),
                to: p("alicia"),
            },
        ))
        .unwrap();
    assert!(matches!(renamed, Reply::Renamed { .. }));

    let after = admin
        .handle(request(
            "admin",
            Operation::Get {
                principal: p("alicia"),
            },
        ))
        .unwrap();
    let Reply::Entry { entry: after } = after else {
        panic!("the new name must answer with the entry");
    };
    assert_eq!(after.kvno, before.kvno, "the kvno follows the name");
    assert_eq!(after.key_count, before.key_count, "and so do the keys");
    assert_eq!(after.flags, before.flags);
    assert_eq!(after.principal, p("alicia"));

    let gone = admin.handle(request(
        "admin",
        Operation::Get {
            principal: p("alice"),
        },
    ));
    assert!(
        gone.is_err(),
        "the old name must not answer after a rename: {gone:?}"
    );
}

/// Two refusals that a rename cannot be allowed to skip.
#[test]
fn a_rename_onto_an_existing_name_is_refused() {
    // A merge, not a rename: whose keys would win is a decision nobody asked this server to make.
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    for name in ["alice", "bob"] {
        admin
            .handle(request("admin", create(name, Role::Client)))
            .unwrap();
    }
    let refused = admin.handle(request(
        "admin",
        Operation::Rename {
            from: p("alice"),
            to: p("bob"),
        },
    ));
    assert!(refused.is_err(), "renaming onto an existing name must fail");
    // And nothing moved: both principals are still there under their own names.
    for name in ["alice", "bob"] {
        admin
            .handle(request("admin", Operation::Get { principal: p(name) }))
            .unwrap_or_else(|e| panic!("{name} must still exist: {e:?}"));
    }
}

/// `krbtgt` may not be renamed: a realm whose ticket-granting ticket changed its name cannot issue
/// a ticket at all.
#[test]
fn the_realms_krbtgt_may_not_be_renamed() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    let refused = admin.handle(request(
        "admin",
        Operation::Rename {
            from: Principal::krbtgt(REALM),
            to: Principal::parse(&format!("krbtgt/OTHER@{REALM}")).unwrap(),
        },
    ));
    assert!(refused.is_err(), "krbtgt must not be renamed");
}

/// The fields `modprinc` gained, applied together the way the wire sends them.
#[test]
fn a_modify_applies_every_field_it_was_given() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    let modified = admin
        .handle(request(
            "admin",
            Operation::Modify {
                principal: p("alice"),
                change: Modify {
                    max_renew: Some(Some(604_800)),
                    require_preauth: Some(true),
                    forwardable: Some(false),
                    allow_server: Some(true),
                    kvno: Some(2),
                    ..Modify::default()
                },
            },
        ))
        .unwrap();
    let Reply::Modified { entry } = modified else {
        panic!("a modify must answer with the entry");
    };
    assert_eq!(entry.max_renew, Some(604_800));
    assert_ne!(entry.flags & entry_flags::REQUIRE_PREAUTH, 0);
    assert_eq!(entry.flags & entry_flags::FORWARDABLE, 0);
    assert_ne!(entry.flags & entry_flags::SERVER, 0);
    assert_eq!(entry.kvno, 2);
}

/// A kvno below the keys is refused rather than written: an entry whose keys are newer than its
/// version is an entry no keytab can be matched against.
#[test]
fn a_kvno_below_the_keys_is_refused() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    // A new password puts the keys at kvno 2.
    admin
        .handle(request(
            "admin",
            Operation::SetPassword {
                principal: p("alice"),
                password: b"another password".to_vec(),
            },
        ))
        .unwrap();
    let refused = admin.handle(request(
        "admin",
        Operation::Modify {
            principal: p("alice"),
            change: Modify {
                kvno: Some(1),
                ..Modify::default()
            },
        },
    ));
    assert!(
        refused.is_err(),
        "kvno 1 is below the keys at 2: {refused:?}"
    );
}

/// String attributes over the wire vocabulary: set, read back, replace, delete.
#[test]
fn string_attributes_are_set_read_and_removed() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();

    let set = admin
        .handle(request(
            "admin",
            Operation::SetString {
                principal: p("alice"),
                key: "kpasswd_server".into(),
                value: Some("kpasswd.example.com".into()),
            },
        ))
        .unwrap();
    let Reply::Strings { strings } = set else {
        panic!("a set_string must answer with the attributes it left");
    };
    assert_eq!(
        strings,
        vec![(
            "kpasswd_server".to_string(),
            "kpasswd.example.com".to_string()
        )]
    );

    // A second key keeps the first, and the order is the order they were set in.
    admin
        .handle(request(
            "admin",
            Operation::SetString {
                principal: p("alice"),
                key: "kadmin_keytab".into(),
                value: Some("/etc/krb5.keytab".into()),
            },
        ))
        .unwrap();
    let read = admin
        .handle(request(
            "admin",
            Operation::Strings {
                principal: p("alice"),
            },
        ))
        .unwrap();
    let Reply::Strings { strings } = read else {
        panic!("a strings read must answer with them");
    };
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].0, "kpasswd_server");

    // The same key again replaces, rather than appending a second pair with that name.
    admin
        .handle(request(
            "admin",
            Operation::SetString {
                principal: p("alice"),
                key: "kpasswd_server".into(),
                value: Some("other.example.com".into()),
            },
        ))
        .unwrap();
    let read = admin
        .handle(request(
            "admin",
            Operation::Strings {
                principal: p("alice"),
            },
        ))
        .unwrap();
    let Reply::Strings { strings } = read else {
        panic!("a strings read");
    };
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].1, "other.example.com");

    // No value deletes: MIT's `delstr`.
    admin
        .handle(request(
            "admin",
            Operation::SetString {
                principal: p("alice"),
                key: "kpasswd_server".into(),
                value: None,
            },
        ))
        .unwrap();
    let read = admin
        .handle(request(
            "admin",
            Operation::Strings {
                principal: p("alice"),
            },
        ))
        .unwrap();
    let Reply::Strings { strings } = read else {
        panic!("a strings read");
    };
    assert_eq!(
        strings,
        vec![("kadmin_keytab".to_string(), "/etc/krb5.keytab".to_string())]
    );
}

/// An empty attribute name is refused: a pair nothing can ask for is a pair nothing reads.
#[test]
fn an_empty_string_attribute_key_is_refused() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    let refused = admin.handle(request(
        "admin",
        Operation::SetString {
            principal: p("alice"),
            key: String::new(),
            value: Some("a value".into()),
        },
    ));
    assert!(refused.is_err(), "an empty key must be refused");
}

/// A policy's whole life over the transport vocabulary: create, read, list, replace, delete.
#[test]
fn a_policy_is_created_read_and_removed() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);

    let created = admin
        .handle(request(
            "admin",
            Operation::CreatePolicy {
                policy: PolicyRec {
                    name: "staff".into(),
                    pw_min_length: 12,
                    pw_min_classes: 3,
                    max_life: 86_400,
                    ..PolicyRec::default()
                },
            },
        ))
        .unwrap();
    let Reply::Policy { policy } = created else {
        panic!("a create_policy must answer with the policy it stored");
    };
    assert_eq!(policy.name, "staff");
    assert_eq!(policy.pw_min_length, 12);

    // The same name again is a refusal: `addpol` does not quietly replace, or every account under
    // the policy would move without the operator having asked.
    let twice = admin.handle(request(
        "admin",
        Operation::CreatePolicy {
            policy: PolicyRec::new("staff"),
        },
    ));
    assert!(
        twice.is_err(),
        "a duplicate policy must be refused: {twice:?}"
    );

    // `modpol` is how a policy changes, and reading it back is how an operator learns it did.
    admin
        .handle(request(
            "admin",
            Operation::ModifyPolicy {
                policy: PolicyRec {
                    name: "staff".into(),
                    pw_min_length: 16,
                    ..PolicyRec::default()
                },
            },
        ))
        .unwrap();
    let read = admin
        .handle(request(
            "admin",
            Operation::Policy {
                name: "staff".into(),
            },
        ))
        .unwrap();
    let Reply::Policy { policy } = read else {
        panic!("a policy read must answer with it");
    };
    assert_eq!(
        policy.pw_min_length, 16,
        "the new number replaced the old one"
    );

    let listed = admin.handle(request("admin", Operation::Policies)).unwrap();
    let Reply::Policies { names } = listed else {
        panic!("a list must answer with names");
    };
    assert_eq!(names, vec!["staff".to_string()]);

    let removed = admin
        .handle(request(
            "admin",
            Operation::DeletePolicy {
                name: "staff".into(),
            },
        ))
        .unwrap();
    let Reply::Policies { names } = removed else {
        panic!("a delete answers with what is left");
    };
    assert!(names.is_empty());
    assert!(
        admin
            .handle(request(
                "admin",
                Operation::Policy {
                    name: "staff".into(),
                },
            ))
            .is_err(),
        "the policy must be gone"
    );
}

/// A policy an entry cites cannot be removed: the entry would go on citing a name that resolves to
/// nothing, and every read of its rules would have to guess.
#[test]
fn a_policy_in_use_cannot_be_deleted() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request(
            "admin",
            Operation::CreatePolicy {
                policy: PolicyRec::new("staff"),
            },
        ))
        .unwrap();
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    admin
        .handle(request(
            "admin",
            Operation::Modify {
                principal: p("alice"),
                change: Modify {
                    policy: Some(Some("staff".into())),
                    ..Modify::default()
                },
            },
        ))
        .unwrap();

    let refused = admin.handle(request(
        "admin",
        Operation::DeletePolicy {
            name: "staff".into(),
        },
    ));
    assert!(
        refused.is_err(),
        "a policy in use must not be deleted: {refused:?}"
    );

    // Once nothing cites it, it goes.
    admin
        .handle(request(
            "admin",
            Operation::Modify {
                principal: p("alice"),
                change: Modify {
                    policy: Some(None),
                    ..Modify::default()
                },
            },
        ))
        .unwrap();
    admin
        .handle(request(
            "admin",
            Operation::DeletePolicy {
                name: "staff".into(),
            },
        ))
        .unwrap();
}

/// A principal cannot be put under a policy that does not exist, and the password it is given is
/// measured against the one it is under.
#[test]
fn a_policy_governs_the_password_of_its_principals() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();

    let absent = admin.handle(request(
        "admin",
        Operation::Modify {
            principal: p("alice"),
            change: Modify {
                policy: Some(Some("nosuch".into())),
                ..Modify::default()
            },
        },
    ));
    assert!(
        absent.is_err(),
        "a missing policy must be refused: {absent:?}"
    );

    admin
        .handle(request(
            "admin",
            Operation::CreatePolicy {
                policy: PolicyRec {
                    name: "staff".into(),
                    pw_min_length: 16,
                    ..PolicyRec::default()
                },
            },
        ))
        .unwrap();
    admin
        .handle(request(
            "admin",
            Operation::Modify {
                principal: p("alice"),
                change: Modify {
                    policy: Some(Some("staff".into())),
                    ..Modify::default()
                },
            },
        ))
        .unwrap();

    let short = admin.handle(request(
        "admin",
        Operation::SetPassword {
            principal: p("alice"),
            password: b"too short".to_vec(),
        },
    ));
    assert!(
        short.is_err(),
        "a password below the policy must be refused: {short:?}"
    );

    // And one that satisfies it goes through, so the refusal is about the length and not the
    // principal being unchangeable.
    admin
        .handle(request(
            "admin",
            Operation::SetPassword {
                principal: p("alice"),
                password: b"a long enough password".to_vec(),
            },
        ))
        .unwrap();
}

#[test]
fn a_missing_principal_is_not_found_and_not_a_storage_failure() {
    // A transport answers 404 or 500 depending on this, so it must not be prose
    // the transport has to parse.
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    let err = admin
        .handle(request(
            "admin",
            Operation::Get {
                principal: p("nobody"),
            },
        ))
        .expect_err("an absent principal is not a read");
    assert_eq!(err.kind(), "not_found");
}

#[test]
fn creating_twice_says_already_exists() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    let err = admin
        .handle(request("admin", create("alice", Role::Client)))
        .expect_err("the second create must be refused");
    assert_eq!(
        err.kind(),
        "already_exists",
        "a transport has to tell a conflict from a bad request, got: {err}"
    );
}

#[test]
fn a_refused_operation_does_not_touch_the_database() {
    // Authorization before the work, not after it: a delete that is refused must
    // leave the entry alone, or the check is decoration.
    let (db, admin) = realm();
    as_owner(&admin)
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();

    let guest = admin.with_policy(Arc::new(Grants::new().grant(&p("guest"), Rights::LIST)));
    let err = guest
        .handle(request(
            "guest",
            Operation::Delete {
                principal: p("alice"),
            },
        ))
        .expect_err("a guest may not delete");
    assert_eq!(err.kind(), "forbidden");
    assert!(
        db.fetch(&p("alice")).unwrap().is_some(),
        "a refused delete must leave the entry in place"
    );
}

#[test]
fn an_empty_modification_is_a_bad_request() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    let err = admin
        .handle(request(
            "admin",
            Operation::Modify {
                principal: p("alice"),
                change: Modify::default(),
            },
        ))
        .expect_err("an empty change must be refused");
    assert_eq!(err.kind(), "bad_request");
}

#[test]
fn a_grant_narrowed_to_one_target_does_not_reach_another() {
    // The helpdesk case: may reset one department's passwords, not everybody's.
    let policy = Grants::new().grant_for(
        &p("helpdesk"),
        Targets::Only(p("alice")),
        Rights::SET_PASSWORD,
    );
    assert!(policy.may(&p("helpdesk"), Right::SetPassword, Some(&p("alice"))));
    assert!(
        !policy.may(&p("helpdesk"), Right::SetPassword, Some(&p("bob"))),
        "a rule for one target must not extend to another"
    );
    assert!(
        !policy.may(&p("helpdesk"), Right::List, None),
        "a rule for one right must not extend to another"
    );
}

#[test]
fn a_keytab_reply_carries_a_parseable_file() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("host/h", Role::Server)))
        .unwrap();
    let reply = admin
        .handle(request(
            "admin",
            Operation::Keytab {
                principals: vec![p("host/h")],
            },
        ))
        .unwrap();
    let Reply::Keytab { bytes } = reply else {
        panic!("a keytab export must answer with the file");
    };
    let parsed = Keytab::parse(&bytes).expect("the reply must be a keytab file");
    assert_eq!(parsed.entries().len(), 4);
}

#[test]
fn exporting_a_keytab_for_several_principals_needs_the_right_for_each() {
    // Otherwise one principal's export is a way to read another's keys by
    // appending it to the list.
    let (_db, admin) = realm();
    let admin = admin.with_policy(Arc::new(Grants::new().grant_for(
        &p("deployer"),
        Targets::Only(p("host/h")),
        Rights::EXPORT_KEYTAB,
    )));
    let err = admin
        .handle(request(
            "deployer",
            Operation::Keytab {
                principals: vec![p("host/h"), Principal::krbtgt(REALM)],
            },
        ))
        .expect_err("the second principal was not granted");
    assert_eq!(err.kind(), "forbidden");
}

#[test]
fn the_entry_view_carries_no_key_material() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    admin
        .handle(request("admin", create("alice", Role::Client)))
        .unwrap();
    let Reply::Entry { entry: view } = admin
        .handle(request(
            "admin",
            Operation::Get {
                principal: p("alice"),
            },
        ))
        .unwrap()
    else {
        panic!("expected an entry");
    };
    // What the view may say: how many keys, in which enctypes. Not the keys.
    assert_eq!(view.key_count, 4);
    assert_eq!(view.enctypes.len(), 4);
    let debug = format!("{view:?}");
    for enctype in view.enctypes {
        let key = OwnCipher
            .s2k(enctype, b"a password", &p("alice").default_salt(), None)
            .unwrap();
        assert!(
            !debug.contains(&hex::encode(key.bytes())),
            "the entry view must not carry key bytes: reading a realm is not reading its secrets"
        );
    }
}

#[test]
fn an_actor_without_a_realm_is_a_bad_request() {
    // A bare name is ambiguous once there is more than one realm; the operation
    // has to say who is asking, and the answer has to be a principal.
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    let err = admin
        .handle(AdminRequest {
            actor: Principal {
                name_type: 1,
                components: vec!["admin".to_owned()],
                realm: String::new(),
            },
            operation: Operation::List,
        })
        .expect_err("an actor with no realm is not an actor");
    assert_eq!(err.kind(), "bad_request");
}

#[test]
fn a_principal_named_without_a_realm_gets_the_administrators() {
    let (_db, admin) = realm();
    let admin = as_owner(&admin);
    let reply = admin
        .handle(request(
            "admin",
            Operation::Create {
                principal: Principal {
                    name_type: 1,
                    components: vec!["bob".to_owned()],
                    realm: String::new(),
                },
                password: b"pw".to_vec(),
                enctypes: Vec::new(),
                role: Role::Client,
            },
        ))
        .unwrap();
    let Reply::Created { entry: view } = reply else {
        panic!("expected the created entry");
    };
    assert_eq!(view.principal.realm, REALM);
}
