//! Второй контроллер домена: слейв обслуживает тикеты и не принимает запись.
//!
//! Проверяется то, ради чего этот шов существует, и на живых путях, а не на трейте:
//!
//! * **слейв выдаёт тикет** — база под `ReadOnly` обслуживает `TGS-REQ`, потому что запрет
//!   касается записи, а не чтения;
//! * **`kadmin` на слейве отказывает** — и отказ посчитан, чтобы мониторинг видел попытки;
//! * **принятый пуш становится базой** — после `commit` тикет выдаётся из реплицированного
//!   хранилища, то есть слейв действительно становится вторым контроллером, а не копией файла;
//! * **запоздалый пуш не откатывает `kvno`** — клиент, получивший тикет до пуша, получает его и
//!   после; это и есть инвариант, ради которого сравнение `kvno` стоит в приёме.

mod common;

use std::sync::Arc;

use common::{NOW, REALM};
use rrl_kdc::admin::{Admin, NewPrincipal};
use rrl_kdc::crypto::{Enctype, OwnCipher};
use rrl_kdc::error::Error;
use rrl_kdc::hdb::{Hdb, HdbEntry, MemoryHdb};
use rrl_kdc::hprop::PropagationTarget;
use rrl_kdc::hprop::StagedHdb;
use rrl_kdc::hprop::replica::{Master, ReadOnly, Replica, ReplicaTarget, Role, Slave};
use rrl_kdc::kdc::{Kdc, KdcConfig};
use rrl_kdc::name::Principal;

/// A realm as a slave receives it: the `krbtgt` and one user, nothing else.
fn replicated() -> (MemoryHdb, rrl_kdc::crypto::Key) {
    common::realm()
}

/// A `TGS-REQ` for the service, from a TGT as the AS exchange would have issued it.
fn service_ticket(kdc: &Kdc, krbtgt_key: &rrl_kdc::crypto::Key) -> Vec<u8> {
    let tgt = common::tgt(
        krbtgt_key,
        &common::alice(),
        NOW + 3600,
        None,
        rrl_kdc::msg::tkt_flags::FORWARDABLE,
    );
    let req = common::tgs_req(&tgt, common::Knobs::default());
    kdc.handle_from(&req, NOW, None)
}

/// A slave serves tickets: the read-only wrapper forbids writing, and the exchange only reads.
#[test]
fn a_slave_issues_a_service_ticket_from_its_copy() {
    let (db, krbtgt_key) = replicated();
    let replica: Arc<dyn Replica> = Arc::new(Slave::new());
    let read_only = ReadOnly::new(db, Arc::clone(&replica));

    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::new(read_only),
        Arc::new(OwnCipher),
    );
    let reply = service_ticket(&kdc, &krbtgt_key);
    assert!(
        rrl_kdc::msg::KrbError::decode(&reply).is_err(),
        "a slave must answer a TGS-REQ with a ticket: {:?}",
        rrl_kdc::msg::KrbError::decode(&reply).map(|e| (e.code, e.e_text))
    );
}

/// `kadmin` on a slave is refused, and the refusal is a decision of the realm, not a database fault.
#[test]
fn an_admin_operation_on_a_slave_is_refused_and_counted() {
    let (db, _) = replicated();
    let replica = Arc::new(Slave::new());
    let read_only: Arc<dyn Hdb> =
        Arc::new(ReadOnly::new(db, Arc::clone(&replica) as Arc<dyn Replica>));

    let admin = Admin::new(
        REALM,
        read_only,
        Arc::new(OwnCipher),
        &[Enctype::Aes256Sha1],
    );
    // Reading is what a slave is for, and it must keep working: `kadmin get` on a slave is the
    // usual way an operator checks what the master has.
    assert!(
        admin.get(&common::alice()).is_ok(),
        "the entry the propagation brought must be visible"
    );

    let err = admin
        .create(NewPrincipal::user(
            Principal::parse(&format!("bob@{REALM}")).unwrap(),
            b"pw".to_vec(),
        ))
        .unwrap_err();
    assert!(
        matches!(err, Error::Forbidden(_)),
        "not `Hdb`: the storage is fine, the role is not: {err}"
    );
    let text = err.to_string();
    assert!(
        text.contains("master") && text.contains("slave"),
        "the refusal says where to write instead: {text}"
    );
    assert_eq!(
        replica.refused_writes(),
        1,
        "one refused write, so an operator can alert on it"
    );
    assert_eq!(replica.role(), Role::Slave);
    assert!(!replica.writable());
}

/// A propagation becomes the database: the ticket the slave issues afterwards comes from what the
/// master sent, and the entry the master deleted is gone.
#[test]
fn a_propagation_becomes_the_database_the_slave_serves() {
    let (live, _) = replicated();
    let live: Arc<dyn Hdb> = Arc::new(live);
    let replica = Arc::new(Slave::new());
    let staged: Arc<dyn Hdb> = Arc::new(MemoryHdb::new());

    let target = ReplicaTarget::new(
        StagedHdb::new(Arc::clone(&staged)),
        Arc::clone(&live),
        Arc::clone(&replica) as Arc<dyn Replica>,
    )
    .unwrap()
    .with_master("kdc1.example.com");

    // The master's stream: the `krbtgt`, `alice`, and a new service the slave never had.
    let mut krbtgt = HdbEntry::krbtgt(REALM);
    krbtgt
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"master", 1)
        .unwrap();
    let krbtgt_key = krbtgt.key_for(Enctype::Aes256Sha1).unwrap().key.clone();
    target.store(krbtgt).unwrap();
    // A propagation is the whole database: every entry the master has, including the service
    // tickets are asked for. Sending only the users would leave a slave that authenticates and then
    // cannot issue a ticket.
    let master = common::realm().0;
    for principal in [common::alice(), common::service()] {
        target
            .store(master.fetch(&principal).unwrap().unwrap())
            .unwrap();
    }

    let mut added = HdbEntry::user(Principal::parse(&format!("carol@{REALM}")).unwrap());
    added
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"carol-pw", 1)
        .unwrap();
    target.store(added).unwrap();
    target.commit().unwrap();

    let sync = replica.last_sync().expect("the push is recorded");
    assert_eq!(sync.entries, 4, "the krbtgt, alice, the service and carol");
    assert_eq!(sync.stale, 0);
    assert_eq!(sync.master.as_deref(), Some("kdc1.example.com"));

    // Now it is a database: the KDC built over the staged copy answers, which is the whole point of
    // a second domain controller.
    assert!(
        staged.fetch(&common::alice()).unwrap().is_some()
            && staged
                .fetch(&Principal::parse(&format!("carol@{REALM}")).unwrap())
                .unwrap()
                .is_some(),
        "both entries the master sent are in the copy the slave serves"
    );
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::clone(&staged),
        Arc::new(OwnCipher),
    );
    let reply = service_ticket(&kdc, &krbtgt_key);
    assert!(
        rrl_kdc::msg::KrbError::decode(&reply).is_err(),
        "the slave answers from what it was sent: {:?}",
        rrl_kdc::msg::KrbError::decode(&reply).map(|e| (e.code, e.e_text))
    );
}

/// A late push does not roll the keys back: the client that could log in before still can.
#[test]
fn a_late_push_does_not_roll_the_keys_back() {
    let (live, krbtgt_key) = replicated();
    let live: Arc<dyn Hdb> = Arc::new(live);
    let replica = Arc::new(Slave::new());

    // The slave is on generation 4 of `alice`; the master sends generation 2, which is a push that
    // was delayed or replayed.
    let mut newer = HdbEntry::user(common::alice());
    newer
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 4)
        .unwrap();
    live.store(newer).unwrap();

    let staged: Arc<dyn Hdb> = Arc::new(MemoryHdb::new());
    let target = ReplicaTarget::new(
        StagedHdb::new(Arc::clone(&staged)),
        Arc::clone(&live),
        Arc::clone(&replica) as Arc<dyn Replica>,
    )
    .unwrap();

    let mut older = HdbEntry::user(common::alice());
    older
        .add_password_key(&OwnCipher, Enctype::Aes256Sha1, b"pw", 2)
        .unwrap();
    target.store(older).unwrap();
    target.commit().unwrap();

    assert_eq!(target.applied(), 0, "a stale entry is not applied");
    assert_eq!(target.stale(), 1);
    let sync = replica
        .last_sync()
        .expect("recorded even when everything was stale");
    assert_eq!(sync.stale, 1, "the divergence is a fact the operator sees");

    // The proof that matters: the slave still issues a ticket from the generation it had, so the
    // user who was working before the late push keeps working after it.
    let kdc = Kdc::new(
        KdcConfig::new(REALM).unwrap(),
        Arc::clone(&live),
        Arc::new(OwnCipher),
    );
    let reply = service_ticket(&kdc, &krbtgt_key);
    assert!(
        rrl_kdc::msg::KrbError::decode(&reply).is_err(),
        "the slave still answers: {:?}",
        rrl_kdc::msg::KrbError::decode(&reply).map(|e| (e.code, e.e_text))
    );
    assert_eq!(
        live.fetch(&common::alice()).unwrap().unwrap().kvno,
        4,
        "the copy is still on the generation the late push tried to replace"
    );
}

/// A master does not accept a propagation: two masters of one realm is a state the protocol cannot
/// resolve, so it is refused before the first entry is read.
#[test]
fn a_master_does_not_accept_a_propagation() {
    let (db, _) = replicated();
    let err = ReplicaTarget::new(
        StagedHdb::new(Arc::new(MemoryHdb::new())),
        Arc::new(db),
        Arc::new(Master) as Arc<dyn Replica>,
    )
    .unwrap_err();
    assert!(err.to_string().contains("only a slave"), "{err}");
}
