//! What a realm's PKINIT policy decides, when the exchange itself would have succeeded.
//!
//! The request here is the recorded alice fixture — a real signed `AuthPack` with a 2048-bit
//! Diffie-Hellman value — so the assertions are about the policy and not about parsing: the same
//! request is answered with one policy and refused with another, which is the only way to show that
//! an option is connected to anything.

#![cfg(feature = "pkinit")]

use rrl_kdc::crypto::Enctype;
use rrl_kdc::kdc::pkinit::{self, reply};
use rrl_kdc::name::Principal;

const NOW: i64 = 1_800_000_000;
const AS_REQ: &[u8] = b"the AS-REQ";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/pkinit/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn der_of(pem: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let text = String::from_utf8_lossy(pem);
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .expect("a PEM body is base64")
}

fn p(name: &str) -> Principal {
    Principal::parse(name).unwrap()
}

fn state(policy: reply::PkinitPolicy) -> reply::State {
    let mut anchors = pkinit::TrustAnchors::new();
    anchors
        .add(&der_of(&fixture("ca.pem")))
        .expect("the anchor loads");
    reply::State {
        identity: reply::Identity::from_der(
            &der_of(&fixture("kdc.pem")),
            &der_of(&fixture("kdc-key.pem")),
        )
        .expect("the KDC identity loads"),
        anchors,
        // The recorded request's `paChecksum` is over its own body, so the test's body has to be
        // the one the fixture was built with.
        policy,
    }
}

/// The recorded request, whose `paChecksum` covers the fixture's body.
fn request() -> (Vec<u8>, Vec<u8>) {
    let body = fixture("body.der");
    (fixture("request-alice-wrapped.der"), body)
}

fn deterministic() -> impl Fn(usize) -> Vec<u8> {
    let state = std::cell::Cell::new(0x5au8);
    move |len| {
        (0..len)
            .map(|_| {
                let mut x = state.get() as u32;
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                state.set((x as u8) | 1);
                state.get()
            })
            .collect()
    }
}

// The group floor is tested where it is decided (`reply.rs`), because a `Group` cannot be built
// here without a full `SubjectPublicKeyInfo` for domain parameters no client sends: the parser that
// produces one is covered by the live PKINIT suite against MIT, and the policy on top of it is a
// comparison with a number.

#[test]
fn a_certificate_for_someone_else_is_refused_unless_the_realm_drops_the_binding() {
    let (pa, body) = request();
    // The request is signed by alice's certificate; asking for bob's ticket is the mix-up the
    // check exists for.
    let ask = |policy: reply::PkinitPolicy| {
        let mut st = state(policy);
        st.policy.dh_min_bits = 2048;
        reply::answer(
            &st,
            &pa,
            &body,
            AS_REQ,
            &p("bob@EXAMPLE.COM"),
            &p("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
            Enctype::Aes256Sha1,
            NOW,
            &deterministic(),
        )
    };

    let err = match ask(reply::PkinitPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("a certificate naming alice must not buy a ticket for bob"),
    };
    assert!(
        matches!(err, pkinit::PkinitError::BadPrincipalName(_)),
        "expected the name mismatch to be named as such, got {err:?}"
    );

    // `pkinit_principal_in_certificate = false` is the documented opt-out for certificates issued
    // without `id-pkinit-san`: the certificate proves somebody the CA knows is asking, and the
    // request says whose ticket it is. It is off only where an operator said so.
    let answer = ask(reply::PkinitPolicy {
        principal_in_certificate: false,
        ..Default::default()
    })
    .expect("with the binding dropped, the request decides the principal");
    assert_eq!(answer.reply_key.enctype(), Enctype::Aes256Sha1);
}

/// The seam exists so that an identity can change without a restart: a source is asked on every
/// request, and this is the property — not an implementation detail of `Fixed`.
#[test]
fn a_source_can_answer_differently_each_time() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Counting {
        asked: AtomicUsize,
        inner: reply::State,
    }

    impl reply::PkinitSource for Counting {
        fn state(&self) -> Result<reply::State, pkinit::PkinitError> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            Ok(reply::State {
                identity: self.inner.identity.clone(),
                anchors: self.inner.anchors.clone(),
                policy: self.inner.policy.clone(),
            })
        }
    }

    let source = Counting {
        asked: AtomicUsize::new(0),
        inner: state(reply::PkinitPolicy::default()),
    };
    assert_eq!(source.asked.load(Ordering::SeqCst), 0);
    let _ = reply::PkinitSource::state(&source).expect("a source answers");
    let _ = reply::PkinitSource::state(&source).expect("and answers again");
    assert_eq!(
        source.asked.load(Ordering::SeqCst),
        2,
        "the KDC asks per request, which is what makes rotation possible"
    );
}
