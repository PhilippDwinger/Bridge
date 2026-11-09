//! Attack tests for envelopes (docs/02 §7, docs/05 Phase 2): every manipulation must be detected.

use bridge_core::envelope::{MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES};
use bridge_core::{Address, CLOCK_SKEW_MS, CoreError, CoreResult, Envelope, Identity, KeyCard, Kind, Role};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};

struct Parties {
    alice: Identity,
    alice_card: KeyCard,
    bob: Identity,
    bob_card: KeyCard,
    node: Identity,
}

fn parties() -> CoreResult<Parties> {
    let alice = Identity::generate(&mut OsRng);
    let bob = Identity::generate(&mut OsRng);
    let node = Identity::generate(&mut OsRng);
    Ok(Parties {
        alice_card: alice.key_card(Role::Client, Some("Alice"), 0)?,
        bob_card: bob.key_card(Role::Client, Some("Bob"), 0)?,
        alice,
        bob,
        node,
    })
}

const NOW: i64 = 1_800_000_000_000;

fn sealed(p: &Parties, plaintext: &[u8]) -> CoreResult<Envelope> {
    let net = p.node.id().clone();
    let address = Address { net: &net, to: &p.bob_card, kind: Kind::Msg, iat: NOW, ttl: 600 };
    Envelope::seal(&p.alice, &address, plaintext, &mut OsRng)
}

#[test]
fn roundtrip_through_bytes() -> CoreResult<()> {
    let p = parties()?;
    let envelope = sealed(&p, "Hallo Bob 👋".as_bytes())?;
    let received = Envelope::parse(&envelope.to_bytes()?)?;
    received.check_time(NOW + 1_000)?;
    received.verify(&p.alice_card)?;
    assert_eq!(received.open(&p.bob, &p.alice_card)?, "Hallo Bob 👋".as_bytes());
    assert_eq!(received.from(), p.alice.id());
    assert_eq!(received.to(), p.bob.id());
    Ok(())
}

#[test]
fn the_node_on_the_way_cannot_read() -> CoreResult<()> {
    let p = parties()?;
    let envelope = sealed(&p, b"geheim")?;
    let bytes = envelope.to_bytes()?;
    assert!(!bytes.windows(6).any(|w| w == b"geheim"), "plaintext must not appear in the bytes");
    envelope.verify(&p.alice_card)?; // the node can check the signature ...
    assert_eq!(envelope.open(&p.node, &p.alice_card), Err(CoreError::CannotOpen)); // ... but not read
    Ok(())
}

#[test]
fn every_field_is_protected() -> CoreResult<()> {
    let p = parties()?;
    let envelope = sealed(&p, b"payload")?;
    let original = envelope.to_value_for_tests();
    let other_id = Identity::generate(&mut OsRng).id().to_string();
    let changes: Vec<(&str, Value)> = vec![
        ("id", json!(bridge_core::encoding::b64(&[1u8; 16]))),
        ("net", json!(other_id)),
        ("from", json!(other_id)),
        ("to", json!(other_id)),
        ("iat", json!(NOW + 1)),
        ("ttl", json!(601)),
        ("kind", json!("req")),
        ("epk", json!(bridge_core::encoding::b64(&[5u8; 32]))),
        ("n", json!(bridge_core::encoding::b64(&[6u8; 12]))),
        ("ct", json!(bridge_core::encoding::b64(&[7u8; 40]))),
    ];
    for (field, new_value) in changes {
        let mut value = original.clone();
        value[field] = new_value;
        let tampered = Envelope::from_value(value)?;
        assert!(tampered.verify(&p.alice_card).is_err(), "changing {field} must break the signature");
        assert!(tampered.open(&p.bob, &p.alice_card).is_err(), "changing {field} must make opening fail");
    }
    // An extra field added later is detected too
    let mut value = original.clone();
    value["extra"] = json!("x");
    assert_eq!(Envelope::from_value(value)?.verify(&p.alice_card), Err(CoreError::BadSignature));
    Ok(())
}

#[test]
fn flipping_any_ciphertext_byte_is_detected() -> CoreResult<()> {
    let p = parties()?;
    let envelope = sealed(&p, &[42u8; 300])?;
    let value = envelope.to_value_for_tests();
    let ct = bridge_core::encoding::b64_var(value["ct"].as_str().unwrap_or_default(), "ct", 4096)?;
    for index in [0, ct.len() / 2, ct.len() - 1] {
        let mut changed = ct.clone();
        changed[index] ^= 0x01;
        let mut value = value.clone();
        value["ct"] = json!(bridge_core::encoding::b64(&changed));
        let tampered = Envelope::from_value(value)?;
        assert!(tampered.open(&p.bob, &p.alice_card).is_err());
    }
    Ok(())
}

#[test]
fn someone_else_cannot_claim_the_envelope_as_theirs() -> CoreResult<()> {
    // Mallory takes Alice's envelope, puts her own ID in "from" and signs it herself (re-attribution).
    let p = parties()?;
    let mallory = Identity::generate(&mut OsRng);
    let mallory_card = mallory.key_card(Role::Client, None, 0)?;
    let envelope = sealed(&p, b"von Alice")?;
    let mut value = envelope.to_value_for_tests();
    value["from"] = json!(mallory.id().as_str());
    // Mallory can not produce a valid signature over the changed envelope without Alice's key; even with her own key
    // the "from" is part of the encryption's associated data, so Bob can not decrypt it as Mallory's message.
    let forged = Envelope::from_value(value)?;
    assert!(forged.verify(&mallory_card).is_err());
    assert!(forged.open(&p.bob, &mallory_card).is_err());
    // Verifying with a card that does not match "from" fails
    assert_eq!(envelope.verify(&mallory_card), Err(CoreError::BadSignature));
    Ok(())
}

#[test]
fn time_window() -> CoreResult<()> {
    let p = parties()?;
    let envelope = sealed(&p, b"t")?;
    assert_eq!(envelope.check_time(NOW), Ok(()));
    assert_eq!(envelope.check_time(NOW + 600_000), Err(CoreError::Expired));
    assert_eq!(envelope.check_time(NOW - CLOCK_SKEW_MS - 1), Err(CoreError::NotYetValid));
    assert_eq!(envelope.check_time(NOW - CLOCK_SKEW_MS), Ok(()), "inside the tolerance");
    Ok(())
}

#[test]
fn size_limits() -> CoreResult<()> {
    let p = parties()?;
    assert!(matches!(sealed(&p, &vec![0u8; MAX_PLAINTEXT_BYTES + 1]), Err(CoreError::TooLarge(_))));
    let biggest = sealed(&p, &vec![0u8; MAX_PLAINTEXT_BYTES])?;
    assert!(biggest.to_bytes()?.len() <= MAX_ENVELOPE_BYTES, "the largest envelope fits the limit");
    assert!(matches!(Envelope::parse(&vec![b' '; MAX_ENVELOPE_BYTES + 1]), Err(CoreError::TooLarge(_))));
    let net = p.node.id().clone();
    for ttl in [0, 7 * 24 * 3600 + 1] {
        let address = Address { net: &net, to: &p.bob_card, kind: Kind::Msg, iat: NOW, ttl };
        assert!(Envelope::seal(&p.alice, &address, b"x", &mut OsRng).is_err(), "ttl {ttl}");
    }
    Ok(())
}

#[test]
fn garbage_never_panics() {
    let mut rng = OsRng;
    for size in [0usize, 1, 7, 64, 512, 4096] {
        for _ in 0..200 {
            let mut bytes = vec![0u8; size];
            rng.fill_bytes(&mut bytes);
            let _ = Envelope::parse(&bytes);
            let _ = KeyCard::parse(&bytes);
            let _ = bridge_core::Statement::parse(&bytes);
            let _ = bridge_core::SignedRequest::parse(&bytes);
            let _ = bridge_core::Puzzle::parse(&bytes);
            let _ = bridge_core::Part::parse(&bytes);
            let _ = bridge_core::Content::parse(&bytes);
        }
    }
    for text in [
        "{}",
        "[]",
        "null",
        r#"{"v":4,"t":"env"}"#,
        r#"{"v":4,"t":"env","id":"","net":"","from":"","to":"","iat":-1,"ttl":0,"kind":"x","epk":"","n":"","ct":"","sig":""}"#,
        r#"{"v":4.0}"#,
    ] {
        assert!(Envelope::parse(text.as_bytes()).is_err(), "{text}");
    }
}

#[test]
fn deep_or_oversized_objects_are_refused() -> CoreResult<()> {
    let p = parties()?;
    let mut value = sealed(&p, b"x")?.to_value_for_tests();
    value["extra"] = serde_json::from_str(&("[".repeat(20) + &"]".repeat(20))).unwrap_or(Value::Null);
    assert!(Envelope::from_value(value).is_err(), "deeply nested extra field");
    let mut card = p.alice_card.to_value();
    card["extra"] = json!("x".repeat(4000));
    assert!(matches!(KeyCard::from_value(card), Err(CoreError::TooLarge(_))));
    Ok(())
}
