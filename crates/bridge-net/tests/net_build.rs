//! Builds a whole small network the normal way: master key from 24 words, genesis manifest, admins, invite,
//! members, seals of level 1-3 (level 3 with several admins), heads, cosignatures, witnessed heads.

mod common;

use bridge_core::{Mnemonic, Role};
use bridge_net::statements::DELEGATION_LIFETIME_MS;
use bridge_net::{
    Applied, Ban, Body, Evidence, Invite, JoinMode, Member, NetError, NetResult, NetState, Revoke, RevokeTarget, Right,
    Rights, Seal, Service, Services, WitnessedHead, check_new_entries, issue_cosign, verify_head,
};
use common::{DAY, MIN, Net, T0, ZERO_WORDS, identity, node_card};
use rand_core::OsRng;

#[test]
fn master_key_from_words_is_the_network() -> NetResult<()> {
    // New words, shown once, typed in again later: the same network ID.
    let words = Mnemonic::generate(&mut OsRng);
    let typed = words.words().to_uppercase();
    assert_eq!(Mnemonic::parse(&typed)?.to_identity()?.id(), words.to_identity()?.id());
    // The fixture's network is the one of the official zero words.
    let net = Net::new(JoinMode::Open)?;
    assert_eq!(net.net, Mnemonic::parse(ZERO_WORDS)?.to_identity()?.id().clone());
    assert_eq!(net.state.manifest().card.role(), Role::Net);
    assert_eq!(net.state.card_of(&net.net), Some(&net.state.manifest().card));
    Ok(())
}

#[test]
fn small_network_end_to_end() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Invite)?;
    let t = T0 + MIN;

    // Before any seal the owner node counts as gateway (start gateway with card).
    assert_eq!(n.state.gateways(t), vec![(n.owner.id().clone(), Some(n.owner_card.clone()))]);

    // Admins: A (members, seals, bans), B and C (seals, rules).
    let a = n.delegate(10, &[Right::Members, Right::Seals, Right::Bans], t)?;
    let b = n.delegate(11, &[Right::Seals, Right::Rules], t)?;
    let c = n.delegate(12, &[Right::Seals, Right::Rules], t)?;
    assert_eq!(n.state.admin_rights(a.id(), t), Rights::of(&[Right::Members, Right::Seals, Right::Bans]));
    assert_eq!(n.state.admins(t).len(), 3);
    assert!(n.state.card_of(b.id()).is_some_and(|card| card.role() == Role::Admin));

    // The master seals the owner node: level 3, gateway + log + witness. From now on only sealed gateways count.
    n.seal_owner(t + 1)?;
    assert_eq!(n.state.level(n.owner.id(), t + 1), Some(3));
    assert_eq!(
        n.state.services(n.owner.id(), t + 1),
        Services::of(&[Service::Gateway, Service::Log, Service::Witness])
    );

    // Invite with 2 uses, created by A; the owner gateway admits two members with it, the third use is refused.
    let code = Invite::hash_code("K7Q2-M9XA-TT3P");
    n.accept(&n.sign(&Invite { code_hash: code, uses: 2 }, &a, t + 2)?)?;
    assert_eq!(n.state.invite_left(&code, t + 2), Some(2));
    let (x, y, z, w) = (identity(20), identity(21), identity(22), identity(23));
    for member in [&x, &y] {
        n.accept(&n.sign(&Member { member: member.id().clone(), invite: Some(code) }, &n.owner, t + 3)?)?;
    }
    assert_eq!(n.state.invite_left(&code, t + 3), Some(0));
    let reason = n.skip(&n.sign(&Member { member: z.id().clone(), invite: Some(code) }, &n.owner, t + 4)?)?;
    assert!(matches!(reason, NetError::QuotaExceeded(_)), "{reason:?}");
    // Invite mode: a gateway needs a code, an admin with "members" does not.
    let reason = n.skip(&n.sign(&Member { member: z.id().clone(), invite: None }, &n.owner, t + 4)?)?;
    assert!(matches!(reason, NetError::Forbidden(_)), "{reason:?}");
    n.accept(&n.sign(&Member { member: w.id().clone(), invite: None }, &a, t + 4)?)?;
    for member in [&x, &y, &w] {
        assert!(n.state.is_member(member.id(), t + 5));
        assert_eq!(n.state.check_login(member.id(), t + 5), Ok(0));
    }
    assert_eq!(n.state.check_login(z.id(), t + 5), Err(NetError::NotMember));
    assert_eq!(n.state.member_count(), 3);

    // Seal level 1 (A) and level 2 with storage (B).
    n.accept(&n.sign(&Seal { subject: x.id().clone(), level: 1, services: Services::NONE, card: None }, &a, t + 6)?)?;
    assert_eq!(n.state.level(x.id(), t + 6), Some(1));
    let storage = identity(30);
    let seal = Seal {
        subject: storage.id().clone(),
        level: 2,
        services: Services::of(&[Service::Storage]),
        card: Some(node_card(&storage, "https://storage.example")?),
    };
    n.accept(&n.sign(&seal, &b, t + 6)?)?;
    assert_eq!(n.state.level(storage.id(), t + 6), Some(2));
    assert!(n.state.services(storage.id(), t + 6).has(Service::Storage));

    // Manifest v2 by B alone (approvals.rules = 1): from now on 2 admins for rules and for seals of level 3.
    let mut v2 = n.state.manifest().next_version();
    v2.approvals.rules = 2;
    v2.approvals.seal3 = 2;
    v2.name = "Testnetz 2".into();
    n.accept(&n.sign(&v2, &b, t + 7)?)?;
    assert_eq!(n.state.manifest().version, 2);
    // v3 by B alone is not enough any more, by B + C it is.
    let mut v3 = v2.next_version();
    v3.description = "Mehr-Augen".into();
    let reason = n.skip(&n.sign(&v3, &b, t + 8)?)?;
    assert!(matches!(reason, NetError::Forbidden(_)), "{reason:?}");
    n.accept(&n.sign_multi(&v3, &[&b, &c], t + 8)?)?;
    assert_eq!(n.state.manifest().description, "Mehr-Augen");

    // Seal level 3 for a second gateway needs B + C now.
    let g2 = identity(31);
    let seal3 = Net::gateway_seal(&g2, 3)?;
    let reason = n.skip(&n.sign(&seal3, &b, t + 9)?)?;
    assert!(matches!(reason, NetError::Forbidden(_)), "{reason:?}");
    n.accept(&n.sign_multi(&seal3, &[&b, &c], t + 9)?)?;
    assert_eq!(n.state.level(g2.id(), t + 9), Some(3));
    let gateways = n.state.gateways(t + 9);
    assert_eq!(gateways.len(), 2);
    assert!(gateways.iter().all(|(_, card)| card.as_ref().is_some_and(|card| !card.urls().is_empty())));
    // The new gateway admits members (with a fresh invite).
    let code2 = Invite::hash_code("second");
    n.accept(&n.sign(&Invite { code_hash: code2, uses: 10 }, &a, t + 10)?)?;
    n.accept(&n.sign(&Member { member: z.id().clone(), invite: Some(code2) }, &g2, t + 10)?)?;
    assert!(n.state.is_member(z.id(), t + 10));

    // Ban and revoke.
    n.accept(&n.sign(&Ban { subject: x.id().clone(), reason: "Spam".into() }, &a, t + 11)?)?;
    assert!(n.state.is_banned(x.id(), t + 11));
    assert_eq!(n.state.level(x.id(), t + 11), None);
    assert_eq!(n.state.check_login(x.id(), t + 11), Err(NetError::Banned));
    assert!(!n.state.is_banned(x.id(), t + 11 + 30 * DAY), "a ban lasts until its exp");
    let y_member = n.sign(&Member { member: y.id().clone(), invite: Some(code) }, &n.owner, t + 3)?;
    let revoke = Revoke { target: RevokeTarget::Statement(y_member.hash_bytes()), reason: "Test".into() };
    n.accept(&n.sign(&revoke, &a, t + 12)?)?;
    assert!(!n.state.is_member(y.id(), t + 12));
    assert!(n.state.is_revoked(&y_member.hash_bytes()));

    // Heads: the owner node (log operator) signs, the owner node (witness) cosigns; checked against the state.
    let head_statement = n.log.issue_head(&n.owner, t + 13)?;
    let head = verify_head(&head_statement, &n.net, &n.owner_card)?;
    assert_eq!(head.size(), n.log.size());
    assert!(n.log.matches(&head));
    check_new_entries(&n.log.entries()[1..], &head)?;
    let cosign = issue_cosign(&n.owner, &head, t + 14)?;
    let witnessed = WitnessedHead { head: head_statement.clone(), cosigns: vec![cosign] };
    let rules = n.state.rules_for_head(head.size()).ok_or(NetError::NotFound("rules".into()))?;
    assert_eq!(witnessed.check(&n.net, &rules, &n.state, t + 15)?, head);
    // Every entry is provably in the head.
    for index in 0..head.size() {
        let proof = n.log.tree().inclusion(index, head.size())?;
        let leaf = bridge_net::merkle::leaf_hash(n.log.entry(index).unwrap_or_default());
        assert!(bridge_net::merkle::verify_inclusion(&leaf, index, head.size(), &proof, head.root()));
    }
    // Honest heads over time never form evidence.
    n.accept(&n.sign(&Ban { subject: identity(40).id().clone(), reason: String::new() }, &a, t + 16)?)?;
    let later = n.log.issue_head(&n.owner, t + 17)?;
    assert!(Evidence::check(&head_statement, &later, &n.owner_card, Some(n.log.tree())).is_none());
    let proof = n.log.tree().consistency(head.size(), n.log.size())?;
    assert!(bridge_net::merkle::verify_consistency(head.size(), n.log.size(), head.root(), &n.log.root(), &proof));

    // Determinism: replaying the whole log gives exactly the same state.
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

#[test]
fn open_and_closed_networks() -> NetResult<()> {
    // Open: the start gateway admits anybody without a code, before any seal.
    let mut open = Net::new(JoinMode::Open)?;
    let x = identity(20);
    open.accept(&open.sign(&Member { member: x.id().clone(), invite: None }, &open.owner, T0 + 1)?)?;
    assert!(open.state.is_member(x.id(), T0 + 1));

    // Closed: gateways admit nobody, admins with "members" do.
    let mut closed = Net::new(JoinMode::Closed)?;
    let reason =
        closed.skip(&closed.sign(&Member { member: x.id().clone(), invite: None }, &closed.owner, T0 + 1)?)?;
    assert!(matches!(reason, NetError::Forbidden(_)));
    let admin = closed.delegate(10, &[Right::Members], T0 + 1)?;
    closed.accept(&closed.sign(&Member { member: x.id().clone(), invite: None }, &admin, T0 + 2)?)?;
    assert!(closed.state.is_member(x.id(), T0 + 2));
    Ok(())
}

#[test]
fn grants_expire_renew_and_are_forgotten() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let x = identity(20);
    let member = Member { member: x.id().clone(), invite: None };
    n.accept(&member.sign(&n.net, T0 + 1, T0 + DAY, &n.owner)?)?;
    assert!(n.state.is_member(x.id(), T0 + DAY - 1));
    assert!(!n.state.is_member(x.id(), T0 + DAY));
    // Renewal: a newer statement replaces the old one; the old one can never come back.
    let renewal = member.sign(&n.net, T0 + 2, T0 + 10 * DAY, &n.owner)?;
    n.accept(&renewal)?;
    assert!(n.state.is_member(x.id(), T0 + 5 * DAY));
    let first = member.sign(&n.net, T0 + 1, T0 + DAY, &n.owner)?;
    assert!(matches!(n.skip(&first)?, NetError::Forbidden(_)), "replaced");
    // An older statement does not replace a newer one.
    let older = member.sign(&n.net, T0, T0 + 20 * DAY, &n.owner)?;
    assert!(matches!(n.skip(&older)?, NetError::Forbidden(_)));
    // After the log clock passed the expiry, the record is forgotten (bounded memory).
    let delegation_end = T0 + 11 * DAY;
    n.accept(&n.sign(
        &Ban { subject: identity(40).id().clone(), reason: String::new() },
        &n.master,
        delegation_end,
    )?)?;
    assert_eq!(n.state.member_count(), 0);
    assert_eq!(n.state.clock(), delegation_end);
    assert!(!n.state.is_revoked(&first.hash_bytes()), "expired revocations are forgotten too");
    // Default delegation lifetime constant is 90 days.
    assert_eq!(DELEGATION_LIFETIME_MS, 90 * DAY);
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

#[test]
fn incremental_equals_replay_with_skips() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let admin = n.delegate(10, &[Right::Members, Right::Seals, Right::Bans], T0 + 1)?;
    let mut skipped = 0;
    for i in 0..60u8 {
        let who = identity(100 + i);
        let statement = match i % 6 {
            0 => n.sign(&Member { member: who.id().clone(), invite: None }, &n.owner, T0 + 10 + i64::from(i))?,
            1 => n.sign(&Member { member: who.id().clone(), invite: None }, &who, T0 + 10)?, // not allowed
            2 => n.sign(
                &Seal { subject: who.id().clone(), level: 1, services: Services::NONE, card: None },
                &admin,
                T0 + 20,
            )?,
            3 => n.sign(&Ban { subject: who.id().clone(), reason: format!("{i}") }, &admin, T0 + 30)?,
            4 => n.sign(
                &Seal { subject: who.id().clone(), level: 3, services: Services::NONE, card: None },
                &admin,
                T0 + 40,
            )?,
            _ => n.sign(&Ban { subject: who.id().clone(), reason: String::new() }, &who, T0 + 50)?, // not allowed
        };
        if let Applied::Skipped(_) = n.push(&statement)? {
            skipped += 1;
        }
        if i % 7 == 0 {
            n.push_bytes(format!("garbage {i}").as_bytes())?;
        }
    }
    assert_eq!(skipped, 20, "members and bans signed by non-admins");
    let replayed = n.replayed()?;
    assert_eq!(replayed, n.state);
    assert_eq!(replayed.size(), n.log.size());
    // Two independent replays agree, and a replay of a prefix plus the rest equals the whole.
    let entries = n.log.entries();
    let mut partial = NetState::replay(&n.net, &entries[..30])?;
    for entry in &entries[30..] {
        partial.apply(entry);
    }
    assert_eq!(partial, n.state);
    assert_eq!(NetState::replay(&n.net, entries)?, replayed);
    Ok(())
}
