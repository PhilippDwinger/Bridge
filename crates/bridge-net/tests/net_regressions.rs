//! Regression tests for the findings of review 3 (each failed before its fix): malleable multi-signatures, the
//! log rules across a manifest change, evicting members by replacement, revoked start gateways coming back, and
//! filling the ban table. Adapted from the reviewer's scratch tests.

mod common;

use bridge_core::{Id, Identity, Role, Statement};
use bridge_net::state::{MAX_BANS, MAX_BANS_PER_ADMIN_PER_DAY};
use bridge_net::{
    Ahead, Applied, Ban, Body, JoinMode, Log, LogRules, Member, NetError, NetResult, NetState, Revoke, RevokeTarget,
    Right, RulesAhead, Seal, Services, WitnessedHead, issue_cosign, verify_head,
};
use common::{DAY, MIN, Net, T0, identity, node_card};
use serde_json::Value;

fn member(who: &Identity) -> Member {
    Member { member: who.id().clone(), invite: None }
}

/// A syntactically valid ID that nobody holds a key for (cheap - no key generation).
fn fake_id(n: u32) -> NetResult<Id> {
    let digits: String = format!("{n:08}").bytes().map(|digit| char::from(b'a' + (digit - b'0'))).collect();
    Ok(Id::parse(&format!("{}{digits}", "q".repeat(24)))?)
}

fn not_found(what: &str) -> NetError {
    NetError::NotFound(what.into())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 1: multi-signed statements are not malleable

/// A revoked multi-signed seal can not come back - neither with its signatures swapped or padded (refused as
/// malformed), nor with another set of signers (same hash = same statement, still revoked).
#[test]
fn revoked_multisig_seal_can_not_be_resurrected() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |m| m.approvals.seal3 = 2)?;
    let a = n.delegate(10, &[Right::Seals], T0)?;
    let b = n.delegate(11, &[Right::Seals], T0)?;
    let c = n.delegate(12, &[Right::Seals], T0)?;
    let node = identity(20);
    let body = Net::gateway_seal(&node, 3)?;
    let seal = n.sign_multi(&body, &[&a, &b], T0 + 1)?;
    n.accept(&seal)?;
    assert_eq!(n.state.level(node.id(), T0 + 2), Some(3));
    let revoke = Revoke { target: RevokeTarget::Statement(seal.hash_bytes()), reason: String::new() };
    n.accept(&n.sign(&revoke, &n.master, T0 + 3)?)?;
    assert_eq!(n.state.level(node.id(), T0 + 4), None, "revoked");
    assert!(n.skip(&seal).is_ok(), "the original can not come back");

    // The same statement with the two signatures swapped: not a statement at all any more ...
    let mut swapped = seal.to_value();
    if let Some(Value::Array(sigs)) = swapped.get_mut("sigs") {
        sigs.reverse();
    }
    assert!(matches!(Statement::from_value(swapped.clone()), Err(bridge_core::CoreError::BadFormat(_))));
    // ... and as raw log bytes it is skipped (a follower mirrors it, the state does not count it).
    let bytes = bridge_core::json::canonical(&swapped)?;
    assert!(matches!(common::expect_skip(n.push_bytes(&bytes)?)?, NetError::BadFormat(_)));
    // An extra field inside one entry: the same.
    let mut padded = seal.to_value();
    if let Some(Value::Object(entry)) = padded.get_mut("sigs").and_then(|sigs| sigs.get_mut(0)) {
        entry.insert("x".into(), Value::from(1));
    }
    assert!(Statement::from_value(padded.clone()).is_err());
    assert!(bridge_net::parse_entry(&bridge_core::json::canonical(&padded)?).is_err());

    // Another valid set of signers for the same content (a, c / c, b): same hash, so still revoked - for the log
    // operator's candidate check as well as on replay.
    for signers in [[&a, &c], [&c, &b]] {
        let other = n.sign_multi(&body, &signers, T0 + 1)?;
        assert_eq!(other.hash_bytes(), seal.hash_bytes());
        assert_ne!(other.canonical_bytes(), seal.canonical_bytes());
        assert!(matches!(n.state.validate_candidate(&other, T0 + 5), Err(NetError::Forbidden(_))));
        assert!(matches!(n.skip(&other)?, NetError::Forbidden(_)));
    }
    assert_eq!(n.state.level(node.id(), T0 + 6), None, "revoked seal stays revoked");

    // Replacement works by content too: re-signing a current seal by other admins is not "newer".
    let fresh = n.sign_multi(&Net::gateway_seal(&identity(21), 3)?, &[&a, &b], T0 + 7)?;
    n.accept(&fresh)?;
    let same_content = n.sign_multi(&Net::gateway_seal(&identity(21), 3)?, &[&b, &c], T0 + 7)?;
    assert!(matches!(n.skip(&same_content)?, NetError::Forbidden(_)), "not newer than itself");
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 2: the log rules across a manifest change (docs/06 §5)

/// A network whose owner is operator and only witness, with a second node W (sealed, with card).
struct Change {
    n: Net,
    witness: Identity,
    /// Index of the manifest entry that changes the rules.
    j: u64,
    old: LogRules,
    new: LogRules,
}

/// Changes the witnesses from the owner to `W` by a manifest signed by the master (entry j).
fn witness_change() -> NetResult<Change> {
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    let witness = identity(30);
    let seal = Seal {
        subject: witness.id().clone(),
        level: 2,
        services: Services::of(&[bridge_net::Service::Witness]),
        card: Some(node_card(&witness, "https://w.example")?),
    };
    n.accept(&n.sign(&seal, &n.master, T0 + 2)?)?;
    let old = n.state.manifest().log_rules();
    let mut manifest = n.state.manifest().next_version();
    manifest.witnesses = vec![witness.id().clone()];
    let j = n.log.size();
    n.accept(&manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?)?;
    let new = n.state.manifest().log_rules();
    assert_ne!(old, new);
    Ok(Change { n, witness, j, old, new })
}

fn witnessed(n: &Net, log: &Log, cosigners: &[&Identity], at: i64) -> NetResult<WitnessedHead> {
    let statement = log.issue_head(&n.owner, at)?;
    let head = verify_head(&statement, &n.net, &n.owner_card)?;
    let cosigns = cosigners.iter().map(|w| issue_cosign(w, &head, at)).collect::<NetResult<_>>()?;
    Ok(WitnessedHead { head: statement, cosigns })
}

#[test]
fn rules_for_a_head_depend_on_its_size() -> NetResult<()> {
    let Change { mut n, witness, j, old, new } = witness_change()?;
    // Heads up to and including the change are checked against the old rules, all larger ones against the new.
    for size in 1..=j + 1 {
        assert_eq!(n.state.rules_for_head(size).as_ref(), Some(&old), "head of size {size}");
    }
    assert_eq!(n.state.rules_for_head(j + 2), Some(new.clone()), "the next head");
    assert_eq!((n.state.rules_for_head(0), n.state.rules_for_head(j + 3)), (None, None), "unknown sizes");
    assert_eq!(n.state.last_rules_change(), j);
    // A manifest that does not touch the rules changes nothing here.
    let mut manifest = n.state.manifest().next_version();
    manifest.name = "Anders".into();
    n.accept(&manifest.sign(&n.net, T0 + 4, T0 + 30 * DAY, &n.master)?)?;
    assert_eq!(n.state.last_rules_change(), j);
    assert_eq!(n.state.rules_for_head(j + 1), Some(old.clone()));
    assert_eq!(n.state.rules_for_head(n.log.size()), Some(new.clone()));

    // The transition head (size j + 1): only the old witness counts - the new one can not cut the old set out.
    let transition = Log::from_entries(n.net.clone(), &n.log.entries()[..usize::try_from(j + 1).unwrap_or(0)])?;
    let rules = n.state.rules_for_head(j + 1).ok_or_else(|| not_found("rules"))?;
    witnessed(&n, &transition, &[&n.owner], T0 + 5)?.check(&n.net, &rules, &n.state, T0 + 6)?;
    let by_new = witnessed(&n, &transition, &[&witness], T0 + 5)?;
    assert!(matches!(by_new.check(&n.net, &rules, &n.state, T0 + 6), Err(NetError::Forbidden(_))));
    // Every later head: only the new witness counts - the old (removed) one can not witness anything new.
    let rules = n.state.rules_for_head(n.log.size()).ok_or_else(|| not_found("rules"))?;
    witnessed(&n, &n.log, &[&witness], T0 + 5)?.check(&n.net, &rules, &n.state, T0 + 6)?;
    let by_old = witnessed(&n, &n.log, &[&n.owner], T0 + 5)?;
    assert!(matches!(by_old.check(&n.net, &rules, &n.state, T0 + 6), Err(NetError::Forbidden(_))));
    // Replaying gives the same history.
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

/// A follower that is behind the change decides with `rules_ahead`: a validly signed manifest change among the
/// new entries means "replay a copy"; made-up manifests do not count, so they can not smuggle in other rules.
#[test]
fn followers_behind_a_change_replay_and_are_not_fooled() -> NetResult<()> {
    let Change { n, witness, j, old, new } = witness_change()?;
    let entries = n.log.entries();
    let split = usize::try_from(j).unwrap_or(0);
    let behind = NetState::replay(&n.net, &entries[..split])?;
    let (master_card, version) = (behind.manifest().card.clone(), behind.manifest().version);

    // Up to the transition head the old rules hold - no replay needed.
    let to_transition = Ahead::parse(&master_card, version, &entries[split..=split]);
    assert_eq!(behind.rules_ahead(&to_transition), RulesAhead::Known(old.clone()));
    // Beyond it: the signed manifest decides, only replaying tells.
    let mut more = entries[split..].to_vec();
    more.push(
        n.sign(&Ban { subject: fake_id(1)?, reason: String::new() }, &n.master, T0 + 4)?.canonical_bytes().to_vec(),
    );
    assert_eq!(behind.rules_ahead(&Ahead::parse(&master_card, version, &more)), RulesAhead::Replay);
    let mut copy = behind.clone();
    for entry in &more {
        assert_eq!(copy.apply(entry), Applied::Accepted);
    }
    assert_eq!(copy.rules_for_head(copy.size()), Some(new));

    // An attacker's log: instead of the real change, a manifest naming its own witness, signed by itself (or by
    // nobody who may sign manifests). It does not count: the head stays under the old rules - and fails there.
    let attacker = identity(66);
    let mut forged = behind.manifest().next_version();
    forged.witnesses = vec![attacker.id().clone()];
    let forged = forged.sign(&n.net, T0 + 3, T0 + DAY, &attacker)?;
    let mut fake: Vec<Vec<u8>> = entries[..split].to_vec();
    fake.push(forged.canonical_bytes().to_vec());
    fake.push(
        n.sign(&Ban { subject: witness.id().clone(), reason: String::new() }, &n.master, T0 + 4)?
            .canonical_bytes()
            .to_vec(),
    );
    let ahead = Ahead::parse(&master_card, version, &fake[split..]);
    let RulesAhead::Known(rules) = behind.rules_ahead(&ahead) else {
        return Err(NetError::Forbidden("a made-up manifest must not force a replay".into()));
    };
    assert_eq!(rules, old);
    let fake_log = Log::from_entries(n.net.clone(), &fake)?;
    let attacker_card = attacker.key_card(Role::Node, None, T0)?;
    let head = witnessed(&n, &fake_log, &[&attacker], T0 + 5)?;
    let cards = (&behind, vec![attacker_card]);
    assert!(matches!(head.check(&n.net, &rules, &cards, T0 + 6), Err(NetError::Forbidden(_))));
    // Many made-up "manifests" are cheap to dismiss as well (no signature checks for unknown signers).
    let mut flood: Vec<Vec<u8>> = (0..50).map(|_| forged.canonical_bytes().to_vec()).collect();
    flood.push(Vec::new());
    assert_eq!(behind.rules_ahead(&Ahead::parse(&master_card, version, &flood)), RulesAhead::Known(old));
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 3: no gateway evicts members it did not admit

#[test]
fn gateway_can_not_evict_a_member_it_did_not_admit() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let admin = n.delegate(10, &[Right::Seals, Right::Members], T0)?;
    let (evil, honest) = (identity(30), identity(31));
    for gateway in [&evil, &honest] {
        n.accept(&n.sign(&Net::gateway_seal(gateway, 2)?, &admin, T0 + 1)?)?;
    }
    let victim = identity(40);
    let long = member(&victim).sign(&n.net, T0 + 2, T0 + 365 * DAY, &admin)?;
    n.accept(&long)?;
    // The evil gateway's "newer" membership that expires in one minute: refused (also by the operator's check).
    let short = member(&victim).sign(&n.net, T0 + 4, T0 + 4 + MIN, &evil)?;
    assert!(matches!(n.state.validate_candidate(&short, T0 + 4), Err(NetError::Forbidden(_))));
    assert!(matches!(n.skip(&short)?, NetError::Forbidden(_)));
    // A long one from a gateway that did not admit the member: refused too (only issuer, admin or after expiry).
    let other = member(&victim).sign(&n.net, T0 + 5, T0 + 400 * DAY, &evil)?;
    assert!(matches!(n.skip(&other)?, NetError::Forbidden(_)));
    assert!(n.state.is_member(victim.id(), T0 + 4 + 2 * MIN), "still a member");

    // The issuing gateway renews its own member, but never shortens it; an admin may do both.
    let mine = identity(41);
    n.accept(&member(&mine).sign(&n.net, T0 + 6, T0 + 100 * DAY, &honest)?)?;
    assert!(matches!(n.skip(&member(&mine).sign(&n.net, T0 + 7, T0 + DAY, &honest)?)?, NetError::Forbidden(_)));
    n.accept(&member(&mine).sign(&n.net, T0 + 8, T0 + 200 * DAY, &honest)?)?;
    n.accept(&member(&mine).sign(&n.net, T0 + 9, T0 + 10 * MIN, &admin)?)?;
    // Once a membership has expired, any gateway may admit the member again.
    let later = T0 + 9 + 11 * MIN;
    n.accept(&n.sign(&Ban { subject: fake_id(2)?, reason: String::new() }, &n.master, later)?)?;
    n.accept(&member(&mine).sign(&n.net, later + 1, later + DAY, &evil)?)?;
    assert!(n.state.is_member(mine.id(), later + 2));
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 5: a revoked start gateway never comes back

#[test]
fn revoked_start_gateway_stays_revoked_after_the_cutoff_is_forgotten() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let owner_id = n.owner.id().clone();
    assert!(n.state.gateways(T0 + 1).iter().any(|(id, _)| id == &owner_id));
    let revoke =
        Revoke { target: RevokeTarget::Identity { id: owner_id.clone(), cascade: false }, reason: String::new() };
    n.accept(&n.sign(&revoke, &n.master, T0 + 1)?)?;
    assert!(!n.state.gateways(T0 + 2).iter().any(|(id, _)| id == &owner_id), "revoked");
    // More than two years pass in the log (the identity cutoff is forgotten by then).
    let later = T0 + 2 * 366 * DAY + 20 * MIN;
    n.accept(&Ban { subject: fake_id(3)?, reason: String::new() }.sign(&n.net, later, later + DAY, &n.master)?)?;
    assert!(!n.state.gateways(later + 1).iter().any(|(id, _)| id == &owner_id), "still no gateway");
    let admitted = member(&identity(60)).sign(&n.net, later + 2, later + DAY, &n.owner)?;
    assert!(matches!(n.skip(&admitted)?, NetError::Forbidden(_)), "can not admit members");
    // A new manifest that lists it again does not bring it back either.
    let mut manifest = n.state.manifest().next_version();
    manifest.description = "neu".into();
    n.accept(&manifest.sign(&n.net, later + 3, later + DAY, &n.master)?)?;
    assert!(!n.state.gateways(later + 4).iter().any(|(id, _)| id == &owner_id));
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 7: the ban table can not be filled against the master

#[test]
fn bans_are_capped_per_admin_and_the_master_keeps_a_reserve() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |m| m.limits.log_entries_per_day = 100_000)?;
    let cap = MAX_BANS_PER_ADMIN_PER_DAY;
    let admins: Vec<Identity> =
        (0..10u8).map(|seed| n.delegate(100 + seed, &[Right::Bans], T0)).collect::<NetResult<_>>()?;
    let ban = |subject: u32| -> NetResult<Ban> { Ok(Ban { subject: fake_id(subject)?, reason: String::new() }) };
    // One admin: at most `cap` bans per day; the next day it may go on.
    let mut subject = 0u32;
    for _ in 0..cap {
        subject += 1;
        n.accept(&n.sign(&ban(subject)?, &admins[0], T0 + 1)?)?;
    }
    subject += 1;
    let one_more = n.sign(&ban(subject)?, &admins[0], T0 + 1)?;
    assert!(matches!(n.state.validate_candidate(&one_more, T0 + 1), Err(NetError::QuotaExceeded(_))));
    assert!(matches!(n.skip(&one_more)?, NetError::QuotaExceeded(_)));
    // Ten admins fill the admin part of the table ...
    for admin in &admins[1..] {
        for _ in 0..cap {
            subject += 1;
            n.accept(&n.sign(&ban(subject)?, admin, T0 + 2)?)?;
        }
    }
    let total = usize::try_from(cap).unwrap_or(usize::MAX) * admins.len();
    assert!(total >= MAX_BANS);
    subject += 1;
    assert!(matches!(n.skip(&n.sign(&ban(subject)?, &admins[0], T0 + DAY)?)?, NetError::QuotaExceeded(_)));
    // ... but the master can still ban (its reserve).
    let target = identity(77);
    n.accept(&n.sign(&Ban { subject: target.id().clone(), reason: "Master".into() }, &n.master, T0 + DAY)?)?;
    assert!(n.state.is_banned(target.id(), T0 + DAY + 1));
    // A cascade revocation of an admin removes the bans it issued (here: a stolen key that flooded the table).
    let first = fake_id(1)?;
    assert!(n.state.is_banned(&first, T0 + DAY + 1));
    let cascade = Revoke {
        target: RevokeTarget::Identity { id: admins[0].id().clone(), cascade: true },
        reason: "gestohlen".into(),
    };
    n.accept(&n.sign(&cascade, &n.master, T0 + DAY + 2)?)?;
    assert!(!n.state.is_banned(&first, T0 + DAY + 3), "bans of the stolen key are gone");
    assert!(n.state.is_banned(&fake_id(subject - 2)?, T0 + DAY + 3), "bans of other admins stay");
    // Room again for the other admins.
    n.accept(&n.sign(&ban(subject + 1)?, &admins[1], T0 + DAY + 4)?)?;
    Ok(())
}

#[test]
fn master_bans_are_not_blocked_by_the_per_subject_limit() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let admin = n.delegate(10, &[Right::Bans], T0)?;
    let victim = identity(50);
    for minute in 0..bridge_net::state::MAX_BANS_PER_SUBJECT {
        let short = Ban { subject: victim.id().clone(), reason: format!("{minute}") };
        n.accept(&short.sign(&n.net, T0 + 1, T0 + 2 * MIN, &admin)?)?;
    }
    let ninth = Ban { subject: victim.id().clone(), reason: "9".into() };
    assert!(matches!(n.skip(&n.sign(&ninth, &admin, T0 + 2)?)?, NetError::QuotaExceeded(_)));
    let year = Ban { subject: victim.id().clone(), reason: "ein Jahr".into() };
    n.accept(&year.sign(&n.net, T0 + 2, T0 + 365 * DAY, &n.master)?)?;
    assert!(n.state.is_banned(victim.id(), T0 + 300 * DAY), "the master's long ban counts");
    Ok(())
}
