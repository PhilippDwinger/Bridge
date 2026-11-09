//! Regression tests for the findings of review 5 in the pure network logic, adapted from the reviewer's scratch
//! tests (each showed the defect before its fix, now each asserts the fixed behaviour):
//! - finding 1 (`words_alone_fork_a_lagging_follower`): a follower that passes a change of the log rules needs its
//!   transition head under the old rules - the 24 words alone can no longer fork it;
//! - finding 2 (`precheck_blocks_head_cosigned_by_witness_sealed_later`,
//!   `may_fetch_refuses_honest_head_when_one_cosigner_card_unknown`): cosignatures of witnesses whose card is not
//!   known yet count as "maybe" before fetching;
//! - finding 3 (`may_fetch_accepts_forged_head_signature`, `single_rules_admin_below_threshold_counts_ahead`): the
//!   head is verified whenever its operator's card is known, a manifest only counts if replay could take it;
//! - finding 4 (`single_seals_admin_rolls_back_card_via_level_1`): the newest card wins, not the newest seal;
//! - finding 5 (`known_admin_raised_ahead_is_refused`): a known signer without `rules` is unknown, not invalid.

mod common;

use std::collections::BTreeMap;

use bridge_core::{Identity, KeyCard, Role, Statement};
use bridge_net::{
    Ahead, Applied, Ban, Body, Delegation, Head, JoinMode, Log, Manifest, NetError, NetResult, NetState, Right, Rights,
    RulesAhead, Seal, Service, Services, Transitions, Tree, WitnessedHead, issue_cosign, verify_head,
};
use common::{DAY, Net, T0, identity, node_card};
use serde_json::Value;

fn seal(node: &Identity, level: u8, services: &[Service], card: Option<KeyCard>) -> Seal {
    Seal { subject: node.id().clone(), level, services: Services::of(services), card }
}

fn witness_card(node: &Identity) -> Option<KeyCard> {
    node_card(node, "https://w.example").ok()
}

/// A head over the whole `log` signed by `operator` (card `card`) and cosigned by `cosigners`.
fn head_by(
    n: &Net,
    log: &Log,
    operator: &Identity,
    card: &KeyCard,
    cosigners: &[&Identity],
    at: i64,
) -> NetResult<WitnessedHead> {
    let statement = log.issue_head(operator, at)?;
    let head = verify_head(&statement, &n.net, card)?;
    let cosigns = cosigners.iter().map(|w| issue_cosign(w, &head, at)).collect::<NetResult<_>>()?;
    Ok(WitnessedHead { head: statement, cosigns })
}

/// A head over the whole `log` signed by the owner node.
fn head_with(n: &Net, log: &Log, cosigners: &[&Identity], at: i64) -> NetResult<WitnessedHead> {
    head_by(n, log, &n.owner, &n.owner_card, cosigners, at)
}

/// The log as it was after its first `size` entries.
fn prefix(n: &Net, size: u64) -> NetResult<Log> {
    Log::from_entries(n.net.clone(), &n.log.entries()[..usize::try_from(size).unwrap_or(0)])
}

fn ban(n: &Net, seed: u8, at: i64) -> NetResult<Statement> {
    n.sign(&Ban { subject: identity(seed).id().clone(), reason: String::new() }, &n.master, at)
}

/// A head of size 65,536 that claims the owner as signer but is signed by an attacker.
fn forged_head(n: &Net) -> NetResult<WitnessedHead> {
    let body = bridge_net::HeadBody { size: 65_536, root: [7u8; 32] };
    let mut value = body.sign(&n.net, T0 + 5, T0 + DAY, &identity(66))?.to_value();
    value["iss"] = Value::from(n.owner.id().as_str());
    Ok(WitnessedHead { head: Statement::from_value(value)?, cosigns: Vec::new() })
}

/// What a follower behind `state` does with the fetched `entries` up to `witnessed` (docs/06 §5 steps 3-4): the
/// rules ahead, the head checked on a copy, the changes of the log rules passed on the way.
fn catch_up(
    state: &NetState,
    entries: &[Vec<u8>],
    witnessed: &WitnessedHead,
    now: i64,
) -> NetResult<(Head, Transitions)> {
    let ahead = Ahead::parse(&state.manifest().card, state.manifest().version, entries);
    if state.rules_ahead(&ahead) != RulesAhead::Replay {
        return Err(NetError::Forbidden("expected a replay on a copy".into()));
    }
    let mut copy = state.clone();
    let mut transitions = Transitions::default();
    for entry in entries {
        copy.apply_tracked(entry, &ahead, &mut transitions);
    }
    Ok((copy.check_witnessed(witnessed, &(&copy, &ahead), now)?, transitions))
}

fn found(heads: &[(u64, &WitnessedHead)]) -> BTreeMap<u64, WitnessedHead> {
    heads.iter().map(|(size, head)| (*size, (*head).clone())).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 1: transition heads when catching up

/// The words alone: a fabricated suffix installs an attacker's log operator and witness with a manifest of the net
/// key alone, they sign and cosign a head. A lagging follower still fetches it (the manifest is genuine) and the head
/// passes under the new rules - but the change has no transition head under the old rules, so it is not taken.
#[test]
fn the_words_alone_can_not_fork_a_lagging_follower() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    n.accept(&ban(&n, 80, T0 + 2)?)?;
    let behind = n.state.clone();
    let start = usize::try_from(behind.size()).unwrap_or(0);
    let (op2, w2) = (identity(70), identity(71));
    let mut fork = Net::new(JoinMode::Open)?;
    for entry in n.log.entries().iter().skip(1) {
        fork.push_bytes(entry)?;
    }
    let card2 = op2.key_card_with(Role::Node, None, &["https://evil.example".to_owned()], None, T0)?;
    fork.accept(&fork.sign(&seal(&op2, 3, &[Service::Log], Some(card2.clone())), &fork.master, T0 + 3)?)?;
    fork.accept(&fork.sign(&seal(&w2, 2, &[Service::Witness], witness_card(&w2)), &fork.master, T0 + 3)?)?;
    let mut manifest = fork.state.manifest().next_version();
    (manifest.logs, manifest.witnesses, manifest.witness_threshold) =
        (vec![op2.id().clone()], vec![w2.id().clone()], 1);
    let change = manifest.sign(&fork.net, T0 + 4, T0 + 30 * DAY, &fork.master)?;
    let index = fork.log.size();
    fork.accept(&change)?;
    fork.accept(&ban(&fork, 81, T0 + 5)?)?;
    let fake = head_by(&fork, &fork.log, &op2, &card2, &[&w2], T0 + 6)?;
    let now = T0 + 7;
    // The pre-fetch gate lets it through (a genuine manifest ahead) and the head passes on the copy ...
    behind.may_fetch(&fake, &change, index, now)?;
    let (head, transitions) = catch_up(&behind, &fork.log.entries()[start..], &fake, now)?;
    let passed: Vec<u64> = transitions.iter().map(bridge_net::Transition::index).collect();
    assert_eq!(passed, vec![index], "the follower notes the change it passes");
    // ... but nothing endorses the change: no transition head at all ...
    let tree: &Tree = fork.log.tree();
    let size = index + 1;
    assert!(transitions.verify(&n.net, tree, &head, &BTreeMap::new()).is_err());
    // ... one by the new operator and witness (not the rules before the change) ...
    let fork_at = Log::from_entries(fork.net.clone(), &fork.log.entries()[..usize::try_from(size).unwrap_or(0)])?;
    let by_new = head_by(&fork, &fork_at, &op2, &card2, &[&w2], T0 + 6)?;
    assert!(transitions.verify(&n.net, tree, &head, &found(&[(size, &by_new)])).is_err());
    // ... nor the rescue form with the words (net key cosignature) but without the old operator's key ...
    let with_words = head_by(&fork, &fork_at, &op2, &card2, &[&fork.master], T0 + 6)?;
    assert!(transitions.verify(&n.net, tree, &head, &found(&[(size, &with_words)])).is_err());
    // ... nor the honest head of that size (other entries: another root).
    for seed in 0..8u8 {
        if n.log.size() < size {
            n.accept(&ban(&n, 100 + seed, T0 + 3)?)?;
        }
    }
    let honest = head_with(&n, &prefix(&n, size)?, &[&n.owner], T0 + 6)?;
    assert!(transitions.verify(&n.net, tree, &head, &found(&[(size, &honest)])).is_err());
    // Only with the old operator's key as well (stolen) - the rescue form - would the fork pass: words AND key.
    let stolen = head_by(&fork, &fork_at, &fork.owner, &fork.owner_card, &[&fork.master], T0 + 6)?;
    let kept = transitions.verify(&n.net, tree, &head, &found(&[(size, &stolen)]))?;
    assert_eq!(kept.iter().map(|(size, _)| *size).collect::<Vec<_>>(), vec![size]);
    Ok(())
}

/// Two honest changes one after the other (witness switch, then operator switch by an admin with `rules`): a
/// follower behind both takes the head with both transition heads - and not without one of them. Transition heads
/// are checked without a time (they are long expired), but by size, rules and root.
#[test]
fn honest_changes_are_endorsed_by_their_transition_heads() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    let admin = n.delegate(10, &[Right::Rules], T0 + 1)?;
    let (w, op2) = (identity(30), identity(31));
    let card2 = node_card(&op2, "https://op2.example")?;
    n.accept(&n.sign(&seal(&w, 2, &[Service::Witness], witness_card(&w)), &n.master, T0 + 2)?)?;
    n.accept(&n.sign(&seal(&op2, 3, &[Service::Log], Some(card2.clone())), &n.master, T0 + 2)?)?;
    let behind = n.state.clone();
    let start = usize::try_from(behind.size()).unwrap_or(0);
    // Change 1: the witness W (by the net key). Its transition head is witnessed by the owner (the old witness).
    let mut manifest = n.state.manifest().next_version();
    manifest.witnesses = vec![w.id().clone()];
    let j1 = n.log.size();
    n.accept(&manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?)?;
    let t1 = head_with(&n, &n.log, &[&n.owner], T0 + 3)?;
    n.accept(&ban(&n, 90, T0 + 4)?)?;
    // Change 2: operator op2 (by the admin). Its transition head: the owner signs (old operator), W cosigns.
    let mut manifest = n.state.manifest().next_version();
    manifest.logs = vec![op2.id().clone()];
    let j2 = n.log.size();
    n.accept(&manifest.sign(&n.net, T0 + 5, T0 + 30 * DAY, &admin)?)?;
    let t2 = head_with(&n, &n.log, &[&w], T0 + 5)?;
    n.accept(&ban(&n, 91, T0 + 6)?)?;
    let last = head_by(&n, &n.log, &op2, &card2, &[&w], T0 + 7)?;
    let now = T0 + 8;
    let (head, transitions) = catch_up(&behind, &n.log.entries()[start..], &last, now)?;
    assert_eq!(transitions.iter().map(bridge_net::Transition::index).collect::<Vec<_>>(), vec![j1, j2]);
    let tree = n.log.tree();
    let both = found(&[(j1 + 1, &t1), (j2 + 1, &t2)]);
    let kept = transitions.verify(&n.net, tree, &head, &both)?;
    assert_eq!(kept.iter().map(|(size, _)| *size).collect::<Vec<_>>(), vec![j1 + 1, j2 + 1]);
    for one in [found(&[(j1 + 1, &t1)]), found(&[(j2 + 1, &t2)])] {
        assert!(transitions.verify(&n.net, tree, &head, &one).is_err(), "each change needs its own");
    }
    // The wrong witnesses (W for change 1, the owner for change 2), or under another size: not endorsed.
    let wrong1 = head_with(&n, &prefix(&n, j1 + 1)?, &[&w], T0 + 3)?;
    assert!(transitions.verify(&n.net, tree, &head, &found(&[(j1 + 1, &wrong1), (j2 + 1, &t2)])).is_err());
    let wrong2 = head_with(&n, &prefix(&n, j2 + 1)?, &[&n.owner], T0 + 5)?;
    assert!(transitions.verify(&n.net, tree, &head, &found(&[(j1 + 1, &t1), (j2 + 1, &wrong2)])).is_err());
    assert!(transitions.verify(&n.net, tree, &head, &found(&[(j1 + 1, &t2), (j2 + 1, &t1)])).is_err());
    // Long after they expired, transition heads still count (no time check for them).
    let later = transitions.iter().map(|t| {
        let root = tree.root_at(t.size())?;
        let value = if t.index() == j1 { &t1 } else { &t2 };
        t.check(&n.net, value, &root).map(|_| ())
    });
    for checked in later {
        checked?;
    }
    assert!(t1.check(&n.net, &behind.manifest().log_rules(), &behind, T0 + 60 * DAY).is_err(), "expired now");
    // When the head itself ends with change 2, it is that change's transition head: only change 1 needs one.
    let (head2, transitions2) =
        catch_up(&behind, &n.log.entries()[start..usize::try_from(j2 + 1).unwrap_or(0)], &t2, now)?;
    let kept = transitions2.verify(&n.net, tree, &head2, &found(&[(j1 + 1, &t1)]))?;
    assert_eq!(kept.len(), 1);
    Ok(())
}

/// A repair hangs on its transition head (the old witness is lost), the net key's rescue right after it brings
/// the network back: its transition head - signed by the old log operator, cosigned by the net key - endorses the
/// repair too. With the words alone (another operator in the repair) it does not.
#[test]
fn a_rescue_endorses_the_change_it_was_taken_after() -> NetResult<()> {
    for words_alone in [false, true] {
        let mut n = Net::new(JoinMode::Open)?;
        n.seal_owner(T0 + 1)?;
        let admin = n.delegate(10, &[Right::Rules], T0 + 1)?;
        let (op2, w2) = (identity(70), identity(71));
        let card2 = node_card(&op2, "https://evil.example")?;
        n.accept(&n.sign(&seal(&op2, 3, &[Service::Log], Some(card2.clone())), &n.master, T0 + 2)?)?;
        n.accept(&n.sign(&seal(&w2, 2, &[Service::Witness], witness_card(&w2)), &n.master, T0 + 2)?)?;
        n.accept(&ban(&n, 90, T0 + 2)?)?;
        let behind = n.state.clone();
        let start = usize::try_from(behind.size()).unwrap_or(0);
        // The repair (never witnessed: honest - the owner and op2 as operators, a witness that is gone; words alone
        // - the attacker's operator) ...
        let mut repair = n.state.manifest().next_version();
        let k = n.log.size();
        let repair = if words_alone {
            repair.logs = vec![op2.id().clone()];
            repair.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?
        } else {
            (repair.logs, repair.witnesses) = (vec![n.owner.id().clone(), op2.id().clone()], vec![w2.id().clone()]);
            repair.sign(&n.net, T0 + 3, T0 + 30 * DAY, &admin)?
        };
        n.accept(&repair)?;
        // ... and the rescue right after it, by the net key alone; its transition head carries the net key's cosign.
        let mut rescue = n.state.manifest().next_version();
        let owner = identity(1); // the owner node (as in the fixture)
        let w_after = if words_alone { &w2 } else { &owner };
        rescue.witnesses = vec![w_after.id().clone()];
        n.accept(&rescue.sign(&n.net, T0 + 4, T0 + 30 * DAY, &n.master)?)?;
        let owner_card = n.owner_card.clone();
        let (signer, card) = if words_alone { (&op2, &card2) } else { (&owner, &owner_card) };
        let rescued = head_by(&n, &n.log, signer, card, &[&n.master], T0 + 4)?;
        n.accept(&ban(&n, 91, T0 + 5)?)?;
        let last = head_by(&n, &n.log, signer, card, &[w_after], T0 + 6)?;
        let now = T0 + 7;
        let (head, transitions) = catch_up(&behind, &n.log.entries()[start..], &last, now)?;
        assert_eq!(transitions.iter().map(bridge_net::Transition::index).collect::<Vec<_>>(), vec![k, k + 1]);
        let verdict = transitions.verify(&n.net, n.log.tree(), &head, &found(&[(k + 2, &rescued)]));
        if words_alone {
            assert!(verdict.is_err(), "the rescue head is not by an operator of the rules before the repair");
        } else {
            assert_eq!(verdict?.len(), 1, "the repair is endorsed through the rescue");
        }
        // The head that ends with the rescue: the same.
        let entries = &n.log.entries()[start..usize::try_from(k + 2).unwrap_or(0)];
        let (head, transitions) = catch_up(&behind, entries, &rescued, now)?;
        let verdict = transitions.verify(&n.net, n.log.tree(), &head, &BTreeMap::new());
        assert_eq!(verdict.is_ok(), !words_alone, "words alone: {words_alone}");
    }
    Ok(())
}

/// Nodes keep transition heads only for sizes that end with a change of the log rules (not the genesis).
#[test]
fn only_sizes_after_a_change_are_transition_heads() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    let w = identity(30);
    n.accept(&n.sign(&seal(&w, 2, &[Service::Witness], witness_card(&w)), &n.master, T0 + 2)?)?;
    let mut manifest = n.state.manifest().next_version();
    manifest.witnesses = vec![w.id().clone()];
    let j = n.log.size();
    n.accept(&manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?)?;
    let mut renamed = n.state.manifest().next_version();
    renamed.name = "nur umbenannt".into();
    n.accept(&renamed.sign(&n.net, T0 + 4, T0 + 30 * DAY, &n.master)?)?;
    let sizes: Vec<u64> = (0..=n.log.size() + 1).filter(|size| n.state.is_transition_head(*size)).collect();
    assert_eq!(sizes, vec![j + 1], "not the genesis, not a manifest that keeps the rules, not beyond the log");
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 2: cosignatures of witnesses whose card is not known yet

/// A witness listed in the rules but sealed after the follower's state cosigns: before fetching it is a "maybe",
/// so the honest head is fetched (and passes after fetching, with the card from the entries).
#[test]
fn precheck_lets_through_a_head_cosigned_by_a_witness_sealed_later() -> NetResult<()> {
    let (a, c) = (identity(30), identity(31));
    let (aid, cid) = (a.id().clone(), c.id().clone());
    let mut n = Net::with(JoinMode::Open, move |m| {
        m.witnesses = vec![m.logs[0].clone(), aid, cid];
        m.witness_threshold = 2;
    })?;
    n.seal_owner(T0 + 1)?;
    n.accept(&n.sign(&seal(&a, 2, &[Service::Witness], witness_card(&a)), &n.master, T0 + 2)?)?;
    let behind = n.state.clone();
    let start = usize::try_from(behind.size()).unwrap_or(0);
    n.accept(&n.sign(&seal(&c, 2, &[Service::Witness], witness_card(&c)), &n.master, T0 + 3)?)?;
    n.accept(&ban(&n, 90, T0 + 4)?)?;
    let head = head_with(&n, &n.log, &[&a, &c], T0 + 5)?;
    let now = T0 + 6;
    let current = behind.manifest().log_rules();
    assert!(head.check(&n.net, &current, &behind, now).is_err(), "the full check needs C's card");
    head.precheck(&n.net, &current, &behind, now)?;
    // Not enough even with maybes: A alone; a junk "cosignature" of C for another head.
    assert!(head_with(&n, &n.log, &[&a], T0 + 5)?.precheck(&n.net, &current, &behind, now).is_err());
    let other = head_with(&n, &prefix(&n, n.log.size() - 1)?, &[&c], T0 + 5)?;
    let mixed =
        WitnessedHead { head: head.head.clone(), cosigns: vec![head.cosigns[0].clone(), other.cosigns[0].clone()] };
    assert!(mixed.precheck(&n.net, &current, &behind, now).is_err(), "a maybe must name exactly this head");
    let entries = &n.log.entries()[start..];
    let ahead = Ahead::parse(&behind.manifest().card, behind.manifest().version, entries);
    assert_eq!(behind.rules_ahead(&ahead), RulesAhead::Known(current.clone()));
    head.check(&n.net, &current, &(&behind, &ahead), now)?;
    Ok(())
}

/// The newest manifest's witnesses: one cosigner's card is known, the other's not yet - the honest head is fetched.
#[test]
fn may_fetch_takes_an_honest_head_with_one_cosigner_card_unknown() -> NetResult<()> {
    let (a, b, c) = (identity(30), identity(31), identity(32));
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    for w in [&a, &b] {
        n.accept(&n.sign(&seal(w, 2, &[Service::Witness], witness_card(w)), &n.master, T0 + 2)?)?;
    }
    let behind = n.state.clone();
    n.accept(&n.sign(&seal(&c, 2, &[Service::Witness], witness_card(&c)), &n.master, T0 + 3)?)?;
    let mut manifest = n.state.manifest().next_version();
    manifest.witnesses = vec![a.id().clone(), b.id().clone(), c.id().clone()];
    manifest.witness_threshold = 2;
    let change = manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?;
    n.state.validate_candidate(&change, T0 + 3)?;
    let index = n.log.size();
    n.accept(&change)?;
    n.accept(&ban(&n, 90, T0 + 4)?)?;
    let now = T0 + 6;
    behind.may_fetch(&head_with(&n, &n.log, &[&b, &c], T0 + 5)?, &change, index, now)?;
    // Still refused: a known cosigner whose cosignature does not verify does not count as maybe.
    let mut broken = head_with(&n, &n.log, &[&b, &c], T0 + 5)?;
    broken.cosigns[0] = head_with(&n, &prefix(&n, index)?, &[&b], T0 + 5)?.cosigns[0].clone();
    assert!(behind.may_fetch(&broken, &change, index, now).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 3: no big downloads for forged heads or manifests that can never count

#[test]
fn may_fetch_refuses_a_forged_head_of_a_known_operator() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    let w = identity(30);
    n.accept(&n.sign(&seal(&w, 2, &[Service::Witness], witness_card(&w)), &n.master, T0 + 2)?)?;
    let behind = n.state.clone();
    let mut manifest = behind.manifest().next_version();
    manifest.witnesses = vec![w.id().clone()];
    let change = manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?;
    let fake = forged_head(&n)?;
    assert!(verify_head(&fake.head, &n.net, &n.owner_card).is_err(), "really forged");
    for index in [65_535, 65_534, 10] {
        assert!(behind.may_fetch(&fake, &change, index, T0 + 6).is_err(), "index {index}");
    }
    Ok(())
}

/// approvals.rules = 2: a manifest of one admin with `rules` can never be accepted - it neither forces a replay nor
/// justifies a fetch. Nor does an expired manifest. But a manifest that lowered approvals.rules ahead is followed by
/// one that a single admin signed (the smallest approvals.rules so far counts).
#[test]
fn manifests_that_replay_can_not_take_count_nowhere() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |m| m.approvals.rules = 2)?;
    n.seal_owner(T0 + 1)?;
    let admin = n.delegate(10, &[Right::Rules], T0 + 2)?;
    let w = identity(30);
    n.accept(&n.sign(&seal(&w, 2, &[Service::Witness], witness_card(&w)), &n.master, T0 + 2)?)?;
    let behind = n.state.clone();
    let mut manifest = behind.manifest().next_version();
    manifest.witnesses = vec![w.id().clone()];
    let lone = manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &admin)?;
    assert!(n.state.validate_candidate(&lone, T0 + 3).is_err(), "never acceptable");
    let tail = ban(&n, 91, T0 + 4)?.canonical_bytes().to_vec();
    let decide = |entries: &[Vec<u8>]| {
        behind.rules_ahead(&Ahead::parse(&behind.manifest().card, behind.manifest().version, entries))
    };
    let entries = vec![lone.canonical_bytes().to_vec(), tail.clone()];
    assert_eq!(decide(&entries), RulesAhead::Known(behind.manifest().log_rules()), "no replay forced");
    let mut copy = behind.clone();
    assert!(matches!(copy.apply(&entries[0]), Applied::Skipped(_)));
    assert!(behind.may_fetch(&forged_head(&n)?, &lone, 65_535, T0 + 6).is_err());
    // Even for a genuine head of the operator behind it: too few admins, so no change ahead.
    let size = n.log.size();
    let mut padded = n.log.clone();
    padded.append(&lone)?;
    padded.append(&ban(&n, 92, T0 + 4)?)?;
    let ahead_head = head_with(&n, &padded, &[&w], T0 + 5)?;
    assert!(behind.may_fetch(&ahead_head, &lone, size, T0 + 6).is_err(), "too few admins: not a change ahead");
    // Expired at its replay time: never counts, never justifies a fetch.
    let expired = manifest.sign(&n.net, T0 - 2 * DAY, T0 - DAY, &n.master)?;
    assert_eq!(
        decide(&[expired.canonical_bytes().to_vec(), tail.clone()]),
        RulesAhead::Known(behind.manifest().log_rules())
    );
    assert!(behind.may_fetch(&ahead_head, &expired, size, T0 + 6).is_err());
    // Version + 1 by the net key lowers approvals.rules to 1, version + 2 by the lone admin changes the rules:
    // replay takes both, so the follower must replay.
    let mut lower = behind.manifest().next_version();
    lower.approvals.rules = 1;
    let lower = lower.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?;
    let mut then = Manifest::from_statement(&lower)?.next_version();
    then.witnesses = vec![w.id().clone()];
    let then = then.sign(&n.net, T0 + 4, T0 + 30 * DAY, &admin)?;
    let entries = vec![lower.canonical_bytes().to_vec(), then.canonical_bytes().to_vec(), tail];
    let mut copy = behind.clone();
    for entry in &entries {
        copy.apply(entry);
    }
    assert_eq!(copy.manifest().witnesses, vec![w.id().clone()], "replay took both");
    assert_eq!(decide(&entries), RulesAhead::Replay);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 4: the newest card, not the newest seal

/// One admin with `seals` (level 3 needs two) re-seals the node at level 1 with its OLD self-signed card (public in
/// the log): the master's level-3 seal with the new card keeps the pin and the addresses. A newer card of the node
/// itself (made after its last seal) wins at any level.
#[test]
fn an_old_card_never_comes_back_through_a_lower_seal() -> NetResult<()> {
    let mut n = Net::with(JoinMode::Open, |m| m.approvals.seal3 = 2)?;
    let admin = n.delegate(10, &[Right::Seals], T0 + 1)?;
    let node = identity(50);
    let card =
        |url: &str, tls: u8, iat: i64| node.key_card_with(Role::Node, None, &[url.to_owned()], Some([tls; 32]), iat);
    let old = card("https://alt.example", 1, T0)?;
    let new = card("https://neu.example", 2, T0 + 5)?;
    n.accept(&n.sign(&seal(&node, 2, &[Service::Gateway], Some(old.clone())), &n.master, T0 + 2)?)?;
    n.accept(&n.sign(&seal(&node, 3, &[Service::Gateway], Some(new)), &n.master, T0 + 6)?)?;
    assert_eq!(n.state.card_of(node.id()).and_then(KeyCard::tls), Some(&[2; 32]));
    n.accept(&n.sign(&seal(&node, 1, &[], Some(old)), &admin, T0 + 7)?)?;
    assert_eq!(n.state.card_of(node.id()).and_then(KeyCard::tls), Some(&[2; 32]), "no roll-back");
    let gateway = n.state.gateways(T0 + 8).into_iter().find(|(id, _)| id == node.id()).and_then(|(_, card)| card);
    assert_eq!(gateway.as_ref().map(|c| c.urls().to_vec()), Some(vec!["https://neu.example".to_owned()]));
    // The node's own newer card, sealed at level 1 by the admin: that one is the newest.
    let newer = card("https://dritt.example", 3, T0 + 8)?;
    n.accept(&n.sign(&seal(&node, 1, &[], Some(newer)), &admin, T0 + 9)?)?;
    assert_eq!(n.state.card_of(node.id()).and_then(KeyCard::tls), Some(&[3; 32]));
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 5: a known signer without `rules` is unknown, not invalid

/// An admin known here with `seals` only gets `rules` among the entries ahead and signs the manifest: like a
/// stranger's, it is fetched for a head of the current operator (and checked after fetching).
#[test]
fn a_known_admin_raised_ahead_may_justify_a_fetch() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    let admin = n.delegate(10, &[Right::Seals], T0 + 2)?;
    let w = identity(30);
    n.accept(&n.sign(&seal(&w, 2, &[Service::Witness], witness_card(&w)), &n.master, T0 + 2)?)?;
    let behind = n.state.clone();
    let raise = Delegation {
        admin: admin.id().clone(),
        rights: Rights::of(&[Right::Seals, Right::Rules]),
        card: admin.key_card(Role::Admin, None, T0)?,
    };
    n.accept(&n.sign(&raise, &n.master, T0 + 3)?)?;
    let mut manifest = n.state.manifest().next_version();
    manifest.witnesses = vec![n.owner.id().clone(), w.id().clone()];
    let change = manifest.sign(&n.net, T0 + 4, T0 + 30 * DAY, &admin)?;
    n.state.validate_candidate(&change, T0 + 4)?;
    let index = n.log.size();
    n.accept(&change)?;
    n.accept(&ban(&n, 90, T0 + 6)?)?;
    let head = head_with(&n, &n.log, &[&w], T0 + 7)?;
    behind.may_fetch(&head, &change, index, T0 + 8)?;
    let stranger = manifest.sign(&n.net, T0 + 4, T0 + 30 * DAY, &identity(77))?;
    behind.may_fetch(&head, &stranger, index, T0 + 8)?;
    // Not for a head of anybody else, and not for a forged one.
    let other = identity(78);
    let card = node_card(&other, "https://other.example")?;
    assert!(behind.may_fetch(&head_by(&n, &n.log, &other, &card, &[&w], T0 + 7)?, &change, index, T0 + 8).is_err());
    assert!(behind.may_fetch(&forged_head(&n)?, &change, index, T0 + 8).is_err());
    Ok(())
}
