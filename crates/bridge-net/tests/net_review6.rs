//! Regression tests for the findings of review 6 in the pure network logic:
//! - finding 1 (`the_words_and_a_self_appointed_second_operator_can_not_fork_a_follower`, adapted from the
//!   reviewer's scratch test `words_plus_self_appointed_second_operator_fork_a_follower`, which showed the fork
//!   accepted): the rescue form and the endorsement of a hanging change count only for a head of the *first* log
//!   operator of the old rules - a second operator the net key once listed is not enough;
//! - finding 4 (`the_walk_goes_newest_first_and_stops_at_the_first_change_not_endorsed`): the endorsement walk asks
//!   for one transition head at a time and stops at the first change that can not be endorsed;
//! - finding 6 (`a_card_from_the_future_does_not_win_for_good`): seals with a card more than 5 minutes younger than
//!   the seal are skipped, and the newest card is decided by `min(card iat, seal iat)`.

mod common;

use std::collections::BTreeMap;

use bridge_core::{Identity, KeyCard, Role, Statement};
use bridge_net::{
    Ahead, Ban, Body, Head, JoinMode, Log, NetError, NetResult, NetState, Right, RulesAhead, Seal, Service, Services,
    Transitions, WitnessedHead, issue_cosign, verify_head,
};
use common::{DAY, MIN, Net, T0, expect_skip, identity, node_card};

fn seal(node: &Identity, level: u8, services: &[Service], card: Option<KeyCard>) -> Seal {
    Seal { subject: node.id().clone(), level, services: Services::of(services), card }
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

fn ban(n: &Net, seed: u8, at: i64) -> NetResult<Statement> {
    n.sign(&Ban { subject: identity(seed).id().clone(), reason: String::new() }, &n.master, at)
}

fn index_of(size: u64) -> usize {
    usize::try_from(size).unwrap_or(usize::MAX)
}

/// A copy of the network whose log has the same entries as `n` (the fork starts from there).
fn copy_of(n: &Net) -> NetResult<Net> {
    let mut fork = Net::new(JoinMode::Open)?;
    for entry in n.log.entries().iter().skip(1) {
        fork.push_bytes(entry)?;
    }
    Ok(fork)
}

/// The real network: the owner O seals a "backup" node A (whose key the attacker holds) and - looking harmless, the
/// docs recommend a second operator - adds it as second log operator: `logs = [O, A]`. One more entry after that.
/// Returns the network, A and A's card.
fn network_with_second_operator() -> NetResult<(Net, Identity, KeyCard)> {
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    let a = identity(70);
    let card_a = node_card(&a, "https://backup.example")?;
    n.accept(&n.sign(&seal(&a, 3, &[Service::Log], Some(card_a.clone())), &n.master, T0 + 2)?)?;
    let mut manifest = n.state.manifest().next_version();
    manifest.logs = vec![n.owner.id().clone(), a.id().clone()];
    n.accept(&manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?)?;
    n.accept(&ban(&n, 80, T0 + 4)?)?;
    Ok((n, a, card_a))
}

/// What a follower behind `state` does with the fetched `entries` up to `last` (docs/06 §5 steps 3-5) - with every
/// transition head in `found`. `Err` wherever it refuses.
fn follow(
    state: &NetState,
    entries: &[Vec<u8>],
    last: &WitnessedHead,
    found: &BTreeMap<u64, WitnessedHead>,
    tree: &bridge_net::Tree,
    now: i64,
) -> NetResult<Vec<u64>> {
    let net = state.net().clone();
    let ahead = Ahead::parse(&state.manifest().card, state.manifest().version, entries);
    let decided = state.rules_ahead(&ahead);
    if let RulesAhead::Known(rules) = &decided {
        if last.check(&net, rules, &(state, &ahead), now).is_ok() {
            return Ok(Vec::new());
        }
    }
    if decided == RulesAhead::Refuse {
        return Err(NetError::Forbidden("refused ahead".into()));
    }
    let mut copy = state.clone();
    let mut transitions = Transitions::default();
    for entry in entries {
        copy.apply_tracked(entry, &ahead, &mut transitions);
    }
    let head = copy.check_witnessed(last, &(&copy, &ahead), now)?;
    let kept = transitions.verify(&net, tree, &head, found)?;
    Ok(kept.iter().map(|(size, _)| *size).collect())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 1: the rescue form needs the FIRST log operator of the old rules

/// The reviewer's scratch test, now asserting refusal. With only the 24 words: (1) in the real log, A (the
/// attacker's node) becomes second log operator; (2) a fork shown to an up-to-date follower: a manifest of the net
/// key alone switches to `logs = [A]`, `witnesses = [X]`, its transition head signed by A and cosigned by the net key
/// (the rescue form). A is an operator of the old rules - but not the first one, so the rescue form does not count:
/// neither when the fork's head is that transition head (short) nor when it goes on (long).
#[test]
fn the_words_and_a_self_appointed_second_operator_can_not_fork_a_follower() -> NetResult<()> {
    let (n, a, card_a) = network_with_second_operator()?;
    let follower = n.state.clone();
    let start = index_of(follower.size());

    let mut fork = copy_of(&n)?;
    let x = identity(71);
    let card_x = node_card(&x, "https://x.example")?;
    fork.accept(&fork.sign(&seal(&x, 2, &[Service::Witness], Some(card_x)), &fork.master, T0 + 5)?)?;
    let mut manifest = fork.state.manifest().next_version();
    (manifest.logs, manifest.witnesses, manifest.witness_threshold) = (vec![a.id().clone()], vec![x.id().clone()], 1);
    let change = manifest.sign(&fork.net, T0 + 5, T0 + 30 * DAY, &fork.master)?;
    let j = fork.log.size();
    fork.accept(&change)?;
    let now = T0 + 7;

    for long in [false, true] {
        let mut f = copy_of(&fork)?;
        let transition = head_by(&f, &f.log, &a, &card_a, &[&f.master], T0 + 6)?;
        let last = if long {
            f.accept(&ban(&f, 81, T0 + 6)?)?;
            head_by(&f, &f.log, &a, &card_a, &[&x], T0 + 6)?
        } else {
            transition.clone()
        };
        let current = follower.manifest().log_rules();
        assert!(last.precheck(&n.net, &current, &follower, now).is_err(), "long={long}: not by the old witness");
        // The gate before fetching: the short fork is not even fetched any more (the rescue form needs the first
        // operator); the long one may be (its head is checked under the fork's own rules, step 5 decides).
        assert_eq!(follower.may_fetch(&last, &change, j, now).is_ok(), long, "long={long}");
        let entries = &f.log.entries()[start..];
        let found: BTreeMap<u64, WitnessedHead> = [(j + 1, transition.clone())].into_iter().collect();
        let verdict = follow(&follower, entries, &last, &found, f.log.tree(), now);
        assert!(verdict.is_err(), "long={long}: the fork must be refused, got {verdict:?}");
        // The transition head on its own: not in the rescue form, not by the witnesses.
        let mut copy = follower.clone();
        let ahead = Ahead::parse(&follower.manifest().card, follower.manifest().version, entries);
        let mut transitions = Transitions::default();
        for entry in &entries[..index_of(j + 1 - follower.size())] {
            copy.apply_tracked(entry, &ahead, &mut transitions);
        }
        assert!(copy.check_witnessed(&transition, &(&copy, &ahead), now).is_err(), "long={long}");
        let root = f.log.tree().root_at(j + 1)?;
        let passed: Vec<_> = transitions.iter().collect();
        assert_eq!(passed.len(), 1);
        assert!(passed[0].check(&n.net, &transition, &root).is_err(), "long={long}: Transition::check refuses");
    }

    // With the key of the FIRST old operator (the owner) as well - words AND that key - the same fork would pass:
    // that is the documented limit of the rescue form.
    let mut f = copy_of(&fork)?;
    let stolen = head_by(&f, &f.log, &f.owner, &f.owner_card, &[&f.master], T0 + 6)?;
    f.accept(&ban(&f, 81, T0 + 6)?)?;
    let last = head_by(&f, &f.log, &a, &card_a, &[&x], T0 + 6)?;
    let found: BTreeMap<u64, WitnessedHead> = [(j + 1, stolen)].into_iter().collect();
    let kept = follow(&follower, &f.log.entries()[start..], &last, &found, f.log.tree(), now)?;
    assert_eq!(kept, vec![j + 1]);
    Ok(())
}

/// The honest rescue in a network with two operators: the first one (the owner, who issues the heads) signs the
/// transition head and the net key cosigns - accepted. The same head signed by the second operator - refused, also
/// in the real log (the rule is the same for every node).
#[test]
fn the_honest_rescue_is_signed_by_the_first_operator() -> NetResult<()> {
    let (mut n, a, card_a) = network_with_second_operator()?;
    let w = identity(72);
    n.accept(&n.sign(
        &seal(&w, 2, &[Service::Witness], Some(node_card(&w, "https://w.example")?)),
        &n.master,
        T0 + 5,
    )?)?;
    let mut rescue = n.state.manifest().next_version();
    rescue.witnesses = vec![w.id().clone()];
    let statement = rescue.sign(&n.net, T0 + 6, T0 + 30 * DAY, &n.master)?;
    n.state.validate_candidate(&statement, T0 + 6)?;
    n.accept(&statement)?;
    let size = n.log.size();
    assert!(n.state.rescue_head(size));
    let now = T0 + 7;
    let by_first = head_by(&n, &n.log, &n.owner, &n.owner_card, &[&n.master], T0 + 6)?;
    assert_eq!(n.state.check_witnessed(&by_first, &n.state, now)?.size(), size);
    let by_second = head_by(&n, &n.log, &a, &card_a, &[&n.master], T0 + 6)?;
    let rules = n.state.rules_for_head(size).ok_or_else(|| NetError::NotFound("rules".into()))?;
    assert!(by_first.signed_by_first(&rules) && !by_second.signed_by_first(&rules));
    let refused = n.state.check_witnessed(&by_second, &n.state, now);
    assert!(matches!(refused, Err(NetError::Forbidden(_))), "{refused:?}");
    Ok(())
}

/// Decision (docs/06 §5): the normal form of a transition head - the old witness quorum - still counts for ANY log
/// operator of the old rules. The witnesses only cosign what is consistent with their own log, whoever signed the
/// head; requiring the first operator there would break the takeover by the second operator after evidence against
/// the first (`operator_for_head`).
#[test]
fn with_the_witness_quorum_any_old_operator_may_sign_the_transition_head() -> NetResult<()> {
    let (mut n, a, card_a) = network_with_second_operator()?;
    let w = identity(72);
    n.accept(&n.sign(
        &seal(&w, 2, &[Service::Witness], Some(node_card(&w, "https://w.example")?)),
        &n.master,
        T0 + 5,
    )?)?;
    let mut change = n.state.manifest().next_version();
    change.witnesses = vec![w.id().clone()];
    n.accept(&change.sign(&n.net, T0 + 6, T0 + 30 * DAY, &n.master)?)?;
    let now = T0 + 7;
    let by_second = head_by(&n, &n.log, &a, &card_a, &[&n.owner], T0 + 6)?;
    assert_eq!(n.state.check_witnessed(&by_second, &n.state, now)?.operator(), a.id());
    // Without the old witness (the owner) it is not witnessed, whoever signs.
    let unwitnessed = head_by(&n, &n.log, &a, &card_a, &[&w], T0 + 6)?;
    assert!(n.state.check_witnessed(&unwitnessed, &n.state, now).is_err());
    Ok(())
}

/// The hanging-change endorsement (a change whose transition head never came about, endorsed by the rescue right
/// after it) also needs the first operator of the rules before the hanging change. The words-only variant of the
/// attack: in the fork, a manifest of the net key alone makes A the (only) operator and hangs, a second one (the
/// "rescue") switches the witnesses; A signs the rescue's transition head - A is first under the hanging change's
/// rules, but only second under the rules before it. Refused; with the owner as first operator, the honest repair
/// passes.
#[test]
fn a_hanging_change_is_endorsed_only_through_the_first_old_operator() -> NetResult<()> {
    for words_alone in [true, false] {
        let (n, a, card_a) = network_with_second_operator()?;
        let follower = n.state.clone();
        let start = index_of(follower.size());
        let mut f = copy_of(&n)?;
        let x = identity(71);
        f.accept(&f.sign(
            &seal(&x, 2, &[Service::Witness], Some(node_card(&x, "https://x.example")?)),
            &f.master,
            T0 + 5,
        )?)?;
        // The hanging change: a lost witness (and, for the attacker, A as the only operator).
        let lost = identity(73);
        f.accept(&f.sign(
            &seal(&lost, 2, &[Service::Witness], Some(node_card(&lost, "https://l.example")?)),
            &f.master,
            T0 + 5,
        )?)?;
        let mut hanging = f.state.manifest().next_version();
        hanging.witnesses = vec![lost.id().clone()];
        if words_alone {
            hanging.logs = vec![a.id().clone()];
        }
        let k = f.log.size();
        f.accept(&hanging.sign(&f.net, T0 + 6, T0 + 30 * DAY, &f.master)?)?;
        let mut rescue = f.state.manifest().next_version();
        rescue.witnesses = vec![x.id().clone()];
        f.accept(&rescue.sign(&f.net, T0 + 7, T0 + 30 * DAY, &f.master)?)?;
        let owner = identity(1); // the owner node of the fixture
        let (signer, card) = if words_alone { (&a, card_a.clone()) } else { (&owner, f.owner_card.clone()) };
        let rescued = head_by(&f, &f.log, signer, &card, &[&f.master], T0 + 7)?;
        f.accept(&ban(&f, 81, T0 + 8)?)?;
        let last = head_by(&f, &f.log, signer, &card, &[&x], T0 + 8)?;
        let found: BTreeMap<u64, WitnessedHead> = [(k + 2, rescued)].into_iter().collect();
        let verdict = follow(&follower, &f.log.entries()[start..], &last, &found, f.log.tree(), T0 + 9);
        if words_alone {
            assert!(verdict.is_err(), "A is not the first operator before the hanging change: {verdict:?}");
        } else {
            assert_eq!(verdict?, vec![k + 2], "the honest repair is endorsed through the rescue");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 4: newest first, one at a time, stop at the first change not endorsed

/// A fork with an attacker's change at the start and three more changes under the attacker's own rules after it
/// (their transition heads the attacker can make). The walk asks for the newest first, one at a time, and stops at
/// the attacker's first change: four heads asked for, the oldest refused - nothing beyond it. If the newest change has
/// no head, the walk stops right there after one question.
#[test]
fn the_walk_goes_newest_first_and_stops_at_the_first_change_not_endorsed() -> NetResult<()> {
    let (n, a, card_a) = network_with_second_operator()?;
    let follower = n.state.clone();
    let start = index_of(follower.size());
    let mut f = copy_of(&n)?;
    let (x, y) = (identity(71), identity(72));
    for w in [&x, &y] {
        let card = node_card(w, "https://w.example")?;
        f.accept(&f.sign(&seal(w, 2, &[Service::Witness], Some(card)), &f.master, T0 + 5)?)?;
    }
    let witness = |step: u8| if step % 2 == 0 { &x } else { &y };
    let mut heads: BTreeMap<u64, WitnessedHead> = BTreeMap::new();
    let mut changes = Vec::new();
    for step in 0..4u8 {
        let mut manifest = f.state.manifest().next_version();
        manifest.logs = vec![a.id().clone()];
        (manifest.witnesses, manifest.witness_threshold) = (vec![witness(step).id().clone()], 1);
        changes.push(f.log.size());
        f.accept(&manifest.sign(&f.net, T0 + 6, T0 + 30 * DAY, &f.master)?)?;
        // Under the attacker's rules (from the second change on) A and the previous witness make a valid transition
        // head; for the first change only the words + A: the rescue form by the second operator - not enough.
        let cosigner = if step == 0 { &f.master } else { witness(step - 1) };
        heads.insert(f.log.size(), head_by(&f, &f.log, &a, &card_a, &[cosigner], T0 + 6)?);
        f.accept(&ban(&f, 90 + step, T0 + 6)?)?;
    }
    let last = head_by(&f, &f.log, &a, &card_a, &[witness(3)], T0 + 7)?;
    let entries = &f.log.entries()[start..];
    let ahead = Ahead::parse(&follower.manifest().card, follower.manifest().version, entries);
    let mut copy = follower.clone();
    let mut transitions = Transitions::default();
    for entry in entries {
        copy.apply_tracked(entry, &ahead, &mut transitions);
    }
    let head: Head = copy.check_witnessed(&last, &(&copy, &ahead), T0 + 8)?;
    let tree = f.log.tree();
    // Walks like a follower: offer the head it has, else "no head of its own"; returns what was asked, where it
    // stopped and whether all were endorsed.
    let walk_with = |heads: &BTreeMap<u64, WitnessedHead>| -> NetResult<(Vec<u64>, Option<u64>, bool)> {
        let mut walk = transitions.endorsement(&n.net, &head)?;
        let (mut asked, mut stopped) = (Vec::new(), None);
        while let Some(transition) = walk.next() {
            asked.push(transition.index());
            let root = tree.root_at(transition.size())?;
            let offered = heads.get(&transition.size()).is_some_and(|value| walk.offer(value, &root));
            if !offered && walk.without_head().is_err() {
                stopped = Some(transition.index());
                break;
            }
        }
        Ok((asked, stopped, walk.finish().is_ok()))
    };
    let newest_first: Vec<u64> = changes.iter().rev().copied().collect();
    assert_eq!(walk_with(&heads)?, (newest_first, changes.first().copied(), false), "stopped at the first change");
    assert!(transitions.verify(&n.net, tree, &head, &heads).is_err());
    let mut without_newest = heads.clone();
    without_newest.retain(|size, _| *size != changes[3] + 1);
    assert_eq!(walk_with(&without_newest)?, (vec![changes[3]], Some(changes[3]), false), "one question, then stop");
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 6: a card from the future

/// A node's card dated a day ahead of its seal is refused (replay skips the seal); one up to 5 minutes ahead is
/// fine, but counts only from the seal's time on: a later re-seal with a genuinely newer card wins. Before, the card
/// with the largest own `iat` won for good.
#[test]
fn a_card_from_the_future_does_not_win_for_good() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let admin = n.delegate(10, &[Right::Seals], T0 + 1)?;
    let node = identity(50);
    let card =
        |url: &str, tls: u8, iat: i64| node.key_card_with(Role::Node, None, &[url.to_owned()], Some([tls; 32]), iat);
    // A day ahead: skipped, at any level, by anybody.
    let future = card("https://zukunft.example", 9, T0 + 10 + DAY)?;
    let reason = n.skip(&n.sign(&seal(&node, 2, &[Service::Gateway], Some(future.clone())), &n.master, T0 + 10)?)?;
    assert!(matches!(reason, NetError::Forbidden(_)), "{reason:?}");
    expect_skip(n.push(&n.sign(&seal(&node, 1, &[], Some(future)), &admin, T0 + 11)?)?)?;
    assert!(n.state.card_of(node.id()).is_none());
    // Exactly at the bound: still taken.
    let skewed = card("https://schief.example", 1, T0 + 20 + 5 * MIN)?;
    n.accept(&n.sign(&seal(&node, 2, &[Service::Gateway], Some(skewed)), &n.master, T0 + 20)?)?;
    assert_eq!(n.state.card_of(node.id()).and_then(KeyCard::tls), Some(&[1; 32]));
    // A genuinely newer card (after the seal above, but before the skewed card's own iat) wins.
    let newer = card("https://neu.example", 2, T0 + 30)?;
    n.accept(&n.sign(&seal(&node, 1, &[], Some(newer)), &admin, T0 + 31)?)?;
    assert_eq!(n.state.card_of(node.id()).and_then(KeyCard::tls), Some(&[2; 32]), "min(card iat, seal iat) decides");
    let gateway = n.state.gateways(T0 + 40).into_iter().find(|(id, _)| id == node.id()).and_then(|(_, card)| card);
    assert_eq!(gateway.as_ref().map(|c| c.urls().to_vec()), Some(vec!["https://neu.example".to_owned()]));
    // One millisecond beyond the bound: skipped.
    let beyond = card("https://drueber.example", 3, T0 + 50 + 5 * MIN + 1)?;
    expect_skip(n.push(&n.sign(&seal(&node, 3, &[Service::Gateway], Some(beyond)), &n.master, T0 + 50)?)?)?;
    assert_eq!(n.state.card_of(node.id()).and_then(KeyCard::tls), Some(&[2; 32]));
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}
