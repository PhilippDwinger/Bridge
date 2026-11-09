//! Regression tests for the findings of review 4 in the pure network logic (each failed before its fix): what a
//! follower decides about the entries ahead of a head (findings 1 and 2, adapted from the reviewer's scratch tests
//! `old_genuine_manifest_forces_replay`, `forged_manifests_claiming_the_net_key_force_replay` and
//! `master_plus_sealed_cosigner_manifest_is_missed`, plus a property test against replay), rules that can never be
//! met and the rescue by the net key (finding 3), and the card of the newest seal (finding 4).

mod common;

use bridge_core::{Identity, KeyCard, Role, Statement};
use bridge_net::state::MAX_AHEAD_CHECKS;
use bridge_net::{
    Ahead, Applied, Ban, Body, Delegation, JoinMode, Log, LogRules, Manifest, NetError, NetResult, NetState, Revoke,
    RevokeTarget, Right, Rights, RulesAhead, Seal, Service, Services, WitnessedHead, issue_cosign, verify_head,
};
use common::{DAY, Net, T0, identity, node_card};
use serde_json::Value;

fn junk_ban(n: &Net, at: i64) -> NetResult<Vec<u8>> {
    let subject = identity(99).id().clone();
    Ok(n.sign(&Ban { subject, reason: String::new() }, &n.master, at)?.canonical_bytes().to_vec())
}

fn seal(node: &Identity, level: u8, services: &[Service], with_card: bool) -> NetResult<Seal> {
    let card = if with_card { Some(node_card(node, &format!("https://{}.example", node.id()))?) } else { None };
    Ok(Seal { subject: node.id().clone(), level, services: Services::of(services), card })
}

/// A network whose owner is sealed (gateway, log, witness) and a node W sealed as witness (with card).
fn with_witness() -> NetResult<(Net, Identity)> {
    let mut n = Net::new(JoinMode::Open)?;
    n.seal_owner(T0 + 1)?;
    let w = identity(30);
    n.accept(&n.sign(&seal(&w, 2, &[Service::Witness], true)?, &n.master, T0 + 2)?)?;
    Ok((n, w))
}

/// What a follower behind `state` decides for the entries `entries` ahead.
fn decide(state: &NetState, entries: &[Vec<u8>]) -> RulesAhead {
    state.rules_ahead(&Ahead::parse(&state.manifest().card, state.manifest().version, entries))
}

/// The rules replay gives for a head that ends with `entries`.
fn replayed_rules(state: &NetState, entries: &[Vec<u8>]) -> Option<LogRules> {
    let mut copy = state.clone();
    for entry in entries {
        copy.apply(entry);
    }
    copy.rules_for_head(copy.size())
}

/// A statement that claims `claimed` as its only signer but is signed by `actual` (a forgery).
fn forged<B: Body>(n: &Net, body: &B, claimed: &bridge_core::Id, actual: &Identity, at: i64) -> NetResult<Vec<u8>> {
    let mut value = n.sign(body, actual, at)?.to_value();
    value["iss"] = Value::from(claimed.as_str());
    Ok(bridge_core::json::canonical(&value)?)
}

/// The master key of the test networks (the same as `Net::master`, for borrowing next to a `&mut Net`).
fn master() -> NetResult<Identity> {
    Ok(bridge_core::Mnemonic::parse(common::ZERO_WORDS)?.to_identity()?)
}

fn head_with(n: &Net, log: &Log, cosigners: &[&Identity], at: i64) -> NetResult<WitnessedHead> {
    let statement = log.issue_head(&n.owner, at)?;
    let head = verify_head(&statement, &n.net, &n.owner_card)?;
    let cosigns = cosigners.iter().map(|w| issue_cosign(w, &head, at)).collect::<NetResult<_>>()?;
    Ok(WitnessedHead { head: statement, cosigns })
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 1: no replay for manifests that can never count, bounded checks

/// An old, genuine manifest (here the genesis) copied in front of junk does not force a replay any more: its version
/// is not current + 1, so it can never be accepted.
#[test]
fn old_genuine_manifest_does_not_force_a_replay() -> NetResult<()> {
    let (mut n, w) = with_witness()?;
    let mut manifest = n.state.manifest().next_version();
    manifest.witnesses = vec![w.id().clone()];
    n.accept(&manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?)?;
    let current = n.state.manifest().log_rules();
    let genesis = n.log.entries()[0].clone();
    let fake = vec![genesis.clone(), junk_ban(&n, T0 + 4)?, junk_ban(&n, T0 + 5)?];
    assert_eq!(decide(&n.state, &fake), RulesAhead::Known(current.clone()), "no replay for an old manifest");
    assert_eq!(replayed_rules(&n.state, &fake), Some(current.clone()), "and replay agrees");
    // The same for the previous version (the manifest that is in force now) and many copies of both.
    let latest = n.log.entries()[n.log.entries().len() - 1].clone();
    let mut many: Vec<Vec<u8>> = (0..200).flat_map(|_| [genesis.clone(), latest.clone()]).collect();
    many.push(junk_ban(&n, T0 + 6)?);
    assert_eq!(decide(&n.state, &many), RulesAhead::Known(current));
    Ok(())
}

/// Manifests that only *claim* the net key are checked (and fail) - a few give the current rules, more than the
/// bound refuse the head instead of replaying it.
#[test]
fn forged_manifests_claiming_the_net_key_are_checked_and_capped() -> NetResult<()> {
    let n = Net::new(JoinMode::Open)?;
    let attacker = identity(66);
    let mut manifest = n.state.manifest().next_version();
    manifest.witnesses = vec![attacker.id().clone()];
    let bytes = forged(&n, &manifest, &n.net, &attacker, T0 + 3)?;
    assert!(bridge_net::parse_entry(&bytes).is_ok(), "parses as an entry");
    let current = n.state.manifest().log_rules();
    let mut few: Vec<Vec<u8>> = (0..5).map(|_| bytes.clone()).collect();
    few.push(Vec::new());
    assert_eq!(decide(&n.state, &few), RulesAhead::Known(current.clone()));
    assert_eq!(replayed_rules(&n.state, &few), Some(current.clone()));
    let mut exactly: Vec<Vec<u8>> = (0..MAX_AHEAD_CHECKS).map(|_| bytes.clone()).collect();
    exactly.push(Vec::new());
    assert_eq!(decide(&n.state, &exactly), RulesAhead::Known(current));
    let mut flood: Vec<Vec<u8>> = (0..=MAX_AHEAD_CHECKS).map(|_| bytes.clone()).collect();
    flood.push(Vec::new());
    assert_eq!(decide(&n.state, &flood), RulesAhead::Refuse, "more checks than allowed: refuse, do not replay");
    // Forged manifests with far-off versions are not even looked at.
    manifest.version += 100;
    let far = forged(&n, &manifest, &n.net, &attacker, T0 + 3)?;
    let mut far_flood: Vec<Vec<u8>> = (0..1000).map(|_| far.clone()).collect();
    far_flood.push(Vec::new());
    assert!(matches!(decide(&n.state, &far_flood), RulesAhead::Known(_)));
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 2: rules_ahead agrees with replay

/// A manifest signed by the net key together with a sealed node is accepted on replay - and seen ahead.
#[test]
fn master_plus_sealed_cosigner_manifest_is_seen() -> NetResult<()> {
    let (n, w) = with_witness()?;
    let behind = n.state.clone();
    let old = behind.manifest().log_rules();
    let mut manifest = behind.manifest().next_version();
    manifest.witnesses = vec![w.id().clone()];
    let m = manifest.sign_multi(&n.net, T0 + 3, T0 + 30 * DAY, &[&n.master, &w])?;
    behind.validate_candidate(&m, T0 + 3)?; // the operator takes it
    let entries = vec![m.canonical_bytes().to_vec(), junk_ban(&n, T0 + 4)?];
    let truth = replayed_rules(&behind, &entries);
    assert_ne!(truth.as_ref(), Some(&old), "the rules did change");
    assert_eq!(decide(&behind, &entries), RulesAhead::Replay, "and the follower sees it");
    // A co-signer whose card only comes with the entries ahead counts as well.
    let late = identity(31);
    let late_seal = n.sign(&seal(&late, 1, &[], true)?, &n.master, T0 + 3)?;
    let m2 = manifest.sign_multi(&n.net, T0 + 4, T0 + 30 * DAY, &[&n.master, &late])?;
    let entries = vec![late_seal.canonical_bytes().to_vec(), m2.canonical_bytes().to_vec(), junk_ban(&n, T0 + 5)?];
    assert_ne!(replayed_rules(&behind, &entries).as_ref(), Some(&old));
    assert_eq!(decide(&behind, &entries), RulesAhead::Replay);
    Ok(())
}

/// A tiny deterministic random source (xorshift64*).
struct Dice(u64);

impl Dice {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let value = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 33;
        usize::try_from(value).unwrap_or(0) % n.max(1)
    }
}

/// Who signs a generated manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signers {
    Master,
    MasterAndSealed,
    MasterAndAdmin,
    Admin,
    TwoAdmins,
    LateAdmin,
    // Never accepted on replay:
    ForgedMaster,
    AdminWithoutRules,
    SealedAlone,
    Unknown,
    MasterAndUnknown,
}

impl Signers {
    const ALL: [Signers; 11] = [
        Signers::Master,
        Signers::MasterAndSealed,
        Signers::MasterAndAdmin,
        Signers::Admin,
        Signers::TwoAdmins,
        Signers::LateAdmin,
        Signers::ForgedMaster,
        Signers::AdminWithoutRules,
        Signers::SealedAlone,
        Signers::Unknown,
        Signers::MasterAndUnknown,
    ];

    fn may_count(self) -> bool {
        matches!(
            self,
            Signers::Master
                | Signers::MasterAndSealed
                | Signers::MasterAndAdmin
                | Signers::Admin
                | Signers::TwoAdmins
                | Signers::LateAdmin
        )
    }
}

/// Property: for generated sequences of manifest changes (various versions, rules and signer sets, delegations and
/// junk in between, sometimes a manifest as last entry), `rules_ahead` never claims rules that replay does not give,
/// never refuses such small sequences, and never asks for a replay when no manifest could count.
#[test]
fn rules_ahead_agrees_with_replay() -> NetResult<()> {
    let (mut n, w1) = with_witness()?;
    let a = n.delegate(10, &[Right::Rules], T0 + 2)?;
    let b = n.delegate(11, &[Right::Rules, Right::Seals], T0 + 2)?;
    let c = n.delegate(12, &[Right::Members], T0 + 2)?;
    let (w2, w3, sealed, unknown, late) = (identity(31), identity(32), identity(33), identity(34), identity(35));
    for node in [&w2, &w3] {
        n.accept(&n.sign(&seal(node, 2, &[Service::Witness], true)?, &n.master, T0 + 3)?)?;
    }
    n.accept(&n.sign(&seal(&sealed, 1, &[], true)?, &n.master, T0 + 3)?)?;
    let base = n.state.clone();
    let late_delegation = n.sign(
        &Delegation {
            admin: late.id().clone(),
            rights: Rights::of(&[Right::Rules]),
            card: late.key_card(Role::Admin, None, T0)?,
        },
        &n.master,
        T0 + 5,
    )?;
    let owner = n.owner.id().clone();
    let rule_sets: Vec<(Vec<bridge_core::Id>, Vec<bridge_core::Id>, usize)> = vec![
        (vec![owner.clone()], vec![owner.clone()], 1),
        (vec![owner.clone()], vec![w1.id().clone()], 1),
        (vec![owner.clone()], vec![w1.id().clone(), w2.id().clone()], 2),
        (vec![owner.clone()], vec![w2.id().clone(), w3.id().clone()], 1),
        (vec![w1.id().clone(), owner.clone()], vec![w3.id().clone()], 1),
    ];
    let mut dice = Dice(0x5eed_1234_abcd_ef01);
    let (mut replays, mut knowns) = (0usize, 0usize);
    for case in 0..300 {
        let mut entries: Vec<Vec<u8>> = Vec::new();
        let mut version = base.manifest().version;
        let mut delegated = false;
        let mut any_may_count = false;
        let mut late_manifest = false;
        let length = 1 + dice.below(7);
        for step in 0..length {
            let at = T0 + 10 + i64::try_from(case * 10 + step).unwrap_or(0);
            match dice.below(6) {
                0 => entries.push(junk_ban(&n, at)?),
                1 => {
                    entries.push(late_delegation.canonical_bytes().to_vec());
                    // A delegation as last entry is not looked at (it can not matter for the head).
                    delegated |= step + 1 < length;
                }
                2 if dice.below(2) == 0 => entries.push(b"junk".to_vec()),
                _ => {
                    let mut manifest = base.manifest().clone();
                    manifest.version = match dice.below(5) {
                        0 => version,                   // a duplicate or old version
                        1 => version.saturating_add(2), // a gap
                        2 => base.manifest().version,   // the version in force
                        _ => version.saturating_add(1), // the next one
                    };
                    let (logs, witnesses, threshold) = rule_sets[dice.below(rule_sets.len())].clone();
                    (manifest.logs, manifest.witnesses, manifest.witness_threshold) = (logs, witnesses, threshold);
                    manifest.name = format!("Fall {case}.{step}");
                    let signers = Signers::ALL[dice.below(Signers::ALL.len())];
                    let (iat, exp) = (at, at + 30 * DAY);
                    let statement: Vec<u8> = match signers {
                        Signers::Master => manifest.sign(&n.net, iat, exp, &n.master)?.canonical_bytes().to_vec(),
                        Signers::MasterAndSealed => {
                            manifest.sign_multi(&n.net, iat, exp, &[&n.master, &sealed])?.canonical_bytes().to_vec()
                        }
                        Signers::MasterAndAdmin => {
                            manifest.sign_multi(&n.net, iat, exp, &[&n.master, &a])?.canonical_bytes().to_vec()
                        }
                        Signers::Admin => manifest.sign(&n.net, iat, exp, &a)?.canonical_bytes().to_vec(),
                        Signers::TwoAdmins => {
                            manifest.sign_multi(&n.net, iat, exp, &[&a, &b])?.canonical_bytes().to_vec()
                        }
                        Signers::LateAdmin => manifest.sign(&n.net, iat, exp, &late)?.canonical_bytes().to_vec(),
                        Signers::ForgedMaster => forged(&n, &manifest, &n.net, &unknown, iat)?,
                        Signers::AdminWithoutRules => manifest.sign(&n.net, iat, exp, &c)?.canonical_bytes().to_vec(),
                        Signers::SealedAlone => manifest.sign(&n.net, iat, exp, &sealed)?.canonical_bytes().to_vec(),
                        Signers::Unknown => manifest.sign(&n.net, iat, exp, &unknown)?.canonical_bytes().to_vec(),
                        Signers::MasterAndUnknown => {
                            manifest.sign_multi(&n.net, iat, exp, &[&n.master, &unknown])?.canonical_bytes().to_vec()
                        }
                    };
                    let last = step + 1 == length;
                    let possible = signers.may_count() && manifest.version > base.manifest().version;
                    if possible && !last {
                        // An admin delegated anywhere ahead may count (rules_ahead ignores the order - a superset).
                        if signers == Signers::LateAdmin {
                            late_manifest = true;
                        } else {
                            any_may_count = true;
                        }
                    }
                    if signers.may_count() && manifest.version == version.saturating_add(1) {
                        version = manifest.version;
                    }
                    entries.push(statement);
                }
            }
        }
        any_may_count |= late_manifest && delegated;
        let decided = decide(&base, &entries);
        let truth = replayed_rules(&base, &entries);
        match &decided {
            RulesAhead::Known(rules) => {
                knowns += 1;
                assert_eq!(Some(rules), truth.as_ref(), "case {case}: rules_ahead says {rules:?}, replay differs");
            }
            RulesAhead::Replay => {
                replays += 1;
                assert!(any_may_count, "case {case}: replay asked although no manifest could count");
            }
            RulesAhead::Refuse => return Err(NetError::Forbidden(format!("case {case}: refused a small sequence"))),
        }
    }
    assert!(replays > 30 && knowns > 30, "both outcomes were exercised ({replays} replays, {knowns} known)");
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 3a: rules that can never be met are refused by the operator

#[test]
fn log_operator_refuses_rules_that_can_not_be_met() -> NetResult<()> {
    let (mut n, w) = with_witness()?;
    let gateway_only = identity(40);
    n.accept(&n.sign(&seal(&gateway_only, 2, &[Service::Gateway], true)?, &n.master, T0 + 3)?)?;
    let cardless = identity(41);
    n.accept(&n.sign(&seal(&cardless, 2, &[Service::Witness], false)?, &n.master, T0 + 3)?)?;
    let banned = identity(42);
    n.accept(&n.sign(&seal(&banned, 2, &[Service::Witness], true)?, &n.master, T0 + 3)?)?;
    n.accept(&n.sign(&Ban { subject: banned.id().clone(), reason: String::new() }, &n.master, T0 + 3)?)?;
    let now = T0 + 4;
    let change = |change: &dyn Fn(&mut Manifest)| -> NetResult<Statement> {
        let mut manifest = n.state.manifest().next_version();
        change(&mut manifest);
        manifest.sign(&n.net, now, now + 30 * DAY, &n.master)
    };
    let refused =
        |statement: &Statement| matches!(n.state.validate_candidate(statement, now), Err(NetError::Forbidden(_)));
    // A typo (an ID nobody sealed), a node without the service, without card, banned: refused.
    for witness in [identity(99).id().clone(), gateway_only.id().clone(), cardless.id().clone(), banned.id().clone()] {
        assert!(refused(&change(&|m| m.witnesses = vec![witness.clone()])?), "witness {witness}");
    }
    // Threshold 2 with only one ready witness.
    assert!(refused(&change(&|m| {
        m.witnesses = vec![w.id().clone(), identity(99).id().clone()];
        m.witness_threshold = 2;
    })?));
    // A first log operator without the service log (the witness W) or not sealed at all.
    assert!(refused(&change(&|m| m.logs = vec![w.id().clone(), n.owner.id().clone()])?));
    assert!(refused(&change(&|m| m.logs = vec![identity(99).id().clone()])?));
    // Ready: W as witness, or the owner and W with threshold 1 and a typo'd third (one ready is enough).
    n.state.validate_candidate(&change(&|m| m.witnesses = vec![w.id().clone()])?, now)?;
    n.state.validate_candidate(
        &change(&|m| m.witnesses = vec![n.owner.id().clone(), w.id().clone(), identity(99).id().clone()])?,
        now,
    )?;
    // Other changes need no seals.
    n.state.validate_candidate(&change(&|m| m.name = "Anders".into())?, now)?;
    // The net key can never be listed as log operator or witness (its cosignature would count everywhere).
    let mut listed = n.state.manifest().next_version();
    listed.witnesses = vec![n.net.clone()];
    assert!(matches!(listed.sign(&n.net, now, now + DAY, &n.master), Err(NetError::BadFormat(_))));
    // Replay does not check any of this (it is no rule of the state): a careless operator's entry still counts.
    let typo = change(&|m| m.witnesses = vec![identity(99).id().clone()])?;
    assert_eq!(n.push(&typo)?, Applied::Accepted);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 3b: the rescue by the net key

/// A network frozen by a witness set that can not cosign any more (and an admin with `rules`, identity 10).
struct Frozen {
    n: Net,
    w: Identity,
}

/// Witnesses switch to W (master), W is lost: nothing after the transition head can be witnessed.
fn frozen() -> NetResult<Frozen> {
    let (mut n, w) = with_witness()?;
    n.delegate(10, &[Right::Rules], T0 + 2)?;
    let mut manifest = n.state.manifest().next_version();
    manifest.witnesses = vec![w.id().clone()];
    n.accept(&manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?)?;
    n.accept(&n.sign(&Ban { subject: identity(98).id().clone(), reason: String::new() }, &n.master, T0 + 4)?)?;
    Ok(Frozen { n, w })
}

/// Appends a repair (witnesses back to the owner) signed by `signers`; returns its transition head's log.
fn repair(f: &mut Frozen, signers: &[&Identity], change_rules: bool) -> NetResult<Log> {
    let mut manifest = f.n.state.manifest().next_version();
    if change_rules {
        manifest.witnesses = vec![f.n.owner.id().clone()];
    } else {
        manifest.name = "nur umbenannt".into();
    }
    let statement = manifest.sign_multi(&f.n.net, T0 + 5, T0 + 30 * DAY, signers)?;
    f.n.accept(&statement)?;
    Log::from_entries(f.n.net.clone(), f.n.log.entries())
}

#[test]
fn net_key_cosigns_only_the_transition_head_of_its_own_rescue() -> NetResult<()> {
    let mut f = frozen()?;
    let master = master()?;
    let log = repair(&mut f, &[&master], true)?;
    let size = log.size();
    assert!(f.n.state.rescue_head(size), "the transition head of a rescue");
    let state = &f.n.state;
    // Without any cosignature, or with the owner's (no witness of the rules before the repair): not witnessed.
    assert!(state.check_witnessed(&head_with(&f.n, &log, &[], T0 + 6)?, state, T0 + 7).is_err());
    assert!(state.check_witnessed(&head_with(&f.n, &log, &[&f.n.owner], T0 + 6)?, state, T0 + 7).is_err());
    // The net key's cosignature counts instead of the lost witness - also next to a useless one.
    state.check_witnessed(&head_with(&f.n, &log, &[&f.n.master], T0 + 6)?, state, T0 + 7)?;
    state.check_witnessed(&head_with(&f.n, &log, &[&f.n.owner, &f.n.master], T0 + 6)?, state, T0 + 7)?;
    // The lost witness itself would still do (the normal way).
    state.check_witnessed(&head_with(&f.n, &log, &[&f.w], T0 + 6)?, state, T0 + 7)?;
    // A forged net key cosignature does not.
    let mut fake = head_with(&f.n, &log, &[&f.n.owner], T0 + 6)?;
    let mut value = fake.cosigns[0].to_value();
    value["iss"] = Value::from(f.n.net.as_str());
    fake.cosigns = vec![Statement::from_value(value)?];
    assert!(state.check_witnessed(&fake, state, T0 + 7).is_err());
    // Any other head: the net key's cosignature never counts - the next one, and the one before the repair.
    let ban = f.n.sign(&Ban { subject: identity(97).id().clone(), reason: String::new() }, &f.n.master, T0 + 8)?;
    f.n.accept(&ban)?;
    let after = f.n.log.clone();
    let state = &f.n.state;
    assert!(!state.rescue_head(after.size()));
    assert!(state.check_witnessed(&head_with(&f.n, &after, &[&f.n.master], T0 + 9)?, state, T0 + 9).is_err());
    state.check_witnessed(&head_with(&f.n, &after, &[&f.n.owner], T0 + 9)?, state, T0 + 9)?;
    let before = Log::from_entries(f.n.net.clone(), &f.n.log.entries()[..usize::try_from(size - 1).unwrap_or(0)])?;
    assert!(!state.rescue_head(before.size()));
    assert!(state.check_witnessed(&head_with(&f.n, &before, &[&f.n.master], T0 + 9)?, state, T0 + 9).is_err());
    // Replay remembers the same.
    assert!(f.n.replayed()?.rescue_head(size));
    Ok(())
}

#[test]
fn no_rescue_for_a_manifest_not_signed_by_the_net_key_alone() -> NetResult<()> {
    for signers in ["admin", "master+admin", "master, no rule change"] {
        let mut f = frozen()?;
        let (admin, master) = (identity(10), master()?);
        let log = match signers {
            "admin" => repair(&mut f, &[&admin], true)?,
            "master+admin" => repair(&mut f, &[&master, &admin], true)?,
            _ => repair(&mut f, &[&master], false)?,
        };
        let state = &f.n.state;
        assert!(!state.rescue_head(log.size()), "{signers}");
        let head = head_with(&f.n, &log, &[&f.n.master], T0 + 6)?;
        assert!(matches!(state.check_witnessed(&head, state, T0 + 7), Err(NetError::Forbidden(_))), "{signers}");
    }
    Ok(())
}

/// The follower decision ahead: a rescue head is only taken after replaying a copy (the last entry is the rescue).
#[test]
fn followers_take_a_rescue_head_only_through_the_copy() -> NetResult<()> {
    let mut f = frozen()?;
    let behind = f.n.state.clone();
    let start = usize::try_from(behind.size()).unwrap_or(0);
    let master = master()?;
    let log = repair(&mut f, &[&master], true)?;
    let entries = &f.n.log.entries()[start..];
    let ahead = Ahead::parse(&behind.manifest().card, behind.manifest().version, entries);
    let RulesAhead::Known(rules) = behind.rules_ahead(&ahead) else {
        return Err(NetError::Forbidden("the rescue is the last entry: the old rules hold".into()));
    };
    let head = head_with(&f.n, &log, &[&f.n.master], T0 + 6)?;
    assert!(head.check(&f.n.net, &rules, &(&behind, &ahead), T0 + 7).is_err(), "not by the witness quorum");
    assert!(ahead.may_rescue() && head.claims_cosign_by(&f.n.net), "so the follower replays a copy");
    let mut copy = behind.clone();
    for entry in entries {
        copy.apply(entry);
    }
    copy.check_witnessed(&head, &(&copy, &ahead), T0 + 7)?;
    // A forged "rescue" as last entry gives no hint.
    let mut manifest = behind.manifest().next_version();
    manifest.witnesses = vec![f.n.owner.id().clone()];
    let fake = forged(&f.n, &manifest, &f.n.net, &identity(66), T0 + 5)?;
    let ahead = Ahead::parse(&behind.manifest().card, behind.manifest().version, &[fake]);
    assert!(!ahead.may_rescue());
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 1, step 2: what may be fetched for a head that is not witnessed under the current rules

#[test]
fn may_fetch_needs_a_genuine_manifest_change_ahead() -> NetResult<()> {
    let (mut n, w) = with_witness()?;
    let (sealed_gateway, attacker) = (identity(44), identity(66));
    n.accept(&n.sign(&seal(&sealed_gateway, 2, &[Service::Gateway], true)?, &n.master, T0 + 2)?)?;
    let behind_gw = n.state.clone();
    let mut manifest = behind_gw.manifest().next_version();
    manifest.witnesses = vec![w.id().clone()];
    let change = manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &n.master)?;
    let index = n.log.size();
    n.accept(&change)?;
    n.accept(&n.sign(&Ban { subject: identity(97).id().clone(), reason: String::new() }, &n.master, T0 + 4)?)?;
    let good = head_with(&n, &n.log, &[&w], T0 + 5)?;
    let now = T0 + 6;
    behind_gw.may_fetch(&good, &change, index, now)?;
    // The source's current manifest must be newer ...
    let current = Statement::parse(&n.log.entries()[0])?;
    assert!(behind_gw.may_fetch(&good, &current, 0, now).is_err(), "the genesis");
    assert!(behind_gw.may_fetch(&good, &change, index - 1, now).is_err(), "not ahead of the own log");
    // ... and genuine: not forged. Signed by a sealed gateway (known here, but no admin with `rules` - review 5: its
    // right may come with the entries ahead): only a head of a current log operator justifies the fetch.
    let fake = Statement::parse(&forged(&n, &manifest, &n.net, &attacker, T0 + 3)?)?;
    assert!(behind_gw.may_fetch(&good, &fake, index, now).is_err());
    let by_gateway = manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &sealed_gateway)?;
    behind_gw.may_fetch(&good, &by_gateway, index, now)?;
    // A head behind the manifest must fit its rules: signed by its operator, cosigned by its witness.
    let wrong_witness = head_with(&n, &n.log, &[&n.owner], T0 + 5)?;
    assert!(behind_gw.may_fetch(&wrong_witness, &change, index, now).is_err());
    let log = Log::from_entries(n.net.clone(), n.log.entries())?;
    let by_attacker = attacker.key_card(Role::Node, None, T0)?;
    let statement = log.issue_head(&attacker, T0 + 5)?;
    let head = verify_head(&statement, &n.net, &by_attacker)?;
    let rogue = WitnessedHead { head: statement, cosigns: vec![issue_cosign(&w, &head, T0 + 5)?] };
    assert!(behind_gw.may_fetch(&rogue, &change, index, now).is_err());
    assert!(behind_gw.may_fetch(&rogue, &by_gateway, index, now).is_err(), "gateway's manifest, stranger's head");
    // Signed by keys unknown here (an admin delegated later?): only a head of a current log operator justifies it.
    let by_unknown = manifest.sign(&n.net, T0 + 3, T0 + 30 * DAY, &attacker)?;
    assert!(behind_gw.may_fetch(&rogue, &by_unknown, index, now).is_err(), "head of a stranger");
    behind_gw.may_fetch(&good, &by_unknown, index, now)?;
    // Review 5: a head that (as the source claims) ends with the next manifest is its transition head - the current
    // rules must hold for it (here: cosigned by the new witness only, not the owner).
    let last = n.log.size() - 1;
    assert!(behind_gw.may_fetch(&good, &by_unknown, last, now).is_err(), "not witnessed under the current rules");
    behind_gw.may_fetch(&head_with(&n, &n.log, &[&n.owner], T0 + 5)?, &by_unknown, last, now)?;
    // Behind the head: the card of the witness is not known (it was sealed after the own state) - its cosignature may
    // count, so fetch and check later (review 5: without any cosignature, nothing may count).
    let unknown_w = identity(45);
    let mut n2 = Net::new(JoinMode::Open)?;
    n2.seal_owner(T0 + 1)?;
    let behind2 = n2.state.clone();
    n2.accept(&n2.sign(&seal(&unknown_w, 2, &[Service::Witness], true)?, &n2.master, T0 + 2)?)?;
    let mut m2 = n2.state.manifest().next_version();
    m2.witnesses = vec![unknown_w.id().clone()];
    let change2 = m2.sign(&n2.net, T0 + 3, T0 + 30 * DAY, &n2.master)?;
    let index2 = n2.log.size();
    n2.accept(&change2)?;
    n2.accept(&n2.sign(&Ban { subject: identity(97).id().clone(), reason: String::new() }, &n2.master, T0 + 4)?)?;
    assert!(behind2.may_fetch(&head_with(&n2, &n2.log, &[], T0 + 5)?, &change2, index2, now).is_err());
    behind2.may_fetch(&head_with(&n2, &n2.log, &[&unknown_w], T0 + 5)?, &change2, index2, now)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Finding 4: the card of the newest seal

fn card_with_tls(node: &Identity, url: &str, tls: u8, iat: i64) -> NetResult<KeyCard> {
    Ok(node.key_card_with(Role::Node, None, &[url.to_owned()], Some([tls; 32]), iat)?)
}

#[test]
fn the_newest_seal_brings_the_card_at_any_level() -> NetResult<()> {
    let mut n = Net::new(JoinMode::Open)?;
    let node = identity(50);
    let sealed = |level: u8, card: KeyCard| Seal {
        subject: node.id().clone(),
        level,
        services: Services::of(&[Service::Gateway]),
        card: Some(card),
    };
    let first = n.sign(&sealed(3, card_with_tls(&node, "https://alt.example", 1, T0)?), &n.master, T0 + 1)?;
    n.accept(&first)?;
    // Re-sealed at a lower level with a new address and certificate: that card wins everywhere.
    let second = n.sign(&sealed(2, card_with_tls(&node, "https://neu.example", 2, T0 + 2)?), &n.master, T0 + 2)?;
    n.accept(&second)?;
    let card = n.state.card_of(node.id()).ok_or_else(|| NetError::NotFound("card".into()))?;
    assert_eq!((card.tls(), card.urls()), (Some(&[2; 32]), &["https://neu.example".to_owned()][..]));
    let gateway = n.state.gateways(T0 + 3).into_iter().find(|(id, _)| id == node.id()).and_then(|(_, card)| card);
    assert_eq!(gateway.as_ref().and_then(KeyCard::tls), Some(&[2; 32]));
    assert_eq!(n.state.seals(node.id(), T0 + 3).iter().map(|(level, _)| *level).collect::<Vec<_>>(), vec![2, 3]);
    // Re-sealed at the higher level again: the newest wins again.
    let third = n.sign(&sealed(3, card_with_tls(&node, "https://dritt.example", 3, T0 + 4)?), &n.master, T0 + 4)?;
    n.accept(&third)?;
    assert_eq!(n.state.card_of(node.id()).and_then(KeyCard::tls), Some(&[3; 32]));
    // The newest one revoked: the next newest current seal brings the card.
    let revoke = Revoke { target: RevokeTarget::Statement(third.hash_bytes()), reason: String::new() };
    n.accept(&n.sign(&revoke, &n.master, T0 + 5)?)?;
    assert_eq!(n.state.card_of(node.id()).and_then(KeyCard::tls), Some(&[2; 32]));
    let gateway = n.state.gateways(T0 + 6).into_iter().find(|(id, _)| id == node.id()).and_then(|(_, card)| card);
    assert_eq!(gateway.as_ref().and_then(KeyCard::tls), Some(&[2; 32]));
    assert_eq!(n.replayed()?, n.state);
    Ok(())
}
