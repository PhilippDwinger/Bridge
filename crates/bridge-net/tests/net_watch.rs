//! Watchers (docs/06 §11, ADR 0016): a node sealed at level ≥ 2 with the service `watch` signs level-1 seals alone -
//! member seals after `member_age` without bans, node seals (node card, services ⊆ {web}) for members - within its
//! budget, never above level 1, never for itself, never over somebody else's level-1 seal. Normal cases and attacks;
//! replay always agrees with the state built entry by entry.

mod common;

use bridge_core::{Identity, Role, Statement};
use bridge_net::{
    Ban, Body, JoinMode, Member, NetError, NetResult, Revoke, RevokeTarget, Right, Seal, Service, Services, WatchRules,
    is_web_host,
};
use common::{DAY, MIN, Net, T0, identity, node_card};

const HOUR: i64 = 60 * MIN;

/// Watcher rules for the tests: members after one hour, seals of at most 2 days, `budget` seals per day.
fn rules(budget: u64) -> WatchRules {
    WatchRules {
        member_age_s: 3600,
        seal_s: 2 * 86_400,
        renew_s: 86_400,
        seals_per_day: budget,
        ..WatchRules::default()
    }
}

struct Watch {
    net: Net,
    /// A watcher (level 2, gateway + watch).
    watcher: Identity,
    /// A second watcher (level 2, watch only).
    other: Identity,
    /// An admin with `seals` and `members` and `bans`.
    admin: Identity,
    /// A member that joined at T0 + 2 min.
    member: Identity,
    /// A node that joined as member at T0 + 2 min (role node, with an address).
    node: Identity,
    /// Hash of the watcher's own seal.
    watcher_seal: String,
}

fn watch_seal(node: &Identity, level: u8, services: &[Service]) -> NetResult<Seal> {
    Ok(Seal {
        subject: node.id().clone(),
        level,
        services: Services::of(services),
        card: Some(node_card(node, &format!("https://{}.example", node.id()))?),
    })
}

fn setup(budget: u64) -> NetResult<Watch> {
    let mut net = Net::with(JoinMode::Open, |manifest| manifest.watch = Some(rules(budget)))?;
    net.seal_owner(T0 + MIN)?;
    let admin = net.delegate(30, &[Right::Seals, Right::Members, Right::Bans], T0 + MIN)?;
    let (member, node) = (identity(31), identity(32));
    for who in [&member, &node] {
        let body = Member { member: who.id().clone(), invite: None };
        let statement = net.sign(&body, &net.owner, T0 + 2 * MIN)?;
        net.accept(&statement)?;
    }
    let watcher = identity(33);
    let statement = net.sign(&watch_seal(&watcher, 2, &[Service::Gateway, Service::Watch])?, &admin, T0 + 3 * MIN)?;
    net.accept(&statement)?;
    let watcher_seal = statement.hash();
    let other = identity(34);
    let statement = net.sign(&watch_seal(&other, 2, &[Service::Watch])?, &admin, T0 + 3 * MIN)?;
    net.accept(&statement)?;
    Ok(Watch { net, watcher, other, admin, member, node, watcher_seal })
}

/// A member seal (level 1, no card, no services).
fn member_seal(subject: &Identity) -> Seal {
    Seal { subject: subject.id().clone(), level: 1, services: Services::NONE, card: None }
}

/// A node seal (level 1, node card with an address).
fn node_seal(subject: &Identity, services: &[Service]) -> NetResult<Seal> {
    Ok(Seal {
        subject: subject.id().clone(),
        level: 1,
        services: Services::of(services),
        card: Some(node_card(subject, "https://node.example/probe")?),
    })
}

/// Signed by `signer` with a lifetime of one day.
fn signed(net: &Net, seal: &Seal, signer: &Identity, iat: i64) -> NetResult<Statement> {
    seal.sign(&net.net, iat, iat + DAY, signer)
}

fn forbidden(error: &NetError) -> bool {
    matches!(error, NetError::Forbidden(_))
}

#[test]
fn watcher_role_comes_from_the_log() -> NetResult<()> {
    let w = setup(100)?;
    let at = T0 + 4 * MIN;
    assert!(w.net.state.is_watcher(w.watcher.id(), at) && w.net.state.is_watcher(w.other.id(), at));
    assert!(!w.net.state.is_watcher(w.net.owner.id(), at), "level 3 without watch: no watcher");
    assert!(!w.net.state.is_watcher(w.member.id(), at));
    let watchers = w.net.state.watchers(at);
    assert_eq!(watchers.len(), 2);
    assert!(watchers.iter().all(|(_, card)| card.as_ref().is_some_and(|card| !card.urls().is_empty())));
    assert_eq!(w.net.state.watch_rules(), rules(100));
    // Without the manifest field: the defaults.
    let plain = Net::new(JoinMode::Open)?;
    assert_eq!(plain.state.watch_rules(), WatchRules::default());
    Ok(())
}

#[test]
fn member_seal_after_member_age() -> NetResult<()> {
    let mut w = setup(100)?;
    // Too young (member since T0 + 2 min, one hour needed).
    let early = signed(&w.net, &member_seal(&w.member), &w.watcher, T0 + 30 * MIN)?;
    assert!(w.net.state.validate_candidate(&early, T0 + 30 * MIN).is_err());
    assert!(forbidden(&w.net.skip(&early)?));
    assert_eq!(w.net.state.level(w.member.id(), T0 + 30 * MIN), Some(0));
    // Old enough.
    let at = T0 + 2 * HOUR;
    let seal = signed(&w.net, &member_seal(&w.member), &w.watcher, at)?;
    w.net.state.validate_candidate(&seal, at)?;
    w.net.accept(&seal)?;
    assert_eq!(w.net.state.level(w.member.id(), at), Some(1));
    assert!(w.net.state.services(w.member.id(), at).is_empty());
    assert_eq!(w.net.state.watch_used(w.watcher.id(), at), 1);
    let info = w.net.state.seal_info(w.member.id(), 1).ok_or(NetError::NotFound("seal".into()))?;
    assert!(info.by_watcher && info.issuers == [w.watcher.id().clone()] && info.active(at));
    assert_eq!(w.net.state.seals_issued_by(w.watcher.id(), 1).len(), 1);
    // Renewal by the same watcher (newer iat) replaces it and counts against the budget.
    let renewal = signed(&w.net, &member_seal(&w.member), &w.watcher, at + HOUR)?;
    w.net.accept(&renewal)?;
    assert!(w.net.state.is_revoked(&seal.hash_bytes()), "the renewed seal is replaced");
    assert_eq!(w.net.state.watch_used(w.watcher.id(), at + HOUR), 2);
    assert_eq!(w.net.replayed()?, w.net.state, "replay agrees");
    Ok(())
}

#[test]
fn node_seal_with_web_makes_a_web_host() -> NetResult<()> {
    let mut w = setup(100)?;
    // A node seal needs no membership age (the probes are the watcher's part).
    let at = T0 + 5 * MIN;
    let seal = signed(&w.net, &node_seal(&w.node, &[Service::Web])?, &w.watcher, at)?;
    w.net.accept(&seal)?;
    assert_eq!(w.net.state.level(w.node.id(), at), Some(1));
    assert!(is_web_host(&w.net.state, w.node.id(), at));
    assert!(w.net.state.card_of(w.node.id()).is_some_and(|card| card.urls() == ["https://node.example/probe"]));
    // Without services is fine too.
    let bare = signed(&w.net, &node_seal(&w.member, &[])?, &w.watcher, at)?;
    w.net.accept(&bare)?;
    assert_eq!(w.net.replayed()?, w.net.state);
    Ok(())
}

#[test]
fn watcher_never_above_level_one_or_beyond_web() -> NetResult<()> {
    let mut w = setup(100)?;
    let at = T0 + 2 * HOUR;
    // Level 2 and 3 (also with a fitting card) are refused.
    for level in [2, 3] {
        let seal = Seal { level, ..node_seal(&w.node, &[Service::Web])? };
        let statement = signed(&w.net, &seal, &w.watcher, at)?;
        assert!(forbidden(&w.net.skip(&statement)?), "level {level}");
        assert!(w.net.state.validate_candidate(&statement, at).is_err());
    }
    // Infrastructure and services without probes are for admins.
    for service in [Service::Gateway, Service::Log, Service::Witness, Service::Watch, Service::Storage, Service::Names]
    {
        let statement = signed(&w.net, &node_seal(&w.node, &[Service::Web, service])?, &w.watcher, at)?;
        assert!(forbidden(&w.net.skip(&statement)?), "{service:?}");
    }
    // A member seal has no services.
    let seal = Seal { services: Services::of(&[Service::Web]), ..member_seal(&w.member) };
    assert!(forbidden(&w.net.skip(&signed(&w.net, &seal, &w.watcher, at)?)?));
    // A node seal needs a node card with addresses: no address, or a client card, is refused.
    let no_urls = Seal { card: Some(w.node.key_card(Role::Node, None, T0)?), ..node_seal(&w.node, &[])? };
    assert!(forbidden(&w.net.skip(&signed(&w.net, &no_urls, &w.watcher, at)?)?));
    let client = Seal { card: Some(w.member.key_card(Role::Client, None, T0)?), ..member_seal(&w.member) };
    assert!(forbidden(&w.net.skip(&signed(&w.net, &client, &w.watcher, at)?)?));
    // Longer than seal_s (2 days).
    let long = node_seal(&w.node, &[Service::Web])?.sign(&w.net.net, at, at + 3 * DAY, &w.watcher)?;
    assert!(forbidden(&w.net.skip(&long)?));
    // Not for itself, not for non-members, not for banned members.
    let own = signed(&w.net, &node_seal(&w.watcher, &[Service::Web])?, &w.watcher, at)?;
    assert!(forbidden(&w.net.skip(&own)?));
    let stranger = identity(50);
    let statement = signed(&w.net, &node_seal(&stranger, &[Service::Web])?, &w.watcher, at)?;
    assert_eq!(w.net.skip(&statement)?, NetError::NotMember);
    let ban = Ban { subject: w.node.id().clone(), reason: "Spam".into() };
    let statement = ban.sign(&w.net.net, at, at + HOUR, &w.admin)?;
    w.net.accept(&statement)?;
    let statement = signed(&w.net, &node_seal(&w.node, &[Service::Web])?, &w.watcher, at + MIN)?;
    assert_eq!(w.net.skip(&statement)?, NetError::Banned);
    // Together with an admin it is an admin seal (needs every signer to be an admin): refused.
    let both = node_seal(&w.member, &[Service::Web])?.sign_multi(&w.net.net, at, at + DAY, &[&w.watcher, &w.admin])?;
    assert!(forbidden(&w.net.skip(&both)?));
    assert_eq!(w.net.state.level(w.node.id(), at + 2 * MIN), None, "banned: no level");
    assert_eq!(w.net.state.watch_used(w.watcher.id(), at), 0, "nothing refused counts");
    assert_eq!(w.net.replayed()?, w.net.state);
    Ok(())
}

#[test]
fn only_watchers_sign_alone() -> NetResult<()> {
    let mut w = setup(100)?;
    let at = T0 + 2 * HOUR;
    // The owner node (level 3, gateway/log/witness - no watch) and a member are no watchers.
    let owner = w.net.owner.clone_identity();
    for signer in [&owner, &w.member] {
        let statement = signed(&w.net, &member_seal(&w.node), signer, at)?;
        assert!(forbidden(&w.net.skip(&statement)?));
    }
    // A watch seal at level 1 (given by an admin) makes no watcher.
    let low = identity(51);
    let statement = w.net.sign(&watch_seal(&low, 1, &[Service::Watch])?, &w.admin, at)?;
    w.net.accept(&statement)?;
    assert!(!w.net.state.is_watcher(low.id(), at));
    let statement = signed(&w.net, &member_seal(&w.node), &low, at + MIN)?;
    assert!(forbidden(&w.net.skip(&statement)?));
    // A watch seal without card makes no watcher either (nobody could verify what it signs).
    let bare = identity(52);
    let seal = Seal { subject: bare.id().clone(), level: 2, services: Services::of(&[Service::Watch]), card: None };
    w.net.accept(&w.net.sign(&seal, &w.admin, at)?)?;
    assert!(!w.net.state.is_watcher(bare.id(), at + MIN));
    assert!(forbidden(&w.net.skip(&signed(&w.net, &member_seal(&w.node), &bare, at + MIN)?)?));
    Ok(())
}

#[test]
fn budget_per_watcher_and_day() -> NetResult<()> {
    let mut w = setup(2)?;
    let at = T0 + 2 * HOUR;
    let subjects: Vec<Identity> = (60..64).map(identity).collect();
    for subject in &subjects {
        let body = Member { member: subject.id().clone(), invite: None };
        w.net.accept(&w.net.sign(&body, &w.net.owner, T0 + 2 * MIN)?)?;
    }
    w.net.accept(&signed(&w.net, &member_seal(&subjects[0]), &w.watcher, at)?)?;
    w.net.accept(&signed(&w.net, &member_seal(&subjects[1]), &w.watcher, at)?)?;
    let third = signed(&w.net, &member_seal(&subjects[2]), &w.watcher, at)?;
    assert!(matches!(w.net.state.validate_candidate(&third, at), Err(NetError::QuotaExceeded(_))));
    assert!(matches!(w.net.skip(&third)?, NetError::QuotaExceeded(_)));
    // The budget is per watcher: the other one still has its own.
    w.net.accept(&signed(&w.net, &member_seal(&subjects[2]), &w.other, at)?)?;
    // A revocation does not count, and is always possible.
    let first = w.net.state.seal_info(subjects[0].id(), 1).ok_or(NetError::NotFound("seal".into()))?;
    let revoke = Revoke { target: RevokeTarget::Statement(first.hash), reason: "Proben".into() };
    w.net.accept(&revoke.sign(&w.net.net, at + MIN, at + DAY, &w.watcher)?)?;
    assert_eq!(w.net.state.level(subjects[0].id(), at + 2 * MIN), Some(0));
    // The next day the budget is back.
    let next_day = (at.div_euclid(DAY) + 1) * DAY + MIN;
    assert_eq!(w.net.state.watch_used(w.watcher.id(), next_day), 0);
    w.net.accept(&signed(&w.net, &member_seal(&subjects[3]), &w.watcher, next_day)?)?;
    assert_eq!(w.net.state.watch_used(w.watcher.id(), next_day), 1);
    assert_eq!(w.net.replayed()?, w.net.state);
    Ok(())
}

#[test]
fn one_level_one_seal_per_subject_first_wins() -> NetResult<()> {
    let mut w = setup(100)?;
    let at = T0 + 2 * HOUR;
    w.net.accept(&signed(&w.net, &member_seal(&w.member), &w.watcher, at)?)?;
    // The other watcher can not replace it (no duplicates, no ping-pong) - also not with a newer iat.
    let theirs = signed(&w.net, &member_seal(&w.member), &w.other, at + MIN)?;
    assert!(forbidden(&w.net.skip(&theirs)?));
    // An admin's level-1 seal is never replaced by a watcher; the admin replaces the watcher's.
    let by_admin = w.net.sign(&node_seal(&w.node, &[Service::Storage])?, &w.admin, at)?;
    w.net.accept(&by_admin)?;
    let over = signed(&w.net, &node_seal(&w.node, &[Service::Web])?, &w.watcher, at + MIN)?;
    assert!(forbidden(&w.net.skip(&over)?));
    w.net.accept(&w.net.sign(&member_seal(&w.member), &w.admin, at + 2 * MIN)?)?;
    let info = w.net.state.seal_info(w.member.id(), 1).ok_or(NetError::NotFound("seal".into()))?;
    assert!(!info.by_watcher && info.issuers == [w.admin.id().clone()]);
    assert_eq!(w.net.replayed()?, w.net.state);
    Ok(())
}

#[test]
fn ended_watcher_keeps_its_seals_until_expiry_others_take_over() -> NetResult<()> {
    let mut w = setup(100)?;
    let at = T0 + 2 * HOUR;
    w.net.accept(&signed(&w.net, &member_seal(&w.member), &w.watcher, at)?)?;
    w.net.accept(&signed(&w.net, &node_seal(&w.node, &[Service::Web])?, &w.watcher, at)?)?;
    // An admin revokes the watcher's seal: no cascade - its level-1 seals stay until they expire.
    let hash = bridge_core::encoding::b64_fixed::<32>(&w.watcher_seal, "hash")?;
    let revoke = Revoke { target: RevokeTarget::Statement(hash), reason: "kein Wächter mehr".into() };
    w.net.accept(&revoke.sign(&w.net.net, at + MIN, at + DAY, &w.admin)?)?;
    let later = at + 2 * MIN;
    assert!(!w.net.state.is_watcher(w.watcher.id(), later));
    assert_eq!(w.net.state.level(w.member.id(), later), Some(1));
    assert!(is_web_host(&w.net.state, w.node.id(), later));
    // The former watcher can sign no new seals (and no renewals).
    let renewal = signed(&w.net, &member_seal(&w.member), &w.watcher, later)?;
    assert!(forbidden(&w.net.skip(&renewal)?));
    // Its seals are orphaned: another watcher may replace (renew) them.
    w.net.accept(&signed(&w.net, &member_seal(&w.member), &w.other, later)?)?;
    let info = w.net.state.seal_info(w.member.id(), 1).ok_or(NetError::NotFound("seal".into()))?;
    assert_eq!(info.issuers, [w.other.id().clone()]);
    // ... and they end when they expire.
    assert_eq!(w.net.state.level(w.node.id(), at + DAY), Some(0));
    // A stolen watcher key: the master's cascade removes everything it issued.
    let cascade =
        Revoke { target: RevokeTarget::Identity { id: w.other.id().clone(), cascade: true }, reason: String::new() };
    w.net.accept(&cascade.sign(&w.net.net, later + 2 * MIN, later + DAY, &w.net.master)?)?;
    assert_eq!(w.net.state.level(w.member.id(), later + 3 * MIN), Some(0), "cascade removed the other's seal");
    assert_eq!(w.net.replayed()?, w.net.state);
    Ok(())
}

#[test]
fn revocation_only_of_own_seals() -> NetResult<()> {
    let mut w = setup(100)?;
    let at = T0 + 2 * HOUR;
    let seal = signed(&w.net, &node_seal(&w.node, &[Service::Web])?, &w.watcher, at)?;
    w.net.accept(&seal)?;
    // The other watcher can not revoke it, not the identity either.
    let theirs = Revoke { target: RevokeTarget::Statement(seal.hash_bytes()), reason: String::new() };
    assert!(forbidden(&w.net.skip(&theirs.sign(&w.net.net, at + MIN, at + DAY, &w.other)?)?));
    let identity =
        Revoke { target: RevokeTarget::Identity { id: w.node.id().clone(), cascade: false }, reason: String::new() };
    assert!(forbidden(&w.net.skip(&identity.sign(&w.net.net, at + MIN, at + DAY, &w.watcher)?)?));
    // The watcher itself can.
    w.net.accept(&theirs.sign(&w.net.net, at + MIN, at + DAY, &w.watcher)?)?;
    assert_eq!(w.net.state.level(w.node.id(), at + 2 * MIN), Some(0));
    assert!(!is_web_host(&w.net.state, w.node.id(), at + 2 * MIN));
    Ok(())
}

#[test]
fn a_ban_resets_the_member_age() -> NetResult<()> {
    let mut w = setup(100)?;
    // Banned for 10 minutes at T0 + 2 h: the hour counts again from the end of the ban (T0 + 2 h 10 min).
    let ban = Ban { subject: w.member.id().clone(), reason: "Spam".into() };
    let ban = ban.sign(&w.net.net, T0 + 2 * HOUR, T0 + 2 * HOUR + 10 * MIN, &w.admin)?;
    w.net.accept(&ban)?;
    // Even if the ban is revoked early, it counts until its exp.
    let lift = Revoke { target: RevokeTarget::Statement(ban.hash_bytes()), reason: "Irrtum".into() };
    w.net.accept(&lift.sign(&w.net.net, T0 + 2 * HOUR + MIN, T0 + 3 * HOUR, &w.admin)?)?;
    let after_ban = signed(&w.net, &member_seal(&w.member), &w.watcher, T0 + 2 * HOUR + 30 * MIN)?;
    assert!(forbidden(&w.net.skip(&after_ban)?));
    let ok = signed(&w.net, &member_seal(&w.member), &w.watcher, T0 + 3 * HOUR + 11 * MIN)?;
    w.net.accept(&ok)?;
    assert_eq!(w.net.state.level(w.member.id(), T0 + 3 * HOUR + 12 * MIN), Some(1));
    // A node seal of a member that was banned once is fine (probes decide there).
    w.net.accept(&signed(&w.net, &node_seal(&w.node, &[Service::Web])?, &w.watcher, T0 + 3 * HOUR + 12 * MIN)?)?;
    assert_eq!(w.net.replayed()?, w.net.state);
    Ok(())
}

#[test]
fn renewal_needs_newer_iat_and_garbage_is_skipped() -> NetResult<()> {
    let mut w = setup(100)?;
    let at = T0 + 2 * HOUR;
    let seal = signed(&w.net, &member_seal(&w.member), &w.watcher, at)?;
    w.net.accept(&seal)?;
    // The same seal again (replay of the entry) and an older one are refused.
    assert!(w.net.skip(&seal).is_ok());
    let older = signed(&w.net, &member_seal(&w.member), &w.watcher, at - MIN)?;
    assert!(w.net.skip(&older).is_ok());
    // A watcher statement for another network does not count.
    let other_net = identity(70).id().clone();
    let foreign = member_seal(&w.member).sign(&other_net, at, at + DAY, &w.watcher)?;
    assert!(w.net.skip(&foreign).is_ok());
    assert_eq!(w.net.state.watch_used(w.watcher.id(), at), 1);
    assert_eq!(w.net.replayed()?, w.net.state);
    Ok(())
}

/// The owner node (a gateway of an open network) admits `who` with this `iat`.
fn admit(net: &mut Net, who: &Identity, iat: i64) -> NetResult<Statement> {
    let statement = net.sign(&Member { member: who.id().clone(), invite: None }, &net.owner, iat)?;
    net.accept(&statement)?;
    Ok(statement)
}

/// Review 8, finding 1: watchers have their own seal table (bounded by the member limit) - at its cap a watcher seal
/// is refused, while admins and the master key still seal (before: one shared table, no cap of its own).
#[test]
fn watcher_seals_have_their_own_table() -> NetResult<()> {
    let mut net = Net::with(JoinMode::Open, |manifest| {
        manifest.watch = Some(rules(100));
        manifest.limits.members = 2;
    })?;
    net.seal_owner(T0 + MIN)?;
    let admin = net.delegate(30, &[Right::Seals, Right::Members], T0 + MIN)?;
    let watcher = identity(33);
    net.accept(&net.sign(&watch_seal(&watcher, 2, &[Service::Watch])?, &admin, T0 + 3 * MIN)?)?;
    let (a, b, c) = (identity(40), identity(41), identity(42));
    let a_member = admit(&mut net, &a, T0 + 2 * MIN)?;
    admit(&mut net, &b, T0 + 2 * MIN)?;
    let at = T0 + 2 * HOUR;
    for who in [&a, &b] {
        net.accept(&signed(&net, &member_seal(who), &watcher, at)?)?;
    }
    assert_eq!((net.state.watch_seal_count(), net.state.watch_seal_limit()), (2, 2));
    // a leaves (its watcher seal stays until it expires), c joins: a third watcher seal does not fit.
    let leave = Revoke { target: RevokeTarget::Statement(a_member.hash_bytes()), reason: String::new() };
    net.accept(&leave.sign(&net.net, at, at + DAY, &admin)?)?;
    admit(&mut net, &c, T0 + 3 * MIN)?;
    let third = signed(&net, &node_seal(&c, &[Service::Web])?, &watcher, at + MIN)?;
    assert!(matches!(net.state.validate_candidate(&third, at + MIN), Err(NetError::QuotaExceeded(_))));
    assert!(matches!(net.skip(&third)?, NetError::QuotaExceeded(_)));
    // Admins and the master key seal as before (their own table).
    net.accept(&net.sign(&Net::gateway_seal(&identity(43), 2)?, &admin, at + MIN)?)?;
    net.accept(&net.sign(&Net::gateway_seal(&identity(44), 2)?, &net.master, at + MIN)?)?;
    net.accept(&net.sign(&member_seal(&c), &admin, at + MIN)?)?;
    // A renewal stays in the watchers' table; an admin seal over a watcher's moves it out (room again).
    net.accept(&signed(&net, &member_seal(&b), &watcher, at + 2 * MIN)?)?;
    assert_eq!(net.state.watch_seal_count(), 2);
    net.accept(&net.sign(&member_seal(&b), &admin, at + 3 * MIN)?)?;
    assert_eq!(net.state.watch_seal_count(), 1);
    assert_eq!(net.replayed()?, net.state, "replay agrees");
    Ok(())
}

/// Review 8, finding 1: entries of watchers count against their own daily pool - a busy watcher does not use up the
/// entries of admins and gateways (before: one pool for all).
#[test]
fn watcher_entries_have_their_own_daily_pool() -> NetResult<()> {
    let mut net = Net::with(JoinMode::Open, |manifest| {
        manifest.watch = Some(rules(2));
        manifest.limits.log_entries_per_day = 8;
    })?;
    net.seal_owner(T0 + MIN)?;
    let admin = net.delegate(30, &[Right::Seals, Right::Members], T0 + MIN)?;
    let watcher = identity(33);
    net.accept(&net.sign(&watch_seal(&watcher, 2, &[Service::Watch])?, &admin, T0 + 3 * MIN)?)?;
    let members: Vec<Identity> = (40..44).map(identity).collect();
    for who in &members {
        admit(&mut net, who, T0 + 2 * MIN)?;
    }
    // 5 general entries so far (watch seal, 4 members); the watcher's two seals go into its pool.
    let at = T0 + 2 * HOUR;
    let seal = signed(&net, &member_seal(&members[0]), &watcher, at)?;
    net.accept(&seal)?;
    net.accept(&signed(&net, &member_seal(&members[1]), &watcher, at)?)?;
    // The admin still has three entries today, then the general pool is used up.
    for seed in 50..53 {
        net.accept(&net.sign(&Net::gateway_seal(&identity(seed), 2)?, &admin, at + MIN)?)?;
    }
    let late = net.sign(&Net::gateway_seal(&identity(53), 2)?, &admin, at + MIN)?;
    assert!(matches!(net.skip(&late)?, NetError::QuotaExceeded(_)));
    // The watcher's revocation of its own seal goes into its pool, too (revocations have the 10 % reserve).
    let revoke = Revoke { target: RevokeTarget::Statement(seal.hash_bytes()), reason: "Proben".into() };
    net.accept(&revoke.sign(&net.net, at + 2 * MIN, at + DAY, &watcher)?)?;
    assert_eq!(net.replayed()?, net.state, "replay agrees");
    Ok(())
}

/// Review 8, finding 10c: a membership's age counts from the replay time it was accepted at, not from its `iat` - a
/// gateway that back-dates a membership does not make it old enough for a member seal.
#[test]
fn backdated_membership_is_not_older() -> NetResult<()> {
    let mut w = setup(100)?;
    let late = identity(45);
    // The log clock moves to T0 + 2 h (any entry), then a membership with an iat of T0 + 3 min is appended.
    admit(&mut w.net, &identity(46), T0 + 2 * HOUR)?;
    admit(&mut w.net, &late, T0 + 3 * MIN)?;
    assert_eq!(w.net.state.member_since(late.id()), Some(T0 + 2 * HOUR), "accepted at the log clock");
    let early = signed(&w.net, &member_seal(&late), &w.watcher, T0 + 2 * HOUR + MIN)?;
    assert!(w.net.state.validate_candidate(&early, T0 + 2 * HOUR + MIN).is_err());
    assert!(forbidden(&w.net.skip(&early)?), "one minute old, not two hours");
    let ok = signed(&w.net, &member_seal(&late), &w.watcher, T0 + 3 * HOUR + MIN)?;
    w.net.accept(&ok)?;
    assert_eq!(w.net.replayed()?, w.net.state, "replay agrees");
    Ok(())
}

/// The same identity again (the fixture's owner is not `Clone`).
trait CloneIdentity {
    fn clone_identity(&self) -> Identity;
}

impl CloneIdentity for Identity {
    fn clone_identity(&self) -> Identity {
        let (sign, receive) = self.secret_bytes();
        Identity::from_secret_bytes(&sign, &receive)
    }
}
