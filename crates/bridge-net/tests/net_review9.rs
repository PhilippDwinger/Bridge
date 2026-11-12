//! Review 9 (phase 4): names can not use up the log, old name statements never come back, labels follow the owner of
//! a name and 18+ from any side wins, the app key may revoke its name, reserved words in tags and descriptions.

mod common;

use bridge_core::{Identity, Role, Statement};
use bridge_net::{
    AdultPolicy, Body, Category, JoinMode, Label, LabelTarget, Member, Name, NameKind, NetError, NetResult, Revoke,
    RevokeTarget, Right, Seal, Services,
};
use common::{DAY, MIN, Net, T0, identity};

/// A network (log entries per day as given, 18+ as given) with the owner node sealed; `members` get the levels given
/// (seeds 50, 51, …) - all by the master key, so none of it counts against the day's entries.
fn network(per_day: u64, adult: Option<AdultPolicy>, levels: &[u8]) -> NetResult<(Net, Vec<Identity>)> {
    let mut net = Net::with(JoinMode::Open, |manifest| {
        manifest.limits.log_entries_per_day = per_day;
        manifest.short = Some("testnetz".into());
        manifest.contact = Some("abuse@example.org".into());
        manifest.adult = adult;
    })?;
    net.seal_owner(T0 + MIN)?;
    let mut members = Vec::new();
    for (index, level) in levels.iter().enumerate() {
        let member = identity(50 + index as u8);
        let iat = T0 + 2 * MIN + index as i64;
        net.accept(&net.sign(&Member { member: member.id().clone(), invite: None }, &net.master, iat)?)?;
        if *level > 0 {
            let seal = Seal { subject: member.id().clone(), level: *level, services: Services::NONE, card: None };
            net.accept(&net.sign(&seal, &net.master, iat + 10)?)?;
        }
        members.push(member);
    }
    Ok((net, members))
}

fn member_name(name: &str, member: &Identity, description: &str) -> NetResult<Name> {
    Ok(Name {
        name: name.into(),
        kind: NameKind::Member,
        target: member.id().clone(),
        owner: member.id().clone(),
        owner_card: member.key_card(Role::Client, None, T0)?,
        card: None,
        description: description.into(),
        tags: Vec::new(),
        category: Category::General,
        hosts: Vec::new(),
    })
}

fn app_name(name: &str, owner: &Identity, app: &Identity) -> NetResult<Name> {
    Ok(Name {
        name: name.into(),
        kind: NameKind::App,
        target: app.id().clone(),
        owner: owner.id().clone(),
        owner_card: owner.key_card(Role::Client, None, T0)?,
        card: Some(app.key_card(Role::App, None, T0)?),
        description: "Ein Laden".into(),
        tags: Vec::new(),
        category: Category::General,
        hosts: Vec::new(),
    })
}

/// A name statement valid for `days` from `iat`.
fn signed(
    net: &Net,
    name: &Name,
    owner: &Identity,
    app: Option<&Identity>,
    iat: i64,
    days: i64,
) -> NetResult<Statement> {
    name.sign_name(&net.net, iat, iat + days * DAY, owner, app)
}

/// Joins of new members by the owner node (a gateway of the open network): they count against the general pool.
fn joins(net: &mut Net, count: u8, iat: i64) -> NetResult<()> {
    for index in 0..count {
        let member = identity(150 + index);
        let statement =
            net.sign(&Member { member: member.id().clone(), invite: None }, &net.owner, iat + i64::from(index))?;
        net.accept(&statement)?;
    }
    Ok(())
}

/// Review 9, finding 2 (the reviewer's case): `log_entries_per_day` 50, a level-1 member renews its name 50 times - it
/// used to fill the day's entries, and joins and labels were refused until the next day. Now: its entries of the day
/// are bounded (quota of its level + 2), names have their own pool, and joins and labels go on.
#[test]
fn fifty_renewals_do_not_block_joins_and_labels() -> NetResult<()> {
    let (mut net, members) = network(50, None, &[1])?;
    let alice = &members[0];
    let iat = T0 + 10 * MIN;
    let mut accepted = 0;
    let mut refused = Vec::new();
    for round in 0..50 {
        // 30 days: always inside the renewal window, so only the day's budget holds it.
        let name = member_name("alice", alice, &format!("Version {round}"))?;
        match net.push(&signed(&net, &name, alice, None, iat + round, 30)?)? {
            bridge_net::Applied::Accepted => accepted += 1,
            bridge_net::Applied::Skipped(reason) => refused.push(reason),
        }
    }
    assert_eq!(accepted, 5, "quota 3 of level 1 + 2 entries a day");
    assert!(refused.iter().all(|reason| matches!(reason, NetError::QuotaExceeded(text) if text.contains("today"))));
    // The general pool is untouched: 45 joins by the gateway and an admin's label go in the same day.
    joins(&mut net, 45, iat + MIN)?;
    let seals = net.delegate(90, &[Right::Seals], iat + 2 * MIN)?;
    let label = Label { target: LabelTarget::Name("alice".into()), category: Category::General, reason: String::new() };
    net.accept(&net.sign(&label, &seals, iat + 3 * MIN)?)?;
    // The next day the member may renew again.
    let name = member_name("alice", alice, "morgen")?;
    net.accept(&signed(&net, &name, alice, None, iat + DAY, 30)?)?;
    assert_eq!(net.replayed()?, net.state);
    Ok(())
}

/// Many members together fill only the names' own pool: joins of the day still go in.
#[test]
fn many_owners_fill_only_the_pool_of_names() -> NetResult<()> {
    let (mut net, members) = network(20, None, &[1; 6])?;
    let iat = T0 + 10 * MIN;
    let mut accepted = 0;
    for (index, member) in members.iter().enumerate() {
        for round in 0..5 {
            let name = member_name(&format!("m{index}-{round}"), member, "")?;
            if net.push(&signed(&net, &name, member, None, iat + (index * 10 + round) as i64, 30)?)?
                == bridge_net::Applied::Accepted
            {
                accepted += 1;
            }
        }
    }
    assert_eq!(accepted, 18, "6 members x 3 names, all within the 20 name entries of the day");
    let one_more = member_name("noch-einer", &members[0], "")?;
    let reason = net.skip(&signed(&net, &one_more, &members[0], None, iat + MIN, 30)?)?;
    assert!(matches!(reason, NetError::QuotaExceeded(_)), "{reason:?}");
    // Two more names by a fresh level-3 member: the names' pool is full for the day (20).
    let (dave, other) = (identity(80), identity(81));
    for (member, offset) in [(&dave, 0), (&other, 1)] {
        net.accept(&net.sign(&Member { member: member.id().clone(), invite: None }, &net.master, iat + offset)?)?;
        let seal = Seal { subject: member.id().clone(), level: 3, services: Services::NONE, card: None };
        net.accept(&net.sign(&seal, &net.master, iat + 10 + offset)?)?;
    }
    net.accept(&signed(&net, &member_name("dave-eins", &dave, "")?, &dave, None, iat + 2 * MIN, 30)?)?;
    net.accept(&signed(&net, &member_name("dave-zwei", &dave, "")?, &dave, None, iat + 2 * MIN + 1, 30)?)?;
    let reason = net.skip(&signed(&net, &member_name("dave-drei", &dave, "")?, &dave, None, iat + 2 * MIN + 2, 30)?)?;
    assert!(matches!(&reason, NetError::QuotaExceeded(text) if text.contains("name entries per day")), "{reason:?}");
    // … and the gateway still admits 19 members the same day.
    joins(&mut net, 19, iat + 3 * MIN)?;
    assert_eq!(net.replayed()?, net.state);
    Ok(())
}

/// Outside the last 30 days before its expiry, the same owner changes a name at most once a day.
#[test]
fn names_change_at_most_once_a_day_outside_the_renewal_window() -> NetResult<()> {
    let (mut net, members) = network(1000, None, &[1])?;
    let alice = &members[0];
    let iat = T0 + 10 * MIN;
    net.accept(&signed(&net, &member_name("alice", alice, "eins")?, alice, None, iat, 365)?)?;
    let soon = signed(&net, &member_name("alice", alice, "zwei")?, alice, None, iat + MIN, 365)?;
    let reason = net.skip(&soon)?;
    assert!(matches!(&reason, NetError::Forbidden(text) if text.contains("less than a day")), "{reason:?}");
    net.accept(&signed(&net, &member_name("alice", alice, "zwei")?, alice, None, iat + DAY, 365)?)?;
    // A name close to its expiry is renewed at any time.
    net.accept(&signed(&net, &member_name("kurz", alice, "eins")?, alice, None, iat + DAY + 1, 20)?)?;
    net.accept(&signed(&net, &member_name("kurz", alice, "zwei")?, alice, None, iat + DAY + MIN, 365)?)?;
    Ok(())
}

/// Older statements of a name never come back - not after the owner revoked it, not after a shorter newer statement
/// expired, not from anybody - while a fresh registration by somebody else is fine.
#[test]
fn old_name_statements_never_come_back() -> NetResult<()> {
    let (mut net, members) = network(1000, None, &[1, 1])?;
    let (alice, bob) = (&members[0], &members[1]);
    let iat = T0 + 10 * MIN;
    let first = signed(&net, &member_name("alice", alice, "alt")?, alice, None, iat, 365)?;
    net.accept(&first)?;
    let second = signed(&net, &member_name("alice", alice, "neu")?, alice, None, iat + DAY, 365)?;
    net.accept(&second)?;
    let revoke = Revoke { target: RevokeTarget::Statement(second.hash_bytes()), reason: String::new() };
    net.accept(&net.sign(&revoke, alice, iat + DAY + MIN)?)?;
    for old in [&first, &second] {
        assert!(matches!(net.skip(old)?, NetError::Forbidden(_)), "an old statement came back");
    }
    // A long statement, then (a day later) a short newer one that expires: the long one stays out.
    let long = signed(&net, &member_name("lang", alice, "lang")?, alice, None, iat + 2 * DAY, 365)?;
    net.accept(&long)?;
    let short = signed(&net, &member_name("lang", alice, "kurz")?, alice, None, iat + 3 * DAY, 2)?;
    net.accept(&short)?;
    // Days later (the short one expired and was forgotten): the long one is refused.
    net.accept(&net.sign(&Member { member: identity(99).id().clone(), invite: None }, &net.master, iat + 6 * DAY)?)?;
    assert!(net.state.name_info("lang").is_none(), "expired and forgotten");
    assert!(matches!(net.skip(&long)?, NetError::Forbidden(_)));
    // Somebody else registers both names anew.
    net.accept(&signed(&net, &member_name("alice", bob, "bobs")?, bob, None, iat + 6 * DAY + 1, 30)?)?;
    net.accept(&signed(&net, &member_name("lang", bob, "bobs")?, bob, None, iat + 6 * DAY + 2, 30)?)?;
    assert_eq!(net.replayed()?, net.state);
    Ok(())
}

/// Review 9, finding 4: a label of a name once outlived a change of the name's owner, and a name's label `general`
/// beat an `adult` label of its target. Now a name's label holds only for the owner it was given under, and 18+ from
/// the owner, the name's label or the target's label wins.
#[test]
fn labels_follow_the_owner_and_18_plus_from_any_side_wins() -> NetResult<()> {
    let (mut net, members) = network(1000, Some(AdultPolicy::Allowed), &[1, 1])?;
    let (alice, bob) = (&members[0], &members[1]);
    let iat = T0 + 10 * MIN;
    let seals = net.delegate(90, &[Right::Seals], iat)?;
    let label = |target: LabelTarget, category: Category| Label { target, category, reason: String::new() };
    // alice's name, labeled 18+ while it is hers.
    let shop = signed(&net, &member_name("shop", alice, "")?, alice, None, iat + MIN, 30)?;
    net.accept(&shop)?;
    net.accept(&net.sign(&label(LabelTarget::Name("shop".into()), Category::Adult), &seals, iat + 2 * MIN)?)?;
    assert_eq!(net.state.resolve_name("shop", iat + 3 * MIN)?.category, Category::Adult);
    // alice gives it up, bob takes it: alice's label does not hold for bob.
    let revoke = Revoke { target: RevokeTarget::Statement(shop.hash_bytes()), reason: String::new() };
    net.accept(&net.sign(&revoke, alice, iat + 3 * MIN)?)?;
    net.accept(&signed(&net, &member_name("shop", bob, "")?, bob, None, iat + 4 * MIN, 30)?)?;
    let resolved = net.state.resolve_name("shop", iat + 5 * MIN)?;
    assert_eq!((resolved.category, resolved.name_label), (Category::General, None));
    // A label of a name nobody holds holds for whoever takes it.
    net.accept(&net.sign(&label(LabelTarget::Name("nachts".into()), Category::Adult), &seals, iat + 5 * MIN)?)?;
    net.accept(&signed(&net, &member_name("nachts", bob, "")?, bob, None, iat + 6 * MIN, 30)?)?;
    assert_eq!(net.state.resolve_name("nachts", iat + 7 * MIN)?.category, Category::Adult);
    // A name's label `general` does not beat the target's 18+ (nor the owner's own 18+).
    let app = identity(70);
    net.accept(&signed(&net, &app_name("kino", alice, &app)?, alice, Some(&app), iat + 7 * MIN, 30)?)?;
    net.accept(&net.sign(&label(LabelTarget::Name("kino".into()), Category::General), &seals, iat + 8 * MIN)?)?;
    net.accept(&net.sign(&label(LabelTarget::Id(app.id().clone()), Category::Adult), &seals, iat + 9 * MIN)?)?;
    let resolved = net.state.resolve_name("kino", iat + 10 * MIN)?;
    assert_eq!(
        (resolved.category, resolved.name_label, resolved.target_label),
        (Category::Adult, Some(Category::General), Some(Category::Adult))
    );
    let mut declared = member_name("selbst", alice, "")?;
    declared.category = Category::Adult;
    net.accept(&signed(&net, &declared, alice, None, iat + 10 * MIN, 30)?)?;
    net.accept(&net.sign(&label(LabelTarget::Name("selbst".into()), Category::General), &seals, iat + 11 * MIN)?)?;
    assert_eq!(net.state.resolve_name("selbst", iat + 12 * MIN)?.category, Category::Adult);
    assert!(net.state.search_names("selbst", true, 10, iat + 12 * MIN).0.is_empty(), "never in the safe search");
    assert_eq!(net.replayed()?, net.state);
    Ok(())
}

/// Review 9, finding 7: the app key signs an app name too (docs/08 §3) and may revoke it - it had no card to sign
/// with. Another app's key can not.
#[test]
fn the_app_key_revokes_its_own_name() -> NetResult<()> {
    let (mut net, members) = network(1000, None, &[1])?;
    let alice = &members[0];
    let (app, other) = (identity(70), identity(71));
    let iat = T0 + 10 * MIN;
    let shop = signed(&net, &app_name("shop", alice, &app)?, alice, Some(&app), iat, 30)?;
    net.accept(&shop)?;
    net.accept(&signed(&net, &app_name("andere", alice, &other)?, alice, Some(&other), iat + 1, 30)?)?;
    let revoke = Revoke { target: RevokeTarget::Statement(shop.hash_bytes()), reason: String::new() };
    assert!(matches!(net.skip(&net.sign(&revoke, &other, iat + MIN)?)?, NetError::Forbidden(_)));
    net.accept(&net.sign(&revoke, &app, iat + 2 * MIN)?)?;
    assert!(net.state.resolve_name("shop", iat + 3 * MIN).is_err());
    assert!(net.state.resolve_name("andere", iat + 3 * MIN).is_ok());
    assert_eq!(net.replayed()?, net.state);
    Ok(())
}

/// Review 9, finding 8: reserved words in tags need level 3 like in names; a description with a reserved word does
/// not count for the search of owners below level 3; a manifest that adds a reserved word marks the names again.
#[test]
fn reserved_words_in_tags_and_descriptions() -> NetResult<()> {
    let (mut net, members) = network(1000, None, &[1, 2, 3])?;
    let (alice, bea, dave) = (&members[0], &members[1], &members[2]);
    let iat = T0 + 10 * MIN;
    let mut tagged = member_name("laden", alice, "")?;
    tagged.tags = vec!["paypa1".into()];
    let reason = net.skip(&signed(&net, &tagged, alice, None, iat, 30)?)?;
    assert!(matches!(&reason, NetError::Forbidden(text) if text.contains("reserved")), "{reason:?}");
    tagged.owner = dave.id().clone();
    tagged.target = dave.id().clone();
    tagged.owner_card = dave.key_card(Role::Client, None, T0)?;
    net.accept(&signed(&net, &tagged, dave, None, iat + 1, 30)?)?;
    assert!(net.state.resolve_name("laden", iat + MIN)?.reserved);
    // Descriptions with "PayPal": bea (level 2) is not found by them, dave (level 3) is.
    net.accept(&signed(&net, &member_name("bea", bea, "Dein PayPal hier")?, bea, None, iat + 2, 30)?)?;
    net.accept(&signed(&net, &member_name("dave", dave, "Offizieller PayPal Support")?, dave, None, iat + 3, 30)?)?;
    let found = |query: &str, safe: bool| -> Vec<String> {
        net.state.search_names(query, safe, 10, iat + MIN).0.into_iter().map(|r| r.info.name.name).collect()
    };
    assert_eq!(found("paypal", false), ["dave"]);
    assert_eq!(found("paypal", true), ["dave"]);
    assert_eq!(found("bea", true), ["bea"], "her name itself is found");
    // A new manifest version reserves "kasse": alice's name with it stops resolving, a level-3 one stays.
    net.accept(&signed(&net, &member_name("kasse-eins", alice, "")?, alice, None, iat + 4, 30)?)?;
    net.accept(&signed(&net, &member_name("kasse-zwei", dave, "")?, dave, None, iat + 5, 30)?)?;
    let mut manifest = net.state.manifest().next_version();
    manifest.names = Some(bridge_net::NameRules { reserved: vec!["kasse".into()], ..Default::default() });
    net.accept(&manifest.sign(&net.net, iat + 2 * MIN, iat + 300 * DAY, &net.master)?)?;
    assert!(net.state.resolve_name("kasse-eins", iat + 3 * MIN).is_err());
    assert!(net.state.resolve_name("kasse-zwei", iat + 3 * MIN)?.reserved);
    assert_eq!(net.replayed()?, net.state);
    Ok(())
}
