//! Names and labels in the network state (docs/08 §3-§5): first come, renewal by the same owner, confusable and
//! reserved names, quotas by level, signers and cards, bans, 18+ policy and labels, search ranking, revocation and
//! replay determinism.

mod common;

use bridge_core::{Id, Identity, Role, Statement};
use bridge_net::names::skeleton;
use bridge_net::{
    AdultPolicy, Ban, Body, Category, Delegation, JoinMode, Label, LabelTarget, Member, Name, NameKind, NameRules,
    NetError, NetResult, Revoke, RevokeTarget, Right, Rights, Seal, Services,
};
use common::{DAY, MIN, Net, T0, expect_skip, identity};

struct Names {
    net: Net,
    alice: Identity,
    bob: Identity,
    carol: Identity,
    dave: Identity,
    app: Identity,
}

/// A network with members: alice and bob (level 1), carol (level 0), dave (level 3); an app key of alice.
fn setup(adult: Option<AdultPolicy>, rules: Option<NameRules>) -> NetResult<Names> {
    let mut net = Net::with(JoinMode::Open, |manifest| {
        manifest.short = Some("testnetz".into());
        manifest.contact = Some("abuse@example.org".into());
        manifest.adult = adult;
        manifest.names = rules;
    })?;
    net.seal_owner(T0 + MIN)?;
    let (alice, bob, carol, dave) = (identity(50), identity(51), identity(52), identity(53));
    for (index, (member, level)) in [(&alice, 1), (&bob, 1), (&carol, 0), (&dave, 3)].into_iter().enumerate() {
        let iat = T0 + 2 * MIN + index as i64;
        let statement = net.sign(&Member { member: member.id().clone(), invite: None }, &net.master, iat)?;
        net.accept(&statement)?;
        if level > 0 {
            let seal = Seal { subject: member.id().clone(), level, services: Services::NONE, card: None };
            let statement = net.sign(&seal, &net.master, iat + 10)?;
            net.accept(&statement)?;
        }
    }
    Ok(Names { net, alice, bob, carol, dave, app: identity(60) })
}

fn app_name(name: &str, owner: &Identity, app: &Identity) -> NetResult<Name> {
    Ok(Name {
        name: name.into(),
        kind: NameKind::App,
        target: app.id().clone(),
        owner: owner.id().clone(),
        owner_card: owner.key_card(Role::Client, None, T0)?,
        card: Some(app.key_card(Role::App, None, T0)?),
        description: "Ein kleiner Laden für Kleidung".into(),
        tags: vec!["laden".into(), "kleidung".into()],
        category: Category::General,
        hosts: vec![identity(70).id().clone()],
    })
}

fn member_name(name: &str, member: &Identity) -> NetResult<Name> {
    Ok(Name {
        name: name.into(),
        kind: NameKind::Member,
        target: member.id().clone(),
        owner: member.id().clone(),
        owner_card: member.key_card(Role::Client, None, T0)?,
        card: None,
        description: String::new(),
        tags: Vec::new(),
        category: Category::General,
        hosts: Vec::new(),
    })
}

fn sign(names: &Names, name: &Name, owner: &Identity, app: Option<&Identity>, iat: i64) -> NetResult<Statement> {
    name.sign_name(&names.net.net, iat, iat + 30 * DAY, owner, app)
}

const NOW: i64 = T0 + 20 * MIN;

#[test]
fn app_name_resolves_with_address_and_safety() -> NetResult<()> {
    let mut names = setup(None, None)?;
    let shop = app_name("shop", &names.alice, &names.app)?;
    let statement = sign(&names, &shop, &names.alice, Some(&names.app), T0 + 10 * MIN)?;
    names.net.accept(&statement)?;
    let state = &names.net.state;
    let resolved = state.resolve_name("shop", NOW)?;
    assert_eq!(resolved.info.name, shop);
    assert_eq!(resolved.info.hash, statement.hash_bytes());
    assert_eq!((resolved.owner_level, resolved.category, resolved.reserved), (1, Category::General, false));
    assert_eq!(state.resolve_name("shop.testnetz", NOW)?, resolved, "with this network's short name");
    assert!(matches!(state.resolve_name("shop.anderes", NOW), Err(NetError::NotFound(_))), "another network");
    assert!(matches!(state.resolve_name("laden", NOW), Err(NetError::NotFound(_))));
    assert_eq!(state.names_of(names.alice.id(), NOW).len(), 1);
    assert_eq!(state.names_for(names.app.id(), NOW).len(), 1);
    // Not yet valid / expired: nothing.
    assert!(state.resolve_name("shop", T0 + 31 * DAY).is_err());
    assert_eq!(names.net.replayed()?, names.net.state, "replay gives the same state");
    Ok(())
}

#[test]
fn forged_and_unruly_names_are_skipped() -> NetResult<()> {
    let mut names = setup(None, None)?;
    let iat = T0 + 10 * MIN;
    let shop = app_name("shop", &names.alice, &names.app)?;
    // An app name signed by the owner alone, or by the app key alone: skipped.
    let alone = shop.sign(&names.net.net, iat, iat + DAY, &names.alice)?;
    assert!(matches!(names.net.skip(&alone)?, NetError::Forbidden(_)));
    let app_alone = shop.sign(&names.net.net, iat, iat + DAY, &names.app)?;
    assert!(matches!(names.net.skip(&app_alone)?, NetError::Forbidden(_)));
    // Signed by the app key and somebody else than the owner in the body: skipped.
    let wrong = shop.sign_multi(&names.net.net, iat, iat + DAY, &[&names.app, &names.bob])?;
    assert!(matches!(names.net.skip(&wrong)?, NetError::Forbidden(_)));
    // A body whose owner card is somebody else's: not even a valid body.
    let mut foreign = shop.clone();
    foreign.owner_card = names.bob.key_card(Role::Client, None, T0)?;
    assert!(foreign.to_body().is_err());
    // A signature that does not fit (bytes changed after signing): skipped.
    let good = sign(&names, &shop, &names.alice, Some(&names.app), iat)?;
    let mut value = good.to_value();
    value["body"]["description"] = serde_json::json!("geändert");
    let tampered = Statement::from_value(value)?;
    assert_eq!(names.net.skip(&tampered)?, NetError::BadSignature);
    // A non-member and a level-0 member may not register (default min_level 1).
    let stranger = identity(80);
    let theirs = member_name("fremd", &stranger)?;
    assert_eq!(names.net.skip(&sign(&names, &theirs, &stranger, None, iat)?)?, NetError::NotMember);
    let carols = member_name("carol", &names.carol)?;
    assert!(matches!(names.net.skip(&sign(&names, &carols, &names.carol, None, iat)?)?, NetError::Forbidden(_)));
    // Longer than a year: skipped.
    let long = shop.sign_multi(&names.net.net, iat, iat + 366 * DAY, &[&names.app, &names.alice])?;
    assert!(matches!(names.net.skip(&long)?, NetError::Forbidden(_)));
    // The real one goes in; then nobody else gets it, nor a confusable of it.
    names.net.accept(&good)?;
    let other_app = identity(61);
    let taken = app_name("shop", &names.bob, &other_app)?;
    let taken = sign(&names, &taken, &names.bob, Some(&other_app), iat + MIN)?;
    assert!(matches!(names.net.skip(&taken)?, NetError::Forbidden(message) if message.contains("taken")));
    for confusable in ["sh0p", "s-hop", "5hop"] {
        let look_alike = app_name(confusable, &names.bob, &other_app)?;
        let statement = sign(&names, &look_alike, &names.bob, Some(&other_app), iat + 2 * MIN)?;
        let reason = names.net.skip(&statement)?;
        assert!(matches!(&reason, NetError::Forbidden(message) if message.contains("confusable")), "{reason:?}");
    }
    // Reserved words: not for level 1, fine for level 3.
    for reserved in ["paypal-login", "mein-8ank", "support-team"] {
        let statement = sign(&names, &member_name(reserved, &names.bob)?, &names.bob, None, iat + 3 * MIN)?;
        assert!(matches!(names.net.skip(&statement)?, NetError::Forbidden(message) if message.contains("reserved")));
    }
    let official = member_name("support-team", &names.dave)?;
    names.net.accept(&sign(&names, &official, &names.dave, None, iat + 4 * MIN)?)?;
    assert!(names.net.state.resolve_name("support-team", NOW)?.reserved);
    assert_eq!(names.net.replayed()?, names.net.state);
    Ok(())
}

#[test]
fn quotas_renewal_expiry_and_revocation() -> NetResult<()> {
    let mut names = setup(None, None)?;
    let iat = T0 + 10 * MIN;
    // Level 1: three names.
    for (index, name) in ["eins", "zwei", "drei"].into_iter().enumerate() {
        let statement = sign(&names, &member_name(name, &names.alice)?, &names.alice, None, iat + index as i64)?;
        names.net.accept(&statement)?;
    }
    let fourth = sign(&names, &member_name("vier", &names.alice)?, &names.alice, None, iat + 10)?;
    assert!(matches!(names.net.skip(&fourth)?, NetError::QuotaExceeded(_)));
    // Renewal of one of them does not count as a new name; an older one is refused.
    let mut renewed = member_name("eins", &names.alice)?;
    renewed.description = "verlängert".into();
    names.net.accept(&sign(&names, &renewed, &names.alice, None, iat + MIN)?)?;
    assert_eq!(names.net.state.resolve_name("eins", NOW)?.info.name.description, "verlängert");
    let stale = sign(&names, &member_name("eins", &names.alice)?, &names.alice, None, iat + 30)?;
    assert!(matches!(names.net.skip(&stale)?, NetError::Forbidden(_)));
    // The owner revokes its own name (its card comes from the name); then bob may take it.
    let hash = names.net.state.resolve_name("zwei", NOW)?.info.hash;
    let revoke = Revoke { target: RevokeTarget::Statement(hash), reason: "brauche ich nicht".into() };
    names.net.accept(&names.net.sign(&revoke, &names.alice, iat + 2 * MIN)?)?;
    assert!(names.net.state.resolve_name("zwei", NOW).is_err());
    names.net.accept(&sign(&names, &member_name("zwei", &names.bob)?, &names.bob, None, iat + 3 * MIN)?)?;
    // A stranger can not revoke bob's name; an admin with only `members` neither; an admin with `seals` can.
    let hash = names.net.state.resolve_name("zwei", NOW)?.info.hash;
    let revoke = Revoke { target: RevokeTarget::Statement(hash), reason: String::new() };
    assert!(names.net.skip(&names.net.sign(&revoke, &names.alice, iat + 4 * MIN)?).is_ok());
    let members = names.net.delegate(90, &[Right::Members], iat + 5 * MIN)?;
    assert!(matches!(names.net.skip(&names.net.sign(&revoke, &members, iat + 6 * MIN)?)?, NetError::Forbidden(_)));
    let seals = names.net.delegate(91, &[Right::Seals], iat + 7 * MIN)?;
    names.net.accept(&names.net.sign(&revoke, &seals, iat + 8 * MIN)?)?;
    assert!(names.net.state.resolve_name("zwei", NOW).is_err());
    // A name that expired is free for anybody.
    let (start, end) = (iat + 9 * MIN, iat + 10 * MIN);
    let short = member_name("kurz", &names.dave)?.sign_name(&names.net.net, start, end, &names.dave, None)?;
    names.net.accept(&short)?;
    let early = sign(&names, &member_name("kurz", &names.bob)?, &names.bob, None, start + 1)?;
    assert!(matches!(names.net.skip(&early)?, NetError::Forbidden(_)), "still dave's");
    let later = sign(&names, &member_name("kurz", &names.bob)?, &names.bob, None, end)?;
    names.net.accept(&later)?;
    assert_eq!(names.net.state.resolve_name("kurz", NOW)?.info.name.owner, names.bob.id().clone());
    assert_eq!(names.net.replayed()?, names.net.state);
    Ok(())
}

#[test]
fn bans_and_identity_revocations_drop_names_at_once() -> NetResult<()> {
    let mut names = setup(None, None)?;
    let iat = T0 + 10 * MIN;
    names.net.accept(&sign(
        &names,
        &app_name("shop", &names.alice, &names.app)?,
        &names.alice,
        Some(&names.app),
        iat,
    )?)?;
    names.net.accept(&sign(&names, &member_name("bob", &names.bob)?, &names.bob, None, iat + 1)?)?;
    // Banning the app ID drops its name; banning the owner drops its names and refuses new ones.
    let ban = Ban { subject: names.app.id().clone(), reason: "Phishing".into() };
    names.net.accept(&names.net.sign(&ban, &names.net.master, iat + MIN)?)?;
    assert_eq!(names.net.state.resolve_name("shop", NOW), Err(NetError::Banned));
    assert!(names.net.state.search_names("shop", false, 10, NOW).0.is_empty());
    let ban = Ban { subject: names.bob.id().clone(), reason: String::new() };
    names.net.accept(&names.net.sign(&ban, &names.net.master, iat + 2 * MIN)?)?;
    assert_eq!(names.net.state.resolve_name("bob", NOW), Err(NetError::Banned));
    let again = sign(&names, &member_name("bobby", &names.bob)?, &names.bob, None, iat + 3 * MIN)?;
    assert_eq!(names.net.skip(&again)?, NetError::Banned);
    // Revoking alice as identity frees her names for others.
    let revoke = Revoke {
        target: RevokeTarget::Identity { id: names.alice.id().clone(), cascade: false },
        reason: String::new(),
    };
    names.net.accept(&names.net.sign(&revoke, &names.net.master, iat + 4 * MIN)?)?;
    assert!(names.net.state.name_info("shop").is_none(), "the name is gone, not just hidden");
    let other_app = identity(62);
    let taken =
        sign(&names, &app_name("shop", &names.dave, &other_app)?, &names.dave, Some(&other_app), iat + 5 * MIN)?;
    names.net.accept(&taken)?;
    assert_eq!(names.net.replayed()?, names.net.state);
    Ok(())
}

#[test]
fn adult_policy_and_labels() -> NetResult<()> {
    // Default: forbidden. A self-declared 18+ name is refused.
    let mut names = setup(None, None)?;
    let iat = T0 + 10 * MIN;
    let mut adult = app_name("nachts", &names.alice, &names.app)?;
    adult.category = Category::Adult;
    let statement = sign(&names, &adult, &names.alice, Some(&names.app), iat)?;
    assert!(matches!(names.net.skip(&statement)?, NetError::Forbidden(_)));
    // A general name labeled 18+ by an admin with `seals` no longer resolves, nor its app is served.
    names.net.accept(&sign(
        &names,
        &app_name("shop", &names.alice, &names.app)?,
        &names.alice,
        Some(&names.app),
        iat,
    )?)?;
    let label =
        Label { target: LabelTarget::Id(names.app.id().clone()), category: Category::Adult, reason: "18+".into() };
    let members = names.net.delegate(90, &[Right::Members], iat + MIN)?;
    assert!(matches!(names.net.skip(&names.net.sign(&label, &members, iat + 2 * MIN)?)?, NetError::Forbidden(_)));
    assert!(!names.net.state.app_labeled_adult(names.app.id(), NOW));
    names.net.accept(&names.net.sign(&label, &names.net.master, iat + 3 * MIN)?)?;
    assert!(names.net.state.resolve_name("shop", NOW).is_err());
    assert!(names.net.state.app_labeled_adult(names.app.id(), NOW));

    // Allowed: 18+ names go in, resolve with their category, the safe search never shows them.
    let mut names = setup(Some(AdultPolicy::Allowed), None)?;
    let statement = sign(&names, &adult, &names.alice, Some(&names.app), iat)?;
    names.net.accept(&statement)?;
    let resolved = names.net.state.resolve_name("nachts", NOW)?;
    assert_eq!(resolved.category, Category::Adult);
    assert!(names.net.state.search_names("nachts", true, 10, NOW).0.is_empty(), "safe search hides 18+");
    // The safe search also hides owners below level 2; without it the name shows.
    names.net.accept(&sign(&names, &member_name("alice", &names.alice)?, &names.alice, None, iat + 1)?)?;
    assert!(names.net.state.search_names("alice", true, 10, NOW).0.is_empty());
    assert_eq!(names.net.state.search_names("alice", false, 10, NOW).0.len(), 1);
    // Review 9: 18+ from any side wins - a label `general` of the name no longer overrides the self-declared 18+ or
    // the target's 18+ label.
    let seals = names.net.delegate(91, &[Right::Seals], iat + MIN)?;
    let fix = Label { target: LabelTarget::Name("nachts".into()), category: Category::General, reason: String::new() };
    names.net.accept(&names.net.sign(&fix, &seals, iat + 2 * MIN)?)?;
    let target =
        Label { target: LabelTarget::Id(names.app.id().clone()), category: Category::Adult, reason: String::new() };
    names.net.accept(&names.net.sign(&target, &seals, iat + 3 * MIN)?)?;
    let resolved = names.net.state.resolve_name("nachts", NOW)?;
    assert_eq!(
        (resolved.category, resolved.name_label, resolved.target_label),
        (Category::Adult, Some(Category::General), Some(Category::Adult))
    );
    assert!(!names.net.state.app_labeled_adult(names.app.id(), NOW), "allowed network: apps stay");
    assert_eq!(names.net.replayed()?, names.net.state);
    Ok(())
}

#[test]
fn search_ranks_and_rules_from_the_manifest() -> NetResult<()> {
    // Level 0 may register here (min_level 0, quota 2).
    let rules = NameRules { min_level: 0, quota: [2, 5, 20, 100], reserved: vec!["sparkasse".into()] };
    let mut names = setup(None, Some(rules))?;
    let iat = T0 + 10 * MIN;
    let apps: Vec<Identity> = (100..104).map(identity).collect();
    let mut entries: Vec<(Name, &Identity, &Identity)> = Vec::new();
    entries.push((app_name("shop", &names.dave, &apps[0])?, &names.dave, &apps[0]));
    entries.push((app_name("shopping", &names.alice, &apps[1])?, &names.alice, &apps[1]));
    let mut tagged = app_name("laden", &names.bob, &apps[2])?;
    tagged.tags = vec!["shop".into()];
    entries.push((tagged, &names.bob, &apps[2]));
    let mut described = app_name("kiosk", &names.carol, &apps[3])?;
    described.tags = Vec::new();
    described.description = "Der Shop an der Ecke".into();
    entries.push((described, &names.carol, &apps[3]));
    for (index, (name, owner, app)) in entries.iter().enumerate() {
        names.net.accept(&sign(&names, name, owner, Some(app), iat + index as i64)?)?;
    }
    let (results, more) = names.net.state.search_names("Shop", false, 10, NOW);
    let found: Vec<&str> = results.iter().map(|result| result.info.name.name.as_str()).collect();
    assert_eq!(found, ["shop", "shopping", "laden", "kiosk"]);
    assert!(!more);
    let (first, more) = names.net.state.search_names("shop", false, 2, NOW);
    assert_eq!((first.len(), more), (2, true));
    // `.testnetz` is cut off; the safe search keeps only owners of level ≥ 2 (dave).
    let (safe, _) = names.net.state.search_names("shop.testnetz", true, 10, NOW);
    assert_eq!(safe.iter().map(|result| result.info.name.name.as_str()).collect::<Vec<_>>(), ["shop"]);
    // A query of the same skeleton finds the name; empty or huge queries find nothing.
    assert_eq!(names.net.state.search_names("sh0p", false, 10, NOW).0[0].info.name.name, "shop");
    assert!(names.net.state.search_names("", false, 10, NOW).0.is_empty());
    assert!(names.net.state.search_names(&"x".repeat(65), false, 10, NOW).0.is_empty());
    // The manifest's reserved words count like the fixed ones.
    let statement = sign(&names, &member_name("sparkasse-hilfe", &names.carol)?, &names.carol, None, iat + 9)?;
    assert!(matches!(names.net.skip(&statement)?, NetError::Forbidden(_)));
    assert_eq!(skeleton("sparkasse"), "sparkasse");
    Ok(())
}

#[test]
fn labels_need_the_right_and_replace_older_ones() -> NetResult<()> {
    let mut names = setup(Some(AdultPolicy::Allowed), None)?;
    let iat = T0 + 10 * MIN;
    let bans = names.net.delegate(92, &[Right::Bans], iat)?;
    let label = Label { target: LabelTarget::Name("shop".into()), category: Category::Adult, reason: String::new() };
    assert!(matches!(names.net.skip(&names.net.sign(&label, &bans, iat + MIN)?)?, NetError::Forbidden(_)));
    // A member can not label at all; a cascade-revoked admin's labels are gone.
    let carol_label = names.net.sign(&label, &names.carol, iat + MIN)?;
    assert!(expect_skip(names.net.push(&carol_label)?).is_ok());
    let admin = identity(93);
    let delegation = Delegation {
        admin: admin.id().clone(),
        rights: Rights::of(&[Right::Seals]),
        card: admin.key_card(Role::Admin, None, T0)?,
    };
    names.net.accept(&names.net.sign(&delegation, &names.net.master, iat + 2 * MIN)?)?;
    names.net.accept(&names.net.sign(&label, &admin, iat + 3 * MIN)?)?;
    let target = LabelTarget::Name("shop".into());
    assert_eq!(names.net.state.label(&target, NOW), Some(Category::Adult));
    let newer = Label { category: Category::General, ..label.clone() };
    names.net.accept(&names.net.sign(&newer, &admin, iat + 4 * MIN)?)?;
    assert_eq!(names.net.state.label(&target, NOW), Some(Category::General));
    let cascade =
        Revoke { target: RevokeTarget::Identity { id: admin.id().clone(), cascade: true }, reason: String::new() };
    names.net.accept(&names.net.sign(&cascade, &names.net.master, iat + 5 * MIN)?)?;
    assert_eq!(names.net.state.label(&target, NOW), None);
    let id: Id = names.app.id().clone();
    assert_eq!(names.net.state.label(&LabelTarget::Id(id), NOW), None);
    assert_eq!(names.net.replayed()?, names.net.state);
    Ok(())
}
