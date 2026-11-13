//! Apps in a network (docs/07 §3): the `app` statement is checked against the network state - owner member, not
//! banned, at least `apps.min_level`, app ID not banned; hosts count only with a `web` seal (level ≥ 1). App
//! statements never go into the log.

mod common;

use bridge_core::{AppFile, AppManifest, FileType, HashList, Identity, Role, Statement};
use bridge_net::{
    AppRules, Ban, Body, JoinMode, Kind, Member, NetError, NetResult, Seal, Service, Services, check_app, is_web_host,
};
use common::{DAY, MIN, Net, T0, identity, node_card};

struct Apps {
    net: Net,
    app: Identity,
    owner: Identity,
    web: Identity,
    plain: Identity,
}

/// A network with a member (owner), a web host (level 1, `web`) and a gateway without `web`.
fn setup(min_level: Option<u8>) -> NetResult<Apps> {
    let mut net = Net::with(JoinMode::Open, |manifest| {
        manifest.apps = min_level.map(|min_level| AppRules { min_level });
    })?;
    net.seal_owner(T0 + MIN)?;
    let owner = identity(40);
    let member = Member { member: owner.id().clone(), invite: None };
    let statement = net.sign(&member, &net.owner, T0 + 2 * MIN)?;
    net.accept(&statement)?;
    let web = identity(41);
    let seal = Seal {
        subject: web.id().clone(),
        level: 1,
        services: Services::of(&[Service::Web]),
        card: Some(node_card(&web, "https://web.example")?),
    };
    let statement = net.sign(&seal, &net.master, T0 + 3 * MIN)?;
    net.accept(&statement)?;
    let plain = identity(42);
    let statement = net.sign(&Net::gateway_seal(&plain, 2)?, &net.master, T0 + 4 * MIN)?;
    net.accept(&statement)?;
    Ok(Apps { net, app: identity(43), owner, web, plain })
}

fn manifest(apps: &Apps, hosts: Vec<bridge_core::Id>) -> NetResult<AppManifest> {
    let blob = HashList::of(b"<p>hi</p>")?.id();
    Ok(AppManifest {
        app: apps.app.id().clone(),
        owner: apps.owner.id().clone(),
        name: "Spiel".into(),
        description: String::new(),
        version: 1,
        entry: "index.html".into(),
        files: vec![AppFile { path: "index.html".into(), blob, size: 9, kind: FileType::Html }],
        hosts,
        card: apps.app.key_card(Role::App, None, T0)?,
        owner_card: apps.owner.key_card(Role::Client, None, T0)?,
        server: None,
    })
}

fn signed(apps: &Apps, manifest: &AppManifest) -> NetResult<Statement> {
    Ok(manifest.sign(&apps.net.net, T0 + 10 * MIN, T0 + 30 * DAY, &apps.app, &apps.owner)?)
}

const NOW: i64 = T0 + 20 * MIN;

#[test]
fn valid_app_and_hosts_that_count() -> NetResult<()> {
    let apps = setup(None)?;
    let stranger = identity(44);
    let hosts = vec![apps.web.id().clone(), apps.plain.id().clone(), stranger.id().clone()];
    let statement = signed(&apps, &manifest(&apps, hosts)?)?;
    let checked = check_app(&apps.net.state, &statement, NOW)?;
    // Only the web host counts: the gateway without `web` and the stranger do not.
    assert_eq!(checked.hosts.len(), 1);
    assert!(checked.is_host(apps.web.id()) && !checked.is_host(apps.plain.id()));
    assert!(checked.hosts[0].1.as_ref().is_some_and(|card| card.urls() == ["https://web.example"]));
    assert!(is_web_host(&apps.net.state, apps.web.id(), NOW));
    // The typed body works like every other body; the kind is no log kind.
    assert_eq!(<AppManifest as Body>::from_statement(&statement)?, checked.manifest);
    assert!(!Kind::App.is_log_kind());
    Ok(())
}

#[test]
fn owner_standing_bans_and_min_level() -> NetResult<()> {
    let mut apps = setup(None)?;
    let statement = signed(&apps, &manifest(&apps, vec![apps.web.id().clone()])?)?;
    // A non-member owner.
    let outsider = Apps { owner: identity(45), ..setup(None)? };
    let foreign = signed(&outsider, &manifest(&outsider, vec![outsider.web.id().clone()])?)?;
    assert_eq!(check_app(&outsider.net.state, &foreign, NOW), Err(NetError::NotMember));
    // A banned app ID, then a banned owner.
    let ban = Ban { subject: apps.app.id().clone(), reason: "Phishing".into() };
    let ban = apps.net.sign(&ban, &apps.net.master, T0 + 5 * MIN)?;
    apps.net.accept(&ban)?;
    assert_eq!(check_app(&apps.net.state, &statement, NOW), Err(NetError::Banned));
    let mut apps = setup(None)?;
    let ban = Ban { subject: apps.owner.id().clone(), reason: String::new() };
    let ban = apps.net.sign(&ban, &apps.net.master, T0 + 5 * MIN)?;
    apps.net.accept(&ban)?;
    assert_eq!(check_app(&apps.net.state, &statement, NOW), Err(NetError::Banned));
    // `apps.min_level` 1: a level-0 member may not publish, a sealed one may.
    let mut apps = setup(Some(1))?;
    let statement = signed(&apps, &manifest(&apps, vec![apps.web.id().clone()])?)?;
    assert!(matches!(check_app(&apps.net.state, &statement, NOW), Err(NetError::Forbidden(_))));
    let seal = Seal { subject: apps.owner.id().clone(), level: 1, services: Services::NONE, card: None };
    let seal = apps.net.sign(&seal, &apps.net.master, T0 + 5 * MIN)?;
    apps.net.accept(&seal)?;
    assert!(check_app(&apps.net.state, &statement, NOW).is_ok());
    Ok(())
}

#[test]
fn signatures_time_and_log() -> NetResult<()> {
    let mut apps = setup(None)?;
    let manifest = manifest(&apps, vec![apps.web.id().clone()])?;
    // Only one signature (the owner's): refused.
    let body = AppManifest::to_body(&manifest)?;
    let draft = bridge_core::Draft { kind: "app", net: &apps.net.net, iat: T0, exp: T0 + DAY, body };
    let one = Statement::sign(&draft, &apps.owner)?;
    assert!(check_app(&apps.net.state, &one, NOW).is_err());
    // Another network, expired.
    let statement = signed(&apps, &manifest)?;
    assert!(check_app(&apps.net.state, &statement, T0 + 31 * DAY).is_err());
    let other = manifest.sign(apps.owner.id(), T0, T0 + DAY, &apps.app, &apps.owner)?;
    assert!(check_app(&apps.net.state, &other, NOW).is_err());
    // An app statement is never a log entry (even a small one).
    assert!(apps.net.state.validate_candidate(&statement, NOW).is_err());
    assert!(apps.net.skip(&statement).is_ok());
    Ok(())
}

/// An app name of the owner for `apps.app`.
fn app_name(apps: &Apps, name: &str) -> NetResult<bridge_net::Name> {
    Ok(bridge_net::Name {
        name: name.into(),
        kind: bridge_net::NameKind::App,
        target: apps.app.id().clone(),
        owner: apps.owner.id().clone(),
        owner_card: apps.owner.key_card(Role::Client, None, T0)?,
        card: Some(apps.app.key_card(Role::App, None, T0)?),
        description: String::new(),
        tags: Vec::new(),
        category: bridge_net::Category::General,
        hosts: Vec::new(),
    })
}

#[test]
fn a_deleted_app_is_gone_with_its_names() -> NetResult<()> {
    use bridge_net::{Retire, Revoke, RevokeTarget};
    let mut apps = setup(None)?;
    let net = apps.net.net.clone();
    // Names need level 1.
    let seal = Seal { subject: apps.owner.id().clone(), level: 1, services: Services::NONE, card: None };
    let sealed = apps.net.sign(&seal, &apps.net.master, T0 + 4 * MIN)?;
    apps.net.accept(&sealed)?;
    let name = app_name(&apps, "laden")?;
    let named = name.sign_name(&net, T0 + 5 * MIN, T0 + 30 * DAY, &apps.owner, Some(&apps.app))?;
    apps.net.accept(&named)?;
    let version = signed(&apps, &manifest(&apps, vec![apps.web.id().clone()])?)?;
    assert!(check_app(&apps.net.state, &version, NOW).is_ok());
    assert!(apps.net.state.resolve_name("laden", NOW).is_ok());

    let body = Retire::new(&apps.app, &apps.owner, T0)?;
    // Attacks first: a stranger's key as owner, only one signer, too short a lifetime, a non-member owner.
    let stranger = identity(50);
    let foreign = Retire::new(&apps.app, &stranger, T0)?.sign_retire(&net, T0 + 15 * MIN, &apps.app, &stranger)?;
    assert_eq!(apps.net.skip(&foreign)?, NetError::NotMember);
    let alone = body.sign(&net, T0 + 15 * MIN, T0 + 15 * MIN + 366 * DAY, &apps.owner)?;
    assert!(matches!(apps.net.skip(&alone)?, NetError::Forbidden(_)), "the app key must sign too");
    let short = body.sign_multi(&net, T0 + 15 * MIN, T0 + 30 * DAY, &[&apps.app, &apps.owner])?;
    assert!(matches!(apps.net.skip(&short)?, NetError::Forbidden(_)), "a year at least");
    let long = body.sign_multi(&net, T0 + 15 * MIN, T0 + 15 * MIN + 400 * DAY, &[&apps.app, &apps.owner])?;
    assert!(matches!(apps.net.skip(&long)?, NetError::Forbidden(_)), "at most a year and a day");

    let retire = body.sign_retire(&net, T0 + 15 * MIN, &apps.app, &apps.owner)?;
    apps.net.accept(&retire)?;
    assert!(apps.net.state.is_retired(apps.app.id(), NOW));
    assert!(matches!(check_app(&apps.net.state, &version, NOW), Err(NetError::Forbidden(_))), "every version");
    assert!(apps.net.state.resolve_name("laden", NOW).is_err(), "its name ended");
    assert!(apps.net.state.names_for(apps.app.id(), NOW).is_empty());
    // Once only, never undone (only the net key could), no new names for it.
    let again = body.sign_retire(&net, T0 + 16 * MIN, &apps.app, &apps.owner)?;
    assert!(matches!(apps.net.skip(&again)?, NetError::Forbidden(_)));
    let undo = Revoke { target: RevokeTarget::Statement(retire.hash_bytes()), reason: String::new() };
    let undo = apps.net.sign(&undo, &apps.owner, T0 + 17 * MIN)?;
    assert!(matches!(apps.net.skip(&undo)?, NetError::Forbidden(_)), "the owner can not undo it");
    let renamed = name.sign_name(&net, T0 + 18 * MIN, T0 + 30 * DAY, &apps.owner, Some(&apps.app))?;
    assert!(matches!(apps.net.skip(&renamed)?, NetError::Forbidden(_)), "no new name for a deleted app");
    // The name is free for another app.
    let other = identity(51);
    let mut free = app_name(&apps, "laden")?;
    free.target = other.id().clone();
    free.card = Some(other.key_card(Role::App, None, T0)?);
    let free = free.sign_name(&net, T0 + 19 * MIN, T0 + 30 * DAY, &apps.owner, Some(&other))?;
    apps.net.accept(&free)?;
    // Replay from scratch gives the same.
    let replayed = apps.net.replayed()?;
    assert!(replayed.is_retired(apps.app.id(), NOW) && replayed.resolve_name("laden", NOW).is_ok());
    // A year later the deletion ends - every version from before has expired by then.
    assert!(!apps.net.state.is_retired(apps.app.id(), T0 + 15 * MIN + 367 * DAY));
    let _ = Kind::Retire;
    Ok(())
}
