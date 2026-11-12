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
