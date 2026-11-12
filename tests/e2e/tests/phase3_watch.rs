//! Watchers (docs/06 §11, ADR 0016), across all compartments: the owner node is sealed with `watch` and the manifest
//! sets short times (`watch`). A member gets level 1 automatically after `member_age_s`; a node started with
//! `--probe web` joins, registers, passes probes and gets level 1 with `web` - and can then host apps; when it goes
//! offline the watcher revokes its seal after `fail_limit` failed probes. Attacks: level-1 seals of non-watchers,
//! level 2 or forbidden services from a watcher, seals for non-members, the daily budget. A restart of the watcher
//! keeps its registrations and probe history. Review 8: a watcher that keeps to public addresses never calls the
//! private addresses members register; a node that stops registering loses its seal.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bridge_core::{Identity, Role, SignedRequest, Statement};
use bridge_net::{Body, JoinMode, NetState, Seal, Service, Services, WatchRules, is_web_host};
use bridge_node::admin::{self, YEAR_MS};
use bridge_node::{NodeConfig, keyfile};
use bridge_sdk::{AppDraft, Client};
use bridge_tests::apps::{app_folder, copy, served};
use bridge_tests::net::{TestNet, TestNode, eventually, membership, test_config, wait_for};
use bridge_tests::now_ms;
use bridge_tests::start_node_on;
use rand_core::OsRng;
use serde_json::{Value, json};
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Short watcher rules for tests: members after 2 s, probes every second, nodes after 3 s of probes, descent after 2
/// failures in a row.
fn fast_rules(seals_per_day: u64, member_age_s: u64) -> WatchRules {
    WatchRules {
        member_age_s,
        probe_interval_s: 1,
        node_observe_s: 3,
        success_pct: 90,
        fail_limit: 2,
        seal_s: 120,
        renew_s: 60,
        seals_per_day,
    }
}

/// A network whose owner node is also watcher and web host (level 3), with `rules` in manifest version 2.
async fn watch_net(rules: WatchRules) -> Result<TestNet, String> {
    let net = TestNet::create(JoinMode::Open).await?;
    let services = admin::parse_services("gateway,log,witness,watch,web")?;
    net.admin.seal(&net.owner.url, &net.owner.id(), 3, services).await?;
    let (_, state) = net.admin.load_state().await?;
    let mut manifest = state.manifest().next_version();
    manifest.watch = Some(rules);
    let statement = net.admin.sign(&manifest, YEAR_MS)?;
    net.admin.submit(&statement).await?;
    wait_for("manifest with watch rules", || net.owner.status().manifest_version == 2).await?;
    wait_for("manifest witnessed", || net.owner.status().witnessed_size == Some(net.owner.status().size)).await?;
    Ok(net)
}

/// The state replayed from the owner's log (what every node computes).
async fn state(net: &TestNet) -> Result<NetState, String> {
    Ok(net.admin.load_state().await?.1)
}

/// A further node that asks the watchers for probes (`--probe web`).
async fn probing_node(net: &TestNet) -> Result<TestNode, String> {
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let mut config: NodeConfig = test_config(dir.path(), Some(net.membership(&[])), &url);
    config.probe = Some(Services::of(&[Service::Web]));
    let node = bridge_node::start(config, listener).await?;
    Ok(TestNode { dir, node, url })
}

/// Submits `statement` at the owner node in a request signed by `signer`; returns (status, error code).
async fn submit_as(net: &TestNet, signer: &Identity, statement: &Statement) -> Result<(u16, String), String> {
    let body = json!({"statement": statement.to_value()});
    let request = SignedRequest::sign(signer, &net.owner.id(), "submit", body, now_ms(), &mut OsRng).map_err(e)?;
    let http = bridge_tests::raw(&net.owner.node)?;
    let answer =
        http.post(&format!("/v4/net/{}/submit", net.net), None, request.to_bytes().map_err(e)?).await.map_err(e)?;
    Ok((answer.status, bridge_tests::code(&answer)))
}

/// A level-1 seal body with the subject's node card.
fn node_seal(subject: &Identity, level: u8, services: &[Service]) -> Result<Seal, String> {
    let card =
        subject.key_card_with(Role::Node, None, &["https://probe.example/n".into()], None, now_ms()).map_err(e)?;
    Ok(Seal { subject: subject.id().clone(), level, services: Services::of(services), card: Some(card) })
}

fn signed(net: &TestNet, seal: &Seal, signer: &Identity) -> Result<Statement, String> {
    let now = now_ms();
    seal.sign(&net.net, now, now + 60_000, signer).map_err(e)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn member_gets_level_one_after_member_age() -> TestResult {
    let net = watch_net(fast_rules(100, 2)).await?;
    let member = Identity::generate(&mut OsRng);
    let id = member.id().clone();
    let _client = Client::join(member, &net.link(None)).await.map_err(e)?;
    let first = state(&net).await?;
    let since = first.member_since(&id).ok_or("no membership")?;
    if first.seal_info(&id, 1).is_none() {
        assert_eq!(first.level(&id, now_ms()), Some(0), "level 0 after joining");
    }
    let sealed = eventually("member level 1", || async {
        let state = state(&net).await?;
        match state.level(&id, now_ms()) {
            Some(1) => state.seal_info(&id, 1).ok_or_else(|| "no seal".to_owned()),
            other => Err(format!("level {other:?}")),
        }
    })
    .await?;
    assert!(sealed.iat >= since + 2_000, "not before the member age (2 s)");
    assert_eq!(sealed.issuers, [net.owner.id()], "signed by the watcher");
    assert!(sealed.by_watcher && sealed.services.is_empty() && sealed.card.is_none());
    assert!(sealed.exp - sealed.iat <= 120_000, "lifetime within seal_s");
    let status = net.owner.node.watch_status().await.ok_or("no watch status")?;
    assert!(status.watcher && status.used_today >= 1);
    assert!(status.seals.iter().any(|(subject, _)| subject == &id));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_passing_probes_gets_web_hosts_apps_and_descends_offline() -> TestResult {
    let net = watch_net(fast_rules(100, 3600)).await?;
    let node = probing_node(&net).await?;
    let node_id = node.id();
    assert!(!is_web_host(&state(&net).await?, &node_id, now_ms()), "no web host before the probes");
    // It joins as a member, registers, passes probes for 3 s, and gets level 1 with web and its card.
    let sealed = eventually("node level 1 with web", || async {
        let state = state(&net).await?;
        if state.level(&node_id, now_ms()) == Some(1) && is_web_host(&state, &node_id, now_ms()) {
            return state.seal_info(&node_id, 1).ok_or_else(|| "no seal".to_owned());
        }
        Err(format!("level {:?}", state.level(&node_id, now_ms())))
    })
    .await?;
    assert_eq!(sealed.issuers, [net.owner.id()]);
    assert!(sealed.card.as_ref().is_some_and(|card| card.urls() == [node.url.clone()]), "its own card");
    let status = net.owner.node.watch_status().await.ok_or("no watch status")?;
    let watched = status.nodes.iter().find(|watched| watched.node == node_id).ok_or("node not registered")?;
    assert!(watched.probes >= 3 && watched.passed == watched.probes && watched.since.is_some(), "{watched:?}");

    // Now it can host apps: the owner publishes at the owner node, listing both; the node fetches the version itself.
    net.synced(&node).await?;
    let owner = Identity::generate(&mut OsRng);
    let client = Client::join(copy(&owner), &net.link(None)).await.map_err(e)?;
    let (folder, _) = app_folder(1000)?;
    let app = Identity::generate(&mut OsRng);
    let draft = AppDraft {
        name: "Wächter-Test".into(),
        description: String::new(),
        entry: "index.html".into(),
        version: 1,
        hosts: vec![net.owner.id(), node_id.clone()],
    };
    client.publish_folder(&app, folder.path(), &draft).await.map_err(e)?;
    served(&format!("{}/app/{}/", node.url, app.id()), b"<!doctype html><h1>Hallo Bridge-App</h1>").await?;

    // The node goes offline: after two failed probes in a row the watcher revokes its seal.
    node.node.shutdown().await;
    eventually("node lost level 1", || async {
        let state = state(&net).await?;
        match state.level(&node_id, now_ms()) {
            Some(0) if !is_web_host(&state, &node_id, now_ms()) => Ok(()),
            other => Err(format!("level {other:?}")),
        }
    })
    .await?;
    assert!(state(&net).await?.is_revoked(&sealed.hash), "revoked, not just expired");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watcher_limits_are_enforced_by_the_log_operator() -> TestResult {
    // No automatic member seals (one hour), a budget of two seals a day.
    let net = watch_net(fast_rules(2, 3600)).await?;
    let watcher = keyfile::load_or_create(net.owner.dir.path())?;
    assert_eq!(watcher.id(), &net.owner.id());
    // A gateway without `watch` is no watcher.
    let gateway = net.add_node(&[]).await?;
    net.seal_gateway(&gateway).await?;
    let gateway_key = keyfile::load_or_create(gateway.dir.path())?;
    // Three members (their node cards are self-signed, so the seals can carry them).
    let members: Vec<Identity> = (0..3).map(|_| Identity::generate(&mut OsRng)).collect();
    for member in &members {
        joined_as(&net, member).await?;
    }

    let refused = |(status, code): (u16, String), want: (u16, &str)| -> TestResult {
        if (status, code.as_str()) == want { Ok(()) } else { Err(format!("got {status} {code}, want {want:?}")) }
    };
    // A non-watcher's level-1 seal is refused.
    let seal = node_seal(&members[0], 1, &[Service::Web])?;
    refused(submit_as(&net, &gateway_key, &signed(&net, &seal, &gateway_key)?).await?, (403, "FORBIDDEN"))?;
    // The watcher can not go above level 1, nor give infrastructure or services without probes.
    let level2 = node_seal(&members[0], 2, &[Service::Web])?;
    refused(submit_as(&net, &watcher, &signed(&net, &level2, &watcher)?).await?, (403, "FORBIDDEN"))?;
    for service in [Service::Gateway, Service::Watch, Service::Names] {
        let seal = node_seal(&members[0], 1, &[Service::Web, service])?;
        refused(submit_as(&net, &watcher, &signed(&net, &seal, &watcher)?).await?, (403, "FORBIDDEN"))?;
    }
    // Not for strangers, not for members younger than member_age (member seal), not longer than seal_s.
    let stranger = Identity::generate(&mut OsRng);
    let seal = node_seal(&stranger, 1, &[Service::Web])?;
    refused(submit_as(&net, &watcher, &signed(&net, &seal, &watcher)?).await?, (403, "NOT_MEMBER"))?;
    let young = Seal { subject: members[0].id().clone(), level: 1, services: Services::NONE, card: None };
    refused(submit_as(&net, &watcher, &signed(&net, &young, &watcher)?).await?, (403, "FORBIDDEN"))?;
    let long = node_seal(&members[0], 1, &[Service::Web])?
        .sign(&net.net, now_ms(), now_ms() + 121_000, &watcher)
        .map_err(e)?;
    refused(submit_as(&net, &watcher, &long).await?, (403, "FORBIDDEN"))?;
    // Budget: two seals today, the third is refused.
    for member in &members[..2] {
        let seal = node_seal(member, 1, &[Service::Web])?;
        refused(submit_as(&net, &watcher, &signed(&net, &seal, &watcher)?).await?, (200, ""))?;
    }
    let seal = node_seal(&members[2], 1, &[Service::Web])?;
    refused(submit_as(&net, &watcher, &signed(&net, &seal, &watcher)?).await?, (429, "QUOTA_EXCEEDED"))?;
    let state = state(&net).await?;
    assert_eq!(state.watch_used(watcher.id(), now_ms()), 2);
    assert_eq!(state.level(members[0].id(), now_ms()), Some(1));
    assert_eq!(state.level(members[2].id(), now_ms()), Some(0));
    // Registration only for members, and only at watchers.
    let registered = register_raw(&net, &gateway, &gateway_key).await?;
    refused(registered, (403, "NOT_MEMBER"))?;
    let at_gateway = register_at(&gateway, &members[0]).await?;
    refused(at_gateway, (403, "FORBIDDEN"))?;
    Ok(())
}

/// Joins `member` at the owner node (its membership is in the log afterwards).
async fn joined_as(net: &TestNet, member: &Identity) -> TestResult {
    Client::join(copy(member), &net.link(None)).await.map_err(e)?;
    let id = member.id().clone();
    eventually("member", || async {
        if state(net).await?.is_member(&id, now_ms()) { Ok(()) } else { Err("not yet".into()) }
    })
    .await
}

/// `POST /v4/node/watch` at the owner node for `node` (signed by its key); returns (status, code).
async fn register_raw(net: &TestNet, node: &TestNode, key: &Identity) -> Result<(u16, String), String> {
    let card = node.node.card().to_value();
    let body = json!({"card": card, "services": ["web"]});
    let request = SignedRequest::sign(key, &net.owner.id(), "watch", body, now_ms(), &mut OsRng).map_err(e)?;
    let answer = bridge_tests::raw(&net.owner.node)?
        .post("/v4/node/watch", None, request.to_bytes().map_err(e)?)
        .await
        .map_err(e)?;
    Ok((answer.status, bridge_tests::code(&answer)))
}

/// `POST /v4/node/watch` at a node that is no watcher, for `member` with a fresh node card.
async fn register_at(at: &TestNode, member: &Identity) -> Result<(u16, String), String> {
    let card = member.key_card_with(Role::Node, None, &["https://m.example".into()], None, now_ms()).map_err(e)?;
    let body = json!({"card": card.to_value(), "services": ["web"]});
    let request = SignedRequest::sign(member, &at.id(), "watch", body, now_ms(), &mut OsRng).map_err(e)?;
    let answer =
        bridge_tests::raw(&at.node)?.post("/v4/node/watch", None, request.to_bytes().map_err(e)?).await.map_err(e)?;
    Ok((answer.status, bridge_tests::code(&answer)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_attacks() -> TestResult {
    let net = watch_net(fast_rules(100, 3600)).await?;
    let member = Identity::generate(&mut OsRng);
    joined_as(&net, &member).await?;
    let post = |body: Vec<u8>| {
        let owner = &net.owner;
        async move {
            let answer = bridge_tests::raw(&owner.node)?.post("/v4/node/watch", None, body).await.map_err(e)?;
            Ok::<_, String>((answer.status, bridge_tests::code(&answer)))
        }
    };
    let card = |identity: &Identity, role: Role, urls: &[String]| {
        identity.key_card_with(role, None, urls, None, now_ms()).map_err(e)
    };
    let url = vec!["https://m.example".to_owned()];
    let request = |signer: &Identity, body: Value| -> Result<Vec<u8>, String> {
        SignedRequest::sign(signer, &net.owner.id(), "watch", body, now_ms(), &mut OsRng)
            .map_err(e)?
            .to_bytes()
            .map_err(e)
    };
    // Garbage, wrong op, extra fields, a client card, no addresses, someone else's card, forbidden services.
    assert_eq!(post(b"{".to_vec()).await?.0, 400);
    let good = json!({"card": card(&member, Role::Node, &url)?.to_value(), "services": ["web"]});
    let wrong_op =
        SignedRequest::sign(&member, &net.owner.id(), "join", good.clone(), now_ms(), &mut OsRng).map_err(e)?;
    assert_eq!(post(wrong_op.to_bytes().map_err(e)?).await?, (400, "BAD_FORMAT".into()));
    let mut extra = good.clone();
    extra["x"] = json!(1);
    assert_eq!(post(request(&member, extra)?).await?, (400, "BAD_FORMAT".into()));
    let client = json!({"card": card(&member, Role::Client, &[])?.to_value(), "services": ["web"]});
    assert_eq!(post(request(&member, client)?).await?, (403, "FORBIDDEN".into()));
    let other = Identity::generate(&mut OsRng);
    let foreign = json!({"card": card(&other, Role::Node, &url)?.to_value(), "services": ["web"]});
    assert_eq!(post(request(&member, foreign)?).await?, (401, "BAD_SIGNATURE".into()));
    for services in [json!(["gateway"]), json!(["web", "web"]), json!(["names"]), json!("web"), json!([1])] {
        let body = json!({"card": card(&member, Role::Node, &url)?.to_value(), "services": services});
        assert_eq!(post(request(&member, body)?).await?.0, if services.is_array() { 403 } else { 400 }, "{services}");
    }
    // A valid registration works once; the same request again is a replay.
    let valid = request(&member, good)?;
    assert_eq!(post(valid.clone()).await?, (200, String::new()));
    assert_eq!(post(valid).await?, (409, "REPLAY".into()));
    // Non-members can not register (the registration table can not be filled by strangers).
    let stranger = Identity::generate(&mut OsRng);
    let body = json!({"card": card(&stranger, Role::Node, &url)?.to_value(), "services": []});
    assert_eq!(post(request(&stranger, body)?).await?, (403, "NOT_MEMBER".into()));
    let status = net.owner.node.watch_status().await.ok_or("no status")?;
    assert_eq!(status.nodes.len(), 1, "only the member");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_keeps_registrations_and_probe_history() -> TestResult {
    // A window of 30 s: no probe drops out of it while the test runs.
    let net = watch_net(WatchRules { node_observe_s: 30, ..fast_rules(100, 3600) }).await?;
    let node = probing_node(&net).await?;
    let node_id = node.id();
    let before = eventually("probes recorded", || async {
        let status = net.owner.node.watch_status().await.ok_or("no status")?;
        let watched = status.nodes.into_iter().find(|watched| watched.node == node_id).ok_or("not registered")?;
        if watched.probes >= 2 && watched.since.is_some() { Ok(watched) } else { Err(format!("{watched:?}")) }
    })
    .await?;
    // The CLI view reads the same from the data folder while the node runs.
    let cli = admin::watch_status(net.owner.dir.path(), now_ms())?;
    assert!(cli.watcher && cli.nodes.iter().any(|watched| watched.node == node_id));

    let TestNet { net: net_id, owner, admin, master } = net;
    let owner = owner.restart(Some(membership(&net_id, &[]))).await?;
    let after = owner.node.watch_status().await.ok_or("no status after restart")?;
    let watched = after.nodes.iter().find(|watched| watched.node == node_id).ok_or("registration lost")?;
    assert_eq!(watched.since, before.since, "observation goes on");
    assert!(watched.probes >= before.probes, "probe history kept ({} < {})", watched.probes, before.probes);
    // And it goes on probing.
    eventually("probes go on after the restart", || async {
        let status = owner.node.watch_status().await.ok_or("no status")?;
        let watched = status.nodes.into_iter().find(|watched| watched.node == node_id).ok_or("not registered")?;
        if watched.probes > before.probes && watched.fails == 0 { Ok(()) } else { Err(format!("{watched:?}")) }
    })
    .await?;
    let _ = (admin, master, node);
    Ok(())
}

/// Review 8, finding 2: a watcher with the default address rule (public only) probes the addresses members register
/// only after checking where they point - its own machine (by IP, as `localhost`, IPv6 loopback) and link-local
/// metadata addresses are never contacted; the probes just fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watcher_never_calls_private_addresses_members_register() -> TestResult {
    let TestNet { net: net_id, owner, admin, master } = watch_net(fast_rules(100, 3600)).await?;
    let addr = owner.node.local_addr();
    owner.node.shutdown().await;
    let mut config = test_config(owner.dir.path(), Some(membership(&net_id, &[])), &owner.url);
    config.peer_addresses = bridge_node::PeerAddresses::Public;
    let node = start_node_on(config, addr).await?;
    let net = TestNet { net: net_id, owner: TestNode { dir: owner.dir, node, url: owner.url }, admin, master };
    // A trap on this machine that must never see a connection.
    let trap = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let port = trap.local_addr().map_err(e)?.port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let accepting = tokio::spawn(async move {
        while trap.accept().await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let targets = [
        format!("http://127.0.0.1:{port}/admin"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
        "http://169.254.169.254/latest/meta-data".to_owned(),
    ];
    let mut registered = Vec::new();
    for url in &targets {
        let member = Identity::generate(&mut OsRng);
        joined_as(&net, &member).await?;
        let card = member.key_card_with(Role::Node, None, std::slice::from_ref(url), None, now_ms()).map_err(e)?;
        let body = json!({"card": card.to_value(), "services": ["web"]});
        let request = SignedRequest::sign(&member, &net.owner.id(), "watch", body, now_ms(), &mut OsRng).map_err(e)?;
        let answer = bridge_tests::raw(&net.owner.node)?
            .post("/v4/node/watch", None, request.to_bytes().map_err(e)?)
            .await
            .map_err(e)?;
        assert_eq!(answer.status, 200, "{url}: registered");
        registered.push(member.id().clone());
    }
    eventually("every registered address probed (and failed) twice", || async {
        let status = net.owner.node.watch_status().await.ok_or("no status")?;
        let done = registered.iter().all(|id| {
            status.nodes.iter().any(|watched| &watched.node == id && watched.probes >= 2 && watched.passed == 0)
        });
        if done { Ok(()) } else { Err(format!("{:?}", status.nodes)) }
    })
    .await?;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the watcher called its own machine");
    accepting.abort();
    Ok(())
}

/// Review 8, finding 5: a node sealed by the watcher that stays online but stops registering (no more probes) does
/// not keep its seal until it expires - the watcher revokes it once the registration lapsed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lapsed_registration_revokes_the_node_seal() -> TestResult {
    let net = watch_net(fast_rules(100, 3600)).await?;
    let node = probing_node(&net).await?;
    let node_id = node.id();
    let sealed = eventually("node level 1 with web", || async {
        let state = state(&net).await?;
        match state.seal_info(&node_id, 1) {
            Some(info) if info.active(now_ms()) && info.card.is_some() => Ok(info),
            other => Err(format!("{other:?}")),
        }
    })
    .await?;
    // Started again without --probe: online, a member, but no more registrations (24 rounds of 500 ms later the
    // registration has lapsed).
    let node = node.restart(Some(net.membership(&[]))).await?;
    eventually("the seal revoked after the registration lapsed", || async {
        let state = state(&net).await?;
        if state.is_revoked(&sealed.hash) {
            Ok(())
        } else {
            Err(format!("level {:?}", state.level(&node_id, now_ms())))
        }
    })
    .await?;
    assert_eq!(state(&net).await?.level(&node_id, now_ms()), Some(0));
    assert!(node.node.net_status().is_some(), "the node itself is still running");
    Ok(())
}
