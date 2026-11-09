//! Phase 3 acceptance, LAN (docs/05: "zwei PCs im selben WLAN reden ohne Internet"; docs/06 §2, §7): clients talk
//! through a node using only its TLS LAN listener; a wrong fingerprint is refused before anything reaches the node;
//! a join link with `node` and `tls` works over the LAN alone; the fingerprint survives restarts; a damaged
//! `node-tls.pem` stops the node; two gateways relay, exchange homes and follow the log when their public
//! addresses lead nowhere (only the pinned LAN path works). The mDNS test needs multicast and runs with
//! `cargo test -- --ignored` (CI: Ubuntu).
//!
//! Without multicast the nodes and clients find each other through [`LanHints`] - the same discovery switch the
//! mDNS path uses, with the addresses given by the test.

use std::time::{Duration, Instant};

use bridge_core::encoding::b64;
use bridge_core::{Content, ContentType, Identity, JoinLink, Payload};
use bridge_guard::Rate;
use bridge_net::JoinMode;
use bridge_node::keyfile::TLS_FILE;
use bridge_node::{Discovery, LanConfig, LanHints, LanPeer, LanPin, NetConfig, NodeConfig, RunningNode};
use bridge_sdk::{Client, ConnectOptions, NodeAddress, SdkError};
use bridge_tests::net::{
    PATIENCE, TestNet, TestNode, dead_url, eventually, lan_config, lan_options, lan_peer, membership, test_config,
    wait_for,
};
use bridge_transport::{HttpClient, TlsIdentity, TransportError};
use rand_core::{OsRng, RngCore};
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn text(content: &Content) -> String {
    match &content.payload {
        Payload::Text(text) => text.clone(),
        other => format!("{other:?}"),
    }
}

fn marker() -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    format!("lan-geheim-{}", b64(&bytes))
}

fn files_contain(dir: &std::path::Path, needle: &[u8]) -> Result<bool, String> {
    for entry in std::fs::read_dir(dir).map_err(e)? {
        let path = entry.map_err(e)?.path();
        if path.is_file() {
            let bytes = std::fs::read(&path).map_err(e)?;
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// A single node (no network) with LAN on, in `dir`.
fn lan_node_config(dir: &std::path::Path, hints: &LanHints) -> NodeConfig {
    let mut config = test_config(dir, None, "http://127.0.0.1:9/unused");
    config.urls = Vec::new();
    config.lan = Some(lan_config(hints));
    config
}

async fn start(config: NodeConfig) -> Result<RunningNode, String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    bridge_node::start(config, listener).await
}

/// The LAN-only address of a node: its ID and TLS pin, no Internet address.
fn lan_only(node: &RunningNode) -> NodeAddress {
    NodeAddress { url: None, ..NodeAddress::from_card(node.card()) }
}

/// Sends once the network knows where `to` lives.
async fn send_when_routed(from: &Client, to: &Client, content: &Content) -> TestResult {
    let id = to.identity().id().clone();
    let card = eventually("card of the recipient", || async { from.card_of(&id).await.map_err(e) }).await?;
    eventually("envelope accepted", || async { from.send(&card, content).await.map(|_| ()).map_err(e) }).await
}

async fn receive_one(client: &mut Client) -> Result<bridge_sdk::Received, String> {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let inbox = client.receive(1).await.map_err(e)?;
        if let Some(message) = inbox.messages.into_iter().next() {
            return Ok(message);
        }
        if Instant::now() >= deadline {
            return Err("no message arrived".into());
        }
    }
}

/// The same identity again (a program that restarts with its stored key).
fn same(identity: &Identity) -> Identity {
    let (sign, receive) = identity.secret_bytes();
    Identity::from_secret_bytes(&sign, &receive)
}

fn refused<T: std::fmt::Debug>(result: Result<T, TransportError>) -> bool {
    matches!(&result, Err(TransportError::Connection(text)) if text.contains("invalid peer certificate"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_clients_talk_through_the_tls_listener_only() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let hints = LanHints::default();
    let node = start(lan_node_config(dir.path(), &hints)).await?;
    let pin = node.card().tls().copied().ok_or("the card of a LAN node pins its certificate")?;
    let lan = node.lan_addr().ok_or("no LAN listener")?;
    assert_ne!(lan, node.local_addr());
    hints.push(lan_peer(&node)?);

    // No Internet address at all: the clients can only use the pinned LAN connection.
    let options = lan_options(&hints);
    let mut alice =
        Client::connect_auto(Identity::generate(&mut OsRng), &lan_only(&node), &options).await.map_err(e)?;
    let mut bob = Client::connect_auto(Identity::generate(&mut OsRng), &lan_only(&node), &options).await.map_err(e)?;
    assert!(alice.via_lan() && bob.via_lan());
    assert_eq!(alice.node_card().and_then(|card| card.tls()), Some(&pin));

    let secret = marker();
    let to_bob = alice.card_of(bob.identity().id()).await.map_err(e)?;
    alice.send(&to_bob, &Content::text(ContentType::Direct, secret.clone())).await.map_err(e)?;
    let message = receive_one(&mut bob).await?;
    assert_eq!((text(&message.content), &message.from), (secret.clone(), alice.identity().id()));
    let to_alice = bob.card_of(alice.identity().id()).await.map_err(e)?;
    bob.send(&to_alice, &Content::text(ContentType::Response, "über das LAN")).await.map_err(e)?;
    assert_eq!(text(&receive_one(&mut alice).await?.content), "über das LAN");
    assert!(!files_contain(dir.path(), secret.as_bytes())?, "the node cannot read it");

    // The LAN port speaks TLS only: plain HTTP and ordinary (certificate authority) HTTPS get nothing.
    let plain = HttpClient::new(&format!("http://{lan}"), Duration::from_secs(5)).map_err(e)?;
    assert!(plain.get("/v4/info").await.is_err());
    let ca = HttpClient::new(&format!("https://{lan}"), Duration::from_secs(5)).map_err(e)?;
    assert!(ca.get("/v4/info").await.is_err());
    node.shutdown().await;
    // The same limits as the main listener (body size; small, so the whole request is read before the answer).
    let small_dir = tempfile::tempdir().map_err(e)?;
    let mut small = lan_node_config(small_dir.path(), &hints);
    small.server.max_body_bytes = 1000;
    let small = start(small).await?;
    let small_pin = small.card().tls().copied().ok_or("no pin")?;
    let lan = small.lan_addr().ok_or("no LAN listener")?;
    let pinned = HttpClient::new_pinned(&format!("https://{lan}"), small_pin, Duration::from_secs(5)).map_err(e)?;
    let plain = HttpClient::new(&format!("http://{}", small.local_addr()), Duration::from_secs(5)).map_err(e)?;
    for client in [&pinned, &plain] {
        assert_eq!(client.post("/v4/send", None, vec![b'x'; 1001]).await.map_err(e)?.status, 413);
    }
    small.shutdown().await;
    Ok(())
}

/// Answers `/v4/info` with fixed bytes (a copy of another node's genuine info) over its own TLS certificate.
struct Replay(Vec<u8>);

impl bridge_transport::Handler for Replay {
    async fn handle(&self, _request: bridge_transport::Request) -> bridge_transport::Response {
        bridge_transport::Response::ok(self.0.clone())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_fingerprint_is_refused_before_anything_reaches_the_node() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let hints = LanHints::default();
    let mut config = lan_node_config(dir.path(), &hints);
    // One request per address and second: any request that reached the node would use it up.
    config.limits.per_address = Rate { per_second: 1, burst: 1 };
    let node = start(config).await?;
    let lan_url = format!("https://{}", node.lan_addr().ok_or("no LAN listener")?);
    let pin = node.card().tls().copied().ok_or("no pin")?;

    let foreign = TlsIdentity::generate().map_err(e)?.fingerprint();
    for wrong in [[0u8; 32], [7u8; 32], foreign] {
        for _ in 0..5 {
            let client = HttpClient::new_pinned(&lan_url, wrong, Duration::from_secs(5)).map_err(e)?;
            assert!(refused(client.get("/v4/info").await), "a wrong pin must fail in the TLS handshake");
        }
    }
    hints.push(lan_peer(&node)?);
    let options = lan_options(&hints);
    let address = NodeAddress { tls: Some(foreign), ..lan_only(&node) };
    let sdk = Client::connect_auto(Identity::generate(&mut OsRng), &address, &options).await.map(|_| ());
    assert!(sdk.is_err(), "the SDK does not connect with a wrong pin: {sdk:?}");
    // None of that reached the node: its per-address bucket is still full ...
    let right = HttpClient::new_pinned(&lan_url, pin, Duration::from_secs(5)).map_err(e)?;
    assert_eq!(right.get("/v4/info").await.map_err(e)?.status, 200);
    // ... and it does count requests that get through.
    assert_eq!(right.get("/v4/info").await.map_err(e)?.status, 429);

    node.shutdown().await;

    // A lying announcement: another node's LAN port under the target's ID. With the right pin the client refuses
    // it and takes the Internet address instead.
    let (target_dir, other_dir) = (tempfile::tempdir().map_err(e)?, tempfile::tempdir().map_err(e)?);
    let target = start(lan_node_config(target_dir.path(), &LanHints::default())).await?;
    let other = start(lan_node_config(other_dir.path(), &LanHints::default())).await?;
    let lying = LanHints::new(vec![LanPeer { id: target.card().id().to_string(), ..lan_peer(&other)? }]);
    let address = NodeAddress { url: Some(format!("http://{}", target.local_addr())), ..lan_only(&target) };
    let client =
        Client::connect_auto(Identity::generate(&mut OsRng), &address, &lan_options(&lying)).await.map_err(e)?;
    assert!(!client.via_lan(), "fell back to the Internet address");
    assert_eq!(client.node_card().map(|card| card.id()), Some(target.card().id()));
    let lan_only_lie =
        Client::connect_auto(Identity::generate(&mut OsRng), &lan_only(&target), &lan_options(&lying)).await;
    assert!(lan_only_lie.is_err(), "without an Internet address there is nothing to fall back to");

    // A manipulated link: the attacker's own certificate as `tls`, the target's ID as `node`, and a copy of the
    // target's genuine info behind it. The TLS handshake matches - but the target's signed card does not pin that
    // certificate, so the client refuses.
    let genuine = HttpClient::new(&format!("http://{}", target.local_addr()), Duration::from_secs(5)).map_err(e)?;
    let info = genuine.get("/v4/info").await.map_err(e)?;
    assert_eq!(info.status, 200);
    let attacker = TlsIdentity::generate().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let fake = bridge_transport::serve_tls(
        listener,
        bridge_transport::ServerConfig::default(),
        std::sync::Arc::new(Replay(info.body)),
        &attacker,
    )
    .map_err(e)?;
    let fake_peer = LanPeer {
        id: target.card().id().to_string(),
        addrs: vec![fake.local_addr().ip()],
        port: fake.local_addr().port(),
    };
    let address = NodeAddress { tls: Some(attacker.fingerprint()), ..lan_only(&target) };
    let hints = LanHints::new(vec![fake_peer]);
    let fooled = Client::connect_auto(Identity::generate(&mut OsRng), &address, &lan_options(&hints)).await.map(|_| ());
    assert!(matches!(&fooled, Err(SdkError::Untrusted(text)) if text.contains("pin")), "{fooled:?}");
    fake.shutdown().await;
    other.shutdown().await;
    target.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_over_the_lan_with_node_and_tls_in_the_link() -> TestResult {
    let hints = LanHints::default();
    let net = TestNet::create_with(JoinMode::Invite, None, Some(lan_config(&hints))).await?;
    hints.push(lan_peer(&net.owner.node)?);
    let owner_pin = net.owner.node.card().tls().copied().ok_or("no pin")?;

    // `net invite` puts the owner's ID and TLS pin into the link (from its verified card).
    let (_, link) = net.admin.invite(5, 1).await?;
    let parsed = JoinLink::parse(&link).map_err(e)?;
    assert_eq!(parsed.node.as_ref(), Some(net.owner.node.card().id()));
    assert_eq!(parsed.tls, Some(owner_pin));
    // No Internet: the link's address leads nowhere. The LAN is enough.
    let offline = JoinLink { gateway: dead_url("owner"), ..parsed.clone() }.to_link();
    let options = lan_options(&hints);
    let alice = Client::join_with(Identity::generate(&mut OsRng), &offline, &options).await.map_err(e)?;
    let mut bob = Client::join_with(Identity::generate(&mut OsRng), &offline, &options).await.map_err(e)?;
    assert!(alice.via_lan() && bob.via_lan());
    assert_eq!(alice.net(), Some(&net.net));
    send_when_routed(&alice, &bob, &Content::text(ContentType::Direct, "ohne Internet")).await?;
    assert_eq!(text(&receive_one(&mut bob).await?.content), "ohne Internet");
    // Reconnecting later works the same way (ID and pin from the node's card).
    let again = Client::connect_auto(
        Identity::generate(&mut OsRng),
        &NodeAddress { url: Some(dead_url("owner")), ..NodeAddress::from_card(net.owner.node.card()) },
        &options,
    )
    .await;
    assert!(matches!(again, Err(SdkError::Node { ref code, .. }) if code == "NOT_MEMBER"), "{:?}", again.map(|_| ()));
    let mut alice_again = Client::connect_auto(
        same(alice.identity()),
        &NodeAddress { url: Some(dead_url("owner")), ..NodeAddress::from_card(net.owner.node.card()) },
        &options,
    )
    .await
    .map_err(e)?;
    assert!(alice_again.via_lan());
    drop(alice_again.receive(0).await.map_err(e)?);

    // Attacks on the link: a wrong pin, a wrong node ID (another real node), tls without node.
    let wrong_pin = JoinLink { tls: Some([9u8; 32]), ..JoinLink::parse(&offline).map_err(e)? }.to_link();
    assert!(Client::join_with(Identity::generate(&mut OsRng), &wrong_pin, &options).await.is_err());
    let other_dir = tempfile::tempdir().map_err(e)?;
    let other = start(lan_node_config(other_dir.path(), &LanHints::default())).await?;
    hints.push(LanPeer { id: other.card().id().to_string(), ..lan_peer(&other)? });
    let wrong_node = JoinLink { node: Some(other.card().id().clone()), ..JoinLink::parse(&offline).map_err(e)? };
    let joined = Client::join_with(Identity::generate(&mut OsRng), &wrong_node.to_link(), &options).await.map(|_| ());
    assert!(joined.is_err(), "the pin of one node with the ID of another: {joined:?}");
    let no_node = format!("bridge4://join?net={}&gw=http%3A%2F%2F127.0.0.1%3A9&tls={}", net.net, b64(&owner_pin));
    assert!(Client::join_with(Identity::generate(&mut OsRng), &no_node, &options).await.is_err());
    other.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_keeps_the_fingerprint() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let hints = LanHints::default();
    let node = start(lan_node_config(dir.path(), &hints)).await?;
    let first = NodeAddress::from_card(node.card());
    let pin = first.tls.ok_or("no pin")?;
    hints.set(vec![lan_peer(&node)?]);
    let identity = Identity::generate(&mut OsRng);
    let client = Client::connect_auto(same(&identity), &first, &lan_options(&hints)).await.map_err(e)?;
    assert!(client.via_lan());
    node.shutdown().await;

    // Restarted (on another LAN port): the same certificate, so the pin a client kept still works.
    let node = start(lan_node_config(dir.path(), &hints)).await?;
    assert_eq!(node.card().tls(), Some(&pin));
    assert_eq!(node.card().id(), &first.node);
    hints.set(vec![lan_peer(&node)?]);
    let client = Client::connect_auto(same(&identity), &first, &lan_options(&hints)).await.map_err(e)?;
    assert!(client.via_lan());
    node.shutdown().await;

    // Without LAN the card has no pin (and the file is left alone); with LAN again it is the same one.
    let mut plain = lan_node_config(dir.path(), &hints);
    plain.lan = None;
    let node = start(plain).await?;
    assert!(node.card().tls().is_none() && node.lan_addr().is_none());
    node.shutdown().await;
    let node = start(lan_node_config(dir.path(), &hints)).await?;
    assert_eq!(node.card().tls(), Some(&pin));
    node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_damaged_tls_file_stops_the_node() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let hints = LanHints::default();
    let node = start(lan_node_config(dir.path(), &hints)).await?;
    let pin = node.card().tls().copied().ok_or("no pin")?;
    node.shutdown().await;
    let path = dir.path().join(TLS_FILE);
    let good = std::fs::read(&path).map_err(e)?;
    let other = TlsIdentity::generate().map_err(e)?.to_pem();
    let key_of_other = format!(
        "{}{}",
        String::from_utf8_lossy(&good).split("-----BEGIN PRIVATE KEY-----").next().unwrap_or_default(),
        other.split("-----END CERTIFICATE-----\n").nth(1).unwrap_or_default()
    );
    for (name, bytes) in [
        ("garbage", b"kaputt".to_vec()),
        ("truncated", good[..good.len() / 2].to_vec()),
        ("key of another certificate", key_of_other.into_bytes()),
        ("empty", Vec::new()),
    ] {
        std::fs::write(&path, &bytes).map_err(e)?;
        let started = start(lan_node_config(dir.path(), &hints)).await;
        let error = started.err().ok_or(format!("{name}: the node started"))?;
        assert!(error.contains(TLS_FILE) && error.contains("not starting"), "{name}: {error}");
        assert_eq!(std::fs::read(&path).map_err(e)?, bytes, "{name}: never silently replaced");
    }
    // A node without LAN does not need the file; restored from a backup, LAN works with the old fingerprint.
    let mut plain = lan_node_config(dir.path(), &hints);
    plain.lan = None;
    start(plain).await?.shutdown().await;
    std::fs::write(&path, &good).map_err(e)?;
    let node = start(lan_node_config(dir.path(), &hints)).await?;
    assert_eq!(node.card().tls(), Some(&pin));
    node.shutdown().await;
    Ok(())
}

/// The acceptance scenario without the Internet: the public addresses of both gateways lead nowhere, so the second
/// node bootstraps from the join link's pinned LAN gateway, follows the log, is sealed, exchanges homes and relays
/// - all over the pinned LAN path. A lying hint (another node's port under the owner's ID) is skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_gateways_work_over_the_lan_alone() -> TestResult {
    let (owner_hints, second_hints, client_hints) = (LanHints::default(), LanHints::default(), LanHints::default());
    let net = TestNet::create_with(JoinMode::Open, Some(&dead_url("owner")), Some(lan_config(&owner_hints))).await?;
    let owner_peer = lan_peer(&net.owner.node)?;
    let owner_pin = net.owner.node.card().tls().copied().ok_or("no pin")?;

    // An impostor answers first under the owner's ID - its certificate is not the one the log pins.
    let impostor_dir = tempfile::tempdir().map_err(e)?;
    let impostor = start(lan_node_config(impostor_dir.path(), &LanHints::default())).await?;
    let lie = LanPeer { id: owner_peer.id.clone(), ..lan_peer(&impostor)? };
    second_hints.set(vec![lie.clone(), owner_peer.clone()]);
    client_hints.set(vec![lie, owner_peer]);

    // The second node joins with the link's LAN pin only (its bootstrap address is dead as well).
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let real = format!("http://{}", listener.local_addr().map_err(e)?);
    let network = NetConfig {
        bootstrap: vec![dead_url("owner")],
        lan_bootstrap: Some(LanPin { node: net.owner.node.card().id().clone(), tls: owner_pin }),
        ..membership(&net.net, &[])
    };
    let mut config = test_config(dir.path(), Some(network), &dead_url("second"));
    config.lan = Some(lan_config(&second_hints));
    let node = bridge_node::start(config, listener).await?;
    let second = TestNode { dir, node, url: real };
    owner_hints.set(vec![lan_peer(&second.node)?]);
    client_hints.push(lan_peer(&second.node)?);
    net.synced(&second).await?;

    // Sealed with its current card (public address dead, TLS pin of its certificate).
    net.seal_gateway(&second).await?;
    net.synced(&second).await?;

    let (_, invite) = net.admin.invite(2, 1).await?;
    let owner_link = JoinLink { gateway: dead_url("owner"), ..JoinLink::parse(&invite).map_err(e)? }.to_link();
    let second_link = JoinLink {
        net: net.net.clone(),
        gateway: dead_url("second"),
        code: None,
        node: Some(second.id()),
        tls: second.node.card().tls().copied(),
    }
    .to_link();
    let options = lan_options(&client_hints);
    let mut alice = Client::join_with(Identity::generate(&mut OsRng), &owner_link, &options).await.map_err(e)?;
    let mut bob = Client::join_with(Identity::generate(&mut OsRng), &second_link, &options).await.map_err(e)?;
    assert!(alice.via_lan() && bob.via_lan());

    // Alice -> Bob: owner -> relay over the LAN -> second (its public address is dead). And back.
    let secret = marker();
    send_when_routed(&alice, &bob, &Content::text(ContentType::Direct, secret.clone())).await?;
    let message = receive_one(&mut bob).await?;
    assert_eq!((text(&message.content), &message.from), (secret.clone(), alice.identity().id()));
    send_when_routed(&bob, &alice, &Content::text(ContentType::Response, "zurück übers LAN")).await?;
    assert_eq!(text(&receive_one(&mut alice).await?.content), "zurück übers LAN");
    for dir in [net.owner.dir.path(), second.dir.path(), impostor_dir.path()] {
        assert!(!files_contain(dir, secret.as_bytes())?, "plaintext in {}", dir.display());
    }
    impostor.shutdown().await;
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

/// mDNS for real: the nodes announce themselves and find each other, clients find their gateway - with all public
/// addresses dead. Needs multicast (`cargo test -- --ignored`; CI: Ubuntu only).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs multicast"]
async fn mdns_discovery_end_to_end() -> TestResult {
    let mdns = || LanConfig {
        discovery: Discovery::Mdns(Duration::from_secs(1)),
        rediscover: Duration::from_millis(300),
        ..LanConfig::new(([0, 0, 0, 0], 0).into())
    };
    let net = TestNet::create_with(JoinMode::Open, Some(&dead_url("owner")), Some(mdns())).await?;
    assert!(net.owner.node.lan_announced(), "the owner is announced");
    let owner_pin = net.owner.node.card().tls().copied().ok_or("no pin")?;

    // A client finds the owner by its ID alone.
    let options = ConnectOptions { lan: Discovery::Mdns(Duration::from_secs(10)), ..ConnectOptions::default() };
    let (_, invite) = net.admin.invite(2, 1).await?;
    let owner_link = JoinLink { gateway: dead_url("owner"), ..JoinLink::parse(&invite).map_err(e)? }.to_link();
    let started = Instant::now();
    let mut alice = Client::join_with(Identity::generate(&mut OsRng), &owner_link, &options).await.map_err(e)?;
    assert!(alice.via_lan());
    assert!(started.elapsed() < Duration::from_secs(9), "found before the timeout: {:?}", started.elapsed());

    // A second node bootstraps from the owner found via mDNS, and the owner finds it the same way.
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let real = format!("http://{}", listener.local_addr().map_err(e)?);
    let network = NetConfig {
        bootstrap: vec![dead_url("owner")],
        lan_bootstrap: Some(LanPin { node: net.owner.node.card().id().clone(), tls: owner_pin }),
        ..membership(&net.net, &[])
    };
    let mut config = test_config(dir.path(), Some(network), &dead_url("second"));
    config.lan = Some(mdns());
    let node = bridge_node::start(config, listener).await?;
    let second = TestNode { dir, node, url: real };
    net.synced(&second).await?;
    net.seal_gateway(&second).await?;
    let second_link = JoinLink {
        net: net.net.clone(),
        gateway: dead_url("second"),
        code: None,
        node: Some(second.id()),
        tls: second.node.card().tls().copied(),
    }
    .to_link();
    let mut bob = Client::join_with(Identity::generate(&mut OsRng), &second_link, &options).await.map_err(e)?;
    assert!(bob.via_lan());
    send_when_routed(&alice, &bob, &Content::text(ContentType::Direct, "per mDNS gefunden")).await?;
    assert_eq!(text(&receive_one(&mut bob).await?.content), "per mDNS gefunden");
    send_when_routed(&bob, &alice, &Content::text(ContentType::Response, "zurück")).await?;
    assert_eq!(text(&receive_one(&mut alice).await?.content), "zurück");
    wait_for("both gateways known", || second.status().gateway).await?;
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}
