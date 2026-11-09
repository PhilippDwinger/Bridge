//! End-to-end regression tests for review 3 (each failed before its fix): a manifest change of witnesses or of the
//! log operator keeps the network running and the transition window can not be used to get a head accepted with
//! the wrong set (finding 2); the proof endpoints only serve sizes up to the own log and are rate-limited per
//! address (finding 4); an open network ignores used-up invite codes (finding 6); `net seal` only seals the node it
//! was told to (finding 8). Adapted from the reviewer's scratch test `review_manifest.rs`. Since review 5 a node behind
//! a change also needs that change's transition head under the old rules (ADR 0013; see `phase3_review5.rs`).

use std::time::Duration;

use bridge_core::{Identity, Statement};
use bridge_net::{Ban, Body, JoinMode, Log, Manifest, WitnessedHead, issue_cosign, issue_head, verify_head};
use bridge_sdk::Client;
use bridge_tests::net::{TestNet, TestNode, joined, membership, test_config, wait_for};
use rand_core::OsRng;

type TestResult = Result<(), String>;

const DAY: i64 = 86_400_000;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

async fn current_manifest(net: &TestNet) -> Result<Manifest, String> {
    let http = bridge_transport::HttpClient::new(&net.owner.url, Duration::from_secs(10)).map_err(e)?;
    let answer = http.get(&format!("/v4/net/{}/manifest", net.net)).await.map_err(e)?;
    let value: serde_json::Value = serde_json::from_slice(&answer.body).map_err(e)?;
    let current = Statement::from_value(value["manifest"].clone()).map_err(e)?;
    Manifest::from_statement(&current).map_err(e)
}

/// Waits until every node holds `size` entries, all in a witnessed head.
async fn all_at(nodes: &[&TestNode], size: u64) -> TestResult {
    for node in nodes {
        wait_for(&format!("node at {size} entries, witnessed"), || {
            let status = node.status();
            status.size == size && status.witnessed_size == Some(size)
        })
        .await?;
    }
    Ok(())
}

/// The whole log of a node.
async fn entries_of(node: &TestNode, net: &bridge_core::Id) -> Result<Vec<Vec<u8>>, String> {
    let http = bridge_transport::HttpClient::new(&node.url, Duration::from_secs(10)).map_err(e)?;
    let page = http.post(&format!("/v4/net/{net}/log"), None, br#"{"from":0}"#.to_vec()).await.map_err(e)?;
    let page: serde_json::Value = serde_json::from_slice(&page.body).map_err(e)?;
    Ok(page["entries"]
        .as_array()
        .map(|list| list.iter().filter_map(|v| bridge_core::encoding::b64_var(v.as_str()?, "e", 65_536).ok()).collect())
        .unwrap_or_default())
}

/// Changes the manifest (admin key) and returns the log index of the change once its transition head is witnessed.
async fn change_manifest(net: &TestNet, change: impl FnOnce(&mut Manifest)) -> Result<u64, String> {
    let mut manifest = current_manifest(net).await?.next_version();
    change(&mut manifest);
    let statement = net.admin.sign(&manifest, 30 * DAY)?;
    let index = net.admin.submit(&statement).await?.index;
    wait_for("transition head witnessed", || net.owner.status().witnessed_size >= Some(index + 1)).await?;
    Ok(index)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn witnesses_switch_to_another_node_and_the_network_keeps_running() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let second = net.add_node(&[]).await?;
    net.seal_as(&second, "gateway,witness").await?; // a witness needs a seal with that service (docs/06 §4)
    let follower = net.add_node(&[]).await?;
    let laggard = net.add_node(&[]).await?;
    all_at(&[&second, &follower, &laggard], net.owner.status().size).await?;
    // One node is offline during the change - it has to catch up across it later.
    let laggard_addr = laggard.node.local_addr();
    let TestNode { dir: laggard_dir, node: laggard_node, url: laggard_url } = laggard;
    laggard_node.shutdown().await;

    let j = change_manifest(&net, |manifest| manifest.witnesses = vec![second.id()]).await?;
    all_at(&[&net.owner, &second, &follower], j + 1).await?;
    assert!(!net.owner.status().witness && second.status().witness, "roles from the new manifest");
    // New entries are witnessed by the new witness and reach the followers: a client joins, the admin bans.
    let mut client = joined(&net.link(None)).await?;
    let ban =
        net.admin.sign(&Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() }, DAY)?;
    net.admin.submit(&ban).await?;
    all_at(&[&net.owner, &second, &follower], j + 3).await?;
    client.receive(0).await.map_err(e)?;

    // The node that was offline catches up across the change (its newest head is beyond the transition head).
    let config = test_config(laggard_dir.path(), Some(net.membership(&[])), &laggard_url);
    let node = bridge_tests::start_node_on(config, laggard_addr).await?;
    let laggard = TestNode { dir: laggard_dir, node, url: laggard_url };
    all_at(&[&laggard], j + 3).await?;
    for node in [second, follower, laggard] {
        node.node.shutdown().await;
    }
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_operator_switches_to_another_node_and_the_network_keeps_running() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let second = net.add_node(&[]).await?;
    net.seal_as(&second, "gateway,log").await?; // a log operator needs a seal with that service (docs/06 §4)
    let follower = net.add_node(&[]).await?;
    all_at(&[&second, &follower], net.owner.status().size).await?;

    // The second node becomes the log operator; the owner stays (backup) operator, witness and gateway.
    let j = change_manifest(&net, |manifest| manifest.logs = vec![second.id(), net.owner.id()]).await?;
    wait_for("the new operator took over", || second.status().operator).await?;
    assert!(!net.owner.status().operator, "the old operator stops taking entries");
    all_at(&[&net.owner, &second, &follower], j + 1).await?;
    // A client joins at the owner: its membership goes to the new operator, is witnessed and reaches everybody.
    let mut client = joined(&net.link(None)).await?;
    // The admin still talks to the owner node: it hands the statement on to the new operator.
    let ban =
        net.admin.sign(&Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() }, DAY)?;
    net.admin.submit(&ban).await?;
    all_at(&[&second, &net.owner, &follower], j + 3).await?;
    client.connect().await.map_err(e)?;
    let mut later = joined(&second.link(&net.net, None)).await?;
    later.receive(0).await.map_err(e)?;
    all_at(&[&second, &net.owner, &follower], j + 4).await?;
    second.node.shutdown().await;
    follower.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

/// A peer that shows whatever head (and entries) the test gives it.
#[derive(Default)]
struct FakePeer {
    head: std::sync::Mutex<Option<Vec<u8>>>,
    entries: std::sync::Mutex<Vec<Vec<u8>>>,
    /// Transition heads it serves at `head/at` (review 5): (size, witnessed head).
    transitions: std::sync::Mutex<Vec<(u64, Vec<u8>)>>,
}

impl bridge_transport::Handler for FakePeer {
    async fn handle(&self, request: bridge_transport::Request) -> bridge_transport::Response {
        use bridge_transport::Response;
        if request.path.ends_with("/head") {
            return match self.head.lock().ok().and_then(|head| head.clone()) {
                Some(head) => Response::ok(head),
                None => Response::error(404, "NOT_FOUND", "none", None),
            };
        }
        if request.path.ends_with("/evidence") {
            return Response::ok(br#"{"evidence":[]}"#.to_vec());
        }
        if request.path.ends_with("/head/at") {
            let size = serde_json::from_slice::<serde_json::Value>(&request.body)
                .ok()
                .and_then(|value| value.get("size").and_then(serde_json::Value::as_u64));
            let shown = self
                .transitions
                .lock()
                .ok()
                .and_then(|list| list.iter().find(|(at, _)| Some(*at) == size).map(|(_, head)| head.clone()));
            return shown.map_or_else(|| Response::error(404, "NOT_FOUND", "none", None), Response::ok);
        }
        if request.path.ends_with("/manifest") {
            // Like an honest node: the newest manifest entry of the log it shows, and its index.
            let entries: Vec<Vec<u8>> = self.entries.lock().ok().map(|entries| entries.clone()).unwrap_or_default();
            let latest = entries.iter().enumerate().rev().find_map(|(index, entry)| {
                let statement = Statement::parse(entry).ok()?;
                (statement.kind() == "manifest").then_some((index, statement))
            });
            return match latest {
                Some((index, statement)) => Response::ok(
                    serde_json::json!({"manifest": statement.to_value(), "index": index}).to_string().into_bytes(),
                ),
                None => Response::error(404, "NOT_FOUND", "none", None),
            };
        }
        if request.path.ends_with("/log") {
            let from = serde_json::from_slice::<serde_json::Value>(&request.body)
                .ok()
                .and_then(|value| value.get("from").and_then(serde_json::Value::as_u64))
                .unwrap_or(0);
            let entries: Vec<Vec<u8>> = self.entries.lock().ok().map(|entries| entries.clone()).unwrap_or_default();
            let page: Vec<String> = entries
                .iter()
                .skip(usize::try_from(from).unwrap_or(usize::MAX))
                .take(256)
                .map(|entry| bridge_core::encoding::b64(entry))
                .collect();
            return Response::ok(serde_json::json!({"entries": page, "size": entries.len()}).to_string().into_bytes());
        }
        Response::error(404, "NOT_FOUND", "not found", None)
    }
}

impl FakePeer {
    fn show(&self, entries: &[Vec<u8>], head: &WitnessedHead) -> TestResult {
        *self.entries.lock().map_err(e)? = entries.to_vec();
        *self.head.lock().map_err(e)? = Some(bridge_core::json::canonical(&head.to_value()).map_err(e)?);
        Ok(())
    }

    /// Also serves `head` as the transition head of its size.
    fn serve_transition(&self, head: &WitnessedHead) -> TestResult {
        let size = bridge_net::HeadBody::from_statement(&head.head).map_err(e)?.size;
        let bytes = bridge_core::json::canonical(&head.to_value()).map_err(e)?;
        self.transitions.lock().map_err(e)?.push((size, bytes));
        Ok(())
    }
}

/// A head over `entries` signed by `operator` and cosigned by `witnesses` (stolen keys).
fn head_over(
    net: &bridge_core::Id,
    entries: &[Vec<u8>],
    operator: &Identity,
    witnesses: &[&Identity],
) -> Result<WitnessedHead, String> {
    let log = Log::from_entries(net.clone(), entries).map_err(e)?;
    let now = bridge_tests::now_ms();
    let statement = issue_head(operator, net, log.size(), log.root(), now).map_err(e)?;
    let card = operator.key_card(bridge_core::Role::Node, None, now).map_err(e)?;
    let head = verify_head(&statement, net, &card).map_err(e)?;
    let cosigns = witnesses.iter().map(|w| issue_cosign(w, &head, now)).collect::<Result<_, _>>().map_err(e)?;
    Ok(WitnessedHead { head: statement, cosigns })
}

/// The transition window can not be used: after the witnesses changed from the owner to the second node, heads
/// cosigned only by the old witness (stolen key) are refused by a synced follower and by one that is still behind
/// the change; the transition head cosigned only by the new witness is refused too. A properly cosigned head from
/// the same fake source is taken (so the source really was asked).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_transition_window_gives_no_head_with_the_wrong_set() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let fake = std::sync::Arc::new(FakePeer::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let server =
        bridge_transport::serve(listener, bridge_transport::ServerConfig::default(), fake.clone()).map_err(e)?;
    let fake_url = format!("http://{}", server.local_addr());
    let second = net.add_node(&[]).await?;
    net.seal_as(&second, "gateway,witness").await?;
    let follower = net.add_node(std::slice::from_ref(&fake_url)).await?;
    let laggard = net.add_node(std::slice::from_ref(&fake_url)).await?;
    all_at(&[&second, &follower, &laggard], net.owner.status().size).await?;
    let laggard_addr = laggard.node.local_addr();
    let TestNode { dir: laggard_dir, node: laggard_node, url: laggard_url } = laggard;
    laggard_node.shutdown().await;
    let behind = net.owner.status().size;

    let j = change_manifest(&net, |manifest| manifest.witnesses = vec![second.id()]).await?;
    let ban =
        net.admin.sign(&Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() }, DAY)?;
    net.admin.submit(&ban).await?;
    all_at(&[&net.owner, &second, &follower], j + 2).await?;

    // The attacker has the keys of the owner (operator, old witness) and of the second node (new witness) and an
    // extra valid admin statement. Then the honest nodes go away, only the fake source is left.
    let owner_key = bridge_node::keyfile::load_or_create(net.owner.dir.path())?;
    let second_key = bridge_node::keyfile::load_or_create(second.dir.path())?;
    let mut entries = entries_of(&net.owner, &net.net).await?;
    assert_eq!(entries.len() as u64, j + 2);
    let extra =
        net.admin.sign(&Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() }, DAY)?;
    entries.push(extra.canonical_bytes().to_vec());
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    let config = test_config(
        laggard_dir.path(),
        Some(membership(&net.net, &[net.owner.url.clone(), fake_url.clone()])),
        &laggard_url,
    );
    let laggard =
        TestNode { dir: laggard_dir, node: bridge_tests::start_node_on(config, laggard_addr).await?, url: laggard_url };
    assert_eq!(laggard.status().size, behind);

    // 1. A new head cosigned by the old (removed) witness only.
    fake.show(&entries, &head_over(&net.net, &entries, &owner_key, &[&owner_key])?)?;
    tokio::time::sleep(Duration::from_millis(1500)).await; // many sync rounds (150 ms each) - nothing may change
    assert_eq!((follower.status().size, laggard.status().size), (j + 2, behind), "old witness after the change");
    // 2. The transition head cosigned by the new witness only (the old set cut out).
    let upto = usize::try_from(j + 1).map_err(e)?;
    fake.show(&entries[..upto], &head_over(&net.net, &entries[..upto], &owner_key, &[&second_key])?)?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(laggard.status().size, behind, "new witness for the transition head");
    // 3. Properly cosigned by the new witness: taken by the synced follower. The laggard behind the change also
    // needs the transition head under the old rules (review 5) - without it nothing is taken; the attacker has the
    // old operator's and witness's key, so it can serve one, and then the laggard replays and takes it.
    fake.show(&entries, &head_over(&net.net, &entries, &owner_key, &[&second_key])?)?;
    all_at(&[&follower], j + 3).await?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(laggard.status().size, behind, "no transition head: the change is not endorsed");
    fake.serve_transition(&head_over(&net.net, &entries[..upto], &owner_key, &[&owner_key])?)?;
    all_at(&[&laggard], j + 3).await?;
    for node in [follower, laggard] {
        node.node.shutdown().await;
    }
    server.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proofs_only_up_to_the_own_size_and_rate_limited() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let created =
        bridge_node::admin::create_network(dir.path(), "Testnetz", &url, JoinMode::Open, bridge_tests::now_ms())?;
    let mut config = test_config(dir.path(), Some(membership(&created.net, &[])), &url);
    config.limits.proofs_per_address = bridge_guard::Limits::default().proofs_per_address;
    let owner = TestNode { node: bridge_node::start(config, listener).await?, dir, url };
    wait_for("owner head witnessed", || owner.status().witnessed_size == Some(3)).await?;
    let http = bridge_transport::HttpClient::new(&owner.url, Duration::from_secs(10)).map_err(e)?;
    let post = |action: &str, body: &str| {
        let path = format!("/v4/net/{}/{action}", created.net);
        let body = body.as_bytes().to_vec();
        let http = http.clone();
        async move { http.post(&path, None, body).await.map(|answer| (answer.status, bridge_tests::code(&answer))) }
    };
    assert_eq!(post("proof", r#"{"index":0,"size":3}"#).await.map_err(e)?.0, 200);
    assert_eq!(post("proof", r#"{"index":0,"size":4}"#).await.map_err(e)?, (404, "NOT_FOUND".to_owned()));
    assert_eq!(post("consistency", r#"{"from":1,"to":4}"#).await.map_err(e)?, (404, "NOT_FOUND".to_owned()));
    // The tighter bucket (5/s, burst 10) runs out; other endpoints are not affected.
    let mut limited = false;
    for _ in 0..20 {
        limited |= post("consistency", r#"{"from":1,"to":3}"#).await.map_err(e)?.0 == 429;
    }
    assert!(limited, "proof requests are rate-limited per address");
    let head = http.get(&format!("/v4/net/{}/head", created.net)).await.map_err(e)?;
    assert_eq!(head.status, 200);
    owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_network_ignores_a_used_up_invite_code() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let (_code, link) = net.admin.invite(1, 1).await?;
    let mut first = joined(&link).await?;
    // The code is used up now. In an open network the second joiner does not need it - it must not fail on it.
    let mut second = Client::join(Identity::generate(&mut OsRng), &link).await.map_err(e)?;
    first.receive(0).await.map_err(e)?;
    second.receive(0).await.map_err(e)?;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seal_only_for_the_expected_node_id() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let (second, third) = (net.add_node(&[]).await?, net.add_node(&[]).await?);
    let size = net.owner.status().size;
    let services = bridge_node::admin::parse_services("gateway")?;
    // The address answers with another node's card (wrong address, or somebody in between): nothing is sealed,
    // and the message names the ID that answered.
    let refused = net.admin.seal(&second.url, &third.id(), 2, services).await.err().unwrap_or_default();
    assert!(refused.contains(second.id().as_str()) && refused.contains("Abgebrochen"), "{refused}");
    assert_eq!(net.owner.status().size, size, "nothing in the log");
    let (statement, _) = net.admin.seal(&second.url, &second.id(), 2, services).await?;
    assert_eq!(statement.body()["subject"].as_str(), Some(second.id().as_str()));
    wait_for("second node is a gateway", || second.status().gateway).await?;
    for node in [second, third] {
        node.node.shutdown().await;
    }
    net.owner.node.shutdown().await;
    Ok(())
}
