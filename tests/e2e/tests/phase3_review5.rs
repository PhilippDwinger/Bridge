//! End-to-end regression tests for review 5, finding 1 (adapted from the reviewer's scratch test
//! `words_alone_fork_a_lagging_follower`): a follower that catches up across a change of the log rules takes the new
//! rules only with that change's transition head, witnessed under the old rules. So the 24 words alone can no longer
//! fork a lagging follower, while honest changes (witness switch, operator switch - the rescue is in
//! `phase3_review4.rs`) still let a follower that was offline across several of them catch up. Every node keeps the
//! transition heads (also over a restart) and serves them at `POST /v4/net/{net}/head/at`, rate-limited like proofs.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bridge_core::{Id, Identity, KeyCard, Role, Statement};
use bridge_net::{
    Ban, Body, JoinMode, Log, Manifest, Seal, Service, Services, WitnessedHead, issue_cosign, issue_head, verify_head,
};
use bridge_tests::net::{TestNet, TestNode, membership, test_config, wait_for};
use rand_core::OsRng;
use serde_json::{Value, json};

type TestResult = Result<(), String>;

const DAY: i64 = 86_400_000;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

async fn current_manifest(net: &TestNet) -> Result<Manifest, String> {
    let http = bridge_transport::HttpClient::new(&net.owner.url, Duration::from_secs(10)).map_err(e)?;
    let answer = http.get(&format!("/v4/net/{}/manifest", net.net)).await.map_err(e)?;
    let value: Value = serde_json::from_slice(&answer.body).map_err(e)?;
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

async fn ban(net: &TestNet) -> Result<u64, String> {
    let ban =
        net.admin.sign(&Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() }, DAY)?;
    Ok(net.admin.submit(&ban).await?.index)
}

/// Changes the manifest (admin key) and returns the log index of the change once its transition head is witnessed.
async fn change_manifest(net: &TestNet, change: impl FnOnce(&mut Manifest)) -> Result<u64, String> {
    let mut manifest = current_manifest(net).await?.next_version();
    change(&mut manifest);
    let index = net.admin.submit(&net.admin.sign(&manifest, 30 * DAY)?).await?.index;
    wait_for("transition head witnessed", || net.owner.status().witnessed_size >= Some(index + 1)).await?;
    Ok(index)
}

/// `POST /v4/net/{net}/head/at` at `node`: status and the head size in the answer (if any).
async fn head_at(node: &TestNode, net: &Id, size: u64) -> Result<(u16, Option<u64>), String> {
    let http = bridge_transport::HttpClient::new(&node.url, Duration::from_secs(10)).map_err(e)?;
    let body = json!({"size": size}).to_string().into_bytes();
    let answer = http.post(&format!("/v4/net/{net}/head/at"), None, body).await.map_err(e)?;
    let value: Value = serde_json::from_slice(&answer.body).map_err(e)?;
    let shown = WitnessedHead::from_value(&value).ok().and_then(|head| head.size().ok());
    Ok((answer.status, shown))
}

/// A head over `entries` signed by `operator` and cosigned by `witnesses`.
fn head_over(
    net: &Id,
    entries: &[Vec<u8>],
    operator: &Identity,
    witnesses: &[&Identity],
) -> Result<WitnessedHead, String> {
    let log = Log::from_entries(net.clone(), entries).map_err(e)?;
    let now = bridge_tests::now_ms();
    let statement = issue_head(operator, net, log.size(), log.root(), now).map_err(e)?;
    let card = operator.key_card(Role::Node, None, now).map_err(e)?;
    let head = verify_head(&statement, net, &card).map_err(e)?;
    let cosigns = witnesses.iter().map(|w| issue_cosign(w, &head, now)).collect::<Result<_, _>>().map_err(e)?;
    Ok(WitnessedHead { head: statement, cosigns })
}

/// A sync source that shows whatever the test gives it - head, entries, manifest, transition heads - and counts what
/// it hands out from `/log` and how often it was asked for a transition head.
#[derive(Default)]
struct ForkSource {
    head: Mutex<Option<Vec<u8>>>,
    entries: Mutex<Vec<Vec<u8>>>,
    manifest: Mutex<Option<Vec<u8>>>,
    transitions: Mutex<Vec<(u64, Vec<u8>)>>,
    log_requests: AtomicU64,
    transition_requests: AtomicU64,
}

impl bridge_transport::Handler for ForkSource {
    async fn handle(&self, request: bridge_transport::Request) -> bridge_transport::Response {
        use bridge_transport::Response;
        let shown = |slot: &Mutex<Option<Vec<u8>>>| slot.lock().ok().and_then(|value| value.clone());
        let none = || Response::error(404, "NOT_FOUND", "none", None);
        let number = |name: &str| {
            serde_json::from_slice::<Value>(&request.body)
                .ok()
                .and_then(|value| value.get(name).and_then(Value::as_u64))
        };
        if request.path.ends_with("/head") {
            return shown(&self.head).map_or_else(none, Response::ok);
        }
        if request.path.ends_with("/manifest") {
            return shown(&self.manifest).map_or_else(none, Response::ok);
        }
        if request.path.ends_with("/evidence") {
            return Response::ok(br#"{"evidence":[]}"#.to_vec());
        }
        if request.path.ends_with("/head/at") {
            self.transition_requests.fetch_add(1, Ordering::SeqCst);
            let size = number("size");
            let found = self
                .transitions
                .lock()
                .ok()
                .and_then(|list| list.iter().find(|(at, _)| Some(*at) == size).map(|(_, head)| head.clone()));
            return found.map_or_else(none, Response::ok);
        }
        if request.path.ends_with("/log") {
            self.log_requests.fetch_add(1, Ordering::SeqCst);
            let from = number("from").unwrap_or(0);
            let entries: Vec<Vec<u8>> = self.entries.lock().ok().map(|entries| entries.clone()).unwrap_or_default();
            let page: Vec<String> = entries
                .iter()
                .skip(usize::try_from(from).unwrap_or(usize::MAX))
                .take(256)
                .map(|entry| bridge_core::encoding::b64(entry))
                .collect();
            return Response::ok(json!({"entries": page, "size": entries.len()}).to_string().into_bytes());
        }
        none()
    }
}

impl ForkSource {
    fn show(&self, entries: &[Vec<u8>], head: &WitnessedHead, manifest: (&Statement, u64)) -> TestResult {
        *self.entries.lock().map_err(e)? = entries.to_vec();
        *self.head.lock().map_err(e)? = Some(bridge_core::json::canonical(&head.to_value()).map_err(e)?);
        let (statement, index) = manifest;
        *self.manifest.lock().map_err(e)? =
            Some(json!({"manifest": statement.to_value(), "index": index}).to_string().into_bytes());
        Ok(())
    }

    fn serve_transition(&self, head: &WitnessedHead) -> TestResult {
        let size = head.size().map_err(e)?;
        let bytes = bridge_core::json::canonical(&head.to_value()).map_err(e)?;
        self.transitions.lock().map_err(e)?.push((size, bytes));
        Ok(())
    }
}

/// A seal by the net key `master` of `net` for `node` with `services` and `card`.
fn sealed(
    (net, master): (&Id, &Identity),
    node: &Identity,
    level: u8,
    services: &[Service],
    card: KeyCard,
) -> Result<Vec<u8>, String> {
    let now = bridge_tests::now_ms();
    let seal = Seal { subject: node.id().clone(), level, services: Services::of(services), card: Some(card) };
    Ok(seal.sign(net, now, now + 30 * DAY, master).map_err(e)?.canonical_bytes().to_vec())
}

/// The scratch test `words_alone_fork_a_lagging_follower` end to end: someone with only the 24 words fabricates a
/// suffix that seals an operator and a witness of their own and switches the log rules to them (a manifest of the
/// net key alone), and shows it to a follower whose honest sources are gone. The follower fetches it (a genuine
/// manifest ahead) and the head passes under the new rules on a copy - but there is no transition head under the
/// old rules, so nothing is taken. A "transition head" by the new operator, or cosigned by the net key, does not
/// help either (that would need the old operator's key).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_words_alone_can_not_fork_a_lagging_follower() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let source = std::sync::Arc::new(ForkSource::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let server =
        bridge_transport::serve(listener, bridge_transport::ServerConfig::default(), source.clone()).map_err(e)?;
    let fake_url = format!("http://{}", server.local_addr());
    let follower = net.add_node(std::slice::from_ref(&fake_url)).await?;
    ban(&net).await?;
    let real = net.admin.fetch_log(0, None).await?;
    all_at(&[&follower], real.len() as u64).await?;
    net.owner.node.shutdown().await; // only the fork source is left

    // The fork: the attacker's operator and witness sealed, the log rules switched to them, one more entry.
    let (op2, w2) = (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
    let now = bridge_tests::now_ms();
    let card = |node: &Identity, url: &str| node.key_card_with(Role::Node, None, &[url.to_owned()], None, now);
    let mut fork = real.clone();
    fork.push(sealed(
        (&net.net, &net.master),
        &op2,
        3,
        &[Service::Log],
        card(&op2, "https://evil.example").map_err(e)?,
    )?);
    fork.push(sealed(
        (&net.net, &net.master),
        &w2,
        2,
        &[Service::Witness],
        card(&w2, "https://evil2.example").map_err(e)?,
    )?);
    let latest = fork
        .iter()
        .rev()
        .filter_map(|entry| Statement::parse(entry).ok())
        .find(|statement| statement.kind() == "manifest")
        .ok_or("no manifest")?;
    let mut manifest = Manifest::from_statement(&latest).map_err(e)?.next_version();
    (manifest.logs, manifest.witnesses, manifest.witness_threshold) =
        (vec![op2.id().clone()], vec![w2.id().clone()], 1);
    let change = manifest.sign(&net.net, now, now + 30 * DAY, &net.master).map_err(e)?;
    let index = fork.len() as u64;
    fork.push(change.canonical_bytes().to_vec());
    let extra = Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() };
    fork.push(extra.sign(&net.net, now, now + DAY, &net.master).map_err(e)?.canonical_bytes().to_vec());
    source.show(&fork, &head_over(&net.net, &fork, &op2, &[&w2])?, (&change, index))?;

    // Fetched, replayed on a copy, the transition head asked for - and refused.
    wait_for("the fork was fetched and its transition head asked for", || {
        source.log_requests.load(Ordering::SeqCst) > 0 && source.transition_requests.load(Ordering::SeqCst) > 0
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(900)).await; // ~6 sync rounds of 150 ms
    assert_eq!(follower.status().size, real.len() as u64, "the fork is not taken");
    assert!(follower.status().state_copies > 0, "it got as far as the copy");
    // "Transition heads" the words can make: by the new operator (cosigned by its witness and the net key).
    let upto = usize::try_from(index + 1).map_err(e)?;
    source.serve_transition(&head_over(&net.net, &fork[..upto], &op2, &[&w2, &net.master])?)?;
    let asked = source.transition_requests.load(Ordering::SeqCst);
    wait_for("asked again", || source.transition_requests.load(Ordering::SeqCst) > asked).await?;
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(follower.status().size, real.len() as u64, "still not taken");
    follower.node.shutdown().await;
    server.shutdown().await;
    Ok(())
}

/// Honest changes, two in a row while a follower is offline: the witnesses switch to a second node, then the log
/// operator to a third. Every node that saw them keeps both transition heads (the owner also after a restart) and
/// serves them; the follower comes back, fetches them and catches up across both - and then serves them too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_follower_offline_across_two_changes_catches_up() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let witness = net.add_node(&[]).await?;
    net.seal_as(&witness, "gateway,witness").await?;
    let operator = net.add_node(&[]).await?;
    net.seal_as(&operator, "gateway,log").await?;
    let follower = net.add_node(&[]).await?;
    all_at(&[&witness, &operator, &follower], net.owner.status().size).await?;
    let behind = follower.status().size;
    let follower_addr = follower.node.local_addr();
    let TestNode { dir: follower_dir, node: follower_node, url: follower_url } = follower;
    follower_node.shutdown().await;

    let j1 = change_manifest(&net, |manifest| manifest.witnesses = vec![witness.id()]).await?;
    ban(&net).await?;
    let j2 = change_manifest(&net, |manifest| manifest.logs = vec![operator.id(), net.owner.id()]).await?;
    wait_for("the new operator took over", || operator.status().operator).await?;
    let last = ban(&net).await?;
    all_at(&[&net.owner, &witness, &operator], last + 1).await?;
    // The owner keeps both transition heads (issued and witnessed there), nothing for other sizes.
    for size in [j1 + 1, j2 + 1] {
        assert_eq!(head_at(&net.owner, &net.net, size).await?, (200, Some(size)), "size {size}");
    }
    for size in [0, j1, j1 + 2, last + 1] {
        assert_eq!(head_at(&net.owner, &net.net, size).await?.0, 404, "size {size}");
    }
    // Kept over a restart.
    let again = net.membership(&[]);
    let owner = net.owner.restart(Some(again)).await?;
    for size in [j1 + 1, j2 + 1] {
        assert_eq!(head_at(&owner, &net.net, size).await?, (200, Some(size)), "after restart: size {size}");
    }

    // The follower comes back: behind both changes, it catches up across them.
    let config =
        test_config(follower_dir.path(), Some(membership(&net.net, std::slice::from_ref(&owner.url))), &follower_url);
    let node = bridge_tests::start_node_on(config, follower_addr).await?;
    let follower = TestNode { dir: follower_dir, node, url: follower_url };
    assert_eq!(follower.status().size, behind);
    all_at(&[&follower], last + 1).await?;
    assert!(follower.status().state_copies > 0, "it replayed the changes on a copy");
    for size in [j1 + 1, j2 + 1] {
        assert_eq!(head_at(&follower, &net.net, size).await?, (200, Some(size)), "the follower serves {size} too");
    }
    // The network runs on with the new operator; everybody follows.
    let extra = Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() };
    let next = net.admin.submit(&net.admin.sign(&extra, DAY)?).await?.index;
    all_at(&[&owner, &witness, &operator, &follower], next + 1).await?;
    for node in [witness, operator, follower, owner] {
        node.node.shutdown().await;
    }
    Ok(())
}

/// `head/at` takes a small JSON body and is rate-limited per address like the proof endpoints.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn head_at_is_checked_and_rate_limited() -> TestResult {
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
    let path = format!("/v4/net/{}/head/at", created.net);
    let post = |body: &[u8]| {
        let (http, path, body) = (http.clone(), path.clone(), body.to_vec());
        async move { http.post(&path, None, body).await.map(|answer| (answer.status, bridge_tests::code(&answer))) }
    };
    assert_eq!(post(br#"{"size":2}"#).await.map_err(e)?, (404, "NOT_FOUND".to_owned()), "no change of the rules yet");
    for junk in [&b"[]"[..], b"{\"size\":-1}", b"{\"size\":\"2\"}", b"{"] {
        assert_eq!(post(junk).await.map_err(e)?.0, 400, "{}", String::from_utf8_lossy(junk));
    }
    assert_eq!(post(&vec![b' '; 2048]).await.map_err(e)?.0, 413, "body too large");
    let mut limited = false;
    for _ in 0..20 {
        limited |= post(br#"{"size":2}"#).await.map_err(e)?.0 == 429;
    }
    assert!(limited, "transition-head requests are rate-limited per address");
    owner.node.shutdown().await;
    Ok(())
}
