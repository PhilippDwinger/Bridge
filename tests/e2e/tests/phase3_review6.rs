//! End-to-end regression tests for review 6 (the pure network logic is in `crates/bridge-net/tests/net_review6.rs`):
//! - finding 2 (`a_transition_head_missing_at_the_source_comes_from_another_node`): transition heads are asked from
//!   up to four distinct nodes, not from four endpoints of the same node;
//! - finding 3 (`a_damaged_transition_head_is_not_served_and_fetched_again`): stored transition heads are verified
//!   again after a restart; a damaged one is not served, fetched again from another node and replaces the stored row;
//! - finding 4 (`a_forged_suffix_from_several_sources_costs_bounded_work`): a refused head is not fetched again from
//!   the next source, a transition head nobody had is not asked for again right away, the source cools down.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bridge_core::{Id, Identity, Role, Statement};
use bridge_net::{
    Ban, Body, JoinMode, Log, Manifest, Seal, Service, Services, WitnessedHead, issue_cosign, issue_head, verify_head,
};
use bridge_node::DB_FILE;
use bridge_store::{Store, TransitionRow};
use bridge_tests::net::{TestNet, TestNode, dead_url, membership, test_config, wait_for};
use bridge_transport::{HttpClient, Method, Request, Response};
use rand_core::OsRng;
use serde_json::{Value, json};

type TestResult = Result<(), String>;

const DAY: i64 = 86_400_000;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

async fn current_manifest(net: &Id, url: &str) -> Result<Manifest, String> {
    let http = HttpClient::new(url, Duration::from_secs(10)).map_err(e)?;
    let answer = http.get(&format!("/v4/net/{net}/manifest")).await.map_err(e)?;
    let value: Value = serde_json::from_slice(&answer.body).map_err(e)?;
    let current = Statement::from_value(value["manifest"].clone()).map_err(e)?;
    Manifest::from_statement(&current).map_err(e)
}

/// Changes the manifest (admin key) and returns the log index of the change once its transition head is witnessed.
async fn change_manifest(net: &TestNet, change: impl FnOnce(&mut Manifest)) -> Result<u64, String> {
    let mut manifest = current_manifest(&net.net, &net.owner.url).await?.next_version();
    change(&mut manifest);
    let index = net.admin.submit(&net.admin.sign(&manifest, 30 * DAY)?).await?.index;
    wait_for("transition head witnessed", || net.owner.status().witnessed_size >= Some(index + 1)).await?;
    Ok(index)
}

async fn ban(net: &TestNet) -> Result<u64, String> {
    let ban =
        net.admin.sign(&Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() }, DAY)?;
    Ok(net.admin.submit(&ban).await?.index)
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

/// `POST /v4/net/{net}/head/at` at `url`: status and the head (if any).
async fn head_at(url: &str, net: &Id, size: u64) -> Result<(u16, Option<WitnessedHead>), String> {
    let http = HttpClient::new(url, Duration::from_secs(10)).map_err(e)?;
    let body = json!({"size": size}).to_string().into_bytes();
    let answer = http.post(&format!("/v4/net/{net}/head/at"), None, body).await.map_err(e)?;
    let value: Value = serde_json::from_slice(&answer.body).map_err(e)?;
    Ok((answer.status, WitnessedHead::from_value(&value).ok()))
}

async fn serve<H: bridge_transport::Handler>(
    handler: std::sync::Arc<H>,
) -> Result<(bridge_transport::RunningServer, String), String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let server = bridge_transport::serve(listener, bridge_transport::ServerConfig::default(), handler).map_err(e)?;
    let url = format!("http://{}", server.local_addr());
    Ok((server, url))
}

/// A stand-in for a node: forwards every request to an honest node (`target`) - its path from `/v4/` on, so the
/// stand-in can have several addresses `…/a`, `…/b` - except what the test switches off: transition heads
/// (`head/at` answers `NOT_FOUND`: a node that lacks them) or the newest head (`/head` answers `UNAVAILABLE`: never a
/// sync source). Counts the transition-head requests.
struct Proxy {
    target: HttpClient,
    no_transitions: AtomicBool,
    no_head: AtomicBool,
    transition_requests: AtomicU64,
}

impl Proxy {
    fn new(target: &str) -> Result<Self, String> {
        Ok(Self {
            target: HttpClient::new(target, Duration::from_secs(10)).map_err(e)?,
            no_transitions: AtomicBool::new(false),
            no_head: AtomicBool::new(false),
            transition_requests: AtomicU64::new(0),
        })
    }
}

impl bridge_transport::Handler for Proxy {
    async fn handle(&self, request: Request) -> Response {
        let Some(start) = request.path.find("/v4/") else {
            return Response::error(404, "NOT_FOUND", "none", None);
        };
        let path = &request.path[start..];
        if path.ends_with("/head/at") {
            self.transition_requests.fetch_add(1, Ordering::SeqCst);
            if self.no_transitions.load(Ordering::SeqCst) {
                return Response::error(404, "NOT_FOUND", "no transition head here", None);
            }
        }
        if path.ends_with("/head") && self.no_head.load(Ordering::SeqCst) {
            return Response::error(503, "UNAVAILABLE", "no head here", None);
        }
        let answer = match request.method {
            Method::Get => self.target.get(path).await,
            Method::Post => self.target.post(path, None, request.body.to_vec()).await,
            Method::Options => return Response::error(404, "NOT_FOUND", "not found", None),
        };
        match answer {
            Ok(answer) => {
                let mut response = Response::ok(answer.body);
                response.status = answer.status;
                response
            }
            Err(error) => Response::error(503, "UNAVAILABLE", &error.to_string(), None),
        }
    }
}

/// Review 6, finding 2. The sync source is a gateway M with four addresses (all one node) that serves the honest
/// log but lacks the transition head of a change the follower F passes; the owner is out of F's reach (its address
/// in the log is dead), and the node W that has the head is never a sync source (its `/head` is switched off) - it
/// is only asked for the transition head. Before, "the source and three more" were M's four addresses, so F never
/// caught up; now the four are distinct nodes: M, the owner, W.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transition_head_missing_at_the_source_comes_from_another_node() -> TestResult {
    let net = TestNet::create_with(JoinMode::Open, Some(&dead_url("owner")), None).await?;
    let w = net.add_node(&[]).await?;
    // M: a stand-in for the owner without its transition heads, sealed as gateway with four addresses.
    let mirror = std::sync::Arc::new(Proxy::new(&net.owner.url)?);
    mirror.no_transitions.store(true, Ordering::SeqCst);
    let (mirror_server, mirror_url) = serve(mirror.clone()).await?;
    let m = Identity::generate(&mut OsRng);
    let urls: Vec<String> = ["a", "b", "c", "d"].iter().map(|path| format!("{mirror_url}/{path}")).collect();
    let card = m.key_card_with(Role::Node, None, &urls, None, bridge_tests::now_ms()).map_err(e)?;
    let seal =
        Seal { subject: m.id().clone(), level: 2, services: Services::of(&[Service::Gateway]), card: Some(card) };
    net.admin.submit(&net.admin.sign(&seal, 30 * DAY)?).await?;
    // W behind a stand-in (F's only bootstrap address), F joins through it.
    let w_proxy = std::sync::Arc::new(Proxy::new(&w.url)?);
    let (w_server, w_proxy_url) = serve(w_proxy.clone()).await?;
    let size = net.owner.status().size;
    all_at(&[&w], size).await?;
    let f_dir = tempfile::tempdir().map_err(e)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let f_addr = listener.local_addr().map_err(e)?;
    let f_url = format!("http://{f_addr}");
    let f_config = || test_config(f_dir.path(), Some(membership(&net.net, std::slice::from_ref(&w_proxy_url))), &f_url);
    let f_node = bridge_node::start(f_config(), listener).await?;
    wait_for("F followed", || f_node.net_status().is_some_and(|status| status.size == size)).await?;
    f_node.shutdown().await;

    // While F is away: a change of the log rules (a second operator), then one more entry.
    let j = change_manifest(&net, |manifest| manifest.logs = vec![net.owner.id(), w.id()]).await?;
    let last = ban(&net).await?;
    all_at(&[&net.owner, &w], last + 1).await?;
    assert_eq!(head_at(&w.url, &net.net, j + 1).await?.0, 200, "W keeps the transition head");
    assert_eq!(head_at(&mirror_url, &net.net, j + 1).await?.0, 404, "M does not");
    w_proxy.no_head.store(true, Ordering::SeqCst);
    let asked_w = w_proxy.transition_requests.load(Ordering::SeqCst);

    // F comes back: it follows M (the only source with a head), asks M - then other nodes, and gets it from W.
    let f = TestNode { node: bridge_tests::start_node_on(f_config(), f_addr).await?, dir: f_dir, url: f_url };
    all_at(&[&f], last + 1).await?;
    assert!(mirror.transition_requests.load(Ordering::SeqCst) > 0, "M was asked");
    assert!(w_proxy.transition_requests.load(Ordering::SeqCst) > asked_w, "and then W, another node");
    assert_eq!(head_at(&f.url, &net.net, j + 1).await?.0, 200, "F keeps it now");
    for node in [f, w] {
        node.node.shutdown().await;
    }
    mirror_server.shutdown().await;
    w_server.shutdown().await;
    Ok(())
}

/// Review 6, finding 3. W keeps a transition head; while it is stopped, the stored row is damaged (its cosignatures
/// unreadable - before, they became an empty list and W served the head without them) and a row is added for a size
/// where no change ends. After the restart W serves neither (verified again like a follower verifies them; the
/// useless row is deleted). While the owner is away W can not fetch it again; once the owner is back, W fetches the
/// head, serves it again and the verified head replaces the damaged row. (A row that was never stored - the node
/// stopped right after noting the head - is fetched again the same way.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_damaged_transition_head_is_not_served_and_fetched_again() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let w = net.add_node(&[]).await?;
    let j = change_manifest(&net, |manifest| manifest.logs = vec![net.owner.id(), w.id()]).await?;
    let last = ban(&net).await?;
    all_at(&[&net.owner, &w], last + 1).await?;
    let (status, served) = head_at(&w.url, &net.net, j + 1).await?;
    assert_eq!(status, 200);
    let good = served.ok_or("no head")?;
    assert!(!good.cosigns.is_empty());

    // Damage W's rows while it is stopped (once W has stored the row: it is written right after it is noted).
    let key = net.net.to_string();
    let w_db = w.dir.path().join(DB_FILE);
    bridge_tests::net::eventually("W stored the transition head", || async {
        let rows = Store::open(&w_db).and_then(|store| store.net_transitions(&key, 64)).map_err(e)?;
        if rows.iter().any(|row| row.size == j + 1) { Ok(()) } else { Err("not yet".to_owned()) }
    })
    .await?;
    let w_addr = w.node.local_addr();
    let TestNode { dir: w_dir, node: w_node, url: w_url } = w;
    w_node.shutdown().await;
    {
        let store = Store::open(&w_dir.path().join(DB_FILE)).map_err(e)?;
        let rows = store.net_transitions(&key, 64).map_err(e)?;
        let row = rows.iter().find(|row| row.size == j + 1).cloned().ok_or("no stored row")?;
        let damaged = TransitionRow { cosigns: br#"[{"kaputt""#.to_vec(), ..row.clone() };
        assert!(store.net_transition_put(&key, &damaged, 64).map_err(e)?);
        store.net_transition_put(&key, &TransitionRow { size: j, ..row }, 64).map_err(e)?;
    }
    // The owner goes away too: nobody to fetch the head from.
    let TestNet { net: id, owner, .. } = net;
    let TestNode { dir: owner_dir, node: owner_node, url: owner_url } = owner;
    let owner_addr = owner_node.local_addr();
    owner_node.shutdown().await;

    let w_config = test_config(w_dir.path(), Some(membership(&id, std::slice::from_ref(&owner_url))), &w_url);
    let w = TestNode { node: bridge_tests::start_node_on(w_config, w_addr).await?, dir: w_dir, url: w_url };
    for size in [j, j + 1] {
        assert_eq!(head_at(&w.url, &id, size).await?.0, 404, "size {size}: not served after the restart");
    }
    tokio::time::sleep(Duration::from_millis(600)).await; // a few sync rounds: nobody has it
    assert_eq!(head_at(&w.url, &id, j + 1).await?.0, 404);

    // The owner is back: W fetches the head again and serves it.
    let owner_config = test_config(owner_dir.path(), Some(membership(&id, &[])), &owner_url);
    let owner =
        TestNode { node: bridge_tests::start_node_on(owner_config, owner_addr).await?, dir: owner_dir, url: owner_url };
    bridge_tests::net::eventually("W serves the transition head again", || async {
        match head_at(&w.url, &id, j + 1).await? {
            (200, Some(head)) if head == good => Ok(()),
            other => Err(format!("{other:?}")),
        }
    })
    .await?;
    // The verified head replaces the damaged row (written right after it is noted), the useless row is gone.
    bridge_tests::net::eventually("the verified head replaced the damaged row", || async {
        let rows = Store::open(&w_db).and_then(|store| store.net_transitions(&key, 64)).map_err(e)?;
        let row = rows.iter().find(|row| row.size == j + 1).ok_or("row gone")?;
        let cosigns: Value = serde_json::from_slice(&row.cosigns).map_err(e)?;
        let replaced = cosigns.as_array().map(Vec::len) == Some(good.cosigns.len());
        if replaced && !rows.iter().any(|row| row.size == j) { Ok(()) } else { Err(format!("{cosigns}")) }
    })
    .await?;
    w.node.shutdown().await;
    owner.node.shutdown().await;
    Ok(())
}

/// A sync source that shows a fixed fork - head, entries, manifest - and counts what it is asked and what it hands
/// out from `/log` (requests and bytes). It has no transition heads.
#[derive(Default)]
struct ForkSource {
    head: Mutex<Option<Vec<u8>>>,
    entries: Mutex<Vec<Vec<u8>>>,
    manifest: Mutex<Option<Vec<u8>>>,
    head_requests: AtomicU64,
    log_requests: AtomicU64,
    log_bytes: AtomicUsize,
    transition_requests: AtomicU64,
}

impl bridge_transport::Handler for ForkSource {
    async fn handle(&self, request: Request) -> Response {
        let shown = |slot: &Mutex<Option<Vec<u8>>>| slot.lock().ok().and_then(|value| value.clone());
        let none = || Response::error(404, "NOT_FOUND", "none", None);
        if request.path.ends_with("/head") {
            self.head_requests.fetch_add(1, Ordering::SeqCst);
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
            return none();
        }
        if request.path.ends_with("/log") {
            self.log_requests.fetch_add(1, Ordering::SeqCst);
            let from = serde_json::from_slice::<Value>(&request.body)
                .ok()
                .and_then(|value| value.get("from").and_then(Value::as_u64))
                .unwrap_or(0);
            let entries: Vec<Vec<u8>> = self.entries.lock().ok().map(|entries| entries.clone()).unwrap_or_default();
            let page: Vec<String> = entries
                .iter()
                .skip(usize::try_from(from).unwrap_or(usize::MAX))
                .take(256)
                .map(|entry| bridge_core::encoding::b64(entry))
                .collect();
            let body = json!({"entries": page, "size": entries.len()}).to_string().into_bytes();
            self.log_bytes.fetch_add(body.len(), Ordering::SeqCst);
            return Response::ok(body);
        }
        none()
    }
}

/// What three fork sources were asked so far: (`/head`, `/log`, bytes from `/log`, `head/at`).
fn asked(sources: &[std::sync::Arc<ForkSource>]) -> (u64, u64, usize, u64) {
    sources.iter().fold((0, 0, 0, 0), |(heads, logs, bytes, at), source| {
        (
            heads + source.head_requests.load(Ordering::SeqCst),
            logs + source.log_requests.load(Ordering::SeqCst),
            bytes + source.log_bytes.load(Ordering::SeqCst),
            at + source.transition_requests.load(Ordering::SeqCst),
        )
    })
}

/// Review 6, finding 4. Three sources show the same forged suffix (the 24 words alone: the attacker's operator and
/// witness, the log rules switched to them) to a follower whose honest sources are gone. The first expensive try
/// (entries fetched, replayed, transition head asked from up to four nodes) refuses it; then the same head is not
/// fetched again from the next source, the transition head nobody had is not asked for again, and the source cools
/// down - for four sync rounds. Before, every source cost a full download, a replay and four `head/at` per round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_suffix_from_several_sources_costs_bounded_work() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let mut sources = Vec::new();
    let mut servers = Vec::new();
    let mut urls = Vec::new();
    for _ in 0..3 {
        let source = std::sync::Arc::new(ForkSource::default());
        let (server, url) = serve(source.clone()).await?;
        sources.push(source);
        servers.push(server);
        urls.push(url);
    }
    let follower = net.add_node(&urls).await?;
    ban(&net).await?;
    let real = net.admin.fetch_log(0, None).await?;
    all_at(&[&follower], real.len() as u64).await?;
    let TestNet { net: id, owner, master, .. } = net;
    owner.node.shutdown().await;

    // The fork (like review 5): the attacker's operator and witness sealed, the rules switched, one more entry.
    let (op2, w2) = (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
    let now = bridge_tests::now_ms();
    let card = |node: &Identity, url: &str| node.key_card_with(Role::Node, None, &[url.to_owned()], None, now);
    let sealed = |node: &Identity, services: &[Service], url: &str| -> Result<Vec<u8>, String> {
        let seal = Seal {
            subject: node.id().clone(),
            level: 3,
            services: Services::of(services),
            card: Some(card(node, url).map_err(e)?),
        };
        Ok(seal.sign(&id, now, now + 30 * DAY, &master).map_err(e)?.canonical_bytes().to_vec())
    };
    let mut fork = real.clone();
    fork.push(sealed(&op2, &[Service::Log], "https://evil.example")?);
    fork.push(sealed(&w2, &[Service::Witness], "https://evil2.example")?);
    let latest = fork
        .iter()
        .rev()
        .filter_map(|entry| Statement::parse(entry).ok())
        .find(|statement| statement.kind() == "manifest")
        .ok_or("no manifest")?;
    let mut manifest = Manifest::from_statement(&latest).map_err(e)?.next_version();
    (manifest.logs, manifest.witnesses, manifest.witness_threshold) =
        (vec![op2.id().clone()], vec![w2.id().clone()], 1);
    let change = manifest.sign(&id, now, now + 30 * DAY, &master).map_err(e)?;
    let index = fork.len() as u64;
    fork.push(change.canonical_bytes().to_vec());
    let extra = Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: String::new() };
    fork.push(extra.sign(&id, now, now + DAY, &master).map_err(e)?.canonical_bytes().to_vec());
    let log = Log::from_entries(id.clone(), &fork).map_err(e)?;
    let statement = issue_head(&op2, &id, log.size(), log.root(), now).map_err(e)?;
    let head = verify_head(&statement, &id, &op2.key_card(Role::Node, None, now).map_err(e)?).map_err(e)?;
    let fake = WitnessedHead { head: statement, cosigns: vec![issue_cosign(&w2, &head, now).map_err(e)?] };
    let head_bytes = bridge_core::json::canonical(&fake.to_value()).map_err(e)?;
    let manifest_bytes = json!({"manifest": change.to_value(), "index": index}).to_string().into_bytes();
    for source in &sources {
        *source.entries.lock().map_err(e)? = fork.clone();
        *source.head.lock().map_err(e)? = Some(head_bytes.clone());
        *source.manifest.lock().map_err(e)? = Some(manifest_bytes.clone());
    }

    wait_for("the fork was fetched once", || asked(&sources).1 > 0).await?;
    let (heads0, logs0, bytes0, at0) = asked(&sources);
    let one_download = bytes0 / usize::try_from(logs0).unwrap_or(1).max(1);
    let started = Instant::now();
    tokio::time::sleep(Duration::from_millis(2400)).await; // ~16 sync rounds of 150 ms
    let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (heads, logs, bytes, at) = asked(&sources);
    let (heads, logs, bytes, at) = (heads - heads0, logs - logs0, bytes - bytes0, at - at0);
    assert_eq!(follower.status().size, real.len() as u64, "the fork is not taken");
    // At most one download of this head per failure window (4 rounds = 600 ms): before, three per round.
    let windows = elapsed / 600 + 1;
    assert!(logs <= windows + 1, "{logs} downloads in {elapsed} ms ({heads} looks at the head)");
    assert!(heads >= 2 * logs, "the other sources were looked at, not downloaded: {heads} / {logs}");
    assert!(bytes <= (usize::try_from(logs).unwrap_or(0) + 1) * one_download, "{bytes} bytes");
    // The transition head: asked from at most the three sources (and the dead owner) per download.
    assert!(at <= 3 * (logs + 1), "{at} transition-head requests for {logs} downloads");
    follower.node.shutdown().await;
    for server in servers {
        server.shutdown().await;
    }
    Ok(())
}
