//! Regression tests for the 7th review of phase 4a (docs/07 "Review 7", ADR 0015): a version with files that exist
//! nowhere is paid for, asked for with bounded requests and dropped; versions that do not fit the node are dropped;
//! a complete host switch stops the old hosts; a removed host is not revived (also after a restart); a transient read
//! error is no data loss; the SDK skips a source that answers nonsense; expired upload pins do not count; nodes
//! without a network take no blobs unless switched on; a lowered app limit stops the surplus apps on start; apps per
//! owner are bounded; transport errors and too many streams carry the node's headers.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use bridge_core::app::{AppFile, AppManifest, FileType};
use bridge_core::blob::{HashList, MAX_BLOB_BYTES, PART_BYTES};
use bridge_core::encoding::b64;
use bridge_core::{BlobId, Id, Identity, SignedRequest};
use bridge_node::NodeConfig;
use bridge_sdk::{AppDraft, BlobSource, SdkError};
use bridge_store::{AppRow, AppState, Store};
use bridge_tests::apps::{
    AppNet, app_folder, counting_proxy, get, gone, header, node_behind, raw_get, served, wait_gateway,
};
use bridge_tests::net::{TestNode, eventually, test_config};
use bridge_tests::{client, now_ms, start_node};
use bridge_transport::{Handler, HttpClient, Request, Response, ServerConfig};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

const ENTRY: &[u8] = b"<!doctype html><h1>Hallo Bridge-App</h1>";

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn draft(version: u64, hosts: Vec<Id>) -> AppDraft {
    AppDraft { name: "Testspiel".into(), description: String::new(), entry: "index.html".into(), version, hosts }
}

fn node_code(result: &Result<impl std::fmt::Debug, SdkError>) -> String {
    match result {
        Err(SdkError::Node { code, .. }) => code.clone(),
        other => format!("{other:?}"),
    }
}

/// An entry file whose blob exists nowhere.
fn fake_file(size: u64) -> Result<AppFile, String> {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let blob = BlobId::parse(&b64(&raw)).map_err(e)?;
    Ok(AppFile { path: "index.html".into(), blob, size, kind: FileType::Html })
}

/// A further web host of the network with its own settings.
async fn custom_node(apps: &AppNet, change: impl FnOnce(&mut NodeConfig)) -> Result<TestNode, String> {
    let dir = tempfile::tempdir().map_err(e)?;
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let mut config = test_config(dir.path(), Some(apps.net.membership(&[])), &url);
    change(&mut config);
    let node = TestNode { node: bridge_node::start(config, listener).await?, dir, url };
    apps.net.synced(&node).await?;
    apps.net.seal_as(&node, "gateway,web").await?;
    Ok(node)
}

/// The database of a running node (a second connection - SQLite in WAL mode allows that).
fn store_of(node: &TestNode) -> Result<Store, String> {
    Store::open(&node.dir.path().join(bridge_node::DB_FILE)).map_err(e)
}

fn row_of(node: &TestNode, app: &Id) -> Result<Option<AppRow>, String> {
    store_of(node)?.app_get(app.as_str()).map_err(e)
}

async fn manifest_status(node: &TestNode, app: &Id) -> Result<u16, String> {
    let http = HttpClient::new(&node.url, Duration::from_secs(10)).map_err(e)?;
    let answer =
        http.post("/v4/app/manifest", None, json!({"app": app.as_str()}).to_string().into_bytes()).await.map_err(e)?;
    Ok(answer.status)
}

/// Review 7 #1: a version whose files exist nowhere costs the owner's quota at once (a 4 GiB one does not fit at
/// all), takes its place only while it waits, is asked for with a bounded number of requests (blob info once per
/// failed round, never a hash list from a host without the blob, never the full manifest of an equal version), and
/// is dropped after its failed rounds: place and reservation are free again, and it never comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_with_files_that_exist_nowhere_is_paid_bounded_and_dropped() -> TestResult {
    let apps = AppNet::new(0).await?;
    // The co-host sits behind a counting proxy (its card names the proxy): what the limited node asks it is counted.
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let real = format!("http://{}", listener.local_addr().map_err(e)?);
    let (proxy_server, proxy, proxy_url) = counting_proxy(&real).await?;
    let cohost = node_behind(&apps.net, &proxy_url, listener).await?;
    apps.net.seal_as(&cohost, "gateway,web").await?;
    wait_gateway(&cohost).await?;
    // The limited node: one app at most, short rounds (the pauses after failures grow from 2 to 16 rounds).
    let limited = custom_node(&apps, |config| {
        config.limits.max_hosted_apps = 1;
        if let Some(network) = config.network.as_mut() {
            network.timing.apps = Duration::from_millis(20);
        }
    })
    .await?;
    apps.net.synced(&cohost).await?;
    let client = apps.owner_at(&limited).await?;
    let owner = apps.owner().id().to_string();
    let hosts = vec![limited.id(), cohost.id()];

    // 4 GiB that exist nowhere do not fit level 0 (50 MiB): refused, nothing stored, nothing reserved.
    let huge = Identity::generate(&mut OsRng);
    let statement = client.sign_app(&huge, &draft(1, hosts.clone()), vec![fake_file(MAX_BLOB_BYTES)?]).map_err(e)?;
    assert_eq!(node_code(&client.publish_app(&statement).await), "QUOTA_EXCEEDED");
    assert_eq!(row_of(&limited, huge.id())?, None);
    // 10 MiB that exist nowhere: accepted (waiting), and 10 MiB of the owner's quota are reserved at once.
    let app = Identity::generate(&mut OsRng);
    let junk = client.sign_app(&app, &draft(1, hosts.clone()), vec![fake_file(10 << 20)?]).map_err(e)?;
    assert!(!client.publish_app(&junk).await.map_err(e)?.active);
    assert_eq!(store_of(&limited)?.blob_owner_bytes(&owner).map_err(e)?, 10 << 20);
    // While it waits it holds the only place.
    let (folder, _) = app_folder(10)?;
    let other = Identity::generate(&mut OsRng);
    let refused = client.publish_folder(&other, folder.path(), &draft(1, vec![limited.id()])).await;
    assert_eq!(node_code(&refused), "QUOTA_EXCEEDED");

    // Dropped after its failed rounds: no app any more, no reservation, only its rank is remembered.
    eventually("the waiting version is dropped", || async {
        match row_of(&limited, app.id())? {
            Some(row) if row.state == AppState::Stopped => Ok(row),
            other => Err(format!("{other:?}")),
        }
    })
    .await
    .map(|row| assert_eq!((row.version, row.current, row.pending), (1, None, None)))?;
    assert_eq!(manifest_status(&limited, app.id()).await?, 404);
    let left = store_of(&limited)?.blob_owner_bytes(&owner).map_err(e)?;
    assert_eq!(
        left,
        3 * bridge_store::CHARGED_MIN_BYTES,
        "reservation released (left: the uploads of the refused app)"
    );
    // Bounded: one blob info per failed round (12, some slack for timing), no hash list from a host that has no
    // such blob, the full manifest never (the co-host has the same version: the head form is enough).
    let info = proxy.count("/v4/blob/info");
    assert!((1..=30).contains(&info), "blob info asked {info} times");
    assert_eq!(proxy.count("/v4/blob/hashes"), 0);
    assert_eq!(proxy.count("/v4/app/manifest"), 0, "only the head form");
    assert!(proxy.count("/v4/app/manifest#head") >= 1);

    // The place is free again; the dropped version stays refused (no retry storm - the owner publishes anew).
    client.publish_folder(&other, folder.path(), &draft(1, vec![limited.id()])).await.map_err(e)?;
    served(&format!("{}/app/{}/", limited.url, other.id()), ENTRY).await?;
    assert_eq!(node_code(&client.publish_app(&junk).await), "REPLAY");
    proxy_server.shutdown().await;
    Ok(())
}

/// Review 7 #5: a waiting version whose files do not fit the node (its storage is full when it fetches them) is
/// dropped - the host stops instead of keeping it waiting forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_that_does_not_fit_the_node_is_dropped() -> TestResult {
    let apps = AppNet::new(0).await?;
    let small = custom_node(&apps, |config| config.limits.blobs.max_node_bytes = 100_000).await?;
    let owner_node = &apps.net.owner;
    let (folder, big) = app_folder(200_000)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(owner_node).await?;
    client.publish_folder(&app, folder.path(), &draft(1, vec![owner_node.id(), small.id()])).await.map_err(e)?;
    served(&format!("{}/app/{}/assets/big.bin", owner_node.url, app.id()), &big).await?;
    // The small node takes the offer (the owner's quota holds it), but its storage is full while fetching: it stops.
    eventually("the small node gives the version up", || async {
        match row_of(&small, app.id())? {
            Some(row) if row.state == AppState::Stopped && row.version == 1 => Ok(()),
            other => Err(format!("{other:?}")),
        }
    })
    .await?;
    assert_eq!(manifest_status(&small, app.id()).await?, 404);
    gone(&format!("{}/app/{}/", small.url, app.id())).await?;
    served(&format!("{}/app/{}/", owner_node.url, app.id()), ENTRY).await?;
    Ok(())
}

/// Review 7 #3: v1 [owner node, a] → v2 [b] (published at b, which never knew v1): the owner tells one old host
/// (`announce_app`); it stops and passes the version on to the other old host, which stops too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_complete_host_switch_stops_the_old_hosts() -> TestResult {
    let apps = AppNet::new(2).await?;
    let (owner_node, a, b) = (&apps.net.owner, &apps.hosts[0], &apps.hosts[1]);
    let (folder, _) = app_folder(10)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(owner_node).await?;
    client.publish_folder(&app, folder.path(), &draft(1, vec![owner_node.id(), a.id()])).await.map_err(e)?;
    served(&format!("{}/app/{}/", owner_node.url, app.id()), ENTRY).await?;
    served(&format!("{}/app/{}/", a.url, app.id()), ENTRY).await?;
    let at_b = apps.owner_at(b).await?;
    let (v2, published) = at_b.publish_folder(&app, folder.path(), &draft(2, vec![b.id()])).await.map_err(e)?;
    assert!(published.active);
    // Nobody the old hosts know has v2: they keep serving until they are told.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(get(&format!("{}/app/{}/", a.url, app.id())).await?.0, 200);
    let told = bridge_sdk::announce_app(&BlobSource::new(&owner_node.url).map_err(e)?, &v2).await.map_err(e)?;
    assert_eq!((told.active, told.hosted), (false, false));
    gone(&format!("{}/app/{}/", owner_node.url, app.id())).await?;
    gone(&format!("{}/app/{}/", a.url, app.id())).await?;
    served(&format!("{}/app/{}/", b.url, app.id()), ENTRY).await?;
    // Both remember the version that removed them.
    for node in [owner_node, a] {
        let rank = eventually("the stop is stored", || async {
            match row_of(node, app.id())? {
                Some(row) if row.state == AppState::Stopped => Ok((row.version, row.hash)),
                other => Err(format!("{other:?}")),
            }
        })
        .await?;
        assert_eq!(rank, (2, Some(v2.hash_bytes())));
    }
    // Telling a node about an app it does not host: 404, nothing verified or stored.
    let other = bridge_sdk::announce_app(&BlobSource::new(&a.url).map_err(e)?, &v2).await;
    assert_eq!(node_code(&other), "NOT_FOUND");
    Ok(())
}

/// Review 7 #2 and #8: a host removed by v2 keeps the rank of v2 (and nothing else of the app): another host's
/// signed offer of v1 is refused - also after a restart - and nothing is served again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_host_is_not_revived_with_an_old_version() -> TestResult {
    let mut apps = AppNet::new(2).await?;
    let (folder, _) = app_folder(10)?;
    let app = Identity::generate(&mut OsRng);
    let all = vec![apps.net.owner.id(), apps.hosts[0].id(), apps.hosts[1].id()];
    let client = apps.owner_at(&apps.net.owner).await?;
    let (v1, _) = client.publish_folder(&app, folder.path(), &draft(1, all)).await.map_err(e)?;
    for node in apps.all() {
        served(&format!("{}/app/{}/", node.url, app.id()), ENTRY).await?;
    }
    let files: Vec<AppFile> = AppManifest::from_body(v1.body()).map_err(e)?.files;
    let a = &apps.hosts[0];
    let at_a = apps.owner_at(a).await?;
    let v2 = at_a.sign_app(&app, &draft(2, vec![apps.net.owner.id(), a.id()]), files).map_err(e)?;
    at_a.publish_app(&v2).await.map_err(e)?;
    let b = &apps.hosts[1];
    gone(&format!("{}/app/{}/", b.url, app.id())).await?;
    // Serving stops at once (memory), the row follows right after.
    let row = eventually("b stored the stop", || async {
        match row_of(b, app.id())? {
            Some(row) if row.state == AppState::Stopped => Ok(row),
            other => Err(format!("{other:?}")),
        }
    })
    .await?;
    assert_eq!((row.version, row.hash), (2, Some(v2.hash_bytes())));
    assert_eq!((row.current, row.previous, row.pending), (None, None, None), "only ID, owner and rank");

    // Host a (a host of v1 as well) offers v1 to b: refused.
    let a_identity = bridge_node::keyfile::load_or_create(a.dir.path())?;
    let offer = |target: Id| -> Result<Vec<u8>, String> {
        let rq = SignedRequest::sign(&a_identity, &target, "app", json!({"manifest": v1.hash()}), now_ms(), &mut OsRng)
            .map_err(e)?;
        Ok(json!({"manifest": v1.to_value(), "rq": rq.to_value()}).to_string().into_bytes())
    };
    let http = HttpClient::new(&b.url, Duration::from_secs(20)).map_err(e)?;
    let answer = http.post("/v4/node/app", None, offer(b.id())?).await.map_err(e)?;
    assert_eq!((answer.status, bridge_tests::code(&answer)), (409, "REPLAY".to_owned()));
    assert_eq!(get(&format!("{}/app/{}/", b.url, app.id())).await?.0, 404);
    // After a restart the rank is still there.
    let b = apps.hosts.remove(1);
    let b = b.restart(Some(apps.net.membership(&[]))).await?;
    apps.net.synced(&b).await?;
    let http = HttpClient::new(&b.url, Duration::from_secs(20)).map_err(e)?;
    let answer = http.post("/v4/node/app", None, offer(b.id())?).await.map_err(e)?;
    assert_eq!((answer.status, bridge_tests::code(&answer)), (409, "REPLAY".to_owned()));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(get(&format!("{}/app/{}/", b.url, app.id())).await?.0, 404);
    Ok(())
}

/// Review 7 #4: a blob file that is away for a moment is no data loss (503 meanwhile, served again at once when it
/// is back); a part that does not verify is dropped, but when the file is right again the host takes it from its own
/// disk before fetching anything (here there is no other host to fetch from).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transient_read_error_is_no_data_loss() -> TestResult {
    let apps = AppNet::new(0).await?;
    let node = &apps.net.owner;
    let (folder, _) = app_folder(10)?;
    let app = Identity::generate(&mut OsRng);
    let client = apps.owner_at(node).await?;
    client.publish_folder(&app, folder.path(), &draft(1, vec![node.id()])).await.map_err(e)?;
    let url = format!("{}/app/{}/", node.url, app.id());
    served(&url, ENTRY).await?;
    let hex = HashList::of(ENTRY).map_err(e)?.id().hex();
    let folder_of_blob = node.dir.path().join(bridge_node::BLOB_DIR).join(&hex[..2]);
    let (file, aside) = (folder_of_blob.join(&hex), node.dir.path().join("aside"));
    std::fs::rename(&file, &aside).map_err(e)?;
    let (during, headers, _) = get(&url).await?;
    assert_eq!(during, 503, "a read error is no proof of loss");
    assert_eq!(header(&headers, "content-security-policy"), bridge_node::APP_CSP);
    std::fs::rename(&aside, &file).map_err(e)?;
    let (after, _, body) = get(&url).await?;
    assert_eq!((after, body.as_slice()), (200, ENTRY), "nothing was changed: served again at once");

    // A part that does not verify is dropped (never served) ...
    let mut damaged = ENTRY.to_vec();
    damaged[3] ^= 0x20;
    std::fs::write(&file, &damaged).map_err(e)?;
    let (status, _, body) = get(&url).await?;
    assert!(status != 200 && body != damaged, "{status}");
    // ... and when the file is right again, the next round takes it from the own disk (the file is `.part` now).
    std::fs::write(folder_of_blob.join(format!("{hex}.part")), ENTRY).map_err(e)?;
    served(&url, ENTRY).await?;
    bridge_tests::net::wait_for("complete again: final name", || file.exists()).await?;
    Ok(())
}

/// A source that answers nonsense to every blob request.
struct Nonsense;

impl Handler for Nonsense {
    async fn handle(&self, request: Request) -> Response {
        match request.path.as_str() {
            "/v4/blob/info" if request.body.windows(4).any(|w| w == b"skip") => Response::ok(b"{}".to_vec()),
            "/v4/blob/info" => Response::ok(br#"{"size":"viel","parts":1,"complete":true}"#.to_vec()),
            "/v4/blob/hashes" => Response::ok(br#"{"from":0,"hashes":["kein hash!"]}"#.to_vec()),
            _ => Response::error(404, "NOT_FOUND", "not found", None),
        }
    }
}

/// A source that tells the right size but sends a broken hash page.
struct BrokenHashes(u64);

impl Handler for BrokenHashes {
    async fn handle(&self, request: Request) -> Response {
        match request.path.as_str() {
            "/v4/blob/info" => {
                Response::ok(json!({"size": self.0, "parts": 3, "complete": true}).to_string().into_bytes())
            }
            "/v4/blob/hashes" => Response::ok(br#"{"from":0,"hashes":["!!","??","%%"]}"#.to_vec()),
            _ => Response::error(404, "NOT_FOUND", "not found", None),
        }
    }
}

/// Review 7 #6: one source that answers nonsense (no size, a broken hash) does not abort a download - the next
/// source is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_download_skips_a_source_that_answers_nonsense() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut config = NodeConfig::new(dir.path());
    config.limits.standalone_blobs = Some(1 << 30);
    let node = start_node(config).await?;
    let alice = client(&node).await?;
    let data: Vec<u8> = (0..2 * PART_BYTES + 99).map(|i| (i % 241) as u8).collect();
    let id = alice.upload_blob(&data, 1).await.map_err(e)?;
    let mut servers = Vec::new();
    let mut sources = Vec::new();
    for bad in [0, 1] {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
        let url = format!("http://{}", listener.local_addr().map_err(e)?);
        let server = if bad == 0 {
            bridge_transport::serve(listener, ServerConfig::default(), Arc::new(Nonsense))
        } else {
            bridge_transport::serve(listener, ServerConfig::default(), Arc::new(BrokenHashes(data.len() as u64)))
        };
        servers.push(server.map_err(e)?);
        sources.push(BlobSource::new(&url).map_err(e)?);
    }
    sources.push(BlobSource::new(&bridge_tests::url(&node)).map_err(e)?);
    let list = bridge_sdk::fetch_hash_list(&sources, &id).await.map_err(e)?;
    assert_eq!(list.id(), id);
    // Parts: the bad sources hand none out (404), the good one all of them.
    assert_eq!(bridge_sdk::fetch_blob(&sources, &id, 1 << 20).await.map_err(e)?, data);
    let target = tempfile::tempdir().map_err(e)?;
    let report = bridge_sdk::download_blob(&sources, &id, &target.path().join("blob")).await.map_err(e)?;
    assert_eq!(report.fetched, 3);
    assert!(bridge_sdk::fetch_hash_list(&sources[..2], &id).await.is_err(), "nonsense alone is no hash list");
    for server in servers {
        server.shutdown().await;
    }
    node.shutdown().await;
    Ok(())
}

/// A clock the test moves.
struct ManualClock(AtomicI64);

impl bridge_node::Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Review 7 #10 and #11: a node without a network takes no blobs unless switched on (then with its cap for all
/// blobs together); an upload pin that ran out does not allow parts any more, even before the garbage collection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blobs_without_a_network_and_expired_pins() -> TestResult {
    // Off by default.
    let dir = tempfile::tempdir().map_err(e)?;
    let node = start_node(NodeConfig::new(dir.path())).await?;
    let alice = client(&node).await?;
    assert_eq!(node_code(&alice.upload_blob(b"hallo", 1).await), "FORBIDDEN");
    let http = bridge_tests::raw(&node)?;
    let chunk = json!({"blob": HashList::of(b"x").map_err(e)?.id().to_text(), "i": 0, "data": b64(b"x")});
    let answer = http.post("/v4/blob/chunk", alice.session_token(), chunk.to_string().into_bytes()).await.map_err(e)?;
    assert_eq!(answer.status, 403);
    node.shutdown().await;

    // On, with a cap of 100 KB for the node: a blob over it does not fit, one under it does.
    let dir = tempfile::tempdir().map_err(e)?;
    let clock = Arc::new(ManualClock(AtomicI64::new(now_ms())));
    let mut config = NodeConfig::new(dir.path());
    config.limits.standalone_blobs = Some(100_000);
    config.clock = clock.clone();
    config.session_lifetime_ms = 3 * 24 * 3600 * 1000; // the session must outlive the jump of the clock
    let node = start_node(config).await?;
    let alice = client(&node).await?;
    assert_eq!(node_code(&alice.upload_blob(&vec![1u8; 150_000], 1).await), "QUOTA_EXCEEDED");
    let data: Vec<u8> = (0..PART_BYTES + 10).map(|i| (i % 7) as u8).collect();
    let list = HashList::of(&data).map_err(e)?;
    let hashes: Vec<String> = list.hashes().iter().map(|hash| b64(hash)).collect();
    let begin = json!({"blob": list.id().to_text(), "size": list.size(), "hashes": hashes, "keep_days": 1});
    let http = bridge_tests::raw(&node)?;
    assert_eq!(
        http.post("/v4/blob/begin", alice.session_token(), begin.to_string().into_bytes()).await.map_err(e)?.status,
        200
    );
    // A day and a bit later (the janitor has not run): the pin no longer counts, parts are refused.
    clock.0.fetch_add(24 * 3600 * 1000 + 1, Ordering::SeqCst);
    let part = json!({"blob": list.id().to_text(), "i": 0, "data": b64(&data[..PART_BYTES])});
    let answer = http.post("/v4/blob/chunk", alice.session_token(), part.to_string().into_bytes()).await.map_err(e)?;
    assert_eq!(answer.status, 404, "an expired pin is no pin");
    node.shutdown().await;
    Ok(())
}

/// Review 7 #12: a lowered `max_hosted_apps` stops the surplus apps on start - deterministically, the most recently
/// changed stay - instead of leaving them "active" and pinned forever; raising it again does not bring them back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lowered_app_limit_stops_the_surplus_on_start() -> TestResult {
    let mut apps = AppNet::new(1).await?;
    let host = apps.hosts.remove(0);
    let client = apps.owner_at(&host).await?;
    let (folder, _) = app_folder(10)?;
    let (older, newer) = (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
    for app in [&older, &newer] {
        client.publish_folder(app, folder.path(), &draft(1, vec![host.id()])).await.map_err(e)?;
        served(&format!("{}/app/{}/", host.url, app.id()), ENTRY).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let restart = |host: TestNode, max: u64| {
        let membership = apps.net.membership(&[]);
        async move {
            let addr = host.node.local_addr();
            host.node.shutdown().await;
            let mut config = test_config(host.dir.path(), Some(membership), &host.url);
            config.limits.max_hosted_apps = max;
            let node = bridge_tests::start_node_on(config, addr).await?;
            Ok::<_, String>(TestNode { node, dir: host.dir, url: host.url })
        }
    };
    let host = restart(host, 1).await?;
    apps.net.synced(&host).await?;
    served(&format!("{}/app/{}/", host.url, newer.id()), ENTRY).await?;
    assert_eq!(get(&format!("{}/app/{}/", host.url, older.id())).await?.0, 404);
    let row = row_of(&host, older.id())?.ok_or("row forgotten")?;
    assert_eq!((row.state, row.version, row.current), (AppState::Stopped, 1, None));
    let holder = format!("{}{}", bridge_store::APP_PIN_PREFIX, older.id());
    assert_eq!(store_of(&host)?.blob_unpin(&holder).map_err(e)?, 0, "its pins went with it");
    let host = restart(host, 64).await?;
    apps.net.synced(&host).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(get(&format!("{}/app/{}/", host.url, older.id())).await?.0, 404, "stopped for good");
    served(&format!("{}/app/{}/", host.url, newer.id()), ENTRY).await?;
    Ok(())
}

/// Review 7 #1: apps per owner and node are bounded by the owner's level (level 0: 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apps_per_owner_are_bounded_by_level() -> TestResult {
    let apps = AppNet::new(0).await?;
    let node = &apps.net.owner;
    let client = apps.owner_at(node).await?;
    let (folder, _) = app_folder(10)?;
    for _ in 0..4 {
        let app = Identity::generate(&mut OsRng);
        client.publish_folder(&app, folder.path(), &draft(1, vec![node.id()])).await.map_err(e)?;
    }
    let fifth = Identity::generate(&mut OsRng);
    let refused = client.publish_folder(&fifth, folder.path(), &draft(1, vec![node.id()])).await;
    assert_eq!(node_code(&refused), "QUOTA_EXCEEDED");
    Ok(())
}

/// Review 7 #9 and #13: too many streams of one address are refused with the sandbox headers, a slow reader of an
/// app file is cut off; `/app/<id>` without a network is 404 (no redirect); errors the transport makes itself carry
/// CORS under `/v4/`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_and_transport_errors_carry_the_nodes_headers() -> TestResult {
    let apps = AppNet::new(0).await?;
    let host = custom_node(&apps, |config| {
        config.server.max_streams_per_address = 1;
        config.server.stream_min_bytes_per_s = 64 << 20;
        config.server.stream_grace = Duration::from_millis(500);
    })
    .await?;
    let client = apps.owner_at(&host).await?;
    let (folder, big) = app_folder(32 << 20)?;
    let app = Identity::generate(&mut OsRng);
    client.publish_folder(&app, folder.path(), &draft(1, vec![host.id()])).await.map_err(e)?;
    let path = format!("/app/{}/assets/big.bin", app.id());
    // A reader that takes nothing holds the only stream of its address: a second one is refused (sandboxed) ...
    let mut slow = tokio::net::TcpStream::connect(host.node.local_addr()).await.map_err(e)?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    slow.write_all(request.as_bytes()).await.map_err(e)?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, head) = raw_get(host.node.local_addr(), &path).await?;
    assert_eq!(status, 429, "{head}");
    assert!(head.contains("content-security-policy: sandbox") && head.contains("access-control-allow-origin: *"));
    // ... and it is cut off long before 32 MiB went out.
    let mut total = 0usize;
    let mut buffer = vec![0u8; 1 << 16];
    tokio::time::sleep(Duration::from_secs(2)).await;
    while let Ok(Ok(read)) = tokio::time::timeout(Duration::from_secs(10), slow.read(&mut buffer)).await {
        if read == 0 {
            break;
        }
        total += read;
    }
    assert!(total < big.len(), "cut off after {total} bytes");
    let (status, _, body) = get(&format!("{}{path}", host.url)).await?;
    assert_eq!((status, body.len()), (200, big.len()), "a reader that reads gets it all");

    // Errors made by the transport: CORS under `/v4/`.
    let put = reqwest::Client::new().put(format!("{}/v4/info", host.url)).send().await.map_err(e)?;
    assert_eq!(put.status().as_u16(), 405);
    assert_eq!(header(put.headers(), "access-control-allow-origin"), "*");
    // Declared too large: answered before the body is read (raw - a client would fail sending the body).
    let mut large = tokio::net::TcpStream::connect(host.node.local_addr()).await.map_err(e)?;
    let request = "POST /v4/send HTTP/1.1\r\nHost: t\r\nContent-Length: 2097152\r\nConnection: close\r\n\r\n";
    large.write_all(request.as_bytes()).await.map_err(e)?;
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), large.read_to_end(&mut answer)).await;
    let answer = String::from_utf8_lossy(&answer).to_ascii_lowercase();
    assert!(answer.starts_with("http/1.1 413"), "{answer}");
    assert!(answer.contains("access-control-allow-origin: *"), "{answer}");

    // Without a network there are no apps - not even the redirect.
    let dir = tempfile::tempdir().map_err(e)?;
    let alone = start_node(NodeConfig::new(dir.path())).await?;
    let (status, head) = raw_get(alone.local_addr(), &format!("/app/{}", app.id())).await?;
    assert_eq!(status, 404, "{head}");
    assert!(!head.contains("location:"));
    assert!(head.contains("content-security-policy: sandbox"));
    alone.shutdown().await;
    Ok(())
}
