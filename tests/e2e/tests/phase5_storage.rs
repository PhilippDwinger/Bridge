//! Phase 5 acceptance, storage (docs/05, docs/09, ADR 0019): a member stores a file encrypted and erasure-coded on 10
//! storage nodes of different hosts; with any 4 of them gone the file comes back; the audit finds the missing shards;
//! the repair puts them on new nodes; a node that answers false data is found by the audit.

use bridge_core::{Id, Identity};
use bridge_net::Member;
use bridge_node::admin::YEAR_MS;
use bridge_sdk::storage::{self, Holder, ShardState};
use bridge_tests::net::{TestNet, TestNode};
use rand_core::OsRng;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 255) as u8).collect()
}

/// `count` storage nodes on the loopback addresses 127.0.0.`first`…, each sealed `gateway,storage`.
async fn storage_nodes(net: &TestNet, first: u8, count: u8) -> Result<Vec<TestNode>, String> {
    let mut nodes = Vec::new();
    for i in 0..count {
        let node = net.add_node_at(&format!("127.0.0.{}", first + i), &[]).await?;
        net.seal_as(&node, "gateway,storage").await?;
        nodes.push(node);
    }
    Ok(nodes)
}

fn holders(nodes: &[TestNode]) -> Vec<Holder> {
    nodes.iter().map(|node| Holder { node: node.id(), urls: vec![node.url.clone()] }).collect()
}

/// A member of the network (admitted by the admin).
async fn member(net: &TestNet) -> Result<Identity, String> {
    let identity = Identity::generate(&mut OsRng);
    let statement = net.admin.sign(&Member { member: identity.id().clone(), invite: None }, YEAR_MS)?;
    net.admin.submit(&statement).await?;
    Ok(identity)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_file_survives_four_of_ten_nodes() -> TestResult {
    let net = TestNet::create(bridge_net::JoinMode::Invite).await?;
    let owner = member(&net).await?;
    let mut nodes = storage_nodes(&net, 20, 10).await?;
    for node in &nodes {
        net.synced(node).await?;
    }
    let input = data(300_000);
    let map = storage::store(&owner, &net.net, &input, &holders(&nodes), 6, 4).await.map_err(e)?;
    assert_eq!((map.k, map.m, map.shards.len()), (6, 4, 10));
    // The map travels as JSON (owner-only) and holds no plaintext.
    let json = map.to_json().map_err(e)?;
    assert!(!json.windows(64).any(|window| input.windows(64).next() == Some(window)));
    let map = storage::StorageMap::from_json(&json).map_err(e)?;
    assert_eq!(storage::audit(&map).await, vec![ShardState::Ok; 10]);
    assert_eq!(storage::fetch(&map).await.map_err(e)?, input);

    // Four nodes go away (data shards and parity shards mixed): the file is still there.
    for index in [9, 5, 2, 0] {
        nodes.remove(index).node.shutdown().await;
    }
    assert_eq!(storage::fetch(&map).await.map_err(e)?, input, "any 6 of 10 are enough");
    let states = storage::audit(&map).await;
    assert_eq!(states.iter().filter(|state| **state == ShardState::Missing).count(), 4, "{states:?}");

    // Repair: the four shards are computed again and go to four new nodes on other hosts.
    let fresh = storage_nodes(&net, 40, 4).await?;
    let mut candidates = holders(&nodes);
    candidates.extend(holders(&fresh));
    let (repaired, report) = storage::repair(&owner, &map, &candidates).await.map_err(e)?;
    assert_eq!(report.moved, vec![0, 2, 5, 9]);
    assert_eq!(storage::audit(&repaired).await, vec![ShardState::Ok; 10]);
    // Now even four more may go.
    for _ in 0..4 {
        nodes.remove(0).node.shutdown().await;
    }
    assert_eq!(storage::fetch(&repaired).await.map_err(e)?, input);
    Ok(())
}

/// Attack: a fifth of a shard swapped on disk (a node that lies about what it stores) - the audit says `False` or
/// `Missing` for it (a damaged part is never served, docs/07 §1), the file still comes back, the repair moves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lying_node_is_found_and_left() -> TestResult {
    let net = TestNet::create(bridge_net::JoinMode::Invite).await?;
    let owner = member(&net).await?;
    let nodes = storage_nodes(&net, 60, 4).await?;
    let input = data(70_000);
    let map = storage::store(&owner, &net.net, &input, &holders(&nodes[..3]), 2, 1).await.map_err(e)?;
    // The first holder replaces every blob file on its disk with garbage.
    let liar = &nodes[0];
    let blob_dir = liar.dir.path().join(bridge_node::BLOB_DIR);
    let mut damaged = 0;
    for entry in walk(&blob_dir)? {
        std::fs::write(&entry, vec![0x5A; std::fs::metadata(&entry).map_err(e)?.len() as usize]).map_err(e)?;
        damaged += 1;
    }
    assert!(damaged > 0);
    let states = storage::audit(&map).await;
    assert_ne!(states[0], ShardState::Ok, "{states:?}");
    assert_eq!(&states[1..], &[ShardState::Ok, ShardState::Ok]);
    assert_eq!(storage::fetch(&map).await.map_err(e)?, input);
    let (repaired, report) = storage::repair(&owner, &map, &holders(&nodes)).await.map_err(e)?;
    assert_eq!(report.moved, vec![0]);
    assert_eq!(repaired.shards[0].holder.node, nodes[3].id());
    assert_ne!(repaired.shards[0].holder.node, Id::parse(liar.id().as_str()).map_err(e)?);
    assert_eq!(storage::audit(&repaired).await, vec![ShardState::Ok; 3]);
    Ok(())
}

fn walk(dir: &std::path::Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(e)? {
        let path = entry.map_err(e)?.path();
        if path.is_dir() {
            files.extend(walk(&path)?);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

/// Phase 5 acceptance (docs/05): a node started with `--probe storage` gets level 1 with `storage` from the watcher
/// after passing its probes (the watcher placed a probe blob there and checks random parts of it); then it throws
/// away what it stored - the next probes fail and the watcher revokes its seal: it loses its level.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lying_storage_node_loses_its_level() -> TestResult {
    use bridge_net::{JoinMode, Service, Services, WatchRules};
    use bridge_tests::net::{eventually, test_config, wait_for};

    let net = TestNet::create(JoinMode::Open).await?;
    let services = bridge_node::admin::parse_services("gateway,log,witness,watch")?;
    net.admin.seal(&net.owner.url, &net.owner.id(), 3, services).await?;
    let (_, state) = net.admin.load_state().await?;
    let mut manifest = state.manifest().next_version();
    manifest.watch = Some(WatchRules {
        member_age_s: 3600,
        probe_interval_s: 1,
        node_observe_s: 3,
        success_pct: 90,
        fail_limit: 2,
        seal_s: 120,
        renew_s: 60,
        seals_per_day: 100,
    });
    net.admin.submit(&net.admin.sign(&manifest, YEAR_MS)?).await?;
    wait_for("watch rules", || net.owner.status().manifest_version == 2).await?;

    let dir = tempfile::tempdir().map_err(e)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let mut config = test_config(dir.path(), Some(net.membership(&[])), &url);
    config.probe = Some(Services::of(&[Service::Storage]));
    let node = TestNode { node: bridge_node::start(config, listener).await?, dir, url };
    let node_id = node.id();
    let storage_node = |state: &bridge_net::NetState| {
        state
            .seals(&node_id, bridge_tests::now_ms())
            .iter()
            .any(|(level, services)| *level >= 1 && services.has(Service::Storage))
    };
    let sealed = eventually("level 1 with storage", || async {
        let state = net.admin.load_state().await?.1;
        if storage_node(&state) {
            return state.seal_info(&node_id, 1).ok_or_else(|| "no seal".to_owned());
        }
        Err(format!("level {:?}", state.level(&node_id, bridge_tests::now_ms())))
    })
    .await?;
    assert_eq!(sealed.issuers, [net.owner.id()], "sealed by the watcher");
    assert!(node.dir.path().join(bridge_node::BLOB_DIR).exists(), "the probe blob is stored there");

    // The node lies: everything it stores is gone (as if it had thrown the data away).
    std::fs::remove_dir_all(node.dir.path().join(bridge_node::BLOB_DIR)).map_err(e)?;
    eventually("the watcher revoked the seal", || async {
        let state = net.admin.load_state().await?.1;
        if state.is_revoked(&sealed.hash) && !storage_node(&state) {
            return Ok(());
        }
        Err(format!("level {:?}", state.level(&node_id, bridge_tests::now_ms())))
    })
    .await?;
    Ok(())
}

/// Attack: only a watcher of the network places probe blobs; strangers, wrong operations and oversized data are
/// refused, and nothing is stored for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_blobs_only_from_watchers() -> TestResult {
    use bridge_core::SignedRequest;
    use bridge_core::encoding::b64;
    use serde_json::json;

    let net = TestNet::create(bridge_net::JoinMode::Open).await?;
    let node = net.add_node(&[]).await?;
    let http = bridge_tests::raw(&node.node)?;
    let send = |signer: &Identity, op: &str, data: Vec<u8>| -> Result<Vec<u8>, String> {
        let request = SignedRequest::sign(
            signer,
            &node.id(),
            op,
            json!({"data": b64(&data)}),
            bridge_tests::now_ms(),
            &mut OsRng,
        )
        .map_err(e)?;
        request.to_bytes().map_err(e)
    };
    let stranger = Identity::generate(&mut OsRng);
    let answer =
        http.post("/v4/storage/probe", None, send(&stranger, "storage-probe", vec![1; 1000])?).await.map_err(e)?;
    assert_eq!(answer.status, 403, "not a watcher");
    // The owner node is no watcher here either (no `watch` seal).
    let owner_key =
        bridge_node::keyfile::load_or_create_at(&net.owner.dir.path().join(bridge_node::keyfile::KEY_FILE))?;
    let answer =
        http.post("/v4/storage/probe", None, send(&owner_key, "storage-probe", vec![1; 1000])?).await.map_err(e)?;
    assert_eq!(answer.status, 403);
    let answer = http.post("/v4/storage/probe", None, send(&stranger, "watch", vec![1; 10])?).await.map_err(e)?;
    assert_eq!(answer.status, 400, "wrong op");
    let answer = http.post("/v4/storage/probe", None, vec![b'{'; 70_000]).await.map_err(e)?;
    assert!(answer.status == 413 || answer.status == 400, "{}", answer.status);
    assert!(!node.dir.path().join(bridge_node::BLOB_DIR).exists(), "nothing stored");
    Ok(())
}
