//! End-to-end regression tests for review 4 (each failed before its fix): a sync source serving junk heads makes a
//! follower neither download entries nor copy its state (finding 1); a manifest change to witnesses that are not
//! sealed for it is refused, and a network whose witnesses are lost runs again after the rescue with the 24 words,
//! while the net key's cosignature counts for nothing else (finding 3); re-sealing keeps level and services
//! (finding 4).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bridge_core::{Id, Identity, Statement};
use bridge_net::{Ban, Body, JoinMode, Log, Manifest, Service, Services, WitnessedHead, issue_cosign, issue_head};
use bridge_node::admin::{RulesChange, seal_defaults};
use bridge_tests::net::{TestNet, TestNode, wait_for};
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

/// The whole log of the owner (as an honest source would serve it).
async fn entries_of(net: &TestNet) -> Result<Vec<Vec<u8>>, String> {
    net.admin.fetch_log(0, None).await
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
    let card = operator.key_card(bridge_core::Role::Node, None, now).map_err(e)?;
    let head = bridge_net::verify_head(&statement, net, &card).map_err(e)?;
    let cosigns = witnesses.iter().map(|w| issue_cosign(w, &head, now)).collect::<Result<_, _>>().map_err(e)?;
    Ok(WitnessedHead { head: statement, cosigns })
}

/// A sync source that shows whatever the test gives it and counts what it hands out from `/log`.
#[derive(Default)]
struct JunkSource {
    head: Mutex<Option<Vec<u8>>>,
    entries: Mutex<Vec<Vec<u8>>>,
    manifest: Mutex<Option<Vec<u8>>>,
    log_requests: AtomicU64,
    log_bytes: AtomicU64,
}

impl bridge_transport::Handler for JunkSource {
    async fn handle(&self, request: bridge_transport::Request) -> bridge_transport::Response {
        use bridge_transport::Response;
        let shown = |slot: &Mutex<Option<Vec<u8>>>| slot.lock().ok().and_then(|value| value.clone());
        if request.path.ends_with("/head") {
            return shown(&self.head).map_or_else(|| Response::error(404, "NOT_FOUND", "none", None), Response::ok);
        }
        if request.path.ends_with("/manifest") {
            return shown(&self.manifest).map_or_else(|| Response::error(404, "NOT_FOUND", "none", None), Response::ok);
        }
        if request.path.ends_with("/evidence") {
            return Response::ok(br#"{"evidence":[]}"#.to_vec());
        }
        if request.path.ends_with("/log") {
            let from = serde_json::from_slice::<Value>(&request.body)
                .ok()
                .and_then(|value| value.get("from").and_then(Value::as_u64))
                .unwrap_or(0);
            let entries: Vec<Vec<u8>> = self.entries.lock().ok().map(|entries| entries.clone()).unwrap_or_default();
            let page: Vec<&Vec<u8>> =
                entries.iter().skip(usize::try_from(from).unwrap_or(usize::MAX)).take(256).collect();
            self.log_requests.fetch_add(1, Ordering::SeqCst);
            let bytes: usize = page.iter().map(|entry| entry.len()).sum();
            self.log_bytes.fetch_add(bytes as u64, Ordering::SeqCst);
            let page: Vec<String> = page.iter().map(|entry| bridge_core::encoding::b64(entry)).collect();
            return Response::ok(json!({"entries": page, "size": entries.len()}).to_string().into_bytes());
        }
        Response::error(404, "NOT_FOUND", "not found", None)
    }
}

impl JunkSource {
    fn show(&self, entries: &[Vec<u8>], head: &WitnessedHead, manifest: Option<(&Statement, u64)>) -> TestResult {
        *self.entries.lock().map_err(e)? = entries.to_vec();
        *self.head.lock().map_err(e)? = Some(bridge_core::json::canonical(&head.to_value()).map_err(e)?);
        *self.manifest.lock().map_err(e)? = manifest.map(|(statement, index)| {
            json!({"manifest": statement.to_value(), "index": index}).to_string().into_bytes()
        });
        Ok(())
    }

    fn fetched(&self) -> (u64, u64) {
        (self.log_requests.load(Ordering::SeqCst), self.log_bytes.load(Ordering::SeqCst))
    }
}

/// Junk heads from a source make a follower fetch nothing and copy nothing: unknown operators, with no, an old,
/// a forged, a gateway's or a stranger's "newer" manifest. Even with the stolen keys of the operator and witness
/// (so the head passes and the entries are fetched), junk manifests cost a bounded number of checks: an old genuine
/// manifest is followed without a copy, a flood of forged ones is refused without a copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_junk_source_causes_no_downloads_and_no_state_copies() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let source = std::sync::Arc::new(JunkSource::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let server =
        bridge_transport::serve(listener, bridge_transport::ServerConfig::default(), source.clone()).map_err(e)?;
    let junk_url = format!("http://{}", server.local_addr());
    let gateway = net.add_node(&[]).await?;
    net.seal_gateway(&gateway).await?;
    let follower = net.add_node(std::slice::from_ref(&junk_url)).await?;
    all_at(&[&follower, &gateway], net.owner.status().size).await?;
    let real = entries_of(&net).await?;
    let size = real.len() as u64;
    let owner_key = bridge_node::keyfile::load_or_create(net.owner.dir.path())?;
    let gateway_key = bridge_node::keyfile::load_or_create(gateway.dir.path())?;
    let attacker = Identity::generate(&mut OsRng);
    // Only the junk source is left to follow.
    gateway.node.shutdown().await;
    net.owner.node.shutdown().await;

    let mut junk = real.clone();
    for _ in 0..1000 {
        let ban = Ban { subject: Identity::generate(&mut OsRng).id().clone(), reason: "x".repeat(150) };
        junk.push(
            ban.sign(&net.net, bridge_tests::now_ms(), bridge_tests::now_ms() + DAY, &attacker)
                .map_err(e)?
                .canonical_bytes()
                .to_vec(),
        );
    }
    let stranger_head = head_over(&net.net, &junk, &attacker, &[&attacker])?;
    let genesis = Statement::parse(&real[0]).map_err(e)?;
    let mut next = Manifest::from_statement(&genesis).map_err(e)?.next_version();
    next.witnesses = vec![attacker.id().clone()];
    let now = bridge_tests::now_ms();
    let mut forged = next.sign(&net.net, now, now + DAY, &attacker).map_err(e)?.to_value();
    forged["iss"] = Value::from(net.net.as_str());
    let forged = Statement::from_value(forged).map_err(e)?;
    let by_gateway = next.sign(&net.net, now, now + DAY, &gateway_key).map_err(e)?;
    let by_stranger = next.sign(&net.net, now, now + DAY, &attacker).map_err(e)?;
    let cases: [(&str, Option<(&Statement, u64)>); 5] = [
        ("no manifest", None),
        ("the old manifest", Some((&genesis, 0))),
        ("a forged newer manifest", Some((&forged, size))),
        ("a newer manifest of a gateway", Some((&by_gateway, size))),
        ("a newer manifest of a stranger", Some((&by_stranger, size))),
    ];
    for (case, manifest) in cases {
        source.show(&junk, &stranger_head, manifest)?;
        tokio::time::sleep(Duration::from_millis(900)).await; // ~6 sync rounds of 150 ms
        assert_eq!(source.fetched(), (0, 0), "{case}: nothing fetched");
        assert_eq!((follower.status().size, follower.status().state_copies), (size, 0), "{case}: nothing changed");
    }

    // Stolen keys of the operator (and only witness): the head passes, the entries are fetched. 65+ forged
    // manifests that claim the net key: checked within the bound, then refused - no copy, no replay.
    let mut flood = real.clone();
    flood.extend((0..70).map(|_| forged.canonical_bytes().to_vec()));
    flood.push(junk[junk.len() - 1].clone());
    source.show(&flood, &head_over(&net.net, &flood, &owner_key, &[&owner_key])?, None)?;
    wait_for("the flood was fetched", || source.fetched().0 > 0).await?;
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!((follower.status().size, follower.status().state_copies), (size, 0), "refused without a copy");
    // An old genuine manifest in front of junk: it can never count, so no copy - the (stolen-key) head is taken.
    let mut old = real.clone();
    old.push(real[0].clone());
    old.extend(junk[junk.len() - 2..].iter().cloned());
    source.show(&old, &head_over(&net.net, &old, &owner_key, &[&owner_key])?, None)?;
    wait_for("the head was taken", || follower.status().size == old.len() as u64).await?;
    assert_eq!(follower.status().state_copies, 0, "no copy of the state for an old manifest");
    follower.node.shutdown().await;
    server.shutdown().await;
    Ok(())
}

/// The log operator refuses a manifest change to witnesses that can not cosign (a typo, a node without a seal for
/// it); once the node is sealed as witness, the same change is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn witnesses_must_be_sealed_for_it_before_a_manifest_names_them() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let second = net.add_node(&[]).await?;
    net.seal_gateway(&second).await?;
    let size = net.owner.status().size;
    for witness in [second.id(), Identity::generate(&mut OsRng).id().clone()] {
        let mut manifest = current_manifest(&net).await?.next_version();
        manifest.witnesses = vec![witness];
        let refused = net.admin.submit(&net.admin.sign(&manifest, 30 * DAY)?).await.err().unwrap_or_default();
        assert!(refused.contains("FORBIDDEN") && refused.contains("witness"), "{refused}");
    }
    assert_eq!(net.owner.status().size, size, "nothing in the log");
    net.seal_as(&second, "gateway,witness").await?;
    let mut manifest = current_manifest(&net).await?.next_version();
    manifest.witnesses = vec![second.id()];
    net.admin.submit(&net.admin.sign(&manifest, 30 * DAY)?).await?;
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

/// POSTs a cosignature of the net key for the operator's newest head (`head/latest`); returns the status.
async fn master_cosign_latest(net: &TestNet) -> Result<u16, String> {
    let http = bridge_transport::HttpClient::new(&net.owner.url, Duration::from_secs(10)).map_err(e)?;
    let latest = http.get(&format!("/v4/net/{}/head/latest", net.net)).await.map_err(e)?;
    let value: Value = serde_json::from_slice(&latest.body).map_err(e)?;
    let latest = WitnessedHead::from_value(&value).map_err(e)?;
    let card = net.owner.node.card().clone();
    let head = bridge_net::verify_head(&latest.head, &net.net, &card).map_err(e)?;
    let cosign = issue_cosign(&net.master, &head, bridge_tests::now_ms()).map_err(e)?;
    let answer =
        http.post(&format!("/v4/net/{}/cosign", net.net), None, cosign.canonical_bytes().to_vec()).await.map_err(e)?;
    Ok(answer.status)
}

/// The rescue: the only witness is lost, nothing gets witnessed any more, an admin's repair hangs on its own
/// transition head. The net key's cosignature counts neither for a normal head nor for that repair. The owner's
/// rescue with the 24 words (a manifest of the net key alone, taken although a transition is pending, its
/// transition head cosigned by the net key) brings the network back: new entries are witnessed again and a
/// follower catches up across all of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rescue_brings_a_network_with_a_lost_witness_back() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let witness = net.add_node(&[]).await?;
    net.seal_as(&witness, "gateway,witness").await?;
    let follower = net.add_node(&[]).await?;
    all_at(&[&witness, &follower], net.owner.status().size).await?;
    let mut manifest = current_manifest(&net).await?.next_version();
    manifest.witnesses = vec![witness.id()];
    let j = net.admin.submit(&net.admin.sign(&manifest, 30 * DAY)?).await?.index;
    wait_for("transition head witnessed", || net.owner.status().witnessed_size >= Some(j + 1)).await?;
    ban(&net).await?;
    all_at(&[&net.owner, &witness, &follower], j + 2).await?;

    // The witness is lost for good: a new entry is never witnessed - and the net key can not stand in for it.
    witness.node.shutdown().await;
    ban(&net).await?;
    wait_for("the operator issued a head for the new entry", || net.owner.status().size == j + 3).await?;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(master_cosign_latest(&net).await?, 403, "no net key cosignature for a normal head");
    assert_eq!(net.owner.status().witnessed_size, Some(j + 2), "frozen");
    // An admin's repair (another log operator in reserve) hangs on its transition head, checked against the lost
    // witness - the net key's cosignature does not count for it either (not signed by the net key alone).
    let mut repair = current_manifest(&net).await?.next_version();
    repair.logs = vec![net.owner.id(), follower.id()];
    let k = net.admin.submit(&net.admin.sign(&repair, 30 * DAY)?).await?.index;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(master_cosign_latest(&net).await?, 403, "no rescue for an admin's manifest");
    assert_eq!(net.owner.status().witnessed_size, Some(j + 2));
    let refused = ban(&net).await.err().unwrap_or_default();
    assert!(refused.contains("UNAVAILABLE"), "the operator waits for the transition head: {refused}");

    // The rescue with the 24 words.
    let change = RulesChange { witnesses: Some(vec![net.owner.id()]), ..RulesChange::default() };
    let wrong = Identity::generate(&mut OsRng);
    assert!(net.admin.rescue(&wrong, &change).await.is_err(), "other words: refused before anything is sent");
    let rescued = net.admin.rescue(&net.master, &change).await?;
    assert_eq!(rescued.index, k + 1);
    assert!(rescued.witnessed, "the transition head of the rescue is witnessed by the net key");
    assert_eq!(rescued.unwitnessed, (k + 2) - (j + 2));
    wait_for("owner witnessed the rescue", || net.owner.status().witnessed_size == Some(k + 2)).await?;
    // The network runs again: new entries are witnessed (now by the owner), the follower catches up.
    let index = ban(&net).await?;
    all_at(&[&net.owner, &follower], index + 1).await?;
    assert!(net.owner.status().witness, "the owner is the witness again");
    follower.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

/// Re-sealing without level and services keeps those of the current seal (the owner node: level 3 with gateway,
/// log and witness); a node without a seal gets level 2 with gateway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resealing_keeps_level_and_services_of_the_current_seal() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let owner_services = Services::of(&[Service::Gateway, Service::Log, Service::Witness]);
    let seals = net.admin.current_seals(&net.owner.id()).await?;
    assert_eq!(seals, vec![(3, owner_services)]);
    let (level, services) = seal_defaults(&seals, None, None);
    assert_eq!((level, services), (3, owner_services));
    // The owner node re-sealed with its current card: the same single seal, no second one at level 2.
    let size = net.owner.status().size;
    net.admin.seal(&net.owner.url, &net.owner.id(), level, services).await?;
    wait_for("re-seal in the log", || net.owner.status().witnessed_size == Some(size + 1)).await?;
    assert_eq!(net.admin.current_seals(&net.owner.id()).await?, vec![(3, owner_services)]);
    let second = net.add_node(&[]).await?;
    let seals = net.admin.current_seals(&second.id()).await?;
    assert_eq!(seal_defaults(&seals, None, None), (2, Services::of(&[Service::Gateway])));
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}
