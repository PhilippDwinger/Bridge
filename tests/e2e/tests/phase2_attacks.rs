//! Phase 2 attack tests (docs/05): forged signature, changed byte, replay, expired, too large, 10,000 requests/s,
//! wrong proof-of-work - and more. Every attack must be refused with the right code, and the node must stay usable.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bridge_core::encoding::b64;
use bridge_core::{Address, Content, ContentType, Envelope, Identity, KeyCard, Kind, Puzzle, Role, SignedRequest};
use bridge_guard::{Limits, PowPolicy};
use bridge_node::{NodeConfig, RunningNode};
use bridge_sdk::Client;
use bridge_tests::{client, code, default_node, now_ms, raw, start_node, url};
use bridge_transport::{HttpClient, ServerConfig};
use rand_core::OsRng;
use serde_json::{Value, json};

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Alice (logged in, raw access with her session) and Bob's card (Bob logged in once, so he is known).
struct Scene {
    node: RunningNode,
    alice: Client,
    bob: Client,
    bob_card: KeyCard,
    http: HttpClient,
}

impl Scene {
    async fn new(node: RunningNode) -> Result<Self, String> {
        let alice = client(&node).await?;
        let bob = client(&node).await?;
        let bob_card = alice.card_of(bob.identity().id()).await.map_err(e)?;
        let http = raw(&node)?;
        Ok(Self { node, alice, bob, bob_card, http })
    }

    fn token(&self) -> Option<&str> {
        self.alice.session_token()
    }

    fn envelope(&self, iat: i64, ttl: u32, plaintext: &[u8]) -> Result<Envelope, String> {
        let net = self.alice.net().ok_or("no net")?;
        let address = Address { net, to: &self.bob_card, kind: Kind::Msg, iat, ttl };
        Envelope::seal(self.alice.identity(), &address, plaintext, &mut OsRng).map_err(e)
    }

    async fn post(&self, path: &str, body: Vec<u8>) -> Result<(u16, String), String> {
        let answer = self.http.post(path, self.token(), body).await.map_err(e)?;
        Ok((answer.status, code(&answer)))
    }
}

fn content(text: &str) -> Result<Vec<u8>, String> {
    Content::text(ContentType::Direct, text).to_bytes().map_err(e)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_signature_and_changed_bytes_are_refused() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut scene = Scene::new(default_node(dir.path()).await?).await?;
    let envelope = scene.envelope(now_ms(), 600, &content("echt")?)?;
    let value = envelope.to_value_for_tests();

    let mut forged = value.clone();
    forged["sig"] = json!(b64(&[7u8; 64]));
    assert_eq!(scene.post("/v4/send", forged.to_string().into_bytes()).await?, (401, "BAD_SIGNATURE".into()));

    for field in ["ct", "to", "kind", "ttl", "n", "epk"] {
        let mut changed = value.clone();
        changed[field] = match field {
            "ct" => {
                let mut text = changed["ct"].as_str().unwrap_or_default().to_owned();
                let flipped = if text.ends_with('A') { 'B' } else { 'A' };
                text.pop();
                text.push(flipped);
                json!(text)
            }
            "to" => json!(scene.alice.identity().id().as_str()),
            "kind" => json!("req"),
            "ttl" => json!(601),
            "n" => json!(b64(&[1u8; 12])),
            _ => json!(b64(&[9u8; 32])),
        };
        let (status, error) = scene.post("/v4/send", changed.to_string().into_bytes()).await?;
        assert!(status == 401 || status == 400, "{field}: {status} {error}");
        assert!(error == "BAD_SIGNATURE" || error == "BAD_FORMAT", "{field}: {error}");
    }
    // Nothing of that arrived at Bob.
    assert!(scene.bob.receive(0).await.map_err(e)?.messages.is_empty());
    // The original still goes through.
    assert_eq!(scene.post("/v4/send", envelope.to_bytes().map_err(e)?).await?, (200, String::new()));
    assert_eq!(scene.bob.receive(0).await.map_err(e)?.messages.len(), 1);
    scene.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_expired_future_and_too_large_are_refused() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut scene = Scene::new(default_node(dir.path()).await?).await?;
    let envelope = scene.envelope(now_ms(), 600, &content("einmal")?)?;
    assert_eq!(scene.post("/v4/send", envelope.to_bytes().map_err(e)?).await?.0, 200);
    assert_eq!(scene.post("/v4/send", envelope.to_bytes().map_err(e)?).await?, (409, "REPLAY".into()));
    // Even after Bob fetched and acknowledged it, the same envelope cannot be delivered again.
    assert_eq!(scene.bob.receive(0).await.map_err(e)?.messages.len(), 1);
    assert_eq!(scene.post("/v4/send", envelope.to_bytes().map_err(e)?).await?, (409, "REPLAY".into()));

    let old = scene.envelope(now_ms() - 2 * 3600 * 1000, 60, &content("alt")?)?;
    assert_eq!(scene.post("/v4/send", old.to_bytes().map_err(e)?).await?, (401, "EXPIRED".into()));
    let future = scene.envelope(now_ms() + 3600 * 1000, 600, &content("zukunft")?)?;
    assert_eq!(scene.post("/v4/send", future.to_bytes().map_err(e)?).await?, (401, "NOT_YET_VALID".into()));

    // Larger than 1 MiB: refused from Content-Length before reading - the client gets 413 or, if it was still
    // sending, a closed connection. Either way nothing was read, and the node keeps working.
    let huge = vec![b' '; 2 * 1024 * 1024];
    match scene.http.post("/v4/send", scene.token(), huge).await {
        Ok(answer) => assert_eq!((answer.status, code(&answer)), (413, "TOO_LARGE".into())),
        Err(error) => assert!(error.to_string().contains("connection"), "{error}"),
    }
    let big_envelope = vec![b' '; 300 * 1024];
    assert_eq!(scene.post("/v4/send", big_envelope).await?, (413, "TOO_LARGE".into()));
    scene.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn impersonation_and_foreign_actions_are_refused() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut scene = Scene::new(default_node(dir.path()).await?).await?;
    let net = scene.alice.net().ok_or("net")?.clone();

    // Alice's session, but an envelope from Mallory (validly signed by Mallory).
    let mallory = Identity::generate(&mut OsRng);
    let address = Address { net: &net, to: &scene.bob_card, kind: Kind::Msg, iat: now_ms(), ttl: 600 };
    let foreign = Envelope::seal(&mallory, &address, &content("x")?, &mut OsRng).map_err(e)?;
    assert_eq!(scene.post("/v4/send", foreign.to_bytes().map_err(e)?).await?, (403, "FORBIDDEN".into()));

    // Wrong network.
    let other_net = Identity::generate(&mut OsRng).id().clone();
    let address = Address { net: &other_net, to: &scene.bob_card, kind: Kind::Msg, iat: now_ms(), ttl: 600 };
    let wrong_net = Envelope::seal(scene.alice.identity(), &address, &content("x")?, &mut OsRng).map_err(e)?;
    assert_eq!(scene.post("/v4/send", wrong_net.to_bytes().map_err(e)?).await?, (403, "FORBIDDEN".into()));

    // Unknown recipient.
    let stranger = Identity::generate(&mut OsRng).key_card(Role::Client, None, 0).map_err(e)?;
    let address = Address { net: &net, to: &stranger, kind: Kind::Msg, iat: now_ms(), ttl: 600 };
    let to_stranger = Envelope::seal(scene.alice.identity(), &address, &content("x")?, &mut OsRng).map_err(e)?;
    assert_eq!(scene.post("/v4/send", to_stranger.to_bytes().map_err(e)?).await?, (404, "UNKNOWN_IDENTITY".into()));

    // No or a made-up session.
    let envelope = scene.envelope(now_ms(), 600, &content("x")?)?;
    let answer = scene.http.post("/v4/send", None, envelope.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (401, "NO_SESSION".into()));
    let answer = scene.http.post("/v4/poll", Some(&b64(&[0u8; 32])), b"{}".to_vec()).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (401, "NO_SESSION".into()));

    // Alice tries to acknowledge (delete) Bob's mail: an ack signed as Bob would need Bob's key; one signed by her
    // only touches her own mailbox.
    assert_eq!(scene.post("/v4/send", envelope.to_bytes().map_err(e)?).await?.0, 200);
    let node_id = scene.node.card().id().clone();
    let ids = json!({"acks": [{"from": scene.alice.identity().id().as_str(), "id": b64(envelope.id())}]});
    let as_bob = SignedRequest::sign(&mallory, &node_id, "ack", ids.clone(), now_ms(), &mut OsRng).map_err(e)?;
    assert_eq!(scene.post("/v4/ack", as_bob.to_bytes().map_err(e)?).await?, (403, "FORBIDDEN".into()));
    let own = SignedRequest::sign(scene.alice.identity(), &node_id, "ack", ids, now_ms(), &mut OsRng).map_err(e)?;
    let answer = scene.http.post("/v4/ack", scene.token(), own.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!(serde_json::from_slice::<Value>(&answer.body).map_err(e)?["removed"], json!(0));
    // Repeating a signed ack changes nothing (acks are idempotent).
    assert_eq!(scene.post("/v4/ack", own.to_bytes().map_err(e)?).await?, (200, String::new()));
    assert_eq!(scene.bob.receive(0).await.map_err(e)?.messages.len(), 1, "Bob still got it");

    // A signed request for another node.
    let elsewhere = Identity::generate(&mut OsRng).id().clone();
    let wrong_aud =
        SignedRequest::sign(scene.alice.identity(), &elsewhere, "ack", json!({"acks": []}), now_ms(), &mut OsRng)
            .map_err(e)?;
    assert_eq!(scene.post("/v4/ack", wrong_aud.to_bytes().map_err(e)?).await?, (401, "BAD_SIGNATURE".into()));
    scene.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_attacks_are_refused() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let node = default_node(dir.path()).await?;
    let http = raw(&node)?;
    let node_id = node.card().id().clone();
    let alice = Identity::generate(&mut OsRng);
    let card = alice.key_card(Role::Client, None, now_ms()).map_err(e)?;

    let challenge = |answer: &bridge_transport::ClientResponse| -> Result<String, String> {
        let value: Value = serde_json::from_slice(&answer.body).map_err(e)?;
        Ok(value["challenge"].as_str().unwrap_or_default().to_owned())
    };
    let first = challenge(&http.post("/v4/auth/challenge", None, b"{}".to_vec()).await.map_err(e)?)?;
    let body = json!({"challenge": first, "card": card.to_value()});
    let login = SignedRequest::sign(&alice, &node_id, "login", body.clone(), now_ms(), &mut OsRng).map_err(e)?;
    let ok = http.post("/v4/auth/login", None, login.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!(ok.status, 200);
    // Replay of the same login.
    let again = http.post("/v4/auth/login", None, login.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!((again.status, code(&again)), (401, "EXPIRED".into()));
    // Someone else's card with Alice's signature.
    let next = challenge(&http.post("/v4/auth/challenge", None, b"{}".to_vec()).await.map_err(e)?)?;
    let other_card = Identity::generate(&mut OsRng).key_card(Role::Client, None, 0).map_err(e)?;
    let body = json!({"challenge": next, "card": other_card.to_value()});
    let wrong = SignedRequest::sign(&alice, &node_id, "login", body, now_ms(), &mut OsRng).map_err(e)?;
    let answer = http.post("/v4/auth/login", None, wrong.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (401, "BAD_SIGNATURE".into()));
    // Made-up challenge.
    let body = json!({"challenge": b64(&[5u8; 32]), "card": card.to_value()});
    let made_up = SignedRequest::sign(&alice, &node_id, "login", body, now_ms(), &mut OsRng).map_err(e)?;
    let answer = http.post("/v4/auth/login", None, made_up.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (401, "EXPIRED".into()));
    node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_proof_of_work_is_refused() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut config = NodeConfig::new(dir.path());
    config.limits.pow = PowPolicy { always_bits: 16, ..config.limits.pow };
    let node = start_node(config).await?;
    let http = raw(&node)?;
    let node_id = node.card().id().clone();
    let alice = Identity::generate(&mut OsRng);
    let card = alice.key_card(Role::Client, None, now_ms()).map_err(e)?;

    for attempt in ["none", "wrong"] {
        let answer: Value =
            serde_json::from_slice(&http.post("/v4/auth/challenge", None, b"{}".to_vec()).await.map_err(e)?.body)
                .map_err(e)?;
        let puzzle = Puzzle::from_value(answer["pow"].clone()).map_err(e)?;
        assert_eq!(puzzle.bits(), 16);
        let mut body = json!({"challenge": answer["challenge"], "card": card.to_value()});
        if attempt == "wrong" {
            let wrong = (0u64..).map(u64::to_be_bytes).find(|c| puzzle.check_solution(c, now_ms()).is_err());
            body["pow"] = json!(b64(&wrong.unwrap_or_default()));
        }
        let login = SignedRequest::sign(&alice, &node_id, "login", body, now_ms(), &mut OsRng).map_err(e)?;
        let answer = http.post("/v4/auth/login", None, login.to_bytes().map_err(e)?).await.map_err(e)?;
        assert_eq!((answer.status, code(&answer)), (403, "POW_REQUIRED".into()), "{attempt}");
    }
    // The SDK solves it and gets in.
    let mut honest = Client::new(Identity::generate(&mut OsRng), &url(&node), Some(node_id)).map_err(e)?;
    honest.connect().await.map_err(e)?;
    node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_thousand_requests_per_second_are_cut_off_and_others_still_get_through() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut config = NodeConfig::new(dir.path());
    // As behind Tailscale Funnel: the proxy (127.0.0.1) tells the real address.
    config.server = ServerConfig { trusted_proxies: vec![[127, 0, 0, 1].into()], ..ServerConfig::default() };
    let node = start_node(config).await?;
    let base = url(&node);
    let http = reqwest_like(&base)?;

    let limited = Arc::new(AtomicUsize::new(0));
    let passed = Arc::new(AtomicUsize::new(0));
    let started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for worker in 0..50 {
        let (http, base, limited, passed) = (http.clone(), base.clone(), Arc::clone(&limited), Arc::clone(&passed));
        tasks.push(tokio::spawn(async move {
            for _ in 0..200 {
                let answer = http
                    .post(format!("{base}/v4/auth/challenge"))
                    .header("x-forwarded-for", "6.6.6.6")
                    .body("{}")
                    .send()
                    .await;
                match answer.map(|a| a.status().as_u16()) {
                    Ok(429) => limited.fetch_add(1, Ordering::Relaxed),
                    Ok(200) => passed.fetch_add(1, Ordering::Relaxed),
                    _ => 0,
                };
            }
            let _ = worker;
        }));
    }
    for task in tasks {
        task.await.map_err(e)?;
    }
    let elapsed = started.elapsed();
    let (limited, passed) = (limited.load(Ordering::Relaxed), passed.load(Ordering::Relaxed));
    assert_eq!(limited + passed, 10_000, "every request got an answer");
    // Per address: burst 40 + 20/s for all requests, burst 10 + 2/s for challenges.
    let allowed = 10 + 2 * (elapsed.as_secs() as usize + 1);
    assert!(passed <= allowed, "{passed} got through in {elapsed:?}");

    // Another address is not affected, and the node still answers normally.
    let other = http
        .post(format!("{base}/v4/auth/challenge"))
        .header("x-forwarded-for", "7.7.7.7")
        .body("{}")
        .send()
        .await
        .map_err(e)?;
    assert_eq!(other.status().as_u16(), 200);
    let mut alice = Client::new(Identity::generate(&mut OsRng), &base, None).map_err(e)?;
    alice.connect().await.map_err(e)?;
    eprintln!("flood: 10,000 requests in {elapsed:?}, {passed} passed, {limited} limited");
    node.shutdown().await;
    Ok(())
}

fn reqwest_like(_base: &str) -> Result<RawClient, String> {
    RawClient::builder().pool_max_idle_per_host(64).timeout(Duration::from_secs(30)).build().map_err(e)
}

type RawClient = bridge_tests::RawClient;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mailbox_quota_and_garbage() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut config = NodeConfig::new(dir.path());
    config.limits = Limits {
        mailbox: bridge_store_limits(5),
        sends_per_identity: bridge_guard::Rate { per_second: 1000, burst: 1000 },
        per_address: bridge_guard::Rate { per_second: 1000, burst: 1000 },
        ..Limits::default()
    };
    let scene = Scene::new(start_node(config).await?).await?;
    for i in 0..5 {
        let envelope = scene.envelope(now_ms(), 600, &content(&format!("{i}"))?)?;
        assert_eq!(scene.post("/v4/send", envelope.to_bytes().map_err(e)?).await?.0, 200);
    }
    let envelope = scene.envelope(now_ms(), 600, &content("zu viel")?)?;
    assert_eq!(scene.post("/v4/send", envelope.to_bytes().map_err(e)?).await?, (429, "QUOTA_EXCEEDED".into()));

    for path in ["/v4/send", "/v4/poll", "/v4/ack", "/v4/card", "/v4/auth/login", "/v4/auth/challenge"] {
        for body in [&b"{"[..], b"[]", b"null", b"\xff\xfe", br#"{"a":1,"a":2}"#, br#"{"wait":1.5}"#, b"{}"] {
            let (status, _) = scene.post(path, body.to_vec()).await?;
            assert!(status < 500, "{path} {body:?} -> {status}");
        }
    }
    let (status, error) = scene.post("/v4/unknown", b"{}".to_vec()).await?;
    assert_eq!((status, error.as_str()), (404, "NOT_FOUND"));
    scene.node.shutdown().await;
    Ok(())
}

fn bridge_store_limits(max_envelopes: u64) -> bridge_tests::MailboxLimits {
    bridge_tests::MailboxLimits { max_envelopes, ..Limits::default().mailbox }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deep_envelopes_and_huge_cards_cannot_block_an_inbox() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let mut scene = Scene::new(default_node(dir.path()).await?).await?;
    // A correctly signed envelope with a deeply nested extra field: refused at the door.
    let net = scene.alice.net().ok_or("net")?.clone();
    let envelope = scene.envelope(now_ms(), 600, &content("x")?)?;
    let mut deep = envelope.to_value_for_tests();
    deep["x"] = serde_json::from_str(&("[".repeat(31) + &"]".repeat(31))).map_err(e)?;
    assert_eq!(scene.post("/v4/send", deep.to_string().into_bytes()).await?.1, "BAD_FORMAT");
    // A login with a huge key card: refused.
    let mallory = Identity::generate(&mut OsRng);
    let mut card = mallory.key_card(Role::Client, None, now_ms()).map_err(e)?.to_value();
    card["padding"] = json!("x".repeat(60_000));
    let answer: Value =
        serde_json::from_slice(&scene.http.post("/v4/auth/challenge", None, b"{}".to_vec()).await.map_err(e)?.body)
            .map_err(e)?;
    let body = json!({"challenge": answer["challenge"], "card": card});
    let login =
        SignedRequest::sign(&mallory, scene.node.card().id(), "login", body, now_ms(), &mut OsRng).map_err(e)?;
    let answer = scene.http.post("/v4/auth/login", None, login.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (413, "TOO_LARGE".into()));
    // Bob's inbox works normally.
    let _ = net;
    assert_eq!(scene.post("/v4/send", envelope.to_bytes().map_err(e)?).await?.0, 200);
    assert_eq!(scene.bob.receive(0).await.map_err(e)?.messages.len(), 1);
    scene.node.shutdown().await;
    Ok(())
}

/// A clock the test moves by hand.
struct ManualClock(std::sync::atomic::AtomicI64);

impl bridge_node::Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_ack_loses_nothing() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let clock = Arc::new(ManualClock(std::sync::atomic::AtomicI64::new(now_ms())));
    let mut config = NodeConfig::new(dir.path());
    config.clock = clock.clone();
    // With a frozen clock the bucket never refills: 9 requests pass, the 10th (Bob's ack) is refused.
    config.limits.per_address = bridge_guard::Rate { per_second: 1, burst: 9 };
    let node = start_node(config).await?;
    let alice = client(&node).await?; // 3 requests
    let mut bob = client(&node).await?; // 3
    let bob_card = alice.card_of(bob.identity().id()).await.map_err(e)?; // 1
    alice.send(&bob_card, &Content::text(ContentType::Direct, "wichtig")).await.map_err(e)?; // 1
    let first = bob.receive(0).await.map_err(e)?; // poll (9), ack (10) refused
    assert_eq!(first.messages.len(), 1, "the message is handed over although the ack failed");
    assert!(first.warning.as_deref().unwrap_or_default().contains("RATE_LIMITED"), "{:?}", first.warning);
    clock.0.fetch_add(60_000, Ordering::SeqCst);
    let second = bob.receive(0).await.map_err(e)?;
    assert_eq!((second.messages.len(), second.duplicates, second.warning.clone()), (0, 1, None), "no second copy");
    let third = bob.receive(0).await.map_err(e)?;
    assert_eq!((third.messages.len(), third.duplicates), (0, 0), "acknowledged now - gone from the node");
    node.shutdown().await;
    Ok(())
}
