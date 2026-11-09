//! Phase 3 acceptance (docs/05): a network is created; a second node joins and is sealed as gateway; clients on
//! different gateways exchange messages through a relay the nodes cannot read; revoking a seal takes effect in the
//! whole network within seconds; forged statements and submits by non-admins are refused; a log operator that
//! shows two different logs is caught by gossip, the evidence spreads and its heads are refused; non-members and
//! banned members can not log in; invite-only joins need a valid code; a restart keeps log and state.

use std::time::{Duration, Instant};

use bridge_core::{Content, ContentType, Identity, Payload};
use bridge_net::JoinMode;
use bridge_sdk::{Client, SdkError};
use bridge_tests::net::{TestNet, eventually, joined, wait_for};
use rand_core::{OsRng, RngCore};

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
    format!("geheim-{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
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

fn code_of<T: std::fmt::Debug>(result: Result<T, SdkError>) -> String {
    match result {
        Err(SdkError::Node { code, .. }) => code,
        other => format!("{other:?}"),
    }
}

/// Sends `content` from `from` to `to` once the network knows where `to` lives (home entries travel between the
/// gateways every few hundred milliseconds).
async fn send_when_routed(from: &Client, to: &Client, content: &Content) -> Result<(), String> {
    let id = to.identity().id().clone();
    let card = eventually("card of the recipient", || async { from.card_of(&id).await.map_err(e) }).await?;
    eventually("envelope accepted", || async { from.send(&card, content).await.map(|_| ()).map_err(e) }).await
}

/// Receives until one message is there.
async fn receive_one(client: &mut Client) -> Result<bridge_sdk::Received, String> {
    let deadline = Instant::now() + bridge_tests::net::PATIENCE;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_with_two_gateways_relays_and_revocation_spreads() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let status = net.owner.status();
    assert!(status.operator && status.witness && status.gateway, "{status:?}");

    // A second node joins with the link (bootstrap) and follows the log; it is no gateway before its seal.
    let second = net.add_node(&[]).await?;
    assert!(!second.status().gateway && !second.status().operator);
    let early = Client::join(Identity::generate(&mut OsRng), &second.link(&net.net, None)).await.map(|_| ());
    assert!(matches!(early, Err(SdkError::Untrusted(_))), "not yet listed as gateway in the log: {early:?}");
    let seal = net.seal_gateway(&second).await?;
    net.synced(&second).await?;

    // Alice joins at the owner, Bob at the second gateway.
    let mut alice = joined(&net.link(None)).await?;
    let mut bob = joined(&second.link(&net.net, None)).await?;
    assert_eq!(alice.net(), Some(&net.net));

    // Alice -> Bob goes owner -> relay -> second gateway. Neither node can read it.
    let secret = marker();
    send_when_routed(&alice, &bob, &Content::text(ContentType::Direct, secret.clone())).await?;
    let message = receive_one(&mut bob).await?;
    assert_eq!((text(&message.content), &message.from), (secret.clone(), alice.identity().id()));
    for dir in [net.owner.dir.path(), second.dir.path()] {
        assert!(!files_contain(dir, secret.as_bytes())?, "plaintext in {}", dir.display());
    }
    // And back.
    send_when_routed(&bob, &alice, &Content::text(ContentType::Response, "angekommen")).await?;
    assert_eq!(text(&receive_one(&mut alice).await?.content), "angekommen");

    // The owner revokes the seal: the second node is no gateway anywhere within seconds (acceptance: < 60 s).
    let started = Instant::now();
    let hash = bridge_core::encoding::b64_fixed::<32>(&seal, "seal").map_err(e)?;
    net.admin.revoke(bridge_net::RevokeTarget::Statement(hash), "Test").await?;
    wait_for("second node no gateway any more", || !second.status().gateway).await?;
    let elapsed = started.elapsed();
    // Typically well under a second here; the bound leaves room for slow CI machines (acceptance: < 60 s).
    assert!(elapsed < Duration::from_secs(30), "revocation took {elapsed:?}");
    assert_eq!(code_of(bob.receive(0).await), "FORBIDDEN", "sessions at the former gateway end");
    assert_eq!(code_of(bob.connect().await), "FORBIDDEN", "no new logins there");
    let to_bob = alice.card_of(bob.identity().id()).await.map_err(e)?;
    assert_eq!(
        code_of(alice.send(&to_bob, &Content::text(ContentType::Direct, "weg?")).await),
        "UNKNOWN_IDENTITY",
        "the owner no longer relays to it"
    );
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_invites_bans_and_non_members() -> TestResult {
    let net = TestNet::create(JoinMode::Invite).await?;
    let second = net.add_node(&[]).await?;
    net.seal_gateway(&second).await?;

    // Invite-only: without a code, with a wrong code - refused.
    assert_eq!(code_of(Client::join(Identity::generate(&mut OsRng), &net.link(None)).await.map(|_| ())), "FORBIDDEN");
    let wrong = net.link(Some("FALSCH-0000".into()));
    assert_eq!(code_of(Client::join(Identity::generate(&mut OsRng), &wrong).await.map(|_| ())), "FORBIDDEN");
    // A code with 2 uses: one join at the owner, one at the second gateway, the third is refused.
    let (code, link) = net.admin.invite(2, 1).await?;
    assert!(link.contains(&format!("code={code}")));
    let mut alice = joined(&link).await?;
    net.synced(&second).await?;
    let mut dave = joined(&second.link(&net.net, Some(code.clone()))).await?;
    let late = Client::join(Identity::generate(&mut OsRng), &link).await.map(|_| ());
    assert_eq!(code_of(late), "FORBIDDEN", "code used up");

    // Not a member: no login, at no gateway.
    for url in [&net.owner.url, &second.url] {
        let mut stranger = Client::new(Identity::generate(&mut OsRng), url, None).map_err(e)?;
        assert_eq!(code_of(stranger.connect().await), "NOT_MEMBER");
    }

    // Banned: refused after the ban reached the gateway - the running session ends, new logins fail.
    net.admin.ban(dave.identity().id().clone(), 1, "Test").await?;
    net.synced(&second).await?;
    assert_eq!(code_of(dave.receive(0).await), "BANNED");
    assert_eq!(code_of(dave.connect().await), "BANNED");
    // Alice is not affected.
    alice.receive(0).await.map_err(e)?;
    alice.connect().await.map_err(e)?;
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_network_and_proof_of_work_from_the_manifest() -> TestResult {
    let net = TestNet::create(JoinMode::Closed).await?;
    assert_eq!(code_of(Client::join(Identity::generate(&mut OsRng), &net.link(None)).await.map(|_| ())), "FORBIDDEN");

    // Manifest version 2 (admin with "rules"): open, with 8 bits of proof-of-work for joining.
    let http = bridge_transport::HttpClient::new(&net.owner.url, Duration::from_secs(10)).map_err(e)?;
    let answer = http.get(&format!("/v4/net/{}/manifest", net.net)).await.map_err(e)?;
    let value: serde_json::Value = serde_json::from_slice(&answer.body).map_err(e)?;
    let current = bridge_core::Statement::from_value(value["manifest"].clone()).map_err(e)?;
    let mut manifest = <bridge_net::Manifest as bridge_net::Body>::from_statement(&current).map_err(e)?.next_version();
    manifest.join = bridge_net::Join { mode: JoinMode::Open, pow_bits: 8 };
    let statement = net.admin.sign(&manifest, 30 * 86_400_000)?;
    net.admin.submit(&statement).await?;
    wait_for("manifest version 2", || net.owner.status().manifest_version == 2).await?;

    // A join with a plain login challenge (no puzzle) is refused; the SDK asks for a join challenge and solves it.
    let joiner = Identity::generate(&mut OsRng);
    let owner_id = net.owner.id();
    let challenge = http.post("/v4/auth/challenge", None, b"{}".to_vec()).await.map_err(e)?;
    let challenge: serde_json::Value = serde_json::from_slice(&challenge.body).map_err(e)?;
    let card = joiner.key_card(bridge_core::Role::Client, None, bridge_tests::now_ms()).map_err(e)?;
    let body = serde_json::json!({"challenge": challenge["challenge"], "card": card.to_value()});
    let request =
        bridge_core::SignedRequest::sign(&joiner, &owner_id, "join", body, bridge_tests::now_ms(), &mut OsRng)
            .map_err(e)?;
    let refused = http.post("/v4/net/join", None, request.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!((refused.status, bridge_tests::code(&refused)), (403, "POW_REQUIRED".to_owned()));
    let mut member = Client::join(joiner, &net.link(None)).await.map_err(e)?;
    member.receive(0).await.map_err(e)?;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_statements_and_foreign_submits_are_refused() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let size = net.owner.status().size;
    let outsider = Identity::generate(&mut OsRng);
    let victim = Identity::generate(&mut OsRng).id().clone();

    // A manifest change signed by somebody who is not the network key and no admin.
    let http = bridge_transport::HttpClient::new(&net.owner.url, Duration::from_secs(10)).map_err(e)?;
    let answer = http.get(&format!("/v4/net/{}/manifest", net.net)).await.map_err(e)?;
    let value: serde_json::Value = serde_json::from_slice(&answer.body).map_err(e)?;
    let current = bridge_core::Statement::from_value(value["manifest"].clone()).map_err(e)?;
    let mut manifest = <bridge_net::Manifest as bridge_net::Body>::from_statement(&current).map_err(e)?.next_version();
    manifest.name = "Gekapert".into();
    let forged_manifest = bridge_net::Body::sign(
        &manifest,
        &net.net,
        bridge_tests::now_ms(),
        bridge_tests::now_ms() + 86_400_000,
        &outsider,
    )
    .map_err(e)?;
    let refused = net.admin.submit(&forged_manifest).await.err().unwrap_or_default();
    assert!(refused.contains("FORBIDDEN"), "{refused}");

    // A seal whose body was changed after signing (level 1 -> 3).
    let seal = bridge_net::Seal { subject: victim.clone(), level: 1, services: bridge_net::Services::NONE, card: None };
    let mut changed = net.admin.sign(&seal, 86_400_000)?.to_value();
    changed["body"]["level"] = serde_json::json!(3);
    let forged_seal = bridge_core::Statement::from_value(changed).map_err(e)?;
    let refused = net.admin.submit(&forged_seal).await.err().unwrap_or_default();
    assert!(refused.contains("BAD_SIGNATURE"), "{refused}");
    // A seal signed by an outsider.
    let foreign_seal =
        bridge_net::Body::sign(&seal, &net.net, bridge_tests::now_ms(), bridge_tests::now_ms() + 86_400_000, &outsider)
            .map_err(e)?;
    let refused = net.admin.submit(&foreign_seal).await.err().unwrap_or_default();
    assert!(refused.contains("FORBIDDEN"), "{refused}");

    // A valid admin statement, but handed in by somebody who is neither admin nor gateway.
    let ban = net.admin.sign(&bridge_net::Ban { subject: victim.clone(), reason: String::new() }, 86_400_000)?;
    let body = serde_json::json!({"statement": ban.to_value()});
    let request = bridge_core::SignedRequest::sign(
        &outsider,
        &net.owner.id(),
        "submit",
        body,
        bridge_tests::now_ms(),
        &mut OsRng,
    )
    .map_err(e)?;
    let answer =
        http.post(&format!("/v4/net/{}/submit", net.net), None, request.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!((answer.status, bridge_tests::code(&answer)), (403, "FORBIDDEN".to_owned()));

    // Nothing of that is in the log; the genuine ban by the admin still goes in.
    assert_eq!(net.owner.status().size, size);
    net.admin.submit(&ban).await?;
    assert_eq!(net.owner.status().size, size + 1);
    // A client is not fooled by a gateway of another network.
    let other = TestNet::create(JoinMode::Open).await?;
    let fake_link = bridge_core::JoinLink {
        net: net.net.clone(),
        gateway: other.owner.url.clone(),
        code: None,
        node: None,
        tls: None,
    }
    .to_link();
    let fooled = Client::join(Identity::generate(&mut OsRng), &fake_link).await.map(|_| ());
    assert!(matches!(fooled, Err(SdkError::Untrusted(_))), "{fooled:?}");
    other.owner.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_keeps_log_state_and_roles() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let second = net.add_node(&[]).await?;
    net.seal_gateway(&second).await?;
    let mut bob = joined(&second.link(&net.net, None)).await?;
    let alice = joined(&net.link(None)).await?;
    net.synced(&second).await?;
    let size = net.owner.status().size;

    // The second gateway restarts: log, state and its role are there at once (from its own store).
    let second = second.restart(None).await?;
    let status = second.status();
    assert_eq!((status.size, status.gateway), (size, true), "{status:?}");
    bob.connect().await.map_err(e)?;

    // The owner restarts too and keeps operating: a new statement goes in and reaches the second node.
    let TestNet { net: id, owner, admin, master } = net;
    let owner = owner.restart(Some(bridge_tests::net::membership(&id, &[]))).await?;
    let net = TestNet { net: id, owner, admin, master };
    assert_eq!(net.owner.status().size, size);
    wait_for("owner witnessed again", || net.owner.status().witnessed_size == Some(size)).await?;
    net.admin.invite(1, 1).await?;
    net.synced(&second).await?;
    assert_eq!(second.status().size, size + 1);

    // Messages still flow between the two gateways after both restarts.
    let mut alice = alice;
    alice.connect().await.map_err(e)?;
    send_when_routed(&alice, &bob, &Content::text(ContentType::Direct, "nach dem Neustart")).await?;
    assert_eq!(text(&receive_one(&mut bob).await?.content), "nach dem Neustart");
    second.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

/// A peer that shows whatever head (and entries) the test gives it - the "other view" of a lying log operator.
#[derive(Default)]
struct FakePeer {
    head: std::sync::Mutex<Option<Vec<u8>>>,
    entries: std::sync::Mutex<Vec<Vec<u8>>>,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_view_is_caught_spread_and_the_operator_deposed() -> TestResult {
    use bridge_net::{WitnessedHead, issue_cosign, issue_head, verify_head};
    let net = TestNet::create(JoinMode::Open).await?;
    let fake = std::sync::Arc::new(FakePeer::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let server =
        bridge_transport::serve(listener, bridge_transport::ServerConfig::default(), fake.clone()).map_err(e)?;
    let fake_url = format!("http://{}", server.local_addr());
    let gateway = net.add_node(std::slice::from_ref(&fake_url)).await?;
    net.seal_gateway(&gateway).await?;
    let follower = net.add_node(std::slice::from_ref(&fake_url)).await?;
    net.synced(&gateway).await?;
    let size = net.owner.status().size;
    assert!(net.owner.status().deposed.is_empty() && gateway.status().deposed.is_empty());

    // The operator's key (it is also the only witness) signs a second, different log of the same size.
    let operator = bridge_node::keyfile::load_or_create(net.owner.dir.path())?;
    let operator_card = operator.key_card(bridge_core::Role::Node, None, bridge_tests::now_ms()).map_err(e)?;
    let now = bridge_tests::now_ms();
    let lie = issue_head(&operator, &net.net, size, [7u8; 32], now).map_err(e)?;
    let checked = verify_head(&lie, &net.net, &operator_card).map_err(e)?;
    let cosign = issue_cosign(&operator, &checked, now).map_err(e)?;
    let shown = WitnessedHead { head: lie, cosigns: vec![cosign] };
    *fake.head.lock().map_err(e)? = Some(bridge_core::json::canonical(&shown.to_value()).map_err(e)?);

    // Gossip catches it; the evidence spreads to every node; everybody deposes the operator (it stops itself too).
    let operator_id = net.owner.id();
    for (name, node) in [("gateway", &gateway), ("follower", &follower), ("owner", &net.owner)] {
        wait_for(&format!("{name} deposed the operator"), || node.status().deposed == vec![operator_id.clone()])
            .await?;
    }
    let http = bridge_transport::HttpClient::new(&follower.url, Duration::from_secs(10)).map_err(e)?;
    let listed = http.get(&format!("/v4/net/{}/evidence", net.net)).await.map_err(e)?;
    let listed: serde_json::Value = serde_json::from_slice(&listed.body).map_err(e)?;
    assert_eq!(listed["evidence"].as_array().map(Vec::len), Some(1), "{listed}");
    assert!(!net.owner.status().operator, "a deposed operator does not operate (fail closed)");
    let refused = net.admin.invite(1, 1).await.err().unwrap_or_default();
    assert!(refused.contains("FORBIDDEN"), "{refused}");

    // Its heads are no longer accepted: a properly witnessed head that extends the log by a valid admin
    // statement is ignored by every node.
    let ban = net.admin.sign(&bridge_net::Ban { subject: operator_id.clone(), reason: String::new() }, 86_400_000)?;
    let owner_http = bridge_transport::HttpClient::new(&net.owner.url, Duration::from_secs(10)).map_err(e)?;
    let page =
        owner_http.post(&format!("/v4/net/{}/log", net.net), None, br#"{"from":0}"#.to_vec()).await.map_err(e)?;
    let page: serde_json::Value = serde_json::from_slice(&page.body).map_err(e)?;
    let mut entries: Vec<Vec<u8>> = page["entries"]
        .as_array()
        .map(|list| list.iter().filter_map(|v| bridge_core::encoding::b64_var(v.as_str()?, "e", 65536).ok()).collect())
        .unwrap_or_default();
    entries.push(ban.canonical_bytes().to_vec());
    let extended = bridge_net::Log::from_entries(net.net.clone(), &entries).map_err(e)?;
    let head = extended.issue_head(&operator, bridge_tests::now_ms()).map_err(e)?;
    let checked = verify_head(&head, &net.net, &operator_card).map_err(e)?;
    let cosign = issue_cosign(&operator, &checked, bridge_tests::now_ms()).map_err(e)?;
    *fake.entries.lock().map_err(e)? = entries;
    *fake.head.lock().map_err(e)? =
        Some(bridge_core::json::canonical(&WitnessedHead { head, cosigns: vec![cosign] }.to_value()).map_err(e)?);
    tokio::time::sleep(Duration::from_millis(1500)).await; // many sync rounds (150 ms each) - nothing may change
    assert_eq!((gateway.status().size, follower.status().size), (size, size));

    // A restart keeps the evidence (the operator stays deposed).
    let follower = follower.restart(Some(net.membership(std::slice::from_ref(&fake_url)))).await?;
    assert_eq!(follower.status().deposed, vec![operator_id]);
    for node in [gateway, follower] {
        node.node.shutdown().await;
    }
    server.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}
