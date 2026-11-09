//! Phase 3 attack tests on the network endpoints (docs/06 §9): garbage never gives a 5xx, oversized bodies are
//! refused, signed requests only count for their `aud`, only gateways may relay and only for recipients that live
//! at the target, a relay can not be replayed, only witnesses cosign, evidence is verified before it counts, and a
//! node without a network knows none of the endpoints.

use std::time::Duration;

use bridge_core::encoding::b64;
use bridge_core::{Address, Content, ContentType, Envelope, Identity, Kind, SignedRequest};
use bridge_net::JoinMode;
use bridge_sdk::Client;
use bridge_tests::net::{TestNet, TestNode, eventually, joined};
use bridge_tests::{code, default_node, now_ms, url};
use bridge_transport::HttpClient;
use rand_core::OsRng;
use serde_json::{Value, json};

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn http(node: &TestNode) -> Result<HttpClient, String> {
    HttpClient::new(&node.url, Duration::from_secs(30)).map_err(e)
}

/// A relay request as a gateway would send it: `{"envelope":…,"rq":…}` with the hash binding.
fn relay_body(
    signer: &Identity,
    aud: &bridge_core::Id,
    envelope: &Envelope,
    sender: &Client,
) -> Result<Vec<u8>, String> {
    let bytes = envelope.to_bytes().map_err(e)?;
    let body = json!({"envelope": b64(&bridge_core::crypto::sha256(&bytes)), "card": sender.card().to_value()});
    let request = SignedRequest::sign(signer, aud, "relay", body, now_ms(), &mut OsRng).map_err(e)?;
    let mut wire = br#"{"envelope":"#.to_vec();
    wire.extend_from_slice(&bytes);
    wire.extend_from_slice(br#","rq":"#);
    wire.extend_from_slice(&request.to_bytes().map_err(e)?);
    wire.push(b'}');
    Ok(wire)
}

fn envelope(from: &Client, to: &Client) -> Result<Envelope, String> {
    let net = from.net().ok_or("no net")?;
    let address = Address { net, to: to.card(), kind: Kind::Msg, iat: now_ms(), ttl: 600 };
    let content = Content::text(ContentType::Direct, "über das Netz").to_bytes().map_err(e)?;
    Envelope::seal(from.identity(), &address, &content, &mut OsRng).map_err(e)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn garbage_never_gives_5xx_and_sizes_are_limited() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let follower = net.add_node(&[]).await?;
    let id = net.net.to_string();
    let posts = [
        format!("/v4/net/{id}/log"),
        format!("/v4/net/{id}/proof"),
        format!("/v4/net/{id}/consistency"),
        format!("/v4/net/{id}/submit"),
        format!("/v4/net/{id}/cosign"),
        format!("/v4/net/{id}/evidence"),
        "/v4/net/join".to_owned(),
        "/v4/node/relay".to_owned(),
        "/v4/node/homes".to_owned(),
    ];
    let bodies: [&[u8]; 12] = [
        b"{",
        b"[]",
        b"null",
        b"\xff\xfe",
        br#"{"a":1,"a":2}"#,
        br#"{"from":1.5}"#,
        b"{}",
        br#"{"from":99999999999,"max":0}"#,
        br#"{"index":5,"size":2}"#,
        br#"{"from":3,"to":1}"#,
        br#"{"rq":{},"envelope":{}}"#,
        br#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":{"r":{"s":{"t":{"u":{"v":{"w":{"x":{"y":{"z":{"0":{"1":{"2":{"3":{"4":{"5":1}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}"#,
    ];
    for node in [&net.owner, &follower] {
        let http = http(node)?;
        for path in &posts {
            for body in bodies {
                let answer = http.post(path, None, body.to_vec()).await.map_err(e)?;
                assert!(answer.status < 500, "{path} {body:?} -> {}", answer.status);
            }
        }
        for path in ["head", "head/latest", "manifest", "evidence"] {
            let answer = http.get(&format!("/v4/net/{id}/{path}")).await.map_err(e)?;
            assert!(answer.status < 500, "{path} -> {}", answer.status);
        }
        // Another network, unknown actions: not found.
        let other = Identity::generate(&mut OsRng).id().to_string();
        for path in [format!("/v4/net/{other}/head"), format!("/v4/net/{id}/secret"), format!("/v4/net/{id}")] {
            assert_eq!(http.get(&path).await.map_err(e)?.status, 404, "{path}");
        }
        // Larger than the 1 MiB a request may have: refused before reading (or the connection is closed).
        let huge = vec![b' '; 2 * 1024 * 1024];
        if let Ok(answer) = http.post("/v4/node/relay", None, huge).await {
            assert_eq!(answer.status, 413);
        }
        // Larger than a relay may be, but below the request limit.
        let big = format!(r#"{{"envelope":"{}","rq":{{}}}}"#, "A".repeat(400 * 1024));
        let answer = http.post("/v4/node/relay", None, big.into_bytes()).await.map_err(e)?;
        assert_eq!((answer.status, code(&answer)), (413, "TOO_LARGE".to_owned()));
    }
    // The follower is no operator and no gateway.
    let follower_http = http(&follower)?;
    assert_eq!(follower_http.get(&format!("/v4/net/{id}/head/latest")).await.map_err(e)?.status, 404);
    // Proofs from the follower's log are real RFC 6962 proofs.
    let proof = follower_http
        .post(&format!("/v4/net/{id}/consistency"), None, br#"{"from":1,"to":3}"#.to_vec())
        .await
        .map_err(e)?;
    assert_eq!(proof.status, 200);
    let proof = follower_http
        .post(&format!("/v4/net/{id}/proof"), None, br#"{"index":0,"size":3}"#.to_vec())
        .await
        .map_err(e)?;
    assert_eq!(proof.status, 200);
    follower.node.shutdown().await;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_only_from_gateways_only_for_residents_and_only_once() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let gateway = net.add_node(&[]).await?;
    net.seal_gateway(&gateway).await?;
    let follower = net.add_node(&[]).await?;
    let alice = joined(&net.link(None)).await?; // lives at the owner
    let bob = joined(&gateway.link(&net.net, None)).await?; // lives at the gateway
    net.synced(&gateway).await?;
    net.synced(&follower).await?;
    let gateway_key = bridge_node::keyfile::load_or_create(gateway.dir.path())?;
    let follower_key = bridge_node::keyfile::load_or_create(follower.dir.path())?;
    let owner = net.owner.id();
    let to_owner = http(&net.owner)?;

    // From a node that is no gateway: refused.
    let letter = envelope(&bob, &alice)?;
    let answer =
        to_owner.post("/v4/node/relay", None, relay_body(&follower_key, &owner, &letter, &bob)?).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (403, "FORBIDDEN".to_owned()));
    // From an outsider key claiming to be the gateway (signature by the wrong key): refused.
    let outsider = Identity::generate(&mut OsRng);
    let mut forged: Value = serde_json::from_slice(&relay_body(&outsider, &owner, &letter, &bob)?).map_err(e)?;
    forged["rq"]["iss"] = json!(gateway.id().as_str());
    let answer = to_owner.post("/v4/node/relay", None, forged.to_string().into_bytes()).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (401, "BAD_SIGNATURE".to_owned()));
    // Meant for another node (aud = the gateway): refused at the owner.
    let answer = to_owner
        .post("/v4/node/relay", None, relay_body(&gateway_key, &gateway.id(), &letter, &bob)?)
        .await
        .map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (401, "BAD_SIGNATURE".to_owned()));
    // For a recipient that does not live at the owner (Bob lives at the gateway).
    let wrong_home = envelope(&alice, &bob)?;
    let answer = to_owner
        .post("/v4/node/relay", None, relay_body(&gateway_key, &owner, &wrong_home, &alice)?)
        .await
        .map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (404, "UNKNOWN_IDENTITY".to_owned()));
    // The envelope does not match the hash in the signed request.
    let mut swapped: Value = serde_json::from_slice(&relay_body(&gateway_key, &owner, &letter, &bob)?).map_err(e)?;
    swapped["envelope"] = serde_json::from_slice(&envelope(&bob, &alice)?.to_bytes().map_err(e)?).map_err(e)?;
    let answer = to_owner.post("/v4/node/relay", None, swapped.to_string().into_bytes()).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (400, "BAD_FORMAT".to_owned()));

    // The right one goes through - once. The same request again, and the same envelope in a fresh request: replay.
    let body = eventually("owner knows the gateway's homes", || {
        let body = relay_body(&gateway_key, &owner, &letter, &bob);
        let to_owner = to_owner.clone();
        async move {
            let body = body?;
            let answer = to_owner.post("/v4/node/relay", None, body.clone()).await.map_err(e)?;
            if answer.status == 200 { Ok(body) } else { Err(format!("{} {}", answer.status, code(&answer))) }
        }
    })
    .await?;
    let answer = to_owner.post("/v4/node/relay", None, body).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (409, "REPLAY".to_owned()));
    let answer =
        to_owner.post("/v4/node/relay", None, relay_body(&gateway_key, &owner, &letter, &bob)?).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (409, "REPLAY".to_owned()));
    let mut alice = alice;
    let inbox = alice.receive(2).await.map_err(e)?;
    assert_eq!(inbox.messages.len(), 1, "delivered exactly once, verified with the card that came along");

    // Homes only for gateways; submits only at the operator; cosigns only from witnesses.
    let homes =
        SignedRequest::sign(&follower_key, &owner, "homes", json!({"since": 0}), now_ms(), &mut OsRng).map_err(e)?;
    let answer = to_owner.post("/v4/node/homes", None, homes.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (403, "FORBIDDEN".to_owned()));
    let statement =
        net.admin.sign(&bridge_net::Ban { subject: outsider.id().clone(), reason: String::new() }, 86_400_000)?;
    let submit = SignedRequest::sign(
        &gateway_key,
        &gateway.id(),
        "submit",
        json!({"statement": statement.to_value()}),
        now_ms(),
        &mut OsRng,
    )
    .map_err(e)?;
    let answer = http(&gateway)?
        .post(&format!("/v4/net/{}/submit", net.net), None, submit.to_bytes().map_err(e)?)
        .await
        .map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (403, "FORBIDDEN".to_owned()), "the gateway is no log operator");
    let latest = to_owner.get(&format!("/v4/net/{}/head/latest", net.net)).await.map_err(e)?;
    let latest = bridge_net::WitnessedHead::parse(&latest.body).map_err(e)?;
    let card = net.owner.node.card().clone();
    let head = bridge_net::verify_head(&latest.head, &net.net, &card).map_err(e)?;
    let fake_cosign = bridge_net::issue_cosign(&gateway_key, &head, now_ms()).map_err(e)?;
    let answer = to_owner
        .post(&format!("/v4/net/{}/cosign", net.net), None, fake_cosign.canonical_bytes().to_vec())
        .await
        .map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (403, "FORBIDDEN".to_owned()), "the gateway is no witness");

    // Evidence that does not hold (two honest heads, or heads by a non-operator) is refused.
    let by_gateway = bridge_net::issue_head(&gateway_key, &net.net, 3, [1u8; 32], now_ms()).map_err(e)?;
    let by_gateway2 = bridge_net::issue_head(&gateway_key, &net.net, 3, [2u8; 32], now_ms()).map_err(e)?;
    let evidence = json!({"a": by_gateway.to_value(), "b": by_gateway2.to_value()});
    let answer = to_owner
        .post(&format!("/v4/net/{}/evidence", net.net), None, evidence.to_string().into_bytes())
        .await
        .map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (403, "FORBIDDEN".to_owned()), "not a log operator");
    let evidence = json!({"a": latest.head.to_value(), "b": latest.head.to_value()});
    let answer = to_owner
        .post(&format!("/v4/net/{}/evidence", net.net), None, evidence.to_string().into_bytes())
        .await
        .map_err(e)?;
    assert_eq!((answer.status, code(&answer)), (403, "FORBIDDEN".to_owned()), "the same head twice is no evidence");
    assert!(net.owner.status().deposed.is_empty());
    for node in [gateway, follower] {
        node.node.shutdown().await;
    }
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_without_network_knows_no_network_endpoints() -> TestResult {
    let dir = tempfile::tempdir().map_err(e)?;
    let node = default_node(dir.path()).await?;
    let http = HttpClient::new(&url(&node), Duration::from_secs(10)).map_err(e)?;
    let id = node.card().id().to_string();
    for path in [format!("/v4/net/{id}/head"), format!("/v4/net/{id}/evidence")] {
        assert_eq!(http.get(&path).await.map_err(e)?.status, 404, "{path}");
    }
    for path in [format!("/v4/net/{id}/log"), "/v4/net/join".to_owned(), "/v4/node/relay".to_owned()] {
        let answer = http.post(&path, None, b"{}".to_vec()).await.map_err(e)?;
        assert_eq!((answer.status, code(&answer)), (404, "NOT_FOUND".to_owned()), "{path}");
    }
    assert!(node.net_status().is_none());
    node.shutdown().await;
    Ok(())
}
