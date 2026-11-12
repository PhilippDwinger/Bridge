//! Phase 6 (docs/10 §6, ADR 0023): two networks connect - only when both net keys agree - and their members write to
//! each other end to end through the listed gateways. One-sided, unlisted callers, wrong target networks and
//! revocations are refused.

use std::time::{Duration, Instant};

use bridge_core::{Content, ContentType, Envelope, Identity, Payload, Role, SignedRequest};
use bridge_net::{JoinMode, RevokeTarget};
use bridge_sdk::{Client, SdkError};
use bridge_tests::net::{PATIENCE, TestNet, eventually, joined};
use bridge_transport::HttpClient;
use rand_core::OsRng;
use serde_json::json;

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

fn code_of<T: std::fmt::Debug>(result: Result<T, SdkError>) -> String {
    match result {
        Err(SdkError::Node { code, .. }) => code,
        other => format!("{other:?}"),
    }
}

async fn receive_within(client: &mut Client, patience: Duration) -> Result<Option<bridge_sdk::Received>, String> {
    let deadline = Instant::now() + patience;
    loop {
        let inbox = client.receive(1).await.map_err(e)?;
        if let Some(message) = inbox.messages.into_iter().next() {
            return Ok(Some(message));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connected_networks_exchange_messages_both_ways() -> TestResult {
    let a = TestNet::create(JoinMode::Open).await?;
    let b = TestNet::create(JoinMode::Open).await?;
    let mut alice = joined(&a.link(None)).await?;
    let mut bob = joined(&b.link(None)).await?;
    let bob_id = bob.identity().id().clone();

    // Only A connects: B's gateway does not answer for A.
    let (_, from_a) = a.admin.federate(&a.master, &b.net, std::slice::from_ref(&b.owner.url), 30).await?;
    assert_eq!(code_of(alice.card_of_in(&bob_id, &b.net).await), "NOT_FOUND");
    // Another key than the net key can not connect networks.
    let stranger = Identity::generate(&mut OsRng);
    assert!(a.admin.federate(&stranger, &b.net, std::slice::from_ref(&b.owner.url), 30).await.is_err());

    // B connects too: cards and messages flow, A -> B and back.
    b.admin.federate(&b.master, &a.net, std::slice::from_ref(&a.owner.url), 30).await?;
    let bob_card =
        eventually("card from the other network", || async { alice.card_of_in(&bob_id, &b.net).await.map_err(e) })
            .await?;
    eventually("envelope accepted", || async {
        alice
            .send_to_net(&bob_card, &b.net, &Content::text(ContentType::Direct, "Hallo Netz B"))
            .await
            .map(|_| ())
            .map_err(e)
    })
    .await?;
    let message = receive_within(&mut bob, PATIENCE).await?.ok_or("no message in network B")?;
    assert_eq!(
        (text(&message.content), &message.from, &message.net),
        ("Hallo Netz B".into(), alice.identity().id(), &a.net)
    );
    let alice_card = bob.card_of(&message.from).await.map_err(e)?;
    bob.send_to_net(&alice_card, &a.net, &Content::text(ContentType::Response, "Hallo zurück")).await.map_err(e)?;
    let answer = receive_within(&mut alice, PATIENCE).await?.ok_or("no answer in network A")?;
    assert_eq!((text(&answer.content), &answer.net), ("Hallo zurück".into(), &b.net));

    // A network that is not connected: refused at the sender's node.
    let c = TestNet::create(JoinMode::Open).await?;
    assert_eq!(
        code_of(alice.send_to_net(&bob_card, &c.net, &Content::text(ContentType::Direct, "x")).await),
        "FORBIDDEN"
    );

    // Only listed gateways deliver: a stranger's fed-relay is refused.
    let mallory = Identity::generate(&mut OsRng);
    let mallory_card = mallory.key_card(Role::Client, None, bridge_tests::now_ms()).map_err(e)?;
    let address = bridge_core::Address {
        net: &a.net,
        to: &bob_card,
        kind: bridge_core::Kind::Msg,
        iat: bridge_tests::now_ms(),
        ttl: 600,
    };
    let envelope = Envelope::seal_for_net(&mallory, &address, &b.net, b"{}", &mut OsRng).map_err(e)?;
    let bytes = envelope.to_bytes().map_err(e)?;
    let hash = bridge_core::encoding::b64(&bridge_core::crypto::sha256(&bytes));
    let b_node = bob.node_card().ok_or("node card")?.id().clone();
    let request = SignedRequest::sign(
        &mallory,
        &b_node,
        "fed-relay",
        json!({"envelope": hash, "card": mallory_card.to_value()}),
        bridge_tests::now_ms(),
        &mut OsRng,
    )
    .map_err(e)?;
    let wire = json!({"envelope": envelope.to_value_for_tests(), "rq": request.to_value()}).to_string();
    let raw = HttpClient::new(&b.owner.url, Duration::from_secs(10)).map_err(e)?;
    let refused = raw.post("/v4/fed/relay", None, wire.into_bytes()).await.map_err(e)?;
    assert_eq!(refused.status, 403, "{}", String::from_utf8_lossy(&refused.body));
    let card_request = SignedRequest::sign(
        &mallory,
        &b_node,
        "fed-card",
        json!({"id": bob_id.as_str()}),
        bridge_tests::now_ms(),
        &mut OsRng,
    )
    .map_err(e)?;
    let refused = raw.post("/v4/fed/card", None, card_request.to_bytes().map_err(e)?).await.map_err(e)?;
    assert_eq!(refused.status, 403);

    // A disconnects: no more sending from A.
    // An admin can not disconnect; the net key can.
    let hash = bridge_core::encoding::b64_fixed::<32>(&from_a.hash, "hash").map_err(e)?;
    assert!(a.admin.revoke(RevokeTarget::Statement(hash), "Test").await.is_err());
    a.admin.unfederate(&a.master, &b.net).await?;
    let blocked = eventually("A no longer connected", || async {
        match alice.send_to_net(&bob_card, &b.net, &Content::text(ContentType::Direct, "noch da?")).await {
            Err(SdkError::Node { code, .. }) if code == "FORBIDDEN" => Ok(()),
            other => Err(format!("still accepted: {other:?}")),
        }
    })
    .await;
    blocked?;
    c.owner.node.shutdown().await;
    a.owner.node.shutdown().await;
    b.owner.node.shutdown().await;
    Ok(())
}
