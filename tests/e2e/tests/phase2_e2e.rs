//! Phase 2 acceptance (docs/05): two clients exchange encrypted messages through a node; the node demonstrably
//! cannot read them; messages not yet fetched survive a restart.

use std::time::{Duration, Instant};

use bridge_core::{Content, ContentType, Payload};
use bridge_node::NodeConfig;
use bridge_sdk::SdkError;
use bridge_tests::{client, default_node, start_node_on};
use rand_core::{OsRng, RngCore};

type TestResult = Result<(), String>;

fn text(content: &Content) -> String {
    match &content.payload {
        Payload::Text(text) => text.clone(),
        other => format!("{other:?}"),
    }
}

fn secret_marker() -> String {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    format!("geheim-{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn files_contain(dir: &std::path::Path, needle: &[u8]) -> Result<bool, String> {
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_file() {
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_clients_talk_and_the_node_cannot_read() -> TestResult {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let node = default_node(dir.path()).await?;
    let alice = client(&node).await?;
    let mut bob = client(&node).await?;

    let marker = secret_marker();
    let bob_card = alice.card_of(bob.identity().id()).await.map_err(|e| e.to_string())?;
    alice.send(&bob_card, &Content::text(ContentType::Direct, marker.clone())).await.map_err(|e| e.to_string())?;

    // The node holds the message now - but nowhere in its files is the plaintext.
    assert!(!files_contain(dir.path(), marker.as_bytes())?, "plaintext found in the node's files");

    let inbox = bob.receive(5).await.map_err(|e| e.to_string())?;
    assert_eq!(inbox.rejected, 0);
    assert_eq!(inbox.messages.len(), 1);
    assert_eq!(&inbox.messages[0].from, alice.identity().id());
    assert_eq!(text(&inbox.messages[0].content), marker);

    // Acknowledged: gone from the node.
    let again = bob.receive(0).await.map_err(|e| e.to_string())?;
    assert!(again.messages.is_empty());

    // And back: Bob answers Alice.
    let mut alice = alice;
    let alice_card = bob.card_of(alice.identity().id()).await.map_err(|e| e.to_string())?;
    let original = inbox.messages[0].id;
    let mut answer = Content::text(ContentType::Response, "angekommen");
    answer.reply = Some(original);
    bob.send(&alice_card, &answer).await.map_err(|e| e.to_string())?;
    let inbox = alice.receive(5).await.map_err(|e| e.to_string())?;
    assert_eq!(text(&inbox.messages[0].content), "angekommen");
    assert_eq!(inbox.messages[0].content.reply, Some(original));
    node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_poll_wakes_up_when_a_message_arrives() -> TestResult {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let node = default_node(dir.path()).await?;
    let alice = client(&node).await?;
    let mut bob = client(&node).await?;
    let bob_card = alice.card_of(bob.identity().id()).await.map_err(|e| e.to_string())?;

    let started = Instant::now();
    let waiting = tokio::spawn(async move { (bob.receive(20).await.map_err(|e| e.to_string()), bob) });
    tokio::time::sleep(Duration::from_millis(400)).await;
    alice.send(&bob_card, &Content::text(ContentType::Direct, "jetzt")).await.map_err(|e| e.to_string())?;
    let (inbox, _bob) = waiting.await.map_err(|e| e.to_string())?;
    let inbox = inbox?;
    assert_eq!(inbox.messages.len(), 1);
    assert!(started.elapsed() < Duration::from_secs(3), "woke up after {:?}", started.elapsed());
    node.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_survive_a_restart() -> TestResult {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let node = default_node(dir.path()).await?;
    let addr = node.local_addr();
    let node_id = node.card().id().clone();
    let alice = client(&node).await?;
    let mut bob = client(&node).await?;
    let bob_card = alice.card_of(bob.identity().id()).await.map_err(|e| e.to_string())?;
    for i in 0..3 {
        alice
            .send(&bob_card, &Content::text(ContentType::Direct, format!("vor dem Neustart {i}")))
            .await
            .map_err(|e| e.to_string())?;
    }
    node.shutdown().await;

    let node = start_node_on(NodeConfig::new(dir.path()), addr).await?;
    assert_eq!(node.card().id(), &node_id, "same identity after restart");

    // Sessions live in RAM only: the old one is gone ...
    match bob.receive(0).await {
        Err(SdkError::Node { code, .. }) => assert_eq!(code, "NO_SESSION"),
        other => return Err(format!("expected NO_SESSION, got {other:?}")),
    }
    // ... after logging in again, everything not yet fetched is still there.
    bob.connect().await.map_err(|e| e.to_string())?;
    let inbox = bob.receive(0).await.map_err(|e| e.to_string())?;
    let texts: Vec<String> = inbox.messages.iter().map(|m| text(&m.content)).collect();
    assert_eq!(texts, vec!["vor dem Neustart 0", "vor dem Neustart 1", "vor dem Neustart 2"]);
    node.shutdown().await;
    Ok(())
}
