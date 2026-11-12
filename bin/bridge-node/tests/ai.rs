//! Phase 6 (docs/10 §4, ADR 0024): the local AI service answers tasks with a model on this PC - here a fake Ollama
//! on loopback. Not allowed senders, bad tasks and too many tasks get error replies; only the asker gets the answer.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bridge_ai::{Allow, Api, Config};
use bridge_core::Identity;
use bridge_net::JoinMode;
use bridge_node_cli::ai;
use bridge_sdk::Client;
use bridge_tests::net::{TestNet, eventually, joined};
use rand_core::OsRng;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type TestResult = Result<(), String>;

fn e(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// A fake Ollama: answers every request with `Echo: <prompt>` (and counts the requests).
async fn fake_ollama() -> Result<(String, Arc<AtomicUsize>), String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(e)?;
    let url = format!("http://{}", listener.local_addr().map_err(e)?);
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0u8; 8192];
                // Read headers and the declared body.
                loop {
                    let Ok(read) = stream.read(&mut buffer).await else { return };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    let text = String::from_utf8_lossy(&request).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_owned())
                            })
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            let body: Value =
                                serde_json::from_slice(&request[end + 4..end + 4 + length]).unwrap_or_default();
                            counter.fetch_add(1, Ordering::SeqCst);
                            let prompt = body["prompt"].as_str().unwrap_or("?");
                            let answer =
                                json!({"model": body["model"], "response": format!("Echo: {prompt}"), "done": true,
                                                "total_duration": 12.5})
                                .to_string();
                            let reply = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                                answer.len()
                            );
                            let _ = stream.write_all(reply.as_bytes()).await;
                            return;
                        }
                    }
                }
            });
        }
    });
    Ok((url, count))
}

fn answer(message: Option<bridge_sdk::Received>) -> Result<Value, String> {
    let message = message.ok_or("no answer")?;
    match message.content.payload {
        bridge_core::Payload::Data(bytes) => serde_json::from_slice(&bytes).map_err(e),
        other => Err(format!("{other:?}")),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ai_service_answers_with_a_local_model() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let (backend, count) = fake_ollama().await?;
    let dir = tempfile::tempdir().map_err(e)?;
    let service = ai::connect(&dir.path().join("ai-key.json"), &ai::Reach::Join(net.link(None))).await?;
    let service_id = service.identity().id().clone();
    let mut alice = joined(&net.link(None)).await?;
    let mut bob = joined(&net.link(None)).await?;
    let config = Config {
        api: Api::Ollama,
        backend,
        model: "llama3.2".into(),
        models: Vec::new(),
        allow: Allow::List(vec![alice.identity().id().clone()]),
        allow_agents: false,
        rate: 3,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(ai::serve(service, config, async {
        let _ = stopped.await;
    }));

    let card = eventually("service card", || async { alice.card_of(&service_id).await.map_err(e) }).await?;
    let wait = Duration::from_secs(20);
    // Alice may ask: the model's answer comes back.
    let task = json!({"prompt": "Wie spät ist es?", "max_tokens": 20}).to_string();
    let first = answer(alice.request(&card, None, task.as_bytes(), wait).await.map_err(e)?)?;
    assert_eq!((first["text"].as_str(), first["model"].as_str()), (Some("Echo: Wie spät ist es?"), Some("llama3.2")));
    // A bad task: error reply, the model is not asked.
    let bad = answer(alice.request(&card, None, br#"{"prompt":""}"#, wait).await.map_err(e)?)?;
    assert_eq!(bad["error"], json!("BAD_TASK"));
    // Bob is not on the list.
    let bob_card = bob.card_of(&service_id).await.map_err(e)?;
    let refused = answer(bob.request(&bob_card, None, task.as_bytes(), wait).await.map_err(e)?)?;
    assert_eq!(refused["error"], json!("NOT_ALLOWED"));
    // Rate 3 per hour (the bad task counted too): the fourth task of Alice is refused.
    let second = answer(alice.request(&card, None, task.as_bytes(), wait).await.map_err(e)?)?;
    assert!(second["text"].is_string());
    let third = answer(alice.request(&card, None, task.as_bytes(), wait).await.map_err(e)?)?;
    assert_eq!(third["error"], json!("RATE_LIMITED"));
    assert_eq!(count.load(Ordering::SeqCst), 2, "the model was asked only for the two allowed tasks");

    let _ = stop.send(());
    running.await.map_err(e)??;
    net.owner.node.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn backend_must_be_on_this_pc() -> TestResult {
    let net = TestNet::create(JoinMode::Open).await?;
    let service = Client::join(Identity::generate(&mut OsRng), &net.link(None)).await.map_err(e)?;
    let config = Config {
        api: Api::OpenAi,
        backend: "https://api.example.com".into(),
        model: "x".into(),
        models: Vec::new(),
        allow: Allow::Members,
        allow_agents: false,
        rate: 1,
    };
    let refused = ai::serve(service, config, async {}).await;
    assert!(refused.is_err_and(|message| message.contains("--backend")));
    net.owner.node.shutdown().await;
    Ok(())
}
