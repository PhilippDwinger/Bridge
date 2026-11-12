//! `sdk-fixture` (docs/10 §2.3): a live counterpart for the SDK tests of other languages. Starts an open test network
//! (one node on 127.0.0.1), an **echo client** in Rust and an **echo agent** (an agent of the echo client), prints one
//! line of JSON (`{"link","url","net","node","echo","echo_agent"}`) and serves until stdin closes (at most 15 minutes):
//!
//! - text `t` → answer `echo: t` (with ` [agent of <owner>]` if the sender is an agent and its statement checks out);
//! - a task (`application/json`) → a response with the same data, naming the task;
//! - text `agent-hello` → additionally the echo agent writes `hallo vom agent` to the sender.

use std::io::Read as _;
use std::time::{Duration, Instant};

use bridge_core::{Content, ContentType, Identity, Payload, Role};
use bridge_net::JoinMode;
use bridge_sdk::{AgentRights, Client, Received};
use bridge_tests::net::{TestNet, eventually};
use rand_core::OsRng;
use serde_json::json;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("sdk-fixture: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let net = TestNet::create(JoinMode::Open).await?;
    let mut echo = Client::join(Identity::generate(&mut OsRng), &net.link(None)).await.map_err(|e| e.to_string())?;
    let agent_key = Identity::generate(&mut OsRng);
    let agent_card = agent_key.key_card(Role::Client, Some("Echo-Agent"), 1).map_err(|e| e.to_string())?;
    let rights = AgentRights { note: Some("Echo-Agent".into()), ..AgentRights::default() };
    let statement = echo.issue_agent(&agent_card, &rights).map_err(|e| e.to_string())?;
    let mut agent = Client::new(agent_key, &net.owner.url, None)
        .and_then(|client| client.with_agent(statement))
        .map_err(|e| e.to_string())?;
    agent.connect().await.map_err(|e| e.to_string())?;
    let node = echo.node_card().map(|card| card.id().to_string()).unwrap_or_default();
    println!(
        "{}",
        json!({
            "link": net.link(None),
            "url": net.owner.url,
            "net": net.net.as_str(),
            "node": node,
            "echo": echo.identity().id().as_str(),
            "echo_agent": agent.identity().id().as_str(),
        })
    );
    // Stdin closed (or 15 minutes): stop.
    let (done_tx, mut done) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        let _ = done_tx.send(());
    });
    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    while Instant::now() < deadline {
        let inbox = tokio::select! {
            _ = &mut done => break,
            inbox = echo.receive(1) => inbox.map_err(|e| e.to_string())?,
        };
        for message in inbox.messages {
            if let Err(error) = answer(&echo, &agent, &message).await {
                eprintln!("sdk-fixture: answer failed: {error}");
            }
        }
        // The agent's own inbox is drained (it only writes).
        let _ = agent.receive(0).await;
    }
    net.owner.node.shutdown().await;
    Ok(())
}

async fn answer(echo: &Client, agent: &Client, message: &Received) -> Result<(), String> {
    let card =
        eventually("sender card", || async { echo.card_of(&message.from).await.map_err(|e| e.to_string()) }).await?;
    let mut reply = match (&message.content.kind, &message.content.payload) {
        (ContentType::Task, Payload::Data(data)) => {
            Content::data(ContentType::Response, message.content.ctype.clone(), data.clone())
        }
        (_, Payload::Text(text)) => {
            let mut answer = format!("echo: {text}");
            if let Some(of) = &message.agent_of {
                answer.push_str(&format!(" [agent of {}]", of.owner));
            }
            if text == "agent-hello" {
                let to = agent.card_of(&message.from).await.map_err(|e| e.to_string())?;
                agent
                    .send(&to, &Content::text(ContentType::Direct, "hallo vom agent"))
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Content::text(ContentType::Response, answer)
        }
        (_, Payload::Data(data)) => Content::data(ContentType::Response, message.content.ctype.clone(), data.clone()),
        (_, Payload::Stream(_)) => return Ok(()),
    };
    reply.reply = Some(message.id);
    echo.send_to_net(&card, &message.net, &reply).await.map(|_| ()).map_err(|e| e.to_string())
}
