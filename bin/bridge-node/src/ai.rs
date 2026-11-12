//! `bridge-node ai` (docs/10 §4, ADR 0024): the local AI service. A client of the network with its own identity: it
//! fetches tasks, asks a model server on this PC (loopback only) and answers the verified sender end to end. One task
//! at a time; at most 16 tasks per round, the rest are told `BUSY`. The logic lives in `services/ai`.

use std::path::Path;
use std::time::Duration;

use bridge_ai::{Config, Limiter};
use bridge_core::{Content, ContentType, Payload};
use bridge_node::keyfile;
use bridge_plugin_api::{Reply, Task};
use bridge_sdk::{Client, Received};
use bridge_transport::HttpClient;

/// Most tasks handled per round (the rest get `BUSY`).
pub const MAX_QUEUE: usize = 16;
/// Time limit of one model answer.
pub const BACKEND_TIMEOUT: Duration = Duration::from_secs(120);

/// How the service reaches its network.
pub enum Reach {
    /// Join with a link (first start).
    Join(String),
    /// Log in at a node (already a member).
    Node(String),
}

/// Connects the service's identity (key file, made on first use).
pub async fn connect(key: &Path, reach: &Reach) -> Result<Client, String> {
    let identity = keyfile::load_or_create_at(key)?;
    match reach {
        Reach::Join(link) => Client::join(identity, link).await.map_err(|e| format!("Beitritt: {e}")),
        Reach::Node(url) => {
            let mut client = Client::new(identity, url, None).map_err(|e| e.to_string())?;
            client.connect().await.map_err(|e| format!("Anmelden: {e}"))?;
            Ok(client)
        }
    }
}

/// Serves tasks until `shutdown` completes.
pub async fn serve(
    mut client: Client,
    config: Config,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), String> {
    bridge_ai::check_backend(&config.backend)?;
    let backend = HttpClient::new(&config.backend, BACKEND_TIMEOUT).map_err(|e| e.to_string())?;
    let mut limiter = Limiter::default();
    tokio::pin!(shutdown);
    loop {
        let inbox = tokio::select! {
            () = &mut shutdown => return Ok(()),
            inbox = client.receive(20) => inbox,
        };
        let inbox = match inbox {
            Ok(inbox) => inbox,
            Err(bridge_sdk::SdkError::Node { code, .. }) if code == "NO_SESSION" => {
                client.connect().await.map_err(|e| format!("Neu anmelden: {e}"))?;
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, "receive");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        let tasks: Vec<Received> =
            inbox.messages.into_iter().filter(|message| message.content.kind == ContentType::Task).collect();
        for (index, message) in tasks.into_iter().enumerate() {
            let task = task_of(&message);
            let reply = if index >= MAX_QUEUE {
                bridge_ai::error(&task, "BUSY", "gerade zu viele Aufgaben - später noch einmal")
            } else {
                handle(&task, &config, &mut limiter, &backend).await
            };
            if let Err(error) = send_reply(&client, &message, &reply).await {
                tracing::warn!(%error, to = %message.from, "reply not sent");
            }
        }
    }
}

fn task_of(message: &Received) -> Task {
    let data = match &message.content.payload {
        Payload::Data(bytes) => bytes.clone(),
        Payload::Text(text) => text.as_bytes().to_vec(),
        Payload::Stream(_) => Vec::new(),
    };
    Task {
        id: message.id,
        from: message.from.clone(),
        agent_of: message.agent_of.as_ref().map(|of| of.owner.clone()),
        ctype: message.content.ctype.clone(),
        data,
    }
}

async fn handle(task: &Task, config: &Config, limiter: &mut Limiter, backend: &HttpClient) -> Reply {
    let request = match bridge_ai::access(task, config)
        .and_then(|()| limiter.admit(task, config.rate, now()))
        .and_then(|()| bridge_ai::parse_task(task, config))
    {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    let (path, body) = bridge_ai::backend_request(config.api, &request);
    match backend.post(path, None, body).await {
        Ok(answer) if answer.status == 200 => match bridge_ai::parse_backend(config.api, &answer.body) {
            Ok(text) => bridge_ai::answer(task, &request.model, &text),
            Err(message) => bridge_ai::error(task, "BACKEND", &message),
        },
        Ok(answer) => bridge_ai::error(task, "BACKEND", &format!("Modell-Server antwortet {}", answer.status)),
        Err(error) => bridge_ai::error(task, "BACKEND", &format!("Modell-Server nicht erreichbar: {error}")),
    }
}

/// The reply goes to the task's verified sender only (in its network).
async fn send_reply(client: &Client, message: &Received, reply: &Reply) -> Result<(), String> {
    let card = client.card_of(&message.from).await.map_err(|e| e.to_string())?;
    let mut content = Content::data(ContentType::Response, reply.ctype.clone(), reply.data.clone());
    content.reply = Some(reply.task);
    client.send_to_net(&card, &message.net, &content).await.map(|_| ()).map_err(|e| e.to_string())
}

fn now() -> i64 {
    use bridge_node::Clock as _;
    bridge_node::SystemClock.now_ms()
}
