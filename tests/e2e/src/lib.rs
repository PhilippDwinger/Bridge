//! Helpers for the cross-compartment tests: start nodes in temporary folders, make clients, send raw requests.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bridge_core::Identity;
use bridge_node::{NodeConfig, RunningNode};
use bridge_sdk::Client;
use bridge_transport::{ClientResponse, HttpClient};
use rand_core::OsRng;
use serde_json::Value;
use tokio::net::TcpListener;

/// Milliseconds since 1970.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(0)).unwrap_or(0)
}

/// Starts a node on a free local port with `config` (its data folder decides its identity).
pub async fn start_node(config: NodeConfig) -> Result<RunningNode, String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    bridge_node::start(config, listener).await
}

/// Starts a node again on the same port (restart test).
pub async fn start_node_on(config: NodeConfig, addr: std::net::SocketAddr) -> Result<RunningNode, String> {
    let mut last = String::new();
    for _ in 0..50 {
        match TcpListener::bind(addr).await {
            Ok(listener) => return bridge_node::start(config, listener).await,
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(last)
}

/// A node with default settings in `dir`.
pub async fn default_node(dir: &Path) -> Result<RunningNode, String> {
    start_node(NodeConfig::new(dir)).await
}

/// Base URL of a running node.
#[must_use]
pub fn url(node: &RunningNode) -> String {
    format!("http://{}", node.local_addr())
}

/// A new client, connected (logged in) to `node`, with the node ID pinned.
pub async fn client(node: &RunningNode) -> Result<Client, String> {
    let mut client = Client::new(Identity::generate(&mut OsRng), &url(node), Some(node.card().id().clone()))
        .map_err(|e| e.to_string())?;
    client.connect().await.map_err(|e| e.to_string())?;
    Ok(client)
}

/// Raw HTTP access for attack tests.
pub fn raw(node: &RunningNode) -> Result<HttpClient, String> {
    HttpClient::new(&url(node), Duration::from_secs(40)).map_err(|e| e.to_string())
}

/// The `error` code of an answer ("" if none).
#[must_use]
pub fn code(answer: &ClientResponse) -> String {
    serde_json::from_slice::<Value>(&answer.body)
        .ok()
        .and_then(|value| value.get("error").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

/// Plain HTTP client for flood tests (custom headers).
pub type RawClient = reqwest::Client;
/// Mailbox quotas (re-exported for tests).
pub use bridge_store::MailboxLimits;
