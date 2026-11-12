//! `bridge-node agent issue|revoke` (docs/10 §3.5): an owner (member) gives a program its own, limited key. The
//! owner logs in at its node over the SDK (so network and home node are the checked ones). User-facing texts are
//! German.

use std::path::Path;

use bridge_core::{Id, Role};
use bridge_node::keyfile;
use bridge_sdk::{AgentRights, Client};

fn owner(path: &str) -> Result<bridge_core::Identity, String> {
    if !Path::new(path).exists() {
        return Err(format!("{path}: Schlüsseldatei des Inhabers fehlt"));
    }
    keyfile::load_or_create_at(Path::new(path))
}

async fn connected(owner_key: &str, node_url: &str) -> Result<Client, String> {
    let mut client = Client::new(owner(owner_key)?, node_url, None).map_err(|e| e.to_string())?;
    client.connect().await.map_err(|e| format!("Anmelden als Inhaber: {e}"))?;
    Ok(client)
}

/// Issues an agent statement; returns (agent ID, statement JSON). Creates the agent's key file if it is missing.
pub async fn issue(
    owner_key: &str,
    agent_key: &str,
    node_url: &str,
    rights: &AgentRights,
) -> Result<(Id, Vec<u8>), String> {
    let client = connected(owner_key, node_url).await?;
    let agent = keyfile::load_or_create_at(Path::new(agent_key))?;
    let card = agent.key_card(Role::Client, rights.note.as_deref(), now()).map_err(|e| e.to_string())?;
    let statement = client.issue_agent(&card, rights).map_err(|e| e.to_string())?;
    Ok((agent.id().clone(), statement.canonical_bytes().to_vec()))
}

/// Revokes an agent at the owner's node; returns whether a session ended.
pub async fn revoke(owner_key: &str, node_url: &str, agent: &Id) -> Result<bool, String> {
    let client = connected(owner_key, node_url).await?;
    client.revoke_agent(agent).await.map_err(|e| e.to_string())
}

/// Parses `--scopes send,receive` into (send, receive).
pub fn scopes(text: &str) -> Result<(bool, bool), String> {
    let (mut send, mut receive) = (false, false);
    for scope in text.split(',').map(str::trim) {
        match scope {
            "send" => send = true,
            "receive" => receive = true,
            other => return Err(format!("--scopes: unbekanntes Recht {other:?} (nur send, receive)")),
        }
    }
    if !(send || receive) {
        return Err("--scopes: mindestens send oder receive".into());
    }
    Ok((send, receive))
}

fn now() -> i64 {
    use bridge_node::Clock as _;
    bridge_node::SystemClock.now_ms()
}
