//! The owner backup in BridgeControll (docs/12 §10): every owner node of this PC is backed up 2 minutes after the
//! start and then every hour - a new version only when something changed (else every 30 days) - and "Netz
//! wiederherstellen" brings an owner node back on a new PC with the 24 words and one address of the network.
//! The work itself is `bridge_node_cli::backup`; the words are never stored or logged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::{JoinLink, Mnemonic};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::config::{self, NodeEntry, NodeRole};
use crate::ops::{self, entry_of};
use crate::{App, now_ms};

/// First backup after the start.
const FIRST: Duration = Duration::from_secs(120);
/// Then every hour (a new version only if something changed).
const EVERY: Duration = Duration::from_secs(3600);
/// Longest words text taken.
const MAX_WORDS_CHARS: usize = 1024;

/// The last error per node (memory only).
#[derive(Debug, Default)]
pub struct Errors(Mutex<HashMap<String, String>>);

impl Errors {
    fn set(&self, id: &str, error: Option<String>) {
        let mut map = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match error {
            Some(error) => {
                map.insert(id.to_owned(), error);
            }
            None => {
                map.remove(id);
            }
        }
    }

    fn get(&self, id: &str) -> Option<String> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id).cloned()
    }
}

/// What of the node's settings goes into the backup (no paths of this PC).
#[must_use]
pub fn settings(entry: &NodeEntry) -> Value {
    json!({
        "name": entry.name,
        "net_name": entry.net_name,
        "listen_port": entry.listen_port,
        "lan_port": entry.lan_port,
        "autostart": entry.autostart,
        "reader": entry.reader.as_str(),
        "peer_addresses": entry.peer_addresses.as_str(),
    })
}

/// The backup state of an owner node for the dashboard.
#[must_use]
pub fn status(app: &App, entry: &NodeEntry) -> Value {
    let last = bridge_node_cli::backup::last(&app.node_dir(entry));
    json!({
        "at": last.as_ref().and_then(|v| v.get("at")).cloned(),
        "hosts": last.as_ref().and_then(|v| v.get("hosts")).cloned(),
        "error": app.backup_errors.get(&entry.id),
    })
}

/// Backs the owner node `id` up now (`force`: a new version even without a change).
pub async fn backup_now(app: &App, id: &str, force: bool) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    if entry.role != NodeRole::Owner {
        return Err("Nur der Owner-Knoten hat ein Backup".into());
    }
    let result =
        bridge_node_cli::backup::make(&app.node_dir(&entry), &settings(&entry), Some(&entry.local_url()), force).await;
    match result {
        Ok(made) => {
            app.backup_errors.set(id, None);
            tracing::info!(node = %id, published = made.published, statement = made.statement, "Owner-Backup");
            Ok(status(app, &entry))
        }
        Err(error) => {
            app.backup_errors.set(id, Some(error.clone()));
            Err(error)
        }
    }
}

/// Backs every running owner node up after [`FIRST`], then every [`EVERY`].
pub async fn rounds(app: Arc<App>) {
    tokio::time::sleep(FIRST).await;
    loop {
        let owners: Vec<NodeEntry> =
            app.config.lock().await.nodes.iter().filter(|entry| entry.role == NodeRole::Owner).cloned().collect();
        for entry in owners {
            if app.supervisor.status(&entry.id).state != crate::supervisor::RunState::Running {
                continue;
            }
            if let Err(error) = backup_now(&app, &entry.id, false).await {
                tracing::warn!(node = %entry.id, %error, "Owner-Backup");
            }
        }
        tokio::time::sleep(EVERY).await;
    }
}

/// `POST /api/restore {words, address}`: an owner node from its backup (docs/12 §10.4) - a new node of this PC with
/// the restored keys, the settings from the backup and the address as its first source of the log; it starts at once.
pub async fn restore(app: &App, body: &Map<String, Value>) -> Result<Value, String> {
    let words = Zeroizing::new(body.get("words").and_then(Value::as_str).unwrap_or_default().to_owned());
    if words.chars().count() > MAX_WORDS_CHARS {
        return Err("Das sind keine 24 Wörter.".into());
    }
    let normalized = Zeroizing::new(words.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase());
    let master = Mnemonic::parse(&normalized)
        .and_then(|words| words.to_identity())
        .map_err(|_| "Das sind keine gültigen 24 Wörter (Prüfsumme).".to_owned())?;
    let raw = body.get("address").and_then(Value::as_str).unwrap_or_default().trim();
    // A join link names its gateway; else the address itself.
    let address = match JoinLink::parse(raw) {
        Ok(link) if &link.net == master.id() => link.gateway,
        Ok(_) => return Err("Dieser Link gehört zu einem anderen Netz als die Wörter.".into()),
        Err(_) => raw.trim_end_matches('/').to_owned(),
    };
    if !(address.starts_with("https://") || address.starts_with("http://")) || address.len() > 512 {
        return Err("Adresse: z. B. https://pc.tail1234.ts.net/bridge4/meinnetz oder ein Einladungslink".into());
    }
    let mut entry = {
        let config = app.config.lock().await;
        if config.nodes.len() >= config::MAX_NODES {
            return Err(format!("Höchstens {} Knoten pro PC", config::MAX_NODES));
        }
        let (listen, _) = ops::suggested_ports(&config);
        NodeEntry {
            id: ops::new_node_id(&config, &app.options.app_dir),
            name: "Owner-Knoten".into(),
            net_name: String::new(),
            role: NodeRole::Owner,
            listen_port: listen,
            lan_port: None,
            public_url: None,
            autostart: true,
            join_link: None,
            probe: None,
            offer_gateway: false,
            peer_addresses: bridge_transport::PeerAddresses::Tailnet,
            reader: bridge_node::ReaderAccess::Local,
            reader_port: None,
            public_key: None,
            public_web: true,
            created: now_ms(),
        }
    };
    let dir = app.node_dir(&entry);
    let restored = match bridge_node_cli::backup::restore(&master, &address, &dir).await {
        Ok(restored) => restored,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(error);
        }
    };
    let text = |name: &str| restored.settings.get(name).and_then(Value::as_str).map(str::to_owned);
    if let Some(name) = text("name").filter(|name| config::check_name(name, "x").is_ok()) {
        entry.name = name;
    }
    if let Some(name) = text("net_name").filter(|name| config::check_name(name, "x").is_ok()) {
        entry.net_name = name;
    }
    let link = JoinLink { net: restored.net.clone(), gateway: address, code: None, node: None, tls: None };
    entry.join_link = Some(link.to_link());
    entry.check()?;
    ops::save(app, |config| {
        config.nodes.push(entry.clone());
        Ok(())
    })
    .await?;
    app.start_node(&entry);
    Ok(json!({"node": entry.id, "net": restored.net.as_str(), "files": restored.files}))
}
