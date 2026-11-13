//! Public through the gate (docs/11 §5, ADR 0025): "Öffentlich machen", "Websites aus/an" (Not-Aus), "Nicht mehr
//! öffentlich", the gate process and Tailscale Funnel.
//!
//! - **The gate** runs as its own supervised process (`bridgecontroll gate`, id [`GATE_ID`]) with the routes this app
//!   writes (`gate/routes.json`, owner-only): one route per public node (`key` → its port, `web`). Any change writes
//!   the file and restarts the gate; without public nodes it is stopped.
//! - **Tailscale**: only `tailscale status --json` (the PC's name) and `tailscale funnel` for exactly `/bridge4` on
//!   the chosen port - set when the first node goes public, removed when the last one stops (only if this app set
//!   it). Never `reset`, never another path: entries of BridgeControll 3 or by hand stay as they are. Fixed arguments,
//!   no shell, 40 s at most ([`TailscaleCli`] - tests put a stand-in there).
//! - **Checks**: only the owner's node (the owner decides for the network); it runs and knows its network; the network
//!   forbids 18+ (else never public, ADR 0018); one public node per network on this PC. The network key is its short name (or its ID if that key is taken) and stays fixed.
//! - The owner's own node is **sealed again** with its new card (level and services as before), so the network learns
//!   its public address; a member's node shows "Karte veraltet" until its owner seals it again.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bridge_gate::{Bridge3Route, Route, Routes};
use bridge_net::{AdultPolicy, Service, Services};
use serde_json::{Value, json};

use crate::config::{self, AppConfig, NodeEntry, NodeRole, check_host};
use crate::ops::{self, admin_client, entry_of, patient, save};
use crate::supervisor::{Launch, RunState};
use crate::{App, now_ms};

/// The gate's ID at the supervisor (no node ID has this form).
pub const GATE_ID: &str = "gate";
/// First port tried for the gate.
pub const FIRST_GATE_PORT: u16 = 7390;
/// The path Tailscale Funnel gives the gate.
pub const FUNNEL_PATH: &str = "/bridge4";
/// Longest wait for a `tailscale` command.
const TAILSCALE_TIMEOUT: Duration = Duration::from_secs(40);
/// Most output of a `tailscale` command read.
const MAX_OUTPUT: usize = 8 * 1024 * 1024;

/// What a `tailscale` command printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOutput {
    /// Exit code (`-1` if it had none).
    pub code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// A boxed future (for the object-safe [`TailscaleCli`]).
pub type CliFuture<'a> = Pin<Box<dyn Future<Output = Result<CliOutput, String>> + Send + 'a>>;

/// Runs the `tailscale` command line.
pub trait TailscaleCli: Send + Sync + std::fmt::Debug {
    /// Runs `tailscale <args>` (fixed arguments, no shell).
    fn run(&self, args: Vec<String>) -> CliFuture<'_>;
}

/// The real `tailscale`: `BRIDGECONTROLL_TAILSCALE` if set, else `C:\Program Files\Tailscale\tailscale.exe` on
/// Windows if it exists, else `tailscale` from the path.
#[derive(Debug, Clone)]
pub struct SystemTailscale {
    exe: PathBuf,
}

impl SystemTailscale {
    /// Finds the program (see type docs).
    #[must_use]
    pub fn find() -> Self {
        if let Some(exe) = std::env::var_os("BRIDGECONTROLL_TAILSCALE").filter(|exe| !exe.is_empty()) {
            return Self { exe: PathBuf::from(exe) };
        }
        let windows = PathBuf::from(r"C:\Program Files\Tailscale\tailscale.exe");
        if cfg!(windows) && windows.exists() {
            return Self { exe: windows };
        }
        Self { exe: PathBuf::from("tailscale") }
    }
}

impl TailscaleCli for SystemTailscale {
    fn run(&self, args: Vec<String>) -> CliFuture<'_> {
        Box::pin(async move {
            let mut command = tokio::process::Command::new(&self.exe);
            command
                .args(&args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            #[cfg(windows)]
            {
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                command.creation_flags(CREATE_NO_WINDOW);
            }
            let output = tokio::time::timeout(TAILSCALE_TIMEOUT, command.output())
                .await
                .map_err(|_| "Tailscale antwortet nicht (40 s).".to_owned())?
                .map_err(|e| format!("Tailscale nicht startbar ({e}) - ist Tailscale installiert?"))?;
            let text = |bytes: &[u8]| String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT)]).into_owned();
            Ok(CliOutput {
                code: output.status.code().unwrap_or(-1),
                stdout: text(&output.stdout),
                stderr: text(&output.stderr),
            })
        })
    }
}

/// The PC's Tailscale name from `tailscale status --json`: running and signed in, `Self.DNSName` without the dot.
///
/// # Errors
/// Not running, not signed in, no name, odd output (German, for people).
pub fn host_from_status(output: &CliOutput) -> Result<String, String> {
    if output.code != 0 {
        return Err(format!(
            "Tailscale läuft nicht oder ist nicht angemeldet: {}",
            short(&output.stderr, &output.stdout)
        ));
    }
    let value: Value = serde_json::from_str(&output.stdout).map_err(|_| "Tailscale antwortet unverständlich.")?;
    if value.get("BackendState").and_then(Value::as_str) != Some("Running") {
        return Err("Tailscale ist nicht verbunden - bitte in Tailscale anmelden.".into());
    }
    let name = value.pointer("/Self/DNSName").and_then(Value::as_str).unwrap_or_default();
    let host = name.trim_end_matches('.').to_ascii_lowercase();
    check_host(&host).map_err(|_| "Tailscale nennt keinen gültigen Namen für diesen PC (MagicDNS an?).".to_owned())?;
    Ok(host)
}

/// The first lines of a command's message (at most 400 characters).
fn short(stderr: &str, stdout: &str) -> String {
    let text = if stderr.trim().is_empty() { stdout } else { stderr };
    let text: String = text.trim().chars().take(400).collect();
    if text.is_empty() { "keine Meldung".into() } else { text }
}

/// `tailscale funnel` for exactly [`FUNNEL_PATH`] on `port`: on (to the gate) or off.
fn funnel_args(port: u16, gate_port: Option<u16>) -> Vec<String> {
    let mut args = vec!["funnel".to_owned()];
    if gate_port.is_some() {
        args.push("--bg".to_owned());
    }
    args.push(format!("--https={port}"));
    args.push(format!("--set-path={FUNNEL_PATH}"));
    args.push(gate_port.map_or_else(|| "off".to_owned(), |gate| format!("http://127.0.0.1:{gate}")));
    args
}

async fn funnel(app: &App, port: u16, gate_port: Option<u16>) -> Result<(), String> {
    let output = app.options.tailscale.run(funnel_args(port, gate_port)).await?;
    if output.code == 0 { Ok(()) } else { Err(format!("Tailscale Funnel: {}", short(&output.stderr, &output.stdout))) }
}

/// The gate's routes from the settings: one per public node.
#[must_use]
pub fn routes_of(config: &AppConfig) -> Vec<Route> {
    config
        .nodes
        .iter()
        .filter_map(|node| {
            let key = node.public_key.as_ref()?;
            let bridge3 = config
                .bridge3
                .servers
                .iter()
                .filter(|server| server.node == node.id)
                .map(|server| Bridge3Route { id: server.id.clone(), port: server.port })
                .collect();
            Some(Route { key: key.clone(), port: node.listen_port, web: node.public_web, bridge3 })
        })
        .collect()
}

/// The gate's route file.
#[must_use]
pub fn routes_file(app: &App) -> PathBuf {
    app.options.app_dir.join("gate").join("routes.json")
}

/// Writes the routes and (re)starts the gate - or stops it when no node is public.
pub async fn apply_gate(app: &App) -> Result<(), String> {
    let (routes, gate_port) = {
        let config = app.config.lock().await;
        (routes_of(&config), config.public.gate_port)
    };
    let Some(gate_port) = gate_port.filter(|_| !routes.is_empty()) else {
        app.supervisor.stop(GATE_ID).await;
        return Ok(());
    };
    let routes = Routes::new(routes)?;
    let file = routes_file(app);
    config::write_private(&file, routes.to_json().as_bytes())?;
    // A running gate takes the new file by itself (docs/11 §3) - no restart, no dropped connection. Its port never
    // changes once chosen; a gate that waits for its watchdog restart reads the new file then.
    if matches!(app.supervisor.status(GATE_ID).state, RunState::Running | RunState::Waiting) {
        return Ok(());
    }
    app.supervisor.stop(GATE_ID).await;
    app.supervisor.start(Launch {
        id: GATE_ID.to_owned(),
        mode: "gate",
        program: None,
        env: Vec::new(),
        args: vec![
            "--listen".to_owned(),
            format!("127.0.0.1:{gate_port}"),
            "--routes".to_owned(),
            file.display().to_string(),
        ],
        log: app.node_log(GATE_ID),
    });
    Ok(())
}

/// The network key for a node: its network's short name, else (or if another public node has it) the network ID.
fn network_key(config: &AppConfig, short: Option<&str>, net: &str) -> String {
    let taken = |key: &str| config.nodes.iter().any(|node| node.public_key.as_deref() == Some(key));
    match short.filter(|short| bridge_gate::route::valid_key(short) && !taken(short)) {
        Some(short) => short.to_owned(),
        None => net.to_ascii_lowercase(),
    }
}

/// "Öffentlich machen" (docs/11 §5) - for a member's node "Erreichbar machen" (§13). `funnel_port`: 443, 8443 or
/// 10000 (only before the first public node).
pub async fn make_public(app: &App, id: &str, funnel_port: Option<u16>) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    if entry.public_key.is_some() {
        return Err("Dieser Knoten ist schon öffentlich.".into());
    }
    // A member's node may become reachable too (docs/11 §13): for the protocol of the other nodes (storage, gateway,
    // logins); websites it shows only once the owner seals it with level 3 - the node itself decides that.
    let (net, short, adult) = {
        let cache = app.poller.cache(id);
        let cache = cache.read().await;
        let view = cache.net.as_ref().ok_or("Der Knoten läuft nicht oder kennt sein Netz noch nicht.")?;
        let manifest = view.state.manifest();
        (view.net.as_str().to_owned(), manifest.short.clone(), manifest.adult_policy())
    };
    if adult != AdultPolicy::Forbidden {
        return Err("Dieses Netz erlaubt 18+-Inhalte - solche Netze werden nie öffentlich (Jugendschutz).".into());
    }
    let other_public = {
        let config = app.config.lock().await;
        config
            .nodes
            .iter()
            .filter(|node| node.id != id && node.public_key.is_some())
            .map(|n| n.id.clone())
            .collect::<Vec<_>>()
    };
    for other in other_public {
        let cache = app.poller.cache(&other);
        if cache.read().await.net.as_ref().is_some_and(|view| view.net.as_str() == net) {
            return Err("Ein anderer Knoten dieses Netzes ist auf diesem PC schon öffentlich.".into());
        }
    }
    let (funnel_on, port) = {
        let config = app.config.lock().await;
        let port = match (config.public.funnel_on, funnel_port) {
            (true, Some(port)) if port != config.public.funnel_port => {
                return Err(format!(
                    "Der Funnel-Port ist schon {} (andere öffentliche Netze) - dieser Knoten nutzt ihn mit.",
                    config.public.funnel_port
                ));
            }
            (true, _) | (false, None) => config.public.funnel_port,
            (false, Some(port)) => port,
        };
        if !config::FUNNEL_PORTS.contains(&port) {
            return Err("Funnel-Port: 443, 8443 oder 10000".into());
        }
        (config.public.funnel_on, port)
    };
    let host = host_from_status(&app.options.tailscale.run(vec!["status".into(), "--json".into()]).await?)?;
    // 1. The gate with this route (nothing is public before Funnel points to it).
    let ui_port = app.port;
    let key = {
        let config = app.config.lock().await;
        network_key(&config, short.as_deref(), &net)
    };
    let url = {
        let mut public = app.config.lock().await.public.clone();
        public.funnel_port = port;
        public.url_of(&host, &key)
    };
    save(app, |config| {
        config.public.funnel_port = port;
        config.public.host = Some(host.clone());
        if config.public.gate_port.is_none() {
            config.public.gate_port = Some(ops::free_port(config, FIRST_GATE_PORT, false, &[ui_port]));
        }
        let node = config.node_mut(id).ok_or("Diesen Knoten gibt es nicht (mehr).")?;
        node.public_key = Some(key.clone());
        node.public_url = Some(url.clone());
        node.public_web = true;
        Ok(())
    })
    .await?;
    if let Err(error) = apply_gate(app).await {
        return Err(rollback(app, id, entry.public_url.clone(), error).await);
    }
    // 2. Funnel `/bridge4` to the gate - once for all networks.
    if !funnel_on {
        let gate_port = app.config.lock().await.public.gate_port;
        if let Err(error) = funnel(app, port, gate_port).await {
            return Err(rollback(app, id, entry.public_url.clone(), error).await);
        }
        save(app, |config| {
            config.public.funnel_on = true;
            Ok(())
        })
        .await?;
    }
    // 3. The node with its public address and the reader `public`.
    let changed = entry_of(app, id).await?;
    let running = restart(app, &entry, &changed).await;
    let sealed = reseal_own(app, &changed, running).await;
    crate::bridge3::restart_for_node(app, id).await; // their address changes with the network's
    Ok(json!({"ok": true, "url": url, "key": key, "sealed": sealed}))
}

/// Undoes a failed "Öffentlich machen": the node as before, the gate without its route.
async fn rollback(app: &App, id: &str, previous_url: Option<String>, error: String) -> String {
    let undone = save(app, |config| {
        if let Some(node) = config.node_mut(id) {
            node.public_key = None;
            node.public_url = previous_url;
            node.public_web = true;
        }
        Ok(())
    })
    .await;
    let _ = apply_gate(app).await;
    match undone {
        Ok(()) => error,
        Err(more) => format!("{error} ({more})"),
    }
}

/// "Websites aus" / "Websites an" (the Not-Aus): only the gate's route, at once.
pub async fn set_web(app: &App, id: &str, on: bool) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    if entry.public_key.is_none() {
        return Err("Dieser Knoten ist nicht öffentlich.".into());
    }
    save(app, |config| {
        let node = config.node_mut(id).ok_or("Diesen Knoten gibt es nicht (mehr).")?;
        node.public_web = on;
        Ok(())
    })
    .await?;
    apply_gate(app).await?;
    Ok(json!({"ok": true, "web": on}))
}

/// "Nicht mehr öffentlich": route away, local address again, the node restarted; the last one also removes Funnel
/// and stops the gate.
pub async fn make_private(app: &App, id: &str) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    if entry.public_key.is_none() {
        return Err("Dieser Knoten ist nicht öffentlich.".into());
    }
    save(app, |config| {
        let node = config.node_mut(id).ok_or("Diesen Knoten gibt es nicht (mehr).")?;
        node.public_key = None;
        node.public_url = None;
        node.public_web = true;
        Ok(())
    })
    .await?;
    apply_gate(app).await?;
    let (last, funnel_on, port) = {
        let config = app.config.lock().await;
        (routes_of(&config).is_empty(), config.public.funnel_on, config.public.funnel_port)
    };
    let mut warning = None;
    if last && funnel_on {
        match funnel(app, port, None).await {
            Ok(()) => {
                save(app, |config| {
                    config.public.funnel_on = false;
                    Ok(())
                })
                .await?;
            }
            Err(error) => warning = Some(format!("Funnel nicht entfernt: {error}")),
        }
    }
    let changed = entry_of(app, id).await?;
    let running = restart(app, &entry, &changed).await;
    let sealed = reseal_own(app, &changed, running).await;
    crate::bridge3::restart_for_node(app, id).await;
    Ok(json!({"ok": true, "sealed": sealed, "warning": warning}))
}

/// Restarts a node whose arguments changed (only if it ran) - whether it did.
async fn restart(app: &App, before: &NodeEntry, after: &NodeEntry) -> bool {
    if app.supervisor.status(&before.id).state != RunState::Running {
        return false;
    }
    app.supervisor.stop(&before.id).await;
    app.start_node(after);
    true
}

/// Seals the owner's own node again with its new card (level and services as before) - `false` for a member's node,
/// a node that does not run, or when that did not work (the dashboard then shows "Karte veraltet").
async fn reseal_own(app: &App, entry: &NodeEntry, running: bool) -> bool {
    if entry.role != NodeRole::Owner || !running {
        return false;
    }
    match reseal(app, entry).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%error, node = %entry.id, "neu siegeln");
            false
        }
    }
}

async fn reseal(app: &App, entry: &NodeEntry) -> Result<(), String> {
    ops::wait_ready(entry).await?;
    let admin = admin_client(app, entry)?;
    let local = entry.local_url();
    let card = patient(|| admin.fetch_node_card(&local)).await?;
    let node = card.id().clone();
    // Level and services from the node's own log now (the status cache may be a round behind - a seal with `web`
    // must never get lost, its apps would stop).
    let (_, state) = patient(|| admin.load_state()).await?;
    let (level, services) = (state.level(&node, now_ms()), state.services(&node, now_ms()));
    let level = level.filter(|level| *level >= 1).ok_or("Knoten hat kein Siegel")?;
    patient(|| admin.seal_card(card.clone(), &node, level, services)).await?;
    Ok(())
}

/// "Login hier einschalten" (docs/11 §9.2): the public owner node also gets the service `storage` - level and its
/// other services stay - and then holds the network's Bridge Login accounts at its public address.
pub async fn login_on(app: &App, id: &str) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    if entry.role != NodeRole::Owner {
        return Err("Das geht nur beim Owner-Knoten eines Netzes.".into());
    }
    if entry.public_key.is_none() {
        return Err("Bridge Login braucht eine öffentliche Adresse – erst „Öffentlich machen“.".into());
    }
    ops::wait_ready(&entry).await?;
    let admin = admin_client(app, &entry)?;
    let local = entry.local_url();
    let card = patient(|| admin.fetch_node_card(&local)).await?;
    let node = card.id().clone();
    let (_, state) = patient(|| admin.load_state()).await?;
    let now = now_ms();
    let level =
        state.level(&node, now).filter(|level| *level >= 2).ok_or("Der Knoten braucht ein Siegel ab Stufe 2.")?;
    let current = state.services(&node, now);
    if current.has(Service::Storage) {
        return Ok(json!({"ok": true, "already": true}));
    }
    let mut services: Vec<Service> = current.iter().collect();
    services.push(Service::Storage);
    let services = Services::of(&services);
    patient(|| admin.seal_card(card.clone(), &node, level, services)).await?;
    Ok(json!({"ok": true}))
}

/// After each status round: a public network that allows 18+ now gets its websites switched off (docs/11 §5).
pub async fn housekeeping(app: &App) {
    let public: Vec<NodeEntry> = app
        .config
        .lock()
        .await
        .nodes
        .iter()
        .filter(|node| node.public_key.is_some() && node.public_web)
        .cloned()
        .collect();
    for entry in public {
        let adult = {
            let cache = app.poller.cache(&entry.id);
            let cache = cache.read().await;
            cache.net.as_ref().map(|view| view.state.manifest().adult_policy())
        };
        if adult.is_some_and(|policy| policy != AdultPolicy::Forbidden) {
            tracing::warn!(node = %entry.id, "Netz erlaubt jetzt 18+ - Websites nicht mehr öffentlich");
            if let Err(error) = set_web(app, &entry.id, false).await {
                tracing::warn!(%error, "Websites ausschalten");
            }
        }
    }
}

/// What the UI shows of a node: `null`, or its key, address and whether its websites are public.
#[must_use]
pub fn node_view(entry: &NodeEntry) -> Value {
    match &entry.public_key {
        Some(key) => json!({"key": key, "url": entry.public_url, "web": entry.public_web}),
        None => Value::Null,
    }
}

/// The global part for the UI: Funnel port and whether it is set, the PC's name, the gate's state.
pub async fn summary(app: &App) -> Value {
    let public = app.config.lock().await.public.clone();
    json!({
        "funnel_port": public.funnel_port,
        "funnel_on": public.funnel_on,
        "host": public.host,
        "gate_port": public.gate_port,
        "gate": app.supervisor.status(GATE_ID).state.as_str(),
        "ports": config::FUNNEL_PORTS,
    })
}

/// The stand-in for tests: answers `status --json` with `host`, records every call, refuses Funnel if asked to.
#[derive(Debug, Default)]
pub struct FakeTailscale {
    /// The name `status` reports (`None`: not signed in).
    pub host: Option<String>,
    /// Refuse `funnel` with this message.
    pub refuse_funnel: Option<String>,
    /// Every call's arguments.
    pub calls: std::sync::Mutex<Vec<Vec<String>>>,
}

impl TailscaleCli for FakeTailscale {
    fn run(&self, args: Vec<String>) -> CliFuture<'_> {
        Box::pin(async move {
            self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(args.clone());
            match args.first().map(String::as_str) {
                Some("status") => Ok(match &self.host {
                    Some(host) => CliOutput {
                        code: 0,
                        stdout: json!({"BackendState": "Running", "Self": {"DNSName": format!("{host}.")}}).to_string(),
                        stderr: String::new(),
                    },
                    None => CliOutput { code: 1, stdout: String::new(), stderr: "Logged out.".into() },
                }),
                Some("funnel") => Ok(match &self.refuse_funnel {
                    Some(message) => CliOutput { code: 1, stdout: String::new(), stderr: message.clone() },
                    None => CliOutput::default(),
                }),
                _ => Ok(CliOutput { code: 1, stdout: String::new(), stderr: "unbekannt".into() }),
            }
        })
    }
}

/// A shared [`TailscaleCli`].
pub type SharedTailscale = Arc<dyn TailscaleCli>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_funnel_commands() -> Result<(), String> {
        let ok = CliOutput {
            code: 0,
            stdout: json!({"BackendState": "Running", "Self": {"DNSName": "PC.tail1234.ts.net."}}).to_string(),
            stderr: String::new(),
        };
        assert_eq!(host_from_status(&ok)?, "pc.tail1234.ts.net");
        let stopped = CliOutput { stdout: json!({"BackendState": "Stopped"}).to_string(), ..ok.clone() };
        assert!(host_from_status(&stopped).is_err());
        let odd = CliOutput {
            stdout: json!({"BackendState": "Running", "Self": {"DNSName": "a b."}}).to_string(),
            ..ok.clone()
        };
        assert!(host_from_status(&odd).is_err());
        assert!(host_from_status(&CliOutput { code: 1, ..ok }).is_err());
        assert_eq!(
            funnel_args(443, Some(7390)),
            ["funnel", "--bg", "--https=443", "--set-path=/bridge4", "http://127.0.0.1:7390"]
        );
        assert_eq!(funnel_args(8443, None), ["funnel", "--https=8443", "--set-path=/bridge4", "off"]);
        for args in [funnel_args(443, Some(7390)), funnel_args(10000, None)] {
            assert!(!args.iter().any(|arg| arg == "reset" || arg.contains("serve")), "never reset: {args:?}");
        }
        Ok(())
    }

    #[test]
    fn network_keys() {
        let mut config = AppConfig::default();
        assert_eq!(network_key(&config, Some("testnetz"), "ABCDEF"), "testnetz");
        assert_eq!(network_key(&config, None, "ABCDEF"), "abcdef");
        assert_eq!(network_key(&config, Some("bridge4"), "ABCDEF"), "abcdef", "never the gate's prefix");
        config.nodes.push(NodeEntry {
            id: "0a0a0a0a".into(),
            name: "pc".into(),
            net_name: "Testnetz".into(),
            role: NodeRole::Owner,
            listen_port: 7401,
            lan_port: None,
            public_url: Some("https://pc.tail1.ts.net/bridge4/testnetz".into()),
            autostart: true,
            join_link: None,
            probe: None,
            offer_gateway: false,
            peer_addresses: bridge_transport::PeerAddresses::Tailnet,
            reader: bridge_node::ReaderAccess::Local,
            reader_port: Some(7601),
            public_key: Some("testnetz".into()),
            public_web: false,
            created: 1,
        });
        assert_eq!(network_key(&config, Some("testnetz"), "ABCDEF"), "abcdef", "taken by another network");
        let routes = routes_of(&config);
        assert_eq!(routes, vec![Route { key: "testnetz".into(), port: 7401, web: false, bridge3: Vec::new() }]);
        assert_eq!(node_view(&config.nodes[0])["web"], json!(false));
    }
}
