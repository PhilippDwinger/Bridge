//! What the buttons do (ADR 0017): create a network, join one, invite, seal, revoke, ban, change and delete nodes -
//! and the views of the start page and the dashboard. Admin actions go through [`AdminClient`] with the admin key in
//! the owner node's folder, exactly like `bridge-node net …` (every statement signed by the admin key, handed to the
//! owner node in a request signed by it too). User-facing texts are German.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use bridge_core::encoding::{b64, b64_var};
use bridge_core::{Id, JoinLink, KeyCard, Role};
use bridge_net::{JoinMode, NetState, RevokeTarget, Service, Services};
use bridge_node::admin::{self, AdminClient};
use bridge_transport::HttpClient;
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};

use crate::config::{self, AppConfig, NodeEntry, NodeRole};
use crate::status::{NodeCache, card_name};
use crate::supervisor::RunState;
use crate::wizard::Wizard;
use crate::{App, BACKUP_DIR, autostart, now_ms, qr};

/// Prefix of a "Knoten-Ausweis": a node's self-signed card, to give to the owner for sealing (ADR 0017).
pub const AUSWEIS_PREFIX: &str = "bridge4://node?card=";
/// Longest Knoten-Ausweis.
pub const MAX_AUSWEIS_CHARS: usize = 4096;
/// Leading characters of a node ID the owner must confirm before sealing a node from another PC.
pub const MIN_CONFIRM_CHARS: usize = 12;
/// How long a new owner node may take until it serves its network.
const READY_WAIT: Duration = Duration::from_secs(30);
/// First port tried for a node, and for its LAN listener.
const FIRST_PORT: u16 = 7401;
const FIRST_LAN_PORT: u16 = 7443;
/// First port tried for a node's loopback reader (`--reader-listen`, review 9).
const FIRST_READER_PORT: u16 = 7601;
/// Most members listed in the dashboard.
const MAX_MEMBERS_SHOWN: usize = 100;
/// Most members looked at for a search.
const MAX_MEMBERS_SCANNED: usize = 5000;
/// File in a node's folder with its join link (owner-only): the node reads it with `--join-net-file`, so the invite
/// code never shows in the process list (review 8).
pub const JOIN_LINK_FILE: &str = "join-link.txt";

/// The arguments of a node process (after `node --supervised`): data folder, listener on 127.0.0.1, its name, its
/// address (the public one with the local proxy trusted, else the local one), LAN, the file with the join link (never
/// the link itself: command lines are readable by every user of the PC - [`write_join_link`] writes the file), probes,
/// the address rule and the reader (Bridge-Browser, docs/08 §8) - for a node with a public address with its loopback
/// reader port (review 9).
#[must_use]
pub fn node_args(entry: &NodeEntry, dir: &Path) -> Vec<String> {
    let mut args = vec![
        "--data".to_owned(),
        dir.display().to_string(),
        "--listen".to_owned(),
        format!("127.0.0.1:{}", entry.listen_port),
        "--name".to_owned(),
        entry.name.clone(),
        "--url".to_owned(),
    ];
    match &entry.public_url {
        Some(url) => args.extend([url.clone(), "--trust-proxy".to_owned(), "127.0.0.1".to_owned()]),
        None => args.push(entry.local_url()),
    }
    if let Some(port) = entry.lan_port {
        args.extend(["--lan".to_owned(), port.to_string()]);
    }
    if entry.join_link.is_some() {
        args.extend(["--join-net-file".to_owned(), dir.join(JOIN_LINK_FILE).display().to_string()]);
    }
    if let Some(probe) = &entry.probe {
        args.extend(["--probe".to_owned(), probe.clone()]);
    }
    args.extend(["--peer-addresses".to_owned(), entry.peer_addresses.as_str().to_owned()]);
    args.extend(["--reader".to_owned(), entry.effective_reader().as_str().to_owned()]);
    if let (Some(_), Some(port), true) =
        (&entry.public_url, entry.reader_port, entry.reader != bridge_node::ReaderAccess::Off)
    {
        args.extend(["--reader-listen".to_owned(), format!("127.0.0.1:{port}")]);
    }
    args
}

/// Gives every node with a public address a loopback reader port (review 9: its main port trusts the local proxy, so
/// this PC's browser needs another one) and takes it from nodes without one. Ports already given stay.
pub fn assign_reader_ports(config: &mut AppConfig) {
    for index in 0..config.nodes.len() {
        let Some(node) = config.nodes.get(index) else { break };
        let wanted = node.public_url.is_some();
        let avoid: Vec<u16> = std::iter::once(node.listen_port).chain(node.lan_port).collect();
        let port = match (wanted, node.reader_port) {
            (true, None) => Some(free_port(config, FIRST_READER_PORT, false, &avoid)),
            (true, known) => known,
            (false, _) => None,
        };
        if let Some(node) = config.nodes.get_mut(index) {
            node.reader_port = port;
        }
    }
}

/// Writes the join link into the node's folder (owner-only, atomically) - or removes the file without a link.
pub fn write_join_link(dir: &Path, link: Option<&str>) -> Result<(), String> {
    let path = dir.join(JOIN_LINK_FILE);
    match link {
        Some(link) => config::write_private(&path, format!("{link}\n").as_bytes()),
        None => match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("{}: {error}", path.display())),
        },
    }
}

/// Where a node is reachable: its port on 127.0.0.1, LAN, public address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach {
    /// HTTP port on 127.0.0.1.
    pub listen_port: u16,
    /// LAN port (TLS), if on.
    pub lan_port: Option<u16>,
    /// Public address, if any.
    pub public_url: Option<String>,
}

impl Reach {
    /// From a JSON body: `listen_port`, `lan_port` (number or null), `public_url` (text, empty or null).
    pub fn from_json(body: &serde_json::Map<String, Value>) -> Result<Self, String> {
        let port = |name: &str| body.get(name).and_then(Value::as_u64).and_then(|port| u16::try_from(port).ok());
        let listen_port = port("listen_port").ok_or("Port: eine Zahl")?;
        let lan_port = match body.get("lan_port") {
            None | Some(Value::Null) => None,
            Some(_) => Some(port("lan_port").ok_or("LAN-Port: eine Zahl")?),
        };
        let public_url = match body.get("public_url") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) if text.trim().is_empty() => None,
            Some(Value::String(text)) => Some(text.trim().to_owned()),
            Some(_) => return Err("Adresse: ein Text".into()),
        };
        Ok(Self { listen_port, lan_port, public_url })
    }

    /// Checks ports (range, not used by another node, free on this PC) and the address; errors by field.
    pub fn check(&self, config: &AppConfig, except: Option<&str>, running_self: bool) -> Vec<(&'static str, String)> {
        let mut errors = Vec::new();
        if let Err(error) = check_port(config, self.listen_port, except, false, running_self) {
            errors.push(("listen_port", error));
        }
        if let Some(lan) = self.lan_port {
            if lan == self.listen_port {
                errors.push(("lan_port", "Der LAN-Port muss ein anderer sein".into()));
            } else if let Err(error) = check_port(config, lan, except, true, running_self) {
                errors.push(("lan_port", error));
            }
        }
        if let Some(url) = &self.public_url {
            if bridge_core::keys::check_url(url).is_err() {
                errors.push((
                    "public_url",
                    "Eine Adresse wie https://pc.tail1234.ts.net:8443/knoten1 (höchstens 200 Zeichen)".into(),
                ));
            }
        }
        errors
    }
}

/// A port for a node: at least 1024, not used by another node here and free on this PC (`lan`: on all addresses).
/// `running_self`: the node with ID `except` runs and holds the port itself (settings of a running node).
fn check_port(
    config: &AppConfig,
    port: u16,
    except: Option<&str>,
    lan: bool,
    running_self: bool,
) -> Result<(), String> {
    if port < config::MIN_PORT {
        return Err(format!("Ports ab {}", config::MIN_PORT));
    }
    if config.port_taken(port, except) {
        return Err(format!("Port {port} nutzt schon ein anderer Knoten"));
    }
    let own = except
        .and_then(|id| config.node(id))
        .is_some_and(|entry| running_self && (entry.listen_port == port || entry.lan_port == Some(port)));
    if !own && !port_free(port, lan) {
        return Err(format!("Port {port} ist auf diesem PC belegt"));
    }
    Ok(())
}

fn port_free(port: u16, lan: bool) -> bool {
    let address = if lan { [0, 0, 0, 0] } else { [127, 0, 0, 1] };
    std::net::TcpListener::bind((std::net::Ipv4Addr::from(address), port)).is_ok()
}

/// The first port from `start` that no node uses and that is free here.
#[must_use]
pub fn free_port(config: &AppConfig, start: u16, lan: bool, avoid: &[u16]) -> u16 {
    (start..u16::MAX)
        .find(|port| !config.port_taken(*port, None) && !avoid.contains(port) && port_free(*port, lan))
        .unwrap_or(start)
}

/// Suggested ports for a new node.
#[must_use]
pub fn suggested_ports(config: &AppConfig) -> (u16, u16) {
    let listen = free_port(config, FIRST_PORT, false, &[]);
    let lan = free_port(config, FIRST_LAN_PORT, true, &[listen]);
    (listen, lan)
}

/// A new local node ID (8 hex characters, unused, and no folder of that name).
fn new_node_id(config: &AppConfig, app_dir: &Path) -> String {
    loop {
        let mut bytes = [0u8; 4];
        OsRng.fill_bytes(&mut bytes);
        let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        if config.node(&id).is_none() && !app_dir.join(config::NODES_DIR).join(&id).exists() {
            return id;
        }
    }
}

/// This PC's name (for the owner node's card), cleaned and bounded.
#[must_use]
pub fn host_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default();
    let name: String = raw.trim().chars().filter(|c| !c.is_control()).take(config::MAX_NAME_CHARS).collect();
    if name.is_empty() { "dieser-pc".to_owned() } else { name.to_lowercase() }
}

/// German name of a join mode.
#[must_use]
pub fn mode_name(mode: JoinMode) -> &'static str {
    match mode {
        JoinMode::Open => "Offen",
        JoinMode::Invite => "Mit Einladung",
        JoinMode::Closed => "Geschlossen",
    }
}

/// A node's card as Knoten-Ausweis: `bridge4://node?card=<Base64url of the canonical card>`.
pub fn ausweis(card: &KeyCard) -> Result<String, String> {
    Ok(format!("{AUSWEIS_PREFIX}{}", b64(&card.to_bytes().map_err(|e| e.to_string())?)))
}

/// Parses a Knoten-Ausweis strictly: exactly the prefix and one Base64url value, a self-signed node card with an
/// address.
pub fn parse_ausweis(text: &str) -> Result<KeyCard, String> {
    let text = text.trim();
    if text.len() > MAX_AUSWEIS_CHARS {
        return Err("Knoten-Ausweis zu lang".into());
    }
    let value = text.strip_prefix(AUSWEIS_PREFIX).ok_or("Das ist kein Knoten-Ausweis (bridge4://node?card=…)")?;
    let bytes = b64_var(value, "card", MAX_AUSWEIS_CHARS).map_err(|_| "Knoten-Ausweis beschädigt".to_owned())?;
    let card = KeyCard::parse(&bytes).map_err(|_| "Knoten-Ausweis: Karte ungültig (Signatur oder Form)".to_owned())?;
    if card.role() != Role::Node || card.urls().is_empty() {
        return Err("Knoten-Ausweis: keine Knoten-Karte mit Adresse".into());
    }
    Ok(card)
}

/// The services a node's seal grants, from API names.
pub fn parse_services(list: &[Value]) -> Result<Services, String> {
    let mut services = Vec::new();
    for item in list.iter().take(Service::ALL.len()) {
        let name = item.as_str().unwrap_or_default();
        services.push(Service::parse(name).ok_or_else(|| format!("unbekannter Dienst {name:?}"))?);
    }
    Ok(Services::of(&services))
}

fn service_names(services: Services) -> Vec<&'static str> {
    services.iter().map(Service::as_str).collect()
}

/// The admin client of an owner node, talking to it on this PC.
pub(crate) fn admin_client(app: &App, entry: &NodeEntry) -> Result<AdminClient, String> {
    if entry.role != NodeRole::Owner {
        return Err("Das geht nur beim Owner-Knoten eines Netzes.".into());
    }
    AdminClient::load(&app.node_dir(entry), Some(&entry.local_url()))
}

/// Runs a request to a node of this PC again (at most four tries, a second apart) while the node answers
/// `RATE_LIMITED`: everything on this PC - the app, its status rounds, the other local nodes, the browser - reaches it
/// from 127.0.0.1 and shares that address's limit (docs/04 §7). A refused request changed nothing; each try signs anew.
pub(crate) async fn patient<T, F, Fut>(mut action: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut tries = 0;
    loop {
        match action().await {
            Err(error) if error.contains("RATE_LIMITED") && tries < 3 => {
                tries += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            other => return other,
        }
    }
}

/// The settings entry of a node of this PC.
pub(crate) async fn entry_of(app: &App, id: &str) -> Result<NodeEntry, String> {
    config::check_id(id)?;
    app.config.lock().await.node(id).cloned().ok_or_else(|| "Diesen Knoten gibt es nicht (mehr).".to_owned())
}

pub(crate) async fn save(app: &App, change: impl FnOnce(&mut AppConfig) -> Result<(), String>) -> Result<(), String> {
    let mut config = app.config.lock().await;
    let mut next = config.clone();
    change(&mut next)?;
    assign_reader_ports(&mut next);
    next.save(&app.options.app_dir)?;
    *config = next;
    Ok(())
}

// --- create -------------------------------------------------------------------------------------------------------

/// Why step 4 failed: `retry` = nothing was created, the words can be used for another try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateError {
    /// Nothing was created.
    pub retry: bool,
    /// What went wrong (German).
    pub message: String,
}

impl From<String> for CreateError {
    fn from(message: String) -> Self {
        Self { retry: true, message }
    }
}

/// Step 4 of the assistant: creates the network in a new node folder (genesis with the short name, Meldeweg and 18+
/// policy of step 1, delegation, owner seal - with the words shown in step 2), starts the owner node, waits until it serves, and returns its join link (with a code in
/// an invite network) and the QR code. Once the network exists the answer is a success; if the node is slow to
/// start, it says so (`warning`) and the link comes from the dashboard later.
pub async fn create_net(app: &App, wizard: &Wizard, reach: &Reach, uses: u32) -> Result<Value, CreateError> {
    let (entry, dir) = {
        let config = app.config.lock().await;
        if config.nodes.len() >= config::MAX_NODES {
            return Err(format!("Höchstens {} Knoten pro PC", config::MAX_NODES).into());
        }
        if let Some((_, error)) = reach.check(&config, None, false).into_iter().next() {
            return Err(error.into());
        }
        let entry = NodeEntry {
            id: new_node_id(&config, &app.options.app_dir),
            name: host_name(),
            net_name: wizard.name.clone(),
            role: NodeRole::Owner,
            listen_port: reach.listen_port,
            lan_port: reach.lan_port,
            public_url: reach.public_url.clone(),
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
        };
        entry.check()?;
        let dir = entry.data_dir(&app.options.app_dir);
        (entry, dir)
    };
    let url = entry.public_url.clone().unwrap_or_else(|| entry.local_url());
    let (name, mode, options) = (wizard.name.clone(), wizard.mode, wizard.options.clone());
    let words = bridge_core::Mnemonic::parse(&wizard.words.words()).map_err(|e| e.to_string())?;
    let target = dir.clone();
    let created = tokio::task::spawn_blocking(move || {
        admin::create_network_with_options(&target, &name, &url, mode, now_ms(), &words, &options)
    })
    .await
    .map_err(|e| e.to_string())?;
    let created = match created {
        Ok(created) => created,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&dir); // nothing of value in it yet: the network was not made
            return Err(error.into());
        }
    };
    let net = created.net.as_str().to_owned();
    drop(created);
    let saved = save(app, |config| {
        config.nodes.push(entry.clone());
        Ok(())
    })
    .await;
    if let Err(error) = saved {
        return Err(CreateError {
            retry: false,
            message: format!("Netz erstellt in {}, aber nicht eingetragen: {error}", dir.display()),
        });
    }
    app.start_node(&entry);
    let mut answer = match wait_ready(&entry).await {
        Ok(()) => match invite_link(app, &entry, mode, uses, 30).await {
            Ok(answer) => answer,
            Err(error) => json!({"link": Value::Null, "warning": error}),
        },
        Err(error) => json!({"link": Value::Null, "warning": error}),
    };
    answer["node"] = json!(entry.id);
    answer["net"] = json!(net);
    Ok(answer)
}

/// Waits until a new owner node serves its network as log operator (or gives up after [`READY_WAIT`]).
pub(crate) async fn wait_ready(entry: &NodeEntry) -> Result<(), String> {
    let http = HttpClient::new(&entry.local_url(), Duration::from_secs(3)).map_err(|e| e.to_string())?;
    let deadline = tokio::time::Instant::now() + READY_WAIT;
    loop {
        if let Ok(answer) = http.get("/v4/info").await {
            let operator = bridge_core::json::parse_strict(&answer.body, 64 * 1024)
                .ok()
                .and_then(|value| value.pointer("/info/body/network/operator").and_then(Value::as_bool));
            if operator == Some(true) {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("Der Owner-Knoten ist erstellt, antwortet aber noch nicht - siehe Protokoll.".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A join link of an owner node: with a new code (`uses`, `days`) in an invite network, else without. The gateway in
/// the link is the owner node's own address from its verified card (its public one), with its ID and - with LAN on -
/// its TLS pin.
async fn invite_link(app: &App, entry: &NodeEntry, mode: JoinMode, uses: u32, days: u32) -> Result<Value, String> {
    let admin = admin_client(app, entry)?;
    let card = admin.fetch_node_card(&entry.local_url()).await?;
    if card.id() != admin.node_id() {
        return Err("Der Knoten an diesem Port ist nicht der Owner-Knoten - keine Einladung erstellt.".into());
    }
    let code = if mode == JoinMode::Invite {
        let (code, _) = admin.invite(uses, days).await?;
        Some(code)
    } else {
        None
    };
    let gateway = card.urls().first().cloned().ok_or("Der Owner-Knoten hat keine Adresse")?;
    let link = JoinLink {
        net: admin.net().clone(),
        gateway,
        code: code.clone(),
        node: Some(card.id().clone()),
        tls: card.tls().copied(),
    }
    .to_link();
    let svg = qr::svg(&link)?;
    app.links.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(entry.id.clone(), link.clone());
    Ok(json!({"link": link, "code": code, "uses": code.as_ref().map(|_| uses), "qr": svg, "lan": card.tls().is_some()}))
}

/// "Neuer Link" in the dashboard.
pub async fn invite(app: &App, id: &str, uses: u32, days: u32) -> Result<Value, String> {
    if !(1..=1000).contains(&uses) || !(1..=365).contains(&days) {
        return Err("1-1000 Nutzungen, 1-365 Tage".into());
    }
    let entry = entry_of(app, id).await?;
    let mode = {
        let cache = app.poller.cache(id);
        let cache = cache.read().await;
        cache.net.as_ref().map(|view| view.state.manifest().join.mode).ok_or("Der Knoten läuft noch nicht")?
    };
    invite_link(app, &entry, mode, uses, days).await
}

// --- join ---------------------------------------------------------------------------------------------------------

/// Checks a join link before joining: form, the network's genesis from the gateway (verified up to the network ID -
/// so its name is the real one), the gateway's ID if the link pins it, and whether the LAN path is possible.
pub async fn join_check(link: &str) -> Value {
    let link = match JoinLink::parse(link.trim()) {
        Ok(link) => link,
        Err(error) => return json!({"ok": false, "error": format!("Kein gültiger Einladungslink: {error}")}),
    };
    let mut answer = json!({
        "ok": true,
        "net": link.net.as_str(),
        "gateway": link.gateway,
        "code": link.code.is_some(),
        "lan": link.tls.is_some(),
        "reachable": false,
        "name": Value::Null,
    });
    let Ok(http) = HttpClient::new(&link.gateway, Duration::from_secs(5)) else { return answer };
    if let Some(expected) = &link.node {
        match http.get("/v4/info").await {
            Ok(response) => {
                let id = bridge_core::json::parse_strict(&response.body, 64 * 1024)
                    .ok()
                    .and_then(|value| value.get("card").cloned())
                    .and_then(|card| KeyCard::from_value(card).ok())
                    .map(|card| card.id().clone());
                if id.as_ref() != Some(expected) {
                    answer["ok"] = json!(false);
                    answer["error"] = json!("Unter der Adresse im Link antwortet ein anderer Knoten - Link prüfen.");
                    return answer;
                }
            }
            Err(_) => return answer,
        }
    }
    if let Ok(entries) = crate::status::fetch_log(&http, &link.net, 0, 1).await {
        if let Some(Ok(state)) = entries.first().map(|entry| NetState::genesis(&link.net, entry)) {
            answer["reachable"] = json!(true);
            answer["name"] = json!(state.manifest().name);
            answer["mode"] = json!(mode_name(state.manifest().join.mode));
        }
    }
    answer
}

/// What "Netz beitreten" was asked for.
pub struct JoinRequest {
    /// The join link.
    pub link: String,
    /// Name of the new node.
    pub name: String,
    /// Where it is reachable.
    pub reach: Reach,
    /// It offers to be a gateway (the owner must seal it).
    pub offer_gateway: bool,
    /// It hosts apps (`--probe web`: the watchers probe it and give it level 1 with `web`).
    pub host_apps: bool,
    /// Start BridgeControll with the system.
    pub autostart_login: bool,
}

/// Creates a node for a network from a link and starts it (`--join-net`).
pub async fn join(app: &App, request: JoinRequest) -> Result<Value, String> {
    let link = JoinLink::parse(request.link.trim()).map_err(|e| format!("Kein gültiger Einladungslink: {e}"))?;
    config::check_name(&request.name, "Name des Knotens")?;
    let net_name = match join_check(&request.link).await.get("name").and_then(Value::as_str) {
        Some(name) if config::check_name(name, "x").is_ok() => name.to_owned(),
        _ => String::new(),
    };
    let entry = {
        let config = app.config.lock().await;
        if config.nodes.len() >= config::MAX_NODES {
            return Err(format!("Höchstens {} Knoten pro PC", config::MAX_NODES));
        }
        if let Some((_, error)) = request.reach.check(&config, None, false).into_iter().next() {
            return Err(error);
        }
        NodeEntry {
            id: new_node_id(&config, &app.options.app_dir),
            name: request.name.trim().to_owned(),
            net_name,
            role: NodeRole::Member,
            listen_port: request.reach.listen_port,
            lan_port: request.reach.lan_port,
            public_url: request.reach.public_url.clone(),
            autostart: true,
            join_link: Some(link.to_link()),
            probe: request.host_apps.then(|| "web".to_owned()),
            offer_gateway: request.offer_gateway,
            peer_addresses: bridge_transport::PeerAddresses::Tailnet,
            reader: bridge_node::ReaderAccess::Local,
            reader_port: None,
            public_key: None,
            public_web: true,
            created: now_ms(),
        }
    };
    entry.check()?;
    std::fs::create_dir_all(app.node_dir(&entry)).map_err(|e| format!("Daten-Ordner: {e}"))?;
    save(app, |config| {
        config.nodes.push(entry.clone());
        Ok(())
    })
    .await?;
    if request.autostart_login {
        set_login_autostart(app, true)?;
    }
    app.start_node(&entry);
    Ok(json!({"node": entry.id}))
}

// --- seal, revoke, ban --------------------------------------------------------------------------------------------

/// Which node to seal and how.
pub struct SealRequest {
    /// The node's ID as the owner confirmed it (at least [`MIN_CONFIRM_CHARS`] leading characters, or all).
    pub confirm: String,
    /// A node of this PC (its card is fetched from it here) ...
    pub local: Option<String>,
    /// ... or a Knoten-Ausweis from another PC.
    pub ausweis: Option<String>,
    /// Level 1-3.
    pub level: u8,
    /// Services.
    pub services: Services,
}

/// Seals a node (owner dashboard): its card from this PC or from its Knoten-Ausweis, the ID confirmed by the owner
/// (like `--node-id` of `bridge-node net seal`), signed with the admin key.
pub async fn seal(app: &App, id: &str, request: SealRequest) -> Result<Value, String> {
    if !(1..=3).contains(&request.level) {
        return Err("Stufe 1-3".into());
    }
    let owner = entry_of(app, id).await?;
    let admin = admin_client(app, &owner)?;
    let card = match (&request.local, &request.ausweis) {
        (Some(local), None) => {
            let target = entry_of(app, local).await?;
            admin.fetch_node_card(&target.local_url()).await?
        }
        (None, Some(ausweis)) => parse_ausweis(ausweis)?,
        _ => return Err("Knoten von diesem PC oder Knoten-Ausweis angeben".into()),
    };
    let confirm: String = request.confirm.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
    if confirm.len() < MIN_CONFIRM_CHARS || !card.id().as_str().starts_with(&confirm) {
        return Err(format!(
            "Die bestätigte Knoten-ID passt nicht zur Karte ({}…) - nichts wurde gesiegelt. Vergleiche die ID mit der \
             Anzeige auf dem anderen PC.",
            card.id().as_str().get(..MIN_CONFIRM_CHARS).unwrap_or_default()
        ));
    }
    let node_id = card.id().clone();
    let (statement, submitted) = admin.seal_card(card, &node_id, request.level, request.services).await?;
    Ok(json!({"ok": true, "node": node_id.as_str(), "index": submitted.index, "statement": statement.hash()}))
}

/// Revokes every active seal of a node (not of a log operator or witness of the current manifest - that would stop
/// the log; not of the owner node).
pub async fn unseal(app: &App, id: &str, node: &str) -> Result<Value, String> {
    let owner = entry_of(app, id).await?;
    let admin = admin_client(app, &owner)?;
    let node = Id::parse(node).map_err(|_| "keine Knoten-ID")?;
    if &node == admin.node_id() {
        return Err("Das Siegel des Owner-Knotens bleibt (sonst steht das Netz).".into());
    }
    let now = now_ms();
    let hashes: Vec<[u8; 32]> = {
        let cache = app.poller.cache(id);
        let cache = cache.read().await;
        let view = cache.net.as_ref().ok_or("Der Owner-Knoten läuft noch nicht")?;
        let manifest = view.state.manifest();
        if manifest.logs.contains(&node) || manifest.witnesses.contains(&node) {
            return Err("Dieser Knoten ist Log-Führer oder Zeuge - erst die Log-Regeln ändern.".into());
        }
        (1..=3)
            .filter_map(|level| view.state.seal_info(&node, level))
            .filter(|info| info.active(now) && !view.state.is_revoked(&info.hash))
            .map(|info| info.hash)
            .collect()
    };
    if hashes.is_empty() {
        return Err("Dieser Knoten hat kein aktives Siegel.".into());
    }
    let mut indexes = Vec::new();
    for hash in hashes {
        let (_, submitted) = admin.revoke(RevokeTarget::Statement(hash), "Siegel entzogen (BridgeControll)").await?;
        indexes.push(submitted.index);
    }
    Ok(json!({"ok": true, "revoked": indexes.len()}))
}

/// Bans an identity or app for `days` days (never the network, the owner node or an admin).
pub async fn ban(app: &App, id: &str, subject: &str, days: u32, reason: &str) -> Result<Value, String> {
    if !(1..=3650).contains(&days) {
        return Err("1-3650 Tage".into());
    }
    if reason.chars().count() > 200 || reason.chars().any(char::is_control) {
        return Err("Grund: höchstens 200 Zeichen".into());
    }
    let owner = entry_of(app, id).await?;
    let admin = admin_client(app, &owner)?;
    let subject = Id::parse(subject.trim()).map_err(|_| "keine ID")?;
    if &subject == admin.net() || &subject == admin.node_id() || &subject == admin.admin_id() {
        return Err("Netz, Owner-Knoten und Admin kann man nicht sperren.".into());
    }
    let (statement, submitted) = admin.ban(subject, days, reason).await?;
    Ok(json!({"ok": true, "index": submitted.index, "statement": statement.hash()}))
}

/// Lifts the bans of an identity (revokes its ban statements known from the log).
pub async fn unban(app: &App, id: &str, subject: &str) -> Result<Value, String> {
    let owner = entry_of(app, id).await?;
    let admin = admin_client(app, &owner)?;
    let subject = Id::parse(subject.trim()).map_err(|_| "keine ID")?;
    let now = now_ms();
    let hashes: Vec<[u8; 32]> = {
        let cache = app.poller.cache(id);
        let cache = cache.read().await;
        let view = cache.net.as_ref().ok_or("Der Owner-Knoten läuft noch nicht")?;
        view.bans
            .iter()
            .filter(|ban| ban.subject == subject && ban.exp > now && !view.state.is_revoked(&ban.hash))
            .map(|ban| ban.hash)
            .collect()
    };
    if hashes.is_empty() {
        return Err("Keine aktive Sperre für diese ID.".into());
    }
    for hash in &hashes {
        admin.revoke(RevokeTarget::Statement(*hash), "Sperre aufgehoben (BridgeControll)").await?;
    }
    Ok(json!({"ok": true, "lifted": hashes.len()}))
}

// --- settings, delete ---------------------------------------------------------------------------------------------

/// Changes a node's name, ports, address, autostart, address rule (`peer_addresses`: `public`, `tailnet`, `any`) and
/// reader (`reader`: `off`, `local`, `lan`; without a field it stays); a running node is restarted with them.
pub async fn settings(app: &App, id: &str, body: &serde_json::Map<String, Value>) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    let reach = Reach::from_json(body)?;
    let autostart = body.get("autostart").and_then(Value::as_bool).ok_or("autostart fehlt")?;
    let peer_addresses = match body.get("peer_addresses") {
        None => entry.peer_addresses,
        Some(value) => value
            .as_str()
            .and_then(bridge_transport::PeerAddresses::parse)
            .ok_or("Adressen anderer Knoten: public, tailnet oder any")?,
    };
    let reader = match body.get("reader") {
        None => entry.reader,
        Some(value) => {
            value.as_str().and_then(bridge_node::ReaderAccess::parse).ok_or("Leser: off, local, lan oder tailnet")?
        }
    };
    let name = body.get("name").and_then(Value::as_str).map_or_else(|| entry.name.clone(), |n| n.trim().to_owned());
    config::check_name(&name, "Name des Knotens")?;
    if entry.public_key.is_some() && reach.public_url != entry.public_url {
        return Err("Die öffentliche Adresse kommt von „Öffentlich machen“ – erst „Nicht mehr öffentlich“.".into());
    }
    let running = app.supervisor.status(id).state == RunState::Running;
    {
        let config = app.config.lock().await;
        if let Some((_, error)) = reach.check(&config, Some(id), running).into_iter().next() {
            return Err(error);
        }
    }
    let mut changed = entry.clone();
    changed.name = name;
    changed.listen_port = reach.listen_port;
    changed.lan_port = reach.lan_port;
    changed.public_url = reach.public_url;
    changed.autostart = autostart;
    changed.peer_addresses = peer_addresses;
    changed.reader = reader;
    changed.check()?;
    let restart = running && node_args(&changed, &app.node_dir(&changed)) != node_args(&entry, &app.node_dir(&entry));
    save(app, |config| {
        let slot = config.node_mut(id).ok_or("Diesen Knoten gibt es nicht (mehr).")?;
        *slot = changed.clone();
        Ok(())
    })
    .await?;
    if restart {
        app.supervisor.stop(id).await;
        app.start_node(&changed);
    }
    Ok(json!({"ok": true, "restarted": restart}))
}

/// Deletes a node from the app after the user typed its name: stops it and moves its folder to `backup/` (key
/// files and the admin key are never deleted).
pub async fn delete(app: &App, id: &str, confirm: &str) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    if confirm.trim() != entry.name {
        return Err(format!("Tippe {} zum Bestätigen.", entry.name));
    }
    if entry.public_key.is_some() {
        crate::public::make_private(app, id).await?; // route, Funnel (if the last) and address first
    }
    crate::bridge3::stop_for_node(app, id).await; // its Bridge 3 servers go with it
    app.supervisor.stop(id).await;
    let dir = app.node_dir(&entry);
    let backup = app.options.app_dir.join(BACKUP_DIR).join(format!("{}-{}", entry.id, now_ms()));
    if dir.exists() {
        std::fs::create_dir_all(app.options.app_dir.join(BACKUP_DIR)).map_err(|e| format!("Sicherung: {e}"))?;
        std::fs::rename(&dir, &backup).map_err(|e| format!("Ordner nicht verschiebbar ({e}) - nichts gelöscht"))?;
    }
    save(app, |config| {
        config.nodes.retain(|node| node.id != id);
        crate::bridge3::forget_node(config, id);
        Ok(())
    })
    .await?;
    app.poller.forget(id);
    Ok(json!({"ok": true, "backup": backup.display().to_string()}))
}

/// `POST /api/startmenu`: the start menu entry "BridgeControll" to this program; on Windows a desktop shortcut
/// "BridgeControll" to another program (Bridge 3) becomes "BridgeControll 3".
pub async fn set_startmenu(app: &App) -> Result<Value, String> {
    let menu = app.options.menu_dir.clone().ok_or("Einen Startmenü-Eintrag gibt es auf diesem System nicht.")?;
    let app_dir = app.options.app_dir.clone();
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let done = tokio::task::spawn_blocking(move || crate::startmenu::set(&menu, &app_dir, &exe, true))
        .await
        .map_err(|e| e.to_string())??;
    Ok(json!({"ok": true, "renamed_old": done.renamed_old}))
}

/// Switches "start with the system" on or off.
pub fn set_login_autostart(app: &App, enabled: bool) -> Result<(), String> {
    let dir = app.autostart_dir().ok_or("Autostart gibt es auf diesem System noch nicht.")?;
    let data = app.options.custom_app_dir.then_some(app.options.app_dir.as_path());
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    autostart::set(dir, enabled, &exe, data)
}

/// After each status round: a joined node that holds its log (and, with probes, is a member) no longer needs the
/// join link; network names follow the manifest.
pub async fn housekeeping(app: &App) {
    let nodes: Vec<NodeEntry> = app.config.lock().await.nodes.clone();
    let mut changes: Vec<(String, Option<String>, bool)> = Vec::new();
    for entry in &nodes {
        let cache = app.poller.cache(&entry.id);
        let cache = cache.read().await;
        let (Some(view), Some(info)) = (&cache.net, &cache.info) else { continue };
        let name = net_name_update(&entry.net_name, &view.state.manifest().name);
        let member_needed = entry.probe.is_some() && !view.state.is_member(info.card.id(), now_ms());
        let drop_link = entry.join_link.is_some() && view.size > 0 && !member_needed;
        if name.is_some() || drop_link {
            changes.push((entry.id.clone(), name, drop_link));
        }
    }
    if changes.is_empty() {
        return;
    }
    let dropped = changes.clone();
    let result = save(app, |config| {
        for (id, name, drop_link) in changes {
            if let Some(entry) = config.node_mut(&id) {
                if let Some(name) = name {
                    entry.net_name = name;
                }
                if drop_link {
                    entry.join_link = None;
                }
            }
        }
        Ok(())
    })
    .await;
    match result {
        Ok(()) => {
            for (id, _, drop_link) in dropped {
                if let Some(entry) = drop_link.then(|| nodes.iter().find(|entry| entry.id == id)).flatten() {
                    if let Err(error) = write_join_link(&app.node_dir(entry), None) {
                        tracing::warn!(%error, "Einladungslink-Datei nicht entfernt");
                    }
                }
            }
        }
        Err(error) => tracing::warn!(%error, "Einstellungen nicht gespeichert"),
    }
}

/// The dashboard's watcher figures: registered nodes, its level-1 seals in effect, today's budget.
fn watch_summary(state: &NetState, watcher: &Id, registered: usize, now: i64) -> Value {
    json!({
        "nodes": registered,
        "seals": state.seals_issued_by(watcher, 1).iter().filter(|(_, info)| info.active(now)).count(),
        "used_today": state.watch_used(watcher, now),
        "per_day": state.watch_rules().seals_per_day,
    })
}

/// The network name an entry takes from its node's manifest: only a changed name that is a valid name here (review
/// 7: the manifest of a foreign network may say " " - the old name stays then, the settings file stays valid).
fn net_name_update(current: &str, manifest: &str) -> Option<String> {
    (manifest != current && config::check_name(manifest, "Name des Netzes").is_ok()).then(|| manifest.to_owned())
}

// --- views --------------------------------------------------------------------------------------------------------

/// The state a row shows: process plus whether the node answers.
fn run_view(app: &App, entry: &NodeEntry, cache: &NodeCache) -> Value {
    let process = app.supervisor.status(&entry.id);
    let state = match process.state {
        RunState::Running if cache.reachable && process.started_at.is_some_and(|start| cache.seen >= start) => "ready",
        RunState::Running => "starting",
        other => other.as_str(),
    };
    json!({
        "state": state,
        "restarts": process.restarts,
        "last_exit": process.last_exit,
        "retry_in_ms": process.retry_at.map(|at| at.saturating_sub(now_ms()).max(0)),
    })
}

/// Level, services and roles of `id` in a network state.
fn standing(state: &NetState, id: &Id, now: i64) -> Value {
    let manifest = state.manifest();
    let services = state.services(id, now);
    let mut roles = Vec::new();
    if manifest.logs.contains(id) {
        roles.push("Log-Führer");
    }
    if manifest.witnesses.contains(id) {
        roles.push("Zeuge");
    }
    if services.has(Service::Gateway) || state.gateways(now).iter().any(|(gateway, _)| gateway == id) {
        roles.push("Empfänger");
    }
    if services.has(Service::Web) {
        roles.push("Apps (web)");
    }
    if services.has(Service::Watch) {
        roles.push("Wächter");
    }
    if services.has(Service::Storage) {
        roles.push("Speicher");
    }
    if services.has(Service::Compute) {
        roles.push("Rechnen");
    }
    json!({
        "level": state.level(id, now),
        "member": state.is_member(id, now),
        "banned": state.is_banned(id, now),
        "services": service_names(services),
        "roles": roles,
    })
}

/// One row of the start page.
async fn overview_row(app: &App, entry: &NodeEntry) -> Value {
    let cache = app.poller.cache(&entry.id);
    let cache = cache.read().await;
    let now = now_ms();
    let mut row = json!({
        "id": entry.id,
        "name": entry.name,
        "net_name": entry.net_name,
        "role": entry.role.as_str(),
        "listen_port": entry.listen_port,
        "lan_port": entry.lan_port,
        "public_url": entry.public_url,
        "autostart": entry.autostart,
        "peer_addresses": entry.peer_addresses.as_str(),
        "reader": entry.reader.as_str(),
        "reader_port": entry.reader_port,
        "offer_gateway": entry.offer_gateway,
        "probe": entry.probe,
        "joining": entry.join_link.is_some(),
        "public": crate::public::node_view(entry),
        "run": run_view(app, entry, &cache),
        "node_id": cache.info.as_ref().map(|info| info.card.id().as_str().to_owned()),
        "error": cache.error,
    });
    if let Some(info) = &cache.info {
        row["ausweis"] = json!(ausweis(&info.card).ok());
        row["version"] = json!(info.version);
    }
    if let (Some(view), Some(info)) = (&cache.net, &cache.info) {
        let manifest = view.state.manifest();
        row["net"] = json!({
            "id": view.net.as_str(),
            "name": manifest.name,
            "mode": mode_name(manifest.join.mode),
            "log_size": view.size,
            "witnessed": cache.head.is_some_and(|head| head.size >= view.size),
            "evidence": cache.evidence,
            "members": view.state.member_count(),
            "gateways": view.state.gateways(now).len(),
            "short": manifest.short,
            "contact": manifest.contact.is_some(),
            "adult": manifest.adult_policy().as_str(),
        });
        row["me"] = standing(&view.state, info.card.id(), now);
    }
    // The Bridge-Browser opens apps through this node's reader - or says why it can not (docs/08 §8).
    row["browser"] = match crate::browser::reader_blocker(app, entry, &cache) {
        None => json!({"usable": true, "why": Value::Null}),
        Some(why) => json!({"usable": false, "why": why}),
    };
    row
}

/// The start page: all nodes of this PC with live status.
pub async fn overview(app: &App) -> Value {
    let nodes: Vec<NodeEntry> = app.config.lock().await.nodes.clone();
    let mut rows = Vec::with_capacity(nodes.len());
    for entry in &nodes {
        let mut row = overview_row(app, entry).await;
        if entry.role == NodeRole::Owner {
            let dir = app.node_dir(entry);
            let apps = tokio::task::spawn_blocking(move || admin::hosted_apps(&dir, 1000).map(|apps| apps.len()))
                .await
                .ok()
                .and_then(Result::ok);
            row["apps"] = json!(apps);
        }
        rows.push(row);
    }
    let (listen, lan) = {
        let config = app.config.lock().await;
        suggested_ports(&config)
    };
    json!({
        "host": host_name(),
        "version": crate::update::own_version().to_string(),
        "nodes": rows,
        "warnings": app.warnings,
        "suggested": {"listen_port": listen, "lan_port": lan},
        "autostart": {
            "supported": app.autostart_dir().is_some(),
            "enabled": app.autostart_dir().is_some_and(autostart::is_enabled),
            "windows": cfg!(windows),
        },
        "startmenu": {
            "supported": app.options.menu_dir.is_some(),
            "exists": app.options.menu_dir.as_deref().is_some_and(crate::startmenu::exists),
        },
        "public": crate::public::summary(app).await,
        "update": app.updater.status(),
    })
}

/// The dashboard of a node: for an owner node the whole network (nodes, candidates, members, invites, apps, log,
/// watcher, names, Meldeweg), for a member node its own standing.
pub async fn dashboard(app: &App, id: &str, query: &str) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    let mut answer = json!({"node": overview_row(app, &entry).await, "public": crate::public::summary(app).await});
    if entry.role != NodeRole::Owner {
        return Ok(answer);
    }
    answer["bridge3"] = crate::bridge3::view(app, id).await;
    let now = now_ms();
    let dir = app.node_dir(&entry);
    let locals = local_nodes(app).await;
    let search = query_value(query, "q").to_lowercase();
    let cache = app.poller.cache(id);
    let cache = cache.read().await;
    let (Some(view), Some(info)) = (&cache.net, &cache.info) else {
        return Ok(answer);
    };
    let state = &view.state;
    let manifest = state.manifest();
    let owner_id = info.card.id().clone();

    // Nodes: every node sealed (active; a member's seal has no node card), the owner node, and the nodes of this PC in
    // this network.
    let mut ids: BTreeSet<Id> = view
        .sealed
        .iter()
        .filter(|id| {
            !state.seals(id, now).is_empty() && state.card_of(id).is_some_and(|card| card.role() == Role::Node)
        })
        .cloned()
        .collect();
    ids.insert(owner_id.clone());
    for (_, local) in locals.iter().filter(|(_, local)| local.net.as_ref() == Some(&view.net)) {
        ids.insert(local.card.id().clone());
    }
    let mut nodes = Vec::new();
    let mut candidates = Vec::new();
    for node in ids.iter().take(500) {
        let card = state.card_of(node);
        let local = locals.iter().find(|(_, local)| local.card.id() == node);
        let live_card = local.map(|(_, local)| &local.card);
        let name = live_card.or(card).map(card_name).unwrap_or_default();
        let standing = standing(state, node, now);
        let level = state.level(node, now);
        let stale = match (live_card, card) {
            (Some(live), Some(sealed)) if level.is_some_and(|level| level >= 1) => {
                live.urls() != sealed.urls() || live.tls() != sealed.tls()
            }
            _ => false,
        };
        let row = json!({
            "id": node.as_str(),
            "name": name,
            "standing": standing,
            "self": node == &owner_id,
            "local": local.map(|(local_id, _)| local_id.clone()),
            "running": local.map(|(_, local)| local.ready),
            "lan": live_card.or(card).is_some_and(|card| card.tls().is_some()),
            "urls": live_card.or(card).map(|card| card.urls().to_vec()).unwrap_or_default(),
            "card_stale": stale,
        });
        if level.unwrap_or(0) < 2 && node != &owner_id {
            if let Some((local_id, local)) = local {
                candidates.push(json!({
                    "id": node.as_str(),
                    "name": name,
                    "local": local_id,
                    "offer_gateway": local.offer_gateway,
                }));
            }
        }
        nodes.push(row);
    }

    // Members (search by ID or name).
    let mut member_ids = Vec::new();
    let mut after: Option<Id> = None;
    while member_ids.len() < MAX_MEMBERS_SCANNED {
        let page = state.members_after(after.as_ref(), 500);
        let Some(last) = page.last().cloned() else { break };
        member_ids.extend(page);
        after = Some(last);
    }
    let lookup: Vec<Id> = member_ids.iter().take(MAX_MEMBERS_SCANNED).cloned().collect();
    let cards_dir = dir.clone();
    let cards = tokio::task::spawn_blocking(move || admin::known_cards(&cards_dir, &lookup))
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let names: BTreeMap<Id, String> = cards.iter().map(|card| (card.id().clone(), card_name(card))).collect();
    let total = state.member_count();
    let members: Vec<Value> = member_ids
        .iter()
        .filter(|member| {
            search.is_empty()
                || member.as_str().contains(&search)
                || names.get(*member).is_some_and(|name| name.to_lowercase().contains(&search))
        })
        .take(MAX_MEMBERS_SHOWN)
        .map(|member| {
            json!({
                "id": member.as_str(),
                "name": names.get(member).cloned().unwrap_or_default(),
                "node": cards.iter().any(|card| card.id() == member && card.role() == Role::Node),
                "standing": standing(state, member, now),
            })
        })
        .collect();

    // Invites with uses left, newest first.
    let mut invites: Vec<Value> = view
        .invites
        .values()
        .filter_map(|invite| {
            state.invite_left(&invite.code_hash, now).map(|left| {
                json!({"hash": invite.hash, "uses": invite.uses, "left": left, "iat": invite.iat, "exp": invite.exp})
            })
        })
        .collect();
    invites.sort_by_key(|invite| std::cmp::Reverse(invite["iat"].as_i64().unwrap_or(0)));
    invites.truncate(20);

    // Bans in effect.
    let bans: Vec<Value> = view
        .bans
        .iter()
        .rev()
        .filter(|ban| ban.exp > now && !state.is_revoked(&ban.hash))
        .take(50)
        .map(|ban| json!({"id": ban.subject.as_str(), "exp": ban.exp}))
        .collect();

    // Apps hosted by the owner node (with where this PC's browsers see them), the watcher's status.
    let reader = crate::browser::reader_origin(&entry);
    let apps_dir = dir.clone();
    let apps = tokio::task::spawn_blocking(move || admin::hosted_apps(&apps_dir, 100))
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let apps: Vec<Value> = apps
        .iter()
        .map(|hosted| {
            // Its address (the first name pointing to it) and - in a public network - the public frame with Bridge
            // Login (docs/07 §8a, docs/11 §9).
            let address = state.names_for(&hosted.app, now).first().map(|resolved| resolved.info.name.name.clone());
            let public = match (&entry.public_url, &address) {
                (Some(base), Some(name)) if entry.public_web => {
                    Some(format!("{}/web/{name}/", base.trim_end_matches('/')))
                }
                _ => None,
            };
            json!({
                "address": address.as_ref().map(|name| match &manifest.short {
                    Some(short) => format!("{name}.{short}"),
                    None => name.clone(),
                }),
                "public": public,
                "id": hosted.app.as_str(),
                "name": hosted.name,
                "version": hosted.version,
                "hosts": hosted.hosts.len(),
                "owner": hosted.owner.as_str(),
                "state": hosted.state,
                "banned": state.is_banned(&hosted.app, now),
                "view": reader.as_ref().map(|origin| format!("{origin}/app/{}/", hosted.app)),
            })
        })
        .collect();
    // The watcher part from the state the poller holds already; only the registrations come from the database (review
    // 7: no replay of the whole log every few seconds).
    let watch = if state.is_watcher(&owner_id, now) {
        let (watch_dir, net) = (dir.clone(), view.net.clone());
        let registered = tokio::task::spawn_blocking(move || admin::watch_registered(&watch_dir, &net, now_ms()))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(0);
        Some(watch_summary(state, &owner_id, registered, now))
    } else {
        None
    };
    let link = app.links.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id).cloned();
    // Names, Meldeweg and the operator's member key (docs/08 §12).
    let names = crate::moderation::names_view(state, now);
    let app_keys = crate::moderation::app_keys(&dir).await;
    let operator = crate::moderation::operator_id(&dir);
    answer["net"] = json!({
        "id": view.net.as_str(),
        "name": manifest.name,
        "mode": manifest.join.mode.as_str(),
        "mode_name": mode_name(manifest.join.mode),
        "manifest_version": manifest.version,
        "log_size": view.size,
        "truncated": view.truncated,
        "witnesses": manifest.witnesses.len(),
        "threshold": manifest.witness_threshold,
        "head": cache.head.map(|head| json!({
            "size": head.size, "age_ms": now.saturating_sub(head.iat).max(0), "cosigns": head.cosigns,
        })),
        "evidence": cache.evidence,
        "members": total,
        "gateways": state.gateways(now).len(),
        "short": manifest.short,
        "contact": manifest.contact,
        "adult": manifest.adult_policy().as_str(),
        "join_mode": manifest.join.mode.as_str(),
    });
    // Was kann mein Netz? (docs/11 §9.1) and Bridge Login at this node (§9.2).
    let abilities: Vec<Value> = state
        .abilities(now)
        .iter()
        .map(|ability| {
            json!({
                "key": ability.key, "name": ability.name, "needs": ability.needs, "have": ability.have,
                "yellow": ability.yellow, "green": ability.green, "status": ability.status(),
            })
        })
        .collect();
    answer["abilities"] = json!(abilities);
    answer["login"] = json!({
        "here": state.login_nodes(now).iter().any(|(node, _)| node == &owner_id),
        "public": entry.public_key.is_some(),
    });
    answer["names"] = names;
    answer["app_keys"] = json!(app_keys);
    answer["operator"] = json!(operator.as_ref().map(|id| json!({
        "id": id.as_str(), "level": state.level(id, now), "member": state.is_member(id, now),
    })));
    answer["nodes"] = json!(nodes);
    answer["candidates"] = json!(candidates);
    answer["members"] = json!({"total": total, "list": members, "more": total > MAX_MEMBERS_SHOWN});
    answer["invites"] = json!(invites);
    answer["bans"] = json!(bans);
    answer["apps"] = json!(apps);
    answer["watch"] = json!(watch);
    answer["link"] = json!(link.as_ref().map(|link| json!({"link": link, "qr": qr::svg(link).ok()})));
    Ok(answer)
}

/// What the dashboard needs of the other nodes of this PC.
struct Local {
    card: KeyCard,
    net: Option<Id>,
    ready: bool,
    offer_gateway: bool,
}

async fn local_nodes(app: &App) -> Vec<(String, Local)> {
    let nodes: Vec<NodeEntry> = app.config.lock().await.nodes.clone();
    let mut locals = Vec::new();
    for entry in nodes {
        let cache = app.poller.cache(&entry.id);
        let cache = cache.read().await;
        if let Some(info) = &cache.info {
            let ready = app.supervisor.status(&entry.id).state == RunState::Running && cache.reachable;
            locals.push((
                entry.id.clone(),
                Local { card: info.card.clone(), net: info.net.clone(), ready, offer_gateway: entry.offer_gateway },
            ));
        }
    }
    locals
}

/// One value of a query string (`a=1&q=x`), percent-decoded, bounded.
#[must_use]
pub fn query_value(query: &str, name: &str) -> String {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
        .map(|value| percent_decode(&value.replace('+', " ")))
        .unwrap_or_default()
        .chars()
        .take(64)
        .collect()
}

/// `%XX` with exactly two hex digits becomes that byte; anything else stays as it is (review 8: also an escape that
/// ends the text, and never a sign - `u8::from_str_radix` took `%+1` as byte 1).
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = match (byte, bytes.get(index + 1), bytes.get(index + 2)) {
            (b'%', Some(&high), Some(&low)) => hex_value(high).zip(hex_value(low)).map(|(high, low)| high * 16 + low),
            _ => None,
        };
        match escaped {
            Some(decoded) => {
                out.push(decoded);
                index += 3;
            }
            None => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> NodeEntry {
        NodeEntry {
            id: "0a1b2c3d".into(),
            name: "laptop".into(),
            net_name: String::new(),
            role: NodeRole::Member,
            listen_port: 7401,
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
            created: 0,
        }
    }

    #[test]
    fn node_arguments() {
        let dir = Path::new("/app/nodes/0a1b2c3d");
        let plain = node_args(&entry(), dir);
        assert_eq!(
            plain,
            vec![
                "--data",
                "/app/nodes/0a1b2c3d",
                "--listen",
                "127.0.0.1:7401",
                "--name",
                "laptop",
                "--url",
                "http://127.0.0.1:7401",
                "--peer-addresses",
                "tailnet",
                "--reader",
                "local"
            ]
        );
        let mut full = entry();
        full.public_url = Some("https://pc.tail1.ts.net:8443/k".into());
        full.lan_port = Some(7443);
        full.join_link = Some("bridge4://join?net=x&code=GEHEIM".into());
        full.probe = Some("web".into());
        let args = node_args(&full, dir).join(" ");
        assert!(args.contains("--url https://pc.tail1.ts.net:8443/k --trust-proxy 127.0.0.1"), "{args}");
        let file = dir.join(JOIN_LINK_FILE).display().to_string();
        assert!(
            args.contains("--lan 7443")
                && args.contains(&format!("--join-net-file {file}"))
                && args.ends_with("--probe web --peer-addresses tailnet --reader local")
        );
        // Review 8, finding 7: the link (with its invite code) is never on the command line.
        assert!(!args.contains("bridge4://") && !args.contains("GEHEIM"), "{args}");
        // Review 9: with its loopback reader port, a public node gets the listener for this PC's browser.
        full.reader_port = Some(7601);
        let args = node_args(&full, dir).join(" ");
        assert!(args.ends_with("--reader local --reader-listen 127.0.0.1:7601"), "{args}");
        full.reader = bridge_node::ReaderAccess::Off;
        assert!(!node_args(&full, dir).join(" ").contains("--reader-listen"), "no reader, no listener");
    }

    /// Review 9 (open point of the UI): a node with a public address trusts the local proxy on its main port; it gets
    /// a loopback reader port of its own (distinct from every other port), a node without one gets none.
    #[test]
    fn public_nodes_get_a_loopback_reader_port() -> Result<(), String> {
        let mut config = AppConfig::default();
        let mut public = entry();
        public.public_url = Some("https://pc.tail1.ts.net:8443/k".into());
        let mut second = public.clone();
        second.id = "0a1b2c3e".into();
        second.listen_port = 7402;
        let mut local = entry();
        local.id = "0a1b2c3f".into();
        local.listen_port = 7403;
        local.reader_port = Some(7699);
        config.nodes = vec![public, second, local];
        assign_reader_ports(&mut config);
        let ports: Vec<Option<u16>> = config.nodes.iter().map(|node| node.reader_port).collect();
        assert!(ports[0].is_some() && ports[1].is_some() && ports[0] != ports[1], "{ports:?}");
        assert_eq!(ports[2], None, "no public address: the main port serves the browser");
        config.check()?;
        // Ports given stay.
        let before = ports.clone();
        assign_reader_ports(&mut config);
        assert_eq!(config.nodes.iter().map(|node| node.reader_port).collect::<Vec<_>>(), before);
        // The browser frames and asks exactly that port - never the main port of a public node.
        let origin = crate::browser::reader_origin(&config.nodes[0]);
        assert_eq!(origin, before[0].map(|port| format!("http://127.0.0.1:{port}")));
        assert_eq!(crate::browser::reader_origin(&config.nodes[2]).as_deref(), Some("http://127.0.0.1:7403"));
        let mut unassigned = config.nodes[0].clone();
        unassigned.reader_port = None;
        assert_eq!(crate::browser::reader_origin(&unassigned), None, "public without a reader port: nothing");
        Ok(())
    }

    #[test]
    fn join_link_file_is_owner_only_and_removed() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let node = dir.path().join("nodes").join("0a1b2c3d");
        write_join_link(&node, Some("bridge4://join?net=x"))?;
        let path = node.join(JOIN_LINK_FILE);
        assert_eq!(std::fs::read_to_string(&path).map_err(|e| e.to_string())?, "bridge4://join?net=x\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).map_err(|e| e.to_string())?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner only");
        }
        write_join_link(&node, None)?;
        assert!(!path.exists());
        write_join_link(&node, None)?;
        Ok(())
    }

    /// Review 8, finding 6: a foreign manifest's name that is no valid name here never goes into the settings.
    #[test]
    fn net_names_follow_the_manifest_only_when_valid() {
        assert_eq!(net_name_update("Alt", "Neu"), Some("Neu".to_owned()));
        assert_eq!(net_name_update("Alt", "Alt"), None);
        for bad in [" ", "", "a\nb", &"x".repeat(65)] {
            assert_eq!(net_name_update("Alt", bad), None, "{bad:?}");
        }
    }

    #[test]
    fn ausweis_round_trip_and_attacks() -> Result<(), String> {
        let identity = bridge_core::Identity::generate(&mut OsRng);
        let card = identity
            .key_card_with(Role::Node, Some("laptop"), &["http://127.0.0.1:7402".to_owned()], Some([7; 32]), 1)
            .map_err(|e| e.to_string())?;
        let text = ausweis(&card)?;
        assert!(text.starts_with(AUSWEIS_PREFIX));
        assert_eq!(parse_ausweis(&format!("  {text}\n"))?, card);
        // A changed byte breaks the self-signature.
        let bytes = card.to_bytes().map_err(|e| e.to_string())?;
        let forged = String::from_utf8_lossy(&bytes).replace("laptop", "laptoq");
        assert!(parse_ausweis(&format!("{AUSWEIS_PREFIX}{}", b64(forged.as_bytes()))).is_err());
        // A client card (no address) is no node card.
        let client = identity.key_card(Role::Client, None, 1).map_err(|e| e.to_string())?;
        assert!(parse_ausweis(&ausweis(&client)?).is_err());
        for bad in ["", "bridge4://join?net=x", "bridge4://node?card=%%%", &format!("{text}&x=1"), &"a".repeat(5000)] {
            assert!(parse_ausweis(bad).is_err(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn reach_from_json_and_checks() -> Result<(), String> {
        let body = |value: Value| value.as_object().cloned().unwrap_or_default();
        let reach = Reach::from_json(&body(json!({"listen_port": 7401, "lan_port": null, "public_url": " "})))?;
        assert_eq!(reach, Reach { listen_port: 7401, lan_port: None, public_url: None });
        assert!(Reach::from_json(&body(json!({"listen_port": "x"}))).is_err());
        assert!(Reach::from_json(&body(json!({"listen_port": 70000}))).is_err());
        assert!(Reach::from_json(&body(json!({"listen_port": 7401, "public_url": 5}))).is_err());
        let config = AppConfig { nodes: vec![entry()], ..AppConfig::default() };
        let taken = Reach { listen_port: 7401, lan_port: Some(7401), public_url: Some("ftp://x".into()) };
        let fields: Vec<&str> = taken.check(&config, None, false).iter().map(|(field, _)| *field).collect();
        assert_eq!(fields, vec!["listen_port", "lan_port", "public_url"]);
        assert!(Reach { listen_port: 80, lan_port: None, public_url: None }.check(&config, None, false).len() == 1);
        // A port in use on this PC.
        let busy = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
        let port = busy.local_addr().map_err(|e| e.to_string())?.port();
        if port >= config::MIN_PORT {
            let errors = Reach { listen_port: port, lan_port: None, public_url: None }.check(&config, None, false);
            assert_eq!(errors.len(), 1, "{errors:?}");
        }
        Ok(())
    }

    #[test]
    fn small_helpers() {
        assert_eq!(query_value("a=1&q=Max%20M%C3%BCller&b=2", "q"), "Max Müller");
        assert_eq!(query_value("q=a+b", "q"), "a b");
        assert_eq!(query_value("qq=1", "q"), "");
        assert_eq!(query_value("q=%zz%4", "q"), "%zz%4");
        // Review 8, finding 10d: an escape at the very end, and no signs inside an escape.
        assert_eq!(query_value("q=%41", "q"), "A");
        assert_eq!(query_value("q=x%41", "q"), "xA");
        assert_eq!(query_value("q=%4", "q"), "%4");
        assert_eq!(query_value("q=%", "q"), "%");
        assert_eq!(percent_decode("%+1%-1"), "%+1%-1");
        assert_eq!(percent_decode("%c3%bc%C3%BC"), "üü");
        assert_eq!(query_value(&format!("q={}", "x".repeat(200)), "q").len(), 64);
        assert!(parse_services(&[json!("gateway"), json!("web")]).is_ok_and(|s| s.has(Service::Web)));
        assert!(parse_services(&[json!("mining")]).is_err());
        assert!(!host_name().is_empty());
        assert_eq!(mode_name(JoinMode::Invite), "Mit Einladung");
    }
}
