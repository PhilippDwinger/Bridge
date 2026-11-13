//! The app's own settings: which nodes this PC runs (`bridgecontroll.json` in the app data folder, ADR 0017).
//!
//! - One entry per node: name, role, ports, public address, autostart, and - until the node has its network's log -
//!   the join link. A node's data folder is always `nodes/<id>` under the app folder; `id` is 8 lowercase hex
//!   characters made here, so no entry can point anywhere else (no paths in the file).
//! - Strict like every Bridge body: exact fields, types and bounds. A file that is no settings file at all (not
//!   JSON, another version, no node list) stops the app with a clear message instead of being overwritten (fail
//!   closed, Z8). A single bad entry does not (review 8: a foreign network's name once made the app write a file it
//!   then refused - it never started again): it is skipped with a warning the start page shows, after the file was
//!   copied to `backup/` (the next save drops the entry). Every entry is checked before the file is written.
//! - Written atomically (temporary file, then rename), only readable by the owner on Unix (it may hold invite codes).

use std::path::{Path, PathBuf};

use bridge_core::json::parse_strict;
use bridge_node::ReaderAccess;
use bridge_transport::PeerAddresses;
use serde_json::{Map, Value, json};

/// File name of the settings inside the app folder.
pub const CONFIG_FILE: &str = "bridgecontroll.json";
/// Folder of the node data folders inside the app folder.
pub const NODES_DIR: &str = "nodes";
/// Most nodes one app manages.
pub const MAX_NODES: usize = 64;
/// Largest settings file.
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// Longest node or network name (like a manifest name, docs/06 §4).
pub const MAX_NAME_CHARS: usize = 64;
/// Lowest port a node may use (no privileged ports).
pub const MIN_PORT: u16 = 1024;

/// What the node is to its network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    /// Made the network here (`admin-key.json` in its folder).
    Owner,
    /// Joined with a link.
    Member,
}

impl NodeRole {
    /// Name in the file and the API.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Member => "member",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "owner" => Some(Self::Owner),
            "member" => Some(Self::Member),
            _ => None,
        }
    }
}

/// One node of this PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry {
    /// Local ID (8 lowercase hex characters) - also the folder name.
    pub id: String,
    /// Name of the node (on its key card).
    pub name: String,
    /// Name of its network as last known (shown while the node is off).
    pub net_name: String,
    /// Owner or member.
    pub role: NodeRole,
    /// Port of the node's HTTP listener on 127.0.0.1.
    pub listen_port: u16,
    /// LAN (TLS + mDNS) port, if on.
    pub lan_port: Option<u16>,
    /// Public address (e.g. Tailscale Funnel), if any.
    pub public_url: Option<String>,
    /// Start this node when BridgeControll starts.
    pub autostart: bool,
    /// The join link, until the node holds its network's log (it may carry an invite code).
    pub join_link: Option<String>,
    /// Services to ask the watchers for (`--probe`): `web` or `-`.
    pub probe: Option<String>,
    /// The node offers to be a gateway (shown to the owner side as "Wartet auf Siegel").
    pub offer_gateway: bool,
    /// Which addresses other nodes chose the node calls (`--peer-addresses`, docs/06 §2): BridgeControll's default is
    /// `tailnet` (public + Tailscale's ranges); the settings offer "Öffentlich", "Öffentlich + Tailnet", "Alle".
    pub peer_addresses: PeerAddresses,
    /// Who may use the node's reader (`--reader`, docs/08 §8): `local` (default, the Bridge-Browser of this PC),
    /// `lan`, `tailnet` or `off`.
    pub reader: ReaderAccess,
    /// The port of the node's loopback reader on 127.0.0.1 (`--reader-listen`, review 9): only for a node with a public
    /// address, whose main port trusts the local proxy (Tailscale Funnel) - the Bridge-Browser of this PC uses this one.
    pub reader_port: Option<u16>,
    /// The network key under which this node is public through the gate (`/bridge4/<key>/`, docs/11 §2) - set by
    /// "Öffentlich machen", fixed from then on; `public_url` is the gate's address then.
    pub public_key: Option<String>,
    /// Websites and apps of the public node are public (`false`: the Not-Aus).
    pub public_web: bool,
    /// Created (ms since 1970).
    pub created: i64,
}

impl NodeEntry {
    /// The node's data folder.
    #[must_use]
    pub fn data_dir(&self, app_dir: &Path) -> PathBuf {
        app_dir.join(NODES_DIR).join(&self.id)
    }

    /// Where the node answers on this PC.
    #[must_use]
    pub fn local_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.listen_port)
    }

    fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "net_name": self.net_name,
            "role": self.role.as_str(),
            "listen_port": self.listen_port,
            "lan_port": self.lan_port,
            "public_url": self.public_url,
            "autostart": self.autostart,
            "join_link": self.join_link,
            "probe": self.probe,
            "offer_gateway": self.offer_gateway,
            "peer_addresses": self.peer_addresses.as_str(),
            "reader": self.reader.as_str(),
            "reader_port": self.reader_port,
            "public_key": self.public_key,
            "public_web": self.public_web,
            "created": self.created,
        })
    }

    fn from_value(value: &Value) -> Result<Self, String> {
        let object = value.as_object().ok_or("Knoten: kein Objekt")?;
        // `peer_addresses` came later: a file without it means the default (`tailnet`).
        let peer_addresses = match object.get("peer_addresses") {
            None => PeerAddresses::Tailnet,
            Some(value) => value.as_str().and_then(PeerAddresses::parse).ok_or("Knoten: peer_addresses")?,
        };
        // `reader` came with the Bridge-Browser: a file without it means the node's default (`local`).
        let reader = match object.get("reader") {
            None => ReaderAccess::Local,
            Some(value) => value.as_str().and_then(ReaderAccess::parse).ok_or("Knoten: reader")?,
        };
        // `reader_port` came with the loopback reader (review 9): a file without it means none (yet).
        let reader_port = match object.get("reader_port") {
            None | Some(Value::Null) => None,
            other => Some(port(other).ok_or("Knoten: reader_port")?),
        };
        // `public_key`/`public_web` came with the gate (phase 7): a file without them means not public.
        let public_key = match object.get("public_key") {
            None | Some(Value::Null) => None,
            Some(Value::String(key)) => Some(key.clone()),
            _ => return Err("Knoten: public_key".into()),
        };
        let public_web = match object.get("public_web") {
            None => true,
            Some(value) => value.as_bool().ok_or("Knoten: public_web")?,
        };
        let mut object = object.clone();
        object.remove("peer_addresses");
        object.remove("reader");
        object.remove("reader_port");
        object.remove("public_key");
        object.remove("public_web");
        let object = &object;
        exact(
            object,
            &[
                "id",
                "name",
                "net_name",
                "role",
                "listen_port",
                "lan_port",
                "public_url",
                "autostart",
                "join_link",
                "probe",
                "offer_gateway",
                "created",
            ],
        )?;
        let text = |name: &str| object.get(name).and_then(Value::as_str).ok_or(format!("Knoten: {name} fehlt"));
        let optional_text = |name: &str| match object.get(name) {
            Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            _ => Err(format!("Knoten: {name} ist kein Text")),
        };
        let flag = |name: &str| object.get(name).and_then(Value::as_bool).ok_or(format!("Knoten: {name} fehlt"));
        let entry = Self {
            id: text("id")?.to_owned(),
            name: text("name")?.to_owned(),
            net_name: text("net_name")?.to_owned(),
            role: NodeRole::parse(text("role")?).ok_or("Knoten: role")?,
            listen_port: port(object.get("listen_port")).ok_or("Knoten: listen_port")?,
            lan_port: match object.get("lan_port") {
                Some(Value::Null) => None,
                other => Some(port(other).ok_or("Knoten: lan_port")?),
            },
            public_url: optional_text("public_url")?,
            autostart: flag("autostart")?,
            join_link: optional_text("join_link")?,
            probe: optional_text("probe")?,
            offer_gateway: flag("offer_gateway")?,
            peer_addresses,
            reader,
            reader_port,
            public_key,
            public_web,
            created: object.get("created").and_then(Value::as_i64).ok_or("Knoten: created")?,
        };
        entry.check()?;
        Ok(entry)
    }

    /// Checks every field (also before an entry is added).
    pub fn check(&self) -> Result<(), String> {
        check_id(&self.id)?;
        check_name(&self.name, "Name des Knotens")?;
        if !self.net_name.is_empty() {
            check_name(&self.net_name, "Name des Netzes")?;
        }
        if self.listen_port < MIN_PORT || self.lan_port.is_some_and(|port| port < MIN_PORT) {
            return Err(format!("Ports ab {MIN_PORT}"));
        }
        if self.lan_port == Some(self.listen_port) {
            return Err("LAN-Port und Port müssen verschieden sein".into());
        }
        if let Some(reader) = self.reader_port {
            if reader < MIN_PORT || reader == self.listen_port || Some(reader) == self.lan_port {
                return Err(format!("Leser-Port: ab {MIN_PORT}, verschieden von Port und LAN-Port"));
            }
        }
        if let Some(url) = &self.public_url {
            bridge_core::keys::check_url(url).map_err(|_| format!("Adresse {url:?} ist ungültig"))?;
        }
        if let Some(link) = &self.join_link {
            bridge_core::JoinLink::parse(link).map_err(|e| format!("Einladungslink: {e}"))?;
        }
        if self.probe.as_deref().is_some_and(|probe| probe != "web" && probe != "-") {
            return Err("probe: web oder -".into());
        }
        if self.reader == ReaderAccess::Public {
            return Err("Leser public gibt es nur über „Öffentlich machen“".into());
        }
        if let Some(key) = &self.public_key {
            if !bridge_gate::route::valid_key(key) {
                return Err("Netz-Schlüssel: a-z, 0-9, - (höchstens 64), nicht bridge3/bridge4".into());
            }
            if self.public_url.is_none() {
                return Err("öffentlich ohne Adresse".into());
            }
        }
        Ok(())
    }

    /// The reader the node runs with: `public` while it is public through the gate, else the chosen one.
    #[must_use]
    pub fn effective_reader(&self) -> ReaderAccess {
        if self.public_key.is_some() && self.reader != ReaderAccess::Off { ReaderAccess::Public } else { self.reader }
    }
}

/// The ports Tailscale Funnel offers (docs/11 §2).
pub const FUNNEL_PORTS: [u16; 3] = [443, 8443, 10000];

/// Settings of the gate and Tailscale Funnel (docs/11 §5) - `public` in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicConfig {
    /// The gate's port on 127.0.0.1 (given when a node goes public first).
    pub gate_port: Option<u16>,
    /// The Funnel port (443, 8443 or 10000).
    pub funnel_port: u16,
    /// Whether this app set `/bridge4` on that port (it removes only what it set).
    pub funnel_on: bool,
    /// The PC's Tailscale name when it was last asked (`pc.tail1234.ts.net`).
    pub host: Option<String>,
}

impl Default for PublicConfig {
    fn default() -> Self {
        Self { gate_port: None, funnel_port: 443, funnel_on: false, host: None }
    }
}

impl PublicConfig {
    fn to_value(&self) -> Value {
        json!({"gate_port": self.gate_port, "funnel_port": self.funnel_port, "funnel_on": self.funnel_on, "host": self.host})
    }

    fn from_value(value: &Value) -> Result<Self, String> {
        let object = value.as_object().ok_or("public: kein Objekt")?;
        exact(object, &["gate_port", "funnel_port", "funnel_on", "host"])?;
        let config = Self {
            gate_port: match object.get("gate_port") {
                Some(Value::Null) => None,
                other => Some(port(other).ok_or("public: gate_port")?),
            },
            funnel_port: object
                .get("funnel_port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .ok_or("public: funnel_port")?,
            funnel_on: object.get("funnel_on").and_then(Value::as_bool).ok_or("public: funnel_on")?,
            host: match object.get("host") {
                Some(Value::Null) => None,
                Some(Value::String(host)) => Some(host.clone()),
                _ => return Err("public: host".into()),
            },
        };
        config.check()?;
        Ok(config)
    }

    /// Funnel port one of [`FUNNEL_PORTS`], gate port not privileged, host a DNS name.
    pub fn check(&self) -> Result<(), String> {
        if !FUNNEL_PORTS.contains(&self.funnel_port) {
            return Err("Funnel-Port: 443, 8443 oder 10000".into());
        }
        if self.gate_port.is_some_and(|port| port < MIN_PORT) {
            return Err(format!("Tor-Port ab {MIN_PORT}"));
        }
        if let Some(host) = &self.host {
            check_host(host)?;
        }
        Ok(())
    }

    /// The public address of a network key: `https://<host>[:<port>]/bridge4/<key>` (no `:443`).
    #[must_use]
    pub fn url_of(&self, host: &str, key: &str) -> String {
        if self.funnel_port == 443 {
            format!("https://{host}/bridge4/{key}")
        } else {
            format!("https://{host}:{}/bridge4/{key}", self.funnel_port)
        }
    }
}

/// A DNS name as Tailscale gives it (`pc.tail1234.ts.net`): labels of `a-z 0-9 -`, at most 253 characters.
pub fn check_host(host: &str) -> Result<(), String> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if ok { Ok(()) } else { Err(format!("Tailscale-Name {host:?} ist ungültig")) }
}

/// Most Bridge 3 servers on one PC (docs/11 §8).
pub const MAX_BRIDGE3: usize = 32;
/// First port tried for a Bridge 3 server.
pub const FIRST_BRIDGE3_PORT: u16 = 7801;
/// Names a Bridge 3 server ID can not have: the paths of Bridge 3/4 and Bridge 3's own routes.
pub const BRIDGE3_RESERVED: [&str; 14] = [
    "bridge3",
    "bridge4",
    "admin",
    "server",
    "s2s",
    "client",
    "message",
    "command",
    "realm",
    "express",
    "agent",
    "conversation",
    "friends",
    "site",
];

/// A Bridge 3 server in a network (docs/11 §8, ADR 0026).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bridge3Server {
    /// Its ID (part of its address `…/bridge3/<id>`): 2-40 of `a-z 0-9 -`, not at the ends, not reserved.
    pub id: String,
    /// Its name for people.
    pub name: String,
    /// The local ID of the owner node whose network it belongs to.
    pub node: String,
    /// Its port on 127.0.0.1.
    pub port: u16,
    /// Its admin password (8-200 characters) - Bridge 3 needs it at every start.
    pub password: String,
    /// Start it when BridgeControll starts.
    pub autostart: bool,
    /// Created (ms since 1970).
    pub created: i64,
}

/// Whether `id` may be a Bridge 3 server ID (see [`Bridge3Server::id`]).
pub fn check_bridge3_id(id: &str) -> Result<(), String> {
    let ok = (2..=40).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-');
    if !ok {
        return Err("Server-ID: 2-40 Zeichen a-z, 0-9 und - (nicht am Anfang/Ende)".into());
    }
    if BRIDGE3_RESERVED.contains(&id) {
        return Err(format!("„{id}“ ist ein Pfad von Bridge und kann keine Server-ID sein."));
    }
    Ok(())
}

impl Bridge3Server {
    fn to_value(&self) -> Value {
        json!({"id": self.id, "name": self.name, "node": self.node, "port": self.port, "password": self.password,
               "autostart": self.autostart, "created": self.created})
    }

    fn from_value(value: &Value) -> Result<Self, String> {
        let object = value.as_object().ok_or("Bridge-3-Server: kein Objekt")?;
        exact(object, &["id", "name", "node", "port", "password", "autostart", "created"])?;
        let text = |name: &str| {
            object.get(name).and_then(Value::as_str).map(str::to_owned).ok_or(format!("Bridge-3-Server: {name}"))
        };
        let server = Self {
            id: text("id")?,
            name: text("name")?,
            node: text("node")?,
            port: port(object.get("port")).ok_or("Bridge-3-Server: port")?,
            password: text("password")?,
            autostart: object.get("autostart").and_then(Value::as_bool).ok_or("Bridge-3-Server: autostart")?,
            created: object.get("created").and_then(Value::as_i64).ok_or("Bridge-3-Server: created")?,
        };
        server.check()?;
        Ok(server)
    }

    /// Every field.
    pub fn check(&self) -> Result<(), String> {
        check_bridge3_id(&self.id)?;
        check_name(&self.name, "Name des Servers")?;
        check_id(&self.node)?;
        if self.port < MIN_PORT {
            return Err(format!("Port ab {MIN_PORT}"));
        }
        let count = self.password.chars().count();
        if !(8..=200).contains(&count) || self.password.chars().any(char::is_control) {
            return Err("Passwort: 8 bis 200 Zeichen, keine Steuerzeichen".into());
        }
        Ok(())
    }
}

/// The Bridge 3 servers of this PC and where their code and Python are (docs/11 §8).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bridge3Config {
    /// The Bridge 3 folder (branch `bridge-3`, with `main.py` and `bridge/server/base_path.py`).
    pub code_dir: Option<String>,
    /// The Python to run it with (`None`: found automatically).
    pub python: Option<String>,
    /// The servers (at most [`MAX_BRIDGE3`]).
    pub servers: Vec<Bridge3Server>,
}

impl Bridge3Config {
    fn to_value(&self) -> Value {
        let servers: Vec<Value> = self.servers.iter().map(Bridge3Server::to_value).collect();
        json!({"code_dir": self.code_dir, "python": self.python, "servers": servers})
    }

    /// The server with this ID.
    #[must_use]
    pub fn server(&self, id: &str) -> Option<&Bridge3Server> {
        self.servers.iter().find(|server| server.id == id)
    }
}

/// A path setting: 1-1024 characters, no control characters.
pub fn check_path_setting(path: &str, what: &str) -> Result<(), String> {
    if path.trim().is_empty() || path.chars().count() > 1024 || path.chars().any(char::is_control) {
        return Err(format!("{what}: 1 bis 1024 Zeichen, keine Steuerzeichen"));
    }
    Ok(())
}

/// All settings of the app.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppConfig {
    /// The nodes of this PC (at most [`MAX_NODES`]).
    pub nodes: Vec<NodeEntry>,
    /// The gate and Tailscale Funnel (phase 7).
    pub public: PublicConfig,
    /// Bridge 3 servers in networks (phase 7).
    pub bridge3: Bridge3Config,
}

/// The settings as loaded, with what was wrong in the file (German, for the start page).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    /// The good entries.
    pub config: AppConfig,
    /// One line per skipped entry, and where the old file was saved.
    pub warnings: Vec<String>,
}

impl AppConfig {
    /// Loads the settings of `app_dir` (none yet: empty). A file that is no settings file fails; bad entries are
    /// skipped with a warning after the file was copied to `backup/bridgecontroll-<ms>.json` (see module docs).
    pub fn load(app_dir: &Path) -> Result<Loaded, String> {
        let path = app_dir.join(CONFIG_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::default()),
            Err(error) => return Err(format!("{} nicht lesbar: {error}", path.display())),
        };
        let (config, mut warnings) = Self::parse_lenient(&bytes)
            .map_err(|e| format!("{} ist beschädigt ({e}) - bitte prüfen, nichts wurde geändert", path.display()))?;
        if !warnings.is_empty() {
            let backup = app_dir.join(crate::BACKUP_DIR).join(format!("bridgecontroll-{}.json", crate::now_ms()));
            write_private(&backup, &bytes).map_err(|e| format!("Sicherung der Einstellungen: {e}"))?;
            warnings.push(format!("Die alte Datei liegt unverändert in {}.", backup.display()));
        }
        Ok(Loaded { config, warnings })
    }

    /// Strict parse of the file content: every entry must be good.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let (config, warnings) = Self::parse_lenient(bytes)?;
        match warnings.first() {
            Some(warning) => Err(warning.clone()),
            None => Ok(config),
        }
    }

    /// Parses the file: errors only if it is no settings file; bad entries (and entries whose ID or port an earlier
    /// one has, and those beyond [`MAX_NODES`]) are left out with a warning each.
    fn parse_lenient(bytes: &[u8]) -> Result<(Self, Vec<String>), String> {
        let value = parse_strict(bytes, MAX_CONFIG_BYTES).map_err(|e| e.to_string())?;
        let object = value.as_object().ok_or("kein Objekt")?;
        // `public` came with the gate (phase 7): a file without it means the defaults.
        let public = match object.get("public") {
            None => PublicConfig::default(),
            Some(value) => PublicConfig::from_value(value)?,
        };
        // `bridge3` came with the Bridge 3 servers (phase 7): a file without it means none.
        let bridge3 = object.get("bridge3").cloned();
        let mut object = object.clone();
        object.remove("public");
        object.remove("bridge3");
        let object = &object;
        exact(object, &["v", "nodes"])?;
        if object.get("v") != Some(&json!(1)) {
            return Err("unbekannte Version".into());
        }
        let list = object.get("nodes").and_then(Value::as_array).ok_or("nodes ist keine Liste")?;
        let mut config = Self { public, ..Self::default() };
        let mut warnings = Vec::new();
        for (index, item) in list.iter().enumerate() {
            let label = item
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| check_id(id).is_ok())
                .map_or_else(|| format!("Eintrag {}", index + 1), |id| format!("Knoten {id}"));
            if config.nodes.len() >= MAX_NODES {
                warnings.push(format!("{label} übersprungen: mehr als {MAX_NODES} Knoten"));
                continue;
            }
            let entry = NodeEntry::from_value(item).and_then(|entry| {
                let mut next = config.clone();
                next.nodes.push(entry.clone());
                next.check().map(|()| entry)
            });
            match entry {
                Ok(entry) => config.nodes.push(entry),
                Err(error) => warnings.push(format!("{label} übersprungen: {error}")),
            }
        }
        if let Some(bridge3) = bridge3 {
            let object = bridge3.as_object().ok_or("bridge3: kein Objekt")?;
            exact(object, &["code_dir", "python", "servers"])?;
            let setting = |name: &str| match object.get(name) {
                Some(Value::Null) => Ok(None),
                Some(Value::String(text)) => check_path_setting(text, name).map(|()| Some(text.clone())),
                _ => Err(format!("bridge3: {name}")),
            };
            config.bridge3.code_dir = setting("code_dir")?;
            config.bridge3.python = setting("python")?;
            let list = object.get("servers").and_then(Value::as_array).ok_or("bridge3: servers")?;
            for (index, item) in list.iter().enumerate() {
                let label = item
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| check_bridge3_id(id).is_ok())
                    .map_or_else(|| format!("Bridge-3-Server {}", index + 1), |id| format!("Bridge-3-Server {id}"));
                let server = Bridge3Server::from_value(item).and_then(|server| {
                    let mut next = config.clone();
                    next.bridge3.servers.push(server.clone());
                    next.check().map(|()| server)
                });
                match server {
                    Ok(server) => config.bridge3.servers.push(server),
                    Err(error) => warnings.push(format!("{label} übersprungen: {error}")),
                }
            }
        }
        Ok((config, warnings))
    }

    /// Every entry is good, and no two nodes share an ID or a port.
    pub fn check(&self) -> Result<(), String> {
        self.public.check()?;
        let mut ids = std::collections::BTreeSet::new();
        let mut ports: std::collections::BTreeSet<u16> = self.public.gate_port.into_iter().collect();
        let mut keys = std::collections::BTreeSet::new();
        for node in &self.nodes {
            node.check().map_err(|e| format!("Knoten {}: {e}", node.id))?;
            if !ids.insert(node.id.as_str()) {
                return Err(format!("Knoten {} doppelt", node.id));
            }
            for port in std::iter::once(node.listen_port).chain(node.lan_port).chain(node.reader_port) {
                if !ports.insert(port) {
                    return Err(format!("Port {port} doppelt vergeben"));
                }
            }
            if let Some(key) = &node.public_key {
                if !keys.insert(key.as_str()) {
                    return Err(format!("Netz-Schlüssel {key} doppelt"));
                }
            }
        }
        if self.bridge3.servers.len() > MAX_BRIDGE3 {
            return Err(format!("höchstens {MAX_BRIDGE3} Bridge-3-Server"));
        }
        let mut servers = std::collections::BTreeSet::new();
        for server in &self.bridge3.servers {
            server.check().map_err(|e| format!("Bridge-3-Server {}: {e}", server.id))?;
            if !servers.insert(server.id.as_str()) {
                return Err(format!("Bridge-3-Server {} doppelt", server.id));
            }
            if self.node(&server.node).is_none_or(|node| node.role != NodeRole::Owner) {
                return Err(format!("Bridge-3-Server {}: kein Owner-Knoten {}", server.id, server.node));
            }
            if !ports.insert(server.port) {
                return Err(format!("Port {} doppelt vergeben", server.port));
            }
        }
        Ok(())
    }

    /// The file content.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let nodes: Vec<Value> = self.nodes.iter().map(NodeEntry::to_value).collect();
        let mut text = serde_json::to_string_pretty(
            &json!({"v": 1, "nodes": nodes, "public": self.public.to_value(), "bridge3": self.bridge3.to_value()}),
        )
        .unwrap_or_default();
        text.push('\n');
        text.into_bytes()
    }

    /// Saves atomically - only a config that [`AppConfig::load`] takes as it is (every entry checked first, review
    /// 7); owner-only file on Unix.
    pub fn save(&self, app_dir: &Path) -> Result<(), String> {
        if self.nodes.len() > MAX_NODES {
            return Err(format!("mehr als {MAX_NODES} Knoten"));
        }
        self.check()?;
        write_private(&app_dir.join(CONFIG_FILE), &self.to_bytes())
    }

    /// The entry with this ID.
    #[must_use]
    pub fn node(&self, id: &str) -> Option<&NodeEntry> {
        self.nodes.iter().find(|node| node.id == id)
    }

    /// The entry with this ID, to change it.
    pub fn node_mut(&mut self, id: &str) -> Option<&mut NodeEntry> {
        self.nodes.iter_mut().find(|node| node.id == id)
    }

    /// Whether a port is used by a node other than `except`.
    #[must_use]
    pub fn port_taken(&self, port: u16, except: Option<&str>) -> bool {
        self.nodes
            .iter()
            .filter(|node| Some(node.id.as_str()) != except)
            .any(|node| node.listen_port == port || node.lan_port == Some(port) || node.reader_port == Some(port))
            || self.public.gate_port == Some(port)
            || self.bridge3.servers.iter().any(|server| server.port == port)
    }
}

/// Exactly these fields (no unknown, none missing).
fn exact(object: &Map<String, Value>, fields: &[&str]) -> Result<(), String> {
    if let Some(key) = object.keys().find(|key| !fields.contains(&key.as_str())) {
        return Err(format!("unbekanntes Feld {key:?}"));
    }
    if let Some(field) = fields.iter().find(|field| !object.contains_key(**field)) {
        return Err(format!("Feld {field:?} fehlt"));
    }
    Ok(())
}

fn port(value: Option<&Value>) -> Option<u16> {
    value.and_then(Value::as_u64).and_then(|port| u16::try_from(port).ok()).filter(|port| *port >= MIN_PORT)
}

/// A local node ID: exactly 8 lowercase hex characters.
pub fn check_id(id: &str) -> Result<(), String> {
    if id.len() == 8 && id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        Ok(())
    } else {
        Err("ungültige Knoten-Nummer".into())
    }
}

/// A name for people: 1-64 characters, no control characters, not only spaces.
pub fn check_name(name: &str, what: &str) -> Result<(), String> {
    let count = name.chars().count();
    if count == 0 || count > MAX_NAME_CHARS || name.trim().is_empty() || name.chars().any(char::is_control) {
        return Err(format!("{what}: 1 bis {MAX_NAME_CHARS} Zeichen, keine Steuerzeichen"));
    }
    Ok(())
}

/// Writes a file only the owner can read (Unix 0600), atomically: a temporary file next to it, then rename.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let dir = path.parent().ok_or("kein Ordner")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let file_name = path.file_name().and_then(|name| name.to_str()).ok_or("kein Dateiname")?;
    let temp = dir.join(format!(".{file_name}.tmp"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|e| format!("{}: {e}", temp.display()))?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| format!("{}: {e}", temp.display()))?;
    drop(file);
    std::fs::rename(&temp, path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, port: u16) -> NodeEntry {
        NodeEntry {
            id: id.into(),
            name: "laptop".into(),
            net_name: "Testnetz".into(),
            role: NodeRole::Member,
            listen_port: port,
            lan_port: Some(port + 1000),
            public_url: Some("https://pc.tail1234.ts.net:8443/k1".into()),
            autostart: true,
            join_link: None,
            probe: Some("web".into()),
            offer_gateway: true,
            peer_addresses: PeerAddresses::Tailnet,
            reader: ReaderAccess::Local,
            reader_port: None,
            public_key: None,
            public_web: true,
            created: 1,
        }
    }

    #[test]
    fn round_trip_and_save() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        assert_eq!(AppConfig::load(dir.path())?, Loaded::default(), "no file yet: empty");
        let config =
            AppConfig { nodes: vec![entry("0a1b2c3d", 7401), entry("ffffffff", 7402)], ..AppConfig::default() };
        config.save(dir.path())?;
        assert_eq!(AppConfig::load(dir.path())?, Loaded { config: config.clone(), warnings: Vec::new() });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join(CONFIG_FILE)).map_err(|e| e.to_string())?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner only");
        }
        assert_eq!(config.node("ffffffff").map(|node| node.listen_port), Some(7402));
        assert!(config.port_taken(8401, None) && !config.port_taken(8401, Some("0a1b2c3d")));
        assert_eq!(config.nodes[0].data_dir(Path::new("/app")), Path::new("/app").join(NODES_DIR).join("0a1b2c3d"));
        Ok(())
    }

    #[test]
    fn damaged_files_are_refused() {
        let good = AppConfig { nodes: vec![entry("0a1b2c3d", 7401)], ..AppConfig::default() }.to_bytes();
        assert!(AppConfig::parse(&good).is_ok());
        let text = String::from_utf8_lossy(&good).to_string();
        for (from, to) in [
            ("\"0a1b2c3d\"", "\"../../etc\""),
            ("\"0a1b2c3d\"", "\"0A1B2C3D\""),
            ("\"v\": 1", "\"v\": 2"),
            ("\"listen_port\": 7401", "\"listen_port\": 80"),
            ("\"listen_port\": 7401", "\"listen_port\": 70000"),
            ("\"listen_port\": 7401", "\"listen_port\": \"7401\""),
            ("\"role\": \"member\"", "\"role\": \"root\""),
            ("\"probe\": \"web\"", "\"probe\": \"gateway\""),
            ("\"public_url\": \"https://pc.tail1234.ts.net:8443/k1\"", "\"public_url\": \"ftp://x\""),
            ("\"name\": \"laptop\"", "\"name\": \"\""),
            ("\"autostart\": true", "\"autostart\": true, \"extra\": 1"),
        ] {
            let bad = text.replacen(from, to, 1);
            assert_ne!(bad, text, "{from}");
            assert!(AppConfig::parse(bad.as_bytes()).is_err(), "{to}");
        }
        assert!(AppConfig::parse(b"[]").is_err());
        assert!(AppConfig::parse(&vec![b' '; MAX_CONFIG_BYTES + 1]).is_err(), "too large");
        let doubled =
            AppConfig { nodes: vec![entry("0a1b2c3d", 7401), entry("0a1b2c3d", 7402)], ..AppConfig::default() };
        assert!(AppConfig::parse(&doubled.to_bytes()).is_err(), "same ID twice");
        let same_port =
            AppConfig { nodes: vec![entry("0a1b2c3d", 7401), entry("0a1b2c3e", 7401)], ..AppConfig::default() };
        assert!(same_port.check().is_err(), "same port twice");
    }

    /// Review 8, finding 6: a foreign network's name " " once went into the file unchecked, and the app refused that
    /// file at every start. Now nothing invalid is written, and a bad entry in a file is skipped (with a warning and a
    /// backup) instead of stopping the app.
    #[test]
    fn a_bad_entry_never_bricks_the_app() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let mut bad = entry("ffffffff", 7402);
        bad.net_name = " ".into();
        let config = AppConfig { nodes: vec![entry("0a1b2c3d", 7401), bad.clone()], ..AppConfig::default() };
        assert!(config.save(dir.path()).is_err(), "an invalid entry is never written");
        assert!(!dir.path().join(CONFIG_FILE).exists());
        // A file with such an entry (written by an older version): the good entry loads, the bad one is reported.
        let bytes = config.to_bytes();
        std::fs::write(dir.path().join(CONFIG_FILE), &bytes).map_err(|e| e.to_string())?;
        let loaded = AppConfig::load(dir.path())?;
        assert_eq!(loaded.config.nodes, vec![entry("0a1b2c3d", 7401)]);
        assert!(loaded.warnings.first().is_some_and(|warning| warning.starts_with("Knoten ffffffff übersprungen")));
        let backups: Vec<_> = std::fs::read_dir(dir.path().join(crate::BACKUP_DIR))
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read(backups[0].path()).map_err(|e| e.to_string())?, bytes, "the old file, unchanged");
        // Duplicates and garbage entries are skipped the same way; the next save writes a good file.
        let text = String::from_utf8_lossy(
            &AppConfig { nodes: vec![entry("0a1b2c3d", 7401)], ..AppConfig::default() }.to_bytes(),
        )
        .replacen("\"nodes\": [", "\"nodes\": [7, {\"id\": \"x\"},", 1)
        .replacen("}\n  ]", "},\n    {\"id\": \"0a1b2c3d\"}\n  ]", 1);
        let (lenient, warnings) = AppConfig::parse_lenient(text.as_bytes())?;
        assert_eq!((lenient.nodes.len(), warnings.len()), (1, 3), "{warnings:?}");
        lenient.save(dir.path())?;
        assert_eq!(AppConfig::load(dir.path())?.warnings, Vec::<String>::new());
        // Not a settings file at all: still refused (nothing is overwritten).
        std::fs::write(dir.path().join(CONFIG_FILE), b"{kaputt").map_err(|e| e.to_string())?;
        assert!(AppConfig::load(dir.path()).is_err());
        Ok(())
    }

    /// Follow-up of review 8: the address rule of a node is kept (`public`, `tailnet`, `any`); files from before it
    /// existed load with BridgeControll's default `tailnet`; anything else is a bad entry.
    #[test]
    fn peer_addresses_per_node() -> Result<(), String> {
        let mut public = entry("0a1b2c3d", 7401);
        public.peer_addresses = PeerAddresses::Public;
        let mut any = entry("0a1b2c3e", 7402);
        any.peer_addresses = PeerAddresses::Any;
        let config = AppConfig { nodes: vec![public, any, entry("0a1b2c3f", 7403)], ..AppConfig::default() };
        assert_eq!(AppConfig::parse(&config.to_bytes())?, config);
        let text = String::from_utf8_lossy(
            &AppConfig { nodes: vec![entry("0a1b2c3d", 7401)], ..AppConfig::default() }.to_bytes(),
        )
        .to_string();
        let old = text.replacen("      \"peer_addresses\": \"tailnet\",\n", "", 1);
        assert_ne!(old, text);
        assert_eq!(AppConfig::parse(old.as_bytes())?.nodes[0].peer_addresses, PeerAddresses::Tailnet, "old file");
        let bad = text.replacen("\"peer_addresses\": \"tailnet\"", "\"peer_addresses\": \"lan\"", 1);
        assert!(AppConfig::parse(bad.as_bytes()).is_err());
        Ok(())
    }

    /// The reader of a node (Bridge-Browser): kept as `off`, `local` or `lan`; files from before it existed load with
    /// `local`; anything else is a bad entry.
    #[test]
    fn reader_per_node() -> Result<(), String> {
        let mut off = entry("0a1b2c3d", 7401);
        off.reader = ReaderAccess::Off;
        let mut lan = entry("0a1b2c3e", 7402);
        lan.reader = ReaderAccess::Lan;
        let config = AppConfig { nodes: vec![off, lan, entry("0a1b2c3f", 7403)], ..AppConfig::default() };
        assert_eq!(AppConfig::parse(&config.to_bytes())?, config);
        let text = String::from_utf8_lossy(
            &AppConfig { nodes: vec![entry("0a1b2c3d", 7401)], ..AppConfig::default() }.to_bytes(),
        )
        .to_string();
        let old = text.replacen("      \"reader\": \"local\",\n", "", 1);
        assert_ne!(old, text);
        assert_eq!(AppConfig::parse(old.as_bytes())?.nodes[0].reader, ReaderAccess::Local, "old file");
        for bad in ["\"reader\": \"public\"", "\"reader\": true"] {
            let changed = text.replacen("\"reader\": \"local\"", bad, 1);
            assert!(AppConfig::parse(changed.as_bytes()).is_err(), "{bad}");
        }
        Ok(())
    }

    /// Review 9: `tailnet` as reader, and the loopback reader port - kept, checked against the other ports, missing in
    /// older files.
    #[test]
    fn reader_tailnet_and_reader_port() -> Result<(), String> {
        let mut node = entry("0a1b2c3d", 7401);
        node.reader = ReaderAccess::Tailnet;
        node.reader_port = Some(7601);
        let config = AppConfig { nodes: vec![node.clone(), entry("0a1b2c3e", 7402)], ..AppConfig::default() };
        assert_eq!(AppConfig::parse(&config.to_bytes())?, config);
        let text = String::from_utf8_lossy(&config.to_bytes()).to_string();
        let old = text.replacen("      \"reader_port\": 7601,\n", "", 1);
        assert_ne!(old, text);
        assert_eq!(AppConfig::parse(old.as_bytes())?.nodes[0].reader_port, None, "old file");
        for port in [7401, 1000] {
            let mut bad = node.clone();
            bad.reader_port = Some(port);
            assert!(bad.check().is_err(), "{port}");
        }
        let mut clash = entry("0a1b2c3e", 7402);
        clash.reader_port = Some(7601);
        assert!(
            AppConfig { nodes: vec![node, clash], ..AppConfig::default() }.check().is_err(),
            "the same reader port twice"
        );
        Ok(())
    }

    #[test]
    fn names_and_ids() {
        assert!(check_id("0123abcd").is_ok());
        for bad in ["", "0123abc", "0123abcde", "0123abcG", "../x/abc", "0123ABCD"] {
            assert!(check_id(bad).is_err(), "{bad}");
        }
        assert!(check_name("Testnetz", "x").is_ok());
        assert!(check_name("Spiele für alle", "x").is_ok());
        for bad in ["", "   ", "a\nb", &"x".repeat(65)] {
            assert!(check_name(bad, "x").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn public_settings() -> Result<(), String> {
        // Old files without `public` / `public_key`: not public, defaults.
        let old = AppConfig { nodes: vec![entry("0a1b2c3d", 7401)], ..AppConfig::default() };
        let text = String::from_utf8_lossy(&old.to_bytes()).to_string();
        let stripped = text.replace("\"public_key\": null,", "").replace("\"public_web\": true,", "");
        let without = serde_json::from_str::<Value>(&stripped).map_err(|e| e.to_string())?;
        let mut without = without.as_object().cloned().unwrap_or_default();
        without.remove("public");
        let parsed = AppConfig::parse(Value::Object(without).to_string().as_bytes())?;
        assert_eq!((parsed.public.clone(), parsed.nodes[0].public_key.clone()), (PublicConfig::default(), None));
        // A public node and the gate round-trip.
        let mut config = old.clone();
        config.public = PublicConfig {
            gate_port: Some(7390),
            funnel_port: 8443,
            funnel_on: true,
            host: Some("pc.tail1.ts.net".into()),
        };
        config.nodes[0].public_key = Some("testnetz".into());
        config.nodes[0].public_web = false;
        assert_eq!(AppConfig::parse(&config.to_bytes())?, config);
        assert_eq!(
            config.public.url_of("pc.tail1.ts.net", "testnetz"),
            "https://pc.tail1.ts.net:8443/bridge4/testnetz"
        );
        let standard = PublicConfig::default();
        assert_eq!(standard.url_of("pc.tail1.ts.net", "n"), "https://pc.tail1.ts.net/bridge4/n");
        assert_eq!(config.nodes[0].effective_reader(), ReaderAccess::Public);
        assert!(config.port_taken(7390, None), "the gate's port");
        // Refused: public without address, bad keys, the same key twice, the gate on a node's port, odd Funnel ports
        // and names, the reader `public` chosen by hand.
        let mut bad = config.clone();
        bad.nodes[0].public_url = None;
        assert!(bad.check().is_err());
        for key in ["Testnetz", "bridge4", "bridge3", "", "a/b"] {
            let mut bad = config.clone();
            bad.nodes[0].public_key = Some(key.into());
            assert!(bad.check().is_err(), "{key:?}");
        }
        let mut twice = config.clone();
        let mut second = entry("0a1b2c3e", 7402);
        second.public_key = Some("testnetz".into());
        twice.nodes.push(second);
        assert!(twice.check().is_err());
        let mut clash = config.clone();
        clash.public.gate_port = Some(7401);
        assert!(clash.check().is_err());
        for port in [80, 444, 9000] {
            let mut bad = config.clone();
            bad.public.funnel_port = port;
            assert!(bad.check().is_err(), "{port}");
        }
        for host in ["", "PC.tail.ts.net", "a..b", "-a.b", "a b.c", "a_b.c"] {
            assert!(check_host(host).is_err(), "{host:?}");
        }
        let mut chosen = config.clone();
        chosen.nodes[0].reader = ReaderAccess::Public;
        assert!(chosen.check().is_err());
        Ok(())
    }
}
