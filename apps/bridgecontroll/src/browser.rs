//! The Bridge-Browser (docs/08 §12, ADR 0017 Nachtrag 2): open `shop.meinnetz` from this PC - always through one of
//! the user's **own** nodes, which checks everything itself (Zero Trust, docs/08 §8). User-facing texts are German.
//!
//! - **Which node**: an address `name.short` goes to the network whose short name is `short` (from the manifest the
//!   poller replayed from the node's own log - the same as `GET /v4/names/info`). If several networks of this PC share
//!   the short name, the answer lists them with network name and ID fingerprint to choose from. A node can open apps
//!   only if its reader is on, it runs and holds its log. A node with a public address trusts the local proxy
//!   (Tailscale Funnel) on its main port and can not tell this PC's browser from a caller on the Internet there - the
//!   browser uses its **loopback reader port** instead (`--reader-listen`, review 9; [`reader_origin`]).
//! - **Resolve / search**: `POST /v4/names/resolve` and `/v4/names/search` at that node's reader address. The answer
//!   is checked strictly like any foreign data (fields, types, bounds, the network ID) and reduced to what the screen
//!   shows; warnings come back as German texts. The app opens at `http://127.0.0.1:<reader port>` + `open` - only if
//!   `open` is exactly `/app/<target>/` of an app name whose app manifest names the same owner.
//! - **Safe mode** (default on): the node's safe search (no 18+, no owners below level 2); a resolved 18+ name is not
//!   opened, a name of an owner below level 2 needs a click on "Trotzdem öffnen". 18+ opens only in networks that allow
//!   it, with safe mode off and an explicit confirmation (`gate`).
//! - **Melden** ([`report`]): signed by the member key of this PC in that network (`owner-key.json` in the node's
//!   folder, made on first use) with a session at a gateway - `POST /v4/report` (docs/08 §6). The text is sealed to the
//!   first log operator of the network (review 9): the gateway can not read it. The owner node admits its member key
//!   itself (admin key); a member node can report once its member key is a member (open networks: it joins on the
//!   first report). Otherwise the answer names the operator's Meldeweg.
//! - The page frames the app in `<iframe sandbox="allow-scripts allow-forms allow-popups">` (never `allow-same-origin`);
//!   the CSP of the page allows exactly the origins of [`frame_origins`].

use std::collections::BTreeMap;
use std::time::Duration;

use bridge_core::json::parse_strict;
use bridge_core::{Address, Envelope, Id, Identity, JoinLink, Kind, SignedRequest};
use bridge_net::names::{check_name, check_word, split_address};
use bridge_net::statements::check_text;
use bridge_net::{AdultPolicy, Category, JoinMode, LabelTarget, NameKind, NetState};
use bridge_node::ReaderAccess;
use bridge_sdk::{Client, SdkError};
use bridge_transport::HttpClient;
use rand_core::OsRng;
use serde_json::{Map, Value, json};

use crate::config::{NodeEntry, NodeRole};
use crate::ops::entry_of;
use crate::status::NodeCache;
use crate::supervisor::RunState;
use crate::{App, now_ms};

/// Longest address typed into the address bar (`name.short`: 40 + 1 + 24).
pub const MAX_ADDRESS_CHARS: usize = 80;
/// Longest search query (docs/08 §7).
pub const MAX_QUERY_CHARS: usize = 64;
/// Search results asked for.
const SEARCH_RESULTS: u64 = 20;
/// Largest answer of a node's name endpoints.
const MAX_ANSWER_BYTES: usize = 512 * 1024;
/// Longest report text (docs/08 §6).
pub const MAX_REPORT_TEXT_CHARS: usize = 500;
/// Reasons of a report (wire names, docs/08 §6).
pub const REASONS: [&str; 5] = ["illegal", "phishing", "adult_unlabeled", "spam", "other"];
/// How long a report waits for a fresh membership to arrive at the gateway.
const MEMBER_WAIT: Duration = Duration::from_secs(20);
/// Gateways tried for a report.
const MAX_GATEWAYS: usize = 4;
/// Timeout of one request to a node.
const TIMEOUT: Duration = Duration::from_secs(20);

/// German name of a report reason.
#[must_use]
pub fn reason_text(reason: &str) -> &'static str {
    match reason {
        "illegal" => "Illegale Inhalte",
        "phishing" => "Phishing oder Betrug",
        "adult_unlabeled" => "18+ ohne Kennzeichnung",
        "spam" => "Spam",
        "other" => "Sonstiges",
        _ => "Unbekannter Grund",
    }
}

/// The German text of a warning code of `POST /v4/names/resolve` (docs/08 §7) - unknown codes get a general text.
#[must_use]
pub fn warning_text(code: &str) -> &'static str {
    match code {
        "owner_level_low" => {
            "Der Inhaber ist neu in diesem Netz (Stufe unter 2) - kein Admin hat ihn versiegelt. Gib hier keine \
             Passwörter oder Zahlungsdaten ein."
        }
        "no_contact" => {
            "Dieses Netz hat keinen Meldeweg: Sein Betreiber hat nicht angegeben, wie man ihm Missbrauch meldet."
        }
        "adult" => "Inhalte ab 18 Jahren.",
        "label_override" => {
            "Die Admins des Netzes haben die Kategorie geändert - die Selbstauskunft des Inhabers stimmte nicht."
        }
        "app_unknown" => "Die App ist gerade nicht erreichbar: Dein Knoten hat keine gültige Version gefunden.",
        "owner_mismatch" => {
            "Die App gehört nicht dem Inhaber des Namens. BridgeControll öffnet sie nicht - das kann Betrug sein."
        }
        "card_unverified" => {
            "Dieser Knoten hat kein Siegel: Seine Karte (Name, Adressen) ist nur seine eigene Angabe, kein Admin hat sie \
             geprüft."
        }
        _ => "Dein Knoten meldet eine Warnung, die diese Version von BridgeControll nicht kennt.",
    }
}

/// German text of a trust level (docs/02 §6).
#[must_use]
pub fn level_text(level: u8) -> &'static str {
    match level {
        0 => "Stufe 0 · neu",
        1 => "Stufe 1 · geprüft",
        2 => "Stufe 2 · versiegelt",
        _ => "Stufe 3 · vertraut",
    }
}

/// The ID of a network as people compare it: the first 12 and the last 4 characters in groups of four.
#[must_use]
pub fn fingerprint(id: &Id) -> String {
    let text = id.as_str();
    let part = |range: std::ops::Range<usize>| text.get(range).unwrap_or_default().to_owned();
    format!("{} {} {} … {}", part(0..4), part(4..8), part(8..12), part(text.len().saturating_sub(4)..text.len()))
}

/// Where the node's reader serves this PC's browser: its port on 127.0.0.1 - for a node with a public address its
/// loopback reader port (`--reader-listen`, review 9), never the main port that trusts the proxy. `None`: reader off,
/// or a public node without a reader port.
#[must_use]
pub fn reader_origin(entry: &NodeEntry) -> Option<String> {
    if entry.reader == ReaderAccess::Off {
        return None;
    }
    match (&entry.public_url, entry.reader_port) {
        (None, _) => Some(entry.local_url()),
        (Some(_), Some(port)) => Some(format!("http://127.0.0.1:{port}")),
        (Some(_), None) => None,
    }
}

/// The origin the page frames for a node (its reader on 127.0.0.1), if the node can serve the browser at all.
#[must_use]
pub fn frame_origin(entry: &NodeEntry) -> Option<String> {
    reader_origin(entry)
}

/// The origins the page may frame: exactly those of [`frame_origin`] (no wildcard, no other host or port).
pub async fn frame_origins(app: &App) -> Vec<String> {
    app.config.lock().await.nodes.iter().filter_map(frame_origin).collect()
}

/// Why a node can not open apps for the browser now (`None`: it can).
#[must_use]
pub fn reader_blocker(app: &App, entry: &NodeEntry, cache: &NodeCache) -> Option<&'static str> {
    if entry.reader == ReaderAccess::Off {
        return Some("Der Leser dieses Knotens ist aus (Einstellungen → Leser für den Bridge-Browser).");
    }
    if reader_origin(entry).is_none() {
        return Some(
            "Dieser Knoten hat eine öffentliche Adresse, aber (noch) keinen eigenen Leser-Zugang für diesen PC - speichere \
             seine Einstellungen einmal und starte ihn neu, dann bekommt er einen.",
        );
    }
    if app.supervisor.status(&entry.id).state != RunState::Running || !cache.reachable {
        return Some("Der Knoten läuft nicht - starte ihn auf der Startseite.");
    }
    if cache.net.is_none() {
        return Some("Der Knoten lädt noch das Log seines Netzes.");
    }
    None
}

/// A node of this PC in a network, as the browser sees it.
struct Local {
    entry: NodeEntry,
    net: Id,
    net_name: String,
    short: Option<String>,
    contact: Option<String>,
    adult: AdultPolicy,
    blocker: Option<&'static str>,
}

impl Local {
    fn net_value(&self) -> Value {
        json!({
            "id": self.net.as_str(),
            "name": self.net_name,
            "fingerprint": fingerprint(&self.net),
            "short": self.short,
            "contact": self.contact,
            "adult": self.adult.as_str(),
        })
    }
}

/// All nodes of this PC that hold a network.
async fn locals(app: &App) -> Vec<Local> {
    let nodes: Vec<NodeEntry> = app.config.lock().await.nodes.clone();
    let mut out = Vec::with_capacity(nodes.len());
    for entry in nodes {
        let cache = app.poller.cache(&entry.id);
        let cache = cache.read().await;
        let Some(view) = &cache.net else { continue };
        let manifest = view.state.manifest();
        out.push(Local {
            net: view.net.clone(),
            net_name: manifest.name.clone(),
            short: manifest.short.clone(),
            contact: manifest.contact.clone(),
            adult: manifest.adult_policy(),
            blocker: reader_blocker(app, &entry, &cache),
            entry,
        });
    }
    out
}

/// `GET /api/browser`: the networks of this PC with the node the browser uses for each (or why none can).
pub async fn nodes(app: &App) -> Value {
    let locals = locals(app).await;
    let mut nets: BTreeMap<String, Value> = BTreeMap::new();
    for local in &locals {
        let usable = local.blocker.is_none();
        let row = nets.entry(local.net.as_str().to_owned()).or_insert_with(
            || json!({"net": local.net_value(), "node": Value::Null, "name": Value::Null, "why": local.blocker}),
        );
        // Prefer a usable node; among usable ones the owner node.
        let better =
            usable && (row["node"].is_null() || (local.entry.role == NodeRole::Owner && row["role"] != json!("owner")));
        if better {
            row["node"] = json!(local.entry.id);
            row["name"] = json!(local.entry.name);
            row["role"] = json!(local.entry.role.as_str());
            row["why"] = Value::Null;
        }
    }
    json!({"nets": nets.into_values().collect::<Vec<_>>(), "frames": frame_origins(app).await})
}

/// The text field `name` of a body (empty if missing).
fn text<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or_default()
}

/// `safe` of a body (default on).
fn safe_of(body: &Map<String, Value>) -> Result<bool, String> {
    match body.get("safe") {
        None | Some(Value::Null) => Ok(true),
        Some(value) => value.as_bool().ok_or_else(|| "Sicherer Modus: true oder false".to_owned()),
    }
}

/// The local node the browser uses in the network of `node` (a node ID of this PC).
async fn local_of(app: &App, node: &str) -> Result<Local, String> {
    crate::config::check_id(node)?;
    locals(app)
        .await
        .into_iter()
        .find(|local| local.entry.id == node)
        .ok_or_else(|| "Dieser Knoten ist (noch) in keinem Netz.".to_owned())
}

/// What the address bar asked for: one network (the local node to use) or a choice between networks.
enum Pick {
    One(Box<Local>),
    Choose(Vec<Value>),
}

/// Picks the network for an address (see module docs). `node`: the network chosen on the screen (or in the choice).
async fn pick(app: &App, short: Option<&str>, node: Option<&str>) -> Result<Pick, String> {
    let locals = locals(app).await;
    let chosen = node.and_then(|node| locals.iter().find(|local| local.entry.id == node)).map(|l| l.net.clone());
    // The networks in question, each with its best node (usable first, then the chosen one, then the owner node).
    let mut nets: BTreeMap<Id, Local> = BTreeMap::new();
    for local in locals {
        let fits = match short {
            Some(short) => local.short.as_deref() == Some(short),
            None => chosen.as_ref().is_none_or(|net| net == &local.net),
        };
        if !fits {
            continue;
        }
        let rank = |l: &Local| {
            (
                u8::from(l.blocker.is_none()),
                u8::from(Some(l.entry.id.as_str()) == node),
                u8::from(l.entry.role == NodeRole::Owner),
            )
        };
        let replace = nets.get(&local.net).is_none_or(|known| rank(&local) > rank(known));
        if replace {
            nets.insert(local.net.clone(), local);
        }
    }
    if let Some(net) = chosen.filter(|net| nets.contains_key(net)) {
        nets.retain(|id, _| id == &net);
    }
    match nets.len() {
        0 => Err(match short {
            Some(short) => format!(
                "Kein Netz auf diesem PC hat den Kurznamen „{short}“. Adressen gelten nur in Netzen, denen dieser PC \
                 beigetreten ist."
            ),
            None => "Dieser PC ist noch in keinem Netz - tritt erst einem bei.".to_owned(),
        }),
        1 => nets.into_values().next().map(|local| Pick::One(Box::new(local))).ok_or_else(|| "kein Netz".to_owned()),
        _ => Ok(Pick::Choose(
            nets.values()
                .map(|local| {
                    json!({"node": local.entry.id, "net": local.net_value(), "usable": local.blocker.is_none()})
                })
                .collect(),
        )),
    }
}

/// A POST to a node's name endpoint at its reader address (loopback, no proxy - so the node fetches app versions for
/// this PC): the parsed answer, or a German error.
async fn ask(local: &Local, path: &str, body: &Value) -> Result<Value, String> {
    let origin = reader_origin(&local.entry).unwrap_or_else(|| local.entry.local_url());
    let http = HttpClient::new(&origin, TIMEOUT).map_err(|e| e.to_string())?;
    let send = || async {
        http.post(path, None, body.to_string().into_bytes())
            .await
            .map_err(|_| "Dein Knoten antwortet nicht - läuft er noch?".to_owned())
    };
    let mut answer = send().await?;
    if answer.status == 429 {
        // Everything of this PC reaches the node from 127.0.0.1 (one limit per address): once more, a second later.
        tokio::time::sleep(Duration::from_secs(1)).await;
        answer = send().await?;
    }
    match answer.status {
        200 => {
            parse_strict(&answer.body, MAX_ANSWER_BYTES).map_err(|_| "Dein Knoten antwortet unverständlich.".to_owned())
        }
        404 => Err(format!(
            "Gibt es in „{}“ nicht - oder der Name ist abgelaufen, gesperrt oder nicht für dieses Netz.",
            local.net_name
        )),
        429 => Err("Zu viele Anfragen in kurzer Zeit - bitte kurz warten.".into()),
        503 => Err("Dein Knoten lädt noch das Log seines Netzes - gleich noch einmal versuchen.".into()),
        400 => Err("Eingabe ungültig.".into()),
        status => Err(format!("Dein Knoten lehnt ab ({status}).")),
    }
}

/// A name as a node answered it, checked strictly (see module docs).
#[derive(Debug, Clone, PartialEq)]
pub struct NameView {
    /// The name.
    pub name: String,
    /// What it points to.
    pub kind: NameKind,
    /// Target ID.
    pub target: Id,
    /// Owner ID.
    pub owner: Id,
    /// Description (0-200 characters).
    pub description: String,
    /// Tags (0-8).
    pub tags: Vec<String>,
    /// The category that counts.
    pub category: Category,
    /// The owner's own category.
    pub declared: Category,
    /// Expires (ms).
    pub expires: i64,
    /// The owner's level (0-3).
    pub owner_level: u8,
    /// The network has a Meldeweg.
    pub contact: bool,
    /// Contains a reserved word.
    pub reserved: bool,
    /// Label of the name.
    pub label_name: Option<Category>,
    /// Label of the target.
    pub label_target: Option<Category>,
    /// The network's 18+ policy.
    pub adult_policy: AdultPolicy,
    /// Warning codes (known ones as they are, others as `unknown`; at most 16).
    pub warnings: Vec<String>,
    /// The app (app names the node knows a version of).
    pub app: Option<AppView>,
    /// Path of the app at the node: exactly `/app/<target>/`, else `None`.
    pub open: Option<String>,
}

/// The app part of a resolved name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppView {
    /// App name.
    pub name: String,
    /// App description.
    pub description: String,
    /// Version.
    pub version: u64,
    /// The app manifest names the owner of the name.
    pub owner_matches: bool,
    /// Hosts known.
    pub hosts: usize,
}

const KNOWN_WARNINGS: [&str; 7] =
    ["owner_level_low", "no_contact", "adult", "label_override", "app_unknown", "owner_mismatch", "card_unverified"];

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, String> {
    object.get(name).ok_or_else(|| format!("Antwort des Knotens ohne {name}"))
}

fn text_field(object: &Map<String, Value>, name: &str, max: usize, newline: bool) -> Result<String, String> {
    let value = field(object, name)?.as_str().ok_or_else(|| format!("Antwort des Knotens: {name} ist kein Text"))?;
    check_text(value, 0, max, newline, name).map_err(|_| format!("Antwort des Knotens: {name} ungültig"))?;
    Ok(value.to_owned())
}

fn id_field(object: &Map<String, Value>, name: &str) -> Result<Id, String> {
    Id::parse(field(object, name)?.as_str().unwrap_or_default()).map_err(|_| format!("Antwort des Knotens: {name}"))
}

fn category_field(value: &Value, name: &str) -> Result<Option<Category>, String> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => Category::parse(text).map(Some).ok_or_else(|| format!("Antwort des Knotens: {name}")),
        _ => Err(format!("Antwort des Knotens: {name}")),
    }
}

impl NameView {
    /// Checks a name of a node's answer for the network `net` (fail closed: anything off is an error).
    pub fn from_node(value: &Value, net: &Id) -> Result<Self, String> {
        let object = value.as_object().ok_or("Antwort des Knotens ist kein Objekt")?;
        let name = text_field(object, "name", 40, false)?;
        check_name(&name).map_err(|_| "Antwort des Knotens: name".to_owned())?;
        if id_field(object, "net")? != *net {
            return Err("Antwort des Knotens gehört zu einem anderen Netz.".into());
        }
        let kind =
            NameKind::parse(field(object, "kind")?.as_str().unwrap_or_default()).ok_or("Antwort des Knotens: kind")?;
        let target = id_field(object, "target")?;
        let owner = id_field(object, "owner")?;
        let description = text_field(object, "description", 200, false)?;
        let tags_value = field(object, "tags")?.as_array().ok_or("Antwort des Knotens: tags")?;
        if tags_value.len() > bridge_net::names::MAX_TAGS {
            return Err("Antwort des Knotens: zu viele tags".into());
        }
        let mut tags = Vec::with_capacity(tags_value.len());
        for tag in tags_value {
            let tag = tag.as_str().unwrap_or_default();
            check_word(tag, 2, bridge_net::names::MAX_TAG_CHARS, "tag").map_err(|_| "Antwort des Knotens: tag")?;
            tags.push(tag.to_owned());
        }
        let category =
            category_field(field(object, "category")?, "category")?.ok_or("Antwort des Knotens: category")?;
        let declared =
            category_field(field(object, "declared")?, "declared")?.ok_or("Antwort des Knotens: declared")?;
        let expires = field(object, "expires")?.as_i64().ok_or("Antwort des Knotens: expires")?;
        let safety = field(object, "safety")?.as_object().ok_or("Antwort des Knotens: safety")?;
        let owner_level = field(safety, "owner_level")?
            .as_u64()
            .and_then(|level| u8::try_from(level).ok())
            .filter(|level| *level <= 3)
            .ok_or("Antwort des Knotens: owner_level")?;
        let flag = |name: &str| field(safety, name).and_then(|v| v.as_bool().ok_or(format!("Antwort: {name}")));
        let labels = field(safety, "labels")?.as_object().ok_or("Antwort des Knotens: labels")?;
        let label_name = category_field(labels.get("name").unwrap_or(&Value::Null), "labels.name")?;
        let label_target = category_field(labels.get("target").unwrap_or(&Value::Null), "labels.target")?;
        let adult_policy = AdultPolicy::parse(field(safety, "adult_policy")?.as_str().unwrap_or_default())
            .ok_or("Antwort des Knotens: adult_policy")?;
        let list = field(safety, "warnings")?.as_array().ok_or("Antwort des Knotens: warnings")?;
        let mut warnings: Vec<String> = Vec::new();
        for code in list.iter().take(16) {
            let code = code.as_str().unwrap_or_default();
            let code = if KNOWN_WARNINGS.contains(&code) { code } else { "unknown" };
            if !warnings.iter().any(|known| known == code) {
                warnings.push(code.to_owned());
            }
        }
        let app = match object.get("app") {
            None | Some(Value::Null) => None,
            Some(Value::Object(app)) => Some(AppView {
                name: text_field(app, "name", bridge_core::app::MAX_APP_NAME_CHARS, false)?,
                description: text_field(app, "description", 500, true)?,
                version: field(app, "version")?.as_u64().ok_or("Antwort des Knotens: app.version")?,
                owner_matches: field(app, "owner_matches")?.as_bool().ok_or("Antwort des Knotens: owner_matches")?,
                hosts: app.get("hosts").and_then(Value::as_array).map_or(0, Vec::len),
            }),
            Some(_) => return Err("Antwort des Knotens: app".into()),
        };
        // `open` counts only as exactly the path of this app, for an app name whose app names the same owner.
        let expected = format!("/app/{target}/");
        let open = match object.get("open") {
            Some(Value::String(path))
                if path == &expected && kind == NameKind::App && app.as_ref().is_some_and(|app| app.owner_matches) =>
            {
                Some(expected)
            }
            _ => None,
        };
        Ok(Self {
            name,
            kind,
            target,
            owner,
            description,
            tags,
            category,
            declared,
            expires,
            owner_level,
            contact: flag("contact")?,
            reserved: flag("reserved")?,
            label_name,
            label_target,
            adult_policy,
            warnings,
            app,
            open,
        })
    }

    fn warnings_value(&self) -> Vec<Value> {
        self.warnings.iter().map(|code| json!({"code": code, "text": warning_text(code)})).collect()
    }

    fn address(&self, short: Option<&str>) -> String {
        short.map_or_else(|| self.name.clone(), |short| format!("{}.{short}", self.name))
    }

    /// A row of the result list.
    fn summary(&self, local: &Local) -> Value {
        json!({
            "name": self.name,
            "address": self.address(local.short.as_deref()),
            "kind": self.kind.as_str(),
            "description": self.description,
            "tags": self.tags,
            "category": self.category.as_str(),
            "owner_level": self.owner_level,
            "owner_level_text": level_text(self.owner_level),
            "warnings": self.warnings_value(),
        })
    }
}

/// What the screen shows for a resolved name: the safety panel, the gate before opening, the URL of the app at the
/// own node's reader (or why it is not opened).
fn resolved_value(view: &NameView, local: &Local, safe: bool) -> Value {
    let mut blocked: Option<&str> = None;
    let mut gate: Option<&str> = None;
    if view.kind != NameKind::App {
        blocked = Some(match view.kind {
            NameKind::Node => {
                "Dieser Name steht für einen Knoten des Netzes, nicht für eine App - hier gibt es nichts zu öffnen."
            }
            _ => "Dieser Name steht für ein Mitglied des Netzes, nicht für eine App - hier gibt es nichts zu öffnen.",
        });
    } else if view.warnings.iter().any(|code| code == "owner_mismatch") {
        blocked = Some(warning_text("owner_mismatch"));
    } else if view.open.is_none() {
        blocked = Some(warning_text("app_unknown"));
    }
    if view.category == Category::Adult {
        if local.adult != AdultPolicy::Allowed || view.adult_policy != AdultPolicy::Allowed {
            blocked = Some("Inhalte ab 18 sind in diesem Netz nicht erlaubt - BridgeControll öffnet sie nicht.");
        } else if safe {
            blocked = Some(
                "Sicherer Modus ist an: Inhalte ab 18 werden nicht geöffnet. Schalte ihn aus, wenn du volljährig bist und \
                 die Seite sehen willst.",
            );
        } else if blocked.is_none() {
            gate = Some("adult");
        }
    } else if safe && view.owner_level < 2 && blocked.is_none() {
        gate = Some("caution");
    }
    let url = match (&view.open, blocked, reader_origin(&local.entry)) {
        (Some(open), None, Some(origin)) if local.blocker.is_none() => Some(format!("{origin}{open}")),
        _ => None,
    };
    if url.is_none() && blocked.is_none() {
        blocked = local.blocker;
    }
    let status = if blocked.is_some() {
        "blocked"
    } else if view.warnings.is_empty() && view.owner_level >= 2 {
        "ok"
    } else {
        "warn"
    };
    let label = |category: Option<Category>| category.map(Category::as_str);
    json!({
        "name": view.name,
        "address": view.address(local.short.as_deref()),
        "node": local.entry.id,
        "net": local.net_value(),
        "kind": view.kind.as_str(),
        "target": view.target.as_str(),
        "owner": view.owner.as_str(),
        "description": view.description,
        "tags": view.tags,
        "category": view.category.as_str(),
        "declared": view.declared.as_str(),
        "expires": view.expires,
        "safety": {
            "status": status,
            "owner_level": view.owner_level,
            "owner_level_text": level_text(view.owner_level),
            "contact": view.contact,
            "reserved": view.reserved,
            "labels": {"name": label(view.label_name), "target": label(view.label_target)},
            "adult_policy": view.adult_policy.as_str(),
            "warnings": view.warnings_value(),
        },
        "app": view.app.as_ref().map(|app| json!({
            "name": app.name, "description": app.description, "version": app.version, "hosts": app.hosts,
        })),
        "url": url,
        "gate": gate,
        "blocked": blocked,
    })
}

/// `POST /api/browser/resolve` `{"address","node"?,"safe"?}` (see module docs).
pub async fn resolve(app: &App, body: &Map<String, Value>) -> Result<Value, String> {
    let address = text(body, "address").trim().to_ascii_lowercase();
    if address.is_empty() || address.chars().count() > MAX_ADDRESS_CHARS {
        return Err("Adresse eingeben, z. B. shop.meinnetz".into());
    }
    let safe = safe_of(body)?;
    let node = body.get("node").and_then(Value::as_str);
    if let Some(node) = node {
        crate::config::check_id(node)?;
    }
    let (name, short) = split_address(&address);
    if check_name(name).is_err() || short.is_some_and(|short| bridge_net::names::check_short(short).is_err()) {
        return Err(
            "Keine gültige Adresse: Namen haben 2-40 Zeichen a-z, 0-9 und -, dazu der Kurzname des Netzes - z. B. \
             shop.meinnetz"
                .into(),
        );
    }
    let local = match pick(app, short, node).await? {
        Pick::One(local) => local,
        Pick::Choose(nets) => {
            return Ok(json!({"choose": nets, "address": address}));
        }
    };
    // A node whose reader can not serve this PC still resolves (the safety panel shows why nothing opens).
    let answer = ask(&local, "/v4/names/resolve", &json!({"name": address})).await?;
    let view = NameView::from_node(&answer, &local.net)?;
    Ok(resolved_value(&view, &local, safe))
}

/// `POST /api/browser/search` `{"node","q","safe"?}`: the names of the node's network that match (docs/08 §7).
pub async fn search(app: &App, body: &Map<String, Value>) -> Result<Value, String> {
    let local = local_of(app, text(body, "node")).await?;
    let query = text(body, "q").trim().to_lowercase();
    if query.is_empty() || query.chars().count() > MAX_QUERY_CHARS || query.chars().any(char::is_control) {
        return Err("Suche: 1-64 Zeichen".into());
    }
    let safe = safe_of(body)?;
    let answer = ask(&local, "/v4/names/search", &json!({"q": query, "safe": safe, "max": SEARCH_RESULTS})).await?;
    let list = answer.get("results").and_then(Value::as_array).ok_or("Antwort des Knotens ohne results")?;
    let mut results = Vec::new();
    for item in list.iter().take(usize::try_from(SEARCH_RESULTS).unwrap_or(20)) {
        // One bad entry does not hide the others (it is left out).
        if let Ok(view) = NameView::from_node(item, &local.net) {
            results.push(view.summary(&local));
        }
    }
    let more = answer.get("more").and_then(Value::as_bool).unwrap_or(false);
    Ok(json!({"results": results, "more": more, "net": local.net_value(), "node": local.entry.id, "safe": safe}))
}

/// A report checked like the node checks it (docs/08 §6): target, reason, text.
pub fn report_body(body: &Map<String, Value>) -> Result<Value, String> {
    let target = LabelTarget::parse(text(body, "target").trim())
        .map_err(|_| "Ziel der Meldung: ein Name (z. B. shop) oder eine ID".to_owned())?;
    let reason = text(body, "reason");
    if !REASONS.contains(&reason) {
        return Err("Bitte einen Grund wählen.".into());
    }
    let message = text(body, "text").replace("\r\n", "\n");
    check_text(&message, 0, MAX_REPORT_TEXT_CHARS, true, "text")
        .map_err(|_| "Text: höchstens 500 Zeichen, keine Steuerzeichen".to_owned())?;
    Ok(json!({"target": target.as_text(), "reason": reason, "text": message}))
}

/// The report as the node takes it (docs/08 §6, review 9): the text sealed to the first log operator of the network
/// (its card from the log), so the gateway that takes it and hands it on can not read it; no text: `sealed: null`.
fn sealed_report(report: &Value, member: &Identity, state: &NetState, net: &Id) -> Result<Value, String> {
    let text = report.get("text").and_then(Value::as_str).unwrap_or_default();
    let sealed = if text.is_empty() {
        Value::Null
    } else {
        let operator = state.log_operators().first().ok_or("Das Netz hat keinen Log-Führer.")?;
        let card = state.card_of(operator).ok_or("Der Log-Führer des Netzes hat keine Karte im Log.")?;
        let address = Address { net, to: card, kind: Kind::Msg, iat: now_ms(), ttl: 7 * 24 * 3600 };
        let envelope = Envelope::seal(member, &address, text.as_bytes(), &mut OsRng).map_err(|e| e.to_string())?;
        parse_strict(&envelope.to_bytes().map_err(|e| e.to_string())?, 64 * 1024).map_err(|e| e.to_string())?
    };
    Ok(json!({"target": report["target"], "reason": report["reason"], "sealed": sealed}))
}

/// Gateways to report at: this node and the other nodes of this PC in the network first (their local address),
/// then the gateways of the log (their sealed addresses).
async fn gateways(app: &App, state: &NetState, net: &Id) -> Vec<(Id, String)> {
    let now = now_ms();
    let gateways: Vec<Id> = state.gateways(now).into_iter().map(|(id, _)| id).collect();
    let mut out: Vec<(Id, String)> = Vec::new();
    for local in locals(app).await.iter().filter(|local| &local.net == net) {
        let cache = app.poller.cache(&local.entry.id);
        let cache = cache.read().await;
        if let Some(info) = &cache.info {
            if gateways.contains(info.card.id()) && cache.reachable {
                out.push((info.card.id().clone(), local.entry.local_url()));
            }
        }
    }
    for id in &gateways {
        if out.iter().any(|(known, _)| known == id) {
            continue;
        }
        if let Some(url) = state.card_of(id).and_then(|card| card.urls().first().cloned()) {
            out.push((id.clone(), url));
        }
    }
    out.truncate(MAX_GATEWAYS);
    out
}

/// The member key of a node folder (`owner-key.json`), loaded off the async threads.
async fn member_key(dir: &std::path::Path) -> Result<bridge_core::Identity, String> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || bridge_node_cli::apps::owner(&dir)).await.map_err(|e| e.to_string())?
}

/// Logs the member key in at `url` (the gateway `id`), waiting a little for a membership that is on its way.
async fn login(dir: &std::path::Path, id: &Id, url: &str) -> Result<Client, String> {
    let deadline = tokio::time::Instant::now() + MEMBER_WAIT;
    loop {
        let mut client = Client::new(member_key(dir).await?, url, Some(id.clone())).map_err(|e| e.to_string())?;
        match client.connect().await {
            Ok(()) => return Ok(client),
            Err(SdkError::Node { code, .. }) if code == "NOT_MEMBER" && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

/// German text of a refused report.
fn refused(status: u16, answer: &[u8]) -> String {
    let value = parse_strict(answer, 64 * 1024).unwrap_or(Value::Null);
    let code = value.get("error").and_then(Value::as_str).unwrap_or_default();
    match (status, code) {
        (429, "RATE_LIMITED") => {
            "Du hast heute schon 10 Meldungen abgegeben - mehr geht erst morgen wieder (Schutz vor Massen-Meldungen)."
                .into()
        }
        (429, _) => "Der Knoten nimmt gerade keine Meldungen an - bitte später noch einmal.".into(),
        (400, _) => "Die Meldung ist ungültig.".into(),
        (403, "NOT_MEMBER") => "Der Mitglieds-Schlüssel dieses PCs ist kein Mitglied des Netzes.".into(),
        (403, "BANNED") => "Der Mitglieds-Schlüssel dieses PCs ist in diesem Netz gesperrt.".into(),
        (status, code) => format!("Meldung abgelehnt ({status} {code})."),
    }
}

/// `POST /api/nodes/<id>/report` `{"target","reason","text"}`: a report about a name or ID of the node's network,
/// signed by this PC's member key there, handed in at a gateway (see module docs). Returns the report's ID.
pub async fn report(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let report = report_body(body)?;
    let entry = entry_of(app, id).await?;
    let (net, net_name, contact, mode, state) = {
        let cache = app.poller.cache(id);
        let cache = cache.read().await;
        let view = cache.net.as_ref().ok_or("Der Knoten lädt noch das Log seines Netzes.")?;
        let manifest = view.state.manifest();
        (view.net.clone(), manifest.name.clone(), manifest.contact.clone(), manifest.join.mode, view.state.clone())
    };
    let dir = app.node_dir(&entry);
    let member_identity = member_key(&dir).await?;
    let member = member_identity.id().clone();
    let report = sealed_report(&report, &member_identity, &state, &net)?;
    let direct = contact
        .as_deref()
        .map_or_else(|| " Dieses Netz hat leider keinen Meldeweg.".to_owned(), |c| format!(" Meldeweg: {c}"));
    let gateways = gateways(app, &state, &net).await;
    let mut joined: Option<Client> = None;
    if !state.is_member(&member, now_ms()) {
        if entry.role == NodeRole::Owner {
            let url = entry.local_url();
            crate::ops::patient(|| bridge_node_cli::apps::admit_owner(&dir, Some(&url))).await?;
        } else if mode == JoinMode::Open {
            let (gateway, url) = gateways.first().cloned().ok_or("Kein Empfänger des Netzes erreichbar.")?;
            let link = JoinLink { net: net.clone(), gateway: url, code: None, node: Some(gateway), tls: None };
            let client = Client::join(member_key(&dir).await?, &link.to_link())
                .await
                .map_err(|e| format!("Der Mitglieds-Schlüssel dieses PCs konnte nicht beitreten ({e}).{direct}"))?;
            joined = Some(client);
        } else {
            return Err(format!(
                "Melden geht über ein Mitglied des Netzes - dieser PC ist in „{net_name}“ noch keins (dafür bräuchte er eine \
                 eigene Einladung). Wende dich direkt an den Betreiber.{direct}"
            ));
        }
    }
    let mut last = format!("Kein Empfänger des Netzes erreichbar.{direct}");
    for (gateway, url) in &gateways {
        let client = match joined.take() {
            Some(client) if client.node_card().is_some_and(|card| card.id() == gateway) => client,
            _ => match login(&dir, gateway, url).await {
                Ok(client) => client,
                Err(error) => {
                    last = format!("Anmeldung beim Empfänger fehlgeschlagen: {error}");
                    continue;
                }
            },
        };
        let Some(token) = client.session_token() else { continue };
        let request = SignedRequest::sign(client.identity(), gateway, "report", report.clone(), now_ms(), &mut OsRng)
            .and_then(|request| request.to_bytes())
            .map_err(|e| e.to_string())?;
        let http = HttpClient::new(url, TIMEOUT).map_err(|e| e.to_string())?;
        let answer = match http.post("/v4/report", Some(token), request).await {
            Ok(answer) => answer,
            Err(_) => {
                last = format!("Empfänger {} antwortet nicht.", short_id(gateway));
                continue;
            }
        };
        if answer.status != 200 {
            return Err(refused(answer.status, &answer.body));
        }
        let value = parse_strict(&answer.body, 64 * 1024).map_err(|_| "Antwort des Empfängers unverständlich")?;
        let report_id = value.get("id").and_then(Value::as_str).filter(|id| id.len() == 43).unwrap_or_default();
        return Ok(json!({
            "ok": true,
            "id": report_id,
            "duplicate": value.get("duplicate").and_then(Value::as_bool).unwrap_or(false),
            "net": net_name,
            "contact": contact,
        }));
    }
    Err(last)
}

fn short_id(id: &Id) -> String {
    id.as_str().get(..8).unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> Id {
        Id::of_sign_key(&[1; 32])
    }

    fn answer(app: &Id, owner: &Id) -> Value {
        json!({
            "name": "shop", "address": "shop.testnetz", "net": net().as_str(), "kind": "app",
            "target": app.as_str(), "owner": owner.as_str(), "description": "Mein <b>Laden</b>",
            "tags": ["laden", "kleidung"], "category": "general", "declared": "general", "expires": 5,
            "statement": "x", "card": null,
            "safety": {"owner_level": 2, "contact": true, "reserved": false, "labels": {"name": null, "target": null},
                       "adult_policy": "forbidden", "warnings": []},
            "app": {"name": "Laden", "description": "", "version": 1, "entry": "index.html", "owner_matches": true,
                    "hosts": [{"id": owner.as_str(), "urls": []}]},
            "open": format!("/app/{app}/"),
        })
    }

    #[test]
    fn a_good_answer_is_taken() -> Result<(), String> {
        let (app, owner) = (Id::of_sign_key(&[2; 32]), Id::of_sign_key(&[3; 32]));
        let view = NameView::from_node(&answer(&app, &owner), &net())?;
        assert_eq!(view.open, Some(format!("/app/{app}/")));
        assert_eq!(view.description, "Mein <b>Laden</b>", "kept as text - the page shows it with textContent");
        assert_eq!((view.owner_level, view.app.as_ref().map(|a| a.hosts)), (2, Some(1)));
        Ok(())
    }

    /// Zero Trust also towards the own node: a manipulated answer never opens anything else, and never another
    /// network's name.
    #[test]
    fn a_manipulated_answer_opens_nothing_else() -> Result<(), String> {
        let (app, owner) = (Id::of_sign_key(&[2; 32]), Id::of_sign_key(&[3; 32]));
        for open in [
            json!("//evil.example/app/"),
            json!("javascript:alert(1)"),
            json!(format!("/app/{owner}/")),
            json!(format!("/app/{app}/../../v4/info")),
            json!(format!("http://127.0.0.1:1/app/{app}/")),
            json!(7),
        ] {
            let mut value = answer(&app, &owner);
            value["open"] = open.clone();
            assert_eq!(NameView::from_node(&value, &net())?.open, None, "{open}");
        }
        // The app manifest names another owner: no open, whatever the node says.
        let mut value = answer(&app, &owner);
        value["app"]["owner_matches"] = json!(false);
        assert_eq!(NameView::from_node(&value, &net())?.open, None);
        // Not an app name: nothing to open.
        let mut value = answer(&app, &owner);
        value["kind"] = json!("member");
        assert_eq!(NameView::from_node(&value, &net())?.open, None);
        // Broken or foreign answers are refused as a whole.
        for (pointer, bad) in [
            ("/net", json!(owner.as_str())),
            ("/name", json!("Shop!")),
            ("/kind", json!("bank")),
            ("/target", json!("x")),
            ("/description", json!("x".repeat(201))),
            ("/description", json!("a\u{1b}[2J")),
            ("/tags", json!(["UPPER"])),
            ("/tags", json!(["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"])),
            ("/category", json!("porn")),
            ("/safety/owner_level", json!(9)),
            ("/safety/adult_policy", json!("maybe")),
            ("/safety", json!(null)),
        ] {
            let mut value = answer(&app, &owner);
            if let Some(slot) = value.pointer_mut(pointer) {
                *slot = bad.clone();
            }
            assert!(NameView::from_node(&value, &net()).is_err(), "{pointer} = {bad}");
        }
        // Unknown warning codes are kept as "unknown" (with a general German text), at most once.
        let mut value = answer(&app, &owner);
        value["safety"]["warnings"] = json!(["adult", "<script>", "x", "no_contact"]);
        let view = NameView::from_node(&value, &net())?;
        assert_eq!(view.warnings, vec!["adult", "unknown", "no_contact"]);
        Ok(())
    }

    #[test]
    fn texts_and_reports() {
        for code in KNOWN_WARNINGS {
            assert!(!warning_text(code).is_empty() && warning_text(code) != warning_text("neu"), "{code}");
        }
        assert_eq!(level_text(2), "Stufe 2 · versiegelt");
        assert_eq!(fingerprint(&net()).chars().filter(|c| *c == ' ').count(), 4);
        let body = |value: Value| value.as_object().cloned().unwrap_or_default();
        let ok = report_body(&body(json!({"target": "shop", "reason": "phishing", "text": "Zeile 1\r\nZeile 2"})));
        assert_eq!(ok, Ok(json!({"target": "shop", "reason": "phishing", "text": "Zeile 1\nZeile 2"})));
        for bad in [
            json!({"target": "shop.testnetz", "reason": "spam", "text": ""}),
            json!({"target": "", "reason": "spam", "text": ""}),
            json!({"target": "shop", "reason": "langweilig", "text": ""}),
            json!({"target": "shop", "reason": "spam", "text": "x".repeat(501)}),
            json!({"target": "shop", "reason": "spam", "text": "bell\u{7}"}),
        ] {
            assert!(report_body(&body(bad.clone())).is_err(), "{bad}");
        }
        assert!(REASONS.iter().all(|reason| reason_text(reason) != reason_text("x")));
    }

    /// Review 9, finding 6: the text of a report is sealed to the log operator - only it can read it, not the gateway.
    #[test]
    fn report_texts_are_sealed_to_the_log_operator() -> Result<(), String> {
        let e = |error: bridge_core::CoreError| error.to_string();
        let master = Identity::from_secret_bytes(&[1; 32], &[2; 32]);
        let operator = Identity::from_secret_bytes(&[3; 32], &[4; 32]);
        let manifest = bridge_net::Manifest::template(
            JoinMode::Open,
            "Netz",
            master.key_card(bridge_core::Role::Net, None, 0).map_err(e)?,
            operator.id(),
            "http://127.0.0.1:7401",
        )
        .map_err(|e| e.to_string())?;
        let now = now_ms();
        let genesis =
            bridge_net::Body::sign(&manifest, master.id(), now, now + 1_000_000, &master).map_err(|e| e.to_string())?;
        let mut state = NetState::genesis(master.id(), genesis.canonical_bytes()).map_err(|e| e.to_string())?;
        let member = Identity::from_secret_bytes(&[5; 32], &[6; 32]);
        let plain = json!({"target": "shop", "reason": "phishing", "text": "Meine Bank-Daten"});
        // Without a card of the log operator in the log nothing goes out (never in plain).
        assert!(sealed_report(&plain, &member, &state, master.id()).is_err());
        let seal = bridge_net::Seal {
            subject: operator.id().clone(),
            level: 3,
            services: bridge_net::Services::of(&[bridge_net::Service::Log]),
            card: Some(operator.key_card(bridge_core::Role::Node, None, now).map_err(e)?),
        };
        let statement =
            bridge_net::Body::sign(&seal, master.id(), now + 1, now + 1_000_000, &master).map_err(|e| e.to_string())?;
        assert_eq!(state.apply(statement.canonical_bytes()), bridge_net::Applied::Accepted);
        let body = sealed_report(&plain, &member, &state, master.id())?;
        assert!(!body.to_string().contains("Bank-Daten"), "no plain text in the report");
        let envelope = Envelope::from_value(body["sealed"].clone()).map_err(e)?;
        let opened = envelope.open(&operator, &member.key_card(bridge_core::Role::Client, None, 0).map_err(e)?);
        assert_eq!(opened.map_err(e)?, b"Meine Bank-Daten");
        let none = json!({"target": "shop", "reason": "spam", "text": ""});
        assert_eq!(sealed_report(&none, &member, &state, master.id())?["sealed"], Value::Null);
        Ok(())
    }
}
