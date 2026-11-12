//! The owner dashboard's tools against abuse (docs/08 §12, ADR 0018): names of the network (list, register, revoke),
//! the reports of the members (list, mark done, quick actions) and the network's Meldeweg. Everything goes through
//! the library functions of `bridge-node name …` / `net …` ([`bridge_node_cli::names`], [`AdminClient`]) with the
//! admin key of the owner node's folder - nothing here signs differently than the command line. User-facing texts
//! are German.
//!
//! - **Names** for an app of the owner folder (`apps/<id>.json`), for the owner node, or for the operator (the member
//!   key `owner-key.json` of the folder). App and operator names belong to that member key; it needs level 2 for them
//!   to show in the safe search (docs/08 §7), so BridgeControll seals it with level 2 first if it has less (a log
//!   entry like every seal). Names of the owner node belong to the node (level 3).
//! - **Reports**: `POST /v4/admin/reports` / `report` at the owner node (the log operator holds all of them), every
//!   row checked strictly. A report triggers nothing by itself; the quick actions are the known tools, each after a
//!   confirmation in the page: label 18+ (the name - and, for an app name, the app ID, so hosts stop serving it in a
//!   network that forbids 18+), ban the app (365 days), revoke the name. "App sperren" only for an ID that is a known
//!   app (the target of an app name in the log, or an app key of the owner folder) - never for the network, a log
//!   operator, witness, watcher, gateway or admin; the confirmation names the kind of the ID (review 9).
//! - The text of a report is sealed to the log operator (docs/08 §6): the owner node opens it; a text sealed to another
//!   log operator shows as such.
//! - **Meldeweg**: older networks have none (warning `no_contact` everywhere); the admin key (right `rules`) adds it with
//!   the next manifest version.

use bridge_core::Id;
use bridge_core::encoding::b64;
use bridge_net::names::check_name;
use bridge_net::statements::check_text;
use bridge_net::{Category, LabelTarget, NameKind, NetState, RevokeTarget, Seal, Services};
use bridge_node::admin::{AdminClient, YEAR_MS};
use bridge_node_cli::names::{self, Target};
use serde_json::{Map, Value, json};

use crate::browser::{REASONS, reason_text};
use crate::config::NodeEntry;
use crate::ops::{admin_client, entry_of, patient, query_value};
use crate::{App, now_ms};

/// Most names listed in the dashboard.
pub const MAX_NAMES_SHOWN: usize = 200;
/// Most app keys of the owner folder offered for names.
const MAX_APP_KEYS: usize = 100;
/// Level the operator's member key needs for its names (safe search: owners from level 2, docs/08 §7).
const OPERATOR_LEVEL: u8 = 2;
/// How long a fresh seal may take until the log operator counts it for a name.
const LEVEL_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

fn text<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or_default()
}

/// A reason for a log entry (0-200 characters, no control characters).
fn reason_of(body: &Map<String, Value>) -> Result<String, String> {
    let reason = text(body, "reason").trim().to_owned();
    check_text(&reason, 0, 200, false, "reason").map_err(|_| "Grund: höchstens 200 Zeichen".to_owned())?;
    Ok(reason)
}

/// The ID of the operator's member key in an owner folder - only if it exists already (a view creates nothing).
#[must_use]
pub fn operator_id(dir: &std::path::Path) -> Option<Id> {
    let path = dir.join(bridge_node_cli::apps::OWNER_KEY_FILE);
    path.is_file().then(|| bridge_node::keyfile::load_or_create_at(&path).ok()).flatten().map(|key| key.id().clone())
}

/// The names of the network for the dashboard (at most [`MAX_NAMES_SHOWN`], by name), with whether they resolve now
/// and why not.
#[must_use]
pub fn names_view(state: &NetState, now: i64) -> Value {
    let short = state.manifest().short.clone();
    let mut list = Vec::new();
    let mut after: Option<String> = None;
    'pages: loop {
        let page = state.names_after(after.as_deref(), 100);
        let Some(last) = page.last() else { break };
        after = Some(last.name.name.clone());
        for info in page {
            if list.len() >= MAX_NAMES_SHOWN {
                break 'pages;
            }
            let body = &info.name;
            let (resolves, category, level, why) = match state.resolve_name(&body.name, now) {
                Ok(resolved) => (true, resolved.category, Some(resolved.owner_level), None),
                Err(error) => (false, body.category, state.level(&body.owner, now), Some(names::refusal(&error))),
            };
            list.push(json!({
                "name": body.name,
                "address": short.as_ref().map_or_else(|| body.name.clone(), |short| format!("{}.{short}", body.name)),
                "kind": body.kind.as_str(),
                "target": body.target.as_str(),
                "owner": body.owner.as_str(),
                "description": body.description,
                "tags": body.tags,
                "category": category.as_str(),
                "resolves": resolves,
                "why": why,
                "owner_level": level,
                "expires": info.exp,
                "statement": b64(&info.hash),
            }));
        }
    }
    let total = state.name_count();
    json!({"total": total, "list": list, "more": total > MAX_NAMES_SHOWN})
}

/// The app keys of the owner folder: `[{id, name}]`.
pub async fn app_keys(dir: &std::path::Path) -> Vec<Value> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || bridge_node_cli::apps::list(&dir, MAX_APP_KEYS))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
        .into_iter()
        .map(|(id, name)| json!({"id": id.as_str(), "name": name}))
        .collect()
}

/// The owner node of `id` with its admin client.
async fn owner_of(app: &App, id: &str) -> Result<(NodeEntry, AdminClient), String> {
    let entry = entry_of(app, id).await?;
    let admin = admin_client(app, &entry)?;
    Ok((entry, admin))
}

/// The network state the dashboard holds for the owner node.
async fn state_of(app: &App, id: &str) -> Result<NetState, String> {
    let cache = app.poller.cache(id);
    let cache = cache.read().await;
    cache.net.as_ref().map(|view| view.state.clone()).ok_or_else(|| "Der Owner-Knoten läuft noch nicht.".to_owned())
}

/// Makes sure the operator's member key is a member with at least [`OPERATOR_LEVEL`]: admitted by the admin key if
/// needed, then sealed (level 2, no services) if its level is lower. Returns its ID.
pub(crate) async fn operator_ready(app: &App, entry: &NodeEntry, admin: &AdminClient) -> Result<Id, String> {
    let dir = app.node_dir(entry);
    let url = entry.local_url();
    let member = patient(|| bridge_node_cli::apps::admit_owner(&dir, Some(&url))).await?;
    let (_, state) = patient(|| admin.load_state()).await?;
    if state.level(&member, now_ms()).unwrap_or(0) < OPERATOR_LEVEL {
        let seal = Seal { subject: member.clone(), level: OPERATOR_LEVEL, services: Services::NONE, card: None };
        patient(|| async { admin.submit(&admin.sign(&seal, YEAR_MS)?).await }).await?;
    }
    Ok(member)
}

/// `POST /api/nodes/<id>/name-register` `{"name","target":"app|node|member","app"?,"description","tags":[…],
/// "category","days"?}`: registers a name like `bridge-node name register` (every rule checked first, a refusal
/// names its reason).
pub async fn register_name(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let (entry, admin) = owner_of(app, id).await?;
    let name = text(body, "name").trim().to_ascii_lowercase();
    check_name(&name)
        .map_err(|_| "Name: 2-40 Zeichen a-z, 0-9 und -, nicht mit - beginnend oder endend, kein --".to_owned())?;
    let app_id = match text(body, "target") {
        "app" => Some(Id::parse(text(body, "app")).map_err(|_| "Bitte eine App wählen.".to_owned())?),
        "node" | "member" => None,
        _ => return Err("Ziel: eine App, der Owner-Knoten oder du als Betreiber".into()),
    };
    let node = text(body, "target") == "node";
    let description = text(body, "description").trim().to_owned();
    check_text(&description, 0, 200, false, "description")
        .map_err(|_| "Beschreibung: höchstens 200 Zeichen".to_owned())?;
    let tags: Vec<String> = match body.get("tags") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(list)) if list.len() <= bridge_net::names::MAX_TAGS => list
            .iter()
            .map(|tag| tag.as_str().unwrap_or_default().trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect(),
        Some(_) => return Err("Schlagworte: höchstens 8".into()),
    };
    for tag in &tags {
        bridge_net::names::check_word(tag, 2, bridge_net::names::MAX_TAG_CHARS, "tag")
            .map_err(|_| format!("Schlagwort „{tag}“: 2-24 Zeichen a-z, 0-9 und -"))?;
    }
    let category = Category::parse(match text(body, "category") {
        "" => "general",
        other => other,
    })
    .ok_or("Kategorie: general oder adult")?;
    let days = match body.get("days") {
        None | Some(Value::Null) => 365,
        Some(value) => {
            value.as_u64().and_then(|d| u32::try_from(d).ok()).filter(|d| (1..=365).contains(d)).ok_or("Tage: 1-365")?
        }
    };
    if let Some(app_id) = &app_id {
        let dir = app.node_dir(&entry);
        let keys = app_keys(&dir).await;
        if !keys.iter().any(|key| key["id"] == json!(app_id.as_str())) {
            return Err("Diese App hat ihren Schlüssel nicht im Ordner des Owner-Knotens.".into());
        }
    }
    if !node {
        operator_ready(app, &entry, &admin).await?;
    }
    let dir = app.node_dir(&entry);
    let url = entry.local_url();
    let deadline = tokio::time::Instant::now() + LEVEL_WAIT;
    loop {
        let target = match (&app_id, node) {
            (Some(app_id), _) => Target::App(app_id.clone()),
            (None, true) => Target::Node,
            (None, false) => Target::Member,
        };
        let request =
            names::Request { name: &name, target, description: &description, tags: tags.clone(), category, days };
        match names::register(&dir, request, Some(&url)).await {
            Ok(done) => {
                return Ok(json!({"ok": true, "address": done.address, "index": done.index, "statement": done.hash}));
            }
            // A seal made just now may not count at the log operator yet; the node may be busy (RATE_LIMITED).
            Err(error)
                if (error.contains("Stufe des Inhabers reicht nicht") || error.contains("RATE_LIMITED"))
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// `POST /api/nodes/<id>/name-revoke` `{"name","reason"?}`: like `bridge-node name revoke` (as owner, else as admin).
pub async fn revoke_name(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let (entry, _) = owner_of(app, id).await?;
    let name = text(body, "name").trim().to_owned();
    check_name(&name).map_err(|_| "kein Name".to_owned())?;
    let reason = reason_of(body)?;
    let (dir, url) = (app.node_dir(&entry), entry.local_url());
    let (who, index) = patient(|| names::revoke(&dir, &name, &reason, Some(&url))).await?;
    Ok(json!({"ok": true, "who": who, "index": index}))
}

/// A report ID: Base64url of a SHA-256 (43 characters).
fn report_id_ok(id: &str) -> bool {
    id.len() == 43 && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// What an ID is in the network (review 9): the roles that must never be banned as an app first, then a known app
/// (the target of an app name in the log, or an app key of the owner folder), a node, a member - else unknown.
#[must_use]
pub fn id_kind(state: &NetState, id: &Id, app_keys: &[Id], now: i64) -> &'static str {
    if id == state.net() {
        "net"
    } else if state.log_operators().contains(id) {
        "operator"
    } else if state.witnesses().contains(id) {
        "witness"
    } else if state.is_watcher(id, now) {
        "watcher"
    } else if state.gateways(now).iter().any(|(gateway, _)| gateway == id) {
        "gateway"
    } else if !state.admin_rights(id, now).is_empty() {
        "admin"
    } else if state.is_app_target(id) || app_keys.contains(id) {
        "app"
    } else if state.card_of(id).is_some_and(|card| card.role() == bridge_core::Role::Node) {
        "node"
    } else if state.level(id, now).is_some() {
        "member"
    } else {
        "unknown"
    }
}

/// The German name of an [`id_kind`].
#[must_use]
pub fn id_kind_text(kind: &str) -> &'static str {
    match kind {
        "net" => "der Schlüssel des Netzes",
        "operator" => "ein Log-Führer des Netzes",
        "witness" => "ein Zeuge des Netzes",
        "watcher" => "ein Wächter des Netzes",
        "gateway" => "ein Empfänger (Gateway) des Netzes",
        "admin" => "ein Admin des Netzes",
        "app" => "eine App",
        "node" => "ein Knoten",
        "member" => "ein Mitglied",
        _ => "eine unbekannte ID",
    }
}

/// What the quick actions can do with a report's target. "App sperren" only for a known app (see [`id_kind`]).
fn target_view(state: &NetState, target: &LabelTarget, app_keys: &[Id], now: i64) -> Value {
    match target {
        LabelTarget::Name(name) => match state.name_info(name) {
            Some(info) => {
                let app = (info.name.kind == NameKind::App).then(|| info.name.target.as_str().to_owned());
                let id_kind =
                    (info.name.kind == NameKind::App).then(|| id_kind(state, &info.name.target, app_keys, now));
                json!({
                    "kind": "name",
                    "name_kind": info.name.kind.as_str(),
                    "app": app,
                    "id_kind": id_kind,
                    "id_kind_text": id_kind.map(id_kind_text),
                    "resolves": state.resolve_name(name, now).is_ok(),
                    "actions": {"label": true, "ban_app": id_kind == Some("app"), "revoke_name": true},
                })
            }
            None => json!({"kind": "name", "name_kind": Value::Null, "app": Value::Null, "id_kind": Value::Null,
                           "id_kind_text": Value::Null, "resolves": false,
                           "actions": {"label": true, "ban_app": false, "revoke_name": false}}),
        },
        LabelTarget::Id(id) => {
            let banned = state.is_banned(id, now);
            let kind = id_kind(state, id, app_keys, now);
            let app = (kind == "app").then(|| id.as_str());
            json!({"kind": "id", "name_kind": Value::Null, "app": app, "id": id.as_str(), "id_kind": kind,
                   "id_kind_text": id_kind_text(kind), "resolves": Value::Null, "banned": banned,
                   "actions": {"label": true, "ban_app": kind == "app" && !banned, "revoke_name": false}})
        }
    }
}

/// One row of `POST /v4/admin/reports`, checked strictly (a bad row is left out). `text: null`: sealed to another log
/// operator (`sealed_to`) - only that node can read it.
fn report_row(row: &Value, state: &NetState, app_keys: &[Id], now: i64) -> Option<Value> {
    let object = row.as_object()?;
    let field = |name: &str| object.get(name).and_then(Value::as_str);
    let id = field("id").filter(|id| report_id_ok(id))?;
    let reporter = Id::parse(field("reporter")?).ok()?;
    let target = LabelTarget::parse(field("target")?).ok()?;
    let reason = field("reason").filter(|reason| REASONS.contains(reason))?;
    let message = match object.get("text") {
        Some(Value::Null) => None,
        Some(Value::String(text)) => {
            check_text(text, 0, crate::browser::MAX_REPORT_TEXT_CHARS, true, "text").ok()?;
            Some(text.as_str())
        }
        _ => return None,
    };
    let sealed_to = match object.get("sealed_to") {
        None | Some(Value::Null) => None,
        Some(value) => Some(Id::parse(value.as_str()?).ok()?),
    };
    let received = object.get("received").and_then(Value::as_i64)?;
    let status = field("status").filter(|status| *status == "open" || *status == "done")?;
    let via = Id::parse(field("via")?).ok()?;
    let handled_by = field("handled_by").and_then(|id| Id::parse(id).ok());
    let handled_at = object.get("handled_at").and_then(Value::as_i64);
    Some(json!({
        "id": id,
        "reporter": reporter.as_str(),
        "target": target.as_text(),
        "reason": reason,
        "reason_text": reason_text(reason),
        "text": message,
        "sealed_to": sealed_to.as_ref().map(Id::as_str),
        "received": received,
        "status": status,
        "via": via.as_str(),
        "handled_by": handled_by.as_ref().map(Id::as_str),
        "handled_at": handled_at,
        "about": target_view(state, &target, app_keys, now),
    }))
}

/// The IDs of the app keys of the owner folder.
async fn app_key_ids(dir: &std::path::Path) -> Vec<Id> {
    app_keys(dir).await.iter().filter_map(|key| key["id"].as_str().and_then(|id| Id::parse(id).ok())).collect()
}

/// `GET /api/nodes/<id>/reports?status=open|done|all`: the newest 100 reports at the owner node.
pub async fn reports(app: &App, id: &str, query: &str) -> Result<Value, String> {
    let status = match query_value(query, "status").as_str() {
        "" | "open" => "open",
        "done" => "done",
        "all" => "all",
        _ => return Err("status: open, done oder all".into()),
    };
    let (entry, admin) = owner_of(app, id).await?;
    let state = state_of(app, id).await?;
    let rows = patient(|| admin.reports(status, 100)).await?;
    let now = now_ms();
    let keys = app_key_ids(&app.node_dir(&entry)).await;
    let list: Vec<Value> = rows.iter().take(100).filter_map(|row| report_row(row, &state, &keys, now)).collect();
    Ok(json!({"status": status, "reports": list}))
}

/// `POST /api/nodes/<id>/report-status` `{"id","status":"done|open"}`.
pub async fn report_status(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let report = text(body, "id");
    if !report_id_ok(report) {
        return Err("keine Meldungs-ID".into());
    }
    let status = match text(body, "status") {
        status @ ("open" | "done") => status,
        _ => return Err("Status: done oder open".into()),
    };
    let (_, admin) = owner_of(app, id).await?;
    patient(|| admin.report_status(report, status)).await?;
    Ok(json!({"ok": true}))
}

/// `POST /api/nodes/<id>/report-action` `{"target","action":"label_adult|ban_app|revoke_name","reason"?,"report"?}`:
/// a quick action on a report's target (see module docs); with `report`, that report is marked done afterwards.
pub async fn report_action(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let target =
        LabelTarget::parse(text(body, "target").trim()).map_err(|_| "Ziel: ein Name oder eine ID".to_owned())?;
    let reason = match reason_of(body)? {
        reason if reason.is_empty() => "Nach einer Meldung (BridgeControll)".to_owned(),
        reason => reason,
    };
    let report = body.get("report").and_then(Value::as_str);
    if report.is_some_and(|report| !report_id_ok(report)) {
        return Err("keine Meldungs-ID".into());
    }
    let (entry, admin) = owner_of(app, id).await?;
    // The owner node's log as it is now (the dashboard's view may be a round behind).
    let (_, state) = patient(|| admin.load_state()).await?;
    let info = match &target {
        LabelTarget::Name(name) => state.name_info(name),
        LabelTarget::Id(_) => None,
    };
    let done = match text(body, "action") {
        "label_adult" => {
            // The name and - for an app name - the app itself: in a network that forbids 18+ hosts stop serving it.
            let mut targets = vec![target.clone()];
            if let Some(info) = info.as_ref().filter(|info| info.name.kind == NameKind::App) {
                targets.push(LabelTarget::Id(info.name.target.clone()));
            }
            let mut labeled = 0;
            for target in targets {
                patient(|| admin.label(target.clone(), Category::Adult, 365, &reason)).await?;
                labeled += 1;
            }
            json!({"ok": true, "labeled": labeled})
        }
        "ban_app" => {
            let subject = match (&target, &info) {
                (LabelTarget::Id(id), _) => id.clone(),
                (LabelTarget::Name(_), Some(info)) if info.name.kind == NameKind::App => info.name.target.clone(),
                _ => return Err("Das Ziel ist keine App (oder der Name gilt nicht mehr).".into()),
            };
            // Only a known app - never a node, member or role of the network that happens to be reported (review 9).
            let keys = app_key_ids(&app.node_dir(&entry)).await;
            let kind = id_kind(&state, &subject, &keys, now_ms());
            if kind != "app" {
                return Err(format!(
                    "„App sperren“ gibt es nur für Apps - diese ID ist {}. Andere Identitäten sperrst du bewusst unter \
                     „Mitglieder“.",
                    id_kind_text(kind)
                ));
            }
            patient(|| crate::ops::ban(app, &entry.id, subject.as_str(), 365, &reason)).await?
        }
        "revoke_name" => {
            let info = info.ok_or("Das Ziel ist kein Name, der gerade gilt.")?;
            let (_, submitted) = patient(|| admin.revoke(RevokeTarget::Statement(info.hash), &reason)).await?;
            json!({"ok": true, "index": submitted.index})
        }
        _ => return Err("Aktion: label_adult, ban_app oder revoke_name".into()),
    };
    if let Some(report) = report {
        patient(|| admin.report_status(report, "done")).await?;
    }
    Ok(done)
}

/// `POST /api/nodes/<id>/contact` `{"contact"}`: adds (or changes) the network's Meldeweg with the next manifest version,
/// signed by the admin key (right `rules`).
pub async fn set_contact(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let contact = text(body, "contact").trim().to_owned();
    let count = contact.chars().count();
    if count == 0 || count > bridge_net::names::MAX_CONTACT_CHARS || contact.chars().any(char::is_control) {
        return Err("Meldeweg: 1-200 Zeichen, z. B. eine E-Mail-Adresse".into());
    }
    let (_, admin) = owner_of(app, id).await?;
    let (_, state) = patient(|| admin.load_state()).await?;
    let mut manifest = state.manifest().next_version();
    manifest.contact = Some(contact);
    let statement = admin.sign(&manifest, YEAR_MS)?;
    state
        .validate_candidate(&statement, now_ms())
        .map_err(|e| format!("Der Log-Führer würde das neue Manifest ablehnen: {e}"))?;
    let submitted = patient(|| admin.submit(&statement)).await?;
    Ok(json!({"ok": true, "version": manifest.version, "index": submitted.index}))
}

#[cfg(test)]
mod tests {
    use bridge_core::{Identity, Role};
    use bridge_net::{Body as _, JoinMode, Manifest};

    use super::*;

    /// A network state with only its genesis manifest.
    fn state() -> Result<NetState, String> {
        let master = Identity::generate(&mut rand_core::OsRng);
        let node = Identity::generate(&mut rand_core::OsRng);
        let card = master.key_card(Role::Net, None, 0).map_err(|e| e.to_string())?;
        let mut manifest = Manifest::template(JoinMode::Open, "Netz", card, node.id(), "http://127.0.0.1:7400")
            .map_err(|e| e.to_string())?;
        manifest.short = Some("netz".into());
        let now = now_ms();
        let statement = manifest.sign(master.id(), now, now + YEAR_MS, &master).map_err(|e| e.to_string())?;
        NetState::genesis(master.id(), statement.canonical_bytes()).map_err(|e| e.to_string())
    }

    fn row() -> Value {
        let id = Id::of_sign_key(&[4; 32]);
        json!({"id": "A".repeat(43), "reporter": id.as_str(), "target": "shop", "reason": "phishing",
               "text": "Sieht aus wie\neine Bank", "received": 5, "status": "open", "via": id.as_str(),
               "handled_by": null, "handled_at": null})
    }

    /// Rows of the owner node are checked strictly; a bad row is left out, never shown half.
    #[test]
    fn report_rows_are_checked() -> Result<(), String> {
        let state = state()?;
        let good = report_row(&row(), &state, &[], 0).ok_or("good row refused")?;
        assert_eq!(good["reason_text"], "Phishing oder Betrug");
        assert_eq!(good["about"]["kind"], "name");
        assert_eq!(good["about"]["actions"]["revoke_name"], false, "no such name in the network");
        let app = Id::of_sign_key(&[5; 32]);
        let mut by_id = row();
        by_id["target"] = json!(app.as_str());
        let by_id = report_row(&by_id, &state, std::slice::from_ref(&app), 0).ok_or("id row refused")?;
        assert_eq!(
            (by_id["about"]["kind"].clone(), by_id["about"]["actions"]["ban_app"].clone()),
            (json!("id"), json!(true))
        );
        // A text sealed to another log operator: no text, but where it is.
        let mut sealed = row();
        sealed["text"] = Value::Null;
        sealed["sealed_to"] = json!(app.as_str());
        let sealed = report_row(&sealed, &state, &[], 0).ok_or("sealed row refused")?;
        assert_eq!((sealed["text"].clone(), sealed["sealed_to"].clone()), (Value::Null, json!(app.as_str())));
        for (field, bad) in [
            ("id", json!("kurz")),
            ("id", json!(format!("{}\"", "A".repeat(42)))),
            ("reporter", json!("x")),
            ("target", json!("<script>")),
            ("reason", json!("boring")),
            ("text", json!("x".repeat(501))),
            ("text", json!("\u{1b}[31m")),
            ("status", json!("deleted")),
            ("received", json!("gestern")),
            ("text", json!(5)),
            ("sealed_to", json!("x")),
        ] {
            let mut value = row();
            value[field] = bad.clone();
            assert!(report_row(&value, &state, &[], 0).is_none(), "{field} = {bad}");
        }
        Ok(())
    }

    /// Review 9, finding 5: "App sperren" was offered for any reported ID - a gateway or the owner node could be banned
    /// by mistake. Only known apps get it; the network's own roles never; every ID says what it is.
    #[test]
    fn ban_app_only_for_known_apps() -> Result<(), String> {
        let state = state()?;
        let now = now_ms();
        let operator = state.log_operators().first().cloned().ok_or("no log operator")?;
        let unknown = Id::of_sign_key(&[6; 32]);
        let app = Id::of_sign_key(&[7; 32]);
        let view = |id: &Id, keys: &[Id]| target_view(&state, &LabelTarget::Id(id.clone()), keys, now);
        for (id, kind) in [(state.net().clone(), "net"), (operator.clone(), "operator"), (unknown.clone(), "unknown")] {
            let about = view(&id, &[]);
            assert_eq!(about["id_kind"], json!(kind));
            assert_eq!(about["actions"]["ban_app"], json!(false), "{kind}");
            assert!(about["id_kind_text"].as_str().is_some_and(|text| !text.is_empty()));
        }
        // An app key of the owner folder is a known app - even if it is (also) listed as operator, the role wins.
        assert_eq!(view(&app, std::slice::from_ref(&app))["actions"]["ban_app"], json!(true));
        assert_eq!(view(&operator, std::slice::from_ref(&operator))["actions"]["ban_app"], json!(false));
        assert_eq!(id_kind_text("gateway"), "ein Empfänger (Gateway) des Netzes");
        Ok(())
    }

    #[test]
    fn names_of_an_empty_network() -> Result<(), String> {
        let view = names_view(&state()?, 0);
        assert_eq!(
            (view["total"].clone(), view["list"].clone(), view["more"].clone()),
            (json!(0), json!([]), json!(false))
        );
        Ok(())
    }
}
