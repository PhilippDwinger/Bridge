//! The owner backup (docs/12 §10): the keys of the owner node's folder (and settings a caller adds), sealed for the
//! net key's receiving key, kept as a Bridge app of its own on the network's web hosts; a `backup` log entry names
//! that app. [`restore`] brings it back on a new PC with nothing but the 24 words and one address of the network.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use bridge_core::encoding::{b64, b64_fixed, b64_var};
use bridge_core::json::{canonical, parse_strict};
use bridge_core::{Id, Identity};
use bridge_net::{Backup, NetState, Service, Services, is_web_host};
use bridge_node::admin::{ADMIN_KEY_FILE, AdminClient, YEAR_MS};
use bridge_node::keyfile;
use bridge_sdk::BlobSource;
use rand_core::OsRng;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::apps::{self, APPS_DIR, OWNER_KEY_FILE};

/// The app key of the backup (not in `apps/`: it is no website).
pub const BACKUP_APP_KEY: &str = "backup-app.json";
/// The only file of the backup app.
pub const BACKUP_FILE: &str = "owner-backup.b4";
/// What the folder remembers about its last backup.
pub const STATE_FILE: &str = "backup-state.json";
/// The single files backed up from the owner node's folder (plus `apps/*.json` and [`BACKUP_APP_KEY`]).
pub const KEY_FILES: [&str; 4] = [keyfile::KEY_FILE, keyfile::TLS_FILE, ADMIN_KEY_FILE, OWNER_KEY_FILE];
/// Largest settings object a caller adds.
pub const MAX_SETTINGS_BYTES: usize = 16 * 1024;
/// Largest single file in a backup.
const MAX_FILE_BYTES: usize = 16 * 1024;
/// Most app keys.
const MAX_APP_KEYS: usize = 2000;
/// Most hosts of the backup app (the owner node and other web hosts).
const MAX_HOSTS: usize = 8;
/// Unchanged backups are published again after this (so the version never expires).
pub const REFRESH_MS: i64 = 30 * 24 * 3600 * 1000;
/// The `backup` entry is renewed when it is older than this.
pub const STATEMENT_RENEW_MS: i64 = 180 * 24 * 3600 * 1000;
/// Lifetime of a new `backup` entry.
const STATEMENT_LIFETIME_MS: i64 = YEAR_MS;

fn now() -> i64 {
    use bridge_node::Clock as _;
    bridge_node::SystemClock.now_ms()
}

/// Whether `name` may be a file of a backup: one of [`KEY_FILES`], [`BACKUP_APP_KEY`] or `apps/<app-id>.json`.
#[must_use]
pub fn allowed_name(name: &str) -> bool {
    if KEY_FILES.contains(&name) || name == BACKUP_APP_KEY {
        return true;
    }
    name.strip_prefix("apps/").and_then(|rest| rest.strip_suffix(".json")).is_some_and(|id| Id::parse(id).is_ok())
}

/// The plaintext of a backup of the folder `data` of network `net`: canonical JSON
/// `{"v":1,"t":"owner-backup","net","files":{name: Base64url},"settings"}` (no time in it: equal folders give equal
/// bytes, so a change is easy to see).
pub fn collect(data: &Path, net: &Id, settings: &Value) -> Result<Vec<u8>, String> {
    if canonical(settings).map_err(|e| e.to_string())?.len() > MAX_SETTINGS_BYTES || !settings.is_object() {
        return Err("Einstellungen: ein JSON-Objekt bis 16 KiB".into());
    }
    let mut files = BTreeMap::new();
    let mut add = |name: String, path: PathBuf| -> Result<(), String> {
        match std::fs::read(&path) {
            Ok(bytes) if bytes.len() <= MAX_FILE_BYTES => {
                files.insert(name, Value::String(b64(&bytes)));
                Ok(())
            }
            Ok(_) => Err(format!("{}: zu groß für ein Backup", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    };
    for name in KEY_FILES.into_iter().chain([BACKUP_APP_KEY]) {
        add(name.to_owned(), data.join(name))?;
    }
    for (app, _) in apps::list(data, MAX_APP_KEYS)? {
        add(format!("{APPS_DIR}/{app}.json"), data.join(APPS_DIR).join(format!("{app}.json")))?;
    }
    if !files.contains_key(ADMIN_KEY_FILE) || !files.contains_key(keyfile::KEY_FILE) {
        return Err(format!("{}: kein Owner-Knoten (admin-key.json, node-key.json)", data.display()));
    }
    let value = json!({"v": 1, "t": "owner-backup", "net": net.as_str(), "files": files, "settings": settings});
    canonical(&value).map_err(|e| e.to_string())
}

/// What [`make`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Made {
    /// The backup app.
    pub app: Id,
    /// Something changed or it was due: a new version was published.
    pub published: bool,
    /// A new `backup` entry went into the log.
    pub statement: bool,
    /// Hosts of the backup app.
    pub hosts: usize,
    /// When the backup was last published (ms).
    pub at: i64,
}

/// The ID of the folder's backup app, if it has one (it is no website: lists of apps leave it out).
#[must_use]
pub fn app_of(data: &Path) -> Option<Id> {
    let bytes = Zeroizing::new(std::fs::read(data.join(BACKUP_APP_KEY)).ok()?);
    let value = parse_strict(&bytes, 2048).ok()?;
    Id::parse(value.get("app")?.as_str()?).ok()
}

/// The state file of the folder (what [`make`] did last).
#[must_use]
pub fn last(data: &Path) -> Option<Value> {
    let bytes = std::fs::read(data.join(STATE_FILE)).ok()?;
    parse_strict(&bytes, 4096).ok()
}

fn load_or_create_app_key(data: &Path) -> Result<Identity, String> {
    let path = data.join(BACKUP_APP_KEY);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let damaged = || format!("{} ist beschädigt", path.display());
            let Value::Object(object) = parse_strict(&bytes, 2048).map_err(|_| damaged())? else {
                return Err(damaged());
            };
            let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
            let sign = Zeroizing::new(b64_fixed::<32>(&text("sign"), "sign").map_err(|_| damaged())?);
            let receive = Zeroizing::new(b64_fixed::<32>(&text("box"), "box").map_err(|_| damaged())?);
            let identity = Identity::from_secret_bytes(&sign, &receive);
            if text("app") != identity.id().as_str() || text("t") != "app-key" {
                return Err(damaged());
            }
            Ok(identity)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let app = Identity::generate(&mut OsRng);
            let (sign, receive) = app.secret_bytes();
            let content = Zeroizing::new(
                json!({"v": 4, "t": "app-key", "app": app.id().as_str(), "name": "Owner-Backup",
                       "sign": b64(sign.as_slice()), "box": b64(receive.as_slice())})
                .to_string(),
            );
            keyfile::write_new_secret(&path, content.as_bytes())?;
            Ok(app)
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// The hosts for the backup app: the owner node first, then other web hosts of the log (at most [`MAX_HOSTS`]).
fn hosts(state: &NetState, owner_node: &Id, at: i64) -> Vec<Id> {
    let mut hosts = vec![owner_node.clone()];
    for id in state.sealed_with(Service::Web, at, 64) {
        if hosts.len() < MAX_HOSTS && !hosts.contains(&id) && is_web_host(state, &id, at) {
            hosts.push(id);
        }
    }
    hosts
}

/// The owner node must host the backup: without the service `web` it gets a new seal (level 3, its services plus
/// `web`) - like for its first website. Returns the state once that holds.
async fn owner_web_host(admin: &AdminClient, state: NetState) -> Result<NetState, String> {
    let node = admin.node_id().clone();
    if is_web_host(&state, &node, now()) {
        return Ok(state);
    }
    let services = state.services(&node, now()).union(Services::of(&[Service::Web]));
    let card = admin.fetch_node_card(admin.node_url()).await?;
    admin.seal_card(card, &node, 3, services).await?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let (_, state) = admin.load_state().await?;
        if is_web_host(&state, &node, now()) {
            return Ok(state);
        }
        if std::time::Instant::now() >= deadline {
            return Err("Das Siegel des Owner-Knotens mit Dienst web zählt noch nicht - gleich noch einmal.".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Backs the owner node's folder `data` up (docs/12 §10.3): if its contents changed since the last time, or the last
/// time is [`REFRESH_MS`] ago, or `force`, a new version of the backup app; a `backup` entry if none names it or the
/// one in effect is older than [`STATEMENT_RENEW_MS`]. `settings`: what the caller wants back (BridgeControll: the
/// node's settings).
pub async fn make(data: &Path, settings: &Value, node_url: Option<&str>, force: bool) -> Result<Made, String> {
    let admin = AdminClient::load(data, node_url)?;
    let (_, state) = admin.load_state().await?;
    let state = owner_web_host(&admin, state).await?;
    let at = now();
    let net = admin.net().clone();
    let card = &state.manifest().card;
    if card.id() != &net {
        return Err("Das Manifest hat nicht die Karte des Hauptschlüssels.".into());
    }
    let key = load_or_create_app_key(data)?;
    // The owner key (made on the first publish) must be in this backup already.
    apps::owner(data)?;
    let plaintext = Zeroizing::new(collect(data, &net, settings)?);
    let digest = b64(&bridge_core::crypto::sha256(&plaintext));
    let previous = last(data);
    let previous_at = previous.as_ref().and_then(|v| v.get("at")).and_then(Value::as_i64).unwrap_or(0);
    let same = previous.as_ref().and_then(|v| v.get("digest")).and_then(Value::as_str) == Some(digest.as_str());
    let hosts = hosts(&state, admin.node_id(), at);
    let mut made =
        Made { app: key.id().clone(), published: false, statement: false, hosts: hosts.len(), at: previous_at };
    if force || !same || at.saturating_sub(previous_at) >= REFRESH_MS {
        let sealed = bridge_core::backup::seal(&plaintext, &net, card.receive_public(), &mut OsRng)
            .map_err(|e| format!("Verschlüsseln: {e}"))?;
        let folder = tempfile_dir()?;
        std::fs::write(folder.path().join(BACKUP_FILE), &sealed).map_err(|e| format!("Backup-Datei: {e}"))?;
        apps::publish_key(
            data,
            &key,
            "Owner-Backup".into(),
            folder.path(),
            hosts.clone(),
            Some(BACKUP_FILE),
            None,
            node_url,
        )
        .await?;
        made.published = true;
        made.at = at;
    }
    let current = state.backup_app(at);
    let fresh =
        current.as_ref().is_some_and(|(app, iat)| app == key.id() && at.saturating_sub(*iat) < STATEMENT_RENEW_MS);
    if !fresh {
        let statement = admin.sign(&Backup { app: key.id().clone() }, STATEMENT_LIFETIME_MS)?;
        admin.submit(&statement).await.map_err(|e| format!("Backup-Eintrag: {e}"))?;
        made.statement = true;
    }
    let remembered = json!({"v": 1, "app": key.id().as_str(), "digest": digest, "at": made.at, "hosts": made.hosts});
    std::fs::write(data.join(STATE_FILE), remembered.to_string()).map_err(|e| format!("{STATE_FILE}: {e}"))?;
    Ok(made)
}

/// A temporary folder that is removed when dropped (no extra crate: a folder under the system's temp folder).
struct TempDir(PathBuf);

impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempfile_dir() -> Result<TempDir, String> {
    let name = format!("bridge-backup-{}-{}", std::process::id(), b64(&rand_bytes()));
    let path = std::env::temp_dir().join(name);
    std::fs::create_dir(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(TempDir(path))
}

fn rand_bytes() -> [u8; 9] {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 9];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// What [`restore`] brought back.
#[derive(Debug, Clone, PartialEq)]
pub struct Restored {
    /// The network.
    pub net: Id,
    /// The owner node's ID (from its restored key).
    pub node: Id,
    /// The settings the caller had added.
    pub settings: Value,
    /// Files written.
    pub files: usize,
}

/// Reads and checks a backup's plaintext: the network, only allowed names, every file within bounds.
fn parse_backup(plaintext: &[u8], net: &Id) -> Result<(BTreeMap<String, Vec<u8>>, Value), String> {
    let value = parse_strict(plaintext, bridge_core::backup::MAX_BACKUP_BYTES).map_err(|_| "Backup: kein JSON")?;
    let object = value.as_object().ok_or("Backup: kein Objekt")?;
    if object.get("v") != Some(&json!(1)) || object.get("t") != Some(&json!("owner-backup")) {
        return Err("Backup: unbekannte Art".into());
    }
    if object.get("net").and_then(Value::as_str) != Some(net.as_str()) {
        return Err("Backup: gehört zu einem anderen Netz".into());
    }
    let mut files = BTreeMap::new();
    for (name, content) in object.get("files").and_then(Value::as_object).ok_or("Backup: keine Dateien")? {
        if !allowed_name(name) {
            return Err(format!("Backup: unerlaubte Datei {name}"));
        }
        let bytes = b64_var(content.as_str().unwrap_or_default(), "file", MAX_FILE_BYTES)
            .map_err(|_| format!("Backup: Datei {name} kaputt"))?;
        files.insert(name.clone(), bytes);
    }
    let settings = object.get("settings").cloned().unwrap_or_else(|| Value::Object(Map::new()));
    Ok((files, settings))
}

/// Brings the owner backup back into the new, empty folder `target` (docs/12 §10.4) with the net key `master` (from
/// the 24 words): the log from `address` (checked against the network of the words), the newest `backup` entry, the backup app's file from one of its hosts, opened
/// with the net key. Refuses when the old owner node still answers at an address of its card.
pub async fn restore(master: &Identity, address: &str, target: &Path) -> Result<Restored, String> {
    let net = master.id().clone();
    let address = address.trim().trim_end_matches('/');
    let (_, state) = AdminClient::load_state_from(address, &net)
        .await
        .map_err(|e| format!("Das Netz dieser Wörter ist unter {address} nicht zu finden: {e}"))?;
    let at = now();
    let (app, _) = state.backup_app(at).ok_or("In diesem Netz gibt es kein Owner-Backup.")?;
    let mut sources = vec![address.to_owned()];
    for id in state.sealed_with(Service::Web, at, 64) {
        if let Some(url) = state.card_of(&id).and_then(|card| card.urls().first().cloned()) {
            if !sources.contains(&url) && sources.len() < 16 {
                sources.push(url);
            }
        }
    }
    let mut errors: Vec<String> = Vec::new();
    let mut sealed = None;
    for url in &sources {
        let Ok(source) = BlobSource::new(url) else { continue };
        match fetch_backup(&source, &app, &net).await {
            Ok(bytes) => {
                sealed = Some(bytes);
                break;
            }
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }
    let sealed = sealed.ok_or_else(|| {
        let shown: Vec<&str> = errors.iter().take(2).map(String::as_str).collect();
        format!(
            "Das Backup ist nicht zu holen ({}).",
            if shown.is_empty() { "kein Host".into() } else { shown.join("; ") }
        )
    })?;
    let plaintext = Zeroizing::new(
        bridge_core::backup::open(&sealed, &net, master)
            .map_err(|_| "Das Backup lässt sich mit diesen Wörtern nicht öffnen.")?,
    );
    let (files, settings) = parse_backup(&plaintext, &net)?;
    let node_key = files.get(keyfile::KEY_FILE).ok_or("Backup ohne node-key.json")?;
    let node = keyfile::identity_of(node_key)?;
    if !state.manifest().logs.contains(node.id()) && !state.gateways(at).iter().any(|(id, _)| id == node.id()) {
        return Err("Der gesicherte Knoten ist nicht der Owner-Knoten dieses Netzes.".into());
    }
    still_running(&state, node.id()).await?;
    if target.join(ADMIN_KEY_FILE).exists() || target.join(keyfile::KEY_FILE).exists() {
        return Err(format!("{} ist nicht leer", target.display()));
    }
    std::fs::create_dir_all(target.join(APPS_DIR)).map_err(|e| format!("{}: {e}", target.display()))?;
    for (name, bytes) in &files {
        keyfile::write_new_secret(&target.join(name), bytes)?;
    }
    Ok(Restored { net, node: node.id().clone(), settings, files: files.len() })
}

async fn fetch_backup(source: &BlobSource, app: &Id, net: &Id) -> Result<Vec<u8>, String> {
    let version = bridge_sdk::fetch_app(source, app, net).await.map_err(|e| e.to_string())?;
    let file =
        version.manifest.files.iter().find(|file| file.path == BACKUP_FILE).ok_or("Version ohne Backup-Datei")?;
    let limit = (bridge_core::backup::MAX_BACKUP_BYTES + 64) as u64;
    if file.size > limit {
        return Err("Backup-Datei zu groß".into());
    }
    bridge_sdk::fetch_blob(std::slice::from_ref(source), &file.blob, limit).await.map_err(|e| e.to_string())
}

/// Refuses when the owner node `node` still answers at one of the addresses of its card (two owner nodes with one key
/// would contradict each other).
async fn still_running(state: &NetState, node: &Id) -> Result<(), String> {
    let urls: Vec<String> = state.card_of(node).map(|card| card.urls().to_vec()).unwrap_or_default();
    for url in urls.iter().take(4) {
        let Ok(http) = bridge_transport::HttpClient::new(url, std::time::Duration::from_secs(5)) else { continue };
        let Ok(answer) = http.get("/v4/info").await else { continue };
        let card = parse_strict(&answer.body, 64 * 1024)
            .ok()
            .and_then(|value| value.get("card").cloned())
            .and_then(|card| bridge_core::KeyCard::from_value(card).ok());
        if answer.status == 200 && card.is_some_and(|card| card.id() == node) {
            return Err(format!(
                "Der alte Owner-Knoten antwortet noch unter {url}. Wiederherstellen nur, wenn der alte PC weg ist - \
                 sonst gäbe es zwei Owner-Knoten mit demselben Schlüssel."
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_key_files_are_allowed() {
        for good in ["node-key.json", "admin-key.json", "owner-key.json", "node-tls.pem", "backup-app.json"] {
            assert!(allowed_name(good), "{good}");
        }
        let app = Identity::generate(&mut OsRng);
        assert!(allowed_name(&format!("apps/{}.json", app.id())));
        for bad in ["../x", "apps/../admin-key.json", "apps/x.json", "store.db", "apps/a/b.json", "/etc/passwd", ""] {
            assert!(!allowed_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_backup_keeps_only_what_it_should() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("bridge-backup-test-{}", b64(&rand_bytes())));
        std::fs::create_dir_all(dir.join(APPS_DIR)).map_err(|e| e.to_string())?;
        let net = Identity::generate(&mut OsRng).id().clone();
        assert!(collect(&dir, &net, &json!({})).is_err(), "no owner node");
        std::fs::write(dir.join(ADMIN_KEY_FILE), b"{\"admin\":1}").map_err(|e| e.to_string())?;
        std::fs::write(dir.join(keyfile::KEY_FILE), b"{\"node\":1}").map_err(|e| e.to_string())?;
        std::fs::write(dir.join("store.db"), b"not in the backup").map_err(|e| e.to_string())?;
        let app = apps::create(&dir, "Laden")?;
        let plain = collect(&dir, &net, &json!({"name": "Owner"}))?;
        assert_eq!(plain, collect(&dir, &net, &json!({"name": "Owner"}))?, "equal folders, equal bytes");
        let (files, settings) = parse_backup(&plain, &net)?;
        let names: Vec<&str> = files.keys().map(String::as_str).collect();
        assert_eq!(names, [ADMIN_KEY_FILE, format!("apps/{app}.json").as_str(), keyfile::KEY_FILE]);
        assert_eq!(settings, json!({"name": "Owner"}));
        assert!(parse_backup(&plain, &Identity::generate(&mut OsRng).id().clone()).is_err(), "another network");
        let evil = canonical(&json!({"v": 1, "t": "owner-backup", "net": net.as_str(), "files": {"../x": "AA"}}))
            .map_err(|e| e.to_string())?;
        assert!(parse_backup(&evil, &net).is_err());
        assert!(collect(&dir, &net, &json!([1])).is_err(), "settings are an object");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
