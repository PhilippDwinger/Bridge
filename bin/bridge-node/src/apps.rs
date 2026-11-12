//! `bridge-node app create|publish|hosts` (docs/07 §8): Bridge apps from the owner's data folder, without
//! BridgeControll. User-facing texts are German.
//!
//! - The app key lives in `apps/<app-id>.json` in the data folder (owner-only file) - never on a host.
//! - The owner is a client identity of the data folder (`owner-key.json`, made on first use). The admin key of the
//!   same folder (`admin-key.json`, from `net create`) admits it as a member if it is none yet - so `app publish`
//!   runs in the owner node's folder.
//! - Hosts must be sealed with the service `web`; the version is handed to the first host that is also a gateway
//!   (the owner logs in there, uploads what is missing, publishes); the other hosts fetch it themselves.
//! - Hosts the new version no longer lists get it too (`/v4/app/update`, no login): they stop at once. A completely
//!   new host does not know them, so the owner tells them (docs/07 §5 "Stopp-Signal").

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bridge_core::app::{AppManifest, MAX_APP_NAME_CHARS};
use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::json::parse_strict;
use bridge_core::{Id, Identity, Statement};
use bridge_net::{Member, NetState, is_web_host};
use bridge_node::admin::{AdminClient, YEAR_MS};
use bridge_node::keyfile;
use bridge_sdk::{AppDraft, AppVersion, BlobSource, Client, SdkError};
use rand_core::OsRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// Folder of the app keys inside the data folder.
pub const APPS_DIR: &str = "apps";
/// The owner's client identity inside the data folder.
pub const OWNER_KEY_FILE: &str = "owner-key.json";
/// How long `app publish` waits until the owner is a member at the publishing host.
const MEMBER_WAIT: Duration = Duration::from_secs(30);
/// Most hosts asked for the current version.
const MAX_ASKED: usize = 16;

fn now() -> i64 {
    use bridge_node::Clock as _;
    bridge_node::SystemClock.now_ms()
}

fn app_key_path(data: &Path, app: &Id) -> PathBuf {
    data.join(APPS_DIR).join(format!("{app}.json"))
}

/// Makes a new app key in `apps/<app-id>.json`. Returns the app ID.
pub fn create(data: &Path, name: &str) -> Result<Id, String> {
    let count = name.chars().count();
    if count == 0 || count > MAX_APP_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(format!("--name: 1-{MAX_APP_NAME_CHARS} Zeichen, keine Steuerzeichen"));
    }
    std::fs::create_dir_all(data.join(APPS_DIR)).map_err(|e| format!("Ordner {APPS_DIR}: {e}"))?;
    let app = Identity::generate(&mut OsRng);
    let (sign, receive) = app.secret_bytes();
    let content = Zeroizing::new(
        json!({"v": 4, "t": "app-key", "app": app.id().as_str(), "name": name,
               "sign": b64(sign.as_slice()), "box": b64(receive.as_slice())})
        .to_string(),
    );
    keyfile::write_new_secret(&app_key_path(data, app.id()), content.as_bytes())?;
    Ok(app.id().clone())
}

/// Loads the app key `apps/<app-id>.json`: (key, name).
pub fn load(data: &Path, app: &Id) -> Result<(Identity, String), String> {
    let path = app_key_path(data, app);
    let bytes = Zeroizing::new(
        std::fs::read(&path).map_err(|e| format!("{} nicht lesbar ({e}) - erst `app create`?", path.display()))?,
    );
    let damaged = |what: &str| format!("{} ist beschädigt ({what})", path.display());
    let Value::Object(object) = parse_strict(&bytes, 2048).map_err(|_| damaged("kein JSON"))? else {
        return Err(damaged("kein Objekt"));
    };
    if object.get("v") != Some(&json!(4)) || object.get("t") != Some(&json!("app-key")) {
        return Err(damaged("Version/Art"));
    }
    let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
    let sign = Zeroizing::new(b64_fixed::<32>(&text("sign"), "sign").map_err(|_| damaged("sign"))?);
    let receive = Zeroizing::new(b64_fixed::<32>(&text("box"), "box").map_err(|_| damaged("box"))?);
    let identity = Identity::from_secret_bytes(&sign, &receive);
    if identity.id() != app || text("app") != app.as_str() {
        return Err(damaged("der Schlüssel gehört nicht zu dieser App-ID"));
    }
    Ok((identity, text("name")))
}

/// The owner's client identity of the data folder (`owner-key.json`, made on first use): owner of the apps and
/// names made there (BridgeControll: the member key of the PC in this network).
pub fn owner(data: &Path) -> Result<Identity, String> {
    keyfile::load_or_create_at(&data.join(OWNER_KEY_FILE))
}

/// Makes sure the owner key of the folder is a member (the admin key of the same folder admits it if needed, like
/// `app publish` does). Returns its ID.
pub async fn admit_owner(data: &Path, node_url: Option<&str>) -> Result<Id, String> {
    Owner::open(data, node_url).await?;
    Ok(owner(data)?.id().clone())
}

/// The app keys of the folder (`apps/<id>.json`): (app ID, name), sorted by name, at most `max`. Files that are no
/// valid app key are left out.
pub fn list(data: &Path, max: usize) -> Result<Vec<(Id, String)>, String> {
    let dir = data.join(APPS_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{}: {error}", dir.display())),
    };
    let mut apps = Vec::new();
    // Bounded: at most 4 × max directory entries are looked at.
    for entry in entries.flatten().take(max.saturating_mul(4)) {
        let file = entry.file_name();
        let Some(id) = file.to_str().and_then(|name| name.strip_suffix(".json")).and_then(|id| Id::parse(id).ok())
        else {
            continue;
        };
        if let Ok((_, name)) = load(data, &id) {
            apps.push((id, name));
        }
        if apps.len() >= max {
            break;
        }
    }
    apps.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.as_str().cmp(b.0.as_str())));
    Ok(apps)
}

/// The owner's admin side: the admin key of the folder, the network state from the owner node, the owner key (a
/// member - admitted here if needed).
pub(crate) struct Owner {
    data: PathBuf,
    pub(crate) admin: AdminClient,
    pub(crate) state: NetState,
}

impl Owner {
    pub(crate) async fn open(data: &Path, node_url: Option<&str>) -> Result<Self, String> {
        let admin = AdminClient::load(data, node_url)?;
        let (_, mut state) = admin.load_state().await?;
        let owner_id = owner(data)?.id().clone();
        if !state.is_member(&owner_id, now()) {
            let member = Member { member: owner_id.clone(), invite: None };
            let statement = admin.sign(&member, YEAR_MS).map_err(|e| format!("Mitgliedschaft: {e}"))?;
            admin.submit(&statement).await.map_err(|e| format!("Owner-Schlüssel aufnehmen: {e}"))?;
            state = admin.load_state().await?.1;
            if !state.is_member(&owner_id, now()) {
                return Err("Der Owner-Schlüssel ist kein Mitglied geworden (Rechte des Admin-Schlüssels?).".into());
            }
        }
        Ok(Self { data: data.to_path_buf(), admin, state })
    }

    /// Every host must be sealed with `web` (level ≥ 1).
    fn check_hosts(&self, hosts: &[Id]) -> Result<(), String> {
        for host in hosts {
            if !is_web_host(&self.state, host, now()) {
                return Err(format!(
                    "Host {host} hat kein Siegel mit Dienst web. Erst siegeln, z. B.: bridge-node net seal --data {} \
                     --node-url <adresse> --node-id {host} --services gateway,web (der Owner-Knoten: \
                     --level 3 --services gateway,log,witness,web)",
                    self.data.display()
                ));
            }
        }
        Ok(())
    }

    /// Where to reach a node: the address of the admin commands for the owner node, else its card in the log.
    fn url_of(&self, id: &Id) -> Option<String> {
        if id == self.admin.node_id() {
            return Some(self.admin.node_url().to_owned());
        }
        self.state.card_of(id).and_then(|card| card.urls().first().cloned())
    }

    /// The owner logged in at the first host of `hosts` that is a gateway (retried while the membership is not
    /// there yet).
    async fn client(&self, hosts: &[Id]) -> Result<(Client, Id), String> {
        let gateways: Vec<Id> = self.state.gateways(now()).into_iter().map(|(id, _)| id).collect();
        let host = hosts
            .iter()
            .find(|host| gateways.contains(host))
            .ok_or("Kein Host ist auch Empfänger (gateway) - dort meldet sich der Owner an, um zu veröffentlichen.")?;
        let url = self.url_of(host).ok_or_else(|| format!("Keine Adresse für Host {host} im Log"))?;
        let deadline = Instant::now() + MEMBER_WAIT;
        loop {
            let mut client = Client::new(owner(&self.data)?, &url, Some(host.clone())).map_err(|e| e.to_string())?;
            match client.connect().await {
                Ok(()) => return Ok((client, host.clone())),
                Err(SdkError::Node { code, .. }) if code == "NOT_MEMBER" && Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(error) => return Err(format!("Anmeldung bei Host {host} ({url}): {error}")),
            }
        }
    }

    /// Hands `statement` to every host of `previous` it no longer lists (`/v4/app/update`): they stop at once.
    /// Returns (told, not reached); a host that does not host the app (any more) counts as told.
    async fn retire(&self, previous: Option<&AppVersion>, statement: &Statement, hosts: &[Id]) -> (Vec<Id>, Vec<Id>) {
        let (mut told, mut unreached) = (Vec::new(), Vec::new());
        let Some(previous) = previous else { return (told, unreached) };
        for id in previous.manifest.hosts.iter().filter(|id| !hosts.contains(id)).take(64) {
            let Some(source) = self.url_of(id).and_then(|url| BlobSource::new(&url).ok()) else {
                unreached.push(id.clone());
                continue;
            };
            match bridge_sdk::announce_app(&source, statement).await {
                Ok(_) => told.push(id.clone()),
                Err(SdkError::Node { code, .. }) if code == "NOT_FOUND" || code == "REPLAY" => told.push(id.clone()),
                Err(_) => unreached.push(id.clone()),
            }
        }
        (told, unreached)
    }

    /// The newest version of `app` any host knows (the owner node first, then web hosts of the log).
    pub(crate) async fn current(&self, app: &Id) -> Option<AppVersion> {
        let mut candidates: Vec<Id> = vec![self.admin.node_id().clone()];
        for (id, _) in self.state.gateways(now()) {
            if is_web_host(&self.state, &id, now()) && !candidates.contains(&id) {
                candidates.push(id);
            }
        }
        let mut best: Option<AppVersion> = None;
        for id in candidates.into_iter().take(MAX_ASKED) {
            let Some(source) = self.url_of(&id).and_then(|url| BlobSource::new(&url).ok()) else { continue };
            if let Ok(found) = bridge_sdk::fetch_app(&source, app, self.admin.net()).await {
                if best.as_ref().is_none_or(|best| found.manifest.version > best.manifest.version) {
                    best = Some(found);
                }
            }
        }
        best
    }
}

/// What `app publish` / `app hosts` did.
pub struct Done {
    /// The new version.
    pub version: u64,
    /// The host it was handed to.
    pub host: Id,
    /// Its address there.
    pub url: String,
    /// Served there right away.
    pub active: bool,
    /// All hosts of the version.
    pub hosts: Vec<Id>,
    /// Hosts of the previous version that were told they are no longer hosts.
    pub retired: Vec<Id>,
    /// Hosts of the previous version that could not be told (they stop when they learn the version otherwise).
    pub unreached: Vec<Id>,
}

/// `app publish`: a new version from `folder` (version +1; hosts as given, else those of the current version, else
/// the owner node).
pub async fn publish(
    data: &Path,
    app: &Id,
    folder: &Path,
    hosts: Vec<Id>,
    entry: Option<&str>,
    description: Option<&str>,
    node_url: Option<&str>,
) -> Result<Done, String> {
    let (key, name) = load(data, app)?;
    let owner = Owner::open(data, node_url).await?;
    let current = owner.current(app).await;
    let hosts = if !hosts.is_empty() {
        hosts
    } else if let Some(current) = &current {
        current.manifest.hosts.clone()
    } else {
        vec![owner.admin.node_id().clone()]
    };
    owner.check_hosts(&hosts)?;
    let draft = AppDraft {
        name,
        description: description
            .map(str::to_owned)
            .or_else(|| current.as_ref().map(|current| current.manifest.description.clone()))
            .unwrap_or_default(),
        entry: entry.unwrap_or("index.html").to_owned(),
        version: current.as_ref().map_or(1, |current| current.manifest.version + 1),
        hosts: hosts.clone(),
    };
    let (client, host) = owner.client(&hosts).await?;
    let (statement, published) =
        client.publish_folder(&key, folder, &draft).await.map_err(|e| format!("Veröffentlichen: {e}"))?;
    let (retired, unreached) = owner.retire(current.as_ref(), &statement, &hosts).await;
    let url = owner.url_of(&host).unwrap_or_default();
    Ok(Done { version: published.version, host, url, active: published.active, hosts, retired, unreached })
}

/// `app hosts`: a new version with the same files and changed hosts.
pub async fn change_hosts(
    data: &Path,
    app: &Id,
    add: Vec<Id>,
    remove: Vec<Id>,
    node_url: Option<&str>,
) -> Result<Done, String> {
    let (key, _) = load(data, app)?;
    let owner = Owner::open(data, node_url).await?;
    let current = owner.current(app).await.ok_or("Keine Version dieser App gefunden - erst `app publish`.")?;
    let mut hosts: Vec<Id> = current.manifest.hosts.iter().filter(|host| !remove.contains(host)).cloned().collect();
    for host in add {
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    if hosts.is_empty() {
        return Err("Eine App braucht mindestens einen Host.".into());
    }
    // `app hosts` uploads nothing: the new hosts fetch the files from the hosts of the new version. Without one of the
    // current hosts among them nobody would have the files - and the old hosts stop at once (fail closed).
    if !hosts.iter().any(|host| current.manifest.hosts.contains(host)) {
        return Err("Mindestens ein bisheriger Host muss bleiben - von ihm holen die neuen Hosts die Dateien. Erst \
                    `app hosts --add <neu>`, warten, bis der neue Host die App ausliefert, dann `app hosts --remove <alt>` \
                    (oder `app publish --folder … --host <neu>`, das lädt die Dateien hoch)."
            .into());
    }
    owner.check_hosts(&hosts)?;
    let manifest: &AppManifest = &current.manifest;
    let draft = AppDraft {
        name: manifest.name.clone(),
        description: manifest.description.clone(),
        entry: manifest.entry.clone(),
        version: manifest.version + 1,
        hosts: hosts.clone(),
    };
    let (client, host) = owner.client(&hosts).await?;
    let statement = client.sign_app(&key, &draft, manifest.files.clone()).map_err(|e| e.to_string())?;
    let published = client.publish_app(&statement).await.map_err(|e| format!("Veröffentlichen: {e}"))?;
    let (retired, unreached) = owner.retire(Some(&current), &statement, &hosts).await;
    let url = owner.url_of(&host).unwrap_or_default();
    Ok(Done { version: published.version, host, url, active: published.active, hosts, retired, unreached })
}

#[cfg(test)]
mod tests {
    use bridge_tests::apps::{app_folder, gone, served};
    use bridge_tests::net::TestNet;

    use super::*;

    /// The commands end to end: the owner node's folder makes an app, publishes it (the owner key is admitted as a
    /// member on the way), adds a host (it fetches the files itself) and removes the owner node (it stops).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn create_publish_and_change_hosts() -> Result<(), String> {
        let net = TestNet::create(bridge_net::JoinMode::Invite).await?;
        let data = net.owner.dir.path().to_path_buf();
        let (folder, _) = app_folder(100)?;
        let app = create(&data, "Spiel")?;
        let url = Some(net.owner.url.as_str());
        // Without a web seal the owner node may not host.
        let refused = publish(&data, &app, folder.path(), Vec::new(), None, None, url).await;
        assert!(refused.as_ref().err().is_some_and(|error| error.contains("web")), "{:?}", refused.as_ref().err());
        let services = bridge_node::admin::parse_services("gateway,log,witness,web")?;
        net.admin.seal(&net.owner.url, &net.owner.id(), 3, services).await?;
        let done = publish(&data, &app, folder.path(), Vec::new(), None, Some("Ein Test"), url).await?;
        assert_eq!((done.version, done.active, done.hosts.clone()), (1, true, vec![net.owner.id()]));
        let entry = b"<!doctype html><h1>Hallo Bridge-App</h1>";
        served(&format!("{}/app/{app}/", net.owner.url), entry).await?;
        // A second publish counts up and keeps the hosts.
        assert_eq!(publish(&data, &app, folder.path(), Vec::new(), None, None, url).await?.version, 2);
        // Add a host: it fetches the version itself.
        let host = net.add_node(&[]).await?;
        net.seal_as(&host, "gateway,web").await?;
        let added = change_hosts(&data, &app, vec![host.id()], Vec::new(), url).await?;
        assert_eq!((added.version, added.hosts.len()), (3, 2));
        served(&format!("{}/app/{app}/", host.url), entry).await?;
        // Remove the owner node: published at the remaining host, the owner node stops.
        let removed = change_hosts(&data, &app, Vec::new(), vec![net.owner.id()], url).await?;
        assert_eq!((removed.version, removed.host.clone()), (4, host.id()));
        gone(&format!("{}/app/{app}/", net.owner.url)).await?;
        served(&format!("{}/app/{app}/", host.url), entry).await?;
        assert!(change_hosts(&data, &app, Vec::new(), vec![host.id()], url).await.is_err(), "no host left");
        // A complete switch in one step would leave nobody with the files (`app hosts` uploads nothing): refused.
        let other = net.add_node(&[]).await?;
        net.seal_as(&other, "gateway,web").await?;
        let at_once = change_hosts(&data, &app, vec![other.id()], vec![host.id()], url).await;
        assert!(at_once.as_ref().err().is_some_and(|error| error.contains("bisheriger Host")), "{:?}", at_once.err());
        // Add first, then remove: the removed host is told and stops at once.
        assert_eq!(change_hosts(&data, &app, vec![other.id()], Vec::new(), url).await?.version, 5);
        served(&format!("{}/app/{app}/", other.url), entry).await?;
        let moved = change_hosts(&data, &app, Vec::new(), vec![host.id()], url).await?;
        assert_eq!((moved.version, moved.hosts.clone()), (6, vec![other.id()]));
        assert_eq!((moved.retired.clone(), moved.unreached.len()), (vec![host.id()], 0));
        gone(&format!("{}/app/{app}/", host.url)).await?;
        served(&format!("{}/app/{app}/", other.url), entry).await?;
        Ok(())
    }

    #[test]
    fn app_key_file_roundtrip_and_checks() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let app = create(dir.path(), "Mein Spiel")?;
        let (key, name) = load(dir.path(), &app)?;
        assert_eq!((key.id(), name.as_str()), (&app, "Mein Spiel"));
        assert!(create(dir.path(), "").is_err());
        assert!(create(dir.path(), &"x".repeat(65)).is_err());
        // Another app's file under this ID: refused.
        let other = create(dir.path(), "Andere")?;
        std::fs::copy(app_key_path(dir.path(), &other), app_key_path(dir.path(), &app)).map_err(|e| e.to_string())?;
        assert!(load(dir.path(), &app).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode =
                std::fs::metadata(app_key_path(dir.path(), &other)).map_err(|e| e.to_string())?.permissions().mode();
            assert_eq!(mode & 0o077, 0, "only the owner may read the app key");
        }
        Ok(())
    }

    #[test]
    fn app_keys_are_listed() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        assert!(list(dir.path(), 10)?.is_empty(), "no folder yet");
        let b = create(dir.path(), "Zweite")?;
        let a = create(dir.path(), "Erste")?;
        std::fs::write(dir.path().join(APPS_DIR).join("kaputt.json"), b"{}").map_err(|e| e.to_string())?;
        std::fs::write(dir.path().join(APPS_DIR).join(format!("{}.json", Id::of_sign_key(&[9; 32]))), b"{}")
            .map_err(|e| e.to_string())?;
        let listed = list(dir.path(), 10)?;
        assert_eq!(listed, vec![(a, "Erste".to_owned()), (b, "Zweite".to_owned())]);
        assert_eq!(list(dir.path(), 1)?.len(), 1, "bounded");
        Ok(())
    }
}
