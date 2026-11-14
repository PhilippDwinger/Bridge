//! "Website hochladen" in the owner dashboard (docs/07 §8a, ADR 0017 Nachtrag 4): a folder of this PC becomes a Bridge
//! app - the same library functions as `bridge-node app create|publish` ([`bridge_node_cli::apps`]), run in the owner
//! node's folder. User-facing texts are German.
//!
//! - The folder is checked first, counted exactly like the upload counts it (no symbolic links, at most 16 levels,
//!   10,000 files, 4 GiB, names after docs/07 §3, the start file present). Nothing is read but names and sizes - and
//!   the first bytes of a `.json` file below a folder `apps` (is it an app key?).
//! - **Never publish keys**: a folder inside BridgeControll's app folder or containing it (both resolved) is refused,
//!   and so is any folder with `admin-key.json`, `owner-key.json`, `node-key.json` or an app key anywhere below it.
//! - The owner node hosts: without a `web` seal it is sealed again (level 3, its services + `web`, its own card). The
//!   member key of this PC gets level 2 first (like for names), so the site shows in the safe search.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bridge_core::Id;
use bridge_core::app::{MAX_APP_BYTES, MAX_APP_DESCRIPTION_CHARS, MAX_APP_FILES, MAX_APP_NAME_CHARS, check_path};
use bridge_net::names::check_name;
use bridge_net::statements::check_text;
use bridge_net::{Service, Services, is_web_host};
use bridge_node::admin::{ADMIN_KEY_FILE, AdminClient};
use bridge_node::keyfile::KEY_FILE;
use bridge_node_cli::apps::{APPS_DIR, OWNER_KEY_FILE};
use serde_json::{Map, Value, json};

use crate::browser::reader_origin;
use crate::config::NodeEntry;
use crate::ops::{admin_client, entry_of, patient};
use crate::{App, now_ms};

/// Longest folder path accepted.
pub const MAX_FOLDER_CHARS: usize = 1024;
/// Deepest folder level below the chosen one (like the upload).
const MAX_DEPTH: usize = 16;
/// Most directory entries looked at in one check (files and folders) - a folder of millions is refused, not walked.
const MAX_ENTRIES: usize = 4 * MAX_APP_FILES;
/// Names of disallowed files shown.
const MAX_BAD_SHOWN: usize = 5;
/// Files that hold secret keys of a node folder: a folder with one of them anywhere below is never published.
pub const KEY_FILES: [&str; 3] = [ADMIN_KEY_FILE, OWNER_KEY_FILE, KEY_FILE];
/// Bytes read of a `.json` below a folder `apps` to see whether it is an app key.
const KEY_SNIFF_BYTES: usize = 512;
/// How long a fresh seal of the owner node may take until its log counts it.
const SEAL_WAIT: Duration = Duration::from_secs(20);

fn text<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or_default()
}

/// The folder from the field: trimmed, without the quotes of Explorer's "Als Pfad kopieren", absolute.
pub fn folder_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    let unquoted = trimmed.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).unwrap_or(trimmed).trim();
    if unquoted.is_empty() {
        return Err("Bitte den Ordner der Website angeben.".into());
    }
    if unquoted.chars().count() > MAX_FOLDER_CHARS || unquoted.chars().any(char::is_control) {
        return Err("Ordner: höchstens 1.024 Zeichen, keine Steuerzeichen.".into());
    }
    let path = PathBuf::from(unquoted);
    if !path.is_absolute() {
        return Err("Ordner: bitte den ganzen Pfad, z. B. C:\\Users\\name\\Documents\\MeineSeite".into());
    }
    Ok(path)
}

/// The start file: `index.html` unless given; a path after docs/07 §3.
fn start_file(body: &Map<String, Value>) -> Result<String, String> {
    let start = match text(body, "entry").trim() {
        "" => "index.html",
        other => other,
    };
    check_path(start).map_err(|_| "Startdatei: nur a-z A-Z 0-9 . _ - und /, z. B. index.html".to_owned())?;
    Ok(start.to_owned())
}

/// The folder resolved, if it may be published at all: it exists, is a folder, and is neither inside BridgeControll's
/// app folder (keys of every node) nor contains it.
pub fn guard(folder: &Path, app_dir: &Path) -> Result<PathBuf, String> {
    let resolved =
        std::fs::canonicalize(folder).map_err(|_| format!("Den Ordner {} gibt es nicht.", folder.display()))?;
    if !resolved.is_dir() {
        return Err(format!("{} ist kein Ordner.", folder.display()));
    }
    // The app folder exists while the app runs; if it cannot be resolved, its path as given is compared.
    let app_dir = std::fs::canonicalize(app_dir).unwrap_or_else(|_| app_dir.to_path_buf());
    if resolved.starts_with(&app_dir) || app_dir.starts_with(&resolved) {
        return Err(
            "Dieser Ordner enthält die Schlüssel von BridgeControll oder liegt darin - so ein Ordner wird nie \
                    veröffentlicht. Bitte einen eigenen Ordner nur mit der Website wählen."
                .into(),
        );
    }
    Ok(resolved)
}

/// What a folder holds, counted like the upload counts it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FolderInfo {
    /// Regular files (symbolic links are skipped).
    pub files: usize,
    /// Their size together.
    pub bytes: u64,
    /// The start file is there.
    pub entry: bool,
    /// The first file paths that are not allowed (docs/07 §3).
    pub bad: Vec<String>,
    /// How many are not allowed.
    pub bad_total: usize,
    /// A key file below the folder (its path) - never published.
    pub key: Option<String>,
}

impl FolderInfo {
    /// What stops an upload (German, most important first). Empty: the folder may go.
    #[must_use]
    pub fn problems(&self, start: &str) -> Vec<String> {
        let mut problems = Vec::new();
        if let Some(key) = &self.key {
            problems.push(format!(
                "Im Ordner liegt eine Schlüssel-Datei ({key}) - so ein Ordner wird nie veröffentlicht. Bitte einen \
                 Ordner nur mit der Website wählen."
            ));
        }
        if self.files == 0 {
            problems.push("Der Ordner ist leer.".into());
        } else if !self.entry {
            problems.push(format!("Die Startdatei „{start}“ fehlt im Ordner."));
        }
        if self.bad_total > 0 {
            let more = if self.bad_total > self.bad.len() { " …" } else { "" };
            problems.push(format!(
                "{} Dateiname(n) nicht erlaubt (nur a-z A-Z 0-9 . _ -, keine Leerzeichen oder Umlaute): {}{more}",
                self.bad_total,
                self.bad.join(", ")
            ));
        }
        if self.bytes > MAX_APP_BYTES {
            problems.push("Zusammen mehr als 4 GiB.".into());
        }
        problems
    }
}

/// Walks the (resolved) folder: files, size, start file, disallowed names, key files. Bounded: at most
/// [`MAX_ENTRIES`] entries, [`MAX_APP_FILES`] files, [`MAX_DEPTH`] levels - more is an error, not a long walk.
pub fn scan(folder: &Path, start: &str) -> Result<FolderInfo, String> {
    fn walk(
        dir: &Path,
        prefix: &str,
        depth: usize,
        seen: &mut usize,
        info: &mut FolderInfo,
        start: &str,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(format!("Mehr als {MAX_DEPTH} Ordner-Ebenen ({prefix})."));
        }
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            *seen += 1;
            if *seen > MAX_ENTRIES {
                return Err(format!("Mehr als {MAX_ENTRIES} Einträge - das ist kein Website-Ordner."));
            }
            let kind = entry.file_type().map_err(|e| format!("{}: {e}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            if kind.is_symlink() {
                continue; // the upload never follows links out of the folder
            }
            if kind.is_dir() {
                walk(&entry.path(), &path, depth + 1, seen, info, start)?;
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            info.files += 1;
            if info.files > MAX_APP_FILES {
                return Err("Mehr als 10.000 Dateien.".into());
            }
            info.bytes = info.bytes.saturating_add(entry.metadata().map(|meta| meta.len()).unwrap_or(0));
            if path == start {
                info.entry = true;
            }
            if check_path(&path).is_err() {
                info.bad_total += 1;
                if info.bad.len() < MAX_BAD_SHOWN {
                    info.bad.push(path.clone());
                }
            }
            if info.key.is_none() && is_key_file(&entry.path(), &name, prefix) {
                info.key = Some(path);
            }
        }
        Ok(())
    }
    let mut info = FolderInfo::default();
    let mut seen = 0;
    walk(folder, "", 0, &mut seen, &mut info, start)?;
    Ok(info)
}

/// A node key file by name, or an app key (`apps/<id>.json` with `"t":"app-key"` in its first bytes).
fn is_key_file(path: &Path, name: &str, parent: &str) -> bool {
    if KEY_FILES.iter().any(|key| name.eq_ignore_ascii_case(key)) {
        return true;
    }
    let in_apps = parent.rsplit('/').next().is_some_and(|last| last.eq_ignore_ascii_case(APPS_DIR));
    if !in_apps || !name.to_ascii_lowercase().ends_with(".json") {
        return false;
    }
    let mut head = vec![0u8; KEY_SNIFF_BYTES];
    let read = std::fs::File::open(path).and_then(|mut file| file.read(&mut head)).unwrap_or(0);
    let head = String::from_utf8_lossy(&head[..read]).replace(char::is_whitespace, "");
    head.contains("\"t\":\"app-key\"")
}

/// The folder as JSON for the dialog.
fn folder_json(info: &FolderInfo, start: &str) -> Value {
    let problems = info.problems(start);
    json!({
        "ok": problems.is_empty(),
        "files": info.files,
        "bytes": info.bytes,
        "entry": info.entry,
        "bad": info.bad,
        "bad_total": info.bad_total,
        "problems": problems,
    })
}

/// Checks the folder of `body` (`folder`, `entry`) off the async threads.
async fn checked_folder(app: &App, body: &Map<String, Value>) -> Result<(PathBuf, FolderInfo, String), String> {
    let start = start_file(body)?;
    let folder = folder_path(text(body, "folder"))?;
    let app_dir = app.options.app_dir.clone();
    let start_name = start.clone();
    let (resolved, info) = tokio::task::spawn_blocking(move || {
        let resolved = guard(&folder, &app_dir)?;
        let info = scan(&resolved, &start_name)?;
        Ok::<_, String>((resolved, info))
    })
    .await
    .map_err(|e| e.to_string())??;
    Ok((resolved, info, start))
}

/// `POST /api/nodes/<id>/site-check` `{"folder","entry"?}`: what the folder holds and what stops an upload.
pub async fn check(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    admin_client(app, &entry)?;
    let (_, info, start) = checked_folder(app, body).await?;
    Ok(folder_json(&info, &start))
}

/// Makes the owner node a web host if it is none: sealed again with level 3, its services + `web` and its own card,
/// then waits until its log counts the seal. Returns whether it sealed.
async fn web_host_ready(entry: &NodeEntry, admin: &AdminClient) -> Result<bool, String> {
    let node = admin.node_id().clone();
    let (_, state) = patient(|| admin.load_state()).await?;
    if is_web_host(&state, &node, now_ms()) {
        return Ok(false);
    }
    let services = state.services(&node, now_ms()).union(Services::of(&[Service::Web]));
    let local = entry.local_url();
    let card = patient(|| admin.fetch_node_card(&local)).await?;
    patient(|| admin.seal_card(card.clone(), &node, 3, services)).await?;
    let deadline = tokio::time::Instant::now() + SEAL_WAIT;
    loop {
        let (_, state) = patient(|| admin.load_state()).await?;
        if is_web_host(&state, &node, now_ms()) {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("Das neue Siegel des Owner-Knotens (Dienst Websites) zählt noch nicht - bitte gleich noch \
                        einmal hochladen."
                .into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// `POST /api/nodes/<id>/site-publish` `{"folder","name"|"app","entry"?,"description"?,"address"?}`: a new app from
/// the folder (`name`) or a new version of an app of the owner folder (`app`); optionally a name for it.
pub async fn publish(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let checked = checked_request(app, id, body).await?;
    let (folder, info, start) = checked_folder(app, body).await?;
    if let Some(problem) = info.problems(&start).into_iter().next() {
        return Err(problem);
    }
    publish_folder(app, id, checked, &folder, &info, &start).await
}

/// What a publish request names besides the folder, checked: description, address, existing app or new name.
pub(crate) struct Checked {
    description: String,
    address: String,
    existing: Option<Id>,
    name: String,
}

/// Checks the inputs of a publish request (`description`, `address`, `app` of the owner folder, else `name`) -
/// nothing changes in the network for a form with a mistake.
pub(crate) async fn checked_request(app: &App, id: &str, body: &Map<String, Value>) -> Result<Checked, String> {
    let entry = entry_of(app, id).await?;
    admin_client(app, &entry)?;
    let dir = app.node_dir(&entry);
    let description = text(body, "description").trim().to_owned();
    check_text(&description, 0, MAX_APP_DESCRIPTION_CHARS, false, "description")
        .map_err(|_| "Beschreibung: höchstens 500 Zeichen, eine Zeile".to_owned())?;
    let address = text(body, "address").trim().to_ascii_lowercase();
    if !address.is_empty() {
        check_name(&address).map_err(|_| {
            "Adresse: 2-40 Zeichen a-z, 0-9 und -, nicht mit - beginnend oder endend, kein --".to_owned()
        })?;
    }
    let existing = match text(body, "app").trim() {
        "" => None,
        raw => {
            let app_id = Id::parse(raw).map_err(|_| "keine App-ID".to_owned())?;
            let keys = crate::moderation::app_keys(&dir).await;
            if !keys.iter().any(|key| key["id"] == json!(app_id.as_str())) {
                return Err("Diese App hat ihren Schlüssel nicht im Ordner des Owner-Knotens.".into());
            }
            Some(app_id)
        }
    };
    let name = text(body, "name").trim().to_owned();
    if existing.is_none() {
        let count = name.chars().count();
        if count == 0 || count > MAX_APP_NAME_CHARS || name.chars().any(char::is_control) {
            return Err(format!("Name der Website: 1-{MAX_APP_NAME_CHARS} Zeichen"));
        }
    }
    Ok(Checked { description, address, existing, name })
}

/// The network side of a publish: member key level 2, the owner node a web host, then the app key, the upload of
/// `folder` (start file `start`) and the address.
pub(crate) async fn publish_folder(
    app: &App,
    id: &str,
    checked: Checked,
    folder: &Path,
    info: &FolderInfo,
    start: &str,
) -> Result<Value, String> {
    let Checked { description, address, existing, name } = checked;
    let entry = entry_of(app, id).await?;
    let admin = admin_client(app, &entry)?;
    let dir = app.node_dir(&entry);
    crate::moderation::operator_ready(app, &entry, &admin).await?;
    let resealed = web_host_ready(&entry, &admin).await?;
    let (app_id, new) = match existing {
        Some(app_id) => (app_id, false),
        None => {
            let (key_dir, key_name) = (dir.clone(), name.clone());
            let created = tokio::task::spawn_blocking(move || bridge_node_cli::apps::create(&key_dir, &key_name))
                .await
                .map_err(|e| e.to_string())??;
            (created, true)
        }
    };
    let url = entry.local_url();
    let described = (!description.is_empty()).then_some(description.as_str());
    let done = patient(|| {
        bridge_node_cli::apps::publish(&dir, &app_id, folder, Vec::new(), Some(start), described, Some(&url))
    })
    .await
    .map_err(|error| {
        if new {
            format!("{error} (Die App ist angelegt - „Neue Version“ versucht es noch einmal.)")
        } else {
            error
        }
    })?;

    // The address: a name for the app, like "Name anmelden". The site is published either way.
    let (mut registered, mut address_error) = (Value::Null, Value::Null);
    if !address.is_empty() {
        let mut request = Map::new();
        request.insert("name".into(), json!(address));
        request.insert("target".into(), json!("app"));
        request.insert("app".into(), json!(app_id.as_str()));
        let short: String = description.chars().take(200).collect();
        request.insert("description".into(), json!(short));
        match crate::moderation::register_name(app, id, &request).await {
            Ok(answer) => registered = answer.get("address").cloned().unwrap_or(Value::Null),
            Err(error) => address_error = json!(error),
        }
    }
    Ok(json!({
        "ok": true,
        "app": app_id.as_str(),
        "new": new,
        "version": done.version,
        "active": done.active,
        "files": info.files,
        "bytes": info.bytes,
        "resealed": resealed,
        "address": registered,
        "address_error": address_error,
        "view": reader_origin(&entry).map(|origin| format!("{origin}/app/{app_id}/")),
    }))
}

/// `POST /api/nodes/<id>/site-delete` `{"app"}`: deletes an app of the owner folder in the whole network (docs/07 §10,
/// ADR 0028) - a `retire` entry signed with its key and the owner key, then the app key is gone. Only apps whose key is
/// in the owner node's folder.
pub async fn delete(app: &App, id: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let entry = entry_of(app, id).await?;
    admin_client(app, &entry)?;
    let dir = app.node_dir(&entry);
    let app_id = Id::parse(text(body, "app").trim()).map_err(|_| "keine App-ID".to_owned())?;
    let keys = crate::moderation::app_keys(&dir).await;
    if !keys.iter().any(|key| key["id"] == json!(app_id.as_str())) {
        return Err("Diese App hat ihren Schlüssel nicht im Ordner des Owner-Knotens – löschen kann sie nur, wer den \
                    Schlüssel hat (fremde Apps: „Sperren“)."
            .into());
    }
    let url = entry.local_url();
    let names = patient(|| bridge_node_cli::apps::delete(&dir, &app_id, Some(&url))).await?;
    crate::templates::forget(&dir, &app_id);
    Ok(json!({"ok": true, "app": app_id.as_str(), "names": names}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_default();
        }
        std::fs::write(path, bytes).unwrap_or_default();
    }

    #[test]
    fn folder_paths() {
        let absolute = if cfg!(windows) { r"C:\Users\x\Seite" } else { "/home/x/Seite" };
        assert_eq!(folder_path(absolute), Ok(PathBuf::from(absolute)));
        assert_eq!(folder_path(&format!("  \"{absolute}\"  ")), Ok(PathBuf::from(absolute)), "Als Pfad kopieren");
        for bad in ["", "   ", "\"\"", "Seite", "./Seite", "..\\Seite"] {
            assert!(folder_path(bad).is_err(), "{bad:?}");
        }
        assert!(folder_path(&format!("{absolute}\nx")).is_err(), "control characters");
        assert!(folder_path(&format!("{absolute}{}", "a".repeat(MAX_FOLDER_CHARS))).is_err(), "too long");
    }

    #[test]
    fn scan_counts_like_the_upload() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let site = dir.path().join("Seite");
        write(&site.join("index.html"), b"<h1>Hallo</h1>");
        write(&site.join("css/style.css"), b"body{}");
        write(&site.join("Mein Bild.png"), b"x");
        write(&site.join("bilder/Größe.jpg"), b"xy");
        let info = scan(&site, "index.html")?;
        assert_eq!((info.files, info.bytes, info.entry), (4, 23, true));
        assert_eq!(info.bad_total, 2);
        assert!(info.bad.contains(&"Mein Bild.png".to_owned()) && info.bad.contains(&"bilder/Größe.jpg".to_owned()));
        let problems = info.problems("index.html");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("nicht erlaubt"), "{problems:?}");
        assert!(scan(&site, "start.html")?.problems("start.html")[0].contains("fehlt"));
        let empty = dir.path().join("leer");
        std::fs::create_dir_all(&empty).map_err(|e| e.to_string())?;
        assert_eq!(scan(&empty, "index.html")?.problems("index.html"), vec!["Der Ordner ist leer.".to_owned()]);
        Ok(())
    }

    /// Attack: a folder with keys in it - node keys anywhere below, an app key, BridgeControll's own folder.
    #[test]
    fn keys_are_never_published() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        for key in KEY_FILES {
            let site = dir.path().join(format!("mit-{key}"));
            write(&site.join("index.html"), b"x");
            write(&site.join("tief/drin").join(key.to_uppercase()), b"{}");
            let info = scan(&site, "index.html")?;
            assert!(info.key.is_some() && info.problems("index.html")[0].contains("Schlüssel"), "{key}");
        }
        let site = dir.path().join("mit-app-key");
        write(&site.join("index.html"), b"x");
        write(&site.join("apps/abc.json"), br#"{ "v": 4, "t": "app-key", "app": "x" }"#);
        assert_eq!(scan(&site, "index.html")?.key.as_deref(), Some("apps/abc.json"));
        // An ordinary JSON file in a folder called apps is fine.
        let site = dir.path().join("normal");
        write(&site.join("index.html"), b"x");
        write(&site.join("apps/liste.json"), br#"{"t":"liste"}"#);
        assert_eq!(scan(&site, "index.html")?.key, None);
        // BridgeControll's app folder: neither inside nor around it.
        let app_dir = dir.path().join("BridgeControll2");
        write(&app_dir.join("nodes/n1/index.html"), b"x");
        assert!(guard(&app_dir.join("nodes/n1"), &app_dir).is_err(), "inside");
        assert!(guard(dir.path(), &app_dir).is_err(), "around");
        assert!(guard(&app_dir, &app_dir).is_err(), "itself");
        assert!(guard(&dir.path().join("normal"), &app_dir).is_ok());
        assert!(guard(&dir.path().join("fehlt"), &app_dir).is_err(), "missing");
        assert!(guard(&dir.path().join("normal/index.html"), &app_dir).is_err(), "a file");
        Ok(())
    }

    /// Attack: endless folders - too deep or too many entries is an error, not a long walk.
    #[test]
    fn scans_are_bounded() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let mut deep = dir.path().join("tief");
        for level in 0..=MAX_DEPTH + 1 {
            deep = deep.join(format!("e{level}"));
        }
        write(&deep.join("a.txt"), b"x");
        assert!(scan(&dir.path().join("tief"), "index.html").is_err_and(|e| e.contains("Ebenen")));
        #[cfg(unix)]
        {
            // A link out of the folder is not followed (like the upload).
            let site = dir.path().join("link");
            write(&site.join("index.html"), b"x");
            std::os::unix::fs::symlink(dir.path(), site.join("raus")).map_err(|e| e.to_string())?;
            assert_eq!(scan(&site, "index.html")?.files, 1);
        }
        Ok(())
    }
}
