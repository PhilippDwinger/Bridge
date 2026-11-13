//! BridgeControll updates itself (docs/12, ADR 0029).
//!
//! An announcement signed with Paddy's release key ([`RELEASE_KEYS`], `bridge_core::release`) says which file of a
//! GitHub release is the new version - size and SHA-256 per platform. The app checks for it one minute after the start
//! and every 6 hours, takes only a **higher** version, downloads the file next to the program (`<program>.new`),
//! checks size and hash, ends cleanly and [`hand_over`] puts the new file in place: `<program>` → `<program>.old`,
//! `<program>.new` → `<program>`, start, wait until the new version runs (its `instance.json` names it) - or go back
//! to the old one and remember that this version failed.
//!
//! Debug builds take a test source from `BRIDGECONTROLL_UPDATE_TEST` and a fake own version from
//! `BRIDGECONTROLL_TEST_VERSION`; release builds have neither.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bridge_core::encoding::b64_fixed;
use bridge_core::release::{MAX_ANNOUNCEMENT_BYTES, Release, Version, verify_announcement};
use bridge_transport::download::{self, HostRule};
use rand_core::{OsRng, RngCore as _};
use serde_json::{Value, json};

use crate::{App, INSTANCE_FILE, config, now_ms};

/// Paddy's public release keys (in `bridge-node release`, which signs with them; empty: self-update is off).
pub use bridge_node_cli::release::RELEASE_KEYS;
/// Where the announcement lies.
pub const ANNOUNCEMENT_URL: &str =
    "https://raw.githubusercontent.com/PhilippDwinger/Bridge/bridge-4/releases/bridgecontroll.json";
/// Every announced file must lie below this.
pub const FILE_URL_PREFIX: &str = bridge_node_cli::release::RELEASE_BASE;
/// The state file in the app folder.
pub const STATE_FILE: &str = "update.json";
/// First check after the start.
const FIRST_CHECK: Duration = Duration::from_secs(60);
/// Then every 6 hours (± 30 minutes).
const EVERY: Duration = Duration::from_secs(6 * 3600);
const JITTER_SECS: u64 = 30 * 60;
/// Time for the announcement.
const ANNOUNCEMENT_TIMEOUT: Duration = Duration::from_secs(20);
/// Time for the program file.
const FILE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// How long the old version waits for the new one to run.
const START_WAIT: Duration = Duration::from_secs(60);
/// How long a version started after an update waits for the app folder's lock.
pub const LOCK_WAIT: Duration = Duration::from_secs(30);
#[cfg(debug_assertions)]
const TEST_SOURCE_ENV: &str = "BRIDGECONTROLL_UPDATE_TEST";
const TEST_VERSION_ENV: &str = "BRIDGECONTROLL_TEST_VERSION";

/// This system's platform name, if updates exist for it.
#[must_use]
pub fn platform() -> Option<&'static str> {
    if cfg!(all(windows, target_arch = "x86_64")) {
        Some("windows-x86_64")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux-x86_64")
    } else {
        None
    }
}

/// The version of this program (debug builds: `BRIDGECONTROLL_TEST_VERSION` if set).
#[must_use]
pub fn own_version() -> Version {
    #[cfg(debug_assertions)]
    if let Some(fake) = std::env::var(TEST_VERSION_ENV).ok().and_then(|text| Version::parse(&text).ok()) {
        return fake;
    }
    Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Version { major: 0, minor: 0, patch: 0 })
}

/// Where updates come from and who may sign them.
#[derive(Debug, Clone)]
pub struct Source {
    /// URL of the announcement.
    pub announcement: String,
    /// Trusted release keys.
    pub keys: Vec<[u8; 32]>,
    /// Announced files must lie below this.
    pub file_prefix: String,
    /// Hosts the downloads may touch (redirects included).
    pub rule: HostRule,
    /// First check after the start.
    pub first_check: Duration,
}

impl Source {
    /// GitHub and the keys built into the program.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            announcement: ANNOUNCEMENT_URL.into(),
            keys: bridge_node_cli::release::built_in_keys(),
            file_prefix: FILE_URL_PREFIX.into(),
            rule: bridge_node_cli::release::github_rule(),
            first_check: FIRST_CHECK,
        }
    }

    /// A source on this PC (tests): announcement and files at `base` (`http://127.0.0.1:<port>`), signed by `key`.
    #[must_use]
    pub fn local(base: &str, key: [u8; 32], first_check: Duration) -> Self {
        Self {
            announcement: format!("{base}/bridgecontroll.json"),
            keys: vec![key],
            file_prefix: format!("{base}/files/"),
            rule: HostRule { hosts: vec!["127.0.0.1".into()], allow_http: true },
            first_check,
        }
    }

    /// The source the program uses: [`Source::standard`]; debug builds take `BRIDGECONTROLL_UPDATE_TEST`
    /// (`{"base": "http://127.0.0.1:<port>", "key": "<Base64url>", "first_check_ms": n}`) if set.
    #[must_use]
    pub fn for_program() -> Self {
        #[cfg(debug_assertions)]
        if let Some(source) = Self::from_test_env() {
            return source;
        }
        Self::standard()
    }

    #[cfg(debug_assertions)]
    fn from_test_env() -> Option<Self> {
        let text = std::env::var(TEST_SOURCE_ENV).ok()?;
        let value: Value = serde_json::from_str(&text).ok()?;
        let base = value.get("base")?.as_str()?;
        if !base.starts_with("http://127.0.0.1:") {
            return None;
        }
        let key = b64_fixed::<32>(value.get("key")?.as_str()?, "key").ok()?;
        let first = Duration::from_millis(value.get("first_check_ms").and_then(Value::as_u64).unwrap_or(60_000));
        Some(Self::local(base, key, first))
    }

    /// Whether updates are possible at all (a key, a platform).
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.keys.is_empty() && platform().is_some()
    }
}

/// What survives a restart (`update.json`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Saved {
    auto: bool,
    failed: Option<String>,
    last: Option<Value>,
}

impl Default for Saved {
    fn default() -> Self {
        Self { auto: true, failed: None, last: None }
    }
}

fn load_saved(app_dir: &Path) -> Saved {
    let Ok(bytes) = std::fs::read(app_dir.join(STATE_FILE)) else { return Saved::default() };
    let Ok(value) = bridge_core::json::parse_strict(&bytes, 4096) else { return Saved::default() };
    Saved {
        auto: value.get("auto").and_then(Value::as_bool).unwrap_or(true),
        failed: value.get("failed").and_then(Value::as_str).and_then(|v| Version::parse(v).ok()).map(|v| v.to_string()),
        last: value.get("last").filter(|last| last.is_object()).cloned(),
    }
}

fn store_saved(app_dir: &Path, saved: &Saved) -> Result<(), String> {
    let value = json!({"auto": saved.auto, "failed": saved.failed, "last": saved.last});
    config::write_private(&app_dir.join(STATE_FILE), value.to_string().as_bytes())
}

fn edit_saved(app_dir: &Path, edit: impl FnOnce(&mut Saved)) {
    let mut saved = load_saved(app_dir);
    edit(&mut saved);
    if let Err(error) = store_saved(app_dir, &saved) {
        tracing::warn!(%error, "update.json");
    }
}

/// A downloaded, checked new version waiting for the app to end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The checked file (`<program>.new`).
    pub file: PathBuf,
    /// Its version.
    pub version: Version,
    /// The version running now.
    pub from: Version,
    /// Installed without anyone asking (then no browser opens afterwards).
    pub auto: bool,
}

#[derive(Debug, Default)]
struct State {
    checking: bool,
    installing: bool,
    checked_at: Option<i64>,
    available: Option<Release>,
    error: Option<String>,
}

/// The app's update state.
#[derive(Debug)]
pub struct Updater {
    source: Source,
    state: Mutex<State>,
    saved: Mutex<Saved>,
    pending: Mutex<Option<Pending>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Updater {
    /// The updater of an app folder.
    #[must_use]
    pub fn new(source: Source, app_dir: &Path) -> Self {
        Self {
            source,
            state: Mutex::new(State::default()),
            saved: Mutex::new(load_saved(app_dir)),
            pending: Mutex::new(None),
        }
    }

    /// The new version waiting to be put in place (taken once, by the program after the app ended).
    pub fn take_pending(&self) -> Option<Pending> {
        lock(&self.pending).take()
    }

    /// For the UI (docs/12 §7).
    #[must_use]
    pub fn status(&self) -> Value {
        let state = lock(&self.state);
        let saved = lock(&self.saved).clone();
        let available = state.available.as_ref().map(|release| {
            let size = platform().and_then(|p| release.file(p)).map(|file| file.size);
            json!({"version": release.version.to_string(), "notes": release.notes, "size": size})
        });
        json!({
            "version": own_version().to_string(),
            "platform": platform(),
            "enabled": self.source.enabled(),
            "auto": saved.auto,
            "checking": state.checking,
            "installing": state.installing,
            "checked_at": state.checked_at,
            "available": available,
            "error": state.error,
            "last": saved.last,
            "failed": saved.failed,
        })
    }
}

/// The newest announced version for this system, if it is higher than this one.
async fn latest(source: &Source) -> Result<Option<Release>, String> {
    if source.keys.is_empty() {
        return Err("Noch kein Update-Schlüssel im Programm".into());
    }
    let platform = platform().ok_or("Für dieses System gibt es keine Updates")?;
    let bytes = download::fetch(&source.announcement, &source.rule, MAX_ANNOUNCEMENT_BYTES, ANNOUNCEMENT_TIMEOUT)
        .await
        .map_err(|e| format!("Update-Ankündigung nicht erreichbar: {e}"))?;
    let (release, _) = verify_announcement(&bytes, &source.keys, now_ms())
        .map_err(|e| format!("Update-Ankündigung abgelehnt: {e}"))?;
    if release.version <= own_version() {
        return Ok(None);
    }
    let Some(file) = release.file(platform) else { return Ok(None) };
    if !file.url.starts_with(&source.file_prefix) {
        return Err("Update-Ankündigung abgelehnt: die Datei liegt nicht bei Bridge auf GitHub".into());
    }
    Ok(Some(release))
}

/// Looks for a new version now.
pub async fn check(app: &App) -> Result<Value, String> {
    let updater = &app.updater;
    {
        let mut state = lock(&updater.state);
        if state.checking || state.installing {
            drop(state);
            return Ok(updater.status());
        }
        state.checking = true;
    }
    let result = latest(&updater.source).await;
    let mut state = lock(&updater.state);
    state.checking = false;
    state.checked_at = Some(now_ms());
    match result {
        Ok(found) => {
            state.available = found;
            state.error = None;
        }
        Err(error) => {
            tracing::info!(%error, "Update-Suche");
            state.error = Some(error.clone());
            drop(state);
            return Err(error);
        }
    }
    drop(state);
    Ok(updater.status())
}

/// `<program><suffix>` next to the program.
#[must_use]
pub fn beside(program: &Path, suffix: &str) -> PathBuf {
    let mut name = program.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Downloads and checks the announced version, then ends the app so that [`hand_over`] puts it in place.
pub async fn install(app: &App, auto: bool) -> Result<Value, String> {
    let program = app.options.program.clone().ok_or("Dieses Programm aktualisiert sich nicht selbst")?;
    let updater = &app.updater;
    if lock(&updater.state).available.is_none() {
        check(app).await?;
    }
    let release = {
        let mut state = lock(&updater.state);
        if state.installing || state.checking {
            return Err("Läuft schon".into());
        }
        let release = state.available.clone().ok_or("BridgeControll ist aktuell")?;
        state.installing = true;
        release
    };
    let result = fetch_file(&updater.source, &program, &release).await;
    let mut state = lock(&updater.state);
    match result {
        Ok(file) => {
            *lock(&updater.pending) = Some(Pending { file, version: release.version, from: own_version(), auto });
            drop(state);
            tracing::info!(version = %release.version, "Update geladen und geprüft - BridgeControll startet neu");
            app.quit.notify_waiters();
            app.quit.notify_one();
            Ok(updater.status())
        }
        Err(error) => {
            state.installing = false;
            state.error = Some(error.clone());
            Err(error)
        }
    }
}

async fn fetch_file(source: &Source, program: &Path, release: &Release) -> Result<PathBuf, String> {
    let platform = platform().ok_or("Für dieses System gibt es keine Updates")?;
    let file = release.file(platform).ok_or("Für dieses System gibt es keine Datei")?;
    if !file.url.starts_with(&source.file_prefix) {
        return Err("Die Datei liegt nicht bei Bridge auf GitHub".into());
    }
    let target = beside(program, ".new");
    let _ = std::fs::remove_file(&target);
    let hash = download::download_to(&file.url, &source.rule, &target, file.size, FILE_TIMEOUT).await.map_err(|e| {
        let folder = program.parent().map(|dir| dir.display().to_string()).unwrap_or_default();
        if matches!(e, bridge_transport::TransportError::Config(_)) {
            format!(
                "BridgeControll liegt in einem Ordner, in den es nicht schreiben darf ({folder}) - leg es in einen \
                 eigenen Ordner (z. B. Dokumente\\BridgeControll): {e}"
            )
        } else {
            format!("Laden ging nicht: {e}")
        }
    })?;
    if hash != file.sha256 {
        let _ = std::fs::remove_file(&target);
        return Err("Die geladene Datei passt nicht zur Unterschrift - verworfen".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("{}: {e}", target.display()))?;
    }
    Ok(target)
}

/// Switches automatic updates on or off.
pub fn set_auto(app: &App, on: bool) -> Result<Value, String> {
    let mut saved = lock(&app.updater.saved);
    saved.auto = on;
    store_saved(&app.options.app_dir, &saved)?;
    drop(saved);
    Ok(app.updater.status())
}

/// Checks after the first minute and every 6 hours; with "automatisch" a new version (not one that failed before) is
/// installed right away.
pub async fn background(app: Arc<App>) {
    if !app.updater.source.enabled() || app.options.program.is_none() {
        return;
    }
    tokio::time::sleep(app.updater.source.first_check).await;
    loop {
        if check(&app).await.is_ok() {
            let available = lock(&app.updater.state).available.as_ref().map(|release| release.version.to_string());
            let saved = lock(&app.updater.saved).clone();
            if let Some(version) = available.filter(|version| saved.auto && saved.failed.as_ref() != Some(version)) {
                match install(&app, true).await {
                    Ok(_) => return,
                    Err(error) => tracing::warn!(%error, %version, "automatisches Update"),
                }
            }
        }
        let jitter = OsRng.next_u64() % (2 * JITTER_SECS);
        tokio::time::sleep(EVERY + Duration::from_secs(jitter) - Duration::from_secs(JITTER_SECS)).await;
    }
}

/// Called by a version started with `--after-update <from>` before the app starts: removes `<program>.old` (if it can)
/// and notes the update (not after going back: then `from` is this version).
pub fn after_update(program: &Path, app_dir: &Path, from: &str) {
    let _ = std::fs::remove_file(beside(program, ".old"));
    let to = own_version().to_string();
    if from == to {
        return;
    }
    edit_saved(app_dir, |saved| {
        saved.last = Some(json!({"from": from, "to": to, "ok": true, "at": now_ms()}));
        if saved.failed.as_deref() == Some(to.as_str()) {
            saved.failed = None;
        }
    });
}

/// The version an `instance.json` names (written by every running app).
fn running_version(app_dir: &Path) -> Option<String> {
    let bytes = std::fs::read(app_dir.join(INSTANCE_FILE)).ok()?;
    let value = bridge_core::json::parse_strict(&bytes, 4096).ok()?;
    value.get("version").and_then(Value::as_str).map(str::to_owned)
}

/// How a hand-over ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandOver {
    /// The new version runs.
    Started,
    /// It did not start; the old version is back in place and running again.
    WentBack(String),
}

/// Puts the new version in place after the app ended (lock released): renames, starts it with `args` (the app's own
/// arguments) plus `--after-update <from>`, and waits until it runs; otherwise goes back (docs/12 §4-5).
pub async fn hand_over(program: &Path, app_dir: &Path, args: &[String], pending: &Pending) -> HandOver {
    let old = beside(program, ".old");
    let mut args: Vec<String> = strip_after_update(args);
    args.push("--after-update".into());
    args.push(pending.from.to_string());
    if pending.auto && !args.iter().any(|arg| arg == "--no-browser" || arg == "--autostart") {
        args.push("--no-browser".into());
    }
    let (from, to) = (pending.from.to_string(), pending.version.to_string());
    // A file that could not be moved (a virus scanner holds it, …) is not the new version's fault: no "failed" then.
    let (why, its_fault) = match swap_in(program, &old, &pending.file) {
        Err(error) => (error, false),
        Ok(()) => match spawn(program, &args, true) {
            Err(error) => (format!("Start: {error}"), true),
            Ok(mut child) => match wait_for(&mut child, app_dir, &to).await {
                Ok(()) => return HandOver::Started,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    (error, true)
                }
            },
        },
    };
    tracing::error!(%why, version = %to, "Update ging schief - zurück zur alten Version");
    go_back(program, &old, &pending.file);
    edit_saved(app_dir, |saved| {
        if its_fault {
            saved.failed = Some(to.clone());
        }
        saved.last = Some(json!({"from": from, "to": to, "ok": false, "at": now_ms(), "why": why}));
    });
    if let Err(error) = spawn(program, &args, false) {
        tracing::error!(%error, "alte Version startet nicht wieder");
    }
    HandOver::WentBack(why)
}

fn strip_after_update(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--after-update" {
            let _ = iter.next();
        } else {
            out.push(arg.clone());
        }
    }
    out
}

/// `std::fs::rename`, tried for up to 5 s (Windows: a virus scanner or a process that is just ending may hold the
/// file for a moment).
fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut tries = 0;
    loop {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(error) if tries >= 20 || error.kind() == std::io::ErrorKind::NotFound => return Err(error),
            Err(_) => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

fn swap_in(program: &Path, old: &Path, new: &Path) -> Result<(), String> {
    if old.exists() && std::fs::remove_file(old).is_err() {
        // Windows: an old version may still be running from there - move it aside.
        let aside = beside(program, &format!(".old-{}", now_ms()));
        rename(old, &aside).map_err(|e| format!("{}: {e}", old.display()))?;
    }
    rename(program, old).map_err(|e| format!("{} → .old: {e}", program.display()))?;
    if let Err(error) = rename(new, program) {
        if let Err(back) = rename(old, program) {
            tracing::error!(%back, "alte Version zurückholen");
        }
        return Err(format!(".new → {}: {error}", program.display()));
    }
    Ok(())
}

fn go_back(program: &Path, old: &Path, new: &Path) {
    if old.exists() {
        let bad = beside(program, ".bad");
        let _ = std::fs::remove_file(&bad);
        if program.exists() {
            if let Err(error) = rename(program, &bad) {
                tracing::error!(%error, "neue Version beiseite legen");
            }
        }
        if let Err(error) = rename(old, program) {
            tracing::error!(%error, "alte Version zurückholen");
        }
    }
    let _ = std::fs::remove_file(new);
}

/// Starts `program` with `args`; `new_version`: the new program (a fake version of the old one is not passed on).
fn spawn(program: &Path, args: &[String], new_version: bool) -> std::io::Result<std::process::Child> {
    let mut command = std::process::Command::new(program);
    if new_version {
        command.env_remove(TEST_VERSION_ENV);
    }
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command.spawn()
}

async fn wait_for(child: &mut std::process::Child, app_dir: &Path, version: &str) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + START_WAIT;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("die neue Version hat sich gleich beendet ({status})"));
        }
        if running_version(app_dir).as_deref() == Some(version) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(format!("die neue Version lief nach {} s noch nicht", START_WAIT.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_for_the_new_version() {
        let args: Vec<String> =
            ["--port", "8000", "--after-update", "0.0.1", "--data", "/x"].map(String::from).to_vec();
        assert_eq!(strip_after_update(&args), ["--port", "8000", "--data", "/x"].map(String::from).to_vec());
        assert_eq!(beside(Path::new("/a/bridgecontroll.exe"), ".new"), PathBuf::from("/a/bridgecontroll.exe.new"));
    }

    #[test]
    fn files_are_swapped_and_swapped_back() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let (program, old, new) =
            (dir.path().join("bc.exe"), dir.path().join("bc.exe.old"), dir.path().join("bc.exe.new"));
        let read = |path: &Path| std::fs::read(path).map_err(|e| e.to_string());
        std::fs::write(&program, b"alt").map_err(|e| e.to_string())?;
        std::fs::write(&old, b"noch aelter").map_err(|e| e.to_string())?;
        // Without the new file nothing changes.
        assert!(swap_in(&program, &old, &new).is_err());
        assert_eq!(read(&program)?, b"alt");
        std::fs::write(&new, b"neu").map_err(|e| e.to_string())?;
        swap_in(&program, &old, &new)?;
        assert_eq!((read(&program)?, read(&old)?), (b"neu".to_vec(), b"alt".to_vec()));
        assert!(!new.exists());
        go_back(&program, &old, &new);
        assert_eq!((read(&program)?, read(&beside(&program, ".bad"))?), (b"alt".to_vec(), b"neu".to_vec()));
        assert!(!old.exists());
        Ok(())
    }

    #[test]
    fn the_standard_source_is_github_only() {
        let source = Source::standard();
        assert!(source.announcement.starts_with("https://raw.githubusercontent.com/PhilippDwinger/Bridge/"));
        assert!(!source.rule.allow_http);
        assert_eq!(source.keys.len(), RELEASE_KEYS.len(), "every built-in key is valid");
    }

    #[test]
    fn saved_state_survives_and_bad_files_fall_back() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        assert_eq!(load_saved(dir.path()), Saved::default());
        std::fs::write(dir.path().join(STATE_FILE), b"{kaputt").map_err(|e| e.to_string())?;
        assert_eq!(load_saved(dir.path()), Saved::default());
        let saved = Saved { auto: false, failed: Some("0.2.0".into()), last: Some(json!({"from": "0.1.0"})) };
        store_saved(dir.path(), &saved)?;
        assert_eq!(load_saved(dir.path()), saved);
        std::fs::write(dir.path().join(STATE_FILE), br#"{"auto":false,"failed":"x.y","last":7}"#)
            .map_err(|e| e.to_string())?;
        assert_eq!(load_saved(dir.path()), Saved { auto: false, failed: None, last: None });
        Ok(())
    }
}
