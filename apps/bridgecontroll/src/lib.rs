//! # BridgeControll v2 – the desktop control app for Bridge 4 / BridgeNet
//!
//! A local web app (ADR 0017): this program serves its screens on `127.0.0.1` only and opens the default browser.
//! It creates networks (assistant "Neues BridgeNet"), joins networks with a link, runs every node of this PC as its
//! own process (the same program in node mode, watched by [`supervisor`]) and shows the owner dashboard (seals,
//! members, invites, apps, names, reports, transparency log). Admin actions use the admin key in the owner node's
//! folder exactly like `bridge-node net …` / `name …` ([`bridge_node::admin`], [`moderation`]). The Bridge-Browser
//! ([`browser`]) opens `shop.meinnetz` through the user's own node, which checks everything itself.
//!
//! Zero Trust also on this PC ([`http`]): a random session (256 bit) handed over once with a one-time login link,
//! then an `HttpOnly` / `SameSite=Strict` cookie; strict `Host` check (DNS rebinding), `Origin` check on every change
//! (CSRF), no CORS, CSP `default-src 'self'`, bounded bodies, no secrets in logs. The 24 words of a new network are
//! shown once (in the answer of one POST) and never stored ([`wizard`]).
//!
//! Layering (docs/03): an app on top - it uses `bridge-node` (admin, key files), `bridge-net` (state from the log),
//! `bridge-core`, `bridge-transport` (HTTP client to the local nodes) and the node program's library.

pub mod api;
pub mod assets;
pub mod autostart;
pub mod browser;
pub mod config;
pub mod http;
pub mod logfile;
pub mod moderation;
pub mod ops;
pub mod qr;
pub mod sites;
pub mod status;
pub mod supervisor;
pub mod wizard;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::config::{AppConfig, NodeEntry};
use crate::http::Auth;
use crate::status::Poller;
use crate::supervisor::{Backoff, Launch, Supervisor};
use crate::wizard::Wizards;

/// Default port of the control UI.
pub const DEFAULT_PORT: u16 = 7380;
/// File in the app folder that lets a second start find the running app (port + launch key, owner-only).
pub const INSTANCE_FILE: &str = "instance.json";
/// File in the app folder the running app holds an exclusive lock on for its whole life (review 8).
pub const LOCK_FILE: &str = "instance.lock";
/// Owner-only page in the app folder that forwards the browser to a login link (review 8: no code on a command line).
pub const LOGIN_PAGE: &str = "login.html";
/// A login page is removed after this long (its code works once and for 5 minutes anyway).
const LOGIN_PAGE_TTL: Duration = Duration::from_secs(120);
/// Folder of the node logs inside the app folder.
pub const LOGS_DIR: &str = "logs";
/// Folder where deleted nodes are moved (key files are never deleted silently).
pub const BACKUP_DIR: &str = "backup";

/// Milliseconds since 1970.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)).unwrap_or(0)
}

/// The default app folder: `%APPDATA%\BridgeControll2` on Windows, `~/.local/share/bridgecontroll2` elsewhere
/// (`$XDG_DATA_HOME/bridgecontroll2` if set).
pub fn default_app_dir() -> Result<PathBuf, String> {
    if cfg!(windows) {
        let appdata = std::env::var_os("APPDATA").ok_or("APPDATA ist nicht gesetzt")?;
        return Ok(PathBuf::from(appdata).join("BridgeControll2"));
    }
    if let Some(data) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|path| path.is_absolute()) {
        return Ok(data.join("bridgecontroll2"));
    }
    let home = std::env::var_os("HOME").ok_or("HOME ist nicht gesetzt")?;
    Ok(PathBuf::from(home).join(".local").join("share").join("bridgecontroll2"))
}

/// How the app runs.
#[derive(Debug, Clone)]
pub struct Options {
    /// The app folder (settings, node folders, logs).
    pub app_dir: PathBuf,
    /// Port of the UI on 127.0.0.1 (0: any free one).
    pub port: u16,
    /// The program started in node mode (normally this program).
    pub node_exe: PathBuf,
    /// Restart timing of the watchdog.
    pub backoff: Backoff,
    /// How often the nodes are asked for their status.
    pub poll_interval: Duration,
    /// Start the nodes marked for autostart.
    pub start_nodes: bool,
    /// Where the "start with the system" entry goes (`None`: the system's place, if any).
    pub autostart_dir: Option<PathBuf>,
    /// The app folder was given explicitly (it then goes into the autostart entry).
    pub custom_app_dir: bool,
}

impl Options {
    /// Defaults for an app folder and this program.
    #[must_use]
    pub fn new(app_dir: PathBuf, node_exe: PathBuf) -> Self {
        Self {
            app_dir,
            port: DEFAULT_PORT,
            node_exe,
            backoff: Backoff::standard(),
            poll_interval: Duration::from_secs(2),
            start_nodes: true,
            autostart_dir: autostart::system_dir(),
            custom_app_dir: false,
        }
    }
}

/// The running app's shared state.
pub struct App {
    /// Options it runs with.
    pub options: Options,
    /// Port of the UI.
    pub port: u16,
    /// Settings (one writer at a time).
    pub config: tokio::sync::Mutex<AppConfig>,
    /// The node processes.
    pub supervisor: Supervisor,
    /// Live status of the nodes.
    pub poller: Poller,
    /// Open assistants (with their words, in memory only).
    pub wizards: Wizards,
    /// Session and login links.
    pub auth: Auth,
    /// The newest invite link per owner node (memory only).
    pub links: Mutex<HashMap<String, String>>,
    /// What was wrong in the settings file at the start (German; the start page shows it).
    pub warnings: Vec<String>,
    /// Signalled when the user ends the app from the UI.
    pub quit: Notify,
}

impl App {
    /// The data folder of a node.
    #[must_use]
    pub fn node_dir(&self, entry: &NodeEntry) -> PathBuf {
        entry.data_dir(&self.options.app_dir)
    }

    /// The log file of a node.
    #[must_use]
    pub fn node_log(&self, id: &str) -> PathBuf {
        self.options.app_dir.join(LOGS_DIR).join(format!("{id}.log"))
    }

    /// Starts a node process (see [`ops::node_args`]); its join link goes into a file in its folder first.
    pub fn start_node(&self, entry: &NodeEntry) {
        if let Err(error) = ops::write_join_link(&self.node_dir(entry), entry.join_link.as_deref()) {
            tracing::warn!(%error, node = %entry.id, "Einladungslink-Datei");
        }
        self.supervisor.start(Launch {
            id: entry.id.clone(),
            args: ops::node_args(entry, &self.node_dir(entry)),
            log: self.node_log(&entry.id),
        });
    }

    /// Where the autostart entry goes, if this system has one.
    #[must_use]
    pub fn autostart_dir(&self) -> Option<&Path> {
        self.options.autostart_dir.as_deref()
    }
}

/// The single-instance lock of an app folder (review 8): an exclusive lock on [`LOCK_FILE`] (flock / LockFileEx), held
/// as long as this value lives. The system frees it when the process ends - also after a crash, so a stale
/// `instance.json` never keeps the app from starting.
pub struct InstanceLock {
    _file: std::fs::File,
}

impl InstanceLock {
    /// Takes the lock of `app_dir` (creates the folder and the owner-only lock file): `Ok(None)` if another app holds
    /// it.
    pub fn acquire(app_dir: &Path) -> Result<Option<Self>, String> {
        std::fs::create_dir_all(app_dir).map_err(|e| format!("{}: {e}", app_dir.display()))?;
        let path = app_dir.join(LOCK_FILE);
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(fs4::TryLockError::WouldBlock) => Ok(None),
            Err(fs4::TryLockError::Error(error)) => Err(format!("{}: {error}", path.display())),
        }
    }
}

/// A running app.
pub struct Running {
    app: Arc<App>,
    addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
    _lock: InstanceLock,
}

impl Running {
    /// Where the UI listens.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// A new one-time login link (valid 5 minutes, works once).
    #[must_use]
    pub fn login_url(&self) -> String {
        format!("http://127.0.0.1:{}/login/{}", self.addr.port(), self.app.auth.new_login_code(now_ms()))
    }

    /// The shared state (tests).
    #[must_use]
    pub fn app(&self) -> &Arc<App> {
        &self.app
    }

    /// Waits until the user ends the app in the UI.
    pub async fn quit_requested(&self) {
        self.app.quit.notified().await;
    }

    /// Stops the UI and all nodes cleanly, removes the instance file and a login page; the lock goes last.
    pub async fn shutdown(self) {
        for task in &self.tasks {
            task.abort();
        }
        self.app.supervisor.stop_all().await;
        let _ = std::fs::remove_file(self.app.options.app_dir.join(INSTANCE_FILE));
        let _ = std::fs::remove_file(self.app.options.app_dir.join(LOGIN_PAGE));
    }
}

/// Starts the app: takes the single-instance lock of its folder (refused while another app holds it), then
/// [`start_locked`].
pub async fn start(options: Options) -> Result<Running, String> {
    let lock = InstanceLock::acquire(&options.app_dir)?
        .ok_or_else(|| format!("BridgeControll läuft schon für {}", options.app_dir.display()))?;
    start_locked(options, lock).await
}

/// Starts the app with its lock held: loads the settings, listens on 127.0.0.1, writes the instance file (a stale one
/// from a crash is simply replaced), starts the status rounds and the nodes marked for autostart.
pub async fn start_locked(options: Options, lock: InstanceLock) -> Result<Running, String> {
    std::fs::create_dir_all(&options.app_dir).map_err(|e| format!("{}: {e}", options.app_dir.display()))?;
    let config::Loaded { mut config, warnings } = AppConfig::load(&options.app_dir)?;
    // Older settings: nodes with a public address get their loopback reader port now (review 9).
    ops::assign_reader_ports(&mut config);
    for warning in &warnings {
        tracing::warn!(%warning, "Einstellungen");
    }
    let listener = bind(options.port).await?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let auth = Auth::new();
    let instance = serde_json::json!({"v": 2, "port": addr.port(), "key": auth.launch_key()}).to_string();
    config::write_private(&options.app_dir.join(INSTANCE_FILE), instance.as_bytes())?;
    let app = Arc::new(App {
        port: addr.port(),
        config: tokio::sync::Mutex::new(config),
        supervisor: Supervisor::new(options.node_exe.clone(), options.backoff),
        poller: Poller::default(),
        wizards: Wizards::default(),
        auth,
        links: Mutex::new(HashMap::new()),
        warnings,
        quit: Notify::new(),
        options,
    });
    if app.options.start_nodes {
        let config = app.config.lock().await;
        for entry in config.nodes.iter().filter(|entry| entry.autostart) {
            app.start_node(entry);
        }
    }
    let tasks = vec![http::serve(listener, Arc::clone(&app)), tokio::spawn(status_rounds(Arc::clone(&app)))];
    tracing::info!(port = addr.port(), "BridgeControll bereit");
    Ok(Running { app, addr, tasks, _lock: lock })
}

/// The UI's listener: the given port (0 = any), or - if taken - the next nine.
async fn bind(port: u16) -> Result<TcpListener, String> {
    if port == 0 {
        return TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| e.to_string());
    }
    let mut last = String::new();
    for candidate in port..port.saturating_add(10) {
        match TcpListener::bind(("127.0.0.1", candidate)).await {
            Ok(listener) => return Ok(listener),
            Err(error) => last = error.to_string(),
        }
    }
    Err(format!("Kein freier Port ab {port} für BridgeControll: {last}"))
}

/// Asks every running node for its status, forever; afterwards the settings follow (a joined node with its log no
/// longer needs the join link).
async fn status_rounds(app: Arc<App>) {
    let mut ticker = tokio::time::interval(app.options.poll_interval.max(Duration::from_millis(100)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let nodes: Vec<NodeEntry> = app.config.lock().await.nodes.clone();
        let mut round = tokio::task::JoinSet::new();
        for entry in nodes {
            if app.supervisor.status(&entry.id).state != supervisor::RunState::Running {
                continue;
            }
            let app = Arc::clone(&app);
            round.spawn(async move { app.poller.poll(&entry.id, &entry.local_url()).await });
        }
        let _ =
            tokio::time::timeout(Duration::from_secs(10), async { while round.join_next().await.is_some() {} }).await;
        round.abort_all();
        ops::housekeeping(&app).await;
        remove_old_login_page(&app.options.app_dir);
    }
}

/// A second start of the app: if one runs already (instance file, launch key), ask it for a new login link - and
/// take the link only if the answer proves the launch key (review 8: a stale instance file may name a port another
/// program listens on now).
pub async fn running_instance(app_dir: &Path) -> Option<String> {
    let bytes = std::fs::read(app_dir.join(INSTANCE_FILE)).ok()?;
    let value = bridge_core::json::parse_strict(&bytes, 4096).ok()?;
    if value.get("v") != Some(&serde_json::json!(2)) {
        return None;
    }
    let port = value.get("port").and_then(serde_json::Value::as_u64).and_then(|port| u16::try_from(port).ok())?;
    let key = zeroize::Zeroizing::new(value.get("key").and_then(serde_json::Value::as_str)?.to_owned());
    ask_for_login(port, &key).await
}

/// Like [`running_instance`], tried for a few seconds: the app that holds the lock may still be starting (its instance
/// file not written yet, or a stale one from before a crash still there).
pub async fn delegate(app_dir: &Path) -> Option<String> {
    for _ in 0..20 {
        if let Some(login) = running_instance(app_dir).await {
            return Some(login);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// `POST /api/launch` to the running instance (a plain HTTP/1.1 request over TCP to 127.0.0.1; bounded): a fresh nonce
/// and the proof `mac(launch key, nonce)` - the key itself never travels. The answer's login path counts only with
/// its code `mac(launch key, nonce, path)`. Returns the login link.
async fn ask_for_login(port: u16, key: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let nonce = http::random_token();
    let proof = http::launch_proof(key, &nonce)?;
    let connect = tokio::net::TcpStream::connect(("127.0.0.1", port));
    let mut stream = tokio::time::timeout(Duration::from_secs(3), connect).await.ok()?.ok()?;
    let request = format!(
        "POST /api/launch HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Launch-Nonce: {}\r\nX-Launch-Proof: {proof}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n",
        nonce.as_str()
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), (&mut stream).take(64 * 1024).read_to_end(&mut answer))
        .await
        .ok()?
        .ok()?;
    let text = String::from_utf8_lossy(&answer);
    if !text.starts_with("HTTP/1.1 200") {
        return None;
    }
    let body = text.split("\r\n\r\n").nth(1)?;
    let value = bridge_core::json::parse_strict(body.as_bytes(), 4096).ok()?;
    let path = value.get("login").and_then(serde_json::Value::as_str)?;
    let mac = value.get("mac").and_then(serde_json::Value::as_str)?;
    let link = format!("http://127.0.0.1:{port}{path}");
    (http::launch_answer_ok(key, &nonce, path, mac) && login_link_ok(&link)).then_some(link)
}

/// Whether `link` is a login link of this app: `http://127.0.0.1:<port>/login/<code>` (code: 1-64 of
/// `A-Z a-z 0-9 - _`) - nothing that could break out of the login page.
#[must_use]
pub fn login_link_ok(link: &str) -> bool {
    let Some(rest) = link.strip_prefix("http://127.0.0.1:") else { return false };
    let Some((port, code)) = rest.split_once("/login/") else { return false };
    port.parse::<u16>().is_ok_and(|port| port > 0)
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && (1..=64).contains(&code.len())
        && code.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Writes the login page (owner-only, atomically) that forwards the browser to `link`; returns its path.
pub fn write_login_page(app_dir: &Path, link: &str) -> Result<PathBuf, String> {
    if !login_link_ok(link) {
        return Err("kein Anmelde-Link dieser App".into());
    }
    let page = format!(
        "<!doctype html>\n<html lang=\"de\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" \
         content=\"no-referrer\">\n<meta http-equiv=\"refresh\" content=\"0;url={link}\">\n<title>BridgeControll</title>\
         </head>\n<body><a href=\"{link}\">BridgeControll öffnen</a></body></html>\n"
    );
    let path = app_dir.join(LOGIN_PAGE);
    config::write_private(&path, page.as_bytes())?;
    Ok(path)
}

/// Removes the login page once it is older than two minutes (its code is used or about to expire).
pub fn remove_old_login_page(app_dir: &Path) {
    let path = app_dir.join(LOGIN_PAGE);
    let old = std::fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .is_ok_and(|modified| modified.elapsed().is_ok_and(|age| age >= LOGIN_PAGE_TTL));
    if old {
        let _ = std::fs::remove_file(&path);
    }
}

/// Opens the login link in the default browser - not as an argument (review 8: every user of the PC can read the
/// command lines of running programs), but through the owner-only login page ([`write_login_page`]).
pub fn open_login(app_dir: &Path, link: &str) -> Result<(), String> {
    let page = write_login_page(app_dir, link)?;
    browser_command(&page)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Browser nicht startbar: {e}"))
}

/// The command that opens `target` (a file) in the default browser (no shell involved: the path is one argument).
#[must_use]
pub fn browser_command(target: &Path) -> std::process::Command {
    if cfg!(windows) {
        let mut command = std::process::Command::new("rundll32.exe");
        command.arg("url.dll,FileProtocolHandler").arg(target);
        command
    } else if cfg!(target_os = "macos") {
        let mut command = std::process::Command::new("open");
        command.arg(target);
        command
    } else {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(target);
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review 8, finding 7: the login code never goes on the browser's command line - the browser gets an owner-only
    /// page that forwards to it.
    #[test]
    fn login_code_stays_off_the_command_line() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let link = "http://127.0.0.1:7380/login/AbC-12_xyz";
        let page = write_login_page(dir.path(), link)?;
        let html = std::fs::read_to_string(&page).map_err(|e| e.to_string())?;
        assert!(html.contains(&format!("content=\"0;url={link}\"")), "{html}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&page).map_err(|e| e.to_string())?.permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "owner only");
        }
        let command = browser_command(&page);
        let args: Vec<String> = command.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect();
        assert!(args.iter().any(|arg| arg.ends_with(LOGIN_PAGE)), "{args:?}");
        assert!(args.iter().all(|arg| !arg.contains("AbC-12_xyz")), "{args:?}");
        // Only real login links of this app go into the page.
        for bad in [
            "http://127.0.0.1:7380/login/\"><script>",
            "http://evil.example/login/x",
            "http://127.0.0.1:7380/login/",
            "http://127.0.0.1:x/login/a",
            "javascript:alert(1)",
        ] {
            assert!(write_login_page(dir.path(), bad).is_err(), "{bad}");
        }
        // An old page goes; a fresh one stays.
        remove_old_login_page(dir.path());
        assert!(page.exists());
        Ok(())
    }

    /// Review 8, finding 8: one app per folder - the lock is exclusive while held and free again after it ends (also
    /// after a crash: the system drops it with the process).
    #[test]
    fn the_instance_lock_is_exclusive() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let first = InstanceLock::acquire(dir.path())?.ok_or("first lock")?;
        assert!(InstanceLock::acquire(dir.path())?.is_none(), "a second one waits");
        drop(first);
        assert!(InstanceLock::acquire(dir.path())?.is_some(), "free again");
        Ok(())
    }
}
