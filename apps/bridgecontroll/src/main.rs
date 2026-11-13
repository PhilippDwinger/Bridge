//! BridgeControll v2 (ADR 0017).
//!
//! ```text
//! bridgecontroll [--data <app folder>] [--port 7380] [--no-browser] [--autostart] [--after-update <version>]
//! bridgecontroll node [--supervised] --data <node folder> [bridge-node flags]
//! bridgecontroll gate [--supervised] --listen 127.0.0.1:<port> --routes <file>
//! ```
//! Without a command it runs the app: the UI on 127.0.0.1, the browser opens with a one-time login link (also printed),
//! the nodes marked for autostart start. One app per app folder (an exclusive lock, held while it runs): a second start
//! only opens the browser (with a new login link, proven by the running app) and ends. `--autostart` (start with the
//! system): no browser. Ends with Ctrl+C or "Beenden" in the UI - or for an update (docs/12): the checked new version
//! takes the program's place and starts with `--after-update <old version>` (it waits for the lock), see
//! [`bridgecontroll::update::hand_over`].
//!
//! `node`: runs one node exactly like `bridge-node` would (same flags); with `--supervised` it also stops cleanly when
//! its standard input closes - that is how the app stops the nodes it watches.
//!
//! `gate`: the gate of the public networks (docs/11 §3, ADR 0025) - its own process without keys; the app starts and
//! watches it like a node.
//!
//! On Windows the program has no console window (`windows_subsystem = "windows"`): it is a background app; its log
//! goes to `bridgecontroll.log` in the app folder.
#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::ExitCode;

use bridgecontroll::logfile::{DEFAULT_KEEP, DEFAULT_MAX_BYTES, LogWriter, RotatingLog};
use bridgecontroll::{InstanceLock, Options, default_app_dir, delegate, open_login};

const USAGE: &str = "Aufruf:
  bridgecontroll [--data <app-ordner>] [--port 7380] [--no-browser] [--autostart]
  bridgecontroll node [--supervised] --data <knoten-ordner> [Optionen von bridge-node]
  bridgecontroll gate [--supervised] --listen 127.0.0.1:<port> --routes <datei>";

struct AppArgs {
    data: Option<PathBuf>,
    port: u16,
    browser: bool,
    autostart: bool,
    after_update: Option<String>,
}

fn app_args(args: &[String]) -> Result<AppArgs, String> {
    let mut parsed =
        AppArgs { data: None, port: bridgecontroll::DEFAULT_PORT, browser: true, autostart: false, after_update: None };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--data" => parsed.data = Some(PathBuf::from(iter.next().ok_or("--data braucht einen Ordner")?)),
            "--port" => {
                let port = iter.next().ok_or("--port braucht eine Zahl")?;
                parsed.port = port.parse().ok().filter(|port| *port >= 1024).ok_or("--port: 1024-65535")?;
            }
            "--no-browser" => parsed.browser = false,
            "--after-update" => {
                let version = iter.next().ok_or("--after-update braucht eine Version")?;
                bridge_core::release::Version::parse(version).map_err(|_| "--after-update: a.b.c")?;
                parsed.after_update = Some(version.clone());
            }
            "--autostart" => {
                parsed.autostart = true;
                parsed.browser = false;
            }
            "--help" | "-h" => return Err(USAGE.to_owned()),
            "--version" => return Err(format!("bridgecontroll {}", env!("CARGO_PKG_VERSION"))),
            other => return Err(format!("unbekanntes Argument {other}\n{USAGE}")),
        }
    }
    Ok(parsed)
}

/// Node mode: `bridge-node`'s node runner; with `--supervised` it also ends when standard input closes.
async fn node(args: Vec<String>) -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let supervised = args.iter().any(|arg| arg == "--supervised");
    let args: Vec<String> = args.into_iter().filter(|arg| arg != "--supervised").collect();
    let shutdown = async move {
        if supervised {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                () = stdin_closed() => {}
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    match bridge_node_cli::run_node(args, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) if bridge_node_cli::is_info(&message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

/// Returns when standard input reaches its end (the supervising app closed the pipe or ended). What is read is
/// thrown away in small pieces (nothing grows).
async fn stdin_closed() {
    use tokio::io::AsyncReadExt as _;
    let mut stdin = tokio::io::stdin();
    let mut buffer = [0u8; 64];
    loop {
        match stdin.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

async fn app(args: &[String]) -> ExitCode {
    let parsed = match app_args(args) {
        Ok(parsed) => parsed,
        Err(message) if message == USAGE || message.starts_with("bridgecontroll ") => {
            println!("{message}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let custom = parsed.data.is_some();
    let app_dir = match parsed.data.map_or_else(default_app_dir, Ok) {
        Ok(dir) => dir,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("Programm-Pfad unbekannt: {error}");
            return ExitCode::from(2);
        }
    };
    let acquired =
        if parsed.after_update.is_some() { lock_after_update(&app_dir).await } else { InstanceLock::acquire(&app_dir) };
    let lock = match acquired {
        Ok(Some(lock)) => lock,
        Ok(None) => return second_start(&app_dir, parsed.autostart).await,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    match RotatingLog::open(&app_dir.join("bridgecontroll.log"), DEFAULT_MAX_BYTES, DEFAULT_KEEP) {
        Ok(log) => tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
            .with_writer(LogWriter(log))
            .with_ansi(false)
            .init(),
        Err(error) => eprintln!("Log-Datei: {error}"),
    }
    if let Some(from) = &parsed.after_update {
        bridgecontroll::update::after_update(&exe, &app_dir, from);
    }
    let mut options = Options::new(app_dir.clone(), exe.clone());
    options.program = Some(exe.clone());
    options.update = bridgecontroll::update::Source::for_program();
    options.port = parsed.port;
    options.custom_app_dir = custom;
    options.menu_dir = bridgecontroll::startmenu::system_dir();
    let running = match bridgecontroll::start_locked(options, lock).await {
        Ok(running) => running,
        Err(message) => {
            eprintln!("{message}");
            tracing::error!(%message, "Start fehlgeschlagen");
            return ExitCode::from(2);
        }
    };
    let login = running.login_url();
    println!("BridgeControll läuft auf http://127.0.0.1:{}", running.addr().port());
    println!("Anmelden (einmal gültig, 5 Minuten): {login}");
    if parsed.browser {
        if let Err(error) = open_login(running.app().options.app_dir.as_path(), &login) {
            eprintln!("{error} - bitte den Link oben selbst öffnen.");
        }
    }
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = running.quit_requested() => {}
    }
    println!("BridgeControll beendet die Knoten …");
    let app = std::sync::Arc::clone(running.app());
    running.shutdown().await;
    if let Some(pending) = app.updater.take_pending() {
        drop(app);
        match bridgecontroll::update::hand_over(&exe, &app_dir, args, &pending).await {
            bridgecontroll::update::HandOver::Started => {
                tracing::info!(version = %pending.version, "Update: die neue Version läuft");
            }
            bridgecontroll::update::HandOver::WentBack(why) => {
                tracing::error!(%why, "Update: zurück zur alten Version");
            }
        }
    }
    ExitCode::SUCCESS
}

/// After an update the old version may still hold the lock for a moment: try for [`bridgecontroll::update::LOCK_WAIT`].
async fn lock_after_update(app_dir: &std::path::Path) -> Result<Option<InstanceLock>, String> {
    let deadline = tokio::time::Instant::now() + bridgecontroll::update::LOCK_WAIT;
    loop {
        if let Some(lock) = InstanceLock::acquire(app_dir)? {
            return Ok(Some(lock));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Another app holds the folder's lock: ask it for a login link (it proves its launch key) and open the browser.
async fn second_start(app_dir: &std::path::Path, autostart: bool) -> ExitCode {
    let Some(login) = delegate(app_dir).await else {
        eprintln!("BridgeControll läuft schon für {}, antwortet aber nicht.", app_dir.display());
        return ExitCode::from(1);
    };
    println!("BridgeControll läuft schon - öffne: {login}");
    if !autostart {
        if let Err(error) = open_login(app_dir, &login) {
            eprintln!("{error}");
        }
    }
    ExitCode::SUCCESS
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("node") {
        args.remove(0);
        return node(args).await;
    }
    if args.first().map(String::as_str) == Some("gate") {
        args.remove(0);
        return gate(args).await;
    }
    app(&args).await
}

/// The gate (docs/11 §3): like a node, it stops cleanly when its standard input closes (`--supervised`).
async fn gate(args: Vec<String>) -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let supervised = args.iter().any(|arg| arg == "--supervised");
    let args: Vec<String> = args.into_iter().filter(|arg| arg != "--supervised").collect();
    let shutdown = async move {
        if supervised {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                () = stdin_closed() => {}
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    match bridge_gate::run(&args, shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|text| (*text).to_owned()).collect()
    }

    #[test]
    fn app_flags() -> Result<(), String> {
        let plain = app_args(&[])?;
        assert!(plain.browser && !plain.autostart && plain.data.is_none() && plain.port == 7380);
        let auto = app_args(&args(&["--autostart", "--data", "/x", "--port", "8000"]))?;
        assert!(!auto.browser && auto.autostart && auto.data == Some(PathBuf::from("/x")) && auto.port == 8000);
        assert_eq!(app_args(&args(&["--after-update", "0.1.0"]))?.after_update.as_deref(), Some("0.1.0"));
        for bad in [
            &["--port", "80"][..],
            &["--port"],
            &["--data"],
            &["--evil"],
            &["--port", "x"],
            &["--after-update"],
            &["--after-update", "1.2"],
        ] {
            assert!(app_args(&args(bad)).is_err(), "{bad:?}");
        }
        Ok(())
    }
}
