//! Bridge 3 servers in a network (docs/11 §8, ADR 0026): Bridge 4 has no realms of its own - a network contains real
//! Bridge 3 servers (realms, topics, commands, friends ... unchanged), run from the Bridge 3 folder with the PC's
//! Python and reached through the gate under `/bridge4/<netz>/bridge3/<id>/`.
//!
//! - **Only at the owner's node** of a network (the owner decides), at most [`config::MAX_BRIDGE3`] per PC, ports from
//!   [`config::FIRST_BRIDGE3_PORT`].
//! - **Started** through this app's own small script ([`RUNNER`], written to `bridge3/runner.py` in the app folder):
//!   it listens on 127.0.0.1 only and stops cleanly when its standard input closes - the supervisor's way to stop.
//!   Watchdog and log like the nodes (supervisor ID `b3-<id>`).
//! - **Python**: the configured one, else `<folder>/../BridgeControll/.venv`, `<folder>/.venv`, then `py -3` (Windows)
//!   or `python3`/`python` - the first that can `import bridge` in the Bridge 3 folder (all its dependencies).
//! - **Address** (= its identity in Bridge 3): the network's public address + `/bridge3/<id>` while the network is
//!   public, else `http://127.0.0.1:<port>`; it restarts when that changes.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::config::{self, AppConfig, Bridge3Server, NodeRole};
use crate::ops::{entry_of, save};
use crate::supervisor::{Launch, RunState};
use crate::{App, now_ms};

/// The script that starts one Bridge 3 server.
pub const RUNNER: &str = include_str!("bridge3_runner.py");
/// Longest wait for the Python check.
const PYTHON_CHECK: Duration = Duration::from_secs(30);

/// What the last check of the Bridge 3 folder and Python found (memory only).
#[derive(Debug, Default)]
pub struct Checks {
    last: Mutex<Option<Result<String, String>>>,
}

impl Checks {
    fn set(&self, result: Result<String, String>) {
        *self.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
    }

    fn get(&self) -> Option<Result<String, String>> {
        self.last.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

/// The supervisor ID of a Bridge 3 server.
#[must_use]
pub fn proc_id(id: &str) -> String {
    format!("b3-{id}")
}

/// Why a folder is no Bridge 3 folder that knows server paths - or `None`.
#[must_use]
pub fn code_dir_problem(dir: &Path) -> Option<String> {
    if !dir.is_absolute() {
        return Some("Bitte den ganzen Pfad des Bridge-3-Ordners angeben.".into());
    }
    if !dir.join("main.py").is_file() || !dir.join("bridge").join("__init__.py").is_file() {
        return Some(format!("{} ist kein Bridge-3-Ordner (main.py und bridge/ fehlen).", dir.display()));
    }
    if !dir.join("bridge").join("server").join("base_path.py").is_file() {
        return Some(
            "Dieser Bridge-3-Stand kennt keine Server-Pfade - bitte den neuesten Stand (Branch bridge-3) holen.".into(),
        );
    }
    None
}

/// The Pythons to try (program and its first arguments), in order (see module docs).
fn python_candidates(configured: Option<&str>, code_dir: &Path) -> Vec<(PathBuf, Vec<String>)> {
    if let Some(python) = configured {
        return vec![(PathBuf::from(python), Vec::new())];
    }
    let mut list = Vec::new();
    let venvs = [code_dir.join("..").join("BridgeControll").join(".venv"), code_dir.join(".venv")];
    for venv in venvs {
        for exe in [venv.join("Scripts").join("python.exe"), venv.join("bin").join("python")] {
            if exe.is_file() {
                list.push((exe, Vec::new()));
            }
        }
    }
    if cfg!(windows) {
        list.push((PathBuf::from("py"), vec!["-3".to_owned()]));
        list.push((PathBuf::from("python"), Vec::new()));
    } else {
        list.push((PathBuf::from("python3"), Vec::new()));
        list.push((PathBuf::from("python"), Vec::new()));
    }
    list
}

/// Whether `python` can import Bridge 3 (with all its dependencies) in `code_dir`.
async fn python_works(program: &Path, pre: &[String], code_dir: &Path) -> Result<(), String> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(pre)
        .args(["-c", "import bridge"])
        .current_dir(code_dir)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let output = tokio::time::timeout(PYTHON_CHECK, command.output())
        .await
        .map_err(|_| format!("{} antwortet nicht", program.display()))?
        .map_err(|e| format!("{}: {e}", program.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&output.stderr);
    let last = text.lines().rev().find(|line| !line.trim().is_empty()).unwrap_or("Fehler").trim();
    Err(format!("{}: {}", program.display(), last.chars().take(300).collect::<String>()))
}

/// The Bridge 3 folder and a Python that runs it - or why not (German). Remembers the result for the dashboard.
async fn ready(app: &App) -> Result<(PathBuf, PathBuf, Vec<String>), String> {
    let (code_dir, python) = {
        let config = app.config.lock().await;
        (config.bridge3.code_dir.clone(), config.bridge3.python.clone())
    };
    let result = async {
        let code_dir = PathBuf::from(code_dir.ok_or("Erst den Bridge-3-Ordner einstellen.")?);
        if let Some(problem) = code_dir_problem(&code_dir) {
            return Err(problem);
        }
        let mut errors = Vec::new();
        for (program, pre) in python_candidates(python.as_deref(), &code_dir) {
            match python_works(&program, &pre, &code_dir).await {
                Ok(()) => return Ok((code_dir, program, pre)),
                Err(error) => errors.push(error),
            }
        }
        Err(format!(
            "Kein Python kann Bridge 3 starten (fehlen Pakete? pip install -r requirements.txt im Bridge-3-Ordner): {}",
            errors.join(" · ")
        ))
    }
    .await;
    app.bridge3.set(result.as_ref().map(|(_, program, pre)| shown(program, pre)).map_err(Clone::clone));
    result
}

fn shown(program: &Path, pre: &[String]) -> String {
    std::iter::once(program.display().to_string()).chain(pre.iter().cloned()).collect::<Vec<_>>().join(" ")
}

/// The address of a server (see module docs).
#[must_use]
pub fn url_of(config: &AppConfig, server: &Bridge3Server) -> String {
    match config.node(&server.node).filter(|node| node.public_key.is_some()).and_then(|node| node.public_url.clone()) {
        Some(public) => format!("{}/bridge3/{}", public.trim_end_matches('/'), server.id),
        None => format!("http://127.0.0.1:{}", server.port),
    }
}

/// Starts a server (nothing happens if it runs).
pub async fn start(app: &App, id: &str) -> Result<Value, String> {
    let (code_dir, python, pre) = ready(app).await?;
    let (server, url) = {
        let config = app.config.lock().await;
        let server = config.bridge3.server(id).cloned().ok_or("Diesen Bridge-3-Server gibt es nicht (mehr).")?;
        let url = url_of(&config, &server);
        (server, url)
    };
    let runner = app.options.app_dir.join("bridge3").join("runner.py");
    config::write_private(&runner, RUNNER.as_bytes())?;
    let mut args = pre;
    args.push(runner.display().to_string());
    let env = vec![
        ("BRIDGE_CODE_DIR".to_owned(), code_dir.display().to_string()),
        ("PORT".to_owned(), server.port.to_string()),
        ("BRIDGE_PASSWORD".to_owned(), server.password.clone()),
        ("BRIDGE_PUBLIC_URL".to_owned(), url.clone()),
        ("BRIDGE_TRUST_PROXY".to_owned(), "1".to_owned()),
        ("BRIDGE_TRUST_PROXY_IPS".to_owned(), "127.0.0.1,::1".to_owned()),
        ("PYTHONUNBUFFERED".to_owned(), "1".to_owned()),
        ("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned()),
    ];
    let proc = proc_id(id);
    app.supervisor.start(Launch {
        id: proc.clone(),
        mode: "node",
        program: Some(python),
        args,
        env,
        log: app.node_log(&proc),
    });
    Ok(json!({"ok": true, "url": url}))
}

/// Stops a server cleanly.
pub async fn stop(app: &App, id: &str) -> Result<Value, String> {
    if app.config.lock().await.bridge3.server(id).is_none() {
        return Err("Diesen Bridge-3-Server gibt es nicht (mehr).".into());
    }
    app.supervisor.stop(&proc_id(id)).await;
    Ok(json!({"ok": true}))
}

/// After the address of the network changed (public or not): its running servers start again with the new one.
pub async fn restart_for_node(app: &App, node: &str) {
    let ids: Vec<String> =
        app.config.lock().await.bridge3.servers.iter().filter(|s| s.node == node).map(|s| s.id.clone()).collect();
    for id in ids {
        if app.supervisor.status(&proc_id(&id)).state == RunState::Running {
            app.supervisor.stop(&proc_id(&id)).await;
            if let Err(error) = start(app, &id).await {
                tracing::warn!(%error, server = %id, "Bridge-3-Server");
            }
        }
    }
}

/// Stops the servers of a node that goes away (its entries are removed with it, [`forget_node`]).
pub async fn stop_for_node(app: &App, node: &str) {
    let ids: Vec<String> =
        app.config.lock().await.bridge3.servers.iter().filter(|s| s.node == node).map(|s| s.id.clone()).collect();
    for id in ids {
        app.supervisor.stop(&proc_id(&id)).await;
    }
}

/// Removes the servers of a node from the settings (in the same save as the node).
pub fn forget_node(config: &mut AppConfig, node: &str) {
    config.bridge3.servers.retain(|server| server.node != node);
}

/// Starts the servers marked for autostart (at the app's start).
pub async fn autostart(app: &App) {
    let ids: Vec<String> =
        app.config.lock().await.bridge3.servers.iter().filter(|s| s.autostart).map(|s| s.id.clone()).collect();
    for id in ids {
        if let Err(error) = start(app, &id).await {
            tracing::warn!(%error, server = %id, "Bridge-3-Server");
        }
    }
}

fn text<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or_default()
}

/// `POST /api/bridge3/settings` `{"code_dir", "python"?}`: the Bridge 3 folder (checked) and the Python (empty:
/// automatic); then the Python check.
pub async fn settings(app: &App, body: &Map<String, Value>) -> Result<Value, String> {
    let code_dir = text(body, "code_dir").trim().trim_matches('"').to_owned();
    config::check_path_setting(&code_dir, "Bridge-3-Ordner")?;
    if let Some(problem) = code_dir_problem(Path::new(&code_dir)) {
        return Err(problem);
    }
    let python = text(body, "python").trim().trim_matches('"').to_owned();
    let python = if python.is_empty() {
        None
    } else {
        config::check_path_setting(&python, "Python")?;
        Some(python)
    };
    save(app, |config| {
        config.bridge3.code_dir = Some(code_dir.clone());
        config.bridge3.python = python.clone();
        Ok(())
    })
    .await?;
    match ready(app).await {
        Ok((_, program, pre)) => Ok(json!({"ok": true, "python": shown(&program, &pre)})),
        Err(problem) => Ok(json!({"ok": false, "problem": problem})),
    }
}

/// `POST /api/nodes/<owner node>/bridge3-add` `{"id", "name", "password", "autostart"?}`: a new server of this
/// network (only at the owner's node), started at once.
pub async fn add(app: &App, node: &str, body: &Map<String, Value>) -> Result<Value, String> {
    let entry = entry_of(app, node).await?;
    if entry.role != NodeRole::Owner {
        return Err("Bridge-3-Server legt der Owner an (auf dem PC mit dem Owner-Knoten).".into());
    }
    let id = text(body, "id").trim().to_ascii_lowercase();
    config::check_bridge3_id(&id)?;
    let name = text(body, "name").trim().to_owned();
    let password = text(body, "password").to_owned();
    let autostart = body.get("autostart").and_then(Value::as_bool).unwrap_or(true);
    let ui_port = app.port;
    save(app, |config| {
        if config.bridge3.server(&id).is_some() {
            return Err(format!("Die Server-ID „{id}“ gibt es schon."));
        }
        if config.bridge3.servers.len() >= config::MAX_BRIDGE3 {
            return Err(format!("Höchstens {} Bridge-3-Server pro PC.", config::MAX_BRIDGE3));
        }
        let port = crate::ops::free_port(config, config::FIRST_BRIDGE3_PORT, false, &[ui_port]);
        let server = Bridge3Server {
            id: id.clone(),
            name: name.clone(),
            node: node.to_owned(),
            port,
            password: password.clone(),
            autostart,
            created: now_ms(),
        };
        server.check()?;
        config.bridge3.servers.push(server);
        Ok(())
    })
    .await?;
    if entry.public_key.is_some() {
        crate::public::apply_gate(app).await?;
    }
    let started = start(app, &id).await;
    let url = {
        let config = app.config.lock().await;
        config.bridge3.server(&id).map(|server| url_of(&config, server))
    };
    Ok(json!({"ok": true, "id": id, "url": url, "started": started.is_ok(), "problem": started.err()}))
}

/// `POST /api/bridge3/<id>/delete` `{"confirm": "<id>"}`: stops the server and removes it (its data was only in RAM).
pub async fn delete(app: &App, id: &str, confirm: &str) -> Result<Value, String> {
    if confirm.trim() != id {
        return Err(format!("Tippe {id} zum Bestätigen."));
    }
    let server =
        app.config.lock().await.bridge3.server(id).cloned().ok_or("Diesen Bridge-3-Server gibt es nicht (mehr).")?;
    app.supervisor.stop(&proc_id(id)).await;
    save(app, |config| {
        config.bridge3.servers.retain(|s| s.id != id);
        Ok(())
    })
    .await?;
    let public = app.config.lock().await.node(&server.node).is_some_and(|node| node.public_key.is_some());
    if public {
        crate::public::apply_gate(app).await?;
    }
    Ok(json!({"ok": true}))
}

/// The dashboard part of an owner node: the settings with the last check, and the network's servers.
pub async fn view(app: &App, node: &str) -> Value {
    let config = app.config.lock().await;
    let servers: Vec<Value> = config
        .bridge3
        .servers
        .iter()
        .filter(|server| server.node == node)
        .map(|server| {
            let process = app.supervisor.status(&proc_id(&server.id));
            json!({
                "id": server.id,
                "name": server.name,
                "port": server.port,
                "url": url_of(&config, server),
                "autostart": server.autostart,
                "state": process.state.as_str(),
                "restarts": process.restarts,
                "last_exit": process.last_exit,
            })
        })
        .collect();
    let check = match app.bridge3.get() {
        None => Value::Null,
        Some(Ok(python)) => json!({"ok": true, "python": python}),
        Some(Err(problem)) => json!({"ok": false, "problem": problem}),
    };
    json!({
        "code_dir": config.bridge3.code_dir,
        "python": config.bridge3.python,
        "check": check,
        "servers": servers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_ids_and_pythons() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        assert!(code_dir_problem(Path::new("relativ")).is_some());
        assert!(code_dir_problem(dir.path()).is_some_and(|p| p.contains("kein Bridge-3-Ordner")));
        std::fs::create_dir_all(dir.path().join("bridge").join("server")).map_err(|e| e.to_string())?;
        std::fs::write(dir.path().join("main.py"), "").map_err(|e| e.to_string())?;
        std::fs::write(dir.path().join("bridge").join("__init__.py"), "").map_err(|e| e.to_string())?;
        assert!(code_dir_problem(dir.path()).is_some_and(|p| p.contains("Server-Pfade")));
        std::fs::write(dir.path().join("bridge").join("server").join("base_path.py"), "").map_err(|e| e.to_string())?;
        assert_eq!(code_dir_problem(dir.path()), None);
        assert_eq!(python_candidates(Some("/x/python"), dir.path()), vec![(PathBuf::from("/x/python"), Vec::new())]);
        let auto = python_candidates(None, dir.path());
        assert!(auto.iter().any(|(program, _)| program.ends_with("python3") || program.ends_with("py")), "{auto:?}");
        for good in ["spiel", "mc-1", "ab"] {
            assert!(config::check_bridge3_id(good).is_ok(), "{good}");
        }
        for bad in ["a", "Spiel", "-a", "a-", "bridge4", "bridge3", "admin", "site", "a/b", &"a".repeat(41)] {
            assert!(config::check_bridge3_id(bad).is_err(), "{bad}");
        }
        assert!(RUNNER.contains("bridge.Bridge(\"127.0.0.1\"") && !RUNNER.contains("0.0.0.0"), "loopback only");
        assert_eq!(proc_id("spiel"), "b3-spiel");
        Ok(())
    }
}
