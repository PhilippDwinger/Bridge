//! Self-update (docs/12 §9): an update server on this PC with announcements signed by a test release key.
//! In-process: what is not signed by the key, not newer, not at the allowed place or not matching its hash changes
//! nothing; a good one is loaded, checked and handed to the program. As real processes (Linux): the program replaces
//! itself and the new version runs - a new version that does not start is replaced by the old one again.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::crypto::sha256;
use bridge_core::release::{Release, ReleaseFile, ReleaseKey, Version};
use bridge_transport::{Handler, Request, Response, RunningServer, ServerConfig, serve};
use bridgecontroll::update::{self, Source};
use common::{TestResult, start_with};
use rand_core::OsRng;
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// Serves `/bridgecontroll.json` and `/files/<name>` from memory.
#[derive(Default)]
struct UpdateServer {
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl Handler for UpdateServer {
    async fn handle(&self, request: Request) -> Response {
        let body = self.files.lock().ok().and_then(|files| files.get(&request.path).cloned());
        match body {
            Some(body) => Response::ok(body).with_header("content-type", "application/octet-stream"),
            None => Response::error(404, "NOT_FOUND", "nicht da", None),
        }
    }
}

struct Server {
    files: Arc<UpdateServer>,
    running: RunningServer,
    base: String,
    key: ReleaseKey,
}

impl Server {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
        let base = format!("http://127.0.0.1:{}", listener.local_addr().map_err(|e| e.to_string())?.port());
        let files = Arc::new(UpdateServer::default());
        let config = ServerConfig { max_body_bytes: 1024, ..ServerConfig::default() };
        let running = serve(listener, config, Arc::clone(&files)).map_err(|e| e.to_string())?;
        Ok(Self { files, running, base, key: ReleaseKey::generate(&mut OsRng) })
    }

    fn put(&self, path: &str, bytes: Vec<u8>) {
        if let Ok(mut files) = self.files.files.lock() {
            files.insert(path.to_owned(), bytes);
        }
    }

    /// A release of `version` whose file for this platform lies at `/files/<name>` with `bytes` (`sha256`: the hash
    /// it claims).
    fn release(&self, version: &str, name: &str, bytes: &[u8], sha256: [u8; 32]) -> Result<Release, String> {
        Ok(Release {
            version: Version::parse(version).map_err(|e| e.to_string())?,
            at: bridgecontroll::now_ms(),
            notes: "Test".into(),
            files: vec![ReleaseFile {
                platform: update::platform().ok_or("no platform")?.to_owned(),
                url: format!("{}/files/{name}", self.base),
                size: bytes.len() as u64,
                sha256,
            }],
        })
    }

    fn announce(&self, release: &Release, key: &ReleaseKey) -> TestResult {
        self.put("/bridgecontroll.json", release.sign(key).map_err(|e| e.to_string())?);
        Ok(())
    }

    fn source(&self, first_check: Duration) -> Source {
        Source::local(&self.base, self.key.public(), first_check)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_newer_version_paddy_signed_is_taken() -> TestResult {
    let server = Server::start().await?;
    let program_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let program = program_dir.path().join("bridgecontroll");
    std::fs::write(&program, b"old program").map_err(|e| e.to_string())?;
    let source = server.source(Duration::from_secs(3600));
    let path = program.clone();
    let app = start_with(move |options| {
        options.update = source;
        options.program = Some(path);
    })
    .await?;
    let (status, state) = app.get("/api/update").await?;
    assert_eq!((status, state["enabled"].clone(), state["available"].clone()), (200, json!(true), Value::Null));
    assert_eq!(state["auto"], json!(true), "automatic by default");

    // Nothing announced yet; then an older version; then one signed by another key; then a file outside the place.
    let (status, answer) = app.post("/api/update/check", &json!({})).await?;
    assert_eq!(status, 400, "{answer}");
    let new_file = b"new program".to_vec();
    let hash = sha256(&new_file);
    server.put("/files/new", new_file.clone());
    server.announce(&server.release("0.0.1", "new", &new_file, hash)?, &server.key)?;
    let (status, answer) = app.post("/api/update/check", &json!({})).await?;
    assert_eq!((status, answer["available"].clone()), (200, Value::Null), "not newer: {answer}");
    let stranger = ReleaseKey::generate(&mut OsRng);
    server.announce(&server.release("9.0.0", "new", &new_file, hash)?, &stranger)?;
    let (status, answer) = app.post("/api/update/check", &json!({})).await?;
    assert!(status == 400 && answer.to_string().contains("abgelehnt"), "foreign key: {answer}");
    let mut elsewhere = server.release("9.0.0", "new", &new_file, hash)?;
    elsewhere.files[0].url = format!("{}/other/new", server.base);
    server.announce(&elsewhere, &server.key)?;
    let (status, answer) = app.post("/api/update/check", &json!({})).await?;
    assert!(status == 400 && answer.to_string().contains("GitHub"), "outside the place: {answer}");

    // Newer and signed, but the file does not match its hash: found, refused when installing; nothing changes.
    server.announce(&server.release("9.0.0", "new", &new_file, [0; 32])?, &server.key)?;
    let (status, answer) = app.post("/api/update/check", &json!({})).await?;
    assert_eq!((status, answer["available"]["version"].clone()), (200, json!("9.0.0")), "{answer}");
    let (status, answer) = app.post("/api/update/install", &json!({})).await?;
    assert!(status == 400 && answer.to_string().contains("passt nicht"), "{answer}");
    assert!(!update::beside(&program, ".new").exists(), "the wrong file is gone");
    assert_eq!(std::fs::read(&program).map_err(|e| e.to_string())?, b"old program");
    assert!(app.running.app().updater.take_pending().is_none());

    // Automatic off is kept in update.json.
    let (status, answer) = app.post("/api/update/auto", &json!({"on": false})).await?;
    assert_eq!((status, answer["auto"].clone()), (200, json!(false)));
    let saved =
        std::fs::read_to_string(app.dir.path().join("app").join(update::STATE_FILE)).map_err(|e| e.to_string())?;
    assert!(saved.contains("\"auto\":false"), "{saved}");

    // The right file: loaded next to the program, checked, handed over - and the app ends for it.
    server.announce(&server.release("9.0.0", "new", &new_file, hash)?, &server.key)?;
    app.post("/api/update/check", &json!({})).await?;
    let (status, answer) = app.post("/api/update/install", &json!({})).await?;
    assert_eq!((status, answer["installing"].clone()), (200, json!(true)), "{answer}");
    let pending = app.running.app().updater.take_pending().ok_or("nothing pending")?;
    assert_eq!((pending.version.to_string(), pending.auto), ("9.0.0".to_owned(), false));
    assert_eq!(std::fs::read(&pending.file).map_err(|e| e.to_string())?, new_file);
    tokio::time::timeout(Duration::from_secs(5), app.running.quit_requested()).await.map_err(|_| "no quit")?;
    server.running.shutdown().await;
    Ok(())
}

// ---- As real processes ----------------------------------------------------------------------------------------------
// Unix only: the program is started and stopped as a real process (SIGINT) and replaced while it runs.

#[cfg(unix)]
mod processes {
    use std::path::{Path, PathBuf};

    use bridge_core::encoding::b64;
    use bridge_core::release::MAX_FILE_BYTES;

    use super::*;
    use crate::common::node_exe;

    fn free_port() -> Result<u16, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        Ok(listener.local_addr().map_err(|e| e.to_string())?.port())
    }

    fn read_json(path: &Path) -> Option<Value> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    async fn wait_until(what: &str, app_dir: &Path, mut check: impl FnMut() -> bool) -> TestResult {
        for _ in 0..600 {
            if check() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let log = std::fs::read_to_string(app_dir.join("bridgecontroll.log")).unwrap_or_default();
        let tail: String =
            log.lines().rev().take(30).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
        Err(format!("{what} - never happened. Log:\n{tail}"))
    }

    /// Ends the app named in `instance.json` (SIGINT = Ctrl+C) and waits until it is gone.
    async fn stop_running(app_dir: &Path) -> TestResult {
        let instance = read_json(&app_dir.join("instance.json")).ok_or("no instance.json")?;
        let pid = instance["pid"].as_u64().ok_or("no pid")?;
        std::process::Command::new("kill").args(["-INT", &pid.to_string()]).status().map_err(|e| e.to_string())?;
        wait_until("the app ended", app_dir, || !app_dir.join("instance.json").exists()).await
    }

    fn start_program(
        program: &Path,
        app_dir: &Path,
        server: &Server,
        fake: &str,
    ) -> Result<std::process::Child, String> {
        let test = json!({"base": server.base, "key": b64(&server.key.public()), "first_check_ms": 300});
        std::process::Command::new(program)
            .args(["--data", &app_dir.display().to_string(), "--port", &free_port()?.to_string(), "--no-browser"])
            .env("BRIDGECONTROLL_UPDATE_TEST", test.to_string())
            .env("BRIDGECONTROLL_TEST_VERSION", fake)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_program_replaces_itself_and_goes_back_if_the_new_one_fails() -> TestResult {
        let server = Server::start().await?;
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let (bin, app_dir) = (dir.path().join("bin"), dir.path().join("app"));
        std::fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
        let program: PathBuf = bin.join("bridgecontroll");
        let real = std::fs::read(node_exe()).map_err(|e| e.to_string())?;
        // The real program is served as the new version - it must fit the limit of an announcement (docs/12 §3).
        if real.len() as u64 > MAX_FILE_BYTES {
            return Err(format!(
                "the test program has {} bytes, more than an update may have - build tests without debug info \
                 ([profile.dev] debug = 0 in Cargo.toml)",
                real.len()
            ));
        }
        std::fs::copy(node_exe(), &program).map_err(|e| e.to_string())?;
        let own = env!("CARGO_PKG_VERSION");

        // The program pretends to be 0.0.1; the announced version is this build (with the same file).
        server.put("/files/new", real.clone());
        server.announce(&server.release(own, "new", &real, sha256(&real))?, &server.key)?;
        let mut first = start_program(&program, &app_dir, &server, "0.0.1")?;
        let state = app_dir.join(update::STATE_FILE);
        wait_until("the new version runs", &app_dir, || {
            read_json(&app_dir.join("instance.json")).is_some_and(|i| i["version"] == json!(own))
                && read_json(&state).is_some_and(|s| s["last"]["ok"] == json!(true))
        })
        .await?;
        let saved = read_json(&state).ok_or("no update.json")?;
        assert_eq!((saved["last"]["from"].clone(), saved["last"]["to"].clone()), (json!("0.0.1"), json!(own)));
        wait_until("the old version ended", &app_dir, || first.try_wait().ok().flatten().is_some()).await?;
        assert!(!update::beside(&program, ".old").exists(), "the new version removed the old file");
        assert_eq!(std::fs::read(&program).map_err(|e| e.to_string())?, real);
        stop_running(&app_dir).await?;

        // A newer version that does not start (exits at once): the old one comes back and notes it.
        let broken = b"#!/bin/sh\nexit 3\n".to_vec();
        server.put("/files/broken", broken.clone());
        server.announce(&server.release("9.9.9", "broken", &broken, sha256(&broken))?, &server.key)?;
        let mut second = start_program(&program, &app_dir, &server, "0.1.5")?;
        wait_until("back on the old version", &app_dir, || {
            read_json(&state).is_some_and(|s| s["failed"] == json!("9.9.9") && s["last"]["ok"] == json!(false))
                && read_json(&app_dir.join("instance.json")).is_some_and(|i| i["version"] == json!("0.1.5"))
        })
        .await?;
        assert_eq!(std::fs::read(&program).map_err(|e| e.to_string())?, real, "the old program is in place again");
        assert_eq!(std::fs::read(update::beside(&program, ".bad")).map_err(|e| e.to_string())?, broken);
        wait_until("the version that went back ended", &app_dir, || second.try_wait().ok().flatten().is_some()).await?;
        // The version that failed is not tried again automatically (the restored one checks right away).
        tokio::time::sleep(Duration::from_secs(2)).await;
        let instance = read_json(&app_dir.join("instance.json")).ok_or("restored app gone")?;
        assert_eq!(instance["version"], json!("0.1.5"));
        stop_running(&app_dir).await?;
        server.running.shutdown().await;
        Ok(())
    }
}
