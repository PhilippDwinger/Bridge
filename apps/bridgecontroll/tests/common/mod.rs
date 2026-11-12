//! Helpers for the integration tests: an app in a temporary folder (nodes as real processes of this program), a
//! logged-in HTTP client, raw requests for attacks, waiting for conditions.
#![allow(dead_code, missing_docs)]

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use bridgecontroll::supervisor::Backoff;
use bridgecontroll::{Options, Running};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

pub type TestResult = Result<(), String>;

/// The Meldeweg of the networks the tests create (docs/08 §2: required).
pub const CONTACT: &str = "meldungen@example.org";

/// The program itself: started in node mode for every node.
pub fn node_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bridgecontroll"))
}

/// A running app with its folder.
pub struct TestApp {
    pub running: Running,
    pub dir: tempfile::TempDir,
    pub port: u16,
    pub http: reqwest::Client,
    pub cookie: String,
}

/// Starts an app on a free port with fast status rounds and a fast watchdog; logs in.
pub async fn start() -> Result<TestApp, String> {
    start_with(|_| {}).await
}

/// Like [`start`], with changed options.
pub async fn start_with(change: impl FnOnce(&mut Options)) -> Result<TestApp, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut options = Options::new(dir.path().join("app"), node_exe());
    options.port = 0;
    options.poll_interval = Duration::from_millis(200);
    options.backoff = Backoff::scaled(Duration::from_millis(20));
    options.autostart_dir = Some(dir.path().join("autostart"));
    change(&mut options);
    let running = bridgecontroll::start(options).await?;
    let port = running.addr().port();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;
    let mut app = TestApp { running, dir, port, http, cookie: String::new() };
    app.cookie = app.login().await?;
    Ok(app)
}

impl TestApp {
    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Uses a fresh login link; returns the session cookie (`bc_session=…`).
    pub async fn login(&self) -> Result<String, String> {
        let answer = self.http.get(self.running.login_url()).send().await.map_err(|e| e.to_string())?;
        if answer.status().as_u16() != 200 {
            return Err(format!("login: {}", answer.status()));
        }
        let cookie =
            answer.headers().get("set-cookie").and_then(|value| value.to_str().ok()).ok_or("no cookie")?.to_owned();
        Ok(cookie.split(';').next().unwrap_or_default().to_owned())
    }

    pub async fn get(&self, path: &str) -> Result<(u16, Value), String> {
        let answer = self
            .http
            .get(format!("{}{path}", self.base()))
            .header("cookie", &self.cookie)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = answer.status().as_u16();
        let bytes = answer.bytes().await.map_err(|e| e.to_string())?;
        let value = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        Ok((status, value))
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        let answer = self
            .http
            .post(format!("{}{path}", self.base()))
            .header("cookie", &self.cookie)
            .header("origin", self.base())
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = answer.status().as_u16();
        let bytes = answer.bytes().await.map_err(|e| e.to_string())?;
        let value = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        Ok((status, value))
    }

    /// A POST that must succeed (200); returns the answer.
    pub async fn ok(&self, path: &str, body: &Value) -> Result<Value, String> {
        match self.post(path, body).await? {
            (200, value) => Ok(value),
            (status, value) => Err(format!("{path}: {status} {value}")),
        }
    }

    /// The row of a node on the start page.
    pub async fn row(&self, id: &str) -> Result<Value, String> {
        let (_, overview) = self.get("/api/overview").await?;
        overview["nodes"]
            .as_array()
            .and_then(|nodes| nodes.iter().find(|node| node["id"] == id).cloned())
            .ok_or_else(|| format!("no row {id}"))
    }

    /// Runs the assistant: name, words + quiz, reachability, create. Returns (owner node, answer of step 4).
    pub async fn create_net(&self, name: &str, template: &str) -> Result<(String, Value), String> {
        self.create_net_words(name, template).await.map(|(node, created, _)| (node, created))
    }

    /// Like [`TestApp::create_net`], also returning the 24 words as shown.
    pub async fn create_net_words(&self, name: &str, template: &str) -> Result<(String, Value, Vec<String>), String> {
        self.create_net_full(name, template, false).await
    }

    /// The assistant with LAN on or off; returns (owner node, answer of step 4, words).
    pub async fn create_net_full(
        &self,
        name: &str,
        template: &str,
        lan: bool,
    ) -> Result<(String, Value, Vec<String>), String> {
        let started =
            self.ok("/api/wizard/start", &json!({"name": name, "template": template, "contact": CONTACT})).await?;
        let wizard = started["wizard"].as_str().ok_or("no wizard")?.to_owned();
        let words: Vec<String> = started["words"]
            .as_array()
            .ok_or("no words")?
            .iter()
            .map(|word| word.as_str().unwrap_or_default().to_owned())
            .collect();
        let answers: Vec<Value> = started["quiz"]
            .as_array()
            .ok_or("no quiz")?
            .iter()
            .map(|position| {
                let index = usize::try_from(position.as_u64().unwrap_or(1)).unwrap_or(1) - 1;
                json!({"position": position, "word": words.get(index).cloned().unwrap_or_default()})
            })
            .collect();
        self.ok("/api/wizard/confirm", &json!({"wizard": wizard, "answers": answers, "written": true})).await?;
        let port = free_port()?;
        let lan_port = if lan { json!(free_port()?) } else { Value::Null };
        let created = self
            .ok(
                "/api/wizard/create",
                &json!({"wizard": wizard, "listen_port": port, "lan_port": lan_port, "public_url": null, "uses": 5}),
            )
            .await?;
        let node = created["node"].as_str().ok_or("no node")?.to_owned();
        Ok((node, created, words))
    }

    /// Joins the network of `link` with a new node; returns its local ID.
    pub async fn join(&self, link: &str, name: &str) -> Result<String, String> {
        self.join_full(link, name, false).await
    }

    /// Joins with LAN on or off.
    pub async fn join_full(&self, link: &str, name: &str, lan: bool) -> Result<String, String> {
        let port = free_port()?;
        let lan_port = if lan { json!(free_port()?) } else { Value::Null };
        let joined = self
            .ok(
                "/api/join",
                &json!({"link": link, "name": name, "listen_port": port, "lan_port": lan_port, "public_url": null,
                        "offer_gateway": true, "host_apps": false, "autostart_login": false}),
            )
            .await?;
        Ok(joined["node"].as_str().ok_or("no node")?.to_owned())
    }

    pub async fn shutdown(self) {
        self.running.shutdown().await;
    }
}

/// A free port (≥ 1024) on 127.0.0.1 and 0.0.0.0 right now.
pub fn free_port() -> Result<u16, String> {
    for _ in 0..50 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        drop(listener);
        if port >= 1024 && std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() {
            return Ok(port);
        }
    }
    Err("no free port".into())
}

/// Waits until `check` gives `Some` (every 100 ms, at most `secs` seconds).
pub async fn wait_for<T, F, Fut>(secs: u64, what: &str, mut check: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>, String>>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(value) = check().await? {
            return Ok(value);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("timeout: {what}"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A raw HTTP/1.1 request (for headers and paths a normal client would fix); returns status line + headers + body.
pub async fn raw(port: u16, request: &str) -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await;
    if read.is_err() {
        return Err("raw: no answer".into());
    }
    Ok(String::from_utf8_lossy(&answer).to_string())
}

/// The status code of a raw answer.
pub fn status_of(answer: &str) -> u16 {
    answer.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0)
}
