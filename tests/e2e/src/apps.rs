//! Helpers for phase 4a tests (docs/07): a network whose nodes are web hosts, an owner that is a member, app
//! folders, plain HTTP with headers (no redirects followed), raw request lines, a proxy that corrupts blob parts and
//! one that counts the requests it forwards.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::encoding::{b64, b64_var};
use bridge_core::{Id, Identity};
use bridge_net::JoinMode;
use bridge_node::admin;
use bridge_sdk::Client;
use bridge_transport::{Handler, HttpClient, Method, Request, Response, RunningServer, ServerConfig};
use rand_core::OsRng;
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use crate::net::{TestNet, TestNode, eventually, test_config, wait_for};

/// A network whose owner node and `hosts` further nodes are gateways with the service `web`, and an owner (a
/// member, joined at the owner node).
pub struct AppNet {
    /// The network (owner node: level 3 with gateway, log, witness, web).
    pub net: TestNet,
    /// Further web hosts (level 2: gateway, web).
    pub hosts: Vec<TestNode>,
    /// The owner's secret (to log in at several hosts).
    owner: ([u8; 32], [u8; 32]),
}

/// The same identity again (the type is not `Clone` on purpose).
#[must_use]
pub fn copy(identity: &Identity) -> Identity {
    let (sign, receive) = identity.secret_bytes();
    Identity::from_secret_bytes(&sign, &receive)
}

impl AppNet {
    /// Creates the network and `hosts` further web hosts; waits until every node knows every seal.
    pub async fn new(hosts: usize) -> Result<Self, String> {
        Self::with_options(hosts, &TestNet::options()).await
    }

    /// Like [`AppNet::new`], with other network options (docs/08 §2, e.g. 18+ allowed).
    pub async fn with_options(hosts: usize, options: &admin::NetOptions) -> Result<Self, String> {
        let net = TestNet::create_full(JoinMode::Open, None, None, options).await?;
        let services = admin::parse_services("gateway,log,witness,web")?;
        net.admin.seal(&net.owner.url, &net.owner.id(), 3, services).await?;
        let mut nodes = Vec::new();
        for _ in 0..hosts {
            let node = net.add_node(&[]).await?;
            net.seal_as(&node, "gateway,web").await?;
            nodes.push(node);
        }
        let owner = Identity::generate(&mut OsRng);
        let secret = owner.secret_bytes();
        let joined = Client::join(owner, &net.link(None)).await.map_err(|e| e.to_string())?;
        drop(joined);
        let app_net = Self { net, hosts: nodes, owner: (*secret.0, *secret.1) };
        app_net.synced().await?;
        Ok(app_net)
    }

    /// Waits until every running host holds the owner's log.
    pub async fn synced(&self) -> Result<(), String> {
        for node in &self.hosts {
            self.net.synced(node).await?;
        }
        Ok(())
    }

    /// The owner identity.
    #[must_use]
    pub fn owner(&self) -> Identity {
        Identity::from_secret_bytes(&self.owner.0, &self.owner.1)
    }

    /// The owner, logged in at `node` (retried while that gateway does not know the membership yet).
    pub async fn owner_at(&self, node: &TestNode) -> Result<Client, String> {
        eventually("owner login", || async {
            let mut client = Client::new(self.owner(), &node.url, Some(node.id())).map_err(|e| e.to_string())?;
            client.connect().await.map_err(|e| e.to_string())?;
            Ok(client)
        })
        .await
    }

    /// Owner node first, then the further hosts.
    #[must_use]
    pub fn all(&self) -> Vec<&TestNode> {
        std::iter::once(&self.net.owner).chain(self.hosts.iter()).collect()
    }
}

/// A folder with an app: `index.html`, `style.css`, `assets/big.bin` (`big` bytes, several parts).
pub fn app_folder(big: usize) -> Result<(TempDir, Vec<u8>), String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let write = |path: &str, data: &[u8]| -> Result<(), String> {
        let full = dir.path().join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(full, data).map_err(|e| e.to_string())
    };
    write("index.html", b"<!doctype html><h1>Hallo Bridge-App</h1>")?;
    write("style.css", b"h1 { color: blue }")?;
    let data: Vec<u8> = (0..big).map(|i| (i % 251) as u8).collect();
    write("assets/big.bin", &data)?;
    Ok((dir, data))
}

/// A plain GET (redirects are not followed): status, headers, body.
pub async fn get(url: &str) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>), String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client.get(url).send().await.map_err(|e| e.to_string())?;
    let (status, headers) = (response.status().as_u16(), response.headers().clone());
    let body = response.bytes().await.map_err(|e| e.to_string())?.to_vec();
    Ok((status, headers, body))
}

/// The value of a header ("" if missing).
#[must_use]
pub fn header(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned()
}

/// Waits until `url` answers 200 with exactly `body`.
pub async fn served(url: &str, body: &[u8]) -> Result<(), String> {
    eventually(url, || async {
        let (status, _, got) = get(url).await?;
        if status == 200 && got == body { Ok(()) } else { Err(format!("status {status}, {} bytes", got.len())) }
    })
    .await
}

/// Waits until `url` answers 404.
pub async fn gone(url: &str) -> Result<(), String> {
    eventually(url, || async {
        let (status, _, _) = get(url).await?;
        if status == 404 { Ok(()) } else { Err(format!("status {status}")) }
    })
    .await
}

/// Sends one raw request line (exactly as given - no client normalizes the path) and returns the status line and
/// the headers as text (lower case).
pub async fn raw_get(addr: std::net::SocketAddr, target: &str) -> Result<(u16, String), String> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let request = format!("GET {target} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
        .await
        .map_err(|_| "timeout".to_owned())?
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&answer).to_ascii_lowercase();
    let status = text.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
    let head = text.split("\r\n\r\n").next().unwrap_or_default().to_owned();
    Ok((status, head))
}

/// A proxy in front of a node that forwards everything but flips a byte in every part `/v4/blob/get` hands out.
pub struct Corrupting {
    target: HttpClient,
    /// Parts it corrupted.
    pub corrupted: AtomicU64,
}

impl Handler for Corrupting {
    async fn handle(&self, request: Request) -> Response {
        let path = request.path.as_str();
        let answer = match request.method {
            Method::Get => self.target.get(path).await,
            Method::Post => self.target.post(path, request.bearer.as_deref(), request.body.to_vec()).await,
            Method::Options => return Response::error(404, "NOT_FOUND", "not found", None),
        };
        let Ok(answer) = answer else { return Response::error(503, "UNAVAILABLE", "target down", None) };
        let mut body = answer.body;
        if path == "/v4/blob/get" && answer.status == 200 {
            if let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(&body) {
                let data = object.get("data").and_then(Value::as_str).unwrap_or_default();
                if let Ok(mut bytes) = b64_var(data, "data", 1 << 20) {
                    if let Some(first) = bytes.first_mut() {
                        *first ^= 0xff;
                        self.corrupted.fetch_add(1, Ordering::SeqCst);
                    }
                    object.insert("data".into(), Value::String(b64(&bytes)));
                    body = Value::Object(object).to_string().into_bytes();
                }
            }
        }
        let mut response = Response::ok(body);
        response.status = answer.status;
        response
    }
}

/// Starts a corrupting proxy in front of `target_url`.
pub async fn corrupting_proxy(target_url: &str) -> Result<(RunningServer, Arc<Corrupting>, String), String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let url = format!("http://{}", listener.local_addr().map_err(|e| e.to_string())?);
    let proxy = Arc::new(Corrupting {
        target: HttpClient::new(target_url, Duration::from_secs(20)).map_err(|e| e.to_string())?,
        corrupted: AtomicU64::new(0),
    });
    let config = ServerConfig { max_connections_per_address: 1024, ..ServerConfig::default() };
    let server = bridge_transport::serve(listener, config, Arc::clone(&proxy)).map_err(|e| e.to_string())?;
    Ok((server, proxy, url))
}

/// A proxy in front of a node that forwards everything and counts the requests per path (`/v4/app/manifest#head` for
/// the head form).
pub struct Counting {
    target: HttpClient,
    counts: Mutex<HashMap<String, u64>>,
}

impl Counting {
    /// Requests forwarded to `path` so far.
    #[must_use]
    pub fn count(&self, path: &str) -> u64 {
        self.counts.lock().map(|counts| counts.get(path).copied().unwrap_or(0)).unwrap_or(0)
    }
}

impl Handler for Counting {
    async fn handle(&self, request: Request) -> Response {
        let mut key = request.path.clone();
        if key == "/v4/app/manifest" && String::from_utf8_lossy(&request.body).contains("\"head\":true") {
            key.push_str("#head");
        }
        if let Ok(mut counts) = self.counts.lock() {
            *counts.entry(key).or_insert(0) += 1;
        }
        let answer = match request.method {
            Method::Get => self.target.get(&request.path).await,
            Method::Post => self.target.post(&request.path, request.bearer.as_deref(), request.body.to_vec()).await,
            Method::Options => return Response::error(404, "NOT_FOUND", "not found", None),
        };
        let Ok(answer) = answer else { return Response::error(503, "UNAVAILABLE", "target down", None) };
        let mut response = Response::ok(answer.body);
        response.status = answer.status;
        response
    }
}

/// Starts a counting proxy in front of `target_url`.
pub async fn counting_proxy(target_url: &str) -> Result<(RunningServer, Arc<Counting>, String), String> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let url = format!("http://{}", listener.local_addr().map_err(|e| e.to_string())?);
    let proxy = Arc::new(Counting {
        target: HttpClient::new(target_url, Duration::from_secs(20)).map_err(|e| e.to_string())?,
        counts: Mutex::new(HashMap::new()),
    });
    let config = ServerConfig { max_connections_per_address: 1024, ..ServerConfig::default() };
    let server = bridge_transport::serve(listener, config, Arc::clone(&proxy)).map_err(|e| e.to_string())?;
    Ok((server, proxy, url))
}

/// Starts a further node whose card names `public` (e.g. a proxy in front of it) as its address, joined to `net`.
pub async fn node_behind(net: &TestNet, public: &str, listener: TcpListener) -> Result<TestNode, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let node = bridge_node::start(test_config(dir.path(), Some(net.membership(&[])), public), listener).await?;
    let node = TestNode { dir, node, url: public.to_owned() };
    net.synced(&node).await?;
    Ok(node)
}

/// Waits until `node` knows that it is a gateway.
pub async fn wait_gateway(node: &TestNode) -> Result<(), String> {
    wait_for("gateway", || node.status().gateway).await
}

/// The ID of an app key.
#[must_use]
pub fn app_id(app: &Identity) -> Id {
    app.id().clone()
}

/// The data folder's blob files of a node (for damage tests).
#[must_use]
pub fn blob_dir(node: &TestNode) -> std::path::PathBuf {
    node.dir.path().join(bridge_node::BLOB_DIR)
}

/// Every file below `dir` (bounded walk).
#[must_use]
pub fn files_below(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.flatten().take(10_000) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}
