//! # bridge-transport – moving bytes
//!
//! Connections only, no network logic (docs/03, ADR 0004): an HTTP/1.1 server that hands a node plain [`Request`]s,
//! and a client for SDKs and node-to-node calls. Phase 2: Internet (HTTP behind a TLS proxy such as Tailscale Funnel,
//! or HTTPS as a client); LAN (mDNS + TLS pinning) follows in phase 3.
//!
//! Zero Trust at the door (Z5): limited connections, a timeout for headers (slowloris), the body size is checked
//! from `Content-Length` *before* reading and again while reading, every request has a total time limit, and
//! `X-Forwarded-For` is only believed from configured proxies. The client limits response sizes too - a node can
//! be malicious as well.
//!
//! Layering (docs/03_ARCHITEKTUR.md): depends only on `bridge-core` (for nothing but its name today).

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-transport";

/// Errors of the transport.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Could not connect, timed out, or the connection broke.
    #[error("connection: {0}")]
    Connection(String),
    /// Bad URL or configuration.
    #[error("config: {0}")]
    Config(String),
    /// The answer was larger than allowed.
    #[error("response too large")]
    TooLarge,
}

/// Result type of the transport.
pub type TransportResult<T> = Result<T, TransportError>;

/// HTTP method (only what the protocol uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET
    Get,
    /// POST
    Post,
}

/// A request as the node sees it.
#[derive(Debug, Clone)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Path without query, e.g. `/v4/send`.
    pub path: String,
    /// Address of the caller (behind a trusted proxy: the forwarded one).
    pub peer: IpAddr,
    /// Session token from `Authorization: Bearer …`, if any.
    pub bearer: Option<String>,
    /// The body (at most `max_body_bytes`).
    pub body: Bytes,
}

/// A response (always JSON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// JSON body.
    pub body: Vec<u8>,
    /// `Retry-After` in seconds.
    pub retry_after: Option<u32>,
    /// Close the connection after this answer (set when the request body was not read).
    pub close: bool,
}

impl Response {
    /// 200 with a JSON body.
    #[must_use]
    pub fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body, retry_after: None, close: false }
    }

    /// An error in the protocol's format (docs/04 §9).
    #[must_use]
    pub fn error(status: u16, code: &str, message: &str, retry_after: Option<u32>) -> Self {
        let mut body = format!(r#"{{"error":"{code}","message":{}"#, json_string(message));
        if let Some(seconds) = retry_after {
            body.push_str(&format!(r#","retry_after":{seconds}"#));
        }
        body.push('}');
        Self { status, body: body.into_bytes(), retry_after, close: false }
    }
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// What a node implements to answer requests.
pub trait Handler: Send + Sync + 'static {
    /// Cheap check before the body is read (e.g. the per-address rate limit). `Some` = answer this, read nothing.
    fn admit(&self, _peer: IpAddr, _path: &str) -> Option<Response> {
        None
    }
    /// Answers one request.
    fn handle(&self, request: Request) -> impl Future<Output = Response> + Send;
}

/// Server limits.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Max request body (docs/04 §1: 1 MiB).
    pub max_body_bytes: usize,
    /// Max time for one request incl. reading the body (long polls wait up to 25 s).
    pub request_timeout: Duration,
    /// Max time to receive the request headers.
    pub header_timeout: Duration,
    /// Max time to receive the request body (slow senders are cut off).
    pub body_timeout: Duration,
    /// Max open connections.
    pub max_connections: usize,
    /// Max open connections from one address (IPv6: one /64). Not applied to trusted proxies.
    pub max_connections_per_address: usize,
    /// Proxies whose `X-Forwarded-For` is believed (e.g. 127.0.0.1 for Tailscale Funnel).
    pub trusted_proxies: Vec<IpAddr>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(35),
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(10),
            max_connections: 1024,
            max_connections_per_address: 32,
            trusted_proxies: Vec::new(),
        }
    }
}

/// A running server.
pub struct RunningServer {
    local_addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl RunningServer {
    /// The address it listens on.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting, lets running requests finish (max. 5 s), then returns.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = (&mut self.task).await;
    }
}

/// Starts serving `handler` on `listener`.
pub fn serve<H: Handler>(
    listener: TcpListener,
    config: ServerConfig,
    handler: Arc<H>,
) -> TransportResult<RunningServer> {
    let local_addr = listener.local_addr().map_err(|e| TransportError::Config(e.to_string()))?;
    let (stop, mut stopped) = oneshot::channel::<()>();
    let config = Arc::new(config);
    let task = tokio::spawn(async move {
        let graceful = hyper_util::server::graceful::GracefulShutdown::new();
        let connections = Arc::new(Semaphore::new(config.max_connections));
        let per_address: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { continue };
                    let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                        drop(stream); // too many connections: refuse instead of queueing (Z5)
                        continue;
                    };
                    let Some(per_address) = PerAddress::acquire(&per_address, peer.ip(), &config) else {
                        drop(stream); // one address must not take all connections
                        continue;
                    };
                    let handler = Arc::clone(&handler);
                    let header_timeout = config.header_timeout;
                    let config = Arc::clone(&config);
                    let service = service_fn(move |request| {
                        let handler = Arc::clone(&handler);
                        let config = Arc::clone(&config);
                        async move { Ok::<_, Infallible>(answer(request, peer.ip(), &config, handler).await) }
                    });
                    let connection = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(header_timeout)
                        .max_buf_size(64 * 1024)
                        .serve_connection(TokioIo::new(stream), service);
                    let connection = graceful.watch(connection);
                    tokio::spawn(async move {
                        let _ = connection.await;
                        drop(per_address);
                        drop(permit);
                    });
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), graceful.shutdown()).await;
    });
    Ok(RunningServer { local_addr, stop: Some(stop), task })
}

/// One open connection counted against its address; dropping it frees the slot.
struct PerAddress {
    table: Arc<Mutex<HashMap<IpAddr, usize>>>,
    key: Option<IpAddr>,
}

impl PerAddress {
    fn acquire(table: &Arc<Mutex<HashMap<IpAddr, usize>>>, ip: IpAddr, config: &ServerConfig) -> Option<Self> {
        if config.trusted_proxies.contains(&ip) {
            return Some(Self { table: Arc::clone(table), key: None }); // a proxy carries many callers
        }
        let key = bridge_core::address_key(ip);
        let mut counts = table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = counts.entry(key).or_insert(0);
        if *count >= config.max_connections_per_address {
            return None;
        }
        *count += 1;
        Some(Self { table: Arc::clone(table), key: Some(key) })
    }
}

impl Drop for PerAddress {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            let mut counts = self.table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(count) = counts.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    counts.remove(&key);
                }
            }
        }
    }
}

fn client_ip(request: &http::Request<Incoming>, peer: IpAddr, config: &ServerConfig) -> IpAddr {
    if !config.trusted_proxies.contains(&peer) {
        return peer;
    }
    // The trusted proxy appends the address it saw as the last entry. Only that entry counts; if it is not a plain
    // IP address, the proxy itself is the caller (never an earlier entry - the client can write those).
    request
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|last| last.trim().parse::<IpAddr>().ok())
        .unwrap_or(peer)
}

async fn answer<H: Handler>(
    request: http::Request<Incoming>,
    peer: IpAddr,
    config: &ServerConfig,
    handler: Arc<H>,
) -> http::Response<Full<Bytes>> {
    let response =
        match tokio::time::timeout(config.request_timeout, read_and_handle(request, peer, config, handler)).await {
            Ok(response) => response,
            Err(_) => Response::error(503, "UNAVAILABLE", "request took too long", None),
        };
    to_http(response)
}

async fn read_and_handle<H: Handler>(
    request: http::Request<Incoming>,
    peer: IpAddr,
    config: &ServerConfig,
    handler: Arc<H>,
) -> Response {
    let method = match *request.method() {
        http::Method::GET => Method::Get,
        http::Method::POST => Method::Post,
        _ => return unread(Response::error(405, "NOT_FOUND", "method not allowed", None)),
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > config.max_body_bytes as u64) {
        return unread(Response::error(413, "TOO_LARGE", "request body too large", None));
    }
    let peer = client_ip(&request, peer, config);
    let path = request.uri().path().to_owned();
    if path.len() > 256 {
        return unread(Response::error(404, "NOT_FOUND", "not found", None));
    }
    if let Some(refused) = handler.admit(peer, &path) {
        return unread(refused); // e.g. rate limited: the body is never read
    }
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| token.len() <= 128)
        .map(str::to_owned);
    let reading = Limited::new(request.into_body(), config.max_body_bytes).collect();
    let body = match tokio::time::timeout(config.body_timeout, reading).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
            return unread(Response::error(413, "TOO_LARGE", "request body too large", None));
        }
        Ok(Err(_)) => return unread(Response::error(400, "BAD_FORMAT", "could not read the request body", None)),
        Err(_) => return unread(Response::error(408, "BAD_FORMAT", "request body too slow", None)),
    };
    handler.handle(Request { method, path, peer, bearer, body }).await
}

/// The body of this request was (partly) not read: the connection cannot be reused, tell the client.
fn unread(response: Response) -> Response {
    Response { close: true, ..response }
}

fn to_http(response: Response) -> http::Response<Full<Bytes>> {
    let mut out = http::Response::new(Full::new(Bytes::from(response.body)));
    *out.status_mut() = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = out.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    if response.close {
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    if let Some(seconds) = response.retry_after {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            headers.insert(header::RETRY_AFTER, value);
        }
    }
    out
}

/// HTTP client for SDKs and node-to-node calls. Only `http://` and `https://` URLs; responses are size-limited.
#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    base: String,
    max_response_bytes: usize,
}

/// Status + body of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResponse {
    /// HTTP status.
    pub status: u16,
    /// Body.
    pub body: Vec<u8>,
}

impl HttpClient {
    /// A client for the node at `base_url` (e.g. `https://pc.tail91b057.ts.net/node1`).
    pub fn new(base_url: &str, timeout: Duration) -> TransportResult<Self> {
        let base = base_url.trim_end_matches('/').to_owned();
        if !(base.starts_with("http://") || base.starts_with("https://")) || base.len() > 512 {
            return Err(TransportError::Config("URL must start with http:// or https://".into()));
        }
        let inner = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("bridge4/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| TransportError::Config(e.to_string()))?;
        Ok(Self { inner, base, max_response_bytes: 2 * 1024 * 1024 })
    }

    /// GET `path`.
    pub async fn get(&self, path: &str) -> TransportResult<ClientResponse> {
        self.finish(self.inner.get(format!("{}{path}", self.base))).await
    }

    /// POST `body` to `path`, optionally with a session token.
    pub async fn post(&self, path: &str, bearer: Option<&str>, body: Vec<u8>) -> TransportResult<ClientResponse> {
        let mut request =
            self.inner.post(format!("{}{path}", self.base)).header(header::CONTENT_TYPE, "application/json").body(body);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        self.finish(request).await
    }

    async fn finish(&self, request: reqwest::RequestBuilder) -> TransportResult<ClientResponse> {
        let mut response = request.send().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        let status = response.status().as_u16();
        if response.content_length().is_some_and(|length| length > self.max_response_bytes as u64) {
            return Err(TransportError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| TransportError::Connection(e.to_string()))? {
            if body.len() + chunk.len() > self.max_response_bytes {
                return Err(TransportError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(ClientResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    impl Handler for Echo {
        async fn handle(&self, request: Request) -> Response {
            if request.path == "/slow" {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            let body = format!(
                r#"{{"path":"{}","peer":"{}","bearer":{},"len":{}}}"#,
                request.path,
                request.peer,
                request.bearer.map_or("null".to_owned(), |t| format!("\"{t}\"")),
                request.body.len()
            );
            Response::ok(body.into_bytes())
        }
    }

    async fn start(config: ServerConfig) -> TransportResult<(RunningServer, HttpClient)> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| TransportError::Config(e.to_string()))?;
        let server = serve(listener, config, Arc::new(Echo))?;
        let client = HttpClient::new(&format!("http://{}", server.local_addr()), Duration::from_secs(10))?;
        Ok((server, client))
    }

    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(COMPARTMENT, env!("CARGO_PKG_NAME"));
    }

    #[tokio::test]
    async fn roundtrip_limits_and_proxy_header() -> TransportResult<()> {
        let config = ServerConfig { max_body_bytes: 1000, ..ServerConfig::default() };
        let (server, client) = start(config).await?;
        let answer = client.post("/v4/x", Some("tok"), vec![b'a'; 1000]).await?;
        assert_eq!(answer.status, 200);
        let text = String::from_utf8_lossy(&answer.body).to_string();
        assert!(text.contains(r#""bearer":"tok""#) && text.contains(r#""len":1000"#) && text.contains("127.0.0.1"));
        let too_big = client.post("/v4/x", None, vec![b'a'; 1001]).await?;
        assert_eq!(too_big.status, 413);
        assert!(String::from_utf8_lossy(&too_big.body).contains("TOO_LARGE"));
        // X-Forwarded-For from an untrusted peer is ignored
        let spoofed = reqwest::Client::new()
            .get(format!("http://{}/x", server.local_addr()))
            .header("x-forwarded-for", "6.6.6.6")
            .send()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?
            .text()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        assert!(spoofed.contains("127.0.0.1") && !spoofed.contains("6.6.6.6"));
        server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn trusted_proxy_and_timeout() -> TransportResult<()> {
        let config = ServerConfig {
            trusted_proxies: vec!["127.0.0.1".parse().map_err(|_| TransportError::Config("ip".into()))?],
            request_timeout: Duration::from_millis(300),
            ..ServerConfig::default()
        };
        let (server, client) = start(config).await?;
        let forwarded = reqwest::Client::new()
            .get(format!("http://{}/x", server.local_addr()))
            .header("x-forwarded-for", "9.9.9.9, 7.7.7.7")
            .send()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?
            .text()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        assert!(forwarded.contains("7.7.7.7"), "{forwarded}");
        for header in ["6.6.6.6, 203.0.113.7:4711", "6.6.6.6, unknown", "6.6.6.6, [2001:db8::1]:443"] {
            let answer = reqwest::Client::new()
                .get(format!("http://{}/x", server.local_addr()))
                .header("x-forwarded-for", header)
                .send()
                .await
                .map_err(|e| TransportError::Connection(e.to_string()))?
                .text()
                .await
                .map_err(|e| TransportError::Connection(e.to_string()))?;
            assert!(!answer.contains("6.6.6.6") && answer.contains("127.0.0.1"), "{header}: {answer}");
        }
        let slow = client.get("/slow").await?;
        assert_eq!(slow.status, 503);
        server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn one_address_cannot_take_all_connections() -> TransportResult<()> {
        let config = ServerConfig { max_connections_per_address: 3, ..ServerConfig::default() };
        let (server, client) = start(config).await?;
        let mut open = Vec::new();
        for _ in 0..3 {
            open.push(
                tokio::net::TcpStream::connect(server.local_addr())
                    .await
                    .map_err(|e| TransportError::Connection(e.to_string()))?,
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(client.get("/x").await.is_err(), "fourth connection from the same address is refused");
        drop(open);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(client.get("/x").await?.status, 200, "slots are freed");
        server.shutdown().await;
        Ok(())
    }

    #[test]
    fn error_body_is_valid_json_and_urls_are_checked() {
        let response = Response::error(429, "RATE_LIMITED", "zu \"viel\"\n", Some(3));
        assert_eq!(
            String::from_utf8_lossy(&response.body),
            r#"{"error":"RATE_LIMITED","message":"zu \"viel\"\u000a","retry_after":3}"#
        );
        assert!(HttpClient::new("ftp://x", Duration::from_secs(1)).is_err());
        assert!(HttpClient::new("file:///etc/passwd", Duration::from_secs(1)).is_err());
    }
}
