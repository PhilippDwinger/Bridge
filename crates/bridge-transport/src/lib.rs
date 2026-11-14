//! # bridge-transport – moving bytes
//!
//! Connections only, no network logic (docs/03, ADR 0004): an HTTP/1.1 server that hands a node plain [`Request`]s
//! (GET, POST, and OPTIONS for CORS preflights) and sends its [`Response`]s (JSON by default, other content types and
//! headers when the node sets them, large bodies streamed from a bounded channel - [`BodyStream`]), and a client for
//! SDKs and node-to-node calls. Internet: HTTP behind a TLS proxy such as Tailscale Funnel, or HTTPS
//! as a client. LAN ([`lan`]): the same server over TLS with a self-signed certificate ([`serve_tls`]), clients that
//! trust exactly the pinned certificate ([`HttpClient::new_pinned`]), and mDNS hints where nodes are.
//!
//! Zero Trust at the door (Z5): limited connections, a timeout for headers (slowloris), the body size is checked
//! from `Content-Length` *before* reading and again while reading, every request has a total time limit, and
//! `X-Forwarded-For` is only believed from configured proxies. Streamed answers are limited too (slow readers):
//! at most `max_streams` at once and `max_streams_per_address` per caller (behind a trusted proxy: the forwarded
//! address), each must average `stream_min_bytes_per_s` after `stream_grace` and ends after `stream_max_duration` -
//! otherwise its connection is cut. Answers the transport makes itself (405, 413, timeouts, too many streams) go
//! through [`Handler::decorate`], so they carry the same headers as the node's own (CORS, sandbox). The client
//! limits response sizes too - a node can be malicious as well.
//!
//! Layering (docs/03_ARCHITEKTUR.md): depends only on `bridge-core` (address keys, hashes, IDs).

pub mod download;
pub mod lan;
mod public;

pub use lan::{Discovery, LanAnnouncer, LanHints, LanPeer, TlsIdentity};
pub use public::{PeerAddresses, is_public_ip, is_tailnet_ip};

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderValue, StatusCode, header};
use http_body_util::{BodyExt, Either, Full, Limited};
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

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
    /// The target is not allowed (an address that is not public, for a client made with
    /// [`HttpClient::new_public`]); nothing was sent.
    #[error("refused: {0}")]
    Refused(String),
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
    /// OPTIONS (CORS preflight of browsers, docs/07 §5)
    Options,
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
    /// The `Host` header (at most 255 bytes, lower case), if any - for answers only meant for local callers.
    pub host: Option<String>,
    /// The request came through a proxy: from a trusted proxy, or with any forwarding header (`X-Forwarded-For`,
    /// `Forwarded`, `X-Real-IP`, `X-Forwarded-Host`) - never a local caller then, whatever `peer` says.
    pub forwarded: bool,
    /// A Bridge Login app token from `X-Bridge-Login` (docs/11 §9.4; at most [`MAX_LOGIN_HEADER`] bytes), if any.
    pub login: Option<String>,
    /// The `Cookie` header (at most [`MAX_COOKIE_HEADER`] bytes; longer ones are dropped), if any - only Bridge Login's
    /// "angemeldet bleiben" uses one (docs/11 §16).
    pub cookies: Option<String>,
    /// `Sec-Fetch-Site` as the browser sent it (at most 32 bytes, lower case), if any.
    pub fetch_site: Option<String>,
}

/// Longest `Cookie` header taken.
pub const MAX_COOKIE_HEADER: usize = 4096;

/// Longest `X-Bridge-Login` header taken.
pub const MAX_LOGIN_HEADER: usize = 4096;

/// A response: JSON unless `headers` name another `Content-Type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// Body (ignored when `stream` is set).
    pub body: Vec<u8>,
    /// `Retry-After` in seconds.
    pub retry_after: Option<u32>,
    /// Close the connection after this answer (set when the request body was not read).
    pub close: bool,
    /// Further headers (name in lower case, value). `content-type` and `cache-control` replace the defaults
    /// (`application/json`, `no-store`); `x-content-type-options: nosniff` is always sent.
    pub headers: Vec<(String, String)>,
    /// A body produced while it is sent (large files) instead of `body`.
    pub stream: Option<BodyStream>,
}

impl Response {
    /// 200 with a JSON body.
    #[must_use]
    pub fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body, retry_after: None, close: false, headers: Vec::new(), stream: None }
    }

    /// The same response with one more header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_ascii_lowercase(), value.into()));
        self
    }

    /// An error in the protocol's format (docs/04 §9).
    #[must_use]
    pub fn error(status: u16, code: &str, message: &str, retry_after: Option<u32>) -> Self {
        let mut body = format!(r#"{{"error":"{code}","message":{}"#, json_string(message));
        if let Some(seconds) = retry_after {
            body.push_str(&format!(r#","retry_after":{seconds}"#));
        }
        body.push('}');
        Self { status, body: body.into_bytes(), retry_after, close: false, headers: Vec::new(), stream: None }
    }
}

/// A response body produced while it is sent: chunks from a bounded channel ([`BodyStream::channel`]), so a large
/// file never sits in memory as a whole. The declared length is sent as `Content-Length`; if the producer stops
/// before it (a part did not verify, the disk failed), the connection is cut - the client never sees a short body
/// as complete.
#[derive(Clone)]
pub struct BodyStream {
    receiver: Arc<Mutex<Option<mpsc::Receiver<Bytes>>>>,
    length: u64,
}

impl BodyStream {
    /// A body of exactly `length` bytes and the sender that produces it (`capacity`: chunks buffered at most).
    #[must_use]
    pub fn channel(length: u64, capacity: usize) -> (StreamSender, Self) {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        (StreamSender(sender), Self { receiver: Arc::new(Mutex::new(Some(receiver))), length })
    }

    /// The declared length.
    #[must_use]
    pub fn length(&self) -> u64 {
        self.length
    }

    fn take(&self) -> Option<mpsc::Receiver<Bytes>> {
        self.receiver.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
    }
}

impl fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BodyStream({} bytes)", self.length)
    }
}

impl PartialEq for BodyStream {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.receiver, &other.receiver)
    }
}

impl Eq for BodyStream {}

/// The producing side of a [`BodyStream`].
pub struct StreamSender(mpsc::Sender<Bytes>);

impl StreamSender {
    /// Sends the next chunk; waits at most `timeout` for room (a client that does not read is given up). `false`:
    /// the client is gone or too slow - stop producing.
    pub async fn send(&self, chunk: Vec<u8>, timeout: Duration) -> bool {
        matches!(tokio::time::timeout(timeout, self.0.send(Bytes::from(chunk))).await, Ok(Ok(())))
    }
}

/// How far one streamed answer got: bytes handed to the connection since it started (watched per connection).
struct Meter {
    started: Instant,
    sent: AtomicU64,
    done: AtomicBool,
}

impl Meter {
    /// Whether the answer is over its time or below its minimum rate (after the grace time).
    fn too_slow(&self, config: &ServerConfig) -> bool {
        let elapsed = self.started.elapsed();
        if elapsed >= config.stream_max_duration {
            return true;
        }
        if elapsed < config.stream_grace {
            return false;
        }
        let needed = u128::from(config.stream_min_bytes_per_s).saturating_mul(elapsed.as_millis()) / 1000;
        u128::from(self.sent.load(Ordering::Relaxed)) < needed
    }
}

/// The streams of a server: all of them and per caller address.
struct Streams {
    all: Arc<Semaphore>,
    per_address: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

/// One streamed answer counted against the server and its caller; dropping it frees both.
struct StreamPermit {
    _all: OwnedSemaphorePermit,
    _address: PerAddress,
    meter: Arc<Meter>,
}

impl Streams {
    fn new(config: &ServerConfig) -> Self {
        Self { all: Arc::new(Semaphore::new(config.max_streams)), per_address: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// A permit for one more stream to `client` (the forwarded address behind a trusted proxy - no exemption).
    fn acquire(&self, client: IpAddr, config: &ServerConfig) -> Option<StreamPermit> {
        let all = Arc::clone(&self.all).try_acquire_owned().ok()?;
        let address =
            PerAddress::take(&self.per_address, bridge_core::address_key(client), config.max_streams_per_address)?;
        let meter = Arc::new(Meter { started: Instant::now(), sent: AtomicU64::new(0), done: AtomicBool::new(false) });
        Some(StreamPermit { _all: all, _address: address, meter })
    }
}

/// The hyper body of a [`BodyStream`]: counts what it hands out and holds the stream's permit until it is dropped.
struct ChannelBody {
    receiver: mpsc::Receiver<Bytes>,
    remaining: u64,
    permit: StreamPermit,
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        self.permit.meter.done.store(true, Ordering::Relaxed);
    }
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.receiver.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let length = chunk.len() as u64;
                if length > this.remaining {
                    return Poll::Ready(Some(Err(std::io::Error::other("body longer than declared"))));
                }
                this.remaining -= length;
                this.permit.meter.sent.fetch_add(length, Ordering::Relaxed);
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Poll::Ready(None) if this.remaining > 0 => {
                Poll::Ready(Some(Err(std::io::Error::other("body ended before its length"))))
            }
            Poll::Ready(None) => {
                this.permit.meter.done.store(true, Ordering::Relaxed);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

/// What the server sends: a body in memory or a stream.
type HttpBody = Either<Full<Bytes>, ChannelBody>;

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
    /// Adds the node's headers to an answer the transport made itself for `path` (405, 413, timeouts, too many
    /// streams, …) - e.g. CORS, so a browser sees the error instead of a CORS failure.
    fn decorate(&self, _path: &str, response: Response) -> Response {
        response
    }
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
    /// Max time for the TLS handshake ([`serve_tls`] only): slow or silent handshakes must not hold connection slots.
    pub tls_handshake_timeout: Duration,
    /// Max streamed answers (large files) at once, all callers together.
    pub max_streams: usize,
    /// Max streamed answers at once per caller address (IPv6: one /64; behind a trusted proxy: the forwarded one).
    pub max_streams_per_address: usize,
    /// A streamed answer must average at least this many bytes per second once `stream_grace` is over - a slower
    /// reader is cut off (it would hold a connection and a stream for hours).
    pub stream_min_bytes_per_s: u64,
    /// Time before the minimum rate of a stream counts.
    pub stream_grace: Duration,
    /// Longest time for one streamed answer.
    pub stream_max_duration: Duration,
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
            tls_handshake_timeout: Duration::from_secs(10),
            max_streams: 128,
            max_streams_per_address: 8,
            stream_min_bytes_per_s: 16 * 1024,
            stream_grace: Duration::from_secs(10),
            stream_max_duration: Duration::from_secs(3600),
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

/// Starts serving `handler` on `listener` (plain HTTP, e.g. behind a TLS proxy).
pub fn serve<H: Handler>(
    listener: TcpListener,
    config: ServerConfig,
    handler: Arc<H>,
) -> TransportResult<RunningServer> {
    run(listener, config, handler, None)
}

/// Starts serving `handler` on `listener` over TLS with the node's self-signed certificate (LAN, docs/06 §2).
/// Same limits as [`serve`]; additionally every TLS handshake must finish within `tls_handshake_timeout`.
pub fn serve_tls<H: Handler>(
    listener: TcpListener,
    config: ServerConfig,
    handler: Arc<H>,
    identity: &TlsIdentity,
) -> TransportResult<RunningServer> {
    let acceptor = TlsAcceptor::from(identity.server_config()?);
    run(listener, config, handler, Some(acceptor))
}

/// The accept loop shared by plain and TLS serving: limits are taken before any byte is read or any TLS work is done.
fn run<H: Handler>(
    listener: TcpListener,
    config: ServerConfig,
    handler: Arc<H>,
    tls: Option<TlsAcceptor>,
) -> TransportResult<RunningServer> {
    let local_addr = listener.local_addr().map_err(|e| TransportError::Config(e.to_string()))?;
    let (stop, mut stopped) = oneshot::channel::<()>();
    let config = Arc::new(config);
    let task = tokio::spawn(async move {
        let graceful = GracefulShutdown::new();
        // Connections still in their TLS handshake hold a watcher but no HTTP connection yet: this tells them to give
        // up, so shutting down never waits for slow handshakes.
        let (closing, _) = watch::channel(());
        let connections = Arc::new(Semaphore::new(config.max_connections));
        let per_address: Arc<Mutex<HashMap<IpAddr, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let streams = Arc::new(Streams::new(&config));
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
                    let connection = Connection {
                        peer: peer.ip(),
                        config: Arc::clone(&config),
                        handler: Arc::clone(&handler),
                        watcher: graceful.watcher(),
                        streams: Arc::clone(&streams),
                    };
                    let tls = tls.clone();
                    let closing = closing.subscribe();
                    tokio::spawn(async move {
                        connection.run(stream, tls, closing).await;
                        drop(per_address);
                        drop(permit);
                    });
                }
            }
        }
        drop(listener);
        let _ = closing.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), graceful.shutdown()).await;
    });
    Ok(RunningServer { local_addr, stop: Some(stop), task })
}

/// One accepted connection: optionally a bounded TLS handshake, then HTTP/1.1 on the resulting byte stream.
struct Connection<H> {
    peer: IpAddr,
    config: Arc<ServerConfig>,
    handler: Arc<H>,
    watcher: Watcher,
    streams: Arc<Streams>,
}

/// The stream a connection is sending right now (HTTP/1.1: one answer at a time), for its watchdog.
type StreamSlot = watch::Sender<Option<Arc<Meter>>>;

impl<H: Handler> Connection<H> {
    async fn run(self, stream: TcpStream, tls: Option<TlsAcceptor>, mut closing: watch::Receiver<()>) {
        let Some(acceptor) = tls else {
            self.serve_http(stream).await;
            return;
        };
        let handshake = tokio::time::timeout(self.config.tls_handshake_timeout, acceptor.accept(stream));
        let stream = tokio::select! {
            done = handshake => match done {
                Ok(Ok(stream)) => stream,
                _ => return, // failed or too slow: drop the connection and free its slots (Z5, Z8)
            },
            _ = closing.changed() => return, // shutting down: no new sessions
        };
        self.serve_http(stream).await;
    }

    async fn serve_http<S>(self, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Self { peer, config, handler, watcher, streams } = self;
        let header_timeout = config.header_timeout;
        let (slot, watched) = watch::channel(None);
        let slot = Arc::new(slot);
        let limits = Arc::clone(&config);
        let service = service_fn(move |request| {
            let handler = Arc::clone(&handler);
            let config = Arc::clone(&config);
            let (streams, slot) = (Arc::clone(&streams), Arc::clone(&slot));
            async move {
                let context = Answering { peer, config: &config, streams: &streams, slot: &slot };
                Ok::<_, Infallible>(answer(request, &context, handler).await)
            }
        });
        let connection = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(header_timeout)
            .max_buf_size(64 * 1024)
            .serve_connection(TokioIo::new(stream), service);
        // A slow reader of a stream loses its connection: dropping the connection future closes the socket, drops
        // the body (freeing its stream permit) and stops the producer.
        tokio::select! {
            _ = watcher.watch(connection) => {}
            () = watchdog(watched, &limits) => tracing::debug!(%peer, "stream too slow or too long: connection cut"),
        }
    }
}

/// Returns when the stream the connection is sending is too slow or too long (never while none is sent).
async fn watchdog(mut slot: watch::Receiver<Option<Arc<Meter>>>, config: &ServerConfig) {
    let tick = (config.stream_grace / 4).clamp(Duration::from_millis(50), Duration::from_secs(1));
    loop {
        let meter = slot.borrow_and_update().clone();
        match meter {
            Some(meter) if !meter.done.load(Ordering::Relaxed) => {
                tokio::time::sleep(tick).await;
                if !meter.done.load(Ordering::Relaxed) && meter.too_slow(config) {
                    return;
                }
            }
            _ => {
                if slot.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }
}

/// What answering one request needs from its connection.
struct Answering<'a> {
    peer: IpAddr,
    config: &'a ServerConfig,
    streams: &'a Streams,
    slot: &'a StreamSlot,
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
        Self::take(table, bridge_core::address_key(ip), config.max_connections_per_address)
    }

    /// One more slot for `key`, if it has fewer than `max`.
    fn take(table: &Arc<Mutex<HashMap<IpAddr, usize>>>, key: IpAddr, max: usize) -> Option<Self> {
        let mut counts = table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = counts.entry(key).or_insert(0);
        if *count >= max {
            if *count == 0 {
                counts.remove(&key);
            }
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
    context: &Answering<'_>,
    handler: Arc<H>,
) -> http::Response<HttpBody> {
    let config = context.config;
    let path = request.uri().path().to_owned();
    let client = client_ip(&request, context.peer, config);
    let proxied = config.trusted_proxies.contains(&context.peer);
    let reading = read_and_handle(request, client, proxied, &path, config, handler.as_ref());
    let response = match tokio::time::timeout(config.request_timeout, reading).await {
        Ok(response) => response,
        Err(_) => handler.decorate(&path, Response::error(503, "UNAVAILABLE", "request took too long", None)),
    };
    if response.stream.is_none() {
        return to_http(response, None);
    }
    match context.streams.acquire(client, config) {
        Some(permit) => {
            context.slot.send_replace(Some(Arc::clone(&permit.meter)));
            to_http(response, Some(permit))
        }
        // Too many streams: the stream is dropped unsent (its producer stops), the caller may come back.
        None => to_http(
            handler.decorate(&path, Response::error(429, "RATE_LIMITED", "too many downloads at once", Some(5))),
            None,
        ),
    }
}

async fn read_and_handle<H: Handler>(
    request: http::Request<Incoming>,
    peer: IpAddr,
    proxied: bool,
    path: &str,
    config: &ServerConfig,
    handler: &H,
) -> Response {
    // Answers made here (the request is not read further) carry the node's headers too.
    let refuse = |status: u16, code: &str, message: &str| {
        handler.decorate(path, unread(Response::error(status, code, message, None)))
    };
    let method = match *request.method() {
        http::Method::GET => Method::Get,
        http::Method::POST => Method::Post,
        http::Method::OPTIONS => Method::Options,
        _ => return refuse(405, "NOT_FOUND", "method not allowed"),
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > config.max_body_bytes as u64) {
        return refuse(413, "TOO_LARGE", "request body too large");
    }
    if path.len() > 256 {
        return refuse(404, "NOT_FOUND", "not found");
    }
    let path = path.to_owned();
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
    let headers = request.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| host.len() <= 255)
        .map(str::to_ascii_lowercase);
    let forwarded = proxied
        || ["x-forwarded-for", "forwarded", "x-real-ip", "x-forwarded-host"]
            .iter()
            .any(|name| headers.contains_key(*name));
    let login = match headers.get("x-bridge-login").map(|value| value.to_str()) {
        None => None,
        Some(Ok(token)) if token.len() <= MAX_LOGIN_HEADER => Some(token.to_owned()),
        Some(_) => return refuse(400, "BAD_FORMAT", "X-Bridge-Login: too long or not text"),
    };
    let cookies = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .filter(|cookies| cookies.len() <= MAX_COOKIE_HEADER)
        .map(str::to_owned);
    let fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .filter(|site| site.len() <= 32)
        .map(str::to_ascii_lowercase);
    let reading = Limited::new(request.into_body(), config.max_body_bytes).collect();
    let body = match tokio::time::timeout(config.body_timeout, reading).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
            return refuse(413, "TOO_LARGE", "request body too large");
        }
        Ok(Err(_)) => return refuse(400, "BAD_FORMAT", "could not read the request body"),
        Err(_) => return refuse(408, "BAD_FORMAT", "request body too slow"),
    };
    handler.handle(Request { method, path, peer, bearer, body, host, forwarded, login, cookies, fetch_site }).await
}

/// The body of this request was (partly) not read: the connection cannot be reused, tell the client.
fn unread(response: Response) -> Response {
    Response { close: true, ..response }
}

fn to_http(response: Response, permit: Option<StreamPermit>) -> http::Response<HttpBody> {
    let body = match (&response.stream, permit) {
        (Some(stream), Some(permit)) => match stream.take() {
            Some(receiver) => Either::Right(ChannelBody { receiver, remaining: stream.length, permit }),
            None => return to_http(Response::error(503, "UNAVAILABLE", "body already sent", None), None),
        },
        (Some(_), None) => return to_http(Response::error(503, "UNAVAILABLE", "no stream permit", None), None),
        (None, _) => Either::Left(Full::new(Bytes::from(response.body))),
    };
    let mut out = http::Response::new(body);
    *out.status_mut() = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = out.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, value) in &response.headers {
        // Only well-formed names and values (no line breaks): anything else is dropped, never sent half.
        if let (Ok(name), Ok(value)) = (http::HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            if name == header::CONTENT_LENGTH || name == header::CONNECTION {
                continue;
            }
            if name == header::CONTENT_TYPE || name == header::CACHE_CONTROL {
                headers.insert(name, value);
            } else {
                headers.append(name, value);
            }
        }
    }
    if let Some(stream) = &response.stream {
        if let Ok(value) = HeaderValue::from_str(&stream.length.to_string()) {
            headers.insert(header::CONTENT_LENGTH, value);
        }
    }
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

/// Max response body the client accepts (a node can be malicious too, Z5).
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Max length of a base URL.
const MAX_BASE_URL: usize = 512;

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
        if !(base.starts_with("http://") || base.starts_with("https://")) || base.len() > MAX_BASE_URL {
            return Err(TransportError::Config("URL must start with http:// or https://".into()));
        }
        let inner = Self::builder(timeout).build().map_err(|e| TransportError::Config(e.to_string()))?;
        Ok(Self { inner, base, max_response_bytes: MAX_RESPONSE_BYTES })
    }

    /// Settings every client shares: timeouts, no redirects (a node must not send us elsewhere), our user agent.
    fn builder(timeout: Duration) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("bridge4/", env!("CARGO_PKG_VERSION")))
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
        let mut response = request.send().await.map_err(|e| connection_error(&e))?;
        let status = response.status().as_u16();
        if response.content_length().is_some_and(|length| length > self.max_response_bytes as u64) {
            return Err(TransportError::TooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| connection_error(&e))? {
            if body.len() + chunk.len() > self.max_response_bytes {
                return Err(TransportError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(ClientResponse { status, body })
    }
}

/// The error with its causes (e.g. "… : invalid peer certificate: …"), bounded in depth and length.
pub(crate) fn connection_error(error: &dyn std::error::Error) -> TransportError {
    let mut text = error.to_string();
    let mut cause = error.source();
    for _ in 0..4 {
        let Some(inner) = cause else { break };
        text.push_str(": ");
        text.push_str(&inner.to_string());
        cause = inner.source();
    }
    if text.len() > 400 {
        let mut end = 400;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    TransportError::Connection(text)
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
                r#"{{"path":"{}","peer":"{}","bearer":{},"len":{},"host":"{}","forwarded":{}}}"#,
                request.path,
                request.peer,
                request.bearer.map_or("null".to_owned(), |t| format!("\"{t}\"")),
                request.body.len(),
                request.host.unwrap_or_default(),
                request.forwarded
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
        // Host and "forwarded" (docs/08 §8): a direct call is not forwarded, the host is what the client asked for.
        let host = format!(r#""host":"{}""#, server.local_addr());
        assert!(text.contains(&host) && text.contains(r#""forwarded":false"#), "{text}");
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
        // ... but the request counts as forwarded: never a local caller for answers only meant for the own computer.
        assert!(spoofed.contains(r#""forwarded":true"#), "{spoofed}");
        for name in ["forwarded", "x-real-ip", "x-forwarded-host"] {
            let answer = reqwest::Client::new()
                .get(format!("http://{}/x", server.local_addr()))
                .header(name, "8.8.8.8")
                .header("host", "Evil.Example")
                .send()
                .await
                .map_err(|e| TransportError::Connection(e.to_string()))?
                .text()
                .await
                .map_err(|e| TransportError::Connection(e.to_string()))?;
            assert!(answer.contains(r#""forwarded":true"#) && answer.contains(r#""host":"evil.example""#), "{answer}");
        }
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
        assert!(forwarded.contains(r#""forwarded":true"#), "{forwarded}");
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

    struct Files;

    impl Handler for Files {
        async fn handle(&self, request: Request) -> Response {
            match (request.method, request.path.as_str()) {
                (Method::Options, _) => {
                    Response { status: 204, ..Response::ok(Vec::new()) }.with_header("access-control-allow-origin", "*")
                }
                (Method::Get, "/file") => {
                    let (sender, stream) = BodyStream::channel(3 * 65_536, 2);
                    tokio::spawn(async move {
                        for byte in [1u8, 2, 3] {
                            if !sender.send(vec![byte; 65_536], Duration::from_secs(5)).await {
                                return;
                            }
                        }
                    });
                    Response { stream: Some(stream), ..Response::ok(Vec::new()) }
                        .with_header("Content-Type", "text/html; charset=utf-8")
                        .with_header("etag", "\"x\"")
                        .with_header("bad", "line\nbreak")
                }
                (Method::Get, "/short") => {
                    let (sender, stream) = BodyStream::channel(100, 2);
                    tokio::spawn(async move {
                        sender.send(vec![0u8; 10], Duration::from_secs(5)).await;
                    });
                    Response { stream: Some(stream), ..Response::ok(Vec::new()) }
                }
                // 64 MiB as fast as the reader takes it.
                (Method::Get, "/big") => stream_of(BIG, Duration::ZERO),
                // 64 KiB every 50 ms (about 1.3 MB/s) - never done within a test.
                (Method::Get, "/trickle") => stream_of(BIG, Duration::from_millis(50)),
                _ => Response::error(404, "NOT_FOUND", "not found", None),
            }
        }

        fn decorate(&self, path: &str, response: Response) -> Response {
            response.with_header("x-decorated", path.to_owned())
        }
    }

    const BIG: u64 = 64 << 20;

    fn stream_of(length: u64, pause: Duration) -> Response {
        let (sender, stream) = BodyStream::channel(length, 4);
        tokio::spawn(async move {
            for _ in 0..length / 65_536 {
                if !pause.is_zero() {
                    tokio::time::sleep(pause).await;
                }
                if !sender.send(vec![7u8; 65_536], Duration::from_secs(30)).await {
                    return;
                }
            }
        });
        Response { stream: Some(stream), ..Response::ok(Vec::new()) }
    }

    /// Sends a raw GET (optionally with `X-Forwarded-For`) and returns the stream after the request was written.
    async fn raw(addr: SocketAddr, path: &str, forwarded: Option<&str>) -> TransportResult<TcpStream> {
        use tokio::io::AsyncWriteExt as _;
        let mut stream = TcpStream::connect(addr).await.map_err(|e| TransportError::Connection(e.to_string()))?;
        let extra = forwarded.map(|ip| format!("X-Forwarded-For: {ip}\r\n")).unwrap_or_default();
        let request = format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n{extra}\r\n");
        stream.write_all(request.as_bytes()).await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(stream)
    }

    /// Reads until the connection ends (or 20 s pass): bytes read, and the status of the answer.
    async fn drain(mut stream: TcpStream) -> (usize, u16, String) {
        use tokio::io::AsyncReadExt as _;
        let mut total = 0usize;
        let mut head = Vec::new();
        let mut buffer = vec![0u8; 1 << 16];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while let Ok(Ok(read)) = tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
            if read == 0 {
                break;
            }
            if head.len() < 1024 {
                head.extend_from_slice(&buffer[..read.min(1024)]);
            }
            total += read;
        }
        let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
        let status = text.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
        (total, status, text)
    }

    async fn files(config: ServerConfig) -> TransportResult<RunningServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| TransportError::Config(e.to_string()))?;
        serve(listener, config, Arc::new(Files))
    }

    #[tokio::test]
    async fn a_slow_reader_is_cut_off_a_fast_one_is_not() -> TransportResult<()> {
        let config = ServerConfig {
            stream_min_bytes_per_s: 16 << 20,
            stream_grace: Duration::from_millis(300),
            ..ServerConfig::default()
        };
        let server = files(config).await?;
        // A reader that takes nothing for 3 s: the server cuts it long before 64 MiB went out.
        let slow = raw(server.local_addr(), "/big", None).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (total, status, _) = drain(slow).await;
        assert_eq!(status, 200);
        assert!(total < BIG as usize / 2, "cut off after {total} bytes");
        // A reader that reads at once gets everything.
        let (total, status, _) = drain(raw(server.local_addr(), "/big", None).await?).await;
        assert_eq!(status, 200);
        assert!(total > BIG as usize, "{total}");
        server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn a_stream_ends_after_its_longest_time() -> TransportResult<()> {
        let config = ServerConfig {
            stream_min_bytes_per_s: 1,
            stream_grace: Duration::from_millis(100),
            stream_max_duration: Duration::from_millis(600),
            ..ServerConfig::default()
        };
        let server = files(config).await?;
        let started = std::time::Instant::now();
        let (total, status, _) = drain(raw(server.local_addr(), "/trickle", None).await?).await;
        assert_eq!(status, 200);
        assert!(total < BIG as usize && started.elapsed() < Duration::from_secs(10), "{total}");
        server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn streams_are_bounded_per_address_also_behind_a_proxy() -> TransportResult<()> {
        let proxy: IpAddr = [127, 0, 0, 1].into();
        let config = ServerConfig {
            trusted_proxies: vec![proxy],
            max_streams_per_address: 2,
            max_streams: 3,
            stream_min_bytes_per_s: 1,
            ..ServerConfig::default()
        };
        let server = files(config).await?;
        let addr = server.local_addr();
        // Two streams of one forwarded caller: a third is refused (with the handler's headers), another caller
        // gets one, then the server's total is reached.
        let first = raw(addr, "/trickle", Some("203.0.113.1")).await?;
        let second = raw(addr, "/trickle", Some("203.0.113.1")).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (_, status, head) = drain(raw(addr, "/trickle", Some("203.0.113.1")).await?).await;
        assert_eq!(status, 429, "{head}");
        assert!(head.contains("x-decorated: /trickle") && head.contains("retry-after: 5"), "{head}");
        let other = raw(addr, "/trickle", Some("203.0.113.2")).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (_, status, _) = drain(raw(addr, "/trickle", Some("203.0.113.3")).await?).await;
        assert_eq!(status, 429, "all streams of the server are taken");
        // Freed when a reader goes.
        drop((first, second, other));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let again = raw(addr, "/trickle", Some("203.0.113.1")).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut again = again;
        let mut head = [0u8; 12];
        tokio::io::AsyncReadExt::read_exact(&mut again, &mut head)
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        assert_eq!(&head, b"HTTP/1.1 200");
        server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn transport_errors_carry_the_handlers_headers() -> TransportResult<()> {
        let config = ServerConfig { max_body_bytes: 10, ..ServerConfig::default() };
        let server = files(config).await?;
        let base = format!("http://{}", server.local_addr());
        let client = reqwest::Client::new();
        let error = |e: reqwest::Error| TransportError::Connection(e.to_string());
        let put = client.put(format!("{base}/v4/x")).send().await.map_err(error)?;
        assert_eq!(put.status().as_u16(), 405);
        assert_eq!(put.headers().get("x-decorated").map(|v| v.as_bytes()), Some(&b"/v4/x"[..]));
        let large = client.post(format!("{base}/v4/y")).body(vec![0u8; 11]).send().await.map_err(error)?;
        assert_eq!(large.status().as_u16(), 413);
        assert_eq!(large.headers().get("x-decorated").map(|v| v.as_bytes()), Some(&b"/v4/y"[..]));
        server.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn options_headers_and_streamed_bodies() -> TransportResult<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| TransportError::Config(e.to_string()))?;
        let server = serve(listener, ServerConfig::default(), Arc::new(Files))?;
        let base = format!("http://{}", server.local_addr());
        let client = reqwest::Client::new();
        let error = |e: reqwest::Error| TransportError::Connection(e.to_string());
        let preflight = client.request(reqwest::Method::OPTIONS, format!("{base}/v4/x")).send().await.map_err(error)?;
        assert_eq!(preflight.status().as_u16(), 204);
        assert_eq!(preflight.headers().get("access-control-allow-origin").map(|v| v.as_bytes()), Some(&b"*"[..]));
        let file = client.get(format!("{base}/file")).send().await.map_err(error)?;
        let headers = file.headers().clone();
        assert_eq!(headers.get("content-type").map(|v| v.as_bytes()), Some(&b"text/html; charset=utf-8"[..]));
        assert_eq!(headers.get("content-length").map(|v| v.as_bytes()), Some(&b"196608"[..]));
        assert_eq!(headers.get("x-content-type-options").map(|v| v.as_bytes()), Some(&b"nosniff"[..]));
        assert!(headers.get("etag").is_some() && headers.get("bad").is_none(), "bad header values are dropped");
        let body = file.bytes().await.map_err(error)?;
        assert_eq!(body.len(), 3 * 65_536);
        assert_eq!((body[0], body[65_536], body[3 * 65_536 - 1]), (1, 2, 3));
        // A stream that ends before its length: the client sees an error, never a short "complete" body.
        let short = client.get(format!("{base}/short")).send().await.map_err(error)?;
        assert!(short.bytes().await.is_err());
        // Other methods are still refused.
        let put = client.put(format!("{base}/file")).send().await.map_err(error)?;
        assert_eq!(put.status().as_u16(), 405);
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
