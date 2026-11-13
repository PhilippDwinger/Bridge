//! The gate's server: accepts, limits, routes ([`crate::decide`]) and forwards to the nodes on `127.0.0.1`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, HOST, HeaderMap, HeaderName};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::route::{Decision, Routes, decide};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;

/// Most client addresses counted at once (beyond that new addresses wait for a free entry: `503`).
const MAX_CLIENTS: usize = 100_000;

/// CSP of the gate's own pages.
const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";

/// Headers of a request that never go to the node: hop-by-hop headers and every forwarding header of the caller
/// (the gate sets its own). Also every header the `Connection` header names.
const DROPPED_REQUEST: [&str; 16] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
];

/// Hop-by-hop headers of an answer.
const DROPPED_ANSWER: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The gate's limits (docs/11 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Connections at once.
    pub max_connections: usize,
    /// Requests at once per client address (IPv6: per /64).
    pub per_client: usize,
    /// Time for the request headers.
    pub header_timeout: Duration,
    /// Most request headers.
    pub max_headers: usize,
    /// Most bytes of the request head (at least 8 KiB).
    pub max_head_bytes: usize,
    /// Largest request body.
    pub max_body: usize,
    /// Time to connect to the node.
    pub connect_timeout: Duration,
    /// Time until the node's answer head (its long polls take up to 25 s, a request at most 35 s).
    pub answer_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 512,
            per_client: 32,
            header_timeout: Duration::from_secs(10),
            max_headers: 64,
            max_head_bytes: 16 * 1024,
            max_body: 4 * 1024 * 1024,
            connect_timeout: Duration::from_secs(5),
            answer_timeout: Duration::from_secs(40),
        }
    }
}

/// The routes the gate uses now - swapped whole when the route file changes (no restart, no dropped connection).
#[derive(Clone, Default)]
pub struct SharedRoutes(Arc<std::sync::RwLock<Arc<Routes>>>);

impl SharedRoutes {
    /// Routes to start with.
    #[must_use]
    pub fn new(routes: Routes) -> Self {
        Self(Arc::new(std::sync::RwLock::new(Arc::new(routes))))
    }

    /// The current routes.
    #[must_use]
    pub fn get(&self) -> Arc<Routes> {
        Arc::clone(&self.0.read().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// Replaces the routes (requests already running keep the ones they started with).
    pub fn set(&self, routes: Routes) {
        *self.0.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(routes);
    }
}

struct State {
    routes: SharedRoutes,
    limits: Limits,
    clients: Mutex<HashMap<IpAddr, usize>>,
}

/// One request of one client address; frees its count when dropped.
struct Slot {
    state: Arc<State>,
    client: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut clients = self.state.clients.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = clients.get_mut(&self.client) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                clients.remove(&self.client);
            }
        }
    }
}

impl State {
    fn enter(self: &Arc<Self>, client: IpAddr) -> Option<Slot> {
        let mut clients = self.clients.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !clients.contains_key(&client) && clients.len() >= MAX_CLIENTS {
            return None;
        }
        let count = clients.entry(client).or_insert(0);
        if *count >= self.limits.per_client {
            return None;
        }
        *count += 1;
        Some(Slot { state: Arc::clone(self), client })
    }
}

/// Serves the gate on `listener` until `shutdown` completes.
pub async fn serve(listener: TcpListener, routes: Routes, limits: Limits, shutdown: impl Future<Output = ()>) {
    serve_shared(listener, SharedRoutes::new(routes), limits, shutdown).await;
}

/// Like [`serve`], with routes that can change while it runs ([`SharedRoutes::set`]).
pub async fn serve_shared(
    listener: TcpListener,
    routes: SharedRoutes,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) {
    let state = Arc::new(State { routes, limits, clients: Mutex::new(HashMap::new()) });
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            () = &mut shutdown => break,
            permit = Arc::clone(&connections).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "accept");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(state.limits.header_timeout)
                .max_headers(state.limits.max_headers)
                .max_buf_size(state.limits.max_head_bytes.max(8192))
                .keep_alive(true);
            let service = service_fn(move |request| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(handle(request, peer, state).await) }
            });
            let _ = builder.serve_connection(TokioIo::new(stream), service).await;
        });
    }
}

async fn handle(request: Request<Incoming>, peer: SocketAddr, state: Arc<State>) -> Response<Body> {
    if !matches!(*request.method(), Method::GET | Method::POST | Method::OPTIONS) {
        return page(StatusCode::METHOD_NOT_ALLOWED, "Nicht erlaubt", "Diese Art Anfrage gibt es hier nicht.");
    }
    if request.uri().scheme().is_some() || request.uri().authority().is_some() {
        return page(StatusCode::BAD_REQUEST, "Ungültig", "Diese Anfrage nimmt das Tor nicht an.");
    }
    let client = client_ip(request.headers(), peer.ip());
    let Some(_slot) = state.enter(bucket(client)) else {
        return page(StatusCode::TOO_MANY_REQUESTS, "Zu viele Anfragen", "Bitte gleich noch einmal versuchen.");
    };
    let target = request.uri().path_and_query().map_or("/", |pq| pq.as_str()).to_owned();
    let routes = state.routes.get();
    match decide(&routes, &target) {
        Decision::Home => page(
            StatusCode::OK,
            "Bridge 4",
            "Hier wohnen BridgeNets. Ohne die Adresse eines Netzes gibt es hier nichts zu sehen.",
        ),
        Decision::Redirect(location) => redirect(&location),
        Decision::NotFound => page(StatusCode::NOT_FOUND, "Nicht gefunden", "Dieses Netz gibt es hier nicht."),
        Decision::Off => page(
            StatusCode::SERVICE_UNAVAILABLE,
            "Gerade nicht öffentlich",
            "Die Websites dieses Netzes sind gerade nicht öffentlich.",
        ),
        Decision::Bad => page(StatusCode::BAD_REQUEST, "Ungültig", "Diese Adresse nimmt das Tor nicht an."),
        Decision::Forward { port, target } => {
            let too_large = request
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|length| length > state.limits.max_body as u64);
            if too_large {
                return page(StatusCode::PAYLOAD_TOO_LARGE, "Zu groß", "Die Anfrage ist zu groß.");
            }
            match forward(request, port, &target, client, &state.limits).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::debug!(%error, port, "forward");
                    page(
                        StatusCode::BAD_GATEWAY,
                        "Gerade nicht erreichbar",
                        "Der Knoten dieses Netzes antwortet gerade nicht.",
                    )
                }
            }
        }
    }
}

/// The client's address: behind Tailscale (a caller on loopback) the last `X-Forwarded-For` entry - the one the
/// proxy appended itself -, else the caller.
fn client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if !peer.to_canonical().is_loopback() {
        return peer;
    }
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|last| last.trim().parse::<IpAddr>().ok())
        .map_or(peer, |ip| ip.to_canonical())
}

/// The address the limit counts: IPv4 as is, IPv6 per /64 (one connection often has a whole /64).
fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            segments[4..].fill(0);
            IpAddr::V6(Ipv6Addr::from(segments))
        }
    }
}

async fn forward(
    request: Request<Incoming>,
    port: u16,
    target: &str,
    client: IpAddr,
    limits: &Limits,
) -> Result<Response<Body>, BoxError> {
    let stream = tokio::time::timeout(limits.connect_timeout, TcpStream::connect((IpAddr::from([127, 0, 0, 1]), port)))
        .await
        .map_err(|_| "connect: timeout")??;
    let _ = stream.set_nodelay(true);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let (parts, body) = request.into_parts();
    let named: Vec<HeaderName> = parts
        .headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    let mut builder = Request::builder().method(parts.method).uri(target);
    for (name, value) in &parts.headers {
        if DROPPED_REQUEST.contains(&name.as_str()) || name.as_str().starts_with("x-forwarded-") || named.contains(name)
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder
        .header(HOST, format!("127.0.0.1:{port}"))
        .header("x-forwarded-for", client.to_string())
        .header("x-forwarded-proto", "https");
    let body: Body = Limited::new(body, limits.max_body).boxed();
    let outgoing = builder.body(body)?;
    let response = tokio::time::timeout(limits.answer_timeout, sender.send_request(outgoing))
        .await
        .map_err(|_| "answer: timeout")??;
    let (mut parts, body) = response.into_parts();
    for name in DROPPED_ANSWER {
        parts.headers.remove(name);
    }
    Ok(Response::from_parts(parts, body.map_err(BoxError::from).boxed()))
}

fn redirect(location: &str) -> Response<Body> {
    let mut response = page(StatusCode::PERMANENT_REDIRECT, "Weiter", "Weiter …");
    if let Ok(value) = location.parse() {
        response.headers_mut().insert(hyper::header::LOCATION, value);
    }
    response
}

/// A small page of the gate itself (German, no scripts).
fn page(status: StatusCode, title: &str, text: &str) -> Response<Body> {
    let html = format!(
        "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width,initial-scale=1\"><title>{title}</title><style>body{{font:16px/1.5 system-ui,\
         sans-serif;color:#1d2433;background:#f6f7fb;max-width:40rem;margin:3rem auto;padding:0 1rem}}</style></head>\
         <body><h1>{title}</h1><p>{text}</p></body></html>"
    );
    let mut response = Response::new(Full::new(Bytes::from(html)).map_err(BoxError::from).boxed());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    for (name, value) in [
        ("content-type", "text/html; charset=utf-8"),
        ("cache-control", "no-store"),
        ("content-security-policy", PAGE_CSP),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
    ] {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), value.parse()) {
            headers.insert(name, value);
        }
    }
    if status == StatusCode::METHOD_NOT_ALLOWED {
        if let Ok(value) = "GET, POST, OPTIONS".parse() {
            headers.insert(hyper::header::ALLOW, value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_addresses() {
        let loopback = IpAddr::from([127, 0, 0, 1]);
        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            "1.1.1.1, 2.2.2.2".parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("")),
        );
        headers.append(
            "x-forwarded-for",
            "9.9.9.9".parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("")),
        );
        assert_eq!(client_ip(&headers, loopback), IpAddr::from([9, 9, 9, 9]), "only the last entry of the proxy");
        assert_eq!(client_ip(&headers, IpAddr::from([5, 5, 5, 5])), IpAddr::from([5, 5, 5, 5]), "no proxy: the caller");
        assert_eq!(client_ip(&HeaderMap::new(), loopback), loopback);
        let mut odd = HeaderMap::new();
        odd.append(
            "x-forwarded-for",
            "nonsense".parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("")),
        );
        assert_eq!(client_ip(&odd, loopback), loopback);
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap_or(loopback);
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap_or(loopback);
        assert_eq!(bucket(a), bucket(b), "one /64");
        assert_ne!(bucket(a), bucket("2001:db8:1:3::1".parse().unwrap_or(loopback)));
    }

    #[test]
    fn slots_are_bounded_per_client_and_freed() {
        let limits = Limits { per_client: 2, ..Limits::default() };
        let state = Arc::new(State { routes: SharedRoutes::default(), limits, clients: Mutex::new(HashMap::new()) });
        let ip = IpAddr::from([1, 2, 3, 4]);
        let first = state.enter(ip);
        let second = state.enter(ip);
        assert!(first.is_some() && second.is_some());
        assert!(state.enter(ip).is_none(), "third at once");
        assert!(state.enter(IpAddr::from([1, 2, 3, 5])).is_some(), "another client");
        drop(first);
        assert!(state.enter(ip).is_some(), "freed");
        drop(second);
        assert!(state.clients.lock().map(|c| c.len()).unwrap_or(9) <= 1);
    }
}
