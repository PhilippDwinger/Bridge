//! The local web server of the UI (ADR 0017) and its protections - Zero Trust also on this PC:
//!
//! - Listens on `127.0.0.1` only. At most [`MAX_CONNECTIONS`] connections, headers within 10 s, bodies at most
//!   [`MAX_BODY_BYTES`] (read within 10 s), only `GET` and `POST`.
//! - **Host check** before anything else: `Host` must be `127.0.0.1:<port>` or `localhost:<port>` - a web page that
//!   points its own name at 127.0.0.1 (DNS rebinding) gets 403.
//! - **Session**: a random 256-bit token made at start. The browser gets it once through a one-time login link
//!   (`/login/<code>`, the code works once and only for 5 minutes) as an `HttpOnly`, `SameSite=Strict` cookie.
//!   Every API call and every screen needs it (401 otherwise); only the design system and the "not logged in" page
//!   are public. Tokens are compared by their SHA-256 (no timing hints).
//! - **CSRF**: every `POST` needs `Origin: http://127.0.0.1:<port>` (or `localhost`) and `Content-Type:
//!   application/json` - a form or a script of another site can send neither without a CORS preflight, and there is
//!   no CORS here at all.
//! - **Headers** on every answer: CSP `default-src 'self'` (no inline scripts or styles, nothing from elsewhere),
//!   `frame-src 'none'`, `frame-ancestors 'none'`, `nosniff`, no referrer, `no-store` for everything but the design
//!   files. Only the page itself (`/`) may frame something: exactly the readers of this PC's nodes
//!   (`http://127.0.0.1:<node port>`, [`crate::browser::frame_origins`]) - the Bridge-Browser shows apps there in a
//!   sandboxed `iframe`.
//! - `POST /api/launch` is how a second start of the app asks for a new login link: it proves the launch key from the
//!   owner-only instance file without sending it (`X-Launch-Nonce`, `X-Launch-Proof` = MAC of the nonce under the key;
//!   each nonce once), and the answer carries a MAC of nonce and login path, so the second start opens nothing a
//!   stranger on a stale port says (review 8). No cookie; it passes the Host check like everything else.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::crypto::sha256;
use bridge_core::encoding::b64;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::{App, api, assets, now_ms};

/// Most connections at once.
pub const MAX_CONNECTIONS: usize = 64;
/// Largest request body.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Longest path (with query).
const MAX_TARGET: usize = 2048;
/// Name of the session cookie.
pub const COOKIE: &str = "bc_session";
/// How long a login link works.
const LOGIN_TTL_MS: i64 = 5 * 60 * 1000;
/// Most login links open at once.
const MAX_LOGIN_CODES: usize = 8;
/// Most launch nonces remembered (each one works once).
const MAX_LAUNCH_NONCES: usize = 64;
/// MAC domains of the launch protocol (`bridge_core::crypto::mac`).
const LAUNCH_REQUEST: &str = "bridgecontroll/launch-request";
const LAUNCH_ANSWER: &str = "bridgecontroll/launch-answer";
/// The Content-Security-Policy of every answer (the page `/` gets [`page_csp`]).
pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; \
                       connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; \
                       frame-ancestors 'none'";

/// The CSP of the page `/`: like [`CSP`], but `frame-src` lists exactly `origins` (the readers of this PC's nodes,
/// `http://127.0.0.1:<port>` - nothing else is accepted); none: `'none'`.
#[must_use]
pub fn page_csp(origins: &[String]) -> String {
    let allowed: Vec<&str> = origins
        .iter()
        .map(String::as_str)
        .filter(|origin| {
            origin
                .strip_prefix("http://127.0.0.1:")
                .is_some_and(|port| !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    if allowed.is_empty() {
        return CSP.to_owned();
    }
    CSP.replace("frame-src 'none'", &format!("frame-src {}", allowed.join(" ")))
}

/// Session and login links of the running app.
pub struct Auth {
    session: Zeroizing<String>,
    session_hash: [u8; 32],
    launch: Zeroizing<String>,
    codes: Mutex<Vec<([u8; 32], i64)>>,
    nonces: Mutex<std::collections::VecDeque<[u8; 32]>>,
}

impl Default for Auth {
    fn default() -> Self {
        Self::new()
    }
}

impl Auth {
    /// New random session token and launch key (256 bit each).
    #[must_use]
    pub fn new() -> Self {
        let session = random_token();
        let launch = random_token();
        Self {
            session_hash: sha256(session.as_bytes()),
            session,
            launch,
            codes: Mutex::new(Vec::new()),
            nonces: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// The launch key (goes into the owner-only instance file).
    #[must_use]
    pub fn launch_key(&self) -> &str {
        &self.launch
    }

    /// A new one-time login code (the oldest open one goes beyond [`MAX_LOGIN_CODES`]).
    #[must_use]
    pub fn new_login_code(&self, now: i64) -> String {
        let code = random_token();
        let mut codes = self.codes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        codes.retain(|(_, exp)| *exp > now);
        if codes.len() >= MAX_LOGIN_CODES {
            codes.remove(0);
        }
        codes.push((sha256(code.as_bytes()), now.saturating_add(LOGIN_TTL_MS)));
        code.to_string()
    }

    /// Uses up a login code: `true` once for a valid, unexpired code.
    pub fn take_login_code(&self, code: &str, now: i64) -> bool {
        if code.len() > 64 {
            return false;
        }
        let hash = sha256(code.as_bytes());
        let mut codes = self.codes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        codes.retain(|(_, exp)| *exp > now);
        let before = codes.len();
        codes.retain(|(known, _)| *known != hash);
        codes.len() < before
    }

    /// Whether a cookie value is the session.
    #[must_use]
    pub fn is_session(&self, token: &str) -> bool {
        token.len() <= 64 && sha256(token.as_bytes()) == self.session_hash
    }

    /// Checks a second start's proof of the launch key for `nonce` (each nonce works once; the last 64 are kept).
    pub fn check_launch(&self, nonce: &str, proof: &str) -> bool {
        if !nonce_ok(nonce) || !launch_answer_ok_parts(&self.launch, LAUNCH_REQUEST, nonce.as_bytes(), proof) {
            return false;
        }
        let seen = sha256(nonce.as_bytes());
        let mut nonces = self.nonces.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if nonces.contains(&seen) {
            return false;
        }
        if nonces.len() >= MAX_LAUNCH_NONCES {
            nonces.pop_front();
        }
        nonces.push_back(seen);
        true
    }

    /// The code that proves the answer `path` to the second start that sent `nonce`.
    #[must_use]
    pub fn launch_answer(&self, nonce: &str, path: &str) -> Option<String> {
        launch_mac(&self.launch, LAUNCH_ANSWER, &answer_message(nonce, path))
    }

    fn cookie(&self) -> String {
        format!("{COOKIE}={}; HttpOnly; SameSite=Strict; Path=/", self.session.as_str())
    }
}

/// 256 random bits, Base64url (43 characters).
#[must_use]
pub fn random_token() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    Zeroizing::new(b64(bytes.as_ref()))
}

/// A launch nonce: 16-64 Base64url characters.
fn nonce_ok(nonce: &str) -> bool {
    (16..=64).contains(&nonce.len())
        && nonce.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn answer_message(nonce: &str, path: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(nonce.len() + 1 + path.len());
    message.extend_from_slice(nonce.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(path.as_bytes());
    message
}

fn launch_mac(key: &str, domain: &str, message: &[u8]) -> Option<String> {
    bridge_core::crypto::mac(key.as_bytes(), domain, message).ok().map(|tag| b64(&tag))
}

fn launch_answer_ok_parts(key: &str, domain: &str, message: &[u8], given: &str) -> bool {
    let Ok(given) = bridge_core::encoding::b64_fixed::<32>(given, "mac") else { return false };
    bridge_core::crypto::mac(key.as_bytes(), domain, message)
        .is_ok_and(|expected| bridge_core::crypto::mac_eq(&expected, &given))
}

/// The second start's proof for `nonce` (sent instead of the launch key).
#[must_use]
pub fn launch_proof(key: &str, nonce: &str) -> Option<String> {
    launch_mac(key, LAUNCH_REQUEST, nonce.as_bytes())
}

/// Whether `mac` proves that the holder of the launch key answered `path` to `nonce`.
#[must_use]
pub fn launch_answer_ok(key: &str, nonce: &str, path: &str, mac: &str) -> bool {
    launch_answer_ok_parts(key, LAUNCH_ANSWER, &answer_message(nonce, path), mac)
}

/// An answer before the common headers are added.
pub struct Answer {
    /// Status code.
    pub status: u16,
    /// Content type.
    pub content_type: &'static str,
    /// Body.
    pub body: Bytes,
    /// More headers.
    pub headers: Vec<(&'static str, String)>,
    /// May be cached (design files).
    pub cacheable: bool,
    /// The page `/` (its CSP may frame the node readers).
    pub page: bool,
}

impl Answer {
    /// A JSON answer.
    #[must_use]
    pub fn json(status: u16, value: &Value) -> Self {
        Self::raw_json(status, value.to_string().into_bytes())
    }

    /// JSON with a secret inside (the words of the assistant, built without `serde_json`; review 8): the bytes stay in
    /// the zeroizing buffer they were built in - no plain copy - and are wiped when the answer is dropped after sending.
    #[must_use]
    pub fn secret_json(status: u16, body: Zeroizing<Vec<u8>>) -> Self {
        Self { body: Bytes::from_owner(body), ..Self::raw_json(status, Vec::new()) }
    }

    /// A JSON answer from bytes made elsewhere.
    #[must_use]
    pub fn raw_json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            body: Bytes::from(body),
            headers: Vec::new(),
            cacheable: false,
            page: false,
        }
    }

    /// An error as JSON: `{"error": text}` (German, for people).
    #[must_use]
    pub fn error(status: u16, text: &str) -> Self {
        Self::json(status, &json!({"error": text}))
    }

    /// An error of one form field: `{"error": text, "field": name}`.
    #[must_use]
    pub fn field_error(status: u16, field: &str, text: &str) -> Self {
        Self::json(status, &json!({"error": text, "field": field}))
    }

    fn page(status: u16, bytes: &'static [u8]) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8",
            body: Bytes::from_static(bytes),
            headers: Vec::new(),
            cacheable: false,
            page: false,
        }
    }

    fn asset(asset: &'static assets::Asset) -> Self {
        Self {
            status: 200,
            content_type: asset.content_type,
            body: Bytes::from_static(asset.bytes),
            headers: Vec::new(),
            cacheable: asset.content_type.starts_with("font/"),
            page: false,
        }
    }
}

/// What the API sees of a request.
pub struct Call<'a> {
    /// Method.
    pub method: &'a Method,
    /// Path (without query).
    pub path: &'a str,
    /// Query (without `?`, may be empty).
    pub query: &'a str,
    /// Body (empty for GET).
    pub body: &'a [u8],
}

/// Serves the UI on `listener` until the task is aborted.
pub fn serve(listener: TcpListener, app: Arc<App>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // e.g. out of file handles: do not spin, try again shortly
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                drop(stream); // too many: refuse instead of queueing (Z5)
                continue;
            };
            let app = Arc::clone(&app);
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let app = Arc::clone(&app);
                    async move { Ok::<_, Infallible>(answer(&app, request).await) }
                });
                let connection = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(10))
                    .max_buf_size(64 * 1024)
                    .serve_connection(TokioIo::new(stream), service);
                let _ = tokio::time::timeout(Duration::from_secs(600), connection).await;
                drop(permit);
            });
        }
    })
}

/// One request: checks, routing, common headers.
async fn answer(app: &App, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let answer = checked(app, request).await;
    let csp = if answer.page { page_csp(&crate::browser::frame_origins(app).await) } else { CSP.to_owned() };
    finish(answer, &csp)
}

fn header<'a>(request: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    request.headers().get(name).and_then(|value| value.to_str().ok())
}

/// The value of our cookie in a `Cookie` header.
fn session_cookie(header: &str) -> Option<&str> {
    header.split(';').map(str::trim).find_map(|pair| pair.strip_prefix(COOKIE)?.strip_prefix('='))
}

async fn checked(app: &App, request: Request<Incoming>) -> Answer {
    let port = app.port;
    let host_ok = header(&request, "host")
        .is_some_and(|host| host == format!("127.0.0.1:{port}") || host == format!("localhost:{port}"));
    if !host_ok {
        return Answer::error(403, "Falscher Host");
    }
    let method = request.method().clone();
    if method != Method::GET && method != Method::POST {
        return Answer { headers: vec![("allow", "GET, POST".into())], ..Answer::error(405, "Methode nicht erlaubt") };
    }
    let target = request.uri().path_and_query().map(|pq| pq.as_str().to_owned()).unwrap_or_default();
    if target.len() > MAX_TARGET {
        return Answer::error(414, "Adresse zu lang");
    }
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let now = now_ms();

    if method == Method::GET {
        if let Some(code) = path.strip_prefix("/login/") {
            return login(app, code, now);
        }
        if let Some(asset) = assets::get(&path).filter(|asset| asset.public) {
            return Answer::asset(asset);
        }
    }
    if method == Method::POST && path == "/api/launch" {
        let proven = match (header(&request, "x-launch-nonce"), header(&request, "x-launch-proof")) {
            (Some(nonce), Some(proof)) if app.auth.check_launch(nonce, proof) => Some(nonce.to_owned()),
            _ => None,
        };
        let Some(nonce) = proven else { return Answer::error(401, "Nicht angemeldet") };
        let login = format!("/login/{}", app.auth.new_login_code(now));
        return match app.auth.launch_answer(&nonce, &login) {
            Some(mac) => Answer::json(200, &json!({"login": login, "mac": mac})),
            None => Answer::error(500, "interner Fehler"),
        };
    }
    let session = header(&request, "cookie").and_then(session_cookie).is_some_and(|token| app.auth.is_session(token));
    if !session {
        if method == Method::GET && !path.starts_with("/api/") && assets::get(&path).is_some() {
            return Answer::page(401, unauthorized_page());
        }
        return Answer::error(401, "Nicht angemeldet - BridgeControll neu öffnen");
    }
    if method == Method::POST {
        let origin_ok = header(&request, "origin").is_some_and(|origin| {
            origin == format!("http://127.0.0.1:{port}") || origin == format!("http://localhost:{port}")
        });
        if !origin_ok {
            return Answer::error(403, "Anfrage von einer fremden Seite abgelehnt");
        }
        let json = header(&request, "content-type").is_some_and(|kind| {
            kind.split(';').next().is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
        });
        if !json {
            return Answer::error(415, "Nur JSON");
        }
    }
    let body = match read_body(request).await {
        Ok(body) => body,
        Err(answer) => return answer,
    };
    if path.starts_with("/api/") {
        return api::route(app, &Call { method: &method, path: &path, query: &query, body: &body }).await;
    }
    match assets::get(&path) {
        Some(asset) if method == Method::GET => Answer { page: path == "/", ..Answer::asset(asset) },
        _ => Answer::error(404, "Nicht gefunden"),
    }
}

fn unauthorized_page() -> &'static [u8] {
    assets::get("/ui/login.html").map_or(b"Nicht angemeldet".as_slice(), |asset| asset.bytes)
}

/// Exchanges a one-time login code for the session cookie and goes to the start page.
fn login(app: &App, code: &str, now: i64) -> Answer {
    if !app.auth.take_login_code(code, now) {
        return Answer::page(401, unauthorized_page());
    }
    Answer {
        status: 303,
        content_type: "text/plain; charset=utf-8",
        body: Bytes::from_static(b"Angemeldet"),
        headers: vec![("location", "/".into()), ("set-cookie", app.auth.cookie())],
        cacheable: false,
        page: false,
    }
}

/// The body, at most [`MAX_BODY_BYTES`], within 10 s.
async fn read_body(request: Request<Incoming>) -> Result<Bytes, Answer> {
    let too_large = || Answer::error(413, "Anfrage zu groß");
    let declared = request
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_BODY_BYTES as u64) {
        return Err(too_large());
    }
    let limited = Limited::new(request.into_body(), MAX_BODY_BYTES);
    match tokio::time::timeout(Duration::from_secs(10), limited.collect()).await {
        Ok(Ok(collected)) => Ok(collected.to_bytes()),
        Ok(Err(_)) => Err(too_large()),
        Err(_) => Err(Answer::error(408, "Anfrage zu langsam")),
    }
}

/// Adds the common headers (`csp`: [`CSP`], or [`page_csp`] for the page).
fn finish(answer: Answer, csp: &str) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(answer.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", answer.content_type)
        .header("content-security-policy", csp)
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .header("referrer-policy", "no-referrer")
        .header("cross-origin-opener-policy", "same-origin")
        .header("cross-origin-resource-policy", "same-origin")
        .header("cache-control", if answer.cacheable { "max-age=86400" } else { "no-store" });
    for (name, value) in answer.headers {
        builder = builder.header(name, value);
    }
    builder.body(Full::new(answer.body)).unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"error"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page may frame exactly the node readers of this PC - nothing else gets into `frame-src`.
    #[test]
    fn page_csp_frames_only_local_readers() {
        assert_eq!(page_csp(&[]), CSP);
        assert!(CSP.contains("frame-src 'none'") && CSP.contains("frame-ancestors 'none'"));
        let csp = page_csp(&["http://127.0.0.1:7401".into(), "http://127.0.0.1:7402".into()]);
        assert!(csp.contains("frame-src http://127.0.0.1:7401 http://127.0.0.1:7402;"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'") && csp.contains("default-src 'self'"));
        for bad in [
            "*",
            "http://evil.example",
            "http://127.0.0.1:*",
            "http://127.0.0.1:1; script-src *",
            "https://127.0.0.1:1",
        ] {
            assert_eq!(page_csp(&[bad.to_owned()]), CSP, "{bad}");
        }
    }

    #[test]
    fn login_codes_work_once_and_expire() {
        let auth = Auth::new();
        let code = auth.new_login_code(0);
        assert!(!auth.take_login_code("falsch", 1));
        assert!(auth.take_login_code(&code, 1));
        assert!(!auth.take_login_code(&code, 2), "once");
        let late = auth.new_login_code(0);
        assert!(!auth.take_login_code(&late, LOGIN_TTL_MS + 1), "expired");
        let codes: Vec<String> = (0..10).map(|n| auth.new_login_code(n)).collect();
        assert!(!auth.take_login_code(&codes[0], 20), "the oldest went");
        assert!(auth.take_login_code(&codes[9], 20));
        assert!(!auth.take_login_code(&"x".repeat(100), 20));
    }

    #[test]
    fn session_and_cookie() {
        let auth = Auth::new();
        let cookie = auth.cookie();
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict") && cookie.contains("Path=/"));
        let token = session_cookie(&cookie).unwrap_or_default();
        assert!(auth.is_session(token));
        assert!(!auth.is_session("") && !auth.is_session(&format!("{token}x")));
        assert_eq!(session_cookie("a=1; bc_session=abc; b=2"), Some("abc"));
        assert_eq!(session_cookie("bc_sessionx=abc"), None);
        assert_ne!(token, auth.launch_key(), "independent secrets");
    }

    /// Review 8, finding 10a: the words' answer keeps its zeroizing buffer (no plain copy on the way to the socket).
    #[test]
    fn secret_answers_keep_their_buffer() {
        let mut secret = Zeroizing::new(Vec::with_capacity(64));
        secret.extend_from_slice(b"{\"words\":[\"abandon\"]}");
        let address = secret.as_ptr();
        let answer = Answer::secret_json(200, secret);
        assert_eq!(answer.body.as_ptr(), address, "the same buffer, not a copy");
        assert_eq!(&answer.body[..], b"{\"words\":[\"abandon\"]}");
        assert_eq!(answer.content_type, "application/json; charset=utf-8");
    }

    /// Review 8, finding 8: the launch key is proven, never sent; each nonce works once; the answer is bound to key,
    /// nonce and path.
    #[test]
    fn launch_proofs_and_answers() {
        let auth = Auth::new();
        let key = auth.launch_key().to_owned();
        let nonce = random_token();
        let proof = launch_proof(&key, &nonce).unwrap_or_default();
        assert!(!auth.check_launch(&nonce, &launch_proof("anderer schluessel", &nonce).unwrap_or_default()));
        assert!(!auth.check_launch(&nonce, &key), "the key itself is no proof");
        assert!(!auth.check_launch("kurz", &launch_proof(&key, "kurz").unwrap_or_default()), "nonce too short");
        assert!(auth.check_launch(&nonce, &proof));
        assert!(!auth.check_launch(&nonce, &proof), "a nonce works once");
        let mac = auth.launch_answer(&nonce, "/login/abc").unwrap_or_default();
        assert!(launch_answer_ok(&key, &nonce, "/login/abc", &mac));
        assert!(!launch_answer_ok(&key, &nonce, "/login/evil", &mac), "another path");
        assert!(!launch_answer_ok(&key, &random_token(), "/login/abc", &mac), "another nonce");
        assert!(!launch_answer_ok("anderer schluessel", &nonce, "/login/abc", &mac), "another key");
        assert!(!launch_answer_ok(&key, &nonce, "/login/abc", "kaputt"));
    }
}
