//! # bridge-node – the node runtime
//!
//! Ties the compartments together: `transport` delivers requests, `guard` decides what may pass, `core` checks every
//! object, `store` keeps mailboxes. Phase 2 endpoints (docs/04 §7): info, challenge, login, send, poll, ack, card.
//! All state hangs on one [`Node`] (no global state, S3) - tests run several nodes in one process.
//!
//! What a node knows about a message: network, from, to, time, kind, size. Never the content (Z1).
//!
//! Layering (docs/03_ARCHITEKTUR.md): uses all crates below it.

mod error;
pub mod keyfile;
mod sessions;

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::json::parse_strict;
use bridge_core::{Draft, Envelope, Id, Identity, KeyCard, Puzzle, Role, SignedRequest, Statement};
use bridge_guard::{Guard, GuardError, Limits};
use bridge_store::{Delivered, Delivery, Store};
use bridge_transport::{Handler, Method, Request, Response, RunningServer, ServerConfig};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub use error::{NodeError, NodeResult};

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-node";
/// Longest long poll.
pub const MAX_POLL_WAIT_S: u64 = 25;
/// Most envelopes per poll, and most IDs per ack.
pub const MAX_BATCH: usize = 100;
/// Most bytes of envelopes in one poll answer (at least one envelope is always included).
pub const POLL_MAX_BYTES: usize = 1024 * 1024;
/// File name of the database inside the data folder.
pub const DB_FILE: &str = "node.db";

/// Where time comes from (tests can pass their own).
pub trait Clock: Send + Sync + 'static {
    /// Milliseconds since 1970 (UTC).
    fn now_ms(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

/// Configuration of one node.
pub struct NodeConfig {
    /// Data folder (key file + database).
    pub data_dir: PathBuf,
    /// Display name on the node's key card.
    pub name: Option<String>,
    /// Network this node serves (phase 2: default = its own ID, a single-node network).
    pub net: Option<Id>,
    /// Guard limits.
    pub limits: Limits,
    /// Transport limits.
    pub server: ServerConfig,
    /// Session lifetime (ms).
    pub session_lifetime_ms: i64,
    /// Sessions per identity.
    pub sessions_per_identity: usize,
    /// Clock.
    pub clock: Arc<dyn Clock>,
}

impl NodeConfig {
    /// Defaults for a data folder.
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            name: None,
            net: None,
            limits: Limits::default(),
            server: ServerConfig::default(),
            session_lifetime_ms: 60 * 60 * 1000,
            sessions_per_identity: 8,
            clock: Arc::new(SystemClock),
        }
    }
}

struct Inner {
    identity: Identity,
    card: KeyCard,
    net: Id,
    store: Arc<Store>,
    guard: Guard,
    sessions: Mutex<sessions::Sessions>,
    waiters: Mutex<HashMap<Id, Weak<Notify>>>,
    clock: Arc<dyn Clock>,
}

/// A node (cheap to clone; all clones are the same node).
#[derive(Clone)]
pub struct Node {
    inner: Arc<Inner>,
}

/// A started node.
pub struct RunningNode {
    node: Node,
    server: RunningServer,
    janitor: JoinHandle<()>,
}

impl RunningNode {
    /// Address the node listens on.
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }
    /// The node's key card.
    #[must_use]
    pub fn card(&self) -> &KeyCard {
        &self.node.inner.card
    }
    /// Stops the node (running requests may finish).
    pub async fn shutdown(self) {
        self.janitor.abort();
        self.server.shutdown().await;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Opens the data folder and starts serving on `listener`.
pub async fn start(config: NodeConfig, listener: TcpListener) -> Result<RunningNode, String> {
    std::fs::create_dir_all(&config.data_dir).map_err(|e| format!("data folder: {e}"))?;
    let identity = keyfile::load_or_create(&config.data_dir)?;
    let now = config.clock.now_ms();
    let card = identity.key_card(Role::Node, config.name.as_deref(), now).map_err(|e| format!("key card: {e}"))?;
    let path = config.data_dir.join(DB_FILE);
    let store = tokio::task::spawn_blocking(move || Store::open(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("database: {e}"))?;
    let net = config.net.clone().unwrap_or_else(|| identity.id().clone());
    let node = Node {
        inner: Arc::new(Inner {
            sessions: Mutex::new(sessions::Sessions::new(
                config.limits.max_tracked,
                config.sessions_per_identity,
                config.session_lifetime_ms,
            )),
            guard: Guard::new(config.limits),
            waiters: Mutex::new(HashMap::new()),
            store: Arc::new(store),
            clock: config.clock,
            identity,
            card,
            net,
        }),
    };
    let server = bridge_transport::serve(listener, config.server, Arc::new(node.clone())).map_err(|e| e.to_string())?;
    let janitor = tokio::spawn(janitor(node.clone()));
    tracing::info!(node = %node.inner.identity.id(), net = %node.inner.net, addr = %server.local_addr(), "node started");
    Ok(RunningNode { node, server, janitor })
}

async fn janitor(node: Node) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let now = node.now();
        lock(&node.inner.sessions).sweep(now);
        let store = Arc::clone(&node.inner.store);
        match tokio::task::spawn_blocking(move || store.purge_expired(now)).await {
            Ok(Ok((envelopes, seen))) if envelopes + seen > 0 => tracing::debug!(envelopes, seen, "purged"),
            Ok(Err(error)) => tracing::error!(%error, "purge"),
            _ => {}
        }
    }
}

impl Handler for Node {
    fn admit(&self, peer: std::net::IpAddr, _path: &str) -> Option<Response> {
        // Step 1 for every request, before its body is read: the per-address bucket.
        self.inner.guard.admit_address(peer, self.now()).err().map(|error| NodeError::from(error).to_response())
    }

    async fn handle(&self, request: Request) -> Response {
        match self.route(request).await {
            Ok(body) => Response::ok(body),
            Err(error) => error.to_response(),
        }
    }
}

fn body_object(bytes: &[u8], max: usize) -> NodeResult<serde_json::Map<String, Value>> {
    match parse_strict(bytes, max)? {
        Value::Object(object) => Ok(object),
        _ => Err(NodeError::bad_format("body: not an object")),
    }
}

fn optional_u64(object: &serde_json::Map<String, Value>, name: &str, default: u64, max: u64) -> NodeResult<u64> {
    match object.get(name) {
        None => Ok(default),
        Some(value) => {
            value.as_u64().filter(|n| *n <= max).ok_or_else(|| NodeError::bad_format(format!("{name}: 0..{max}")))
        }
    }
}

impl Node {
    fn now(&self) -> i64 {
        self.inner.clock.now_ms()
    }

    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Store) -> Result<T, bridge_store::StoreError> + Send + 'static,
    ) -> NodeResult<T> {
        let store = Arc::clone(&self.inner.store);
        match tokio::task::spawn_blocking(move || work(&store)).await {
            Ok(result) => Ok(result?),
            Err(_) => Err(NodeError::unavailable()),
        }
    }

    async fn route(&self, request: Request) -> NodeResult<Vec<u8>> {
        let now = self.now();
        match (request.method, request.path.as_str()) {
            (Method::Get, "/v4/info") => self.info(now),
            (Method::Post, "/v4/auth/challenge") => self.challenge(&request, now),
            (Method::Post, "/v4/auth/login") => self.login(&request.body, now).await,
            (Method::Post, "/v4/send") => self.send(&request, now).await,
            (Method::Post, "/v4/poll") => self.poll(&request).await,
            (Method::Post, "/v4/ack") => self.ack(&request, now).await,
            (Method::Post, "/v4/card") => self.card(&request, now).await,
            _ => Err(NodeError::not_found()),
        }
    }

    fn session(&self, request: &Request, now: i64) -> NodeResult<Id> {
        let token = request.bearer.as_deref().ok_or_else(NodeError::no_session)?;
        let token = b64_fixed::<32>(token, "session").map_err(|_| NodeError::no_session())?;
        lock(&self.inner.sessions).lookup(&token, now).ok_or_else(NodeError::no_session)
    }

    async fn known_card(&self, id: &Id) -> NodeResult<Option<KeyCard>> {
        let key = id.to_string();
        match self.blocking(move |store| store.get_card(&key)).await? {
            Some(bytes) => Ok(Some(KeyCard::parse(&bytes)?)),
            None => Ok(None),
        }
    }

    fn info(&self, now: i64) -> NodeResult<Vec<u8>> {
        let limits = self.inner.guard.limits();
        let body = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "phase": 2,
            "pow_bits": self.inner.guard.pow_bits(now),
            "limits": {
                "max_envelope_bytes": bridge_core::envelope::MAX_ENVELOPE_BYTES,
                "max_poll_wait_s": MAX_POLL_WAIT_S,
                "max_batch": MAX_BATCH,
                "mailbox_envelopes": limits.mailbox.max_envelopes,
                "mailbox_bytes": limits.mailbox.max_bytes,
            },
        });
        let draft = Draft { kind: "info", net: &self.inner.net, iat: now, exp: now + 10 * 60 * 1000, body };
        let statement = Statement::sign(&draft, &self.inner.identity)?;
        Ok(json!({"card": self.inner.card.to_value(), "info": statement.to_value()}).to_string().into_bytes())
    }

    fn challenge(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        self.inner.guard.admit_challenge(request.peer, now)?;
        let bits = self.inner.guard.pow_bits(now);
        let puzzle = if bits > 0 { Some(Puzzle::issue(&self.inner.identity, bits, now, &mut OsRng)?) } else { None };
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        let puzzle_value = puzzle.as_ref().map_or(Value::Null, Puzzle::to_value);
        let exp = self.inner.guard.register_challenge(challenge, puzzle, now)?;
        Ok(json!({"challenge": b64(&challenge), "exp": exp, "pow": puzzle_value}).to_string().into_bytes())
    }

    async fn login(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let request = SignedRequest::parse(body)?;
        request.check(self.inner.identity.id(), now)?;
        if request.op() != "login" {
            return Err(NodeError::bad_format("op: expected login"));
        }
        let text = |name: &str| request.body().get(name).and_then(Value::as_str);
        let challenge = b64_fixed::<32>(text("challenge").unwrap_or_default(), "challenge")?;
        let puzzle = self.inner.guard.take_challenge(&challenge, now).map_err(|error| match error {
            GuardError::Replay => NodeError::new(401, "EXPIRED", "challenge unknown, used or expired"),
            other => other.into(),
        })?;
        if let Some(puzzle) = puzzle {
            let solution = text("pow").ok_or_else(|| NodeError::new(403, "POW_REQUIRED", "proof of work required"))?;
            puzzle.check_solution(&b64_fixed::<8>(solution, "pow")?, now)?;
        }
        let card = KeyCard::from_value(request.body().get("card").cloned().unwrap_or(Value::Null))?;
        if card.id() != request.iss() {
            return Err(NodeError::new(401, "BAD_SIGNATURE", "card does not belong to the caller"));
        }
        if card.role() == Role::Net {
            return Err(NodeError::forbidden("a network master key never logs in"));
        }
        request.verify(&card)?;
        // No nonce table needed: the challenge above is one-time.
        let (id, bytes, max_cards) =
            (card.id().to_string(), card.to_bytes()?, self.inner.guard.limits().max_identities);
        if !self.blocking(move |store| store.put_card(&id, &bytes, now, max_cards)).await? {
            return Err(NodeError { retry_after: Some(3600), ..NodeError::new(429, "QUOTA_EXCEEDED", "node is full") });
        }
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        let exp = lock(&self.inner.sessions).create(card.id(), &token, now)?;
        Ok(json!({"session": b64(&token), "exp": exp}).to_string().into_bytes())
    }

    async fn send(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let caller = self.session(request, now)?;
        let envelope = Envelope::parse(&request.body)?;
        envelope.check_time(now)?;
        if envelope.from() != &caller {
            return Err(NodeError::forbidden("from must be the logged-in identity"));
        }
        if envelope.net() != &self.inner.net {
            return Err(NodeError::forbidden("wrong network"));
        }
        self.inner.guard.admit_send(&caller, now)?;
        if self.known_card(envelope.to()).await?.is_none() {
            return Err(NodeError::new(404, "UNKNOWN_IDENTITY", "recipient unknown here"));
        }
        let sender = self.known_card(&caller).await?.ok_or_else(NodeError::no_session)?;
        envelope.verify(&sender)?;
        let (recipient, from, env_id, expires_at) =
            (envelope.to().to_string(), caller.to_string(), *envelope.id(), envelope.expires_at());
        let bytes = envelope.to_bytes()?;
        let limits = self.inner.guard.mailbox_limits();
        let outcome = self
            .blocking(move |store| {
                let delivery = Delivery {
                    recipient: &recipient,
                    sender: &from,
                    env_id: &env_id,
                    expires_at,
                    envelope: &bytes,
                    now,
                };
                store.deliver(&delivery, &limits)
            })
            .await?;
        match outcome {
            Delivered::Stored => {}
            Delivered::Replay => return Err(NodeError::new(409, "REPLAY", "envelope already delivered")),
            Delivered::MailboxFull | Delivered::SenderLimit | Delivered::NodeFull => return Err(NodeError::quota()),
        }
        let waiter = lock(&self.inner.waiters).get(envelope.to()).and_then(Weak::upgrade);
        if let Some(waiter) = waiter {
            waiter.notify_waiters();
        }
        Ok(br#"{"ok":true}"#.to_vec())
    }

    fn waiter(&self, id: &Id) -> Arc<Notify> {
        let mut waiters = lock(&self.inner.waiters);
        if let Some(existing) = waiters.get(id).and_then(Weak::upgrade) {
            return existing;
        }
        if waiters.len() > 10_000 {
            waiters.retain(|_, weak| weak.strong_count() > 0);
        }
        let notify = Arc::new(Notify::new());
        waiters.insert(id.clone(), Arc::downgrade(&notify));
        notify
    }

    async fn poll(&self, request: &Request) -> NodeResult<Vec<u8>> {
        let caller = self.session(request, self.now())?;
        let options = if request.body.is_empty() { serde_json::Map::new() } else { body_object(&request.body, 1024)? };
        let wait = optional_u64(&options, "wait", 0, MAX_POLL_WAIT_S)?;
        let max = u32::try_from(optional_u64(&options, "max", MAX_BATCH as u64, MAX_BATCH as u64)?.max(1)).unwrap_or(1);
        let _permit = self.inner.guard.try_poll(&caller)?;
        let notify = self.waiter(&caller);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
        loop {
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable(); // register before looking, so no delivery in between is missed
            let (recipient, now) = (caller.to_string(), self.now());
            let batch = self
                .blocking(move |store| {
                    let items = store.fetch(&recipient, max, POLL_MAX_BYTES, now)?;
                    let senders: BTreeSet<String> = items.iter().map(|item| item.sender.clone()).collect();
                    let mut cards = Vec::with_capacity(senders.len());
                    for sender in senders {
                        if let Some(card) = store.get_card(&sender)? {
                            cards.push((sender, card));
                        }
                    }
                    Ok((items, cards))
                })
                .await?;
            if !batch.0.is_empty() || tokio::time::Instant::now() >= deadline {
                return Ok(poll_answer(&batch.0, &batch.1));
            }
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(deadline) => {}
            }
        }
    }

    async fn ack(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let caller = self.session(request, now)?;
        let signed = SignedRequest::parse(&request.body)?;
        signed.check(self.inner.identity.id(), now)?;
        if signed.op() != "ack" || signed.iss() != &caller {
            return Err(NodeError::forbidden("ack must be signed by the logged-in identity"));
        }
        let card = self.known_card(&caller).await?.ok_or_else(NodeError::no_session)?;
        signed.verify(&card)?;
        // Acks are idempotent (an envelope ID of a sender exists only once, see replay protection), so a repeated
        // ack changes nothing - no nonce table needed.
        let acks = signed.body().get("acks").and_then(Value::as_array).ok_or_else(|| NodeError::bad_format("acks"))?;
        if acks.len() > MAX_BATCH {
            return Err(NodeError::bad_format("acks: too many"));
        }
        let acks = acks
            .iter()
            .map(|ack| {
                let from = Id::parse(ack.get("from").and_then(Value::as_str).unwrap_or_default())?;
                let id = b64_fixed::<16>(ack.get("id").and_then(Value::as_str).unwrap_or_default(), "id")?;
                Ok((from.to_string(), id))
            })
            .collect::<Result<Vec<_>, bridge_core::CoreError>>()?;
        let recipient = caller.to_string();
        let removed = self.blocking(move |store| store.ack(&recipient, &acks)).await?;
        Ok(json!({"removed": removed}).to_string().into_bytes())
    }

    async fn card(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        self.session(request, now)?;
        let object = body_object(&request.body, 1024)?;
        let id = Id::parse(object.get("id").and_then(Value::as_str).unwrap_or_default())?;
        match self.known_card(&id).await? {
            Some(card) => Ok(json!({"card": card.to_value()}).to_string().into_bytes()),
            None => Err(NodeError::not_found()),
        }
    }
}

fn poll_answer(items: &[bridge_store::Stored], cards: &[(String, Vec<u8>)]) -> Vec<u8> {
    // The stored bytes are canonical JSON written by this node - they are embedded as they are.
    let mut out = br#"{"envelopes":["#.to_vec();
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&item.envelope);
    }
    out.extend_from_slice(br#"],"cards":{"#);
    for (index, (id, card)) in cards.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(format!("\"{id}\":").as_bytes());
        out.extend_from_slice(card);
    }
    out.extend_from_slice(b"}}");
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
