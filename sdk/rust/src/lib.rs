//! # bridge-sdk – Bridge 4 for Rust programs
//!
//! A client that logs in at its node, sends end-to-end encrypted messages and receives them (docs/04).
//! Zero Trust from the client side as well: the node's card is checked against its ID, the node's `info` statement
//! is verified, every received envelope is verified with the sender's (self-certifying) card and opened locally,
//! duplicates are dropped, answers from the node are size-limited and parsed strictly.
//!
//! Depends only on the protocol (`bridge-core`) and `bridge-transport` - never on node internals.

use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bridge_core::encoding::b64;
use bridge_core::json::parse_strict;
use bridge_core::{
    Address, Content, CoreError, Envelope, Id, Identity, KeyCard, Kind, Puzzle, Role, SignedRequest, Statement,
};
use bridge_transport::{ClientResponse, HttpClient, TransportError};
use rand_core::OsRng;
use serde_json::{Value, json};
use thiserror::Error;

/// Errors of the SDK.
#[derive(Debug, Error)]
pub enum SdkError {
    /// The node answered with an error code (docs/04 §9).
    #[error("{code}: {message}")]
    Node {
        /// Wire code, e.g. `RATE_LIMITED`.
        code: String,
        /// Text from the node.
        message: String,
        /// Seconds to wait.
        retry_after: Option<u32>,
    },
    /// A check failed on our side.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// Network problem.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The node is not who it should be, or answered nonsense.
    #[error("node not trustworthy: {0}")]
    Untrusted(String),
}

/// Result type of the SDK.
pub type SdkResult<T> = Result<T, SdkError>;

/// One received, verified and opened message.
#[derive(Debug, Clone, PartialEq)]
pub struct Received {
    /// Envelope ID.
    pub id: [u8; 16],
    /// Verified sender.
    pub from: Id,
    /// The content.
    pub content: Content,
}

/// The result of one receive call.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Inbox {
    /// Valid messages.
    pub messages: Vec<Received>,
    /// Envelopes that failed a check (bad signature, cannot open, unknown sender ...). They are acknowledged so
    /// the node deletes them.
    pub rejected: usize,
    /// Envelopes received before (replays or repeated deliveries) - dropped.
    pub duplicates: usize,
    /// Set if acknowledging failed (retried with the next `receive`) or the seen-file could not be written. The
    /// messages above are valid anyway.
    pub warning: Option<String>,
}

/// How many received envelope IDs are remembered (replay protection; per (sender, ID) until they expire).
pub const SEEN_MEMORY: usize = 100_000;
const MAX_PENDING_ACKS: usize = 1_000;

type SeenKey = (Id, [u8; 16]);

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)).unwrap_or(0)
}

/// A client of one node.
pub struct Client {
    identity: Identity,
    card: KeyCard,
    http: HttpClient,
    expected_node: Option<Id>,
    node: Option<KeyCard>,
    net: Option<Id>,
    session: Option<String>,
    seen: HashMap<SeenKey, i64>,
    seen_order: VecDeque<SeenKey>,
    seen_file: Option<PathBuf>,
    pending_acks: Vec<SeenKey>,
    /// Max proof-of-work hashes the client is willing to compute for a login.
    pub max_pow_tries: u64,
    /// Lifetime of sent envelopes (s).
    pub ttl_s: u32,
}

impl Client {
    /// A client for the node at `node_url`. `expected_node`: the node's ID if known (pinning - recommended).
    pub fn new(identity: Identity, node_url: &str, expected_node: Option<Id>) -> SdkResult<Self> {
        let card = identity.key_card(Role::Client, None, now_ms())?;
        Ok(Self {
            http: HttpClient::new(node_url, Duration::from_secs(40))?,
            identity,
            card,
            expected_node,
            node: None,
            net: None,
            session: None,
            seen: HashMap::new(),
            seen_order: VecDeque::new(),
            seen_file: None,
            pending_acks: Vec::new(),
            max_pow_tries: 1 << 30,
            ttl_s: 7 * 24 * 3600,
        })
    }

    /// This client's identity.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// This client's key card.
    #[must_use]
    pub fn card(&self) -> &KeyCard {
        &self.card
    }
    /// The node's verified card (after `connect`).
    #[must_use]
    pub fn node_card(&self) -> Option<&KeyCard> {
        self.node.as_ref()
    }
    /// The network (after `connect`).
    #[must_use]
    pub fn net(&self) -> Option<&Id> {
        self.net.as_ref()
    }
    /// The current session token (diagnostics and tests).
    #[must_use]
    pub fn session_token(&self) -> Option<&str> {
        self.session.as_deref()
    }

    fn check(answer: ClientResponse) -> SdkResult<serde_json::Map<String, Value>> {
        let value =
            parse_strict(&answer.body, 4 * 1024 * 1024).map_err(|e| SdkError::Untrusted(format!("bad answer: {e}")))?;
        let Value::Object(object) = value else {
            return Err(SdkError::Untrusted("answer is not an object".into()));
        };
        if answer.status != 200 {
            let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
            return Err(SdkError::Node {
                code: text("error"),
                message: text("message"),
                retry_after: object.get("retry_after").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()),
            });
        }
        Ok(object)
    }

    /// Fetches and verifies the node's info, then logs in (solving a proof-of-work puzzle if the node asks for one).
    pub async fn connect(&mut self) -> SdkResult<()> {
        let info = Self::check(self.http.get("/v4/info").await?)?;
        let card = KeyCard::from_value(info.get("card").cloned().unwrap_or(Value::Null))?;
        if self.expected_node.as_ref().is_some_and(|expected| expected != card.id()) {
            return Err(SdkError::Untrusted("node ID does not match".into()));
        }
        let statement = Statement::from_value(info.get("info").cloned().unwrap_or(Value::Null))?;
        statement.verify(&[&card], 1)?;
        statement.check_time(now_ms())?;
        if statement.kind() != "info" {
            return Err(SdkError::Untrusted("info statement expected".into()));
        }
        self.net = Some(statement.net().clone());
        self.node = Some(card.clone());

        let challenge = Self::check(self.http.post("/v4/auth/challenge", None, b"{}".to_vec()).await?)?;
        let challenge_text = challenge.get("challenge").and_then(Value::as_str).unwrap_or_default().to_owned();
        let mut body = json!({"challenge": challenge_text, "card": self.card.to_value()});
        if let Some(puzzle) = challenge.get("pow").filter(|value| !value.is_null()) {
            let puzzle = Puzzle::from_value(puzzle.clone())?;
            puzzle.verify(&card)?;
            let solution =
                puzzle.solve(self.max_pow_tries).ok_or_else(|| SdkError::Untrusted("proof of work too hard".into()))?;
            body["pow"] = json!(b64(&solution));
        }
        let login = SignedRequest::sign(&self.identity, card.id(), "login", body, now_ms(), &mut OsRng)?;
        let session = Self::check(self.http.post("/v4/auth/login", None, login.to_bytes()?).await?)?;
        let token = session.get("session").and_then(Value::as_str).unwrap_or_default();
        if token.len() != 43 {
            return Err(SdkError::Untrusted("bad session token".into()));
        }
        self.session = Some(token.to_owned());
        Ok(())
    }

    fn node_id(&self) -> SdkResult<&Id> {
        self.node.as_ref().map(KeyCard::id).ok_or_else(|| SdkError::Untrusted("not connected".into()))
    }

    /// The key card of another identity known to the node (cards are self-certifying: the ID is checked).
    pub async fn card_of(&self, id: &Id) -> SdkResult<KeyCard> {
        let body = json!({"id": id.as_str()}).to_string().into_bytes();
        let answer = Self::check(self.http.post("/v4/card", self.session.as_deref(), body).await?)?;
        let card = KeyCard::from_value(answer.get("card").cloned().unwrap_or(Value::Null))?;
        if card.id() != id {
            return Err(SdkError::Untrusted("node returned a card for another ID".into()));
        }
        Ok(card)
    }

    /// Encrypts `content` for `to` and hands it to the node. Returns the envelope ID.
    pub async fn send(&self, to: &KeyCard, content: &Content) -> SdkResult<[u8; 16]> {
        let net = self.net.as_ref().ok_or_else(|| SdkError::Untrusted("not connected".into()))?;
        let address = Address { net, to, kind: Kind::Msg, iat: now_ms(), ttl: self.ttl_s };
        let envelope = Envelope::seal(&self.identity, &address, &content.to_bytes()?, &mut OsRng)?;
        self.send_envelope(&envelope).await?;
        Ok(*envelope.id())
    }

    /// Hands a prepared envelope to the node.
    pub async fn send_envelope(&self, envelope: &Envelope) -> SdkResult<()> {
        Self::check(self.http.post("/v4/send", self.session.as_deref(), envelope.to_bytes()?).await?)?;
        Ok(())
    }

    /// Keeps the replay protection across restarts in `path` (one line per received envelope until it expires).
    /// Recommended: without it, a malicious node could hand out old envelopes again after the program restarts.
    pub fn with_seen_file(mut self, path: impl AsRef<Path>) -> SdkResult<Self> {
        let path = path.as_ref().to_path_buf();
        let now = now_ms();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines().rev().take(SEEN_MEMORY) {
                let mut parts = line.split(' ');
                let (Some(from), Some(id), Some(expires)) = (parts.next(), parts.next(), parts.next()) else {
                    continue;
                };
                let (Ok(from), Ok(id), Ok(expires)) =
                    (Id::parse(from), bridge_core::encoding::b64_fixed::<16>(id, "id"), expires.parse::<i64>())
                else {
                    continue;
                };
                if expires > now && !self.seen.contains_key(&(from.clone(), id)) {
                    self.seen.insert((from.clone(), id), expires);
                    self.seen_order.push_front((from, id));
                }
            }
        }
        // Rewrite without expired lines.
        let mut compact = String::new();
        for key in &self.seen_order {
            if let Some(expires) = self.seen.get(key) {
                compact.push_str(&format!("{} {} {expires}\n", key.0, b64(&key.1)));
            }
        }
        std::fs::write(&path, compact).map_err(|e| SdkError::Untrusted(format!("seen file: {e}")))?;
        self.seen_file = Some(path);
        Ok(self)
    }

    /// Fetches waiting envelopes (waiting up to `wait_s` seconds), verifies and opens them, drops duplicates and
    /// acknowledges everything fetched. If acknowledging fails, the messages are returned anyway and the
    /// acknowledgement is repeated with the next call (at-least-once from the node, exactly-once to the caller).
    pub async fn receive(&mut self, wait_s: u64) -> SdkResult<Inbox> {
        let body = json!({"wait": wait_s.min(25), "max": 100}).to_string().into_bytes();
        let answer = Self::check(self.http.post("/v4/poll", self.session.as_deref(), body).await?)?;
        let envelopes = answer.get("envelopes").and_then(Value::as_array).cloned().unwrap_or_default();
        let cards = answer.get("cards").and_then(Value::as_object).cloned().unwrap_or_default();
        let mut inbox = Inbox::default();
        let mut to_ack: Vec<SeenKey> = std::mem::take(&mut self.pending_acks);
        for value in envelopes.into_iter().take(100) {
            let Ok(envelope) = Envelope::from_value(value) else {
                inbox.rejected += 1; // not even an envelope: nothing to name in an ack
                continue;
            };
            let key = (envelope.from().clone(), *envelope.id());
            if !to_ack.contains(&key) {
                to_ack.push(key.clone());
            }
            if self.seen.contains_key(&key) {
                inbox.duplicates += 1;
                continue;
            }
            match self.open(&envelope, &cards) {
                Some(received) => {
                    if let Err(warning) = self.remember(key, envelope.expires_at()) {
                        inbox.warning = Some(warning);
                    }
                    inbox.messages.push(received);
                }
                None => inbox.rejected += 1,
            }
        }
        if !to_ack.is_empty() {
            if let Err(error) = self.ack(&to_ack).await {
                to_ack.truncate(MAX_PENDING_ACKS);
                self.pending_acks = to_ack;
                inbox.warning = Some(format!("acknowledging failed, will retry: {error}"));
            }
        }
        Ok(inbox)
    }

    fn open(&self, envelope: &Envelope, cards: &serde_json::Map<String, Value>) -> Option<Received> {
        if envelope.to() != self.identity.id() || Some(envelope.net()) != self.net.as_ref() {
            return None;
        }
        let card = KeyCard::from_value(cards.get(envelope.from().as_str())?.clone()).ok()?;
        if card.id() != envelope.from() || envelope.check_time(now_ms()).is_err() {
            return None;
        }
        let plaintext = envelope.open(&self.identity, &card).ok()?;
        let content = Content::parse(&plaintext).ok()?;
        Some(Received { id: *envelope.id(), from: envelope.from().clone(), content })
    }

    fn remember(&mut self, key: SeenKey, expires: i64) -> Result<(), String> {
        if self.seen.insert(key.clone(), expires).is_none() {
            self.seen_order.push_back(key.clone());
            while self.seen_order.len() > SEEN_MEMORY {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
        if let Some(path) = &self.seen_file {
            let line = format!("{} {} {expires}\n", key.0, b64(&key.1));
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut file| file.write_all(line.as_bytes()))
                .map_err(|e| format!("seen file: {e}"))?;
        }
        Ok(())
    }

    /// Acknowledges envelopes, each named by (sender, envelope ID) - the node deletes them.
    pub async fn ack(&self, envelopes: &[(Id, [u8; 16])]) -> SdkResult<usize> {
        let mut removed = 0;
        for chunk in envelopes.chunks(100) {
            let list: Vec<Value> =
                chunk.iter().map(|(from, id)| json!({"from": from.as_str(), "id": b64(id)})).collect();
            let request = SignedRequest::sign(
                &self.identity,
                self.node_id()?,
                "ack",
                json!({"acks": list}),
                now_ms(),
                &mut OsRng,
            )?;
            let answer = Self::check(self.http.post("/v4/ack", self.session.as_deref(), request.to_bytes()?).await?)?;
            removed += answer.get("removed").and_then(Value::as_u64).unwrap_or(0) as usize;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_file_survives_a_restart_and_drops_expired_and_broken_lines() -> SdkResult<()> {
        let dir = std::env::temp_dir().join(format!("bridge-sdk-seen-{}", now_ms()));
        std::fs::create_dir_all(&dir).map_err(|e| SdkError::Untrusted(e.to_string()))?;
        let path = dir.join("seen.txt");
        let sender = Identity::generate(&mut OsRng).id().clone();
        {
            let mut client =
                Client::new(Identity::generate(&mut OsRng), "http://127.0.0.1:1", None)?.with_seen_file(&path)?;
            client.remember((sender.clone(), [1; 16]), now_ms() + 60_000).map_err(SdkError::Untrusted)?;
            client.remember((sender.clone(), [2; 16]), now_ms() - 1).map_err(SdkError::Untrusted)?;
        }
        let mut text = std::fs::read_to_string(&path).map_err(|e| SdkError::Untrusted(e.to_string()))?;
        text.push_str("garbage line\n");
        std::fs::write(&path, text).map_err(|e| SdkError::Untrusted(e.to_string()))?;
        let client = Client::new(Identity::generate(&mut OsRng), "http://127.0.0.1:1", None)?.with_seen_file(&path)?;
        assert!(client.seen.contains_key(&(sender.clone(), [1; 16])), "still known after restart");
        assert!(!client.seen.contains_key(&(sender, [2; 16])), "expired: dropped");
        let compact = std::fs::read_to_string(&path).map_err(|e| SdkError::Untrusted(e.to_string()))?;
        assert_eq!(compact.lines().count(), 1, "file compacted: {compact}");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
