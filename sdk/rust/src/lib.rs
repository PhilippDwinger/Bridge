//! # bridge-sdk – Bridge 4 for Rust programs
//!
//! A client that logs in at its node, sends end-to-end encrypted messages and receives them (docs/04). In a
//! BridgeNet (docs/06) a client joins once with a join link ([`Client::join`]) and registers its node as its home
//! gateway with every login; sending to members of other gateways needs nothing else - the gateways relay.
//! Zero Trust from the client side as well: the node's card is checked against its ID, the node's `info` statement
//! is verified, every received envelope is verified with the sender's (self-certifying) card and opened locally,
//! duplicates are dropped, answers from the node are size-limited and parsed strictly.
//!
//! LAN before Internet (docs/04 §7, docs/06 §2): with the node's ID and the TLS pin from its signed card (or from a
//! join link with `node` and `tls`), [`Client::connect_auto`] and [`Client::join`] look for the node in the LAN
//! first and connect with exactly that certificate; only if that does not work, they use the Internet address.
//! Everything above the connection is checked the same way on both paths.
//!
//! Files and apps (docs/07, module [`apps`]): upload blobs, download them from several hosts at once (verified per
//! part, resumable), publish an app folder as a version signed by the app key and the owner, fetch and verify app
//! versions, pick a host (LAN first).
//!
//! Depends only on the protocol (`bridge-core`) and `bridge-transport` - never on node internals.

use std::collections::{HashMap, VecDeque};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bridge_core::encoding::{b64, b64_var};
use bridge_core::json::parse_strict;
use bridge_core::{
    Address, Agent, Content, CoreError, Draft, Envelope, Id, Identity, JoinLink, KeyCard, Kind, Puzzle, Role, Scope,
    SignedRequest, Statement,
};
use bridge_transport::{ClientResponse, Discovery, HttpClient, TransportError};
use rand_core::OsRng;
use serde_json::{Value, json};
use thiserror::Error;

pub mod apps;
pub mod compute;
pub mod storage;

pub use apps::{
    Announced, AppDraft, AppVersion, BlobSource, DownloadReport, FolderFile, Published, RECORDS_FILE, SERVER_FILE,
    announce_app, download_blob, fetch_app, fetch_blob, fetch_hash_list, pick_host, reach_host, reachable_hosts,
    scan_app_folder,
};

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
    /// The sender's network: this client's network, or a connected one (checked, docs/10 §6.3) - answer with
    /// [`Client::send_to_net`] then.
    pub net: Id,
    /// The content.
    pub content: Content,
    /// The sender is an agent acting for this owner (its statement was checked here, docs/10 §3.4).
    pub agent_of: Option<AgentOf>,
}

/// Who an agent acts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOf {
    /// The owner (a member).
    pub owner: Id,
    /// Name or purpose from the statement.
    pub note: Option<String>,
}

/// What an agent may do (for [`Client::issue_agent`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRights {
    /// Send messages.
    pub send: bool,
    /// Fetch and acknowledge messages.
    pub receive: bool,
    /// Only to these recipients (`None`: every member).
    pub to: Option<Vec<Id>>,
    /// Sends per hour (1-3600).
    pub rate: u64,
    /// Name or purpose (at most 64 characters).
    pub note: Option<String>,
    /// Lifetime in days (1-30).
    pub days: u32,
}

impl Default for AgentRights {
    fn default() -> Self {
        Self { send: true, receive: true, to: None, rate: 60, note: None, days: 7 }
    }
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
/// Lifetime of the `home` statement sent with every login in a network (docs/06 §8: at most 30 days).
pub const HOME_LIFETIME_MS: i64 = 30 * 24 * 3600 * 1000 - 60_000;
/// How many log entries a join looks through to find the gateway's seal.
pub const JOIN_CHECK_MAX_ENTRIES: u64 = 4096;
const MAX_PENDING_ACKS: usize = 1_000;
/// Timeout of the connection used for everything after connecting (long polls wait up to 25 s).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(40);
/// Most LAN addresses tried for one node.
pub const MAX_LAN_TRIES: usize = 8;

/// How to reach a node: its ID (always pinned), the TLS pin for the LAN, the Internet address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddress {
    /// The node's ID: a node with another ID is refused on every path.
    pub node: Id,
    /// Fingerprint of the node's TLS certificate (`tls` of its signed card, or of a join link). Without it the LAN
    /// is not tried.
    pub tls: Option<[u8; 32]>,
    /// The Internet address (fallback; `None`: LAN only).
    pub url: Option<String>,
}

impl NodeAddress {
    /// From a node's verified key card: its ID, its TLS pin and its first address.
    #[must_use]
    pub fn from_card(card: &KeyCard) -> Self {
        Self { node: card.id().clone(), tls: card.tls().copied(), url: card.urls().first().cloned() }
    }
}

/// How a client looks for its node in the LAN.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Where to look (default: mDNS, up to 2 s - it returns as soon as the node was seen). `Discovery::Off`: never
    /// the LAN.
    pub lan: Discovery,
    /// Time limit for trying one LAN address.
    pub probe_timeout: Duration,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self { lan: Discovery::mdns(), probe_timeout: Duration::from_secs(5) }
    }
}

type SeenKey = (Id, [u8; 16]);

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)).unwrap_or(0)
}

/// A client of one node.
pub struct Client {
    identity: Identity,
    card: KeyCard,
    http: HttpClient,
    /// The connection is a pinned LAN connection (with this pin).
    lan_pin: Option<[u8; 32]>,
    expected_node: Option<Id>,
    node: Option<KeyCard>,
    net: Option<Id>,
    session: Option<String>,
    seen: HashMap<SeenKey, i64>,
    seen_order: VecDeque<SeenKey>,
    seen_file: Option<PathBuf>,
    pending_acks: Vec<SeenKey>,
    /// Log in as an agent with this statement of its owner (docs/10 §3).
    agent: Option<Statement>,
    /// Messages that arrived while [`Client::request`] waited for its answer (the next `receive` hands them out).
    stash: VecDeque<Received>,
    /// Max proof-of-work hashes the client is willing to compute for a login.
    pub max_pow_tries: u64,
    /// Lifetime of sent envelopes (s).
    pub ttl_s: u32,
}

impl Client {
    /// A client for the node at `node_url`. `expected_node`: the node's ID if known (pinning - recommended).
    pub fn new(identity: Identity, node_url: &str, expected_node: Option<Id>) -> SdkResult<Self> {
        Self::with_http(identity, HttpClient::new(node_url, REQUEST_TIMEOUT)?, expected_node)
    }

    fn with_http(identity: Identity, http: HttpClient, expected_node: Option<Id>) -> SdkResult<Self> {
        let card = identity.key_card(Role::Client, None, now_ms())?;
        Ok(Self {
            http,
            lan_pin: None,
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
            agent: None,
            stash: VecDeque::new(),
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
    /// Whether this client talks to its node over the LAN (pinned TLS) rather than the Internet address.
    #[must_use]
    pub fn via_lan(&self) -> bool {
        self.lan_pin.is_some()
    }

    /// LAN before Internet: looks for the node in the LAN (if `address` has a TLS pin), tries each address found
    /// with exactly that certificate and takes the first one where the node proves itself (card with the pinned
    /// ID and this TLS pin, valid `info`); otherwise the Internet address. Then logs in like [`Client::connect`].
    pub async fn connect_auto(identity: Identity, address: &NodeAddress, options: &ConnectOptions) -> SdkResult<Self> {
        let mut client = Self::reach(identity, address, options).await?;
        client.connect().await?;
        Ok(client)
    }

    /// A client for `address` with the connection chosen (LAN first), not logged in yet.
    async fn reach(identity: Identity, address: &NodeAddress, options: &ConnectOptions) -> SdkResult<Self> {
        let mut last: Option<SdkError> = None;
        if let Some(pin) = address.tls {
            let peers = options.lan.find(address.node.as_str()).await;
            let urls: Vec<String> =
                peers.iter().flat_map(bridge_transport::LanPeer::urls).take(MAX_LAN_TRIES).collect();
            for url in urls {
                let probe = HttpClient::new_pinned(&url, pin, options.probe_timeout);
                let checked = match &probe {
                    Ok(probe) => Self::info_of(probe, Some(&address.node), Some(&pin)).await.map(|_| ()),
                    Err(_) => Err(SdkError::Untrusted(format!("bad LAN address {url}"))),
                };
                match checked {
                    Ok(()) => {
                        let http = HttpClient::new_pinned(&url, pin, REQUEST_TIMEOUT)?;
                        let mut client = Self::with_http(identity, http, Some(address.node.clone()))?;
                        client.lan_pin = Some(pin);
                        return Ok(client);
                    }
                    Err(error) => last = Some(error), // a stale or foreign announcement: next address
                }
            }
        }
        match &address.url {
            Some(url) => Self::new(identity, url, Some(address.node.clone())),
            None => Err(last.unwrap_or_else(|| SdkError::Untrusted("node not found in the LAN".into()))),
        }
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
    /// In a network the login carries a `home` statement: this node is the client's home gateway.
    pub async fn connect(&mut self) -> SdkResult<()> {
        let card = self.fetch_info().await?;
        let net = self.net.clone().ok_or_else(|| SdkError::Untrusted("no network".into()))?;
        let challenge = Self::check(self.http.post("/v4/auth/challenge", None, b"{}".to_vec()).await?)?;
        let mut body = json!({"challenge": challenge.get("challenge").cloned().unwrap_or(Value::Null),
                              "card": self.card.to_value()});
        self.solve_puzzle(&challenge, &card, &mut body)?;
        if let Some(agent) = &self.agent {
            // An agent's home is its statement (docs/10 §3.2).
            body["agent"] = agent.to_value();
        } else if &net != card.id() {
            let now = now_ms();
            let home = Draft {
                kind: "home",
                net: &net,
                iat: now,
                exp: now + HOME_LIFETIME_MS,
                body: json!({"node": card.id().as_str()}),
            };
            body["home"] = Statement::sign(&home, &self.identity)?.to_value();
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

    /// Logs in as an agent from now on (docs/10 §3): `statement` is the `agent` statement its owner issued for this
    /// client's key (see [`Client::issue_agent`]); the client must talk to the home node named in it. The client
    /// uses the agent card from the statement as its own card (same key; the node compares them exactly).
    pub fn with_agent(mut self, statement: Statement) -> SdkResult<Self> {
        let agent = Agent::from_statement(&statement)?;
        if agent.card.id() != self.identity.id()
            || agent.card.sign_public() != &self.identity.sign_public()
            || agent.card.receive_public() != &self.identity.receive_public()
        {
            return Err(SdkError::Untrusted("the agent statement is for another key".into()));
        }
        self.card = agent.card;
        self.agent = Some(statement);
        Ok(self)
    }

    /// Issues an agent card as this client (the owner, a member): `agent` gets its own key with `rights`, homed at
    /// this client's node (docs/10 §3.1).
    pub fn issue_agent(&self, agent: &KeyCard, rights: &AgentRights) -> SdkResult<Statement> {
        let net = self.net.as_ref().ok_or_else(|| SdkError::Untrusted("not connected".into()))?;
        let mut scopes = std::collections::BTreeSet::new();
        if rights.send {
            scopes.insert(Scope::Send);
        }
        if rights.receive {
            scopes.insert(Scope::Receive);
        }
        let body = Agent {
            agent: agent.id().clone(),
            card: agent.clone(),
            owner: self.card.clone(),
            node: self.node_id()?.clone(),
            scopes,
            to: rights.to.clone(),
            rate: rights.rate,
            note: rights.note.clone(),
        };
        Ok(body.issue(net, &self.identity, now_ms(), rights.days)?)
    }

    /// Revokes an agent of this client at this node (its home): its session ends and its statements issued until now
    /// are invalid (docs/10 §3.3). Returns whether a session ended.
    pub async fn revoke_agent(&self, agent: &Id) -> SdkResult<bool> {
        let request = SignedRequest::sign(
            &self.identity,
            self.node_id()?,
            "agent-revoke",
            json!({"agent": agent.as_str()}),
            now_ms(),
            &mut OsRng,
        )?;
        let answer =
            Self::check(self.http.post("/v4/agent/revoke", self.session.as_deref(), request.to_bytes()?).await?)?;
        Ok(answer.get("ended").and_then(Value::as_bool).unwrap_or(false))
    }

    /// Joins a network with a join link (docs/06 §7): checks that the gateway belongs to the network of the link
    /// (its info, the genesis manifest up to the network ID, and that the log lists the gateway), solves the
    /// proof-of-work if asked, presents the invite code if the link has one, verifies the membership it gets and
    /// logs in. From then on the gateway's ID is pinned. A link with `node` pins it from the start; with `node` and
    /// `tls` the gateway is looked for in the LAN first (mDNS, see [`ConnectOptions`]).
    pub async fn join(identity: Identity, link: &str) -> SdkResult<Self> {
        Self::join_with(identity, link, &ConnectOptions::default()).await
    }

    /// [`Client::join`] with options for the LAN.
    pub async fn join_with(identity: Identity, link: &str, options: &ConnectOptions) -> SdkResult<Self> {
        let link = JoinLink::parse(link)?;
        let mut client = match &link.node {
            Some(node) => {
                let address = NodeAddress { node: node.clone(), tls: link.tls, url: Some(link.gateway.clone()) };
                Self::reach(identity, &address, options).await?
            }
            None => Self::new(identity, &link.gateway, None)?,
        };
        let node = client.fetch_info().await?;
        if client.net.as_ref() != Some(&link.net) {
            return Err(SdkError::Untrusted("the gateway belongs to another network".into()));
        }
        client.check_gateway_in_log(&link.net, node.id()).await?;
        let challenge =
            Self::check(client.http.post("/v4/auth/challenge", None, br#"{"for":"join"}"#.to_vec()).await?)?;
        let mut body = json!({"challenge": challenge.get("challenge").cloned().unwrap_or(Value::Null),
                              "card": client.card.to_value()});
        if let Some(code) = &link.code {
            body["code"] = json!(code);
        }
        client.solve_puzzle(&challenge, &node, &mut body)?;
        let request = SignedRequest::sign(&client.identity, node.id(), "join", body, now_ms(), &mut OsRng)?;
        let answer = Self::check(client.http.post("/v4/net/join", None, request.to_bytes()?).await?)?;
        if let Some(member) = answer.get("member").filter(|value| !value.is_null()) {
            let statement = Statement::from_value(member.clone())?;
            statement.verify(&[&node], 1)?;
            let named = statement.body().get("member").and_then(Value::as_str);
            if statement.kind() != "member"
                || statement.net() != &link.net
                || named != Some(client.identity.id().as_str())
            {
                return Err(SdkError::Untrusted("the gateway answered with another membership".into()));
            }
        }
        client.expected_node = Some(node.id().clone());
        client.connect().await?;
        Ok(client)
    }

    /// Fetches `/v4/info`: the node's card (checked against the pinned ID and, over the LAN, against the TLS pin)
    /// and its signed info statement.
    async fn fetch_info(&mut self) -> SdkResult<KeyCard> {
        let (card, net) = Self::info_of(&self.http, self.expected_node.as_ref(), self.lan_pin.as_ref()).await?;
        self.net = Some(net);
        self.node = Some(card.clone());
        Ok(card)
    }

    /// `/v4/info` of the node behind `http`, verified: the card has the `expected` ID and - over the LAN - pins the
    /// certificate `pin` the connection was made with; the `info` statement is signed by that card and fresh.
    /// Returns the card and the network.
    async fn info_of(http: &HttpClient, expected: Option<&Id>, pin: Option<&[u8; 32]>) -> SdkResult<(KeyCard, Id)> {
        let info = Self::check(http.get("/v4/info").await?)?;
        let card = KeyCard::from_value(info.get("card").cloned().unwrap_or(Value::Null))?;
        if expected.is_some_and(|expected| expected != card.id()) {
            return Err(SdkError::Untrusted("node ID does not match".into()));
        }
        if pin.is_some() && card.tls() != pin {
            // The certificate matched, but the node's signed card does not pin it: not the node we were told about.
            return Err(SdkError::Untrusted("the node's card does not pin this TLS certificate".into()));
        }
        let statement = Statement::from_value(info.get("info").cloned().unwrap_or(Value::Null))?;
        statement.verify(&[&card], 1)?;
        statement.check_time(now_ms())?;
        if statement.kind() != "info" {
            return Err(SdkError::Untrusted("info statement expected".into()));
        }
        Ok((card, statement.net().clone()))
    }

    /// Solves the proof-of-work puzzle of a challenge answer, if there is one (verified as the node's first).
    fn solve_puzzle(
        &self,
        challenge: &serde_json::Map<String, Value>,
        node: &KeyCard,
        body: &mut Value,
    ) -> SdkResult<()> {
        if let Some(puzzle) = challenge.get("pow").filter(|value| !value.is_null()) {
            let puzzle = Puzzle::from_value(puzzle.clone())?;
            puzzle.verify(node)?;
            let solution =
                puzzle.solve(self.max_pow_tries).ok_or_else(|| SdkError::Untrusted("proof of work too hard".into()))?;
            body["pow"] = json!(b64(&solution));
        }
        Ok(())
    }

    /// The part of the network's log a client can check without replaying it (see [`gateway_in_log`]), on the
    /// first 4,096 entries fetched from the gateway itself.
    async fn check_gateway_in_log(&self, net: &Id, node: &Id) -> SdkResult<()> {
        let untrusted = |what: &str| SdkError::Untrusted(format!("network log: {what}"));
        let mut entries: Vec<Statement> = Vec::new();
        let mut from = 0u64;
        while from < JOIN_CHECK_MAX_ENTRIES {
            let query = json!({"from": from, "max": 256}).to_string().into_bytes();
            let page = Self::check(self.http.post(&format!("/v4/net/{net}/log"), None, query).await?)?;
            let list = page.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
            if list.is_empty() || list.len() > 256 {
                break;
            }
            for item in &list {
                from += 1;
                let bytes = b64_var(item.as_str().unwrap_or_default(), "entry", 64 * 1024)?;
                // Garbage entries do not count (docs/06 §6), and they do not stop the check either.
                if let Ok(statement) = Statement::parse(&bytes) {
                    entries.push(statement);
                } else if from == 1 {
                    return Err(untrusted("entry 0 is not a statement"));
                }
            }
            if page.get("size").and_then(Value::as_u64).is_some_and(|size| from >= size) {
                break;
            }
        }
        gateway_in_log(net, node, &entries)
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

    /// The card of `id` in the connected network `net` (docs/10 §6.3), fetched by this client's node from that
    /// network's gateways. Cards are self-certifying: the ID is checked here.
    pub async fn card_of_in(&self, id: &Id, net: &Id) -> SdkResult<KeyCard> {
        let body = json!({"id": id.as_str(), "net": net.as_str()}).to_string().into_bytes();
        let answer = Self::check(self.http.post("/v4/card", self.session.as_deref(), body).await?)?;
        let card = KeyCard::from_value(answer.get("card").cloned().unwrap_or(Value::Null))?;
        if card.id() != id {
            return Err(SdkError::Untrusted("node returned a card for another ID".into()));
        }
        Ok(card)
    }

    /// Like [`Client::send`] to a member of the connected network `dnet` (docs/10 §6.2).
    pub async fn send_to_net(&self, to: &KeyCard, dnet: &Id, content: &Content) -> SdkResult<[u8; 16]> {
        let net = self.net.as_ref().ok_or_else(|| SdkError::Untrusted("not connected".into()))?;
        let address = Address { net, to, kind: Kind::Msg, iat: now_ms(), ttl: self.ttl_s };
        let envelope = if dnet == net {
            Envelope::seal(&self.identity, &address, &content.to_bytes()?, &mut OsRng)?
        } else {
            Envelope::seal_for_net(&self.identity, &address, dnet, &content.to_bytes()?, &mut OsRng)?
        };
        self.send_envelope(&envelope).await?;
        Ok(*envelope.id())
    }

    /// Encrypts `content` for `to` and hands it to the node. Returns the envelope ID.
    pub async fn send(&self, to: &KeyCard, content: &Content) -> SdkResult<[u8; 16]> {
        let net = self.net.as_ref().ok_or_else(|| SdkError::Untrusted("not connected".into()))?;
        let address = Address { net, to, kind: Kind::Msg, iat: now_ms(), ttl: self.ttl_s };
        let envelope = Envelope::seal(&self.identity, &address, &content.to_bytes()?, &mut OsRng)?;
        self.send_envelope(&envelope).await?;
        Ok(*envelope.id())
    }

    /// Sends a task (`application/json`, e.g. to the AI service, docs/10 §4) to `to` - in the connected network `net`,
    /// if given - and waits up to `wait` for its response (content type `response` naming the task, from `to`).
    /// Other messages that arrive meanwhile are kept for the next [`Client::receive`]. `None`: no answer in time.
    pub async fn request(
        &mut self,
        to: &KeyCard,
        net: Option<&Id>,
        json: &[u8],
        wait: Duration,
    ) -> SdkResult<Option<Received>> {
        let content = Content::data(bridge_core::ContentType::Task, "application/json", json.to_vec());
        let task = match net {
            Some(net) => self.send_to_net(to, net, &content).await?,
            None => self.send(to, &content).await?,
        };
        let deadline = std::time::Instant::now() + wait;
        while std::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(std::time::Instant::now()).as_secs().clamp(1, 25);
            let inbox = self.receive_fresh(left).await?;
            let mut answer = None;
            for message in inbox.messages {
                let fits = answer.is_none()
                    && &message.from == to.id()
                    && message.content.kind == bridge_core::ContentType::Response
                    && message.content.reply == Some(task);
                if fits {
                    answer = Some(message);
                } else if self.stash.len() < 1_000 {
                    self.stash.push_back(message);
                }
            }
            if answer.is_some() {
                return Ok(answer);
            }
        }
        Ok(None)
    }

    /// Like [`Client::receive`], but always asks the node (the stash stays for later).
    async fn receive_fresh(&mut self, wait_s: u64) -> SdkResult<Inbox> {
        let stash = std::mem::take(&mut self.stash);
        let result = self.receive(wait_s).await;
        let mut kept = stash;
        kept.extend(std::mem::take(&mut self.stash));
        self.stash = kept;
        result
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
        if !self.stash.is_empty() {
            return Ok(Inbox { messages: self.stash.drain(..).collect(), ..Inbox::default() });
        }
        let body = json!({"wait": wait_s.min(25), "max": 100}).to_string().into_bytes();
        let answer = Self::check(self.http.post("/v4/poll", self.session.as_deref(), body).await?)?;
        let envelopes = answer.get("envelopes").and_then(Value::as_array).cloned().unwrap_or_default();
        let cards = answer.get("cards").and_then(Value::as_object).cloned().unwrap_or_default();
        let agents = answer.get("agents").and_then(Value::as_object).cloned().unwrap_or_default();
        let connected = self.connected_nets(&answer);
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
            match self.open(&envelope, &cards, &agents, &connected) {
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

    fn open(
        &self,
        envelope: &Envelope,
        cards: &serde_json::Map<String, Value>,
        agents: &serde_json::Map<String, Value>,
        connected: &[Id],
    ) -> Option<Received> {
        let own = self.net.as_ref()?;
        let from_here = envelope.net() == own && envelope.dnet().is_none();
        let from_connected = envelope.dnet() == Some(own) && connected.contains(envelope.net());
        if envelope.to() != self.identity.id() || !(from_here || from_connected) {
            return None;
        }
        let card = KeyCard::from_value(cards.get(envelope.from().as_str())?.clone()).ok()?;
        if card.id() != envelope.from() || envelope.check_time(now_ms()).is_err() {
            return None;
        }
        let plaintext = envelope.open(&self.identity, &card).ok()?;
        let content = Content::parse(&plaintext).ok()?;
        let agent_of =
            agents.get(envelope.from().as_str()).and_then(|statement| agent_of(statement, &card, envelope.net()));
        Some(Received {
            id: *envelope.id(),
            from: envelope.from().clone(),
            net: envelope.net().clone(),
            content,
            agent_of,
        })
    }

    /// The connected networks proven by a poll answer (docs/10 §6.3): `feds` statements of this network, signed by its
    /// net key alone (`master`, the card with this network's ID), in effect, for messages.
    fn connected_nets(&self, answer: &serde_json::Map<String, Value>) -> Vec<Id> {
        let (Some(own), Some(feds), Some(master)) =
            (self.net.as_ref(), answer.get("feds").and_then(Value::as_object), answer.get("master"))
        else {
            return Vec::new();
        };
        let Ok(master) = KeyCard::from_value(master.clone()) else { return Vec::new() };
        if master.id() != own || master.role() != Role::Net {
            return Vec::new();
        }
        feds.iter()
            .take(32)
            .filter_map(|(peer, statement)| {
                let statement = Statement::from_value(statement.clone()).ok()?;
                let body = statement.body();
                let scope = body.get("scope").and_then(Value::as_array)?;
                let fine = statement.kind() == "federation"
                    && statement.net() == own
                    && statement.claimed_signers() == [own]
                    && body.get("peer").and_then(Value::as_str) == Some(peer.as_str())
                    && scope.len() == 1
                    && scope[0].as_str() == Some("messages")
                    && statement.check_time(now_ms()).is_ok()
                    && statement.verify(&[&master], 1).is_ok();
                fine.then(|| Id::parse(peer).ok()).flatten()
            })
            .collect()
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

/// The owner an agent acts for, from its statement - only if it checks out (docs/10 §3.4): a valid agent statement of
/// this network for exactly this sender and card, signed by the owner in it.
fn agent_of(statement: &Value, sender: &KeyCard, net: &Id) -> Option<AgentOf> {
    let statement = Statement::from_value(statement.clone()).ok()?;
    let agent = Agent::check(&statement, net, now_ms()).ok()?;
    (&agent.agent == sender.id() && agent.card.to_value() == sender.to_value())
        .then(|| AgentOf { owner: agent.owner.id().clone(), note: agent.note })
}

/// What a client checks in a network's log before it joins at the gateway `node` (docs/06 §7): entry 0 is the
/// genesis manifest of `net`, signed by the network key (the trust anchor is the network ID), and `node` is a start
/// gateway of that manifest or has a `gateway` seal (level ≥ 2) **of this network**, signed by the network key or
/// only by admins whose delegation (by the network key, for this network) contains the right `seals`. Revocations,
/// expiry and multi-admin approvals are the nodes' business (they replay the whole log).
pub fn gateway_in_log(net: &Id, node: &Id, entries: &[Statement]) -> SdkResult<()> {
    let untrusted = |what: &str| SdkError::Untrusted(format!("network log: {what}"));
    let genesis = entries.first().ok_or_else(|| untrusted("empty"))?;
    let master = KeyCard::from_value(genesis.body().get("card").cloned().unwrap_or(Value::Null))?;
    if genesis.kind() != "manifest"
        || genesis.net() != net
        || master.id() != net
        || master.role() != Role::Net
        || genesis.body().get("version").and_then(Value::as_u64) != Some(1)
        || genesis.claimed_signers() != [net]
    {
        return Err(untrusted("entry 0 is not the genesis manifest of this network"));
    }
    genesis.verify(&[&master], 1)?;
    let listed =
        genesis.body().get("gateways").and_then(Value::as_array).is_some_and(|list| {
            list.iter().any(|entry| entry.get("id").and_then(Value::as_str) == Some(node.as_str()))
        });
    if listed {
        return Ok(());
    }
    // Who may seal: the network key, and admins it delegated the right `seals` to in this network.
    let mut cards = vec![master.clone()];
    for statement in
        entries.iter().filter(|s| s.kind() == "delegation" && s.net() == net && s.claimed_signers() == [net])
    {
        let body = statement.body();
        let seals = body
            .get("rights")
            .and_then(Value::as_array)
            .is_some_and(|rights| rights.iter().any(|right| right.as_str() == Some("seals")));
        if !seals || statement.verify(&[&master], 1).is_err() {
            continue;
        }
        if let Ok(card) = KeyCard::from_value(body.get("card").cloned().unwrap_or(Value::Null)) {
            let admin = body.get("admin").and_then(Value::as_str);
            if card.role() == Role::Admin && admin == Some(card.id().as_str()) && cards.len() < 10_000 {
                cards.push(card);
            }
        }
    }
    let card_refs: Vec<&KeyCard> = cards.iter().collect();
    let sealed = entries.iter().filter(|s| s.kind() == "seal" && s.net() == net).any(|seal| {
        let body = seal.body();
        body.get("subject").and_then(Value::as_str) == Some(node.as_str())
            && body.get("level").and_then(Value::as_u64).is_some_and(|level| level >= 2)
            && body
                .get("services")
                .and_then(Value::as_array)
                .is_some_and(|services| services.iter().any(|s| s.as_str() == Some("gateway")))
            // Every signer must be one of the cards above (an unknown signer fails the check).
            && seal.verify(&card_refs, seal.claimed_signers().len()).is_ok()
    });
    if sealed { Ok(()) } else { Err(untrusted("the gateway is not a gateway of this network")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (review 3, finding 9): the join check only takes gateway seals of this network, signed by the
    /// network key or by admins that have the right `seals`.
    #[test]
    fn join_check_takes_only_seals_of_this_network_by_sealing_admins() -> SdkResult<()> {
        let now = now_ms();
        let master = Identity::generate(&mut OsRng);
        let net = master.id().clone();
        let statement = |kind: &str, net: &Id, body: Value, signer: &Identity| {
            Statement::sign(&Draft { kind, net, iat: now, exp: now + 86_400_000, body }, signer)
        };
        let card = |who: &Identity, role: Role| who.key_card(role, None, now);
        let start = Identity::generate(&mut OsRng).id().clone();
        let genesis = statement(
            "manifest",
            &net,
            json!({"version": 1, "card": card(&master, Role::Net)?.to_value(), "gateways": [{"id": start.as_str()}]}),
            &master,
        )?;
        let delegation = |admin: &Identity, rights: &[&str], net: &Id| -> SdkResult<Statement> {
            let body =
                json!({"admin": admin.id().as_str(), "rights": rights, "card": card(admin, Role::Admin)?.to_value()});
            Ok(statement("delegation", net, body, &master)?)
        };
        let seal = |node: &Id, level: u8, net: &Id, signer: &Identity| -> SdkResult<Statement> {
            let body = json!({"subject": node.as_str(), "level": level, "services": ["gateway"]});
            Ok(statement("seal", net, body, signer)?)
        };
        let (sealer, banner) = (Identity::generate(&mut OsRng), Identity::generate(&mut OsRng));
        let other_net = Identity::generate(&mut OsRng).id().clone();
        let log = |extra: Vec<Statement>| -> SdkResult<Vec<Statement>> {
            let mut entries =
                vec![genesis.clone(), delegation(&sealer, &["seals"], &net)?, delegation(&banner, &["bans"], &net)?];
            entries.extend(extra);
            Ok(entries)
        };
        let node = Identity::generate(&mut OsRng).id().clone();
        let ok = |entries: &[Statement]| gateway_in_log(&net, &node, entries).is_ok();

        assert!(gateway_in_log(&net, &start, &log(vec![])?).is_ok(), "start gateway of the genesis");
        assert!(ok(&log(vec![seal(&node, 2, &net, &master)?])?), "sealed by the network key");
        assert!(ok(&log(vec![seal(&node, 2, &net, &sealer)?])?), "sealed by an admin with seals");
        assert!(!ok(&log(vec![])?), "not sealed at all");
        assert!(!ok(&log(vec![seal(&node, 2, &net, &banner)?])?), "an admin without seals");
        assert!(!ok(&log(vec![seal(&node, 1, &net, &sealer)?])?), "level 1 is no gateway");
        // The same admin key seals the node in another network: that seal does not count here.
        assert!(!ok(&log(vec![seal(&node, 2, &other_net, &sealer)?])?), "a seal of another network");
        // A delegation the network key gave for another network does not make an admin here.
        let foreign_admin = Identity::generate(&mut OsRng);
        let mut entries = log(vec![seal(&node, 2, &net, &foreign_admin)?])?;
        entries.push(delegation(&foreign_admin, &["seals"], &other_net)?);
        assert!(!ok(&entries), "a delegation of another network");
        // A wrong network ID: entry 0 is not its genesis.
        assert!(gateway_in_log(&other_net, &node, &log(vec![seal(&node, 2, &net, &master)?])?).is_err());
        Ok(())
    }

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
