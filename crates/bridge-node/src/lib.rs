//! # bridge-node – the node runtime
//!
//! Ties the compartments together: `transport` delivers requests, `guard` decides what may pass, `core` checks every
//! object, `store` keeps mailboxes. Phase 2 endpoints (docs/04 §7): info, challenge, login, send, poll, ack, card.
//! Phase 3 (docs/06): a node can belong to one BridgeNet ([`NetConfig`]) - then it follows the network's log, takes
//! the roles the log gives it (log operator, witness, gateway) and relays envelopes between gateways. A node
//! without a network behaves exactly as in phase 2.
//! LAN ([`LanConfig`], docs/06 §2): the same node also listens with TLS and its own certificate (fingerprint in its
//! card), announces itself via mDNS and reaches other nodes of its network over the pinned LAN path first.
//! Phase 4a (docs/07): blobs (files by content: upload with quotas, read by ID, parts verified on every read) and
//! Bridge apps (versions signed by app key and owner, hosted by several nodes that fetch new versions from each
//! other, served under `/app/<id>/` in a sandboxed origin). The Bridge API answers browsers with CORS (`*`).
//! All state hangs on one [`Node`] (no global state, S3) - tests run several nodes in one process.
//!
//! What a node knows about a message: network, from, to, time, kind, size. Never the content (Z1).
//!
//! Layering (docs/03_ARCHITEKTUR.md): uses all crates below it.

pub mod admin;
mod apps;
mod blobs;
mod error;
pub mod keyfile;
mod lan;
mod names;
mod network;
mod reader;
mod reports;
mod sessions;

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::json::parse_strict;
use bridge_core::{Draft, Envelope, Id, Identity, KeyCard, Puzzle, Role, SignedRequest, Statement};
use bridge_guard::{Guard, GuardError, Limits};
use bridge_store::{BlobFiles, Delivered, Delivery, Store};
use bridge_transport::{Handler, LanAnnouncer, Method, Request, Response, RunningServer, ServerConfig, TlsIdentity};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub use bridge_transport::{Discovery, LanHints, LanPeer, PeerAddresses};
pub use error::{NodeError, NodeResult};
pub use lan::LanConfig;
pub use network::{
    LanPin, MAX_BOOTSTRAP, MEMBER_LIFETIME_MS, NetConfig, NetStatus, NetTiming, WatchStatus, WatchedNode,
};
pub use reader::{ReaderAccess, ReaderConfig};

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
/// Folder of the blob files inside the data folder.
pub const BLOB_DIR: &str = "blobs";
pub use apps::APP_CSP;

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
    /// Network this node serves (phase 2: default = its own ID, a single-node network). Ignored when
    /// [`NodeConfig::network`] is set.
    pub net: Option<Id>,
    /// Membership in a BridgeNet (phase 3). `None`: the membership stored in the data folder, if any.
    pub network: Option<NetConfig>,
    /// Public addresses of this node for its key card (1-4). Empty: the ones stored in the data folder; for a node
    /// of a network without any, `http://<listen address>`.
    pub urls: Vec<String>,
    /// Guard limits.
    pub limits: Limits,
    /// Transport limits (the LAN listener has the same ones, without trusted proxies).
    pub server: ServerConfig,
    /// LAN access (`None`: Internet only). With it, the node's card carries the fingerprint of its TLS certificate
    /// (`tls`, kept in `node-tls.pem` in the data folder).
    pub lan: Option<LanConfig>,
    /// In a network: ask its watchers for probes and level 1 with these services (⊆ {web}; docs/06 §11.5) - the
    /// node joins as a member if it is none yet and registers at the watchers. `None`: not.
    pub probe: Option<bridge_net::Services>,
    /// Which addresses this node calls when another node chose them itself (review 8, docs/06 §2 "Adress-Schutz"):
    /// the addresses of nodes registered at this watcher, and addresses in cards only a watcher sealed. `Public` (the
    /// default): public IPs only (no loopback, private, link-local, CGNAT, ULA …) unless the node is reached in the LAN
    /// with its pinned certificate; `Tailnet`: also Tailscale's ranges (networks over Tailscale, BridgeControll's
    /// default); `Any`: no check (LAN-only networks, tests on 127.0.0.1). `bridge-node --peer-addresses …`.
    pub peer_addresses: PeerAddresses,
    /// The reader (docs/08 §8): who may load apps this node does not host through it (default: only this computer).
    pub reader: ReaderConfig,
    /// A second listener only for this computer (review 9, docs/08 §8): bound to a loopback address, never behind a
    /// proxy, it serves the reader (`/app/…`) and the name lookups only - so the own browser can use the reader of a
    /// node whose main listener trusts a local proxy (Tailscale Funnel). `None`: none. A non-loopback address is
    /// refused at the start.
    pub reader_listen: Option<std::net::SocketAddr>,
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
            network: None,
            urls: Vec::new(),
            limits: Limits::default(),
            server: ServerConfig::default(),
            lan: None,
            probe: None,
            peer_addresses: PeerAddresses::Public,
            reader: ReaderConfig::default(),
            reader_listen: None,
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
    network: Option<network::SharedNet>,
    /// Where other nodes were seen in the LAN (only with LAN on).
    lan: Option<lan::Directory>,
    /// The bytes of blobs (`blobs/` in the data folder).
    blobs: BlobFiles,
    /// The apps this node hosts.
    apps: apps::Apps,
    /// Apps it loads for the own browser (docs/08 §8).
    reader: reader::Reader,
    /// Name searches running now, all callers together (review 9: at most [`names::MAX_SEARCHES_AT_ONCE`]).
    searches: Arc<tokio::sync::Semaphore>,
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
    lan: Option<RunningServer>,
    /// The loopback listener for the own browser ([`NodeConfig::reader_listen`]).
    local_reader: Option<RunningServer>,
    announcer: Option<LanAnnouncer>,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningNode {
    /// Address the node listens on.
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.server.local_addr()
    }
    /// Address of the LAN listener (TLS), if LAN is on.
    #[must_use]
    pub fn lan_addr(&self) -> Option<std::net::SocketAddr> {
        self.lan.as_ref().map(RunningServer::local_addr)
    }
    /// Address of the loopback listener for the own browser ([`NodeConfig::reader_listen`]), if on.
    #[must_use]
    pub fn reader_addr(&self) -> Option<std::net::SocketAddr> {
        self.local_reader.as_ref().map(RunningServer::local_addr)
    }
    /// Whether the node is announced in the LAN (mDNS). `false` with LAN on means the announcement failed (e.g.
    /// no multicast): the LAN listener works, but others only find it with the address.
    #[must_use]
    pub fn lan_announced(&self) -> bool {
        self.announcer.is_some()
    }
    /// The node's key card.
    #[must_use]
    pub fn card(&self) -> &KeyCard {
        &self.node.inner.card
    }
    /// What the node knows about its network (`None` for a node without a network).
    #[must_use]
    pub fn net_status(&self) -> Option<NetStatus> {
        self.node.net_status()
    }
    /// Bytes the reader keeps in memory (docs/08 §8; bounded by `ReaderConfig::cache_bytes`).
    #[must_use]
    pub fn reader_bytes(&self) -> u64 {
        self.node.inner.reader.kept_bytes()
    }
    /// The watcher's view (docs/06 §11): whether it is one, its seals, the nodes registered with their probes
    /// (`None` without a network or log).
    pub async fn watch_status(&self) -> Option<WatchStatus> {
        self.node.watch_status().await
    }
    /// Stops the node: background duties, the mDNS announcement (with a goodbye), then both listeners (running
    /// requests may finish).
    pub async fn shutdown(self) {
        let Self { server, lan, local_reader, announcer, tasks, .. } = self;
        for task in &tasks {
            task.abort();
        }
        drop(announcer);
        let others = async move {
            if let Some(lan) = lan {
                lan.shutdown().await;
            }
            if let Some(local_reader) = local_reader {
                local_reader.shutdown().await;
            }
        };
        tokio::join!(server.shutdown(), others);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Opens the data folder and starts serving on `listener` (and, with [`NodeConfig::lan`], on the LAN listener).
pub async fn start(config: NodeConfig, listener: TcpListener) -> Result<RunningNode, String> {
    std::fs::create_dir_all(&config.data_dir).map_err(|e| format!("data folder: {e}"))?;
    let identity = keyfile::load_or_create(&config.data_dir)?;
    let tls = match &config.lan {
        Some(_) => Some(keyfile::load_or_create_tls(&config.data_dir)?),
        None => None,
    };
    let now = config.clock.now_ms();
    let path = config.data_dir.join(DB_FILE);
    let store = tokio::task::spawn_blocking(move || Store::open(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("database: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    let (network_config, urls) = resolve_network(&store, &config, local)?;
    let card = identity
        .key_card_with(Role::Node, config.name.as_deref(), &urls, tls.as_ref().map(TlsIdentity::fingerprint), now)
        .map_err(|e| format!("key card: {e}"))?;
    let network = match &network_config {
        Some(network_config) => Some(Arc::new(network::NetRuntime::open(
            &store,
            identity.id(),
            network_config,
            now,
            config.probe,
            config.peer_addresses,
        )?)),
        None => None,
    };
    let apps = match &network_config {
        Some(network_config) => apps::Apps::load(&store, &network_config.net, config.limits.max_hosted_apps, now)?,
        None => apps::Apps::empty(),
    };
    let net = match &network_config {
        Some(network_config) => network_config.net.clone(),
        None => config.net.clone().unwrap_or_else(|| identity.id().clone()),
    };
    // Bound before anything runs: a LAN port in use stops the start instead of leaving half a node behind.
    let lan_listener = match &config.lan {
        Some(lan) => Some(
            TcpListener::bind(lan.listen).await.map_err(|e| format!("LAN: cannot listen on {}: {e}", lan.listen))?,
        ),
        None => None,
    };
    let reader_listener = match config.reader_listen {
        Some(addr) if !addr.ip().is_loopback() => {
            return Err(format!("reader: {addr} is no loopback address (only this computer may use the reader)"));
        }
        Some(addr) => Some(TcpListener::bind(addr).await.map_err(|e| format!("reader: cannot listen on {addr}: {e}"))?),
        None => None,
    };
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
            network,
            lan: config.lan.as_ref().map(lan::Directory::new),
            blobs: BlobFiles::new(config.data_dir.join(BLOB_DIR)),
            apps,
            reader: reader::Reader::new(config.reader),
            searches: Arc::new(tokio::sync::Semaphore::new(names::MAX_SEARCHES_AT_ONCE)),
        }),
    };
    let lan_server = match (lan_listener, &tls) {
        (Some(listener), Some(tls)) => Some(
            bridge_transport::serve_tls(listener, lan::server_config(&config.server), Arc::new(node.clone()), tls)
                .map_err(|e| format!("LAN: {e}"))?,
        ),
        _ => None,
    };
    // The loopback listener never trusts a proxy: every request there comes straight from this computer.
    let local_config = ServerConfig { trusted_proxies: Vec::new(), ..config.server.clone() };
    let local_reader = match reader_listener {
        Some(listener) => {
            match bridge_transport::serve(listener, local_config, Arc::new(reader::LocalReader(node.clone()))) {
                Ok(server) => Some(server),
                Err(error) => {
                    if let Some(lan_server) = lan_server {
                        lan_server.shutdown().await;
                    }
                    return Err(format!("reader: {error}"));
                }
            }
        }
        None => None,
    };
    let server = match bridge_transport::serve(listener, config.server, Arc::new(node.clone())) {
        Ok(server) => server,
        Err(error) => {
            if let Some(lan_server) = lan_server {
                lan_server.shutdown().await;
            }
            if let Some(local_reader) = local_reader {
                local_reader.shutdown().await;
            }
            return Err(error.to_string());
        }
    };
    let announcer = match (&config.lan, &lan_server) {
        (Some(lan), Some(lan_server)) if lan.announce => node.announce(lan_server.local_addr().port()),
        _ => None,
    };
    let mut tasks = vec![tokio::spawn(janitor(node.clone()))];
    tasks.extend(network::spawn(&node));
    if node.network().is_some() {
        tasks.push(tokio::spawn(apps::run(node.clone())));
    }
    if node.network().is_some() && node.inner.lan.as_ref().is_some_and(lan::Directory::is_on) {
        tasks.push(tokio::spawn(lan::discover(node.clone())));
    }
    node.check_sealed_pin();
    tracing::info!(
        node = %node.inner.identity.id(),
        net = %node.inner.net,
        addr = %server.local_addr(),
        lan = ?lan_server.as_ref().map(RunningServer::local_addr),
        reader = ?local_reader.as_ref().map(RunningServer::local_addr),
        "node started"
    );
    Ok(RunningNode { node, server, lan: lan_server, local_reader, announcer, tasks })
}

/// Which network the node belongs to (configured, or stored in the data folder) and its addresses. A configured
/// membership is stored, so the next start without configuration continues in the same network.
fn resolve_network(
    store: &Store,
    config: &NodeConfig,
    local: std::net::SocketAddr,
) -> Result<(Option<NetConfig>, Vec<String>), String> {
    let network = match &config.network {
        Some(network) => {
            network::store_membership(store, &network.net, &network.bootstrap, network.lan_bootstrap.as_ref())?;
            Some(network.clone())
        }
        None => network::stored_membership(store)?.map(|stored| NetConfig {
            bootstrap: stored.bootstrap,
            lan_bootstrap: stored.lan,
            ..NetConfig::new(stored.net)
        }),
    };
    let mut urls = config.urls.clone();
    if urls.is_empty() {
        if let Some(stored) = store.meta_get(network::META_URLS).map_err(|e| e.to_string())? {
            urls = network::string_list(&stored)?;
        }
    } else {
        let list = json!(urls).to_string();
        store.meta_set(network::META_URLS, list.as_bytes()).map_err(|e| e.to_string())?;
    }
    if urls.is_empty() && network.is_some() {
        urls.push(format!("http://{local}"));
    }
    urls.truncate(bridge_core::keys::MAX_URLS);
    Ok((network, urls))
}

async fn janitor(node: Node) {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let now = node.now();
        lock(&node.inner.sessions).sweep(now);
        let store = Arc::clone(&node.inner.store);
        let network = node.network().is_some();
        let purged = tokio::task::spawn_blocking(move || {
            let (envelopes, seen) = store.purge_expired(now)?;
            let (homes, outbox) = if network { store.purge_net(now)? } else { (0, 0) };
            if network {
                store.purge_watch(now)?;
                store.purge_reports(now.saturating_sub(reports::KEEP_DONE_MS))?;
                store.purge_open_reports(1, now.saturating_sub(reports::KEEP_OPEN_LEVEL0_MS))?;
            }
            Ok::<_, bridge_store::StoreError>((envelopes, seen, homes, outbox))
        })
        .await;
        match purged {
            Ok(Ok((envelopes, seen, homes, outbox))) if envelopes + seen + homes + outbox > 0 => {
                tracing::debug!(envelopes, seen, homes, outbox, "purged");
            }
            Ok(Err(error)) => tracing::error!(%error, "purge"),
            _ => {}
        }
        node.blob_gc(now).await;
    }
}

impl Handler for Node {
    fn admit(&self, peer: std::net::IpAddr, path: &str) -> Option<Response> {
        // Step 1 for every request, before its body is read: the per-address bucket.
        let refused = self.inner.guard.admit_address(peer, self.now()).err()?;
        Some(self.decorate(path, NodeError::from(refused).to_response()))
    }

    fn decorate(&self, path: &str, response: Response) -> Response {
        // Also for answers the transport makes itself (405, 413, timeouts, too many streams): a browser must see the
        // error, not a CORS failure, and an app answer never goes out without its sandbox (docs/07 §5).
        if path.starts_with("/app/") { apps_headers(response) } else { cors(path, response) }
    }

    async fn handle(&self, request: Request) -> Response {
        if request.path.starts_with("/app/") {
            return self.serve_app(&request).await;
        }
        let path = request.path.clone();
        if request.method == Method::Options {
            return preflight(&path);
        }
        let response = match self.route(request).await {
            Ok(body) => Response::ok(body),
            Err(error) => error.to_response(),
        };
        cors(&path, response)
    }
}

/// The Bridge API may be called from apps in browsers (docs/07 §5): any origin, only with a bearer token (no cookies,
/// so no credentials are allowed), only what the API uses.
fn cors(path: &str, response: Response) -> Response {
    if !path.starts_with("/v4/") {
        return response;
    }
    response.with_header("access-control-allow-origin", "*").with_header("access-control-expose-headers", "Retry-After")
}

/// Answer to a CORS preflight (`OPTIONS`) for the Bridge API; other paths know no `OPTIONS`.
fn preflight(path: &str) -> Response {
    if !path.starts_with("/v4/") {
        return NodeError::not_found().to_response();
    }
    cors(path, Response { status: 204, ..Response::ok(Vec::new()) })
        .with_header("access-control-allow-methods", "GET, POST")
        .with_header("access-control-allow-headers", "Authorization, Content-Type")
        .with_header("access-control-max-age", "600")
}

/// The sandbox headers of app answers (also for refusals before the request is read).
fn apps_headers(response: Response) -> Response {
    response
        .with_header("content-security-policy", APP_CSP)
        .with_header("access-control-allow-origin", "*")
        .with_header("referrer-policy", "no-referrer")
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

    /// Announces the node in the LAN; a failure (no multicast, firewall) is logged, the node runs on without it.
    fn announce(&self, port: u16) -> Option<LanAnnouncer> {
        let net = self.network().map(|network| network.net.to_string());
        let extra: Vec<(&str, &str)> = net.as_deref().map(|net| vec![("net", net)]).unwrap_or_default();
        match LanAnnouncer::start(self.inner.identity.id().as_str(), port, &extra) {
            Ok(announcer) => Some(announcer),
            Err(error) => {
                tracing::warn!(%error, "LAN: mDNS announcement failed - others find this node only by its address");
                None
            }
        }
    }

    /// Other nodes pin the TLS certificate from this node's card in the network log (its seal). Warns when that
    /// card pins another certificate than the one this node serves (or none) - then they cannot use the LAN path to
    /// it until it is sealed again with its current card (docs/06 §2).
    fn check_sealed_pin(&self) {
        let Some(mine) = self.inner.card.tls().copied() else { return };
        let me = self.inner.identity.id().clone();
        let sealed = self.with_core(|core| core.state.card_of(&me).map(|card| card.tls().copied()));
        if let Ok(Some(sealed)) = sealed {
            if sealed != Some(mine) {
                tracing::warn!(
                    "LAN: the card in this node's seal pins another TLS certificate (or none) - other nodes reach it \
                     only by its public address until it is sealed again (bridge-node net seal)"
                );
            }
        }
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
            (_, path) if path.starts_with("/v4/net/") || path.starts_with("/v4/node/") => {
                self.route_network(&request, now).await
            }
            (_, path) if path.starts_with("/v4/blob/") => self.route_blob(&request, now).await,
            (_, path) if path.starts_with("/v4/app/") => self.route_app(&request, now).await,
            (_, path) if path.starts_with("/v4/names/") => self.route_names(&request, now).await,
            (Method::Post, "/v4/report") => self.report_in(&request, now).await,
            (_, path) if path.starts_with("/v4/admin/") => self.route_admin(&request, now).await,
            _ => Err(NodeError::not_found()),
        }
    }

    fn session(&self, request: &Request, now: i64) -> NodeResult<Id> {
        let token = request.bearer.as_deref().ok_or_else(NodeError::no_session)?;
        let token = b64_fixed::<32>(token, "session").map_err(|_| NodeError::no_session())?;
        let id = lock(&self.inner.sessions).lookup(&token, now).ok_or_else(NodeError::no_session)?;
        // In a network: still a member, not banned, and this node still a gateway (revocations take effect at once).
        self.net_session_check(&id, now)?;
        Ok(id)
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
        let mut body = json!({
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
        if let Some(status) = self.net_status() {
            body["phase"] = json!(3);
            body["network"] = json!({
                "log_size": status.size,
                "gateway": status.gateway,
                "operator": status.operator,
                "witness": status.witness,
            });
        }
        let draft = Draft { kind: "info", net: &self.inner.net, iat: now, exp: now + 10 * 60 * 1000, body };
        let statement = Statement::sign(&draft, &self.inner.identity)?;
        Ok(json!({"card": self.inner.card.to_value(), "info": statement.to_value()}).to_string().into_bytes())
    }

    fn challenge(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        self.inner.guard.admit_challenge(request.peer, now)?;
        let mut bits = self.inner.guard.pow_bits(now);
        // A challenge for joining a network carries the proof-of-work the manifest asks for (docs/06 §7). The body
        // is optional (phase 2 sends `{}`), anything unreadable counts as a login challenge.
        let for_join = body_object(&request.body, 1024)
            .is_ok_and(|object| object.get("for").and_then(Value::as_str) == Some("join"));
        if for_join {
            if let Ok(join_bits) = self.with_core(|core| core.state.manifest().join.pow_bits) {
                bits = bits.max(join_bits).min(bridge_core::pow::MAX_POW_BITS);
            }
        }
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
        if card.role() == Role::App {
            return Err(NodeError::forbidden("an app key only signs app versions, it never logs in"));
        }
        request.verify(&card)?;
        if self.network().is_some() {
            self.net_login(&card, request.body().get("home"), now).await?;
        }
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
        let route = if self.network().is_some() {
            self.route_recipient(envelope.to(), now).await?
        } else if self.known_card(envelope.to()).await?.is_none() {
            return Err(NodeError::new(404, "UNKNOWN_IDENTITY", "recipient unknown here"));
        } else {
            network::Route::Local
        };
        let sender = self.known_card(&caller).await?.ok_or_else(NodeError::no_session)?;
        envelope.verify(&sender)?;
        match route {
            network::Route::Local => self.deliver_local(&envelope, now).await?,
            network::Route::Relay(target) => self.relay_enqueue(&envelope, &sender, &target, now).await?,
        }
        Ok(br#"{"ok":true}"#.to_vec())
    }

    /// Puts a fully checked envelope into its recipient's mailbox here (quotas, replay) and wakes a waiting poll.
    async fn deliver_local(&self, envelope: &Envelope, now: i64) -> NodeResult<()> {
        let (recipient, from, env_id, expires_at) =
            (envelope.to().to_string(), envelope.from().to_string(), *envelope.id(), envelope.expires_at());
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
        Ok(())
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
        let card = match self.known_card(&id).await? {
            Some(card) => Some(card),
            // A member homed at another gateway: its card came with the exchanged home entry.
            None => self.home_card(&id, now).await?,
        };
        match card {
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
