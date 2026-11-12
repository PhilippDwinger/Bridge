//! The reader (docs/08 §8, ADR 0018): a node serves `GET /app/<app-id>/…` also for apps it does not host - for the
//! browser of its own user, so the verification happens in the user's own node (zero trust), never in a stranger's.
//!
//! - **Only local callers** ([`ReaderAccess`], default `Local`): straight from loopback, no proxy (no trusted proxy,
//!   no forwarding header), and a local `Host` (DNS rebinding and requests that came in through Tailscale Funnel are
//!   refused). `Lan` adds private addresses of the home network (RFC 1918, IPv6 ULA without Tailscale's
//!   fd7a:115c:a1e0::/48, link-local), `Tailnet` adds Tailscale's ranges (100.64.0.0/10, fd7a:115c:a1e0::/48) instead -
//!   both with an IP literal as `Host`. Everybody else gets the old `404` - never an open proxy.
//! - **Loopback listener** ([`LocalReader`], `--reader-listen`, review 9): a second listener of the node, bound to a
//!   loopback address and never behind a proxy, with only the reader and the name lookups - for the own browser when
//!   the main listener trusts a local proxy (Tailscale Funnel) and so can not tell it from the Internet.
//! - **Version**: from the reader's memory (at most 30 s old), else asked at the hosts of the last known version, the
//!   `hosts` hints of names of the app and up to 16 nodes with a `web` seal (in an order fixed per app) - verified
//!   like a host does (both signatures, owner standing, bans, 18+ label, at least one valid host); the best version
//!   wins. A miss is remembered 10 s.
//! - **Files**: part by part from the valid hosts, the hash list checked against the blob ID, every part against its
//!   hash - a host that sends a wrong part is skipped for that file. Served with the same sandbox headers as a host.
//! - **Memory**: parts and hash lists in an LRU in RAM (default 64 MiB, at most 4,096 entries), separate from the
//!   host's quotas, never pinned, empty after a restart; at most 256 versions.
//! - Every request checks the version again against the current network state (ban, label, expiry).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::Id;
use bridge_core::app::check_path;
use bridge_core::blob::{self, BlobId, HashList, PART_BYTES};
use bridge_core::crypto::sha256_parts;
use bridge_core::encoding::b64_var;
use bridge_net::{Service, check_standing, valid_hosts};
use bridge_transport::{BodyStream, Handler, Method, Request, Response};
use serde_json::{Value, json};

use crate::apps::{Hosts, Version};
use crate::network::Endpoint;
use crate::{Node, NodeError, NodeResult, lock};

/// Who may use the reader (`--reader off|local|lan|tailnet`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderAccess {
    /// No reader: apps this node does not host are `404`.
    Off,
    /// Only the own computer: loopback, no proxy, local `Host` (default).
    Local,
    /// Also the home network: RFC 1918, IPv6 ULA (without Tailscale's fd7a:115c:a1e0::/48) and link-local addresses,
    /// with an IP address as `Host`.
    Lan,
    /// Also the own tailnet: Tailscale's ranges 100.64.0.0/10 and fd7a:115c:a1e0::/48 (the same as
    /// `--peer-addresses tailnet` adds), with an IP address as `Host` (review 9).
    Tailnet,
}

impl ReaderAccess {
    /// `off`, `local`, `lan` or `tailnet`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "off" => Some(Self::Off),
            "local" => Some(Self::Local),
            "lan" => Some(Self::Lan),
            "tailnet" => Some(Self::Tailnet),
            _ => None,
        }
    }

    /// The name [`ReaderAccess::parse`] takes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Local => "local",
            Self::Lan => "lan",
            Self::Tailnet => "tailnet",
        }
    }
}

/// Settings of the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderConfig {
    /// Who may use it.
    pub access: ReaderAccess,
    /// Most bytes of parts and hash lists kept in memory.
    pub cache_bytes: u64,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self { access: ReaderAccess::Local, cache_bytes: 64 * 1024 * 1024 }
    }
}

/// Most app versions the reader remembers.
const MAX_VERSIONS: usize = 256;
/// Most parts and hash lists in the memory.
const MAX_ENTRIES: usize = 4_096;
/// A remembered version is asked for again after this time.
const FRESH_MS: i64 = 30_000;
/// An app that was not found is not looked up again for this time.
const MISS_MS: i64 = 10_000;
/// Most remembered misses.
const MAX_MISSES: usize = 1_024;
/// Most nodes asked for a version.
const MAX_ASKED: usize = 16;
/// Asking stops after this many verified answers.
const ENOUGH_ANSWERS: usize = 2;
/// Most web hosts of the log looked at for one lookup.
const MAX_WEB_HOSTS: usize = 4_096;
/// Longest wait for a slow browser per streamed part.
const STREAM_PART_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Part(BlobId, u32),
    List(BlobId),
}

#[derive(Clone)]
enum Cached {
    Part(Arc<Vec<u8>>),
    List(Arc<HashList>),
}

/// A least-recently-used memory with a byte and an entry cap.
struct Lru {
    entries: HashMap<Key, (Cached, u64, u64)>,
    order: BTreeMap<u64, Key>,
    bytes: u64,
    stamp: u64,
    cap: u64,
}

impl Lru {
    fn get(&mut self, key: &Key) -> Option<Cached> {
        let (value, stamp, _) = self.entries.get_mut(key)?;
        self.order.remove(stamp);
        self.stamp = self.stamp.wrapping_add(1);
        *stamp = self.stamp;
        self.order.insert(self.stamp, key.clone());
        Some(value.clone())
    }

    fn put(&mut self, key: Key, value: Cached, size: u64) {
        if size > self.cap {
            return;
        }
        self.remove(&key);
        self.stamp = self.stamp.wrapping_add(1);
        self.entries.insert(key.clone(), (value, self.stamp, size));
        self.order.insert(self.stamp, key);
        self.bytes = self.bytes.saturating_add(size);
        while self.bytes > self.cap || self.entries.len() > MAX_ENTRIES {
            let Some((_, oldest)) = self.order.pop_first() else { break };
            self.remove(&oldest);
        }
    }

    fn remove(&mut self, key: &Key) {
        if let Some((_, stamp, size)) = self.entries.remove(key) {
            self.order.remove(&stamp);
            self.bytes = self.bytes.saturating_sub(size);
        }
    }
}

/// A version the reader learned, with when.
struct Known {
    version: Version,
    fetched: i64,
}

struct Memory {
    versions: BTreeMap<Id, Known>,
    misses: BTreeMap<Id, i64>,
    lru: Lru,
}

/// The reader of one node.
pub(crate) struct Reader {
    config: ReaderConfig,
    memory: Mutex<Memory>,
}

impl Reader {
    pub(crate) fn new(config: ReaderConfig) -> Self {
        let lru = Lru { entries: HashMap::new(), order: BTreeMap::new(), bytes: 0, stamp: 0, cap: config.cache_bytes };
        Self { config, memory: Mutex::new(Memory { versions: BTreeMap::new(), misses: BTreeMap::new(), lru }) }
    }

    fn cached(&self, key: &Key) -> Option<Cached> {
        lock(&self.memory).lru.get(key)
    }

    fn keep(&self, key: Key, value: Cached, size: u64) {
        lock(&self.memory).lru.put(key, value, size);
    }

    /// Bytes kept in the memory (tests, status).
    pub(crate) fn kept_bytes(&self) -> u64 {
        lock(&self.memory).lru.bytes
    }
}

/// `localhost`, a loopback address, optionally with a port.
fn local_host(host: Option<&str>) -> bool {
    host_ip(host).is_some_and(|ip| ip.is_loopback()) || host_name(host) == Some("localhost")
}

/// The host part of a `Host` header (without port).
fn host_name(host: Option<&str>) -> Option<&str> {
    let host = host?;
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split_once(']').map(|(inner, _)| inner);
    }
    Some(match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    })
}

/// The IP address a `Host` header names, if it is one.
fn host_ip(host: Option<&str>) -> Option<IpAddr> {
    host_name(host)?.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// A private address of the home network: RFC 1918, IPv6 ULA (fc00::/7) without Tailscale's fd7a:115c:a1e0::/48,
/// link-local (review 9: a Tailscale address is no home network - that is [`ReaderAccess::Tailnet`]).
fn private(ip: IpAddr) -> bool {
    if bridge_transport::is_tailnet_ip(ip) {
        return false;
    }
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

impl Node {
    /// Whether `request` may use the reader (see module docs).
    pub(crate) fn reader_allows(&self, request: &Request) -> bool {
        if request.forwarded {
            return false;
        }
        let peer = request.peer.to_canonical();
        let local = peer.is_loopback() && local_host(request.host.as_deref());
        let literal = host_ip(request.host.as_deref()).is_some();
        match self.inner.reader.config.access {
            ReaderAccess::Off => false,
            ReaderAccess::Local => local,
            ReaderAccess::Lan => local || (private(peer) && literal),
            ReaderAccess::Tailnet => local || (bridge_transport::is_tailnet_ip(peer) && literal),
        }
    }

    /// Whether a remembered version still holds: not expired, the network's rules (owner, bans, 18+ label), at least
    /// one valid host. Returns those hosts.
    fn reader_valid(&self, version: &Version, now: i64) -> NodeResult<Hosts> {
        version.statement.check_time(now)?;
        if self.app_blocked(&version.manifest.app, &version.manifest.owner, now) {
            return Err(NodeError::not_found());
        }
        let hosts = self.with_core(|core| -> NodeResult<Hosts> {
            check_standing(&core.state, &version.manifest, now)?;
            Ok(valid_hosts(&core.state, &version.manifest, now))
        })??;
        if hosts.is_empty() {
            return Err(NodeError::not_found());
        }
        Ok(hosts)
    }

    /// The version of `app` the reader knows, checked again now - without asking anybody.
    pub(crate) fn reader_known(&self, app: &Id, now: i64) -> Option<(Version, Hosts)> {
        let version = lock(&self.inner.reader.memory).versions.get(app).map(|known| known.version.clone())?;
        let hosts = self.reader_valid(&version, now).ok()?;
        Some((version, hosts))
    }

    /// The newest valid version of `app` (see module docs): from memory while fresh, else asked.
    pub(crate) async fn reader_version(&self, app: &Id, now: i64) -> NodeResult<(Version, Hosts)> {
        let (known, miss) = {
            let memory = lock(&self.inner.reader.memory);
            let known = memory.versions.get(app).map(|known| (known.version.clone(), known.fetched));
            (known, memory.misses.get(app).is_some_and(|until| *until > now))
        };
        if let Some((version, fetched)) = &known {
            if now.saturating_sub(*fetched) < FRESH_MS {
                return self.reader_valid(version, now).map(|hosts| (version.clone(), hosts));
            }
        }
        if miss && known.is_none() {
            return Err(NodeError::not_found());
        }
        let found = self.reader_lookup(app, known.as_ref().map(|(version, _)| version), now).await;
        let mut memory = lock(&self.inner.reader.memory);
        match found {
            Some(version) => {
                memory.misses.remove(app);
                if !memory.versions.contains_key(app) && memory.versions.len() >= MAX_VERSIONS {
                    let oldest =
                        memory.versions.iter().min_by_key(|(_, known)| known.fetched).map(|(id, _)| id.clone());
                    if let Some(oldest) = oldest {
                        memory.versions.remove(&oldest);
                    }
                }
                memory.versions.insert(app.clone(), Known { version: version.clone(), fetched: now });
                drop(memory);
                let hosts = self.reader_valid(&version, now)?;
                Ok((version, hosts))
            }
            None => {
                if memory.misses.len() >= MAX_MISSES {
                    memory.misses.retain(|_, until| *until > now);
                    if memory.misses.len() >= MAX_MISSES {
                        memory.misses.clear();
                    }
                }
                memory.misses.insert(app.clone(), now.saturating_add(MISS_MS));
                if let Some(known) = memory.versions.get_mut(app) {
                    known.fetched = now; // nobody had a newer one: the known one goes on (checked below)
                }
                drop(memory);
                match known {
                    Some((version, _)) => self.reader_valid(&version, now).map(|hosts| (version, hosts)),
                    None => Err(NodeError::not_found()),
                }
            }
        }
    }

    /// Asks the candidates for `app` (hosts of the known version, hints of its names, web hosts of the log in an order
    /// fixed per app) and returns the best verified version that is newer than or as new as `known`.
    async fn reader_lookup(&self, app: &Id, known: Option<&Version>, now: i64) -> Option<Version> {
        let me = self.inner.identity.id().clone();
        let candidates = self
            .with_core(|core| {
                let mut ids: Vec<Id> = Vec::new();
                if let Some(known) = known {
                    ids.extend(known.manifest.hosts.iter().cloned());
                }
                for name in core.state.names_for(app, now) {
                    ids.extend(name.info.name.hosts.iter().cloned());
                }
                let mut web = core.state.sealed_with(Service::Web, now, MAX_WEB_HOSTS);
                web.sort_by_key(|id| sha256_parts(&[app.as_str().as_bytes(), id.as_str().as_bytes()]));
                ids.extend(web);
                let mut seen = BTreeSet::new();
                ids.retain(|id| id != &me && seen.insert(id.clone()));
                ids.truncate(MAX_ASKED);
                ids
            })
            .ok()?;
        let query = json!({"app": app.as_str()}).to_string().into_bytes();
        let mut best: Option<Version> = known.cloned();
        let mut answers = 0;
        for id in candidates {
            let endpoints = self.reach(&id);
            if endpoints.is_empty() {
                continue;
            }
            let Ok(answer) = self.peer_post_any(&endpoints, "/v4/app/manifest", query.clone()).await else { continue };
            if answer.status != 200 {
                continue;
            }
            let Some((version, _)) = self.parse_manifest(app, &answer.body, now) else { continue };
            answers += 1;
            if best.as_ref().is_none_or(|best| version.rank() > best.rank()) {
                best = Some(version);
            }
            if answers >= ENOUGH_ANSWERS {
                break;
            }
        }
        best
    }

    /// `GET /app/<app-id>/<path>` for an app this node does not host (`path` empty: the entry).
    pub(crate) async fn reader_file(&self, request: &Request, app: &Id, path: &str, now: i64) -> NodeResult<Response> {
        if !self.reader_allows(request) {
            return Err(NodeError::not_found());
        }
        // A version that does not hold (banned, labeled, expired, nowhere) is `404` like at a host.
        let (version, hosts) = self.reader_version(app, now).await.map_err(|_| NodeError::not_found())?;
        let path = if path.is_empty() { version.manifest.entry.as_str() } else { path };
        check_path(path).map_err(|_| NodeError::not_found())?;
        let file = version.manifest.file(path).ok_or_else(NodeError::not_found)?;
        let (id, size, kind) = (file.blob, file.size, file.kind);
        let me = self.inner.identity.id().clone();
        let sources: Vec<Vec<Endpoint>> = hosts
            .iter()
            .filter(|(host, _)| host != &me)
            .filter_map(|(host, card)| {
                let card = card.as_ref()?;
                Some(self.endpoints_of(host, card.tls().copied(), card.urls()))
            })
            .filter(|endpoints| !endpoints.is_empty())
            .collect();
        if sources.is_empty() && size > 0 {
            return Err(NodeError::unavailable());
        }
        let response = if size == 0 {
            Response::ok(Vec::new())
        } else {
            let list = self.reader_list(&id, size, &sources).await?;
            let bad = Arc::new(Mutex::new(BTreeSet::new()));
            if size <= PART_BYTES as u64 {
                let data = self.reader_part(&id, &list, 0, &sources, &bad).await?;
                Response::ok(data.as_ref().clone())
            } else {
                let parts = list.parts();
                let (sender, stream) = BodyStream::channel(size, 4);
                let node = self.clone();
                tokio::spawn(async move {
                    for index in 0..parts {
                        let Ok(data) = node.reader_part(&id, &list, index, &sources, &bad).await else { return };
                        if !sender.send(data.as_ref().clone(), STREAM_PART_TIMEOUT).await {
                            return;
                        }
                    }
                });
                Response { stream: Some(stream), ..Response::ok(Vec::new()) }
            }
        };
        Ok(response
            .with_header("content-type", kind.content_type())
            .with_header("cache-control", "no-cache")
            .with_header("etag", format!("\"{}\"", id.to_text())))
    }

    /// The verified hash list of a blob (memory, else from the sources).
    async fn reader_list(&self, id: &BlobId, size: u64, sources: &[Vec<Endpoint>]) -> NodeResult<Arc<HashList>> {
        let key = Key::List(*id);
        if let Some(Cached::List(list)) = self.inner.reader.cached(&key) {
            return Ok(list);
        }
        let list = Arc::new(self.lookup_hash_list(id, size, sources).await?);
        let bytes = u64::from(list.parts()).saturating_mul(32);
        self.inner.reader.keep(key, Cached::List(Arc::clone(&list)), bytes);
        Ok(list)
    }

    /// One verified part (memory, else from the sources in turn, starting at a different one per part; a source that
    /// sends a wrong part is not asked again for this file).
    async fn reader_part(
        &self,
        id: &BlobId,
        list: &HashList,
        index: u32,
        sources: &[Vec<Endpoint>],
        bad: &Mutex<BTreeSet<usize>>,
    ) -> NodeResult<Arc<Vec<u8>>> {
        let key = Key::Part(*id, index);
        if let Some(Cached::Part(data)) = self.inner.reader.cached(&key) {
            return Ok(data);
        }
        let query = json!({"blob": id.to_text(), "i": index}).to_string().into_bytes();
        let count = sources.len();
        for step in 0..count {
            let source = (index as usize + step) % count;
            if lock(bad).contains(&source) {
                continue;
            }
            let Ok(answer) = self.peer_post_any(&sources[source], "/v4/blob/get", query.clone()).await else {
                continue;
            };
            if answer.status != 200 {
                continue;
            }
            let data = answer
                .body
                .get("data")
                .and_then(Value::as_str)
                .and_then(|text| b64_var(text, "data", blob::PART_BYTES).ok());
            match data {
                Some(data) if list.verify_part(index, &data).is_ok() => {
                    let data = Arc::new(data);
                    let bytes = data.len() as u64;
                    self.inner.reader.keep(key, Cached::Part(Arc::clone(&data)), bytes);
                    return Ok(data);
                }
                _ => {
                    tracing::warn!(blob = %id, index, "reader: a host sent a wrong part - skipped for this file");
                    lock(bad).insert(source);
                }
            }
        }
        Err(NodeError::unavailable())
    }

    /// What the reader knows about an app, for `names/resolve` (the hosted version first).
    pub(crate) async fn app_view(&self, app: &Id, fetch: bool, now: i64) -> Option<(Version, Hosts)> {
        if let Some(version) = self.inner.apps.current(app) {
            if let Ok(hosts) = self.reader_valid(&version, now) {
                return Some((version, hosts));
            }
        }
        if fetch {
            return self.reader_version(app, now).await.ok();
        }
        self.reader_known(app, now)
    }
}

/// The loopback listener of a node for its own browser ([`crate::NodeConfig::reader_listen`]): the reader (`GET
/// /app/…`, also for hosted apps) and the read-only name lookups (`/v4/names/info|resolve|search|list`) - nothing else
/// (`404`). It never trusts a proxy, so a request here is local unless it carries a forwarding header; the reader's
/// own checks (loopback peer, local `Host`, access not `off`) still apply.
pub(crate) struct LocalReader(pub(crate) Node);

/// What the loopback listener serves besides `/app/…`.
fn local_reader_path(method: Method, path: &str) -> bool {
    matches!(
        (method, path),
        (Method::Get, "/v4/names/info")
            | (Method::Post, "/v4/names/resolve" | "/v4/names/search" | "/v4/names/list")
            | (Method::Options, "/v4/names/info" | "/v4/names/resolve" | "/v4/names/search" | "/v4/names/list")
    )
}

impl Handler for LocalReader {
    fn admit(&self, peer: IpAddr, path: &str) -> Option<Response> {
        self.0.admit(peer, path)
    }

    fn decorate(&self, path: &str, response: Response) -> Response {
        self.0.decorate(path, response)
    }

    async fn handle(&self, request: Request) -> Response {
        let path = request.path.clone();
        let served = request.peer.to_canonical().is_loopback()
            && (path.starts_with("/app/") || local_reader_path(request.method, &path));
        if !served {
            return self.0.decorate(&path, NodeError::not_found().to_response());
        }
        self.0.handle(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_addresses() {
        assert!(local_host(Some("127.0.0.1:7400")));
        assert!(local_host(Some("localhost:7400")));
        assert!(local_host(Some("localhost")));
        assert!(local_host(Some("[::1]:7400")));
        assert!(local_host(Some("127.0.0.2")));
        assert!(!local_host(Some("evil.example")));
        assert!(!local_host(Some("127.0.0.1.evil.example:80")));
        assert!(!local_host(Some("pc.tail1234.ts.net")));
        assert!(!local_host(None));
        assert_eq!(host_ip(Some("192.168.1.20:7400")), Some(IpAddr::from([192, 168, 1, 20])));
        assert!(private(IpAddr::from([10, 0, 0, 1])) && private(IpAddr::from([169, 254, 1, 1])));
        assert!(!private(IpAddr::from([100, 64, 0, 1])) && !private(IpAddr::from([8, 8, 8, 8])));
        assert!(private(IpAddr::from([0xfd00, 0, 0, 0, 0, 0, 0, 1])));
        assert_eq!(ReaderAccess::parse("lan"), Some(ReaderAccess::Lan));
        assert_eq!(ReaderAccess::parse("all"), None);
    }

    /// Review 9, finding 9: `lan` once took Tailscale's IPv6 range (inside fc00::/7) for the home network but not its
    /// IPv4 range. The home network is RFC 1918 + ULA without Tailscale now; Tailscale has its own mode `tailnet`.
    #[test]
    fn lan_is_the_home_network_and_tailnet_is_tailscale() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        for home in ["10.1.2.3", "172.16.0.9", "192.168.178.20", "169.254.3.4", "fd12:3456::1", "fe80::1"] {
            assert!(private(ip(home)), "{home}");
        }
        for tailscale in ["fd7a:115c:a1e0::1", "fd7a:115c:a1e0:ab12::99", "100.64.0.1", "100.101.102.103"] {
            assert!(!private(ip(tailscale)), "{tailscale} is no home network");
            assert!(bridge_transport::is_tailnet_ip(ip(tailscale)), "{tailscale}");
        }
        for name in ["off", "local", "lan", "tailnet"] {
            assert_eq!(ReaderAccess::parse(name).map(ReaderAccess::as_str), Some(name));
        }
        assert!(local_reader_path(Method::Post, "/v4/names/search"));
        assert!(!local_reader_path(Method::Post, "/v4/names/submit"), "nothing that writes");
        assert!(!local_reader_path(Method::Post, "/v4/send") && !local_reader_path(Method::Get, "/v4/info"));
    }

    #[test]
    fn lru_is_bounded_by_bytes_and_entries() -> Result<(), bridge_core::CoreError> {
        let mut lru = Lru { entries: HashMap::new(), order: BTreeMap::new(), bytes: 0, stamp: 0, cap: 10 };
        let id = HashList::of(b"x")?.id();
        let part = |n: usize| Cached::Part(Arc::new(vec![0; n]));
        lru.put(Key::Part(id, 0), part(4), 4);
        lru.put(Key::Part(id, 1), part(4), 4);
        assert!(lru.get(&Key::Part(id, 0)).is_some(), "touch 0: 1 is the oldest now");
        lru.put(Key::Part(id, 2), part(4), 4);
        assert!(lru.get(&Key::Part(id, 1)).is_none(), "evicted");
        assert!(lru.get(&Key::Part(id, 0)).is_some() && lru.get(&Key::Part(id, 2)).is_some());
        assert_eq!(lru.bytes, 8);
        lru.put(Key::Part(id, 3), part(11), 11);
        assert!(lru.get(&Key::Part(id, 3)).is_none(), "larger than the whole memory: not kept");
        lru.put(Key::Part(id, 0), part(2), 2);
        assert_eq!(lru.bytes, 6, "replacing counts once");
        Ok(())
    }
}
