//! Talking to other nodes: a bounded cache of HTTP clients, strict parsing of their answers, signed requests, and
//! the choice of peers (bounded, round robin, at most one gossip call per peer within `peer_gap`).
//!
//! LAN before Internet (docs/04 §7, docs/06 §2): a node is reached through its [`Endpoint`]s - first the LAN
//! addresses where it was seen lately (pinned to the TLS certificate of its card in the network log), then its
//! public addresses. A failed connection moves on to the next endpoint; an answer is an answer.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;

use bridge_core::encoding::b64_var;
use bridge_core::json::parse_strict;
use bridge_core::{Id, SignedRequest};
use bridge_transport::HttpClient;
use rand_core::OsRng;
use serde_json::{Map, Value, json};

use crate::{Node, lock};

/// Most cached HTTP clients (one per peer address).
const MAX_CLIENTS: usize = 256;
/// Most remembered peers (gossip times, home cursors).
const MAX_REMEMBERED: usize = 1024;
/// Most bytes of an answer from another node that are parsed (the transport cuts at 2 MiB).
const MAX_ANSWER_BYTES: usize = 3 * 1024 * 1024;
/// Most entries fetched for one head (more must come in later rounds - see docs/06 §10).
pub(crate) const MAX_FETCH_ENTRIES: u64 = 65_536;
/// Most bytes of entries fetched for one head.
const MAX_FETCH_BYTES: usize = 64 * 1024 * 1024;
/// Most LAN endpoints tried for one node (before its public addresses).
const MAX_LAN_ENDPOINTS: usize = 4;

/// One way to reach another node: a LAN address with the pin of its TLS certificate (and the node it was seen
/// for), or a public address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Endpoint {
    pub(crate) url: String,
    pub(crate) pin: Option<[u8; 32]>,
    /// LAN only: the node ID the directory listed this address for (a failed connection forgets it for that ID).
    pub(crate) node: Option<Id>,
}

impl Endpoint {
    /// A public address (`http://` or `https://` with certificate authorities).
    pub(crate) fn public(url: &str) -> Self {
        Self { url: url.trim_end_matches('/').to_owned(), pin: None, node: None }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pin {
            Some(_) => write!(f, "{} (LAN)", self.url),
            None => f.write_str(&self.url),
        }
    }
}

/// Per-node memory about peers.
#[derive(Default)]
pub(crate) struct Peers {
    clients: HashMap<Endpoint, HttpClient>,
    last_contact: HashMap<String, i64>,
    cursor: usize,
    /// Home exchange: the `seq` up to which a gateway's entries were taken.
    pub(crate) homes_since: HashMap<Id, i64>,
    /// Home exchange: where the next round starts in the list of gateways.
    pub(crate) homes_cursor: usize,
}

/// An answer of another node: status and the parsed JSON object.
pub(crate) struct Answer {
    pub(crate) status: u16,
    pub(crate) body: Map<String, Value>,
}

impl Answer {
    pub(crate) fn ok(self) -> Result<Map<String, Value>, String> {
        if self.status == 200 {
            return Ok(self.body);
        }
        let code = self.body.get("error").and_then(Value::as_str).unwrap_or("?");
        Err(format!("peer answered {} {code}", self.status))
    }

    /// The error code of an error answer.
    pub(crate) fn code(&self) -> &str {
        self.body.get("error").and_then(Value::as_str).unwrap_or_default()
    }
}

impl Node {
    fn client(&self, endpoint: &Endpoint) -> Result<HttpClient, String> {
        let network = self.network().ok_or("no network")?;
        let mut peers = lock(&network.peers);
        if let Some(client) = peers.clients.get(endpoint) {
            return Ok(client.clone());
        }
        let timeout = network.timing.peer_timeout;
        let client = match endpoint.pin {
            Some(pin) => HttpClient::new_pinned(&endpoint.url, pin, timeout),
            None => HttpClient::new(&endpoint.url, timeout),
        }
        .map_err(|e| e.to_string())?;
        if peers.clients.len() >= MAX_CLIENTS {
            peers.clients.clear();
        }
        peers.clients.insert(endpoint.clone(), client.clone());
        Ok(client)
    }

    fn parse_answer(status: u16, body: &[u8]) -> Result<Answer, String> {
        match parse_strict(body, MAX_ANSWER_BYTES).map_err(|e| format!("bad answer: {e}"))? {
            Value::Object(body) => Ok(Answer { status, body }),
            _ => Err("answer is not an object".into()),
        }
    }

    /// GET `path` at `to`.
    pub(crate) async fn peer_get(&self, to: &Endpoint, path: &str) -> Result<Answer, String> {
        let answer = self.client(to)?.get(path).await;
        self.answered(to, answer)
    }

    /// POST `body` to `path` at `to`.
    pub(crate) async fn peer_post(&self, to: &Endpoint, path: &str, body: Vec<u8>) -> Result<Answer, String> {
        let answer = self.client(to)?.post(path, None, body).await;
        self.answered(to, answer)
    }

    /// Parses an answer; a LAN address that failed (no connection, wrong certificate, nonsense) is forgotten for
    /// that node until the next discovery round, so the following calls take the next address right away (only for
    /// that node: a fake announcement of another ID with the same address must not take it from the real one).
    fn answered(
        &self,
        to: &Endpoint,
        answer: bridge_transport::TransportResult<bridge_transport::ClientResponse>,
    ) -> Result<Answer, String> {
        let parsed =
            answer.map_err(|e| e.to_string()).and_then(|answer| Self::parse_answer(answer.status, &answer.body));
        if let (true, Some(_), Some(node), Some(directory)) =
            (parsed.is_err(), to.pin, to.node.as_ref(), self.inner.lan.as_ref())
        {
            directory.forget(node, &to.url);
        }
        parsed
    }

    /// GET at the first of `endpoints` (one node) that answers at all.
    pub(crate) async fn peer_get_any(&self, endpoints: &[Endpoint], path: &str) -> Result<Answer, String> {
        let mut last = String::from("no address");
        for endpoint in endpoints {
            match self.peer_get(endpoint, path).await {
                Ok(answer) => return Ok(answer),
                Err(error) => last = format!("{endpoint}: {error}"),
            }
        }
        Err(last)
    }

    /// POST at the first of `endpoints` (one node) that answers at all.
    pub(crate) async fn peer_post_any(
        &self,
        endpoints: &[Endpoint],
        path: &str,
        body: Vec<u8>,
    ) -> Result<Answer, String> {
        let mut last = String::from("no address");
        for endpoint in endpoints {
            match self.peer_post(endpoint, path, body.clone()).await {
                Ok(answer) => return Ok(answer),
                Err(error) => last = format!("{endpoint}: {error}"),
            }
        }
        Err(last)
    }

    /// How to reach the node `id`: its LAN addresses first - if it was seen in the LAN lately and `tls` (from its
    /// card) pins a certificate - then its public `urls`. Never this node itself.
    pub(crate) fn endpoints_of(&self, id: &Id, tls: Option<[u8; 32]>, urls: &[String]) -> Vec<Endpoint> {
        if id == self.inner.identity.id() {
            return Vec::new();
        }
        let mut endpoints: Vec<Endpoint> = Vec::new();
        if let (Some(pin), Some(directory)) = (tls, self.inner.lan.as_ref()) {
            for url in directory.urls_of(id).into_iter().take(MAX_LAN_ENDPOINTS) {
                endpoints.push(Endpoint { url, pin: Some(pin), node: Some(id.clone()) });
            }
        }
        for url in urls.iter().take(bridge_core::keys::MAX_URLS) {
            let endpoint = Endpoint::public(url);
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
        endpoints
    }

    /// How to reach a node known from the network log (see [`Node::endpoints_of`]).
    pub(crate) fn reach(&self, id: &Id) -> Vec<Endpoint> {
        match self.with_core(|core| core.reach(id)) {
            Ok((tls, urls)) => self.endpoints_of(id, tls, &urls),
            Err(_) => Vec::new(),
        }
    }

    /// A request signed by this node for the node `aud`.
    pub(crate) fn signed(&self, aud: &Id, op: &str, body: Value) -> Result<Vec<u8>, String> {
        let request = SignedRequest::sign(&self.inner.identity, aud, op, body, self.now(), &mut OsRng)
            .map_err(|e| e.to_string())?;
        request.to_bytes().map_err(|e| e.to_string())
    }

    /// Path of a network endpoint.
    pub(crate) fn net_path(&self, action: &str) -> String {
        let net = self.network().map(|network| network.net.to_string()).unwrap_or_default();
        format!("/v4/net/{net}/{action}")
    }

    /// Log entries `[from, to)` from `source` (pages of up to 256, bounded in number and bytes).
    pub(crate) async fn fetch_entries(&self, source: &Endpoint, from: u64, to: u64) -> Result<Vec<Vec<u8>>, String> {
        if to.saturating_sub(from) > MAX_FETCH_ENTRIES {
            return Err(format!("log too far ahead ({} entries)", to.saturating_sub(from)));
        }
        let path = self.net_path("log");
        let mut entries: Vec<Vec<u8>> = Vec::new();
        let mut bytes = 0usize;
        let mut next = from;
        // An honest node fills a page up to 256 entries or 1 MiB, so with entries of at most 64 KiB a page has at
        // least 16 entries: a peer handing out one entry per page can not keep this node busy for long.
        let mut pages_left = to.saturating_sub(from) / 16 + 2;
        while next < to {
            if pages_left == 0 {
                return Err("too many pages".into());
            }
            pages_left -= 1;
            let body = json!({"from": next, "max": bridge_net::log::MAX_PAGE_ENTRIES}).to_string().into_bytes();
            let page = self.peer_post(source, &path, body).await?.ok()?;
            let list = page.get("entries").and_then(Value::as_array).ok_or("entries missing")?;
            if list.is_empty() || list.len() > bridge_net::log::MAX_PAGE_ENTRIES {
                return Err("bad page".into());
            }
            for item in list {
                if next >= to {
                    break;
                }
                let entry = b64_var(item.as_str().unwrap_or_default(), "entry", bridge_net::log::MAX_ENTRY_BYTES)
                    .map_err(|e| e.to_string())?;
                bytes = bytes.saturating_add(entry.len());
                if bytes > MAX_FETCH_BYTES {
                    return Err("entries too large".into());
                }
                entries.push(entry);
                next += 1;
            }
        }
        Ok(entries)
    }

    /// Addresses of this node (never talk to yourself).
    pub(crate) fn own_urls(&self) -> BTreeSet<String> {
        self.inner.card.urls().iter().map(|url| url.trim_end_matches('/').to_owned()).collect()
    }

    /// Up to `max` peers for this round: `candidates` (each the endpoints of one node, see
    /// [`Node::peer_candidates`]) without own addresses, without nodes whose endpoints all came before, and without
    /// peers contacted within `peer_gap`, rotating through the list.
    pub(crate) fn pick_peers(&self, candidates: Vec<Vec<Endpoint>>, max: usize) -> Vec<Vec<Endpoint>> {
        let Some(network) = self.network() else { return Vec::new() };
        let unique = self.distinct(candidates, MAX_REMEMBERED);
        if unique.is_empty() {
            return Vec::new();
        }
        let now = self.now();
        let gap = i64::try_from(network.timing.peer_gap.as_millis()).unwrap_or(i64::MAX);
        let mut peers = lock(&network.peers);
        if peers.last_contact.len() >= MAX_REMEMBERED {
            peers.last_contact.clear();
        }
        let start = peers.cursor % unique.len();
        let mut picked = Vec::new();
        for offset in 0..unique.len() {
            if picked.len() >= max {
                break;
            }
            let group = &unique[(start + offset) % unique.len()];
            let Some(key) = group.first().map(|endpoint| endpoint.url.clone()) else { continue };
            if peers.last_contact.get(&key).is_some_and(|last| now.saturating_sub(*last) < gap) {
                continue;
            }
            peers.last_contact.insert(key, now);
            picked.push(group.clone());
        }
        peers.cursor = peers.cursor.wrapping_add(picked.len().max(1));
        picked
    }

    /// At most `max` groups of endpoints without own addresses and without groups whose endpoints were all in
    /// earlier groups (a gateway that is also log operator, a bootstrap address of a known gateway).
    pub(crate) fn distinct(&self, candidates: Vec<Vec<Endpoint>>, max: usize) -> Vec<Vec<Endpoint>> {
        let groups = candidates.into_iter().map(|endpoints| Group { key: String::new(), endpoints }).collect();
        self.distinct_groups(groups, max).into_iter().map(|group| group.endpoints).collect()
    }

    /// Like [`Node::distinct`] for groups that know their node: a later group of a node ID that came before is merged
    /// into the first one (its new endpoints appended), so every node is one group.
    pub(crate) fn distinct_groups(&self, candidates: Vec<Group>, max: usize) -> Vec<Group> {
        let own = self.own_urls();
        let mut covered: HashSet<Endpoint> = HashSet::new();
        let mut unique: Vec<Group> = Vec::new();
        for group in candidates {
            let endpoints: Vec<Endpoint> = group
                .endpoints
                .into_iter()
                .filter(|endpoint| endpoint.pin.is_some() || !own.contains(&endpoint.url))
                .collect();
            if endpoints.is_empty() || endpoints.iter().all(|endpoint| covered.contains(endpoint)) {
                continue;
            }
            let known = unique.iter().position(|known| !group.key.is_empty() && known.key == group.key);
            if let Some(known) = known.and_then(|position| unique.get_mut(position)) {
                let new: Vec<Endpoint> = endpoints.into_iter().filter(|endpoint| !covered.contains(endpoint)).collect();
                covered.extend(new.iter().cloned());
                known.endpoints.extend(new);
            } else if unique.len() < max {
                covered.extend(endpoints.iter().cloned());
                unique.push(Group { key: group.key, endpoints });
            }
        }
        unique
    }

    /// Candidate peers, one group of endpoints per node: the log operators and all gateways (LAN first, see
    /// [`Node::endpoints_of`]), then each bootstrap address.
    pub(crate) fn peer_candidates(&self) -> Vec<Vec<Endpoint>> {
        self.peer_groups().into_iter().map(|group| group.endpoints).collect()
    }

    /// Like [`Node::peer_candidates`], each group with its node ID (bootstrap addresses: the address).
    pub(crate) fn peer_groups(&self) -> Vec<Group> {
        let Some(network) = self.network() else { return Vec::new() };
        let now = self.now();
        let nodes = self
            .with_core(|core| {
                let mut nodes: Vec<(Id, Option<[u8; 32]>, Vec<String>)> = Vec::new();
                for operator in core.state.log_operators() {
                    let (tls, urls) = core.reach(operator);
                    nodes.push((operator.clone(), tls, urls));
                }
                for (id, card) in core.state.gateways(now).into_iter().take(MAX_REMEMBERED) {
                    if let Some(card) = card {
                        nodes.push((id, card.tls().copied(), card.urls().to_vec()));
                    }
                }
                nodes
            })
            .unwrap_or_default();
        let mut groups: Vec<Group> = nodes
            .iter()
            .map(|(id, tls, urls)| Group { key: id.to_string(), endpoints: self.endpoints_of(id, *tls, urls) })
            .collect();
        groups.extend(network.bootstrap.iter().map(|url| Group::public(url)));
        groups
    }
}

/// The endpoints of one node (LAN first, then public) or of one bootstrap address: what counts as one source when
/// following the log - several endpoints of the same node are still one node (review 6, finding 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Group {
    /// The node's ID, or the bootstrap address (empty: unknown).
    pub(crate) key: String,
    /// How to reach it, best first.
    pub(crate) endpoints: Vec<Endpoint>,
}

impl Group {
    /// One public address of a node not known by ID (a bootstrap address).
    pub(crate) fn public(url: &str) -> Self {
        let endpoint = Endpoint::public(url);
        Self { key: endpoint.url.clone(), endpoints: vec![endpoint] }
    }
}
