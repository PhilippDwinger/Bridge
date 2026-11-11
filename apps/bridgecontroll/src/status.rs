//! Live status of the local nodes (ADR 0017): every few seconds each running node is asked over its local address for
//! `/v4/info` (its card, verified: self-signed card, info statement signed by it), its network's log from where the
//! cache ends (checked from entry 0 = the genesis of the network ID, replayed with `bridge-net` exactly as every node
//! does), its newest witnessed head and the evidence it holds.
//!
//! The cache keeps only what the views need: the replayed [`NetState`] and, gathered while replaying, the subjects of
//! seals, the invites and the bans of the log (all bounded). A node that does not answer keeps its last view,
//! marked stale.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::json::parse_strict;
use bridge_core::{Id, KeyCard, Statement};
use bridge_net::{Ban, Body as _, Invite, NetState, Seal, WitnessedHead};
use bridge_transport::HttpClient;
use serde_json::{Value, json};
use tokio::sync::RwLock;

use crate::now_ms;

/// Most log entries a view replays (beyond that the view stops growing and says so).
pub const MAX_VIEW_ENTRIES: u64 = 1 << 18;
/// Most log entries fetched per node and round.
const MAX_FETCH_PER_ROUND: u64 = 4096;
/// Most invites, bans and seal subjects remembered per view.
const MAX_TRACKED: usize = 100_000;
/// Timeout of one request to a local node.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// What `/v4/info` says (checked).
#[derive(Debug, Clone, PartialEq)]
pub struct NodeInfo {
    /// The node's card.
    pub card: KeyCard,
    /// Its network (`None` for a node without one).
    pub net: Option<Id>,
    /// Log entries it holds.
    pub log_size: u64,
    /// It is a gateway now.
    pub gateway: bool,
    /// It is the active log operator.
    pub operator: bool,
    /// It is a witness.
    pub witness: bool,
    /// Its program version.
    pub version: String,
}

impl NodeInfo {
    /// The name on its card (empty if none).
    #[must_use]
    pub fn name(&self) -> String {
        card_name(&self.card)
    }
}

/// The name on a card (empty if none).
#[must_use]
pub fn card_name(card: &KeyCard) -> String {
    card.to_value().get("name").and_then(Value::as_str).unwrap_or_default().to_owned()
}

/// An invite statement of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteEntry {
    /// Hash of the statement.
    pub hash: String,
    /// Hash of the code (key for the remaining uses).
    pub code_hash: [u8; 32],
    /// Uses it was made with.
    pub uses: u32,
    /// Issued at / expires (ms).
    pub iat: i64,
    /// Expires (ms).
    pub exp: i64,
}

/// A ban statement of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    /// Hash of the statement (to lift it with a revocation).
    pub hash: [u8; 32],
    /// The banned identity (or app).
    pub subject: Id,
    /// Expires (ms).
    pub exp: i64,
}

/// A network as one local node holds it.
#[derive(Debug, Clone)]
pub struct NetView {
    /// Network ID.
    pub net: Id,
    /// Entries replayed.
    pub size: u64,
    /// The state from the log.
    pub state: NetState,
    /// Everybody a seal was ever issued for (in the log order of first appearance, bounded).
    pub sealed: BTreeSet<Id>,
    /// Invites by statement hash.
    pub invites: BTreeMap<String, InviteEntry>,
    /// Bans (newest last, bounded).
    pub bans: Vec<BanEntry>,
    /// The log is longer than [`MAX_VIEW_ENTRIES`]: the view stopped growing.
    pub truncated: bool,
}

impl NetView {
    fn genesis(net: &Id, entry: &[u8]) -> Result<Self, String> {
        let state = NetState::genesis(net, entry).map_err(|e| format!("Eintrag 0 ungültig: {e}"))?;
        Ok(Self {
            net: net.clone(),
            size: 1,
            state,
            sealed: BTreeSet::new(),
            invites: BTreeMap::new(),
            bans: Vec::new(),
            truncated: false,
        })
    }

    fn apply(&mut self, entry: &[u8]) {
        self.state.apply(entry);
        self.size += 1;
        let Ok(statement) = Statement::parse(entry) else { return };
        match statement.kind() {
            "seal" => {
                if let Ok(seal) = Seal::from_statement(&statement) {
                    if self.sealed.len() < MAX_TRACKED {
                        self.sealed.insert(seal.subject);
                    }
                }
            }
            "invite" => {
                if let Ok(invite) = Invite::from_statement(&statement) {
                    if self.invites.len() < MAX_TRACKED {
                        let (iat, exp) = statement.times();
                        let hash = statement.hash();
                        self.invites.insert(
                            hash.clone(),
                            InviteEntry { hash, code_hash: invite.code_hash, uses: invite.uses, iat, exp },
                        );
                    }
                }
            }
            "ban" => {
                if let Ok(ban) = Ban::from_statement(&statement) {
                    if self.bans.len() >= MAX_TRACKED {
                        self.bans.remove(0);
                    }
                    self.bans.push(BanEntry {
                        hash: statement.hash_bytes(),
                        subject: ban.subject,
                        exp: statement.times().1,
                    });
                }
            }
            _ => {}
        }
    }
}

/// The newest witnessed head a node shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadInfo {
    /// Its size.
    pub size: u64,
    /// When the log operator issued it (ms).
    pub iat: i64,
    /// Cosignatures with it.
    pub cosigns: usize,
}

/// Everything known about one local node.
#[derive(Debug, Clone, Default)]
pub struct NodeCache {
    /// Last answer of `/v4/info`.
    pub info: Option<NodeInfo>,
    /// When it answered last (ms).
    pub seen: i64,
    /// The last round reached it.
    pub reachable: bool,
    /// Its network.
    pub net: Option<NetView>,
    /// Its newest witnessed head.
    pub head: Option<HeadInfo>,
    /// Pieces of evidence against log operators it holds.
    pub evidence: usize,
    /// What went wrong in the last round (German).
    pub error: Option<String>,
}

/// The caches of all local nodes.
#[derive(Default)]
pub struct Poller {
    caches: Mutex<HashMap<String, Arc<RwLock<NodeCache>>>>,
}

impl Poller {
    /// The cache of a node (made empty on first use).
    #[must_use]
    pub fn cache(&self, id: &str) -> Arc<RwLock<NodeCache>> {
        let mut caches = self.caches.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(caches.entry(id.to_owned()).or_default())
    }

    /// Forgets a node (deleted).
    pub fn forget(&self, id: &str) {
        self.caches.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(id);
    }

    /// One round for a node that runs at `url`.
    pub async fn poll(&self, id: &str, url: &str) {
        let cache = self.cache(id);
        let http = match HttpClient::new(url, REQUEST_TIMEOUT) {
            Ok(http) => http,
            Err(error) => {
                cache.write().await.error = Some(error.to_string());
                return;
            }
        };
        let info = match fetch_info(&http).await {
            Ok(info) => info,
            Err(error) => {
                let mut cache = cache.write().await;
                cache.reachable = false;
                cache.error = Some(error);
                return;
            }
        };
        let (net, log_size) = (info.net.clone(), info.log_size);
        {
            let mut cache = cache.write().await;
            cache.info = Some(info);
            cache.seen = now_ms();
            cache.reachable = true;
            cache.error = None;
            if cache.net.as_ref().map(|view| &view.net) != net.as_ref() {
                cache.net = None;
                cache.head = None;
            }
        }
        let Some(net) = net else { return };
        let from = cache.read().await.net.as_ref().map_or(0, |view| view.size);
        if log_size > from {
            if let Err(error) = self.follow(&cache, &http, &net, from, log_size).await {
                cache.write().await.error = Some(error);
            }
        }
        let head = fetch_head(&http, &net).await;
        let evidence = fetch_evidence(&http, &net).await;
        let mut cache = cache.write().await;
        if let Some(head) = head {
            cache.head = Some(head);
        }
        cache.evidence = evidence.unwrap_or(cache.evidence);
    }

    /// Fetches entries `[from, to)` (at most a round's worth) and replays them into the view.
    async fn follow(
        &self,
        cache: &RwLock<NodeCache>,
        http: &HttpClient,
        net: &Id,
        from: u64,
        to: u64,
    ) -> Result<(), String> {
        if from >= MAX_VIEW_ENTRIES {
            if let Some(view) = cache.write().await.net.as_mut() {
                view.truncated = true;
            }
            return Ok(());
        }
        let to = to.min(from.saturating_add(MAX_FETCH_PER_ROUND)).min(MAX_VIEW_ENTRIES);
        let entries = fetch_log(http, net, from, to).await?;
        let mut cache = cache.write().await;
        // Only continue a view that still ends where this round started (another round may have run).
        if cache.net.as_ref().map_or(0, |view| view.size) != from {
            return Ok(());
        }
        for entry in entries {
            match cache.net.as_mut() {
                Some(view) => view.apply(&entry),
                None => cache.net = Some(NetView::genesis(net, &entry)?),
            }
        }
        Ok(())
    }
}

/// `GET /v4/info`, checked: the card is self-signed, the info statement is signed by it.
async fn fetch_info(http: &HttpClient) -> Result<NodeInfo, String> {
    let answer = http.get("/v4/info").await.map_err(|e| format!("nicht erreichbar: {e}"))?;
    let Ok(Value::Object(object)) = parse_strict(&answer.body, 64 * 1024) else {
        return Err(format!("antwortet unverständlich ({})", answer.status));
    };
    let card = KeyCard::from_value(object.get("card").cloned().unwrap_or(Value::Null))
        .map_err(|e| format!("Karte ungültig: {e}"))?;
    let statement = Statement::from_value(object.get("info").cloned().unwrap_or(Value::Null))
        .map_err(|e| format!("Info ungültig: {e}"))?;
    statement.verify(&[&card], 1).map_err(|_| "Info nicht vom Knoten signiert".to_owned())?;
    if statement.kind() != "info" {
        return Err("keine Info".into());
    }
    let body = statement.body();
    let network = body.get("network");
    let flag = |name: &str| network.and_then(|n| n.get(name)).and_then(Value::as_bool).unwrap_or(false);
    Ok(NodeInfo {
        net: network.map(|_| statement.net().clone()),
        log_size: network.and_then(|n| n.get("log_size")).and_then(Value::as_u64).unwrap_or(0),
        gateway: flag("gateway"),
        operator: flag("operator"),
        witness: flag("witness"),
        version: body.get("version").and_then(Value::as_str).unwrap_or_default().chars().take(32).collect(),
        card,
    })
}

/// Log entries `[from, to)` in pages.
pub async fn fetch_log(http: &HttpClient, net: &Id, from: u64, to: u64) -> Result<Vec<Vec<u8>>, String> {
    let path = format!("/v4/net/{net}/log");
    let mut entries = Vec::new();
    let mut next = from;
    while next < to {
        let body = json!({"from": next, "max": bridge_net::log::MAX_PAGE_ENTRIES}).to_string().into_bytes();
        let answer = http.post(&path, None, body).await.map_err(|e| format!("Log: {e}"))?;
        let Ok(Value::Object(page)) = parse_strict(&answer.body, 4 * 1024 * 1024) else {
            return Err(format!("Log: unverständlich ({})", answer.status));
        };
        if answer.status != 200 {
            return Err(format!("Log: {}", page.get("error").and_then(Value::as_str).unwrap_or("Fehler")));
        }
        let list = page.get("entries").and_then(Value::as_array).filter(|list| !list.is_empty()).ok_or("Log: leer")?;
        for item in list {
            if next >= to {
                break;
            }
            let entry = bridge_core::encoding::b64_var(
                item.as_str().unwrap_or_default(),
                "entry",
                bridge_net::log::MAX_ENTRY_BYTES,
            )
            .map_err(|e| format!("Log: {e}"))?;
            entries.push(entry);
            next += 1;
        }
    }
    Ok(entries)
}

async fn fetch_head(http: &HttpClient, net: &Id) -> Option<HeadInfo> {
    let answer = http.get(&format!("/v4/net/{net}/head")).await.ok()?;
    if answer.status != 200 {
        return None;
    }
    let value = parse_strict(&answer.body, bridge_net::log::MAX_WITNESSED_HEAD_BYTES).ok()?;
    let witnessed = WitnessedHead::from_value(&value).ok()?;
    Some(HeadInfo { size: witnessed.size().ok()?, iat: witnessed.head.times().0, cosigns: witnessed.cosigns.len() })
}

async fn fetch_evidence(http: &HttpClient, net: &Id) -> Option<usize> {
    let answer = http.get(&format!("/v4/net/{net}/evidence")).await.ok()?;
    if answer.status != 200 {
        return None;
    }
    let value = parse_strict(&answer.body, 4 * 1024 * 1024).ok()?;
    value.get("evidence").and_then(Value::as_array).map(Vec::len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_names() {
        let identity = bridge_core::Identity::generate(&mut rand_core::OsRng);
        let named = identity.key_card(bridge_core::Role::Client, Some("laptop"), 1);
        let unnamed = identity.key_card(bridge_core::Role::Client, None, 1);
        assert_eq!(named.map(|card| card_name(&card)), Ok("laptop".to_owned()));
        assert_eq!(unnamed.map(|card| card_name(&card)), Ok(String::new()));
    }

    #[tokio::test]
    async fn unreachable_nodes_are_marked() {
        let poller = Poller::default();
        poller.poll("0a1b2c3d", "http://127.0.0.1:9").await;
        let cache = poller.cache("0a1b2c3d");
        let cache = cache.read().await;
        assert!(!cache.reachable && cache.info.is_none() && cache.error.is_some());
        drop(cache);
        poller.forget("0a1b2c3d");
    }
}
