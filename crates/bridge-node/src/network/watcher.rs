//! The watcher (docs/06 §11, ADR 0016): automatic level 1.
//!
//! A node is a watcher while the log gives it an active seal of level ≥ 2 with the service `watch` (the state decides,
//! [`bridge_net::NetState::is_watcher`]). Then, every round (`NetTiming::watch`), it
//! - **probes** the nodes registered here (`POST /v4/node/watch`) - at most 16 at a time, each at most every
//!   `probe_interval_s`: `/v4/info` (right ID, signed, right clock) and `/v4/net/{net}/head` (consistent with the own
//!   log, not far behind), both within 5 s, LAN first with the pin of the registered card, then its `urls`;
//! - **decides** (at most 16 statements per round, never beyond the budget of the day): level-1 node seals for nodes
//!   observed long enough with enough passed probes, level-1 member seals for members old enough without bans (256
//!   members per round, in turns), renewals of its own seals, and revocations of its own seals after `fail_limit`
//!   failed probes in a row or when the subject is banned or no member any more. Every seal is checked with the same
//!   rule the state applies (`check_watch_seal`) before it is signed;
//! - **submits** them to the active log operator like an admin (`submit` takes watchers).
//!
//! Registrations and the probe history are stored (schema 7) and survive restarts. A statement in flight is
//! remembered (pending) until the log shows it or 30 s passed, so no round signs the same thing twice.
//!
//! Review 8: registered addresses are the node's own choice - probes go only to public IPs, resolved and pinned per
//! call (with `tailnet` also Tailscale's ranges, with `any` all; [`crate::NodeConfig::peer_addresses`]). A full table makes room by
//! evicting the oldest registration that is not passing; new registrations are limited per address. New addresses
//! (or a new LAN pin) start the observation again, and only a renewal with the same card goes without the full window.
//! A node seal whose registration lapsed is revoked (no seal without probes).
//!
//! A node started with `--probe` ([`super::NetConfig::probe`]) joins as a member if it is none yet (like a client,
//! docs/06 §7) and registers at up to 8 watchers every `NetTiming::register`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use bridge_core::blob::HashList;
use bridge_core::encoding::{b64, b64_var};
use bridge_core::{CLOCK_SKEW_MS, Id, KeyCard, Puzzle, Role, SignedRequest, Statement};
use bridge_net::{
    Body, Hash, Revoke, RevokeTarget, Seal, SealInfo, Service, Services, WATCH_SERVICES, WatchRules, WitnessedHead,
    verify_head,
};
use bridge_store::{Probe, Registration, Standing, Store, WatchNode, WatchRegistered};
use rand_core::{OsRng, RngCore};
use serde_json::{Map, Value, json};
use tokio::task::JoinSet;

use super::Core;
use crate::{Node, NodeError, NodeResult, lock};

/// Most nodes registered at one watcher (docs/06 §11.5).
pub(crate) const MAX_WATCHED: usize = 1024;
/// Most probes kept per node (the newest).
pub(crate) const MAX_PROBES_PER_NODE: usize = 1024;
/// A registration lives this many registration rounds of the watcher.
pub(crate) const REGISTRATION_ROUNDS: u32 = 24;
/// Most probes started per round (they run at the same time).
const MAX_PROBES_PER_ROUND: usize = 16;
/// Most statements (seals, revocations) signed per round.
const MAX_STATEMENTS_PER_ROUND: usize = 16;
/// Most members looked at per round.
const MAX_MEMBERS_PER_ROUND: usize = 256;
/// Most registered nodes whose success ratio is read from the store per round.
const MAX_RATIOS_PER_ROUND: usize = 64;
/// A probe (both requests) must answer within this time.
const PROBE_LIMIT: Duration = Duration::from_secs(5);
/// How far the head of a probed node may be from the own log ("not far behind", and not wildly ahead).
const MAX_HEAD_LAG: u64 = 64;
/// Most watchers a node registers at.
const MAX_WATCHERS_ASKED: usize = 8;
/// Most gateways a node tries to join at in one round.
const MAX_JOIN_GATEWAYS: usize = 4;
/// A statement in flight is not signed again for this long (unless the log shows it earlier).
const PENDING_MS: i64 = 30_000;
/// Most statements remembered in flight.
const MAX_PENDING: usize = 4096;
/// Most hashes tried for a join puzzle (28 bits need ~2^28).
const MAX_POW_TRIES: u64 = 1 << 30;
/// Lifetime of a revocation statement of the watcher.
const REVOKE_LIFETIME_MS: i64 = 24 * 3600 * 1000;
/// Most new registrations from one address (IPv4, IPv6 /64) per window (review 8).
const MAX_NEW_PER_ADDRESS: u32 = 16;
/// The window of [`MAX_NEW_PER_ADDRESS`].
const NEW_PER_ADDRESS_WINDOW_MS: i64 = 3600 * 1000;
/// Most addresses tracked for [`MAX_NEW_PER_ADDRESS`] (when full, ended windows go first, then new ones are refused).
const MAX_TRACKED_ADDRESSES: usize = 4096;
/// A lapsed registration revokes its node seal only after the watcher ran this many registration rounds (after a
/// long pause of the watcher, the nodes get time to register again first).
const LAPSE_GRACE_ROUNDS: i64 = 2;

/// A node registered here for probes (the memory copy of its row).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Watched {
    pub(crate) card: KeyCard,
    pub(crate) services: Services,
    pub(crate) expires: i64,
    pub(crate) since: Option<i64>,
    pub(crate) fails: u32,
    pub(crate) last_probe: Option<i64>,
    pub(crate) last_ok: bool,
}

impl Watched {
    /// A stored row, checked again (a damaged row is skipped, never half taken).
    fn from_row(row: &WatchNode) -> Option<(Id, Self)> {
        let id = Id::parse(&row.node).ok()?;
        let card = KeyCard::parse(&row.card).ok()?;
        if card.id() != &id || card.role() != Role::Node || card.urls().is_empty() {
            return None;
        }
        let services = services_from(row.services.split(',').filter(|name| !name.is_empty()))?;
        let watched = Self {
            card,
            services,
            expires: row.expires,
            since: row.since,
            fails: row.fails,
            last_probe: row.last_probe,
            last_ok: row.last_ok,
        };
        Some((id, watched))
    }

    fn due(&self, now: i64, rules: &WatchRules) -> bool {
        self.last_probe.is_none_or(|last| now.saturating_sub(last) >= rules.probe_interval_ms())
    }

    /// Counts a probe: a passed one ends the failure series and starts `since` if needed; `fail_limit` failures in
    /// a row end `since` (the node must earn its observation time again).
    fn record(&mut self, ok: bool, at: i64, fail_limit: u64) {
        self.last_probe = Some(at);
        self.last_ok = ok;
        if ok {
            self.fails = 0;
            self.since = self.since.or(Some(at));
        } else {
            self.fails = self.fails.saturating_add(1);
            if u64::from(self.fails) >= fail_limit {
                self.since = None;
            }
        }
    }

    /// Observed long enough, last probe passed, no failures (a new seal; the ratio is checked separately).
    fn ready(&self, now: i64, rules: &WatchRules) -> bool {
        self.last_ok
            && self.fails == 0
            && self.since.is_some_and(|since| now.saturating_sub(since) >= rules.node_observe_ms())
    }

    /// The card in a seal differs from the registered one in what others use (addresses, LAN pin).
    fn card_changed(&self, sealed: Option<&KeyCard>) -> bool {
        sealed.is_none_or(|card| card.urls() != self.card.urls() || card.tls() != self.card.tls())
    }
}

/// A statement in flight (signed, submitted, not in the log yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    /// A seal signed at this time.
    Seal(i64),
    /// A revocation of the seal with this hash, signed at this time.
    Revoke(i64, Hash),
}

/// What the watcher keeps in memory: the registered nodes (also in the store), where the member walk goes on, and
/// the statements in flight.
#[derive(Debug, Default)]
pub(crate) struct WatchMemory {
    pub(crate) nodes: BTreeMap<Id, Watched>,
    cursor: Option<Id>,
    pending: BTreeMap<Id, Pending>,
    /// New registrations per address (`address_key`): window start, count (review 8; bounded).
    new_by_address: BTreeMap<IpAddr, (i64, u32)>,
    /// The first round of this watcher since the node started (for [`LAPSE_GRACE_ROUNDS`]).
    started: Option<i64>,
    /// Storage probes (docs/09 §6): the probe blob placed at each node, with its hash list (memory only - after a
    /// restart a new one is placed, which replaces the old one at the node).
    pub(crate) storage_probes: BTreeMap<Id, HashList>,
}

impl WatchMemory {
    /// The registrations stored for `net`.
    pub(crate) fn load(store: &Store, net: &Id) -> Result<Self, String> {
        let rows = store.watch_nodes(net.as_str(), MAX_WATCHED as u64).map_err(|e| format!("watched nodes: {e}"))?;
        let nodes = rows.iter().filter_map(Watched::from_row).collect();
        Ok(Self { nodes, ..Self::default() })
    }

    /// Counts a new registration from `peer`: at most [`MAX_NEW_PER_ADDRESS`] per address and window (review 8).
    fn admit_new(&mut self, peer: IpAddr, now: i64) -> bool {
        let key = bridge_core::address_key(peer);
        let live = |(start, _): &(i64, u32)| now.saturating_sub(*start) < NEW_PER_ADDRESS_WINDOW_MS;
        if !self.new_by_address.contains_key(&key) && self.new_by_address.len() >= MAX_TRACKED_ADDRESSES {
            self.new_by_address.retain(|_, window| live(window));
            if self.new_by_address.len() >= MAX_TRACKED_ADDRESSES {
                return false;
            }
        }
        let window = self.new_by_address.entry(key).or_insert((now, 0));
        if !live(window) {
            *window = (now, 0);
        }
        if window.1 >= MAX_NEW_PER_ADDRESS {
            return false;
        }
        window.1 = window.1.saturating_add(1);
        true
    }

    /// Forgets statements that are in the log now, or were in flight too long.
    fn settle(&mut self, state: &bridge_net::NetState, me: &Id, now: i64) {
        self.pending.retain(|subject, pending| match *pending {
            Pending::Seal(at) => {
                now.saturating_sub(at) < PENDING_MS
                    && !state.seal_info(subject, 1).is_some_and(|info| info.issuers == [me.clone()] && info.iat >= at)
            }
            Pending::Revoke(at, hash) => {
                now.saturating_sub(at) < PENDING_MS && state.seal_info(subject, 1).is_some_and(|info| info.hash == hash)
            }
        });
    }
}

/// What a watcher reports about itself (owner dashboard, CLI, tests).
#[derive(Debug, Clone, PartialEq)]
pub struct WatchStatus {
    /// The network.
    pub net: Id,
    /// This node.
    pub node: Id,
    /// This node is a watcher now.
    pub watcher: bool,
    /// The rules of the watchers.
    pub rules: WatchRules,
    /// Seals this node issued today (its budget is `rules.seals_per_day`).
    pub used_today: u64,
    /// The level-1 seals this node issued that are in effect (subject, seal).
    pub seals: Vec<(Id, SealInfo)>,
    /// The nodes registered here.
    pub nodes: Vec<WatchedNode>,
}

/// A node registered at a watcher, with its probes in the window (`node_observe_s`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedNode {
    /// Node ID.
    pub node: Id,
    /// Requested services.
    pub services: Services,
    /// The registration ends then (ms).
    pub expires: i64,
    /// Observed since (ms).
    pub since: Option<i64>,
    /// Failed probes in a row.
    pub fails: u32,
    /// Last probe (ms).
    pub last_probe: Option<i64>,
    /// Probes in the window.
    pub probes: u64,
    /// Passed probes in the window.
    pub passed: u64,
}

/// Services from wire names: known, no duplicates, only those a watcher may give (docs/06 §11.2).
fn services_from<'a>(names: impl Iterator<Item = &'a str>) -> Option<Services> {
    let mut list: Vec<Service> = Vec::new();
    for name in names {
        let service = Service::parse(name).filter(|service| WATCH_SERVICES.contains(service))?;
        if list.contains(&service) || list.len() >= bridge_net::statements::MAX_SERVICES {
            return None;
        }
        list.push(service);
    }
    Some(Services::of(&list))
}

/// Services as stored (comma list of wire names).
fn services_text(services: Services) -> String {
    services.iter().map(Service::as_str).collect::<Vec<_>>().join(",")
}

/// The status of a watcher from its store and state (also for `net watch-status` on a data folder).
pub(crate) fn status(
    store: &Store,
    state: &bridge_net::NetState,
    me: &Id,
    memory: &WatchMemory,
    now: i64,
) -> Result<WatchStatus, String> {
    let mut status = status_of_state(state, me, now);
    status.nodes = watched_nodes(store, &status.net, &status.rules, &memory.nodes, now)?;
    Ok(status)
}

/// The part of the status the state tells (without the registered nodes) - cheap, taken under the lock.
fn status_of_state(state: &bridge_net::NetState, me: &Id, now: i64) -> WatchStatus {
    WatchStatus {
        net: state.net().clone(),
        node: me.clone(),
        watcher: state.is_watcher(me, now),
        rules: state.watch_rules(),
        used_today: state.watch_used(me, now),
        seals: state.seals_issued_by(me, 1).into_iter().filter(|(_, info)| info.active(now)).collect(),
        nodes: Vec::new(),
    }
}

/// The registered nodes with their probes in the window (from the store).
fn watched_nodes(
    store: &Store,
    net: &Id,
    rules: &WatchRules,
    nodes: &BTreeMap<Id, Watched>,
    now: i64,
) -> Result<Vec<WatchedNode>, String> {
    let from = now.saturating_sub(rules.node_observe_ms());
    let mut list = Vec::with_capacity(nodes.len());
    for (id, watched) in nodes {
        let (probes, passed) = store.watch_probe_counts(net.as_str(), id.as_str(), from).map_err(|e| e.to_string())?;
        list.push(WatchedNode {
            node: id.clone(),
            services: watched.services,
            expires: watched.expires,
            since: watched.since,
            fails: watched.fails,
            last_probe: watched.last_probe,
            probes,
            passed,
        });
    }
    Ok(list)
}

/// Whether the registered node `subject` may get a seal from this watcher now, apart from its success ratio (docs/06
/// §11.6): a member without an active seal of level ≥ 2; with an own active level-1 seal: a pure renewal (same
/// addresses and pin) when it is due and the node is observed, a seal with a changed card only when the node is ready
/// with it (review 8: new addresses never ride on the window of the old ones - their registration restarted the
/// observation); with a foreign active one only when that one is orphaned; otherwise it must be ready (observed long
/// enough, last probe passed, no failures).
fn wants_node_seal(
    state: &bridge_net::NetState,
    me: &Id,
    subject: &Id,
    watched: &Watched,
    rules: &WatchRules,
    now: i64,
) -> bool {
    if !state.is_member(subject, now) || state.seals(subject, now).iter().any(|(level, _)| *level >= 2) {
        return false;
    }
    match state.seal_info(subject, 1).filter(|info| info.active(now)) {
        Some(info) if info.issuers.as_slice() == [me.clone()] => {
            if watched.card_changed(info.card.as_ref()) {
                watched.ready(now, rules)
            } else {
                watched.since.is_some() && info.exp.saturating_sub(now) < rules.renew_ms()
            }
        }
        Some(info) if !(info.by_watcher && info.issuers.iter().all(|issuer| !state.is_watcher(issuer, now))) => false,
        _ => watched.ready(now, rules),
    }
}

impl Node {
    fn register_ttl_ms(&self) -> i64 {
        let interval = self.network().map_or(Duration::from_secs(600), |network| network.timing.register);
        i64::try_from(interval.as_millis()).unwrap_or(i64::MAX).saturating_mul(i64::from(REGISTRATION_ROUNDS))
    }

    /// The watcher's view of itself (`None` without a network or log).
    pub(crate) async fn watch_status(&self) -> Option<WatchStatus> {
        let network = self.network()?;
        let now = self.now();
        let me = self.inner.identity.id().clone();
        // The state part under the lock (no snapshot is held across the store reads below).
        let mut status = self.with_core(|core| status_of_state(&core.state, &me, now)).ok()?;
        let nodes = lock(&network.watch).nodes.clone();
        let (store, net, rules) = (std::sync::Arc::clone(&self.inner.store), status.net.clone(), status.rules);
        let listed = tokio::task::spawn_blocking(move || watched_nodes(&store, &net, &rules, &nodes, now)).await;
        status.nodes = listed.ok()?.ok()?;
        Some(status)
    }

    // --- registration (`POST /v4/node/watch`) ------------------------------------------------------------------

    /// `POST /v4/node/watch`: a node registers for probes (docs/06 §11.5). Cheap checks first; a new node at most
    /// [`MAX_NEW_PER_ADDRESS`] times per hour from one address (`peer`).
    pub(crate) async fn watch_in(&self, body: &[u8], peer: IpAddr, now: i64) -> NodeResult<Vec<u8>> {
        let network = self.network().ok_or_else(NodeError::not_found)?;
        let me = self.inner.identity.id().clone();
        if !self.with_core(|core| core.state.is_watcher(&me, now))? {
            return Err(NodeError::forbidden("this node is no watcher of the network"));
        }
        let request = SignedRequest::parse(body)?;
        request.check(&me, now)?;
        if request.op() != "watch" {
            return Err(NodeError::bad_format("op: expected watch"));
        }
        let fields = request.body().as_object().ok_or_else(|| NodeError::bad_format("body: not an object"))?;
        if fields.len() != 2 {
            return Err(NodeError::bad_format("body: exactly card and services"));
        }
        let card = KeyCard::from_value(fields.get("card").cloned().unwrap_or(Value::Null))?;
        if card.id() != request.iss() {
            return Err(NodeError::new(401, "BAD_SIGNATURE", "card does not belong to the caller"));
        }
        if card.role() != Role::Node || card.urls().is_empty() {
            return Err(NodeError::forbidden("only nodes with addresses register for probes"));
        }
        if card.iat() > now.saturating_add(CLOCK_SKEW_MS) {
            return Err(NodeError::new(400, "NOT_YET_VALID", "card from the future"));
        }
        let names =
            fields.get("services").and_then(Value::as_array).ok_or_else(|| NodeError::bad_format("services"))?;
        let services = services_from(names.iter().map(|name| name.as_str().unwrap_or("?")))
            .ok_or_else(|| NodeError::forbidden("services: only web (docs/06 §11.2)"))?;
        request.verify(&card)?;
        self.inner.guard.remember_nonce(
            request.iss(),
            request.nonce(),
            request.iat().saturating_add(CLOCK_SKEW_MS),
            now,
        )?;
        self.inner.guard.admit_send(request.iss(), now)?;
        let node = card.id().clone();
        self.with_core(|core| -> NodeResult<()> {
            if core.state.is_banned(&node, now) {
                return Err(NodeError::new(403, "BANNED", "banned"));
            }
            if !core.state.is_member(&node, now) {
                return Err(NodeError::new(403, "NOT_MEMBER", "only members register for probes"));
            }
            Ok(())
        })??;
        // Known: new addresses or a new pin restart the observation (review 8). New: limited per address.
        let restart = {
            let mut memory = lock(&network.watch);
            let known = memory
                .nodes
                .get(&node)
                .map(|watched| card.iat() >= watched.card.iat() && watched.card_changed(Some(&card)));
            match known {
                Some(restart) => restart,
                None if memory.admit_new(peer, now) => false,
                None => return Err(NodeError::quota()),
            }
        };
        let expires = now.saturating_add(self.register_ttl_ms());
        let (net, id, bytes, card_iat, text) =
            (network.net.to_string(), node.to_string(), card.to_bytes()?, card.iat(), services_text(services));
        let stored = self
            .blocking(move |store| {
                let registration =
                    Registration { node: &id, card: &bytes, card_iat, services: &text, expires, at: now, restart };
                store.watch_register(&net, &registration, MAX_WATCHED as u64)
            })
            .await?;
        if stored == WatchRegistered::Full {
            return Err(NodeError::quota());
        }
        let since = {
            let mut memory = lock(&network.watch);
            if let WatchRegistered::Evicted(victim) = &stored {
                if let Ok(victim) = Id::parse(victim) {
                    memory.nodes.remove(&victim);
                    tracing::info!(node = %victim, "watcher: registration evicted (table full, not passing)");
                }
            }
            let entry = memory.nodes.entry(node.clone()).or_insert_with(|| Watched {
                card: card.clone(),
                services,
                expires,
                since: None,
                fails: 0,
                last_probe: None,
                last_ok: false,
            });
            entry.services = services;
            entry.expires = entry.expires.max(expires);
            if card.iat() >= entry.card.iat() {
                if restart {
                    entry.since = None;
                }
                entry.card = card;
            }
            entry.since
        };
        if matches!(stored, WatchRegistered::New | WatchRegistered::Evicted(_)) {
            tracing::info!(%node, "watcher: node registered for probes");
        }
        Ok(json!({"ok": true, "since": since}).to_string().into_bytes())
    }

    // --- the watcher's round -----------------------------------------------------------------------------------

    /// One round of the watcher (docs/06 §11.4, §11.6): probe, decide, submit. Nothing happens unless the log makes
    /// this node a watcher now.
    pub(crate) async fn watch_round(&self) {
        let Some(network) = self.network() else { return };
        let me = self.inner.identity.id().clone();
        let now = self.now();
        let Ok(Some(rules)) = self.with_core(|core| core.state.is_watcher(&me, now).then(|| core.state.watch_rules()))
        else {
            return;
        };
        {
            let mut memory = lock(&network.watch);
            memory.started.get_or_insert(now);
            memory.nodes.retain(|_, watched| watched.expires > now);
        }
        self.probe_round(&rules).await;
        let ratios = self.ratios(&rules).await;
        let now = self.now();
        let planned = self.with_core(|core| {
            let mut memory = lock(&network.watch);
            self.plan(core, &mut memory, &ratios, &rules, now)
        });
        for (subject, statement) in planned.unwrap_or_default() {
            match self.submit_to_operator(&statement).await {
                Ok(appended) => {
                    tracing::info!(%subject, kind = statement.kind(), index = appended.index, "watcher: submitted");
                }
                Err(error) => tracing::debug!(%subject, ?error, "watcher: statement refused (kept pending)"),
            }
        }
    }

    /// Probes the due nodes (at most 16, at the same time) and records the results (memory and store).
    async fn probe_round(&self, rules: &WatchRules) {
        let Some(network) = self.network() else { return };
        let now = self.now();
        // The longest waiting first (never probed, then by the last probe): no node starves behind others.
        let mut due: Vec<(Option<i64>, Id, KeyCard, Services)> = lock(&network.watch)
            .nodes
            .iter()
            .filter(|(_, watched)| watched.due(now, rules))
            .map(|(id, watched)| (watched.last_probe, id.clone(), watched.card.clone(), watched.services))
            .collect();
        due.sort_by_key(|(last, _, _, _)| *last);
        let due: Vec<(Id, KeyCard, Services)> =
            due.into_iter().take(MAX_PROBES_PER_ROUND).map(|(_, id, card, services)| (id, card, services)).collect();
        if due.is_empty() {
            return;
        }
        let mut running = JoinSet::new();
        for (id, card, services) in due {
            let node = self.clone();
            running.spawn(async move {
                let started = Instant::now();
                let ok = node.probe(&id, &card, services).await;
                (id, ok, i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX))
            });
        }
        while let Some(done) = running.join_next().await {
            let Ok((id, ok, ms)) = done else { continue };
            self.record_probe(&id, ok, ms, rules).await;
        }
    }

    async fn record_probe(&self, id: &Id, ok: bool, ms: i64, rules: &WatchRules) {
        let Some(network) = self.network() else { return };
        let at = self.now();
        let standing = {
            let mut memory = lock(&network.watch);
            memory.nodes.get_mut(id).map(|watched| {
                watched.record(ok, at, rules.fail_limit);
                (watched.since, watched.fails)
            })
        };
        let Some((since, fails)) = standing else { return };
        if !ok {
            tracing::debug!(node = %id, fails, "watcher: probe failed");
        }
        let (net, node) = (network.net.to_string(), id.to_string());
        let keep_after = at.saturating_sub(rules.node_observe_ms());
        let probe = Probe { at, ok, ms };
        let stored = self
            .blocking(move |store| {
                store.watch_probe_put(&net, &node, &probe, Standing { since, fails }, keep_after, MAX_PROBES_PER_NODE)
            })
            .await;
        if let Err(error) = stored {
            tracing::warn!(?error, "watcher: could not store a probe");
        }
    }

    /// One probe (docs/06 §11.4): `/v4/info` and the head, both within 5 s.
    async fn probe(&self, id: &Id, card: &KeyCard, services: Services) -> bool {
        // The node chose these addresses itself: only public IPs (review 8), its pinned LAN address first.
        let endpoints = self.guarded_endpoints_of(id, card.tls().copied(), card.urls());
        if endpoints.is_empty() {
            return false;
        }
        let work = async {
            let info = self.peer_get_any(&endpoints, "/v4/info").await.ok()?.ok().ok()?;
            if !self.probe_info_ok(id, &info) {
                return None;
            }
            let head = self.peer_get_any(&endpoints, &self.net_path("head")).await.ok()?.ok().ok()?;
            if !self.probe_head_ok(head) {
                return None;
            }
            if services.has(Service::Storage) && !self.probe_storage(id, &endpoints).await {
                return None;
            }
            if services.has(Service::Compute) && !self.probe_compute(id, &endpoints).await {
                return None;
            }
            Some(())
        };
        matches!(tokio::time::timeout(PROBE_LIMIT, work).await, Ok(Some(())))
    }

    /// Compute probe (docs/09 §6): the built-in probe module with random input, computed here too - the node must give
    /// the same output.
    async fn probe_compute(&self, id: &Id, endpoints: &[super::peer::Endpoint]) -> bool {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let module = crate::compute::COMPUTE_PROBE;
        let expected = tokio::task::spawn_blocking(move || {
            bridge_wasm::run(
                module,
                "run",
                &input,
                bridge_wasm::Limits::default(),
                bridge_wasm::Grants::default(),
                bridge_wasm::NoHost,
            )
            .map(|(outcome, _)| outcome.output)
        })
        .await;
        let Ok(Ok(expected)) = expected else { return false };
        let Ok(body) = self.signed(id, "compute", json!({"module": b64(module), "input": b64(&input)})) else {
            return false;
        };
        let Ok(answer) = self.peer_post_any(endpoints, "/v4/compute/probe", body).await else { return false };
        let Ok(answer) = answer.ok() else { return false };
        answer.get("output") == Some(&json!(b64(&expected)))
    }

    /// Storage probe (docs/09 §6): the first time a probe blob is placed (random data, signed request); every later
    /// time one random part of it is fetched and checked against the kept hash list.
    async fn probe_storage(&self, id: &Id, endpoints: &[super::peer::Endpoint]) -> bool {
        let Some(network) = self.network() else { return false };
        let held = lock(&network.watch).storage_probes.get(id).cloned();
        match held {
            None => {
                let mut data = vec![0u8; crate::storage::MAX_PROBE_BYTES];
                OsRng.fill_bytes(&mut data);
                let Ok(list) = HashList::of(&data) else { return false };
                let Ok(body) = self.signed(id, "storage-probe", json!({"data": b64(&data)})) else { return false };
                let placed =
                    self.peer_post_any(endpoints, "/v4/storage/probe", body).await.ok().and_then(|a| a.ok().ok());
                let ok = placed.is_some_and(|answer| answer.get("blob") == Some(&json!(list.id().to_text())));
                if ok {
                    lock(&network.watch).storage_probes.insert(id.clone(), list);
                }
                ok
            }
            Some(list) => {
                let index = OsRng.next_u32() % list.parts().max(1);
                let body = json!({"blob": list.id().to_text(), "i": index}).to_string().into_bytes();
                let Ok(answer) = self.peer_post_any(endpoints, "/v4/blob/get", body).await else { return false };
                let Ok(answer) = answer.ok() else { return false };
                let data = b64_var(answer.get("data").and_then(Value::as_str).unwrap_or_default(), "data", 65_536);
                data.is_ok_and(|data| list.verify_part(index, &data).is_ok())
            }
        }
    }

    /// `/v4/info`: the card has exactly the ID (role node), the info statement is signed by it, of this network, and
    /// its time is within the clock skew of this node's clock.
    fn probe_info_ok(&self, id: &Id, info: &Map<String, Value>) -> bool {
        let Ok(card) = KeyCard::from_value(info.get("card").cloned().unwrap_or(Value::Null)) else { return false };
        let Ok(statement) = Statement::from_value(info.get("info").cloned().unwrap_or(Value::Null)) else {
            return false;
        };
        card.id() == id
            && card.role() == Role::Node
            && statement.kind() == "info"
            && statement.net() == &self.inner.net
            && statement.times().0.abs_diff(self.now()) <= CLOCK_SKEW_MS.unsigned_abs()
            && statement.verify(&[&card], 1).is_ok()
    }

    /// `/v4/net/{net}/head`: within 64 of the own log size; up to the own size + 1 fully checked (and up to the own
    /// size with the same root as the own log and not more than 64 behind the own witnessed head), beyond it signed
    /// by a log operator of the current rules.
    fn probe_head_ok(&self, head: Map<String, Value>) -> bool {
        let Ok(value) = WitnessedHead::from_value(&Value::Object(head)) else { return false };
        let Ok(size) = value.size() else { return false };
        let now = self.now();
        self.with_core(|core| {
            let own = core.log.size();
            if size > own.saturating_add(MAX_HEAD_LAG) {
                return false;
            }
            if size > own.saturating_add(1) {
                let [operator] = value.head.claimed_signers()[..] else { return false };
                return core.state.log_operators().contains(operator)
                    && core
                        .state
                        .card_of(operator)
                        .is_some_and(|card| verify_head(&value.head, core.log.net(), card).is_ok());
            }
            let Ok(checked) = core.check_witnessed(&value, now) else { return false };
            if size > own {
                return true;
            }
            let witnessed = core.best_witnessed().map_or(0, |witnessed| witnessed.head.size());
            core.log.matches(&checked) && size.saturating_add(MAX_HEAD_LAG) >= witnessed
        })
        .unwrap_or(false)
    }

    /// Whether the success ratio in the window holds, for the registered nodes that may get a seal or a renewal now
    /// (at most 64 per round, read from the store).
    async fn ratios(&self, rules: &WatchRules) -> BTreeMap<Id, bool> {
        let Some(network) = self.network() else { return BTreeMap::new() };
        let now = self.now();
        let candidates: Vec<Id> = self
            .with_core(|core| {
                let memory = lock(&network.watch);
                memory
                    .nodes
                    .iter()
                    .filter(|(id, watched)| {
                        !memory.pending.contains_key(*id)
                            && wants_node_seal(&core.state, &core.me, id, watched, rules, now)
                    })
                    .map(|(id, _)| id.clone())
                    .take(MAX_RATIOS_PER_ROUND)
                    .collect()
            })
            .unwrap_or_default();
        if candidates.is_empty() {
            return BTreeMap::new();
        }
        let (net, from, pct) =
            (network.net.to_string(), now.saturating_sub(rules.node_observe_ms()), rules.success_pct);
        self.blocking(move |store| {
            let mut ratios = BTreeMap::new();
            for id in candidates {
                let (total, passed) = store.watch_probe_counts(&net, id.as_str(), from)?;
                ratios.insert(id, total > 0 && passed.saturating_mul(100) >= pct.saturating_mul(total));
            }
            Ok(ratios)
        })
        .await
        .unwrap_or_default()
    }

    /// What this round signs (docs/06 §11.6): revocations first (descent), then node seals, then member seals - at
    /// most 16, never more seals than the budget of the day leaves, nothing for a subject with a statement in flight.
    fn plan(
        &self,
        core: &Core,
        memory: &mut WatchMemory,
        ratios: &BTreeMap<Id, bool>,
        rules: &WatchRules,
        now: i64,
    ) -> Vec<(Id, Statement)> {
        let state = &core.state;
        let me = &core.me;
        memory.settle(state, me, now);
        let mut out: Vec<(Id, Statement)> = Vec::new();
        let mut seals_left = rules.seals_per_day.saturating_sub(state.watch_used(me, now));
        let full = |out: &Vec<(Id, Statement)>, memory: &WatchMemory| {
            out.len() >= MAX_STATEMENTS_PER_ROUND || memory.pending.len() >= MAX_PENDING
        };
        let interval = self.network().map_or(Duration::from_secs(600), |network| network.timing.register);
        let grace = i64::try_from(interval.as_millis()).unwrap_or(i64::MAX).saturating_mul(LAPSE_GRACE_ROUNDS);
        let settled = memory.started.is_some_and(|started| now.saturating_sub(started) >= grace);

        // Descent: own seals of subjects that failed, are banned or are no members any more - and node seals whose
        // registration lapsed (review 8: a node must not escape its probes by no longer registering).
        for (subject, info) in state.seals_issued_by(me, 1) {
            if full(&out, memory) {
                return out;
            }
            if memory.pending.contains_key(&subject) || !info.active(now) {
                continue;
            }
            let registered = memory.nodes.get(&subject);
            let failed = registered.is_some_and(|watched| u64::from(watched.fails) >= rules.fail_limit);
            let lapsed = settled && info.card.is_some() && registered.is_none();
            let reason = if state.is_banned(&subject, now) {
                "gesperrt"
            } else if !state.is_member(&subject, now) {
                "kein Mitglied mehr"
            } else if failed {
                "Proben fehlgeschlagen"
            } else if lapsed {
                "Anmeldung abgelaufen"
            } else {
                continue;
            };
            let revoke = Revoke { target: RevokeTarget::Statement(info.hash), reason: reason.to_owned() };
            if let Ok(statement) =
                revoke.sign(&self.inner.net, now, now.saturating_add(REVOKE_LIFETIME_MS), &self.inner.identity)
            {
                memory.pending.insert(subject.clone(), Pending::Revoke(now, info.hash));
                out.push((subject, statement));
            }
        }

        // Nodes: new seals and renewals for those whose ratio holds.
        let exp = now.saturating_add(rules.seal_ms());
        let nodes: Vec<(Id, Watched)> = memory
            .nodes
            .iter()
            .filter(|(id, _)| ratios.get(*id) == Some(&true))
            .map(|(id, w)| (id.clone(), w.clone()))
            .collect();
        for (subject, watched) in nodes {
            if full(&out, memory) || seals_left == 0 {
                return out;
            }
            if memory.pending.contains_key(&subject) || !wants_node_seal(state, me, &subject, &watched, rules, now) {
                continue;
            }
            let seal =
                Seal { subject: subject.clone(), level: 1, services: watched.services, card: Some(watched.card) };
            if self.sign_seal(state, &seal, now, exp, memory, &mut out) {
                seals_left = seals_left.saturating_sub(1);
            }
        }

        // Members, in turns: member seals (no card, no services) and their renewals.
        let members = state.members_after(memory.cursor.as_ref(), MAX_MEMBERS_PER_ROUND);
        memory.cursor = if members.len() < MAX_MEMBERS_PER_ROUND { None } else { members.last().cloned() };
        for subject in members {
            if full(&out, memory) || seals_left == 0 {
                return out;
            }
            if &subject == me
                || memory.pending.contains_key(&subject)
                || memory.nodes.contains_key(&subject)
                || state.seals(&subject, now).iter().any(|(level, _)| *level >= 2)
            {
                continue;
            }
            let fresh = state.seal_info(&subject, 1).is_some_and(|info| {
                info.active(now) && info.issuers == [me.clone()] && info.exp.saturating_sub(now) >= rules.renew_ms()
            });
            if fresh {
                continue;
            }
            let seal = Seal { subject: subject.clone(), level: 1, services: Services::NONE, card: None };
            if self.sign_seal(state, &seal, now, exp, memory, &mut out) {
                seals_left = seals_left.saturating_sub(1);
            }
        }
        out
    }

    /// Signs `seal` if the state would take it now (the same rule as on replay); remembers it as in flight.
    fn sign_seal(
        &self,
        state: &bridge_net::NetState,
        seal: &Seal,
        now: i64,
        exp: i64,
        memory: &mut WatchMemory,
        out: &mut Vec<(Id, Statement)>,
    ) -> bool {
        if state.check_watch_seal(&self.inner.identity.id().clone(), seal, now, exp, now).is_err() {
            return false;
        }
        let Ok(statement) = seal.sign(&self.inner.net, now, exp, &self.inner.identity) else { return false };
        memory.pending.insert(seal.subject.clone(), Pending::Seal(now));
        out.push((seal.subject.clone(), statement));
        true
    }

    // --- the probed node's side ----------------------------------------------------------------------------------

    /// One round of a node that wants probes (`--probe`): join as a member if it is none, else register at up to 8
    /// watchers from the log (docs/06 §11.5).
    pub(crate) async fn register_round(&self) {
        let Some(network) = self.network() else { return };
        let Some(services) = network.probe else { return };
        let me = self.inner.identity.id().clone();
        let now = self.now();
        let Ok((member, watchers)) = self.with_core(|core| (core.state.is_member(&me, now), core.state.watchers(now)))
        else {
            return;
        };
        if !member {
            self.join_for_probes().await;
            return;
        }
        let names: Vec<&str> = services.iter().map(Service::as_str).collect();
        let body = json!({"card": self.inner.card.to_value(), "services": names});
        for (watcher, card) in watchers.into_iter().filter(|(id, _)| id != &me).take(MAX_WATCHERS_ASKED) {
            let Some(card) = card else { continue };
            let endpoints = self.endpoints_of(&watcher, card.tls().copied(), card.urls());
            let Ok(request) = self.signed(&watcher, "watch", body.clone()) else { continue };
            match self.peer_post_any(&endpoints, "/v4/node/watch", request).await {
                Ok(answer) if answer.status == 200 => tracing::debug!(%watcher, "registered for probes"),
                Ok(answer) => {
                    tracing::info!(%watcher, status = answer.status, code = answer.code(), "registration refused")
                }
                Err(error) => tracing::debug!(%watcher, %error, "watcher not reached"),
            }
        }
    }

    /// Joins the network as a member at one of the gateways from the log (like a client, docs/06 §7), with the
    /// invite code of the join link if there was one. The membership arrives with the log.
    async fn join_for_probes(&self) {
        let Some(network) = self.network() else { return };
        let me = self.inner.identity.id().clone();
        let now = self.now();
        let gateways: Vec<(Id, KeyCard)> = self
            .with_core(|core| core.state.gateways(now))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(id, card)| card.map(|card| (id, card)))
            .filter(|(id, _)| id != &me)
            .take(MAX_JOIN_GATEWAYS)
            .collect();
        for (gateway, card) in gateways {
            let endpoints = self.endpoints_of(&gateway, card.tls().copied(), card.urls());
            match self.join_at(&gateway, &card, &endpoints, network.invite.as_deref()).await {
                Ok(()) => {
                    tracing::info!(%gateway, "joined as a member (for probes)");
                    network.wake_sync.notify_one();
                    return;
                }
                Err(error) => tracing::debug!(%gateway, %error, "join for probes"),
            }
        }
    }

    async fn join_at(
        &self,
        gateway: &Id,
        card: &KeyCard,
        endpoints: &[super::Endpoint],
        code: Option<&str>,
    ) -> Result<(), String> {
        let challenge =
            self.peer_post_any(endpoints, "/v4/auth/challenge", br#"{"for":"join"}"#.to_vec()).await?.ok()?;
        let mut body = json!({"challenge": challenge.get("challenge").cloned().unwrap_or(Value::Null),
                              "card": self.inner.card.to_value()});
        if let Some(code) = code {
            body["code"] = json!(code);
        }
        if let Some(puzzle) = challenge.get("pow").filter(|value| !value.is_null()) {
            let puzzle = Puzzle::from_value(puzzle.clone()).map_err(|e| e.to_string())?;
            puzzle.verify(card).map_err(|e| e.to_string())?;
            let solution = tokio::task::spawn_blocking(move || puzzle.solve(MAX_POW_TRIES))
                .await
                .map_err(|e| e.to_string())?
                .ok_or("proof of work too hard")?;
            body["pow"] = json!(bridge_core::encoding::b64(&solution));
        }
        let request = self.signed(gateway, "join", body)?;
        self.peer_post_any(endpoints, "/v4/net/join", request).await?.ok().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watched(card: KeyCard) -> Watched {
        Watched {
            card,
            services: Services::of(&[Service::Web]),
            expires: 100,
            since: None,
            fails: 0,
            last_probe: None,
            last_ok: false,
        }
    }

    #[test]
    fn probes_count_since_and_failure_series() -> Result<(), String> {
        let node = bridge_core::Identity::from_secret_bytes(&[7; 32], &[8; 32]);
        let card =
            node.key_card_with(Role::Node, None, &["https://n.example".into()], None, 0).map_err(|e| e.to_string())?;
        let rules = WatchRules { node_observe_s: 10, fail_limit: 2, ..WatchRules::default() };
        let mut node = watched(card.clone());
        assert!(node.due(0, &rules));
        node.record(true, 1_000, rules.fail_limit);
        assert_eq!((node.since, node.fails), (Some(1_000), 0));
        assert!(!node.due(1_000 + 1, &rules), "probe interval");
        assert!(!node.ready(5_000, &rules), "observed too short");
        assert!(node.ready(11_000, &rules));
        node.record(false, 12_000, rules.fail_limit);
        assert_eq!((node.since, node.fails), (Some(1_000), 1), "one failure keeps since");
        assert!(!node.ready(12_000, &rules), "not after a failure");
        node.record(false, 13_000, rules.fail_limit);
        assert_eq!((node.since, node.fails), (None, 2), "a series ends since");
        node.record(true, 14_000, rules.fail_limit);
        assert_eq!((node.since, node.fails), (Some(14_000), 0), "starts again");
        // The sealed card: other addresses or another pin mean re-sealing.
        assert!(!node.card_changed(Some(&card)));
        assert!(node.card_changed(None));
        let moved = node_card_with(&[7; 32], "https://elsewhere.example").map_err(|e| e.to_string())?;
        assert!(node.card_changed(Some(&moved)));
        Ok(())
    }

    fn node_card_with(seed: &[u8; 32], url: &str) -> bridge_core::CoreResult<KeyCard> {
        bridge_core::Identity::from_secret_bytes(seed, &[8; 32]).key_card_with(Role::Node, None, &[url.into()], None, 5)
    }

    /// Review 8, finding 3: new registrations are limited per address (IPv6 per /64), per window; the table of
    /// addresses is bounded.
    #[test]
    fn new_registrations_are_limited_per_address() {
        let mut memory = WatchMemory::default();
        let one: IpAddr = [203, 0, 113, 7].into();
        for _ in 0..MAX_NEW_PER_ADDRESS {
            assert!(memory.admit_new(one, 1_000));
        }
        assert!(!memory.admit_new(one, 2_000), "17th within the hour");
        assert!(memory.admit_new([203, 0, 113, 8].into(), 2_000), "another address");
        let six: IpAddr = "2001:db8:1:2::1".parse().unwrap_or(one);
        let same_64: IpAddr = "2001:db8:1:2::ffff".parse().unwrap_or(one);
        for _ in 0..MAX_NEW_PER_ADDRESS {
            assert!(memory.admit_new(six, 1_000));
        }
        assert!(!memory.admit_new(same_64, 1_000), "the same /64");
        assert!(memory.admit_new(one, 1_000 + NEW_PER_ADDRESS_WINDOW_MS), "a new window");
        // Bounded: when full of live windows, new addresses are refused (fail closed); ended windows make room.
        let mut full = WatchMemory::default();
        for index in 0..MAX_TRACKED_ADDRESSES {
            let ip: IpAddr = std::net::Ipv4Addr::from(u32::try_from(index).unwrap_or(0) + 1).into();
            assert!(full.admit_new(ip, 0));
        }
        assert!(!full.admit_new(one, 1));
        assert!(full.admit_new(one, NEW_PER_ADDRESS_WINDOW_MS));
        assert_eq!(full.new_by_address.len(), 1);
    }

    /// Review 8, finding 4: a seal with new addresses (or a new LAN pin) needs the full observation window - only a
    /// renewal with the same card goes on the running observation.
    #[test]
    fn new_addresses_need_the_full_window() -> Result<(), String> {
        use bridge_net::{Body, JoinMode, Manifest, Member, NetState};
        let e = |error: bridge_net::NetError| error.to_string();
        let t0: i64 = 1_794_200_000_000;
        let master = bridge_core::Identity::from_secret_bytes(&[1; 32], &[2; 32]);
        let net = master.id().clone();
        let watcher = bridge_core::Identity::from_secret_bytes(&[3; 32], &[4; 32]);
        let subject = bridge_core::Identity::from_secret_bytes(&[5; 32], &[6; 32]);
        let card_of = |identity: &bridge_core::Identity, url: &str| {
            identity.key_card_with(Role::Node, None, &[url.to_owned()], None, t0).map_err(|e| e.to_string())
        };
        let master_card = master.key_card(Role::Net, None, t0).map_err(|e| e.to_string())?;
        let manifest =
            Manifest::template(JoinMode::Open, "Netz", master_card, watcher.id(), "https://w.example").map_err(e)?;
        let mut entries = vec![manifest.sign(&net, t0, t0 + 400 * 86_400_000, &master).map_err(e)?];
        let watch = Seal {
            subject: watcher.id().clone(),
            level: 2,
            services: Services::of(&[Service::Watch]),
            card: Some(card_of(&watcher, "https://w.example")?),
        };
        entries.push(watch.sign(&net, t0, t0 + 30 * 86_400_000, &master).map_err(e)?);
        let member = Member { member: subject.id().clone(), invite: None };
        entries.push(member.sign(&net, t0, t0 + 30 * 86_400_000, &master).map_err(e)?);
        let old_card = card_of(&subject, "https://old.example")?;
        let rules = WatchRules { node_observe_s: 3600, seal_s: 2 * 86_400, renew_s: 86_400, ..WatchRules::default() };
        let seal =
            Seal { subject: subject.id().clone(), level: 1, services: Services::NONE, card: Some(old_card.clone()) };
        entries.push(seal.sign(&net, t0 + 60_000, t0 + 60_000 + rules.seal_ms(), &watcher).map_err(e)?);
        let bytes: Vec<Vec<u8>> = entries.iter().map(|statement| statement.canonical_bytes().to_vec()).collect();
        let state = NetState::replay(&net, &bytes).map_err(e)?;
        let (me, id) = (watcher.id().clone(), subject.id().clone());
        assert!(state.seal_info(&id, 1).is_some_and(|info| info.issuers == [me.clone()]), "the watcher's own seal");

        // Renewal due (less than renew_s left), observed for only a minute.
        let now = t0 + 60_000 + rules.seal_ms() - rules.renew_ms() + 1;
        let observed = |card: KeyCard, since: i64| Watched {
            card,
            services: Services::NONE,
            expires: now + 1_000,
            since: Some(since),
            fails: 0,
            last_probe: Some(now - 1),
            last_ok: true,
        };
        let fresh = now - 60_000;
        assert!(wants_node_seal(&state, &me, &id, &observed(old_card.clone(), fresh), &rules, now), "pure renewal");
        let moved = card_of(&subject, "https://new.example")?;
        assert!(
            !wants_node_seal(&state, &me, &id, &observed(moved.clone(), fresh), &rules, now),
            "new addresses do not ride on the old observation"
        );
        let long = now - rules.node_observe_ms();
        assert!(wants_node_seal(&state, &me, &id, &observed(moved, long), &rules, now), "after the full window");
        Ok(())
    }

    #[test]
    fn only_probed_services_and_no_duplicates() {
        assert_eq!(services_from(["web"].into_iter()), Some(Services::of(&[Service::Web])));
        assert_eq!(
            services_from(["storage", "compute"].into_iter()),
            Some(Services::of(&[Service::Storage, Service::Compute])),
            "probed since phase 5 (docs/09 §6)"
        );
        assert_eq!(services_from([].into_iter()), Some(Services::NONE));
        for bad in [vec!["web", "web"], vec!["gateway"], vec!["watch"], vec!["names"], vec!["?"]] {
            assert_eq!(services_from(bad.clone().into_iter()), None, "{bad:?}");
        }
        assert_eq!(services_text(Services::of(&[Service::Web])), "web");
        assert_eq!(services_text(Services::NONE), "");
    }

    #[test]
    fn damaged_rows_are_skipped() -> Result<(), String> {
        let node = bridge_core::Identity::from_secret_bytes(&[9; 32], &[8; 32]);
        let card =
            node.key_card_with(Role::Node, None, &["https://n.example".into()], None, 0).map_err(|e| e.to_string())?;
        let row = WatchNode {
            node: node.id().to_string(),
            card: card.to_bytes().map_err(|e| e.to_string())?,
            card_iat: 0,
            services: "web".into(),
            expires: 10,
            since: Some(1),
            fails: 0,
            last_probe: Some(1),
            last_ok: true,
        };
        assert!(Watched::from_row(&row).is_some());
        for broken in [
            WatchNode { node: "kaputt".into(), ..row.clone() },
            WatchNode { card: b"{}".to_vec(), ..row.clone() },
            WatchNode { services: "gateway".into(), ..row.clone() },
            WatchNode { node: bridge_core::Id::of_sign_key(&[1; 32]).to_string(), ..row.clone() },
        ] {
            assert!(Watched::from_row(&broken).is_none());
        }
        Ok(())
    }
}
