//! Following the log (docs/06 §5): fetch the newest witnessed head, check it, fetch the missing entries, check that
//! they give exactly the head's root, then store, append and replay. Nothing is applied before it is in a witnessed
//! head (Z9). A node without a log yet bootstraps from its bootstrap addresses: entry 0 must be the genesis
//! manifest signed by the network key - the trust anchor is the network ID itself.
//!
//! Which log rules a head is checked against depends on its size: those after its first n − 1 entries. For a head
//! beyond the own log (docs/06 §5 "Folgende Knoten"):
//! 1. before anything is fetched, the head must pass the pre-check under the current rules (signature of a known
//!    log operator, enough cosignatures may count: `WitnessedHead::precheck`) - or the source's current manifest
//!    must show a genuine manifest change ahead (`NetState::may_fetch`; one small request);
//! 2. the entries are fetched (bounded) and must give the head's root;
//! 3. `NetState::rules_ahead` decides on a snapshot of the state, outside the lock: the current rules, a replay
//!    on a copy (only behind a validly signed change, or for a possible rescue head), or refuse;
//! 4. a copy is made and replayed in a blocking thread - never under the lock of the network core - noting every
//!    change of the log rules on the way;
//! 5. each of those changes must be endorsed by its transition head, witnessed under the rules from before it
//!    (`POST …/head/at` at the source's node, then at up to three other nodes - distinct nodes, not endpoints;
//!    `Transitions::endorsement`: newest first, one at a time, stop at the first change that is not endorsed).
//!    Only then is the head taken - a fabricated suffix that installs new log operators and witnesses needs more
//!    than the 24 words.
//!
//! The first contact checks the same transition heads (the last 64 changes; its anchor remains the network ID).
//!
//! Bounded work against bad sources (review 6, finding 4): a head refused after its entries were fetched (or
//! before) is not fetched again from the next source for a few rounds, a transition head no source had is not asked
//! for again for as long, and the source that showed the refused head is skipped for as long ([`Failures`]). A
//! node keeps verified transition heads; a stored one that does not verify after a restart is fetched again
//! (one per round, growing pauses), and rows that could not be stored are tried again every round.

use std::collections::BTreeMap;
use std::sync::Arc;

use bridge_core::Statement;
use bridge_net::{Ahead, Body, Hash, Head, HeadBody, NetState, RulesAhead, Transitions, Tree, WitnessedHead};
use serde_json::{Value, json};

use super::peer::{Endpoint, Group};
use super::{Core, MAX_BOOTSTRAP, MAX_TRANSITIONS, NetRuntime, Noted};
use crate::{Node, lock};

/// Most sources (nodes, bootstrap addresses) asked in one round.
const MAX_SOURCES: usize = 16;
/// Most endpoints tried in one round, over all sources.
const MAX_SOURCE_ENDPOINTS: usize = 32;
/// Most endpoints of one source tried.
const MAX_ENDPOINTS_PER_SOURCE: usize = 8;
/// Most sources (distinct nodes) asked for one transition head: the sync source's node first, then three others.
const MAX_TRANSITION_SOURCES: usize = 4;
/// How long a failure is remembered, in sync intervals.
const FAILURE_ROUNDS: u32 = 4;
/// Most remembered failures of each kind.
const MAX_FAILURES: usize = 64;
/// Longest pause before a damaged transition head is fetched again, in sync intervals.
const MAX_REPAIR_ROUNDS: i64 = 64;

/// What failed lately when following (review 6, finding 4), each until a time (bounded; when a table is full the
/// entry that ends first makes room).
#[derive(Debug, Default)]
pub(crate) struct Failures {
    /// Heads (size, root) refused - the next source showing the same head is not followed until then.
    heads: BTreeMap<(u64, Hash), i64>,
    /// Transition heads (size, root of the entries up to it) none of the asked sources had.
    gaps: BTreeMap<(u64, Hash), i64>,
    /// Sources (node ID or address) that showed a refused head or entries that did not fit it: skipped until then.
    sources: BTreeMap<String, i64>,
}

impl Failures {
    fn prune(&mut self, now: i64) {
        self.heads.retain(|_, until| *until > now);
        self.gaps.retain(|_, until| *until > now);
        self.sources.retain(|_, until| *until > now);
    }

    fn note<K: Ord + Clone>(map: &mut BTreeMap<K, i64>, key: K, until: i64) {
        if !map.contains_key(&key) && map.len() >= MAX_FAILURES {
            if let Some(first) = map.iter().min_by_key(|(_, until)| **until).map(|(key, _)| key.clone()) {
                map.remove(&first);
            }
        }
        map.insert(key, until);
    }

    fn holds<K: Ord>(map: &BTreeMap<K, i64>, key: &K, now: i64) -> bool {
        map.get(key).is_some_and(|until| *until > now)
    }
}

/// What a head means for this node.
enum Step {
    /// Nothing new (maybe a fresher head of the same log).
    UpToDate,
    /// The head contradicts a head this node keeps.
    Evidence(Box<bridge_net::Evidence>),
    /// New entries `[start, size)` are needed; `tree` is a snapshot of the own tree to check them against and
    /// `state` a snapshot of the state (shared - copied only if a replay is needed, outside the lock).
    Fetch { size: u64, root: bridge_net::Hash, start: u64, tree: Tree, state: Arc<NetState> },
}

/// A head checked against the rules for its size, the entries up to it, and the changes of the log rules they
/// passed (their transition heads are checked next).
type Checked = (Head, Vec<Vec<u8>>, Transitions);

impl Node {
    /// One sync round: bootstrap, or follow the newest witnessed head (the active operator itself has nothing to
    /// follow). Before that: transition-head rows not stored yet, and one damaged transition head due to be fetched
    /// again.
    pub(crate) async fn sync_round(&self) {
        let Some(network) = self.network() else { return };
        self.store_unsaved().await;
        lock(&network.failures).prune(self.now());
        let has_core = lock(&network.core).is_some();
        if !has_core {
            // The trust anchor is the network ID (entry 0 is checked against it), so any source will do: the join
            // link's gateway in the LAN first (pinned), then the bootstrap addresses.
            let sources = self.bootstrap_sources(network);
            self.follow_any(&sources, true).await;
            return;
        }
        self.repair_transition().await;
        if self.with_core(|core| core.is_active_operator()).unwrap_or(true) {
            return;
        }
        let sources = self.sync_sources();
        self.follow_any(&sources, false).await;
    }

    /// Tries the sources one endpoint after the other (bounded) until one round of following - or the first contact
    /// (`bootstrap`) - succeeds. A source that showed a refused head lately is skipped, and its other endpoints are
    /// not tried after it showed one.
    async fn follow_any(&self, sources: &[Group], bootstrap: bool) {
        let mut budget = MAX_SOURCE_ENDPOINTS;
        for (position, group) in sources.iter().enumerate() {
            if self.cooling(&group.key) {
                continue;
            }
            for endpoint in group.endpoints.iter().take(MAX_ENDPOINTS_PER_SOURCE) {
                let Some(left) = budget.checked_sub(1) else { return };
                budget = left;
                let result = if bootstrap {
                    self.bootstrap_from(endpoint, position, sources).await
                } else {
                    self.sync_from(endpoint, position, sources).await
                };
                match result {
                    Ok(()) if bootstrap => {
                        tracing::info!(source = %endpoint, "network log loaded");
                        return;
                    }
                    Ok(()) => return,
                    Err(error) => tracing::debug!(source = %endpoint, %error, "sync"),
                }
                if self.cooling(&group.key) {
                    break;
                }
            }
        }
    }

    /// Where the first contact loads the log from: the join link's gateway in the LAN (pinned), then the bootstrap
    /// addresses.
    fn bootstrap_sources(&self, network: &NetRuntime) -> Vec<Group> {
        let mut sources: Vec<Group> = Vec::new();
        if let Some(pin) = &network.lan_bootstrap {
            let endpoints = self.endpoints_of(&pin.node, Some(pin.tls), &[]);
            if !endpoints.is_empty() {
                sources.push(Group { key: pin.node.to_string(), endpoints });
            }
        }
        sources.extend(network.bootstrap.iter().take(MAX_BOOTSTRAP).map(|url| Group::public(url)));
        sources
    }

    /// Where to follow from, one group per node: the active operator first, then the other operators and gateways,
    /// then bootstrap - for each node its LAN endpoints before its public addresses (at most 16 sources).
    pub(crate) fn sync_sources(&self) -> Vec<Group> {
        let mut groups: Vec<Group> = Vec::new();
        if let Ok(Some(operator)) = self.with_core(|core| core.active_operator().cloned()) {
            groups.push(Group { key: operator.to_string(), endpoints: self.reach(&operator) });
        }
        groups.extend(self.peer_groups());
        self.distinct_groups(groups, MAX_SOURCES)
    }

    /// How long a failure is remembered.
    fn failure_window(&self) -> i64 {
        let sync = self.network().map_or(0, |network| i64::try_from(network.timing.sync.as_millis()).unwrap_or(0));
        sync.saturating_mul(i64::from(FAILURE_ROUNDS))
    }

    /// The source `key` showed a refused head lately.
    fn cooling(&self, key: &str) -> bool {
        let Some(network) = self.network() else { return false };
        Failures::holds(&lock(&network.failures).sources, &key.to_owned(), self.now())
    }

    /// Remembers a refused head (and, with `source`, the source that showed it).
    fn note_refused(&self, size: u64, root: Hash, source: Option<&str>) {
        let Some(network) = self.network() else { return };
        let until = self.now().saturating_add(self.failure_window());
        let mut failures = lock(&network.failures);
        Failures::note(&mut failures.heads, (size, root), until);
        if let Some(source) = source {
            Failures::note(&mut failures.sources, source.to_owned(), until);
        }
    }

    /// Remembers a source that handed out entries that did not fit its head.
    fn note_bad_source(&self, source: &str) {
        let Some(network) = self.network() else { return };
        let until = self.now().saturating_add(self.failure_window());
        Failures::note(&mut lock(&network.failures).sources, source.to_owned(), until);
    }

    /// The head (size, root) was refused lately: not followed again from another source yet.
    fn refused_lately(&self, size: u64, root: &Hash) -> bool {
        let Some(network) = self.network() else { return false };
        Failures::holds(&lock(&network.failures).heads, &(size, *root), self.now())
    }

    /// No asked source had the transition head of `size` over the entries with root `root` lately.
    fn gap_lately(&self, size: u64, root: &Hash) -> bool {
        let Some(network) = self.network() else { return false };
        Failures::holds(&lock(&network.failures).gaps, &(size, *root), self.now())
    }

    fn note_gap(&self, size: u64, root: Hash) {
        let Some(network) = self.network() else { return };
        let until = self.now().saturating_add(self.failure_window());
        Failures::note(&mut lock(&network.failures).gaps, (size, root), until);
    }

    async fn fetch_witnessed(&self, source: &Endpoint) -> Result<WitnessedHead, String> {
        let answer = self.peer_get(source, &self.net_path("head")).await?.ok()?;
        WitnessedHead::from_value(&Value::Object(answer)).map_err(|e| e.to_string())
    }

    /// The transition head of `size` that a node keeps (`POST /v4/net/{net}/head/at` at the first of its
    /// `endpoints` that answers at all; form only).
    async fn fetch_transition(&self, endpoints: &[Endpoint], size: u64) -> Result<WitnessedHead, String> {
        let body = json!({"size": size}).to_string().into_bytes();
        let answer = self.peer_post_any(endpoints, &self.net_path("head/at"), body).await?.ok()?;
        WitnessedHead::from_value(&Value::Object(answer)).map_err(|e| e.to_string())
    }

    /// The source's current manifest and its log index (`GET /v4/net/{net}/manifest`, form only).
    async fn fetch_manifest(&self, source: &Endpoint) -> Result<(Statement, u64), String> {
        let answer = self.peer_get(source, &self.net_path("manifest")).await?.ok()?;
        let statement = Statement::from_value(answer.get("manifest").cloned().unwrap_or(Value::Null))
            .map_err(|e| format!("source manifest: {e}"))?;
        let index = answer.get("index").and_then(Value::as_u64).ok_or("source manifest: no index")?;
        Ok((statement, index))
    }

    /// First contact: the whole log up to the newest witnessed head of `source` (replayed before anything is
    /// stored, so the head is checked against the rules for its size), and the transition head of every change of
    /// the log rules in it (from the node of `source` - `sources[position]` -, then up to three other sources).
    async fn bootstrap_from(&self, source: &Endpoint, position: usize, sources: &[Group]) -> Result<(), String> {
        let network = self.network().ok_or("no network")?;
        let key = sources.get(position).map_or("", |group| group.key.as_str());
        let witnessed = self.fetch_witnessed(source).await?;
        let claimed = HeadBody::from_statement(&witnessed.head).map_err(|e| e.to_string())?;
        if self.refused_lately(claimed.size, &claimed.root) {
            return Err("this head was refused lately: not fetched again yet".into());
        }
        let entries = self.fetch_entries(source, 0, claimed.size).await?;
        let me = self.inner.identity.id().clone();
        let (mut core, transitions) =
            Core::restore_tracked(me, &network.net, &entries).map_err(|e| format!("log: {e}"))?;
        let now = self.now();
        if core.log.size() != claimed.size || core.log.root() != claimed.root {
            self.note_bad_source(key);
            return Err("entries do not match the witnessed head".into());
        }
        let checked = core.check_witnessed(&witnessed, now).map_err(|e| e.to_string());
        let head = match checked {
            Ok(head) => head,
            Err(error) => {
                self.note_refused(claimed.size, claimed.root, Some(key));
                return Err(error);
            }
        };
        let tree = core.log.tree().clone();
        let order = transition_sources(source, position, sources);
        let endorsed = match self.endorse(&order, &transitions, &tree, &head, true).await {
            Ok(endorsed) => endorsed,
            Err(error) => {
                self.note_refused(claimed.size, claimed.root, Some(key));
                return Err(error);
            }
        };
        let mut noted = core.note_witnessed(head, witnessed);
        for (size, value) in &endorsed {
            noted.transitions.extend(core.note_transition(*size, value));
        }
        let _serial = network.append.lock().await;
        if lock(&network.core).is_some() {
            return Ok(()); // loaded in the meantime
        }
        let (net, all) = (network.net.to_string(), entries);
        if !self.blocking(move |store| store.net_log_append(&net, 0, &all)).await.map_err(|e| e.message)? {
            return Err("store already has entries".into());
        }
        let size = core.log.size();
        *lock(&network.core) = Some(core);
        network.applied.send_replace(size);
        lock(&network.fetched_transitions).clear();
        self.store_noted(noted).await;
        Ok(())
    }

    /// Follows `source` (an endpoint of the node `sources[position]`): checks its newest witnessed head and takes
    /// the entries up to it (transition heads also from up to three other sources).
    async fn sync_from(&self, source: &Endpoint, position: usize, sources: &[Group]) -> Result<(), String> {
        let network = self.network().ok_or("no network")?;
        let key = sources.get(position).map_or("", |group| group.key.as_str());
        let witnessed = self.fetch_witnessed(source).await?;
        let claimed = HeadBody::from_statement(&witnessed.head).map_err(|e| e.to_string())?;
        if self.refused_lately(claimed.size, &claimed.root) {
            return Err("this head was refused lately: not fetched again yet".into());
        }
        let now = self.now();
        let net = network.net.clone();
        // Under the lock only cheap work: evidence, an up-to-date head, or O(1) snapshots for a fetch.
        let (step, noted) = self
            .with_core(|core| -> Result<(Step, Noted), String> {
                let size = core.log.size();
                let operator = match witnessed.head.claimed_signers().as_slice() {
                    [operator] => (*operator).clone(),
                    _ => return Err("head: exactly one signer".into()),
                };
                if core.evidence.contains_key(&operator) {
                    return Err("head of a deposed log operator".into());
                }
                if let Some(evidence) = core.find_evidence(&operator, &witnessed.head, None) {
                    return Ok((Step::Evidence(Box::new(evidence)), Noted::default()));
                }
                if claimed.size > size {
                    let fetch = Step::Fetch {
                        size: claimed.size,
                        root: claimed.root,
                        start: size,
                        tree: core.log.tree().clone(),
                        state: Arc::clone(&core.state),
                    };
                    return Ok((fetch, Noted::default()));
                }
                let head = core.check_witnessed(&witnessed, now).map_err(|e| e.to_string())?;
                if !core.log.matches(&head) {
                    return Err("witnessed head does not match the own log".into());
                }
                let noted = core.note_witnessed(head, witnessed.clone());
                Ok((Step::UpToDate, noted))
            })
            .map_err(|e| e.message)??;
        let (size, root, start, mut tree, state) = match step {
            Step::UpToDate => {
                self.store_noted(noted).await;
                return Ok(());
            }
            Step::Evidence(evidence) => {
                self.record_evidence(*evidence, true).await.map_err(|e| e.message)?;
                return Err("split view".into());
            }
            Step::Fetch { size, root, start, tree, state } => (size, root, start, tree, state),
        };
        // 1. Nothing is fetched for a head that can not be one this node lacks (docs/06 §5).
        let current = state.manifest().log_rules();
        if witnessed.precheck(&net, &current, &*state, now).is_err() {
            let (latest, index) = self.fetch_manifest(source).await?;
            if let Err(error) = state.may_fetch(&witnessed, &latest, index, now) {
                self.note_refused(size, root, None);
                return Err(format!("head not taken, nothing fetched: {error}"));
            }
        }
        // 2. The entries, bounded, giving exactly the head's root.
        let entries = self.fetch_entries(source, start, size).await?;
        for entry in &entries {
            tree.push_entry(entry).map_err(|e| e.to_string())?;
        }
        if tree.size() != size || tree.root() != root {
            // The head may be fine - this source's entries are not: another source may hand out the right ones.
            self.note_bad_source(key);
            return Err("entries do not give the head's root".into());
        }
        // 3./4. Which rules hold for the head (the snapshot is gone afterwards, so the append changes the state in
        // place), and the changes of the log rules on the way. 5. Each of those changes endorsed by its transition
        // head under the rules before it. A refusal holds for every source with the same head (same entries).
        let order = transition_sources(source, position, sources);
        let checked = match self.check_ahead(state, entries, &witnessed, now).await {
            Ok((head, entries, transitions)) => {
                self.endorse(&order, &transitions, &tree, &head, false).await.map(|endorsed| (head, entries, endorsed))
            }
            Err(error) => Err(error),
        };
        let (head, entries, endorsed) = match checked {
            Ok(checked) => checked,
            Err(error) => {
                self.note_refused(size, root, Some(key));
                return Err(error);
            }
        };
        if self.with_core(|core| core.evidence.contains_key(head.operator())).map_err(|e| e.message)? {
            return Err("head of a deposed log operator".into());
        }
        self.commit_entries(start, entries, Some((head, witnessed)), endorsed).await
    }

    /// Which rules hold for a head that ends with the fetched `entries` beyond `state`, decided on the snapshot
    /// outside the lock (`NetState::rules_ahead`), and the head checked against them. Takes the snapshot by value:
    /// it is dropped on every path before the caller appends.
    async fn check_ahead(
        &self,
        state: Arc<NetState>,
        entries: Vec<Vec<u8>>,
        witnessed: &WitnessedHead,
        now: i64,
    ) -> Result<Checked, String> {
        let net = state.net().clone();
        let ahead = Ahead::parse(&state.manifest().card, state.manifest().version, &entries);
        match state.rules_ahead(&ahead) {
            RulesAhead::Known(rules) => {
                let checked = witnessed.check(&net, &rules, &(&*state, &ahead), now);
                match checked {
                    // No change of the log rules on the way: nothing more to endorse.
                    Ok(head) => Ok((head, entries, Transitions::default())),
                    // Not by the witnesses - only a replay tells whether it is the transition head of a rescue (only a
                    // head of the first operator can be one, docs/06 §5).
                    Err(_)
                        if ahead.may_rescue()
                            && witnessed.claims_cosign_by(&net)
                            && witnessed.signed_by_first(&rules) =>
                    {
                        self.replay_and_check(state, entries, witnessed, ahead, now).await
                    }
                    Err(error) => Err(error.to_string()),
                }
            }
            RulesAhead::Replay => self.replay_and_check(state, entries, witnessed, ahead, now).await,
            RulesAhead::Refuse => Err("too much to check ahead of the head: not taken".into()),
        }
    }

    /// Step 4: replays `entries` on a copy of `state`, noting every change of the log rules, and checks the head
    /// against the copy (rules for its size, rescue). The copy is made and replayed in a blocking thread, never
    /// under the lock; the snapshot is dropped there, so the following append changes the state in place. Returns
    /// the entries for the commit.
    async fn replay_and_check(
        &self,
        state: Arc<NetState>,
        entries: Vec<Vec<u8>>,
        witnessed: &WitnessedHead,
        ahead: Ahead,
        now: i64,
    ) -> Result<Checked, String> {
        self.with_core(|core| core.copies = core.copies.saturating_add(1)).map_err(|e| e.message)?;
        let value = witnessed.clone();
        let (checked, entries, transitions) = tokio::task::spawn_blocking(move || {
            let mut copy = NetState::clone(&state);
            drop(state);
            let mut transitions = Transitions::default();
            for entry in &entries {
                copy.apply_tracked(entry, &ahead, &mut transitions);
            }
            (copy.check_witnessed(&value, &(&copy, &ahead), now), entries, transitions)
        })
        .await
        .map_err(|_| "replay on a copy failed".to_owned())?;
        Ok((checked.map_err(|e| e.to_string())?, entries, transitions))
    }

    /// Step 5 (docs/06 §5 "Übergänge beim Aufholen"): every change of the log rules passed on the way to `head`
    /// (verified; `tree` holds the entries up to it) must be endorsed by its transition head, witnessed under the
    /// rules from before it. Newest first, one at a time (`Transitions::endorsement`): a head checked in an earlier
    /// round that was cut short (rate limits) first, then asked from each of `sources` in turn (distinct nodes, the
    /// sync source's first; [`transition_sources`]) - unless none of them had it lately -, and the walk stops at the
    /// first change that can not be endorsed (review 6, finding 4). A follower refuses more than 64 changes at once;
    /// the first contact checks the last 64 (`first_contact`). Returns the verified transition heads to keep.
    async fn endorse(
        &self,
        sources: &[Vec<Endpoint>],
        transitions: &Transitions,
        tree: &Tree,
        head: &Head,
        first_contact: bool,
    ) -> Result<Vec<(u64, WitnessedHead)>, String> {
        if transitions.is_empty() {
            return Ok(Vec::new());
        }
        if transitions.overflow() && !first_contact {
            return Err("more than 64 changes of the log rules at once: head not taken".into());
        }
        let network = self.network().ok_or("no network")?;
        let net = network.net.clone();
        let refused =
            |e: bridge_net::NetError| format!("head not taken, a change of the log rules is not endorsed: {e}");
        let mut walk = transitions.endorsement(&net, head).map_err(refused)?;
        while let Some(transition) = walk.next() {
            let size = transition.size();
            let root = tree.root_at(size).map_err(|e| e.to_string())?;
            let cached = lock(&network.fetched_transitions).get(&size).cloned();
            if cached.is_some_and(|value| walk.offer(&value, &root)) {
                continue;
            }
            let mut offered = false;
            if !self.gap_lately(size, &root) {
                for endpoints in sources.iter().take(MAX_TRANSITION_SOURCES) {
                    let Ok(value) = self.fetch_transition(endpoints, size).await else { continue };
                    if walk.offer(&value, &root) {
                        remember_fetched(network, size, &value);
                        offered = true;
                        break;
                    }
                }
                if !offered {
                    self.note_gap(size, root);
                }
            }
            if !offered {
                walk.without_head().map_err(refused)?;
            }
        }
        walk.finish().map_err(refused)
    }

    /// Fetches one transition head again that this node does not hold after a restart - its stored copy did not
    /// verify, or it was never stored (docs/06 §5; review 6, finding 3): the first one due, from up to four sources,
    /// checked like a follower checks it. On failure the pause before the next try doubles (up to 64 sync
    /// intervals); after 8 tries it is given up until the next restart.
    async fn repair_transition(&self) {
        let Some(network) = self.network() else { return };
        let now = self.now();
        let due = self.with_core(|core| {
            // Held again in the meantime (witnessed here, or taken while following): nothing to fetch.
            let held = &core.transitions;
            core.missing.retain(|size, _| !held.contains_key(size));
            let (size, missing) = core.missing.iter().find(|(_, missing)| missing.next <= now)?;
            let root = core.log.tree().root_at(*size).ok()?;
            Some((*size, missing.transition.clone(), root))
        });
        let Ok(Some((size, transition, root))) = due else { return };
        let net = network.net.clone();
        for group in self.sync_sources().iter().take(MAX_TRANSITION_SOURCES) {
            let Ok(value) = self.fetch_transition(&group.endpoints, size).await else { continue };
            if transition.check(&net, &value, &root).is_err() {
                continue;
            }
            let row = self.with_core(|core| {
                core.missing.remove(&size);
                core.note_transition(size, &value)
            });
            tracing::info!(size, "transition head fetched again");
            if let Ok(Some(row)) = row {
                self.store_noted(Noted { head: None, transitions: vec![row] }).await;
            }
            return;
        }
        let longest = super::repair_pause(&network.timing).saturating_mul(MAX_REPAIR_ROUNDS);
        let _ = self.with_core(|core| {
            let Some(missing) = core.missing.get_mut(&size) else { return };
            missing.tries = missing.tries.saturating_add(1);
            if missing.tries >= super::MAX_REPAIR_TRIES {
                // Nobody has it (or it never came about): tried again after the next restart.
                core.missing.remove(&size);
                tracing::debug!(size, "transition head not found again: given up until the next restart");
                return;
            }
            missing.next = now.saturating_add(missing.pause);
            missing.pause = missing.pause.saturating_mul(2).min(longest);
        });
    }

    /// Stores verified entries at `start`, then appends and replays them (serialized with every other append); keeps
    /// the witnessed head and the `endorsed` transition heads.
    pub(crate) async fn commit_entries(
        &self,
        start: u64,
        entries: Vec<Vec<u8>>,
        witnessed: Option<(bridge_net::Head, WitnessedHead)>,
        endorsed: Vec<(u64, WitnessedHead)>,
    ) -> Result<(), String> {
        let network = self.network().ok_or("no network")?;
        let _serial = network.append.lock().await;
        if self.with_core(|core| core.log.size()).map_err(|e| e.message)? != start {
            return Err("log changed in the meantime".into());
        }
        let (net, stored) = (network.net.to_string(), entries.clone());
        if !self.blocking(move |store| store.net_log_append(&net, start, &stored)).await.map_err(|e| e.message)? {
            return Err("store refused the entries".into());
        }
        let (size, noted) = self
            .with_core(|core| -> Result<(u64, Noted), String> {
                core.extend(&entries).map_err(|e| e.to_string())?;
                let mut noted = witnessed.map(|(head, value)| core.note_witnessed(head, value)).unwrap_or_default();
                for (size, value) in &endorsed {
                    noted.transitions.extend(core.note_transition(*size, value));
                }
                Ok((core.log.size(), noted))
            })
            .map_err(|e| e.message)??;
        network.applied.send_replace(size);
        drop(_serial);
        if !endorsed.is_empty() {
            lock(&network.fetched_transitions).clear();
        }
        self.store_noted(noted).await;
        Ok(())
    }
}

/// The sources asked for a transition head (review 6, finding 2): the node of the sync source (`source`, an endpoint
/// of `sources[position]`) first - the endpoint that answered first, then its others -, then up to three other
/// sources in their order. Distinct nodes, not endpoints: before, "the source and three more" were often four
/// endpoints of the same node.
fn transition_sources(source: &Endpoint, position: usize, sources: &[Group]) -> Vec<Vec<Endpoint>> {
    let mut first = vec![source.clone()];
    if let Some(group) = sources.get(position) {
        let others = group.endpoints.iter().filter(|endpoint| *endpoint != source);
        first.extend(others.take(MAX_ENDPOINTS_PER_SOURCE.saturating_sub(1)).cloned());
    }
    let mut ordered = vec![first];
    for (index, group) in sources.iter().enumerate() {
        if ordered.len() >= MAX_TRANSITION_SOURCES {
            break;
        }
        if index != position && !group.endpoints.is_empty() {
            ordered.push(group.endpoints.iter().take(MAX_ENDPOINTS_PER_SOURCE).cloned().collect());
        }
    }
    ordered
}

/// Keeps a checked transition head for the next round (bounded: at most 64, the smallest sizes go first).
fn remember_fetched(network: &NetRuntime, size: u64, value: &WitnessedHead) {
    let mut fetched = lock(&network.fetched_transitions);
    fetched.insert(size, value.clone());
    while fetched.len() > MAX_TRANSITIONS {
        fetched.pop_first();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(url: &str) -> Endpoint {
        Endpoint::public(url)
    }

    fn group(key: &str, urls: &[&str]) -> Group {
        Group { key: key.to_owned(), endpoints: urls.iter().map(|url| endpoint(url)).collect() }
    }

    /// Review 6, finding 2: a source node with four endpoints counts once - the next three sources are other nodes.
    #[test]
    fn transition_heads_are_asked_from_distinct_nodes() {
        let sources = vec![
            group("op", &["http://op/1", "http://op/2"]),
            group("m", &["http://m/a", "http://m/b", "http://m/c", "http://m/d"]),
            group("x", &[]),
            group("w", &["http://w"]),
            group("v", &["http://v"]),
            group("u", &["http://u"]),
        ];
        let order = transition_sources(&endpoint("http://m/c"), 1, &sources);
        let urls: Vec<Vec<&str>> =
            order.iter().map(|endpoints| endpoints.iter().map(|endpoint| endpoint.url.as_str()).collect()).collect();
        assert_eq!(
            urls,
            vec![
                vec!["http://m/c", "http://m/a", "http://m/b", "http://m/d"],
                vec!["http://op/1", "http://op/2"],
                vec!["http://w"],
                vec!["http://v"],
            ],
            "the source's node first (the endpoint that answered first), then three other nodes"
        );
        // A source outside the list (or a list of one node): just that node.
        assert_eq!(transition_sources(&endpoint("http://z"), 9, &sources[..1]).len(), 2);
        assert_eq!(transition_sources(&endpoint("http://op/1"), 0, &sources[..1]).len(), 1);
    }

    /// Remembered failures are bounded and end on time; when a table is full, the one that ends first goes.
    #[test]
    fn failures_are_bounded_and_end() {
        let mut failures = Failures::default();
        for i in 0..(MAX_FAILURES as u64 + 10) {
            Failures::note(&mut failures.heads, (i, [0; 32]), 1_000 + i64::try_from(i).unwrap_or(0));
            Failures::note(&mut failures.sources, format!("s{i}"), 1_000);
        }
        assert_eq!(failures.heads.len(), MAX_FAILURES);
        assert_eq!(failures.sources.len(), MAX_FAILURES);
        assert!(!Failures::holds(&failures.heads, &(0, [0; 32]), 0), "the earliest went first");
        assert!(Failures::holds(&failures.heads, &(MAX_FAILURES as u64 + 9, [0; 32]), 0));
        assert!(!Failures::holds(&failures.heads, &(MAX_FAILURES as u64 + 9, [1; 32]), 0), "another root");
        failures.prune(1_000 + i64::try_from(MAX_FAILURES).unwrap_or(0));
        assert!(failures.sources.is_empty());
        assert_eq!(failures.heads.len(), 9, "only those that end later stay");
        assert!(!Failures::holds(&failures.gaps, &(1, [0; 32]), 0));
    }
}
