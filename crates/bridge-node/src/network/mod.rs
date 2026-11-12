//! BridgeNet inside the node (docs/06 §5, §7-§9, ADR 0009).
//!
//! A node of a network keeps the whole transparency log and computes the network state from it. Its roles come
//! from that state alone:
//! - **log operator** (first operator of the log rules that is not deposed here): accepts `submit` after
//!   `NetState::validate_candidate`, appends, issues heads;
//! - **witness** (listed in the log rules): fetches every new head of each operator, checks it against its last
//!   cosigned head and the entries, cosigns it;
//!
//! Which log rules (operators, witnesses, threshold) hold depends on the size of a head (docs/06 §5): those of the
//! manifest in force after the first n − 1 entries, so the head that contains a manifest change is still checked
//! against the rules from before it. After appending such a change the operator issues that head at once and takes
//! no further entries until it is witnessed.
//! - **gateway** (sealed `gateway` level ≥ 2, or start gateway): serves clients - login only for members, join,
//!   `home` entries, relay to other gateways;
//! - everybody **follows**: fetches witnessed heads + entries, verifies them, appends, replays; gossips heads and
//!   deposes an operator locally as soon as it holds evidence of a split view.
//! - **watcher** (sealed `watch` level ≥ 2, docs/06 §11): probes registered nodes and gives level 1 automatically
//!   (module `watcher`); a node started with `--probe` joins as a member and registers at the watchers.
//!
//! Everything node-to-node is a signed request (`rq`, `aud` = the target node) or a signed statement, every answer
//! from another node is size-limited, parsed strictly and verified before it changes anything (Z3).
//!
//! Transition heads (docs/06 §5 "Übergänge beim Aufholen"): every node keeps the witnessed head that ends with each
//! change of the log rules (the last 64, stored for good) and serves it (`POST …/head/at`); a follower that passes a
//! change while catching up takes the new rules only after it verified that head under the old ones.
//!
//! Locking: the log + state ([`Core`]) sit behind a `std::sync::Mutex` that is never held across an `await`;
//! appends (store first, then memory) are serialized by an async mutex so the stored log and the one in memory
//! never diverge. The state is an `Arc`: a sync takes a snapshot under the lock in O(1) and does everything
//! expensive (signature checks for the entries ahead, a copy and replay) outside it, dropping the snapshot before it
//! appends - the state is never copied under the lock (docs/06 §5).

pub(crate) mod endpoints;
mod gateway;
mod gossip;
mod operator;
mod peer;
mod relay;
mod sync;
mod watcher;
mod witness;

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::{Id, Identity, JoinLink, KeyCard, Statement};
use bridge_net::{
    Evidence, Head, Log, NetError, NetResult, NetState, Transition, Transitions, WitnessedHead, verify_head,
};
use bridge_store::{HeadRow, Store, TransitionRow};
use serde_json::Value;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use crate::{Node, lock};

pub(crate) use gateway::Route;
pub(crate) use peer::{Endpoint, Peers};
pub(crate) use watcher::{WatchMemory, status as watch_status_of};
pub use watcher::{WatchStatus, WatchedNode};

/// Meta keys in the store (the network a data folder belongs to survives restarts).
pub(crate) const META_NET: &str = "net.id";
pub(crate) const META_BOOTSTRAP: &str = "net.bootstrap";
pub(crate) const META_BOOTSTRAP_LAN: &str = "net.bootstrap_lan";
pub(crate) const META_URLS: &str = "node.urls";
/// Most bootstrap addresses.
pub const MAX_BOOTSTRAP: usize = 8;
/// Most heads an operator keeps waiting for cosignatures (a cosignature for any of them counts).
const MAX_PENDING_HEADS: usize = 4;
/// Most operators whose heads a node keeps (a manifest lists at most 3; older manifests may have listed others).
const MAX_TRACKED_OPERATORS: usize = 16;
/// Most transition heads a node keeps and serves (one per change of the log rules, like the remembered history).
pub(crate) const MAX_TRANSITIONS: usize = bridge_net::state::MAX_RULES_HISTORY;
/// Lifetime of a membership issued at join (docs/06 §7).
pub const MEMBER_LIFETIME_MS: i64 = 365 * 24 * 3600 * 1000;

/// Timing of the network duties (defaults: docs/06 §5, §8; tests use a few hundred milliseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetTiming {
    /// Followers fetch the newest witnessed head this often.
    pub sync: Duration,
    /// Gossip: ask known gateways for their heads this often.
    pub gossip: Duration,
    /// Log operator: check for new entries (and issue a head) this often.
    pub head: Duration,
    /// Log operator: issue a fresh head without new entries after this time.
    pub head_refresh: Duration,
    /// Witness: fetch the operators' newest heads this often.
    pub cosign: Duration,
    /// Relay: retry undelivered envelopes after this time.
    pub relay_retry: Duration,
    /// Gateways exchange `home` entries this often.
    pub homes: Duration,
    /// Timeout of one node-to-node request.
    pub peer_timeout: Duration,
    /// At most one gossip request per peer within this time.
    pub peer_gap: Duration,
    /// Join: wait at most this long until the new membership is in a witnessed head here.
    pub join_wait: Duration,
    /// Apps: ask the other hosts of every hosted app for newer versions this often (docs/07 §4).
    pub apps: Duration,
    /// Watcher: one round (probes due, decisions) this often (docs/06 §11.4).
    pub watch: Duration,
    /// A node with `probe`: join / register at the watchers this often; a watcher keeps a registration 24 times this
    /// long (docs/06 §11.5).
    pub register: Duration,
}

impl Default for NetTiming {
    fn default() -> Self {
        Self {
            sync: Duration::from_secs(2),
            gossip: Duration::from_secs(5),
            head: Duration::from_secs(1),
            head_refresh: Duration::from_secs(10 * 60),
            cosign: Duration::from_secs(2),
            relay_retry: Duration::from_secs(30),
            homes: Duration::from_secs(5),
            peer_timeout: Duration::from_secs(10),
            peer_gap: Duration::from_secs(1),
            join_wait: Duration::from_secs(20),
            apps: Duration::from_secs(30),
            watch: Duration::from_secs(10),
            register: Duration::from_secs(10 * 60),
        }
    }
}

impl NetTiming {
    /// Short intervals for tests with several nodes in one process.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            sync: Duration::from_millis(150),
            gossip: Duration::from_millis(200),
            head: Duration::from_millis(100),
            head_refresh: Duration::from_secs(60),
            cosign: Duration::from_millis(100),
            relay_retry: Duration::from_millis(250),
            homes: Duration::from_millis(150),
            peer_timeout: Duration::from_secs(3),
            peer_gap: Duration::from_millis(100),
            join_wait: Duration::from_secs(10),
            apps: Duration::from_millis(200),
            watch: Duration::from_millis(200),
            register: Duration::from_millis(500),
        }
    }
}

/// A gateway to look for in the LAN for the first contact (a join link's `node` and `tls`, docs/06 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPin {
    /// The gateway's ID (announced via mDNS).
    pub node: Id,
    /// The fingerprint of its TLS certificate.
    pub tls: [u8; 32],
}

/// Membership of a node in a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetConfig {
    /// The network ID (= ID of its master key).
    pub net: Id,
    /// Addresses of nodes of the network to start from (a join link's gateway; at most 8).
    pub bootstrap: Vec<String>,
    /// The join link's gateway in the LAN: tried first while the node has no log yet (needs LAN on).
    pub lan_bootstrap: Option<LanPin>,
    /// Timing of the network duties.
    pub timing: NetTiming,
    /// The invite code of the join link (only in memory): used when the node joins as a member for probes.
    pub invite: Option<String>,
}

impl NetConfig {
    /// Membership in `net` with default timing and no bootstrap addresses (owner node).
    #[must_use]
    pub fn new(net: Id) -> Self {
        Self { net, bootstrap: Vec::new(), lan_bootstrap: None, timing: NetTiming::default(), invite: None }
    }

    /// Membership from a join link: its gateway is the bootstrap address, and - with `node` and `tls` - the gateway
    /// to look for in the LAN first.
    #[must_use]
    pub fn from_link(link: &JoinLink) -> Self {
        let lan_bootstrap = match (&link.node, link.tls) {
            (Some(node), Some(tls)) => Some(LanPin { node: node.clone(), tls }),
            _ => None,
        };
        Self {
            bootstrap: vec![link.gateway.clone()],
            lan_bootstrap,
            invite: link.code.clone(),
            ..Self::new(link.net.clone())
        }
    }
}

/// What a node knows about its network (owner dashboard, CLI, tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetStatus {
    /// Network ID.
    pub net: Id,
    /// Entries in the local log (0 while still bootstrapping).
    pub size: u64,
    /// Size of the newest witnessed head this node holds.
    pub witnessed_size: Option<u64>,
    /// Version of the current manifest.
    pub manifest_version: u64,
    /// This node is a gateway now.
    pub gateway: bool,
    /// This node is the active log operator now.
    pub operator: bool,
    /// This node is a witness.
    pub witness: bool,
    /// Log operators deposed here because of evidence.
    pub deposed: Vec<Id>,
    /// Deep copies of the network state since the start (docs/06 §5: only behind a real change of the log rules).
    pub state_copies: u64,
}

/// A head this node issued as log operator, with the cosignatures collected so far.
pub(crate) struct Issued {
    pub(crate) statement: Statement,
    pub(crate) head: Head,
    pub(crate) cosigns: Vec<Statement>,
}

/// What noting a verified witnessed head gives to persist: its row (if it is the newest of its operator) and the
/// transition heads to keep.
#[derive(Default)]
pub(crate) struct Noted {
    pub(crate) head: Option<HeadRow>,
    pub(crate) transitions: Vec<TransitionRow>,
}

/// A witnessed head whose log this node holds.
pub(crate) struct Witnessed {
    pub(crate) head: Head,
    pub(crate) value: WitnessedHead,
}

/// The log, the state replayed from it, and the heads around it.
pub(crate) struct Core {
    pub(crate) me: Id,
    pub(crate) log: Log,
    /// Shared so that a sync can take a snapshot under the lock in O(1) and copy it - if at all - outside the lock
    /// (docs/06 §5). Appends change it in place while nobody else holds it.
    pub(crate) state: Arc<NetState>,
    /// Deep copies of the state since the start (replays on a copy, or an append while a snapshot was held).
    pub(crate) copies: u64,
    /// Log index of the statement of the current manifest.
    pub(crate) manifest_index: u64,
    /// Operator: heads issued, newest last.
    pub(crate) issued: VecDeque<Issued>,
    /// Newest witnessed head per operator that this log matches.
    pub(crate) witnessed: BTreeMap<Id, Witnessed>,
    /// Witness: last head cosigned per operator (with its statement).
    pub(crate) cosigned: BTreeMap<Id, (Head, Statement)>,
    /// Deposed operators with the evidence against them.
    pub(crate) evidence: BTreeMap<Id, Evidence>,
    /// Transition heads by size (the witnessed head ending with each change of the log rules; at most 64). Only
    /// verified ones: checked before they are noted, and again after a restart.
    pub(crate) transitions: BTreeMap<u64, WitnessedHead>,
    /// Transition heads of changes in the own log that this node does not hold after a restart (the stored copy did
    /// not verify, or it was never stored - e.g. the node stopped right before): fetched again from other nodes, one
    /// at a time with growing pauses, at most [`MAX_REPAIR_TRIES`] tries each (a change whose own transition head
    /// never came about - endorsed by a rescue right after it - has none anywhere). At most 64.
    pub(crate) missing: BTreeMap<u64, Missing>,
}

/// Most tries to fetch a missing transition head again after a restart (with doubling pauses).
pub(crate) const MAX_REPAIR_TRIES: u32 = 8;

/// A transition head to fetch again (see [`Core::missing`]): the change it ends, when to try next, the pause after
/// the next failure, the tries so far.
pub(crate) struct Missing {
    pub(crate) transition: Transition,
    pub(crate) next: i64,
    pub(crate) pause: i64,
    pub(crate) tries: u32,
}

impl Core {
    /// Restores from entries (replays them; fails if entry 0 is not the genesis of `net`) and notes the changes of
    /// the log rules on the way: for the first contact, whose transition heads must be checked before the log is
    /// taken, and after a restart, whose stored transition heads are checked again (docs/06 §5).
    pub(crate) fn restore_tracked(me: Id, net: &Id, entries: &[Vec<u8>]) -> NetResult<(Self, Transitions)> {
        let mut transitions = Transitions::default();
        let core = Self::restore_with(me, net, entries, Some(&mut transitions))?;
        Ok((core, transitions))
    }

    fn restore_with(me: Id, net: &Id, entries: &[Vec<u8>], transitions: Option<&mut Transitions>) -> NetResult<Self> {
        let mut log = Log::new(net.clone());
        let (first, rest) = entries.split_first().ok_or_else(|| NetError::NotFound("genesis entry".into()))?;
        log.append_bytes(first)?;
        let state = Arc::new(NetState::genesis(net, first)?);
        let mut core = Self {
            me,
            log,
            state,
            copies: 0,
            manifest_index: 0,
            issued: VecDeque::new(),
            witnessed: BTreeMap::new(),
            cosigned: BTreeMap::new(),
            evidence: BTreeMap::new(),
            transitions: BTreeMap::new(),
            missing: BTreeMap::new(),
        };
        core.extend_with(rest, transitions)?;
        Ok(core)
    }

    /// Appends entries to the log and replays them (in lockstep). Invalid entries are kept but do not count.
    pub(crate) fn extend(&mut self, entries: &[Vec<u8>]) -> NetResult<()> {
        self.extend_with(entries, None)
    }

    fn extend_with(&mut self, entries: &[Vec<u8>], mut transitions: Option<&mut Transitions>) -> NetResult<()> {
        let no_cards: &[KeyCard] = &[];
        for entry in entries {
            let index = self.log.append_bytes(entry)?;
            let version = self.state.manifest().version;
            if Arc::get_mut(&mut self.state).is_none() {
                // Somebody holds a snapshot: `make_mut` copies (should not happen - syncs drop theirs first).
                self.copies = self.copies.saturating_add(1);
            }
            let state = Arc::make_mut(&mut self.state);
            let applied = match transitions.as_deref_mut() {
                Some(transitions) => state.apply_tracked(entry, no_cards, transitions),
                None => state.apply(entry),
            };
            if let bridge_net::Applied::Skipped(reason) = applied {
                tracing::debug!(index, %reason, "log entry does not count");
            }
            if self.state.manifest().version != version {
                self.manifest_index = index;
            }
        }
        Ok(())
    }

    /// The operator that takes new entries now: the first of the current log rules without evidence against it.
    pub(crate) fn active_operator(&self) -> Option<&Id> {
        self.state.log_operators().iter().find(|id| !self.evidence.contains_key(*id))
    }

    pub(crate) fn is_active_operator(&self) -> bool {
        self.active_operator() == Some(&self.me)
    }

    /// The operator that signs a head of size `n`: the first operator of the rules for that size without evidence.
    pub(crate) fn operator_for_head(&self, n: u64) -> Option<Id> {
        self.state.rules_for_head(n)?.logs.into_iter().find(|id| !self.evidence.contains_key(id))
    }

    /// The log ends with a manifest that changed the log rules, and no head of that size is witnessed yet: the
    /// operator takes no further entries until it is (docs/06 §5).
    pub(crate) fn transition_pending(&self) -> bool {
        let change = self.state.last_rules_change();
        change > 0
            && self.log.size() == change.saturating_add(1)
            && !self.witnessed.values().any(|witnessed| witnessed.head.size() > change)
    }

    /// Checks a witnessed head of at most the own log size + 1 against the rules for its size, with the rescue for
    /// the transition head of a change by the net key alone (cards from the state; docs/06 §5).
    pub(crate) fn check_witnessed(&self, value: &WitnessedHead, now: i64) -> NetResult<Head> {
        self.state.check_witnessed(value, &*self.state, now)
    }

    /// The head with the largest size this witness cosigned, of any operator.
    pub(crate) fn last_cosigned(&self) -> Option<&Head> {
        self.cosigned.values().map(|(head, _)| head).max_by_key(|head| (head.size(), head.times().0))
    }

    /// Issues a head over the whole log if this node is the operator for that size and one is due (new entries,
    /// `force`, or the last one is older than `refresh`). Returns the row to store.
    pub(crate) fn issue_head(
        &mut self,
        identity: &Identity,
        card: &KeyCard,
        now: i64,
        refresh: i64,
        force: bool,
    ) -> Option<HeadRow> {
        let size = self.log.size();
        if self.operator_for_head(size).as_ref() != Some(&self.me) {
            return None;
        }
        let due = force
            || self
                .issued
                .back()
                .is_none_or(|last| last.head.size() < size || now.saturating_sub(last.head.times().0) >= refresh);
        if !due {
            return None;
        }
        let statement = self.log.issue_head(identity, now).ok()?;
        let head = verify_head(&statement, self.log.net(), card).ok()?;
        let row = head_row(&self.me, "issued", head.size(), &statement, &[]);
        self.issued.push_back(Issued { statement, head, cosigns: Vec::new() });
        while self.issued.len() > MAX_PENDING_HEADS {
            self.issued.pop_front();
        }
        row
    }

    pub(crate) fn is_witness(&self) -> bool {
        self.state.witnesses().contains(&self.me)
    }

    /// The card of a gateway of the network at `now` (`None` if `id` is no gateway or has no card).
    pub(crate) fn gateway_card(&self, id: &Id, now: i64) -> Option<KeyCard> {
        self.state.gateways(now).into_iter().find(|(gateway, _)| gateway == id).and_then(|(_, card)| card)
    }

    pub(crate) fn is_gateway(&self, id: &Id, now: i64) -> bool {
        self.state.gateways(now).iter().any(|(gateway, _)| gateway == id)
    }

    /// How to reach a node known from the log: the TLS pin of its card (LAN) and its addresses.
    pub(crate) fn reach(&self, id: &Id) -> (Option<[u8; 32]>, Vec<String>) {
        (self.state.card_of(id).and_then(|card| card.tls().copied()), self.urls_of(id))
    }

    /// Addresses of a node known from the log: its card (seal or start gateway) and the manifest entry.
    pub(crate) fn urls_of(&self, id: &Id) -> Vec<String> {
        let mut urls: Vec<String> = self.state.card_of(id).map(|card| card.urls().to_vec()).unwrap_or_default();
        for entry in &self.state.manifest().gateways {
            if &entry.id == id && !urls.contains(&entry.url) {
                urls.push(entry.url.clone());
            }
        }
        urls
    }

    /// Every head of `operator` this node keeps (statements).
    fn known_heads(&self, operator: &Id) -> Vec<&Statement> {
        let mut heads: Vec<&Statement> = Vec::new();
        if operator == &self.me {
            heads.extend(self.issued.iter().map(|issued| &issued.statement));
        }
        if let Some(witnessed) = self.witnessed.get(operator) {
            heads.push(&witnessed.value.head);
        }
        if let Some((_, statement)) = self.cosigned.get(operator) {
            heads.push(statement);
        }
        heads
    }

    /// Compares a head of `operator` with every head of it this node keeps. `tree`: the leaves of a log that may
    /// match the larger head (default: the own log). Returns evidence of a split view, never for consistent heads.
    pub(crate) fn find_evidence(
        &self,
        operator: &Id,
        head: &Statement,
        tree: Option<&bridge_net::Tree>,
    ) -> Option<Evidence> {
        let card = self.state.card_of(operator)?;
        let tree = tree.unwrap_or_else(|| self.log.tree());
        self.known_heads(operator).into_iter().find_map(|known| Evidence::check(known, head, card, Some(tree)))
    }

    /// Remembers a verified witnessed head of this log: as the newest of its operator (if it is newer than the one
    /// kept) and, if it ends with a change of the log rules, as a transition head.
    pub(crate) fn note_witnessed(&mut self, head: Head, value: WitnessedHead) -> Noted {
        let mut noted = Noted::default();
        noted.transitions.extend(self.note_transition(head.size(), &value));
        let operator = head.operator().clone();
        let newer = self
            .witnessed
            .get(&operator)
            .is_none_or(|known| (head.size(), head.times().0) > (known.head.size(), known.head.times().0));
        if !newer || (!self.witnessed.contains_key(&operator) && self.witnessed.len() >= MAX_TRACKED_OPERATORS) {
            return noted;
        }
        noted.head = head_row(&operator, "witnessed", head.size(), &value.head, &value.cosigns);
        self.witnessed.insert(operator, Witnessed { head, value });
        noted
    }

    /// Keeps a verified transition head (docs/06 §5): only for a size that ends with a change of the log rules of
    /// this log, the first one per size, at most [`MAX_TRANSITIONS`] (the smallest sizes go first). Returns the row
    /// to store if it is new.
    pub(crate) fn note_transition(&mut self, size: u64, value: &WitnessedHead) -> Option<TransitionRow> {
        if !self.state.is_transition_head(size) || self.transitions.contains_key(&size) {
            return None;
        }
        self.transitions.insert(size, value.clone());
        while self.transitions.len() > MAX_TRANSITIONS {
            self.transitions.pop_first();
        }
        self.transitions.contains_key(&size).then(|| transition_row(size, value)).flatten()
    }

    /// Takes back stored transition heads after a restart (review 6, finding 3): each is verified again like a
    /// follower verifies it - against the rules from before its change, in the normal or the rescue form, with the
    /// cards of that time (`transitions`, noted while the stored log was replayed) and the root of the own log. A row
    /// that does not verify (damaged, unparsable cosignatures, another size or root) is not served; the head is
    /// fetched again from other nodes (`missing`, like the head of every change without a stored row), and a verified
    /// one replaces the stored row. Returns the sizes of rows where no change of the log rules ends (any more) -
    /// nothing to fetch for them, they can go.
    fn restore_transitions(
        &mut self,
        rows: &[TransitionRow],
        transitions: &Transitions,
        now: i64,
        pause: i64,
    ) -> Vec<u64> {
        let net = self.log.net().clone();
        let mut useless = Vec::new();
        for row in rows.iter().rev().take(MAX_TRANSITIONS) {
            let Some(transition) = transitions.iter().find(|transition| transition.size() == row.size) else {
                useless.push(row.size);
                continue;
            };
            let verified = self.log.tree().root_at(row.size).ok().and_then(|root| {
                let head = Statement::parse(&row.head).ok()?;
                let value = WitnessedHead { head, cosigns: parse_cosigns(&row.cosigns)? };
                transition.check(&net, &value, &root).ok().map(|_| value)
            });
            match verified {
                Some(value) => {
                    self.transitions.insert(row.size, value);
                }
                None => tracing::warn!(size = row.size, "a stored transition head does not verify: fetching it again"),
            }
        }
        for transition in transitions.iter() {
            let size = transition.size();
            if !self.transitions.contains_key(&size) && self.missing.len() < MAX_TRANSITIONS {
                let missing = Missing { transition: transition.clone(), next: now, pause, tries: 0 };
                self.missing.insert(size, missing);
            }
        }
        useless
    }

    /// The newest witnessed head this node can serve: the largest one of an operator that is not deposed.
    pub(crate) fn best_witnessed(&self) -> Option<&Witnessed> {
        self.witnessed
            .iter()
            .filter(|(operator, _)| !self.evidence.contains_key(*operator))
            .map(|(_, witnessed)| witnessed)
            .max_by_key(|witnessed| (witnessed.head.size(), witnessed.head.times().0))
    }

    /// Takes back stored heads after a restart (each verified again; heads that do not fit are dropped).
    fn restore_heads(&mut self, rows: &[HeadRow], net: &Id) {
        for row in rows {
            let Ok(operator) = Id::parse(&row.operator) else { continue };
            let Some(card) = self.state.card_of(&operator).cloned() else { continue };
            let Ok(statement) = Statement::parse(&row.head) else { continue };
            let Ok(head) = verify_head(&statement, net, &card) else { continue };
            let cosigns = parse_cosigns(&row.cosigns).unwrap_or_default();
            match row.role.as_str() {
                "witnessed" if self.log.matches(&head) => {
                    let value = WitnessedHead { head: statement, cosigns };
                    self.witnessed.insert(operator, Witnessed { head, value });
                }
                "cosigned" => {
                    self.cosigned.insert(operator, (head, statement));
                }
                _ => {}
            }
        }
    }
}

/// A row of the head table (cosignatures as one JSON array).
pub(crate) fn head_row(
    operator: &Id,
    role: &str,
    size: u64,
    head: &Statement,
    cosigns: &[Statement],
) -> Option<HeadRow> {
    let list = Value::Array(cosigns.iter().map(Statement::to_value).collect());
    let cosigns = bridge_core::json::canonical(&list).ok()?;
    Some(HeadRow {
        operator: operator.to_string(),
        role: role.to_owned(),
        size,
        head: head.canonical_bytes().to_vec(),
        cosigns,
    })
}

/// A row of the transition table (cosignatures as one JSON array).
fn transition_row(size: u64, value: &WitnessedHead) -> Option<TransitionRow> {
    let list = Value::Array(value.cosigns.iter().map(Statement::to_value).collect());
    let cosigns = bridge_core::json::canonical(&list).ok()?;
    Some(TransitionRow { size, head: value.head.canonical_bytes().to_vec(), cosigns })
}

/// The cosignatures of a stored row: a JSON array of at most 32 statements - `None` if it is anything else (a damaged
/// row is not half taken).
fn parse_cosigns(bytes: &[u8]) -> Option<Vec<Statement>> {
    let Ok(Value::Array(list)) = bridge_core::json::parse_strict(bytes, bridge_net::log::MAX_WITNESSED_HEAD_BYTES)
    else {
        return None;
    };
    if list.len() > bridge_net::log::MAX_COSIGNS {
        return None;
    }
    list.into_iter().map(|value| Statement::from_value(value).ok()).collect()
}

/// The network part of a node.
pub(crate) struct NetRuntime {
    pub(crate) net: Id,
    pub(crate) bootstrap: Vec<String>,
    pub(crate) lan_bootstrap: Option<LanPin>,
    pub(crate) timing: NetTiming,
    pub(crate) core: Mutex<Option<Core>>,
    /// Serializes log appends (store first, then memory).
    pub(crate) append: tokio::sync::Mutex<()>,
    /// Size of the applied log (join waits on it).
    pub(crate) applied: watch::Sender<u64>,
    pub(crate) wake_sync: Notify,
    pub(crate) wake_head: Notify,
    pub(crate) wake_witness: Notify,
    pub(crate) wake_relay: Notify,
    pub(crate) peers: Mutex<Peers>,
    /// Transition heads fetched (and checked) for a catch-up that is not done yet, by size (at most 64): a round
    /// cut short by rate limits goes on where it stopped. Checked again before they count.
    pub(crate) fetched_transitions: Mutex<BTreeMap<u64, WitnessedHead>>,
    /// What failed lately when following (refused heads, transition heads no source had, sources that showed a
    /// refused head) - so the same work is not done again right away (docs/06 §5; bounded).
    pub(crate) failures: Mutex<sync::Failures>,
    /// Transition-head rows that could not be stored yet: tried again on every store and every sync round (at most
    /// 64).
    pub(crate) unsaved: Mutex<BTreeMap<u64, TransitionRow>>,
    /// Watcher: registered nodes, member walk, statements in flight (docs/06 §11). Lock order: core, then this.
    pub(crate) watch: Mutex<WatchMemory>,
    /// This node asks the watchers for probes with these services.
    pub(crate) probe: Option<bridge_net::Services>,
    /// Invite code of the join link (memory only), for joining as a member for probes.
    pub(crate) invite: Option<String>,
    /// Which addresses other nodes chose are called ([`crate::NodeConfig::peer_addresses`]).
    pub(crate) peer_addresses: bridge_transport::PeerAddresses,
}

/// The first pause before a damaged transition head is fetched again (it doubles up to 64 times this).
fn repair_pause(timing: &NetTiming) -> i64 {
    i64::try_from(timing.sync.as_millis()).unwrap_or(i64::MAX).max(1)
}

impl NetRuntime {
    /// Loads what the store holds for `config.net` (log, heads, transition heads - verified again -, evidence).
    /// `probe`: ask the watchers for probes with these services ([`crate::NodeConfig::probe`]); `peer_addresses`: see
    /// [`crate::NodeConfig::peer_addresses`].
    pub(crate) fn open(
        store: &Store,
        me: &Id,
        config: &NetConfig,
        now: i64,
        probe: Option<bridge_net::Services>,
        peer_addresses: bridge_transport::PeerAddresses,
    ) -> Result<Self, String> {
        let net = config.net.clone();
        let key = net.to_string();
        let entries =
            store.net_log_load(&key, bridge_net::merkle::MAX_TREE_SIZE).map_err(|e| format!("network log: {e}"))?;
        let core = if entries.is_empty() {
            None
        } else {
            let (mut core, transitions) = Core::restore_tracked(me.clone(), &net, &entries)
                .map_err(|e| format!("the stored network log is invalid ({e}); not starting"))?;
            core.restore_heads(&store.net_heads(&key).map_err(|e| format!("network heads: {e}"))?, &net);
            let rows =
                store.net_transitions(&key, MAX_TRANSITIONS).map_err(|e| format!("network transition heads: {e}"))?;
            let pause = repair_pause(&config.timing);
            for size in core.restore_transitions(&rows, &transitions, now, pause) {
                if let Err(error) = store.net_transition_delete(&key, size) {
                    tracing::warn!(?error, size, "could not delete a stored transition head");
                }
            }
            for (operator, bytes) in store.net_evidence(&key).map_err(|e| format!("network evidence: {e}"))? {
                if let (Ok(operator), Ok(evidence)) = (Id::parse(&operator), Evidence::parse(&bytes)) {
                    core.evidence.insert(operator, evidence);
                }
            }
            Some(core)
        };
        let size = core.as_ref().map_or(0, |core| core.log.size());
        let watch = WatchMemory::load(store, &net)?;
        Ok(Self {
            net,
            bootstrap: config.bootstrap.iter().take(MAX_BOOTSTRAP).cloned().collect(),
            lan_bootstrap: config.lan_bootstrap.clone(),
            timing: config.timing,
            core: Mutex::new(core),
            append: tokio::sync::Mutex::new(()),
            applied: watch::Sender::new(size),
            wake_sync: Notify::new(),
            wake_head: Notify::new(),
            wake_witness: Notify::new(),
            wake_relay: Notify::new(),
            peers: Mutex::new(Peers::default()),
            fetched_transitions: Mutex::new(BTreeMap::new()),
            failures: Mutex::new(sync::Failures::default()),
            unsaved: Mutex::new(BTreeMap::new()),
            watch: Mutex::new(watch),
            probe,
            invite: config.invite.clone(),
            peer_addresses,
        })
    }
}

impl Node {
    pub(crate) fn network(&self) -> Option<&NetRuntime> {
        self.inner.network.as_deref()
    }

    /// Runs `work` on the network core. `UNAVAILABLE` if this node is in no network or still bootstrapping.
    pub(crate) fn with_core<R>(&self, work: impl FnOnce(&mut Core) -> R) -> crate::NodeResult<R> {
        let network = self.network().ok_or_else(crate::NodeError::not_found)?;
        let mut core = lock(&network.core);
        let core = core.as_mut().ok_or_else(crate::NodeError::unavailable)?;
        Ok(work(core))
    }

    /// Runs `work` on a snapshot of the network state in a blocking thread (review 9): the core lock is held only to
    /// copy the `Arc` (O(1)), never during the work, and no worker thread is busy with it - other requests go on. An
    /// append while a snapshot is held changes a copy of the state (counted in `state_copies`); the work is bounded by
    /// the caller. `UNAVAILABLE` like [`Node::with_core`].
    pub(crate) async fn on_snapshot<T: Send + 'static>(
        &self,
        work: impl FnOnce(&NetState) -> T + Send + 'static,
    ) -> crate::NodeResult<T> {
        let state = self.with_core(|core| Arc::clone(&core.state))?;
        tokio::task::spawn_blocking(move || {
            let result = work(&state);
            drop(state); // in the blocking thread, before the answer goes out
            result
        })
        .await
        .map_err(|_| crate::NodeError::unavailable())
    }

    /// Persists a head row (best effort - it is a cache of what can be fetched again).
    pub(crate) async fn store_head(&self, row: Option<HeadRow>) {
        let (Some(row), Some(network)) = (row, self.network()) else { return };
        let (net, now) = (network.net.to_string(), self.now());
        if let Err(error) = self.blocking(move |store| store.net_head_put(&net, &row, now)).await {
            tracing::warn!(?error, "could not store a head");
        }
    }

    /// Persists what noting a witnessed head gave: the head row best effort (like [`Node::store_head`]), the
    /// transition heads for good - a row that can not be stored now is kept and tried again later (with every
    /// store and every sync round, [`Node::store_unsaved`]; review 6, finding 3).
    pub(crate) async fn store_noted(&self, noted: Noted) {
        self.store_head(noted.head).await;
        let Some(network) = self.network() else { return };
        if !noted.transitions.is_empty() {
            let mut unsaved = lock(&network.unsaved);
            for row in noted.transitions {
                unsaved.insert(row.size, row);
            }
            while unsaved.len() > MAX_TRANSITIONS {
                unsaved.pop_first();
            }
        }
        self.store_unsaved().await;
    }

    /// Stores the transition-head rows not stored yet (each verified before; a stored row of the same size, which
    /// can only be one that did not verify, is replaced). What fails stays for the next try.
    pub(crate) async fn store_unsaved(&self) {
        let Some(network) = self.network() else { return };
        let rows: Vec<TransitionRow> = lock(&network.unsaved).values().cloned().collect();
        for row in rows {
            let (net, size) = (network.net.to_string(), row.size);
            match self.blocking(move |store| store.net_transition_put(&net, &row, MAX_TRANSITIONS)).await {
                Ok(_) => {
                    lock(&network.unsaved).remove(&size);
                }
                Err(error) => tracing::warn!(?error, size, "could not store a transition head (tried again later)"),
            }
        }
    }

    /// The node's view of its network.
    pub(crate) fn net_status(&self) -> Option<NetStatus> {
        let network = self.network()?;
        let now = self.now();
        let core = lock(&network.core);
        let Some(core) = core.as_ref() else {
            return Some(NetStatus {
                net: network.net.clone(),
                size: 0,
                witnessed_size: None,
                manifest_version: 0,
                gateway: false,
                operator: false,
                witness: false,
                deposed: Vec::new(),
                state_copies: 0,
            });
        };
        Some(NetStatus {
            net: network.net.clone(),
            size: core.log.size(),
            witnessed_size: core.best_witnessed().map(|witnessed| witnessed.head.size()),
            manifest_version: core.state.manifest().version,
            gateway: core.is_gateway(&core.me, now),
            operator: core.is_active_operator(),
            witness: core.is_witness(),
            deposed: core.evidence.keys().cloned().collect(),
            state_copies: core.copies,
        })
    }
}

/// Starts the background duties of a network node.
pub(crate) fn spawn(node: &Node) -> Vec<JoinHandle<()>> {
    let Some(network) = node.network() else { return Vec::new() };
    let timing = network.timing;
    let mut tasks = vec![
        tokio::spawn(duty(node.clone(), timing.sync, Duty::Sync)),
        tokio::spawn(duty(node.clone(), timing.gossip, Duty::Gossip)),
        tokio::spawn(duty(node.clone(), timing.head, Duty::Head)),
        tokio::spawn(duty(node.clone(), timing.cosign, Duty::Witness)),
        tokio::spawn(duty(node.clone(), timing.relay_retry, Duty::Relay)),
        tokio::spawn(duty(node.clone(), timing.homes, Duty::Homes)),
        tokio::spawn(duty(node.clone(), timing.watch, Duty::Watch)),
        tokio::spawn(duty(node.clone(), timing.relay_retry, Duty::Reports)),
    ];
    if network.probe.is_some() {
        tasks.push(tokio::spawn(duty(node.clone(), timing.register, Duty::Register)));
    }
    tasks
}

#[derive(Debug, Clone, Copy)]
enum Duty {
    Sync,
    Gossip,
    Head,
    Witness,
    Relay,
    Homes,
    Watch,
    Register,
    Reports,
}

/// One duty: run, then wait for the interval (or a wake-up), forever. A round never panics the task: errors are
/// logged and the next round tries again.
async fn duty(node: Node, interval: Duration, duty: Duty) {
    let interval = interval.max(Duration::from_millis(10));
    loop {
        match duty {
            Duty::Sync => node.sync_round().await,
            Duty::Gossip => node.gossip_round().await,
            Duty::Head => node.head_round().await,
            Duty::Witness => node.witness_round().await,
            Duty::Relay => node.relay_round().await,
            Duty::Homes => node.homes_round().await,
            Duty::Watch => node.watch_round().await,
            Duty::Register => node.register_round().await,
            Duty::Reports => node.reports_round().await,
        }
        let Some(network) = node.network() else { return };
        let wake = match duty {
            Duty::Sync => Some(&network.wake_sync),
            Duty::Head => Some(&network.wake_head),
            Duty::Witness => Some(&network.wake_witness),
            Duty::Relay => Some(&network.wake_relay),
            Duty::Gossip | Duty::Homes | Duty::Watch | Duty::Register | Duty::Reports => None,
        };
        match wake {
            Some(wake) => {
                tokio::select! {
                    () = wake.notified() => {}
                    () = tokio::time::sleep(interval) => {}
                }
            }
            None => tokio::time::sleep(interval).await,
        }
    }
}

/// The network membership stored in a data folder.
pub(crate) struct Stored {
    pub(crate) net: Id,
    pub(crate) bootstrap: Vec<String>,
    pub(crate) lan: Option<LanPin>,
}

/// Reads the network membership stored in a data folder (if any).
pub(crate) fn stored_membership(store: &Store) -> Result<Option<Stored>, String> {
    let Some(net) = store.meta_get(META_NET).map_err(|e| e.to_string())? else { return Ok(None) };
    let net = Id::parse(&String::from_utf8_lossy(&net)).map_err(|e| format!("stored network ID: {e}"))?;
    let bootstrap = match store.meta_get(META_BOOTSTRAP).map_err(|e| e.to_string())? {
        Some(bytes) => string_list(&bytes)?,
        None => Vec::new(),
    };
    let lan = match store.meta_get(META_BOOTSTRAP_LAN).map_err(|e| e.to_string())? {
        Some(bytes) => parse_lan_pin(&bytes)?,
        None => None,
    };
    Ok(Some(Stored { net, bootstrap, lan }))
}

/// Stores the network membership of a data folder; refuses to switch a folder to another network (Z8).
pub(crate) fn store_membership(
    store: &Store,
    net: &Id,
    bootstrap: &[String],
    lan: Option<&LanPin>,
) -> Result<(), String> {
    if let Some(stored) = stored_membership(store)? {
        if &stored.net != net {
            return Err(format!("this data folder belongs to network {}, not {net}", stored.net));
        }
    }
    store.meta_set(META_NET, net.as_str().as_bytes()).map_err(|e| e.to_string())?;
    let list = serde_json::json!(bootstrap.iter().take(MAX_BOOTSTRAP).collect::<Vec<_>>()).to_string();
    store.meta_set(META_BOOTSTRAP, list.as_bytes()).map_err(|e| e.to_string())?;
    let pin = match lan {
        Some(pin) => serde_json::json!({"node": pin.node.as_str(), "tls": b64(&pin.tls)}),
        None => Value::Null,
    };
    store.meta_set(META_BOOTSTRAP_LAN, pin.to_string().as_bytes()).map_err(|e| e.to_string())
}

/// `null` or `{"node","tls"}` (strict: anything else means the data folder is damaged).
fn parse_lan_pin(bytes: &[u8]) -> Result<Option<LanPin>, String> {
    let damaged = |what: &str| format!("stored LAN bootstrap: {what}");
    match bridge_core::json::parse_strict(bytes, 1024).map_err(|e| damaged(&e.to_string()))? {
        Value::Null => Ok(None),
        Value::Object(object) if object.len() == 2 => {
            let text = |name: &str| object.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();
            let node = Id::parse(&text("node")).map_err(|e| damaged(&e.to_string()))?;
            let tls = b64_fixed::<32>(&text("tls"), "tls").map_err(|e| damaged(&e.to_string()))?;
            Ok(Some(LanPin { node, tls }))
        }
        _ => Err(damaged("not a pin")),
    }
}

/// A JSON list of strings stored in the meta table (addresses), bounded.
pub(crate) fn string_list(bytes: &[u8]) -> Result<Vec<String>, String> {
    match bridge_core::json::parse_strict(bytes, 8 * 1024).map_err(|e| e.to_string())? {
        Value::Array(items) => {
            Ok(items.iter().filter_map(Value::as_str).take(MAX_BOOTSTRAP).map(str::to_owned).collect())
        }
        _ => Err("stored list is not a list".into()),
    }
}

/// Shared handle type for the runtime.
pub(crate) type SharedNet = Arc<NetRuntime>;
