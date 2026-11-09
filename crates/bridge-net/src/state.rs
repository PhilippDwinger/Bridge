//! The network state (docs/06 §6, ADR 0009): built only by replaying the log in order. Every node computes it
//! itself and gets the same result - [`NetState`] is a pure function of the entries.
//!
//! Rules (precisely):
//! - Entry 0 must be the genesis manifest, otherwise the whole log is invalid.
//! - Every further entry is checked at its position and at its time `t = max(iat, log clock)`; the log clock is
//!   the largest `t` of all accepted entries so far (monotonic, from the entries alone - no head times, so all nodes
//!   agree). An entry is skipped (does not count, stops nothing) if any check fails: canonical form, network, log
//!   kind, `exp > t`, not revoked/replaced, rights of all signers at `t`, signatures, limits.
//! - Grants (delegation, invite, member, seal) are active at time T if `iat − 5 min ≤ T < exp` and they are still
//!   current (not revoked, not replaced by a newer one). A newer grant for the same thing replaces the older one
//!   (newer = larger `iat`, ties by hash); replaced statements count as revoked, so they can never come back.
//!   Statements are identified by their hash *without signatures* (`Statement::hash_bytes`), so another set of
//!   signers for the same content is the same statement.
//! - A membership is replaced only by its issuer, by an admin with `members` (or the master), or once it has
//!   expired; a replacement by a non-admin never shortens it (no gateway can evict members it did not admit).
//! - Restrictions (ban, revoke) take effect at their position and stay until `exp` (bans) or forever (revoke) -
//!   fail closed.
//! - `revoke identity X` (master, or an admin with `members` + `seals` if X is not an active admin) removes
//!   everything X received (delegation only by the master, membership, seals) and voids every grant for X with
//!   `iat ≤ t` (so old statements can not be re-appended). New grants with a later `iat` are possible.
//! - `cascade: true` (master only) additionally marks X as compromised for good: X can no longer sign or receive
//!   anything, and every invite, member, seal and ban X issued (alone or as one of several signers) is removed.
//!   Revocations X issued stay (undo them one by one with new grants).
//! - A start gateway that was ever revoked as identity stays out of the start-gateway exception for good (a
//!   bounded set; when it is full, the exception ends for all start gateways - fail closed).
//! - `revoke statement H`: the master, an original signer of H, or an admin with the matching right (members for
//!   member/invite, seals for seal, bans for ban; delegations only by the master). Manifests and revocations can
//!   not be revoked (a new manifest version / a new grant is the way).
//! - Entries signed by the master key do not count against `limits.log_entries_per_day`; revoke and ban have a
//!   reserve of 10 % above the limit, so admins can still act after a flood. Each admin bans at most
//!   [`MAX_BANS_PER_ADMIN_PER_DAY`] identities per day; the master key is exempt and has a reserve in the ban table
//!   that admins can not fill.
//! - The log rules (operators, witnesses, threshold) for a head of size n are those of the manifest in force after
//!   the first n − 1 entries (docs/06 §5): a head that ends exactly with a manifest change is still checked
//!   against the rules from before it. [`NetState::rules_for_head`] answers this from a bounded history. The
//!   transition head of a change by a manifest signed by the net key alone may carry the net key's cosignature
//!   instead of the witness quorum - if the head is signed by the *first* log operator of the rules before it
//!   (rescue, ADR 0012, [`NetState::check_witnessed`]).
//! - A follower that passes a change of the log rules while catching up takes the new rules only with that change's
//!   transition head under the old ones ([`NetState::apply_tracked`], [`Transitions::verify`],
//!   [`Transitions::endorsement`], ADR 0013).
//! - Key cards (`card_of`): for sealed identities the newest card among their current seals, newest by
//!   `min(card iat, seal iat)` (docs/06 §2, §6). A seal whose card's `iat` is more than 5 minutes after the seal's
//!   own `iat` is skipped - a card from the future would otherwise win for good.
//!
//! Only the log operator additionally refuses manifest changes whose log rules can not be met (first operator and
//! `witness_threshold` witnesses sealed with a card and the service - [`NetState::validate_candidate`]); replay does
//! not check that.
//!
//! Expired grants are forgotten once the log clock is 5 minutes past their `exp`; all maps are bounded.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bridge_core::statement::MAX_STATEMENT_LIFETIME_MS;
use bridge_core::{CLOCK_SKEW_MS, Id, KeyCard, Statement};

use crate::Cards;
use crate::error::{NetError, NetResult};
use crate::log::{Head, MAX_ENTRY_BYTES, WitnessedHead, parse_entry, verify_head};
use crate::merkle::{Hash, MAX_TREE_SIZE, Tree};
use crate::statements::{
    Ban, Body, DAY_MS, Delegation, Invite, JoinMode, Kind, LogRules, Manifest, Member, Revoke, RevokeTarget, Right,
    Rights, Seal, Service, Services,
};

/// Maximum number of admins (current delegations).
pub const MAX_ADMINS: usize = 10_000;
/// Maximum number of current seals (one per subject and level).
pub const MAX_SEALS: usize = 10_000;
/// Maximum number of current bans issued by admins.
pub const MAX_BANS: usize = 10_000;
/// Room in the ban table that only the master key can use (admins can never block it).
pub const MASTER_BAN_RESERVE: usize = 1_000;
/// Maximum number of bans one admin issues per day (by replay time).
pub const MAX_BANS_PER_ADMIN_PER_DAY: u32 = 1_000;
/// Maximum number of current bans of one identity.
pub const MAX_BANS_PER_SUBJECT: usize = 8;
/// Maximum number of current invites.
pub const MAX_INVITES: usize = 10_000;
/// Maximum number of identities revoked with `cascade`.
pub const MAX_COMPROMISED: usize = 10_000;
/// Maximum number of remembered revoked or replaced statements that have not expired yet.
pub const MAX_REVOKED: usize = 1_000_000;
/// Maximum number of remembered identity revocations.
pub const MAX_IDENTITY_REVOCATIONS: usize = 1_000_000;
/// Maximum number of start gateways remembered as revoked for good (beyond: the start-gateway exception ends).
pub const MAX_REVOKED_START_GATEWAYS: usize = 1_024;
/// Maximum number of remembered changes of the log rules (a head needs at most the last two).
pub const MAX_RULES_HISTORY: usize = 64;
/// Most signature checks [`NetState::rules_ahead`] makes for the entries ahead of one head (manifests and the
/// delegations of their signers). More: the head is refused, nothing is replayed (fail closed).
pub const MAX_AHEAD_CHECKS: usize = 64;
/// Most key cards taken from entries ahead.
const MAX_AHEAD_CARDS: usize = 4_096;
/// Most manifests (in the version window) and most `rules` delegations kept from entries ahead.
const MAX_AHEAD_MANIFESTS: usize = 256;
const MAX_AHEAD_DELEGATIONS: usize = 1_024;

/// What replaying one entry did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// The entry is valid and changed the state.
    Accepted,
    /// The entry is invalid and does not count (the reason is given).
    Skipped(NetError),
}

// ---------------------------------------------------------------------------------------------------------------
// Grants

/// Identifies a current grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Delegation(Id),
    Member(Id),
    Seal(Id, u8),
    Ban(Id, Hash),
    Invite(Hash),
}

#[derive(Debug, Clone, PartialEq)]
enum Data {
    Delegation { rights: Rights, card: Box<KeyCard> },
    Member,
    Seal { services: Services, card: Option<Box<KeyCard>> },
    Ban,
    Invite { uses: u32, used: u32 },
}

/// A statement that is currently in effect.
#[derive(Debug, Clone, PartialEq)]
struct Grant {
    hash: Hash,
    iat: i64,
    exp: i64,
    issuers: Vec<Id>,
    data: Data,
}

impl Grant {
    fn active(&self, at: i64) -> bool {
        self.iat.saturating_sub(CLOCK_SKEW_MS) <= at && at < self.exp
    }

    fn newer_than(&self, other: &Grant) -> bool {
        (self.iat, self.hash) > (other.iat, other.hash)
    }
}

/// All current grants, with an index by statement hash (revocation) and by expiry (forgetting).
#[derive(Debug, Clone, Default, PartialEq)]
struct Grants {
    delegations: BTreeMap<Id, Grant>,
    members: BTreeMap<Id, Grant>,
    seals: BTreeMap<(Id, u8), Grant>,
    bans: BTreeMap<(Id, Hash), Grant>,
    invites: BTreeMap<Hash, Grant>,
    by_hash: BTreeMap<Hash, Key>,
    by_exp: BTreeSet<(i64, Key)>,
}

impl Grants {
    fn get(&self, key: &Key) -> Option<&Grant> {
        match key {
            Key::Delegation(id) => self.delegations.get(id),
            Key::Member(id) => self.members.get(id),
            Key::Seal(id, level) => self.seals.get(&(id.clone(), *level)),
            Key::Ban(id, hash) => self.bans.get(&(id.clone(), *hash)),
            Key::Invite(code) => self.invites.get(code),
        }
    }

    /// Inserts or replaces; returns the replaced grant.
    fn insert(&mut self, key: Key, grant: Grant) -> Option<Grant> {
        let old = self.remove(&key);
        self.by_hash.insert(grant.hash, key.clone());
        self.by_exp.insert((grant.exp, key.clone()));
        match key {
            Key::Delegation(id) => self.delegations.insert(id, grant),
            Key::Member(id) => self.members.insert(id, grant),
            Key::Seal(id, level) => self.seals.insert((id, level), grant),
            Key::Ban(id, hash) => self.bans.insert((id, hash), grant),
            Key::Invite(code) => self.invites.insert(code, grant),
        };
        old
    }

    fn remove(&mut self, key: &Key) -> Option<Grant> {
        let grant = match key {
            Key::Delegation(id) => self.delegations.remove(id),
            Key::Member(id) => self.members.remove(id),
            Key::Seal(id, level) => self.seals.remove(&(id.clone(), *level)),
            Key::Ban(id, hash) => self.bans.remove(&(id.clone(), *hash)),
            Key::Invite(code) => self.invites.remove(code),
        }?;
        self.by_hash.remove(&grant.hash);
        self.by_exp.remove(&(grant.exp, key.clone()));
        Some(grant)
    }

    /// Forgets every grant with `exp ≤ before` (amortized O(log n) per grant).
    fn prune(&mut self, before: i64) {
        while let Some((exp, key)) = self.by_exp.first() {
            if *exp > before {
                break;
            }
            let key = key.clone();
            self.remove(&key);
        }
    }

    fn seals_of<'a>(&'a self, id: &Id) -> impl DoubleEndedIterator<Item = (u8, &'a Grant)> + 'a {
        self.seals.range((id.clone(), 0)..=(id.clone(), u8::MAX)).map(|((_, level), grant)| (*level, grant))
    }

    fn bans_of<'a>(&'a self, id: &Id) -> impl Iterator<Item = &'a Grant> + 'a {
        self.bans.range((id.clone(), [0u8; 32])..=(id.clone(), [0xffu8; 32])).map(|(_, grant)| grant)
    }

    /// Keys of all grants and bans that `issuer` signed (delegations are only signed by the master).
    fn issued_by(&self, issuer: &Id) -> Vec<Key> {
        let mut keys = Vec::new();
        let issued = |grant: &Grant| grant.issuers.contains(issuer);
        keys.extend(self.members.iter().filter(|(_, g)| issued(g)).map(|(id, _)| Key::Member(id.clone())));
        keys.extend(self.seals.iter().filter(|(_, g)| issued(g)).map(|((id, l), _)| Key::Seal(id.clone(), *l)));
        keys.extend(self.invites.iter().filter(|(_, g)| issued(g)).map(|(code, _)| Key::Invite(*code)));
        keys.extend(self.bans.iter().filter(|(_, g)| issued(g)).map(|((id, hash), _)| Key::Ban(id.clone(), *hash)));
        keys
    }
}

/// A map whose entries are forgotten after their expiry (amortized O(log n)).
#[derive(Debug, Clone, PartialEq)]
struct Expiring<K: Ord + Clone, V> {
    items: BTreeMap<K, (i64, V)>,
    by_exp: BTreeSet<(i64, K)>,
}

impl<K: Ord + Clone, V> Expiring<K, V> {
    fn new() -> Self {
        Self { items: BTreeMap::new(), by_exp: BTreeSet::new() }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.items.get(key).map(|(_, value)| value)
    }

    fn contains(&self, key: &K) -> bool {
        self.items.contains_key(key)
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    fn insert(&mut self, key: K, exp: i64, value: V) {
        if let Some((old_exp, _)) = self.items.insert(key.clone(), (exp, value)) {
            self.by_exp.remove(&(old_exp, key.clone()));
        }
        self.by_exp.insert((exp, key));
    }

    fn prune(&mut self, before: i64) {
        while let Some((exp, key)) = self.by_exp.first() {
            if *exp > before {
                break;
            }
            let key = key.clone();
            self.by_exp.remove(&(*exp, key.clone()));
            self.items.remove(&key);
        }
    }
}

/// Grants for an identity with `iat` up to these times are void (identity revocations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cutoff {
    grants: i64,
    delegation: i64,
}

/// One change of the log rules (docs/06 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RulesChange {
    /// Log index of the manifest entry (0: the genesis).
    index: u64,
    /// The rules from then on.
    rules: LogRules,
    /// The manifest was signed by the net key alone: its transition head may carry the net key's cosignature instead
    /// of the witness quorum (rescue, ADR 0012).
    master_alone: bool,
}

/// What an accepted entry changes.
enum Effect {
    Manifest(Box<Manifest>, Hash),
    Grant(Key, Grant),
    Ban(Key, Grant, Option<Id>),
    Member(Key, Grant, Option<Hash>),
    Seal(Key, Grant, bool),
    RevokeStatement(Key),
    RevokeIdentity { id: Id, cascade: bool, by_master: bool },
}

// ---------------------------------------------------------------------------------------------------------------
// NetState

/// The state of one network, computed from its log (see module docs for the exact rules).
#[derive(Debug, Clone, PartialEq)]
pub struct NetState {
    net: Id,
    manifest: Manifest,
    manifest_hash: Hash,
    clock: i64,
    size: u64,
    day: i64,
    day_count: u64,
    gateway_sealed: bool,
    grants: Grants,
    revoked: Expiring<Hash, ()>,
    cutoffs: Expiring<Id, Cutoff>,
    compromised: BTreeSet<Id>,
    /// Start gateways that were revoked as identity: never start gateways again (bounded).
    revoked_starts: BTreeSet<Id>,
    /// The start-gateway exception is over for everybody (the set above was full).
    starts_over: bool,
    /// Bans per admin on `ban_day` (cleared when the day changes).
    ban_day: i64,
    bans_today: BTreeMap<Id, u32>,
    /// Changes of the log rules (bounded, oldest first); the first is the genesis.
    rules: VecDeque<RulesChange>,
}

impl NetState {
    /// The state after the genesis manifest (log entry 0). Fails if it is not a valid genesis of `net`.
    pub fn genesis(net: &Id, entry: &[u8]) -> NetResult<Self> {
        let statement = parse_entry(entry)?;
        let manifest = Manifest::genesis(&statement, net)?;
        let clock = statement.times().0;
        let rules = VecDeque::from([RulesChange { index: 0, rules: manifest.log_rules(), master_alone: true }]);
        Ok(Self {
            net: net.clone(),
            manifest,
            manifest_hash: statement.hash_bytes(),
            clock,
            size: 1,
            day: clock.div_euclid(DAY_MS),
            day_count: 0,
            gateway_sealed: false,
            grants: Grants::default(),
            revoked: Expiring::new(),
            cutoffs: Expiring::new(),
            compromised: BTreeSet::new(),
            revoked_starts: BTreeSet::new(),
            starts_over: false,
            ban_day: i64::MIN,
            bans_today: BTreeMap::new(),
            rules,
        })
    }

    /// Replays a whole log. Fails only if entry 0 is not a valid genesis (or the log is impossibly large); invalid
    /// later entries are skipped. Linear in the number of entries.
    pub fn replay(net: &Id, entries: &[Vec<u8>]) -> NetResult<Self> {
        if entries.len() as u64 > MAX_TREE_SIZE {
            return Err(NetError::TooLarge("log".into()));
        }
        let (genesis, rest) = entries.split_first().ok_or_else(|| NetError::NotFound("genesis entry".into()))?;
        let mut state = Self::genesis(net, genesis)?;
        for entry in rest {
            state.apply(entry);
        }
        Ok(state)
    }

    /// Applies the next log entry (index = [`NetState::size`] before the call). Never fails: invalid entries are
    /// skipped and the reason is returned.
    pub fn apply(&mut self, entry: &[u8]) -> Applied {
        self.size = self.size.saturating_add(1);
        let checked = parse_entry(entry).and_then(|statement| {
            let at = self.time_of(&statement);
            let effect = self.check(&statement, at)?;
            Ok((statement, at, effect))
        });
        match checked {
            Ok((statement, at, effect)) => {
                self.commit(&statement, at, effect);
                Applied::Accepted
            }
            Err(reason) => Applied::Skipped(reason),
        }
    }

    /// What a log operator asks before appending `statement` at real time `now_ms`: valid now (`iat` at most 5
    /// minutes ahead, not expired), at most 64 KiB, and it would be accepted as the next entry - with rights that
    /// hold both at its replay time and now (so expired admins can not slip in back-dated statements). A manifest
    /// that changes the log rules is only taken if they can be met (docs/06 §4 "Vorbeugung"): the first log
    /// operator has an active seal with its card and the service `log`, and at least `witness_threshold` of the
    /// witnesses have one with the service `witness`. Replay does not check this (it is no rule of the state).
    pub fn validate_candidate(&self, statement: &Statement, now_ms: i64) -> NetResult<()> {
        if statement.canonical_bytes().len() > MAX_ENTRY_BYTES {
            return Err(NetError::TooLarge("log entry".into()));
        }
        statement.check_time(now_ms)?;
        let at = self.time_of(statement);
        self.check(statement, at)?;
        let now = now_ms.max(self.clock);
        if now > at {
            self.check(statement, now)?;
        }
        if Kind::parse(statement.kind()) == Some(Kind::Manifest) {
            let rules = Manifest::from_body(statement.body())?.log_rules();
            if rules != self.manifest.log_rules() {
                self.check_rules_reachable(&rules, at)?;
                self.check_rules_reachable(&rules, now)?;
            }
        }
        Ok(())
    }

    /// The log rules can be met at `at`: the first operator and `witness_threshold` witnesses are sealed for it.
    fn check_rules_reachable(&self, rules: &LogRules, at: i64) -> NetResult<()> {
        let first = rules.logs.first().ok_or_else(|| NetError::format("manifest: no log operator"))?;
        if !self.sealed_for(first, Service::Log, at) {
            return Err(NetError::forbidden(
                "manifest: the first log operator needs an active seal with its card and the service log",
            ));
        }
        let ready = rules.witnesses.iter().filter(|witness| self.sealed_for(witness, Service::Witness, at)).count();
        if ready < rules.witness_threshold {
            return Err(NetError::forbidden(format!(
                "manifest: only {ready} of the {} needed witnesses have an active seal with their card and the \
                 service witness",
                rules.witness_threshold
            )));
        }
        Ok(())
    }

    /// `id` is not banned or compromised and has a seal active at `at` that carries its card and `service`.
    fn sealed_for(&self, id: &Id, service: Service, at: i64) -> bool {
        !self.excluded(id, at)
            && self.grants.seals_of(id).any(|(_, grant)| {
                grant.active(at)
                    && matches!(&grant.data, Data::Seal { services, card: Some(_) } if services.has(service))
            })
    }

    fn time_of(&self, statement: &Statement) -> i64 {
        statement.times().0.max(self.clock)
    }

    // --- checks (pure) -----------------------------------------------------------------------------------------

    fn check(&self, statement: &Statement, at: i64) -> NetResult<Effect> {
        if statement.net() != &self.net {
            return Err(NetError::format("entry: other network"));
        }
        let kind = Kind::parse(statement.kind())
            .filter(|kind| kind.is_log_kind())
            .ok_or_else(|| NetError::format("entry: not a log kind"))?;
        if statement.times().1 <= at {
            return Err(NetError::Expired);
        }
        if self.revoked.contains(&statement.hash_bytes()) {
            return Err(NetError::forbidden("statement revoked or replaced"));
        }
        let signers: Vec<Id> = statement.claimed_signers().into_iter().cloned().collect();
        let by_master = signers.contains(&self.net);
        let effect = match kind {
            Kind::Manifest => self.check_manifest(statement, &signers, by_master, at)?,
            Kind::Delegation => self.check_delegation(statement, &signers, at)?,
            Kind::Invite => self.check_invite(statement, &signers, at)?,
            Kind::Member => self.check_member(statement, &signers, at)?,
            Kind::Seal => self.check_seal(statement, &signers, by_master, at)?,
            Kind::Revoke => self.check_revoke(statement, &signers, at)?,
            Kind::Ban => self.check_ban(statement, &signers, at)?,
            Kind::Head | Kind::Cosign | Kind::Home => return Err(NetError::format("entry: not a log kind")),
        };
        // Effects that remember a revoked or replaced statement need room for it (soft cap; a cascade may add a
        // bounded number more).
        let remembers = match &effect {
            Effect::RevokeStatement(_) | Effect::RevokeIdentity { .. } => true,
            Effect::Grant(key, _) | Effect::Member(key, ..) | Effect::Seal(key, ..) => self.grants.get(key).is_some(),
            Effect::Manifest(..) | Effect::Ban(..) => false,
        };
        if remembers && self.revoked.len() >= MAX_REVOKED {
            return Err(NetError::quota("remembered revocations"));
        }
        self.check_quota(kind, by_master, at)?;
        // Most expensive last: standing and signatures of every signer.
        self.verify_signers(statement, &signers, at)?;
        Ok(effect)
    }

    fn check_manifest(&self, statement: &Statement, signers: &[Id], by_master: bool, at: i64) -> NetResult<Effect> {
        let manifest = Manifest::from_body(statement.body())?;
        if manifest.card.id() != &self.net {
            return Err(NetError::format("manifest: card is not the net key"));
        }
        if manifest.version != self.manifest.version.saturating_add(1) {
            return Err(NetError::forbidden("manifest: version must be the current one + 1"));
        }
        if !by_master {
            self.require_admins(signers, Right::Rules, self.manifest.approvals.rules, at)?;
        }
        Ok(Effect::Manifest(Box::new(manifest), statement.hash_bytes()))
    }

    fn check_delegation(&self, statement: &Statement, signers: &[Id], at: i64) -> NetResult<Effect> {
        if one_signer(signers)? != &self.net {
            return Err(NetError::forbidden("delegation: only the net key delegates"));
        }
        let delegation = Delegation::from_body(statement.body())?;
        let iat = statement.times().0;
        self.check_subject(&delegation.admin, iat, at, true)?;
        let key = Key::Delegation(delegation.admin.clone());
        let data = Data::Delegation { rights: delegation.rights, card: Box::new(delegation.card) };
        let grant = self.new_grant(statement, signers, data);
        self.check_replace(&key, &grant, self.grants.delegations.len(), MAX_ADMINS)?;
        Ok(Effect::Grant(key, grant))
    }

    fn check_invite(&self, statement: &Statement, signers: &[Id], at: i64) -> NetResult<Effect> {
        let issuer = one_signer(signers)?;
        self.require_right(issuer, Right::Members, at)?;
        let invite = Invite::from_body(statement.body())?;
        let key = Key::Invite(invite.code_hash);
        if self.grants.get(&key).is_some() {
            return Err(NetError::forbidden("invite: code already exists"));
        }
        if self.grants.invites.len() >= MAX_INVITES {
            return Err(NetError::quota("invites"));
        }
        let grant = self.new_grant(statement, signers, Data::Invite { uses: invite.uses, used: 0 });
        Ok(Effect::Grant(key, grant))
    }

    fn check_member(&self, statement: &Statement, signers: &[Id], at: i64) -> NetResult<Effect> {
        let issuer = one_signer(signers)?;
        let member = Member::from_body(statement.body())?;
        let by_admin = issuer == &self.net || self.admin_rights_at(issuer, at).has(Right::Members);
        if !by_admin {
            if !self.is_gateway_at(issuer, at) {
                return Err(NetError::forbidden("member: only admins with members or gateways admit members"));
            }
            match self.manifest.join.mode {
                JoinMode::Open => {}
                JoinMode::Invite if member.invite.is_some() => {}
                JoinMode::Invite => return Err(NetError::forbidden("member: invite code required")),
                JoinMode::Closed => return Err(NetError::forbidden("member: closed network, only admins admit")),
            }
        }
        self.check_subject(&member.member, statement.times().0, at, false)?;
        if let Some(code) = &member.invite {
            let invite = self.grants.invites.get(code).ok_or_else(|| NetError::NotFound("invite".into()))?;
            if !invite.active(at) {
                return Err(NetError::Expired);
            }
            if matches!(invite.data, Data::Invite { uses, used } if used >= uses) {
                return Err(NetError::quota("invite used up"));
            }
        }
        let key = Key::Member(member.member.clone());
        let grant = self.new_grant(statement, signers, Data::Member);
        if let Some(current) = self.grants.members.get(&member.member) {
            // Only the issuer of the membership, an admin with `members` (or the master) replaces it - or anybody
            // once it has expired. A gateway that did not admit the member can not evict it.
            let expired = at >= current.exp;
            if !(by_admin || expired || current.issuers.contains(issuer)) {
                return Err(NetError::forbidden("member: only its issuer or an admin replaces a membership"));
            }
            if !by_admin && grant.exp < current.exp {
                return Err(NetError::forbidden("member: a replacement must not shorten the membership"));
            }
        }
        let limit = usize::try_from(self.manifest.limits.members).unwrap_or(usize::MAX);
        self.check_replace(&key, &grant, self.grants.members.len(), limit)?;
        Ok(Effect::Member(key, grant, member.invite))
    }

    fn check_seal(&self, statement: &Statement, signers: &[Id], by_master: bool, at: i64) -> NetResult<Effect> {
        let seal = Seal::from_body(statement.body())?;
        // A card from the future would be the "newest" card of the node for good (`seal_card`): the card may be at
        // most the clock skew younger than the seal that carries it (review 6, finding 6).
        if seal.card.as_ref().is_some_and(|card| card.iat() > statement.times().0.saturating_add(CLOCK_SKEW_MS)) {
            return Err(NetError::forbidden("seal: the card is issued more than 5 minutes after the seal"));
        }
        if !by_master {
            let needed = if seal.level == 3 { self.manifest.approvals.seal3 } else { 1 };
            self.require_admins(signers, Right::Seals, needed, at)?;
        }
        self.check_subject(&seal.subject, statement.times().0, at, false)?;
        let key = Key::Seal(seal.subject.clone(), seal.level);
        let gateway = seal.level >= 2 && seal.services.has(Service::Gateway);
        let data = Data::Seal { services: seal.services, card: seal.card.map(Box::new) };
        let grant = self.new_grant(statement, signers, data);
        self.check_replace(&key, &grant, self.grants.seals.len(), MAX_SEALS)?;
        Ok(Effect::Seal(key, grant, gateway))
    }

    fn check_ban(&self, statement: &Statement, signers: &[Id], at: i64) -> NetResult<Effect> {
        let issuer = one_signer(signers)?;
        self.require_right(issuer, Right::Bans, at)?;
        let ban = Ban::from_body(statement.body())?;
        if ban.subject == self.net {
            return Err(NetError::forbidden("ban: the net key can not be banned"));
        }
        let key = Key::Ban(ban.subject.clone(), statement.hash_bytes());
        if self.grants.get(&key).is_some() {
            return Err(NetError::forbidden("ban: already applied"));
        }
        let grant = self.new_grant(statement, signers, Data::Ban);
        if issuer == &self.net {
            // The master key has its own reserve: admins can never fill the table (or a subject's slots) for it.
            if self.grants.bans.len() >= MAX_BANS + MASTER_BAN_RESERVE {
                return Err(NetError::quota("bans"));
            }
            return Ok(Effect::Ban(key, grant, None));
        }
        let today = if at.div_euclid(DAY_MS) == self.ban_day { self.bans_today.get(issuer).copied() } else { None };
        if today.unwrap_or(0) >= MAX_BANS_PER_ADMIN_PER_DAY {
            return Err(NetError::quota("bans of this admin today"));
        }
        if self.grants.bans_of(&ban.subject).count() >= MAX_BANS_PER_SUBJECT || self.grants.bans.len() >= MAX_BANS {
            return Err(NetError::quota("bans"));
        }
        Ok(Effect::Ban(key, grant, Some(issuer.clone())))
    }

    fn check_revoke(&self, statement: &Statement, signers: &[Id], at: i64) -> NetResult<Effect> {
        let issuer = one_signer(signers)?;
        let by_master = issuer == &self.net;
        let rights = if by_master { Rights::all() } else { self.admin_rights_at(issuer, at) };
        let revoke = Revoke::from_body(statement.body())?;
        match revoke.target {
            RevokeTarget::Statement(target) => {
                let key = self
                    .grants
                    .by_hash
                    .get(&target)
                    .ok_or_else(|| NetError::NotFound("statement to revoke (not in effect)".into()))?;
                let original = self.grants.get(key).is_some_and(|grant| grant.issuers.contains(issuer));
                let by_right = match key {
                    Key::Delegation(_) => false,
                    Key::Member(_) | Key::Invite(_) => rights.has(Right::Members),
                    Key::Seal(..) => rights.has(Right::Seals),
                    Key::Ban(..) => rights.has(Right::Bans),
                };
                if !(by_master || original || by_right) {
                    return Err(NetError::forbidden("revoke: no right for this statement"));
                }
                Ok(Effect::RevokeStatement(key.clone()))
            }
            RevokeTarget::Identity { id, cascade } => {
                if id == self.net {
                    return Err(NetError::forbidden("revoke: the net key can not be revoked"));
                }
                if cascade && !by_master {
                    return Err(NetError::forbidden("revoke: cascade only by the net key"));
                }
                if !by_master {
                    if !(rights.has(Right::Members) && rights.has(Right::Seals)) {
                        return Err(NetError::forbidden("revoke: identity needs the rights members and seals"));
                    }
                    if self.grants.delegations.get(&id).is_some_and(|grant| grant.active(at)) {
                        return Err(NetError::forbidden("revoke: admins are revoked by the net key only"));
                    }
                }
                if cascade && !self.compromised.contains(&id) && self.compromised.len() >= MAX_COMPROMISED {
                    return Err(NetError::quota("compromised identities"));
                }
                if !self.cutoffs.contains(&id) && self.cutoffs.len() >= MAX_IDENTITY_REVOCATIONS {
                    return Err(NetError::quota("identity revocations"));
                }
                Ok(Effect::RevokeIdentity { id, cascade, by_master })
            }
        }
    }

    /// The identity may receive a grant: not the net key, not compromised, not banned, not voided by an identity
    /// revocation for statements up to `iat`.
    fn check_subject(&self, id: &Id, iat: i64, at: i64, delegation: bool) -> NetResult<()> {
        if id == &self.net {
            return Err(NetError::format("the net key can not receive grants"));
        }
        if self.compromised.contains(id) {
            return Err(NetError::forbidden("identity revoked (cascade)"));
        }
        if let Some(cutoff) = self.cutoffs.get(id) {
            let until = if delegation { cutoff.delegation } else { cutoff.grants };
            if iat <= until {
                return Err(NetError::forbidden("identity revoked"));
            }
        }
        if self.banned_at(id, at) {
            return Err(NetError::Banned);
        }
        Ok(())
    }

    /// A new grant may be stored: newer than the current one, or room for another one.
    fn check_replace(&self, key: &Key, grant: &Grant, count: usize, limit: usize) -> NetResult<()> {
        match self.grants.get(key) {
            Some(current) if !grant.newer_than(current) => {
                Err(NetError::forbidden("not newer than the statement in effect"))
            }
            Some(_) => Ok(()),
            None if count >= limit => Err(NetError::quota("limit reached")),
            None => Ok(()),
        }
    }

    fn new_grant(&self, statement: &Statement, signers: &[Id], data: Data) -> Grant {
        let (iat, exp) = statement.times();
        Grant { hash: statement.hash_bytes(), iat, exp, issuers: signers.to_vec(), data }
    }

    /// One signer, the net key or an admin with `right`.
    fn require_right(&self, issuer: &Id, right: Right, at: i64) -> NetResult<()> {
        if issuer == &self.net || self.admin_rights_at(issuer, at).has(right) {
            return Ok(());
        }
        Err(NetError::forbidden(format!("needs the right {}", right.as_str())))
    }

    /// Every signer is an admin with `right`, and there are at least `needed` of them (distinct - the statement
    /// format refuses the same signer twice).
    fn require_admins(&self, signers: &[Id], right: Right, needed: usize, at: i64) -> NetResult<()> {
        if signers.iter().any(|signer| !self.admin_rights_at(signer, at).has(right)) {
            return Err(NetError::forbidden(format!("every signer needs the right {}", right.as_str())));
        }
        if signers.len() < needed {
            return Err(NetError::forbidden(format!("needs {needed} admins with the right {}", right.as_str())));
        }
        Ok(())
    }

    fn check_quota(&self, kind: Kind, by_master: bool, at: i64) -> NetResult<()> {
        if by_master {
            return Ok(());
        }
        let used = if at.div_euclid(DAY_MS) == self.day { self.day_count } else { 0 };
        let mut limit = self.manifest.limits.log_entries_per_day;
        if matches!(kind, Kind::Revoke | Kind::Ban) {
            limit = limit.saturating_add(limit / 10);
        }
        if used >= limit {
            return Err(NetError::quota("log entries per day"));
        }
        Ok(())
    }

    /// Every signer is in good standing and has a known card at `at`; all signatures are valid.
    fn verify_signers(&self, statement: &Statement, signers: &[Id], at: i64) -> NetResult<()> {
        let mut cards = Vec::with_capacity(signers.len());
        for signer in signers {
            if self.compromised.contains(signer) {
                return Err(NetError::forbidden("signer revoked (cascade)"));
            }
            if signer != &self.net && self.banned_at(signer, at) {
                return Err(NetError::Banned);
            }
            cards.push(self.signer_card(signer, at).ok_or_else(|| NetError::forbidden("signer without rights"))?);
        }
        statement.verify(&cards, signers.len())?;
        Ok(())
    }

    /// The card of a signer that has some standing at `at`: the net key, an active admin, an actively sealed
    /// identity, or a start gateway with a card.
    fn signer_card(&self, id: &Id, at: i64) -> Option<&KeyCard> {
        if id == &self.net {
            return Some(&self.manifest.card);
        }
        if let Some(Grant { data: Data::Delegation { card, .. }, .. }) =
            self.grants.delegations.get(id).filter(|grant| grant.active(at))
        {
            return Some(card);
        }
        for (_, grant) in self.grants.seals_of(id).rev() {
            if let Data::Seal { card: Some(card), .. } = &grant.data {
                if grant.active(at) {
                    return Some(card);
                }
            }
        }
        if self.is_start_gateway(id) {
            return self.manifest.gateways.iter().find(|entry| &entry.id == id).and_then(|entry| entry.card.as_ref());
        }
        None
    }

    // --- changes -----------------------------------------------------------------------------------------------

    fn commit(&mut self, statement: &Statement, at: i64, effect: Effect) {
        match effect {
            Effect::Manifest(manifest, hash) => {
                let rules = manifest.log_rules();
                if self.rules.back().is_none_or(|change| change.rules != rules) {
                    // Index of the entry being applied (`apply` counted it already).
                    let index = self.size.saturating_sub(1);
                    let master_alone = statement.claimed_signers() == [&self.net];
                    self.rules.push_back(RulesChange { index, rules, master_alone });
                    while self.rules.len() > MAX_RULES_HISTORY {
                        self.rules.pop_front();
                    }
                }
                for entry in &manifest.gateways {
                    // A listed start gateway that is (still) revoked stays out of the exception for good.
                    if self.cutoffs.contains(&entry.id) {
                        self.forget_start(&entry.id);
                    }
                }
                self.manifest = *manifest;
                self.manifest_hash = hash;
            }
            Effect::Grant(key, grant) => self.put(key, grant),
            Effect::Ban(key, grant, admin) => {
                if let Some(admin) = admin {
                    let day = at.div_euclid(DAY_MS);
                    if day != self.ban_day {
                        self.ban_day = day;
                        self.bans_today.clear();
                    }
                    let count = self.bans_today.entry(admin).or_insert(0);
                    *count = count.saturating_add(1);
                }
                self.put(key, grant);
            }
            Effect::Member(key, grant, invite) => {
                if let Some(Grant { data: Data::Invite { used, .. }, .. }) =
                    invite.and_then(|code| self.grants.invites.get_mut(&code))
                {
                    *used = used.saturating_add(1);
                }
                self.put(key, grant);
            }
            Effect::Seal(key, grant, gateway) => {
                self.gateway_sealed |= gateway;
                self.put(key, grant);
            }
            Effect::RevokeStatement(key) => self.take(&key),
            Effect::RevokeIdentity { id, cascade, by_master } => self.revoke_identity(&id, cascade, by_master, at),
        }
        if !statement.claimed_signers().contains(&&self.net) {
            let day = at.div_euclid(DAY_MS);
            if day != self.day {
                self.day = day;
                self.day_count = 0;
            }
            self.day_count = self.day_count.saturating_add(1);
        }
        self.clock = self.clock.max(at);
        let before = self.clock.saturating_sub(CLOCK_SKEW_MS);
        self.grants.prune(before);
        self.revoked.prune(before);
        self.cutoffs.prune(before);
    }

    /// Stores a grant; a replaced one counts as revoked from now on.
    fn put(&mut self, key: Key, grant: Grant) {
        if let Some(old) = self.grants.insert(key, grant) {
            self.revoked.insert(old.hash, old.exp, ());
        }
    }

    /// Removes a grant; it counts as revoked from now on.
    fn take(&mut self, key: &Key) {
        if let Some(old) = self.grants.remove(key) {
            self.revoked.insert(old.hash, old.exp, ());
        }
    }

    /// `id` is never a start gateway again (bounded; when full, the exception ends for everybody - fail closed).
    fn forget_start(&mut self, id: &Id) {
        if self.revoked_starts.len() >= MAX_REVOKED_START_GATEWAYS && !self.revoked_starts.contains(id) {
            self.starts_over = true;
            return;
        }
        self.revoked_starts.insert(id.clone());
    }

    fn revoke_identity(&mut self, id: &Id, cascade: bool, by_master: bool, at: i64) {
        if self.manifest.gateways.iter().any(|entry| &entry.id == id) {
            self.forget_start(id);
        }
        if by_master {
            self.take(&Key::Delegation(id.clone()));
        }
        self.take(&Key::Member(id.clone()));
        for level in 1..=3 {
            self.take(&Key::Seal(id.clone(), level));
        }
        let mut cutoff = self.cutoffs.get(id).copied().unwrap_or(Cutoff { grants: i64::MIN, delegation: i64::MIN });
        cutoff.grants = cutoff.grants.max(at);
        if by_master {
            cutoff.delegation = cutoff.delegation.max(at);
        }
        // After this time no statement with iat ≤ cutoff can still be valid, so the cutoff can be forgotten.
        let forget = cutoff.grants.max(cutoff.delegation).saturating_add(MAX_STATEMENT_LIFETIME_MS + CLOCK_SKEW_MS);
        self.cutoffs.insert(id.clone(), forget, cutoff);
        if cascade {
            self.compromised.insert(id.clone());
            for key in self.grants.issued_by(id) {
                self.take(&key);
            }
        }
    }

    // --- queries -----------------------------------------------------------------------------------------------

    fn banned_at(&self, id: &Id, at: i64) -> bool {
        self.grants.bans_of(id).any(|ban| at < ban.exp)
    }

    fn admin_rights_at(&self, id: &Id, at: i64) -> Rights {
        if self.compromised.contains(id) {
            return Rights::NONE;
        }
        match self.grants.delegations.get(id) {
            Some(grant @ Grant { data: Data::Delegation { rights, .. }, .. }) if grant.active(at) => *rights,
            _ => Rights::NONE,
        }
    }

    /// Start gateways of the current manifest count as gateways until the first gateway seal was logged (and only
    /// if they were never revoked).
    fn is_start_gateway(&self, id: &Id) -> bool {
        !self.gateway_sealed
            && !self.starts_over
            && !self.compromised.contains(id)
            && !self.revoked_starts.contains(id)
            && !self.cutoffs.contains(id)
            && self.manifest.gateways.iter().any(|entry| &entry.id == id)
    }

    fn is_gateway_at(&self, id: &Id, at: i64) -> bool {
        if self.compromised.contains(id) {
            return false;
        }
        let sealed = self.grants.seals_of(id).any(|(level, grant)| {
            level >= 2
                && grant.active(at)
                && matches!(grant.data, Data::Seal { services, .. } if services.has(Service::Gateway))
        });
        sealed || self.is_start_gateway(id)
    }

    fn excluded(&self, id: &Id, at: i64) -> bool {
        self.compromised.contains(id) || self.banned_at(id, at)
    }

    /// Trust level at time `at`: the highest active seal (1-3), else 0 for a member, else `None` (also when
    /// banned). Login in a network (docs/06 §7) needs a level.
    #[must_use]
    pub fn level(&self, id: &Id, at: i64) -> Option<u8> {
        if self.excluded(id, at) {
            return None;
        }
        let sealed = self.grants.seals_of(id).filter(|(_, grant)| grant.active(at)).map(|(level, _)| level).max();
        sealed.or_else(|| self.is_member(id, at).then_some(0))
    }

    /// Whether `id` may log in at `at`: its level, or `BANNED` / `NOT_MEMBER`.
    pub fn check_login(&self, id: &Id, at: i64) -> NetResult<u8> {
        if self.banned_at(id, at) {
            return Err(NetError::Banned);
        }
        self.level(id, at).ok_or(NetError::NotMember)
    }

    /// Whether `id` has an active membership and is not banned.
    #[must_use]
    pub fn is_member(&self, id: &Id, at: i64) -> bool {
        !self.excluded(id, at) && self.grants.members.get(id).is_some_and(|grant| grant.active(at))
    }

    /// Whether `id` is banned at `at`.
    #[must_use]
    pub fn is_banned(&self, id: &Id, at: i64) -> bool {
        self.banned_at(id, at)
    }

    /// Services of `id` at `at` (union of its active seals; none when banned).
    #[must_use]
    pub fn services(&self, id: &Id, at: i64) -> Services {
        if self.excluded(id, at) {
            return Services::NONE;
        }
        self.grants.seals_of(id).filter(|(_, grant)| grant.active(at)).fold(Services::NONE, |all, (_, grant)| {
            match grant.data {
                Data::Seal { services, .. } => all.union(services),
                _ => all,
            }
        })
    }

    /// Admin rights of `id` at `at` (none when banned). The net key itself has all rights.
    #[must_use]
    pub fn admin_rights(&self, id: &Id, at: i64) -> Rights {
        if id == &self.net {
            return Rights::all();
        }
        if self.excluded(id, at) {
            return Rights::NONE;
        }
        self.admin_rights_at(id, at)
    }

    /// All active admins at `at` with their rights.
    #[must_use]
    pub fn admins(&self, at: i64) -> Vec<(Id, Rights)> {
        self.grants
            .delegations
            .keys()
            .map(|id| (id.clone(), self.admin_rights(id, at)))
            .filter(|(_, rights)| !rights.is_empty())
            .collect()
    }

    /// All gateways at `at`: identities with an active seal of level ≥ 2 with service `gateway` - with the newest
    /// card among the seals of that identity active at `at` (a re-seal with a new card at any level brings new
    /// addresses and TLS pins, docs/06 §2) - and, until the first gateway seal, the start gateways of the manifest
    /// (card if listed). Banned and revoked identities are left out. Sorted by ID.
    #[must_use]
    pub fn gateways(&self, at: i64) -> Vec<(Id, Option<KeyCard>)> {
        let mut gateways: BTreeMap<Id, Option<KeyCard>> = BTreeMap::new();
        for ((id, level), grant) in &self.grants.seals {
            if let Data::Seal { services, .. } = &grant.data {
                if *level >= 2 && services.has(Service::Gateway) && grant.active(at) && !self.excluded(id, at) {
                    gateways.insert(id.clone(), self.seal_card(id, Some(at)).cloned());
                }
            }
        }
        for entry in &self.manifest.gateways {
            if self.is_start_gateway(&entry.id) && !self.banned_at(&entry.id, at) {
                gateways.entry(entry.id.clone()).or_insert_with(|| entry.card.clone());
            }
        }
        gateways.into_iter().collect()
    }

    /// Remaining uses of an invite code at `at` (`None` if unknown, revoked or expired).
    #[must_use]
    pub fn invite_left(&self, code_hash: &Hash, at: i64) -> Option<u32> {
        let invite = self.grants.invites.get(code_hash).filter(|grant| grant.active(at))?;
        match invite.data {
            Data::Invite { uses, used } => Some(uses.saturating_sub(used)),
            _ => None,
        }
    }

    /// A key card for `id` known from the log: the net key (manifest), an admin (delegation), a sealed identity (the
    /// newest card among its current seals - newest = largest `min(card iat, seal iat)`, ties by the seal's `iat`,
    /// then its hash - so a re-seal with a new card at any level replaces an old address or TLS pin, and a re-seal
    /// with an old card never brings one back), a start gateway (manifest). Cards are self-certifying; use them for
    /// heads, cosignatures, relays, and the LAN pin.
    #[must_use]
    pub fn card_of(&self, id: &Id) -> Option<&KeyCard> {
        if id == &self.net {
            return Some(&self.manifest.card);
        }
        if let Some(Grant { data: Data::Delegation { card, .. }, .. }) = self.grants.delegations.get(id) {
            return Some(card);
        }
        if let Some(card) = self.seal_card(id, None) {
            return Some(card);
        }
        self.manifest.gateways.iter().find(|entry| &entry.id == id).and_then(|entry| entry.card.as_ref())
    }

    /// The newest card among the current seals of `id` (only seals active at `at`, if given): newest by
    /// `min(card iat, seal iat)`, ties by the seal's `iat`, then its hash (docs/06 §2 "Welche Karte gilt"). A card is
    /// signed by the node itself, so only the node can make a newer one; an admin who re-seals with an old card from
    /// the log (at any level) can never bring back old addresses or an old TLS pin. The seal's `iat` caps the card's
    /// (a seal check refuses cards more than 5 minutes younger than their seal): a card dated into the future can not
    /// stay the newest for good (review 6, finding 6).
    fn seal_card(&self, id: &Id, at: Option<i64>) -> Option<&KeyCard> {
        self.grants
            .seals_of(id)
            .filter(|(_, grant)| at.is_none_or(|at| grant.active(at)))
            .filter_map(|(_, grant)| match &grant.data {
                Data::Seal { card: Some(card), .. } => {
                    Some(((card.iat().min(grant.iat), grant.iat, grant.hash), card.as_ref()))
                }
                _ => None,
            })
            .max_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, card)| card)
    }

    /// The seals of `id` active at `at`: (level, services), ascending by level (none when banned).
    #[must_use]
    pub fn seals(&self, id: &Id, at: i64) -> Vec<(u8, Services)> {
        if self.excluded(id, at) {
            return Vec::new();
        }
        self.grants
            .seals_of(id)
            .filter(|(_, grant)| grant.active(at))
            .filter_map(|(level, grant)| match grant.data {
                Data::Seal { services, .. } => Some((level, services)),
                _ => None,
            })
            .collect()
    }

    /// Whether a statement hash is revoked or replaced (and not yet expired).
    #[must_use]
    pub fn is_revoked(&self, hash: &Hash) -> bool {
        self.revoked.contains(hash)
    }

    /// The current manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Hash of the statement of the current manifest.
    #[must_use]
    pub fn manifest_hash(&self) -> &Hash {
        &self.manifest_hash
    }

    /// Log operators of the current manifest.
    #[must_use]
    pub fn log_operators(&self) -> &[Id] {
        &self.manifest.logs
    }

    /// The log rules that hold for a head of size `n` (docs/06 §5): those of the manifest in force after the first
    /// `n − 1` entries. So a head that ends exactly with a manifest change (`n = j + 1`) is checked against the
    /// rules from before entry j (for j = 0: the genesis), every larger head against the rules of entry j.
    /// Known for `1 ≤ n ≤ size + 1`; `None` for other sizes and for heads older than the remembered history
    /// (fail closed).
    #[must_use]
    pub fn rules_for_head(&self, n: u64) -> Option<LogRules> {
        if n == 0 || n > self.size.saturating_add(1) {
            return None;
        }
        let position = self.rules.iter().rposition(|change| change.index < n)?;
        let change = self.rules.get(position)?;
        if n == change.index.saturating_add(1) && change.index > 0 {
            return self.rules.get(position.checked_sub(1)?).map(|before| before.rules.clone());
        }
        Some(change.rules.clone())
    }

    /// Log index of the latest manifest that changed the log rules (0: none since the genesis).
    #[must_use]
    pub fn last_rules_change(&self) -> u64 {
        self.rules.back().map_or(0, |change| change.index)
    }

    /// Whether a head of size `n` is the transition head of a log-rules change by a manifest signed by the net key
    /// alone (entry `n − 1`, not the genesis, within the remembered history): then the net key's cosignature counts
    /// instead of the witness quorum (rescue, docs/06 §5, ADR 0012). Never for any other head.
    #[must_use]
    pub fn rescue_head(&self, n: u64) -> bool {
        n >= 2
            && n <= self.size
            && self
                .rules
                .iter()
                .any(|change| change.index.saturating_add(1) == n && change.master_alone && change.index > 0)
    }

    /// Whether a head of size `n` is the transition head of a change of the log rules (entry `n − 1` is a manifest
    /// that changed them, not the genesis, within the remembered history). Nodes keep such heads for good and serve
    /// them to followers that catch up (docs/06 §5 "Übergänge beim Aufholen").
    #[must_use]
    pub fn is_transition_head(&self, n: u64) -> bool {
        n >= 2
            && n <= self.size
            && self.rules.iter().any(|change| change.index > 0 && change.index.saturating_add(1) == n)
    }

    /// Like [`NetState::apply`], and notes in `transitions` a change of the log rules made by this entry: what it
    /// takes to check its transition head later (the rules before it, whether the net key signed it alone, the cards
    /// of those log operators and witnesses - from this state or from `extra`, e.g. the entries ahead).
    pub fn apply_tracked<C: Cards + ?Sized>(
        &mut self,
        entry: &[u8],
        extra: &C,
        transitions: &mut Transitions,
    ) -> Applied {
        let index = self.size;
        let applied = self.apply(entry);
        if applied == Applied::Accepted && index > 0 && self.last_rules_change() == index {
            let before = self.rules.len().checked_sub(2).and_then(|position| self.rules.get(position));
            if let (Some(before), Some(change)) = (before, self.rules.back()) {
                let mut cards = BTreeMap::new();
                for id in before.rules.logs.iter().chain(&before.rules.witnesses) {
                    if let Some(card) = self.card_of(id).or_else(|| extra.card(id)) {
                        cards.insert(id.clone(), card.clone());
                    }
                }
                transitions.push(Transition {
                    index,
                    rules: before.rules.clone(),
                    master_alone: change.master_alone,
                    cards,
                    master: self.manifest.card.clone(),
                });
            }
        }
        applied
    }

    /// Checks a witnessed head of size `n ≤ size + 1` (docs/06 §5): signed by a log operator of the rules for its
    /// size, valid at `now_ms`, cosigned by `witness_threshold` of their witnesses - or, for the transition head of a
    /// change by a manifest signed by the net key alone ([`NetState::rescue_head`]), signed by the first log operator
    /// of those rules and cosigned by the net key ([`WitnessedHead::check_rescue`]). Cards come from `cards`.
    pub fn check_witnessed<C: Cards + ?Sized>(&self, value: &WitnessedHead, cards: &C, now_ms: i64) -> NetResult<Head> {
        let size = value.size()?;
        let rules =
            self.rules_for_head(size).ok_or_else(|| NetError::forbidden("head: no known log rules for its size"))?;
        match value.check(&self.net, &rules, cards, now_ms) {
            Ok(head) => Ok(head),
            Err(error) if self.rescue_head(size) => {
                value.check_rescue(&self.net, &rules, &self.manifest.card, cards, now_ms).map_err(|_| error)
            }
            Err(error) => Err(error),
        }
    }

    /// The log rules for a head that covers the entries in `ahead` beyond this state (fetched, not replayed yet;
    /// docs/06 §5 "Folgende Knoten", step 4). It agrees with replay for every manifest replay accepts:
    /// - only manifests before the head's last entry with exactly the next possible version count (current + 1;
    ///   every one that checks out widens the window by one) - old or far-off versions can never be accepted;
    /// - their signers must be able to count on replay: the net key with co-signers that have a card (from this
    ///   state or the entries ahead - cards are self-certifying), or admins with the right `rules` only (known here,
    ///   or delegated by the net key among the entries ahead), at least as many as the smallest `approvals.rules`
    ///   of the current manifest and of the manifests counted so far (the one in force on replay is one of them);
    /// - replay could still take them at their time: `exp` after their `iat` and after the own log clock;
    /// - each such manifest (and each delegation needed for it) is verified; at most [`MAX_AHEAD_CHECKS`] checks.
    ///
    /// If none of the manifests that check out changes the rules: [`RulesAhead::Known`] with the current ones.
    /// If one does, only replaying a copy tells ([`RulesAhead::Replay`]). If the bounds are exceeded (too many
    /// manifests, checks or cards to decide): [`RulesAhead::Refuse`] - the head is not taken, nothing is replayed.
    #[must_use]
    pub fn rules_ahead(&self, ahead: &Ahead) -> RulesAhead {
        let current = self.manifest.log_rules();
        if ahead.version != self.manifest.version || ahead.net != self.net || ahead.too_many {
            return RulesAhead::Refuse;
        }
        let mut checks = AheadChecks { ahead, left: MAX_AHEAD_CHECKS, admins: BTreeMap::new() };
        let first = self.manifest.version.saturating_add(1);
        let mut next = first;
        let mut changes = false;
        let mut approvals = self.manifest.approvals.rules;
        for statement in &ahead.manifests {
            let Ok(manifest) = Manifest::from_body(statement.body()) else { continue };
            if manifest.version < first || manifest.version > next || manifest.card.id() != &self.net {
                continue;
            }
            match self.manifest_may_count(statement, approvals, &mut checks) {
                None => return RulesAhead::Refuse,
                Some(false) => {}
                Some(true) => {
                    if manifest.version == next {
                        next = next.saturating_add(1);
                    }
                    changes |= manifest.log_rules() != current;
                    approvals = approvals.min(manifest.approvals.rules);
                }
            }
        }
        if changes { RulesAhead::Replay } else { RulesAhead::Known(current) }
    }

    /// Whether replay could still take `statement` at its time: it expires after its `iat` and after the own log
    /// clock (the replay time is at least both).
    fn may_be_in_time(&self, statement: &Statement) -> bool {
        let (iat, exp) = statement.times();
        exp > iat.max(self.clock)
    }

    /// Whether a manifest among the entries ahead can count on replay as far as its signers and its time go (see
    /// [`NetState::rules_ahead`]; `approvals`: the fewest admins with `rules` that may be enough); `None`:
    /// undecidable within the bounds.
    fn manifest_may_count(
        &self,
        statement: &Statement,
        approvals: usize,
        checks: &mut AheadChecks<'_>,
    ) -> Option<bool> {
        let signers = statement.claimed_signers();
        let by_master = signers.contains(&&self.net);
        if !self.may_be_in_time(statement) || (!by_master && signers.len() < approvals) {
            return Some(false);
        }
        let mut cards: Vec<&KeyCard> = Vec::with_capacity(signers.len());
        for signer in &signers {
            if self.compromised.contains(*signer) {
                return Some(false);
            }
            let card = if by_master {
                match self.card_of(signer).or_else(|| checks.ahead.cards.get(*signer)) {
                    Some(card) => card,
                    // No card anywhere: replay can not verify it either - unless cards were dropped (bounds).
                    None if checks.ahead.cards_full => return None,
                    None => return Some(false),
                }
            } else {
                match self.rules_admin_card(signer) {
                    Some(card) => card,
                    None => match checks.delegated_admin(signer, &self.manifest.card)? {
                        Some(card) => card,
                        None => return Some(false),
                    },
                }
            };
            cards.push(card);
        }
        checks.spend()?;
        Some(statement.verify(&cards, cards.len()).is_ok())
    }

    /// The card of an admin with the right `rules` in this state (any current delegation; the time is not known).
    fn rules_admin_card(&self, id: &Id) -> Option<&KeyCard> {
        if self.compromised.contains(id) {
            return None;
        }
        match self.grants.delegations.get(id) {
            Some(Grant { data: Data::Delegation { rights, card }, .. }) if rights.has(Right::Rules) => Some(card),
            _ => None,
        }
    }

    /// Whether a manifest is signed validly and acceptably by the net key (co-signers with a card from the log) or
    /// only by admins with the right `rules` known here - as many as `approvals.rules` asks for if it is the next
    /// version (`next`; further ahead a manifest in between may have lowered it, so one is enough). A signer that is
    /// not known here as admin with `rules` (a stranger, a sealed node, an admin with other rights) gives `Unknown`:
    /// a delegation among the entries ahead may give it the right.
    fn manifest_signed_here(&self, statement: &Statement, next: bool) -> Signed {
        let signers = statement.claimed_signers();
        let by_master = signers.contains(&&self.net);
        let mut cards: Vec<&KeyCard> = Vec::with_capacity(signers.len());
        for signer in &signers {
            if self.compromised.contains(*signer) {
                return Signed::Invalid;
            }
            let card = if by_master { self.card_of(signer) } else { self.rules_admin_card(signer) };
            match card {
                Some(card) => cards.push(card),
                None => return Signed::Unknown,
            }
        }
        let needed = if next { self.manifest.approvals.rules } else { 1 };
        if !by_master && signers.len() < needed {
            return Signed::Invalid; // all known here, too few: replay can never take it
        }
        if statement.verify(&cards, cards.len()).is_ok() { Signed::Valid } else { Signed::Invalid }
    }

    /// Before fetching the entries of a witnessed head beyond this state that does not pass the pre-check under the
    /// current log rules ([`WitnessedHead::precheck`]; docs/06 §5 "Folgende Knoten", step 2): `latest`, the
    /// source's current manifest at log index `index`, must show that a manifest change lies ahead - a manifest of
    /// this network with a higher version, at `index ≥ size`, that replay could still take at its time, validly and
    /// acceptably signed by the net key or by admins with `rules` known here ([`NetState::manifest_signed_here`];
    /// with signers not known here as such, the head must instead be validly signed by a log operator of the current
    /// rules). Whenever the head's operator has a known card, the head's signature and time are verified. If the
    /// manifest comes before the head's last entry, its log rules hold for the head: signed by one of its log
    /// operators, enough cosignatures may count ([`WitnessedHead::precheck_cosigns`]). If the head ends with the next
    /// manifest, the current rules hold for it (or, for a manifest of the net key alone, the rescue form). `Ok`:
    /// fetch; `Err`: the head can not be one this node lacks, fetch nothing.
    pub fn may_fetch(&self, witnessed: &WitnessedHead, latest: &Statement, index: u64, now_ms: i64) -> NetResult<()> {
        let n = witnessed.size()?;
        if n <= self.size {
            return Err(NetError::format("head: not beyond the own log"));
        }
        if latest.net() != &self.net || Kind::parse(latest.kind()) != Some(Kind::Manifest) {
            return Err(NetError::format("source manifest: not a manifest of this network"));
        }
        let manifest = Manifest::from_body(latest.body())?;
        if manifest.version <= self.manifest.version || manifest.card.id() != &self.net || index < self.size {
            return Err(NetError::forbidden("source manifest: no manifest change ahead"));
        }
        if !self.may_be_in_time(latest) || latest.times().0 > now_ms.saturating_add(CLOCK_SKEW_MS) {
            return Err(NetError::forbidden("source manifest: replay could not take it at its time"));
        }
        if witnessed.cosigns.len() > crate::log::MAX_COSIGNS {
            return Err(NetError::TooLarge("cosigns".into()));
        }
        let operator = match witnessed.head.claimed_signers().as_slice() {
            [operator] => (*operator).clone(),
            _ => return Err(NetError::format("head: exactly one signer")),
        };
        let extra: Vec<KeyCard> = manifest.gateways.iter().filter_map(|gateway| gateway.card.clone()).collect();
        let cards = (self, extra);
        // The head itself, whenever its signer's card is known (Z3): a forged head never gets past this point.
        let head = match cards.card(&operator) {
            Some(card) => {
                let head = verify_head(&witnessed.head, &self.net, card)?;
                witnessed.head.check_time(now_ms)?;
                Some(head)
            }
            None => None,
        };
        let next = manifest.version == self.manifest.version.saturating_add(1);
        match self.manifest_signed_here(latest, next) {
            Signed::Valid => {}
            Signed::Invalid => return Err(NetError::forbidden("source manifest: not validly signed by keys that may")),
            Signed::Unknown => {
                // Signers not known here as admins with `rules`: only a head of a current log operator justifies it.
                if !self.manifest.logs.contains(&operator) || head.is_none() {
                    return Err(NetError::forbidden("source manifest: signers unknown here"));
                }
            }
        }
        if index.saturating_add(1) < n {
            let rules = manifest.log_rules();
            if !rules.logs.contains(&operator) {
                return Err(NetError::forbidden("head: not signed by a log operator of the newest manifest"));
            }
            witnessed.precheck_cosigns(&self.net, head.as_ref(), &rules, &cards, now_ms)?;
        } else if index.saturating_add(1) == n && next {
            // The head ends with the next manifest: the rules from before it - the current ones - hold for it.
            let current = self.manifest.log_rules();
            if !current.logs.contains(&operator) {
                return Err(NetError::forbidden("head: not signed by a log operator of the current rules"));
            }
            // The rescue form only counts for a head of the first operator (review 6, finding 1).
            let rescue = latest.claimed_signers() == [&self.net]
                && witnessed.signed_by_first(&current)
                && witnessed.precheck_rescue(&self.net, head.as_ref(), &self.manifest.card, now_ms);
            if !rescue {
                witnessed.precheck_cosigns(&self.net, head.as_ref(), &current, &cards, now_ms)?;
            }
        }
        Ok(())
    }

    /// Witnesses of the current manifest.
    #[must_use]
    pub fn witnesses(&self) -> &[Id] {
        &self.manifest.witnesses
    }

    /// Network ID.
    #[must_use]
    pub fn net(&self) -> &Id {
        &self.net
    }

    /// Number of entries replayed so far (accepted and skipped) - the index of the next entry.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The log clock: the largest time of an accepted entry.
    #[must_use]
    pub fn clock(&self) -> i64 {
        self.clock
    }

    /// Number of current member records (including ones expired less than 5 minutes ago).
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.grants.members.len()
    }
}

impl Cards for NetState {
    fn card(&self, id: &Id) -> Option<&KeyCard> {
        self.card_of(id)
    }
}

/// How [`NetState::rules_ahead`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesAhead {
    /// These rules hold for the head.
    Known(LogRules),
    /// A validly signed manifest among the entries may change the rules: replay the entries on a copy of the state
    /// and ask the copy ([`NetState::check_witnessed`]).
    Replay,
    /// Undecidable within the bounds (too many manifests, signature checks or cards): do not take the head.
    Refuse,
}

/// What entries fetched beyond the replayed log tell about the rules for heads, parsed without the state's lock:
/// the manifests before the last entry whose version may follow the state's (`version` + 1 … + 65), the
/// delegations with the right `rules` claimed by the net key alone (verified only when a manifest needs them), and
/// the key cards the entries carry (seals, delegations, start gateways - cards are self-certifying, so any source
/// is fine for checking signatures). Everything is bounded; beyond the bounds [`NetState::rules_ahead`] refuses.
#[derive(Debug, Clone)]
pub struct Ahead {
    net: Id,
    version: u64,
    manifests: Vec<Statement>,
    delegations: Vec<(Id, Statement, KeyCard)>,
    cards: BTreeMap<Id, KeyCard>,
    /// More manifests or delegations than kept.
    too_many: bool,
    /// Cards were dropped (a missing card means nothing then).
    cards_full: bool,
    /// The last entry is a manifest of this network validly signed by the net key alone (rescue, docs/06 §5).
    rescue: bool,
}

impl Ahead {
    /// Looks at the entries `entries` fetched beyond a state of the network `master.id()` whose manifest has
    /// version `version` (garbage is ignored). At most one signature check (the last entry, for the rescue).
    #[must_use]
    pub fn parse(master: &KeyCard, version: u64, entries: &[Vec<u8>]) -> Self {
        let mut ahead = Self {
            net: master.id().clone(),
            version,
            manifests: Vec::new(),
            delegations: Vec::new(),
            cards: BTreeMap::new(),
            too_many: false,
            cards_full: false,
            rescue: false,
        };
        // Versions beyond this window can never be accepted within one head (each step needs a checked manifest).
        let window = version.saturating_add(1)..=version.saturating_add(1).saturating_add(MAX_AHEAD_CHECKS as u64);
        for (offset, entry) in entries.iter().enumerate() {
            let Ok(statement) = parse_entry(entry) else { continue };
            if statement.net() != master.id() {
                continue;
            }
            let last = offset.saturating_add(1) == entries.len();
            match Kind::parse(statement.kind()) {
                Some(Kind::Manifest) => {
                    let Ok(manifest) = Manifest::from_body(statement.body()) else { continue };
                    let next = window.contains(&manifest.version);
                    for card in manifest.gateways.into_iter().filter_map(|gateway| gateway.card) {
                        ahead.add_card(card);
                    }
                    if !next {
                        continue;
                    }
                    if last {
                        ahead.rescue =
                            statement.claimed_signers() == [master.id()] && statement.verify(&[master], 1).is_ok();
                    } else if ahead.manifests.len() >= MAX_AHEAD_MANIFESTS {
                        ahead.too_many = true;
                    } else {
                        ahead.manifests.push(statement);
                    }
                }
                Some(Kind::Delegation) => {
                    let Ok(delegation) = Delegation::from_body(statement.body()) else { continue };
                    if !last && delegation.rights.has(Right::Rules) && statement.claimed_signers() == [master.id()] {
                        if ahead.delegations.len() >= MAX_AHEAD_DELEGATIONS {
                            ahead.too_many = true;
                        } else {
                            ahead.delegations.push((delegation.admin.clone(), statement, delegation.card.clone()));
                        }
                    }
                    ahead.add_card(delegation.card);
                }
                Some(Kind::Seal) => {
                    if let Some(card) = Seal::from_body(statement.body()).ok().and_then(|seal| seal.card) {
                        ahead.add_card(card);
                    }
                }
                _ => {}
            }
        }
        ahead
    }

    fn add_card(&mut self, card: KeyCard) {
        if self.cards.contains_key(card.id()) {
            return;
        }
        if self.cards.len() >= MAX_AHEAD_CARDS {
            self.cards_full = true;
            return;
        }
        self.cards.insert(card.id().clone(), card);
    }

    /// The head that ends with these entries may be the transition head of a rescue (its last entry is a manifest
    /// validly signed by the net key alone, with a version that may follow): if it is not witnessed by the rules,
    /// only replaying a copy tells whether the net key's cosignature counts ([`NetState::check_witnessed`]).
    #[must_use]
    pub fn may_rescue(&self) -> bool {
        self.rescue
    }
}

/// A change of the log rules that a follower passes while catching up (docs/06 §5 "Übergänge beim Aufholen"): before
/// it continues under the new rules, the transition head of exactly this change (size `index + 1`) must be
/// witnessed under the rules from before it - or, for a manifest of the net key alone, carry the rescue form (signed
/// by the first log operator of the old rules, cosigned by the net key). So a fork needs more than the 24 words or
/// the admins with `rules`: an old log operator's key and the old witness quorum, or the words and the key of the
/// first old log operator.
#[derive(Debug, Clone)]
pub struct Transition {
    /// Log index of the manifest that changed the rules.
    index: u64,
    /// The rules from before the change (they hold for its transition head).
    rules: LogRules,
    /// The manifest was signed by the net key alone (the rescue form counts).
    master_alone: bool,
    /// Cards of the log operators and witnesses of `rules`.
    cards: BTreeMap<Id, KeyCard>,
    /// The net key's card.
    master: KeyCard,
}

impl Transition {
    /// Log index of the manifest.
    #[must_use]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Size of its transition head (`index + 1`).
    #[must_use]
    pub fn size(&self) -> u64 {
        self.index.saturating_add(1)
    }

    /// Checks a fetched transition head: exactly this size, root `root` (that of the entries `[0, size)` this node
    /// fetched), signed by a log operator of the rules from before the change, cosigned by `witness_threshold` of
    /// their witnesses - or, for a change by the net key alone, signed by the first of those operators and cosigned
    /// by the net key (rescue form). No time check (a head from the past).
    pub fn check(&self, net: &Id, value: &WitnessedHead, root: &Hash) -> NetResult<Head> {
        if value.size()? != self.size() {
            return Err(NetError::format("transition head: other size"));
        }
        let head = match value.check_history(net, &self.rules, &self.cards) {
            Ok(head) => head,
            Err(error) if self.master_alone => {
                value.check_rescue_history(net, &self.rules, &self.master, &self.cards).map_err(|_| error)?
            }
            Err(error) => return Err(error),
        };
        if head.root() != root {
            return Err(NetError::forbidden("transition head: other entries than the ones fetched"));
        }
        Ok(head)
    }
}

/// The changes of the log rules passed by one replay (oldest first, at most [`MAX_RULES_HISTORY`] - beyond that
/// the oldest are dropped and [`Transitions::overflow`] says so).
#[derive(Debug, Clone, Default)]
pub struct Transitions {
    list: VecDeque<Transition>,
    overflow: bool,
}

impl Transitions {
    fn push(&mut self, transition: Transition) {
        if self.list.len() >= MAX_RULES_HISTORY {
            self.list.pop_front();
            self.overflow = true;
        }
        self.list.push_back(transition);
    }

    /// No change of the log rules was passed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// More changes than kept: the oldest ones can not be checked (a follower refuses; docs/06 §10).
    #[must_use]
    pub fn overflow(&self) -> bool {
        self.overflow
    }

    /// The changes, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &Transition> {
        self.list.iter()
    }

    /// Whether every change passed on the way to `last` (the verified head of size n that ends the entries, checked
    /// against the rules for its size) is endorsed (docs/06 §5 "Übergänge beim Aufholen") by the transition heads in
    /// `found` (roots from `tree`) - see [`Transitions::endorsement`] for the rules; this is the same walk with all
    /// heads at hand. Returns the transition heads to keep (verified, from `found`); `Err` if a change is not
    /// endorsed.
    pub fn verify(
        &self,
        net: &Id,
        tree: &Tree,
        last: &Head,
        found: &BTreeMap<u64, WitnessedHead>,
    ) -> NetResult<Vec<(u64, WitnessedHead)>> {
        let mut walk = self.endorsement(net, last)?;
        while let Some(transition) = walk.next() {
            let root = tree.root_at(transition.size())?;
            if !found.get(&transition.size()).is_some_and(|value| walk.offer(value, &root)) {
                walk.without_head()?;
            }
        }
        walk.finish()
    }

    /// Starts the walk over the changes passed on the way to `last` (the verified head of size n that ends the
    /// entries, checked against the rules for its size), newest first (docs/06 §5 "Übergänge beim Aufholen"). Each
    /// change is endorsed
    /// - at n − 1: by `last` itself (it is that change's transition head) - decided here;
    /// - otherwise by its own transition head ([`Endorsement::offer`], [`Transition::check`]);
    /// - or, if its transition head never came about (the operator took the next entry while waiting - only a
    ///   rescue manifest of the net key, docs/06 §5; [`Endorsement::without_head`]): when the very next entry is a
    ///   change by the net key alone that is endorsed itself, by a head signed by the **first** log operator of the
    ///   rules from before *this* change. So the old operator still vouches for the log that contains the change,
    ///   and the net key for the rescue (review 6, finding 1: any operator of those rules was enough before).
    ///
    /// One change at a time, so a follower fetches a transition head only when it is needed and stops at the first
    /// change that can not be endorsed (review 6, finding 4). `Err` if `last` can not end these changes.
    pub fn endorsement(&self, net: &Id, last: &Head) -> NetResult<Endorsement<'_>> {
        let mut walk =
            Endorsement { net: net.clone(), list: &self.list, pending: self.list.len(), later: None, keep: Vec::new() };
        if let Some(newest) = self.list.back() {
            if newest.size() > last.size() {
                return Err(NetError::format("transition beyond the head"));
            }
            if newest.size() == last.size() {
                if !newest.rules.logs.contains(last.operator()) {
                    return Err(NetError::forbidden("head: not signed by a log operator of the rules before it"));
                }
                walk.later = Some((newest.index, last.operator().clone(), newest.master_alone));
                walk.pending = walk.pending.saturating_sub(1);
            }
        }
        Ok(walk)
    }
}

/// The walk over the changes of the log rules a follower passes, newest first ([`Transitions::endorsement`]).
#[derive(Debug)]
pub struct Endorsement<'a> {
    net: Id,
    list: &'a VecDeque<Transition>,
    /// The changes `list[..pending]` are not decided yet.
    pending: usize,
    /// The endorsement of the change after the next one: (its index, the operator who signed, net key alone).
    later: Option<(u64, Id, bool)>,
    /// Verified transition heads to keep, newest first.
    keep: Vec<(u64, WitnessedHead)>,
}

impl<'a> Endorsement<'a> {
    /// The newest change not decided yet - its transition head is needed (`None`: every change is endorsed).
    #[must_use]
    pub fn next(&self) -> Option<&'a Transition> {
        let list: &'a VecDeque<Transition> = self.list;
        self.pending.checked_sub(1).and_then(|position| list.get(position))
    }

    /// Offers a transition head for [`Endorsement::next`] (`root`: that of the entries `[0, size)` this node holds).
    /// `true`: it endorses the change ([`Transition::check`]) - kept, and the walk moves on; `false`: it does not
    /// (nothing changes, another one may be offered).
    pub fn offer(&mut self, value: &WitnessedHead, root: &Hash) -> bool {
        let Some(transition) = self.next() else { return false };
        let Ok(head) = transition.check(&self.net, value, root) else { return false };
        self.keep.push((transition.size(), value.clone()));
        self.later = Some((transition.index, head.operator().clone(), transition.master_alone));
        self.pending = self.pending.saturating_sub(1);
        true
    }

    /// No transition head of its own for [`Endorsement::next`]: it is endorsed only if it hung before a rescue (the
    /// very next entry is an endorsed change by the net key alone whose head the first operator of the rules from
    /// before this change signed). `Err`: not endorsed - the follower stops here.
    pub fn without_head(&mut self) -> NetResult<()> {
        let Some(transition) = self.next() else { return Ok(()) };
        match &self.later {
            Some((index, operator, true))
                if *index == transition.size() && transition.rules.logs.first() == Some(operator) =>
            {
                self.later = Some((transition.index, operator.clone(), transition.master_alone));
                self.pending = self.pending.saturating_sub(1);
                Ok(())
            }
            _ => Err(NetError::forbidden(format!(
                "no transition head of size {} witnessed under the rules before log entry {}",
                transition.size(),
                transition.index
            ))),
        }
    }

    /// The verified transition heads to keep, oldest first - only when every change is endorsed.
    pub fn finish(self) -> NetResult<Vec<(u64, WitnessedHead)>> {
        if let Some(transition) = self.next() {
            return Err(NetError::forbidden(format!("change at log entry {} not endorsed yet", transition.index)));
        }
        let mut keep = self.keep;
        keep.reverse();
        Ok(keep)
    }
}

/// How a manifest is signed, as far as a state can tell ([`NetState::may_fetch`]).
enum Signed {
    /// By the net key or by admins with `rules` known here, all signatures valid.
    Valid,
    /// Invalid signatures, or signers that can never sign a manifest.
    Invalid,
    /// A signer is not known here at all (an admin delegated later?).
    Unknown,
}

/// The signature checks [`NetState::rules_ahead`] may still make, and the admins delegated ahead checked so far.
struct AheadChecks<'a> {
    ahead: &'a Ahead,
    left: usize,
    admins: BTreeMap<Id, Option<&'a KeyCard>>,
}

impl<'a> AheadChecks<'a> {
    /// One signature check; `None` when the budget is used up.
    fn spend(&mut self) -> Option<()> {
        self.left = self.left.checked_sub(1)?;
        Some(())
    }

    /// The card of `admin` if a delegation with `rules` by the net key among the entries ahead checks out
    /// (`Some(None)`: none does; `None`: budget used up, or delegations were dropped).
    fn delegated_admin(&mut self, admin: &Id, master: &KeyCard) -> Option<Option<&'a KeyCard>> {
        if let Some(known) = self.admins.get(admin) {
            return Some(*known);
        }
        let ahead = self.ahead;
        let mut found = None;
        for (id, statement, card) in &ahead.delegations {
            if id != admin {
                continue;
            }
            self.spend()?;
            if statement.verify(&[master], 1).is_ok() {
                found = Some(card);
                break;
            }
        }
        if found.is_none() && ahead.too_many {
            return None;
        }
        self.admins.insert(admin.clone(), found);
        Some(found)
    }
}

impl Cards for Ahead {
    fn card(&self, id: &Id) -> Option<&KeyCard> {
        self.cards.get(id)
    }
}

/// Exactly one signer (all kinds except manifest and seal).
fn one_signer(signers: &[Id]) -> NetResult<&Id> {
    match signers {
        [one] => Ok(one),
        _ => Err(NetError::format("entry: exactly one signer expected")),
    }
}
