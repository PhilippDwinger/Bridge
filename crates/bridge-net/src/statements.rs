//! Typed bodies of the statements of a network (docs/06 §3, §4).
//!
//! Every body is parsed strictly: exactly the allowed fields (unknown fields inside a body are refused), fixed
//! types, bounded lengths and counts. `to_body()` builds the JSON body and checks it with the same parser, so a
//! builder can never produce a body that others would refuse. The [`Body`] trait signs bodies into statements.

use std::collections::BTreeSet;

use bridge_core::crypto::sha256;
use bridge_core::encoding::{b64, b64_fixed};
use bridge_core::keys::check_url;
use bridge_core::statement::MAX_SIGNERS;
use bridge_core::{Draft, Id, Identity, KeyCard, Role, Statement};
use serde_json::{Map, Value, json};

use crate::error::{NetError, NetResult};
use crate::merkle::{Hash, MAX_TREE_SIZE};
use crate::names::{AdultPolicy, MAX_BLOCKLISTS, MAX_CONTACT_CHARS, NameRules, check_short, id_set};

/// One day in milliseconds.
pub const DAY_MS: i64 = 24 * 3600 * 1000;
/// Default lifetime of a delegation: 90 days.
pub const DELEGATION_LIFETIME_MS: i64 = 90 * DAY_MS;
/// Lifetime of a log head: 30 days.
pub const HEAD_LIFETIME_MS: i64 = 30 * DAY_MS;
/// Longest lifetime of a `home` statement: 30 days.
pub const HOME_MAX_LIFETIME_MS: i64 = 30 * DAY_MS;
/// Maximum length of a network name.
pub const MAX_NET_NAME_CHARS: usize = 64;
/// Maximum length of a network description.
pub const MAX_DESCRIPTION_CHARS: usize = 500;
/// Maximum length of a reason (revoke, ban).
pub const MAX_REASON_CHARS: usize = 200;
/// Maximum number of log operators in a manifest.
pub const MAX_LOGS: usize = 3;
/// Maximum number of witnesses in a manifest.
pub const MAX_WITNESSES: usize = 16;
/// Maximum number of start gateways in a manifest.
pub const MAX_GATEWAYS: usize = 8;
/// Highest number of required approvals (a statement has at most 16 signers).
pub const MAX_APPROVALS: usize = MAX_SIGNERS;
/// Highest proof-of-work difficulty a manifest may ask for (docs/04 §8).
pub const MAX_POW_BITS: u32 = bridge_core::pow::MAX_POW_BITS;
/// Highest member limit a manifest may set.
pub const MAX_MEMBERS_LIMIT: u64 = 1_000_000;
/// Highest daily entry limit a manifest may set.
pub const MAX_ENTRIES_PER_DAY_LIMIT: u64 = 100_000;
/// Maximum uses of one invite code.
pub const MAX_INVITE_USES: u32 = 1000;
/// Maximum number of services in one seal.
pub const MAX_SERVICES: usize = 8;

// ---------------------------------------------------------------------------------------------------------------
// Kinds

/// The kinds of statements of a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Rules of the network (log).
    Manifest,
    /// Admin rights from the net master key (log).
    Delegation,
    /// Invite code (log).
    Invite,
    /// Membership, level 0 (log).
    Member,
    /// Seal of level 1-3 with services (log).
    Seal,
    /// Revocation of a statement or an identity (log).
    Revoke,
    /// Ban of an identity (log).
    Ban,
    /// Signed log head (not in the log).
    Head,
    /// Witness cosignature of a head (not in the log).
    Cosign,
    /// Home gateway of a member (not in the log).
    Home,
    /// One version of a Bridge app (docs/07 §3; not in the log - hosts keep it).
    App,
    /// A name of an app, node or member (docs/08 §3; log).
    Name,
    /// An admin's label of a name or target (docs/08 §5; log).
    Label,
    /// A publisher's blocklist (docs/08 §9; not in the log - nodes keep the newest version).
    Blocklist,
    /// An agent card issued by a member (docs/10 §3; not in the log - the agent's home entry).
    Agent,
    /// A connection to another network (docs/10 §6; log, net key only).
    Federation,
    /// An app deleted by its owner (docs/07 §10; log, app key and owner).
    Retire,
}

impl Kind {
    /// The kinds that are entries of the transparency log.
    pub const LOG_KINDS: [Kind; 11] = [
        Kind::Manifest,
        Kind::Delegation,
        Kind::Invite,
        Kind::Member,
        Kind::Seal,
        Kind::Revoke,
        Kind::Ban,
        Kind::Name,
        Kind::Label,
        Kind::Federation,
        Kind::Retire,
    ];

    /// Wire name (`t`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Delegation => "delegation",
            Self::Invite => "invite",
            Self::Member => "member",
            Self::Seal => "seal",
            Self::Revoke => "revoke",
            Self::Ban => "ban",
            Self::Head => "head",
            Self::Cosign => "cosign",
            Self::Home => "home",
            Self::App => "app",
            Self::Name => "name",
            Self::Label => "label",
            Self::Blocklist => "blocklist",
            Self::Agent => "agent",
            Self::Federation => "federation",
            Self::Retire => "retire",
        }
    }

    /// The kind for a wire name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "manifest" => Self::Manifest,
            "delegation" => Self::Delegation,
            "invite" => Self::Invite,
            "member" => Self::Member,
            "seal" => Self::Seal,
            "revoke" => Self::Revoke,
            "ban" => Self::Ban,
            "head" => Self::Head,
            "cosign" => Self::Cosign,
            "home" => Self::Home,
            "app" => Self::App,
            "name" => Self::Name,
            "label" => Self::Label,
            "blocklist" => Self::Blocklist,
            "agent" => Self::Agent,
            "federation" => Self::Federation,
            "retire" => Self::Retire,
            _ => return None,
        })
    }

    /// Whether statements of this kind are log entries.
    #[must_use]
    pub fn is_log_kind(self) -> bool {
        Self::LOG_KINDS.contains(&self)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Body trait

/// A typed statement body.
pub trait Body: Sized {
    /// The statement kind this body belongs to.
    const KIND: Kind;

    /// Strict parse of a body (exact fields, types, bounds).
    fn from_body(body: &Value) -> NetResult<Self>;

    /// The JSON body (checked with [`Body::from_body`]).
    fn to_body(&self) -> NetResult<Value>;

    /// Parses the body of a statement after checking its kind. Does not verify signatures.
    fn from_statement(statement: &Statement) -> NetResult<Self> {
        if statement.kind() != Self::KIND.as_str() {
            return Err(NetError::format(format!("expected a {} statement", Self::KIND.as_str())));
        }
        Self::from_body(statement.body())
    }

    /// Signs this body as a statement of one signer.
    fn sign(&self, net: &Id, iat: i64, exp: i64, signer: &Identity) -> NetResult<Statement> {
        let draft = Draft { kind: Self::KIND.as_str(), net, iat, exp, body: self.to_body()? };
        Ok(Statement::sign(&draft, signer)?)
    }

    /// Signs this body as a statement of several signers (`sigs`, "k of n").
    fn sign_multi(&self, net: &Id, iat: i64, exp: i64, signers: &[&Identity]) -> NetResult<Statement> {
        let draft = Draft { kind: Self::KIND.as_str(), net, iat, exp, body: self.to_body()? };
        Ok(Statement::sign_multi(&draft, signers)?)
    }
}

/// `to_body` = build, then parse with the strict parser (a builder can never produce what others refuse).
pub(crate) fn checked<B: Body>(value: Value) -> NetResult<Value> {
    B::from_body(&value)?;
    Ok(value)
}

// ---------------------------------------------------------------------------------------------------------------
// Rights and services

/// A right an admin can be delegated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Right {
    /// Admit members, create invites.
    Members,
    /// Issue seals.
    Seals,
    /// Ban identities.
    Bans,
    /// Change the manifest (together with `approvals.rules` admins).
    Rules,
}

impl Right {
    /// All rights in wire order.
    pub const ALL: [Right; 4] = [Right::Members, Right::Seals, Right::Bans, Right::Rules];

    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Members => "members",
            Self::Seals => "seals",
            Self::Bans => "bans",
            Self::Rules => "rules",
        }
    }

    /// The right for a wire name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|right| right.as_str() == text)
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A set of rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Rights(u8);

impl Rights {
    /// No rights.
    pub const NONE: Rights = Rights(0);

    /// All rights.
    #[must_use]
    pub fn all() -> Self {
        Self::of(&Right::ALL)
    }

    /// The set of the given rights.
    #[must_use]
    pub fn of(rights: &[Right]) -> Self {
        Self(rights.iter().fold(0, |bits, right| bits | right.bit()))
    }

    /// Whether `right` is in the set.
    #[must_use]
    pub fn has(self, right: Right) -> bool {
        self.0 & right.bit() != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The rights in wire order.
    pub fn iter(self) -> impl Iterator<Item = Right> {
        Right::ALL.into_iter().filter(move |right| self.has(*right))
    }

    fn parse(value: Option<&Value>) -> NetResult<Self> {
        let list = value
            .and_then(Value::as_array)
            .filter(|list| (1..=Right::ALL.len()).contains(&list.len()))
            .ok_or_else(|| NetError::format("rights: 1..=4 rights"))?;
        let mut rights = Self::NONE;
        for item in list {
            let right =
                item.as_str().and_then(Right::parse).ok_or_else(|| NetError::format("rights: unknown right"))?;
            if rights.has(right) {
                return Err(NetError::format("rights: duplicate"));
            }
            rights.0 |= right.bit();
        }
        Ok(rights)
    }

    fn to_value(self) -> Value {
        Value::Array(self.iter().map(|right| json!(right.as_str())).collect())
    }
}

/// A service a sealed node offers (docs/06 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Service {
    /// Gateway ("Empfänger"): admits members, holds mailboxes, relays.
    Gateway,
    /// Log operator.
    Log,
    /// Witness.
    Witness,
    /// Watcher.
    Watch,
    /// Name service.
    Names,
    /// Storage.
    Storage,
    /// Compute.
    Compute,
    /// Web sites.
    Web,
}

impl Service {
    /// All services in wire order.
    pub const ALL: [Service; 8] = [
        Service::Gateway,
        Service::Log,
        Service::Witness,
        Service::Watch,
        Service::Names,
        Service::Storage,
        Service::Compute,
        Service::Web,
    ];

    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Log => "log",
            Self::Witness => "witness",
            Self::Watch => "watch",
            Self::Names => "names",
            Self::Storage => "storage",
            Self::Compute => "compute",
            Self::Web => "web",
        }
    }

    /// The service for a wire name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|service| service.as_str() == text)
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A set of services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Services(u8);

impl Services {
    /// No services.
    pub const NONE: Services = Services(0);

    /// The set of the given services.
    #[must_use]
    pub fn of(services: &[Service]) -> Self {
        Self(services.iter().fold(0, |bits, service| bits | service.bit()))
    }

    /// Whether `service` is in the set.
    #[must_use]
    pub fn has(self, service: Service) -> bool {
        self.0 & service.bit() != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Union of two sets.
    #[must_use]
    pub fn union(self, other: Services) -> Self {
        Self(self.0 | other.0)
    }

    /// The services in wire order.
    pub fn iter(self) -> impl Iterator<Item = Service> {
        Service::ALL.into_iter().filter(move |service| self.has(*service))
    }

    fn parse(value: Option<&Value>) -> NetResult<Self> {
        let list = value
            .and_then(Value::as_array)
            .filter(|list| list.len() <= MAX_SERVICES)
            .ok_or_else(|| NetError::format("services: 0..=8 services"))?;
        let mut services = Self::NONE;
        for item in list {
            let service =
                item.as_str().and_then(Service::parse).ok_or_else(|| NetError::format("services: unknown service"))?;
            if services.has(service) {
                return Err(NetError::format("services: duplicate"));
            }
            services.0 |= service.bit();
        }
        Ok(services)
    }

    fn to_value(self) -> Value {
        Value::Array(self.iter().map(|service| json!(service.as_str())).collect())
    }
}

/// How identities join a network (and which template a network was made from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JoinMode {
    /// Everybody may join (proof-of-work only under load).
    Open,
    /// Only with an invite code.
    Invite,
    /// Only an admin admits members.
    Closed,
}

impl JoinMode {
    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Invite => "invite",
            Self::Closed => "closed",
        }
    }

    fn parse(value: Option<&Value>, what: &str) -> NetResult<Self> {
        match value.and_then(Value::as_str) {
            Some("open") => Ok(Self::Open),
            Some("invite") => Ok(Self::Invite),
            Some("closed") => Ok(Self::Closed),
            _ => Err(NetError::format(format!("{what}: open, invite or closed"))),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Manifest

/// Join rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Join {
    /// Join mode.
    pub mode: JoinMode,
    /// Proof-of-work bits for joining (0-28).
    pub pow_bits: u32,
}

/// Number of distinct admins needed for critical changes ("Mehr-Augen").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approvals {
    /// Admins with right `rules` for a manifest change without the master key (1-16).
    pub rules: usize,
    /// Admins with right `seals` for a seal of level 3 without the master key (1-16).
    pub seal3: usize,
}

/// A start gateway of the manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayEntry {
    /// Node ID.
    pub id: Id,
    /// Address.
    pub url: String,
    /// Optional key card of the node (role `node`, same ID) - lets everybody verify what this gateway signs before
    /// it has a seal.
    pub card: Option<KeyCard>,
}

/// Rules for Bridge apps in the network (docs/07 §3): optional manifest field `apps`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppRules {
    /// Lowest level an owner needs to publish apps (0-3; without the field: 0).
    pub min_level: u8,
}

/// Rules of the watchers (docs/06 §11.3): optional manifest field `watch`, all times in seconds. Without the field
/// the defaults ([`WatchRules::default`]) hold. The state checks `member_age_s`, `seal_s` and `seals_per_day`; the other
/// fields steer the watchers and are public that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchRules {
    /// Minimum age of a membership (and distance to the end of the last ban) for a member seal (1 s - 365 days).
    pub member_age_s: u64,
    /// Time between two probes of one node (1 s - 1 day).
    pub probe_interval_s: u64,
    /// How long a node must have passed probes, and the window of the success ratio (1 s - 30 days).
    pub node_observe_s: u64,
    /// Minimum share of passed probes in the window, in percent (50-100).
    pub success_pct: u64,
    /// Failed probes in a row until the watcher revokes its seal (1-100).
    pub fail_limit: u64,
    /// Longest lifetime of a watcher's seal (60 s - 90 days).
    pub seal_s: u64,
    /// A seal is renewed when less than this is left (1 s .. `seal_s`, exclusive).
    pub renew_s: u64,
    /// Seals one watcher may issue per day (1-10,000).
    pub seals_per_day: u64,
}

impl Default for WatchRules {
    fn default() -> Self {
        Self {
            member_age_s: 7 * 86_400,
            probe_interval_s: 300,
            node_observe_s: 86_400,
            success_pct: 90,
            fail_limit: 3,
            seal_s: 30 * 86_400,
            renew_s: 7 * 86_400,
            seals_per_day: 1_000,
        }
    }
}

/// Bounds of the fields of [`WatchRules`] (inclusive), in wire order.
const WATCH_FIELDS: [(&str, u64, u64); 8] = [
    ("member_age_s", 1, 365 * 86_400),
    ("probe_interval_s", 1, 86_400),
    ("node_observe_s", 1, 30 * 86_400),
    ("success_pct", 50, 100),
    ("fail_limit", 1, 100),
    ("seal_s", 60, 90 * 86_400),
    ("renew_s", 1, 90 * 86_400),
    ("seals_per_day", 1, 10_000),
];

/// The services a watcher may put into a level-1 seal (docs/06 §11.2): a fixed list, the manifest can not widen it.
pub const WATCH_SERVICES: [Service; 3] = [Service::Web, Service::Storage, Service::Compute];

impl WatchRules {
    /// Longest lifetime of a watcher's seal in milliseconds.
    #[must_use]
    pub fn seal_ms(&self) -> i64 {
        secs_to_ms(self.seal_s)
    }

    /// Minimum membership age in milliseconds.
    #[must_use]
    pub fn member_age_ms(&self) -> i64 {
        secs_to_ms(self.member_age_s)
    }

    /// Renewal threshold in milliseconds.
    #[must_use]
    pub fn renew_ms(&self) -> i64 {
        secs_to_ms(self.renew_s)
    }

    /// Probe interval in milliseconds.
    #[must_use]
    pub fn probe_interval_ms(&self) -> i64 {
        secs_to_ms(self.probe_interval_s)
    }

    /// Observation time (and window) in milliseconds.
    #[must_use]
    pub fn node_observe_ms(&self) -> i64 {
        secs_to_ms(self.node_observe_s)
    }

    fn parse(object: &Map<String, Value>) -> NetResult<Self> {
        let names: Vec<&str> = WATCH_FIELDS.iter().map(|(name, _, _)| *name).collect();
        let watch = sub_object(object, "watch", &names)?;
        let mut values = [0u64; 8];
        for (value, (name, min, max)) in values.iter_mut().zip(WATCH_FIELDS) {
            *value = number(watch, name, min, max)?;
        }
        let [member_age_s, probe_interval_s, node_observe_s, success_pct, fail_limit, seal_s, renew_s, seals_per_day] =
            values;
        if renew_s >= seal_s {
            return Err(NetError::format("watch.renew_s: must be below watch.seal_s"));
        }
        Ok(Self {
            member_age_s,
            probe_interval_s,
            node_observe_s,
            success_pct,
            fail_limit,
            seal_s,
            renew_s,
            seals_per_day,
        })
    }

    fn to_value(self) -> Value {
        json!({
            "member_age_s": self.member_age_s,
            "probe_interval_s": self.probe_interval_s,
            "node_observe_s": self.node_observe_s,
            "success_pct": self.success_pct,
            "fail_limit": self.fail_limit,
            "seal_s": self.seal_s,
            "renew_s": self.renew_s,
            "seals_per_day": self.seals_per_day,
        })
    }
}

/// Highest `watch.seals_per_day` a manifest with these limits may set: a quarter of `log_entries_per_day`, at least 1
/// (docs/06 §11.3).
#[must_use]
pub fn max_watch_seals_per_day(limits: &Limits) -> u64 {
    (limits.log_entries_per_day / 4).max(1)
}

/// Seconds (bounded by the parser) to milliseconds.
fn secs_to_ms(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(i64::MAX / 1000).saturating_mul(1000)
}

/// Limits of the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of members (1-1,000,000).
    pub members: u64,
    /// Maximum number of log entries per day (1-100,000).
    pub log_entries_per_day: u64,
}

/// The manifest: rules of the network (docs/06 §4). Field `card` carries the key card of the net master key
/// (role `net`, ID = network ID) so that everybody holding the log can verify master signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    /// Name (1-64 characters).
    pub name: String,
    /// Description (0-500 characters, line breaks allowed).
    pub description: String,
    /// Version: 1 for the genesis manifest, +1 for every change.
    pub version: u64,
    /// The template the network was created from.
    pub template: JoinMode,
    /// Join rules.
    pub join: Join,
    /// Multi-admin approvals.
    pub approvals: Approvals,
    /// Log operators (1-3).
    pub logs: Vec<Id>,
    /// Witnesses (1-16).
    pub witnesses: Vec<Id>,
    /// Cosignatures needed for a witnessed head (1 ≤ threshold ≤ witnesses).
    pub witness_threshold: usize,
    /// Start gateways (1-8).
    pub gateways: Vec<GatewayEntry>,
    /// Limits.
    pub limits: Limits,
    /// Key card of the net master key.
    pub card: KeyCard,
    /// Rules for apps (optional field `apps`, docs/07 §3; `None` = not in the body, the defaults hold).
    pub apps: Option<AppRules>,
    /// Rules of the watchers (optional field `watch`, docs/06 §11.3; `None` = not in the body, the defaults hold).
    pub watch: Option<WatchRules>,
    /// Short name of the network for addresses `<name>.<short>` (optional field `short`, docs/08 §2).
    pub short: Option<String>,
    /// The operator's way to receive reports (optional field `contact`, docs/08 §2; `None`: flagged everywhere).
    pub contact: Option<String>,
    /// Name rules (optional field `names`, docs/08 §2; `None`: the defaults hold).
    pub names: Option<NameRules>,
    /// Whether 18+ content is allowed (optional field `adult`, docs/08 §2; `None`: forbidden).
    pub adult: Option<AdultPolicy>,
    /// Publishers of blocklists (optional field `blocklists`, docs/08 §9; only the field so far).
    pub blocklists: Option<Vec<Id>>,
}

/// Who runs and who witnesses the log: the part of a manifest that heads are checked against (docs/06 §5). Which
/// manifest's rules hold for a head depends on the head's size (`NetState::rules_for_head`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRules {
    /// Log operators (1-3); the first one without evidence against it is the active one.
    pub logs: Vec<Id>,
    /// Witnesses (1-16).
    pub witnesses: Vec<Id>,
    /// Cosignatures needed for a witnessed head.
    pub witness_threshold: usize,
}

/// Optional fields of the manifest (absent fields stay absent: older manifests keep their bytes).
const MANIFEST_OPTIONAL: [&str; 7] = ["apps", "watch", "short", "contact", "names", "adult", "blocklists"];

const MANIFEST_FIELDS: [&str; 12] = [
    "name",
    "description",
    "version",
    "template",
    "join",
    "approvals",
    "logs",
    "witnesses",
    "witness_threshold",
    "gateways",
    "limits",
    "card",
];

impl Manifest {
    /// A small network (docs/06 §4 "Vorlagen"): the owner node is log operator, witness and gateway, threshold 1,
    /// approvals 1/1, 100,000 members, 10,000 entries per day. `master_card` is the key card of the net master key.
    /// Set `gateways[0].card` to the owner node's card if it should count as gateway before its seal is logged.
    pub fn template(
        mode: JoinMode,
        name: &str,
        master_card: KeyCard,
        owner_node: &Id,
        owner_gateway_url: &str,
    ) -> NetResult<Self> {
        let manifest = Self {
            name: name.to_owned(),
            description: String::new(),
            version: 1,
            template: mode,
            join: Join { mode, pow_bits: 0 },
            approvals: Approvals { rules: 1, seal3: 1 },
            logs: vec![owner_node.clone()],
            witnesses: vec![owner_node.clone()],
            witness_threshold: 1,
            gateways: vec![GatewayEntry { id: owner_node.clone(), url: owner_gateway_url.to_owned(), card: None }],
            limits: Limits { members: 100_000, log_entries_per_day: 10_000 },
            card: master_card,
            apps: None,
            watch: None,
            short: None,
            contact: None,
            names: None,
            adult: None,
            blocklists: None,
        };
        manifest.to_body()?;
        Ok(manifest)
    }

    /// Who runs and witnesses the log under this manifest.
    #[must_use]
    pub fn log_rules(&self) -> LogRules {
        LogRules {
            logs: self.logs.clone(),
            witnesses: self.witnesses.clone(),
            witness_threshold: self.witness_threshold,
        }
    }

    /// Lowest level an owner needs to publish apps (`apps.min_level`, default 0).
    #[must_use]
    pub fn app_min_level(&self) -> u8 {
        self.apps.map_or(0, |apps| apps.min_level)
    }

    /// Rules of the watchers (`watch`, or the defaults without the field).
    #[must_use]
    pub fn watch_rules(&self) -> WatchRules {
        self.watch.unwrap_or_default()
    }

    /// Name rules (`names`, or the defaults without the field).
    #[must_use]
    pub fn name_rules(&self) -> NameRules {
        self.names.clone().unwrap_or_default()
    }

    /// Whether 18+ content is allowed (`adult`, default forbidden).
    #[must_use]
    pub fn adult_policy(&self) -> AdultPolicy {
        self.adult.unwrap_or(AdultPolicy::Forbidden)
    }

    /// A copy with the version increased by one - the start of every change.
    #[must_use]
    pub fn next_version(&self) -> Self {
        let mut next = self.clone();
        next.version = next.version.saturating_add(1);
        next
    }

    /// Checks the genesis manifest (log entry 0, docs/06 §6.1): kind `manifest`, network `net`, version 1, exactly
    /// one signer = the network ID, master card for `net`, valid signature.
    pub fn genesis(statement: &Statement, net: &Id) -> NetResult<Self> {
        let manifest = Self::from_statement(statement)?;
        if statement.net() != net || manifest.card.id() != net {
            return Err(NetError::format("genesis: other network"));
        }
        if manifest.version != 1 {
            return Err(NetError::format("genesis: version must be 1"));
        }
        if statement.claimed_signers() != [net] {
            return Err(NetError::forbidden("genesis: must be signed by the net key alone"));
        }
        statement.verify(&[&manifest.card], 1)?;
        Ok(manifest)
    }
}

impl Body for Manifest {
    const KIND: Kind = Kind::Manifest;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "manifest")?;
        fields(object, &MANIFEST_FIELDS, &MANIFEST_OPTIONAL, "manifest")?;
        let name = text(object, "name")?;
        check_text(name, 1, MAX_NET_NAME_CHARS, false, "name")?;
        let description = text(object, "description")?;
        check_text(description, 0, MAX_DESCRIPTION_CHARS, true, "description")?;
        let version = number(object, "version", 1, bridge_core::json::MAX_SAFE_INTEGER.unsigned_abs())?;
        let template = JoinMode::parse(object.get("template"), "template")?;

        let join = sub_object(object, "join", &["mode", "pow_bits"])?;
        let join = Join {
            mode: JoinMode::parse(join.get("mode"), "join.mode")?,
            pow_bits: u32::try_from(number(join, "pow_bits", 0, u64::from(MAX_POW_BITS))?)
                .map_err(|_| NetError::format("join.pow_bits"))?,
        };
        let approvals = sub_object(object, "approvals", &["rules", "seal3"])?;
        let approvals = Approvals {
            rules: small(number(approvals, "rules", 1, MAX_APPROVALS as u64)?),
            seal3: small(number(approvals, "seal3", 1, MAX_APPROVALS as u64)?),
        };
        let logs = id_list(object.get("logs"), MAX_LOGS, "logs")?;
        let witnesses = id_list(object.get("witnesses"), MAX_WITNESSES, "witnesses")?;
        let witness_threshold = small(number(object, "witness_threshold", 1, witnesses.len() as u64)?);
        let gateways = gateway_list(object.get("gateways"))?;
        let limits = sub_object(object, "limits", &["members", "log_entries_per_day"])?;
        let limits = Limits {
            members: number(limits, "members", 1, MAX_MEMBERS_LIMIT)?,
            log_entries_per_day: number(limits, "log_entries_per_day", 1, MAX_ENTRIES_PER_DAY_LIMIT)?,
        };
        let card = card(object.get("card"), "card")?;
        if card.role() != Role::Net {
            return Err(NetError::format("card: must be the net master key (role net)"));
        }
        // The net key is never log operator or witness: its cosignature counts only in the rescue (docs/06 §4, §5).
        if logs.contains(card.id()) || witnesses.contains(card.id()) {
            return Err(NetError::format("logs/witnesses: the net key can not be log operator or witness"));
        }
        let apps = if object.contains_key("apps") {
            let apps = sub_object(object, "apps", &["min_level"])?;
            let min_level =
                u8::try_from(number(apps, "min_level", 0, 3)?).map_err(|_| NetError::format("apps.min_level"))?;
            Some(AppRules { min_level })
        } else {
            None
        };
        let watch = if object.contains_key("watch") { Some(WatchRules::parse(object)?) } else { None };
        if let Some(watch) = &watch {
            // One watcher's budget is at most a quarter of its pool of log entries per day (docs/06 §11.3): at least
            // four watchers fit, and none can use up the pool for the others.
            if watch.seals_per_day > max_watch_seals_per_day(&limits) {
                return Err(NetError::format(
                    "watch.seals_per_day: at most a quarter of limits.log_entries_per_day (at least 1)",
                ));
            }
        }
        let short = match object.get("short") {
            None => None,
            Some(_) => {
                let short = text(object, "short")?;
                check_short(short)?;
                Some(short.to_owned())
            }
        };
        let contact = match object.get("contact") {
            None => None,
            Some(_) => {
                let contact = text(object, "contact")?;
                check_text(contact, 1, MAX_CONTACT_CHARS, false, "contact")?;
                Some(contact.to_owned())
            }
        };
        let names = object.get("names").map(NameRules::parse).transpose()?;
        let adult = match object.get("adult") {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(AdultPolicy::parse)
                    .ok_or_else(|| NetError::format("adult: allowed or forbidden"))?,
            ),
        };
        let blocklists = match object.get("blocklists") {
            None => None,
            Some(value) => Some(id_set(Some(value), MAX_BLOCKLISTS, "blocklists")?),
        };
        Ok(Self {
            name: name.to_owned(),
            description: description.to_owned(),
            version,
            template,
            join,
            approvals,
            logs,
            witnesses,
            witness_threshold,
            gateways,
            limits,
            card,
            apps,
            watch,
            short,
            contact,
            names,
            adult,
            blocklists,
        })
    }

    fn to_body(&self) -> NetResult<Value> {
        let gateways: Vec<Value> = self
            .gateways
            .iter()
            .map(|gateway| {
                let mut entry = Map::new();
                entry.insert("id".into(), json!(gateway.id.as_str()));
                entry.insert("url".into(), json!(gateway.url));
                if let Some(card) = &gateway.card {
                    entry.insert("card".into(), card.to_value());
                }
                Value::Object(entry)
            })
            .collect();
        let mut body = json!({
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "template": self.template.as_str(),
            "join": {"mode": self.join.mode.as_str(), "pow_bits": self.join.pow_bits},
            "approvals": {"rules": self.approvals.rules, "seal3": self.approvals.seal3},
            "logs": ids_value(&self.logs),
            "witnesses": ids_value(&self.witnesses),
            "witness_threshold": self.witness_threshold,
            "gateways": gateways,
            "limits": {"members": self.limits.members, "log_entries_per_day": self.limits.log_entries_per_day},
            "card": self.card.to_value(),
        });
        if let Some(apps) = self.apps {
            body["apps"] = json!({"min_level": apps.min_level});
        }
        if let Some(watch) = self.watch {
            body["watch"] = watch.to_value();
        }
        if let Some(short) = &self.short {
            body["short"] = json!(short);
        }
        if let Some(contact) = &self.contact {
            body["contact"] = json!(contact);
        }
        if let Some(names) = &self.names {
            body["names"] = names.to_value();
        }
        if let Some(adult) = self.adult {
            body["adult"] = json!(adult.as_str());
        }
        if let Some(blocklists) = &self.blocklists {
            body["blocklists"] = ids_value(blocklists);
        }
        checked::<Self>(body)
    }
}

fn gateway_list(value: Option<&Value>) -> NetResult<Vec<GatewayEntry>> {
    let list = value
        .and_then(Value::as_array)
        .filter(|list| (1..=MAX_GATEWAYS).contains(&list.len()))
        .ok_or_else(|| NetError::format("gateways: 1..=8 entries"))?;
    let mut gateways: Vec<GatewayEntry> = Vec::with_capacity(list.len());
    for item in list {
        let entry = object(item, "gateway")?;
        fields(entry, &["id", "url"], &["card"], "gateway")?;
        let id = id(entry, "id")?;
        let url = text(entry, "url")?;
        check_url(url)?;
        let card = match entry.get("card") {
            None => None,
            Some(value) => {
                let card = card(Some(value), "gateway.card")?;
                if card.id() != &id || card.role() != Role::Node {
                    return Err(NetError::format("gateway.card: must be the node's own card"));
                }
                Some(card)
            }
        };
        if gateways.iter().any(|known| known.id == id) {
            return Err(NetError::format("gateways: duplicate"));
        }
        gateways.push(GatewayEntry { id, url: url.to_owned(), card });
    }
    Ok(gateways)
}

// ---------------------------------------------------------------------------------------------------------------
// Delegation, invite, member

/// Admin rights given by the net master key. `card` is the admin's key card (role `admin`) - so everybody holding
/// the log can verify what the admin signs.
#[derive(Debug, Clone, PartialEq)]
pub struct Delegation {
    /// Admin ID.
    pub admin: Id,
    /// Rights (1-4).
    pub rights: Rights,
    /// The admin's key card.
    pub card: KeyCard,
}

impl Body for Delegation {
    const KIND: Kind = Kind::Delegation;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "delegation")?;
        fields(object, &["admin", "rights", "card"], &[], "delegation")?;
        let admin = id(object, "admin")?;
        let rights = Rights::parse(object.get("rights"))?;
        let card = card(object.get("card"), "card")?;
        if card.id() != &admin || card.role() != Role::Admin {
            return Err(NetError::format("card: must be the admin's own card (role admin)"));
        }
        Ok(Self { admin, rights, card })
    }

    fn to_body(&self) -> NetResult<Value> {
        checked::<Self>(json!({
            "admin": self.admin.as_str(),
            "rights": self.rights.to_value(),
            "card": self.card.to_value(),
        }))
    }
}

/// An invite code (only its hash is public).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invite {
    /// SHA-256 of the code.
    pub code_hash: Hash,
    /// How many members may join with it (1-1000).
    pub uses: u32,
}

impl Invite {
    /// The hash of an invite code as it goes into the log.
    #[must_use]
    pub fn hash_code(code: &str) -> Hash {
        sha256(code.as_bytes())
    }
}

impl Body for Invite {
    const KIND: Kind = Kind::Invite;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "invite")?;
        fields(object, &["code_hash", "uses"], &[], "invite")?;
        Ok(Self {
            code_hash: hash(object, "code_hash")?,
            uses: u32::try_from(number(object, "uses", 1, u64::from(MAX_INVITE_USES))?)
                .map_err(|_| NetError::format("uses"))?,
        })
    }

    fn to_body(&self) -> NetResult<Value> {
        checked::<Self>(json!({"code_hash": b64(&self.code_hash), "uses": self.uses}))
    }
}

/// Membership (level 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Member ID.
    pub member: Id,
    /// Hash of the invite code used to join, if any.
    pub invite: Option<Hash>,
}

impl Body for Member {
    const KIND: Kind = Kind::Member;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "member")?;
        fields(object, &["member"], &["invite"], "member")?;
        let invite = if object.contains_key("invite") { Some(hash(object, "invite")?) } else { None };
        Ok(Self { member: id(object, "member")?, invite })
    }

    fn to_body(&self) -> NetResult<Value> {
        let mut object = Map::new();
        object.insert("member".into(), json!(self.member.as_str()));
        if let Some(invite) = &self.invite {
            object.insert("invite".into(), json!(b64(invite)));
        }
        checked::<Self>(Value::Object(object))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Seal, revoke, ban

/// A seal: level 1-3 and the services of the subject. Seals with service `gateway` must carry the subject's node
/// card with addresses (docs/06 §3), so the log lists all gateways with their addresses.
#[derive(Debug, Clone, PartialEq)]
pub struct Seal {
    /// The sealed identity.
    pub subject: Id,
    /// Level 1-3.
    pub level: u8,
    /// Services (0-8).
    pub services: Services,
    /// The subject's key card (required with `gateway`).
    pub card: Option<KeyCard>,
}

impl Body for Seal {
    const KIND: Kind = Kind::Seal;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "seal")?;
        fields(object, &["subject", "level", "services"], &["card"], "seal")?;
        let subject = id(object, "subject")?;
        let level = u8::try_from(number(object, "level", 1, 3)?).map_err(|_| NetError::format("level"))?;
        let services = Services::parse(object.get("services"))?;
        let card = match object.get("card") {
            None => None,
            Some(value) => {
                let card = card(Some(value), "card")?;
                if card.id() != &subject || card.role() == Role::Net {
                    return Err(NetError::format("card: must be the subject's own card"));
                }
                Some(card)
            }
        };
        if services.has(Service::Gateway)
            && !card.as_ref().is_some_and(|card| card.role() == Role::Node && !card.urls().is_empty())
        {
            return Err(NetError::format("seal: a gateway needs its node card with urls"));
        }
        Ok(Self { subject, level, services, card })
    }

    fn to_body(&self) -> NetResult<Value> {
        let mut object = Map::new();
        object.insert("subject".into(), json!(self.subject.as_str()));
        object.insert("level".into(), json!(self.level));
        object.insert("services".into(), self.services.to_value());
        if let Some(card) = &self.card {
            object.insert("card".into(), card.to_value());
        }
        checked::<Self>(Value::Object(object))
    }
}

/// What a revocation is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeTarget {
    /// One statement, by its hash.
    Statement(Hash),
    /// Everything an identity received; with `cascade` (master only) also everything it issued.
    Identity {
        /// The identity.
        id: Id,
        /// Also invalidate what it issued (stolen keys).
        cascade: bool,
    },
}

/// A revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoke {
    /// Target.
    pub target: RevokeTarget,
    /// Reason (0-200 characters).
    pub reason: String,
}

impl Body for Revoke {
    const KIND: Kind = Kind::Revoke;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "revoke")?;
        let target = if object.contains_key("statement") {
            fields(object, &["statement", "reason"], &[], "revoke")?;
            RevokeTarget::Statement(hash(object, "statement")?)
        } else {
            fields(object, &["identity", "cascade", "reason"], &[], "revoke")?;
            let cascade =
                object.get("cascade").and_then(Value::as_bool).ok_or_else(|| NetError::format("cascade: bool"))?;
            RevokeTarget::Identity { id: id(object, "identity")?, cascade }
        };
        let reason = text(object, "reason")?;
        check_text(reason, 0, MAX_REASON_CHARS, false, "reason")?;
        Ok(Self { target, reason: reason.to_owned() })
    }

    fn to_body(&self) -> NetResult<Value> {
        checked::<Self>(match &self.target {
            RevokeTarget::Statement(hash) => json!({"statement": b64(hash), "reason": self.reason}),
            RevokeTarget::Identity { id, cascade } => {
                json!({"identity": id.as_str(), "cascade": cascade, "reason": self.reason})
            }
        })
    }
}

/// A ban (its duration is the statement's lifetime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    /// The banned identity.
    pub subject: Id,
    /// Reason (0-200 characters).
    pub reason: String,
}

impl Body for Ban {
    const KIND: Kind = Kind::Ban;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "ban")?;
        fields(object, &["subject", "reason"], &[], "ban")?;
        let reason = text(object, "reason")?;
        check_text(reason, 0, MAX_REASON_CHARS, false, "reason")?;
        Ok(Self { subject: id(object, "subject")?, reason: reason.to_owned() })
    }

    fn to_body(&self) -> NetResult<Value> {
        checked::<Self>(json!({"subject": self.subject.as_str(), "reason": self.reason}))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Head, cosign, home (not in the log)

/// Body of a signed log head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadBody {
    /// Tree size.
    pub size: u64,
    /// Root of the tree of that size.
    pub root: Hash,
}

impl Body for HeadBody {
    const KIND: Kind = Kind::Head;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "head")?;
        fields(object, &["size", "root"], &[], "head")?;
        Ok(Self { size: number(object, "size", 0, MAX_TREE_SIZE)?, root: hash(object, "root")? })
    }

    fn to_body(&self) -> NetResult<Value> {
        checked::<Self>(json!({"size": self.size, "root": b64(&self.root)}))
    }
}

/// Body of a witness cosignature: binds to exactly one head (its hash) and repeats operator, size and root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosign {
    /// Hash of the head statement.
    pub head: Hash,
    /// The log operator that signed the head.
    pub log: Id,
    /// Tree size.
    pub size: u64,
    /// Root.
    pub root: Hash,
}

impl Body for Cosign {
    const KIND: Kind = Kind::Cosign;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "cosign")?;
        fields(object, &["head", "log", "size", "root"], &[], "cosign")?;
        Ok(Self {
            head: hash(object, "head")?,
            log: id(object, "log")?,
            size: number(object, "size", 0, MAX_TREE_SIZE)?,
            root: hash(object, "root")?,
        })
    }

    fn to_body(&self) -> NetResult<Value> {
        checked::<Self>(json!({
            "head": b64(&self.head),
            "log": self.log.as_str(),
            "size": self.size,
            "root": b64(&self.root),
        }))
    }
}

/// The home gateway of a member (docs/06 §8), signed by the member itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    /// Node ID of the gateway.
    pub node: Id,
}

impl Home {
    /// Checks a `home` statement of `member`: kind, network, single signer = the member, lifetime at most 30 days,
    /// valid at `now_ms`, signature. Whether the member is a member is the caller's check (state).
    pub fn check(statement: &Statement, net: &Id, member: &KeyCard, now_ms: i64) -> NetResult<Self> {
        let home = Self::from_statement(statement)?;
        if statement.net() != net {
            return Err(NetError::format("home: other network"));
        }
        if statement.claimed_signers() != [member.id()] {
            return Err(NetError::forbidden("home: must be signed by the member alone"));
        }
        let (iat, exp) = statement.times();
        if exp - iat > HOME_MAX_LIFETIME_MS {
            return Err(NetError::format("home: lifetime over 30 days"));
        }
        statement.check_time(now_ms)?;
        statement.verify(&[member], 1)?;
        Ok(home)
    }
}

impl Body for Home {
    const KIND: Kind = Kind::Home;

    fn from_body(body: &Value) -> NetResult<Self> {
        let object = object(body, "home")?;
        fields(object, &["node"], &[], "home")?;
        Ok(Self { node: id(object, "node")? })
    }

    fn to_body(&self) -> NetResult<Value> {
        checked::<Self>(json!({"node": self.node.as_str()}))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Strict field helpers

pub(crate) fn object<'a>(value: &'a Value, what: &str) -> NetResult<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| NetError::format(format!("{what}: not an object")))
}

/// Exactly the allowed fields: all `required` present, nothing besides `required` and `optional`.
pub(crate) fn fields(object: &Map<String, Value>, required: &[&str], optional: &[&str], what: &str) -> NetResult<()> {
    if let Some(unknown) =
        object.keys().find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(NetError::format(format!("{what}: unknown field {unknown:?}")));
    }
    if let Some(missing) = required.iter().find(|key| !object.contains_key(**key)) {
        return Err(NetError::format(format!("{what}: missing field {missing}")));
    }
    Ok(())
}

pub(crate) fn sub_object<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    required: &[&str],
) -> NetResult<&'a Map<String, Value>> {
    let inner = object.get(name).ok_or_else(|| NetError::format(format!("{name}: missing")))?;
    let inner = self::object(inner, name)?;
    fields(inner, required, &[], name)?;
    Ok(inner)
}

pub(crate) fn text<'a>(object: &'a Map<String, Value>, name: &str) -> NetResult<&'a str> {
    object.get(name).and_then(Value::as_str).ok_or_else(|| NetError::format(format!("{name}: missing or not a string")))
}

pub(crate) fn number(object: &Map<String, Value>, name: &str, min: u64, max: u64) -> NetResult<u64> {
    object
        .get(name)
        .and_then(Value::as_u64)
        .filter(|value| (min..=max).contains(value))
        .ok_or_else(|| NetError::format(format!("{name}: integer {min}..={max}")))
}

/// Narrows a number already bounded by a small maximum.
pub(crate) fn small(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

pub(crate) fn id(object: &Map<String, Value>, name: &str) -> NetResult<Id> {
    Ok(Id::parse(text(object, name)?)?)
}

pub(crate) fn hash(object: &Map<String, Value>, name: &str) -> NetResult<Hash> {
    Ok(b64_fixed::<32>(text(object, name)?, name)?)
}

pub(crate) fn card(value: Option<&Value>, what: &str) -> NetResult<KeyCard> {
    let value = value.ok_or_else(|| NetError::format(format!("{what}: missing")))?;
    Ok(KeyCard::from_value(value.clone())?)
}

/// Text rules: length in characters, no control characters (line breaks only where allowed).
pub fn check_text(text: &str, min_chars: usize, max_chars: usize, allow_newline: bool, what: &str) -> NetResult<()> {
    let count = text.chars().count();
    if count < min_chars || count > max_chars {
        return Err(NetError::format(format!("{what}: {min_chars}..={max_chars} characters")));
    }
    if text.chars().any(|c| c.is_control() && !(allow_newline && c == '\n')) {
        return Err(NetError::format(format!("{what}: control characters")));
    }
    Ok(())
}

/// 1..=max distinct IDs.
pub(crate) fn id_list(value: Option<&Value>, max: usize, what: &str) -> NetResult<Vec<Id>> {
    let list = value
        .and_then(Value::as_array)
        .filter(|list| (1..=max).contains(&list.len()))
        .ok_or_else(|| NetError::format(format!("{what}: 1..={max} ids")))?;
    let mut seen = BTreeSet::new();
    let mut ids = Vec::with_capacity(list.len());
    for item in list {
        let id = Id::parse(item.as_str().ok_or_else(|| NetError::format(format!("{what}: not a string")))?)?;
        if !seen.insert(id.clone()) {
            return Err(NetError::format(format!("{what}: duplicate")));
        }
        ids.push(id);
    }
    Ok(ids)
}

pub(crate) fn ids_value(ids: &[Id]) -> Value {
    Value::Array(ids.iter().map(|id| json!(id.as_str())).collect())
}

#[cfg(test)]
mod tests {
    use bridge_core::Role;

    use super::*;
    use crate::names::{AdultPolicy, NameRules};

    const T0: i64 = 1_794_200_000_000;

    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes(&[seed; 32], &[seed.wrapping_add(100); 32])
    }

    fn master() -> NetResult<(Identity, KeyCard)> {
        let master = identity(1);
        let card = master.key_card(Role::Net, None, T0)?;
        Ok((master, card))
    }

    fn node_card(node: &Identity) -> NetResult<KeyCard> {
        Ok(node.key_card_with(Role::Node, None, &["https://node.example/n".to_string()], None, T0)?)
    }

    fn manifest() -> NetResult<Manifest> {
        let (_, card) = master()?;
        Manifest::template(JoinMode::Invite, "Mein Netz", card, identity(2).id(), "https://node.example/n")
    }

    /// Changing one field of a valid body must be refused (`Value::Null` removes the field).
    fn refuse<B: Body + std::fmt::Debug>(valid: &Value, path: &[&str], bad: Value) {
        let mut value = valid.clone();
        let (last, parents) = path.split_last().unwrap_or((&"", &[]));
        let pointer: String = parents.iter().map(|key| format!("/{key}")).collect();
        if let Some(object) = value.pointer_mut(&pointer).and_then(Value::as_object_mut) {
            if bad.is_null() {
                object.remove(*last);
            } else {
                object.insert((*last).to_string(), bad.clone());
            }
        }
        assert_ne!(&value, valid, "{path:?} must change the body");
        assert!(B::from_body(&value).is_err(), "{path:?} = {bad} must be refused");
    }

    #[test]
    fn manifest_template_roundtrip_and_genesis() -> NetResult<()> {
        let (master, _) = master()?;
        let manifest = manifest()?;
        assert_eq!(manifest.logs, vec![identity(2).id().clone()]);
        assert_eq!(manifest.witness_threshold, 1);
        let body = manifest.to_body()?;
        assert_eq!(Manifest::from_body(&body)?, manifest);

        let net = master.id().clone();
        let genesis = manifest.sign(&net, T0, T0 + DAY_MS, &master)?;
        assert_eq!(Manifest::genesis(&genesis, &net)?, manifest);
        // Version 2, signed by somebody else, other net: no genesis
        assert!(Manifest::genesis(&manifest.next_version().sign(&net, T0, T0 + 1, &master)?, &net).is_err());
        assert!(Manifest::genesis(&manifest.sign(&net, T0, T0 + 1, &identity(3))?, &net).is_err());
        let other = identity(4).id().clone();
        assert!(Manifest::genesis(&manifest.sign(&other, T0, T0 + 1, &master)?, &other).is_err());
        assert!(Manifest::genesis(&manifest.sign_multi(&net, T0, T0 + 1, &[&master, &identity(3)])?, &net).is_err());
        // Wrong kind
        let ban = Ban { subject: other, reason: String::new() }.sign(&net, T0, T0 + 1, &master)?;
        assert!(Manifest::genesis(&ban, &net).is_err());
        Ok(())
    }

    #[test]
    fn manifest_constraints() -> NetResult<()> {
        let mut manifest = manifest()?;
        manifest.gateways[0].card = Some(node_card(&identity(2))?);
        let valid = manifest.to_body()?;
        let ids: Vec<String> = (10..30).map(|i| identity(i).id().to_string()).collect();
        let r = refuse::<Manifest>;
        r(&valid, &["extra"], json!(1));
        r(&valid, &["name"], json!(""));
        r(&valid, &["name"], json!("x".repeat(65)));
        r(&valid, &["name"], json!("a\nb"));
        r(&valid, &["name"], Value::Null);
        r(&valid, &["description"], json!("x".repeat(501)));
        r(&valid, &["description"], json!("bell\u{7}"));
        r(&valid, &["version"], json!(0));
        r(&valid, &["version"], json!(-1));
        r(&valid, &["version"], json!("1"));
        r(&valid, &["template"], json!("public"));
        r(&valid, &["join", "mode"], json!("everyone"));
        r(&valid, &["join", "pow_bits"], json!(29));
        r(&valid, &["join", "extra"], json!(0));
        r(&valid, &["approvals", "rules"], json!(0));
        r(&valid, &["approvals", "seal3"], json!(17));
        r(&valid, &["approvals", "seal3"], Value::Null);
        r(&valid, &["logs"], json!([]));
        r(&valid, &["logs"], json!(ids[..4]));
        r(&valid, &["logs"], json!([ids[0], ids[0]]));
        r(&valid, &["logs"], json!(["not-an-id"]));
        r(&valid, &["witnesses"], json!(ids[..17]));
        r(&valid, &["witness_threshold"], json!(0));
        r(&valid, &["witness_threshold"], json!(2));
        r(&valid, &["gateways"], json!([]));
        let gateway = |id: &str| json!({"id": id, "url": "https://g.example"});
        r(&valid, &["gateways"], Value::Array(ids[..9].iter().map(|id| gateway(id)).collect()));
        r(&valid, &["gateways"], json!([gateway(&ids[0]), gateway(&ids[0])]));
        r(&valid, &["gateways"], json!([{"id": ids[0], "url": "ftp://g.example"}]));
        r(&valid, &["gateways"], json!([{"id": ids[0], "url": "https://g.example", "x": 1}]));
        let foreign_card = node_card(&identity(5))?.to_value();
        r(&valid, &["gateways"], json!([{"id": ids[0], "url": "https://g.example", "card": foreign_card}]));
        r(&valid, &["limits", "members"], json!(1_000_001));
        r(&valid, &["limits", "members"], json!(0));
        r(&valid, &["limits", "log_entries_per_day"], json!(100_001));
        r(&valid, &["card"], identity(5).key_card(Role::Admin, None, 0)?.to_value());
        let mut tampered = master()?.1.to_value();
        tampered["name"] = json!("x");
        r(&valid, &["card"], tampered);
        // The optional `apps` field: min_level 0-3, nothing else in it.
        let mut with_apps = valid.clone();
        with_apps["apps"] = json!({"min_level": 2});
        assert_eq!(Manifest::from_body(&with_apps)?.app_min_level(), 2);
        assert_eq!(Manifest::from_body(&valid)?.app_min_level(), 0, "without the field: 0");
        assert_eq!(Manifest::from_body(&with_apps)?.to_body()?, with_apps, "kept exactly");
        assert_eq!(Manifest::from_body(&valid)?.to_body()?, valid, "not added");
        r(&with_apps, &["apps", "min_level"], json!(4));
        r(&with_apps, &["apps", "min_level"], json!(-1));
        r(&with_apps, &["apps", "min_level"], Value::Null);
        r(&with_apps, &["apps", "max"], json!(1));
        r(&with_apps, &["apps"], json!(1));
        // The optional `watch` field: exactly the eight fields, each within its bounds, renew below seal.
        let mut with_watch = valid.clone();
        with_watch["watch"] = WatchRules::default().to_value();
        assert_eq!(Manifest::from_body(&with_watch)?.watch_rules(), WatchRules::default());
        assert_eq!(Manifest::from_body(&with_watch)?.to_body()?, with_watch, "kept exactly");
        assert_eq!(Manifest::from_body(&valid)?.watch, None, "without the field: none");
        assert_eq!(Manifest::from_body(&valid)?.watch_rules(), WatchRules::default(), "defaults");
        for (name, min, max) in WATCH_FIELDS {
            r(&with_watch, &["watch", name], json!(max + 1));
            r(&with_watch, &["watch", name], json!(min - 1));
            r(&with_watch, &["watch", name], json!(-1));
            r(&with_watch, &["watch", name], json!("1"));
            r(&with_watch, &["watch", name], json!(1.5));
            r(&with_watch, &["watch", name], Value::Null);
        }
        r(&with_watch, &["watch", "extra"], json!(1));
        r(&with_watch, &["watch"], json!([]));
        r(&with_watch, &["watch", "renew_s"], json!(WatchRules::default().seal_s));
        // Review 8: one watcher's budget is at most a quarter of the daily log entries (10,000 → 2,500).
        let mut quarter = with_watch.clone();
        quarter["watch"]["seals_per_day"] = json!(2_500);
        assert!(Manifest::from_body(&quarter).is_ok());
        r(&with_watch, &["watch", "seals_per_day"], json!(2_501));
        let mut tiny = quarter.clone();
        tiny["limits"]["log_entries_per_day"] = json!(3);
        tiny["watch"]["seals_per_day"] = json!(1);
        assert!(Manifest::from_body(&tiny).is_ok(), "at least 1");
        r(&tiny, &["watch", "seals_per_day"], json!(2));
        let mut short = with_watch.clone();
        short["watch"]["seal_s"] = json!(60);
        short["watch"]["renew_s"] = json!(59);
        short["watch"]["member_age_s"] = json!(1);
        short["watch"]["probe_interval_s"] = json!(1);
        let rules = Manifest::from_body(&short)?.watch_rules();
        assert_eq!((rules.seal_ms(), rules.renew_ms(), rules.member_age_ms()), (60_000, 59_000, 1_000));
        // Phase 4 (docs/08 §2): short, contact, names, adult, blocklists - optional, kept exactly, strict.
        let mut phase4 = valid.clone();
        phase4["short"] = json!("meinnetz");
        phase4["contact"] = json!("abuse@example.org");
        phase4["names"] = json!({"min_level": 1, "quota": [0, 3, 20, 100], "reserved": ["sparkasse"]});
        phase4["adult"] = json!("allowed");
        phase4["blocklists"] = json!([ids[0]]);
        let parsed = Manifest::from_body(&phase4)?;
        assert_eq!(parsed.to_body()?, phase4, "kept exactly");
        assert_eq!(parsed.adult_policy(), AdultPolicy::Allowed);
        assert_eq!(parsed.name_rules().reserved, vec!["sparkasse".to_owned()]);
        let plain = Manifest::from_body(&valid)?;
        assert_eq!((plain.adult_policy(), plain.name_rules()), (AdultPolicy::Forbidden, NameRules::default()));
        assert_eq!((plain.short, plain.contact, plain.blocklists), (None, None, None));
        r(&phase4, &["short"], json!("Mein Netz"));
        r(&phase4, &["short"], json!("x"));
        r(&phase4, &["short"], json!("x".repeat(25)));
        r(&phase4, &["short"], json!(7));
        r(&phase4, &["contact"], json!(""));
        r(&phase4, &["contact"], json!("x".repeat(201)));
        r(&phase4, &["contact"], json!("a\nb"));
        r(&phase4, &["names", "min_level"], json!(4));
        r(&phase4, &["names", "quota"], json!([0, 1, 2]));
        r(&phase4, &["names", "extra"], json!(1));
        r(&phase4, &["adult"], json!("yes"));
        r(&phase4, &["blocklists"], json!([ids[0], ids[0]]));
        r(&phase4, &["blocklists"], json!(ids[..9]));
        let mut empty = phase4.clone();
        empty["blocklists"] = json!([]);
        assert!(Manifest::from_body(&empty).is_ok(), "an empty blocklist list is fine");
        // Limits at the edges are fine
        let mut edge = valid.clone();
        edge["limits"]["members"] = json!(MAX_MEMBERS_LIMIT);
        edge["join"]["pow_bits"] = json!(28);
        edge["witnesses"] = json!(ids[..16]);
        edge["witness_threshold"] = json!(16);
        edge["description"] = json!("Zeile 1\nZeile 2");
        assert!(Manifest::from_body(&edge).is_ok());
        Ok(())
    }

    #[test]
    fn other_bodies_roundtrip_and_refuse_bad_values() -> NetResult<()> {
        let admin = identity(6);
        let admin_card = admin.key_card(Role::Admin, None, T0)?;
        let delegation =
            Delegation { admin: admin.id().clone(), rights: Rights::of(&[Right::Seals]), card: admin_card };
        let body = delegation.to_body()?;
        assert_eq!(Delegation::from_body(&body)?, delegation);
        assert_eq!(body["rights"], json!(["seals"]));
        refuse::<Delegation>(&body, &["rights"], json!([]));
        refuse::<Delegation>(&body, &["rights"], json!(["seals", "seals"]));
        refuse::<Delegation>(&body, &["rights"], json!(["root"]));
        refuse::<Delegation>(&body, &["card"], identity(7).key_card(Role::Admin, None, 0)?.to_value());
        refuse::<Delegation>(&body, &["card"], admin.key_card(Role::Client, None, 0)?.to_value());
        refuse::<Delegation>(&body, &["card"], Value::Null);
        let all = Delegation { rights: Rights::all(), ..delegation };
        assert_eq!(all.to_body()?["rights"], json!(["members", "seals", "bans", "rules"]));

        let invite = Invite { code_hash: Invite::hash_code("K7Q2-M9XA"), uses: 5 };
        let body = invite.to_body()?;
        assert_eq!(Invite::from_body(&body)?, invite);
        refuse::<Invite>(&body, &["uses"], json!(0));
        refuse::<Invite>(&body, &["uses"], json!(1001));
        refuse::<Invite>(&body, &["code_hash"], json!(b64(&[0u8; 31])));
        refuse::<Invite>(&body, &["code_hash"], json!("K7Q2-M9XA"));

        let member = Member { member: identity(8).id().clone(), invite: Some(invite.code_hash) };
        let body = member.to_body()?;
        assert_eq!(Member::from_body(&body)?, member);
        let plain = Member { invite: None, ..member.clone() };
        assert_eq!(Member::from_body(&plain.to_body()?)?, plain);
        refuse::<Member>(&body, &["level"], json!(2));
        refuse::<Member>(&body, &["member"], json!("x"));

        let node = identity(9);
        let seal = Seal {
            subject: node.id().clone(),
            level: 2,
            services: Services::of(&[Service::Gateway, Service::Storage]),
            card: Some(node_card(&node)?),
        };
        let body = seal.to_body()?;
        assert_eq!(Seal::from_body(&body)?, seal);
        refuse::<Seal>(&body, &["level"], json!(0));
        refuse::<Seal>(&body, &["level"], json!(4));
        refuse::<Seal>(&body, &["services"], json!(["gateway", "gateway"]));
        refuse::<Seal>(&body, &["services"], json!(["teleport"]));
        refuse::<Seal>(&body, &["card"], Value::Null); // gateway without card
        refuse::<Seal>(&body, &["card"], node.key_card(Role::Node, None, 0)?.to_value()); // gateway without urls
        refuse::<Seal>(&body, &["card"], node_card(&identity(10))?.to_value()); // someone else's card
        let nine: Vec<&str> = Service::ALL.iter().map(|s| s.as_str()).chain(["web"]).collect();
        refuse::<Seal>(&body, &["services"], json!(nine));
        let bare = Seal { subject: node.id().clone(), level: 1, services: Services::NONE, card: None };
        assert_eq!(Seal::from_body(&bare.to_body()?)?, bare);

        for revoke in [
            Revoke { target: RevokeTarget::Statement([3; 32]), reason: "Fehler".into() },
            Revoke { target: RevokeTarget::Identity { id: node.id().clone(), cascade: true }, reason: String::new() },
        ] {
            let body = revoke.to_body()?;
            assert_eq!(Revoke::from_body(&body)?, revoke);
            refuse::<Revoke>(&body, &["reason"], json!("x".repeat(201)));
            refuse::<Revoke>(&body, &["reason"], Value::Null);
            refuse::<Revoke>(&body, &["extra"], json!(true));
        }
        let both = json!({"statement": b64(&[3; 32]), "identity": node.id().as_str(), "cascade": false, "reason": ""});
        assert!(Revoke::from_body(&both).is_err());
        assert!(Revoke::from_body(&json!({"identity": node.id().as_str(), "reason": ""})).is_err(), "cascade missing");

        let ban = Ban { subject: node.id().clone(), reason: "Spam".into() };
        let body = ban.to_body()?;
        assert_eq!(Ban::from_body(&body)?, ban);
        refuse::<Ban>(&body, &["subject"], json!(42));

        let head = HeadBody { size: 7, root: [1; 32] };
        let body = head.to_body()?;
        assert_eq!(HeadBody::from_body(&body)?, head);
        refuse::<HeadBody>(&body, &["size"], json!(MAX_TREE_SIZE + 1));
        refuse::<HeadBody>(&body, &["size"], json!(-1));

        let cosign = Cosign { head: [2; 32], log: node.id().clone(), size: 7, root: [1; 32] };
        let body = cosign.to_body()?;
        assert_eq!(Cosign::from_body(&body)?, cosign);
        refuse::<Cosign>(&body, &["log"], Value::Null);

        let home = Home { node: node.id().clone() };
        assert_eq!(Home::from_body(&home.to_body()?)?, home);
        assert!(Home::from_body(&json!("x")).is_err());
        Ok(())
    }

    #[test]
    fn home_check() -> NetResult<()> {
        let (master, _) = master()?;
        let net = master.id().clone();
        let member = identity(11);
        let card = member.key_card(Role::Client, None, T0)?;
        let home = Home { node: identity(2).id().clone() };
        let statement = home.sign(&net, T0, T0 + DAY_MS, &member)?;
        assert_eq!(Home::check(&statement, &net, &card, T0 + 1)?, home);
        assert_eq!(Home::check(&statement, &net, &card, T0 + DAY_MS), Err(NetError::Expired));
        let long = home.sign(&net, T0, T0 + HOME_MAX_LIFETIME_MS + 1, &member)?;
        assert!(Home::check(&long, &net, &card, T0).is_err());
        let foreign = home.sign(&net, T0, T0 + DAY_MS, &identity(12))?;
        assert!(Home::check(&foreign, &net, &card, T0).is_err());
        assert!(Home::check(&statement, identity(3).id(), &card, T0).is_err());
        Ok(())
    }

    #[test]
    fn kinds() {
        for kind in Kind::LOG_KINDS {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
            assert!(kind.is_log_kind());
        }
        for kind in [Kind::Head, Kind::Cosign, Kind::Home, Kind::App] {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
            assert!(!kind.is_log_kind());
        }
        assert_eq!(Kind::parse("env"), None);
    }
}
