//! Bridge apps at a node (docs/07 §2-§5): accepting versions, hosting them together with other hosts, serving them
//! to browsers.
//!
//! - **Accept** a version only if it verifies (form, both signatures, time - `bridge-core`), holds in the network
//!   (owner member with `apps.min_level`, owner and app not banned - `bridge-net`), lists this node as a host, and
//!   this node counts as one (seal with `web`). From the owner (`POST /v4/app/publish`, session), from another host
//!   of that version (`POST /v4/node/app`, signed by it), or - for apps hosted here - from anybody
//!   (`POST /v4/app/update`: the two signatures are the proof). Only versions above the app's **rank**: the highest
//!   (version, statement hash) this node decided on - accepted, refused, or the version that removed it as a host.
//!   The rank is kept after stopping (only ID, owner and rank), so neither a rollback nor a revival works.
//! - **Pay first**: accepting reserves the whole version against the owner's quota (pins with the sizes of the
//!   manifest, also for blobs that are not here yet) in the same transaction as the app row; apps per owner are
//!   bounded by level. Fetching registers a blob only while that reservation exists - it never creates a pin.
//! - **Fetch instead of push**: every round (30 s) a host asks up to 8 other hosts for their newest version - the
//!   cheap head form first (version + hash), the full manifest only when it is above the rank - offers its own to
//!   hosts that lack it (pausing after a refusal), and fetches missing blobs of a pending version: blob info first,
//!   the hash list only from a host that has the blob (checked against the ID), at most 64 new blobs per round,
//!   every part against its hash; a host that sends a wrong part is skipped for that blob. A round without progress
//!   is a failure: the next try waits longer, after 12 in a row the pending version is dropped (refused for good).
//!   Only when everything is here does it switch (database first, then memory) and keep the version before as the way
//!   back.
//! - **Stop** at once when the newest version no longer lists this node (a newer valid version that does not name
//!   it is a stop signal, wherever it comes from), the app or its owner is banned, the owner no longer qualifies, or
//!   the version expired: nothing is served any more and the blobs are unpinned. A host that moves to a newer version
//!   or stops because of one tells the hosts of its previous version that the new one does not name.
//! - **Serve** `GET /app/<app-id>/<path>` from the current version, with its own sandboxed origin (CSP `sandbox`
//!   without `allow-same-origin`), `nosniff`, the content type only from the manifest, the blob ID as ETag. Every
//!   part read from disk is checked again; large files are streamed (the transport bounds slow readers).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_core::app::{AppManifest, MAX_APP_LIFETIME_MS, MAX_APP_MANIFEST_BYTES, check_path};
use bridge_core::blob::{self, BlobId, HASH_PAGE, HashList, PART_BYTES};
use bridge_core::encoding::{b64_fixed, b64_var};
use bridge_core::json::{canonical, parse_strict};
use bridge_core::request::MAX_REQUEST_BYTES;
use bridge_core::{CLOCK_SKEW_MS, Id, KeyCard, SignedRequest, Statement};
use bridge_net::{NetError, check_standing, is_web_host, valid_hosts};
use bridge_store::{
    APP_PIN_PREFIX, AppLimits, AppRow, AppState, AppStored, BlobFiles, NewBlob, PartStored, Registered, Reservation,
    Store,
};
use bridge_transport::{BodyStream, Method, Request, Response};
use serde_json::{Map, Value, json};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;

use crate::blobs::quota_error;
use crate::network::Endpoint;
use crate::{Node, NodeError, NodeResult, body_object, lock};

/// The sandbox every app runs in (docs/07 §5): scripts, forms and popups, but an opaque origin of its own.
pub const APP_CSP: &str = "sandbox allow-scripts allow-forms allow-popups";
/// Stopped apps a node remembers (only ID, owner and rank each).
const MAX_STOPPED_APPS: u64 = 100_000;
/// Stopped apps of one owner a node remembers (beyond: that owner's oldest are forgotten).
const MAX_STOPPED_PER_OWNER: u64 = 1_024;
/// A stopped app may be forgotten this long after it stopped: every version that existed then has expired.
const FORGET_STOPPED_MS: i64 = MAX_APP_LIFETIME_MS + 24 * 3600 * 1000;
/// Other hosts asked per round and app.
const HOSTS_ASKED_PER_ROUND: usize = 8;
/// Parts fetched at once per blob.
const FETCH_WORKERS: usize = 8;
/// Blobs fetched at once per app version (so many small files do not come one after the other).
const BLOBS_AT_ONCE: usize = 4;
/// Blobs that are not here yet looked up (info, hash list) per round and pending version.
const LOOKUPS_PER_ROUND: usize = 64;
/// Hosts asked for one blob that is not here yet.
const SOURCES_PER_LOOKUP: usize = 8;
/// Rounds in a row without progress after which a pending version is dropped (refused for good).
const MAX_FETCH_FAILURES: u32 = 12;
/// The longest pause between two tries of a pending version, in rounds.
const MAX_PAUSE_ROUNDS: u32 = 16;
/// The longest pause before a host that refused a version is offered the same one again.
const MAX_OFFER_PAUSE_MS: i64 = 6 * 3600 * 1000;
/// Remembered refused offers (app, host).
const MAX_OFFER_PAUSES: usize = 4096;
/// Runs at once that tell the hosts of a previous version about a newer one.
const NOTIFY_RUNS: usize = 4;
/// Incomplete blobs of the current version looked at per round (repair).
const REPAIRS_PER_ROUND: usize = 1024;
/// Longest wait for a slow browser per streamed part (the transport also bounds the whole stream).
const STREAM_PART_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest `POST /v4/node/app` body.
const MAX_OFFER_BYTES: usize = MAX_APP_MANIFEST_BYTES + MAX_REQUEST_BYTES + 1024;
/// Largest `POST /v4/app/manifest` body.
const MAX_QUERY_BYTES: usize = 1024;

/// The listed hosts of a version that count in the network, with their cards from the log.
pub(crate) type Hosts = Vec<(Id, Option<KeyCard>)>;
/// Order of versions: higher `version` first, then the larger statement hash (all hosts agree).
pub(crate) type Rank = (u64, [u8; 32]);

/// One verified version of an app.
#[derive(Clone)]
pub(crate) struct Version {
    pub(crate) statement: Arc<Statement>,
    pub(crate) manifest: Arc<AppManifest>,
}

impl Version {
    fn new(statement: Statement, manifest: AppManifest) -> Self {
        Self { statement: Arc::new(statement), manifest: Arc::new(manifest) }
    }

    pub(crate) fn rank(&self) -> Rank {
        (self.manifest.version, self.statement.hash_bytes())
    }

    fn bytes(&self) -> Vec<u8> {
        self.statement.canonical_bytes().to_vec()
    }

    fn blob_keys(&self) -> BTreeSet<String> {
        self.manifest.blobs().into_iter().map(|(id, _)| id.to_text()).collect()
    }
}

/// An app this node hosts (in memory; the database has the same).
struct Hosted {
    owner: Id,
    current: Option<Version>,
    previous: Option<Version>,
    pending: Option<Version>,
    /// The highest rank decided on: only versions above it are taken (the current or pending one again is fine).
    floor: Rank,
    /// Rounds in a row in which the pending version made no progress, and when to try it next.
    failures: u32,
    retry_at: i64,
}

impl Hosted {
    fn newest(&self) -> Option<&Version> {
        self.pending.as_ref().or(self.current.as_ref())
    }

    /// Whether `rank` is the current or the pending version.
    fn holds(&self, rank: &Rank) -> bool {
        [&self.current, &self.pending].into_iter().flatten().any(|version| &version.rank() == rank)
    }

    fn row(&self, app: &Id, now: i64) -> AppRow {
        AppRow {
            app: app.to_string(),
            owner: self.owner.to_string(),
            version: self.floor.0,
            hash: Some(self.floor.1),
            state: if self.current.is_some() { AppState::Serving } else { AppState::Fetching },
            current: self.current.as_ref().map(Version::bytes),
            previous: self.previous.as_ref().map(Version::bytes),
            pending: self.pending.as_ref().map(Version::bytes),
            updated: now,
        }
    }

    /// The blobs kept besides a pending version: those of the current and the previous version.
    fn kept_blobs(&self) -> Vec<String> {
        let mut keep: BTreeSet<String> = BTreeSet::new();
        for version in [&self.current, &self.previous].into_iter().flatten() {
            keep.extend(version.blob_keys());
        }
        keep.into_iter().collect()
    }
}

/// The rank a stored row remembers (rows from before schema 6 have no hash: then the best of their manifests).
fn row_floor(row: &AppRow) -> Rank {
    let mut floor = (row.version, row.hash.unwrap_or_default());
    if row.hash.is_none() {
        for bytes in [&row.current, &row.previous, &row.pending].into_iter().flatten() {
            let Ok(statement) = AppManifest::parse_statement(bytes) else { continue };
            let Ok(manifest) = AppManifest::from_body(statement.body()) else { continue };
            floor = floor.max((manifest.version, statement.hash_bytes()));
        }
    }
    floor
}

/// A pause before offering a version to a host again (after it refused).
struct Pause {
    rank: Rank,
    refusals: u32,
    until: i64,
}

/// The apps of one node.
pub(crate) struct Apps {
    hosted: Mutex<BTreeMap<Id, Hosted>>,
    /// Serializes changes (accept, switch, drop, stop): database and memory never diverge.
    changes: tokio::sync::Mutex<()>,
    wake: Notify,
    /// Refused offers per (app, host).
    pauses: Mutex<HashMap<(Id, Id), Pause>>,
    /// Bounds the runs that tell old hosts about a newer version.
    notify: Arc<Semaphore>,
}

/// How a node keeps its stopped apps (the active limits do not matter for a stop).
fn stopped_limits(max_active: u64, now: i64) -> AppLimits {
    AppLimits {
        max_active,
        max_active_per_owner: u64::MAX,
        max_stopped: MAX_STOPPED_APPS,
        max_stopped_per_owner: MAX_STOPPED_PER_OWNER,
        forget_before: now.saturating_sub(FORGET_STOPPED_MS),
    }
}

impl Apps {
    fn with(hosted: BTreeMap<Id, Hosted>) -> Self {
        Self {
            hosted: Mutex::new(hosted),
            changes: tokio::sync::Mutex::new(()),
            wake: Notify::new(),
            pauses: Mutex::new(HashMap::new()),
            notify: Arc::new(Semaphore::new(NOTIFY_RUNS)),
        }
    }

    /// The apps stored for `net`: at most `max` (the most recently changed first, then by ID) - any beyond (e.g.
    /// after the limit was lowered) are stopped for good. Each version is verified again (form and signatures; an
    /// expired one is loaded anyway and stopped normally in its first round, so its rank is kept).
    pub(crate) fn load(store: &Store, net: &Id, max: u64, now: i64) -> Result<Self, String> {
        let keep = usize::try_from(max).unwrap_or(usize::MAX);
        for _ in 0..1000 {
            let beyond = store.apps_beyond(keep, 1000).map_err(|e| e.to_string())?;
            if beyond.is_empty() {
                break;
            }
            for app in beyond {
                let Some(row) = store.app_get(&app).map_err(|e| e.to_string())? else { continue };
                let floor = row_floor(&row);
                let row = AppRow { version: floor.0, hash: Some(floor.1), updated: now, ..row };
                store
                    .app_stop(&row, &stopped_limits(max, now), &format!("{APP_PIN_PREFIX}{app}"))
                    .map_err(|e| e.to_string())?;
                tracing::warn!(app = %app, "more apps than max_hosted_apps: this one is no longer hosted here");
            }
        }
        let rows = store.apps_active(keep).map_err(|e| e.to_string())?;
        let mut hosted = BTreeMap::new();
        for row in rows {
            let (Ok(app), Ok(owner)) = (Id::parse(&row.app), Id::parse(&row.owner)) else { continue };
            let version = |bytes: &Option<Vec<u8>>| {
                let statement = AppManifest::parse_statement(bytes.as_deref()?).ok()?;
                // Form and signatures only: the time is checked in the round (an expired version stops normally).
                let (iat, _) = statement.times();
                let manifest = AppManifest::verify(&statement, net, iat).ok()?;
                (manifest.app == app).then(|| Version::new(statement, manifest))
            };
            let mut entry = Hosted {
                current: version(&row.current),
                previous: version(&row.previous),
                pending: version(&row.pending),
                owner,
                floor: row_floor(&row),
                failures: 0,
                retry_at: 0,
            };
            for version in [&entry.current, &entry.pending].into_iter().flatten() {
                entry.floor = entry.floor.max(version.rank());
            }
            hosted.insert(app, entry);
        }
        Ok(Self::with(hosted))
    }

    /// No apps (a node without a network).
    pub(crate) fn empty() -> Self {
        Self::with(BTreeMap::new())
    }

    /// Wakes the hosting loop (a part went missing, a version came in).
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    fn ids(&self) -> Vec<Id> {
        lock(&self.hosted).keys().cloned().collect()
    }

    fn hosts(&self, app: &Id) -> bool {
        lock(&self.hosted).contains_key(app)
    }

    fn floor(&self, app: &Id) -> Option<Rank> {
        lock(&self.hosted).get(app).map(|hosted| hosted.floor)
    }

    fn newest(&self, app: &Id) -> Option<Version> {
        lock(&self.hosted).get(app).and_then(Hosted::newest).cloned()
    }

    pub(crate) fn current(&self, app: &Id) -> Option<Version> {
        lock(&self.hosted).get(app).and_then(|hosted| hosted.current.clone())
    }

    fn pending(&self, app: &Id) -> Option<Version> {
        lock(&self.hosted).get(app).and_then(|hosted| hosted.pending.clone())
    }

    /// Whether the pending version of `app` may be tried now (not in a pause after failures).
    fn due(&self, app: &Id, now: i64) -> bool {
        lock(&self.hosted).get(app).is_some_and(|hosted| hosted.retry_at <= now)
    }

    /// Whether `version` may be offered to `host` now (not in a pause after a refusal of the same version).
    fn may_offer(&self, app: &Id, host: &Id, rank: &Rank, now: i64) -> bool {
        lock(&self.pauses)
            .get(&(app.clone(), host.clone()))
            .is_none_or(|pause| &pause.rank != rank || pause.until <= now)
    }

    /// Remembers how `host` answered an offer of `rank`: a refusal pauses offers (interval × 2ⁿ, at most 6 hours).
    fn offered(&self, app: &Id, host: &Id, rank: Rank, accepted: bool, interval_ms: i64, now: i64) {
        let mut pauses = lock(&self.pauses);
        let key = (app.clone(), host.clone());
        if accepted {
            pauses.remove(&key);
            return;
        }
        if pauses.len() >= MAX_OFFER_PAUSES && !pauses.contains_key(&key) {
            pauses.retain(|_, pause| pause.until > now);
            if pauses.len() >= MAX_OFFER_PAUSES {
                pauses.clear();
            }
        }
        let refusals = pauses.get(&key).filter(|pause| pause.rank == rank).map_or(0, |pause| pause.refusals) + 1;
        let pause = interval_ms.saturating_mul(1i64 << refusals.min(20)).min(MAX_OFFER_PAUSE_MS);
        pauses.insert(key, Pause { rank, refusals, until: now.saturating_add(pause) });
    }
}

/// Why a version does not hold here (any more).
enum Invalid {
    /// For good: stop hosting (banned, owner no member, expired, this node not a host).
    Stop(String),
    /// Not now (the network log is still loading).
    Later,
}

/// What became of a version handed to this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Taken {
    /// The app is hosted here; `true`: the version is served now (else its files are being fetched).
    Hosted(bool),
    /// It is a newer version without this node: the app is no longer hosted here.
    Stopped,
}

impl Taken {
    fn active(self) -> bool {
        self == Self::Hosted(true)
    }
}

/// What one round of fetching a pending version did.
enum Fetched {
    /// Everything is here: it is served now.
    Active,
    /// `stored`: parts and blobs that came in; `more`: blobs left for the next round (the lookup limit was hit).
    Progress { stored: u64, more: bool },
}

/// The hosting loop: every round one task per hosted app (never two for the same app); the tasks end with the
/// node (aborted together with this loop).
pub(crate) async fn run(node: Node) {
    let Some(network) = node.network() else { return };
    let interval = network.timing.apps.max(Duration::from_millis(10));
    let mut running: JoinSet<()> = JoinSet::new();
    let mut busy: HashMap<tokio::task::Id, Id> = HashMap::new();
    loop {
        while let Some(done) = running.try_join_next_with_id() {
            let task = match &done {
                Ok((task, ())) => *task,
                Err(error) => error.id(),
            };
            busy.remove(&task);
        }
        for app in node.inner.apps.ids() {
            if !busy.values().any(|known| known == &app) {
                let handle = running.spawn(node.clone().sync_app(app.clone()));
                busy.insert(handle.id(), app);
            }
        }
        tokio::select! {
            () = node.inner.apps.wake.notified() => {}
            () = tokio::time::sleep(interval) => {}
        }
    }
}

fn not_found() -> NodeError {
    NodeError::not_found()
}

fn full(message: &str) -> NodeError {
    NodeError { retry_after: Some(3600), ..NodeError::new(429, "QUOTA_EXCEEDED", message) }
}

/// `{"version":n,"hash":"…"}` of a head answer.
fn parse_head(body: &Map<String, Value>) -> Option<Rank> {
    let version = body.get("version").and_then(Value::as_u64)?;
    let hash = b64_fixed::<32>(body.get("hash").and_then(Value::as_str)?, "hash").ok()?;
    Some((version, hash))
}

impl Node {
    /// Routes `/v4/app/...` (apps exist only in a network).
    pub(crate) async fn route_app(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        if self.network().is_none() {
            return Err(not_found());
        }
        match (request.method, request.path.as_str()) {
            (Method::Post, "/v4/app/publish") => self.app_publish(request, now).await,
            (Method::Post, "/v4/app/manifest") => {
                self.inner.guard.admit_read(request.peer, now)?;
                self.app_manifest(&request.body, now)
            }
            (Method::Post, "/v4/app/update") => {
                self.inner.guard.admit_read(request.peer, now)?;
                self.app_update(&request.body, now).await
            }
            _ => Err(not_found()),
        }
    }

    /// Verifies a version (outside the lock of the network core) and checks it against the network: returns it with
    /// the hosts that count.
    fn check_version(&self, statement: Statement, now: i64) -> NodeResult<(Version, Hosts)> {
        let manifest = AppManifest::verify(&statement, &self.inner.net, now)?;
        if self.app_blocked(&manifest.app, &manifest.owner, now) {
            return Err(NetError::Banned.into());
        }
        let hosts = self.with_core(|core| -> NodeResult<_> {
            check_standing(&core.state, &manifest, now)?;
            Ok(valid_hosts(&core.state, &manifest, now))
        })??;
        Ok((Version::new(statement, manifest), hosts))
    }

    /// Whether this node is a host of a version that counts.
    fn hosts_me(&self, version: &Version, hosts: &[(Id, Option<KeyCard>)]) -> bool {
        let me = self.inner.identity.id();
        version.manifest.hosts.contains(me) && hosts.iter().any(|(id, _)| id == me)
    }

    /// The bounds for app rows; `per_owner`: the apps the owner may have here (only checked for a new app).
    fn app_limits(&self, per_owner: u64, now: i64) -> AppLimits {
        AppLimits { max_active_per_owner: per_owner, ..stopped_limits(self.inner.guard.limits().max_hosted_apps, now) }
    }

    fn apps_interval_ms(&self) -> i64 {
        let interval = self.network().map_or(Duration::from_secs(30), |network| network.timing.apps);
        i64::try_from(interval.as_millis()).unwrap_or(30_000).max(10)
    }

    /// `POST /v4/app/publish` (session of the owner): the body is the app statement. Answer
    /// `{"ok":true,"version":n,"active":bool}` (`active`: served now; else its files are being fetched - or, for a
    /// newer version without this node, the app stopped here).
    async fn app_publish(&self, request: &Request, now: i64) -> NodeResult<Vec<u8>> {
        let caller = self.session(request, now)?;
        let statement = AppManifest::parse_statement(&request.body)?;
        let (version, hosts) = self.check_version(statement, now)?;
        if version.manifest.owner != caller {
            return Err(NodeError::forbidden("only the owner publishes an app"));
        }
        if !self.inner.apps.hosts(&version.manifest.app) {
            if !version.manifest.hosts.contains(self.inner.identity.id()) {
                return Err(NodeError::forbidden("this node is not a host of this app"));
            }
            if !self.hosts_me(&version, &hosts) {
                return Err(NodeError::forbidden("this node may not host apps (it needs a seal with the service web)"));
            }
        }
        let number = version.manifest.version;
        let taken = self.take_version(version, &hosts, now).await?;
        Ok(json!({"ok": true, "version": number, "active": taken.active()}).to_string().into_bytes())
    }

    /// `POST /v4/node/app` `{"manifest":<statement>,"rq":<rq op "app">}`: another host of the app offers its
    /// version (`rq.body = {"manifest":"<hash of the statement>"}`, signed by that host). Checked like a publish,
    /// cheap first: request for this node and fresh, caller a web host of the network, signature, once; then the
    /// version, the caller one of its hosts, this node one too (or the app hosted here: a stop signal).
    pub(crate) async fn app_offer_in(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let me = self.inner.identity.id().clone();
        if body.len() > MAX_OFFER_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "offer too large"));
        }
        let Value::Object(outer) = parse_strict(body, MAX_OFFER_BYTES)? else {
            return Err(NodeError::bad_format("offer: not an object"));
        };
        if outer.len() != 2 {
            return Err(NodeError::bad_format("offer: exactly manifest and rq"));
        }
        let rq = outer.get("rq").cloned().ok_or_else(|| NodeError::bad_format("offer: rq missing"))?;
        if canonical(&rq)?.len() > MAX_REQUEST_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "request too large"));
        }
        let request = SignedRequest::from_value(rq)?;
        request.check(&me, now)?;
        if request.op() != "app" {
            return Err(NodeError::bad_format("op: expected app"));
        }
        let caller = self
            .with_core(|core| {
                is_web_host(&core.state, request.iss(), now).then(|| core.state.card_of(request.iss()).cloned())
            })?
            .flatten()
            .ok_or_else(|| NodeError::forbidden("only hosts of the network offer apps"))?;
        request.verify(&caller)?;
        self.inner.guard.remember_nonce(
            request.iss(),
            request.nonce(),
            request.iat().saturating_add(CLOCK_SKEW_MS),
            now,
        )?;
        let value = outer.get("manifest").cloned().ok_or_else(|| NodeError::bad_format("offer: manifest missing"))?;
        let statement = Statement::from_value_with_limit(value, MAX_APP_MANIFEST_BYTES)?;
        if request.body().get("manifest").and_then(Value::as_str) != Some(statement.hash().as_str()) {
            return Err(NodeError::bad_format("offer: manifest hash does not match"));
        }
        let (version, hosts) = self.check_version(statement, now)?;
        if !hosts.iter().any(|(id, _)| id == request.iss()) {
            return Err(NodeError::forbidden("only hosts of this app offer it"));
        }
        if !self.inner.apps.hosts(&version.manifest.app) && !self.hosts_me(&version, &hosts) {
            return Err(NodeError::forbidden("this node is not a host of this app"));
        }
        let taken = self.take_version(version, &hosts, now).await?;
        Ok(json!({"ok": true, "active": taken.active()}).to_string().into_bytes())
    }

    /// `POST /v4/app/update` (anybody; read limit): a newer version of an app hosted here - taken like an offer
    /// (listed: accepted; not listed: a stop signal). The two signatures are the proof, the caller does not matter.
    /// Cheap first: only apps hosted here (else `404`), only ranks not below what this node decided (else `409`).
    async fn app_update(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        if body.len() > MAX_APP_MANIFEST_BYTES {
            return Err(NodeError::new(413, "TOO_LARGE", "app version too large"));
        }
        let statement = AppManifest::parse_statement(body)?;
        let claimed = statement.body().get("app").and_then(Value::as_str).and_then(|text| Id::parse(text).ok());
        let app = claimed.ok_or_else(not_found)?;
        let floor = self.inner.apps.floor(&app).ok_or_else(not_found)?;
        // Unverified, only to skip work: a lie here can only lead to a refusal after the full check.
        let version = statement.body().get("version").and_then(Value::as_u64).unwrap_or(0);
        if (version, statement.hash_bytes()) < floor {
            return Err(NodeError::new(409, "REPLAY", "this node knows a newer version of this app"));
        }
        let (version, hosts) = self.check_version(statement, now)?;
        if version.manifest.app != app {
            return Err(NodeError::bad_format("app: inconsistent"));
        }
        let taken = self.take_version(version, &hosts, now).await?;
        Ok(json!({"ok": true, "active": taken.active(), "hosted": taken != Taken::Stopped}).to_string().into_bytes())
    }

    /// Takes a checked version: the current or pending one again changes nothing; at or below the rank → `REPLAY`;
    /// not listing this node → a stop signal (only for apps hosted here); else it becomes the pending version with
    /// its whole size reserved (quota, apps per owner, apps per node - all or nothing), and is switched to at once if
    /// all its blobs are here.
    async fn take_version(&self, version: Version, hosts: &Hosts, now: i64) -> NodeResult<Taken> {
        let app = version.manifest.app.clone();
        let rank = version.rank();
        let changes = self.inner.apps.changes.lock().await;
        let known = {
            let hosted = lock(&self.inner.apps.hosted);
            hosted.get(&app).map(|entry| {
                let held = entry.holds(&rank);
                let served = entry.current.as_ref().is_some_and(|current| current.rank() == rank);
                (entry.floor, held, served, entry.newest().cloned(), entry.current.clone(), entry.previous.clone())
            })
        };
        let floor = match &known {
            Some((floor, held, served, ..)) => {
                if *held {
                    return Ok(Taken::Hosted(*served)); // the same version again: nothing changes
                }
                Some(*floor)
            }
            None => {
                let key = app.to_string();
                self.blocking(move |store| store.app_get(&key)).await?.as_ref().map(row_floor)
            }
        };
        if floor.is_some_and(|floor| rank <= floor) {
            return Err(NodeError::new(409, "REPLAY", "this node knows a newer version of this app"));
        }
        let (old, current, previous) = match known {
            Some((_, _, _, old, current, previous)) => {
                if !self.hosts_me(&version, hosts) {
                    self.stop_locked(&changes, &app, Some(rank), "a newer version does not list this node").await;
                    drop(changes);
                    if let Some(old) = old {
                        self.notify_retired(&old, &version, now);
                    }
                    return Ok(Taken::Stopped);
                }
                (old, current, previous)
            }
            None if !self.hosts_me(&version, hosts) => {
                return Err(NodeError::forbidden("this node is not a host of this app"));
            }
            None => (None, None, None),
        };
        self.accept_locked(&changes, version, old, current, previous, now).await?;
        drop(changes);
        let active = self.try_activate(&app, now).await?;
        if !active {
            self.inner.apps.wake();
        }
        Ok(Taken::Hosted(active))
    }

    /// Accepts a version as pending (the caller holds the lock of changes and checked the rank); see
    /// [`Node::take_version`].
    async fn accept_locked(
        &self,
        changes: &tokio::sync::MutexGuard<'_, ()>,
        version: Version,
        old: Option<Version>,
        current: Option<Version>,
        previous: Option<Version>,
        now: i64,
    ) -> NodeResult<()> {
        let app = version.manifest.app.clone();
        let mut sizes: BTreeMap<BlobId, u64> = BTreeMap::new();
        for file in &version.manifest.files {
            if *sizes.entry(file.blob).or_insert(file.size) != file.size {
                return Err(NodeError::bad_format("app: one blob with two sizes"));
            }
        }
        let owner = version.manifest.owner.clone();
        let level = self.with_core(|core| core.state.level(&owner, now))?.unwrap_or(0);
        let quota = self.blob_quota(&owner, now)?;
        let entry = Hosted {
            owner: owner.clone(),
            current,
            previous,
            pending: Some(version.clone()),
            floor: version.rank(),
            failures: 0,
            retry_at: 0,
        };
        let (row, keep) = (entry.row(&app, now), entry.kept_blobs());
        let reserve: Vec<(String, u64)> = sizes.iter().map(|(id, size)| (id.to_text(), *size)).collect();
        let (holder, owner_key) = (format!("{APP_PIN_PREFIX}{app}"), owner.to_string());
        let limits = self.app_limits(self.inner.guard.limits().apps_for(level), now);
        let stored = self
            .blocking(move |store| {
                let reservation = Reservation { owner: &owner_key, quota, keep: &keep, reserve: &reserve };
                store.app_accept(&row, &limits, &holder, &reservation)
            })
            .await?;
        match stored {
            AppStored::Stored => {}
            AppStored::NodeFull => return Err(full("this node hosts as many apps as it may")),
            AppStored::OwnerFull => return Err(full("the owner has as many apps on this node as it may")),
            AppStored::Quota => {
                // Not kept waiting; for an app hosted here this version stays refused (no retry storm).
                self.refuse_locked(changes, &app, version.rank(), now).await;
                return Err(quota_error(bridge_store::Pinned::Quota));
            }
        }
        lock(&self.inner.apps.hosted).insert(app.clone(), entry);
        tracing::info!(app = %app, version = version.manifest.version, "app version accepted");
        if let Some(old) = old {
            self.notify_retired(&old, &version, now);
        }
        Ok(())
    }

    /// Remembers a refused version of an app hosted here: its rank becomes the floor (memory and database).
    async fn refuse_locked(&self, _changes: &tokio::sync::MutexGuard<'_, ()>, app: &Id, rank: Rank, now: i64) {
        let row = {
            let mut hosted = lock(&self.inner.apps.hosted);
            let Some(entry) = hosted.get_mut(app) else { return };
            entry.floor = entry.floor.max(rank);
            entry.row(app, now)
        };
        let limits = self.app_limits(u64::MAX, now);
        if let Err(error) = self.blocking(move |store| store.app_put(&row, &limits)).await {
            tracing::warn!(error = %error.message, app = %app, "could not store a refused version");
        }
    }

    /// Switches to the pending version at once if all its blobs are here (sizes checked; a version whose sizes do not
    /// match its blobs is dropped). Returns whether the pending version (or, without one, the current one) is served.
    async fn try_activate(&self, app: &Id, now: i64) -> NodeResult<bool> {
        let Some(pending) = self.inner.apps.pending(app) else {
            return Ok(self.inner.apps.current(app).is_some());
        };
        let blobs: Vec<(String, u64)> =
            pending.manifest.blobs().into_iter().map(|(id, size)| (id.to_text(), size)).collect();
        let keys: Vec<String> = blobs.iter().map(|(key, _)| key.clone()).collect();
        let states = self
            .blocking(move |store| keys.iter().map(|key| store.blob_state(key)).collect::<Result<Vec<_>, _>>())
            .await?;
        let mut complete = true;
        for ((_, size), state) in blobs.iter().zip(states) {
            match state {
                None => complete = false,
                Some(state) if state.size != *size => {
                    // The manifest names a size the blob does not have: this version can never be served.
                    self.give_up(app, &pending, "a file size does not match its blob").await;
                    return Err(NodeError::bad_format("app: a file size does not match its blob"));
                }
                Some(state) => complete &= state.present == state.parts,
            }
        }
        if !complete {
            return Ok(false);
        }
        self.switch(app, &pending, now).await?;
        Ok(true)
    }

    /// The pending version becomes the current one, the current one the previous one (database first, then memory);
    /// pins only for those two.
    async fn switch(&self, app: &Id, pending: &Version, now: i64) -> NodeResult<()> {
        let _changes = self.inner.apps.changes.lock().await;
        let entry = {
            let hosted = lock(&self.inner.apps.hosted);
            let Some(entry) = hosted.get(app) else { return Ok(()) };
            if entry.pending.as_ref().map(Version::rank) != Some(pending.rank()) {
                return Ok(()); // something newer came in meanwhile
            }
            Hosted {
                owner: entry.owner.clone(),
                previous: entry.current.clone(),
                current: Some(pending.clone()),
                pending: None,
                floor: entry.floor,
                failures: 0,
                retry_at: 0,
            }
        };
        let (row, holder, keep) = (entry.row(app, now), format!("{APP_PIN_PREFIX}{app}"), entry.kept_blobs());
        let limits = self.app_limits(u64::MAX, now);
        self.blocking(move |store| store.app_keep(&row, &limits, &holder, &keep)).await?;
        lock(&self.inner.apps.hosted).insert(app.clone(), entry);
        tracing::info!(app = %app, version = pending.manifest.version, "app version served now");
        Ok(())
    }

    /// Gives up a pending version (it stays refused - its rank is the floor already): without a served version the
    /// app stops (its place is free), else the reservation is released.
    async fn give_up(&self, app: &Id, pending: &Version, reason: &str) {
        let changes = self.inner.apps.changes.lock().await;
        let now = self.now();
        let update = {
            let mut hosted = lock(&self.inner.apps.hosted);
            let Some(entry) = hosted.get_mut(app) else { return };
            if entry.pending.as_ref().map(Version::rank) != Some(pending.rank()) {
                return;
            }
            if entry.current.is_none() {
                None
            } else {
                entry.pending = None;
                (entry.failures, entry.retry_at) = (0, 0);
                Some((entry.row(app, now), entry.kept_blobs()))
            }
        };
        tracing::info!(app = %app, version = pending.manifest.version, reason, "pending app version dropped");
        let Some((row, keep)) = update else {
            return self.stop_locked(&changes, app, None, reason).await;
        };
        let (holder, limits) = (format!("{APP_PIN_PREFIX}{app}"), self.app_limits(u64::MAX, now));
        if let Err(error) = self.blocking(move |store| store.app_keep(&row, &limits, &holder, &keep)).await {
            tracing::warn!(error = %error.message, app = %app, "could not store a dropped version");
        }
    }

    /// One more round without progress for the pending version: wait longer before the next try, give it up after
    /// [`MAX_FETCH_FAILURES`].
    async fn failed_round(&self, app: &Id, pending: &Version, now: i64) {
        let interval = self.apps_interval_ms();
        let give_up = {
            let mut hosted = lock(&self.inner.apps.hosted);
            let Some(entry) = hosted.get_mut(app) else { return };
            if entry.pending.as_ref().map(Version::rank) != Some(pending.rank()) {
                return;
            }
            entry.failures += 1;
            let rounds = (1i64 << entry.failures.min(10)).min(i64::from(MAX_PAUSE_ROUNDS));
            entry.retry_at = now.saturating_add(interval.saturating_mul(rounds));
            entry.failures >= MAX_FETCH_FAILURES
        };
        if give_up {
            self.give_up(app, pending, "its files could not be fetched").await;
        }
    }

    /// Progress for the pending version: the count of failures starts again.
    fn progressed(&self, app: &Id, pending: &Version) {
        let mut hosted = lock(&self.inner.apps.hosted);
        if let Some(entry) = hosted.get_mut(app) {
            if entry.pending.as_ref().map(Version::rank) == Some(pending.rank()) {
                (entry.failures, entry.retry_at) = (0, 0);
            }
        }
    }

    /// Stops hosting an app (taking the lock of changes).
    async fn stop_app(&self, app: &Id, floor: Option<Rank>, reason: &str) {
        let changes = self.inner.apps.changes.lock().await;
        self.stop_locked(&changes, app, floor, reason).await;
    }

    /// Stops hosting an app: nothing is served any more, the blobs are unpinned, only ID, owner and rank are kept -
    /// the higher of the app's floor and `floor` (the version that removed this node), so no older or equal version
    /// is taken again.
    async fn stop_locked(
        &self,
        _changes: &tokio::sync::MutexGuard<'_, ()>,
        app: &Id,
        floor: Option<Rank>,
        reason: &str,
    ) {
        let Some(entry) = lock(&self.inner.apps.hosted).remove(app) else { return };
        let rank = floor.map_or(entry.floor, |floor| floor.max(entry.floor));
        let now = self.now();
        let row = AppRow {
            app: app.to_string(),
            owner: entry.owner.to_string(),
            version: rank.0,
            hash: Some(rank.1),
            state: AppState::Stopped,
            current: None,
            previous: None,
            pending: None,
            updated: now,
        };
        let (holder, limits) = (format!("{APP_PIN_PREFIX}{app}"), self.app_limits(u64::MAX, now));
        if let Err(error) = self.blocking(move |store| store.app_stop(&row, &limits, &holder)).await {
            tracing::warn!(error = %error.message, app = %app, "could not store that the app stopped");
        }
        tracing::info!(app = %app, reason, "app no longer hosted here");
    }

    /// Tells the hosts of `old` that `new` does not name about `new` (`POST /v4/app/update`, best effort, in the
    /// background, at most [`NOTIFY_RUNS`] runs at once): so they stop, also when no host they know has it.
    fn notify_retired(&self, old: &Version, new: &Version, now: i64) {
        let me = self.inner.identity.id().clone();
        let Ok(hosts) = self.with_core(|core| valid_hosts(&core.state, &old.manifest, now)) else { return };
        let targets: Vec<Vec<Endpoint>> = hosts
            .iter()
            .filter(|(id, _)| id != &me && !new.manifest.hosts.contains(id))
            .filter_map(|(id, card)| card.as_ref().map(|card| self.endpoints_of(id, card.tls().copied(), card.urls())))
            .filter(|endpoints| !endpoints.is_empty())
            .collect();
        if targets.is_empty() {
            return;
        }
        let Ok(permit) = Arc::clone(&self.inner.apps.notify).try_acquire_owned() else { return };
        let (node, body) = (self.clone(), new.bytes());
        tokio::spawn(async move {
            for endpoints in targets {
                match node.peer_post_any(&endpoints, "/v4/app/update", body.clone()).await {
                    Ok(answer) => tracing::debug!(status = answer.status, "newer app version passed on"),
                    Err(error) => tracing::debug!(%error, "could not pass a newer app version on"),
                }
            }
            drop(permit);
        });
    }

    /// Whether a version still holds here at `now`: verified once, so only what changes - expiry, the network's
    /// rules, this node a host.
    fn still_valid(&self, version: &Version, now: i64) -> Result<Hosts, Invalid> {
        if version.statement.check_time(now).is_err() {
            return Err(Invalid::Stop("the version expired".into()));
        }
        if self.app_blocked(&version.manifest.app, &version.manifest.owner, now) {
            return Err(Invalid::Stop("the app or its owner is on a blocklist".into()));
        }
        let checked = self.with_core(|core| {
            check_standing(&core.state, &version.manifest, now)
                .map(|()| valid_hosts(&core.state, &version.manifest, now))
        });
        match checked {
            Err(_) => Err(Invalid::Later),
            Ok(Err(NetError::Banned)) => Err(Invalid::Stop("the app or its owner is banned".into())),
            Ok(Err(error)) => Err(Invalid::Stop(format!("the owner may not publish apps ({error})"))),
            Ok(Ok(hosts)) if !self.hosts_me(version, &hosts) => {
                Err(Invalid::Stop("this node is no (valid) host of the app any more".into()))
            }
            Ok(Ok(hosts)) => Ok(hosts),
        }
    }

    /// `POST /v4/app/manifest` `{"app","head"?}` → `{"manifest":<newest version here>,"hosts":[<cards of the hosts
    /// that count>]}`, or with `"head":true` only `{"version":n,"hash":"…"}` - only while it holds.
    fn app_manifest(&self, body: &[u8], now: i64) -> NodeResult<Vec<u8>> {
        let body = body_object(body, MAX_QUERY_BYTES)?;
        let app = Id::parse(body.get("app").and_then(Value::as_str).unwrap_or_default())?;
        let head = match body.get("head") {
            None => false,
            Some(value) => value.as_bool().ok_or_else(|| NodeError::bad_format("head: true or false"))?,
        };
        let version = self.inner.apps.newest(&app).ok_or_else(not_found)?;
        let hosts = self.still_valid(&version, now).map_err(|_| not_found())?;
        if head {
            let answer = json!({"version": version.manifest.version, "hash": version.statement.hash()});
            return Ok(answer.to_string().into_bytes());
        }
        let cards: Vec<Value> = hosts.iter().filter_map(|(_, card)| card.as_ref().map(KeyCard::to_value)).collect();
        Ok(json!({"manifest": version.statement.to_value(), "hosts": cards}).to_string().into_bytes())
    }

    /// One round for one app (see module docs).
    async fn sync_app(self, app: Id) {
        let now = self.now();
        // A waiting version that expired is given up - the served one goes on (if it still holds itself).
        if let (Some(pending), Some(_)) = (self.inner.apps.pending(&app), self.inner.apps.current(&app)) {
            if pending.statement.check_time(now).is_err() {
                self.give_up(&app, &pending, "the waiting version expired").await;
            }
        }
        let Some(newest) = self.inner.apps.newest(&app) else {
            // No version left that verifies (a damaged database row).
            return self.stop_app(&app, None, "no valid version left").await;
        };
        let hosts = match self.still_valid(&newest, now) {
            Ok(hosts) => hosts,
            Err(Invalid::Later) => return,
            Err(Invalid::Stop(reason)) => return self.stop_app(&app, None, &reason).await,
        };
        let me = self.inner.identity.id().clone();
        let others: Vec<(Id, Vec<Endpoint>)> = hosts
            .iter()
            .filter(|(id, _)| id != &me)
            .filter_map(|(id, card)| {
                let card = card.as_ref()?;
                Some((id.clone(), self.endpoints_of(id, card.tls().copied(), card.urls())))
            })
            .collect();
        if let Some((newer, newer_hosts)) = self.ask_hosts(&app, &newest, &others, now).await {
            if let Err(error) = self.take_version(newer, &newer_hosts, now).await {
                tracing::debug!(app = %app, %error.message, "newer version not taken");
            }
        }
        if let Some(pending) = self.inner.apps.pending(&app) {
            if self.inner.apps.due(&app, now) {
                let sources: Vec<Vec<Endpoint>> = match self.still_valid(&pending, now) {
                    Ok(hosts) => hosts
                        .iter()
                        .filter(|(id, _)| id != &me)
                        .filter_map(|(id, card)| {
                            let card = card.as_ref()?;
                            Some(self.endpoints_of(id, card.tls().copied(), card.urls()))
                        })
                        .collect(),
                    Err(Invalid::Later) => return,
                    Err(Invalid::Stop(reason)) => return self.stop_app(&app, None, &reason).await,
                };
                match self.fetch_version(&pending, &sources, now).await {
                    Ok(Fetched::Active) => {}
                    Ok(Fetched::Progress { stored, more }) if stored > 0 => {
                        self.progressed(&app, &pending);
                        if more {
                            self.inner.apps.wake();
                        }
                    }
                    Ok(Fetched::Progress { .. }) => self.failed_round(&app, &pending, now).await,
                    Err(error) if error.code == "QUOTA_EXCEEDED" => {
                        self.give_up(&app, &pending, "this node's storage is full").await;
                    }
                    Err(error) => {
                        tracing::debug!(app = %app, %error.message, "fetching the new version");
                        self.failed_round(&app, &pending, now).await;
                    }
                }
            }
        }
        // Repair: a part of the served version that did not verify when read is checked on disk, else fetched again.
        if let Some(current) = self.inner.apps.current(&app) {
            let holder = format!("{APP_PIN_PREFIX}{app}");
            let incomplete = self
                .blocking(move |store| store.blobs_incomplete(&holder, REPAIRS_PER_ROUND))
                .await
                .unwrap_or_default();
            let mine = current.blob_keys();
            let sources: Vec<Vec<Endpoint>> = others.iter().map(|(_, endpoints)| endpoints.clone()).collect();
            for id in incomplete.iter().filter(|key| mine.contains(*key)).filter_map(|key| BlobId::parse(key).ok()) {
                if let Err(error) = self.repair(&id, &sources).await {
                    tracing::debug!(app = %app, %error.message, "repairing a blob");
                }
            }
        }
    }

    /// Asks up to 8 other hosts for their newest version (head form; the full manifest only when it is above this
    /// app's floor): returns the best newer valid one (with its hosts), and offers the own version to hosts that have
    /// none or an older one (not again while they refused it lately).
    async fn ask_hosts(
        &self,
        app: &Id,
        own: &Version,
        others: &[(Id, Vec<Endpoint>)],
        now: i64,
    ) -> Option<(Version, Hosts)> {
        let floor = self.inner.apps.floor(app).unwrap_or_else(|| own.rank());
        let mut best: Option<(Version, Hosts)> = None;
        let start = usize::try_from(now / 1000).unwrap_or(0) % others.len().max(1);
        let picked = others.iter().cycle().skip(start).take(others.len().min(HOSTS_ASKED_PER_ROUND));
        let head = json!({"app": app.as_str(), "head": true}).to_string().into_bytes();
        for (host, endpoints) in picked {
            let theirs = match self.peer_post_any(endpoints, "/v4/app/manifest", head.clone()).await {
                Ok(answer) if answer.status == 200 => match parse_head(&answer.body) {
                    Some(rank) => Some(rank),
                    // A host without the head form answers with the whole manifest.
                    None => match self.parse_manifest(app, &answer.body, now) {
                        Some(found) => {
                            let rank = found.0.rank();
                            if rank > floor && best.as_ref().is_none_or(|best| rank > best.0.rank()) {
                                best = Some(found);
                            }
                            Some(rank)
                        }
                        None => continue,
                    },
                },
                Ok(answer) if answer.status == 404 => None,
                _ => continue, // no answer: neither fetch nor offer
            };
            match theirs {
                Some(rank) if rank > floor => {
                    if best.as_ref().is_some_and(|best| best.0.rank() >= rank) {
                        continue;
                    }
                    let query = json!({"app": app.as_str()}).to_string().into_bytes();
                    let Ok(answer) = self.peer_post_any(endpoints, "/v4/app/manifest", query).await else { continue };
                    if answer.status != 200 {
                        continue;
                    }
                    if let Some(found) = self.parse_manifest(app, &answer.body, now) {
                        if found.0.rank() > floor && best.as_ref().is_none_or(|best| found.0.rank() > best.0.rank()) {
                            best = Some(found);
                        }
                    }
                }
                Some(rank) if rank >= own.rank() => {} // the same, or one this node refused or was removed by
                _ => self.offer(app, host, endpoints, own, now).await,
            }
        }
        best
    }

    /// A full `/v4/app/manifest` answer, verified (both signatures, the network's rules) and of this app.
    pub(crate) fn parse_manifest(&self, app: &Id, body: &Map<String, Value>, now: i64) -> Option<(Version, Hosts)> {
        let value = body.get("manifest").cloned()?;
        let statement = Statement::from_value_with_limit(value, MAX_APP_MANIFEST_BYTES).ok()?;
        self.check_version(statement, now).ok().filter(|(version, _)| &version.manifest.app == app)
    }

    /// Offers the own version to another host (`POST /v4/node/app`, best effort; paused after a refusal).
    async fn offer(&self, app: &Id, host: &Id, endpoints: &[Endpoint], version: &Version, now: i64) {
        if !self.inner.apps.may_offer(app, host, &version.rank(), now) {
            return;
        }
        let Ok(request) = self.signed(host, "app", json!({"manifest": version.statement.hash()})) else { return };
        let Ok(request) = parse_strict(&request, MAX_REQUEST_BYTES) else { return };
        let body = json!({"manifest": version.statement.to_value(), "rq": request}).to_string().into_bytes();
        let accepted = match self.peer_post_any(endpoints, "/v4/node/app", body).await {
            Ok(answer) if answer.status == 200 => {
                tracing::debug!(host = %host, "app offered");
                true
            }
            Ok(answer) => {
                tracing::debug!(host = %host, code = answer.code(), "app offer refused");
                false
            }
            Err(error) => {
                tracing::debug!(host = %host, %error, "app offer failed");
                false
            }
        };
        self.inner.apps.offered(app, host, version.rank(), accepted, self.apps_interval_ms(), now);
    }

    /// One round of fetching a pending version: blobs registered here get their missing parts; blobs not here yet
    /// are looked up (at most [`LOOKUPS_PER_ROUND`]); a few blobs at once, each with its parts in parallel. Then
    /// switches if everything is here.
    async fn fetch_version(&self, pending: &Version, sources: &[Vec<Endpoint>], now: i64) -> NodeResult<Fetched> {
        let app = pending.manifest.app.clone();
        let holder = format!("{APP_PIN_PREFIX}{app}");
        let blobs = pending.manifest.blobs();
        let keys: Vec<String> = blobs.iter().map(|(id, _)| id.to_text()).collect();
        let states = self
            .blocking(move |store| keys.iter().map(|key| store.blob_state(key)).collect::<Result<Vec<_>, _>>())
            .await?;
        let sources = Arc::new(sources.to_vec());
        let (mut jobs, mut lookups, mut more) = (Vec::new(), 0usize, false);
        for ((id, size), state) in blobs.into_iter().zip(states) {
            let lookup = match state {
                Some(state) if state.present == state.parts => continue,
                Some(_) => false,
                None if lookups < LOOKUPS_PER_ROUND => {
                    lookups += 1;
                    true
                }
                None => {
                    more = true;
                    continue;
                }
            };
            jobs.push(BlobJob { id, size, lookup, holder: holder.clone(), sources: Arc::clone(&sources) });
        }
        let mut waiting = jobs.into_iter();
        let mut running = JoinSet::new();
        let mut stored = 0u64;
        loop {
            while running.len() < BLOBS_AT_ONCE {
                let Some(job) = waiting.next() else { break };
                running.spawn(self.clone().fetch_blob(job));
            }
            match running.join_next().await {
                None => break,
                Some(Ok(Ok(Some(count)))) => stored += count,
                // The app stopped or moved on meanwhile: its reservation is gone, nothing more to do.
                Some(Ok(Ok(None))) => return Ok(Fetched::Progress { stored, more: false }),
                Some(Ok(Err(error))) if error.code == "QUOTA_EXCEEDED" => return Err(error),
                Some(Ok(Err(_)) | Err(_)) => {}
            }
        }
        if self.try_activate(&app, now).await? {
            return Ok(Fetched::Active);
        }
        Ok(Fetched::Progress { stored, more })
    }

    /// One blob of a pending version: looked up first if it is not here yet (registered only while the app still
    /// reserves it), then its missing parts. Returns what came in (a registration counts as one); `None`: the app
    /// does not reserve the blob any more.
    async fn fetch_blob(self, job: BlobJob) -> NodeResult<Option<u64>> {
        let mut stored = 0;
        if job.lookup {
            let list = self.lookup_hash_list(&job.id, job.size, &job.sources).await?;
            let (key, size, limits, holder) = (job.id.to_text(), job.size, self.blob_limits(), job.holder.clone());
            let registered = self
                .blocking(move |store| {
                    store.blob_register(&NewBlob { id: &key, size, hashes: list.hashes() }, &holder, &limits)
                })
                .await?;
            match registered {
                Registered::Ok => stored += 1,
                Registered::NotPinned => return Ok(None),
                Registered::NodeFull => return Err(quota_error(bridge_store::Pinned::NodeFull)),
            }
        }
        Ok(Some(stored + self.fetch_parts(&job.id, &job.sources).await?))
    }

    /// The hash list of a blob that is not here yet: `/v4/blob/info` at up to 8 sources first, the list only from
    /// one that has the blob with this size - the first list that matches the ID.
    pub(crate) async fn lookup_hash_list(
        &self,
        id: &BlobId,
        size: u64,
        sources: &[Vec<Endpoint>],
    ) -> NodeResult<HashList> {
        let parts = blob::parts_for(size)?;
        let start = usize::from(id.as_bytes()[0]) % sources.len().max(1);
        let picked = sources.iter().cycle().skip(start).take(sources.len().min(SOURCES_PER_LOOKUP));
        let info = json!({"blob": id.to_text()}).to_string().into_bytes();
        'sources: for endpoints in picked {
            let Ok(answer) = self.peer_post_any(endpoints, "/v4/blob/info", info.clone()).await else { continue };
            let Ok(found) = answer.ok() else { continue };
            if found.get("size").and_then(Value::as_u64) != Some(size) {
                continue;
            }
            let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(parts as usize);
            while hashes.len() < parts as usize {
                let from = u32::try_from(hashes.len()).unwrap_or(u32::MAX);
                let query = json!({"blob": id.to_text(), "from": from, "max": HASH_PAGE}).to_string().into_bytes();
                let Ok(answer) = self.peer_post_any(endpoints, "/v4/blob/hashes", query).await else {
                    continue 'sources;
                };
                let Ok(page) = answer.ok() else { continue 'sources };
                let Ok(list) = crate::blobs::parse_hashes(page.get("hashes")) else { continue 'sources };
                if list.is_empty() || page.get("from").and_then(Value::as_u64) != Some(u64::from(from)) {
                    continue 'sources;
                }
                hashes.extend(list.into_iter().take(parts as usize - hashes.len()));
            }
            if let Ok(list) = HashList::new(size, hashes) {
                if list.check(id).is_ok() {
                    return Ok(list);
                }
            }
            tracing::warn!(blob = %id, "a host sent a hash list that does not match the blob ID");
        }
        Err(NodeError::unavailable())
    }

    /// Repairs a blob of the served version: parts that verify on the own disk count again first (a read error was
    /// no data loss), the rest is fetched from the other hosts.
    async fn repair(&self, id: &BlobId, sources: &[Vec<Endpoint>]) -> NodeResult<u64> {
        let restored = self.reverify_local(id).await?;
        if restored > 0 {
            tracing::info!(blob = %id, restored, "parts verify on disk again");
        }
        Ok(restored + self.fetch_parts(id, sources).await?)
    }

    /// Checks the parts of a blob that count as missing against the own file: those that verify are marked present
    /// again. Returns how many.
    async fn reverify_local(&self, id: &BlobId) -> NodeResult<u64> {
        let (key, hex, files) = (id.to_text(), id.hex(), self.inner.blobs.clone());
        self.blocking(move |store| {
            let Some(state) = store.blob_state(&key)? else { return Ok(0) };
            let Ok(mut file) = files.open(&hex) else { return Ok(0) };
            let missing = store.blob_missing(&key, 0, blob::MAX_PARTS as usize)?;
            let hashes = store.blob_hashes(&key, 0, blob::MAX_PARTS)?.unwrap_or_default();
            let (mut restored, mut all) = (0u64, false);
            for index in missing {
                let (Some(hash), Some(length)) = (hashes.get(index as usize), blob::part_len(state.size, index)) else {
                    continue;
                };
                let Ok(data) = BlobFiles::read_at(&mut file, blob::part_offset(index), length) else { continue };
                if blob::verify_part(hash, state.size, index, &data).is_ok() {
                    if let PartStored::Added { all: last } = store.blob_part_stored(&key, index)? {
                        restored += 1;
                        all |= last;
                    }
                }
            }
            if all {
                match files.finish(&hex) {
                    Ok(()) => store.blob_set_complete(&key, true)?,
                    Err(error) => tracing::warn!(%error, "blob file: could not give it its final name"),
                }
            }
            Ok(restored)
        })
        .await
    }

    /// Fetches the missing parts of a registered blob from all `sources` in parallel: each part checked against its
    /// hash; a source that sends a wrong part is not asked again for this blob, the part comes from another one.
    /// Returns how many parts came in.
    async fn fetch_parts(&self, id: &BlobId, sources: &[Vec<Endpoint>]) -> NodeResult<u64> {
        let key = id.to_text();
        let (missing, hashes, size) = self
            .blocking(move |store| {
                let state = store.blob_state(&key)?;
                let missing = store.blob_missing(&key, 0, blob::MAX_PARTS as usize)?;
                let hashes = store.blob_hashes(&key, 0, blob::MAX_PARTS)?;
                Ok((missing, hashes, state.map(|state| state.size)))
            })
            .await?;
        let (Some(hashes), Some(size)) = (hashes, size) else { return Err(not_found()) };
        if missing.is_empty() {
            return Ok(0);
        }
        if sources.is_empty() {
            return Err(NodeError::unavailable());
        }
        let shared = Arc::new(Fetch {
            queue: Mutex::new(missing.into_iter().map(|index| (index, 0usize)).collect()),
            bad: Mutex::new(BTreeSet::new()),
            stored: AtomicU64::new(0),
            hashes,
            size,
            id: *id,
            sources: sources.to_vec(),
        });
        let mut workers = JoinSet::new();
        for _ in 0..FETCH_WORKERS {
            workers.spawn(self.clone().fetch_worker(Arc::clone(&shared)));
        }
        while workers.join_next().await.is_some() {}
        Ok(shared.stored.load(Ordering::Relaxed))
    }

    /// One fetch worker: takes the next missing part and tries the sources in turn (starting at a different one per
    /// part, so all sources work in parallel).
    async fn fetch_worker(self, fetch: Arc<Fetch>) {
        let count = fetch.sources.len();
        loop {
            let Some((index, tries)) = lock(&fetch.queue).pop_front() else { return };
            if tries >= count {
                continue; // no source had a good copy this round
            }
            let source = (index as usize + tries) % count;
            if lock(&fetch.bad).contains(&source) {
                lock(&fetch.queue).push_back((index, tries + 1));
                continue;
            }
            let query = json!({"blob": fetch.id.to_text(), "i": index}).to_string().into_bytes();
            let data = match self.peer_post_any(&fetch.sources[source], "/v4/blob/get", query).await {
                Ok(answer) if answer.status == 200 => answer
                    .body
                    .get("data")
                    .and_then(Value::as_str)
                    .and_then(|text| b64_var(text, "data", PART_BYTES).ok()),
                _ => None,
            };
            let Some(hash) = fetch.hashes.get(index as usize) else { continue };
            match data {
                Some(data) if blob::verify_part(hash, fetch.size, index, &data).is_ok() => {
                    match self.store_part(&fetch.id, fetch.size, index, data).await {
                        Ok(_) => {
                            fetch.stored.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => tracing::warn!(error = %error.message, "could not store a fetched part"),
                    }
                }
                Some(_) => {
                    tracing::warn!(blob = %fetch.id, index, "a host sent a wrong part - not asked again for this blob");
                    lock(&fetch.bad).insert(source);
                    lock(&fetch.queue).push_back((index, tries + 1));
                }
                None => lock(&fetch.queue).push_back((index, tries + 1)),
            }
        }
    }

    /// `GET /app/<app-id>/<path>` (and `/app/<app-id>/` for the entry): always with the sandbox headers, also for
    /// errors.
    pub(crate) async fn serve_app(&self, request: &Request) -> Response {
        let response = match self.app_file(request).await {
            Ok(response) => response,
            Err(error) => error.to_response(),
        };
        crate::apps_headers(response)
    }

    async fn app_file(&self, request: &Request) -> NodeResult<Response> {
        if request.method != Method::Get || self.network().is_none() {
            return Err(not_found()); // apps exist only in a network - not even the redirect without one
        }
        let now = self.now();
        self.inner.guard.admit_read(request.peer, now)?;
        let rest = request.path.strip_prefix("/app/").ok_or_else(not_found)?;
        let (app, path) = match rest.split_once('/') {
            Some((app, path)) => (app, Some(path)),
            None => (rest, None),
        };
        let app = Id::parse(app).map_err(|_| not_found())?;
        let Some(path) = path else {
            // `/app/<id>` → `/app/<id>/`, relative (works behind a path prefix too).
            return Ok(Response { status: 308, ..Response::ok(Vec::new()) }.with_header("location", format!("{app}/")));
        };
        let Some(version) = self.inner.apps.current(&app) else {
            // Not hosted here: maybe as reader for the owner's own browser (docs/08 §8) - else 404 as before.
            return self.reader_file(request, &app, path, now).await;
        };
        if self.still_valid(&version, now).is_err() {
            self.inner.apps.wake(); // the loop stops it for good
            return Err(not_found());
        }
        let path = if path.is_empty() { version.manifest.entry.as_str() } else { path };
        check_path(path).map_err(|_| not_found())?;
        let file = version.manifest.file(path).ok_or_else(not_found)?;
        let (id, size, kind) = (file.blob, file.size, file.kind);
        let response = if size <= PART_BYTES as u64 {
            let data = if size == 0 {
                Vec::new()
            } else {
                self.read_part(&id, 0).await?.ok_or_else(NodeError::unavailable)?
            };
            Response::ok(data)
        } else {
            let parts = blob::parts_for(size)?;
            let (sender, stream) = BodyStream::channel(size, 4);
            let node = self.clone();
            tokio::spawn(async move {
                for index in 0..parts {
                    let Ok(Some(data)) = node.read_part(&id, index).await else { return };
                    if !sender.send(data, STREAM_PART_TIMEOUT).await {
                        return;
                    }
                }
            });
            Response { stream: Some(stream), ..Response::ok(Vec::new()) }
        };
        Ok(response
            .with_header("content-type", kind.content_type())
            .with_header("cache-control", "no-cache")
            .with_header("etag", format!("\"{}\"", id.to_text())))
    }
}

/// One blob to fetch for a pending version.
struct BlobJob {
    id: BlobId,
    size: u64,
    /// Not here yet: look it up first.
    lookup: bool,
    holder: String,
    sources: Arc<Vec<Vec<Endpoint>>>,
}

/// Shared state of the workers fetching one blob.
struct Fetch {
    queue: Mutex<VecDeque<(u32, usize)>>,
    bad: Mutex<BTreeSet<usize>>,
    stored: AtomicU64,
    hashes: Vec<[u8; 32]>,
    size: u64,
    id: BlobId,
    sources: Vec<Vec<Endpoint>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_never_allows_the_same_origin() {
        assert!(APP_CSP.starts_with("sandbox ") && !APP_CSP.contains("allow-same-origin"));
    }

    #[test]
    fn a_row_without_hash_keeps_the_best_rank_of_its_manifests() {
        let row = AppRow {
            app: "a".into(),
            owner: "o".into(),
            version: 3,
            hash: None,
            state: AppState::Stopped,
            current: Some(b"not a statement".to_vec()),
            previous: None,
            pending: None,
            updated: 0,
        };
        assert_eq!(row_floor(&row), (3, [0u8; 32]));
        let row = AppRow { hash: Some([5u8; 32]), ..row };
        assert_eq!(row_floor(&row), (3, [5u8; 32]));
    }

    #[test]
    fn offer_pauses_grow_and_are_bounded() {
        let apps = Apps::empty();
        let app = bridge_core::Identity::generate(&mut rand_core::OsRng).id().clone();
        let host = bridge_core::Identity::generate(&mut rand_core::OsRng).id().clone();
        let rank = (1, [1u8; 32]);
        assert!(apps.may_offer(&app, &host, &rank, 0));
        apps.offered(&app, &host, rank, false, 1_000, 0);
        assert!(!apps.may_offer(&app, &host, &rank, 1_999));
        assert!(apps.may_offer(&app, &host, &rank, 2_000));
        assert!(apps.may_offer(&app, &host, &(2, [0u8; 32]), 0), "another version is offered at once");
        for _ in 0..40 {
            apps.offered(&app, &host, rank, false, 1_000, 0);
        }
        assert!(!apps.may_offer(&app, &host, &rank, MAX_OFFER_PAUSE_MS - 1));
        assert!(apps.may_offer(&app, &host, &rank, MAX_OFFER_PAUSE_MS));
        apps.offered(&app, &host, rank, true, 1_000, 0);
        assert!(apps.may_offer(&app, &host, &rank, 0), "taken: no pause");
    }
}
