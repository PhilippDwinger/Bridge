//! Apps a node hosts (schema 5 + 6, docs/07 §3-§5): per app the newest accepted manifest (`current`), the one before
//! (`previous`, the way back), a newer one whose files are still being fetched (`pending`), the **rank** of the
//! highest version the node decided on (version + statement hash: accepted, refused, or the version that removed it
//! as a host) and the state. The rank only ever grows (`MAX` in [`Store::app_put`]), so no old version can come back.
//!
//! Bounded (Z5): at most `max_active` apps hosted at once and `max_active_per_owner` per owner (full: refused). A
//! stopped app keeps only ID, owner and rank (the node passes no manifests); stopped apps are forgotten only when
//! they are older than `forget_before` (the node passes one year after the longest validity of a version - every
//! version that existed then has expired, forgetting opens no way back), or beyond `max_stopped_per_owner` of the
//! same owner (that only weakens the protection of that owner's own apps). When `max_active + max_stopped` rows are
//! there and none may be forgotten, a new app is refused (fail closed).
//!
//! An accepted version reserves its blobs in the same transaction as its row ([`Store::app_accept`]): pins of the
//! holder `app:<app-id>` with the sizes from the manifest, quota checked; stopping removes the row's pins in the same
//! transaction ([`Store::app_stop`]). The store checks no signatures - the node verified the manifests.

use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::blobs::owner_bytes;
use crate::{Store, StoreError, StoreResult};

/// State of a hosted app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// A version is served (a newer one may be pending).
    Serving,
    /// No version served yet: the first one is being fetched.
    Fetching,
    /// Not hosted any more (removed from the hosts, banned, expired, refused); only ID, owner and rank are kept.
    Stopped,
}

impl AppState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Serving => "serving",
            Self::Fetching => "fetching",
            Self::Stopped => "stopped",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "serving" => Self::Serving,
            "fetching" => Self::Fetching,
            "stopped" => Self::Stopped,
            _ => return None,
        })
    }
}

/// One app as stored (manifests as canonical JSON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRow {
    /// App ID.
    pub app: String,
    /// Owner ID.
    pub owner: String,
    /// Rank, part 1: the highest version decided on (also after stopping; never lowered).
    pub version: u64,
    /// Rank, part 2: the statement hash of that version (`None` only in rows from before schema 6).
    pub hash: Option<[u8; 32]>,
    /// State.
    pub state: AppState,
    /// The version served.
    pub current: Option<Vec<u8>>,
    /// The version before (kept as the way back).
    pub previous: Option<Vec<u8>>,
    /// A newer version being fetched.
    pub pending: Option<Vec<u8>>,
    /// Last change (ms).
    pub updated: i64,
}

/// Bounds for the apps of a node (decided by the node from its limits and the owner's level).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppLimits {
    /// Apps hosted at once.
    pub max_active: u64,
    /// Apps of this row's owner hosted at once.
    pub max_active_per_owner: u64,
    /// Stopped apps remembered.
    pub max_stopped: u64,
    /// Stopped apps of one owner remembered (beyond: that owner's oldest are forgotten).
    pub max_stopped_per_owner: u64,
    /// Stopped apps last changed before this time (ms) may be forgotten.
    pub forget_before: i64,
}

/// Result of storing an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStored {
    /// Stored.
    Stored,
    /// The node hosts as many apps as it may (or remembers as many as it may and none may be forgotten).
    NodeFull,
    /// The owner has as many apps on this node as it may.
    OwnerFull,
    /// The owner's storage quota does not hold the reservation.
    Quota,
}

/// The blobs an accepted version reserves for its app (holder `app:<app-id>`).
#[derive(Debug, Clone, Copy)]
pub struct Reservation<'a> {
    /// Whose quota it counts against.
    pub owner: &'a str,
    /// The owner's quota in bytes.
    pub quota: u64,
    /// Blobs the holder keeps besides the reserved ones (current and previous version); all others are released.
    pub keep: &'a [String],
    /// Blobs of the new version with their sizes from the manifest (pinned now, registered or not).
    pub reserve: &'a [(String, u64)],
}

fn row_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppRow> {
    let state: String = row.get(3)?;
    let hash: Option<Vec<u8>> = row.get(8)?;
    Ok(AppRow {
        app: row.get(0)?,
        owner: row.get(1)?,
        version: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
        hash: hash.and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok()),
        state: AppState::parse(&state).unwrap_or(AppState::Stopped),
        current: row.get(4)?,
        previous: row.get(5)?,
        pending: row.get(6)?,
        updated: row.get(7)?,
    })
}

const COLUMNS: &str = "app, owner, version, state, current, previous, pending, updated, hash";

fn count(transaction: &Transaction<'_>, sql: &str, value: Option<&str>) -> StoreResult<u64> {
    let found: i64 = match value {
        Some(value) => transaction.query_row(sql, [value], |row| row.get(0))?,
        None => transaction.query_row(sql, [], |row| row.get(0))?,
    };
    Ok(u64::try_from(found).unwrap_or(u64::MAX))
}

fn limit(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Forgets up to 1,000 stopped apps last changed before `before` (they can not open a way back any more).
fn forget_old(transaction: &Transaction<'_>, before: i64) -> StoreResult<usize> {
    Ok(transaction.execute(
        "DELETE FROM apps WHERE app IN (SELECT app FROM apps WHERE state = 'stopped' AND updated < ?1
           ORDER BY updated LIMIT 1000)",
        [before],
    )?)
}

/// Stores a row inside a transaction (see [`Store::app_put`]).
fn put_in(transaction: &Transaction<'_>, row: &AppRow, limits: &AppLimits) -> StoreResult<AppStored> {
    let before: Option<String> =
        transaction.query_row("SELECT state FROM apps WHERE app = ?1", [&row.app], |row| row.get(0)).optional()?;
    let was_active = before.as_deref().and_then(AppState::parse).is_some_and(|state| state != AppState::Stopped);
    if row.state != AppState::Stopped && !was_active {
        if count(transaction, "SELECT COUNT(*) FROM apps WHERE state != 'stopped'", None)? >= limits.max_active {
            return Ok(AppStored::NodeFull);
        }
        let mine =
            count(transaction, "SELECT COUNT(*) FROM apps WHERE owner = ?1 AND state != 'stopped'", Some(&row.owner))?;
        if mine >= limits.max_active_per_owner {
            return Ok(AppStored::OwnerFull);
        }
        let room = limits.max_active.saturating_add(limits.max_stopped);
        if before.is_none() && count(transaction, "SELECT COUNT(*) FROM apps", None)? >= room {
            forget_old(transaction, limits.forget_before)?;
            if count(transaction, "SELECT COUNT(*) FROM apps", None)? >= room {
                return Ok(AppStored::NodeFull);
            }
        }
    }
    let version = i64::try_from(row.version).map_err(|_| StoreError::Database("version too large".into()))?;
    // The rank only grows: a row with a lower rank changes everything else, but never the remembered rank.
    transaction.execute(
        &format!(
            "INSERT INTO apps ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (app) DO UPDATE SET owner = excluded.owner,
             version = CASE WHEN excluded.version > apps.version OR (excluded.version = apps.version
                 AND COALESCE(excluded.hash, x'') > COALESCE(apps.hash, x'')) THEN excluded.version ELSE apps.version END,
             hash = CASE WHEN excluded.version > apps.version OR (excluded.version = apps.version
                 AND COALESCE(excluded.hash, x'') > COALESCE(apps.hash, x'')) THEN excluded.hash ELSE apps.hash END,
             state = excluded.state, current = excluded.current, previous = excluded.previous,
             pending = excluded.pending, updated = excluded.updated"
        ),
        params![
            row.app,
            row.owner,
            version,
            row.state.as_str(),
            row.current,
            row.previous,
            row.pending,
            row.updated,
            row.hash.map(|hash| hash.to_vec())
        ],
    )?;
    if row.state == AppState::Stopped {
        transaction.execute(
            "DELETE FROM apps WHERE app IN (SELECT app FROM apps WHERE owner = ?1 AND state = 'stopped'
               ORDER BY updated DESC, app LIMIT -1 OFFSET ?2)",
            params![row.owner, limit(limits.max_stopped_per_owner)],
        )?;
        forget_old(transaction, limits.forget_before)?;
    }
    Ok(AppStored::Stored)
}

/// Removes the pins of `holder` on blobs not in `keep`.
fn retain_in(transaction: &Transaction<'_>, holder: &str, keep: &BTreeSet<&str>) -> StoreResult<usize> {
    let pinned: Vec<String> = {
        let mut statement = transaction.prepare("SELECT blob FROM blob_pins WHERE holder = ?1")?;
        let rows = statement.query_map([holder], |row| row.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut removed = 0;
    for blob in pinned.iter().filter(|blob| !keep.contains(blob.as_str())) {
        removed +=
            transaction.execute("DELETE FROM blob_pins WHERE holder = ?1 AND blob = ?2", params![holder, blob])?;
    }
    Ok(removed)
}

impl Store {
    /// The stored app.
    pub fn app_get(&self, app: &str) -> StoreResult<Option<AppRow>> {
        Ok(self.lock()?.query_row(&format!("SELECT {COLUMNS} FROM apps WHERE app = ?1"), [app], row_of).optional()?)
    }

    /// Stores an app (insert or replace; the rank only grows). A new active app only while the node and the owner
    /// are below their limits; a stopped app keeps at most `max_stopped_per_owner` of its owner.
    pub fn app_put(&self, row: &AppRow, limits: &AppLimits) -> StoreResult<AppStored> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = put_in(&transaction, row, limits)?;
        if stored == AppStored::Stored {
            transaction.commit()?;
        }
        Ok(stored)
    }

    /// Accepts a version: stores the row and, in the same transaction, pins every blob of the new version for
    /// `holder` (with its size from the manifest - registered or not), releases the holder's other pins except
    /// `keep`, and checks the owner's quota with all of it. Anything refused changes nothing.
    pub fn app_accept(
        &self,
        row: &AppRow,
        limits: &AppLimits,
        holder: &str,
        reservation: &Reservation<'_>,
    ) -> StoreResult<AppStored> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = put_in(&transaction, row, limits)?;
        if stored != AppStored::Stored {
            return Ok(stored);
        }
        let mut keep: BTreeSet<&str> = reservation.keep.iter().map(String::as_str).collect();
        keep.extend(reservation.reserve.iter().map(|(blob, _)| blob.as_str()));
        retain_in(&transaction, holder, &keep)?;
        for (blob, size) in reservation.reserve {
            transaction.execute(
                "INSERT INTO blob_pins (blob, holder, owner, expires, size) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (blob, holder) DO UPDATE SET owner = excluded.owner, size = excluded.size,
                 expires = MAX(expires, excluded.expires)",
                params![blob, holder, reservation.owner, i64::MAX, limit(*size)],
            )?;
        }
        if owner_bytes(&transaction, reservation.owner)? > reservation.quota {
            return Ok(AppStored::Quota);
        }
        transaction.commit()?;
        Ok(AppStored::Stored)
    }

    /// Stores a changed row of a hosted app and keeps only the pins of `holder` on `keep` (one transaction).
    pub fn app_keep(&self, row: &AppRow, limits: &AppLimits, holder: &str, keep: &[String]) -> StoreResult<AppStored> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = put_in(&transaction, row, limits)?;
        if stored != AppStored::Stored {
            return Ok(stored);
        }
        retain_in(&transaction, holder, &keep.iter().map(String::as_str).collect())?;
        transaction.commit()?;
        Ok(stored)
    }

    /// Stores a stopped app (only ID, owner, rank) and removes every pin of `holder` (one transaction).
    pub fn app_stop(&self, row: &AppRow, limits: &AppLimits, holder: &str) -> StoreResult<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stopped = AppRow { state: AppState::Stopped, current: None, previous: None, pending: None, ..row.clone() };
        put_in(&transaction, &stopped, limits)?;
        transaction.execute("DELETE FROM blob_pins WHERE holder = ?1", [holder])?;
        transaction.commit()?;
        Ok(())
    }

    /// The apps this node hosts (serving or fetching), at most `max`: the most recently changed first, then by ID.
    pub fn apps_active(&self, max: usize) -> StoreResult<Vec<AppRow>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(&format!(
            "SELECT {COLUMNS} FROM apps WHERE state != 'stopped' ORDER BY updated DESC, app LIMIT ?1"
        ))?;
        let rows = statement.query_map([i64::try_from(max).unwrap_or(i64::MAX)], row_of)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// IDs of up to `max` active apps beyond the first `skip` in the order of [`Store::apps_active`] (e.g. after the
    /// limit was lowered).
    pub fn apps_beyond(&self, skip: usize, max: usize) -> StoreResult<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT app FROM apps WHERE state != 'stopped' ORDER BY updated DESC, app LIMIT ?1 OFFSET ?2")?;
        let rows = statement.query_map(
            params![i64::try_from(max).unwrap_or(i64::MAX), i64::try_from(skip).unwrap_or(i64::MAX)],
            |row| row.get(0),
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobLimits, NewBlob, Pin};

    const LIMITS: AppLimits = AppLimits {
        max_active: 2,
        max_active_per_owner: 2,
        max_stopped: 2,
        max_stopped_per_owner: 2,
        forget_before: 0,
    };

    fn row(app: &str, state: AppState, updated: i64) -> AppRow {
        AppRow {
            app: app.into(),
            owner: "o".into(),
            version: 3,
            hash: Some([3u8; 32]),
            state,
            current: Some(b"{}".to_vec()),
            previous: None,
            pending: None,
            updated,
        }
    }

    #[test]
    fn bounded_active_and_stopped() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let limits = AppLimits { max_stopped_per_owner: 10, ..LIMITS };
        assert_eq!(store.app_put(&row("a", AppState::Serving, 1), &limits)?, AppStored::Stored);
        assert_eq!(store.app_put(&row("b", AppState::Fetching, 2), &limits)?, AppStored::Stored);
        assert_eq!(store.app_put(&row("c", AppState::Serving, 3), &limits)?, AppStored::NodeFull, "two at most");
        assert_eq!(store.app_put(&row("a", AppState::Serving, 4), &limits)?, AppStored::Stored, "an app can change");
        assert_eq!(store.apps_active(10)?.len(), 2);
        store.app_stop(&row("a", AppState::Serving, 5), &limits, "app:a")?;
        assert_eq!(store.app_put(&row("c", AppState::Serving, 6), &limits)?, AppStored::Stored, "room again");
        let stopped = store.app_get("a")?.ok_or(StoreError::Database("a forgotten".into()))?;
        assert_eq!((stopped.state, stopped.version, stopped.hash), (AppState::Stopped, 3, Some([3u8; 32])));
        assert_eq!((stopped.current, stopped.previous, stopped.pending), (None, None, None), "only ID, owner, rank");
        // Rows: 2 active + 2 stopped at most. Stopped apps are not forgotten by count: a new app is refused instead.
        store.app_stop(&row("b", AppState::Serving, 7), &limits, "app:b")?;
        assert_eq!(store.app_put(&row("d", AppState::Serving, 8), &limits)?, AppStored::Stored);
        store.app_stop(&row("d", AppState::Serving, 9), &limits, "app:d")?;
        assert_eq!(store.app_put(&row("e", AppState::Serving, 10), &limits)?, AppStored::NodeFull, "fail closed");
        assert!(store.app_get("a")?.is_some(), "nothing forgotten that may still matter");
        // Old enough (every version of that time has expired): forgotten to make room.
        let later = AppLimits { forget_before: 8, ..limits };
        assert_eq!(store.app_put(&row("e", AppState::Serving, 10), &later)?, AppStored::Stored);
        assert_eq!(store.app_get("a")?, None);
        assert_eq!(store.app_get("b")?, None);
        assert!(store.app_get("d")?.is_some(), "younger than the limit");
        assert_eq!(store.app_get("c")?.map(|app| app.state), Some(AppState::Serving), "active ones stay");
        Ok(())
    }

    #[test]
    fn rank_only_grows_and_owners_are_bounded() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let limits = AppLimits { max_active: 10, max_stopped: 10, ..LIMITS };
        store.app_put(&AppRow { version: 5, hash: Some([1u8; 32]), ..row("a", AppState::Serving, 1) }, &limits)?;
        // A lower version, then the same version with a smaller hash: the rank stays, the rest changes.
        store.app_stop(
            &AppRow { version: 4, hash: Some([9u8; 32]), ..row("a", AppState::Serving, 2) },
            &limits,
            "x",
        )?;
        let found = store.app_get("a")?.ok_or(StoreError::Database("gone".into()))?;
        assert_eq!((found.version, found.hash, found.state), (5, Some([1u8; 32]), AppState::Stopped));
        store.app_put(&AppRow { version: 5, hash: Some([0u8; 32]), ..row("a", AppState::Stopped, 3) }, &limits)?;
        assert_eq!(store.app_get("a")?.map(|app| app.hash), Some(Some([1u8; 32])));
        store.app_put(&AppRow { version: 5, hash: Some([2u8; 32]), ..row("a", AppState::Stopped, 4) }, &limits)?;
        assert_eq!(store.app_get("a")?.map(|app| (app.version, app.hash)), Some((5, Some([2u8; 32]))));
        store.app_put(&AppRow { version: 6, hash: None, ..row("a", AppState::Stopped, 5) }, &limits)?;
        assert_eq!(store.app_get("a")?.map(|app| (app.version, app.hash)), Some((6, None)));
        // Per owner: two active apps of "o"; another owner still fits.
        store.app_put(&row("b", AppState::Serving, 6), &limits)?;
        store.app_put(&row("c", AppState::Serving, 7), &limits)?;
        assert_eq!(store.app_put(&row("d", AppState::Serving, 8), &limits)?, AppStored::OwnerFull);
        let other = AppRow { owner: "p".into(), ..row("d", AppState::Serving, 8) };
        assert_eq!(store.app_put(&other, &limits)?, AppStored::Stored);
        // Stopped per owner: beyond two, that owner's oldest stopped apps go.
        for (index, app) in ["b", "c"].iter().enumerate() {
            store.app_stop(&row(app, AppState::Serving, 20 + index as i64), &limits, "x")?;
        }
        assert_eq!(store.app_get("a")?, None, "oldest stopped app of the owner forgotten");
        assert!(store.app_get("b")?.is_some() && store.app_get("c")?.is_some());
        // Order of the active ones: most recently changed first; beyond a limit.
        assert_eq!(store.apps_beyond(0, 10)?, vec!["d".to_owned()]);
        Ok(())
    }

    #[test]
    fn accept_reserves_quota_for_blobs_not_here_yet() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let limits = AppLimits { max_active: 10, max_stopped: 10, ..LIMITS };
        let blob_limits = BlobLimits {
            quota: [1 << 20, 1 << 20, 1 << 20],
            max_node_bytes: 1 << 30,
            max_blobs: 100,
            max_keep_days: 30,
            max_staged_per_owner: 1,
            max_staged: 1,
        };
        // The owner already pins 100 KiB by upload.
        let upload = Pin { holder: "up:o", owner: "o", expires: 1_000, quota: 1 << 20 };
        store.blob_add(&NewBlob { id: "u", size: 100_000, hashes: &[[1u8; 32], [2u8; 32]] }, &upload, &blob_limits)?;
        let reserve = vec![("missing".to_owned(), 900_000u64), ("u".to_owned(), 100_000u64)];
        let too_much = Reservation { owner: "o", quota: 999_999, keep: &[], reserve: &reserve };
        assert_eq!(store.app_accept(&row("a", AppState::Fetching, 1), &limits, "app:a", &too_much)?, AppStored::Quota);
        assert_eq!(store.app_get("a")?, None, "nothing stored when the quota says no");
        assert_eq!(store.blob_owner_bytes("o")?, 100_000, "and nothing reserved");
        let fits = Reservation { quota: 1_000_000, ..too_much };
        assert_eq!(store.app_accept(&row("a", AppState::Fetching, 1), &limits, "app:a", &fits)?, AppStored::Stored);
        assert_eq!(store.blob_owner_bytes("o")?, 1_000_000, "the missing blob counts with its size, `u` once");
        // A blob not here and not registered: only registered while the app pins it.
        let hashes = [[7u8; 32]];
        let missing = NewBlob { id: "missing", size: 900_000, hashes: &hashes };
        assert_eq!(store.blob_register(&missing, "app:a", &blob_limits)?, crate::Registered::Ok);
        let stray = NewBlob { id: "stray", size: 5, hashes: &hashes };
        assert_eq!(store.blob_register(&stray, "app:a", &blob_limits)?, crate::Registered::NotPinned);
        assert_eq!(store.blob_state("stray")?, None);
        // Stopping removes the reservation in the same transaction.
        store.app_stop(&row("a", AppState::Fetching, 2), &limits, "app:a")?;
        assert_eq!(store.blob_owner_bytes("o")?, 100_000);
        assert_eq!(store.blob_register(&missing, "app:a", &blob_limits)?, crate::Registered::NotPinned);
        Ok(())
    }
}
