//! Blobs (schema 5, docs/07 §1): metadata in SQLite, bytes as files.
//!
//! - A blob row exists only with a **verified** hash list (the node checked it against the ID before
//!   [`Store::blob_add`]); hash lists of large blobs arrive in pages and wait per uploader in `blob_staging` until
//!   complete (so nobody can squat a blob ID with a wrong list for others).
//! - Which parts are present is a bitmap; the node marks a part only after it verified and wrote it
//!   ([`Store::blob_part_stored`]), and un-marks it when a later read does not verify ([`Store::blob_part_lost`]).
//! - A blob stays while it is **pinned**: by its uploader until a date (`up:<id>`), by an app version this node
//!   hosts (`app:<app-id>`). Quotas count the distinct blobs an owner pins (each at least [`CHARGED_MIN_BYTES`]), the
//!   node counts all blob bytes and rows - checked atomically with the insert. Unpinned blobs go in [`Store::blob_gc`].
//! - An app pin may come **before** its blob (schema 6): an accepted version reserves all its blobs with their sizes
//!   from the manifest ([`Store::app_accept`]); such a blob counts with that size until it is registered. A blob for
//!   an app is registered only while the app still pins it ([`Store::blob_register`]) - fetching never creates a pin,
//!   so a fetch racing with a stop can not leave one behind. The garbage collection drops `app:` pins of apps that
//!   are not hosted (any more) as well.
//! - [`BlobFiles`]: one file per blob in `blobs/<2 hex>/<64 hex>`, named by the hex blob ID (Base64url would differ
//!   only by case on some file systems). While parts are missing it is `<hex>.part`; when all are there it is synced
//!   and renamed. Readers try both names.

use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{Store, StoreError, StoreResult};

/// Hashes per database row of a hash list (32 KiB).
pub const HASHES_PER_ROW: u32 = 1024;
/// Every blob counts at least this much against quotas (so a flood of tiny blobs is bounded too).
pub const CHARGED_MIN_BYTES: u64 = 4096;
/// Hash-list pages waiting longer than this are dropped.
const STAGING_LIFETIME_MS: i64 = 60 * 60 * 1000;
/// Prefix of the pins of a hosted app: `app:<app-id>` (the rest is the app ID of its row in `apps`).
pub const APP_PIN_PREFIX: &str = "app:";
/// Most hashes in one staged page (= the wire page, docs/07 §7).
const STAGING_PAGE: u32 = bridge_core::blob::HASH_PAGE;

/// Storage limits for blobs (decided by `bridge-guard`; docs/07 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobLimits {
    /// Bytes an owner may pin on this node, by level: 0, 1, 2 and above.
    pub quota: [u64; 3],
    /// Bytes of all blobs of this node.
    pub max_node_bytes: u64,
    /// Number of blobs of this node.
    pub max_blobs: u64,
    /// Longest upload pin in days.
    pub max_keep_days: u32,
    /// Hash lists one uploader may have waiting at once.
    pub max_staged_per_owner: u64,
    /// Hash lists waiting at once on this node.
    pub max_staged: u64,
}

impl BlobLimits {
    /// The quota of an owner of `level` (`None`: not a member of a network - a logged-in identity on a node
    /// without network counts as level 0).
    #[must_use]
    pub fn quota_for(&self, level: u8) -> u64 {
        self.quota[usize::from(level.min(2))]
    }
}

/// A blob to register: ID, size and its verified hash list.
#[derive(Debug, Clone, Copy)]
pub struct NewBlob<'a> {
    /// Blob ID (wire form).
    pub id: &'a str,
    /// Size in bytes.
    pub size: u64,
    /// The hashes of all parts (verified against the ID by the caller).
    pub hashes: &'a [[u8; 32]],
}

/// Who keeps a blob, and until when.
#[derive(Debug, Clone, Copy)]
pub struct Pin<'a> {
    /// What holds it: `up:<identity>` (an upload) or `app:<app-id>` (a hosted app).
    pub holder: &'a str,
    /// Whose quota it counts against.
    pub owner: &'a str,
    /// Until when (ms; an app pin holds until it is removed: `i64::MAX`). A pin never gets shorter.
    pub expires: i64,
    /// The owner's quota in bytes.
    pub quota: u64,
}

/// Result of registering a blob for a holder that pins it already ([`Store::blob_register`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// Registered (or it was known already).
    Ok,
    /// The holder does not pin this blob (any more): nothing registered.
    NotPinned,
    /// The node's storage for blobs is full.
    NodeFull,
}

/// Result of registering or pinning a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pinned {
    /// Pinned (new blob registered, or an existing one pinned).
    Ok,
    /// The owner's quota would be exceeded.
    Quota,
    /// The node's storage for blobs is full.
    NodeFull,
}

/// What a node knows about a blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobState {
    /// Size in bytes.
    pub size: u64,
    /// Number of parts.
    pub parts: u32,
    /// Parts present.
    pub present: u32,
    /// All parts present and the file renamed to its final name.
    pub complete: bool,
}

/// Result of marking a stored part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartStored {
    /// No such blob (or part number).
    Unknown,
    /// Marked; `all`: this was the last missing part.
    Added {
        /// All parts are present now.
        all: bool,
    },
    /// It was present already.
    Already,
}

/// One page of a hash list an uploader sends (`from` a multiple of 4,096).
#[derive(Debug, Clone, Copy)]
pub struct StagePage<'a> {
    /// Blob ID (wire form).
    pub id: &'a str,
    /// The uploader.
    pub owner: &'a str,
    /// Size of the blob.
    pub size: u64,
    /// Number of the first hash of this page.
    pub from: u32,
    /// The hashes of this page.
    pub hashes: &'a [[u8; 32]],
}

/// Result of staging one page of a hash list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staged {
    /// Stored; `known` hashes are there so far.
    Waiting {
        /// Hashes known so far.
        known: u32,
    },
    /// The list is complete: all hashes, in order (check them against the ID).
    Complete(Vec<[u8; 32]>),
    /// Too many hash lists are waiting (for this uploader or the node).
    Full,
    /// Pages out of order or not of the page size.
    Bad,
}

fn bitmap_len(parts: u32) -> usize {
    (parts as usize).div_ceil(8)
}

fn has_bit(bitmap: &[u8], index: u32) -> bool {
    bitmap.get(index as usize / 8).is_some_and(|byte| byte & (1 << (index % 8)) != 0)
}

fn set_bit(bitmap: &mut [u8], index: u32, on: bool) {
    if let Some(byte) = bitmap.get_mut(index as usize / 8) {
        if on {
            *byte |= 1 << (index % 8);
        } else {
            *byte &= !(1 << (index % 8));
        }
    }
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn charged(size: u64) -> u64 {
    size.max(CHARGED_MIN_BYTES)
}

/// Bytes the distinct blobs pinned by `owner` count against its quota: a registered blob with its size, a reserved one
/// that is not here yet with the size its pins name.
pub(crate) fn owner_bytes(transaction: &Transaction<'_>, owner: &str) -> StoreResult<u64> {
    let bytes: i64 = transaction.query_row(
        "SELECT COALESCE(SUM(MAX(COALESCE(blobs.size, pins.size), ?2)), 0)
         FROM (SELECT blob, MAX(size) AS size FROM blob_pins WHERE owner = ?1 GROUP BY blob) AS pins
         LEFT JOIN blobs ON blobs.id = pins.blob",
        params![owner, to_i64(CHARGED_MIN_BYTES)],
        |row| row.get(0),
    )?;
    Ok(to_u64(bytes))
}

/// Adds or extends a pin inside a transaction (the blob row exists). Quota only counts if the owner does not pin
/// this blob already.
fn pin_in(transaction: &Transaction<'_>, blob: &str, size: u64, pin: &Pin<'_>) -> StoreResult<Pinned> {
    let pinned_by_owner: Option<i64> = transaction
        .query_row("SELECT 1 FROM blob_pins WHERE blob = ?1 AND owner = ?2 LIMIT 1", params![blob, pin.owner], |row| {
            row.get(0)
        })
        .optional()?;
    if pinned_by_owner.is_none() && owner_bytes(transaction, pin.owner)?.saturating_add(charged(size)) > pin.quota {
        return Ok(Pinned::Quota);
    }
    transaction.execute(
        "INSERT INTO blob_pins (blob, holder, owner, expires, size) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (blob, holder) DO UPDATE SET expires = MAX(expires, excluded.expires), owner = excluded.owner,
         size = excluded.size",
        params![blob, pin.holder, pin.owner, pin.expires, to_i64(size)],
    )?;
    Ok(Pinned::Ok)
}

/// Whether the node has room for one more blob of `size` bytes.
fn node_has_room(transaction: &Transaction<'_>, size: u64, limits: &BlobLimits) -> StoreResult<bool> {
    let bytes: i64 =
        transaction.query_row("SELECT value FROM counters WHERE name = 'blob_bytes'", [], |row| row.get(0))?;
    let count: i64 =
        transaction.query_row("SELECT value FROM counters WHERE name = 'blob_count'", [], |row| row.get(0))?;
    Ok(to_u64(bytes).saturating_add(size) <= limits.max_node_bytes && to_u64(count) < limits.max_blobs)
}

/// Inserts a new blob row with its hash list and counts it.
fn insert_blob(transaction: &Transaction<'_>, blob: &NewBlob<'_>, parts: u32) -> StoreResult<()> {
    transaction.execute(
        "INSERT INTO blobs (id, size, parts, have, present, complete, created) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
        params![blob.id, to_i64(blob.size), parts, vec![0u8; bitmap_len(parts)], i64::from(parts == 0), 0i64],
    )?;
    for (row, chunk) in blob.hashes.chunks(HASHES_PER_ROW as usize).enumerate() {
        let bytes: Vec<u8> = chunk.iter().flatten().copied().collect();
        transaction.execute(
            "INSERT INTO blob_hashes (blob, row, hashes) VALUES (?1, ?2, ?3)",
            params![blob.id, row as i64, bytes],
        )?;
    }
    transaction.execute("UPDATE counters SET value = value + ?1 WHERE name = 'blob_bytes'", [to_i64(blob.size)])?;
    transaction.execute("UPDATE counters SET value = value + 1 WHERE name = 'blob_count'", [])?;
    Ok(())
}

impl Store {
    /// Registers a blob with its verified hash list (if new: node limits checked) and pins it (quota checked) - one
    /// transaction. An existing blob is only pinned.
    pub fn blob_add(&self, blob: &NewBlob<'_>, pin: &Pin<'_>, limits: &BlobLimits) -> StoreResult<Pinned> {
        let parts = u32::try_from(blob.hashes.len()).map_err(|_| StoreError::Database("too many parts".into()))?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let known: Option<i64> =
            transaction.query_row("SELECT size FROM blobs WHERE id = ?1", [blob.id], |row| row.get(0)).optional()?;
        if known.is_none() {
            if !node_has_room(&transaction, blob.size, limits)? {
                return Ok(Pinned::NodeFull);
            }
            if owner_bytes(&transaction, pin.owner)?.saturating_add(charged(blob.size)) > pin.quota {
                return Ok(Pinned::Quota);
            }
            insert_blob(&transaction, blob, parts)?;
        }
        let outcome = pin_in(&transaction, blob.id, blob.size, pin)?;
        if outcome == Pinned::Ok {
            transaction.commit()?;
        }
        Ok(outcome)
    }

    /// Registers a blob with its verified hash list for `holder`, which must pin it already (an app reserved it
    /// when it accepted the version - the quota was checked then). Node limits are checked; no pin is created, so a
    /// holder that stopped meanwhile gets [`Registered::NotPinned`] and nothing changes.
    pub fn blob_register(&self, blob: &NewBlob<'_>, holder: &str, limits: &BlobLimits) -> StoreResult<Registered> {
        let parts = u32::try_from(blob.hashes.len()).map_err(|_| StoreError::Database("too many parts".into()))?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pinned: Option<i64> = transaction
            .query_row("SELECT 1 FROM blob_pins WHERE blob = ?1 AND holder = ?2", params![blob.id, holder], |row| {
                row.get(0)
            })
            .optional()?;
        if pinned.is_none() {
            return Ok(Registered::NotPinned);
        }
        let known: Option<i64> =
            transaction.query_row("SELECT 1 FROM blobs WHERE id = ?1", [blob.id], |row| row.get(0)).optional()?;
        if known.is_none() {
            if !node_has_room(&transaction, blob.size, limits)? {
                return Ok(Registered::NodeFull);
            }
            insert_blob(&transaction, blob, parts)?;
            transaction.execute(
                "UPDATE blob_pins SET size = ?3 WHERE blob = ?1 AND holder = ?2",
                params![blob.id, holder, to_i64(blob.size)],
            )?;
        }
        transaction.commit()?;
        Ok(Registered::Ok)
    }

    /// Pins a known blob (`None`: unknown).
    pub fn blob_pin(&self, id: &str, pin: &Pin<'_>) -> StoreResult<Option<Pinned>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let size: Option<i64> =
            transaction.query_row("SELECT size FROM blobs WHERE id = ?1", [id], |row| row.get(0)).optional()?;
        let Some(size) = size else { return Ok(None) };
        let outcome = pin_in(&transaction, id, to_u64(size), pin)?;
        if outcome == Pinned::Ok {
            transaction.commit()?;
        }
        Ok(Some(outcome))
    }

    /// What this node knows about a blob.
    pub fn blob_state(&self, id: &str) -> StoreResult<Option<BlobState>> {
        Ok(self
            .lock()?
            .query_row("SELECT size, parts, present, complete FROM blobs WHERE id = ?1", [id], |row| {
                Ok(BlobState {
                    size: to_u64(row.get(0)?),
                    parts: u32::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    present: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    complete: row.get::<_, i64>(3)? != 0,
                })
            })
            .optional()?)
    }

    /// Up to `max` numbers of parts that are not present, ascending from `from`.
    pub fn blob_missing(&self, id: &str, from: u32, max: usize) -> StoreResult<Vec<u32>> {
        let row: Option<(i64, Vec<u8>)> = self
            .lock()?
            .query_row("SELECT parts, have FROM blobs WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let Some((parts, have)) = row else { return Ok(Vec::new()) };
        let parts = u32::try_from(parts).unwrap_or(0);
        Ok((from..parts).filter(|index| !has_bit(&have, *index)).take(max).collect())
    }

    /// Hashes `from..from+max` of a known blob (`None`: unknown blob).
    pub fn blob_hashes(&self, id: &str, from: u32, max: u32) -> StoreResult<Option<Vec<[u8; 32]>>> {
        let connection = self.lock()?;
        let parts: Option<i64> =
            connection.query_row("SELECT parts FROM blobs WHERE id = ?1", [id], |row| row.get(0)).optional()?;
        let Some(parts) = parts else { return Ok(None) };
        let parts = u32::try_from(parts).unwrap_or(0);
        let end = from.saturating_add(max).min(parts);
        let mut out = Vec::with_capacity(end.saturating_sub(from) as usize);
        let mut statement = connection.prepare_cached("SELECT hashes FROM blob_hashes WHERE blob = ?1 AND row = ?2")?;
        let mut index = from;
        while index < end {
            let row = index / HASHES_PER_ROW;
            let bytes: Vec<u8> = statement.query_row(params![id, i64::from(row)], |row| row.get(0))?;
            while index < end && index / HASHES_PER_ROW == row {
                let start = (index % HASHES_PER_ROW) as usize * 32;
                let hash: [u8; 32] = bytes
                    .get(start..start + 32)
                    .and_then(|slice| slice.try_into().ok())
                    .ok_or_else(|| StoreError::Database("hash list row too short".into()))?;
                out.push(hash);
                index += 1;
            }
        }
        Ok(Some(out))
    }

    /// Size of a blob and the hash of part `index` (`None`: unknown blob or part).
    pub fn blob_part_hash(&self, id: &str, index: u32) -> StoreResult<Option<(u64, [u8; 32])>> {
        let size: Option<i64> = self
            .lock()?
            .query_row("SELECT size FROM blobs WHERE id = ?1 AND parts > ?2", params![id, index], |row| row.get(0))
            .optional()?;
        let Some(size) = size else { return Ok(None) };
        Ok(self.blob_hashes(id, index, 1)?.and_then(|list| list.first().copied()).map(|hash| (to_u64(size), hash)))
    }

    /// Whether `holder` pins the blob and the pin has not run out at `now` (expired pins wait for the garbage
    /// collection, but no longer count).
    pub fn blob_pinned_by(&self, id: &str, holder: &str, now: i64) -> StoreResult<bool> {
        let found: Option<i64> = self
            .lock()?
            .query_row(
                "SELECT 1 FROM blob_pins WHERE blob = ?1 AND holder = ?2 AND expires > ?3",
                params![id, holder, now],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Up to `max` blobs pinned by `holder` that miss parts (registered ones only).
    pub fn blobs_incomplete(&self, holder: &str, max: usize) -> StoreResult<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id FROM blobs WHERE present < parts AND id IN (SELECT blob FROM blob_pins WHERE holder = ?1)
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![holder, i64::try_from(max).unwrap_or(i64::MAX)], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Whether part `index` is present.
    pub fn blob_has_part(&self, id: &str, index: u32) -> StoreResult<bool> {
        let have: Option<Vec<u8>> =
            self.lock()?.query_row("SELECT have FROM blobs WHERE id = ?1", [id], |row| row.get(0)).optional()?;
        Ok(have.is_some_and(|have| has_bit(&have, index)))
    }

    /// Marks part `index` as present (after the caller verified and wrote it).
    pub fn blob_part_stored(&self, id: &str, index: u32) -> StoreResult<PartStored> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(i64, Vec<u8>, i64)> = transaction
            .query_row("SELECT parts, have, present FROM blobs WHERE id = ?1", [id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .optional()?;
        let Some((parts, mut have, present)) = row else { return Ok(PartStored::Unknown) };
        if i64::from(index) >= parts || have.len() != bitmap_len(u32::try_from(parts).unwrap_or(0)) {
            return Ok(PartStored::Unknown);
        }
        if has_bit(&have, index) {
            return Ok(PartStored::Already);
        }
        set_bit(&mut have, index, true);
        transaction.execute("UPDATE blobs SET have = ?2, present = present + 1 WHERE id = ?1", params![id, have])?;
        transaction.commit()?;
        Ok(PartStored::Added { all: present + 1 == parts })
    }

    /// Marks a blob complete (its file has its final name) or not.
    pub fn blob_set_complete(&self, id: &str, complete: bool) -> StoreResult<()> {
        self.lock()?.execute("UPDATE blobs SET complete = ?2 WHERE id = ?1", params![id, i64::from(complete)])?;
        Ok(())
    }

    /// A part did not verify when read (damaged file): not present any more, the blob not complete. Returns whether
    /// it was complete before (then the caller renames the file back).
    pub fn blob_part_lost(&self, id: &str, index: u32) -> StoreResult<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(Vec<u8>, i64)> = transaction
            .query_row("SELECT have, complete FROM blobs WHERE id = ?1", [id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let Some((mut have, complete)) = row else { return Ok(false) };
        if has_bit(&have, index) {
            set_bit(&mut have, index, false);
            transaction.execute(
                "UPDATE blobs SET have = ?2, present = present - 1, complete = 0 WHERE id = ?1",
                params![id, have],
            )?;
        } else {
            transaction.execute("UPDATE blobs SET complete = 0 WHERE id = ?1", [id])?;
        }
        transaction.commit()?;
        Ok(complete != 0)
    }

    /// Removes every pin of `holder`. Returns how many.
    pub fn blob_unpin(&self, holder: &str) -> StoreResult<usize> {
        Ok(self.lock()?.execute("DELETE FROM blob_pins WHERE holder = ?1", [holder])?)
    }

    /// Removes the pins of `holder` on blobs not in `keep`. Returns how many.
    pub fn blob_retain(&self, holder: &str, keep: &[String]) -> StoreResult<usize> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let pinned: Vec<String> = {
            let mut statement = transaction.prepare("SELECT blob FROM blob_pins WHERE holder = ?1")?;
            let rows = statement.query_map([holder], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut removed = 0;
        for blob in pinned.iter().filter(|blob| !keep.contains(blob)) {
            removed +=
                transaction.execute("DELETE FROM blob_pins WHERE holder = ?1 AND blob = ?2", params![holder, blob])?;
        }
        transaction.commit()?;
        Ok(removed)
    }

    /// Bytes the blobs pinned by `owner` count against its quota.
    pub fn blob_owner_bytes(&self, owner: &str) -> StoreResult<u64> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        owner_bytes(&transaction, owner)
    }

    /// Bytes and number of all blobs of this node.
    pub fn blob_totals(&self) -> StoreResult<(u64, u64)> {
        let connection = self.lock()?;
        let value = |name: &str| -> StoreResult<u64> {
            Ok(to_u64(connection.query_row("SELECT value FROM counters WHERE name = ?1", [name], |row| row.get(0))?))
        };
        Ok((value("blob_bytes")?, value("blob_count")?))
    }

    /// Stores one page of a hash list that `owner` uploads for a blob of `size` bytes with `parts` parts (pages of
    /// 4,096 hashes, `from` a multiple of it, in order; a page again replaces it). When all pages are there, returns
    /// the whole list (the caller checks it against the ID and drops the staging).
    pub fn blob_stage(&self, page: &StagePage<'_>, limits: &BlobLimits, now: i64) -> StoreResult<Staged> {
        let StagePage { id, owner, size, from, hashes } = *page;
        let parts = bridge_core::blob::parts_for(size).map_err(|e| StoreError::Database(e.to_string()))?;
        let page = from / STAGING_PAGE;
        let expected = parts.saturating_sub(from).min(STAGING_PAGE) as usize;
        if from % STAGING_PAGE != 0 || from >= parts || hashes.len() != expected {
            return Ok(Staged::Bad);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // A list with another size from the same uploader is replaced.
        transaction.execute(
            "DELETE FROM blob_staging WHERE blob = ?1 AND owner = ?2 AND size != ?3",
            params![id, owner, to_i64(size)],
        )?;
        let pages: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM blob_staging WHERE blob = ?1 AND owner = ?2",
            params![id, owner],
            |row| row.get(0),
        )?;
        if pages == 0 {
            let mine: i64 = transaction.query_row(
                "SELECT COUNT(DISTINCT blob) FROM blob_staging WHERE owner = ?1",
                [owner],
                |row| row.get(0),
            )?;
            let all: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM (SELECT DISTINCT blob, owner FROM blob_staging)",
                [],
                |row| row.get(0),
            )?;
            if to_u64(mine) >= limits.max_staged_per_owner || to_u64(all) >= limits.max_staged {
                return Ok(Staged::Full);
            }
        }
        if i64::from(page) > pages {
            return Ok(Staged::Bad); // a page is missing before this one
        }
        let bytes: Vec<u8> = hashes.iter().flatten().copied().collect();
        transaction.execute(
            "INSERT INTO blob_staging (blob, owner, page, size, hashes, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (blob, owner, page) DO UPDATE SET hashes = excluded.hashes",
            params![id, owner, i64::from(page), to_i64(size), bytes, now],
        )?;
        let total_pages = i64::from(parts.div_ceil(STAGING_PAGE));
        let pages = pages.max(i64::from(page) + 1);
        if pages < total_pages {
            transaction.commit()?;
            let known = u32::try_from(pages).unwrap_or(0).saturating_mul(STAGING_PAGE).min(parts);
            return Ok(Staged::Waiting { known });
        }
        let mut list: Vec<[u8; 32]> = Vec::with_capacity(parts as usize);
        {
            let mut statement =
                transaction.prepare("SELECT hashes FROM blob_staging WHERE blob = ?1 AND owner = ?2 ORDER BY page")?;
            let rows = statement.query_map(params![id, owner], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                for chunk in row?.chunks_exact(32) {
                    let hash: [u8; 32] =
                        chunk.try_into().map_err(|_| StoreError::Database("staged hash too short".into()))?;
                    list.push(hash);
                }
            }
        }
        transaction.commit()?;
        Ok(Staged::Complete(list))
    }

    /// Drops the staged hash list of `owner` for a blob.
    pub fn blob_stage_drop(&self, id: &str, owner: &str) -> StoreResult<()> {
        self.lock()?.execute("DELETE FROM blob_staging WHERE blob = ?1 AND owner = ?2", params![id, owner])?;
        Ok(())
    }

    /// Garbage collection (janitor): drops expired pins and old staged hash lists, then removes up to `max` blobs
    /// that nothing pins any more (rows first - the caller deletes their files). Returns their IDs.
    pub fn blob_gc(&self, now: i64, max: usize) -> StoreResult<Vec<String>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM blob_pins WHERE expires <= ?1", [now])?;
        // Pins of apps this node does not host (any more): a safety net - stopping removes them in its transaction.
        let prefix_len = i64::try_from(APP_PIN_PREFIX.len()).unwrap_or(0);
        transaction.execute(
            "DELETE FROM blob_pins WHERE substr(holder, 1, ?1) = ?2 AND NOT EXISTS (SELECT 1 FROM apps
               WHERE apps.state != 'stopped' AND apps.app = substr(blob_pins.holder, ?1 + 1))",
            params![prefix_len, APP_PIN_PREFIX],
        )?;
        transaction
            .execute("DELETE FROM blob_staging WHERE created <= ?1", [now.saturating_sub(STAGING_LIFETIME_MS)])?;
        let unpinned: Vec<(String, i64)> = {
            let mut statement = transaction.prepare(
                "SELECT id, size FROM blobs WHERE NOT EXISTS (SELECT 1 FROM blob_pins WHERE blob_pins.blob = blobs.id)
                 LIMIT ?1",
            )?;
            let rows =
                statement.query_map([i64::try_from(max).unwrap_or(i64::MAX)], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        for (id, size) in &unpinned {
            transaction.execute("DELETE FROM blob_hashes WHERE blob = ?1", [id])?;
            transaction.execute("DELETE FROM blobs WHERE id = ?1", [id])?;
            transaction.execute("UPDATE counters SET value = value - ?1 WHERE name = 'blob_bytes'", [size])?;
            transaction.execute("UPDATE counters SET value = value - 1 WHERE name = 'blob_count'", [])?;
        }
        transaction.commit()?;
        Ok(unpinned.into_iter().map(|(id, _)| id).collect())
    }
}

/// The bytes of blobs as files in one folder (see module docs). Plain I/O - the node verifies what it reads.
#[derive(Debug, Clone)]
pub struct BlobFiles {
    dir: PathBuf,
}

/// Longest accepted file name stem (64 hex characters).
const HEX_LEN: usize = 64;

impl BlobFiles {
    /// Blob files in `dir` (created on the first write).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The folder.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn paths(&self, hex: &str) -> std::io::Result<(PathBuf, PathBuf)> {
        if hex.len() != HEX_LEN || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "blob file name: 64 hex characters"));
        }
        let folder = self.dir.join(&hex[..2]);
        Ok((folder.join(hex), folder.join(format!("{hex}.part"))))
    }

    /// Writes part `index` (at `offset`) of the blob with `size` bytes into its `.part` file and syncs it.
    pub fn write_part(&self, hex: &str, size: u64, offset: u64, data: &[u8]) -> std::io::Result<()> {
        let (_, part) = self.paths(hex)?;
        if let Some(folder) = part.parent() {
            fs::create_dir_all(folder)?;
        }
        let mut file = fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&part)?;
        if file.metadata()?.len() != size {
            file.set_len(size)?;
        }
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        file.sync_data()
    }

    /// All parts are there: sync and give the file its final name.
    pub fn finish(&self, hex: &str) -> std::io::Result<()> {
        let (done, part) = self.paths(hex)?;
        if part.exists() {
            // Windows: FlushFileBuffers needs a handle with write access (a read-only one gives "access denied").
            fs::OpenOptions::new().write(true).open(&part)?.sync_all()?;
            fs::rename(&part, &done)?;
        }
        Ok(())
    }

    /// A part of a complete blob was lost: back to the temporary name (parts get written again).
    pub fn unfinish(&self, hex: &str) -> std::io::Result<()> {
        let (done, part) = self.paths(hex)?;
        if done.exists() {
            fs::rename(&done, &part)?;
        }
        Ok(())
    }

    /// Reads `len` bytes at `offset` (final name first, then the temporary one). A file that is too short gives
    /// [`std::io::ErrorKind::UnexpectedEof`] - the only error that says something about the data (others, like a
    /// missing or locked file, may pass).
    pub fn read_part(&self, hex: &str, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        Self::read_at(&mut self.open(hex)?, offset, len)
    }

    /// Opens a blob's file for reading (final name first, then the temporary one).
    pub fn open(&self, hex: &str) -> std::io::Result<fs::File> {
        let (done, part) = self.paths(hex)?;
        match fs::File::open(&done) {
            Ok(file) => Ok(file),
            Err(_) => fs::File::open(&part),
        }
    }

    /// Reads `len` bytes at `offset` of an open blob file.
    pub fn read_at(file: &mut fs::File, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        file.seek(SeekFrom::Start(offset))?;
        let mut data = vec![0u8; len];
        file.read_exact(&mut data)?;
        Ok(data)
    }

    /// Removes both names of a blob's file (missing files are fine).
    pub fn remove(&self, hex: &str) -> std::io::Result<()> {
        let (done, part) = self.paths(hex)?;
        for path in [done, part] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: BlobLimits = BlobLimits {
        quota: [20_000, 100_000, 1_000_000],
        max_node_bytes: 200_000,
        max_blobs: 4,
        max_keep_days: 30,
        max_staged_per_owner: 1,
        max_staged: 2,
    };

    fn pin<'a>(holder: &'a str, owner: &'a str, quota: u64) -> Pin<'a> {
        Pin { holder, owner, expires: 1_000, quota }
    }

    #[test]
    fn add_pin_quota_and_node_limits() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let hashes = [[1u8; 32], [2u8; 32]];
        let blob = NewBlob { id: "b1", size: 70_000, hashes: &hashes };
        assert_eq!(store.blob_add(&blob, &pin("up:alice", "alice", 20_000), &LIMITS)?, Pinned::Quota);
        assert_eq!(store.blob_state("b1")?, None, "nothing registered when the quota says no");
        assert_eq!(store.blob_add(&blob, &pin("up:alice", "alice", 100_000), &LIMITS)?, Pinned::Ok);
        assert_eq!(store.blob_state("b1")?, Some(BlobState { size: 70_000, parts: 2, present: 0, complete: false }));
        assert_eq!(store.blob_hashes("b1", 0, 10)?, Some(hashes.to_vec()));
        assert_eq!(store.blob_hashes("b1", 1, 10)?, Some(vec![[2u8; 32]]));
        assert_eq!(store.blob_part_hash("b1", 1)?, Some((70_000, [2u8; 32])));
        assert_eq!(store.blob_part_hash("b1", 2)?, None);
        // The same owner pins it again under another holder: counted once.
        assert_eq!(store.blob_pin("b1", &pin("app:x", "alice", 70_000))?, Some(Pinned::Ok));
        assert_eq!(store.blob_owner_bytes("alice")?, 70_000);
        // Tiny blobs count at least 4 KiB.
        let tiny = NewBlob { id: "b2", size: 1, hashes: &[[3u8; 32]] };
        assert_eq!(store.blob_add(&tiny, &pin("up:bob", "bob", 4_095), &LIMITS)?, Pinned::Quota);
        assert_eq!(store.blob_add(&tiny, &pin("up:bob", "bob", 4_096), &LIMITS)?, Pinned::Ok);
        // Node limits: bytes, then the number of blobs.
        let big = NewBlob { id: "b3", size: 140_000, hashes: &[[4u8; 32], [5u8; 32], [6u8; 32]] };
        assert_eq!(store.blob_add(&big, &pin("up:carol", "carol", 1_000_000), &LIMITS)?, Pinned::NodeFull);
        for id in ["b4", "b5"] {
            let small = NewBlob { id, size: 10, hashes: &[[7u8; 32]] };
            store.blob_add(&small, &pin("up:carol", "carol", 1_000_000), &LIMITS)?;
        }
        let one_more = NewBlob { id: "b6", size: 10, hashes: &[[8u8; 32]] };
        assert_eq!(store.blob_add(&one_more, &pin("up:carol", "carol", 1_000_000), &LIMITS)?, Pinned::NodeFull);
        assert_eq!(store.blob_totals()?, (70_021, 4));
        assert_eq!(store.blob_pin("nope", &pin("up:x", "x", 1))?, None);
        // An empty blob is complete right away.
        let store = Store::open_in_memory()?;
        store.blob_add(&NewBlob { id: "e", size: 0, hashes: &[] }, &pin("up:a", "a", 10_000), &LIMITS)?;
        assert_eq!(store.blob_state("e")?.map(|state| state.complete), Some(true));
        Ok(())
    }

    #[test]
    fn parts_lost_parts_and_gc() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let hashes = [[1u8; 32], [2u8; 32], [3u8; 32]];
        store.blob_add(&NewBlob { id: "b", size: 150_000, hashes: &hashes }, &pin("up:a", "a", 1 << 20), &LIMITS)?;
        assert_eq!(store.blob_missing("b", 0, 10)?, vec![0, 1, 2]);
        assert_eq!(store.blob_part_stored("b", 1)?, PartStored::Added { all: false });
        assert_eq!(store.blob_part_stored("b", 1)?, PartStored::Already);
        assert_eq!(store.blob_part_stored("b", 3)?, PartStored::Unknown);
        assert_eq!(store.blob_part_stored("x", 0)?, PartStored::Unknown);
        assert_eq!(store.blob_part_stored("b", 0)?, PartStored::Added { all: false });
        assert_eq!(store.blob_missing("b", 0, 10)?, vec![2]);
        assert_eq!(store.blob_part_stored("b", 2)?, PartStored::Added { all: true });
        store.blob_set_complete("b", true)?;
        assert!(store.blob_has_part("b", 2)?);
        assert!(store.blob_part_lost("b", 2)?, "was complete");
        assert_eq!(store.blob_state("b")?.map(|state| (state.present, state.complete)), Some((2, false)));
        assert_eq!(store.blob_missing("b", 0, 10)?, vec![2]);
        // GC: pinned until 1000.
        assert!(store.blob_gc(999, 10)?.is_empty());
        assert_eq!(store.blob_gc(1_000, 10)?, vec!["b".to_owned()]);
        assert_eq!(store.blob_state("b")?, None);
        assert_eq!(store.blob_hashes("b", 0, 1)?, None);
        assert_eq!(store.blob_totals()?, (0, 0));
        // App pins hold until removed; retain keeps only what is listed.
        for (id, hash) in [("p", [1u8; 32]), ("q", [2u8; 32])] {
            let app = Pin { holder: "app:z", owner: "a", expires: i64::MAX, quota: 1 << 20 };
            store.blob_add(&NewBlob { id, size: 5, hashes: &[hash] }, &app, &LIMITS)?;
        }
        assert_eq!(store.blob_retain("app:z", &["q".to_owned()])?, 1);
        // `app:z` is no app this node hosts: the garbage collection drops its pins as well (safety net).
        assert_eq!(store.blob_gc(i64::MAX - 1, 10)?, vec!["p".to_owned(), "q".to_owned()]);
        assert_eq!(store.blob_unpin("app:z")?, 0);
        Ok(())
    }

    #[test]
    fn pins_count_only_until_they_expire_and_orphaned_app_pins_go() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        store.blob_add(&NewBlob { id: "b", size: 5, hashes: &[[1u8; 32]] }, &pin("up:a", "a", 1 << 20), &LIMITS)?;
        assert!(store.blob_pinned_by("b", "up:a", 999)?);
        assert!(!store.blob_pinned_by("b", "up:a", 1_000)?, "expired (the GC has not run yet)");
        assert!(!store.blob_pinned_by("b", "up:x", 0)?);
        // A hosted app keeps its pins; once the app is not active any more, the GC removes them.
        let limits = crate::AppLimits {
            max_active: 4,
            max_active_per_owner: 4,
            max_stopped: 4,
            max_stopped_per_owner: 4,
            forget_before: 0,
        };
        let row = crate::AppRow {
            app: "z".into(),
            owner: "a".into(),
            version: 1,
            hash: Some([1u8; 32]),
            state: crate::AppState::Fetching,
            current: None,
            previous: None,
            pending: None,
            updated: 0,
        };
        store.app_put(&row, &limits)?;
        let app = Pin { holder: "app:z", owner: "a", expires: i64::MAX, quota: 1 << 20 };
        store.blob_add(&NewBlob { id: "c", size: 5, hashes: &[[2u8; 32]] }, &app, &LIMITS)?;
        assert_eq!(store.blob_gc(2_000, 10)?, vec!["b".to_owned()], "the app's blob stays");
        store.app_put(&crate::AppRow { state: crate::AppState::Stopped, ..row }, &limits)?;
        assert_eq!(store.blob_gc(2_000, 10)?, vec!["c".to_owned()], "a pin left behind by a race is cleaned");
        Ok(())
    }

    #[test]
    fn staged_hash_lists() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let size = 4097 * 65_536; // 4,097 parts: two pages
        let first: Vec<[u8; 32]> = (0..4096u32).map(|i| [(i % 251) as u8; 32]).collect();
        let second = vec![[9u8; 32]];
        // Pages in order only, of the right length.
        assert_eq!(
            store.blob_stage(&StagePage { id: "b", owner: "a", size, from: 4096, hashes: &second }, &LIMITS, 0)?,
            Staged::Bad
        );
        assert_eq!(
            store.blob_stage(&StagePage { id: "b", owner: "a", size, from: 0, hashes: &first[..10] }, &LIMITS, 0)?,
            Staged::Bad
        );
        assert_eq!(
            store.blob_stage(&StagePage { id: "b", owner: "a", size, from: 1, hashes: &first }, &LIMITS, 0)?,
            Staged::Bad
        );
        assert_eq!(
            store.blob_stage(&StagePage { id: "b", owner: "a", size, from: 0, hashes: &first }, &LIMITS, 0)?,
            Staged::Waiting { known: 4096 }
        );
        // One list per uploader at a time (limit 1), two on the node.
        assert_eq!(
            store.blob_stage(&StagePage { id: "c", owner: "a", size, from: 0, hashes: &first }, &LIMITS, 0)?,
            Staged::Full
        );
        assert_eq!(
            store.blob_stage(&StagePage { id: "b", owner: "x", size, from: 0, hashes: &first }, &LIMITS, 0)?,
            Staged::Waiting { known: 4096 }
        );
        assert_eq!(
            store.blob_stage(&StagePage { id: "c", owner: "y", size, from: 0, hashes: &first }, &LIMITS, 0)?,
            Staged::Full
        );
        let Staged::Complete(list) =
            store.blob_stage(&StagePage { id: "b", owner: "a", size, from: 4096, hashes: &second }, &LIMITS, 0)?
        else {
            return Err(StoreError::Database("expected the complete list".into()));
        };
        assert_eq!(list.len(), 4097);
        assert_eq!(list[4096], [9u8; 32]);
        assert_eq!(list[..4096], first[..]);
        store.blob_stage_drop("b", "a")?;
        // Old staging goes in the GC.
        store.blob_gc(STAGING_LIFETIME_MS + 1, 10)?;
        assert_eq!(
            store.blob_stage(&StagePage { id: "c", owner: "y", size, from: 0, hashes: &first }, &LIMITS, 0)?,
            Staged::Waiting { known: 4096 }
        );
        Ok(())
    }

    #[test]
    fn files() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let files = BlobFiles::new(dir.path().join("blobs"));
        let hex = "ab".repeat(32);
        files.write_part(&hex, 10, 5, b"world")?;
        files.write_part(&hex, 10, 0, b"hello")?;
        assert_eq!(files.read_part(&hex, 0, 10)?, b"helloworld");
        assert!(dir.path().join("blobs/ab").join(format!("{hex}.part")).exists());
        files.finish(&hex)?;
        assert!(dir.path().join("blobs/ab").join(&hex).exists());
        assert_eq!(files.read_part(&hex, 5, 5)?, b"world");
        assert!(files.read_part(&hex, 8, 5).is_err(), "past the end");
        files.unfinish(&hex)?;
        assert_eq!(files.read_part(&hex, 0, 5)?, b"hello");
        files.remove(&hex)?;
        files.remove(&hex)?;
        assert!(files.read_part(&hex, 0, 1).is_err());
        for bad in ["../../etc/passwd", "AB", &"AB".repeat(32), &"g".repeat(64)] {
            assert!(files.write_part(bad, 1, 0, b"x").is_err(), "{bad}");
        }
        Ok(())
    }
}
