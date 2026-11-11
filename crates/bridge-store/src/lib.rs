//! # bridge-store – persistence
//!
//! One SQLite database per node (WAL mode, `synchronous = FULL`: an accepted message survives a crash or power loss)
//! with numbered schema migrations. Stores only what a node may see: key cards (public), encrypted envelopes in
//! mailboxes, and the IDs of accepted envelopes for replay protection. Nothing here can decrypt anything.
//!
//! Since schema 3 also what a node of a BridgeNet keeps (docs/06): the log entries it follows, the latest heads of
//! the log operators with their cosignatures, split-view evidence, the `home` entries of members, and the outbox of
//! envelopes waiting to be relayed to another gateway; since schema 4 the transition heads of changes of the log
//! rules. All of it is public or encrypted - still nothing to decrypt.
//!
//! Since schema 5 files and apps (docs/07): blobs (verified hash lists, which parts are present, pins with owner and
//! expiry for quotas), their bytes as files in the `blobs/` folder of the data folder ([`BlobFiles`]: content
//! addressed by the hex blob ID, written under a temporary name and renamed when complete), and the apps a node
//! hosts. Since schema 6 a pin carries the bytes it reserves (an accepted app version reserves its whole size, also
//! for blobs that are not here yet) and an app its rank (version + statement hash; a stopped app keeps only that).
//!
//! Since schema 7 what a watcher keeps (docs/06 §11.7): the nodes registered for probes and their probe history;
//! since schema 8 with the time of the first registration (a full table makes room by that order).
//!
//! Layering (docs/03_ARCHITEKTUR.md): depends only on `bridge-core`. It never checks hashes or signatures itself -
//! the node verifies every part before it is stored and after it is read.
//! Quotas are passed in by the caller (`bridge-guard` decides them) and checked atomically with the insert, so two
//! parallel deliveries can never exceed them together.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

mod apps;
mod blobs;
mod net;
mod watch;

pub use apps::{AppLimits, AppRow, AppState, AppStored, Reservation};
pub use blobs::{
    APP_PIN_PREFIX, BlobFiles, BlobLimits, BlobState, CHARGED_MIN_BYTES, HASHES_PER_ROW, NewBlob, PartStored, Pin,
    Pinned, Registered, StagePage, Staged,
};
pub use net::{
    HeadRow, HomeRow, HomeStored, MAX_EVIDENCE_PER_NET, MAX_HEAD_ROWS_PER_NET, Outgoing, RelayItem, RelayLimits,
    TransitionRow,
};
pub use watch::{Probe, Registration, Standing, WatchNode, WatchRegistered};

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-store";

/// Schema migrations; index + 1 = schema version. Never change an existing entry - only append (S5: one truth).
const MIGRATIONS: &[&str] = &[
    // 1: cards, mailboxes, replay protection
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
     CREATE TABLE cards (id TEXT PRIMARY KEY, card BLOB NOT NULL, first_seen INTEGER NOT NULL,
                         last_seen INTEGER NOT NULL);
     CREATE TABLE mailbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, sender TEXT NOT NULL,
                           env_id BLOB NOT NULL, expires_at INTEGER NOT NULL, size INTEGER NOT NULL,
                           envelope BLOB NOT NULL, received_at INTEGER NOT NULL,
                           UNIQUE (recipient, sender, env_id));
     CREATE INDEX mailbox_by_recipient ON mailbox (recipient, seq);
     CREATE INDEX mailbox_by_expiry ON mailbox (expires_at);
     CREATE TABLE seen (sender TEXT NOT NULL, env_id BLOB NOT NULL, expires_at INTEGER NOT NULL,
                        PRIMARY KEY (sender, env_id)) WITHOUT ROWID;
     CREATE INDEX seen_by_expiry ON seen (expires_at);",
    // 2: running totals, so a delivery never has to scan all mailboxes
    "CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
     INSERT INTO counters (name, value) SELECT 'mailbox_bytes', COALESCE(SUM(size), 0) FROM mailbox;",
    // 3: BridgeNet (docs/06): log entries per network, latest heads per operator and role (+ cosignatures),
    // split-view evidence, one `home` entry per member (newest wins), relay outbox
    "CREATE TABLE net_log (net TEXT NOT NULL, idx INTEGER NOT NULL, entry BLOB NOT NULL,
                           PRIMARY KEY (net, idx)) WITHOUT ROWID;
     CREATE TABLE net_heads (net TEXT NOT NULL, operator TEXT NOT NULL, role TEXT NOT NULL, size INTEGER NOT NULL,
                             head BLOB NOT NULL, cosigns BLOB NOT NULL, updated INTEGER NOT NULL,
                             PRIMARY KEY (net, operator, role)) WITHOUT ROWID;
     CREATE TABLE net_evidence (net TEXT NOT NULL, operator TEXT NOT NULL, evidence BLOB NOT NULL,
                                received INTEGER NOT NULL, PRIMARY KEY (net, operator)) WITHOUT ROWID;
     CREATE TABLE net_homes (net TEXT NOT NULL, member TEXT NOT NULL, node TEXT NOT NULL, iat INTEGER NOT NULL,
                             exp INTEGER NOT NULL, seq INTEGER NOT NULL, home BLOB NOT NULL, card BLOB NOT NULL,
                             PRIMARY KEY (net, member)) WITHOUT ROWID;
     CREATE INDEX net_homes_by_node ON net_homes (net, node, seq);
     CREATE INDEX net_homes_by_exp ON net_homes (exp);
     CREATE TABLE relay_outbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, sender TEXT NOT NULL,
                                env_id BLOB NOT NULL, expires_at INTEGER NOT NULL, next_attempt INTEGER NOT NULL,
                                attempts INTEGER NOT NULL, size INTEGER NOT NULL, envelope BLOB NOT NULL,
                                card BLOB NOT NULL, UNIQUE (sender, env_id));
     CREATE INDEX relay_by_due ON relay_outbox (next_attempt);
     CREATE INDEX relay_by_expiry ON relay_outbox (expires_at);
     CREATE INDEX relay_by_target ON relay_outbox (target);
     INSERT INTO counters (name, value) VALUES ('relay_bytes', 0), ('home_seq', 0);",
    // 4: BridgeNet transition heads (docs/06 §5 "Übergänge beim Aufholen"): the witnessed head that ends with each
    // change of the log rules, kept for good (bounded per network) and served to followers that catch up
    "CREATE TABLE net_transitions (net TEXT NOT NULL, size INTEGER NOT NULL, head BLOB NOT NULL,
                                   cosigns BLOB NOT NULL, PRIMARY KEY (net, size)) WITHOUT ROWID;",
    // 5: files and apps (docs/07): blobs with their verified hash lists (rows of 1024 hashes) and which parts are
    // present (bitmap), pins (holder + owner for quotas + expiry), hash lists still being uploaded (per uploader),
    // hosted apps (newest manifest, the one before, one being fetched, state). The bytes are files in `blobs/`.
    "CREATE TABLE blobs (id TEXT PRIMARY KEY, size INTEGER NOT NULL, parts INTEGER NOT NULL, have BLOB NOT NULL,
                         present INTEGER NOT NULL, complete INTEGER NOT NULL, created INTEGER NOT NULL) WITHOUT ROWID;
     CREATE TABLE blob_hashes (blob TEXT NOT NULL, row INTEGER NOT NULL, hashes BLOB NOT NULL,
                               PRIMARY KEY (blob, row)) WITHOUT ROWID;
     CREATE TABLE blob_pins (blob TEXT NOT NULL, holder TEXT NOT NULL, owner TEXT NOT NULL, expires INTEGER NOT NULL,
                             PRIMARY KEY (blob, holder)) WITHOUT ROWID;
     CREATE INDEX blob_pins_by_owner ON blob_pins (owner, blob);
     CREATE INDEX blob_pins_by_holder ON blob_pins (holder);
     CREATE INDEX blob_pins_by_expiry ON blob_pins (expires);
     CREATE TABLE blob_staging (blob TEXT NOT NULL, owner TEXT NOT NULL, page INTEGER NOT NULL, size INTEGER NOT NULL,
                                hashes BLOB NOT NULL, created INTEGER NOT NULL,
                                PRIMARY KEY (blob, owner, page)) WITHOUT ROWID;
     CREATE INDEX blob_staging_by_owner ON blob_staging (owner);
     CREATE TABLE apps (app TEXT PRIMARY KEY, owner TEXT NOT NULL, version INTEGER NOT NULL, state TEXT NOT NULL,
                        current BLOB, previous BLOB, pending BLOB, updated INTEGER NOT NULL) WITHOUT ROWID;
     CREATE INDEX apps_by_state ON apps (state, updated);
     INSERT INTO counters (name, value) VALUES ('blob_bytes', 0), ('blob_count', 0);",
    // 6: review 7 of phase 4a (docs/07 §3, §5): a pin carries the bytes it reserves (an app version reserves its whole
    // size when it is accepted, also for blobs that are not here yet); an app carries its rank (version + statement
    // hash), so a stopped app keeps only ID, owner and rank; apps are counted per owner.
    "ALTER TABLE blob_pins ADD COLUMN size INTEGER NOT NULL DEFAULT 0;
     UPDATE blob_pins SET size = COALESCE((SELECT size FROM blobs WHERE blobs.id = blob_pins.blob), 0);
     ALTER TABLE apps ADD COLUMN hash BLOB;
     CREATE INDEX apps_by_owner ON apps (owner, state, updated);",
    // 7: watchers (docs/06 §11.7): nodes registered for probes (card, requested services, until when, observed since,
    // failures in a row, last probe) and the probe history (bounded per node by the node).
    "CREATE TABLE watch_nodes (net TEXT NOT NULL, node TEXT NOT NULL, card BLOB NOT NULL, card_iat INTEGER NOT NULL,
                               services TEXT NOT NULL, expires INTEGER NOT NULL, since INTEGER,
                               fails INTEGER NOT NULL, last_probe INTEGER, last_ok INTEGER NOT NULL,
                               PRIMARY KEY (net, node)) WITHOUT ROWID;
     CREATE INDEX watch_nodes_by_expiry ON watch_nodes (expires);
     CREATE TABLE watch_probes (net TEXT NOT NULL, node TEXT NOT NULL, at INTEGER NOT NULL, ok INTEGER NOT NULL,
                                ms INTEGER NOT NULL, PRIMARY KEY (net, node, at)) WITHOUT ROWID;",
    // 8: review 8 (docs/06 §11.5): when the table of a watcher is full, a new registration takes the place of the
    // oldest one that is not passing its probes - the time of the first registration decides "oldest".
    "ALTER TABLE watch_nodes ADD COLUMN registered INTEGER NOT NULL DEFAULT 0;",
];

/// An identity counts as idle (its card may be forgotten when the table is full) after one day without login.
pub const IDLE_CARD_MS: i64 = 24 * 3600 * 1000;

/// Schema version this build knows.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// What can go wrong. Details stay in the node's log; clients only ever see `UNAVAILABLE`.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The database reported an error.
    #[error("database: {0}")]
    Database(String),
    /// The database was written by a newer Bridge version - refuse instead of guessing (Z8: fail closed).
    #[error("database schema {found} is newer than this program ({known})")]
    NewerSchema {
        /// Version in the file.
        found: u32,
        /// Version this build knows.
        known: u32,
    },
    /// A previous operation panicked while holding the connection.
    #[error("database lock poisoned")]
    Poisoned,
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error.to_string())
    }
}

/// Result type of the store.
pub type StoreResult<T> = Result<T, StoreError>;

/// Limits for one delivery, decided by `bridge-guard`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxLimits {
    /// Max envelopes waiting for one recipient.
    pub max_envelopes: u64,
    /// Max bytes waiting for one recipient.
    pub max_bytes: u64,
    /// Max envelopes waiting from one sender for one recipient.
    pub max_from_one_sender: u64,
    /// Max bytes in all mailboxes of this node.
    pub max_node_bytes: u64,
    /// Max remembered envelope IDs (replay protection, kept until expiry) per sender - bounds what one sender can
    /// make the node store even if every message is fetched right away.
    pub max_seen_per_sender: u64,
}

/// An envelope to deliver (already fully checked by the node).
#[derive(Debug, Clone, Copy)]
pub struct Delivery<'a> {
    /// Recipient ID.
    pub recipient: &'a str,
    /// Sender ID.
    pub sender: &'a str,
    /// Envelope ID.
    pub env_id: &'a [u8; 16],
    /// End of life (ms) - also how long the replay entry is kept.
    pub expires_at: i64,
    /// The envelope bytes (encrypted content).
    pub envelope: &'a [u8],
    /// Now (ms).
    pub now: i64,
}

/// Result of a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// Stored.
    Stored,
    /// This sender already delivered this envelope ID (replay).
    Replay,
    /// The recipient's mailbox is full.
    MailboxFull,
    /// Too many envelopes from this sender are waiting for this recipient.
    SenderLimit,
    /// The node's storage for mailboxes is full.
    NodeFull,
}

/// A stored envelope as handed out to its recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// Sender ID.
    pub sender: String,
    /// The envelope bytes.
    pub envelope: Vec<u8>,
}

/// The database of one node. Cheap operations, one connection behind a lock (callers on async runtimes should
/// call it from a blocking task).
pub struct Store {
    connection: Mutex<Connection>,
}

impl Store {
    /// Opens (or creates) the database file and brings the schema up to date.
    pub fn open(path: &Path) -> StoreResult<Self> {
        Self::setup(Connection::open(path)?, true)
    }

    /// A database in memory (tests).
    pub fn open_in_memory() -> StoreResult<Self> {
        Self::setup(Connection::open_in_memory()?, false)
    }

    fn setup(connection: Connection, file: bool) -> StoreResult<Self> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        if file {
            let mode: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(StoreError::Database(format!("journal mode {mode} instead of wal")));
            }
        }
        connection
            .execute_batch("PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")?;
        let mut store = Self { connection: Mutex::new(connection) };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> StoreResult<()> {
        let connection = self.connection.get_mut().map_err(|_| StoreError::Poisoned)?;
        let found: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if found > SCHEMA_VERSION {
            return Err(StoreError::NewerSchema { found, known: SCHEMA_VERSION });
        }
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(found as usize) {
            let transaction = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
            transaction.execute_batch(sql)?;
            transaction.pragma_update(None, "user_version", index as u32 + 1)?;
            transaction.commit()?;
        }
        Ok(())
    }

    fn lock(&self) -> StoreResult<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StoreError::Poisoned)
    }

    /// Schema version of the open database.
    pub fn schema_version(&self) -> StoreResult<u32> {
        Ok(self.lock()?.query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    /// Stores a value under a key (small node settings).
    pub fn meta_set(&self, key: &str, value: &[u8]) -> StoreResult<()> {
        self.lock()?.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Reads a value.
    pub fn meta_get(&self, key: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self.lock()?.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| row.get(0)).optional()?)
    }

    /// Remembers a verified key card (the caller checked it - cards are self-certifying). A new identity is only
    /// added while fewer than `max_cards` are known; returns `false` if the table is full.
    pub fn put_card(&self, id: &str, card: &[u8], now: i64, max_cards: u64) -> StoreResult<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let known: Option<i64> =
            transaction.query_row("SELECT 1 FROM cards WHERE id = ?1", [id], |row| row.get(0)).optional()?;
        if known.is_none() {
            let count: i64 = transaction.query_row("SELECT COUNT(*) FROM cards", [], |row| row.get(0))?;
            if count as u64 >= max_cards {
                // Make room: forget the identity idle the longest (no login for a day, no waiting mail). Cards are
                // self-certifying - it simply sends its card again on its next login.
                let evicted = transaction.execute(
                    "DELETE FROM cards WHERE id = (SELECT id FROM cards WHERE last_seen < ?1
                       AND id NOT IN (SELECT recipient FROM mailbox) ORDER BY last_seen LIMIT 1)",
                    [now.saturating_sub(IDLE_CARD_MS)],
                )?;
                if evicted == 0 {
                    return Ok(false);
                }
            }
        }
        transaction.execute(
            "INSERT INTO cards (id, card, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT (id) DO UPDATE SET card = excluded.card, last_seen = excluded.last_seen",
            params![id, card, now],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// A known key card.
    pub fn get_card(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self.lock()?.query_row("SELECT card FROM cards WHERE id = ?1", [id], |row| row.get(0)).optional()?)
    }

    /// Delivers an envelope: replay check, quotas and insert in one transaction.
    pub fn deliver(&self, delivery: &Delivery<'_>, limits: &MailboxLimits) -> StoreResult<Delivered> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let seen: Option<i64> = transaction
            .query_row(
                "SELECT expires_at FROM seen WHERE sender = ?1 AND env_id = ?2",
                params![delivery.sender, &delivery.env_id[..]],
                |row| row.get(0),
            )
            .optional()?;
        if seen.is_some() {
            return Ok(Delivered::Replay);
        }
        let size = delivery.envelope.len() as i64;
        let (count, bytes): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM mailbox WHERE recipient = ?1 AND expires_at > ?2",
            params![delivery.recipient, delivery.now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count as u64 >= limits.max_envelopes || (bytes + size) as u64 > limits.max_bytes {
            return Ok(Delivered::MailboxFull);
        }
        let from_sender: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM mailbox WHERE recipient = ?1 AND sender = ?2 AND expires_at > ?3",
            params![delivery.recipient, delivery.sender, delivery.now],
            |row| row.get(0),
        )?;
        if from_sender as u64 >= limits.max_from_one_sender {
            return Ok(Delivered::SenderLimit);
        }
        let remembered: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM seen WHERE sender = ?1 AND expires_at > ?2",
            params![delivery.sender, delivery.now],
            |row| row.get(0),
        )?;
        if remembered as u64 >= limits.max_seen_per_sender {
            return Ok(Delivered::SenderLimit);
        }
        let node_bytes: i64 =
            transaction.query_row("SELECT value FROM counters WHERE name = 'mailbox_bytes'", [], |row| row.get(0))?;
        if (node_bytes + size) as u64 > limits.max_node_bytes {
            return Ok(Delivered::NodeFull);
        }
        transaction.execute(
            "INSERT INTO mailbox (recipient, sender, env_id, expires_at, size, envelope, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                delivery.recipient,
                delivery.sender,
                &delivery.env_id[..],
                delivery.expires_at,
                size,
                delivery.envelope,
                delivery.now
            ],
        )?;
        transaction.execute(
            "INSERT INTO seen (sender, env_id, expires_at) VALUES (?1, ?2, ?3)",
            params![delivery.sender, &delivery.env_id[..], delivery.expires_at],
        )?;
        transaction.execute("UPDATE counters SET value = value + ?1 WHERE name = 'mailbox_bytes'", [size])?;
        transaction.commit()?;
        Ok(Delivered::Stored)
    }

    /// Up to `max` waiting, not expired envelopes of `recipient`, oldest first, together at most `max_bytes` (but
    /// always at least one). They stay until acknowledged.
    pub fn fetch(&self, recipient: &str, max: u32, max_bytes: usize, now: i64) -> StoreResult<Vec<Stored>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare_cached(
            "SELECT sender, envelope FROM mailbox WHERE recipient = ?1 AND expires_at > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = statement
            .query_map(params![recipient, now, max], |row| Ok(Stored { sender: row.get(0)?, envelope: row.get(1)? }))?;
        let mut out = Vec::new();
        let mut total = 0usize;
        for row in rows {
            let row = row?;
            total += row.envelope.len();
            if total > max_bytes && !out.is_empty() {
                break;
            }
            out.push(row);
        }
        Ok(out)
    }

    /// Removes acknowledged envelopes of `recipient`, each named by (sender, envelope ID). Returns how many.
    pub fn ack(&self, recipient: &str, envelopes: &[(String, [u8; 16])]) -> StoreResult<usize> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut removed = 0;
        let mut bytes = 0i64;
        {
            let mut statement = transaction.prepare_cached(
                "DELETE FROM mailbox WHERE recipient = ?1 AND sender = ?2 AND env_id = ?3 RETURNING size",
            )?;
            for (sender, env_id) in envelopes {
                let mut rows = statement.query(params![recipient, sender, &env_id[..]])?;
                while let Some(row) = rows.next()? {
                    bytes += row.get::<_, i64>(0)?;
                    removed += 1;
                }
            }
        }
        transaction.execute("UPDATE counters SET value = value - ?1 WHERE name = 'mailbox_bytes'", [bytes])?;
        transaction.commit()?;
        Ok(removed)
    }

    /// Number and bytes of waiting (not expired) envelopes of `recipient`.
    pub fn mailbox_stats(&self, recipient: &str, now: i64) -> StoreResult<(u64, u64)> {
        let (count, bytes): (i64, i64) = self.lock()?.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM mailbox WHERE recipient = ?1 AND expires_at > ?2",
            params![recipient, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok((count as u64, bytes as u64))
    }

    /// Deletes expired envelopes and replay entries. Returns (envelopes, replay entries) removed.
    pub fn purge_expired(&self, now: i64) -> StoreResult<(usize, usize)> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM mailbox WHERE expires_at <= ?1",
            [now],
            |row| row.get(0),
        )?;
        let envelopes = transaction.execute("DELETE FROM mailbox WHERE expires_at <= ?1", [now])?;
        let seen = transaction.execute("DELETE FROM seen WHERE expires_at <= ?1", [now])?;
        transaction.execute("UPDATE counters SET value = value - ?1 WHERE name = 'mailbox_bytes'", [bytes])?;
        transaction.commit()?;
        Ok((envelopes, seen))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: MailboxLimits = MailboxLimits {
        max_envelopes: 3,
        max_bytes: 100,
        max_from_one_sender: 2,
        max_node_bytes: 1000,
        max_seen_per_sender: 1000,
    };

    fn delivery<'a>(sender: &'a str, env_id: &'a [u8; 16], envelope: &'a [u8], expires_at: i64) -> Delivery<'a> {
        Delivery { recipient: "bob", sender, env_id, expires_at, envelope, now: 0 }
    }

    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(COMPARTMENT, env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn deliver_fetch_ack_replay() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert_eq!(store.schema_version()?, SCHEMA_VERSION);
        assert_eq!(store.deliver(&delivery("alice", &[1; 16], b"e1", 100), &LIMITS)?, Delivered::Stored);
        assert_eq!(store.deliver(&delivery("alice", &[1; 16], b"e1", 100), &LIMITS)?, Delivered::Replay);
        assert_eq!(store.deliver(&delivery("carol", &[1; 16], b"c1", 100), &LIMITS)?, Delivered::Stored);
        let waiting = store.fetch("bob", 10, usize::MAX, 0)?;
        assert_eq!(waiting.len(), 2);
        assert_eq!(waiting[0], Stored { sender: "alice".into(), envelope: b"e1".to_vec() });
        assert_eq!(store.fetch("bob", 1, usize::MAX, 0)?.len(), 1, "max is respected");
        assert_eq!(store.fetch("alice", 10, usize::MAX, 0)?.len(), 0, "only own mailbox");
        assert_eq!(store.ack("mallory", &[("alice".into(), [1; 16])])?, 0, "others cannot acknowledge");
        assert_eq!(store.ack("bob", &[("alice".into(), [1; 16])])?, 1, "only the named sender");
        assert_eq!(store.ack("bob", &[("carol".into(), [1; 16]), ("carol".into(), [9; 16])])?, 1);
        assert!(store.fetch("bob", 10, usize::MAX, 0)?.is_empty());
        assert_eq!(
            store.deliver(&delivery("alice", &[1; 16], b"e1", 100), &LIMITS)?,
            Delivered::Replay,
            "even after ack"
        );
        Ok(())
    }

    #[test]
    fn quotas() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert_eq!(store.deliver(&delivery("alice", &[1; 16], b"a", 100), &LIMITS)?, Delivered::Stored);
        assert_eq!(store.deliver(&delivery("alice", &[2; 16], b"a", 100), &LIMITS)?, Delivered::Stored);
        assert_eq!(store.deliver(&delivery("alice", &[3; 16], b"a", 100), &LIMITS)?, Delivered::SenderLimit);
        assert_eq!(store.deliver(&delivery("carol", &[4; 16], &[0; 99], 100), &LIMITS)?, Delivered::MailboxFull);
        assert_eq!(store.deliver(&delivery("carol", &[4; 16], b"c", 100), &LIMITS)?, Delivered::Stored);
        assert_eq!(
            store.deliver(&delivery("dave", &[5; 16], b"d", 100), &LIMITS)?,
            Delivered::MailboxFull,
            "3 waiting"
        );
        let node_limit = MailboxLimits { max_node_bytes: 3, ..LIMITS };
        let to_eve = Delivery { recipient: "eve", ..delivery("dave", &[6; 16], b"d", 100) };
        assert_eq!(store.deliver(&to_eve, &node_limit)?, Delivered::NodeFull);
        assert_eq!(store.mailbox_stats("bob", 0)?, (3, 3));
        Ok(())
    }

    #[test]
    fn fetch_respects_byte_budget_and_seen_limit_per_sender() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let roomy = MailboxLimits {
            max_envelopes: 100,
            max_bytes: 10_000,
            max_from_one_sender: 100,
            max_node_bytes: 100_000,
            max_seen_per_sender: 3,
        };
        for i in 1..=3u8 {
            assert_eq!(store.deliver(&delivery("alice", &[i; 16], &[i; 40], 100), &roomy)?, Delivered::Stored);
        }
        assert_eq!(store.fetch("bob", 10, 100, 0)?.len(), 2, "40 + 40 fit into 100, the third not");
        assert_eq!(store.fetch("bob", 10, 10, 0)?.len(), 1, "always at least one");
        store.ack("bob", &[("alice".into(), [1; 16]), ("alice".into(), [2; 16]), ("alice".into(), [3; 16])])?;
        assert_eq!(
            store.deliver(&delivery("alice", &[4; 16], b"x", 100), &roomy)?,
            Delivered::SenderLimit,
            "mailbox empty, but 3 IDs of alice are remembered until they expire"
        );
        assert_eq!(store.deliver(&delivery("carol", &[4; 16], b"x", 100), &roomy)?, Delivered::Stored);
        Ok(())
    }

    #[test]
    fn expiry_and_purge() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        store.deliver(&delivery("alice", &[1; 16], b"a", 50), &LIMITS)?;
        store.deliver(&delivery("alice", &[2; 16], b"b", 500), &LIMITS)?;
        assert_eq!(store.fetch("bob", 10, usize::MAX, 60)?.len(), 1, "expired ones are not handed out");
        assert_eq!(store.purge_expired(60)?, (1, 1));
        assert_eq!(
            store.deliver(&delivery("alice", &[1; 16], b"a", 50), &LIMITS)?,
            Delivered::Stored,
            "after expiry the ID is free again (the envelope itself would be expired)"
        );
        Ok(())
    }

    #[test]
    fn survives_reopen_and_refuses_newer_schema() -> StoreResult<()> {
        let dir = tempfile::tempdir().map_err(|e| StoreError::Database(e.to_string()))?;
        let path = dir.path().join("node.db");
        {
            let store = Store::open(&path)?;
            store.deliver(&delivery("alice", &[1; 16], b"kept", 100), &LIMITS)?;
            assert!(store.put_card("alice", b"{card}", 0, 1)?);
            assert!(store.put_card("alice", b"{card}", 1, 1)?, "known IDs can update");
            assert!(!store.put_card("bob", b"{card}", 1, 1)?, "full, and alice is not idle yet");
            assert!(store.put_card("bob", b"{card}", IDLE_CARD_MS + 2, 1)?, "alice idle for a day: forgotten");
            assert_eq!(store.get_card("alice")?, None);
            assert!(!store.put_card("carol", b"{card}", 3 * IDLE_CARD_MS, 1)?, "bob is idle but has mail: kept");
            assert!(store.put_card("alice", b"{card}", 0, 2)?);
            store.meta_set("k", b"v")?;
        }
        let store = Store::open(&path)?;
        assert_eq!(store.fetch("bob", 10, usize::MAX, 0)?[0].envelope, b"kept");
        assert_eq!(store.get_card("bob")?, Some(b"{card}".to_vec()));
        assert_eq!(store.meta_get("k")?, Some(b"v".to_vec()));
        drop(store);
        Connection::open(&path)?.pragma_update(None, "user_version", SCHEMA_VERSION + 1)?;
        assert!(matches!(Store::open(&path), Err(StoreError::NewerSchema { .. })));
        Ok(())
    }

    #[test]
    fn schema_5_pins_get_their_sizes() -> StoreResult<()> {
        let dir = tempfile::tempdir().map_err(|e| StoreError::Database(e.to_string()))?;
        let path = dir.path().join("node.db");
        {
            let connection = Connection::open(&path)?;
            for sql in &MIGRATIONS[..5] {
                connection.execute_batch(sql)?;
            }
            connection.pragma_update(None, "user_version", 5)?;
            connection.execute(
                "INSERT INTO blobs (id, size, parts, have, present, complete, created) VALUES ('b', 70000, 2, x'00', 0, 0, 0)",
                [],
            )?;
            connection
                .execute("INSERT INTO blob_pins (blob, holder, owner, expires) VALUES ('b', 'up:a', 'a', 9)", [])?;
            connection.execute(
                "INSERT INTO apps (app, owner, version, state, current, previous, pending, updated)
                 VALUES ('x', 'a', 3, 'stopped', NULL, NULL, NULL, 0)",
                [],
            )?;
        }
        let store = Store::open(&path)?;
        assert_eq!(store.schema_version()?, SCHEMA_VERSION);
        assert_eq!(store.blob_owner_bytes("a")?, 70_000);
        let size: i64 = store.lock()?.query_row("SELECT size FROM blob_pins WHERE blob = 'b'", [], |row| row.get(0))?;
        assert_eq!(size, 70_000);
        assert_eq!(store.app_get("x")?.map(|app| (app.version, app.hash)), Some((3, None)));
        Ok(())
    }
}
