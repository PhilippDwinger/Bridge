//! What a node of a BridgeNet persists (schema 3 and 4, docs/06): log entries, heads, transition heads, evidence, homes,
//! relay outbox.
//!
//! The store checks nothing cryptographic - the node verified everything before. It enforces structure and bounds:
//! log indices are contiguous (an append at the wrong index writes nothing), the head and evidence tables have a
//! fixed number of rows per network, transition heads are kept one per size (a newer row replaces one the node
//! could not verify) up to a caller limit (the oldest go first), `home` entries are one per member (newest `iat` wins) up to a caller limit,
//! and the outbox has the same replay protection and quotas as the mailboxes.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Delivered, MailboxLimits, Store, StoreResult};

/// Rows of the head table per network (operators × roles; a manifest lists at most 3 operators).
pub const MAX_HEAD_ROWS_PER_NET: usize = 64;
/// Evidence entries per network (one per operator is enough to depose it).
pub const MAX_EVIDENCE_PER_NET: usize = 16;

/// A stored head: the head statement and the cosignatures collected for it (both as canonical JSON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadRow {
    /// Log operator that signed the head.
    pub operator: String,
    /// Why this node keeps it, e.g. `issued`, `witnessed`, `cosigned`.
    pub role: String,
    /// Tree size of the head.
    pub size: u64,
    /// The head statement.
    pub head: Vec<u8>,
    /// JSON array of cosignature statements.
    pub cosigns: Vec<u8>,
}

/// A stored transition head (docs/06 §5 "Übergänge beim Aufholen"): the witnessed head that ends with a change of
/// the log rules, as canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRow {
    /// Tree size of the head (the index of the manifest + 1).
    pub size: u64,
    /// The head statement.
    pub head: Vec<u8>,
    /// JSON array of cosignature statements.
    pub cosigns: Vec<u8>,
}

/// A stored `home` entry (docs/06 §8) with the member's key card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeRow {
    /// Member ID.
    pub member: String,
    /// Node ID of the member's home gateway.
    pub node: String,
    /// Issued at (ms) - the newest entry of a member wins.
    pub iat: i64,
    /// Expires (ms).
    pub exp: i64,
    /// Change counter (assigned by the store; `homes_of_node_since` pages by it).
    pub seq: i64,
    /// The `home` statement.
    pub home: Vec<u8>,
    /// The member's key card.
    pub card: Vec<u8>,
}

/// Result of storing a `home` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeStored {
    /// Stored (new or newer than the one before).
    Stored,
    /// Not newer than the stored entry - nothing changed.
    Older,
    /// The table is full.
    Full,
}

/// Quotas of the relay outbox (decided by `bridge-guard`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Max envelopes waiting in the outbox.
    pub max_entries: u64,
    /// Max bytes waiting in the outbox.
    pub max_bytes: u64,
    /// Max envelopes waiting for one target gateway.
    pub max_per_target: u64,
}

/// An envelope to relay (already fully checked by the node).
#[derive(Debug, Clone, Copy)]
pub struct RelayItem<'a> {
    /// Node ID of the target gateway.
    pub target: &'a str,
    /// Sender ID.
    pub sender: &'a str,
    /// Envelope ID.
    pub env_id: &'a [u8; 16],
    /// End of life (ms).
    pub expires_at: i64,
    /// The envelope bytes.
    pub envelope: &'a [u8],
    /// The sender's key card (travels with the relay).
    pub card: &'a [u8],
    /// Now (ms).
    pub now: i64,
}

/// An envelope waiting in the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// Row number (for `relay_done` / `relay_later`).
    pub seq: i64,
    /// Node ID of the target gateway.
    pub target: String,
    /// Sender ID.
    pub sender: String,
    /// The envelope bytes.
    pub envelope: Vec<u8>,
    /// The sender's key card.
    pub card: Vec<u8>,
    /// Delivery attempts so far.
    pub attempts: u32,
}

impl Store {
    // --- log ---------------------------------------------------------------------------------------------------

    /// Number of stored log entries of `net` (the next index).
    pub fn net_log_size(&self, net: &str) -> StoreResult<u64> {
        let size: i64 =
            self.lock()?
                .query_row("SELECT COALESCE(MAX(idx) + 1, 0) FROM net_log WHERE net = ?1", [net], |row| row.get(0))?;
        Ok(u64::try_from(size).unwrap_or(0))
    }

    /// Appends `entries` at index `start`. Writes nothing and returns `false` unless `start` is exactly the current
    /// size (indices stay contiguous even if two writers race).
    pub fn net_log_append(&self, net: &str, start: u64, entries: &[Vec<u8>]) -> StoreResult<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let size: i64 =
            transaction
                .query_row("SELECT COALESCE(MAX(idx) + 1, 0) FROM net_log WHERE net = ?1", [net], |row| row.get(0))?;
        let Ok(start) = i64::try_from(start) else {
            return Ok(false);
        };
        if size != start {
            return Ok(false);
        }
        {
            let mut insert = transaction.prepare_cached("INSERT INTO net_log (net, idx, entry) VALUES (?1, ?2, ?3)")?;
            for (offset, entry) in (0i64..).zip(entries) {
                insert.execute(params![net, start + offset, entry])?;
            }
        }
        transaction.commit()?;
        Ok(true)
    }

    /// The first `max` log entries of `net`, in order.
    pub fn net_log_load(&self, net: &str, max: u64) -> StoreResult<Vec<Vec<u8>>> {
        let connection = self.lock()?;
        let mut statement =
            connection.prepare_cached("SELECT entry FROM net_log WHERE net = ?1 ORDER BY idx LIMIT ?2")?;
        let rows = statement.query_map(params![net, i64::try_from(max).unwrap_or(i64::MAX)], |row| row.get(0))?;
        rows.collect::<Result<Vec<Vec<u8>>, _>>().map_err(Into::into)
    }

    // --- heads -------------------------------------------------------------------------------------------------

    /// Stores (or replaces) the head of `row.operator` in `row.role`. Returns `false` if the network already has
    /// [`MAX_HEAD_ROWS_PER_NET`] other rows.
    pub fn net_head_put(&self, net: &str, row: &HeadRow, now: i64) -> StoreResult<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let known: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM net_heads WHERE net = ?1 AND operator = ?2 AND role = ?3",
                params![net, row.operator, row.role],
                |r| r.get(0),
            )
            .optional()?;
        if known.is_none() {
            let count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM net_heads WHERE net = ?1", [net], |r| r.get(0))?;
            if count as u64 >= MAX_HEAD_ROWS_PER_NET as u64 {
                return Ok(false);
            }
        }
        transaction.execute(
            "INSERT INTO net_heads (net, operator, role, size, head, cosigns, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (net, operator, role) DO UPDATE SET size = excluded.size, head = excluded.head,
                 cosigns = excluded.cosigns, updated = excluded.updated",
            params![
                net,
                row.operator,
                row.role,
                i64::try_from(row.size).unwrap_or(i64::MAX),
                row.head,
                row.cosigns,
                now
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// All stored heads of `net` (at most [`MAX_HEAD_ROWS_PER_NET`]).
    pub fn net_heads(&self, net: &str) -> StoreResult<Vec<HeadRow>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare_cached(
            "SELECT operator, role, size, head, cosigns FROM net_heads WHERE net = ?1 ORDER BY operator, role LIMIT ?2",
        )?;
        let rows = statement.query_map(params![net, MAX_HEAD_ROWS_PER_NET as i64], |row| {
            Ok(HeadRow {
                operator: row.get(0)?,
                role: row.get(1)?,
                size: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                head: row.get(3)?,
                cosigns: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // --- transition heads --------------------------------------------------------------------------------------

    /// Keeps the transition head `row` of `net` for good. The node stores only heads it verified and does not hold
    /// yet - so a row already stored for that size is one that did not verify after a restart, and the new one
    /// replaces it (`false`: exactly this row was there already). At most `max` per network - beyond that the
    /// smallest sizes go.
    pub fn net_transition_put(&self, net: &str, row: &TransitionRow, max: usize) -> StoreResult<bool> {
        let Ok(size) = i64::try_from(row.size) else {
            return Ok(false);
        };
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "INSERT INTO net_transitions (net, size, head, cosigns) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (net, size) DO UPDATE SET head = excluded.head, cosigns = excluded.cosigns
             WHERE head <> excluded.head OR cosigns <> excluded.cosigns",
            params![net, size, row.head, row.cosigns],
        )?;
        transaction.execute(
            "DELETE FROM net_transitions WHERE net = ?1 AND size NOT IN
                 (SELECT size FROM net_transitions WHERE net = ?1 ORDER BY size DESC LIMIT ?2)",
            params![net, i64::try_from(max).unwrap_or(i64::MAX)],
        )?;
        transaction.commit()?;
        Ok(changed == 1)
    }

    /// Removes the stored transition head of `net` for `size` (one that can never be served: no change of the log
    /// rules ends there). Returns whether there was one.
    pub fn net_transition_delete(&self, net: &str, size: u64) -> StoreResult<bool> {
        let Ok(size) = i64::try_from(size) else {
            return Ok(false);
        };
        let connection = self.lock()?;
        let deleted =
            connection.execute("DELETE FROM net_transitions WHERE net = ?1 AND size = ?2", params![net, size])?;
        Ok(deleted == 1)
    }

    /// The stored transition heads of `net`, ascending by size (at most `max`, the largest sizes).
    pub fn net_transitions(&self, net: &str, max: usize) -> StoreResult<Vec<TransitionRow>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare_cached(
            "SELECT size, head, cosigns FROM net_transitions WHERE net = ?1 ORDER BY size DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![net, i64::try_from(max).unwrap_or(i64::MAX)], |row| {
            Ok(TransitionRow {
                size: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                head: row.get(1)?,
                cosigns: row.get(2)?,
            })
        })?;
        let mut rows = rows.collect::<Result<Vec<_>, _>>()?;
        rows.reverse();
        Ok(rows)
    }

    // --- evidence ----------------------------------------------------------------------------------------------

    /// Stores evidence against `operator`. Returns `true` if it is new (the first evidence against this operator);
    /// `false` if there already is some, or the table of this network is full.
    pub fn net_evidence_put(&self, net: &str, operator: &str, evidence: &[u8], now: i64) -> StoreResult<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM net_evidence WHERE net = ?1", [net], |r| r.get(0))?;
        if count as u64 >= MAX_EVIDENCE_PER_NET as u64 {
            return Ok(false);
        }
        let inserted = transaction.execute(
            "INSERT INTO net_evidence (net, operator, evidence, received) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (net, operator) DO NOTHING",
            params![net, operator, evidence, now],
        )?;
        transaction.commit()?;
        Ok(inserted == 1)
    }

    /// All evidence of `net`: (operator, evidence), at most [`MAX_EVIDENCE_PER_NET`].
    pub fn net_evidence(&self, net: &str) -> StoreResult<Vec<(String, Vec<u8>)>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare_cached("SELECT operator, evidence FROM net_evidence WHERE net = ?1 ORDER BY received LIMIT ?2")?;
        let rows =
            statement.query_map(params![net, MAX_EVIDENCE_PER_NET as i64], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // --- homes -------------------------------------------------------------------------------------------------

    /// Stores the `home` entry of `row.member` if it is newer (larger `iat`) than the stored one. A new member is
    /// only added while fewer than `max_homes` entries exist. `row.seq` is ignored (the store assigns it).
    pub fn home_put(&self, net: &str, row: &HomeRow, max_homes: u64) -> StoreResult<HomeStored> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<i64> = transaction
            .query_row("SELECT iat FROM net_homes WHERE net = ?1 AND member = ?2", params![net, row.member], |r| {
                r.get(0)
            })
            .optional()?;
        match stored {
            Some(iat) if iat >= row.iat => return Ok(HomeStored::Older),
            Some(_) => {}
            None => {
                let count: i64 =
                    transaction.query_row("SELECT COUNT(*) FROM net_homes WHERE net = ?1", [net], |r| r.get(0))?;
                if count as u64 >= max_homes {
                    // Make room: entries that expired can go.
                    let freed = transaction.execute("DELETE FROM net_homes WHERE exp <= ?1", [row.iat])?;
                    if freed == 0 {
                        return Ok(HomeStored::Full);
                    }
                }
            }
        }
        let seq: i64 = transaction.query_row(
            "UPDATE counters SET value = value + 1 WHERE name = 'home_seq' RETURNING value",
            [],
            |r| r.get(0),
        )?;
        transaction.execute(
            "INSERT INTO net_homes (net, member, node, iat, exp, seq, home, card) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (net, member) DO UPDATE SET node = excluded.node, iat = excluded.iat, exp = excluded.exp,
                 seq = excluded.seq, home = excluded.home, card = excluded.card",
            params![net, row.member, row.node, row.iat, row.exp, seq, row.home, row.card],
        )?;
        transaction.commit()?;
        Ok(HomeStored::Stored)
    }

    /// The `home` entry of `member`, if one exists that has not expired at `now`.
    pub fn home_get(&self, net: &str, member: &str, now: i64) -> StoreResult<Option<HomeRow>> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT member, node, iat, exp, seq, home, card FROM net_homes WHERE net = ?1 AND member = ?2 AND exp > ?3",
                params![net, member, now],
                home_row,
            )
            .optional()?)
    }

    /// Up to `max` entries of members whose home is `node`, changed after `since` (ascending by `seq`), not
    /// expired at `now`.
    pub fn homes_of_node_since(
        &self,
        net: &str,
        node: &str,
        since: i64,
        max: u32,
        now: i64,
    ) -> StoreResult<Vec<HomeRow>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare_cached(
            "SELECT member, node, iat, exp, seq, home, card FROM net_homes
             WHERE net = ?1 AND node = ?2 AND seq > ?3 AND exp > ?4 ORDER BY seq LIMIT ?5",
        )?;
        let rows = statement.query_map(params![net, node, since, now, max], home_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // --- relay outbox ------------------------------------------------------------------------------------------

    /// Puts an envelope into the outbox: replay check (the same `seen` table as the mailboxes), quotas and insert
    /// in one transaction. Uses `Delivered::MailboxFull` when the outbox (or the share of one target) is full.
    pub fn relay_enqueue(
        &self,
        item: &RelayItem<'_>,
        limits: &RelayLimits,
        mailbox: &MailboxLimits,
    ) -> StoreResult<Delivered> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let seen: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM seen WHERE sender = ?1 AND env_id = ?2",
                params![item.sender, &item.env_id[..]],
                |row| row.get(0),
            )
            .optional()?;
        if seen.is_some() {
            return Ok(Delivered::Replay);
        }
        let size = item.envelope.len() as i64;
        let (count, bytes): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), (SELECT value FROM counters WHERE name = 'relay_bytes') FROM relay_outbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count as u64 >= limits.max_entries || (bytes + size) as u64 > limits.max_bytes {
            return Ok(Delivered::NodeFull);
        }
        let for_target: i64 =
            transaction
                .query_row("SELECT COUNT(*) FROM relay_outbox WHERE target = ?1", [item.target], |r| r.get(0))?;
        if for_target as u64 >= limits.max_per_target {
            return Ok(Delivered::MailboxFull);
        }
        let from_sender: i64 =
            transaction
                .query_row("SELECT COUNT(*) FROM relay_outbox WHERE sender = ?1", [item.sender], |r| r.get(0))?;
        if from_sender as u64 >= mailbox.max_from_one_sender {
            return Ok(Delivered::SenderLimit);
        }
        let remembered: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM seen WHERE sender = ?1 AND expires_at > ?2",
            params![item.sender, item.now],
            |row| row.get(0),
        )?;
        if remembered as u64 >= mailbox.max_seen_per_sender {
            return Ok(Delivered::SenderLimit);
        }
        transaction.execute(
            "INSERT INTO relay_outbox (target, sender, env_id, expires_at, next_attempt, attempts, size, envelope, card)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8)",
            params![
                item.target,
                item.sender,
                &item.env_id[..],
                item.expires_at,
                item.now,
                size,
                item.envelope,
                item.card
            ],
        )?;
        transaction.execute(
            "INSERT INTO seen (sender, env_id, expires_at) VALUES (?1, ?2, ?3)",
            params![item.sender, &item.env_id[..], item.expires_at],
        )?;
        transaction.execute("UPDATE counters SET value = value + ?1 WHERE name = 'relay_bytes'", [size])?;
        transaction.commit()?;
        Ok(Delivered::Stored)
    }

    /// Up to `max` outbox entries that are due at `now` and not expired, oldest attempt first.
    pub fn relay_due(&self, now: i64, max: u32) -> StoreResult<Vec<Outgoing>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare_cached(
            "SELECT seq, target, sender, envelope, card, attempts FROM relay_outbox
             WHERE next_attempt <= ?1 AND expires_at > ?1 ORDER BY next_attempt, seq LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now, max], |row| {
            Ok(Outgoing {
                seq: row.get(0)?,
                target: row.get(1)?,
                sender: row.get(2)?,
                envelope: row.get(3)?,
                card: row.get(4)?,
                attempts: u32::try_from(row.get::<_, i64>(5)?).unwrap_or(u32::MAX),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Removes a delivered (or undeliverable) outbox entry.
    pub fn relay_done(&self, seq: i64) -> StoreResult<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let size: Option<i64> = transaction
            .query_row("DELETE FROM relay_outbox WHERE seq = ?1 RETURNING size", [seq], |row| row.get(0))
            .optional()?;
        if let Some(size) = size {
            transaction.execute("UPDATE counters SET value = value - ?1 WHERE name = 'relay_bytes'", [size])?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Schedules the next attempt for an outbox entry.
    pub fn relay_later(&self, seq: i64, next_attempt: i64) -> StoreResult<()> {
        self.lock()?.execute(
            "UPDATE relay_outbox SET next_attempt = ?2, attempts = attempts + 1 WHERE seq = ?1",
            params![seq, next_attempt],
        )?;
        Ok(())
    }

    /// Number of envelopes waiting in the outbox (diagnostics, tests).
    pub fn relay_waiting(&self) -> StoreResult<u64> {
        let count: i64 = self.lock()?.query_row("SELECT COUNT(*) FROM relay_outbox", [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Deletes expired `home` entries and outbox entries. Returns (homes, outbox entries) removed.
    pub fn purge_net(&self, now: i64) -> StoreResult<(usize, usize)> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let homes = transaction.execute("DELETE FROM net_homes WHERE exp <= ?1", [now])?;
        let bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM relay_outbox WHERE expires_at <= ?1",
            [now],
            |row| row.get(0),
        )?;
        let outbox = transaction.execute("DELETE FROM relay_outbox WHERE expires_at <= ?1", [now])?;
        transaction.execute("UPDATE counters SET value = value - ?1 WHERE name = 'relay_bytes'", [bytes])?;
        transaction.commit()?;
        Ok((homes, outbox))
    }
}

fn home_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HomeRow> {
    Ok(HomeRow {
        member: row.get(0)?,
        node: row.get(1)?,
        iat: row.get(2)?,
        exp: row.get(3)?,
        seq: row.get(4)?,
        home: row.get(5)?,
        card: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SCHEMA_VERSION, StoreError};

    const MAILBOX: MailboxLimits = MailboxLimits {
        max_envelopes: 10,
        max_bytes: 1000,
        max_from_one_sender: 3,
        max_node_bytes: 10_000,
        max_seen_per_sender: 100,
    };
    const RELAY: RelayLimits = RelayLimits { max_entries: 4, max_bytes: 100, max_per_target: 3 };

    fn home(member: &str, node: &str, iat: i64) -> HomeRow {
        HomeRow {
            member: member.into(),
            node: node.into(),
            iat,
            exp: iat + 1000,
            seq: 0,
            home: format!("home-{member}-{iat}").into_bytes(),
            card: b"card".to_vec(),
        }
    }

    fn item<'a>(target: &'a str, sender: &'a str, env_id: &'a [u8; 16], envelope: &'a [u8]) -> RelayItem<'a> {
        RelayItem { target, sender, env_id, expires_at: 500, envelope, card: b"card", now: 0 }
    }

    #[test]
    fn log_indices_stay_contiguous_and_survive_reopen() -> StoreResult<()> {
        let dir = tempfile::tempdir().map_err(|e| StoreError::Database(e.to_string()))?;
        let path = dir.path().join("node.db");
        {
            let store = Store::open(&path)?;
            assert_eq!(store.schema_version()?, SCHEMA_VERSION);
            assert_eq!(store.net_log_size("n1")?, 0);
            assert!(store.net_log_append("n1", 0, &[b"genesis".to_vec(), b"e1".to_vec()])?);
            assert!(!store.net_log_append("n1", 1, &[b"other".to_vec()])?, "wrong index: nothing written");
            assert!(!store.net_log_append("n1", 5, &[b"gap".to_vec()])?, "a gap is refused");
            assert!(store.net_log_append("n1", 2, &[b"e2".to_vec()])?);
            assert!(store.net_log_append("n2", 0, &[b"other net".to_vec()])?);
        }
        let store = Store::open(&path)?;
        assert_eq!(store.net_log_size("n1")?, 3);
        assert_eq!(store.net_log_load("n1", 100)?, vec![b"genesis".to_vec(), b"e1".to_vec(), b"e2".to_vec()]);
        assert_eq!(store.net_log_load("n1", 2)?.len(), 2, "bounded");
        assert_eq!(store.net_log_load("n2", 100)?.len(), 1);
        Ok(())
    }

    #[test]
    fn heads_and_evidence_are_bounded() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let row = |operator: &str, role: &str, size: u64| HeadRow {
            operator: operator.into(),
            role: role.into(),
            size,
            head: b"h".to_vec(),
            cosigns: b"[]".to_vec(),
        };
        assert!(store.net_head_put("n", &row("op", "issued", 1), 0)?);
        assert!(store.net_head_put("n", &row("op", "issued", 2), 1)?, "replaced");
        assert_eq!(store.net_heads("n")?, vec![row("op", "issued", 2)]);
        for i in 1..MAX_HEAD_ROWS_PER_NET {
            assert!(store.net_head_put("n", &row(&format!("op{i}"), "witnessed", 1), 0)?);
        }
        assert!(!store.net_head_put("n", &row("one-too-many", "witnessed", 1), 0)?);
        assert!(store.net_head_put("n", &row("op", "issued", 3), 0)?, "existing rows can still change");
        assert!(store.net_head_put("other", &row("op", "issued", 1), 0)?, "per network");

        assert!(store.net_evidence_put("n", "op", b"e1", 0)?);
        assert!(!store.net_evidence_put("n", "op", b"e2", 1)?, "one per operator");
        assert_eq!(store.net_evidence("n")?, vec![("op".to_owned(), b"e1".to_vec())]);
        for i in 1..MAX_EVIDENCE_PER_NET {
            assert!(store.net_evidence_put("n", &format!("op{i}"), b"e", 0)?);
        }
        assert!(!store.net_evidence_put("n", "late", b"e", 0)?, "full");
        assert_eq!(store.net_evidence("n")?.len(), MAX_EVIDENCE_PER_NET);
        Ok(())
    }

    #[test]
    fn transition_heads_are_replaced_deleted_and_bounded() -> StoreResult<()> {
        let dir = tempfile::tempdir().map_err(|e| StoreError::Database(e.to_string()))?;
        let path = dir.path().join("node.db");
        let row = |size: u64, tag: &str| TransitionRow {
            size,
            head: format!("head-{size}-{tag}").into_bytes(),
            cosigns: b"[]".to_vec(),
        };
        {
            let store = Store::open(&path)?;
            assert!(store.net_transition_put("n", &row(5, "damaged"), 3)?);
            // The node stores a row only for a verified head it does not hold: it replaces one that did not verify.
            assert!(store.net_transition_put("n", &row(5, "a"), 3)?, "replaced");
            assert!(!store.net_transition_put("n", &row(5, "a"), 3)?, "the same row again: nothing changes");
            assert_eq!(store.net_transitions("n", 3)?, vec![row(5, "a")]);
            assert!(store.net_transition_put("n", &row(4, "a"), 3)?);
            assert!(store.net_transition_delete("n", 4)?);
            assert!(!store.net_transition_delete("n", 4)?, "gone");
            assert!(!store.net_transition_delete("n", u64::MAX)?);
            for size in [2, 9, 7] {
                assert!(store.net_transition_put("n", &row(size, "a"), 3)?);
            }
            assert!(store.net_transition_put("other", &row(1, "a"), 3)?, "per network");
            assert!(!store.net_transition_put("n", &row(u64::MAX, "a"), 3)?, "impossible size");
        }
        // Survives a restart; at most 3 kept, the smallest went.
        let store = Store::open(&path)?;
        let sizes: Vec<u64> = store.net_transitions("n", 64)?.iter().map(|row| row.size).collect();
        assert_eq!(sizes, vec![5, 7, 9]);
        assert_eq!(store.net_transitions("n", 2)?.len(), 2, "bounded read");
        assert_eq!(store.net_transitions("other", 64)?.len(), 1);
        Ok(())
    }

    #[test]
    fn newest_home_wins_and_paging_by_node() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert_eq!(store.home_put("n", &home("alice", "g1", 10), 2)?, HomeStored::Stored);
        assert_eq!(store.home_put("n", &home("alice", "g2", 5), 2)?, HomeStored::Older, "older entry loses");
        assert_eq!(store.home_put("n", &home("alice", "g2", 10), 2)?, HomeStored::Older, "same iat loses too");
        assert_eq!(store.home_get("n", "alice", 0)?.map(|h| h.node), Some("g1".to_owned()));
        assert_eq!(store.home_put("n", &home("bob", "g1", 20), 2)?, HomeStored::Stored);
        assert_eq!(store.home_put("n", &home("carol", "g1", 20), 2)?, HomeStored::Full, "limit");
        assert_eq!(store.home_put("n", &home("alice", "g2", 30), 2)?, HomeStored::Stored, "move to g2");

        let g1 = store.homes_of_node_since("n", "g1", 0, 10, 0)?;
        assert_eq!(g1.iter().map(|h| h.member.as_str()).collect::<Vec<_>>(), vec!["bob"]);
        let g2 = store.homes_of_node_since("n", "g2", 0, 10, 0)?;
        assert_eq!(g2.len(), 1);
        assert!(store.homes_of_node_since("n", "g2", g2[0].seq, 10, 0)?.is_empty(), "nothing newer");
        assert!(store.homes_of_node_since("n", "g1", 0, 10, 2000)?.is_empty(), "expired ones are not handed out");
        assert_eq!(store.home_get("n", "bob", 1020)?, None, "expired");
        assert_eq!(store.home_put("n", &home("carol", "g1", 1500), 2)?, HomeStored::Stored, "room after expiry");
        assert_eq!(store.purge_net(1_000_000)?.0, 1, "only carol was left");
        Ok(())
    }

    #[test]
    fn outbox_replay_quotas_and_retries() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert_eq!(store.relay_enqueue(&item("g2", "alice", &[1; 16], b"e1"), &RELAY, &MAILBOX)?, Delivered::Stored);
        assert_eq!(store.relay_enqueue(&item("g2", "alice", &[1; 16], b"e1"), &RELAY, &MAILBOX)?, Delivered::Replay);
        assert_eq!(store.relay_enqueue(&item("g2", "bob", &[2; 16], b"e2"), &RELAY, &MAILBOX)?, Delivered::Stored);
        assert_eq!(store.relay_enqueue(&item("g2", "carol", &[3; 16], b"e3"), &RELAY, &MAILBOX)?, Delivered::Stored);
        assert_eq!(
            store.relay_enqueue(&item("g2", "dave", &[4; 16], b"e4"), &RELAY, &MAILBOX)?,
            Delivered::MailboxFull,
            "3 per target"
        );
        assert_eq!(
            store.relay_enqueue(&item("g3", "dave", &[4; 16], &[0; 200]), &RELAY, &MAILBOX)?,
            Delivered::NodeFull,
            "bytes"
        );
        assert_eq!(store.relay_enqueue(&item("g3", "dave", &[4; 16], b"e4"), &RELAY, &MAILBOX)?, Delivered::Stored);
        assert_eq!(
            store.relay_enqueue(&item("g3", "erin", &[5; 16], b"e5"), &RELAY, &MAILBOX)?,
            Delivered::NodeFull,
            "4 entries"
        );
        // The mailbox shares the replay table: the same envelope can not also be delivered locally.
        let local = crate::Delivery {
            recipient: "x",
            sender: "alice",
            env_id: &[1; 16],
            expires_at: 500,
            envelope: b"e1",
            now: 0,
        };
        assert_eq!(store.deliver(&local, &MAILBOX)?, Delivered::Replay);

        let due = store.relay_due(0, 10)?;
        assert_eq!(due.len(), 4);
        assert_eq!((due[0].target.as_str(), due[0].sender.as_str(), due[0].attempts), ("g2", "alice", 0));
        store.relay_later(due[0].seq, 100)?;
        assert_eq!(store.relay_due(50, 10)?.len(), 3, "postponed");
        let retried = store.relay_due(100, 10)?;
        assert_eq!(retried.iter().find(|o| o.sender == "alice").map(|o| o.attempts), Some(1));
        store.relay_done(due[1].seq)?;
        assert_eq!(store.relay_waiting()?, 3);
        assert!(store.relay_due(500, 10)?.is_empty(), "expired ones are not handed out");
        assert_eq!(store.purge_net(500)?.1, 3);
        assert_eq!(store.relay_enqueue(&item("g3", "erin", &[5; 16], b"e5"), &RELAY, &MAILBOX)?, Delivered::Stored);
        Ok(())
    }
}
