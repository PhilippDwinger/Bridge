//! What the sandboxed code keeps (schema 12, docs/09 §12, §13): the key-value store of every plugin and the event
//! log of every app with server code. The store checks bounds, nothing cryptographic (the node verified events).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, StoreResult};

/// Most events kept per app and host (at most 4 KiB each).
pub const MAX_EVENTS_PER_HOST: u64 = 10_000;
/// Most events kept per app, all hosts together.
pub const MAX_EVENTS_PER_APP: u64 = 50_000;

/// One stored event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    /// Host node ID.
    pub host: String,
    /// Sequence number at that host (1, 2, …).
    pub seq: u64,
    /// Issued at (ms).
    pub iat: i64,
    /// The signed statement.
    pub statement: Vec<u8>,
}

impl Store {
    /// A plugin's value for `key`.
    pub fn plugin_kv_get(&self, plugin: &str, key: &[u8]) -> StoreResult<Option<Vec<u8>>> {
        Ok(self
            .lock()?
            .query_row("SELECT value FROM plugin_kv WHERE plugin = ?1 AND key = ?2", params![plugin, key], |r| r.get(0))
            .optional()?)
    }

    /// Stores a plugin's value if the plugin stays within `quota` bytes (keys and values together). Returns whether
    /// it was stored.
    pub fn plugin_kv_put(&self, plugin: &str, key: &[u8], value: &[u8], quota: u64) -> StoreResult<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let used: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(length(key) + length(value)), 0) FROM plugin_kv WHERE plugin = ?1 AND key != ?2",
            params![plugin, key],
            |r| r.get(0),
        )?;
        if used as u64 + key.len() as u64 + value.len() as u64 > quota {
            return Ok(false);
        }
        transaction.execute(
            "INSERT INTO plugin_kv (plugin, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (plugin, key) DO UPDATE SET value = ?3",
            params![plugin, key, value],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// The highest sequence number of `host`'s events of `app` (0: none).
    pub fn app_event_last(&self, app: &str, host: &str) -> StoreResult<u64> {
        let last: i64 = self.lock()?.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM app_events WHERE app = ?1 AND host = ?2",
            params![app, host],
            |r| r.get(0),
        )?;
        Ok(last as u64)
    }

    /// Adds an event if it continues `host`'s sequence (`seq` = last + 1) and the host is below
    /// [`MAX_EVENTS_PER_HOST`]. Returns whether it was added.
    pub fn app_event_add(&self, app: &str, event: &EventRow) -> StoreResult<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM app_events WHERE app = ?1 AND host = ?2",
            params![app, event.host],
            |r| r.get(0),
        )?;
        if event.seq != last as u64 + 1 || event.seq > MAX_EVENTS_PER_HOST {
            return Ok(false);
        }
        let total: i64 =
            transaction.query_row("SELECT COUNT(*) FROM app_events WHERE app = ?1", [app], |r| r.get(0))?;
        if total as u64 >= MAX_EVENTS_PER_APP {
            return Ok(false);
        }
        transaction.execute(
            "INSERT INTO app_events (app, host, seq, iat, statement) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![app, event.host, event.seq as i64, event.iat, event.statement],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// `host`'s events of `app` after `after`, at most `max`, in order.
    pub fn app_events_of(&self, app: &str, host: &str, after: u64, max: usize) -> StoreResult<Vec<EventRow>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT host, seq, iat, statement FROM app_events WHERE app = ?1 AND host = ?2 AND seq > ?3
             ORDER BY seq LIMIT ?4",
        )?;
        let rows = statement
            .query_map(params![app, host, after as i64, max as i64], |row| {
                Ok(EventRow {
                    host: row.get(0)?,
                    seq: row.get::<_, i64>(1)? as u64,
                    iat: row.get(2)?,
                    statement: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Number of events of `app` (all hosts).
    pub fn app_event_count(&self, app: &str) -> StoreResult<u64> {
        let count: i64 =
            self.lock()?.query_row("SELECT COUNT(*) FROM app_events WHERE app = ?1", [app], |r| r.get(0))?;
        Ok(count as u64)
    }

    /// Event number `index` of `app` in the agreed order `(iat, host, seq)`.
    pub fn app_event_at(&self, app: &str, index: u64) -> StoreResult<Option<EventRow>> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT host, seq, iat, statement FROM app_events WHERE app = ?1 ORDER BY iat, host, seq
                 LIMIT 1 OFFSET ?2",
                params![app, index as i64],
                |row| {
                    Ok(EventRow {
                        host: row.get(0)?,
                        seq: row.get::<_, i64>(1)? as u64,
                        iat: row.get(2)?,
                        statement: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(host: &str, seq: u64, iat: i64) -> EventRow {
        EventRow { host: host.into(), seq, iat, statement: format!("{host}{seq}").into_bytes() }
    }

    #[test]
    fn plugin_store_has_a_quota() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert!(store.plugin_kv_put("p", b"k", b"1234", 10)?);
        assert_eq!(store.plugin_kv_get("p", b"k")?, Some(b"1234".to_vec()));
        assert!(store.plugin_kv_put("p", b"k", b"123456789", 10)?, "replacing counts the new value only");
        assert!(!store.plugin_kv_put("p", b"x", b"1", 10)?, "quota");
        assert_eq!(store.plugin_kv_get("other", b"k")?, None, "plugins do not see each other");
        Ok(())
    }

    #[test]
    fn events_continue_and_merge_in_order() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert!(store.app_event_add("a", &event("h1", 1, 10))?);
        assert!(!store.app_event_add("a", &event("h1", 3, 11))?, "no gap");
        assert!(!store.app_event_add("a", &event("h1", 1, 11))?, "no repeat");
        assert!(store.app_event_add("a", &event("h2", 1, 5))?);
        assert!(store.app_event_add("a", &event("h1", 2, 20))?);
        assert_eq!(store.app_event_count("a")?, 3);
        let order: Vec<(String, u64)> =
            (0..3).filter_map(|i| store.app_event_at("a", i).ok().flatten()).map(|e| (e.host, e.seq)).collect();
        assert_eq!(order, vec![("h2".into(), 1), ("h1".into(), 1), ("h1".into(), 2)]);
        assert_eq!(store.app_events_of("a", "h1", 1, 10)?.len(), 1);
        assert_eq!(store.app_event_last("a", "h1")?, 2);
        Ok(())
    }
}
