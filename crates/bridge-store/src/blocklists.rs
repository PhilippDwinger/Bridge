//! Blocklists a node keeps (schema 11, docs/08 §9): the newest list statement per network and publisher. The store
//! checks nothing cryptographic - the node verified the list before. It keeps at most one row per publisher, only a
//! higher version replaces it, and at most [`MAX_BLOCKLISTS_PER_NET`] rows per network.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, StoreResult};

/// Most lists kept per network (the manifest names at most 8 publishers).
pub const MAX_BLOCKLISTS_PER_NET: usize = 8;

impl Store {
    /// Keeps `statement` as `publisher`'s list if it is newer than the one kept (and there is room). Returns
    /// whether it was kept.
    pub fn blocklist_put(
        &self,
        net: &str,
        publisher: &str,
        version: u64,
        statement: &[u8],
        now: i64,
    ) -> StoreResult<bool> {
        let version = i64::try_from(version).unwrap_or(i64::MAX);
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let held: Option<i64> = transaction
            .query_row(
                "SELECT version FROM blocklists WHERE net = ?1 AND publisher = ?2",
                params![net, publisher],
                |row| row.get(0),
            )
            .optional()?;
        match held {
            Some(held) if held >= version => return Ok(false),
            Some(_) => {}
            None => {
                let count: i64 =
                    transaction.query_row("SELECT COUNT(*) FROM blocklists WHERE net = ?1", [net], |r| r.get(0))?;
                if count as u64 >= MAX_BLOCKLISTS_PER_NET as u64 {
                    return Ok(false);
                }
            }
        }
        transaction.execute(
            "INSERT INTO blocklists (net, publisher, version, statement, received) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (net, publisher) DO UPDATE SET version = ?3, statement = ?4, received = ?5",
            params![net, publisher, version, statement, now],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// The kept lists of a network: (publisher, statement), at most [`MAX_BLOCKLISTS_PER_NET`].
    pub fn blocklists(&self, net: &str) -> StoreResult<Vec<(String, Vec<u8>)>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT publisher, statement FROM blocklists WHERE net = ?1 ORDER BY publisher LIMIT ?2")?;
        let rows = statement
            .query_map(params![net, MAX_BLOCKLISTS_PER_NET as i64], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Forgets the lists of a network whose publishers are not in `keep`.
    pub fn blocklists_retain(&self, net: &str, keep: &[String]) -> StoreResult<usize> {
        let connection = self.lock()?;
        let mut removed = 0;
        for (publisher, _) in self.blocklists_unlocked(&connection, net)? {
            if !keep.contains(&publisher) {
                removed += connection
                    .execute("DELETE FROM blocklists WHERE net = ?1 AND publisher = ?2", params![net, publisher])?;
            }
        }
        Ok(removed)
    }

    fn blocklists_unlocked(&self, connection: &rusqlite::Connection, net: &str) -> StoreResult<Vec<(String, i64)>> {
        let mut statement = connection.prepare("SELECT publisher, version FROM blocklists WHERE net = ?1 LIMIT 64")?;
        let rows = statement.query_map([net], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Store, StoreResult};

    #[test]
    fn newer_versions_replace_older_ones_and_the_table_is_bounded() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert!(store.blocklist_put("n", "p1", 2, b"v2", 1)?);
        assert!(!store.blocklist_put("n", "p1", 2, b"again", 2)?, "same version");
        assert!(!store.blocklist_put("n", "p1", 1, b"v1", 3)?, "no rollback");
        assert!(store.blocklist_put("n", "p1", 3, b"v3", 4)?);
        assert_eq!(store.blocklists("n")?, vec![("p1".to_owned(), b"v3".to_vec())]);
        for i in 2..=8 {
            assert!(store.blocklist_put("n", &format!("p{i}"), 1, b"x", 5)?);
        }
        assert!(!store.blocklist_put("n", "p9", 1, b"x", 6)?, "at most 8 per network");
        assert!(store.blocklist_put("other", "p9", 1, b"x", 6)?);
        assert_eq!(store.blocklists_retain("n", &["p1".to_owned()])?, 7);
        assert_eq!(store.blocklists("n")?.len(), 1);
        Ok(())
    }
}
