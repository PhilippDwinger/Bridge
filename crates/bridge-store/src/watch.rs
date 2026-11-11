//! What a watcher persists (schema 7, docs/06 §11.7): the nodes registered for probes and their probe history.
//!
//! The store checks nothing cryptographic - the node verified the registration before. It enforces the bounds: at
//! most `max_nodes` registrations per network (a renewal always fits; a new node takes the place of the oldest
//! registration that is not passing its probes, review 8), a card is only replaced by one at least as new, and the
//! probes of a node are kept from `keep_after` on, at most `max_per_node` (the newest). Expired or evicted
//! registrations go with their probes.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, StoreResult};

/// A node registered for probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchNode {
    /// Node ID.
    pub node: String,
    /// The node's key card (as it registered).
    pub card: Vec<u8>,
    /// `iat` of that card (a registration with an older card keeps the stored one).
    pub card_iat: i64,
    /// Requested services (comma list of wire names, may be empty).
    pub services: String,
    /// The registration ends then (ms).
    pub expires: i64,
    /// First passed probe of the current run (ms; none yet, or reset after a series of failures).
    pub since: Option<i64>,
    /// Failed probes in a row.
    pub fails: u32,
    /// Time of the last probe (ms).
    pub last_probe: Option<i64>,
    /// Whether the last probe passed.
    pub last_ok: bool,
}

/// One probe of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// When (ms).
    pub at: i64,
    /// Passed.
    pub ok: bool,
    /// How long it took (ms).
    pub ms: i64,
}

/// A registration to store (checked by the node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration<'a> {
    /// Node ID.
    pub node: &'a str,
    /// The node's key card.
    pub card: &'a [u8],
    /// `iat` of that card.
    pub card_iat: i64,
    /// Requested services (comma list of wire names).
    pub services: &'a str,
    /// The registration ends then (ms).
    pub expires: i64,
    /// Now (ms): a new registration is "registered" at this time (the order of eviction).
    pub at: i64,
    /// The node's addresses or LAN pin changed: its observation starts again (`since` cleared, review 8). Only applied
    /// when the card is taken.
    pub restart: bool,
}

/// What the node made of a node's probes so far (stored with each probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    /// Observed since (ms).
    pub since: Option<i64>,
    /// Failed probes in a row.
    pub fails: u32,
}

/// Result of a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchRegistered {
    /// A new node.
    New,
    /// A known node: registration renewed.
    Renewed,
    /// A new node that took the place of this one (the oldest registration not passing its probes, removed with its
    /// probes).
    Evicted(String),
    /// The table is full and every node in it passes its probes (a new node does not fit).
    Full,
}

impl Store {
    /// Registers `node` for probes in `net` (or renews its registration until `expires`). A new node is added while
    /// fewer than `max_nodes` are registered; in a full table it takes the place of the registration that is not
    /// passing - without `since` first (probed ones before never probed ones), then with failures in a row - the
    /// oldest first (review 8). The card is taken if it is at least as new as the stored one; observation (`since`,
    /// failures, last probe) stays, unless `restart` (then `since` is cleared with the new card).
    pub fn watch_register(
        &self,
        net: &str,
        registration: &Registration<'_>,
        max_nodes: u64,
    ) -> StoreResult<WatchRegistered> {
        let Registration { node, card, card_iat, services, expires, at, restart } = *registration;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let known: Option<i64> = transaction
            .query_row("SELECT card_iat FROM watch_nodes WHERE net = ?1 AND node = ?2", params![net, node], |row| {
                row.get(0)
            })
            .optional()?;
        let result = match known {
            Some(stored_iat) => {
                transaction.execute(
                    "UPDATE watch_nodes SET services = ?3, expires = MAX(expires, ?4) WHERE net = ?1 AND node = ?2",
                    params![net, node, services, expires],
                )?;
                if card_iat >= stored_iat {
                    transaction.execute(
                        "UPDATE watch_nodes SET card = ?3, card_iat = ?4, since = CASE WHEN ?5 THEN NULL ELSE since END
                         WHERE net = ?1 AND node = ?2",
                        params![net, node, card, card_iat, restart],
                    )?;
                }
                WatchRegistered::Renewed
            }
            None => {
                let count: i64 =
                    transaction
                        .query_row("SELECT COUNT(*) FROM watch_nodes WHERE net = ?1", [net], |row| row.get(0))?;
                let mut result = WatchRegistered::New;
                if u64::try_from(count).unwrap_or(u64::MAX) >= max_nodes {
                    let victim: Option<String> = transaction
                        .query_row(
                            "SELECT node FROM watch_nodes WHERE net = ?1 AND (since IS NULL OR fails > 0)
                             ORDER BY since IS NOT NULL, last_probe IS NULL, registered, node LIMIT 1",
                            [net],
                            |row| row.get(0),
                        )
                        .optional()?;
                    let Some(victim) = victim else { return Ok(WatchRegistered::Full) };
                    transaction
                        .execute("DELETE FROM watch_probes WHERE net = ?1 AND node = ?2", params![net, victim])?;
                    transaction
                        .execute("DELETE FROM watch_nodes WHERE net = ?1 AND node = ?2", params![net, victim])?;
                    result = WatchRegistered::Evicted(victim);
                }
                transaction.execute(
                    "INSERT INTO watch_nodes (net, node, card, card_iat, services, expires, since, fails, last_probe,
                                              last_ok, registered)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0, NULL, 0, ?7)",
                    params![net, node, card, card_iat, services, expires, at],
                )?;
                result
            }
        };
        transaction.commit()?;
        Ok(result)
    }

    /// The registered nodes of `net` (at most `max`, by node ID).
    pub fn watch_nodes(&self, net: &str, max: u64) -> StoreResult<Vec<WatchNode>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare_cached(
            "SELECT node, card, card_iat, services, expires, since, fails, last_probe, last_ok FROM watch_nodes
             WHERE net = ?1 ORDER BY node LIMIT ?2",
        )?;
        let rows = statement.query_map(params![net, i64::try_from(max).unwrap_or(i64::MAX)], |row| {
            Ok(WatchNode {
                node: row.get(0)?,
                card: row.get(1)?,
                card_iat: row.get(2)?,
                services: row.get(3)?,
                expires: row.get(4)?,
                since: row.get(5)?,
                fails: u32::try_from(row.get::<_, i64>(6)?).unwrap_or(u32::MAX),
                last_probe: row.get(7)?,
                last_ok: row.get::<_, i64>(8)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Stores a probe of `node` together with its new standing, and forgets its probes before
    /// `keep_after` and beyond the newest `max_per_node`. Returns `false` (nothing stored) if the node is not
    /// registered (any more).
    pub fn watch_probe_put(
        &self,
        net: &str,
        node: &str,
        probe: &Probe,
        standing: Standing,
        keep_after: i64,
        max_per_node: usize,
    ) -> StoreResult<bool> {
        let Standing { since, fails } = standing;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE watch_nodes SET since = ?3, fails = ?4, last_probe = ?5, last_ok = ?6 WHERE net = ?1 AND node = ?2",
            params![net, node, since, i64::from(fails), probe.at, i64::from(probe.ok)],
        )?;
        if updated == 0 {
            return Ok(false);
        }
        transaction.execute(
            "INSERT INTO watch_probes (net, node, at, ok, ms) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (net, node, at) DO UPDATE SET ok = excluded.ok, ms = excluded.ms",
            params![net, node, probe.at, i64::from(probe.ok), probe.ms],
        )?;
        transaction.execute(
            "DELETE FROM watch_probes WHERE net = ?1 AND node = ?2 AND (at < ?3 OR at NOT IN
                 (SELECT at FROM watch_probes WHERE net = ?1 AND node = ?2 ORDER BY at DESC LIMIT ?4))",
            params![net, node, keep_after, i64::try_from(max_per_node).unwrap_or(i64::MAX)],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// (probes, passed probes) of `node` from `from` on.
    pub fn watch_probe_counts(&self, net: &str, node: &str, from: i64) -> StoreResult<(u64, u64)> {
        let connection = self.lock()?;
        let (total, passed): (i64, i64) = connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(ok), 0) FROM watch_probes WHERE net = ?1 AND node = ?2 AND at >= ?3",
            params![net, node, from],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok((u64::try_from(total).unwrap_or(0), u64::try_from(passed).unwrap_or(0)))
    }

    /// The newest probes of `node` (at most `max`, newest first).
    pub fn watch_probes(&self, net: &str, node: &str, max: u64) -> StoreResult<Vec<Probe>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare_cached(
            "SELECT at, ok, ms FROM watch_probes WHERE net = ?1 AND node = ?2 ORDER BY at DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(params![net, node, i64::try_from(max).unwrap_or(i64::MAX)], |row| {
            Ok(Probe { at: row.get(0)?, ok: row.get::<_, i64>(1)? != 0, ms: row.get(2)? })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Removes registrations that ended before `now`, with their probes. Returns how many.
    pub fn purge_watch(&self, now: i64) -> StoreResult<usize> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM watch_probes WHERE EXISTS (SELECT 1 FROM watch_nodes n WHERE n.net = watch_probes.net
                 AND n.node = watch_probes.node AND n.expires <= ?1)",
            [now],
        )?;
        let nodes = transaction.execute("DELETE FROM watch_nodes WHERE expires <= ?1", [now])?;
        transaction.commit()?;
        Ok(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "net";

    fn probe(at: i64, ok: bool) -> Probe {
        Probe { at, ok, ms: 7 }
    }

    fn standing(since: Option<i64>, fails: u32) -> Standing {
        Standing { since, fails }
    }

    fn reg<'a>(node: &'a str, card: &'a [u8], card_iat: i64, services: &'a str, expires: i64) -> Registration<'a> {
        Registration { node, card, card_iat, services, expires, at: 0, restart: false }
    }

    #[test]
    fn registrations_are_bounded_renewed_and_keep_newer_cards() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert_eq!(store.watch_register(NET, &reg("a", b"card-a1", 10, "web", 1000), 2)?, WatchRegistered::New);
        assert_eq!(store.watch_register(NET, &reg("b", b"card-b", 10, "", 1000), 2)?, WatchRegistered::New);
        // Both are new (never probed): the oldest registration makes room (review 8) - "a" (at 0) before "b" (at 0,
        // then by ID).
        store.watch_probe_put(NET, "a", &probe(1, true), standing(Some(1), 0), 0, 4)?;
        store.watch_probe_put(NET, "b", &probe(1, true), standing(Some(1), 0), 0, 4)?;
        assert_eq!(store.watch_register(NET, &reg("c", b"card-c", 10, "", 1000), 2)?, WatchRegistered::Full);
        let other = store.watch_register("other", &reg("c", b"card-c", 10, "", 1000), 2)?;
        assert_eq!(other, WatchRegistered::New, "per net");
        // Renewal always fits; an older card is not taken, a newer one is; the end only moves forward.
        assert_eq!(store.watch_register(NET, &reg("a", b"card-a0", 5, "", 2000), 2)?, WatchRegistered::Renewed);
        let nodes = store.watch_nodes(NET, 10)?;
        assert_eq!(nodes.len(), 2);
        assert_eq!(
            (nodes[0].card.as_slice(), nodes[0].services.as_str(), nodes[0].expires),
            (&b"card-a1"[..], "", 2000)
        );
        store.watch_register(NET, &reg("a", b"card-a2", 20, "web", 1500), 2)?;
        let nodes = store.watch_nodes(NET, 10)?;
        assert_eq!((nodes[0].card.as_slice(), nodes[0].card_iat, nodes[0].expires), (&b"card-a2"[..], 20, 2000));
        assert_eq!(store.watch_nodes(NET, 1)?.len(), 1, "bounded answer");
        Ok(())
    }

    /// Review 8, finding 3: 1,024 registrations of nodes that never pass a probe kept every new node out. A full
    /// table now makes room: the oldest registration without `since` (probed before never probed), then one with
    /// failures in a row; a table of passing nodes stays closed.
    #[test]
    fn a_full_table_evicts_the_oldest_not_passing() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let at = |node: &'static str, at: i64| Registration { at, ..reg(node, b"card", 1, "", 10_000) };
        for (node, time) in [("good", 1), ("never", 2), ("failed", 3), ("shaky", 4)] {
            assert_eq!(store.watch_register(NET, &at(node, time), 4)?, WatchRegistered::New);
        }
        store.watch_probe_put(NET, "good", &probe(5, true), standing(Some(5), 0), 0, 8)?;
        store.watch_probe_put(NET, "failed", &probe(5, false), standing(None, 1), 0, 8)?;
        store.watch_probe_put(NET, "shaky", &probe(5, true), standing(Some(5), 0), 0, 8)?;
        store.watch_probe_put(NET, "shaky", &probe(6, false), standing(Some(5), 1), 0, 8)?;
        // Probed and failed first (even though "never" is older), then never probed, then failures in a row.
        assert_eq!(store.watch_register(NET, &at("n1", 7), 4)?, WatchRegistered::Evicted("failed".into()));
        assert_eq!(store.watch_probe_counts(NET, "failed", 0)?, (0, 0), "its probes go too");
        assert_eq!(store.watch_register(NET, &at("n2", 8), 4)?, WatchRegistered::Evicted("never".into()));
        assert_eq!(store.watch_register(NET, &at("n3", 9), 4)?, WatchRegistered::Evicted("n1".into()));
        assert_eq!(store.watch_register(NET, &at("n4", 10), 4)?, WatchRegistered::Evicted("n2".into()));
        // Passing nodes keep their place; the one with a failure goes before them.
        store.watch_probe_put(NET, "n3", &probe(11, true), standing(Some(11), 0), 0, 8)?;
        store.watch_probe_put(NET, "n4", &probe(11, true), standing(Some(11), 0), 0, 8)?;
        assert_eq!(store.watch_register(NET, &at("n5", 12), 4)?, WatchRegistered::Evicted("shaky".into()));
        store.watch_probe_put(NET, "n5", &probe(13, true), standing(Some(13), 0), 0, 8)?;
        assert_eq!(store.watch_register(NET, &at("n6", 14), 4)?, WatchRegistered::Full);
        let nodes: Vec<String> = store.watch_nodes(NET, 10)?.into_iter().map(|node| node.node).collect();
        assert_eq!(nodes, ["good", "n3", "n4", "n5"]);
        // A renewal with new addresses starts the observation again (`restart`), an older card does not.
        let renewal = |iat: i64, restart: bool| Registration { restart, ..reg("good", b"card2", iat, "", 10_000) };
        store.watch_register(NET, &renewal(0, true), 4)?;
        assert_eq!(store.watch_nodes(NET, 1)?.remove(0).since, Some(5), "older card: not taken, since stays");
        store.watch_register(NET, &renewal(2, true), 4)?;
        assert_eq!(store.watch_nodes(NET, 1)?.remove(0).since, None, "restarted");
        Ok(())
    }

    #[test]
    fn probes_are_counted_bounded_and_purged() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert!(!store.watch_probe_put(NET, "a", &probe(1, true), standing(Some(1), 0), 0, 4)?, "not registered");
        store.watch_register(NET, &reg("a", b"card", 1, "web", 100), 8)?;
        for at in 1..=6 {
            let ok = at != 3;
            store.watch_probe_put(NET, "a", &probe(at, ok), standing(Some(1), u32::from(!ok)), 0, 4)?;
        }
        // Only the newest 4 are kept: 3 (failed), 4, 5, 6.
        assert_eq!(store.watch_probe_counts(NET, "a", 0)?, (4, 3));
        assert_eq!(store.watch_probe_counts(NET, "a", 5)?, (2, 2));
        let newest = store.watch_probes(NET, "a", 2)?;
        assert_eq!(newest.iter().map(|p| p.at).collect::<Vec<_>>(), vec![6, 5]);
        // Older than the window go too.
        store.watch_probe_put(NET, "a", &probe(7, false), standing(None, 1), 6, 4)?;
        assert_eq!(store.watch_probe_counts(NET, "a", 0)?, (2, 1));
        let node = store.watch_nodes(NET, 1)?.remove(0);
        assert_eq!((node.since, node.fails, node.last_probe, node.last_ok), (None, 1, Some(7), false));
        // Expired registrations go with their probes; others stay.
        store.watch_register(NET, &reg("b", b"card", 1, "", 1000), 8)?;
        store.watch_probe_put(NET, "b", &probe(8, true), standing(Some(8), 0), 0, 4)?;
        assert_eq!(store.purge_watch(100)?, 1);
        assert_eq!(store.watch_probe_counts(NET, "a", 0)?, (0, 0));
        assert_eq!(store.watch_probe_counts(NET, "b", 0)?, (1, 1));
        assert_eq!(store.watch_nodes(NET, 10)?.len(), 1);
        Ok(())
    }

    #[test]
    fn survives_reopen() -> StoreResult<()> {
        let dir = tempfile::tempdir().map_err(|e| crate::StoreError::Database(e.to_string()))?;
        let path = dir.path().join("node.db");
        {
            let store = Store::open(&path)?;
            store.watch_register(NET, &reg("a", b"card", 1, "web", 100), 8)?;
            store.watch_probe_put(NET, "a", &probe(5, true), standing(Some(5), 0), 0, 8)?;
        }
        let store = Store::open(&path)?;
        assert_eq!(store.watch_nodes(NET, 8)?.first().and_then(|node| node.since), Some(5));
        assert_eq!(store.watch_probe_counts(NET, "a", 0)?, (1, 1));
        Ok(())
    }
}
