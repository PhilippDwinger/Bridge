//! Agent revocations (schema 13, docs/10 §3.3): kept at the agent's home node until the latest possible expiry of
//! the revoked statements. Bounded per owner and per node. Nothing cryptographic here (the node checked the request).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, StoreResult};

/// Most remembered revocations per owner.
pub const MAX_AGENT_REVOCATIONS_PER_OWNER: i64 = 256;
/// Most remembered revocations per node.
pub const MAX_AGENT_REVOCATIONS: i64 = 100_000;

impl Store {
    /// Remembers that statements of `owner` for `agent` issued up to `before` are invalid until `until`. Expired rows
    /// go first; returns `false` if the owner's or the node's share is full (an existing row is always updated).
    pub fn agent_revoke(&self, agent: &str, owner: &str, before: i64, until: i64, now: i64) -> StoreResult<bool> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM agent_revocations WHERE until <= ?1", [now])?;
        let exists: Option<i64> = transaction
            .query_row(
                "SELECT before FROM agent_revocations WHERE agent = ?1 AND owner = ?2",
                params![agent, owner],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_none() {
            let of_owner: i64 =
                transaction
                    .query_row("SELECT COUNT(*) FROM agent_revocations WHERE owner = ?1", [owner], |r| r.get(0))?;
            let all: i64 = transaction.query_row("SELECT COUNT(*) FROM agent_revocations", [], |r| r.get(0))?;
            if of_owner >= MAX_AGENT_REVOCATIONS_PER_OWNER || all >= MAX_AGENT_REVOCATIONS {
                return Ok(false);
            }
        }
        transaction.execute(
            "INSERT INTO agent_revocations (agent, owner, before, until) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (agent, owner) DO UPDATE SET before = MAX(before, excluded.before),
                 until = MAX(until, excluded.until)",
            params![agent, owner, before, until],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Up to when statements of `owner` for `agent` are revoked (`None`: not revoked), as seen at `now`.
    pub fn agent_revoked_before(&self, agent: &str, owner: &str, now: i64) -> StoreResult<Option<i64>> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT before FROM agent_revocations WHERE agent = ?1 AND owner = ?2 AND until > ?3",
                params![agent, owner, now],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Removes the home entry of `member` (an agent that was revoked here).
    pub fn home_delete(&self, net: &str, member: &str) -> StoreResult<bool> {
        Ok(self.lock()?.execute("DELETE FROM net_homes WHERE net = ?1 AND member = ?2", params![net, member])? > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocations_are_bounded_and_expire() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        assert_eq!(store.agent_revoked_before("a", "o", 0)?, None);
        assert!(store.agent_revoke("a", "o", 100, 1_000, 0)?);
        assert_eq!(store.agent_revoked_before("a", "o", 500)?, Some(100));
        assert_eq!(store.agent_revoked_before("a", "x", 500)?, None, "only for this owner");
        // A later revocation moves `before` forward, an older one never back.
        assert!(store.agent_revoke("a", "o", 300, 1_200, 10)?);
        assert!(store.agent_revoke("a", "o", 200, 900, 20)?);
        assert_eq!(store.agent_revoked_before("a", "o", 500)?, Some(300));
        assert_eq!(store.agent_revoked_before("a", "o", 1_200)?, None, "expired");
        // Per owner bounded; others still fit; expired rows make room.
        for index in 1..MAX_AGENT_REVOCATIONS_PER_OWNER {
            assert!(store.agent_revoke(&format!("agent{index}"), "o", 1, 5_000, 30)?);
        }
        assert!(!store.agent_revoke("one-more", "o", 1, 5_000, 30)?, "owner's share full");
        assert!(store.agent_revoke("a", "o", 400, 5_000, 30)?, "an existing row is always updated");
        assert!(store.agent_revoke("one-more", "p", 1, 5_000, 30)?);
        assert!(store.agent_revoke("one-more", "o", 1, 9_000, 6_000)?, "after expiry there is room again");
        Ok(())
    }
}
