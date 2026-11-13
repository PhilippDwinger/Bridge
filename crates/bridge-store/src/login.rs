//! Bridge Login accounts (schema 14, docs/11 §9.3): the newest state of every account, every entry in arrival order
//! (the exchange between storage nodes asks "since sequence number"), the signature counters this node saw.
//! Nothing cryptographic here - the node checked every entry before it comes here.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, StoreResult};

/// Most accounts per network on one node.
pub const MAX_LOGIN_ACCOUNTS: i64 = 100_000;

/// What became of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginApplied {
    /// Stored: the account has this version now.
    Applied,
    /// This node has this version (or a newer one) already.
    Known,
    /// Not the next version, or its passkey belongs to another account.
    Conflict,
    /// No room for another account.
    Full,
}

impl Store {
    /// The stored state of an account (JSON) and its version.
    pub fn login_account(&self, net: &str, account: &str) -> StoreResult<Option<(String, u32)>> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT state, version FROM login_accounts WHERE net = ?1 AND account = ?2",
                params![net, account],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// The stored state of the account that has the passkey `cred_id`.
    pub fn login_account_by_credential(&self, net: &str, cred_id: &[u8]) -> StoreResult<Option<String>> {
        Ok(self
            .lock()?
            .query_row("SELECT state FROM login_accounts WHERE net = ?1 AND cred_id = ?2", params![net, cred_id], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Stores a checked entry with the account state it makes: only the next version (`version` 1 only for a new
    /// account), a passkey only for one account, at most [`MAX_LOGIN_ACCOUNTS`] accounts.
    #[allow(clippy::too_many_arguments)]
    pub fn login_apply(
        &self,
        net: &str,
        account: &str,
        version: u32,
        cred_id: &[u8],
        state: &str,
        entry: &[u8],
        updated: i64,
    ) -> StoreResult<LoginApplied> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<u32> = transaction
            .query_row(
                "SELECT version FROM login_accounts WHERE net = ?1 AND account = ?2",
                params![net, account],
                |r| r.get(0),
            )
            .optional()?;
        match current {
            Some(have) if have >= version => return Ok(LoginApplied::Known),
            Some(have) if have.saturating_add(1) != version => return Ok(LoginApplied::Conflict),
            None if version != 1 => return Ok(LoginApplied::Conflict),
            _ => {}
        }
        let holder: Option<String> = transaction
            .query_row(
                "SELECT account FROM login_accounts WHERE net = ?1 AND cred_id = ?2",
                params![net, cred_id],
                |r| r.get(0),
            )
            .optional()?;
        if holder.is_some_and(|holder| holder != account) {
            return Ok(LoginApplied::Conflict);
        }
        if current.is_none() {
            let count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM login_accounts WHERE net = ?1", [net], |r| r.get(0))?;
            if count >= MAX_LOGIN_ACCOUNTS {
                return Ok(LoginApplied::Full);
            }
        }
        transaction.execute(
            "INSERT INTO login_accounts (net, account, cred_id, version, state, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (net, account) DO UPDATE SET cred_id = excluded.cred_id, version = excluded.version,
                 state = excluded.state, updated = excluded.updated",
            params![net, account, cred_id, version, state, updated],
        )?;
        transaction.execute(
            "INSERT INTO login_entries (net, account, version, entry) VALUES (?1, ?2, ?3, ?4)",
            params![net, account, version, entry],
        )?;
        transaction.commit()?;
        Ok(LoginApplied::Applied)
    }

    /// Entries after `seq` in arrival order (at most `limit`): `(seq, entry)`.
    pub fn login_entries_since(&self, net: &str, seq: i64, limit: usize) -> StoreResult<Vec<(i64, Vec<u8>)>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT seq, entry FROM login_entries WHERE net = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3")?;
        let rows = statement
            .query_map(params![net, seq, i64::try_from(limit).unwrap_or(i64::MAX)], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// The highest signature counter this node saw for a passkey (0: none).
    pub fn login_counter(&self, net: &str, cred_id: &[u8]) -> StoreResult<u32> {
        Ok(self
            .lock()?
            .query_row("SELECT count FROM login_counters WHERE net = ?1 AND cred_id = ?2", params![net, cred_id], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(0))
    }

    /// Remembers a signature counter (only ever upwards).
    pub fn login_counter_set(&self, net: &str, cred_id: &[u8], count: u32) -> StoreResult<()> {
        self.lock()?.execute(
            "INSERT INTO login_counters (net, cred_id, count) VALUES (?1, ?2, ?3)
             ON CONFLICT (net, cred_id) DO UPDATE SET count = MAX(count, excluded.count)",
            params![net, cred_id, count],
        )?;
        Ok(())
    }

    /// How many accounts this node holds for a network.
    pub fn login_accounts_count(&self, net: &str) -> StoreResult<i64> {
        Ok(self.lock()?.query_row("SELECT COUNT(*) FROM login_accounts WHERE net = ?1", [net], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_credentials_and_order() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let apply = |account: &str, version: u32, cred: &[u8]| {
            store.login_apply("net", account, version, cred, &format!("{account}-{version}"), b"entry", 1)
        };
        assert_eq!(apply("a", 2, b"c1")?, LoginApplied::Conflict, "a new account starts with version 1");
        assert_eq!(apply("a", 1, b"c1")?, LoginApplied::Applied);
        assert_eq!(apply("a", 1, b"c1")?, LoginApplied::Known);
        assert_eq!(apply("b", 1, b"c1")?, LoginApplied::Conflict, "a passkey belongs to one account");
        assert_eq!(apply("a", 3, b"c2")?, LoginApplied::Conflict, "no version skipped");
        assert_eq!(apply("a", 2, b"c2")?, LoginApplied::Applied);
        assert_eq!(store.login_account("net", "a")?, Some(("a-2".to_owned(), 2)));
        assert_eq!(store.login_account_by_credential("net", b"c2")?, Some("a-2".to_owned()));
        assert_eq!(store.login_account_by_credential("net", b"c1")?, None, "the old passkey is gone");
        assert_eq!(apply("b", 1, b"c1")?, LoginApplied::Applied, "free again");
        let entries = store.login_entries_since("net", 0, 10)?;
        assert_eq!(entries.len(), 3);
        assert_eq!(store.login_entries_since("net", entries[1].0, 10)?.len(), 1);
        assert_eq!(store.login_entries_since("other", 0, 10)?.len(), 0);
        assert_eq!(store.login_accounts_count("net")?, 2);
        store.login_counter_set("net", b"c2", 5)?;
        store.login_counter_set("net", b"c2", 3)?;
        assert_eq!(store.login_counter("net", b"c2")?, 5, "only upwards");
        Ok(())
    }
}
