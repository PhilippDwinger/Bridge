//! Bridge Login accounts (schema 14/15, docs/11 §9.3): the newest state of every account, its passkeys (each belongs to
//! one account), every entry in arrival order (the exchange between storage nodes asks "since sequence number"), the
//! signature counters this node saw.
//! Nothing cryptographic here - the node checked every entry before it comes here.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, StoreResult};

/// Most accounts per network on one node.
pub const MAX_LOGIN_ACCOUNTS: i64 = 100_000;
/// Most passkeys of one account (docs/11 §14).
pub const MAX_LOGIN_DEVICES: usize = 8;
/// Most remember keys of one account (docs/11 §16).
pub const MAX_REMEMBER_PER_ACCOUNT: i64 = 16;
/// Most remember keys per network on one node.
pub const MAX_REMEMBER: i64 = 100_000;

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
            .query_row(
                "SELECT a.state FROM login_credentials c JOIN login_accounts a ON a.net = c.net AND a.account = c.account
                 WHERE c.net = ?1 AND c.cred_id = ?2",
                params![net, cred_id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Stores a checked entry with the account state it makes (`cred_ids`: all its passkeys after the entry, 1-8):
    /// only the next version (`version` 1 only for a new account), a passkey only for one account, at most
    /// [`MAX_LOGIN_ACCOUNTS`] accounts.
    #[allow(clippy::too_many_arguments)]
    pub fn login_apply(
        &self,
        net: &str,
        account: &str,
        version: u32,
        cred_ids: &[Vec<u8>],
        state: &str,
        entry: &[u8],
        updated: i64,
    ) -> StoreResult<LoginApplied> {
        let Some(first) = cred_ids.first().filter(|_| cred_ids.len() <= MAX_LOGIN_DEVICES) else {
            return Ok(LoginApplied::Conflict);
        };
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
        for cred_id in cred_ids {
            let holder: Option<String> = transaction
                .query_row(
                    "SELECT account FROM login_credentials WHERE net = ?1 AND cred_id = ?2",
                    params![net, cred_id],
                    |r| r.get(0),
                )
                .optional()?;
            if holder.is_some_and(|holder| holder != account) {
                return Ok(LoginApplied::Conflict);
            }
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
            params![net, account, first, version, state, updated],
        )?;
        transaction.execute("DELETE FROM login_credentials WHERE net = ?1 AND account = ?2", params![net, account])?;
        for cred_id in cred_ids {
            transaction.execute(
                "INSERT INTO login_credentials (net, cred_id, account) VALUES (?1, ?2, ?3)",
                params![net, cred_id, account],
            )?;
        }
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

    /// Keeps the hash of a remember key (docs/11 §16) for `account`'s device `cred_id` until `exp`: expired ones go
    /// first, then the oldest of the account beyond [`MAX_REMEMBER_PER_ACCOUNT`] and of the network beyond
    /// [`MAX_REMEMBER`].
    pub fn login_remember_add(
        &self,
        net: &str,
        hash: &[u8; 32],
        account: &str,
        cred_id: &[u8],
        exp: i64,
        now: i64,
    ) -> StoreResult<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM login_remember WHERE net = ?1 AND exp <= ?2", params![net, now])?;
        transaction.execute(
            "DELETE FROM login_remember WHERE net = ?1 AND hash IN (SELECT hash FROM login_remember
             WHERE net = ?1 AND account = ?2 ORDER BY exp DESC LIMIT -1 OFFSET ?3)",
            params![net, account, MAX_REMEMBER_PER_ACCOUNT - 1],
        )?;
        transaction.execute(
            "DELETE FROM login_remember WHERE net = ?1 AND hash IN (SELECT hash FROM login_remember
             WHERE net = ?1 ORDER BY exp DESC LIMIT -1 OFFSET ?2)",
            params![net, MAX_REMEMBER - 1],
        )?;
        transaction.execute(
            "INSERT OR REPLACE INTO login_remember (net, hash, account, cred_id, exp) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![net, hash.as_slice(), account, cred_id, exp],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Takes a remember key (it is used up either way): its account and device if it had not expired at `now`.
    pub fn login_remember_take(&self, net: &str, hash: &[u8; 32], now: i64) -> StoreResult<Option<(String, Vec<u8>)>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let found: Option<(String, Vec<u8>, i64)> = transaction
            .query_row(
                "SELECT account, cred_id, exp FROM login_remember WHERE net = ?1 AND hash = ?2",
                params![net, hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        transaction
            .execute("DELETE FROM login_remember WHERE net = ?1 AND hash = ?2", params![net, hash.as_slice()])?;
        transaction.commit()?;
        Ok(found.filter(|(_, _, exp)| *exp > now).map(|(account, cred, _)| (account, cred)))
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
    fn remember_keys_are_used_once_expire_and_are_bounded() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        store.login_remember_add("net", &[1; 32], "a", b"c1", 1_000, 0)?;
        assert_eq!(store.login_remember_take("other", &[1; 32], 10)?, None, "another network");
        assert_eq!(store.login_remember_take("net", &[1; 32], 10)?, Some(("a".into(), b"c1".to_vec())));
        assert_eq!(store.login_remember_take("net", &[1; 32], 10)?, None, "used up");
        store.login_remember_add("net", &[2; 32], "a", b"c1", 1_000, 0)?;
        assert_eq!(store.login_remember_take("net", &[2; 32], 1_000)?, None, "expired");
        for n in 0..20u8 {
            store.login_remember_add("net", &[10 + n; 32], "b", b"c2", 2_000 + i64::from(n), 0)?;
        }
        let kept = (0..20u8).filter(|n| store.login_remember_take("net", &[10 + n; 32], 1).ok().flatten().is_some());
        assert_eq!(kept.collect::<Vec<_>>(), (4..20).collect::<Vec<_>>(), "the newest 16 of the account");
        Ok(())
    }

    #[test]
    fn versions_credentials_and_order() -> StoreResult<()> {
        let store = Store::open_in_memory()?;
        let apply = |account: &str, version: u32, cred: &[u8]| {
            store.login_apply("net", account, version, &[cred.to_vec()], &format!("{account}-{version}"), b"entry", 1)
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
        // Several devices: both passkeys find the account, one of another account is refused, removing frees it.
        let several = |version: u32, creds: &[&[u8]]| {
            let creds: Vec<Vec<u8>> = creds.iter().map(|cred| cred.to_vec()).collect();
            store.login_apply("net", "a", version, &creds, &format!("a-{version}"), b"entry", 1)
        };
        assert_eq!(several(3, &[b"c2", b"c1"])?, LoginApplied::Conflict, "c1 is b's");
        assert_eq!(several(3, &[b"c2", b"c3"])?, LoginApplied::Applied);
        assert_eq!(store.login_account_by_credential("net", b"c3")?, Some("a-3".to_owned()));
        assert_eq!(store.login_account_by_credential("net", b"c2")?, Some("a-3".to_owned()));
        assert_eq!(several(4, &[b"c3"])?, LoginApplied::Applied);
        assert_eq!(store.login_account_by_credential("net", b"c2")?, None, "removed");
        assert_eq!(several(5, &[])?, LoginApplied::Conflict, "never without a passkey");
        store.login_counter_set("net", b"c2", 5)?;
        store.login_counter_set("net", b"c2", 3)?;
        assert_eq!(store.login_counter("net", b"c2")?, 5, "only upwards");
        Ok(())
    }
}
