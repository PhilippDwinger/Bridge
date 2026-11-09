//! Sessions (docs/04 §7): only for cheap things (polling); RAM only - after a restart clients log in again.
//! Tokens are random 32 bytes; the table is keyed by SHA-256 of the token, so lookups reveal nothing about tokens.

use std::collections::{HashMap, VecDeque};

use bridge_core::Id;
use bridge_core::crypto::sha256;

use crate::error::{NodeError, NodeResult};

struct Session {
    id: Id,
    expires_ms: i64,
}

/// All sessions of a node (bounded).
pub(crate) struct Sessions {
    by_hash: HashMap<[u8; 32], Session>,
    per_identity: HashMap<Id, VecDeque<[u8; 32]>>,
    max_total: usize,
    max_per_identity: usize,
    lifetime_ms: i64,
}

impl Sessions {
    pub(crate) fn new(max_total: usize, max_per_identity: usize, lifetime_ms: i64) -> Self {
        Self {
            by_hash: HashMap::new(),
            per_identity: HashMap::new(),
            max_total,
            max_per_identity: max_per_identity.max(1),
            lifetime_ms,
        }
    }

    /// Creates a session for `id` with `token`; the oldest session of `id` goes if it has too many.
    pub(crate) fn create(&mut self, id: &Id, token: &[u8; 32], now_ms: i64) -> NodeResult<i64> {
        if self.by_hash.len() >= self.max_total {
            self.sweep(now_ms);
            if self.by_hash.len() >= self.max_total {
                return Err(NodeError {
                    retry_after: Some(30),
                    ..NodeError::new(429, "RATE_LIMITED", "too many sessions")
                });
            }
        }
        let hash = sha256(token);
        let expires_ms = now_ms.saturating_add(self.lifetime_ms);
        let list = self.per_identity.entry(id.clone()).or_default();
        while list.len() >= self.max_per_identity {
            if let Some(old) = list.pop_front() {
                self.by_hash.remove(&old);
            }
        }
        list.push_back(hash);
        self.by_hash.insert(hash, Session { id: id.clone(), expires_ms });
        Ok(expires_ms)
    }

    /// The identity of a valid session.
    pub(crate) fn lookup(&mut self, token: &[u8; 32], now_ms: i64) -> Option<Id> {
        let hash = sha256(token);
        match self.by_hash.get(&hash) {
            Some(session) if session.expires_ms > now_ms => Some(session.id.clone()),
            Some(_) => {
                self.remove(&hash);
                None
            }
            None => None,
        }
    }

    fn remove(&mut self, hash: &[u8; 32]) {
        if let Some(session) = self.by_hash.remove(hash) {
            if let Some(list) = self.per_identity.get_mut(&session.id) {
                list.retain(|entry| entry != hash);
                if list.is_empty() {
                    self.per_identity.remove(&session.id);
                }
            }
        }
    }

    /// Removes expired sessions.
    pub(crate) fn sweep(&mut self, now_ms: i64) {
        let expired: Vec<[u8; 32]> =
            self.by_hash.iter().filter(|(_, session)| session.expires_ms <= now_ms).map(|(hash, _)| *hash).collect();
        for hash in expired {
            self.remove(&hash);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_hash.len()
    }
}

#[cfg(test)]
mod tests {
    use bridge_core::Identity;
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn lifetime_and_limits() -> NodeResult<()> {
        let mut sessions = Sessions::new(3, 2, 100);
        let alice = Identity::generate(&mut OsRng).id().clone();
        let bob = Identity::generate(&mut OsRng).id().clone();
        sessions.create(&alice, &[1; 32], 0)?;
        assert_eq!(sessions.lookup(&[1; 32], 50), Some(alice.clone()));
        assert_eq!(sessions.lookup(&[2; 32], 50), None);
        assert_eq!(sessions.lookup(&[1; 32], 100), None, "expired");
        sessions.create(&alice, &[1; 32], 0)?;
        sessions.create(&alice, &[2; 32], 0)?;
        sessions.create(&alice, &[3; 32], 0)?;
        assert_eq!(sessions.lookup(&[1; 32], 10), None, "oldest of alice dropped");
        assert_eq!(sessions.lookup(&[3; 32], 10), Some(alice.clone()));
        sessions.create(&bob, &[4; 32], 0)?;
        assert!(sessions.create(&bob, &[5; 32], 10).is_err(), "table full");
        assert!(sessions.create(&bob, &[5; 32], 200).is_ok(), "after expiry there is room");
        assert_eq!(sessions.len(), 1);
        Ok(())
    }
}
