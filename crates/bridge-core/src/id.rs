//! IDs: Base32 of the first 20 bytes of SHA-256(Ed25519 public key) - 32 characters (docs/04 §2).
//! Whoever holds the key owns the ID; nobody can take over someone else's ID.

use std::fmt;

use crate::encoding::base32;
use crate::error::{CoreError, CoreResult};

/// Length of an ID in characters.
pub const ID_LEN: usize = 32;

/// The ID of an identity (client, node, network, admin).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(String);

impl Id {
    /// The ID that belongs to an Ed25519 public key.
    #[must_use]
    pub fn of_sign_key(public_key: &[u8; 32]) -> Self {
        let digest = crate::crypto::sha256(public_key);
        Self(base32(&digest[..20]))
    }

    /// The ID from a SHA-256 digest (its first 20 bytes) - for IDs that are no key's (Bridge Login accounts and
    /// per-app users, docs/11 §9).
    #[must_use]
    pub fn of_digest(digest: &[u8; 32]) -> Self {
        Self(base32(&digest[..20]))
    }

    /// Checks the form (32 characters of lower-case Base32) - nothing else.
    pub fn parse(text: &str) -> CoreResult<Self> {
        let ok = text.len() == ID_LEN && text.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
        if !ok {
            return Err(CoreError::format("id: expected 32 characters of base32"));
        }
        Ok(Self(text.to_owned()))
    }

    /// The ID as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_shape_and_parse() {
        let id = Id::of_sign_key(&[7u8; 32]);
        assert_eq!(id.as_str().len(), ID_LEN);
        assert_eq!(Id::parse(id.as_str()), Ok(id.clone()));
        assert!(Id::parse("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").is_err(), "upper case");
        assert!(Id::parse("abcdefghijklmnopqrstuvwxyz23456").is_err(), "too short");
        assert!(Id::parse("abcdefghijklmnopqrstuvwxyz234568").is_err(), "8 is not base32");
        assert_ne!(Id::of_sign_key(&[1u8; 32]), Id::of_sign_key(&[2u8; 32]));
    }
}
