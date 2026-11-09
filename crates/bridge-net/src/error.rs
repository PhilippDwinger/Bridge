//! Errors of the network layer, with the wire codes of docs/04 §9. Also used as the reason why a log entry was
//! skipped during replay (docs/06 §6: invalid entries do not count, but stop nothing).

use bridge_core::CoreError;
use thiserror::Error;

/// Every way a network operation can fail. `code()` is what goes over the wire.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NetError {
    /// Malformed input: wrong field, wrong length, unknown kind, other network, not canonical ...
    #[error("bad format: {0}")]
    BadFormat(String),
    /// Input larger than allowed.
    #[error("too large: {0}")]
    TooLarge(String),
    /// Signature missing or wrong.
    #[error("bad signature")]
    BadSignature,
    /// Lifetime over (at the time that counts).
    #[error("expired")]
    Expired,
    /// Issued too far in the future.
    #[error("not yet valid")]
    NotYetValid,
    /// The signer(s) do not have the right (or the target does not allow it).
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Not a member of the network.
    #[error("not a member")]
    NotMember,
    /// Banned (the signer, or the subject of a grant).
    #[error("banned")]
    Banned,
    /// A limit of the manifest or of this crate is reached.
    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
    /// The referenced object (statement, invite, entry) is unknown.
    #[error("not found: {0}")]
    NotFound(String),
    /// Any other core error (not expected in this layer).
    #[error("{0}")]
    Core(CoreError),
}

impl NetError {
    /// Wire code (docs/04 §9).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadFormat(_) => "BAD_FORMAT",
            Self::TooLarge(_) => "TOO_LARGE",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::Expired => "EXPIRED",
            Self::NotYetValid => "NOT_YET_VALID",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::NotMember => "NOT_MEMBER",
            Self::Banned => "BANNED",
            Self::QuotaExceeded(_) => "QUOTA_EXCEEDED",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Core(inner) => inner.code(),
        }
    }

    pub(crate) fn format(what: impl Into<String>) -> Self {
        Self::BadFormat(what.into())
    }

    pub(crate) fn forbidden(what: impl Into<String>) -> Self {
        Self::Forbidden(what.into())
    }

    pub(crate) fn quota(what: impl Into<String>) -> Self {
        Self::QuotaExceeded(what.into())
    }
}

impl From<CoreError> for NetError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::BadFormat(what) => Self::BadFormat(what),
            CoreError::TooLarge(what) => Self::TooLarge(what),
            CoreError::BadSignature => Self::BadSignature,
            CoreError::Expired => Self::Expired,
            CoreError::NotYetValid => Self::NotYetValid,
            other => Self::Core(other),
        }
    }
}

/// Result type of the network layer.
pub type NetResult<T> = Result<T, NetError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_core_mapping() {
        assert_eq!(NetError::forbidden("x").code(), "FORBIDDEN");
        assert_eq!(NetError::quota("x").code(), "QUOTA_EXCEEDED");
        assert_eq!(NetError::NotMember.code(), "NOT_MEMBER");
        assert_eq!(NetError::Banned.code(), "BANNED");
        assert_eq!(NetError::from(CoreError::BadSignature), NetError::BadSignature);
        assert_eq!(NetError::from(CoreError::Expired).code(), "EXPIRED");
        assert_eq!(NetError::from(CoreError::CannotOpen).code(), "CANNOT_OPEN");
        assert_eq!(NetError::from(CoreError::BadFormat("y".into())), NetError::BadFormat("y".into()));
    }
}
