//! Error codes of the protocol (docs/04 §9). Stable strings - clients rely on them.
//! Errors never reveal more than needed (no "exists but forbidden" vs "does not exist").

use thiserror::Error;

/// Every way a core operation can fail. `code()` is what goes over the wire.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Malformed input: not strict JSON, wrong field, wrong length, unknown kind ...
    #[error("bad format: {0}")]
    BadFormat(String),
    /// Input larger than allowed (checked before parsing).
    #[error("too large: {0}")]
    TooLarge(String),
    /// Signature missing or wrong, or the signer does not match the claimed identity.
    #[error("bad signature")]
    BadSignature,
    /// Lifetime over.
    #[error("expired")]
    Expired,
    /// Issued too far in the future (clock skew beyond the tolerance).
    #[error("not yet valid")]
    NotYetValid,
    /// Decryption failed (wrong recipient, tampered ciphertext, weak key).
    #[error("cannot open")]
    CannotOpen,
    /// Proof-of-work missing or wrong.
    #[error("proof of work required")]
    PowRequired,
}

impl CoreError {
    /// Wire code (docs/04 §9).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadFormat(_) => "BAD_FORMAT",
            Self::TooLarge(_) => "TOO_LARGE",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::Expired => "EXPIRED",
            Self::NotYetValid => "NOT_YET_VALID",
            Self::CannotOpen => "CANNOT_OPEN",
            Self::PowRequired => "POW_REQUIRED",
        }
    }

    pub(crate) fn format(what: impl Into<String>) -> Self {
        Self::BadFormat(what.into())
    }
}

/// Result type of the core.
pub type CoreResult<T> = Result<T, CoreError>;
