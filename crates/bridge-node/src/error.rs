//! Errors as clients see them (docs/04 §9): a fixed code, an HTTP status, a short message - never internals.

use bridge_core::CoreError;
use bridge_guard::GuardError;
use bridge_store::StoreError;
use bridge_transport::Response;

/// One error answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeError {
    /// HTTP status.
    pub status: u16,
    /// Wire code.
    pub code: &'static str,
    /// Short, harmless text.
    pub message: String,
    /// Seconds until a retry makes sense.
    pub retry_after: Option<u32>,
}

impl NodeError {
    pub(crate) fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), retry_after: None }
    }
    pub(crate) fn bad_format(message: impl Into<String>) -> Self {
        Self::new(400, "BAD_FORMAT", message)
    }
    pub(crate) fn no_session() -> Self {
        Self::new(401, "NO_SESSION", "log in first")
    }
    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(403, "FORBIDDEN", message)
    }
    pub(crate) fn not_found() -> Self {
        Self::new(404, "NOT_FOUND", "not found")
    }
    pub(crate) fn quota() -> Self {
        Self { retry_after: Some(60), ..Self::new(429, "QUOTA_EXCEEDED", "mailbox full") }
    }
    pub(crate) fn unavailable() -> Self {
        Self::new(503, "UNAVAILABLE", "temporarily unavailable")
    }

    /// The HTTP answer.
    #[must_use]
    pub fn to_response(&self) -> Response {
        Response::error(self.status, self.code, &self.message, self.retry_after)
    }
}

impl From<CoreError> for NodeError {
    fn from(error: CoreError) -> Self {
        let status = match error {
            CoreError::BadFormat(_) | CoreError::CannotOpen => 400,
            CoreError::TooLarge(_) => 413,
            CoreError::BadSignature | CoreError::Expired | CoreError::NotYetValid => 401,
            CoreError::PowRequired => 403,
        };
        Self::new(status, error.code(), error.to_string())
    }
}

impl From<GuardError> for NodeError {
    fn from(error: GuardError) -> Self {
        match error {
            GuardError::RateLimited { retry_after_s } => {
                Self { retry_after: Some(retry_after_s.max(1)), ..Self::new(429, error.code(), "too many requests") }
            }
            GuardError::Replay => Self::new(409, error.code(), "already used"),
        }
    }
}

impl From<StoreError> for NodeError {
    fn from(error: StoreError) -> Self {
        tracing::error!(%error, "store");
        Self::unavailable()
    }
}

/// Result type of the node.
pub type NodeResult<T> = Result<T, NodeError>;
