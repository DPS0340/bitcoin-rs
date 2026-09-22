//! Error types shared by the e2e harness.

use std::fmt;
use std::path::PathBuf;

/// Anything that can go wrong while driving a node process end-to-end.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure (spawn, socket, file).
    Io(std::io::Error),
    /// JSON encode/decode failure.
    Json(serde_json::Error),
    /// RPC returned a structured error reply.
    Rpc {
        /// Method that was called.
        method: String,
        /// JSON-RPC error code.
        code: i64,
        /// Server-side message.
        message: String,
    },
    /// The child exited before it became ready or while still owned.
    ChildExit {
        /// Process id.
        pid: u32,
        /// Exit status observed.
        status: std::process::ExitStatus,
        /// Directory holding captured output.
        evidence: PathBuf,
    },
    /// A deadline expired while waiting for a condition.
    Timeout {
        /// What was being awaited.
        operation: &'static str,
        /// Last observed state, for debugging.
        detail: String,
    },
    /// A test-level assertion or protocol assumption failed.
    Assertion(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io: {error}"),
            Self::Json(error) => write!(f, "json: {error}"),
            Self::Rpc {
                method,
                code,
                message,
            } => write!(f, "rpc {method} rejected ({code}): {message}"),
            Self::ChildExit {
                pid,
                status,
                evidence,
            } => write!(
                f,
                "child {pid} exited early ({status}); evidence {}",
                evidence.display()
            ),
            Self::Timeout { operation, detail } => {
                write!(f, "timeout waiting for {operation}: {detail}")
            }
            Self::Assertion(detail) => write!(f, "assertion: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Convenience result alias used by every harness call.
pub type Result<T> = std::result::Result<T, Error>;

/// Extension helpers for JSON values returned by the node.
pub trait ValueExt {
    /// Required object field.
    fn field(&self, key: &str) -> Result<&serde_json::Value>;
    /// Required string field.
    fn str_field(&self, key: &str) -> Result<&str>;
    /// Required unsigned integer field.
    fn u64_field(&self, key: &str) -> Result<u64>;
    /// Required array field.
    fn array_field(&self, key: &str) -> Result<&Vec<serde_json::Value>>;
}

impl ValueExt for serde_json::Value {
    fn field(&self, key: &str) -> Result<&serde_json::Value> {
        self.get(key)
            .ok_or_else(|| Error::Assertion(format!("missing field {key} in {self}")))
    }

    fn str_field(&self, key: &str) -> Result<&str> {
        self.field(key)?
            .as_str()
            .ok_or_else(|| Error::Assertion(format!("field {key} is not a string in {self}")))
    }

    fn u64_field(&self, key: &str) -> Result<u64> {
        self.field(key)?.as_u64().ok_or_else(|| {
            Error::Assertion(format!("field {key} is not an unsigned integer in {self}"))
        })
    }

    fn array_field(&self, key: &str) -> Result<&Vec<serde_json::Value>> {
        self.field(key)?
            .as_array()
            .ok_or_else(|| Error::Assertion(format!("field {key} is not an array in {self}")))
    }
}
