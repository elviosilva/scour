//! scour-core — the scanning and cleaning engine.
//!
//! This crate is engine-only: it discovers reclaimable files, groups them into
//! categories, and executes deletions through a safety-checked operation layer.
//! It contains no UI and performs no privilege elevation itself — privileged
//! deletions are described as [`ops::Operation`]s and handed to a separate
//! helper (see `scour-helperd`) over the [`ipc`] protocol.

pub mod ipc;
pub mod model;
pub mod ops;
pub mod platform;
pub mod scan;

pub use model::{Category, Finding, FindingId, Reclaimable, RiskLevel, ScanReport};
pub use ops::{Operation, OpOutcome, OpStatus};

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("path {0:?} is not inside any allowlisted root for its category")]
    PathNotAllowed(std::path::PathBuf),
    #[error("refusing to operate on a symlink: {0:?}")]
    SymlinkRejected(std::path::PathBuf),
    #[error("i/o error at {path:?}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn io_err(path: impl Into<std::path::PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}
