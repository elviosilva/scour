//! IPC protocol between the unprivileged front-end and the privileged helper.
//!
//! Transport for v1 is a single request/response exchange over the helper's
//! stdin/stdout as newline-delimited JSON. The front-end spawns the helper
//! elevated (pkexec on Linux; see `scour-helperd`), writes one [`Request`],
//! then reads one [`Response`].
//!
//! The protocol is deliberately tiny and declarative: the helper receives a
//! list of operations, re-validates each one against the same allowlist the
//! front-end used (defense in depth — the helper trusts nothing from the
//! caller), performs the deletions, and reports per-op outcomes. The helper
//! never receives or executes arbitrary commands.

use serde::{Deserialize, Serialize};

use crate::ops::{OpOutcome, Operation};

/// Protocol version; the helper refuses mismatched majors.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    /// Operations to perform. The helper independently re-validates each.
    pub operations: Vec<Operation>,
    /// If true the helper reports what it would do without deleting.
    pub dry_run: bool,
}

impl Request {
    pub fn new(operations: Vec<Operation>, dry_run: bool) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            operations,
            dry_run,
        }
    }

    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        Ok(format!("{}\n", serde_json::to_string(self)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub version: u32,
    pub outcomes: Vec<OpOutcome>,
    /// Set if the whole request was rejected before any op ran.
    pub fatal: Option<String>,
}

impl Response {
    pub fn fatal(msg: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            outcomes: Vec::new(),
            fatal: Some(msg.into()),
        }
    }

    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        Ok(format!("{}\n", serde_json::to_string(self)?))
    }
}
