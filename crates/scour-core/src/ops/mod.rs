//! The operation layer: turns a selection of [`Finding`]s into safety-checked
//! [`Operation`]s and executes the unprivileged ones in-process. Privileged
//! operations are serialized and handed to the helper via [`crate::ipc`].
//!
//! Safety invariants enforced here (and independently re-checked by the
//! helper):
//!   * every target path must be contained in an allowlisted root for its
//!     category (see [`crate::platform`]);
//!   * symlinks are never followed or deleted;
//!   * `..` components are rejected;
//!   * nothing happens in dry-run mode.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::{Category, Finding};
use crate::{platform, Error, Result};

/// A single vetted deletion. Constructing one does not perform it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub category: Category,
    pub path: PathBuf,
    pub is_dir: bool,
    /// True if this op must run under the privileged helper.
    pub privileged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpStatus {
    Removed,
    /// Reported in dry-run: would have been removed.
    Planned,
    Failed,
    /// Rejected by a safety check before any filesystem call.
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpOutcome {
    pub path: PathBuf,
    pub status: OpStatus,
    /// Bytes reclaimed (0 unless actually removed).
    pub bytes: u64,
    pub message: Option<String>,
}

/// Validate a finding and, if it passes, build an [`Operation`]. This is the
/// only sanctioned way to turn a finding into an operation.
pub fn plan(finding: &Finding) -> Result<Operation> {
    validate_path(finding.category, &finding.path)?;
    Ok(Operation {
        category: finding.category,
        path: finding.path.clone(),
        is_dir: finding.is_dir,
        privileged: finding.requires_privilege,
    })
}

/// Re-run every safety check for a path/category pair. Used both when planning
/// and, crucially, inside the helper before it deletes as root.
pub fn validate_path(cat: Category, path: &std::path::Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::PathNotAllowed(path.to_path_buf()));
    }
    // Reject symlinks outright (symlink_metadata does not follow).
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::SymlinkRejected(path.to_path_buf()));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Already gone — treat as allowed; executor will no-op.
        }
        Err(e) => return Err(crate::io_err(path, e)),
    }
    if platform::classify(cat, path).is_none() {
        return Err(Error::PathNotAllowed(path.to_path_buf()));
    }
    Ok(())
}

/// Size of what an operation would reclaim (recomputed at execution time so the
/// reported figure reflects reality, not a stale scan).
fn current_size(op: &Operation) -> u64 {
    if op.is_dir {
        crate::scan::dir_size(&op.path, false).0
    } else {
        std::fs::symlink_metadata(&op.path).map(|m| m.len()).unwrap_or(0)
    }
}

/// Execute one operation in-process. Returns an outcome; never panics.
/// With `dry_run`, performs all checks but no deletion.
pub fn execute(op: &Operation, dry_run: bool) -> OpOutcome {
    if let Err(e) = validate_path(op.category, &op.path) {
        return OpOutcome {
            path: op.path.clone(),
            status: OpStatus::Rejected,
            bytes: 0,
            message: Some(e.to_string()),
        };
    }

    let bytes = current_size(op);

    if dry_run {
        return OpOutcome {
            path: op.path.clone(),
            status: OpStatus::Planned,
            bytes,
            message: None,
        };
    }

    let result = if op.is_dir {
        std::fs::remove_dir_all(&op.path)
    } else {
        std::fs::remove_file(&op.path)
    };

    match result {
        Ok(()) => OpOutcome {
            path: op.path.clone(),
            status: OpStatus::Removed,
            bytes,
            message: None,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => OpOutcome {
            path: op.path.clone(),
            status: OpStatus::Removed,
            bytes: 0,
            message: Some("already gone".into()),
        },
        Err(e) => OpOutcome {
            path: op.path.clone(),
            status: OpStatus::Failed,
            bytes: 0,
            message: Some(e.to_string()),
        },
    }
}

/// Execute a batch in-process, returning per-op outcomes. Privileged ops are
/// *not* elevated here — callers must route `op.privileged` operations to the
/// helper. This function executes them anyway (they will simply fail with a
/// permission error if the caller lacks rights), which keeps single-user,
/// already-root invocations working.
pub fn execute_batch(ops: &[Operation], dry_run: bool) -> Vec<OpOutcome> {
    ops.iter().map(|op| execute(op, dry_run)).collect()
}
