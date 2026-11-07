//! Core data model shared across scanners, the CLI, the TUI and the helper.

use std::path::PathBuf;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// The functional categories scour scans. Each maps to a set of allowlisted
/// roots per OS (see [`crate::platform`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Application caches, logs and temporary files owned by the user.
    Junk,
    /// Files sitting in the OS trash / recycle bin.
    Trash,
    /// Large and/or old files surfaced for manual review (never auto-selected).
    LargeFiles,
    /// Groups of byte-identical files; all but one copy are reclaimable.
    Duplicates,
}

impl Category {
    pub const ALL: [Category; 4] = [
        Category::Junk,
        Category::Trash,
        Category::LargeFiles,
        Category::Duplicates,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Junk => "junk",
            Category::Trash => "trash",
            Category::LargeFiles => "large-files",
            Category::Duplicates => "duplicates",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Category::Junk => "System junk",
            Category::Trash => "Trash",
            Category::LargeFiles => "Large & old files",
            Category::Duplicates => "Duplicates",
        }
    }
}

/// How dangerous it is to delete a finding. Drives default selection and the
/// confirmation the UI must demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    /// Safe to remove by default (regenerated caches, trashed items).
    Safe,
    /// Reclaimable but the user should glance at it (old downloads, dupes).
    Review,
    /// Never selected automatically; requires explicit per-item confirmation.
    Manual,
}

/// Stable identifier for a finding within a single report (index-based; not
/// persisted across scans).
pub type FindingId = u64;

/// A single reclaimable item discovered by a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub category: Category,
    pub path: PathBuf,
    /// Size in bytes reclaimed if this finding is removed. For a directory this
    /// is the recursive size of its contents.
    pub size: u64,
    /// Whether `path` is a directory (removed recursively) or a single file.
    pub is_dir: bool,
    pub risk: RiskLevel,
    /// Last modification time, when known. Used for age-based review.
    #[serde(with = "opt_systemtime")]
    pub modified: Option<SystemTime>,
    /// Human-facing one-line reason, e.g. "Firefox disk cache".
    pub label: String,
    /// For duplicates: the group key (content hash) so the UI can cluster them.
    pub group: Option<String>,
    /// True when deleting this path needs privileges the current user lacks;
    /// such findings are routed to the helper.
    pub requires_privilege: bool,
}

/// What a scanner returns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    /// Non-fatal problems encountered (unreadable dirs, etc.), for transparency.
    pub warnings: Vec<String>,
}

impl ScanReport {
    pub fn merge(&mut self, other: ScanReport) {
        self.findings.extend(other.findings);
        self.warnings.extend(other.warnings);
    }

    pub fn total_size(&self) -> u64 {
        self.findings.iter().map(|f| f.size).sum()
    }

    pub fn by_category(&self, cat: Category) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.category == cat)
    }

    /// Reassign stable ids after merging several scanners' output.
    pub fn renumber(&mut self) {
        for (i, f) in self.findings.iter_mut().enumerate() {
            f.id = i as FindingId;
        }
    }
}

/// A convenience summary of what a selection would reclaim.
#[derive(Debug, Clone, Copy, Default)]
pub struct Reclaimable {
    pub count: usize,
    pub bytes: u64,
}

mod opt_systemtime {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        v: &Option<SystemTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let secs = v.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs());
        s.serialize_some(&secs)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<SystemTime>, D::Error> {
        let secs: Option<u64> = Option::deserialize(d)?;
        Ok(secs.map(|s| UNIX_EPOCH + Duration::from_secs(s)))
    }
}
