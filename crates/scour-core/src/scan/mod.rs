//! Scanners. Each scanner discovers findings for one category and is pure
//! (read-only); nothing here deletes.

pub mod dupes;
pub mod junk;
pub mod large;
pub mod trash;

use std::path::Path;
use std::time::SystemTime;

use crate::model::ScanReport;

/// Options that tune the scanners.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Minimum file size (bytes) to surface in the "large files" scan.
    pub large_min_size: u64,
    /// A file is considered "old" if not modified within this many days.
    pub old_after_days: u64,
    /// Minimum size (bytes) a file must have to be considered for duplicate
    /// hashing (tiny files are rarely worth deduplicating).
    pub dupe_min_size: u64,
    /// Follow symlinks while walking. Off by default for safety.
    pub follow_symlinks: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            large_min_size: 100 * 1024 * 1024, // 100 MiB
            old_after_days: 180,
            dupe_min_size: 1024 * 1024, // 1 MiB
            follow_symlinks: false,
        }
    }
}

/// Run every scanner for the requested categories and return one merged,
/// renumbered report.
pub fn scan_all(categories: &[crate::model::Category], opts: &ScanOptions) -> ScanReport {
    use crate::model::Category::*;
    let mut report = ScanReport::default();
    for &cat in categories {
        let r = match cat {
            Junk => junk::scan(opts),
            Trash => trash::scan(opts),
            LargeFiles => large::scan(opts),
            Duplicates => dupes::scan(opts),
        };
        report.merge(r);
    }
    report.renumber();
    report
}

/// Recursively sum the size of a directory's regular files, skipping symlinks.
/// Returns `(bytes, newest_mtime)`.
pub(crate) fn dir_size(path: &Path, follow_symlinks: bool) -> (u64, Option<SystemTime>) {
    let mut total = 0u64;
    let mut newest: Option<SystemTime> = None;
    for entry in jwalk::WalkDir::new(path)
        .follow_links(follow_symlinks)
        .skip_hidden(false)
    {
        let Ok(entry) = entry else { continue };
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_file() {
            total += meta.len();
            if let Ok(m) = meta.modified() {
                newest = Some(newest.map_or(m, |n| n.max(m)));
            }
        }
    }
    (total, newest)
}

/// Age in days of a mtime relative to now (saturating at 0).
pub(crate) fn age_days(modified: SystemTime) -> u64 {
    SystemTime::now()
        .duration_since(modified)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}
