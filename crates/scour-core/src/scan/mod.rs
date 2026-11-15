//! Scanners. Each scanner discovers findings for one category and is pure
//! (read-only); nothing here deletes.

pub mod dupes;
pub mod junk;
pub mod large;
pub mod recycle;
pub mod trash;

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::model::{Category, ScanReport};

/// Progress events emitted while scanning. A `Tick` is throttled at the source
/// (every few thousand entries) so sinks stay cheap.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// A category's scan has begun.
    Started(Category),
    /// Periodic update while walking: entries/bytes seen so far and the path
    /// currently under the cursor.
    Tick {
        category: Category,
        entries: u64,
        bytes: u64,
        current: Option<PathBuf>,
    },
    /// Informational note (e.g. "hashing 42 candidate files").
    Note { category: Category, message: String },
    /// A category's scan has finished.
    Finished {
        category: Category,
        findings: usize,
        bytes: u64,
    },
}

/// A sink for [`ProgressEvent`]s. Must be `Sync` because the duplicate scanner
/// hashes files in parallel with rayon and reports from worker threads.
pub trait Progress: Sync {
    fn event(&self, ev: ProgressEvent);
}

/// A no-op sink for callers that don't want progress.
pub struct NoProgress;

impl Progress for NoProgress {
    fn event(&self, _ev: ProgressEvent) {}
}

/// How many walked entries between throttled `Tick`s.
pub(crate) const TICK_EVERY: u64 = 2048;

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
/// renumbered report. No progress reporting.
pub fn scan_all(categories: &[Category], opts: &ScanOptions) -> ScanReport {
    scan_all_with_progress(categories, opts, &NoProgress)
}

/// Like [`scan_all`] but reports [`ProgressEvent`]s to `progress`.
pub fn scan_all_with_progress(
    categories: &[Category],
    opts: &ScanOptions,
    progress: &dyn Progress,
) -> ScanReport {
    use Category::*;
    let mut report = ScanReport::default();
    for &cat in categories {
        progress.event(ProgressEvent::Started(cat));
        let r = match cat {
            Junk => junk::scan(opts, progress),
            Trash => trash::scan(opts, progress),
            LargeFiles => large::scan(opts, progress),
            Duplicates => dupes::scan(opts, progress),
        };
        progress.event(ProgressEvent::Finished {
            category: cat,
            findings: r.findings.len(),
            bytes: r.total_size(),
        });
        report.merge(r);
    }
    report.renumber();
    report
}

/// Directories that the "large files" and "duplicate" walks skip entirely.
/// These hold regenerable build output, package/dependency caches, or VCS data:
/// hashing gigabytes of them would saturate the machine for no useful result
/// (caches are already covered by the junk scanner, and build output is
/// reproducible). Pruning them at the directory level keeps a whole-home scan
/// from reading tens of gigabytes.
pub(crate) fn is_heavy_dir(name: &str) -> bool {
    matches!(
        name,
        // Dependency / build output
        "node_modules"
            | "target"
            | "build"
            | "dist"
            | ".next"
            | ".nuxt"
            | ".gradle"
            | ".tox"
            // Language / tool caches
            | ".cache"
            | ".cargo"
            | ".rustup"
            | ".npm"
            | ".pnpm-store"
            | ".yarn"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".mypy_cache"
            | ".pytest_cache"
            | ".ruff_cache"
            // VCS and large app stores
            | ".git"
            | ".svn"
            | ".hg"
            | "snap"
            | ".steam"
    )
}

/// A `jwalk::WalkDir` configured for heavy content scans: it prunes
/// [`is_heavy_dir`] sub-trees up front so they are never descended into.
pub(crate) fn pruned_walk(root: &Path, follow_symlinks: bool) -> jwalk::WalkDir {
    jwalk::WalkDir::new(root)
        .follow_links(follow_symlinks)
        .skip_hidden(false)
        .process_read_dir(|_depth, _path, _state, children| {
            children.retain(|entry| match entry {
                Ok(e) => {
                    let is_dir = e.file_type().is_dir();
                    let name = e.file_name().to_string_lossy();
                    !(is_dir && is_heavy_dir(&name))
                }
                Err(_) => true,
            });
        })
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
