//! Trash scanner.
//!
//! * **Linux** — XDG trash: `<Trash>/files` holds the payload and `<Trash>/info`
//!   the restore metadata; both are surfaced so emptying is complete.
//! * **macOS** — `~/.Trash` holds items directly.
//! * **Windows** — each volume's `$Recycle.Bin\<SID>` holds `$R*` payload files
//!   and paired `$I*` metadata records. Both are surfaced; the original path
//!   from the `$I` record (when readable) is used to label the matching `$R`.

use std::path::{Path, PathBuf};

use crate::model::{Category, Finding, RiskLevel, ScanReport};
use crate::platform;
use crate::scan::{dir_size, Progress, ScanOptions};

pub fn scan(opts: &ScanOptions, _progress: &dyn Progress) -> ScanReport {
    let mut report = ScanReport::default();

    for root in platform::trash_roots() {
        for dir in item_dirs(&root.path) {
            scan_dir(&dir, root.risk, &mut report);
        }
    }

    let _ = opts;
    report
}

fn scan_dir(dir: &Path, risk: RiskLevel, report: &mut ScanReport) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            // Missing or access-denied (other users' SID dirs) are expected.
            if !matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) {
                report.warnings.push(format!("{}: {}", dir.display(), e));
            }
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        // DirEntry::metadata() does not traverse symlinks.
        let Ok(meta) = entry.metadata() else { continue };

        let (size, modified, is_dir) = if meta.is_dir() {
            let (s, m) = dir_size(&path, false);
            (s, m, true)
        } else {
            (meta.len(), meta.modified().ok(), false)
        };

        report.findings.push(Finding {
            id: 0,
            category: Category::Trash,
            path: path.clone(),
            size,
            is_dir,
            risk,
            modified,
            label: label_for(&path),
            group: None,
            requires_privilege: false,
        });
    }
}

/// The directories whose entries are reclaimable for a given trash root.
#[cfg(target_os = "linux")]
fn item_dirs(root: &Path) -> Vec<PathBuf> {
    vec![root.join("files"), root.join("info")]
}

/// On Windows the trash root is `$Recycle.Bin`; its per-SID sub-directories hold
/// the actual items.
#[cfg(target_os = "windows")]
fn item_dirs(root: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(root) {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn item_dirs(root: &Path) -> Vec<PathBuf> {
    vec![root.to_path_buf()]
}

/// Build a human label for a trashed entry.
#[cfg(target_os = "windows")]
fn label_for(path: &Path) -> String {
    use crate::scan::recycle;

    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("item");
    // For a `$R` payload, the paired `$I` record carries the original path.
    if let Some(rest) = name.strip_prefix("$R") {
        let i_name = format!("$I{rest}");
        if let Some(parent) = path.parent() {
            if let Ok(bytes) = std::fs::read(parent.join(&i_name)) {
                if let Some(meta) = recycle::parse_i_file(&bytes) {
                    return format!("Recycle Bin — {}", meta.original_path);
                }
            }
        }
    }
    format!("Recycle Bin — {name}")
}

#[cfg(not(target_os = "windows"))]
fn label_for(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("item");
    format!("Trash — {name}")
}
