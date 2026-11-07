//! Trash scanner.
//!
//! On Linux and macOS the trash is a real directory tree whose contents we
//! enumerate directly. On Windows the recycle bin is virtual; for v1 we leave
//! Windows trash enumeration to a follow-up (it needs the Shell API or the
//! `trash` crate's listing support) and emit nothing rather than guess.

use crate::model::{Category, Finding, ScanReport};
use crate::platform;
use crate::scan::{dir_size, ScanOptions};

pub fn scan(opts: &ScanOptions) -> ScanReport {
    let mut report = ScanReport::default();

    for root in platform::trash_roots() {
        // On Linux the deletable payload lives in `<Trash>/files`; `info/` holds
        // restore metadata. We surface both so emptying is complete.
        let targets = linux_trash_subdirs(&root.path);

        for dir in targets {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        report.warnings.push(format!("{}: {}", dir.display(), e));
                    }
                    continue;
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

                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("item")
                    .to_string();

                report.findings.push(Finding {
                    id: 0,
                    category: Category::Trash,
                    path,
                    size,
                    is_dir,
                    risk: root.risk,
                    modified,
                    label: format!("Trash — {name}"),
                    group: None,
                    requires_privilege: false,
                });
            }
        }
    }

    let _ = opts;
    report
}

#[cfg(target_os = "linux")]
fn linux_trash_subdirs(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    vec![root.join("files"), root.join("info")]
}

#[cfg(not(target_os = "linux"))]
fn linux_trash_subdirs(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    // macOS ~/.Trash holds items directly.
    vec![root.to_path_buf()]
}
