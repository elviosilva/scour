//! Junk scanner: enumerates the top-level entries under each junk root (caches,
//! logs, temp) and emits one finding per entry with its recursive size.
//!
//! We emit at the first level below each root rather than per-file so the user
//! reasons about "Firefox cache" instead of thousands of individual blobs.

use crate::model::{Category, Finding, ScanReport};
use crate::platform;
use crate::scan::{dir_size, ScanOptions};

pub fn scan(opts: &ScanOptions) -> ScanReport {
    let mut report = ScanReport::default();

    for root in platform::roots_for(Category::Junk) {
        let entries = match std::fs::read_dir(&root.path) {
            Ok(e) => e,
            Err(e) => {
                // Missing roots are normal; only warn on real access errors.
                if e.kind() != std::io::ErrorKind::NotFound {
                    report
                        .warnings
                        .push(format!("{}: {}", root.path.display(), e));
                }
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };

            // Never descend into or delete symlinks from junk roots.
            if meta.file_type().is_symlink() {
                continue;
            }

            let (size, modified, is_dir) = if meta.is_dir() {
                let (s, m) = dir_size(&path, opts.follow_symlinks);
                (s, m, true)
            } else {
                (meta.len(), meta.modified().ok(), false)
            };

            if size == 0 {
                continue;
            }

            let label = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => format!("{} — {}", root.label, name),
                None => root.label.clone(),
            };

            report.findings.push(Finding {
                id: 0,
                category: Category::Junk,
                path,
                size,
                is_dir,
                risk: root.risk,
                modified,
                label,
                group: None,
                requires_privilege: root.privileged,
            });
        }
    }

    report
}
