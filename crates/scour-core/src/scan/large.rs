//! Large & old files scanner.
//!
//! Walks the home tree in parallel and surfaces individual files that are
//! either larger than `large_min_size` or older than `old_after_days`. These
//! are always [`RiskLevel::Manual`]: never auto-selected, because they are the
//! user's own data, not regenerable junk.

use crate::model::{Category, Finding, RiskLevel, ScanReport};
use crate::platform;
use crate::scan::{age_days, Progress, ProgressEvent, ScanOptions, TICK_EVERY};

pub fn scan(opts: &ScanOptions, progress: &dyn Progress) -> ScanReport {
    let mut report = ScanReport::default();
    let mut entries_seen: u64 = 0;
    let mut bytes_seen: u64 = 0;

    for root in platform::roots_for(Category::LargeFiles) {
        for entry in jwalk::WalkDir::new(&root.path)
            .follow_links(opts.follow_symlinks)
            .skip_hidden(false)
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();

            entries_seen += 1;
            if entries_seen % TICK_EVERY == 0 {
                progress.event(ProgressEvent::Tick {
                    category: Category::LargeFiles,
                    entries: entries_seen,
                    bytes: bytes_seen,
                    current: Some(path.clone()),
                });
            }

            // Skip anything that also lives under a junk/trash root — those are
            // handled by their own scanners and shouldn't double-count here.
            if is_managed_elsewhere(&path) {
                continue;
            }

            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() || meta.file_type().is_symlink() {
                continue;
            }

            let size = meta.len();
            bytes_seen += size;
            let modified = meta.modified().ok();
            let old = modified.map(|m| age_days(m) >= opts.old_after_days).unwrap_or(false);
            let big = size >= opts.large_min_size;

            if !big && !old {
                continue;
            }

            let label = match (big, old) {
                (true, true) => "Large & old file".to_string(),
                (true, false) => "Large file".to_string(),
                (false, true) => "Old file".to_string(),
                _ => unreachable!(),
            };

            report.findings.push(Finding {
                id: 0,
                category: Category::LargeFiles,
                path,
                size,
                is_dir: false,
                risk: RiskLevel::Manual,
                modified,
                label,
                group: None,
                requires_privilege: false,
            });
        }
    }

    // Biggest first — most impactful for the user to review.
    report.findings.sort_by(|a, b| b.size.cmp(&a.size));
    report
}

fn is_managed_elsewhere(path: &std::path::Path) -> bool {
    use crate::model::Category;
    platform::classify(Category::Junk, path).is_some()
        || platform::classify(Category::Trash, path).is_some()
}
