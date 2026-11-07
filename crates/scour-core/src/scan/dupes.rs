//! Duplicate finder.
//!
//! Three-stage pipeline to keep hashing cheap:
//!   1. Group candidate files by size (different sizes can't be identical).
//!   2. Within each size group, hash a small head sample to split obvious
//!      non-matches apart.
//!   3. Within each surviving group, hash the full file (BLAKE3) in parallel.
//!
//! For each group of identical files we keep the oldest copy as the "original"
//! and emit every other copy as a reclaimable finding.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::time::SystemTime;

use rayon::prelude::*;

use crate::model::{Category, Finding, RiskLevel, ScanReport};
use crate::platform;
use crate::scan::ScanOptions;

const HEAD_SAMPLE: usize = 16 * 1024;

struct Candidate {
    path: PathBuf,
    size: u64,
    modified: Option<SystemTime>,
}

pub fn scan(opts: &ScanOptions) -> ScanReport {
    let mut report = ScanReport::default();

    // 1. Collect candidates grouped by size.
    let mut by_size: HashMap<u64, Vec<Candidate>> = HashMap::new();
    for root in platform::roots_for(Category::Duplicates) {
        for entry in jwalk::WalkDir::new(&root.path)
            .follow_links(opts.follow_symlinks)
            .skip_hidden(false)
        {
            let Ok(entry) = entry else { continue };
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() || meta.file_type().is_symlink() {
                continue;
            }
            let size = meta.len();
            if size < opts.dupe_min_size {
                continue;
            }
            by_size.entry(size).or_default().push(Candidate {
                path: entry.path(),
                size,
                modified: meta.modified().ok(),
            });
        }
    }

    // Keep only sizes with more than one file.
    let size_groups: Vec<Vec<Candidate>> =
        by_size.into_values().filter(|v| v.len() > 1).collect();

    // 2 + 3. Refine each size group by head sample, then full hash.
    for group in size_groups {
        let mut by_head: HashMap<[u8; 32], Vec<Candidate>> = HashMap::new();
        for c in group {
            match head_hash(&c.path) {
                Ok(h) => by_head.entry(h).or_default().push(c),
                Err(e) => report.warnings.push(format!("{}: {}", c.path.display(), e)),
            }
        }

        for head_group in by_head.into_values().filter(|v| v.len() > 1) {
            // Full-hash in parallel.
            let hashed: Vec<(Candidate, [u8; 32])> = head_group
                .into_par_iter()
                .filter_map(|c| full_hash(&c.path).ok().map(|h| (c, h)))
                .collect();

            let mut by_full: HashMap<[u8; 32], Vec<Candidate>> = HashMap::new();
            for (c, h) in hashed {
                by_full.entry(h).or_default().push(c);
            }

            for (hash, mut dup_group) in by_full {
                if dup_group.len() < 2 {
                    continue;
                }
                // Keep the oldest as original; reclaim the rest.
                dup_group.sort_by_key(|c| c.modified.unwrap_or(SystemTime::UNIX_EPOCH));
                let group_key = hex32(&hash);
                for c in dup_group.into_iter().skip(1) {
                    report.findings.push(Finding {
                        id: 0,
                        category: Category::Duplicates,
                        path: c.path,
                        size: c.size,
                        is_dir: false,
                        risk: RiskLevel::Review,
                        modified: c.modified,
                        label: "Duplicate copy".into(),
                        group: Some(group_key.clone()),
                        requires_privilege: false,
                    });
                }
            }
        }
    }

    report.findings.sort_by(|a, b| b.size.cmp(&a.size));
    report
}

fn head_hash(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; HEAD_SAMPLE];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(*blake3::hash(&buf).as_bytes())
}

fn full_hash(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
