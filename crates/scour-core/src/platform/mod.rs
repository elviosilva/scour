//! Per-OS knowledge: where junk lives, where the trash lives, and which roots
//! are legitimate deletion targets for each [`Category`].
//!
//! The allowlist here is the single source of truth for safety. A scanner may
//! only emit findings whose paths are contained in one of these roots, and the
//! operation layer (and the privileged helper, independently) re-checks
//! containment before deleting anything. Nothing outside these roots is ever
//! removable.

use std::path::{Path, PathBuf};

use crate::model::{Category, RiskLevel};

/// A named cleanup root: a directory whose descendants are candidates for a
/// given category.
#[derive(Debug, Clone)]
pub struct CleanupRoot {
    pub path: PathBuf,
    /// Human label shown against findings under this root.
    pub label: String,
    /// Default risk for items found here.
    pub risk: RiskLevel,
    /// If true, this root normally requires elevated privileges (system-wide
    /// locations not owned by the current user).
    pub privileged: bool,
}

impl CleanupRoot {
    fn user(path: Option<PathBuf>, label: &str, risk: RiskLevel) -> Option<Self> {
        path.map(|p| CleanupRoot {
            path: p,
            label: label.to_string(),
            risk,
            privileged: false,
        })
    }
}

/// All junk roots (caches, logs, temp) for the current OS and user.
pub fn junk_roots() -> Vec<CleanupRoot> {
    let mut roots = Vec::new();
    let cache = dirs::cache_dir();

    #[cfg(target_os = "linux")]
    {
        roots.extend(CleanupRoot::user(cache.clone(), "User cache", RiskLevel::Safe));
        roots.extend(CleanupRoot::user(
            dirs::home_dir().map(|h| h.join(".local/state")),
            "Application state logs",
            RiskLevel::Review,
        ));
        roots.extend(CleanupRoot::user(
            Some(PathBuf::from("/tmp")),
            "Temporary files (/tmp)",
            RiskLevel::Review,
        ));
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir();
        roots.extend(CleanupRoot::user(
            home.as_ref().map(|h| h.join("Library/Caches")),
            "User caches",
            RiskLevel::Safe,
        ));
        roots.extend(CleanupRoot::user(
            home.as_ref().map(|h| h.join("Library/Logs")),
            "User logs",
            RiskLevel::Safe,
        ));
        // System-wide caches: present but privileged.
        roots.push(CleanupRoot {
            path: PathBuf::from("/Library/Caches"),
            label: "System caches".into(),
            risk: RiskLevel::Review,
            privileged: true,
        });
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local) = dirs::cache_dir().or_else(dirs::data_local_dir) {
            roots.push(CleanupRoot {
                path: local.join("Temp"),
                label: "User temp".into(),
                risk: RiskLevel::Safe,
                privileged: false,
            });
        }
        roots.extend(CleanupRoot::user(
            dirs::data_local_dir(),
            "Local app data caches",
            RiskLevel::Review,
        ));
    }

    // Fallback so non-tier-1 targets still get the generic cache dir.
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        roots.extend(CleanupRoot::user(cache, "User cache", RiskLevel::Safe));
    }

    let _ = cache;
    roots.retain(|r| r.path.is_absolute());
    roots
}

/// Trash / recycle-bin roots whose *contents* are reclaimable.
pub fn trash_roots() -> Vec<CleanupRoot> {
    // Explicit type: on Windows no branch pushes (the recycle bin is virtual),
    // so inference has nothing to go on.
    let mut roots: Vec<CleanupRoot> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // XDG trash spec: $XDG_DATA_HOME/Trash (default ~/.local/share/Trash).
        if let Some(data) = dirs::data_dir() {
            roots.push(CleanupRoot {
                path: data.join("Trash"),
                label: "Trash".into(),
                risk: RiskLevel::Safe,
                privileged: false,
            });
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            roots.push(CleanupRoot {
                path: home.join(".Trash"),
                label: "Trash".into(),
                risk: RiskLevel::Safe,
                privileged: false,
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        // The recycle bin is a per-volume `$Recycle.Bin` directory holding one
        // sub-directory per user SID. We add the `$Recycle.Bin` root of every
        // fixed drive that has one; the scanner walks into the SID dirs the
        // current user can access. ACLs keep other users' items unreadable.
        for letter in b'A'..=b'Z' {
            let p = PathBuf::from(format!("{}:\\$Recycle.Bin", letter as char));
            if p.is_dir() {
                roots.push(CleanupRoot {
                    path: p,
                    label: "Recycle Bin".into(),
                    risk: RiskLevel::Safe,
                    privileged: false,
                });
            }
        }
    }

    roots.retain(|r| r.path.is_absolute());
    roots
}

/// Roots under which "large & old files" scanning is allowed (the user's home
/// by default — we never surface system files for manual deletion).
pub fn large_file_roots() -> Vec<CleanupRoot> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(CleanupRoot {
            path: home,
            label: "Home".into(),
            risk: RiskLevel::Manual,
            privileged: false,
        });
    }
    roots
}

/// Default search roots for duplicate detection (home by default).
pub fn duplicate_roots() -> Vec<CleanupRoot> {
    large_file_roots()
        .into_iter()
        .map(|mut r| {
            r.risk = RiskLevel::Review;
            r
        })
        .collect()
}

/// Additional user-supplied roots from the `SCOUR_ALLOW_ROOT` environment
/// variable (platform path separator between entries). These are *opt-in* and
/// come only from the invoking user's own environment, so they extend — never
/// weaken — the allowlist: the user is explicitly naming extra directories
/// (e.g. a custom cache location) they want scour to manage. Each is treated as
/// `Review` risk and unprivileged.
pub fn extra_roots() -> Vec<CleanupRoot> {
    let Some(raw) = std::env::var_os("SCOUR_ALLOW_ROOT") else {
        return Vec::new();
    };
    std::env::split_paths(&raw)
        .filter(|p| p.is_absolute())
        .map(|p| CleanupRoot {
            path: p,
            label: "Custom root".into(),
            risk: RiskLevel::Review,
            privileged: false,
        })
        .collect()
}

/// Return the allowlisted roots governing a category's deletions.
pub fn roots_for(cat: Category) -> Vec<CleanupRoot> {
    let mut roots = match cat {
        Category::Junk => junk_roots(),
        Category::Trash => trash_roots(),
        Category::LargeFiles => large_file_roots(),
        Category::Duplicates => duplicate_roots(),
    };
    roots.extend(extra_roots());
    roots
}

/// True if `candidate` is lexically contained within `root` (after
/// normalization). Both must be absolute. This is deliberately conservative:
/// it does not resolve symlinks (callers reject symlinks separately) and
/// rejects any `..` components.
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    if !root.is_absolute() || !candidate.is_absolute() {
        return false;
    }
    if candidate.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return false;
    }
    candidate.starts_with(root)
}

/// Check a path against every allowlisted root for `cat`; returns the matching
/// root's risk/privilege if allowed.
pub fn classify(cat: Category, path: &Path) -> Option<(RiskLevel, bool)> {
    for r in roots_for(cat) {
        if is_within(&r.path, path) {
            return Some((r.risk, r.privileged));
        }
    }
    None
}
