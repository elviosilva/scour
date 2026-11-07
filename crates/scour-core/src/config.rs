//! User configuration, loaded from `scour.toml`.
//!
//! Config only ever tightens or tunes behaviour: it can lower/raise scan
//! thresholds, add extra directories to manage, and add exclusion globs. It can
//! never remove the built-in protected patterns (see [`crate::ops::policy`]).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::scan::ScanOptions;

/// Deserialized `scour.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub scan: ScanConfig,
    /// Extra absolute directories to treat as managed roots (same effect as
    /// `SCOUR_ALLOW_ROOT`, but persistent).
    pub allow_roots: Vec<PathBuf>,
    /// Glob patterns (matched against absolute paths) that must never be
    /// deleted, in addition to the built-in protected set.
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub large_min_size: u64,
    pub old_after_days: u64,
    pub dupe_min_size: u64,
    pub follow_symlinks: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        let d = ScanOptions::default();
        Self {
            large_min_size: d.large_min_size,
            old_after_days: d.old_after_days,
            dupe_min_size: d.dupe_min_size,
            follow_symlinks: d.follow_symlinks,
        }
    }
}

impl Config {
    /// Parse config from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Load config from an explicit path.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| crate::io_err(path, e))?;
        Self::from_toml(&text).map_err(|e| crate::Error::Other(format!("{}: {e}", path.display())))
    }

    /// The conventional config location: `<config_dir>/scour/scour.toml`.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("scour").join("scour.toml"))
    }

    /// Load from the default path if it exists, else return defaults.
    pub fn load_default() -> crate::Result<Self> {
        match Self::default_path() {
            Some(p) if p.exists() => Self::load(&p),
            _ => Ok(Self::default()),
        }
    }

    pub fn scan_options(&self) -> ScanOptions {
        ScanOptions {
            large_min_size: self.scan.large_min_size,
            old_after_days: self.scan.old_after_days,
            dupe_min_size: self.scan.dupe_min_size,
            follow_symlinks: self.scan.follow_symlinks,
        }
    }
}
