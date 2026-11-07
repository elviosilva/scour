//! Deletion policy: a compiled set of glob patterns whose matches must never be
//! removed, no matter which category or allowlisted root they fall under.
//!
//! The policy is the union of a hard-coded **protected set** (credentials,
//! keys, wallets, keychains — things a "cleaner" must never touch) and optional
//! user-supplied exclusions. Because exclusions only ever *prevent* deletions,
//! accepting them from an untrusted caller (e.g. over IPC into the privileged
//! helper) cannot widen what gets deleted.

use std::path::Path;

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};

/// Patterns always protected, matched case-insensitively against the absolute
/// path with gitignore-style separators (`*` does not cross `/`, `**` does).
pub const PROTECTED: &[&str] = &[
    // SSH / private keys
    "**/.ssh/**",
    "**/.ssh",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "**/*.pem",
    // GPG
    "**/.gnupg/**",
    "**/.gnupg",
    // Password managers & secret stores
    "**/.password-store/**",
    "**/*.kdbx",
    "**/.config/gh/hosts.yml",
    // Cloud / infra credentials
    "**/.aws/**",
    "**/.kube/config",
    "**/.docker/config.json",
    // Crypto wallets
    "**/wallet.dat",
    "**/.electrum/**",
    "**/.bitcoin/wallet*",
    "**/.ethereum/keystore/**",
    // macOS keychains
    "**/Keychains/**",
    "**/*.keychain",
    "**/*.keychain-db",
    // Windows credential/DPAPI stores
    "**/Microsoft/Credentials/**",
    "**/Microsoft/Protect/**",
];

/// A compiled deletion policy.
#[derive(Clone)]
pub struct Policy {
    set: GlobSet,
}

impl Policy {
    /// The built-in protected set only.
    pub fn protected_only() -> Self {
        Self::build(std::iter::empty()).expect("built-in protected globs are valid")
    }

    /// Built-in protected set plus `user_excludes`. Invalid user patterns are
    /// skipped rather than failing the whole policy (a bad glob must not
    /// silently disable protection), and reported via the returned warnings.
    pub fn with_excludes<I, S>(user_excludes: I) -> (Self, Vec<String>)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut warnings = Vec::new();
        let mut valid = Vec::new();
        for pat in user_excludes {
            let pat = pat.as_ref().to_string();
            match Glob::new(&pat) {
                Ok(_) => valid.push(pat),
                Err(e) => warnings.push(format!("ignoring invalid exclude {pat:?}: {e}")),
            }
        }
        let policy = Self::build(valid.into_iter())
            .unwrap_or_else(|_| Self::protected_only());
        (policy, warnings)
    }

    fn build<I: Iterator<Item = String>>(extra: I) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for pat in PROTECTED.iter().map(|s| s.to_string()).chain(extra) {
            // Protect both the named path and its contents, whichever form the
            // pattern was written in, so excluding a directory also blocks a
            // wholesale delete of that directory (which would destroy the
            // protected contents).
            for expanded in expand(&pat) {
                let glob: Glob = GlobBuilder::new(&expanded)
                    .literal_separator(true)
                    .case_insensitive(true)
                    .build()?;
                builder.add(glob);
            }
        }
        Ok(Self {
            set: builder.build()?,
        })
    }

    /// True if `path`, or any of its ancestors, must be protected from
    /// deletion. The ancestor walk means protecting a directory protects
    /// everything under it, even when only the directory form was listed.
    pub fn is_protected(&self, path: &Path) -> bool {
        if self.set.is_match(path) {
            return true;
        }
        path.ancestors().skip(1).any(|a| self.set.is_match(a))
    }
}

/// Expand one pattern into the set of forms that protect both a directory and
/// its contents. `"**/foo/**"` -> `["**/foo/**", "**/foo"]`; `"**/foo"` ->
/// `["**/foo", "**/foo/**"]`. Patterns already ending in a wildcard segment
/// other than `/**` (e.g. `**/*.pem`) are returned as-is.
fn expand(pattern: &str) -> Vec<String> {
    if let Some(stripped) = pattern.strip_suffix("/**") {
        vec![pattern.to_string(), stripped.to_string()]
    } else if pattern.ends_with('*') {
        vec![pattern.to_string()]
    } else {
        vec![pattern.to_string(), format!("{pattern}/**")]
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::protected_only()
    }
}
