//! Integration tests for the scour engine.
//!
//! All filesystem effects are confined to a fresh `tempfile::TempDir`, made
//! visible to the allowlist via the `SCOUR_ALLOW_ROOT` env var. No real user
//! data is ever touched. Run single-threaded (`--test-threads=1`) because the
//! env var is process-global.

use std::fs;
use std::io::Write;

use scour_core::config::Config;
use scour_core::model::Category;
use scour_core::ops::{self, OpStatus, Policy};
use scour_core::scan::{self, ScanOptions};
use scour_core::{platform, Error};

fn write_file(path: &std::path::Path, bytes: &[u8]) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(bytes).unwrap();
}

/// A file inside an allowlisted (custom) root can be planned and really removed.
#[test]
fn plans_and_removes_within_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("SCOUR_ALLOW_ROOT", dir.path());

    let victim = dir.path().join("cache-blob");
    write_file(&victim, &vec![7u8; 4096]);
    assert!(victim.exists());

    let report = scan::scan_all(&[Category::Junk], &ScanOptions::default());
    let finding = report
        .findings
        .iter()
        .find(|f| f.path == victim)
        .expect("junk scan should surface the blob under the custom root");

    let op = ops::plan(finding).expect("planning a path inside the allowlist must succeed");
    let outcome = ops::execute(&op, false);
    assert_eq!(outcome.status, OpStatus::Removed);
    assert!(!victim.exists(), "file should be gone after apply");

    std::env::remove_var("SCOUR_ALLOW_ROOT");
}

/// Dry-run never deletes.
#[test]
fn dry_run_keeps_files() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("SCOUR_ALLOW_ROOT", dir.path());

    let keep = dir.path().join("keep-me");
    write_file(&keep, &vec![1u8; 2048]);

    let report = scan::scan_all(&[Category::Junk], &ScanOptions::default());
    let f = report.findings.iter().find(|f| f.path == keep).unwrap();
    let op = ops::plan(f).unwrap();
    let outcome = ops::execute(&op, true); // dry-run
    assert_eq!(outcome.status, OpStatus::Planned);
    assert!(keep.exists(), "dry-run must not delete");

    std::env::remove_var("SCOUR_ALLOW_ROOT");
}

/// The duplicate finder clusters byte-identical files and reclaims all but one.
#[test]
fn finds_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("SCOUR_ALLOW_ROOT", dir.path());

    let payload = vec![42u8; 1_500_000]; // > default dupe_min_size (1 MiB)
    write_file(&dir.path().join("a.bin"), &payload);
    write_file(&dir.path().join("b.bin"), &payload); // identical
    write_file(&dir.path().join("unique.bin"), &vec![99u8; 1_500_000]);

    let report = scan::scan_all(&[Category::Duplicates], &ScanOptions::default());
    // The scan also covers $HOME; restrict the assertion to our isolated dir.
    let dupes: Vec<_> = report
        .by_category(Category::Duplicates)
        .filter(|f| f.path.starts_with(dir.path()))
        .collect();

    assert_eq!(
        dupes.len(),
        1,
        "exactly one redundant copy should be reported for the two identical files"
    );
    assert!(dupes[0].group.is_some(), "duplicates carry a group key");
    // The surfaced copy must be one of our two identical files, not the unique one.
    assert!(dupes[0].path.ends_with("a.bin") || dupes[0].path.ends_with("b.bin"));

    std::env::remove_var("SCOUR_ALLOW_ROOT");
}

/// A path outside every allowlisted root is rejected before any fs call.
#[test]
fn rejects_paths_outside_allowlist() {
    std::env::remove_var("SCOUR_ALLOW_ROOT");
    // An absolute system path that is in no category root.
    let outside = std::path::Path::new("/etc/hostname");
    let err = ops::validate_path(Category::Junk, outside).unwrap_err();
    assert!(matches!(err, Error::PathNotAllowed(_)));
}

/// Symlinks inside an allowed root are refused (no symlink traversal).
#[cfg(unix)]
#[test]
fn rejects_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("SCOUR_ALLOW_ROOT", dir.path());

    let target = dir.path().join("real");
    write_file(&target, b"data");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let err = ops::validate_path(Category::Junk, &link).unwrap_err();
    assert!(matches!(err, Error::SymlinkRejected(_)));

    std::env::remove_var("SCOUR_ALLOW_ROOT");
}

/// A protected path (e.g. an SSH key) inside an allowed root is never deletable,
/// even though it passes the allowlist check.
#[test]
fn protects_credentials_inside_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("SCOUR_ALLOW_ROOT", dir.path());

    // Simulate ~/.ssh/id_ed25519 living under a managed root.
    let ssh = dir.path().join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    let key = ssh.join("id_ed25519");
    write_file(&key, b"PRIVATE KEY");

    // Allowlist alone would accept it...
    assert!(platform::classify(Category::Junk, &key).is_some());
    // ...but the default policy's protected set refuses it.
    let err = ops::validate_path(Category::Junk, &key).unwrap_err();
    assert!(matches!(err, Error::ProtectedPath(_)));
    assert!(key.exists(), "protected file must survive");

    std::env::remove_var("SCOUR_ALLOW_ROOT");
}

/// A user exclusion glob prevents deletion of matching files.
#[test]
fn user_exclude_prevents_deletion() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("SCOUR_ALLOW_ROOT", dir.path());

    let keep = dir.path().join("important.bin");
    write_file(&keep, &vec![5u8; 1024]);

    let (policy, warns) = Policy::with_excludes(["**/important.bin"]);
    assert!(warns.is_empty());

    let err = ops::validate_path_with(Category::Junk, &keep, &policy).unwrap_err();
    assert!(matches!(err, Error::ProtectedPath(_)));

    // Without the exclusion it would be allowed.
    assert!(ops::validate_path(Category::Junk, &keep).is_ok());

    std::env::remove_var("SCOUR_ALLOW_ROOT");
}

/// Excluding a directory (in either glob form) protects both the directory
/// itself and everything under it.
#[test]
fn directory_exclusion_covers_contents_and_self() {
    // Contents form protects a wholesale delete of the directory.
    let (p1, _) = Policy::with_excludes(["**/mozilla/**"]);
    assert!(p1.is_protected(std::path::Path::new("/home/u/.cache/mozilla")));
    assert!(p1.is_protected(std::path::Path::new("/home/u/.cache/mozilla/x/y")));

    // Directory form protects files inside via the ancestor walk.
    let (p2, _) = Policy::with_excludes(["**/mozilla"]);
    assert!(p2.is_protected(std::path::Path::new("/home/u/.cache/mozilla")));
    assert!(p2.is_protected(std::path::Path::new("/home/u/.cache/mozilla/deep/file")));

    // A sibling is not affected.
    assert!(!p2.is_protected(std::path::Path::new("/home/u/.cache/chromium")));
}

/// Config round-trips through TOML and overrides scan thresholds.
#[test]
fn config_parses_and_overrides_thresholds() {
    let toml = r#"
        allow_roots = ["/tmp/example-cache"]
        exclude = ["**/*.keepme"]

        [scan]
        large_min_size = 1234
        old_after_days = 7
        dupe_min_size = 4096
        follow_symlinks = true
    "#;
    let cfg = Config::from_toml(toml).unwrap();
    assert_eq!(cfg.allow_roots.len(), 1);
    assert_eq!(cfg.exclude, vec!["**/*.keepme".to_string()]);
    let opts = cfg.scan_options();
    assert_eq!(opts.large_min_size, 1234);
    assert_eq!(opts.old_after_days, 7);
    assert_eq!(opts.dupe_min_size, 4096);
    assert!(opts.follow_symlinks);
}

/// `is_within` rejects parent-dir escapes.
#[test]
fn containment_rejects_dotdot() {
    let root = std::path::Path::new("/home/user/.cache");
    let escape = std::path::Path::new("/home/user/.cache/../../etc/passwd");
    assert!(!platform::is_within(root, escape));
}
