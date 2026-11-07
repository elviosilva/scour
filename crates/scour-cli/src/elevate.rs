//! Privilege routing for the front-end.
//!
//! Unprivileged operations run in-process via scour-core. Privileged ones are
//! batched into a single [`Request`] and executed by `scour-helperd` launched
//! elevated. The helper is located next to our own executable (so a tampered
//! `scour-helperd` on `$PATH` can't be substituted), then elevated with the
//! platform's standard mechanism:
//!
//!   * **Linux** — `pkexec` (polkit), falling back to `sudo`; the request is
//!     piped over stdin and the response read from stdout.
//!   * **macOS** — `osascript`'s `do shell script … with administrator
//!     privileges`, which raises the native auth dialog. Elevation crosses a
//!     session boundary, so the request/response travel through files in a
//!     private temp directory rather than pipes.
//!   * **Windows** — `Start-Process -Verb RunAs` (UAC); again file-based.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use scour_core::ipc::{Request, Response};
use scour_core::ops::{OpOutcome, Operation};

/// Find `scour-helperd` next to the current executable.
fn helper_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolving current executable")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("executable has no parent directory"))?;
    let name = if cfg!(windows) {
        "scour-helperd.exe"
    } else {
        "scour-helperd"
    };
    let candidate = dir.join(name);
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(anyhow!(
            "privileged helper not found next to {} (looked for {})",
            exe.display(),
            candidate.display()
        ))
    }
}

/// Run a batch of privileged operations through the elevated helper. `exclude`
/// carries the user's exclusion globs so the root helper honors them too.
pub fn run_privileged(
    ops: &[Operation],
    dry_run: bool,
    exclude: Vec<String>,
) -> Result<Vec<OpOutcome>> {
    if ops.is_empty() {
        return Ok(Vec::new());
    }
    let helper = helper_path()?;
    let request = Request::new(ops.to_vec(), dry_run).with_exclude(exclude);

    #[cfg(target_os = "linux")]
    {
        run_via_pipe(&helper, &request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        run_via_files(&helper, &request)
    }
}

// ---------------------------------------------------------------------------
// Linux: pkexec/sudo with stdin/stdout pipes.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn run_via_pipe(helper: &Path, request: &Request) -> Result<Vec<OpOutcome>> {
    use std::process::Stdio;

    let launcher = if which("pkexec") {
        "pkexec"
    } else if which("sudo") {
        "sudo"
    } else {
        return Err(anyhow!("neither pkexec nor sudo is available for elevation"));
    };

    let mut child = Command::new(launcher)
        .arg(helper)
        .arg("--exec")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("launching {launcher} {}", helper.display()))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to open helper stdin"))?;
        stdin
            .write_all(request.to_line()?.as_bytes())
            .context("writing request to helper")?;
    }

    let output = child.wait_with_output().context("waiting for helper")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .next()
        .ok_or_else(|| anyhow!("helper produced no response"))?;
    parse_response(line)
}

#[cfg(target_os = "linux")]
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|p| p.join(bin).is_file()))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// macOS / Windows: file-based transport across the elevation boundary.
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn run_via_files(helper: &Path, request: &Request) -> Result<Vec<OpOutcome>> {
    let workdir = PrivateTempDir::new().context("creating private temp directory")?;
    let req_path = workdir.path.join("request.json");
    let resp_path = workdir.path.join("response.json");

    write_private(&req_path, request.to_line()?.as_bytes())
        .context("writing request file")?;

    let mut cmd = elevated_file_command(helper, &req_path, &resp_path)?;
    let status = cmd
        .status()
        .with_context(|| format!("launching elevated helper {}", helper.display()))?;

    if !resp_path.exists() {
        return Err(anyhow!(
            "elevation did not produce a response (helper exit: {status}); \
             the request may have been cancelled at the authentication prompt"
        ));
    }
    let body = std::fs::read_to_string(&resp_path).context("reading response file")?;
    let line = body
        .lines()
        .next()
        .ok_or_else(|| anyhow!("helper produced an empty response"))?;
    parse_response(line)
    // `workdir` is removed when it drops.
}

#[cfg(target_os = "macos")]
fn elevated_file_command(helper: &Path, req: &Path, resp: &Path) -> Result<Command> {
    // Build the /bin/sh command line the admin shell will run, then wrap it in
    // an AppleScript string for `do shell script`.
    let shell_cmd = format!(
        "{} --request-file {} --response-file {}",
        quote::shell_single_quote(&helper.to_string_lossy()),
        quote::shell_single_quote(&req.to_string_lossy()),
        quote::shell_single_quote(&resp.to_string_lossy()),
    );
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        quote::applescript_escape(&shell_cmd)
    );
    let mut cmd = Command::new("osascript");
    cmd.arg("-e").arg(script);
    Ok(cmd)
}

#[cfg(target_os = "windows")]
fn elevated_file_command(helper: &Path, req: &Path, resp: &Path) -> Result<Command> {
    // Start-Process -Verb RunAs triggers UAC; -Wait blocks until the elevated
    // helper exits, after which we read the response file it wrote.
    let ps = format!(
        "Start-Process -FilePath {} -ArgumentList {},{},{},{} -Verb RunAs -Wait",
        quote::ps_single_quote(&helper.to_string_lossy()),
        quote::ps_single_quote("--request-file"),
        quote::ps_single_quote(&req.to_string_lossy()),
        quote::ps_single_quote("--response-file"),
        quote::ps_single_quote(&resp.to_string_lossy()),
    );
    let mut cmd = Command::new("powershell");
    cmd.arg("-NoProfile").arg("-NonInteractive").arg("-Command").arg(ps);
    Ok(cmd)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn elevated_file_command(helper: &Path, req: &Path, resp: &Path) -> Result<Command> {
    // No known elevation mechanism: run the helper directly (succeeds only if
    // already privileged).
    let mut cmd = Command::new(helper);
    cmd.arg("--request-file").arg(req).arg("--response-file").arg(resp);
    Ok(cmd)
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

fn parse_response(line: &str) -> Result<Vec<OpOutcome>> {
    let resp: Response = serde_json::from_str(line).context("parsing helper response")?;
    if let Some(fatal) = resp.fatal {
        return Err(anyhow!("helper rejected request: {fatal}"));
    }
    Ok(resp.outcomes)
}

/// Write a file readable/writable only by the owner (best effort on non-unix).
#[cfg(not(target_os = "linux"))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = std::fs::File::create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    Ok(())
}

/// A uniquely-named temp directory with owner-only permissions, removed on drop.
#[cfg(not(target_os = "linux"))]
struct PrivateTempDir {
    path: PathBuf,
}

#[cfg(not(target_os = "linux"))]
impl PrivateTempDir {
    fn new() -> std::io::Result<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let base = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = base.join(format!("scour-{}-{}", std::process::id(), nonce));
        std::fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { path })
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Argument-quoting for the elevation launchers. Compiled on every platform
/// (and tested there) even though each function is only *used* on one OS, so
/// the escaping logic — the part most prone to subtle bugs with spaces and
/// quotes in paths — is exercised by the test suite regardless of host.
mod quote {
    /// Quote a string for a POSIX `/bin/sh` single-quoted argument.
    #[allow(dead_code)]
    pub fn shell_single_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }

    /// Escape a string for an AppleScript double-quoted literal.
    #[allow(dead_code)]
    pub fn applescript_escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    /// Quote a string for a PowerShell single-quoted literal (double the quotes).
    #[allow(dead_code)]
    pub fn ps_single_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "''"))
    }
}

#[cfg(test)]
mod tests {
    use super::quote::*;

    #[test]
    fn shell_quote_wraps_and_escapes() {
        assert_eq!(shell_single_quote("/tmp/x"), "'/tmp/x'");
        assert_eq!(shell_single_quote("/a b/c"), "'/a b/c'");
        // An embedded single quote is closed, escaped, and reopened.
        assert_eq!(shell_single_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn applescript_escapes_backslash_and_quote() {
        assert_eq!(applescript_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(applescript_escape(r"a\b"), r"a\\b");
        // Order matters: a backslash before a quote must not double-escape.
        assert_eq!(applescript_escape(r#"\""#), r#"\\\""#);
    }

    #[test]
    fn powershell_doubles_single_quotes() {
        assert_eq!(ps_single_quote(r"C:\Program Files\x"), r"'C:\Program Files\x'");
        assert_eq!(ps_single_quote("O'Brien"), "'O''Brien'");
    }
}
