//! Privilege routing for the front-end.
//!
//! Unprivileged operations run in-process via scour-core. Privileged ones are
//! batched into a single [`Request`] and executed by `scour-helperd` launched
//! elevated. We locate the helper next to our own executable (so a tampered
//! `scour-helperd` on `$PATH` can't be substituted), then elevate it with the
//! platform's standard mechanism.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

/// Build the elevation command for the current OS, wrapping the helper.
fn elevated_command(helper: &PathBuf) -> Result<Command> {
    #[cfg(target_os = "linux")]
    {
        // Prefer polkit's pkexec; fall back to sudo if pkexec is absent.
        let launcher = if which("pkexec") {
            "pkexec"
        } else if which("sudo") {
            "sudo"
        } else {
            return Err(anyhow!("neither pkexec nor sudo is available for elevation"));
        };
        let mut cmd = Command::new(launcher);
        cmd.arg(helper).arg("--exec");
        Ok(cmd)
    }

    #[cfg(target_os = "macos")]
    {
        // v1: use sudo for a terminal flow. A production build would install a
        // privileged launchd helper via SMAppService instead.
        let mut cmd = Command::new("sudo");
        cmd.arg(helper).arg("--exec");
        Ok(cmd)
    }

    #[cfg(target_os = "windows")]
    {
        // v1: run the helper directly and rely on the caller already being
        // elevated. A production build would relaunch via ShellExecute "runas".
        let mut cmd = Command::new(helper);
        cmd.arg("--exec");
        Ok(cmd)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let mut cmd = Command::new(helper);
        cmd.arg("--exec");
        Ok(cmd)
    }
}

#[cfg(target_os = "linux")]
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|p| p.join(bin).is_file())
        })
        .unwrap_or(false)
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
    let mut cmd = elevated_command(&helper)?;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("launching elevated helper {}", helper.display()))?;

    let request = Request::new(ops.to_vec(), dry_run).with_exclude(exclude);
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
    let resp: Response = serde_json::from_str(line).context("parsing helper response")?;

    if let Some(fatal) = resp.fatal {
        return Err(anyhow!("helper rejected request: {fatal}"));
    }
    Ok(resp.outcomes)
}
