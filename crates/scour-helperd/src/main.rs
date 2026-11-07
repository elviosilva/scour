//! scour-helperd — the minimal privileged helper.
//!
//! Launched elevated by the unprivileged front-end. It does exactly one thing:
//! read a single JSON [`Request`], re-validate and perform each deletion, and
//! write a single JSON [`Response`].
//!
//! Two transports are supported, chosen by the launcher:
//!   * `--exec` — read the request from stdin, write the response to stdout.
//!     Used on Linux where `pkexec`/`sudo` preserve the pipes.
//!   * `--request-file <in> --response-file <out>` — read/write files. Used on
//!     macOS (`osascript ... with administrator privileges`) and Windows
//!     (`runas`/UAC), where elevation crosses a session boundary and stdin/
//!     stdout cannot be piped to the elevated process.
//!
//! Trust model: the helper trusts nothing from the request. Every path is
//! re-checked against scour-core's allowlist and protected set, so elevation
//! cannot be abused to delete arbitrary paths — the request can only ask for
//! deletions the policy already permits.

use std::io::{Read, Write};
use std::process::ExitCode;

use scour_core::ipc::{Request, Response, PROTOCOL_VERSION};
use scour_core::ops::{self, Policy};

enum Transport {
    Stdio,
    Files { request: String, response: String },
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("scour-helperd protocol {PROTOCOL_VERSION}");
        return ExitCode::SUCCESS;
    }

    let transport = match parse_transport(&args) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
    };

    // Read the raw request from the chosen transport.
    let raw = match &transport {
        Transport::Stdio => {
            let mut s = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut s) {
                return finish(&transport, Response::fatal(format!("failed to read request: {e}")));
            }
            s
        }
        Transport::Files { request, .. } => match std::fs::read_to_string(request) {
            Ok(s) => s,
            Err(e) => {
                return finish(
                    &transport,
                    Response::fatal(format!("failed to read request file {request}: {e}")),
                )
            }
        },
    };

    let req: Request = match serde_json::from_str(raw.trim()) {
        Ok(r) => r,
        Err(e) => return finish(&transport, Response::fatal(format!("malformed request: {e}"))),
    };

    if req.version != PROTOCOL_VERSION {
        return finish(
            &transport,
            Response::fatal(format!(
                "protocol mismatch: helper={PROTOCOL_VERSION} request={}",
                req.version
            )),
        );
    }

    // The built-in protected set is always applied; caller-supplied excludes can
    // only add further protection, never remove it.
    let (policy, _warnings) = Policy::with_excludes(&req.exclude);

    // `execute_with` re-validates internally, so even a tampered request cannot
    // escape the allowlist or the protected set.
    let outcomes = ops::execute_batch_with(&req.operations, req.dry_run, &policy);

    finish(
        &transport,
        Response {
            version: PROTOCOL_VERSION,
            outcomes,
            fatal: None,
        },
    )
}

fn parse_transport(args: &[String]) -> Result<Transport, String> {
    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let request = flag("--request-file");
    let response = flag("--response-file");
    match (request, response) {
        (Some(request), Some(response)) => Ok(Transport::Files { request, response }),
        (Some(_), None) | (None, Some(_)) => {
            Err("--request-file and --response-file must be given together".into())
        }
        (None, None) if args.iter().any(|a| a == "--exec") => Ok(Transport::Stdio),
        (None, None) => Err(
            "scour-helperd is launched by scour; use --exec (stdin/stdout) or \
             --request-file/--response-file"
                .into(),
        ),
    }
}

/// Deliver the response over the transport and map it to an exit code.
fn finish(transport: &Transport, resp: Response) -> ExitCode {
    let line = match resp.to_line() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to serialize response: {e}");
            return ExitCode::FAILURE;
        }
    };

    let write_result = match transport {
        Transport::Stdio => (|| {
            let mut out = std::io::stdout();
            out.write_all(line.as_bytes())?;
            out.flush()
        })(),
        Transport::Files { response, .. } => write_response_file(response, &line),
    };

    if write_result.is_err() {
        eprintln!("failed to deliver response");
        return ExitCode::FAILURE;
    }
    if resp.fatal.is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Write the response file with owner-only permissions where the platform
/// supports it.
fn write_response_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
