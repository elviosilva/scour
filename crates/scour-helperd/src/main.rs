//! scour-helperd — the minimal privileged helper.
//!
//! It is intended to be launched elevated (e.g. `pkexec scour-helperd` on
//! Linux) by the unprivileged front-end. It does exactly one thing: read a
//! single JSON [`Request`] from stdin, re-validate and perform each deletion,
//! and write a single JSON [`Response`] to stdout.
//!
//! Trust model: the helper trusts nothing from the request. Every path is
//! re-checked against scour-core's allowlist with the same `validate_path`
//! used unprivileged, so elevation cannot be abused to delete arbitrary paths
//! — the request can only ask for deletions the policy already permits.

use std::io::{Read, Write};
use std::process::ExitCode;

use scour_core::ipc::{Request, Response, PROTOCOL_VERSION};
use scour_core::ops;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("scour-helperd protocol {PROTOCOL_VERSION}");
        return ExitCode::SUCCESS;
    }
    // The front-end passes `--exec` to request the stdin/stdout exchange. We
    // refuse to run interactively so an accidental invocation does nothing.
    if !args.iter().any(|a| a == "--exec") {
        eprintln!("scour-helperd is launched by scour; run with --exec to process a request on stdin");
        return ExitCode::FAILURE;
    }

    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        return emit(Response::fatal(format!("failed to read request: {e}")));
    }

    let req: Request = match serde_json::from_str(input.trim()) {
        Ok(r) => r,
        Err(e) => return emit(Response::fatal(format!("malformed request: {e}"))),
    };

    if req.version != PROTOCOL_VERSION {
        return emit(Response::fatal(format!(
            "protocol mismatch: helper={PROTOCOL_VERSION} request={}",
            req.version
        )));
    }

    // Execute each operation. `ops::execute` re-validates internally, so even a
    // tampered request cannot escape the allowlist.
    let outcomes = ops::execute_batch(&req.operations, req.dry_run);

    emit(Response {
        version: PROTOCOL_VERSION,
        outcomes,
        fatal: None,
    })
}

fn emit(resp: Response) -> ExitCode {
    let line = match resp.to_line() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to serialize response: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut out = std::io::stdout();
    if out.write_all(line.as_bytes()).is_err() || out.flush().is_err() {
        return ExitCode::FAILURE;
    }
    if resp.fatal.is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
