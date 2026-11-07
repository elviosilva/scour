//! Thin binary wrapper so `scour-tui` can be launched directly; it scans every
//! category and hands the report to the shared interactive UI.

use std::process::ExitCode;

use scour_core::scan::{self, ScanOptions};

const USAGE: &str = "\
scour-tui — interactive terminal UI for the scour disk cleaner

USAGE:
    scour-tui [--version] [--help]

Scans every category, then opens the interactive UI. Requires a terminal;
for scripting use the `scour` CLI instead (`scour scan`, `scour clean`).";

fn main() -> ExitCode {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("scour-tui {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("scour-tui: unexpected argument {other:?}\n\n{USAGE}");
                return ExitCode::FAILURE;
            }
        }
    }

    let report = scan::scan_all(&scour_core::model::Category::ALL, &ScanOptions::default());
    match scour_tui::run(report) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("scour-tui: {e}");
            ExitCode::FAILURE
        }
    }
}
