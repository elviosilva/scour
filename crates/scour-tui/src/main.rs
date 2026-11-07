//! Thin binary wrapper so `scour-tui` can be launched directly; it scans every
//! category and hands the report to the shared UI.

use anyhow::Result;
use scour_core::scan::{self, ScanOptions};

fn main() -> Result<()> {
    let report = scan::scan_all(&scour_core::model::Category::ALL, &ScanOptions::default());
    scour_tui::run(report)
}
