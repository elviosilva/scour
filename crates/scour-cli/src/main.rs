//! scour — cross-platform disk cleaner (CLI front-end).

mod elevate;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use humansize::{format_size, BINARY};

use scour_core::config::Config;
use scour_core::model::{Category, Finding, RiskLevel, ScanReport};
use scour_core::ops::{self, OpStatus, Policy};
use scour_core::scan;

#[derive(Parser)]
#[command(name = "scour", version, about = "Cross-platform disk cleaner")]
struct Cli {
    /// Path to a scour.toml config (defaults to <config-dir>/scour/scour.toml).
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for reclaimable files and print a report (never deletes).
    Scan {
        /// Categories to scan (default: all).
        #[arg(value_enum)]
        categories: Vec<CatArg>,
        /// Emit the full report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove reclaimable files. Dry-run unless --apply is given.
    Clean {
        #[arg(value_enum)]
        categories: Vec<CatArg>,
        /// Actually delete (otherwise only shows what would be removed).
        #[arg(long)]
        apply: bool,
        /// Also act on Review-risk findings (old files, duplicates).
        #[arg(long)]
        include_review: bool,
        /// Also act on Manual-risk findings (large/old personal files).
        /// Dangerous; off unless explicitly requested.
        #[arg(long)]
        include_manual: bool,
        /// Skip the confirmation prompt when applying.
        #[arg(long)]
        yes: bool,
    },
    /// Launch the interactive terminal UI.
    Tui {
        #[arg(value_enum)]
        categories: Vec<CatArg>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum CatArg {
    Junk,
    Trash,
    LargeFiles,
    Duplicates,
}

impl From<CatArg> for Category {
    fn from(c: CatArg) -> Self {
        match c {
            CatArg::Junk => Category::Junk,
            CatArg::Trash => Category::Trash,
            CatArg::LargeFiles => Category::LargeFiles,
            CatArg::Duplicates => Category::Duplicates,
        }
    }
}

fn resolve_categories(args: &[CatArg]) -> Vec<Category> {
    if args.is_empty() {
        Category::ALL.to_vec()
    } else {
        args.iter().copied().map(Category::from).collect()
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Load config (explicit path, else conventional default, else built-in
    // defaults) and apply its custom roots to the environment the scanners read.
    let config = match &cli.config {
        Some(p) => Config::load(p)?,
        None => Config::load_default()?,
    };
    apply_allow_roots(&config);

    match cli.command {
        Commands::Scan { categories, json } => {
            cmd_scan(&resolve_categories(&categories), json, &config)
        }
        Commands::Clean {
            categories,
            apply,
            include_review,
            include_manual,
            yes,
        } => cmd_clean(
            &resolve_categories(&categories),
            apply,
            include_review,
            include_manual,
            yes,
            &config,
        ),
        Commands::Tui { categories } => {
            let report = scan::scan_all(&resolve_categories(&categories), &config.scan_options());
            scour_tui::run(report)?;
            Ok(())
        }
    }
}

/// Merge config `allow_roots` into `SCOUR_ALLOW_ROOT` so `platform::extra_roots`
/// (the single mechanism for custom roots) picks them up.
fn apply_allow_roots(config: &Config) {
    if config.allow_roots.is_empty() {
        return;
    }
    let mut paths: Vec<std::path::PathBuf> = config.allow_roots.clone();
    if let Some(existing) = std::env::var_os("SCOUR_ALLOW_ROOT") {
        paths.extend(std::env::split_paths(&existing));
    }
    if let Ok(joined) = std::env::join_paths(paths) {
        std::env::set_var("SCOUR_ALLOW_ROOT", joined);
    }
}

fn cmd_scan(categories: &[Category], json: bool, config: &Config) -> Result<()> {
    let report = scan::scan_all(categories, &config.scan_options());

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    print_report(&report);
    Ok(())
}

fn print_report(report: &ScanReport) {
    for cat in Category::ALL {
        let items: Vec<&Finding> = report.by_category(cat).collect();
        if items.is_empty() {
            continue;
        }
        let total: u64 = items.iter().map(|f| f.size).sum();
        println!(
            "\n{} — {} items, {}",
            cat.title(),
            items.len(),
            format_size(total, BINARY)
        );
        for f in items.iter().take(15) {
            println!(
                "  [{}] {:>10}  {}",
                risk_tag(f.risk),
                format_size(f.size, BINARY),
                f.path.display()
            );
        }
        if items.len() > 15 {
            println!("  … {} more", items.len() - 15);
        }
    }

    println!(
        "\nTotal reclaimable: {} across {} items",
        format_size(report.total_size(), BINARY),
        report.findings.len()
    );
    if !report.warnings.is_empty() {
        println!("\n{} warning(s):", report.warnings.len());
        for w in report.warnings.iter().take(10) {
            println!("  ! {w}");
        }
    }
}

fn risk_tag(r: RiskLevel) -> &'static str {
    match r {
        RiskLevel::Safe => "safe  ",
        RiskLevel::Review => "review",
        RiskLevel::Manual => "manual",
    }
}

fn cmd_clean(
    categories: &[Category],
    apply: bool,
    include_review: bool,
    include_manual: bool,
    yes: bool,
    config: &Config,
) -> Result<()> {
    let report = scan::scan_all(categories, &config.scan_options());

    // Build the deletion policy from the user's exclusions (built-in protected
    // paths are always included).
    let (policy, warnings) = Policy::with_excludes(&config.exclude);
    for w in &warnings {
        eprintln!("config: {w}");
    }

    // Select findings by risk policy.
    let selected: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| match f.risk {
            RiskLevel::Safe => true,
            RiskLevel::Review => include_review,
            RiskLevel::Manual => include_manual,
        })
        .collect();

    if selected.is_empty() {
        println!("Nothing selected. (Safe items only by default; use --include-review / --include-manual.)");
        return Ok(());
    }

    // Plan & split by privilege.
    let mut local = Vec::new();
    let mut privileged = Vec::new();
    let mut rejected = 0usize;
    for f in &selected {
        match ops::plan_with(f, &policy) {
            Ok(op) if op.privileged => privileged.push(op),
            Ok(op) => local.push(op),
            Err(_) => rejected += 1,
        }
    }

    let total_bytes: u64 = selected.iter().map(|f| f.size).sum();
    println!(
        "Selected {} items ({}). {} local, {} privileged{}.",
        selected.len(),
        format_size(total_bytes, BINARY),
        local.len(),
        privileged.len(),
        if rejected > 0 {
            format!(", {rejected} rejected by safety checks")
        } else {
            String::new()
        }
    );

    let dry_run = !apply;
    if dry_run {
        println!("\nDRY RUN — nothing will be deleted. Re-run with --apply to act.\n");
    } else if !yes && !confirm(selected.len(), total_bytes)? {
        println!("Aborted.");
        return Ok(());
    }

    let mut reclaimed = 0u64;
    let mut removed = 0usize;
    let mut failed = 0usize;

    for outcome in ops::execute_batch_with(&local, dry_run, &policy) {
        tally(&outcome, &mut reclaimed, &mut removed, &mut failed);
    }

    if !privileged.is_empty() {
        match elevate::run_privileged(&privileged, dry_run, config.exclude.clone()) {
            Ok(outcomes) => {
                for outcome in outcomes {
                    tally(&outcome, &mut reclaimed, &mut removed, &mut failed);
                }
            }
            Err(e) => {
                eprintln!("privileged batch failed: {e:#}");
                failed += privileged.len();
            }
        }
    }

    let verb = if dry_run { "Would reclaim" } else { "Reclaimed" };
    println!(
        "\n{verb} {} ({} items{}).",
        format_size(reclaimed, BINARY),
        removed,
        if failed > 0 {
            format!(", {failed} failed")
        } else {
            String::new()
        }
    );
    Ok(())
}

fn tally(outcome: &ops::OpOutcome, reclaimed: &mut u64, removed: &mut usize, failed: &mut usize) {
    match outcome.status {
        OpStatus::Removed | OpStatus::Planned => {
            *reclaimed += outcome.bytes;
            *removed += 1;
        }
        OpStatus::Failed | OpStatus::Rejected => {
            *failed += 1;
            if let Some(msg) = &outcome.message {
                eprintln!("  ! {}: {}", outcome.path.display(), msg);
            }
        }
    }
}

fn confirm(count: usize, bytes: u64) -> Result<bool> {
    use std::io::Write;
    print!(
        "Delete {count} items ({})? This cannot be undone. [y/N] ",
        format_size(bytes, BINARY)
    );
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}
