//! scour-gui — a native desktop front-end for the scour disk cleaner, built on
//! egui/eframe.
//!
//! The window shows a category sidebar, a checkable list of findings, and a
//! bottom bar with the selection total and Scan / Clean actions. Scanning runs
//! on a background thread and streams progress back over a channel so the UI
//! stays responsive. Cleaning removes unprivileged items in-process; items that
//! need elevation are reported and left for `scour clean --apply` (which routes
//! them through the privileged helper), mirroring the TUI.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;
use std::thread;

use eframe::egui;
use humansize::{format_size, BINARY};

use scour_core::config::Config;
use scour_core::model::{Category, FindingId, RiskLevel, ScanReport};
use scour_core::ops::{self, OpStatus, Policy};
use scour_core::scan::{self, Progress, ProgressEvent};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 620.0])
            .with_min_inner_size([640.0, 420.0])
            .with_title("scour"),
        ..Default::default()
    };
    eframe::run_native(
        "scour",
        options,
        Box::new(|_cc| Ok(Box::new(ScourApp::new()))),
    )
}

/// Messages streamed from the background scan thread to the UI.
enum Msg {
    Progress(ProgressEvent),
    Done(ScanReport),
}

/// A [`Progress`] sink that forwards events to the UI thread and wakes it.
struct ChannelProgress {
    tx: Mutex<Sender<Msg>>,
    ctx: egui::Context,
}

impl Progress for ChannelProgress {
    fn event(&self, ev: ProgressEvent) {
        if let Ok(tx) = self.tx.lock() {
            let _ = tx.send(Msg::Progress(ev));
        }
        self.ctx.request_repaint();
    }
}

#[derive(Default)]
struct ScanStatus {
    category: Option<Category>,
    entries: u64,
    bytes: u64,
    current: Option<PathBuf>,
}

struct ScourApp {
    config: Config,
    report: ScanReport,
    selected: BTreeSet<FindingId>,
    focused: Category,
    scanning: bool,
    rx: Option<Receiver<Msg>>,
    status: String,
    scan_status: ScanStatus,
}

impl ScourApp {
    fn new() -> Self {
        let config = Config::load_default().unwrap_or_default();
        apply_allow_roots(&config);
        Self {
            config,
            report: ScanReport::default(),
            selected: BTreeSet::new(),
            focused: Category::Junk,
            scanning: false,
            rx: None,
            status: "Ready. Click Scan to begin.".into(),
            scan_status: ScanStatus::default(),
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.selected.clear();
        self.report = ScanReport::default();
        self.scan_status = ScanStatus::default();
        self.status = "Scanning…".into();

        let (tx, rx) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        let opts = self.config.scan_options();
        let ctx = ctx.clone();

        thread::spawn(move || {
            let sink = ChannelProgress {
                tx: Mutex::new(tx.clone()),
                ctx,
            };
            let report = scan::scan_all_with_progress(&Category::ALL, &opts, &sink);
            let _ = tx.send(Msg::Done(report));
        });
    }

    fn drain_messages(&mut self) {
        let Some(rx) = &self.rx else { return };
        // Collect first to avoid holding a borrow of self.rx while mutating self.
        let mut done = None;
        let mut last_tick = None;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                Msg::Progress(ProgressEvent::Tick {
                    category,
                    entries,
                    bytes,
                    current,
                }) => {
                    last_tick = Some(ScanStatus {
                        category: Some(category),
                        entries,
                        bytes,
                        current,
                    });
                }
                Msg::Progress(ProgressEvent::Started(cat)) => {
                    self.scan_status.category = Some(cat);
                }
                Msg::Progress(ProgressEvent::Note { .. })
                | Msg::Progress(ProgressEvent::Finished { .. }) => {}
                Msg::Done(report) => done = Some(report),
            }
        }
        if let Some(tick) = last_tick {
            self.scan_status = tick;
        }
        if let Some(report) = done {
            self.report = report;
            self.scanning = false;
            self.rx = None;
            self.status = format!(
                "Scan complete: {} reclaimable across {} items.",
                format_size(self.report.total_size(), BINARY),
                self.report.findings.len()
            );
        }
    }

    fn selected_bytes(&self) -> u64 {
        self.report
            .findings
            .iter()
            .filter(|f| self.selected.contains(&f.id))
            .map(|f| f.size)
            .sum()
    }

    fn select_all_safe_in_focus(&mut self) {
        let ids: Vec<FindingId> = self
            .report
            .by_category(self.focused)
            .filter(|f| f.risk == RiskLevel::Safe)
            .map(|f| f.id)
            .collect();
        for id in ids {
            self.selected.insert(id);
        }
    }

    fn clean_selection(&mut self) {
        let chosen: Vec<_> = self
            .report
            .findings
            .iter()
            .filter(|f| self.selected.contains(&f.id))
            .cloned()
            .collect();
        if chosen.is_empty() {
            self.status = "Nothing selected.".into();
            return;
        }

        let (policy, _warnings) = Policy::with_excludes(&self.config.exclude);
        let mut reclaimed = 0u64;
        let mut removed = 0usize;
        let mut failed = 0usize;
        let mut deferred = 0usize;
        let mut done_ids = BTreeSet::new();

        for f in &chosen {
            match ops::plan_with(f, &policy) {
                Ok(op) if op.privileged => deferred += 1,
                Ok(op) => match ops::execute_with(&op, false, &policy).status {
                    OpStatus::Removed => {
                        reclaimed += f.size;
                        removed += 1;
                        done_ids.insert(f.id);
                    }
                    OpStatus::Planned => {}
                    OpStatus::Failed | OpStatus::Rejected => failed += 1,
                },
                Err(_) => failed += 1,
            }
        }

        self.report.findings.retain(|f| !done_ids.contains(&f.id));
        self.selected.retain(|id| !done_ids.contains(id));

        self.status = format!(
            "Reclaimed {} ({removed} removed{}{}).",
            format_size(reclaimed, BINARY),
            if failed > 0 {
                format!(", {failed} failed")
            } else {
                String::new()
            },
            if deferred > 0 {
                format!(", {deferred} need `scour clean --apply` for privileges")
            } else {
                String::new()
            }
        );
    }
}

impl eframe::App for ScourApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_messages();

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("scour");
                ui.separator();
                let scan_label = if self.scanning { "Scanning…" } else { "Scan" };
                if ui
                    .add_enabled(!self.scanning, egui::Button::new(scan_label))
                    .clicked()
                {
                    self.start_scan(ctx);
                }
                if ui
                    .add_enabled(
                        !self.scanning && !self.selected.is_empty(),
                        egui::Button::new("Clean selection"),
                    )
                    .clicked()
                {
                    self.clean_selection();
                }
                if ui
                    .add_enabled(!self.scanning, egui::Button::new("Select safe"))
                    .clicked()
                {
                    self.select_all_safe_in_focus();
                }
            });
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(2.0);
            if self.scanning {
                ui.horizontal(|ui| {
                    ui.spinner();
                    let where_ = self
                        .scan_status
                        .current
                        .as_deref()
                        .and_then(|p| p.to_str())
                        .unwrap_or("");
                    ui.label(format!(
                        "Scanning {}… {} entries, {} — {}",
                        self.scan_status
                            .category
                            .map(|c| c.title())
                            .unwrap_or("…"),
                        self.scan_status.entries,
                        format_size(self.scan_status.bytes, BINARY),
                        shorten(where_, 70),
                    ));
                });
            } else {
                ui.label(&self.status);
            }
            ui.add_space(2.0);
        });

        egui::SidePanel::left("categories")
            .resizable(false)
            .exact_width(220.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Categories").strong());
                ui.separator();
                for cat in Category::ALL {
                    let total: u64 = self.report.by_category(cat).map(|f| f.size).sum();
                    let count = self.report.by_category(cat).count();
                    let text = format!("{}  ({}, {})", cat.title(), count, format_size(total, BINARY));
                    if ui
                        .selectable_label(self.focused == cat, text)
                        .clicked()
                    {
                        self.focused = cat;
                    }
                }
                ui.separator();
                let sel = self.selected.len();
                ui.label(format!(
                    "Selected: {sel} items\n{}",
                    format_size(self.selected_bytes(), BINARY)
                ));
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);
            ui.label(egui::RichText::new(self.focused.title()).heading());
            ui.label(
                egui::RichText::new(
                    "Yellow = review · Red = manual (your own files; never auto-selected)",
                )
                .small()
                .weak(),
            );
            ui.separator();

            // Snapshot the focused findings' ids so we don't borrow self.report
            // while mutating self.selected inside the loop.
            let rows: Vec<(FindingId, u64, bool, RiskLevel, String)> = self
                .report
                .by_category(self.focused)
                .map(|f| {
                    (
                        f.id,
                        f.size,
                        f.requires_privilege,
                        f.risk,
                        f.path.display().to_string(),
                    )
                })
                .collect();

            if rows.is_empty() {
                ui.add_space(12.0);
                ui.weak("No findings in this category. Click Scan to (re)scan.");
                return;
            }

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (id, size, privileged, risk, path) in rows {
                    ui.horizontal(|ui| {
                        let mut checked = self.selected.contains(&id);
                        if ui.checkbox(&mut checked, "").changed() {
                            if checked {
                                self.selected.insert(id);
                            } else {
                                self.selected.remove(&id);
                            }
                        }
                        ui.monospace(format!("{:>10}", format_size(size, BINARY)));
                        let mut label = egui::RichText::new(path);
                        label = match risk {
                            RiskLevel::Safe => label,
                            RiskLevel::Review => label.color(egui::Color32::from_rgb(200, 170, 0)),
                            RiskLevel::Manual => label.color(egui::Color32::from_rgb(210, 80, 80)),
                        };
                        ui.label(label);
                        if privileged {
                            ui.label(
                                egui::RichText::new("[needs privileges]")
                                    .small()
                                    .weak(),
                            );
                        }
                    });
                }
            });
        });
    }
}

/// Merge config `allow_roots` into `SCOUR_ALLOW_ROOT`, as the CLI does.
fn apply_allow_roots(config: &Config) {
    if config.allow_roots.is_empty() {
        return;
    }
    let mut paths: Vec<PathBuf> = config.allow_roots.clone();
    if let Some(existing) = std::env::var_os("SCOUR_ALLOW_ROOT") {
        paths.extend(std::env::split_paths(&existing));
    }
    if let Ok(joined) = std::env::join_paths(paths) {
        std::env::set_var("SCOUR_ALLOW_ROOT", joined);
    }
}

/// Shorten a long string with a middle ellipsis for the status line.
fn shorten(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let head = keep / 2;
    let tail = keep - head;
    let front: String = chars[..head].iter().collect();
    let back: String = chars[chars.len() - tail..].iter().collect();
    format!("{front}…{back}")
}
