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

use eframe::egui::{Color32, Margin, RichText, Rounding, Stroke};
use scour_core::config::Config;
use scour_core::model::{Category, FindingId, RiskLevel, ScanReport};
use scour_core::ops::{self, OpStatus, Policy};
use scour_core::scan::{self, Progress, ProgressEvent};

/// Colour palette — a calm dark theme with a teal "clean" accent.
mod palette {
    use eframe::egui::Color32;
    pub const BG: Color32 = Color32::from_rgb(0x15, 0x17, 0x1C); // window / central
    pub const PANEL: Color32 = Color32::from_rgb(0x1B, 0x1E, 0x24); // side/top panels
    pub const CARD: Color32 = Color32::from_rgb(0x22, 0x26, 0x2E); // list / cards
    pub const CARD_HOVER: Color32 = Color32::from_rgb(0x2A, 0x2F, 0x39);
    pub const STROKE: Color32 = Color32::from_rgb(0x30, 0x36, 0x41);
    pub const INK: Color32 = Color32::from_rgb(0xE7, 0xE9, 0xEC); // primary text
    pub const MUTED: Color32 = Color32::from_rgb(0x97, 0xA0, 0xAD); // secondary text
    pub const ACCENT: Color32 = Color32::from_rgb(0x2D, 0xD4, 0xBF); // teal
    pub const ON_ACCENT: Color32 = Color32::from_rgb(0x08, 0x1A, 0x18); // text on accent
    pub const REVIEW: Color32 = Color32::from_rgb(0xEA, 0xB3, 0x08); // amber
    pub const MANUAL: Color32 = Color32::from_rgb(0xEF, 0x6B, 0x6B); // red
    pub const BLUE: Color32 = Color32::from_rgb(0x60, 0xA5, 0xFA);
    pub const PURPLE: Color32 = Color32::from_rgb(0xA7, 0x8B, 0xFA);
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 660.0])
            .with_min_inner_size([680.0, 440.0])
            .with_title("scour"),
        ..Default::default()
    };
    eframe::run_native(
        "scour",
        options,
        Box::new(|cc| {
            install_theme(&cc.egui_ctx);
            Ok(Box::new(ScourApp::new()))
        }),
    )
}

/// Apply the custom dark theme: colours, rounding and spacing.
fn install_theme(ctx: &egui::Context) {
    use palette::*;
    let mut style = (*ctx.style()).clone();
    let v = &mut style.visuals;

    v.dark_mode = true;
    v.panel_fill = PANEL;
    v.window_fill = PANEL;
    v.extreme_bg_color = BG;
    v.faint_bg_color = CARD;
    v.override_text_color = Some(INK);
    v.hyperlink_color = ACCENT;
    v.window_rounding = Rounding::same(12.0);
    v.window_stroke = Stroke::new(1.0_f32, STROKE);
    v.selection.bg_fill = ACCENT.linear_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);

    let rounding = Rounding::same(7.0);
    v.widgets.noninteractive.bg_fill = PANEL;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, MUTED);

    v.widgets.inactive.bg_fill = CARD;
    v.widgets.inactive.weak_bg_fill = CARD;
    v.widgets.inactive.rounding = rounding;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, INK);
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, STROKE);

    v.widgets.hovered.bg_fill = CARD_HOVER;
    v.widgets.hovered.weak_bg_fill = CARD_HOVER;
    v.widgets.hovered.rounding = rounding;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT.linear_multiply(0.6));
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, INK);

    v.widgets.active.bg_fill = ACCENT;
    v.widgets.active.weak_bg_fill = ACCENT;
    v.widgets.active.rounding = rounding;
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, ON_ACCENT);

    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.window_margin = Margin::same(14.0);
    style.spacing.scroll.bar_width = 10.0;

    ctx.set_style(style);
}

/// Accent-filled primary button. Returns true when clicked (and enabled).
fn primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    let text = RichText::new(label).color(palette::ON_ACCENT).strong();
    let btn = egui::Button::new(text)
        .fill(palette::ACCENT)
        .rounding(Rounding::same(7.0));
    ui.add_enabled(enabled, btn).clicked()
}

/// A small coloured dot used in the category list.
fn dot(cat: Category) -> RichText {
    let c = match cat {
        Category::Junk => palette::ACCENT,
        Category::Trash => palette::BLUE,
        Category::LargeFiles => palette::REVIEW,
        Category::Duplicates => palette::PURPLE,
    };
    RichText::new("●").color(c)
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
    confirm_clean: bool,
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
            confirm_clean: false,
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
        if self.scanning {
            // Animate at ~10 fps while scanning instead of an uncapped repaint
            // loop that would peg a core on its own.
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        self.top_bar(ctx);
        self.status_bar(ctx);
        self.sidebar(ctx);
        self.central(ctx);
        self.confirm_modal(ctx);
    }
}

impl ScourApp {
    fn top_bar(&mut self, ctx: &egui::Context) {
        let frame = egui::Frame::none()
            .fill(palette::PANEL)
            .inner_margin(Margin::symmetric(16.0, 12.0));
        egui::TopBottomPanel::top("top")
            .frame(frame)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("scour").size(24.0).strong().color(palette::ACCENT));
                    ui.label(RichText::new("disk cleaner").color(palette::MUTED));

                    // Right-aligned reclaimable total.
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if !self.report.findings.is_empty() {
                            ui.vertical(|ui| {
                                ui.with_layout(
                                    egui::Layout::top_down(egui::Align::Max),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format_size(
                                                self.report.total_size(),
                                                BINARY,
                                            ))
                                            .size(20.0)
                                            .strong()
                                            .color(palette::INK),
                                        );
                                        ui.label(
                                            RichText::new("reclaimable")
                                                .small()
                                                .color(palette::MUTED),
                                        );
                                    },
                                );
                            });
                        }
                    });
                });

                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    let scan_label = if self.scanning { "Scanning…" } else { "Scan" };
                    if primary_button(ui, scan_label, !self.scanning) {
                        self.start_scan(ctx);
                    }
                    if ui
                        .add_enabled(
                            !self.scanning && !self.report.findings.is_empty(),
                            egui::Button::new("Select safe"),
                        )
                        .clicked()
                    {
                        self.select_all_safe_in_focus();
                    }
                    if ui
                        .add_enabled(!self.selected.is_empty(), egui::Button::new("Clear"))
                        .clicked()
                    {
                        self.selected.clear();
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let can_clean = !self.scanning && !self.selected.is_empty();
                        let label =
                            format!("Clean {} selected", self.selected.len());
                        if primary_button(ui, &label, can_clean) {
                            self.confirm_clean = true;
                        }
                    });
                });

                if self.scanning {
                    ui.add_space(8.0);
                    let t = ui.input(|i| i.time) as f32;
                    let frac = 0.5 + 0.45 * (t * 1.6).sin();
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .fill(palette::ACCENT)
                            .desired_height(6.0)
                            .animate(true),
                    );
                }
            });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        let frame = egui::Frame::none()
            .fill(palette::PANEL)
            .inner_margin(Margin::symmetric(16.0, 8.0));
        egui::TopBottomPanel::bottom("status")
            .frame(frame)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.scanning {
                        ui.spinner();
                        let where_ = self
                            .scan_status
                            .current
                            .as_deref()
                            .and_then(|p| p.to_str())
                            .unwrap_or("");
                        ui.label(
                            RichText::new(format!(
                                "Scanning {}… {} entries, {} — {}",
                                self.scan_status.category.map(|c| c.title()).unwrap_or("…"),
                                self.scan_status.entries,
                                format_size(self.scan_status.bytes, BINARY),
                                shorten(where_, 64),
                            ))
                            .color(palette::MUTED),
                        );
                    } else {
                        ui.label(RichText::new("●").color(palette::ACCENT).small());
                        ui.label(RichText::new(&self.status).color(palette::MUTED));
                    }
                });
            });
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        let frame = egui::Frame::none()
            .fill(palette::PANEL)
            .inner_margin(Margin::same(12.0));
        egui::SidePanel::left("categories")
            .resizable(false)
            .exact_width(236.0)
            .frame(frame)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("CATEGORIES")
                        .small()
                        .strong()
                        .color(palette::MUTED),
                );
                ui.add_space(6.0);

                for cat in Category::ALL {
                    let total: u64 = self.report.by_category(cat).map(|f| f.size).sum();
                    let count = self.report.by_category(cat).count();
                    let selected = self.focused == cat;

                    let fill = if selected { palette::CARD } else { palette::PANEL };
                    let stroke = if selected {
                        Stroke::new(1.0_f32, palette::ACCENT)
                    } else {
                        Stroke::new(1.0_f32, palette::STROKE)
                    };
                    let resp = egui::Frame::none()
                        .fill(fill)
                        .stroke(stroke)
                        .rounding(Rounding::same(8.0))
                        .inner_margin(Margin::symmetric(10.0, 8.0))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(dot(cat));
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(cat.title()).strong().color(palette::INK));
                                    ui.label(
                                        RichText::new(format!(
                                            "{count} items · {}",
                                            format_size(total, BINARY)
                                        ))
                                        .small()
                                        .color(palette::MUTED),
                                    );
                                });
                            });
                        })
                        .response;
                    if resp.interact(egui::Sense::click()).clicked() {
                        self.focused = cat;
                    }
                    ui.add_space(6.0);
                }

                ui.add_space(4.0);
                egui::Frame::none()
                    .fill(palette::CARD)
                    .rounding(Rounding::same(8.0))
                    .inner_margin(Margin::same(10.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new("SELECTED").small().strong().color(palette::MUTED));
                        ui.label(
                            RichText::new(format_size(self.selected_bytes(), BINARY))
                                .size(18.0)
                                .strong()
                                .color(palette::ACCENT),
                        );
                        ui.label(
                            RichText::new(format!("{} items", self.selected.len()))
                                .small()
                                .color(palette::MUTED),
                        );
                    });
            });
    }

    fn central(&mut self, ctx: &egui::Context) {
        let frame = egui::Frame::none()
            .fill(palette::BG)
            .inner_margin(Margin::same(16.0));
        egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(self.focused.title()).size(18.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    legend_chip(ui, "manual", palette::MANUAL);
                    legend_chip(ui, "review", palette::REVIEW);
                    legend_chip(ui, "safe", palette::ACCENT);
                });
            });
            ui.add_space(8.0);

            // Indices of findings in the focused category — cheap to rebuild
            // each frame (no per-frame string allocation), unlike cloning every
            // path. Paths are formatted only for the rows actually visible.
            let indices: Vec<usize> = self
                .report
                .findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.category == self.focused)
                .map(|(i, _)| i)
                .collect();

            if indices.is_empty() {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("Nothing here yet")
                            .size(16.0)
                            .color(palette::MUTED),
                    );
                    ui.label(
                        RichText::new("Click Scan to look for reclaimable files.")
                            .small()
                            .color(palette::MUTED),
                    );
                });
                return;
            }

            let row_height = 28.0;
            egui::Frame::none()
                .fill(palette::CARD)
                .rounding(Rounding::same(10.0))
                .inner_margin(Margin::same(6.0))
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    // Virtualized: only the visible rows are built each frame, so
                    // a list of tens of thousands of findings stays smooth.
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show_rows(ui, row_height, indices.len(), |ui, range| {
                            for vi in range {
                                let f = &self.report.findings[indices[vi]];
                                let id = f.id;
                                let size = f.size;
                                let privileged = f.requires_privilege;
                                let risk = f.risk;
                                let path = f.path.display().to_string();

                                let row_fill = if vi % 2 == 0 {
                                    palette::CARD
                                } else {
                                    palette::CARD_HOVER.linear_multiply(0.5)
                                };
                                egui::Frame::none()
                                    .fill(row_fill)
                                    .inner_margin(Margin::symmetric(8.0, 5.0))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            let mut checked = self.selected.contains(&id);
                                            if ui.checkbox(&mut checked, "").changed() {
                                                if checked {
                                                    self.selected.insert(id);
                                                } else {
                                                    self.selected.remove(&id);
                                                }
                                            }
                                            ui.add_space(2.0);
                                            ui.monospace(
                                                RichText::new(format!(
                                                    "{:>10}",
                                                    format_size(size, BINARY)
                                                ))
                                                .color(palette::INK),
                                            );
                                            ui.add_space(6.0);
                                            ui.label(
                                                RichText::new(path).color(risk_color(risk)),
                                            );
                                            if privileged {
                                                ui.with_layout(
                                                    egui::Layout::right_to_left(
                                                        egui::Align::Center,
                                                    ),
                                                    |ui| {
                                                        pill(ui, "needs privileges", palette::MUTED);
                                                    },
                                                );
                                            }
                                        });
                                    });
                            }
                        });
                });
        });
    }

    fn confirm_modal(&mut self, ctx: &egui::Context) {
        if !self.confirm_clean {
            return;
        }
        let count = self.selected.len();
        let bytes = self.selected_bytes();
        let mut close = false;
        let mut do_clean = false;

        egui::Window::new("Confirm cleanup")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.set_width(360.0);
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!(
                        "Delete {count} item(s), freeing {}?",
                        format_size(bytes, BINARY)
                    ))
                    .size(15.0)
                    .strong(),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "This permanently removes the selected files. Protected paths \
                         (keys, wallets, credentials) are always skipped. Items needing \
                         system privileges are left for `scour clean --apply`.",
                    )
                    .small()
                    .color(palette::MUTED),
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let btn = egui::Button::new(
                            RichText::new("Delete").color(Color32::WHITE).strong(),
                        )
                        .fill(palette::MANUAL)
                        .rounding(Rounding::same(7.0));
                        if ui.add(btn).clicked() {
                            do_clean = true;
                        }
                    });
                });
                ui.add_space(2.0);
            });

        if do_clean {
            self.clean_selection();
            self.confirm_clean = false;
        } else if close {
            self.confirm_clean = false;
        }
    }
}

fn risk_color(risk: RiskLevel) -> Color32 {
    match risk {
        RiskLevel::Safe => palette::INK,
        RiskLevel::Review => palette::REVIEW,
        RiskLevel::Manual => palette::MANUAL,
    }
}

/// A small coloured legend chip: "● label".
fn legend_chip(ui: &mut egui::Ui, label: &str, color: Color32) {
    ui.label(RichText::new("●").color(color).small());
    ui.label(RichText::new(label).small().color(palette::MUTED));
    ui.add_space(8.0);
}

/// A small rounded pill badge.
fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::none()
        .fill(palette::BG)
        .stroke(Stroke::new(1.0_f32, color.linear_multiply(0.5)))
        .rounding(Rounding::same(10.0))
        .inner_margin(Margin::symmetric(8.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).small().color(color));
        });
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
