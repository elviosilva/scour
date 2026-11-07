//! scour-tui — interactive terminal UI over a [`ScanReport`].
//!
//! Layout: a category list on the left, the findings of the focused category on
//! the right. Space toggles a finding's selection; `a` selects every Safe item
//! in the focused category; `c` cleans the current selection (unprivileged
//! items only — privileged ones are flagged to run via the CLI); `q` quits.

use std::collections::BTreeSet;
use std::io::{self, Stdout};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use humansize::{format_size, BINARY};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use scour_core::model::{Category, FindingId, RiskLevel, ScanReport};
use scour_core::ops::{self, OpStatus};

/// Entry point: take over the terminal, run the UI loop, and restore on exit.
pub fn run(report: ScanReport) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = App::new(report);
    let result = app.run(&mut terminal);
    restore_terminal(&mut terminal)?;
    result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

struct App {
    report: ScanReport,
    categories: Vec<Category>,
    cat_index: usize,
    list_state: ListState,
    selected: BTreeSet<FindingId>,
    status: String,
    quit: bool,
}

impl App {
    fn new(report: ScanReport) -> Self {
        let categories: Vec<Category> = Category::ALL
            .into_iter()
            .filter(|c| report.by_category(*c).next().is_some())
            .collect();
        let mut list_state = ListState::default();
        if !categories.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            report,
            categories,
            cat_index: 0,
            list_state,
            selected: BTreeSet::new(),
            status: "space: toggle · a: all-safe · c: clean · tab: category · q: quit".into(),
            quit: false,
        }
    }

    fn current_category(&self) -> Option<Category> {
        self.categories.get(self.cat_index).copied()
    }

    fn current_findings(&self) -> Vec<&scour_core::model::Finding> {
        match self.current_category() {
            Some(cat) => self.report.by_category(cat).collect(),
            None => Vec::new(),
        }
    }

    fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    self.on_key(key.code);
                }
            }
        }
        Ok(())
    }

    fn on_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Tab | KeyCode::Right => self.next_category(),
            KeyCode::BackTab | KeyCode::Left => self.prev_category(),
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Char(' ') => self.toggle_current(),
            KeyCode::Char('a') => self.select_all_safe(),
            KeyCode::Char('c') => self.clean_selection(),
            _ => {}
        }
    }

    fn next_category(&mut self) {
        if self.categories.is_empty() {
            return;
        }
        self.cat_index = (self.cat_index + 1) % self.categories.len();
        self.list_state.select(Some(0));
    }

    fn prev_category(&mut self) {
        if self.categories.is_empty() {
            return;
        }
        self.cat_index = (self.cat_index + self.categories.len() - 1) % self.categories.len();
        self.list_state.select(Some(0));
    }

    fn move_cursor(&mut self, delta: isize) {
        let len = self.current_findings().len();
        if len == 0 {
            return;
        }
        let cur = self.list_state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, len as isize - 1);
        self.list_state.select(Some(next as usize));
    }

    fn toggle_current(&mut self) {
        let findings = self.current_findings();
        if let Some(i) = self.list_state.selected() {
            if let Some(f) = findings.get(i) {
                let id = f.id;
                if !self.selected.remove(&id) {
                    self.selected.insert(id);
                }
            }
        }
    }

    fn select_all_safe(&mut self) {
        let ids: Vec<FindingId> = self
            .current_findings()
            .iter()
            .filter(|f| f.risk == RiskLevel::Safe)
            .map(|f| f.id)
            .collect();
        for id in ids {
            self.selected.insert(id);
        }
    }

    fn clean_selection(&mut self) {
        let chosen: Vec<scour_core::model::Finding> = self
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

        let mut reclaimed = 0u64;
        let mut removed = 0usize;
        let mut failed = 0usize;
        let mut deferred = 0usize;
        let mut done_ids = BTreeSet::new();

        for f in &chosen {
            match ops::plan(f) {
                Ok(op) if op.privileged => deferred += 1,
                Ok(op) => {
                    let outcome = ops::execute(&op, false);
                    match outcome.status {
                        OpStatus::Removed => {
                            reclaimed += outcome.bytes;
                            removed += 1;
                            done_ids.insert(f.id);
                        }
                        OpStatus::Planned => {}
                        OpStatus::Failed | OpStatus::Rejected => failed += 1,
                    }
                }
                Err(_) => failed += 1,
            }
        }

        // Drop everything we actually removed from both the report and the
        // selection, then keep the cursor in range.
        self.report.findings.retain(|f| !done_ids.contains(&f.id));
        self.selected.retain(|id| !done_ids.contains(id));
        self.clamp_cursor();

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

    fn clamp_cursor(&mut self) {
        let len = self.current_findings().len();
        if len == 0 {
            self.list_state.select(None);
        } else {
            let cur = self.list_state.selected().unwrap_or(0).min(len - 1);
            self.list_state.select(Some(cur));
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(frame.area());

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(32), Constraint::Percentage(68)])
            .split(chunks[0]);

        self.draw_categories(frame, body[0]);
        self.draw_findings(frame, body[1]);
        self.draw_status(frame, chunks[1]);
    }

    fn draw_categories(&self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .categories
            .iter()
            .enumerate()
            .map(|(i, cat)| {
                let total: u64 = self.report.by_category(*cat).map(|f| f.size).sum();
                let marker = if i == self.cat_index { "▶ " } else { "  " };
                let line = format!("{marker}{} ({})", cat.title(), format_size(total, BINARY));
                ListItem::new(line)
            })
            .collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(" Categories "));
        frame.render_widget(list, area);
    }

    fn draw_findings(&mut self, frame: &mut Frame, area: Rect) {
        let selected = &self.selected;
        let items: Vec<ListItem> = self
            .current_findings()
            .iter()
            .map(|f| {
                let mark = if selected.contains(&f.id) { "[x]" } else { "[ ]" };
                let priv_tag = if f.requires_privilege { " *" } else { "" };
                let line = format!(
                    "{mark} {:>10}  {}{priv_tag}",
                    format_size(f.size, BINARY),
                    f.path.display()
                );
                let style = match f.risk {
                    RiskLevel::Safe => Style::default(),
                    RiskLevel::Review => Style::default().fg(Color::Yellow),
                    RiskLevel::Manual => Style::default().fg(Color::Red),
                };
                ListItem::new(line).style(style)
            })
            .collect();

        let title = match self.current_category() {
            Some(cat) => format!(" {} — * = needs privileges ", cat.title()),
            None => " (no findings) ".into(),
        };
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_symbol("» ")
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn draw_status(&self, frame: &mut Frame, area: Rect) {
        let sel_bytes: u64 = self
            .report
            .findings
            .iter()
            .filter(|f| self.selected.contains(&f.id))
            .map(|f| f.size)
            .sum();
        let text = format!(
            "{}   |   selected: {} ({})",
            self.status,
            self.selected.len(),
            format_size(sel_bytes, BINARY)
        );
        let para = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true });
        frame.render_widget(para, area);
    }
}
