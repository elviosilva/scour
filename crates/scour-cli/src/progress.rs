//! A terminal progress sink for the CLI.
//!
//! Renders a single, self-overwriting status line on stderr while scanning, so
//! walking a large home directory gives live feedback instead of a silent wait.
//! It is TTY-aware: when stderr is not a terminal (piped, redirected, CI) it
//! stays quiet except for one concise line per category, keeping logs clean.

use std::io::{IsTerminal, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use humansize::{format_size, BINARY};
use scour_core::scan::{Progress, ProgressEvent};

/// Minimum interval between redraws of the live line.
const REDRAW_EVERY: Duration = Duration::from_millis(100);

pub struct TermProgress {
    tty: bool,
    state: Mutex<State>,
}

struct State {
    last_draw: Instant,
    /// True while a live line is on screen and needs clearing before other
    /// output.
    line_active: bool,
}

impl TermProgress {
    pub fn new() -> Self {
        Self {
            tty: std::io::stderr().is_terminal(),
            state: Mutex::new(State {
                last_draw: Instant::now() - REDRAW_EVERY,
                line_active: false,
            }),
        }
    }

    fn clear_line(err: &mut impl Write) {
        // Carriage return + clear-to-end-of-line.
        let _ = write!(err, "\r\x1b[K");
    }
}

impl Default for TermProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl Progress for TermProgress {
    fn event(&self, ev: ProgressEvent) {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(), // keep reporting even if a thread panicked
        };
        let mut err = std::io::stderr().lock();

        match ev {
            ProgressEvent::Started(cat) => {
                if self.tty {
                    Self::clear_line(&mut err);
                    let _ = write!(err, "Scanning {}…", cat.title());
                    let _ = err.flush();
                    state.line_active = true;
                }
            }
            ProgressEvent::Tick {
                category,
                entries,
                bytes,
                current,
            } => {
                if !self.tty {
                    return;
                }
                if state.last_draw.elapsed() < REDRAW_EVERY {
                    return;
                }
                state.last_draw = Instant::now();
                Self::clear_line(&mut err);
                let where_ = current
                    .as_deref()
                    .and_then(|p| p.to_str())
                    .map(truncate_middle)
                    .unwrap_or_default();
                let _ = write!(
                    err,
                    "Scanning {}… {} entries, {} — {}",
                    category.title(),
                    entries,
                    format_size(bytes, BINARY),
                    where_
                );
                let _ = err.flush();
                state.line_active = true;
            }
            ProgressEvent::Note { category, message } => {
                if self.tty {
                    Self::clear_line(&mut err);
                    let _ = write!(err, "Scanning {}… {message}", category.title());
                    let _ = err.flush();
                    state.line_active = true;
                }
            }
            ProgressEvent::Finished {
                category,
                findings,
                bytes,
            } => {
                if self.tty && state.line_active {
                    Self::clear_line(&mut err);
                }
                let _ = writeln!(
                    err,
                    "{:<18} {} items, {}",
                    category.title(),
                    findings,
                    format_size(bytes, BINARY)
                );
                let _ = err.flush();
                state.line_active = false;
            }
        }
    }
}

/// Shorten a long path to `head…tail` so the status line fits typical widths.
fn truncate_middle(s: &str) -> String {
    const MAX: usize = 60;
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= MAX {
        return s.to_string();
    }
    let keep = MAX - 1;
    let head = keep / 2;
    let tail = keep - head;
    let front: String = chars[..head].iter().collect();
    let back: String = chars[chars.len() - tail..].iter().collect();
    format!("{front}…{back}")
}

#[cfg(test)]
mod tests {
    use super::truncate_middle;

    #[test]
    fn short_paths_are_unchanged() {
        assert_eq!(truncate_middle("/home/u/x"), "/home/u/x");
    }

    #[test]
    fn long_paths_are_elided_in_the_middle() {
        let long = format!("/home/user/{}/file.bin", "d".repeat(100));
        let out = truncate_middle(&long);
        assert!(out.chars().count() <= 60);
        assert!(out.contains('…'));
        assert!(out.starts_with("/home/user/"));
        assert!(out.ends_with("file.bin"));
    }

    #[test]
    fn handles_multibyte_without_panicking() {
        let s = "/café/".repeat(40);
        let out = truncate_middle(&s);
        assert!(out.chars().count() <= 60);
    }
}

/// Convenience: a boxed sink, or a no-op one, depending on whether the caller
/// wants progress.
pub fn sink(enabled: bool) -> Box<dyn Progress> {
    if enabled {
        Box::new(TermProgress::new())
    } else {
        Box::new(scour_core::scan::NoProgress)
    }
}
