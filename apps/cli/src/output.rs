//! Output formatting.
//!
//! Two rules keep the CLI honest and pipeable:
//!
//! 1. **Data goes to stdout, messages go to stderr.** `--json` output can therefore be piped
//!    without log lines corrupting it.
//! 2. **The CLI prints what the engine computed.** It formats, it does not analyse. There is no
//!    place here where a threshold, a sort key or a verdict is invented.

use anyhow::Result;
use sentinel_common::clock;
use serde::Serialize;

/// Prints a value as JSON, or falls back to a human-readable summary.
///
/// `human` is always evaluated lazily inside the non-JSON branch, so it can use formatting that
/// is pointless when JSON is requested.
pub fn emit<T: Serialize>(json: bool, value: &T, human: impl FnOnce()) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        human();
    }
    Ok(())
}

/// Prints an informational line to stderr, so stdout stays clean for data.
pub fn note(quiet: bool, message: impl AsRef<str>) {
    if !quiet {
        eprintln!("{}", message.as_ref());
    }
}

/// Formats a byte count for terminal output.
#[must_use]
pub fn bytes(value: u64) -> String {
    clock::format_bytes(value)
}

/// Formats a bits-per-second rate for terminal output.
#[must_use]
pub fn rate(value: f64) -> String {
    clock::format_bps(value)
}

/// Formats a duration for terminal output.
///
/// Sub-second values are shown in milliseconds: a capture that spans 166 ms is not "0s", and
/// "0s" reads as "nothing happened" rather than "it was quick".
#[must_use]
pub fn duration_seconds_micros(micros: u64) -> String {
    if micros < 1_000_000 {
        return format!("{}ms", micros / 1_000);
    }
    clock::format_duration(micros / 1_000_000)
}

/// Formats a timestamp for terminal output.
#[must_use]
pub fn timestamp(micros: u64) -> String {
    clock::unix_micros_to_rfc3339(micros)
}

/// A plain-text table with aligned columns.
///
/// Written by hand rather than pulled in as a dependency: the CLI needs eight columns of
/// right-aligned numbers, and a table crate would be more code than this.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    right_aligned_from: usize,
}

impl Table {
    /// Creates a table with the given headers.
    ///
    /// `right_aligned_from` is the first column index rendered right-aligned, which is where
    /// numbers begin. Alignment is a presentation detail of the terminal, not of the data.
    #[must_use]
    pub fn new(headers: &[&str], right_aligned_from: usize) -> Self {
        Self {
            headers: headers.iter().map(|header| (*header).to_string()).collect(),
            rows: Vec::new(),
            right_aligned_from,
        }
    }

    /// Adds a row.
    pub fn push(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    /// Prints the table with a blank line between the header and the body.
    ///
    /// An empty table prints only its header. Callers check for emptiness first when there is
    /// something more useful to say.
    pub fn print(&self) {
        let mut widths: Vec<usize> = self
            .headers
            .iter()
            .map(|header| header.chars().count())
            .collect();
        for row in &self.rows {
            for (index, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(index) {
                    *width = (*width).max(cell.chars().count());
                }
            }
        }

        print_row(&self.headers, &widths, 0, self.right_aligned_from);
        println!();
        for row in &self.rows {
            print_row(row, &widths, 0, self.right_aligned_from);
        }
    }
}

/// Prints one padded row.
fn print_row(cells: &[String], widths: &[usize], indent: usize, right_aligned_from: usize) {
    let mut line = " ".repeat(indent);
    for (index, cell) in cells.iter().enumerate() {
        let width = widths.get(index).copied().unwrap_or(0);
        let padding = width.saturating_sub(cell.chars().count());
        if index >= right_aligned_from {
            line.push_str(&" ".repeat(padding));
            line.push_str(cell);
        } else {
            line.push_str(cell);
            line.push_str(&" ".repeat(padding));
        }
        if index + 1 < cells.len() {
            line.push_str("  ");
        }
    }
    println!("{line}");
}
