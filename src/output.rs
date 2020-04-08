use anyhow::Result;
use colored::*;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

/// Serialize any value as pretty-printed JSON to stdout.
pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{}", json);
    Ok(())
}

/// Print a section header with a colored separator.
pub fn print_header(title: &str) {
    println!();
    println!("{}", title.bold().underline());
    println!("{}", "─".repeat(60).dimmed());
}

/// Print a key-value pair with proper alignment.
pub fn print_kv(key: &str, value: &str) {
    println!("  {:<20} {}", key.dimmed(), value);
}

/// Print a success message.
pub fn print_success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg);
}

/// Print a warning message.
pub fn print_warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), msg);
}

/// Print an error message.
pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✗".red().bold(), msg);
}

/// Print a progress indicator (overwrites current line).
pub fn print_progress(current: usize, total: usize, label: &str) {
    let pct = if total > 0 {
        (current as f64 / total as f64 * 100.0) as u8
    } else {
        0
    };
    let bar_width = 30;
    let filled = (pct as usize * bar_width) / 100;
    let empty = bar_width - filled;
    eprint!(
        "\r  {} [{}{}] {}% ({}/{})",
        label.dimmed(),
        "█".repeat(filled).green(),
        "░".repeat(empty).dimmed(),
        pct,
        current,
        total
    );
    if current == total {
        eprintln!();
    }
}

/// Render a simple ASCII table.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    widths: Vec<usize>,
}

impl Table {
    pub fn new(headers: Vec<&str>) -> Self {
        let widths = headers.iter().map(|h| h.len()).collect();
        Table {
            headers: headers.into_iter().map(String::from).collect(),
            rows: Vec::new(),
            widths,
        }
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        for (i, cell) in row.iter().enumerate() {
            if i < self.widths.len() {
                self.widths[i] = self.widths[i].max(cell.len());
            }
        }
        self.rows.push(row);
    }

    pub fn print(&self) {
        // Print headers
        let header_line: Vec<String> = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:<width$}", h, width = self.widths[i] + 2))
            .collect();
        println!("{}", header_line.join("").bold());

        // Separator
        let sep_width: usize = self.widths.iter().sum::<usize>() + self.widths.len() * 2;
        println!("{}", "─".repeat(sep_width).dimmed());

        // Rows
        for row in &self.rows {
            let line: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    let width = if i < self.widths.len() {
                        self.widths[i] + 2
                    } else {
                        cell.len() + 2
                    };
                    format!("{:<width$}", cell, width = width)
                })
                .collect();
            println!("{}", line.join(""));
        }
    }
}
