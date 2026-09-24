//! Bounded command parsing and dispatch for the early line shell.

use crate::report::ReportBuf;
use core::fmt::Write;

pub const LINE_CAPACITY: usize = 64;
pub const TOKEN_CAPACITY: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command<'a> {
    Help,
    Mem,
    El,
    Report,
    Uptime,
    Exit,
    Unknown(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedLine<'a> {
    pub command: Command<'a>,
    pub arg: Option<&'a str>,
}

/// Parse one whitespace-delimited command and at most one bounded argument.
pub fn parse_line(line: &str) -> Option<ParsedLine<'_>> {
    if line.len() > LINE_CAPACITY {
        return None;
    }
    let mut words = line.split_ascii_whitespace();
    let first = words.next()?;
    if first.len() > TOKEN_CAPACITY {
        return None;
    }
    let arg = words.next();
    if arg.is_some_and(|s| s.len() > TOKEN_CAPACITY) || words.next().is_some() {
        return None;
    }
    let command = match first {
        "help" => Command::Help,
        "mem" => Command::Mem,
        "el" => Command::El,
        "report" => Command::Report,
        "uptime" => Command::Uptime,
        "exit" => Command::Exit,
        _ => Command::Unknown(first),
    };
    Some(ParsedLine { command, arg })
}

pub struct ShellContext<'a> {
    pub conventional_memory_kb: u64,
    pub exception_level: u8,
    pub report: &'a str,
    pub uptime_ms: u64,
}

/// Format a command result in a fixed-capacity buffer. Invalid/oversized input
/// produces a bounded diagnostic and never allocates.
pub fn dispatch(line: &str, context: &ShellContext<'_>) -> ReportBuf<2048> {
    let mut out = ReportBuf::new();
    match parse_line(line) {
        None => {
            let _ = writeln!(out, "invalid command line");
        }
        Some(ParsedLine {
            command: Command::Help,
            ..
        }) => {
            let _ = writeln!(out, "commands: help mem el report uptime exit");
        }
        Some(ParsedLine {
            command: Command::Mem,
            ..
        }) => {
            let _ = writeln!(
                out,
                "conventional_memory_kb: {}",
                context.conventional_memory_kb
            );
        }
        Some(ParsedLine {
            command: Command::El,
            ..
        }) => {
            let _ = writeln!(out, "EL{}", context.exception_level);
        }
        Some(ParsedLine {
            command: Command::Report,
            ..
        }) => {
            let _ = write!(out, "{}", context.report);
        }
        Some(ParsedLine {
            command: Command::Uptime,
            ..
        }) => {
            let _ = writeln!(out, "uptime_ms: {}", context.uptime_ms);
        }
        Some(ParsedLine {
            command: Command::Exit,
            ..
        }) => {}
        Some(ParsedLine {
            command: Command::Unknown(name),
            ..
        }) => {
            let _ = writeln!(out, "unknown command: {name}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands_and_bounded_arguments() {
        assert_eq!(
            parse_line("mem"),
            Some(ParsedLine {
                command: Command::Mem,
                arg: None
            })
        );
        assert_eq!(parse_line("unknown abc").unwrap().arg, Some("abc"));
        assert!(parse_line(&"x".repeat(LINE_CAPACITY + 1)).is_none());
        assert!(parse_line("x 12345678901234567").is_none());
        assert!(parse_line("x a b").is_none());
    }

    #[test]
    fn dispatches_report_and_diagnostics() {
        let ctx = ShellContext {
            conventional_memory_kb: 42,
            exception_level: 1,
            report: "final report\n",
            uptime_ms: 7,
        };
        assert!(dispatch("el", &ctx).as_str().contains("EL1"));
        assert!(dispatch("mem", &ctx).as_str().contains("42"));
        assert!(dispatch("report", &ctx).as_str().contains("final report"));
        assert!(dispatch("wat", &ctx)
            .as_str()
            .contains("unknown command: wat"));
    }
}
