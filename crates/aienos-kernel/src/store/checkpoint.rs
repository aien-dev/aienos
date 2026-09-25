//! Crash Checkpoint ABI for AIENOS System Store transactions.
//!
//! Provides a tiny test-only checkpoint interface consumed by crash controllers,
//! integration tests (e.g. QEMU crash injection), and the store transaction engine.
//!
//! Checkpoints define deterministic, crash-consistent observation boundaries during
//! a store transaction commit sequence:
//! 1. `BeforeFirstWrite` ("before_first_write")
//! 2. `AfterPayloads` ("after_payloads" / "after_payload_objects")
//! 3. `AfterCatalog` ("after_catalog")
//! 4. `AfterCommitRecord` ("after_commit_record")
//! 5. `AfterFirstFlush` ("after_first_flush")
//! 6. `AfterSuperblockWrite` ("after_superblock_write" / "after_inactive_superblock")
//! 7. `AfterFinalFlush` ("after_final_flush")
//!
//! Architectural invariants:
//! - Deterministic ordering: sequence strictly advances from 0 to 6.
//! - Non-mutating: observing a checkpoint never mutates storage buffers or persisted bytes.
//! - Non-flushing: observing a checkpoint performs zero device flushes.
//! - Ephemeral: checkpoints are an in-memory observation ABI and do not exist on disk.
//! - Production elision: null hook (`NullCheckpointHook` / `null_hook`) is zero-sized and
//!   elided at compile time with zero runtime overhead or serial output.
//! - Serial observation: formatted strings match `CHECKPOINT: <name>` as recognized
//!   by crash controllers.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

/// Prefix recognized by the QEMU crash controller harness.
pub const CHECKPOINT_PREFIX: &str = "CHECKPOINT: ";

/// Total count of distinct checkpoints in the transaction commit sequence.
pub const CHECKPOINT_COUNT: usize = 7;

/// Canonical checkpoint identifiers during transaction commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Checkpoint {
    /// Before any block or unit write for the transaction is initiated.
    BeforeFirstWrite = 0,
    /// After all payload/application objects have been written to disk units.
    AfterPayloads = 1,
    /// After the new catalog units have been written to disk.
    AfterCatalog = 2,
    /// After the commit record unit has been written to disk.
    AfterCommitRecord = 3,
    /// After the first device flush (persisting payload, catalog, and commit record).
    AfterFirstFlush = 4,
    /// After the inactive superblock has been updated with the new commit reference.
    AfterSuperblockWrite = 5,
    /// After the final device flush (persisting the newly activated superblock).
    AfterFinalFlush = 6,
}

impl Checkpoint {
    /// Alias matching the Codex store engine variant name.
    pub const AfterPayloadObjects: Checkpoint = Checkpoint::AfterPayloads;
    /// Alias matching the Codex store engine variant name.
    pub const AfterInactiveSuperblock: Checkpoint = Checkpoint::AfterSuperblockWrite;

    /// All 7 canonical checkpoints in their exact deterministic execution order.
    pub const ORDERED: [Checkpoint; CHECKPOINT_COUNT] = [
        Checkpoint::BeforeFirstWrite,
        Checkpoint::AfterPayloads,
        Checkpoint::AfterCatalog,
        Checkpoint::AfterCommitRecord,
        Checkpoint::AfterFirstFlush,
        Checkpoint::AfterSuperblockWrite,
        Checkpoint::AfterFinalFlush,
    ];

    /// Returns the canonical lower_snake_case name of the checkpoint.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Checkpoint::BeforeFirstWrite => "before_first_write",
            Checkpoint::AfterPayloads => "after_payloads",
            Checkpoint::AfterCatalog => "after_catalog",
            Checkpoint::AfterCommitRecord => "after_commit_record",
            Checkpoint::AfterFirstFlush => "after_first_flush",
            Checkpoint::AfterSuperblockWrite => "after_superblock_write",
            Checkpoint::AfterFinalFlush => "after_final_flush",
        }
    }

    /// Returns the store engine variant alias name.
    #[inline]
    pub const fn engine_name(&self) -> &'static str {
        match self {
            Checkpoint::BeforeFirstWrite => "before_first_write",
            Checkpoint::AfterPayloads => "after_payload_objects",
            Checkpoint::AfterCatalog => "after_catalog",
            Checkpoint::AfterCommitRecord => "after_commit_record",
            Checkpoint::AfterFirstFlush => "after_first_flush",
            Checkpoint::AfterSuperblockWrite => "after_inactive_superblock",
            Checkpoint::AfterFinalFlush => "after_final_flush",
        }
    }

    /// Returns all accepted names and aliases for this checkpoint.
    pub const fn aliases(&self) -> &'static [&'static str] {
        match self {
            Checkpoint::BeforeFirstWrite => &["before_first_write"],
            Checkpoint::AfterPayloads => &["after_payloads", "after_payload_objects"],
            Checkpoint::AfterCatalog => &["after_catalog"],
            Checkpoint::AfterCommitRecord => &["after_commit_record"],
            Checkpoint::AfterFirstFlush => &["after_first_flush"],
            Checkpoint::AfterSuperblockWrite => {
                &["after_superblock_write", "after_inactive_superblock"]
            }
            Checkpoint::AfterFinalFlush => &["after_final_flush"],
        }
    }

    /// Deterministic 0-indexed execution order.
    #[inline]
    pub const fn order(&self) -> u8 {
        *self as u8
    }

    /// Returns the checkpoint corresponding to an execution index (0..6), if valid.
    pub const fn from_order(order: u8) -> Option<Checkpoint> {
        match order {
            0 => Some(Checkpoint::BeforeFirstWrite),
            1 => Some(Checkpoint::AfterPayloads),
            2 => Some(Checkpoint::AfterCatalog),
            3 => Some(Checkpoint::AfterCommitRecord),
            4 => Some(Checkpoint::AfterFirstFlush),
            5 => Some(Checkpoint::AfterSuperblockWrite),
            6 => Some(Checkpoint::AfterFinalFlush),
            _ => None,
        }
    }

    /// Returns the next checkpoint in the commit sequence, or `None` if at final flush.
    pub const fn next(&self) -> Option<Checkpoint> {
        Self::from_order(self.order() + 1)
    }

    /// Returns the previous checkpoint in the commit sequence, or `None` if at initial point.
    pub const fn prev(&self) -> Option<Checkpoint> {
        if self.order() == 0 {
            None
        } else {
            Self::from_order(self.order() - 1)
        }
    }

    /// Formats the checkpoint into the canonical serial string `CHECKPOINT: <name>`.
    pub fn format_serial(&self) -> String {
        format_checkpoint(*self)
    }
}

impl fmt::Display for Checkpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error returned when parsing an unrecognized checkpoint name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseCheckpointError;

impl fmt::Display for ParseCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown or invalid crash checkpoint identifier")
    }
}

impl FromStr for Checkpoint {
    type Err = ParseCheckpointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_checkpoint(s).ok_or(ParseCheckpointError)
    }
}

/// Parses a checkpoint identifier from a string.
///
/// Accepts:
/// - Canonical names: `"before_first_write"`, `"after_payloads"`, `"after_catalog"`,
///   `"after_commit_record"`, `"after_first_flush"`, `"after_superblock_write"`, `"after_final_flush"`
/// - Engine aliases: `"after_payload_objects"`, `"after_inactive_superblock"`
/// - Full serial lines: `"CHECKPOINT: <name>"`
/// - Surrounding whitespace or newlines.
pub fn parse_checkpoint(input: &str) -> Option<Checkpoint> {
    let trimmed = input.trim();
    let name = if let Some(stripped) = trimmed.strip_prefix("CHECKPOINT:") {
        stripped.trim()
    } else {
        trimmed
    };

    match name {
        "before_first_write" => Some(Checkpoint::BeforeFirstWrite),
        "after_payloads" | "after_payload_objects" => Some(Checkpoint::AfterPayloads),
        "after_catalog" => Some(Checkpoint::AfterCatalog),
        "after_commit_record" => Some(Checkpoint::AfterCommitRecord),
        "after_first_flush" => Some(Checkpoint::AfterFirstFlush),
        "after_superblock_write" | "after_inactive_superblock" => {
            Some(Checkpoint::AfterSuperblockWrite)
        }
        "after_final_flush" => Some(Checkpoint::AfterFinalFlush),
        _ => None,
    }
}

/// Formats a checkpoint into the canonical serial line: `CHECKPOINT: <canonical_name>`.
pub fn format_checkpoint(checkpoint: Checkpoint) -> String {
    format!("{}{}", CHECKPOINT_PREFIX, checkpoint.as_str())
}

/// Formats a checkpoint with an explicit name or alias into serial format: `CHECKPOINT: <name>`.
pub fn format_checkpoint_with_name(name: &str) -> String {
    format!("{}{}", CHECKPOINT_PREFIX, name)
}

/// Formats a checkpoint into a stack-allocated byte buffer without heap allocation.
/// Returns the resulting string slice on success, or `None` if the buffer is too small.
pub fn format_checkpoint_buf(checkpoint: Checkpoint, buf: &mut [u8]) -> Option<&str> {
    let prefix = CHECKPOINT_PREFIX.as_bytes();
    let name = checkpoint.as_str().as_bytes();
    let total = prefix.len() + name.len();
    if buf.len() < total {
        return None;
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..total].copy_from_slice(name);
    core::str::from_utf8(&buf[..total]).ok()
}

/// Logs a checkpoint to standard output if running with `std`.
/// In bare-metal `no_std`, this is a no-op unless a specific console writer is plugged.
pub fn log_checkpoint(checkpoint: Checkpoint) {
    #[cfg(feature = "std")]
    {
        println!("{}{}", CHECKPOINT_PREFIX, checkpoint.as_str());
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = checkpoint;
    }
}

/// Logs a checkpoint to an arbitrary `core::fmt::Write` destination.
pub fn log_checkpoint_to<W: fmt::Write>(writer: &mut W, checkpoint: Checkpoint) -> fmt::Result {
    writeln!(writer, "{}{}", CHECKPOINT_PREFIX, checkpoint.as_str())
}

/// Interface for crash checkpoint observers.
pub trait CheckpointHook {
    /// Fired synchronously at the specified checkpoint boundary.
    ///
    /// Implementors MUST NOT:
    /// - Mutate storage device buffers or bytes.
    /// - Trigger I/O flushes.
    /// - Persist checkpoint state to media.
    fn on_checkpoint(&mut self, checkpoint: Checkpoint);
}

/// Zero-sized null hook that compiles down to a no-op with zero runtime overhead.
///
/// Intended for production builds where crash injection / checkpoint observation
/// is disabled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NullCheckpointHook;

impl CheckpointHook for NullCheckpointHook {
    #[inline(always)]
    fn on_checkpoint(&mut self, _checkpoint: Checkpoint) {
        // Compile-time no-op.
    }
}

/// Compile-time elided function pointer hook.
#[inline(always)]
pub fn null_hook(_checkpoint: Checkpoint) {
    // Compile-time no-op.
}

/// Closure adapter allowing any `FnMut(Checkpoint)` to act as a `CheckpointHook`.
impl<F: FnMut(Checkpoint)> CheckpointHook for F {
    #[inline(always)]
    fn on_checkpoint(&mut self, checkpoint: Checkpoint) {
        (self)(checkpoint);
    }
}

/// Test helper hook that records observed checkpoints in sequence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingHook {
    pub visited: Vec<Checkpoint>,
}

impl RecordingHook {
    pub const fn new() -> Self {
        Self {
            visited: Vec::new(),
        }
    }
}

impl CheckpointHook for RecordingHook {
    fn on_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.visited.push(checkpoint);
    }
}

/// Serial hook that writes `CHECKPOINT: <name>\n` lines to a string buffer.
#[derive(Debug, Default)]
pub struct SerialCaptureHook {
    pub output: String,
}

impl SerialCaptureHook {
    pub fn new() -> Self {
        Self {
            output: String::new(),
        }
    }
}

impl CheckpointHook for SerialCaptureHook {
    fn on_checkpoint(&mut self, checkpoint: Checkpoint) {
        use fmt::Write;
        let _ = writeln!(self.output, "{}{}", CHECKPOINT_PREFIX, checkpoint.as_str());
    }
}
