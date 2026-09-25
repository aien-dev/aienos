//! AIENOS Agent State ABI (§9).

use crate::id::{LogicalAgentId, LogicalBranchId};
use crate::incarnation::SequenceId;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Checkpoint cryptographic integrity hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CheckpointHash(pub [u8; 32]);

impl fmt::Debug for CheckpointHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CheckpointHash({:02x}{:02x}...)", self.0[0], self.0[1])
    }
}

impl fmt::Display for CheckpointHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Errors occurring during Agent State operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    AgentNotFound(LogicalAgentId),
    BranchNotFound(LogicalBranchId),
    ParentBranchNotFound(LogicalBranchId),
    AlreadySuspended(LogicalBranchId),
    NotSuspended(LogicalBranchId),
    SerializationError(String),
    DeserializationError(String),
    ChecksumMismatch,
    InvalidCheckpoint(&'static str),
    ReconstructionFailed(String),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentNotFound(id) => write!(f, "Agent not found: {}", id),
            Self::BranchNotFound(id) => write!(f, "Branch not found: {}", id),
            Self::ParentBranchNotFound(id) => write!(f, "Parent branch not found: {}", id),
            Self::AlreadySuspended(id) => write!(f, "Branch already suspended: {}", id),
            Self::NotSuspended(id) => write!(f, "Branch not suspended: {}", id),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            Self::ChecksumMismatch => write!(f, "Checkpoint checksum mismatch"),
            Self::InvalidCheckpoint(reason) => write!(f, "Invalid checkpoint: {reason}"),
            Self::ReconstructionFailed(msg) => write!(f, "Physical reconstruction failed: {}", msg),
        }
    }
}

/// The Agent State ABI (§9).
///
/// Decouples persistent semantic identity from ephemeral execution incarnations.
pub trait AgentStateAbi {
    /// Fork an existing logical branch into an isolated child branch.
    fn fork_branch(&self, parent: LogicalBranchId) -> Result<LogicalBranchId, StateError>;

    /// Checkpoint logical agent state to durable storage.
    fn checkpoint(&self, agent_id: LogicalAgentId) -> Result<CheckpointHash, StateError>;

    /// Suspend execution incarnation without mutating logical state.
    fn suspend(&mut self, branch_id: LogicalBranchId) -> Result<(), StateError>;

    /// Resume execution, re-instantiating physical state via recompute or cache.
    fn resume(&mut self, branch_id: LogicalBranchId) -> Result<SequenceId, StateError>;

    /// Reconstruct lost physical state from TokenHistory and EpistemicRefs.
    fn reconstruct_physical(&mut self, branch_id: LogicalBranchId) -> Result<(), StateError>;
}
