//! AIENOS Agent State ABI & Execution Incarnation Substrate (§9).
//!
//! Provides sovereign logical agent identities, deterministic branch derivation,
//! append-only token history logs with rolling cryptographic hash chains,
//! and complete decoupling of persistent semantic identity from ephemeral
//! physical compute incarnations.

pub mod abi;
pub mod history;
pub mod id;
pub mod incarnation;
pub mod lineage;
pub mod manager;

pub use abi::{AgentStateAbi, CheckpointHash, StateError};
pub use history::{TokenHistory, TokenRecord};
pub use id::{LogicalAgentId, LogicalBranchId};
pub use incarnation::{
    ComputeState, ExecutionIncarnation, IncarnationId, LogicalBranch, PhysicalInferenceState,
    SequenceId,
};
pub use lineage::{EpistemicRefs, Lineage};
pub use manager::{AgentSnapshot, AgentStateManager, CheckpointEnvelope};
