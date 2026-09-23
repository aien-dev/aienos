//! Ephemeral execution incarnations and decoupled physical inference states.

use crate::history::TokenHistory;
use crate::id::{LogicalAgentId, LogicalBranchId};
use crate::lineage::{EpistemicRefs, Lineage};
use serde::{Deserialize, Serialize};

/// Monotonic boot / process incarnation counter.
pub type IncarnationId = u64;

/// Ephemeral scheduler slot identifier.
pub type SequenceId = u32;

/// State of accelerator/hardware inference pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputeState {
    Idle,
    Prefilling,
    Decoding,
    Suspended,
    Evicted,
}

/// Ephemeral physical inference allocation.
///
/// Losing this state costs computation (recompute / cache reload), NEVER identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalInferenceState {
    pub kv_page_table_ref: Option<usize>,
    pub accelerator_buffer_ref: Option<usize>,
    pub compute_state: ComputeState,
    pub allocated_tokens_in_kv: usize,
}

impl Default for PhysicalInferenceState {
    fn default() -> Self {
        Self {
            kv_page_table_ref: None,
            accelerator_buffer_ref: None,
            compute_state: ComputeState::Idle,
            allocated_tokens_in_kv: 0,
        }
    }
}

/// Ephemeral per-boot/process execution instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionIncarnation {
    pub incarnation_id: IncarnationId,
    pub sequence_id: SequenceId,
    pub physical_state: PhysicalInferenceState,
}

impl ExecutionIncarnation {
    /// Create new active execution incarnation.
    pub fn new(incarnation_id: IncarnationId, sequence_id: SequenceId) -> Self {
        Self {
            incarnation_id,
            sequence_id,
            physical_state: PhysicalInferenceState::default(),
        }
    }

    /// Mark incarnation as evicted (hardware resources reclaimed).
    pub fn evict(&mut self) {
        self.physical_state.kv_page_table_ref = None;
        self.physical_state.accelerator_buffer_ref = None;
        self.physical_state.allocated_tokens_in_kv = 0;
        self.physical_state.compute_state = ComputeState::Evicted;
    }
}

/// Persistent Logical Branch entity holding complete semantic identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalBranch {
    pub branch_id: LogicalBranchId,
    pub parent_branch_id: Option<LogicalBranchId>,
    pub agent_id: LogicalAgentId,
    pub token_history: TokenHistory,
    pub lineage: Lineage,
    pub epistemic_refs: EpistemicRefs,
    pub created_at_utc: u64,
}

impl LogicalBranch {
    /// Initialize a new root branch for an agent.
    pub fn new_root(agent_id: LogicalAgentId, timestamp: u64) -> Self {
        let branch_id = LogicalBranchId::root_branch(agent_id);
        Self {
            branch_id,
            parent_branch_id: None,
            agent_id,
            token_history: TokenHistory::new(),
            lineage: Lineage::new_root(agent_id),
            epistemic_refs: EpistemicRefs::new(),
            created_at_utc: timestamp,
        }
    }

    /// Fork this branch into a child branch, inheriting token history and extending lineage.
    pub fn fork(&self, child_id: LogicalBranchId, timestamp: u64) -> Self {
        Self {
            branch_id: child_id,
            parent_branch_id: Some(self.branch_id),
            agent_id: self.agent_id,
            token_history: self.token_history.fork(),
            lineage: self.lineage.extend(child_id),
            epistemic_refs: self.epistemic_refs.clone(),
            created_at_utc: timestamp,
        }
    }
}
