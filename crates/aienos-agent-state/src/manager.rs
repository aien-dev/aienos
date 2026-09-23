//! Concrete thread-safe AgentStateManager implementing AgentStateAbi.

use crate::abi::{AgentStateAbi, CheckpointHash, StateError};
use crate::id::{LogicalAgentId, LogicalBranchId};
use crate::incarnation::{ComputeState, ExecutionIncarnation, LogicalBranch, SequenceId};
use aienos_kernel::crypto::sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;

/// Persistent snapshot of agent state for cross-boot serialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentSnapshot {
    pub agents: Vec<LogicalAgentId>,
    pub branches: Vec<LogicalBranch>,
    pub snapshot_incarnation: u64,
}

/// Durable checkpoint container with cryptographic seal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointEnvelope {
    pub hash: [u8; 32],
    pub payload_json: String,
}

struct InnerState {
    agents: Vec<LogicalAgentId>,
    branches: HashMap<LogicalBranchId, LogicalBranch>,
    incarnations: HashMap<LogicalBranchId, ExecutionIncarnation>,
    branch_child_counters: HashMap<LogicalBranchId, u64>,
}

/// Thread-safe sovereign manager for logical agent states and execution incarnations.
pub struct AgentStateManager {
    inner: RwLock<InnerState>,
    current_incarnation_id: AtomicU64,
    next_sequence_id: AtomicU32,
}

impl Default for AgentStateManager {
    fn default() -> Self {
        Self::new(1)
    }
}

impl AgentStateManager {
    /// Initialize a new manager with a specific boot incarnation ID.
    pub fn new(incarnation_id: u64) -> Self {
        Self {
            inner: RwLock::new(InnerState {
                agents: Vec::new(),
                branches: HashMap::new(),
                incarnations: HashMap::new(),
                branch_child_counters: HashMap::new(),
            }),
            current_incarnation_id: AtomicU64::new(incarnation_id),
            next_sequence_id: AtomicU32::new(1),
        }
    }

    /// Register a new agent and instantiate its root branch.
    pub fn register_agent(&self, agent_id: LogicalAgentId, timestamp: u64) -> LogicalBranchId {
        let mut inner = self.inner.write().unwrap();
        if !inner.agents.contains(&agent_id) {
            inner.agents.push(agent_id);
        }

        let root_branch = LogicalBranch::new_root(agent_id, timestamp);
        let branch_id = root_branch.branch_id;
        inner.branches.insert(branch_id, root_branch);

        let seq = self.next_sequence_id.fetch_add(1, Ordering::SeqCst);
        let incarnation_id = self.current_incarnation_id.load(Ordering::SeqCst);
        inner
            .incarnations
            .insert(branch_id, ExecutionIncarnation::new(incarnation_id, seq));

        branch_id
    }

    /// Append tokens to an existing branch's history.
    pub fn append_tokens(
        &self,
        branch_id: LogicalBranchId,
        tokens: &[u32],
    ) -> Result<(), StateError> {
        let mut inner = self.inner.write().unwrap();
        let history_len = {
            let branch = inner
                .branches
                .get_mut(&branch_id)
                .ok_or(StateError::BranchNotFound(branch_id))?;
            branch.token_history.append_tokens(tokens);
            branch.token_history.len()
        };

        if let Some(inc) = inner.incarnations.get_mut(&branch_id) {
            if inc.physical_state.compute_state != ComputeState::Suspended
                && inc.physical_state.compute_state != ComputeState::Evicted
            {
                inc.physical_state.allocated_tokens_in_kv = history_len;
                inc.physical_state.compute_state = ComputeState::Decoding;
            }
        }
        Ok(())
    }

    /// Attach a Cortex epistemic reference to a branch.
    pub fn add_epistemic_ref(
        &self,
        branch_id: LogicalBranchId,
        record_id: [u8; 16],
    ) -> Result<(), StateError> {
        let mut inner = self.inner.write().unwrap();
        let branch = inner
            .branches
            .get_mut(&branch_id)
            .ok_or(StateError::BranchNotFound(branch_id))?;
        branch.epistemic_refs.insert(record_id);
        Ok(())
    }

    /// Retrieve branch details.
    pub fn get_branch(&self, branch_id: &LogicalBranchId) -> Option<LogicalBranch> {
        let inner = self.inner.read().unwrap();
        inner.branches.get(branch_id).cloned()
    }

    /// Retrieve ephemeral incarnation details.
    pub fn get_incarnation(&self, branch_id: &LogicalBranchId) -> Option<ExecutionIncarnation> {
        let inner = self.inner.read().unwrap();
        inner.incarnations.get(branch_id).cloned()
    }

    /// Export a durable checkpoint envelope with SHA-256 seal.
    pub fn export_checkpoint(&self, agent_id: LogicalAgentId) -> Result<Vec<u8>, StateError> {
        let inner = self.inner.read().unwrap();
        if !inner.agents.contains(&agent_id) {
            return Err(StateError::AgentNotFound(agent_id));
        }

        let agent_branches: Vec<LogicalBranch> = inner
            .branches
            .values()
            .filter(|b| b.agent_id == agent_id)
            .cloned()
            .collect();

        let snapshot = AgentSnapshot {
            agents: vec![agent_id],
            branches: agent_branches,
            snapshot_incarnation: self.current_incarnation_id.load(Ordering::SeqCst),
        };

        let json = serde_json::to_string(&snapshot)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        let hash = sha256::hash(json.as_bytes());

        let envelope = CheckpointEnvelope {
            hash,
            payload_json: json,
        };

        serde_json::to_vec(&envelope).map_err(|e| StateError::SerializationError(e.to_string()))
    }

    /// Restore state from a durable checkpoint envelope across reboot.
    ///
    /// Verifies cryptographic checksum, restores all logical state, and
    /// resets physical state to `Evicted` under a new monotonic boot incarnation.
    pub fn restore_from_checkpoint(
        checkpoint_data: &[u8],
        new_incarnation_id: u64,
    ) -> Result<Self, StateError> {
        let envelope: CheckpointEnvelope = serde_json::from_slice(checkpoint_data)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        let expected_hash = sha256::hash(envelope.payload_json.as_bytes());
        if envelope.hash != expected_hash {
            return Err(StateError::ChecksumMismatch);
        }

        let snapshot: AgentSnapshot = serde_json::from_str(&envelope.payload_json)
            .map_err(|e| StateError::DeserializationError(e.to_string()))?;

        let manager = Self::new(new_incarnation_id);
        {
            let mut inner = manager.inner.write().unwrap();
            inner.agents = snapshot.agents;
            for branch in snapshot.branches {
                let branch_id = branch.branch_id;
                inner.branches.insert(branch_id, branch);

                // Re-instantiate ephemeral incarnation with EVICTED physical state
                let seq = manager.next_sequence_id.fetch_add(1, Ordering::SeqCst);
                let mut inc = ExecutionIncarnation::new(new_incarnation_id, seq);
                inc.evict();
                inner.incarnations.insert(branch_id, inc);
            }
        }

        Ok(manager)
    }
}

impl AgentStateAbi for AgentStateManager {
    fn fork_branch(&self, parent: LogicalBranchId) -> Result<LogicalBranchId, StateError> {
        let mut inner = self.inner.write().unwrap();
        let parent_branch = inner
            .branches
            .get(&parent)
            .ok_or(StateError::ParentBranchNotFound(parent))?
            .clone();

        let counter = inner.branch_child_counters.entry(parent).or_insert(0);
        let child_idx = *counter;
        *counter += 1;

        let child_id = LogicalBranchId::derive(parent, child_idx);
        let child_branch = parent_branch.fork(child_id, 1000 + child_idx);

        inner.branches.insert(child_id, child_branch);

        let seq = self.next_sequence_id.fetch_add(1, Ordering::SeqCst);
        let incarnation_id = self.current_incarnation_id.load(Ordering::SeqCst);
        inner
            .incarnations
            .insert(child_id, ExecutionIncarnation::new(incarnation_id, seq));

        Ok(child_id)
    }

    fn checkpoint(&self, agent_id: LogicalAgentId) -> Result<CheckpointHash, StateError> {
        let bytes = self.export_checkpoint(agent_id)?;
        let envelope: CheckpointEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| StateError::SerializationError(e.to_string()))?;
        Ok(CheckpointHash(envelope.hash))
    }

    fn suspend(&mut self, branch_id: LogicalBranchId) -> Result<(), StateError> {
        let mut inner = self.inner.write().unwrap();
        if !inner.branches.contains_key(&branch_id) {
            return Err(StateError::BranchNotFound(branch_id));
        }
        let inc = inner
            .incarnations
            .get_mut(&branch_id)
            .ok_or(StateError::BranchNotFound(branch_id))?;

        if inc.physical_state.compute_state == ComputeState::Suspended {
            return Err(StateError::AlreadySuspended(branch_id));
        }

        inc.physical_state.compute_state = ComputeState::Suspended;
        Ok(())
    }

    fn resume(&mut self, branch_id: LogicalBranchId) -> Result<SequenceId, StateError> {
        let mut inner = self.inner.write().unwrap();
        if !inner.branches.contains_key(&branch_id) {
            return Err(StateError::BranchNotFound(branch_id));
        }

        let seq = self.next_sequence_id.fetch_add(1, Ordering::SeqCst);
        let inc = inner
            .incarnations
            .get_mut(&branch_id)
            .ok_or(StateError::BranchNotFound(branch_id))?;

        inc.sequence_id = seq;
        if inc.physical_state.compute_state == ComputeState::Suspended {
            inc.physical_state.compute_state = ComputeState::Idle;
        }

        Ok(seq)
    }

    fn reconstruct_physical(&mut self, branch_id: LogicalBranchId) -> Result<(), StateError> {
        let mut inner = self.inner.write().unwrap();
        let branch = inner
            .branches
            .get(&branch_id)
            .ok_or(StateError::BranchNotFound(branch_id))?
            .clone();

        let inc = inner
            .incarnations
            .get_mut(&branch_id)
            .ok_or(StateError::BranchNotFound(branch_id))?;

        // Reconstruct physical inference state deterministically from TokenHistory
        inc.physical_state.allocated_tokens_in_kv = branch.token_history.len();
        inc.physical_state.kv_page_table_ref = Some(0xDEAD_0000 + branch.token_history.len());
        inc.physical_state.compute_state = ComputeState::Decoding;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_reboot_and_reconstruction() {
        let manager = AgentStateManager::new(1);
        let agent_id = LogicalAgentId::from_seed("aienos-sovereign-agent");
        let root_branch = manager.register_agent(agent_id, 100);

        // Append 50 tokens
        let tokens: Vec<u32> = (1..=50).collect();
        manager.append_tokens(root_branch, &tokens).unwrap();

        // Fork branch
        let child_branch = manager.fork_branch(root_branch).unwrap();
        manager.append_tokens(child_branch, &[51, 52]).unwrap();

        // Add epistemic ref
        let ref_id = [7u8; 16];
        manager.add_epistemic_ref(child_branch, ref_id).unwrap();

        // Checkpoint agent
        let checkpoint_bytes = manager.export_checkpoint(agent_id).unwrap();
        let CheckpointHash(hash) = manager.checkpoint(agent_id).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // SIMULATE SOFT REBOOT: Host powers down, new manager boots with incarnation 2
        let mut rebooted_manager =
            AgentStateManager::restore_from_checkpoint(&checkpoint_bytes, 2).unwrap();

        // Verify logical identity intact
        let restored_root = rebooted_manager.get_branch(&root_branch).unwrap();
        assert_eq!(restored_root.agent_id, agent_id);
        assert_eq!(restored_root.token_history.len(), 50);

        let restored_child = rebooted_manager.get_branch(&child_branch).unwrap();
        assert_eq!(restored_child.parent_branch_id, Some(root_branch));
        assert_eq!(restored_child.token_history.len(), 52);
        assert!(restored_child.epistemic_refs.contains(&ref_id));

        // Physical state is evicted post-reboot
        let inc = rebooted_manager.get_incarnation(&child_branch).unwrap();
        assert_eq!(inc.incarnation_id, 2);
        assert_eq!(inc.physical_state.compute_state, ComputeState::Evicted);
        assert_eq!(inc.physical_state.allocated_tokens_in_kv, 0);

        // Resume and reconstruct physical inference state
        let new_seq = rebooted_manager.resume(child_branch).unwrap();
        assert!(new_seq > 0);

        rebooted_manager.reconstruct_physical(child_branch).unwrap();
        let inc_reconstructed = rebooted_manager.get_incarnation(&child_branch).unwrap();
        assert_eq!(
            inc_reconstructed.physical_state.compute_state,
            ComputeState::Decoding
        );
        assert_eq!(inc_reconstructed.physical_state.allocated_tokens_in_kv, 52);
        assert!(inc_reconstructed.physical_state.kv_page_table_ref.is_some());
    }

    #[test]
    fn test_suspend_resume_lifecycle_and_tamper_rejection() {
        let mut manager = AgentStateManager::new(1);
        let agent_id = LogicalAgentId::from_seed("suspend-test-agent");
        let branch = manager.register_agent(agent_id, 100);

        // Suspend branch
        manager.suspend(branch).expect("Suspend active branch");
        let inc = manager.get_incarnation(&branch).unwrap();
        assert_eq!(inc.physical_state.compute_state, ComputeState::Suspended);

        // Suspending already suspended branch must fail
        assert!(matches!(
            manager.suspend(branch),
            Err(StateError::AlreadySuspended(_))
        ));

        // Resume branch returns new sequence ID and transitions to Idle
        let seq = manager.resume(branch).expect("Resume branch");
        assert!(seq > 0);
        let inc_resumed = manager.get_incarnation(&branch).unwrap();
        assert_eq!(inc_resumed.physical_state.compute_state, ComputeState::Idle);

        // Tamper detection on checkpoint restore
        let mut valid_checkpoint = manager.export_checkpoint(agent_id).unwrap();
        // Corrupt one byte in payload JSON
        let last_idx = valid_checkpoint.len() - 5;
        valid_checkpoint[last_idx] ^= 0x55;

        let restore_result = AgentStateManager::restore_from_checkpoint(&valid_checkpoint, 2);
        assert!(
            matches!(
                restore_result,
                Err(StateError::ChecksumMismatch) | Err(StateError::DeserializationError(_))
            ),
            "Corrupted checkpoint must be detected and rejected"
        );
    }
}
