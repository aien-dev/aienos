//! Sovereign cryptographic identities for agents and reasoning branches.

use aienos_kernel::crypto::sha256;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Sovereign Logical Agent Identifier (32-byte cryptographic key or UUIDv7 digest).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogicalAgentId(pub [u8; 32]);

impl LogicalAgentId {
    /// Construct a LogicalAgentId directly from 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Deterministically derive an agent ID from a canonical seed string.
    pub fn from_seed(seed: &str) -> Self {
        let prefix = b"AIENOS_AGENT_GENESIS_v1:";
        let seed_bytes = seed.as_bytes();
        let mut hasher = sha256::Sha256::new();
        hasher.update(prefix);
        hasher.update(seed_bytes);
        Self(hasher.finalize())
    }

    /// Return raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LogicalAgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentId({}", &self.to_string()[..12])?;
        write!(f, "...)")
    }
}

impl fmt::Display for LogicalAgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Deterministic Logical Branch Identifier derived from parent branch + branch index.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogicalBranchId(pub [u8; 32]);

impl LogicalBranchId {
    /// Construct directly from 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create root branch for an agent.
    pub fn root_branch(agent_id: LogicalAgentId) -> Self {
        let mut hasher = sha256::Sha256::new();
        hasher.update(b"AIENOS_ROOT_BRANCH_v1:");
        hasher.update(agent_id.as_bytes());
        Self(hasher.finalize())
    }

    /// Deterministically derive a child branch ID from a parent branch ID and a child index.
    pub fn derive(parent: LogicalBranchId, branch_index: u64) -> Self {
        let mut hasher = sha256::Sha256::new();
        hasher.update(b"AIENOS_CHILD_BRANCH_v1:");
        hasher.update(&parent.0);
        hasher.update(&branch_index.to_be_bytes());
        Self(hasher.finalize())
    }

    /// Return raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LogicalBranchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BranchId({}", &self.to_string()[..12])?;
        write!(f, "...)")
    }
}

impl fmt::Display for LogicalBranchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id_determinism() {
        let id1 = LogicalAgentId::from_seed("agent-alpha");
        let id2 = LogicalAgentId::from_seed("agent-alpha");
        let id3 = LogicalAgentId::from_seed("agent-beta");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_eq!(id1.to_string().len(), 64);
    }

    #[test]
    fn test_branch_id_derivation() {
        let agent = LogicalAgentId::from_seed("spark-agent");
        let root = LogicalBranchId::root_branch(agent);
        let child0 = LogicalBranchId::derive(root, 0);
        let child1 = LogicalBranchId::derive(root, 1);
        let child0_repeat = LogicalBranchId::derive(root, 0);

        assert_eq!(child0, child0_repeat);
        assert_ne!(child0, child1);
        assert_ne!(root, child0);
    }
}
