//! Agent lineage provenance tracking and Cortex epistemic references.

use crate::id::{LogicalAgentId, LogicalBranchId};
use serde::{Deserialize, Serialize};

/// Provenance lineage tree path tracing back to Genesis root agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lineage {
    pub root_agent: LogicalAgentId,
    pub ancestor_branches: Vec<LogicalBranchId>,
    pub depth: usize,
}

impl Lineage {
    /// Create root lineage for an agent.
    pub fn new_root(root_agent: LogicalAgentId) -> Self {
        Self {
            root_agent,
            ancestor_branches: Vec::new(),
            depth: 0,
        }
    }

    /// Extend lineage with a new descendant branch.
    pub fn extend(&self, branch_id: LogicalBranchId) -> Self {
        let mut ancestors = self.ancestor_branches.clone();
        ancestors.push(branch_id);
        Self {
            root_agent: self.root_agent,
            ancestor_branches: ancestors,
            depth: self.depth + 1,
        }
    }

    /// Check if this branch is in the lineage.
    pub fn contains(&self, branch_id: &LogicalBranchId) -> bool {
        self.ancestor_branches.contains(branch_id)
    }
}

/// Set of Cortex observation/fact record UUIDs referenced by a reasoning branch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemicRefs {
    record_ids: Vec<[u8; 16]>,
}

impl EpistemicRefs {
    /// Create empty epistemic references set.
    pub fn new() -> Self {
        Self {
            record_ids: Vec::new(),
        }
    }

    /// Insert a Cortex record reference UUID.
    pub fn insert(&mut self, record_id: [u8; 16]) {
        if !self.record_ids.contains(&record_id) {
            self.record_ids.push(record_id);
        }
    }

    /// Check if a Cortex record is referenced.
    pub fn contains(&self, record_id: &[u8; 16]) -> bool {
        self.record_ids.contains(record_id)
    }

    /// Access all referenced record UUIDs.
    pub fn records(&self) -> &[[u8; 16]] {
        &self.record_ids
    }

    /// Count of referenced epistemic records.
    pub fn len(&self) -> usize {
        self.record_ids.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.record_ids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lineage_extension() {
        let agent = LogicalAgentId::from_seed("lineage-test");
        let root = Lineage::new_root(agent);
        assert_eq!(root.depth, 0);

        let b1 = LogicalBranchId::derive(LogicalBranchId::root_branch(agent), 1);
        let l1 = root.extend(b1);
        assert_eq!(l1.depth, 1);
        assert!(l1.contains(&b1));

        let b2 = LogicalBranchId::derive(b1, 2);
        let l2 = l1.extend(b2);
        assert_eq!(l2.depth, 2);
        assert!(l2.contains(&b1));
        assert!(l2.contains(&b2));
    }
}
