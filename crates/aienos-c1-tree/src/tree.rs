//! C1 Copy-On-Write Prefix Tree engine (§10, §28).

use crate::metrics::C1MemoryMetrics;
use crate::page::{PageId, PAGE_CAPACITY_TOKENS};
use crate::pool::PhysicalPagePool;
use aienos_agent_state::LogicalBranchId;
use core::fmt;
use std::collections::HashMap;

/// Errors occurring during C1 prefix tree operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum C1Error {
    BranchNotFound(LogicalBranchId),
    BranchEvicted(LogicalBranchId),
    BranchAlreadyExists(LogicalBranchId),
    CorruptedPage(PageId),
    ReservationQuotaExceeded { requested: usize, available: usize },
}

impl fmt::Display for C1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BranchNotFound(b) => write!(f, "C1 branch not found: {}", b),
            Self::BranchEvicted(b) => {
                write!(f, "C1 branch physical KV is currently evicted: {}", b)
            }
            Self::BranchAlreadyExists(b) => write!(f, "C1 branch already exists: {}", b),
            Self::CorruptedPage(p) => write!(f, "Physical KV page corrupted: {}", p),
            Self::ReservationQuotaExceeded {
                requested,
                available,
            } => write!(
                f,
                "KV reservation quota exceeded: requested {} pages, available {}",
                requested, available
            ),
        }
    }
}

/// Transactional KV step reservation receipt (ADR 0005).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationReceipt {
    pub branch_id: LogicalBranchId,
    pub tokens_reserved: usize,
    pub pages_reserved: usize,
    pub reservation_tick: u64,
}

/// Descriptor tracking physical KV page table bindings for a reasoning branch.
#[derive(Clone, Debug)]
pub struct BranchDescriptor {
    pub branch_id: LogicalBranchId,
    pub page_ids: Vec<PageId>,
    pub total_tokens: usize,
    pub evicted: bool,
}

/// The C1 Prefix Tree: Bare-metal copy-on-write KV engine for agent branching.
#[derive(Default)]
pub struct C1PrefixTree {
    pool: PhysicalPagePool,
    branches: HashMap<LogicalBranchId, BranchDescriptor>,
}

impl C1PrefixTree {
    /// Initialize an empty C1 prefix tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Access underlying physical page pool.
    pub fn pool(&self) -> &PhysicalPagePool {
        &self.pool
    }

    /// Initialize a new root reasoning branch populated with a prompt token sequence.
    pub fn create_root_branch(
        &mut self,
        branch_id: LogicalBranchId,
        prompt_tokens: &[u32],
    ) -> Result<(), C1Error> {
        if self.branches.contains_key(&branch_id) {
            return Err(C1Error::BranchAlreadyExists(branch_id));
        }

        let mut desc = BranchDescriptor {
            branch_id,
            page_ids: Vec::new(),
            total_tokens: 0,
            evicted: false,
        };

        for &tok in prompt_tokens {
            Self::append_single_token(&mut self.pool, &mut desc, tok)?;
        }

        self.branches.insert(branch_id, desc);
        Ok(())
    }

    /// Fork an existing reasoning branch with ZERO memory duplication (§10).
    ///
    /// The child branch points directly to the parent's physical KV pages.
    /// Memory overhead of fork = 0 bytes!
    pub fn fork_branch(
        &mut self,
        parent_id: LogicalBranchId,
        child_id: LogicalBranchId,
    ) -> Result<(), C1Error> {
        let parent = self
            .branches
            .get(&parent_id)
            .ok_or(C1Error::BranchNotFound(parent_id))?
            .clone();

        if parent.evicted {
            return Err(C1Error::BranchEvicted(parent_id));
        }

        if self.branches.contains_key(&child_id) {
            return Err(C1Error::BranchAlreadyExists(child_id));
        }

        // Increment reference count on all shared physical pages
        for &pid in &parent.page_ids {
            self.pool.retain(pid);
        }

        let child = BranchDescriptor {
            branch_id: child_id,
            page_ids: parent.page_ids.clone(),
            total_tokens: parent.total_tokens,
            evicted: false,
        };

        self.branches.insert(child_id, child);
        Ok(())
    }

    /// Explicit transactional KV reservation prior to step admission (ADR 0005).
    pub fn reserve_step_capacity(
        &self,
        branch_id: LogicalBranchId,
        num_tokens: usize,
        tick: u64,
        max_pool_pages: usize,
    ) -> Result<ReservationReceipt, C1Error> {
        let desc = self
            .branches
            .get(&branch_id)
            .ok_or(C1Error::BranchNotFound(branch_id))?;

        if desc.evicted {
            return Err(C1Error::BranchEvicted(branch_id));
        }

        let needed_pages = num_tokens.div_ceil(PAGE_CAPACITY_TOKENS);
        let current_allocated = self.pool.allocated_page_count();
        if current_allocated + needed_pages > max_pool_pages {
            return Err(C1Error::ReservationQuotaExceeded {
                requested: needed_pages,
                available: max_pool_pages.saturating_sub(current_allocated),
            });
        }

        Ok(ReservationReceipt {
            branch_id,
            tokens_reserved: num_tokens,
            pages_reserved: needed_pages,
            reservation_tick: tick,
        })
    }

    /// Append tokens to an active reasoning branch, triggering Copy-On-Write only upon divergence.
    pub fn append_tokens(
        &mut self,
        branch_id: LogicalBranchId,
        tokens: &[u32],
    ) -> Result<(), C1Error> {
        let mut desc = self
            .branches
            .get(&branch_id)
            .ok_or(C1Error::BranchNotFound(branch_id))?
            .clone();

        if desc.evicted {
            return Err(C1Error::BranchEvicted(branch_id));
        }

        for &tok in tokens {
            Self::append_single_token(&mut self.pool, &mut desc, tok)?;
        }

        self.branches.insert(branch_id, desc);
        Ok(())
    }

    fn append_single_token(
        pool: &mut PhysicalPagePool,
        desc: &mut BranchDescriptor,
        token_id: u32,
    ) -> Result<(), C1Error> {
        if desc.page_ids.is_empty() {
            let pid = pool.allocate();
            let page = pool.get_mut(pid).unwrap();
            page.append(token_id);
            desc.page_ids.push(pid);
            desc.total_tokens += 1;
            return Ok(());
        }

        let last_pid = *desc.page_ids.last().unwrap();
        let page = pool.get(last_pid).ok_or(C1Error::CorruptedPage(last_pid))?;
        if !page.verify_checksum() {
            return Err(C1Error::CorruptedPage(last_pid));
        }

        if !page.is_full() {
            if page.ref_count == 1 {
                // Exclusive ownership: append directly
                let page_mut = pool.get_mut(last_pid).unwrap();
                page_mut.append(token_id);
            } else {
                // Shared page: perform Copy-On-Write!
                let new_pid = pool.clone_on_write(last_pid);
                let page_mut = pool.get_mut(new_pid).unwrap();
                page_mut.append(token_id);
                // Replace last page with private page in this branch
                let last_idx = desc.page_ids.len() - 1;
                desc.page_ids[last_idx] = new_pid;
            }
        } else {
            // Last page is full: allocate a brand new page
            let new_pid = pool.allocate();
            let page_mut = pool.get_mut(new_pid).unwrap();
            page_mut.append(token_id);
            desc.page_ids.push(new_pid);
        }

        desc.total_tokens += 1;
        Ok(())
    }

    /// Retrieve complete token sequence for a branch.
    pub fn get_tokens(&self, branch_id: LogicalBranchId) -> Result<Vec<u32>, C1Error> {
        let desc = self
            .branches
            .get(&branch_id)
            .ok_or(C1Error::BranchNotFound(branch_id))?;

        if desc.evicted {
            return Err(C1Error::BranchEvicted(branch_id));
        }

        let mut out = Vec::with_capacity(desc.total_tokens);
        for &pid in &desc.page_ids {
            let page = self.pool.get(pid).ok_or(C1Error::CorruptedPage(pid))?;
            if !page.verify_checksum() {
                return Err(C1Error::CorruptedPage(pid));
            }
            for i in 0..page.len {
                out.push(page.tokens[i]);
            }
        }
        Ok(out)
    }

    /// Evict physical KV pages for a branch to simulate memory reclamation.
    pub fn evict_branch(&mut self, branch_id: LogicalBranchId) -> Result<(), C1Error> {
        let desc = self
            .branches
            .get_mut(&branch_id)
            .ok_or(C1Error::BranchNotFound(branch_id))?;

        if desc.evicted {
            return Ok(());
        }

        for &pid in &desc.page_ids {
            self.pool.release(pid);
        }
        desc.page_ids.clear();
        desc.evicted = true;
        Ok(())
    }

    /// Remove and deallocate an exploratory or completed reasoning branch, releasing all its pages.
    pub fn remove_branch(&mut self, branch_id: LogicalBranchId) -> Result<(), C1Error> {
        let desc = self
            .branches
            .remove(&branch_id)
            .ok_or(C1Error::BranchNotFound(branch_id))?;

        if !desc.evicted {
            for &pid in &desc.page_ids {
                self.pool.release(pid);
            }
        }
        Ok(())
    }

    /// Reconstruct physical KV pages deterministically from token sequence.
    /// Re-allocates pages cleanly without leaking existing physical frames.
    pub fn reconstruct_branch(
        &mut self,
        branch_id: LogicalBranchId,
        tokens: &[u32],
    ) -> Result<(), C1Error> {
        let desc = self
            .branches
            .get_mut(&branch_id)
            .ok_or(C1Error::BranchNotFound(branch_id))?;

        if !desc.evicted {
            for &pid in &desc.page_ids {
                self.pool.release(pid);
            }
        }

        desc.page_ids.clear();
        desc.total_tokens = 0;
        desc.evicted = false;

        for &tok in tokens {
            Self::append_single_token(&mut self.pool, desc, tok)?;
        }

        Ok(())
    }

    /// Compute memory and sharing metrics across all branches.
    pub fn memory_metrics(&self) -> C1MemoryMetrics {
        let physical_pages = self.pool.allocated_page_count();
        let physical_bytes = self.pool.physical_memory_bytes();
        let total_virtual_tokens: usize = self.branches.values().map(|b| b.total_tokens).sum();
        let total_unique_physical_tokens: usize = physical_pages * PAGE_CAPACITY_TOKENS;

        let sharing_ratio = if total_unique_physical_tokens > 0 {
            total_virtual_tokens as f64 / total_unique_physical_tokens as f64
        } else {
            1.0
        };

        C1MemoryMetrics {
            physical_pages_allocated: physical_pages,
            physical_memory_bytes: physical_bytes,
            total_virtual_tokens,
            total_unique_physical_tokens,
            sharing_ratio,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aienos_agent_state::{LogicalAgentId, LogicalBranchId};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn test_zero_memory_increase_on_10k_tokens_fork() {
        let mut tree = C1PrefixTree::new();
        let agent = LogicalAgentId::from_seed("c1-cow-test");
        let root_branch = LogicalBranchId::root_branch(agent);

        // 1. Create a 10,000-token prompt
        let prompt_tokens: Vec<u32> = (0..10_000).map(|i| 1000 + (i % 50000)).collect();
        tree.create_root_branch(root_branch, &prompt_tokens)
            .unwrap();

        let initial_pages = tree.pool().allocated_page_count();
        let initial_bytes = tree.pool().physical_memory_bytes();
        assert_eq!(initial_pages, 10_000_usize.div_ceil(PAGE_CAPACITY_TOKENS));

        // 2. Fork into 10 concurrent exploratory branches
        let mut child_branches = Vec::new();
        for i in 0..10 {
            let child = LogicalBranchId::derive(root_branch, i);
            tree.fork_branch(root_branch, child).unwrap();
            child_branches.push(child);
        }

        // ACCEPTANCE CRITERIA VERIFICATION:
        // Demonstrates ZERO memory increase when branching a 10,000-token prefix across 10 concurrent exploratory branches!
        let post_fork_pages = tree.pool().allocated_page_count();
        let post_fork_bytes = tree.pool().physical_memory_bytes();
        assert_eq!(
            initial_pages, post_fork_pages,
            "Physical pages allocated must NOT increase upon branching"
        );
        assert_eq!(
            initial_bytes, post_fork_bytes,
            "Physical memory bytes must NOT increase upon branching (ZERO overhead)"
        );

        // 3. Verify deterministic divergence upon appending tokens
        for (i, &child) in child_branches.iter().enumerate() {
            tree.append_tokens(child, &[9999 + i as u32]).unwrap();
            let tokens = tree.get_tokens(child).unwrap();
            assert_eq!(tokens.len(), 10_001);
            assert_eq!(tokens[10_000], 9999 + i as u32);
        }

        // After appending 1 divergent token each, only private pages allocated for divergent step
        let post_divergence_pages = tree.pool().allocated_page_count();
        assert_eq!(post_divergence_pages, initial_pages + 10);
    }

    #[test]
    fn test_transactional_kv_reservation() {
        let mut tree = C1PrefixTree::new();
        let agent = LogicalAgentId::from_seed("reservation-test");
        let root = LogicalBranchId::root_branch(agent);
        tree.create_root_branch(root, &[1, 2, 3]).unwrap();

        // Limit pool to 10 pages total
        let receipt = tree.reserve_step_capacity(root, 64, 42, 10).unwrap();
        assert_eq!(receipt.pages_reserved, 1);
        assert_eq!(receipt.tokens_reserved, 64);

        // Try reserving more pages than available in quota
        let overflow = tree.reserve_step_capacity(root, 1000, 43, 10);
        assert!(matches!(
            overflow,
            Err(C1Error::ReservationQuotaExceeded { .. })
        ));
    }

    #[test]
    fn test_reconstruct_branch_no_page_leak() {
        let mut tree = C1PrefixTree::new();
        let agent = LogicalAgentId::from_seed("reconstruct-leak-test");
        let root = LogicalBranchId::root_branch(agent);
        tree.create_root_branch(root, &[10, 20, 30]).unwrap();
        let initial_pages = tree.pool().allocated_page_count();
        assert_eq!(initial_pages, 1);

        // Reconstructing an active branch must release previous pages and allocate clean ones without leak
        tree.reconstruct_branch(root, &[10, 20, 30]).unwrap();
        assert_eq!(tree.pool().allocated_page_count(), initial_pages);

        // Remove branch should release all pages back to 0
        tree.remove_branch(root).unwrap();
        assert_eq!(tree.pool().allocated_page_count(), 0);
    }

    #[test]
    fn test_concurrent_multithreaded_branching_and_reservations() {
        let tree = Arc::new(Mutex::new(C1PrefixTree::new()));
        let agent = LogicalAgentId::from_seed("concurrent-c1-agent");
        let root = LogicalBranchId::root_branch(agent);

        {
            let mut t = tree.lock().unwrap();
            let prompt: Vec<u32> = (0..128).collect();
            t.create_root_branch(root, &prompt).unwrap();
        }

        let mut handles = Vec::new();
        for worker_id in 0..8 {
            let tree_clone = Arc::clone(&tree);
            let handle = thread::spawn(move || {
                let child = LogicalBranchId::derive(root, worker_id);
                {
                    let mut t = tree_clone.lock().unwrap();
                    t.fork_branch(root, child).unwrap();
                }

                // Reserve capacity
                {
                    let t = tree_clone.lock().unwrap();
                    let res = t
                        .reserve_step_capacity(child, 16, 100 + worker_id, 1000)
                        .unwrap();
                    assert_eq!(res.tokens_reserved, 16);
                }

                // Append divergent tokens
                {
                    let mut t = tree_clone.lock().unwrap();
                    t.append_tokens(child, &[5000 + worker_id as u32]).unwrap();
                    let tokens = t.get_tokens(child).unwrap();
                    assert_eq!(tokens.len(), 129);
                    assert_eq!(tokens[128], 5000 + worker_id as u32);
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let t = tree.lock().unwrap();
        let metrics = t.memory_metrics();
        assert_eq!(metrics.total_virtual_tokens, 128 + 8 * 129);
        assert!(metrics.sharing_ratio > 1.0);
    }
}
