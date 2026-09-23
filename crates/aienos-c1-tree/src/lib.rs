//! AIENOS C1 Copy-On-Write Prefix Tree (§10, §28).
//!
//! Provides zero-duplication prefix sharing across reasoning branches,
//! deterministic Copy-On-Write divergence, and complete eviction independence.

pub mod metrics;
pub mod page;
pub mod pool;
pub mod tree;

pub use metrics::C1MemoryMetrics;
pub use page::{PageId, PhysicalKvPage, PAGE_CAPACITY_TOKENS, PAGE_KV_BYTES};
pub use pool::PhysicalPagePool;
pub use tree::{BranchDescriptor, C1Error, C1PrefixTree, ReservationReceipt};
