//! Memory metrics for C1 Copy-On-Write Prefix Tree verification.

use serde::{Deserialize, Serialize};

/// Performance and memory metrics proving sub-linear scaling and zero-copy branching.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct C1MemoryMetrics {
    pub physical_pages_allocated: usize,
    pub physical_memory_bytes: usize,
    pub total_virtual_tokens: usize,
    pub total_unique_physical_tokens: usize,
    pub sharing_ratio: f64,
}
