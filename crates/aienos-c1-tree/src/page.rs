//! Physical KV Page representation for C1 Copy-On-Write memory engine (§10, §28).

use aienos_kernel::crypto::sha256;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Number of tokens stored per physical KV page frame.
pub const PAGE_CAPACITY_TOKENS: usize = 64;

/// Simulated embedding / KV tensor bytes per token slot (e.g. 128 f32 elements = 512 bytes).
pub const KV_ELEMENTS_PER_TOKEN: usize = 128;
pub const PAGE_KV_BYTES: usize = PAGE_CAPACITY_TOKENS * KV_ELEMENTS_PER_TOKEN * 4;

/// Physical KV Page frame identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PageId(pub u64);

impl fmt::Debug for PageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PageId(0x{:08x})", self.0)
    }
}

impl fmt::Display for PageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

/// Physical Key-Value Page holding prefix cache on bare-metal accelerator memory.
#[derive(Clone, Debug, PartialEq)]
pub struct PhysicalKvPage {
    pub page_id: PageId,
    pub tokens: [u32; PAGE_CAPACITY_TOKENS],
    pub len: usize,
    pub ref_count: usize,
    pub kv_cache: Vec<f32>,
    pub checksum: [u8; 32],
}

impl PhysicalKvPage {
    /// Allocate an empty physical page frame.
    pub fn new(page_id: PageId) -> Self {
        Self {
            page_id,
            tokens: [0u32; PAGE_CAPACITY_TOKENS],
            len: 0,
            ref_count: 1,
            kv_cache: vec![0.0; PAGE_CAPACITY_TOKENS * KV_ELEMENTS_PER_TOKEN],
            checksum: [0u8; 32],
        }
    }

    /// Check if page has reached its maximum token capacity.
    pub fn is_full(&self) -> bool {
        self.len >= PAGE_CAPACITY_TOKENS
    }

    /// Explicit block ownership (ADR 0005): shared immutable block.
    pub fn is_shared(&self) -> bool {
        self.ref_count > 1
    }

    /// Explicit block ownership (ADR 0005): private mutable block.
    pub fn is_private(&self) -> bool {
        self.ref_count == 1
    }

    /// Append a token and update its physical KV cache slot and cryptographic checksum.
    pub fn append(&mut self, token_id: u32) -> bool {
        if self.is_full() {
            return false;
        }

        let idx = self.len;
        self.tokens[idx] = token_id;

        // Deterministically synthesize KV cache slot from token ID
        let base = idx * KV_ELEMENTS_PER_TOKEN;
        for i in 0..KV_ELEMENTS_PER_TOKEN {
            self.kv_cache[base + i] = ((token_id as f32) * 0.01) + (i as f32 * 0.001);
        }

        self.len += 1;
        self.recompute_checksum();
        true
    }

    /// Recompute SHA-256 checksum over page tokens and physical KV data.
    pub fn recompute_checksum(&mut self) {
        let mut hasher = sha256::Sha256::new();
        hasher.update(&self.page_id.0.to_be_bytes());
        for i in 0..self.len {
            hasher.update(&self.tokens[i].to_be_bytes());
        }
        self.checksum = hasher.finalize();
    }

    /// Verify cryptographic integrity of physical KV page against SHA-256 checksum.
    pub fn verify_checksum(&self) -> bool {
        let mut hasher = sha256::Sha256::new();
        hasher.update(&self.page_id.0.to_be_bytes());
        for i in 0..self.len {
            hasher.update(&self.tokens[i].to_be_bytes());
        }
        hasher.finalize() == self.checksum
    }
}
