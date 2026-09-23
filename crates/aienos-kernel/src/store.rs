//! Host-tested implementation of ADR 0003 storage semantics.
//!
//! Note: This module provides a host-tested implementation of ADR 0003 storage semantics,
//! not yet native AIENOS storage on bare-metal block devices.
//!
//! Content-addressed extents (`model/<hash>`, `cortex/wal`, `agent/<id>`)
//! rather than a general-purpose POSIX filesystem.

use crate::crypto::sha256;

/// An immutable content-addressed storage extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtentDescriptor {
    pub hash: [u8; 32],
    pub offset: usize,
    pub length: usize,
}

/// Fixed-buffer Sovereign System Store for bare-metal `#![no_std]` substrate.
pub struct SystemStore<const CAPACITY: usize> {
    storage: [u8; CAPACITY],
    allocated: usize,
}

impl<const CAPACITY: usize> Default for SystemStore<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> SystemStore<CAPACITY> {
    /// Create a new sovereign system store over a fixed buffer.
    pub const fn new() -> Self {
        Self {
            storage: [0u8; CAPACITY],
            allocated: 0,
        }
    }

    /// Write an immutable content-addressed extent into store.
    pub fn write_extent(&mut self, payload: &[u8]) -> Option<ExtentDescriptor> {
        let new_allocated = self.allocated.checked_add(payload.len())?;
        if new_allocated > CAPACITY {
            return None;
        }

        let hash = sha256::hash(payload);
        let offset = self.allocated;
        let length = payload.len();

        self.storage[offset..new_allocated].copy_from_slice(payload);
        self.allocated = new_allocated;

        Some(ExtentDescriptor {
            hash,
            offset,
            length,
        })
    }

    /// Read an extent and verify its cryptographic integrity.
    pub fn read_extent<'a>(&'a self, desc: &ExtentDescriptor) -> Option<&'a [u8]> {
        let extent_end = desc.offset.checked_add(desc.length)?;
        if extent_end > self.allocated {
            return None;
        }

        let slice = &self.storage[desc.offset..extent_end];
        let actual_hash = sha256::hash(slice);
        if actual_hash != desc.hash {
            return None; // Integrity violation
        }

        Some(slice)
    }

    /// Total bytes currently stored.
    pub const fn allocated_bytes(&self) -> usize {
        self.allocated
    }

    /// Total capacity.
    pub const fn capacity(&self) -> usize {
        CAPACITY
    }
}

/// Slice-backed Sovereign System Store operating over caller-allocated memory
/// (e.g. static memory frame, DMA region, or heap buffer) without stack allocation risk.
pub struct SliceStore<'a> {
    storage: &'a mut [u8],
    allocated: usize,
}

impl<'a> SliceStore<'a> {
    /// Create a new store backed by an existing memory slice.
    pub fn new(storage: &'a mut [u8]) -> Self {
        Self {
            storage,
            allocated: 0,
        }
    }

    /// Write an immutable content-addressed extent into the memory slice.
    pub fn write_extent(&mut self, payload: &[u8]) -> Option<ExtentDescriptor> {
        let new_allocated = self.allocated.checked_add(payload.len())?;
        if new_allocated > self.storage.len() {
            return None;
        }

        let hash = sha256::hash(payload);
        let offset = self.allocated;
        let length = payload.len();

        self.storage[offset..new_allocated].copy_from_slice(payload);
        self.allocated = new_allocated;

        Some(ExtentDescriptor {
            hash,
            offset,
            length,
        })
    }

    /// Read an extent and verify its cryptographic integrity.
    pub fn read_extent(&self, desc: &ExtentDescriptor) -> Option<&[u8]> {
        let extent_end = desc.offset.checked_add(desc.length)?;
        if extent_end > self.allocated {
            return None;
        }

        let slice = &self.storage[desc.offset..extent_end];
        let actual_hash = sha256::hash(slice);
        if actual_hash != desc.hash {
            return None; // Integrity violation
        }

        Some(slice)
    }

    /// Total bytes allocated so far.
    pub fn allocated_bytes(&self) -> usize {
        self.allocated
    }

    /// Total available capacity.
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_addressed_extent_storage() {
        let mut store = SystemStore::<4096>::new();

        let model_header = b"AIENOS_MODEL_METADATA_v1:llama-3.2-1b";
        let desc = store.write_extent(model_header).expect("Write extent");

        let read_back = store.read_extent(&desc).expect("Read extent");
        assert_eq!(read_back, model_header);

        // Verify tamper detection
        let mut corrupted_desc = desc;
        corrupted_desc.hash[0] ^= 0xFF;
        assert!(store.read_extent(&corrupted_desc).is_none());
    }

    #[test]
    fn test_slice_store_operations_and_boundaries() {
        let mut mem = [0u8; 1024];
        let mut store = SliceStore::new(&mut mem);

        let data1 = b"cortex_snapshot_data_001";
        let desc1 = store.write_extent(data1).expect("Write data1");
        assert_eq!(store.read_extent(&desc1), Some(&data1[..]));

        // Capacity overflow check
        let huge_data = [0x55u8; 2048];
        assert!(store.write_extent(&huge_data).is_none());

        // Zero-length extent
        let empty_desc = store.write_extent(b"").expect("Write empty extent");
        assert_eq!(store.read_extent(&empty_desc), Some(&b""[..]));
    }
}
