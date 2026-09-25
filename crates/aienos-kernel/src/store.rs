//! Host-tested implementation of ADR 0003 storage semantics.
//!
//! Note: This module provides a host-tested implementation of ADR 0003 storage semantics,
//! not yet native AIENOS storage on bare-metal block devices.
//!
//! Content-addressed extents (`model/<hash>`, `cortex/wal`, `agent/<id>`)
//! rather than a general-purpose POSIX filesystem.

/// Canonical System Store v1 byte format. This module does not provide a
/// persistent transaction or mount implementation.
pub mod v1;

use crate::block::{BlockDevice, BlockError};
use crate::crypto::sha256;

const STORE_MAGIC: &[u8; 8] = b"AIENST01";
const WAL_MAGIC: &[u8; 8] = b"AIENWL01";

/// Latest committed extent on a block device. Payloads must fit in one block.
/// Blocks 0 and 1 are alternating superblocks; later blocks form the WAL ring.
pub struct BlockStore<D> {
    device: D,
    generation: u64,
    wal_lba: u64,
    length: usize,
    hash: [u8; 32],
}

impl<D: BlockDevice> BlockStore<D> {
    pub fn format(mut device: D) -> Result<Self, BlockError> {
        if (device.block_size() as usize) < 92 || device.block_count() < 5 {
            return Err(BlockError::InvalidInput);
        }
        let zero = alloc::vec![0; device.block_size() as usize];
        device.write_blocks(0, &zero)?;
        device.flush()?;
        device.write_blocks(1, &zero)?;
        device.flush()?;
        Ok(Self {
            device,
            generation: 0,
            wal_lba: 0,
            length: 0,
            hash: [0; 32],
        })
    }

    pub fn open(mut device: D) -> Result<Self, BlockError> {
        if (device.block_size() as usize) < 92 || device.block_count() < 5 {
            return Err(BlockError::InvalidInput);
        }
        let size = device.block_size() as usize;
        let mut best: Option<(u64, u64, usize, [u8; 32])> = None;
        let mut saw_data = false;
        for lba in 0..2 {
            let mut b = alloc::vec![0; size];
            device.read_blocks(lba, &mut b)?;
            if b.iter().all(|x| *x == 0) {
                continue;
            }
            saw_data = true;
            if &b[..8] != STORE_MAGIC || checksum(&b[..size - 32]) != b[size - 32..] {
                continue;
            }
            let generation = get_u64(&b, 8);
            let wal = get_u64(&b, 16);
            let len = get_u32(&b, 24) as usize;
            let mut hash = [0; 32];
            hash.copy_from_slice(&b[28..60]);
            if len > size.saturating_sub(84) || wal < 2 || wal >= device.block_count() {
                continue;
            }
            let mut record = alloc::vec![0; size];
            device.read_blocks(wal, &mut record)?;
            if &record[..8] != WAL_MAGIC
                || get_u64(&record, 8) != generation
                || get_u32(&record, 16) as usize != len
                || record[20..52] != hash
                || checksum(&record[..size - 32]) != record[size - 32..]
                || sha256::hash(&record[52..52 + len]) != hash
            {
                continue;
            }
            if best.is_none_or(|v| generation > v.0) {
                best = Some((generation, wal, len, hash));
            }
        }
        if let Some((generation, wal_lba, length, hash)) = best {
            Ok(Self {
                device,
                generation,
                wal_lba,
                length,
                hash,
            })
        } else if saw_data {
            Err(BlockError::DeviceError)
        } else {
            Self::format(device)
        }
    }

    /// Append and commit one extent. The returned descriptor addresses its WAL payload.
    pub fn write_extent(&mut self, payload: &[u8]) -> Result<ExtentDescriptor, BlockError> {
        let size = self.device.block_size() as usize;
        if payload.len() > size.saturating_sub(84) {
            return Err(BlockError::InvalidInput);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(BlockError::DeviceError)?;
        let wal = 2 + (generation - 1) % (self.device.block_count() - 2);
        let hash = sha256::hash(payload);
        let mut record = alloc::vec![0; size];
        record[..8].copy_from_slice(WAL_MAGIC);
        record[8..16].copy_from_slice(&generation.to_le_bytes());
        record[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        record[20..52].copy_from_slice(&hash);
        record[52..52 + payload.len()].copy_from_slice(payload);
        let sum = sha256::hash(&record[..size - 32]);
        record[size - 32..].copy_from_slice(&sum);
        self.device.write_blocks(wal, &record)?;
        self.device.flush()?;
        let mut sb = alloc::vec![0; size];
        sb[..8].copy_from_slice(STORE_MAGIC);
        sb[8..16].copy_from_slice(&generation.to_le_bytes());
        sb[16..24].copy_from_slice(&wal.to_le_bytes());
        sb[24..28].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        sb[28..60].copy_from_slice(&hash);
        let sum = sha256::hash(&sb[..size - 32]);
        sb[size - 32..].copy_from_slice(&sum);
        self.device.write_blocks(generation % 2, &sb)?;
        self.device.flush()?;
        self.generation = generation;
        self.wal_lba = wal;
        self.length = payload.len();
        self.hash = hash;
        Ok(ExtentDescriptor {
            hash,
            offset: wal as usize * size + 52,
            length: payload.len(),
        })
    }

    pub fn read_extent(&mut self) -> Result<Option<alloc::vec::Vec<u8>>, BlockError> {
        if self.generation == 0 {
            return Ok(None);
        }
        let size = self.device.block_size() as usize;
        if self.length > size.saturating_sub(84)
            || self.wal_lba < 2
            || self.wal_lba >= self.device.block_count()
        {
            return Err(BlockError::InvalidInput);
        }
        let mut b = alloc::vec![0; size];
        self.device.read_blocks(self.wal_lba, &mut b)?;
        if &b[..8] != WAL_MAGIC || get_u32(&b, 16) as usize != self.length {
            return Err(BlockError::InvalidInput);
        }
        let data = &b[52..52 + self.length];
        if sha256::hash(data) != self.hash {
            return Err(BlockError::DeviceError);
        }
        Ok(Some(data.to_vec()))
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn into_device(self) -> D {
        self.device
    }
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    sha256::hash(bytes)
}
fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

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
    use crate::block::RamDisk;

    #[test]
    fn block_store_persists_reopens_and_falls_back_from_bad_copy() {
        let disk = RamDisk::new(256, 12).unwrap();
        let mut store = BlockStore::format(disk).unwrap();
        store.write_extent(b"first committed payload").unwrap();
        store.write_extent(b"second committed payload").unwrap();
        let mut disk = store.into_device();
        // Generation two is in copy A (LBA 0); damage its checksum and use generation one.
        disk.corrupt_byte(256 - 1, 0x80).unwrap();
        let mut reopened = BlockStore::open(disk).unwrap();
        assert_eq!(reopened.generation(), 1);
        assert_eq!(
            reopened.read_extent().unwrap().unwrap(),
            b"first committed payload"
        );
    }

    #[test]
    fn block_store_rejects_wrong_magic() {
        let mut disk = RamDisk::new(256, 8).unwrap();
        disk.corrupt_byte(0, 0x7f).unwrap();
        assert!(matches!(
            BlockStore::open(disk),
            Err(BlockError::DeviceError)
        ));
    }

    #[test]
    fn block_store_crash_boundaries_keep_old_or_new_commit() {
        let mut formatted = BlockStore::format(RamDisk::new(256, 12).unwrap()).unwrap();
        formatted.write_extent(b"old state").unwrap();
        let base = formatted.into_device();
        let block_size = base.block_size() as usize;
        // write_extent issues exactly two single-block writes (WAL record, then the
        // superblock commit). Tear each one at every byte offset, 0..=block_size.
        for write_number in 1..=2 {
            for offset in 0..=block_size {
                let mut store = BlockStore::open(base.clone()).unwrap();
                store.device.tear_write(write_number, offset);
                assert!(store.write_extent(b"new state").is_err());
                let mut reopened = BlockStore::open(store.into_device()).unwrap();
                let value = reopened.read_extent().unwrap().unwrap();
                assert!(value == b"old state" || value == b"new state");
            }
        }
    }

    #[test]
    fn block_store_rejects_corrupt_in_memory_length_without_panicking() {
        let mut store = BlockStore::format(RamDisk::new(256, 8).unwrap()).unwrap();
        store.write_extent(b"committed").unwrap();
        store.length = usize::MAX;
        assert_eq!(store.read_extent(), Err(BlockError::InvalidInput));
    }

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
