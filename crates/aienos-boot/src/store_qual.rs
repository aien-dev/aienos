//! Test-only Store-over-NVMe qualification plumbing.
//!
//! Bounded block device over the native NVMe controller plus canonical Store v1
//! genesis bytes. No production Store, NVMe, or recovery semantics are changed.

extern crate alloc;

use aienos_kernel::block::{BlockDevice, BlockError};
use aienos_kernel::nvme::driver::{Delay, DmaMemory, NvmeController};
use aienos_kernel::nvme::Registers;

/// Bounded Store region base LBA and size, in logical blocks.
pub const STORE_BASE_LBA: u64 = 64;
pub const STORE_REGION_BLOCKS: u64 = 256;
/// Control block LBA the host script writes to select the qualification mode.
pub const CONFIG_LBA: u64 = 32;

pub const MODE_VERIFY: u8 = 2;

/// Adds a fixed LBA offset and rejects accesses past the bounded region.
pub struct BoundedNvme<R: Registers, D: DmaMemory, T: Delay> {
    inner: NvmeController<R, D, T>,
    base_lba: u64,
    blocks: u64,
}

impl<R: Registers, D: DmaMemory, T: Delay> BoundedNvme<R, D, T> {
    pub fn new(inner: NvmeController<R, D, T>, base_lba: u64, blocks: u64) -> Self {
        Self {
            inner,
            base_lba,
            blocks,
        }
    }
}

impl<R: Registers, D: DmaMemory, T: Delay> BlockDevice for BoundedNvme<R, D, T> {
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }
    fn block_count(&self) -> u64 {
        self.blocks
    }
    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let bs = self.inner.block_size() as usize;
        if bs == 0 || !buffer.len().is_multiple_of(bs) {
            return Err(BlockError::InvalidInput);
        }
        let count = (buffer.len() / bs) as u64;
        if lba.checked_add(count).is_none_or(|end| end > self.blocks) {
            return Err(BlockError::OutOfRange);
        }
        self.inner.read_blocks(self.base_lba + lba, buffer)
    }
    fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let bs = self.inner.block_size() as usize;
        if bs == 0 || !buffer.len().is_multiple_of(bs) {
            return Err(BlockError::InvalidInput);
        }
        let count = (buffer.len() / bs) as u64;
        if lba.checked_add(count).is_none_or(|end| end > self.blocks) {
            return Err(BlockError::OutOfRange);
        }
        self.inner.write_blocks(self.base_lba + lba, buffer)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        self.inner.flush()
    }
}

pub const STORE_UNIT_BYTES: usize = 4096;

/// Canonical Store v1 genesis: Superblock A only (slot B is left all zero so
/// the first transaction exercises the "inactive slot initially zero" case),
/// an empty catalog at unit 2, and the CommitRecord at unit 3.
pub fn genesis_units(region_units: u64) -> [[u8; STORE_UNIT_BYTES]; 4] {
    use aienos_kernel::store::v1::{
        object_unit_count, Catalog, CommitRecord, ObjectId, Superblock, OBJECT_KIND_CATALOG,
        OBJECT_VERSION_V1,
    };

    let catalog = Catalog {
        entries: alloc::vec::Vec::new(),
    };
    let catalog_bytes = catalog.encode().expect("catalog encode");
    let catalog_id = ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &catalog_bytes)
        .expect("catalog id");
    let catalog_units = object_unit_count(catalog_bytes.len() as u64).expect("catalog units");
    let catalog_first = 2u64;
    let commit_unit = catalog_first + u64::from(catalog_units);
    let high_water = commit_unit + 1;
    let uuid = [0x5Au8; 16];

    let commit = CommitRecord {
        store_uuid: uuid,
        region_units,
        generation: 1,
        previous_generation: 0,
        previous_commit_id: ObjectId([0u8; 32]),
        previous_catalog_id: ObjectId([0u8; 32]),
        catalog_id,
        catalog_first_unit: catalog_first,
        catalog_byte_length: catalog_bytes.len() as u64,
        catalog_unit_count: catalog_units,
        catalog_entry_count: 0,
        committed_high_water: high_water,
    };
    let commit_bytes = commit.encode().expect("commit encode");
    let commit_id = commit.object_id().expect("commit id");

    let superblock = Superblock {
        store_uuid: uuid,
        slot_id: 0,
        region_units,
        generation: 1,
        commit_record_id: commit_id,
        commit_record_unit: commit_unit,
        catalog_id,
        catalog_first_unit: catalog_first,
        catalog_byte_length: catalog_bytes.len() as u64,
        catalog_unit_count: catalog_units,
        catalog_entry_count: 0,
        committed_high_water: high_water,
    };

    let mut out = [[0u8; STORE_UNIT_BYTES]; 4];
    out[0].copy_from_slice(&superblock.encode().expect("superblock encode"));
    out[2][..catalog_bytes.len()].copy_from_slice(&catalog_bytes);
    out[3][..commit_bytes.len()].copy_from_slice(&commit_bytes);
    out
}
