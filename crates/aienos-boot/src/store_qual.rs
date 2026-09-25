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

/// 512-byte LBA qualification constants.
pub const MODE_RUN_512B: u8 = 3;
pub const MODE_VERIFY_512B: u8 = 4;
pub const STORE_BASE_LBA_512: u64 = 512;
pub const STORE_REGION_BLOCKS_512: u64 = 2048;
pub const CONFIG_LBA_512: u64 = 256;

/// M4 continuity qualification modes (ADR 0016), 4096-byte LBA only.
/// Provision: format if blank, then create the one identity from RNDR.
#[cfg(feature = "continuity-qual")]
pub const MODE_CONT_PROVISION: u8 = 5;
/// Resume: locate and verify the identity, commit incarnation + 1. Never mints.
#[cfg(feature = "continuity-qual")]
pub const MODE_CONT_RESUME: u8 = 6;
/// Resume, then commit one Cortex fact and one branch fork.
#[cfg(feature = "continuity-qual")]
pub const MODE_CONT_REMEMBER: u8 = 7;
/// Resume, then commit one Cortex fact while emitting Store checkpoints.
#[cfg(feature = "continuity-qual")]
pub const MODE_CONT_CRASH: u8 = 8;

/// Recovery Core qualification modes (ADR 0006). The operator response, when
/// needed, is control-block bytes 16..48.
#[cfg(feature = "recovery-qual")]
pub const MODE_RECOVERY_INSPECT: u8 = 9;
#[cfg(feature = "recovery-qual")]
pub const MODE_RECOVERY_REPAIR: u8 = 10;
#[cfg(feature = "recovery-qual")]
pub const MODE_RECOVERY_PROVISION: u8 = 11;

#[cfg(feature = "recovery-qual")]
pub const fn is_recovery_mode(mode: u8) -> bool {
    matches!(
        mode,
        MODE_RECOVERY_INSPECT | MODE_RECOVERY_REPAIR | MODE_RECOVERY_PROVISION
    )
}

/// TEST ONLY operator key for the QEMU Recovery Core qualification. It is
/// public in this source tree and proves nothing about a real operator; the
/// real credential scheme (ADR 0006 / M5) is not decided. Every boot that uses
/// it prints `RECOVERY_OPERATOR_KEY: TEST-ONLY`.
#[cfg(feature = "recovery-qual")]
pub const TEST_ONLY_OPERATOR_KEY: [u8; 32] = [0x0f; 32];

#[cfg(feature = "continuity-qual")]
pub const fn is_continuity_mode(mode: u8) -> bool {
    matches!(
        mode,
        MODE_CONT_PROVISION | MODE_CONT_RESUME | MODE_CONT_REMEMBER | MODE_CONT_CRASH
    )
}

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
    aienos_kernel::store::genesis::genesis_units(QUAL_STORE_UUID, region_units)
}

/// Fixed test-only Store UUID used by the qualification images.
pub const QUAL_STORE_UUID: [u8; 16] = [0x5A; 16];
