//! Host-testable block device contract and in-memory disk.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockError {
    InvalidGeometry,
    OutOfBounds,
    BufferSize,
    Io,
}

pub trait BlockDevice {
    fn block_size(&self) -> usize;
    fn block_count(&self) -> u64;
    fn read_blocks(&mut self, lba: u64, blocks: &mut [u8]) -> Result<(), BlockError>;
    fn write_blocks(&mut self, lba: u64, blocks: &[u8]) -> Result<(), BlockError>;
    fn flush(&mut self) -> Result<(), BlockError>;
}

/// Volatile memory disk. `fail_after` simulates a torn write by persisting only
/// the permitted prefix of each write, then returning an I/O error.
#[derive(Clone)]
pub struct RamDisk {
    bytes: Vec<u8>,
    block_size: usize,
    fail_after: Option<usize>,
}

impl RamDisk {
    pub fn new(block_size: usize, block_count: usize) -> Result<Self, BlockError> {
        if block_size < 64 || block_count < 4 {
            return Err(BlockError::InvalidGeometry);
        }
        Ok(Self {
            bytes: vec![
                0;
                block_size
                    .checked_mul(block_count)
                    .ok_or(BlockError::InvalidGeometry)?
            ],
            block_size,
            fail_after: None,
        })
    }
    pub fn fail_after_blocks(&mut self, count: Option<usize>) {
        self.fail_after = count;
    }
    pub fn corrupt_byte(&mut self, offset: usize, value: u8) -> Result<(), BlockError> {
        let byte = self.bytes.get_mut(offset).ok_or(BlockError::OutOfBounds)?;
        *byte = value;
        Ok(())
    }
    fn range(&self, lba: u64, len: usize) -> Result<core::ops::Range<usize>, BlockError> {
        if !len.is_multiple_of(self.block_size) {
            return Err(BlockError::BufferSize);
        }
        let start = usize::try_from(lba)
            .ok()
            .and_then(|n| n.checked_mul(self.block_size))
            .ok_or(BlockError::OutOfBounds)?;
        let end = start.checked_add(len).ok_or(BlockError::OutOfBounds)?;
        if end > self.bytes.len() {
            return Err(BlockError::OutOfBounds);
        }
        Ok(start..end)
    }
}

impl BlockDevice for RamDisk {
    fn block_size(&self) -> usize {
        self.block_size
    }
    fn block_count(&self) -> u64 {
        (self.bytes.len() / self.block_size) as u64
    }
    fn read_blocks(&mut self, lba: u64, out: &mut [u8]) -> Result<(), BlockError> {
        let r = self.range(lba, out.len())?;
        out.copy_from_slice(&self.bytes[r]);
        Ok(())
    }
    fn write_blocks(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        let r = self.range(lba, data.len())?;
        if let Some(n) = self.fail_after {
            let count = data.len() / self.block_size;
            let allowed = n.min(count) * self.block_size;
            self.bytes[r.start..r.start + allowed].copy_from_slice(&data[..allowed]);
            if n < count {
                self.fail_after = Some(0);
                return Err(BlockError::Io);
            }
            self.fail_after = Some(n - count);
            return Ok(());
        }
        self.bytes[r].copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}
