//! Minimal block device interface shared by storage drivers.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockError {
    InvalidInput,
    OutOfRange,
    DeviceError,
    Timeout,
}

pub trait BlockDevice {
    fn block_size(&self) -> u32;
    fn block_count(&self) -> u64;
    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError>;
    fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError>;
    fn flush(&mut self) -> Result<(), BlockError>;
}

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

/// Volatile memory disk. `fail_after` simulates a torn write by persisting only
/// the permitted prefix of each write, then returning an I/O error.
#[derive(Clone)]
pub struct RamDisk {
    bytes: Vec<u8>,
    block_size: usize,
    fail_after: Option<usize>,
    fail_write: Option<(usize, usize)>,
    write_count: usize,
    failed: bool,
}

impl RamDisk {
    pub fn new(block_size: usize, block_count: usize) -> Result<Self, BlockError> {
        if block_size < 64 || block_size > u32::MAX as usize || block_count < 4 {
            return Err(BlockError::InvalidInput);
        }
        Ok(Self {
            bytes: vec![
                0;
                block_size
                    .checked_mul(block_count)
                    .ok_or(BlockError::InvalidInput)?
            ],
            block_size,
            fail_after: None,
            fail_write: None,
            write_count: 0,
            failed: false,
        })
    }
    pub fn fail_after_blocks(&mut self, count: Option<usize>) {
        self.fail_after = count;
        self.fail_write = None;
        self.write_count = 0;
        self.failed = false;
    }
    /// Tear the selected write after persisting `bytes` of its input.
    /// Every write from that point onward fails.
    pub fn tear_write(&mut self, write_number: usize, bytes: usize) {
        self.fail_after = None;
        self.fail_write = Some((write_number.max(1), bytes));
        self.write_count = 0;
        self.failed = false;
    }
    pub fn corrupt_byte(&mut self, offset: usize, value: u8) -> Result<(), BlockError> {
        let byte = self.bytes.get_mut(offset).ok_or(BlockError::OutOfRange)?;
        *byte = value;
        Ok(())
    }
    fn range(&self, lba: u64, len: usize) -> Result<core::ops::Range<usize>, BlockError> {
        if !len.is_multiple_of(self.block_size) {
            return Err(BlockError::InvalidInput);
        }
        let start = usize::try_from(lba)
            .ok()
            .and_then(|n| n.checked_mul(self.block_size))
            .ok_or(BlockError::OutOfRange)?;
        let end = start.checked_add(len).ok_or(BlockError::OutOfRange)?;
        if end > self.bytes.len() {
            return Err(BlockError::OutOfRange);
        }
        Ok(start..end)
    }
}

impl BlockDevice for RamDisk {
    fn block_size(&self) -> u32 {
        self.block_size as u32
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
        if self.failed {
            return Err(BlockError::DeviceError);
        }
        if let Some(remaining) = self.fail_after {
            let block_count = data.len() / self.block_size;
            let allowed = remaining.min(block_count) * self.block_size;
            self.bytes[r.start..r.start + allowed].copy_from_slice(&data[..allowed]);
            if remaining < block_count {
                self.fail_after = Some(0);
                return Err(BlockError::DeviceError);
            }
            self.fail_after = Some(remaining - block_count);
            return Ok(());
        }
        self.write_count += 1;
        if let Some((write_number, bytes)) = self.fail_write {
            if self.write_count == write_number {
                let allowed = bytes.min(data.len());
                self.bytes[r.start..r.start + allowed].copy_from_slice(&data[..allowed]);
                self.failed = true;
                return Err(BlockError::DeviceError);
            }
        }
        self.bytes[r].copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_disk_rejects_block_size_that_would_truncate() {
        if usize::BITS > 32 {
            assert!(matches!(
                RamDisk::new(u32::MAX as usize + 1, 4),
                Err(BlockError::InvalidInput)
            ));
        }
    }
}
