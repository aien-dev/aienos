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

/// A checked view of a contiguous region of a block device.
///
/// The view exposes region-relative block numbers. The region is rejected
/// unless its start and length are aligned to a 4 KiB store unit and the
/// device uses one of the block sizes supported by Store v1.
pub struct BoundedBlockDevice<D> {
    inner: D,
    start_lba: u64,
    block_count: u64,
    block_size: u32,
}

impl<D: BlockDevice> BoundedBlockDevice<D> {
    pub fn new(inner: D, start_lba: u64, block_count: u64) -> Result<Self, BlockError> {
        let block_size = inner.block_size();
        let blocks_per_store_unit = match block_size {
            512 => 8,
            4096 => 1,
            _ => return Err(BlockError::InvalidInput),
        };

        if block_count == 0
            || !start_lba.is_multiple_of(blocks_per_store_unit)
            || !block_count.is_multiple_of(blocks_per_store_unit)
        {
            return Err(BlockError::InvalidInput);
        }

        let region_end = start_lba
            .checked_add(block_count)
            .ok_or(BlockError::OutOfRange)?;
        if region_end > inner.block_count() {
            return Err(BlockError::OutOfRange);
        }

        Ok(Self {
            inner,
            start_lba,
            block_count,
            block_size,
        })
    }

    pub fn region_start_lba(&self) -> u64 {
        self.start_lba
    }

    pub fn region_block_count(&self) -> u64 {
        self.block_count
    }

    pub fn into_store_device(self) -> StoreDevice<D> {
        StoreDevice { bounded: self }
    }

    fn translated_range(&self, local_lba: u64, buffer_len: usize) -> Result<u64, BlockError> {
        let block_size = usize::try_from(self.block_size).map_err(|_| BlockError::InvalidInput)?;
        if !buffer_len.is_multiple_of(block_size) {
            return Err(BlockError::InvalidInput);
        }
        let request_blocks =
            u64::try_from(buffer_len / block_size).map_err(|_| BlockError::OutOfRange)?;
        let local_end = local_lba
            .checked_add(request_blocks)
            .ok_or(BlockError::OutOfRange)?;
        if local_end > self.block_count {
            return Err(BlockError::OutOfRange);
        }
        self.start_lba
            .checked_add(local_lba)
            .ok_or(BlockError::OutOfRange)
    }
}

impl<D: BlockDevice> BlockDevice for BoundedBlockDevice<D> {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let translated_lba = self.translated_range(lba, buffer.len())?;
        self.inner.read_blocks(translated_lba, buffer)
    }

    fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let translated_lba = self.translated_range(lba, buffer.len())?;
        self.inner.write_blocks(translated_lba, buffer)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.inner.flush()
    }
}

/// Fixed 4 KiB block view used by System Store v1.
///
/// Store unit numbers are relative to the bounded region. A unit is mapped
/// directly to eight 512-byte device blocks or one 4096-byte device block;
/// this adapter never performs read-modify-write.
pub struct StoreDevice<D> {
    bounded: BoundedBlockDevice<D>,
}

impl<D: BlockDevice> StoreDevice<D> {
    pub const UNIT_BYTES: usize = 4096;

    pub fn unit_count(&self) -> u64 {
        match self.bounded.block_size {
            512 => self.bounded.block_count / 8,
            4096 => self.bounded.block_count,
            _ => 0, // BoundedBlockDevice::new makes this unreachable.
        }
    }

    pub fn read_units(&mut self, first_unit: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let first_block = self.validate_unit_range(first_unit, buffer.len())?;
        self.bounded.read_blocks(first_block, buffer)
    }

    pub fn write_units(&mut self, first_unit: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let first_block = self.validate_unit_range(first_unit, buffer.len())?;
        self.bounded.write_blocks(first_block, buffer)
    }

    pub fn flush(&mut self) -> Result<(), BlockError> {
        self.bounded.flush()
    }

    fn validate_unit_range(&self, first_unit: u64, buffer_len: usize) -> Result<u64, BlockError> {
        if !buffer_len.is_multiple_of(Self::UNIT_BYTES) {
            return Err(BlockError::InvalidInput);
        }
        let unit_count =
            u64::try_from(buffer_len / Self::UNIT_BYTES).map_err(|_| BlockError::OutOfRange)?;
        let unit_end = first_unit
            .checked_add(unit_count)
            .ok_or(BlockError::OutOfRange)?;
        if unit_end > self.unit_count() {
            return Err(BlockError::OutOfRange);
        }
        let blocks_per_unit = match self.bounded.block_size {
            512 => 8,
            4096 => 1,
            _ => return Err(BlockError::InvalidInput),
        };
        let first_block = first_unit
            .checked_mul(blocks_per_unit)
            .ok_or(BlockError::OutOfRange)?;
        Ok(first_block)
    }
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

    #[test]
    fn bounded_device_uses_region_relative_blocks_and_enforces_bounds() {
        let disk = RamDisk::new(512, 64).unwrap();
        let mut bounded = BoundedBlockDevice::new(disk, 8, 32).unwrap();
        assert_eq!(bounded.block_size(), 512);
        assert_eq!(bounded.block_count(), 32);

        let pattern = [0xa5; 512];
        bounded.write_blocks(0, &pattern).unwrap();
        let mut actual = [0; 512];
        bounded.read_blocks(0, &mut actual).unwrap();
        assert_eq!(actual, pattern);

        assert_eq!(
            bounded.read_blocks(32, &mut actual),
            Err(BlockError::OutOfRange)
        );
        assert_eq!(
            bounded.read_blocks(u64::MAX, &mut actual),
            Err(BlockError::OutOfRange)
        );
        assert_eq!(
            bounded.write_blocks(0, &[0; 513]),
            Err(BlockError::InvalidInput)
        );
    }

    #[test]
    fn bounded_region_requires_supported_block_size_and_unit_alignment() {
        let disk = RamDisk::new(512, 64).unwrap();
        assert!(matches!(
            BoundedBlockDevice::new(disk.clone(), 1, 8),
            Err(BlockError::InvalidInput)
        ));
        assert!(matches!(
            BoundedBlockDevice::new(disk.clone(), 8, 7),
            Err(BlockError::InvalidInput)
        ));
        assert!(matches!(
            BoundedBlockDevice::new(disk, 8, 0),
            Err(BlockError::InvalidInput)
        ));
        assert!(matches!(
            BoundedBlockDevice::new(RamDisk::new(1024, 16).unwrap(), 0, 8),
            Err(BlockError::InvalidInput)
        ));
    }

    #[test]
    fn bounded_region_must_fit_without_arithmetic_overflow() {
        struct HugeDevice;
        impl BlockDevice for HugeDevice {
            fn block_size(&self) -> u32 {
                512
            }
            fn block_count(&self) -> u64 {
                u64::MAX
            }
            fn read_blocks(&mut self, _: u64, _: &mut [u8]) -> Result<(), BlockError> {
                Ok(())
            }
            fn write_blocks(&mut self, _: u64, _: &[u8]) -> Result<(), BlockError> {
                Ok(())
            }
            fn flush(&mut self) -> Result<(), BlockError> {
                Ok(())
            }
        }

        assert!(matches!(
            BoundedBlockDevice::new(HugeDevice, u64::MAX - 7, 8),
            Err(BlockError::OutOfRange)
        ));
    }

    #[test]
    fn store_device_maps_units_for_512_and_4096_byte_devices() {
        let disk512 = RamDisk::new(512, 64).unwrap();
        let bounded512 = BoundedBlockDevice::new(disk512, 8, 32).unwrap();
        let mut store512 = bounded512.into_store_device();
        assert_eq!(store512.unit_count(), 4);
        store512.write_units(1, &[0x5a; 4096]).unwrap();
        let mut unit = [0; 4096];
        store512.read_units(1, &mut unit).unwrap();
        assert_eq!(unit, [0x5a; 4096]);
        assert_eq!(
            store512.read_units(4, &mut unit),
            Err(BlockError::OutOfRange)
        );
        assert_eq!(
            store512.read_units(0, &mut [0; 4097]),
            Err(BlockError::InvalidInput)
        );

        let disk4096 = RamDisk::new(4096, 16).unwrap();
        let bounded4096 = BoundedBlockDevice::new(disk4096, 2, 8).unwrap();
        let mut store4096 = bounded4096.into_store_device();
        assert_eq!(store4096.unit_count(), 8);
        store4096.write_units(7, &[0x3c; 4096]).unwrap();
        let mut last = [0; 4096];
        store4096.read_units(7, &mut last).unwrap();
        assert_eq!(last, [0x3c; 4096]);
        assert_eq!(store4096.write_units(8, &last), Err(BlockError::OutOfRange));
    }
}
