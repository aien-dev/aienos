//! ADR 0015 geometry adapter for StoreDevice.
//!
//! Maps an underlying `BlockDevice` with a 512-byte or 4096-byte logical block size
//! to sovereign 4096-byte Store units. Rejects all other block sizes and forbids
//! read-modify-write emulation.

use crate::block::{BlockDevice, BlockError};
pub use crate::store::engine::StoreDevice;
pub use crate::store::v1::STORE_UNIT_BYTES;

pub const STORE_UNIT_BLOCKS_512: u64 = 8;
pub const STORE_UNIT_BLOCKS_4096: u64 = 1;

/// Errors returned by [`StoreDeviceAdapter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreDeviceError {
    /// Device has an unsupported logical block size.
    UnsupportedBlockSize(u32),
    /// Requested unit index or range is outside the provisioned region.
    OutOfBounds,
    /// Buffer length is not an exact multiple of the Store unit size (4096 bytes).
    InvalidBufferSize(usize),
    /// Calculation resulted in arithmetic overflow.
    UnitOverflow,
    /// Underlying block device error.
    Block(BlockError),
}

impl core::fmt::Display for StoreDeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedBlockSize(bs) => write!(f, "unsupported block size: {bs}"),
            Self::OutOfBounds => write!(f, "unit index out of bounds"),
            Self::InvalidBufferSize(len) => {
                write!(
                    f,
                    "invalid buffer size {len}, must be multiple of {STORE_UNIT_BYTES}"
                )
            }
            Self::UnitOverflow => write!(f, "unit arithmetic overflow"),
            Self::Block(err) => write!(f, "block device error: {err:?}"),
        }
    }
}

impl From<BlockError> for StoreDeviceError {
    fn from(err: BlockError) -> Self {
        Self::Block(err)
    }
}

/// Geometry adapter exposing 4096-byte Store units over an underlying [`BlockDevice`].
#[derive(Clone, Debug)]
pub struct StoreDeviceAdapter<D> {
    device: D,
    block_size: u32,
    blocks_per_unit: u64,
    region_units: u64,
}

impl<D: BlockDevice> StoreDeviceAdapter<D> {
    /// Constructs a new adapter over `device`.
    ///
    /// Validates that the device logical block size is exactly 512 or 4096 bytes.
    /// Otherwise returns [`StoreDeviceError::UnsupportedBlockSize`].
    pub fn new(device: D) -> Result<Self, StoreDeviceError> {
        let block_size = device.block_size();
        let blocks_per_unit = match block_size {
            512 => STORE_UNIT_BLOCKS_512,
            4096 => STORE_UNIT_BLOCKS_4096,
            other => return Err(StoreDeviceError::UnsupportedBlockSize(other)),
        };
        let region_units = device.block_count() / blocks_per_unit;
        Ok(Self {
            device,
            block_size,
            blocks_per_unit,
            region_units,
        })
    }

    /// Number of full 4096-byte Store units in this region.
    #[inline]
    pub fn region_units(&self) -> u64 {
        self.region_units
    }

    /// Underlying device logical block size (512 or 4096).
    #[inline]
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Reads exactly one 4096-byte Store unit.
    pub fn read_unit(
        &mut self,
        unit: u64,
        out: &mut [u8; STORE_UNIT_BYTES],
    ) -> Result<(), StoreDeviceError> {
        self.read_units(unit, out)
    }

    /// Writes exactly one 4096-byte Store unit.
    pub fn write_unit(
        &mut self,
        unit: u64,
        bytes: &[u8; STORE_UNIT_BYTES],
    ) -> Result<(), StoreDeviceError> {
        self.write_units(unit, bytes)
    }

    /// Reads one or more contiguous 4096-byte Store units.
    ///
    /// Buffer length must be a multiple of 4096 bytes.
    pub fn read_units(&mut self, start_unit: u64, out: &mut [u8]) -> Result<(), StoreDeviceError> {
        if !out.len().is_multiple_of(STORE_UNIT_BYTES) {
            return Err(StoreDeviceError::InvalidBufferSize(out.len()));
        }
        let count = (out.len() / STORE_UNIT_BYTES) as u64;
        let end_unit = start_unit
            .checked_add(count)
            .ok_or(StoreDeviceError::UnitOverflow)?;
        if end_unit > self.region_units {
            return Err(StoreDeviceError::OutOfBounds);
        }
        if count == 0 {
            return Ok(());
        }
        let start_lba = start_unit
            .checked_mul(self.blocks_per_unit)
            .ok_or(StoreDeviceError::UnitOverflow)?;
        self.device.read_blocks(start_lba, out)?;
        Ok(())
    }

    /// Writes one or more contiguous 4096-byte Store units.
    ///
    /// Buffer length must be a multiple of 4096 bytes.
    pub fn write_units(&mut self, start_unit: u64, bytes: &[u8]) -> Result<(), StoreDeviceError> {
        if !bytes.len().is_multiple_of(STORE_UNIT_BYTES) {
            return Err(StoreDeviceError::InvalidBufferSize(bytes.len()));
        }
        let count = (bytes.len() / STORE_UNIT_BYTES) as u64;
        let end_unit = start_unit
            .checked_add(count)
            .ok_or(StoreDeviceError::UnitOverflow)?;
        if end_unit > self.region_units {
            return Err(StoreDeviceError::OutOfBounds);
        }
        if count == 0 {
            return Ok(());
        }
        let start_lba = start_unit
            .checked_mul(self.blocks_per_unit)
            .ok_or(StoreDeviceError::UnitOverflow)?;
        self.device.write_blocks(start_lba, bytes)?;
        Ok(())
    }

    /// Flushes dirty blocks to persistent storage.
    pub fn flush(&mut self) -> Result<(), StoreDeviceError> {
        self.device.flush().map_err(StoreDeviceError::Block)
    }

    /// Consumes the adapter and returns the underlying block device.
    pub fn into_inner(self) -> D {
        self.device
    }

    /// Borrows the underlying block device.
    pub fn inner(&self) -> &D {
        &self.device
    }

    /// Mutably borrows the underlying block device.
    pub fn inner_mut(&mut self) -> &mut D {
        &mut self.device
    }
}

impl<D: BlockDevice> StoreDevice for StoreDeviceAdapter<D> {
    type Error = StoreDeviceError;

    fn region_units(&self) -> u64 {
        self.region_units()
    }

    fn read_unit(
        &mut self,
        unit: u64,
        out: &mut [u8; STORE_UNIT_BYTES],
    ) -> Result<(), Self::Error> {
        self.read_unit(unit, out)
    }

    fn write_unit(&mut self, unit: u64, bytes: &[u8; STORE_UNIT_BYTES]) -> Result<(), Self::Error> {
        self.write_unit(unit, bytes)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.flush()
    }
}
