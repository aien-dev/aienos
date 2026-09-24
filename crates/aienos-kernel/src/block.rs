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
