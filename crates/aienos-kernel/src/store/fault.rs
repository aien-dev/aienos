//! Deterministic block-device fault injection for Store tests and qualification.
//!
//! This adapter is test infrastructure, not a production storage layer. A torn
//! write is modeled by persisting exactly the requested byte prefix and
//! preserving the pre-write bytes after that prefix. Since `BlockDevice` only
//! accepts whole logical blocks, a non-aligned prefix is emulated with a
//! bounded read/modify/write of its final logical block.

extern crate alloc;

use alloc::vec;

use crate::block::{BlockDevice, BlockError};

/// A one-shot failure on a one-based write call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteFault {
    /// Which write call should be faulted (the first call is 1).
    pub call: u64,
    /// Number of leading bytes to persist before returning `DeviceError`.
    /// Values greater than the write length persist the complete write and
    /// still return an error.
    pub persisted_prefix_bytes: usize,
}

/// A one-shot failure on a one-based flush call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlushFault {
    /// Which flush call should fail (the first call is 1).
    pub call: u64,
}

/// Faults to inject. Write and flush faults can be armed independently.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FaultPlan {
    pub write: Option<WriteFault>,
    pub flush: Option<FlushFault>,
}

/// A `BlockDevice` decorator that injects deterministic, one-shot failures.
///
/// The underlying device remains available through [`Self::into_inner`] after
/// a fault, allowing callers to discard volatile store state and reopen the
/// same media. Call counters include every attempted write/flush, whether or
/// not that operation is the selected fault point.
pub struct FaultInjectingDevice<D> {
    inner: D,
    plan: FaultPlan,
    write_calls: u64,
    flush_calls: u64,
}

impl<D> FaultInjectingDevice<D> {
    pub const fn new(inner: D, plan: FaultPlan) -> Self {
        Self {
            inner,
            plan,
            write_calls: 0,
            flush_calls: 0,
        }
    }

    pub const fn write_calls(&self) -> u64 {
        self.write_calls
    }

    pub const fn flush_calls(&self) -> u64 {
        self.flush_calls
    }

    pub const fn inner(&self) -> &D {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    pub fn set_plan(&mut self, plan: FaultPlan) {
        self.plan = plan;
    }

    /// Reset operation counters and arm a fresh plan without replacing media.
    pub fn reset(&mut self, plan: FaultPlan) {
        self.write_calls = 0;
        self.flush_calls = 0;
        self.plan = plan;
    }

    pub fn into_inner(self) -> D {
        self.inner
    }

    fn next_write_call(&mut self) -> Result<u64, BlockError> {
        self.write_calls = self
            .write_calls
            .checked_add(1)
            .ok_or(BlockError::DeviceError)?;
        Ok(self.write_calls)
    }

    fn next_flush_call(&mut self) -> Result<u64, BlockError> {
        self.flush_calls = self
            .flush_calls
            .checked_add(1)
            .ok_or(BlockError::DeviceError)?;
        Ok(self.flush_calls)
    }

    fn persist_prefix(
        &mut self,
        lba: u64,
        data: &[u8],
        prefix_bytes: usize,
    ) -> Result<(), BlockError>
    where
        D: BlockDevice,
    {
        let block_size =
            usize::try_from(self.inner.block_size()).map_err(|_| BlockError::InvalidInput)?;
        if block_size == 0 || !data.len().is_multiple_of(block_size) {
            return Err(BlockError::InvalidInput);
        }

        let prefix = prefix_bytes.min(data.len());
        let complete_bytes = prefix / block_size * block_size;
        let partial_bytes = prefix - complete_bytes;
        // Reject an unsupported sub-block tear before persisting even the
        // block-aligned prefix, so configuration errors cannot create a
        // misleading partial failure.
        if partial_bytes != 0 && block_size > 4096 {
            return Err(BlockError::InvalidInput);
        }
        if complete_bytes != 0 {
            self.inner.write_blocks(lba, &data[..complete_bytes])?;
        }

        if partial_bytes != 0 {
            // Bound scratch memory independently of the caller's write size.
            // Store qualification devices use 512- or 4096-byte logical
            // blocks; larger devices cannot model sub-block tears here.
            let partial_lba = lba
                .checked_add((complete_bytes / block_size) as u64)
                .ok_or(BlockError::OutOfRange)?;
            let mut block = vec![0; block_size];
            self.inner.read_blocks(partial_lba, &mut block)?;
            block[..partial_bytes]
                .copy_from_slice(&data[complete_bytes..complete_bytes + partial_bytes]);
            self.inner.write_blocks(partial_lba, &block)?;
        }

        Ok(())
    }
}

impl<D: BlockDevice> BlockDevice for FaultInjectingDevice<D> {
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.inner.read_blocks(lba, buffer)
    }

    fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let call = self.next_write_call()?;
        if self.plan.write.is_some_and(|fault| fault.call == call) {
            let fault = self.plan.write.take().ok_or(BlockError::DeviceError)?;
            self.persist_prefix(lba, buffer, fault.persisted_prefix_bytes)?;
            return Err(BlockError::DeviceError);
        }
        self.inner.write_blocks(lba, buffer)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        let call = self.next_flush_call()?;
        if self.plan.flush.is_some_and(|fault| fault.call == call) {
            self.plan.flush = None;
            return Err(BlockError::DeviceError);
        }
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::{vec, vec::Vec};

    struct TestDisk {
        bytes: Vec<u8>,
        block_size: usize,
    }

    impl TestDisk {
        fn new(block_size: usize, blocks: usize) -> Self {
            Self {
                bytes: vec![0; block_size * blocks],
                block_size,
            }
        }
    }

    impl BlockDevice for TestDisk {
        fn block_size(&self) -> u32 {
            self.block_size as u32
        }

        fn block_count(&self) -> u64 {
            (self.bytes.len() / self.block_size) as u64
        }

        fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            if !buffer.len().is_multiple_of(self.block_size) {
                return Err(BlockError::InvalidInput);
            }
            let start = usize::try_from(lba)
                .ok()
                .and_then(|block| block.checked_mul(self.block_size))
                .ok_or(BlockError::OutOfRange)?;
            let end = start
                .checked_add(buffer.len())
                .ok_or(BlockError::OutOfRange)?;
            let source = self.bytes.get(start..end).ok_or(BlockError::OutOfRange)?;
            buffer.copy_from_slice(source);
            Ok(())
        }

        fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
            if !buffer.len().is_multiple_of(self.block_size) {
                return Err(BlockError::InvalidInput);
            }
            let start = usize::try_from(lba)
                .ok()
                .and_then(|block| block.checked_mul(self.block_size))
                .ok_or(BlockError::OutOfRange)?;
            let end = start
                .checked_add(buffer.len())
                .ok_or(BlockError::OutOfRange)?;
            let target = self
                .bytes
                .get_mut(start..end)
                .ok_or(BlockError::OutOfRange)?;
            target.copy_from_slice(buffer);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            Ok(())
        }
    }

    #[test]
    fn torn_write_persists_exact_prefix_and_keeps_media_reopenable() {
        let original = [0x11; 512];
        let replacement = [0xA5; 512];
        let mut disk = TestDisk::new(512, 4);
        disk.write_blocks(1, &original).unwrap();
        let mut faulted = FaultInjectingDevice::new(
            disk,
            FaultPlan {
                write: Some(WriteFault {
                    call: 1,
                    persisted_prefix_bytes: 73,
                }),
                flush: None,
            },
        );

        assert_eq!(
            faulted.write_blocks(1, &replacement),
            Err(BlockError::DeviceError)
        );
        let mut disk = faulted.into_inner();
        let mut observed = [0; 512];
        disk.read_blocks(1, &mut observed).unwrap();
        assert_eq!(&observed[..73], &replacement[..73]);
        assert_eq!(&observed[73..], &original[73..]);
    }

    #[test]
    fn flush_failure_is_one_shot_and_counted() {
        let disk = TestDisk::new(512, 4);
        let mut faulted = FaultInjectingDevice::new(
            disk,
            FaultPlan {
                write: None,
                flush: Some(FlushFault { call: 2 }),
            },
        );

        assert_eq!(faulted.flush(), Ok(()));
        assert_eq!(faulted.flush(), Err(BlockError::DeviceError));
        assert_eq!(faulted.flush(), Ok(()));
        assert_eq!(faulted.flush_calls(), 3);
    }
}
