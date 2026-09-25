//! Polled NVMe admin controller initialization and Identify commands.

use crate::block::BlockError;
use alloc::vec;
use alloc::vec::Vec;

use super::{
    build_prps, doorbell_offset, Cap, Completion, ControllerError, Registers, Submission, CC_EN,
    CSTS_CFS, CSTS_RDY, REG_ACQ, REG_AQA, REG_ASQ, REG_CC, REG_CSTS,
};

use super::atomicity::{self, AtomicityFields};

pub const PAGE_SIZE: usize = 4096;
pub const ADMIN_DEPTH: usize = 8;
/// Admin commands complete quickly; bound the wait in real time.
const ADMIN_TIMEOUT_MS: u32 = 1000;

/// Real-time delay used to bound register and completion polling.
pub trait Delay {
    fn delay_us(&mut self, us: u32);
}

/// Wait for CSTS.RDY to equal `want`, polling every 1 ms for up to
/// `timeout_ms`. CSTS.CFS aborts immediately.
fn wait_ready<R: Registers, T: Delay>(
    registers: &mut R,
    delay: &mut T,
    want: bool,
    timeout_ms: u32,
) -> Result<(), ControllerError> {
    for _ in 0..=timeout_ms {
        let status = registers.read32(REG_CSTS);
        if status & CSTS_CFS != 0 {
            return Err(ControllerError::Failed);
        }
        if (status & CSTS_RDY != 0) == want {
            return Ok(());
        }
        delay.delay_us(1000);
    }
    Err(ControllerError::Timeout)
}
const CC_NVM: u32 = 0 << 4;
const CC_MPS_4K: u32 = 0 << 7;
const CC_IOSQES_64: u32 = 6 << 16;
const CC_IOCQES_16: u32 = 4 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeError {
    Controller(ControllerError),
    Dma,
    Timeout,
    CompletionStatus {
        sct: u8,
        sc: u8,
    },
    InvalidIdentify,
    InvalidQueueDepth,
    /// The controller needs a memory page size larger than the 4 KiB the
    /// driver programs into CC.MPS (CAP.MPSMIN != 0), or another base
    /// property this read substrate does not support.
    UnsupportedController,
}

/// A zeroed, physically contiguous DMA allocation and its CPU byte view.
pub struct DmaRegion {
    pub physical: u64,
    pub bytes: Vec<u8>,
}

pub trait DmaMemory {
    fn allocate(&mut self, size: usize, alignment: usize) -> Result<DmaRegion, NvmeError>;
    fn read(&self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError>;
    fn write(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceInfo {
    pub block_count: u64,
    pub block_size: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoQueueState {
    pub depth: u16,
    pub submission_tail: usize,
    pub completion_head: usize,
    pub phase: bool,
    pub submission_doorbell: u32,
    pub completion_doorbell: u32,
}

pub struct NvmeController<R: Registers, D: DmaMemory, T: Delay> {
    pub registers: R,
    pub dma: D,
    delay: T,
    cap: Cap,
    sq: DmaRegion,
    cq: DmaRegion,
    identify: DmaRegion,
    sq_tail: usize,
    cq_head: usize,
    phase: bool,
    next_cid: u16,
    io_cq: Option<DmaRegion>,
    io_sq: Option<DmaRegion>,
    io_queue: Option<IoQueueState>,
    mdts: u8,
    namespace: Option<NamespaceInfo>,
    awupf_raw: Option<u16>,
    nawupf_raw: Option<u16>,
    nabspf_raw: Option<u16>,
    nabo_blocks: u16,
}

impl<R: Registers, D: DmaMemory, T: Delay> NvmeController<R, D, T> {
    /// Reset and enable the controller. Ready waits honour CAP.TO (500 ms units).
    pub fn init(mut registers: R, mut dma: D, mut delay: T) -> Result<Self, NvmeError> {
        let cap = Cap(((registers.read32(4) as u64) << 32) | registers.read32(0) as u64);
        // The driver programs CC.MPS for a 4 KiB memory page (CC_MPS_4K) and
        // builds 4 KiB queues, so a controller that demands a larger minimum
        // page size is refused rather than mis-programmed.
        if cap.mpsmin() != 0 {
            return Err(NvmeError::UnsupportedController);
        }
        let timeout_ms = u32::from(cap.timeout_units().max(1)) * 500;
        let cc = registers.read32(REG_CC);
        registers.write32(REG_CC, cc & !CC_EN);
        wait_ready(&mut registers, &mut delay, false, timeout_ms).map_err(NvmeError::Controller)?;
        let sq = dma.allocate(PAGE_SIZE, PAGE_SIZE)?;
        let cq = dma.allocate(PAGE_SIZE, PAGE_SIZE)?;
        let identify = dma.allocate(PAGE_SIZE, PAGE_SIZE)?;
        registers.write32(
            REG_AQA,
            ((ADMIN_DEPTH as u32 - 1) << 16) | (ADMIN_DEPTH as u32 - 1),
        );
        registers.write32(REG_ASQ, sq.physical as u32);
        registers.write32(REG_ASQ + 4, (sq.physical >> 32) as u32);
        registers.write32(REG_ACQ, cq.physical as u32);
        registers.write32(REG_ACQ + 4, (cq.physical >> 32) as u32);
        let cc = CC_NVM | CC_MPS_4K | CC_IOSQES_64 | CC_IOCQES_16 | CC_EN;
        registers.write32(REG_CC, cc);
        wait_ready(&mut registers, &mut delay, true, timeout_ms).map_err(NvmeError::Controller)?;
        let mut controller = Self {
            registers,
            dma,
            delay,
            cap,
            sq,
            cq,
            identify,
            sq_tail: 0,
            cq_head: 0,
            phase: true,
            next_cid: 1,
            io_cq: None,
            io_sq: None,
            io_queue: None,
            mdts: 0,
            namespace: None,
            awupf_raw: None,
            nawupf_raw: None,
            nabspf_raw: None,
            nabo_blocks: 0,
        };
        controller.identify_controller()?;
        controller.identify_namespace(1)?;
        Ok(controller)
    }

    pub fn identify_controller(&mut self) -> Result<(), NvmeError> {
        let bytes = self.submit_identify(0, 1)?;
        self.mdts = bytes[77];
        // NVMe 1.4 Identify Controller: AWUPF is a 0-based power-fail atomic
        // write unit in logical blocks.
        self.awupf_raw = atomicity::read_u16_le(&bytes, atomicity::ID_CTRL_AWUPF_OFFSET);
        Ok(())
    }

    pub fn identify_namespace(&mut self, nsid: u32) -> Result<NamespaceInfo, NvmeError> {
        let bytes = self.submit_identify(nsid, 0)?;
        let block_count = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let flbas = (bytes[26] & 0x0f) as usize;
        let descriptor = 128 + flbas * 4;
        let lbads = *bytes
            .get(descriptor + 2)
            .ok_or(NvmeError::InvalidIdentify)?;
        // NVMe LBA sizes are 512 bytes (lbads 9) through 2^31; anything smaller
        // is not a valid data block size.
        if block_count == 0 || !(9..=31).contains(&lbads) {
            return Err(NvmeError::InvalidIdentify);
        }
        let info = NamespaceInfo {
            block_count,
            block_size: 1u32 << lbads,
        };
        self.namespace = Some(info);
        // NVMe 1.4 Identify Namespace: NAWUPF/NABO/NABSPF, all little-endian.
        // NAWUPF 0h means the controller AWUPF applies; NABSPF 0h means no
        // atomic boundary.
        self.nawupf_raw = atomicity::read_u16_le(&bytes, atomicity::ID_NS_NAWUPF_OFFSET);
        self.nabo_blocks =
            atomicity::read_u16_le(&bytes, atomicity::ID_NS_NABO_OFFSET).unwrap_or(0);
        self.nabspf_raw = atomicity::read_u16_le(&bytes, atomicity::ID_NS_NABSPF_OFFSET);
        Ok(info)
    }

    /// The effective power-fail atomicity contract for the identified
    /// namespace, or `None` before a namespace has been identified.
    pub fn atomicity(&self) -> Option<AtomicityFields> {
        let namespace = self.namespace?;
        Some(AtomicityFields {
            lba_bytes: namespace.block_size,
            awupf_raw: self.awupf_raw,
            nawupf_raw: self.nawupf_raw,
            nabspf_raw: self.nabspf_raw,
            nabo_blocks: self.nabo_blocks,
        })
    }

    /// Create polled I/O completion and submission queues, both with QID 1.
    pub fn create_io_queues(&mut self, depth: u16) -> Result<(), NvmeError> {
        // NVMe requires at least 2 entries, and the queue may not exceed the
        // controller's advertised maximum (CAP.MQES + 1).
        if depth < 2 || depth > self.cap.mqes() {
            return Err(NvmeError::InvalidQueueDepth);
        }
        let size = usize::from(depth).checked_mul(16).ok_or(NvmeError::Dma)?;
        let cq = self.dma.allocate(size, PAGE_SIZE)?;
        let sq = self.dma.allocate(
            usize::from(depth).checked_mul(64).ok_or(NvmeError::Dma)?,
            PAGE_SIZE,
        )?;
        self.submit_admin(Submission::create_io_cq(1, depth, cq.physical))?;
        self.submit_admin(Submission::create_io_sq(1, depth, sq.physical, 1))?;
        self.io_cq = Some(cq);
        self.io_sq = Some(sq);
        let stride = self.cap.doorbell_stride();
        self.io_queue = Some(IoQueueState {
            depth,
            submission_tail: 0,
            completion_head: 0,
            phase: true,
            submission_doorbell: doorbell_offset(1, false, stride),
            completion_doorbell: doorbell_offset(1, true, stride),
        });
        Ok(())
    }

    pub fn io_queue(&self) -> Option<IoQueueState> {
        self.io_queue
    }

    fn submit_admin(&mut self, command: Submission) -> Result<(), NvmeError> {
        self.submit_admin_inner(command)?;
        Ok(())
    }

    fn submit_admin_inner(&mut self, mut command: Submission) -> Result<Vec<u8>, NvmeError> {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        command.set_u32(0, (command.u32_at(0) & 0xffff) | ((cid as u32) << 16));
        let offset = self.sq_tail * 64;
        self.sq.bytes[offset..offset + 64].copy_from_slice(&command.0);
        self.dma
            .write(self.sq.physical + offset as u64, &command.0)?;
        self.sq_tail = (self.sq_tail + 1) % ADMIN_DEPTH;
        self.registers.write32(
            doorbell_offset(0, false, self.cap.doorbell_stride()),
            self.sq_tail as u32,
        );
        for _ in 0..=ADMIN_TIMEOUT_MS {
            let mut raw = [0u8; 16];
            self.dma
                .read(self.cq.physical + (self.cq_head * 16) as u64, &mut raw)?;
            let completion = Completion(raw);
            if completion.phase() != self.phase {
                self.delay.delay_us(1000);
                continue;
            }
            if completion.command_id() != cid {
                return Err(NvmeError::InvalidIdentify);
            }
            let status = completion.status() >> 1;
            if status != 0 {
                return Err(NvmeError::CompletionStatus {
                    sct: ((status >> 8) & 7) as u8,
                    sc: (status & 0xff) as u8,
                });
            }
            self.cq_head += 1;
            if self.cq_head == ADMIN_DEPTH {
                self.cq_head = 0;
                self.phase = !self.phase;
            }
            self.registers.write32(
                doorbell_offset(0, true, self.cap.doorbell_stride()),
                self.cq_head as u32,
            );
            let mut data = vec![0; PAGE_SIZE];
            self.dma.read(self.identify.physical, &mut data)?;
            return Ok(data);
        }
        Err(NvmeError::Timeout)
    }

    fn submit_identify(&mut self, nsid: u32, cns: u32) -> Result<Vec<u8>, NvmeError> {
        self.identify.bytes.fill(0);
        self.dma
            .write(self.identify.physical, &self.identify.bytes)?;
        let command = if cns == 1 {
            Submission::identify_controller(self.identify.physical)
        } else {
            Submission::identify_namespace(nsid, self.identify.physical)
        };
        self.submit_admin_inner(command)
    }

    fn ensure_namespace(&mut self) -> Result<NamespaceInfo, BlockError> {
        match self.namespace {
            Some(info) => Ok(info),
            None => self.identify_namespace(1).map_err(map_error),
        }
    }

    fn transfer(
        &mut self,
        nsid: u32,
        write: bool,
        lba: u64,
        data: &mut [u8],
    ) -> Result<(), BlockError> {
        let info = self.ensure_namespace()?;
        let block_size = info.block_size as usize;
        if data.is_empty() || !data.len().is_multiple_of(block_size) {
            return Err(BlockError::InvalidInput);
        }
        let blocks =
            u64::try_from(data.len() / block_size).map_err(|_| BlockError::InvalidInput)?;
        if lba
            .checked_add(blocks)
            .filter(|end| *end <= info.block_count)
            .is_none()
        {
            return Err(BlockError::OutOfRange);
        }
        let mdts_limit = if self.mdts == 0 {
            128 * 1024
        } else {
            (PAGE_SIZE
                .checked_shl(u32::from(self.mdts))
                .unwrap_or(usize::MAX))
            .min(128 * 1024)
        };
        let chunk_limit = mdts_limit / block_size * block_size;
        if chunk_limit == 0 {
            return Err(BlockError::InvalidInput);
        }
        let mut offset = 0usize;
        while offset < data.len() {
            let len = (data.len() - offset).min(chunk_limit);
            let count = len / block_size;
            let mut region = self.dma.allocate(len, PAGE_SIZE).map_err(map_error)?;
            if write {
                region.bytes[..len].copy_from_slice(&data[offset..offset + len]);
                self.dma
                    .write(region.physical, &region.bytes[..len])
                    .map_err(map_error)?;
            }
            let list_pages = len.div_ceil(PAGE_SIZE);
            let list_region = if list_pages > 2 {
                Some(self.dma.allocate(PAGE_SIZE, PAGE_SIZE).map_err(map_error)?)
            } else {
                None
            };
            let mut list = alloc::vec![0u64; PAGE_SIZE / 8];
            let list_address = list_region.as_ref().map_or(0, |r| r.physical);
            let (p1, p2, used) =
                build_prps(region.physical, len, PAGE_SIZE, list_address, &mut list)
                    .map_err(|_| BlockError::InvalidInput)?;
            if let Some(ref list_mem) = list_region {
                let bytes =
                    unsafe { core::slice::from_raw_parts(list.as_ptr() as *const u8, used * 8) };
                self.dma
                    .write(list_mem.physical, bytes)
                    .map_err(map_error)?;
            }
            self.submit_io(if write {
                Submission::write(
                    nsid,
                    lba + (offset / block_size) as u64,
                    count as u16,
                    p1,
                    p2,
                )
            } else {
                Submission::read(
                    nsid,
                    lba + (offset / block_size) as u64,
                    count as u16,
                    p1,
                    p2,
                )
            })?;
            if !write {
                self.dma
                    .read(region.physical, &mut data[offset..offset + len])
                    .map_err(map_error)?;
            }
            offset += len;
        }
        Ok(())
    }

    fn submit_io(&mut self, mut command: Submission) -> Result<(), BlockError> {
        let q = self.io_queue.as_mut().ok_or(BlockError::DeviceError)?;
        let sq = self.io_sq.as_mut().ok_or(BlockError::DeviceError)?;
        let cq = self.io_cq.as_ref().ok_or(BlockError::DeviceError)?;
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        command.set_u32(0, (command.u32_at(0) & 0xffff) | (u32::from(cid) << 16));
        let offset = q.submission_tail * 64;
        sq.bytes[offset..offset + 64].copy_from_slice(&command.0);
        self.dma
            .write(sq.physical + offset as u64, &command.0)
            .map_err(map_error)?;
        q.submission_tail = (q.submission_tail + 1) % usize::from(q.depth);
        self.registers
            .write32(q.submission_doorbell, q.submission_tail as u32);
        for _ in 0..=1000 {
            let mut raw = [0u8; 16];
            self.dma
                .read(cq.physical + (q.completion_head * 16) as u64, &mut raw)
                .map_err(map_error)?;
            let c = Completion(raw);
            if c.phase() != q.phase {
                self.delay.delay_us(1000);
                continue;
            }
            if c.command_id() != cid {
                return Err(BlockError::DeviceError);
            }
            let status = c.status() >> 1;
            q.completion_head = (q.completion_head + 1) % usize::from(q.depth);
            if q.completion_head == 0 {
                q.phase = !q.phase;
            }
            self.registers
                .write32(q.completion_doorbell, q.completion_head as u32);
            return if status == 0 {
                Ok(())
            } else {
                Err(BlockError::DeviceError)
            };
        }
        Err(BlockError::Timeout)
    }
}

fn map_error(error: NvmeError) -> BlockError {
    match error {
        NvmeError::Timeout => BlockError::Timeout,
        NvmeError::Dma => BlockError::DeviceError,
        NvmeError::CompletionStatus { .. } => BlockError::DeviceError,
        _ => BlockError::DeviceError,
    }
}

impl<R: Registers, D: DmaMemory, T: Delay> crate::block::BlockDevice for NvmeController<R, D, T> {
    fn block_size(&self) -> u32 {
        self.namespace.map_or(0, |n| n.block_size)
    }
    fn block_count(&self) -> u64 {
        self.namespace.map_or(0, |n| n.block_count)
    }
    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.transfer(1, false, lba, buffer)
    }
    fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
        let mut owned = buffer.to_vec();
        self.transfer(1, true, lba, &mut owned)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        self.submit_io({
            let mut c = Submission::zeroed();
            c.set_u32(0, 0);
            c.set_u32(1, 1);
            c
        })
    }
}

impl<R: Registers, D: DmaMemory, T: Delay> NvmeController<R, D, T> {
    /// Read `buffer` from an explicit namespace id. The `BlockDevice` trait
    /// path fixes NSID 1; this exists so a caller (and the qualification
    /// phase) can exercise the invalid-namespace error path and any future
    /// multi-namespace use without special-casing the driver.
    pub fn read_blocks_nsid(
        &mut self,
        nsid: u32,
        lba: u64,
        buffer: &mut [u8],
    ) -> Result<(), BlockError> {
        self.transfer(nsid, false, lba, buffer)
    }

    /// Write `buffer` to an explicit namespace id. See `read_blocks_nsid`.
    pub fn write_blocks_nsid(
        &mut self,
        nsid: u32,
        lba: u64,
        buffer: &[u8],
    ) -> Result<(), BlockError> {
        let mut owned = buffer.to_vec();
        self.transfer(nsid, true, lba, &mut owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    use std::vec;

    type Shared = Rc<RefCell<BTreeMap<u64, Vec<u8>>>>;

    struct FakeDma {
        shared: Shared,
        next: u64,
    }
    impl DmaMemory for FakeDma {
        fn allocate(&mut self, size: usize, alignment: usize) -> Result<DmaRegion, NvmeError> {
            assert_eq!(alignment, PAGE_SIZE);
            let physical = self.next;
            self.next = (self.next + size as u64 + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
            self.shared.borrow_mut().insert(physical, vec![0; size]);
            Ok(DmaRegion {
                physical,
                bytes: vec![0; size],
            })
        }
        fn read(&self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError> {
            let memory = self.shared.borrow();
            let (base, bytes) = memory
                .range(..=physical)
                .next_back()
                .ok_or(NvmeError::Dma)?;
            let offset = (physical - base) as usize;
            output.copy_from_slice(
                bytes
                    .get(offset..offset + output.len())
                    .ok_or(NvmeError::Dma)?,
            );
            Ok(())
        }
        fn write(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> {
            let mut memory = self.shared.borrow_mut();
            let (base, bytes) = memory
                .range_mut(..=physical)
                .next_back()
                .ok_or(NvmeError::Dma)?;
            let offset = (physical - *base) as usize;
            bytes
                .get_mut(offset..offset + input.len())
                .ok_or(NvmeError::Dma)?
                .copy_from_slice(input);
            Ok(())
        }
    }

    struct FakeRegs {
        shared: Shared,
        status: u32,
        cc: u32,
        writes: Vec<(u32, u32)>,
        namespace_size: u64,
        completion_status: u16,
        never_ready: bool,
        ready_after_reads: u32,
        fatal: bool,
        cq_tail: usize,
        sq_tail: usize,
        cq_ids: Vec<u16>,
        command_error: u16,
        disk: Vec<u8>,
        io_sq: Option<u64>,
        io_cq: Option<u64>,
        io_cq_tail: usize,
        io_sq_tail: usize,
        io_phase: bool,
        /// CAP high dword (offset 4). Bits 16..20 carry CAP.MPSMIN.
        cap_high: u32,
        /// LBA data size (lbads) the fake reports for namespace 1.
        lbads: u8,
        awupf: u16,
        nawupf: u16,
        nabspf: u16,
        nabo: u16,
    }
    impl Registers for FakeRegs {
        fn read32(&mut self, offset: u32) -> u32 {
            match offset {
                0 => 0x0100_03ff, // CAP.TO = 1 (500 ms), MQES = 1023
                4 => self.cap_high,
                REG_CC => self.cc,
                REG_CSTS => {
                    if self.ready_after_reads > 0 && self.cc & CC_EN != 0 {
                        self.ready_after_reads -= 1;
                        return self.status & !CSTS_RDY;
                    }
                    self.status
                }
                _ => 0,
            }
        }
        fn write32(&mut self, offset: u32, value: u32) {
            self.writes.push((offset, value));
            if offset == REG_CC {
                self.cc = value;
                self.status = if value & CC_EN == 0 {
                    0
                } else if self.fatal {
                    CSTS_CFS
                } else if self.never_ready {
                    0
                } else {
                    CSTS_RDY
                };
            }
            if offset == doorbell_offset(0, false, 4) {
                let mut memory = self.shared.borrow_mut();
                let sq = u64::from_le_bytes([
                    self.writes.iter().find(|(r, _)| *r == REG_ASQ).unwrap().1 as u8,
                    (self.writes.iter().find(|(r, _)| *r == REG_ASQ).unwrap().1 >> 8) as u8,
                    (self.writes.iter().find(|(r, _)| *r == REG_ASQ).unwrap().1 >> 16) as u8,
                    (self.writes.iter().find(|(r, _)| *r == REG_ASQ).unwrap().1 >> 24) as u8,
                    self.writes
                        .iter()
                        .find(|(r, _)| *r == REG_ASQ + 4)
                        .unwrap()
                        .1 as u8,
                    (self
                        .writes
                        .iter()
                        .find(|(r, _)| *r == REG_ASQ + 4)
                        .unwrap()
                        .1
                        >> 8) as u8,
                    (self
                        .writes
                        .iter()
                        .find(|(r, _)| *r == REG_ASQ + 4)
                        .unwrap()
                        .1
                        >> 16) as u8,
                    (self
                        .writes
                        .iter()
                        .find(|(r, _)| *r == REG_ASQ + 4)
                        .unwrap()
                        .1
                        >> 24) as u8,
                ]);
                let command_offset = self.sq_tail * 64;
                let command =
                    memory.get(&sq).unwrap()[command_offset..command_offset + 64].to_vec();
                let cid = u16::from_le_bytes([command[2], command[3]]);
                let prp = u64::from_le_bytes(command[24..32].try_into().unwrap());
                let opcode = u32::from_le_bytes(command[0..4].try_into().unwrap()) as u8;
                let cdw10 = u32::from_le_bytes(command[40..44].try_into().unwrap());
                let cdw11 = u32::from_le_bytes(command[44..48].try_into().unwrap());
                self.command_error = 0;
                match opcode {
                    0x06 => {
                        let cns = cdw10;
                        let data = memory.get_mut(&prp).unwrap();
                        if cns == 0 {
                            data[0..8].copy_from_slice(&self.namespace_size.to_le_bytes());
                            data[26] = 0;
                            data[130] = self.lbads;
                            data[36..38].copy_from_slice(&self.nawupf.to_le_bytes());
                            data[42..44].copy_from_slice(&self.nabo.to_le_bytes());
                            data[44..46].copy_from_slice(&self.nabspf.to_le_bytes());
                        } else if cns == 1 {
                            data[528..530].copy_from_slice(&self.awupf.to_le_bytes());
                        }
                    }
                    0x05 => {
                        assert_eq!(cdw10, 1 | (3 << 16)); // QID 1, depth 4 minus one
                        assert_eq!(cdw11, 1); // PC=1, IEN=0
                        self.cq_ids.push(1);
                        self.io_cq = Some(prp);
                    }
                    0x01 if cdw10 & 0xffff == 1 && cdw11 & 0xffff == 1 => {
                        assert_eq!(cdw10, 1 | (3 << 16));
                        assert_eq!(cdw11, 1 | (1 << 16));
                        if !self.cq_ids.contains(&1) {
                            self.command_error = 1 << 1;
                        }
                        self.io_sq = Some(prp);
                    }
                    _ => panic!("unexpected admin opcode {opcode:#x}"),
                }
                let cq = u64::from_le_bytes([
                    self.writes.iter().find(|(r, _)| *r == REG_ACQ).unwrap().1 as u8,
                    (self.writes.iter().find(|(r, _)| *r == REG_ACQ).unwrap().1 >> 8) as u8,
                    (self.writes.iter().find(|(r, _)| *r == REG_ACQ).unwrap().1 >> 16) as u8,
                    (self.writes.iter().find(|(r, _)| *r == REG_ACQ).unwrap().1 >> 24) as u8,
                    self.writes
                        .iter()
                        .find(|(r, _)| *r == REG_ACQ + 4)
                        .unwrap()
                        .1 as u8,
                    (self
                        .writes
                        .iter()
                        .find(|(r, _)| *r == REG_ACQ + 4)
                        .unwrap()
                        .1
                        >> 8) as u8,
                    (self
                        .writes
                        .iter()
                        .find(|(r, _)| *r == REG_ACQ + 4)
                        .unwrap()
                        .1
                        >> 16) as u8,
                    (self
                        .writes
                        .iter()
                        .find(|(r, _)| *r == REG_ACQ + 4)
                        .unwrap()
                        .1
                        >> 24) as u8,
                ]);
                let cqe = memory.get_mut(&cq).unwrap();
                let completion_offset = self.cq_tail * 16;
                cqe[completion_offset + 12..completion_offset + 14]
                    .copy_from_slice(&cid.to_le_bytes());
                cqe[completion_offset + 14..completion_offset + 16].copy_from_slice(
                    &(1 | self.completion_status | self.command_error).to_le_bytes(),
                );
                self.cq_tail = (self.cq_tail + 1) % ADMIN_DEPTH;
                self.sq_tail = (self.sq_tail + 1) % ADMIN_DEPTH;
            }
            if offset == doorbell_offset(1, false, 4) {
                let mut memory = self.shared.borrow_mut();
                let sq = self.io_sq.expect("I/O SQ created");
                let cq = self.io_cq.expect("I/O CQ created");
                let command_offset = self.io_sq_tail * 64;
                let command =
                    memory.get(&sq).unwrap()[command_offset..command_offset + 64].to_vec();
                let opcode = command[0];
                let cid = u16::from_le_bytes(command[2..4].try_into().unwrap());
                let nsid = u32::from_le_bytes(command[4..8].try_into().unwrap());
                let p1 = u64::from_le_bytes(command[24..32].try_into().unwrap());
                let p2 = u64::from_le_bytes(command[32..40].try_into().unwrap());
                let lba = u64::from(u32::from_le_bytes(command[40..44].try_into().unwrap()))
                    | (u64::from(u32::from_le_bytes(command[44..48].try_into().unwrap())) << 32);
                let len =
                    (u32::from_le_bytes(command[48..52].try_into().unwrap()) as usize + 1) * 512;
                self.command_error = 0;
                if nsid != 1 {
                    self.command_error = 1 << 1;
                }
                if opcode == 0x01 || opcode == 0x02 {
                    let mut addresses = vec![p1];
                    let first = (PAGE_SIZE - (p1 as usize & (PAGE_SIZE - 1))).min(len);
                    let remaining = len.saturating_sub(first);
                    if remaining > 0 {
                        if p2 != 0 && remaining <= PAGE_SIZE {
                            addresses.push(p2);
                        } else {
                            let mut list_page = p2;
                            let mut left = remaining;
                            while left > 0 {
                                let entries = memory.get(&list_page).unwrap();
                                for i in 0..PAGE_SIZE / 8 {
                                    let address = u64::from_le_bytes(
                                        entries[i * 8..i * 8 + 8].try_into().unwrap(),
                                    );
                                    if address == 0 {
                                        break;
                                    }
                                    if i == PAGE_SIZE / 8 - 1 && left > PAGE_SIZE {
                                        list_page = address;
                                        break;
                                    }
                                    addresses.push(address);
                                    left = left.saturating_sub(PAGE_SIZE);
                                    if left == 0 {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    let disk_start = lba as usize * 512;
                    let mut done = 0;
                    for address in addresses {
                        if done == len {
                            break;
                        }
                        let n = (len - done).min(PAGE_SIZE - (address as usize & (PAGE_SIZE - 1)));
                        let disk = &mut self.disk[disk_start + done..disk_start + done + n];
                        let data = memory.range_mut(..=address).next_back().unwrap();
                        let off = (address - *data.0) as usize;
                        let dma = &mut data.1[off..off + n];
                        if opcode == 0x01 {
                            disk.copy_from_slice(dma);
                        } else {
                            dma.copy_from_slice(disk);
                        }
                        done += n;
                    }
                } else if opcode != 0x00 {
                    self.command_error = 1 << 1;
                }
                let cqe = memory.get_mut(&cq).unwrap();
                let at = self.io_cq_tail * 16;
                cqe[at + 12..at + 14].copy_from_slice(&cid.to_le_bytes());
                cqe[at + 14..at + 16].copy_from_slice(
                    &((self.io_phase as u16) | self.completion_status | self.command_error)
                        .to_le_bytes(),
                );
                self.io_cq_tail = (self.io_cq_tail + 1) % 4;
                if self.io_cq_tail == 0 {
                    self.io_phase = !self.io_phase;
                }
                self.io_sq_tail = (self.io_sq_tail + 1) % 4;
            }
        }
    }

    fn fixture() -> (FakeRegs, FakeDma) {
        let shared = Rc::new(RefCell::new(BTreeMap::new()));
        (
            FakeRegs {
                shared: shared.clone(),
                status: 0,
                cc: 0,
                writes: Vec::new(),
                namespace_size: 12345,
                completion_status: 0,
                never_ready: false,
                ready_after_reads: 0,
                fatal: false,
                cq_tail: 0,
                sq_tail: 0,
                cq_ids: Vec::new(),
                command_error: 0,
                disk: vec![0; 12345 * 512],
                io_sq: None,
                io_cq: None,
                io_cq_tail: 0,
                io_sq_tail: 0,
                io_phase: true,
                cap_high: 0,
                lbads: 9,
                awupf: 0,
                nawupf: 0,
                nabspf: 0,
                nabo: 0,
            },
            FakeDma {
                shared,
                next: 0x1000,
            },
        )
    }

    /// Host stand-in for a real-time delay: counts 1 ms waits instead of sleeping.
    #[derive(Default)]
    struct CountingDelay {
        waited_us: u64,
    }
    impl Delay for CountingDelay {
        fn delay_us(&mut self, us: u32) {
            self.waited_us += u64::from(us);
        }
    }

    #[test]
    fn readiness_wait_honours_cap_timeout() {
        // CAP.TO = 1 (500 ms). Ready after 200 status reads (~200 ms): must succeed,
        // where a fixed 100-read poll limit would have reported a timeout.
        let (mut regs, dma) = fixture();
        regs.ready_after_reads = 200;
        let controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        let waited = controller.delay.waited_us;
        assert!((199_000..=201_000).contains(&waited), "waited {waited} us");
        // Never ready: gives up after about CAP.TO x 500 ms, not sooner.
        let (mut regs, dma) = fixture();
        regs.never_ready = true;
        let mut delay = CountingDelay::default();
        let mut regs2 = regs;
        regs2.write32(REG_CC, CC_EN);
        assert_eq!(
            wait_ready(&mut regs2, &mut delay, true, 500),
            Err(ControllerError::Timeout)
        );
        assert_eq!(delay.waited_us, 501_000);
        let _ = dma;
    }

    #[test]
    fn parses_power_fail_atomicity_fields() {
        use super::atomicity::AtomicityDecision;
        let (mut regs, dma) = fixture();
        regs.awupf = 7; // 8 blocks
        regs.nawupf = 3; // 4 blocks: namespace overrides
        regs.nabspf = 7; // boundary size 8 blocks
        regs.nabo = 0;
        let controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        let a = controller.atomicity().expect("atomicity after identify");
        assert_eq!(a.lba_bytes, 512);
        assert_eq!(a.awupf_raw, Some(7));
        assert_eq!(a.nawupf_raw, Some(3));
        assert_eq!(a.nabspf_raw, Some(7));
        assert_eq!(a.nabo_blocks, 0);
        assert_eq!(a.effective_power_fail_blocks(), Some(4));
        assert_eq!(a.store_unit_lba(1), Some((8, 8)));
        assert!(matches!(
            a.store_root_decision(0),
            AtomicityDecision::NotAtomic(_)
        ));
    }

    #[test]
    fn initializes_and_identifies_namespace() {
        let (regs, dma) = fixture();
        let mut controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        assert_eq!(
            controller
                .registers
                .writes
                .iter()
                .find(|(r, _)| *r == REG_AQA)
                .unwrap()
                .1,
            0x0007_0007
        );
        assert_eq!(
            controller
                .registers
                .writes
                .iter()
                .rev()
                .find(|(r, _)| *r == REG_CC)
                .unwrap()
                .1,
            CC_IOSQES_64 | CC_IOCQES_16 | CC_EN
        );
        assert!(controller
            .registers
            .writes
            .iter()
            .any(|(register, value)| *register == REG_ASQ && *value == 0x1000));
        assert!(controller
            .registers
            .writes
            .iter()
            .any(|(register, value)| *register == REG_ACQ && *value == 0x2000));
        assert_eq!(
            controller.identify_namespace(1).unwrap(),
            NamespaceInfo {
                block_count: 12345,
                block_size: 512
            }
        );
    }

    #[test]
    fn creates_polled_io_queues() {
        let (regs, dma) = fixture();
        let mut controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        controller.create_io_queues(4).unwrap();
        assert_eq!(
            controller.io_queue(),
            Some(IoQueueState {
                depth: 4,
                submission_tail: 0,
                completion_head: 0,
                phase: true,
                submission_doorbell: doorbell_offset(1, false, 4),
                completion_doorbell: doorbell_offset(1, true, 4),
            })
        );
        assert_eq!(controller.registers.command_error, 0);
    }

    #[test]
    fn simulator_rejects_submission_queue_without_completion_queue() {
        let (regs, dma) = fixture();
        let mut controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        assert_eq!(
            controller.submit_admin(Submission::create_io_sq(1, 4, 0x5000, 1)),
            Err(NvmeError::CompletionStatus { sct: 0, sc: 1 })
        );
    }

    #[test]
    fn shallow_io_queue_is_rejected_before_submission() {
        let (regs, dma) = fixture();
        let mut controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        let submissions = controller
            .registers
            .writes
            .iter()
            .filter(|(offset, _)| *offset == doorbell_offset(0, false, 4))
            .count();
        assert_eq!(
            controller.create_io_queues(1),
            Err(NvmeError::InvalidQueueDepth)
        );
        assert_eq!(
            controller
                .registers
                .writes
                .iter()
                .filter(|(offset, _)| *offset == doorbell_offset(0, false, 4))
                .count(),
            submissions
        );
    }

    #[test]
    fn block_io_roundtrips_small_and_prp_list_transfers_with_mdts_chunks() {
        use crate::block::BlockDevice;
        let (regs, dma) = fixture();
        let mut controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        controller.create_io_queues(4).unwrap();
        for blocks in [1usize, 8, 300] {
            let input: Vec<u8> = (0..blocks * 512).map(|i| (i * 17) as u8).collect();
            controller.write_blocks(10, &input).unwrap_or_else(|e| {
                panic!(
                    "write {blocks}: {e:?}, queue {:?}, io {:?}/{:?}, tail {}",
                    controller.io_queue,
                    controller.registers.io_cq,
                    controller.registers.io_sq,
                    controller.registers.io_cq_tail
                )
            });
            let mut output = vec![0; input.len()];
            controller.read_blocks(10, &mut output).unwrap();
            assert_eq!(output, input);
        }
        // The final transfer exceeds the 128 KiB cap and is split into two commands.
        let io_doorbells = controller
            .registers
            .writes
            .iter()
            .filter(|(r, _)| *r == doorbell_offset(1, false, 4))
            .count();
        assert!(io_doorbells >= 8);
    }

    #[test]
    fn invalid_range_has_no_io_command_and_write_completion_error_propagates() {
        use crate::block::{BlockDevice, BlockError};
        let (regs, dma) = fixture();
        let mut controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        controller.create_io_queues(4).unwrap();
        let before = controller
            .registers
            .writes
            .iter()
            .filter(|(r, _)| *r == doorbell_offset(1, false, 4))
            .count();
        assert_eq!(
            controller.write_blocks(12345, &[0; 512]),
            Err(BlockError::OutOfRange)
        );
        assert_eq!(
            controller
                .registers
                .writes
                .iter()
                .filter(|(r, _)| *r == doorbell_offset(1, false, 4))
                .count(),
            before
        );
        controller.registers.completion_status = 2;
        assert_eq!(
            controller.write_blocks(0, &[7; 512]),
            Err(BlockError::DeviceError)
        );
    }

    #[test]
    fn readiness_and_completion_errors_are_bounded() {
        let (mut regs, dma) = fixture();
        regs.never_ready = true;
        assert_eq!(
            NvmeController::init(regs, dma, CountingDelay::default()).err(),
            Some(NvmeError::Controller(ControllerError::Timeout))
        );
        let (mut regs, dma) = fixture();
        regs.fatal = true;
        assert_eq!(
            NvmeController::init(regs, dma, CountingDelay::default()).err(),
            Some(NvmeError::Controller(ControllerError::Failed))
        );
        let (mut regs, dma) = fixture();
        regs.completion_status = 2;
        assert!(matches!(
            NvmeController::init(regs, dma, CountingDelay::default()),
            Err(NvmeError::CompletionStatus { sc: 1, .. })
        ));
    }

    #[test]
    fn controller_requiring_larger_pages_is_refused() {
        let (mut regs, dma) = fixture();
        // CAP.MPSMIN = 1 means the controller needs 8 KiB pages; the driver
        // only programs 4 KiB.
        regs.cap_high = 1 << 16;
        assert_eq!(
            NvmeController::init(regs, dma, CountingDelay::default()).err(),
            Some(NvmeError::UnsupportedController)
        );
    }

    #[test]
    fn io_queue_depth_above_mqes_is_rejected() {
        let (regs, dma) = fixture();
        let mut controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        // CAP.MQES + 1 = 1024 in the fixture.
        assert_eq!(
            controller.create_io_queues(1025),
            Err(NvmeError::InvalidQueueDepth)
        );
    }

    #[test]
    fn lbads_below_512_is_invalid_identify() {
        let (mut regs, dma) = fixture();
        regs.lbads = 8;
        assert_eq!(
            NvmeController::init(regs, dma, CountingDelay::default()).err(),
            Some(NvmeError::InvalidIdentify)
        );
    }

    #[test]
    fn explicit_namespace_write_surfaces_device_error() {
        let (regs, dma) = fixture();
        let mut controller = NvmeController::init(regs, dma, CountingDelay::default()).unwrap();
        controller.create_io_queues(4).unwrap();
        // The simulator rejects any NSID other than 1 with a completion error.
        assert_eq!(
            controller.write_blocks_nsid(0xffff_ffff, 0, &[0xAB; 512]),
            Err(BlockError::DeviceError)
        );
        // A valid explicit namespace write still round-trips.
        controller.write_blocks_nsid(1, 0, &[0xCD; 512]).unwrap();
        let mut out = [0u8; 512];
        controller.read_blocks_nsid(1, 0, &mut out).unwrap();
        assert_eq!(out, [0xCD; 512]);
    }
}
