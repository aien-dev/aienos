//! Polled NVMe admin controller initialization and Identify commands.

use alloc::vec;
use alloc::vec::Vec;

use super::{
    doorbell_offset, Cap, Completion, ControllerError, Registers, Submission, CC_EN, CSTS_CFS,
    CSTS_RDY, REG_ACQ, REG_AQA, REG_ASQ, REG_CC, REG_CSTS,
};

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
    CompletionStatus { sct: u8, sc: u8 },
    InvalidIdentify,
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
}

impl<R: Registers, D: DmaMemory, T: Delay> NvmeController<R, D, T> {
    /// Reset and enable the controller. Ready waits honour CAP.TO (500 ms units).
    pub fn init(mut registers: R, mut dma: D, mut delay: T) -> Result<Self, NvmeError> {
        let cap = Cap(((registers.read32(4) as u64) << 32) | registers.read32(0) as u64);
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
        };
        controller.identify_controller()?;
        Ok(controller)
    }

    pub fn identify_controller(&mut self) -> Result<(), NvmeError> {
        self.submit_identify(0, 1).map(|_| ())
    }

    pub fn identify_namespace(&mut self, nsid: u32) -> Result<NamespaceInfo, NvmeError> {
        let bytes = self.submit_identify(nsid, 0)?;
        let block_count = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let flbas = (bytes[26] & 0x0f) as usize;
        let descriptor = 128 + flbas * 4;
        let lbads = *bytes
            .get(descriptor + 2)
            .ok_or(NvmeError::InvalidIdentify)?;
        if block_count == 0 || lbads >= 32 {
            return Err(NvmeError::InvalidIdentify);
        }
        Ok(NamespaceInfo {
            block_count,
            block_size: 1u32 << lbads,
        })
    }

    fn submit_identify(&mut self, nsid: u32, cns: u32) -> Result<Vec<u8>, NvmeError> {
        self.identify.bytes.fill(0);
        self.dma
            .write(self.identify.physical, &self.identify.bytes)?;
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        let mut command = if cns == 1 {
            Submission::identify_controller(self.identify.physical)
        } else {
            Submission::identify_namespace(nsid, self.identify.physical)
        };
        command.set_u32(0, (command.u32_at(0) & 0xffff) | ((cid as u32) << 16));
        let slot = self.sq_tail;
        let offset = slot * 64;
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
            self.next += size as u64;
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
    }
    impl Registers for FakeRegs {
        fn read32(&mut self, offset: u32) -> u32 {
            match offset {
                0 => 0x0100_03ff, // CAP.TO = 1 (500 ms), MQES = 1023
                4 => 0,
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
                let cns = u32::from_le_bytes(command[40..44].try_into().unwrap());
                let data = memory.get_mut(&prp).unwrap();
                if cns == 0 {
                    data[0..8].copy_from_slice(&self.namespace_size.to_le_bytes());
                    data[26] = 0;
                    data[130] = 9;
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
                cqe[completion_offset + 14..completion_offset + 16]
                    .copy_from_slice(&(1 | self.completion_status).to_le_bytes());
                self.cq_tail = (self.cq_tail + 1) % ADMIN_DEPTH;
                self.sq_tail = (self.sq_tail + 1) % ADMIN_DEPTH;
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
}
