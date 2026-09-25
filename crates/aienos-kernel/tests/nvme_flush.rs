//! D2 integration tests: NVMe Flush (opcode 0x00) on the polled I/O queue.
//!
//! Target: `crates/aienos-kernel/tests/nvme_flush.rs`.
//!
//! Self-contained: this file uses only the public `aienos_kernel::nvme` and
//! `aienos_kernel::nvme::driver` API plus local `Registers`, `DmaMemory`, and
//! `Delay` fakes. The fake controller records every I/O command and every I/O
//! submission-doorbell write, so the tests can prove that `flush()` issues a
//! real Flush command that reaches the device instead of being a silent no-op.
//!
//! Base: aien-dev/aienos @ ef359ec.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use aienos_kernel::block::{BlockDevice, BlockError};
use aienos_kernel::nvme::driver::{
    Delay, DmaMemory, DmaRegion, NvmeController, NvmeError, ADMIN_DEPTH,
};
use aienos_kernel::nvme::{
    doorbell_offset, Registers, CSTS_RDY, REG_ACQ, REG_ASQ, REG_CC, REG_CSTS,
};

const PAGE: usize = 4096;
/// CAP.DSTRD = 0 -> 4-byte doorbell stride. CAP.TO = 1 -> 500 ms ready budget.
const CAP_LOW: u32 = 0x0100_03ff;
const STRIDE: u32 = 4;
const ADMIN_DOORBELL: u32 = doorbell_offset(0, false, STRIDE);
const IO_SQ_DOORBELL: u32 = doorbell_offset(1, false, STRIDE);
const NS_BLOCKS: u64 = 12_345;
/// The driver loops `for _ in 0..=1000`, i.e. 1001 polls, each backing off 1 ms.
const POLLS: u64 = 1_001;
const FLUSH_OPCODE: u8 = 0x00;
const WRITE_OPCODE: u8 = 0x01;
const IO_DEPTH: u16 = 4;

type Shared = Rc<RefCell<Device>>;

// ---------------------------------------------------------------------------
// Device model
// ---------------------------------------------------------------------------

/// Knobs the tests flip to shape I/O completion behaviour.
#[derive(Clone, Default)]
struct Behavior {
    /// Raw status bits (SC/SCT/DNR) ORed with the phase bit before delivery.
    io_raw_status: Option<u16>,
    /// If true, never place an I/O completion (driver must bound its poll).
    io_never_complete: bool,
}

struct Region {
    base: u64,
    len: usize,
    bytes: Vec<u8>,
}

/// Every I/O command the device observed, parsed from its SQ entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordedIo {
    opcode: u8,
    nsid: u32,
    cid: u16,
    cdw10: u32,
    cdw11: u32,
    prp1: u64,
    prp2: u64,
}

struct Device {
    regions: Vec<Region>,
    next_phys: u64,
    cc: u32,
    csts: u32,
    asq: u64,
    acq: u64,
    admin_cq_base: Option<u64>,
    admin_cq_len: usize,
    io_sq_base: Option<u64>,
    io_cq_base: Option<u64>,
    io_depth: usize,
    admin_sq_tail: usize,
    admin_cq_tail: usize,
    admin_phase: bool,
    io_sq_tail: usize,
    io_cq_tail: usize,
    io_phase: bool,
    admin_queue: VecDeque<[u8; 16]>,
    io_queue: VecDeque<[u8; 16]>,
    io_commands: u64,
    io_sq_doorbells: u64,
    io_log: Vec<RecordedIo>,
    behavior: Behavior,
}

impl Device {
    fn new() -> Self {
        Self {
            regions: Vec::new(),
            next_phys: 0x1000,
            cc: 0,
            csts: 0,
            asq: 0,
            acq: 0,
            admin_cq_base: None,
            admin_cq_len: 0,
            io_sq_base: None,
            io_cq_base: None,
            io_depth: 0,
            admin_sq_tail: 0,
            admin_cq_tail: 0,
            admin_phase: true,
            io_sq_tail: 0,
            io_cq_tail: 0,
            io_phase: true,
            admin_queue: VecDeque::new(),
            io_queue: VecDeque::new(),
            io_commands: 0,
            io_sq_doorbells: 0,
            io_log: Vec::new(),
            behavior: Behavior::default(),
        }
    }

    fn alloc(&mut self, size: usize, alignment: usize) -> u64 {
        let align = alignment.max(1) as u64;
        let base = (self.next_phys + align - 1) & !(align - 1);
        self.next_phys = base + size as u64;
        self.regions.push(Region {
            base,
            len: size,
            bytes: vec![0; size],
        });
        base
    }

    fn find_region(&self, physical: u64, len: usize) -> Option<usize> {
        self.regions
            .iter()
            .position(|r| physical >= r.base && physical + len as u64 <= r.base + r.len as u64)
    }

    fn read_mem(&mut self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError> {
        if output.len() == 16 {
            if let Some(base) = self.admin_cq_base {
                if physical >= base && physical + 16 <= base + self.admin_cq_len as u64 {
                    match self.admin_queue.pop_front() {
                        Some(cqe) => output.copy_from_slice(&cqe),
                        None => output.fill(0),
                    }
                    return Ok(());
                }
            }
            if let Some(base) = self.io_cq_base {
                let len = (self.io_depth * 16) as u64;
                if physical >= base && physical + 16 <= base + len {
                    match self.io_queue.pop_front() {
                        Some(cqe) => output.copy_from_slice(&cqe),
                        None => output.fill(0),
                    }
                    return Ok(());
                }
            }
        }
        match self.find_region(physical, output.len()) {
            Some(i) => {
                output.copy_from_slice(&self.regions[i].bytes[..output.len()]);
                Ok(())
            }
            None => Err(NvmeError::Dma),
        }
    }

    fn write_mem(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> {
        match self.find_region(physical, input.len()) {
            Some(i) => {
                self.regions[i].bytes[..input.len()].copy_from_slice(input);
                Ok(())
            }
            None => Err(NvmeError::Dma),
        }
    }

    fn peek_command(&self, base: u64, slot: usize) -> [u8; 64] {
        let addr = base + (slot * 64) as u64;
        let mut out = [0u8; 64];
        if let Some(i) = self.find_region(addr, 64) {
            out.copy_from_slice(&self.regions[i].bytes[..64]);
        }
        out
    }

    fn fill_identify(&mut self, prp: u64, cns: u32) {
        if let Some(i) = self.find_region(prp, PAGE) {
            let bytes = &mut self.regions[i].bytes;
            if cns == 1 {
                bytes[77] = 0; // MDTS = 0 -> 128 KiB chunk cap
            } else {
                bytes[0..8].copy_from_slice(&NS_BLOCKS.to_le_bytes());
                bytes[26] = 0; // FLBAS -> format 0
                bytes[128 + 2] = 9; // LBADS -> 512-byte blocks
            }
        }
    }

    fn push_admin(&mut self, phase: bool, cid: u16, raw: u16) {
        let mut cqe = [0u8; 16];
        cqe[12..14].copy_from_slice(&cid.to_le_bytes());
        cqe[14..16].copy_from_slice(&(raw | u16::from(phase)).to_le_bytes());
        self.admin_queue.push_back(cqe);
    }

    fn push_io(&mut self, phase: bool, cid: u16, raw: u16) {
        let mut cqe = [0u8; 16];
        cqe[12..14].copy_from_slice(&cid.to_le_bytes());
        cqe[14..16].copy_from_slice(&(raw | u16::from(phase)).to_le_bytes());
        self.io_queue.push_back(cqe);
    }

    fn on_admin_doorbell(&mut self) {
        let slot = self.admin_sq_tail;
        let cmd = self.peek_command(self.asq, slot);
        let opcode = cmd[0];
        let cid = u16::from_le_bytes([cmd[2], cmd[3]]);
        let p1 = u64::from_le_bytes(cmd[24..32].try_into().unwrap());
        let cdw10 = u32::from_le_bytes(cmd[40..44].try_into().unwrap());
        match opcode {
            0x06 => self.fill_identify(p1, cdw10),
            0x05 => {
                // Create I/O CQ (QID 1): remember buffer and depth.
                self.io_cq_base = Some(p1);
                self.io_depth = ((cdw10 >> 16) & 0xffff) as usize + 1;
            }
            0x01 => self.io_sq_base = Some(p1), // Create I/O SQ (QID 1)
            _ => {}
        }
        self.push_admin(self.admin_phase, cid, 0);
        self.admin_sq_tail = (slot + 1) % ADMIN_DEPTH;
        self.admin_cq_tail = (self.admin_cq_tail + 1) % ADMIN_DEPTH;
        if self.admin_cq_tail == 0 {
            self.admin_phase = !self.admin_phase;
        }
    }

    fn on_io_doorbell(&mut self) {
        self.io_sq_doorbells += 1;
        let Some(sq) = self.io_sq_base else {
            return;
        };
        if self.io_depth == 0 {
            return;
        }
        let slot = self.io_sq_tail;
        let cmd = self.peek_command(sq, slot);
        let opcode = cmd[0];
        let cid = u16::from_le_bytes([cmd[2], cmd[3]]);
        let nsid = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        let prp1 = u64::from_le_bytes(cmd[24..32].try_into().unwrap());
        let prp2 = u64::from_le_bytes(cmd[32..40].try_into().unwrap());
        let cdw10 = u32::from_le_bytes(cmd[40..44].try_into().unwrap());
        let cdw11 = u32::from_le_bytes(cmd[44..48].try_into().unwrap());
        self.io_commands += 1;
        self.io_log.push(RecordedIo {
            opcode,
            nsid,
            cid,
            cdw10,
            cdw11,
            prp1,
            prp2,
        });
        if !self.behavior.io_never_complete {
            let raw = self.behavior.io_raw_status.unwrap_or(0);
            self.push_io(self.io_phase, cid, raw);
        }
        self.io_sq_tail = (slot + 1) % self.io_depth;
        self.io_cq_tail = (self.io_cq_tail + 1) % self.io_depth;
        if self.io_cq_tail == 0 {
            self.io_phase = !self.io_phase;
        }
    }

    fn reg_read(&mut self, offset: u32) -> u32 {
        match offset {
            0 => CAP_LOW,
            4 => 0,
            REG_CC => self.cc,
            REG_CSTS => self.csts,
            _ => 0,
        }
    }

    fn reg_write(&mut self, offset: u32, value: u32) {
        match offset {
            REG_CC => {
                self.cc = value;
                self.csts = if value & 1 == 0 { 0 } else { CSTS_RDY };
            }
            REG_ASQ => self.asq = (self.asq & 0xffff_ffff_0000_0000) | u64::from(value),
            x if x == REG_ASQ + 4 => self.asq = (self.asq & 0xffff_ffff) | (u64::from(value) << 32),
            REG_ACQ => {
                self.acq = (self.acq & 0xffff_ffff_0000_0000) | u64::from(value);
                self.admin_cq_base = Some(self.acq);
                self.admin_cq_len = PAGE;
            }
            x if x == REG_ACQ + 4 => {
                self.acq = (self.acq & 0xffff_ffff) | (u64::from(value) << 32);
                self.admin_cq_base = Some(self.acq);
                self.admin_cq_len = PAGE;
            }
            ADMIN_DOORBELL => self.on_admin_doorbell(),
            IO_SQ_DOORBELL => self.on_io_doorbell(),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Fakes implementing the public driver traits
// ---------------------------------------------------------------------------

struct FakeRegs {
    shared: Shared,
}

impl Registers for FakeRegs {
    fn read32(&mut self, offset: u32) -> u32 {
        self.shared.borrow_mut().reg_read(offset)
    }
    fn write32(&mut self, offset: u32, value: u32) {
        self.shared.borrow_mut().reg_write(offset, value);
    }
}

struct FakeDma {
    shared: Shared,
}

impl DmaMemory for FakeDma {
    fn allocate(&mut self, size: usize, alignment: usize) -> Result<DmaRegion, NvmeError> {
        let physical = self.shared.borrow_mut().alloc(size, alignment);
        Ok(DmaRegion {
            physical,
            bytes: vec![0; size],
        })
    }
    fn read(&self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError> {
        self.shared.borrow_mut().read_mem(physical, output)
    }
    fn write(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> {
        self.shared.borrow_mut().write_mem(physical, input)
    }
}

#[derive(Default)]
struct CountingDelay {
    waited_us: Rc<RefCell<u64>>,
}

impl Delay for CountingDelay {
    fn delay_us(&mut self, us: u32) {
        *self.waited_us.borrow_mut() += u64::from(us);
    }
}

type Controller = NvmeController<FakeRegs, FakeDma, CountingDelay>;

fn make_controller() -> (Controller, Shared, Rc<RefCell<u64>>) {
    let shared: Shared = Rc::new(RefCell::new(Device::new()));
    let regs = FakeRegs {
        shared: shared.clone(),
    };
    let dma = FakeDma {
        shared: shared.clone(),
    };
    let delay = CountingDelay::default();
    let waited = delay.waited_us.clone();
    let controller = NvmeController::init(regs, dma, delay).expect("init should succeed");
    (controller, shared, waited)
}

fn recorded_io(shared: &Shared) -> Vec<RecordedIo> {
    shared.borrow().io_log.clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Flush is opcode 0x00, addressed to NSID 1, with no PRP data pointer.
#[test]
fn flush_submits_opcode_zero_nsid_one_without_data_pointer() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    controller.flush().unwrap();

    let log = recorded_io(&shared);
    assert_eq!(log.len(), 1, "exactly one I/O command: the Flush");
    let flush = log[0];
    assert_eq!(flush.opcode, FLUSH_OPCODE, "Flush is opcode 0x00");
    assert_eq!(flush.nsid, 1, "Flush targets NSID 1");
    assert_eq!(
        (flush.prp1, flush.prp2),
        (0, 0),
        "Flush is data-less: PRP1/PRP2 must stay zero"
    );
    assert_eq!(
        (flush.cdw10, flush.cdw11),
        (0, 0),
        "reserved CDW10/CDW11 must stay zero"
    );
}

/// A zero-status completion means the controller reported the cache durable.
#[test]
fn successful_flush_completion_returns_ok() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();

    assert_eq!(controller.flush(), Ok(()));

    let device = shared.borrow();
    assert_eq!(device.io_commands, 1, "the Flush reached the device");
    assert_eq!(device.io_log[0].opcode, FLUSH_OPCODE);
}

/// Durability is exposed only through successful completion: any nonzero status
/// is a failure, never an assumed success.
#[test]
fn nonzero_flush_completion_status_returns_device_error() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    // status word 0x0002 -> status >> 1 == 1 (nonzero).
    shared.borrow_mut().behavior.io_raw_status = Some(0x0002);

    assert_eq!(controller.flush(), Err(BlockError::DeviceError));
}

/// A missing completion is bounded and surfaced as a timeout, not an infinite
/// loop and not a fake success.
#[test]
fn flush_timeout_returns_timeout_and_is_bounded() {
    let (mut controller, shared, waited) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    shared.borrow_mut().behavior.io_never_complete = true;

    let before = *waited.borrow();
    assert_eq!(controller.flush(), Err(BlockError::Timeout));
    assert_eq!(
        *waited.borrow() - before,
        POLLS * 1_000,
        "the poll budget must be bounded"
    );
}

/// Flush must not be a silent no-op: it must ring the I/O submission doorbell
/// and the command must actually reach the device simulator.
#[test]
fn flush_is_not_a_silent_no_op_doorbell_and_command_reach_device() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    let (doorbells_before, commands_before) = {
        let device = shared.borrow();
        (device.io_sq_doorbells, device.io_commands)
    };

    controller.flush().unwrap();

    let device = shared.borrow();
    assert_eq!(
        device.io_sq_doorbells,
        doorbells_before + 1,
        "a Flush must ring the I/O submission-queue doorbell"
    );
    assert_eq!(
        device.io_commands,
        commands_before + 1,
        "the Flush command must reach the device"
    );
    assert_eq!(
        device.io_log.last().unwrap().opcode,
        FLUSH_OPCODE,
        "the delivered command is a Flush"
    );
}

/// Flush after a write in the same session must use a fresh command id, never
/// reuse the write's CID.
#[test]
fn flush_after_write_in_same_session_uses_fresh_cid() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();

    controller.write_blocks(0, &[0xAB; 512]).unwrap();
    controller.flush().unwrap();

    let log = recorded_io(&shared);
    assert_eq!(log.len(), 2, "one Write then one Flush");
    let write = log[0];
    let flush = log[1];
    assert_eq!(write.opcode, WRITE_OPCODE, "first command is a Write");
    assert_eq!(flush.opcode, FLUSH_OPCODE, "second command is a Flush");
    assert_ne!(flush.cid, write.cid, "Flush must not reuse the Write CID");
    assert_eq!(
        flush.cid,
        write.cid.wrapping_add(1),
        "the CID must advance monotonically"
    );
}
