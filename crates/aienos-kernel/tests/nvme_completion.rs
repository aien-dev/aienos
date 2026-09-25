//! External integration tests for the polled NVMe completion/error path.
//!
//! Target: `crates/aienos-kernel/tests/nvme_completion.rs`.
//!
//! Uses only the public `aienos_kernel::nvme` and
//! `aienos_kernel::nvme::driver` API plus our own `Registers`, `DmaMemory`
//! and `Delay` fakes. The device fake is programmable: it can echo a wrong
//! command id, park a stale-phase completion ahead of the real one, return
//! crafted status words, never complete, or fault/never-ready the controller.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use aienos_kernel::block::{BlockDevice, BlockError};
use aienos_kernel::nvme::driver::{
    Delay, DmaMemory, DmaRegion, NvmeController, NvmeError, ADMIN_DEPTH,
};
use aienos_kernel::nvme::{
    doorbell_offset, Completion, CompletionQueue, ControllerError, Registers, Submission, CSTS_CFS,
    CSTS_RDY, REG_ACQ, REG_ASQ, REG_CC, REG_CSTS,
};

const PAGE: usize = 4096;
/// CAP.DSTRD = 0 -> 4-byte doorbell stride. CAP.TO = 1 -> 500 ms ready budget.
const CAP_LOW: u32 = 0x0100_03ff;
const STRIDE: u32 = 4;
const ADMIN_DOORBELL: u32 = doorbell_offset(0, false, STRIDE);
const IO_SQ_DOORBELL: u32 = doorbell_offset(1, false, STRIDE);
const NS_BLOCKS: u64 = 12_345;
const POLLS: u64 = 1_001; // driver loops `0..=1000`

type Shared = Rc<RefCell<Device>>;

// ---------------------------------------------------------------------------
// Programmable device model
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Behavior {
    /// Raw status bits (SC/SCT/DNR) ORed with the phase bit before delivery.
    admin_raw_status: Option<u16>,
    /// Added to the echoed CID; nonzero forces a command-id mismatch.
    admin_cid_delta: i32,
    /// Emit this many stale-phase completions before the real one.
    admin_stale_reads: u32,
    /// If true, never place an admin completion (driver must bound its poll).
    admin_never_complete: bool,
    io_raw_status: Option<u16>,
    io_cid_delta: i32,
    io_stale_reads: u32,
    io_never_complete: bool,
}

struct Region {
    base: u64,
    len: usize,
    bytes: Vec<u8>,
}

struct Device {
    regions: Vec<Region>,
    next_phys: u64,
    cc: u32,
    csts: u32,
    fatal_on_enable: bool,
    never_ready: bool,
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
    admin_commands: u64,
    io_commands: u64,
    behavior: Behavior,
}

impl Device {
    fn new() -> Self {
        Self {
            regions: Vec::new(),
            next_phys: 0x1000,
            cc: 0,
            csts: 0,
            fatal_on_enable: false,
            never_ready: false,
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
            admin_commands: 0,
            io_commands: 0,
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
        let idx = self.find_region(prp, PAGE);
        if let Some(i) = idx {
            let bytes = &mut self.regions[i].bytes;
            if cns == 1 {
                bytes[77] = 0; // MDTS = 0
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
                self.io_cq_base = Some(p1);
                self.io_depth = ((cdw10 >> 16) & 0xffff) as usize + 1;
            }
            0x01 => self.io_sq_base = Some(p1),
            _ => {}
        }
        self.admin_commands += 1;
        if !self.behavior.admin_never_complete {
            let echo = if self.behavior.admin_cid_delta == 0 {
                cid
            } else {
                cid.wrapping_add(self.behavior.admin_cid_delta as u16)
            };
            let mut stale = self.behavior.admin_stale_reads;
            while stale > 0 {
                let phase = !self.admin_phase;
                self.push_admin(phase, cid, 0);
                stale -= 1;
            }
            let raw = self.behavior.admin_raw_status.unwrap_or(0);
            let phase = self.admin_phase;
            self.push_admin(phase, echo, raw);
        }
        self.admin_sq_tail = (slot + 1) % ADMIN_DEPTH;
        self.admin_cq_tail = (self.admin_cq_tail + 1) % ADMIN_DEPTH;
        if self.admin_cq_tail == 0 {
            self.admin_phase = !self.admin_phase;
        }
    }

    fn on_io_doorbell(&mut self) {
        let Some(sq) = self.io_sq_base else {
            return;
        };
        if self.io_depth == 0 {
            return;
        }
        let slot = self.io_sq_tail;
        let cmd = self.peek_command(sq, slot);
        let cid = u16::from_le_bytes([cmd[2], cmd[3]]);
        self.io_commands += 1;
        if !self.behavior.io_never_complete {
            let echo = if self.behavior.io_cid_delta == 0 {
                cid
            } else {
                cid.wrapping_add(self.behavior.io_cid_delta as u16)
            };
            let mut stale = self.behavior.io_stale_reads;
            while stale > 0 {
                let phase = !self.io_phase;
                self.push_io(phase, cid, 0);
                stale -= 1;
            }
            let raw = self.behavior.io_raw_status.unwrap_or(0);
            let phase = self.io_phase;
            self.push_io(phase, echo, raw);
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
                self.csts = if value & 1 == 0 {
                    0
                } else if self.fatal_on_enable {
                    CSTS_CFS
                } else if self.never_ready {
                    0
                } else {
                    CSTS_RDY
                };
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

/// Build a controller that completes its initialization normally.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn admin_command_id_mismatch_reports_invalid_identify() {
    let (mut controller, shared, _) = make_controller();
    shared.borrow_mut().behavior.admin_cid_delta = 1;
    assert_eq!(
        controller.identify_controller(),
        Err(NvmeError::InvalidIdentify)
    );
}

#[test]
fn io_command_id_mismatch_reports_device_error() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(4).unwrap();
    shared.borrow_mut().behavior.io_cid_delta = 1;
    let mut buffer = [0u8; 512];
    assert_eq!(
        controller.read_blocks(0, &mut buffer),
        Err(BlockError::DeviceError)
    );
}

#[test]
fn stale_phase_completion_is_skipped_and_matching_one_consumed() {
    let (mut controller, shared, waited) = make_controller();
    shared.borrow_mut().behavior.admin_stale_reads = 1;
    let before = *waited.borrow();
    controller.identify_controller().unwrap();
    // Exactly one backoff: the stale entry was skipped, the real one consumed.
    assert_eq!(*waited.borrow() - before, 1_000);
    let device = shared.borrow();
    assert!(device.admin_queue.is_empty());
    assert_eq!(device.admin_commands, 3); // two during init + this one
    assert!(device.admin_phase);
}

#[test]
fn admin_cq_phase_flips_when_head_wraps_at_depth_eight() {
    let (mut controller, shared, _) = make_controller();
    for _ in 0..6 {
        controller.identify_controller().unwrap();
    }
    {
        let device = shared.borrow();
        assert_eq!(device.admin_commands, 8);
        assert_eq!(device.admin_cq_tail, 0);
        assert!(!device.admin_phase, "phase must flip once the head wraps");
    }
    // The 9th command only completes if the driver tracked the same flip.
    controller.identify_controller().unwrap();
    let device = shared.borrow();
    assert_eq!(device.admin_commands, 9);
    assert!(!device.admin_phase);
}

#[test]
fn admin_timeout_is_bounded_no_infinite_loop() {
    let (mut controller, shared, waited) = make_controller();
    shared.borrow_mut().behavior.admin_never_complete = true;
    let before = *waited.borrow();
    assert_eq!(controller.identify_controller(), Err(NvmeError::Timeout));
    assert_eq!(*waited.borrow() - before, POLLS * 1_000);
}

#[test]
fn io_timeout_is_bounded_no_infinite_loop() {
    let (mut controller, shared, waited) = make_controller();
    controller.create_io_queues(4).unwrap();
    shared.borrow_mut().behavior.io_never_complete = true;
    let before = *waited.borrow();
    let mut buffer = [0u8; 512];
    assert_eq!(
        controller.read_blocks(0, &mut buffer),
        Err(BlockError::Timeout)
    );
    assert_eq!(*waited.borrow() - before, POLLS * 1_000);
}

#[test]
fn controller_fatal_status_maps_to_controller_failed() {
    let shared: Shared = Rc::new(RefCell::new(Device::new()));
    shared.borrow_mut().fatal_on_enable = true;
    let regs = FakeRegs {
        shared: shared.clone(),
    };
    let dma = FakeDma {
        shared: shared.clone(),
    };
    let result = NvmeController::init(regs, dma, CountingDelay::default());
    assert_eq!(
        result.err(),
        Some(NvmeError::Controller(ControllerError::Failed))
    );
}

#[test]
fn controller_never_ready_maps_to_controller_timeout() {
    let shared: Shared = Rc::new(RefCell::new(Device::new()));
    shared.borrow_mut().never_ready = true;
    let regs = FakeRegs {
        shared: shared.clone(),
    };
    let dma = FakeDma {
        shared: shared.clone(),
    };
    let result = NvmeController::init(regs, dma, CountingDelay::default());
    assert_eq!(
        result.err(),
        Some(NvmeError::Controller(ControllerError::Timeout))
    );
}

#[test]
fn admin_status_word_decodes_exact_sc_and_sct() {
    // status word 0x0002 -> status >> 1 = 1 -> sc 1, sct 0.
    let (mut controller, shared, _) = make_controller();
    shared.borrow_mut().behavior.admin_raw_status = Some(0x0002);
    assert_eq!(
        controller.identify_namespace(1),
        Err(NvmeError::CompletionStatus { sct: 0, sc: 1 })
    );

    // 0x2804 style: 0x2804 >> 1 = 0x1402 -> sc 2, sct (0x1402 >> 8) & 7 = 4.
    let (mut controller, shared, _) = make_controller();
    shared.borrow_mut().behavior.admin_raw_status = Some(0x2804);
    assert_eq!(
        controller.identify_namespace(1),
        Err(NvmeError::CompletionStatus { sct: 4, sc: 2 })
    );
}

#[test]
fn io_nonzero_status_maps_to_device_error() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(4).unwrap();
    shared.borrow_mut().behavior.io_raw_status = Some(0x0002);
    let mut buffer = [0u8; 512];
    assert_eq!(
        controller.read_blocks(0, &mut buffer),
        Err(BlockError::DeviceError)
    );
}

#[test]
fn malformed_completions_do_not_panic() {
    // Garbage status word: 0xffff -> sc 0xff, sct 7. Must decode, not panic.
    let (mut controller, shared, _) = make_controller();
    shared.borrow_mut().behavior.admin_raw_status = Some(0xffff);
    assert_eq!(
        controller.identify_namespace(1),
        Err(NvmeError::CompletionStatus { sct: 7, sc: 0xff })
    );

    // All-zero CQE has phase 0, which mismatches the live phase, so it is
    // ignored until the poll budget runs out.
    let (mut controller, shared, _) = make_controller();
    shared.borrow_mut().behavior.admin_never_complete = true;
    assert_eq!(controller.identify_controller(), Err(NvmeError::Timeout));
}

#[test]
fn io_cq_wraparound_consumes_completions_in_order() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(4).unwrap();
    for lba in 0..4u64 {
        let mut buffer = [0u8; 512];
        controller.read_blocks(lba, &mut buffer).unwrap();
    }
    {
        let device = shared.borrow();
        assert_eq!(device.io_cq_tail, 0);
        assert!(!device.io_phase, "I/O CQ phase must flip at depth 4");
        assert_eq!(device.io_commands, 4);
    }
    // A fifth transfer only succeeds if the driver flipped in lockstep.
    let mut buffer = [0u8; 512];
    controller.read_blocks(4, &mut buffer).unwrap();
    let device = shared.borrow();
    assert_eq!(device.io_commands, 5);
    assert!(device.io_queue.is_empty());
}

#[test]
fn completion_accessors_decode_little_endian_fields() {
    let mut raw = [0u8; 16];
    raw[0..4].copy_from_slice(&0x1122_3344u32.to_le_bytes());
    raw[8..10].copy_from_slice(&0x5566u16.to_le_bytes());
    raw[10..12].copy_from_slice(&0x7788u16.to_le_bytes());
    raw[12..14].copy_from_slice(&0x99aau16.to_le_bytes());
    raw[14..16].copy_from_slice(&0x0003u16.to_le_bytes());
    let cqe = Completion(raw);
    assert_eq!(cqe.result(), 0x1122_3344);
    assert_eq!(cqe.sq_head(), 0x5566);
    assert_eq!(cqe.sq_id(), 0x7788);
    assert_eq!(cqe.command_id(), 0x99aa);
    assert_eq!(cqe.status(), 0x0003);
    assert!(cqe.phase());
}

#[test]
fn completion_queue_phase_flips_at_depth_eight() {
    let mut mem = vec![Completion([0u8; 16]); 8];
    for entry in &mut mem {
        entry.0[14..16].copy_from_slice(&1u16.to_le_bytes());
    }
    let mut queue = CompletionQueue::new(&mem);
    for _ in 0..8 {
        assert!(queue.poll().is_some());
    }
    assert_eq!(queue.head(), 0);
    assert!(!queue.phase());
    assert!(queue.poll().is_none());
}

// Keep Submission in scope for device-model fidelity and to document the
// layouts the fake parses (opcode/CID/PRP dwords).
#[allow(dead_code)]
fn submission_layout_probe() -> Submission {
    Submission::identify_controller(0)
}
