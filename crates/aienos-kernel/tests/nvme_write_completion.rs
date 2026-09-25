//! External integration tests for the native NVMe write + flush completion lane.
//!
//! Target: `crates/aienos-kernel/tests/nvme_write_completion.rs`.
//!
//! These tests drive `aienos_kernel::nvme::driver::NvmeController` only through
//! its public API plus local `Registers`, `DmaMemory`, and `Delay` fakes. The
//! fake device is programmable: it records every submitted I/O command and can
//! inject crafted 16-byte completions (wrong status, wrong command id, wrong
//! phase, all-zero, or none at all).
//!
//! Reachability notes for the negative paths:
//! * `NvmeController::identify_namespace(nsid)` is public and takes an arbitrary
//!   `nsid`, so the invalid-namespace error path is reachable and tested here.
//! * `BlockDevice::write_blocks` and `BlockDevice::flush` both funnel through the
//!   private `transfer`/`submit_io` path, which hard-codes namespace id `1` when
//!   it builds `Submission::write(1, ...)`. There is no public method that takes
//!   an NSID for I/O, so a *write-side* invalid-namespace test is NOT reachable
//!   today. It would require a new public method such as
//!   `write_blocks_ns(nsid, lba, buffer)`; we deliberately do not add it here.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use aienos_kernel::block::{BlockDevice, BlockError};
use aienos_kernel::nvme::driver::{
    Delay, DmaMemory, DmaRegion, NvmeController, NvmeError, ADMIN_DEPTH,
};
use aienos_kernel::nvme::{
    doorbell_offset, Registers, Submission, CSTS_RDY, REG_ACQ, REG_ASQ, REG_CC, REG_CSTS,
};

const PAGE: usize = 4096;
/// CAP.DSTRD = 0 -> 4-byte doorbell stride; CAP.TO = 1 -> 500 ms ready budget;
/// CAP.MQES + 1 = 1024.
const CAP_LOW: u32 = 0x0100_03ff;
const STRIDE: u32 = 4;
const ADMIN_DOORBELL: u32 = doorbell_offset(0, false, STRIDE);
const IO_SQ_DOORBELL: u32 = doorbell_offset(1, false, STRIDE);
const NS_BLOCKS: u64 = 12_345;
/// The driver's I/O poll budget is `for _ in 0..=1000`, i.e. 1001 iterations.
const POLLS: u64 = 1_001;
const IO_DEPTH: u16 = 4;

type Shared = Rc<RefCell<Device>>;

/// One submitted I/O command, decoded from the SQ slot the driver filled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IoCommand {
    opcode: u32,
    cid: u16,
    nsid: u32,
    lba: u64,
    blocks: u32,
}

#[derive(Clone, Copy, Default)]
struct Behavior {
    /// Raw SC/SCT/DNR bits delivered on I/O completions (phase bit added later).
    io_raw_status: Option<u16>,
    /// Added to the echoed command id; nonzero forces a command-id mismatch.
    io_cid_delta: i32,
    /// Emit this many wrong-phase (zeroed) completions before the real one.
    io_stale_wrong_phase: u32,
    /// If true, never place an I/O completion (driver must bound its poll).
    io_never_complete: bool,
    /// Reject `Identify` for any namespace other than NSID 1.
    reject_bad_nsid: bool,
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
    io_submissions: Vec<IoCommand>,
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
            io_submissions: Vec::new(),
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

    /// Completion-queue reads are served from FIFO queues so a wrong-phase entry
    /// can be parked ahead of the real one regardless of the exact slot address.
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
                bytes[77] = 0; // MDTS = 0 -> 128 KiB default chunk limit.
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

    /// A malformed, all-zero-otherwise CQE tagged with the *wrong* phase bit.
    fn push_io_wrong_phase(&mut self) {
        let mut cqe = [0u8; 16];
        cqe[14..16].copy_from_slice(&u16::from(!self.io_phase).to_le_bytes());
        self.io_queue.push_back(cqe);
    }

    fn on_admin_doorbell(&mut self) {
        let slot = self.admin_sq_tail;
        let cmd = self.peek_command(self.asq, slot);
        let opcode = u32::from_le_bytes(cmd[0..4].try_into().unwrap()) & 0xff; // low byte; high half is the CID
        let cid = u16::from_le_bytes(cmd[2..4].try_into().unwrap());
        let nsid = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        let p1 = u64::from_le_bytes(cmd[24..32].try_into().unwrap());
        let cdw10 = u32::from_le_bytes(cmd[40..44].try_into().unwrap());
        let mut raw = 0u16;
        match opcode {
            0x06 => {
                if cdw10 == 0 && self.behavior.reject_bad_nsid && nsid != 1 {
                    raw |= 0x0002; // SC 0x01: invalid namespace, SCT 0.
                } else {
                    self.fill_identify(p1, cdw10);
                }
            }
            0x05 => {
                self.io_cq_base = Some(p1);
                self.io_depth = ((cdw10 >> 16) & 0xffff) as usize + 1;
            }
            0x01 => self.io_sq_base = Some(p1),
            _ => {}
        }
        let echo = if self.behavior.io_cid_delta == 0 {
            cid
        } else {
            cid.wrapping_add(self.behavior.io_cid_delta as u16)
        };
        self.push_admin(self.admin_phase, echo, raw);
        self.admin_sq_tail = (slot + 1) % ADMIN_DEPTH;
        self.admin_cq_tail = (self.admin_cq_tail + 1) % ADMIN_DEPTH;
        if self.admin_cq_tail == 0 {
            self.admin_phase = !self.admin_phase;
        }
    }

    fn on_io_doorbell(&mut self) {
        let Some(sq) = self.io_sq_base else { return };
        if self.io_depth == 0 {
            return;
        }
        let slot = self.io_sq_tail;
        let cmd = self.peek_command(sq, slot);
        let opcode = u32::from_le_bytes(cmd[0..4].try_into().unwrap()) & 0xff; // low byte; high half is the CID
        let cid = u16::from_le_bytes(cmd[2..4].try_into().unwrap());
        let nsid = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        let lba = u64::from(u32::from_le_bytes(cmd[40..44].try_into().unwrap()))
            | (u64::from(u32::from_le_bytes(cmd[44..48].try_into().unwrap())) << 32);
        let blocks = u32::from_le_bytes(cmd[48..52].try_into().unwrap()) + 1;
        self.io_submissions.push(IoCommand {
            opcode,
            cid,
            nsid,
            lba,
            blocks,
        });
        self.io_commands += 1;
        if !self.behavior.io_never_complete {
            let mut stale = self.behavior.io_stale_wrong_phase;
            while stale > 0 {
                self.push_io_wrong_phase();
                stale -= 1;
            }
            let echo = if self.behavior.io_cid_delta == 0 {
                cid
            } else {
                cid.wrapping_add(self.behavior.io_cid_delta as u16)
            };
            let raw = self.behavior.io_raw_status.unwrap_or(0);
            self.push_io(self.io_phase, echo, raw);
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
fn failed_write_completion_maps_to_device_error() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    shared.borrow_mut().behavior.io_raw_status = Some(0x0002);
    assert_eq!(
        controller.write_blocks(0, &[0xAB; 512]),
        Err(BlockError::DeviceError)
    );
    let device = shared.borrow();
    assert_eq!(device.io_submissions.len(), 1);
    let command = device.io_submissions[0];
    assert_eq!(command.opcode, 0x01, "write opcode");
    assert_eq!(command.nsid, 1, "writes are hard-coded to NSID 1");
    assert_eq!(command.lba, 0);
    assert_eq!(command.blocks, 1);
    // A failing completion is still consumed; the driver's CQ head advances.
    assert_eq!(controller.io_queue().unwrap().completion_head, 1);
}

#[test]
fn failed_flush_completion_maps_to_device_error() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    shared.borrow_mut().behavior.io_raw_status = Some(0x0084);
    assert_eq!(controller.flush(), Err(BlockError::DeviceError));
    let device = shared.borrow();
    assert_eq!(device.io_submissions.len(), 1);
    assert_eq!(device.io_submissions[0].opcode, 0x00, "flush opcode");
    assert_eq!(device.io_submissions[0].nsid, 1);
}

#[test]
fn write_timeout_is_bounded_no_infinite_loop() {
    let (mut controller, shared, waited) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    shared.borrow_mut().behavior.io_never_complete = true;
    let before = *waited.borrow();
    assert_eq!(
        controller.write_blocks(0, &[0; 512]),
        Err(BlockError::Timeout)
    );
    assert_eq!(*waited.borrow() - before, POLLS * 1_000);
    // Nothing was consumed because nothing ever completed.
    assert_eq!(controller.io_queue().unwrap().completion_head, 0);
}

#[test]
fn flush_timeout_is_bounded_no_infinite_loop() {
    let (mut controller, shared, waited) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    shared.borrow_mut().behavior.io_never_complete = true;
    let before = *waited.borrow();
    assert_eq!(controller.flush(), Err(BlockError::Timeout));
    assert_eq!(*waited.borrow() - before, POLLS * 1_000);
}

#[test]
fn write_batch_cq_wraparound_flips_phase_and_consumes_in_order() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    for lba in 0..4u64 {
        controller.write_blocks(lba, &[(lba as u8); 512]).unwrap();
    }
    {
        let device = shared.borrow();
        assert_eq!(device.io_cq_tail, 0, "producer tail wraps at depth 4");
        assert!(!device.io_phase, "producer phase flips after the wrap");
        assert_eq!(device.io_commands, 4);
        let lbas: Vec<u64> = device.io_submissions.iter().map(|c| c.lba).collect();
        assert_eq!(lbas, vec![0, 1, 2, 3], "commands recorded in submit order");
    }
    {
        let q = controller.io_queue().unwrap();
        assert_eq!(q.completion_head, 0, "consumer head wraps at depth 4");
        assert!(!q.phase, "consumer flips in lockstep with the producer");
    }
    // The fifth write only completes if the driver flipped in lockstep.
    controller.write_blocks(4, &[0x44; 512]).unwrap();
    let q = controller.io_queue().unwrap();
    assert_eq!(q.completion_head, 1);
    assert!(!q.phase, "phase stays flipped past the wrap");
    assert!(shared.borrow().io_queue.is_empty());
}

#[test]
fn invalid_namespace_identify_surfaces_completion_status() {
    let (mut controller, shared, _) = make_controller();
    shared.borrow_mut().behavior.reject_bad_nsid = true;
    // NSID 1 stays reachable and valid.
    assert_eq!(
        controller.identify_namespace(1).unwrap().block_count,
        NS_BLOCKS
    );
    // NSID 2 is rejected by the controller with a non-zero status.
    assert_eq!(
        controller.identify_namespace(2),
        Err(NvmeError::CompletionStatus { sct: 0, sc: 1 })
    );
}

#[test]
fn write_command_id_mismatch_maps_to_device_error() {
    let (mut controller, shared, _) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    shared.borrow_mut().behavior.io_cid_delta = 1;
    assert_eq!(
        controller.write_blocks(0, &[0; 512]),
        Err(BlockError::DeviceError)
    );
    // A command-id mismatch is rejected before the head advances.
    assert_eq!(controller.io_queue().unwrap().completion_head, 0);
}

#[test]
fn wrong_phase_zero_completion_is_ignored_not_consumed() {
    let (mut controller, shared, waited) = make_controller();
    controller.create_io_queues(IO_DEPTH).unwrap();
    // An all-zero CQE (phase bit 0) is parked ahead of the real completion.
    shared.borrow_mut().behavior.io_stale_wrong_phase = 1;
    let before = *waited.borrow();
    controller.write_blocks(0, &[0x5A; 512]).unwrap();
    // Exactly one backoff: the mismatched entry was read and skipped, never
    // consumed. The CQ head advanced once, only for the real completion.
    assert_eq!(*waited.borrow() - before, 1_000);
    let q = controller.io_queue().unwrap();
    assert_eq!(q.completion_head, 1);
    assert!(q.phase);
}

// Keep `Submission` in scope and document the command layout the fake parses.
#[allow(dead_code)]
fn io_command_layout_probe() -> Submission {
    Submission::write(1, 0, 1, 0, 0)
}
