//! External integration tests for the AIENOS P3 native NVMe write + flush lane.
//!
//! Target: `crates/aienos-kernel/tests/nvme_write.rs`.
//! Repo mirror (read-only): aien-dev/aienos @ ef359ec.
//!
//! Uses only the public `aienos_kernel::nvme` and
//! `aienos_kernel::nvme::driver` API plus our own `Registers`, `DmaMemory`
//! and `Delay` fakes. Unlike the completion fake, this device model is
//! *persistent*: `opcode 0x01` copies the DMA payload into a per-LBA disk map
//! and `opcode 0x02` copies it back, so a written buffer can be read back.
//!
//! Covered deterministically:
//!   * one-block write command encoding (opcode/NSID/LBA/NLB/PRP1),
//!   * 8-block single command within MDTS,
//!   * starting LBA split across CDW10/CDW11 for an offset write,
//!   * out-of-range writes rejected with no I/O doorbell / no DMA / no command,
//!   * empty and non-block-multiple buffers -> InvalidInput,
//!   * fresh command id per I/O command and CID-matched completion consumption,
//!   * nonzero completion status -> DeviceError,
//!   * 300-block MDTS chunking with correct per-chunk LBA and NLB,
//!   * exact byte round-trip through `read_blocks`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use aienos_kernel::block::{BlockDevice, BlockError};
use aienos_kernel::nvme::driver::{
    Delay, DmaMemory, DmaRegion, NvmeController, NvmeError, ADMIN_DEPTH, PAGE_SIZE,
};
use aienos_kernel::nvme::{
    doorbell_offset, Registers, CC_EN, CSTS_RDY, REG_ACQ, REG_ASQ, REG_CC, REG_CSTS,
};

const CAP_LOW: u32 = 0x0100_03ff; // CAP.MQES = 1023, CAP.TO = 1 (500 ms), CAP.DSTRD = 0
const STRIDE: u32 = 4;
const ADMIN_DOORBELL: u32 = doorbell_offset(0, false, STRIDE);
const IO_SQ_DOORBELL: u32 = doorbell_offset(1, false, STRIDE);

const NS_BLOCKS: u64 = 12_345;
const BLOCK_SIZE: usize = 512;

type Shared = Rc<RefCell<Device>>;

// ---------------------------------------------------------------------------
// Persistent device model
// ---------------------------------------------------------------------------

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
    io_sq_base: Option<u64>,
    io_cq_base: Option<u64>,
    io_depth: usize,
    admin_sq_tail: usize,
    admin_cq_tail: usize,
    admin_phase: bool,
    io_sq_tail: usize,
    io_cq_tail: usize,
    io_phase: bool,
    /// I/O commands actually processed (one per I/O SQ doorbell that had a queue).
    io_commands: u64,
    /// I/O SQ doorbell register writes seen, including ones with no queue yet.
    io_doorbell_writes: u64,
    io_cids: Vec<u16>,
    io_completed: Vec<u16>,
    io_log: Vec<[u8; 64]>,
    /// Persistent block store: LBA -> block payload.
    disk: BTreeMap<u64, Vec<u8>>,
    namespace_blocks: u64,
    lbads: u8,
    mdts: u8,
    completion_status: u16,
    command_error: u16,
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
            io_sq_base: None,
            io_cq_base: None,
            io_depth: 0,
            admin_sq_tail: 0,
            admin_cq_tail: 0,
            admin_phase: true,
            io_sq_tail: 0,
            io_cq_tail: 0,
            io_phase: true,
            io_commands: 0,
            io_doorbell_writes: 0,
            io_cids: Vec::new(),
            io_completed: Vec::new(),
            io_log: Vec::new(),
            disk: BTreeMap::new(),
            namespace_blocks: NS_BLOCKS,
            lbads: 9,
            mdts: 0,
            completion_status: 0,
            command_error: 0,
        }
    }

    fn block_size(&self) -> usize {
        1usize << u32::from(self.lbads)
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
        let i = self
            .find_region(physical, output.len())
            .ok_or(NvmeError::Dma)?;
        let off = (physical - self.regions[i].base) as usize;
        output.copy_from_slice(&self.regions[i].bytes[off..off + output.len()]);
        Ok(())
    }

    fn write_mem(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> {
        let i = self
            .find_region(physical, input.len())
            .ok_or(NvmeError::Dma)?;
        let off = (physical - self.regions[i].base) as usize;
        self.regions[i].bytes[off..off + input.len()].copy_from_slice(input);
        Ok(())
    }

    fn region_vec(&self, physical: u64, len: usize) -> Option<Vec<u8>> {
        let i = self.find_region(physical, len)?;
        let off = (physical - self.regions[i].base) as usize;
        Some(self.regions[i].bytes[off..off + len].to_vec())
    }

    fn peek_command(&self, base: u64, slot: usize) -> [u8; 64] {
        let addr = base + (slot * 64) as u64;
        let mut out = [0u8; 64];
        if let Some(bytes) = self.region_vec(addr, 64) {
            out.copy_from_slice(&bytes);
        }
        out
    }

    fn fill_identify(&mut self, prp: u64, cns: u32) {
        if let Some(i) = self.find_region(prp, PAGE_SIZE) {
            let bytes = &mut self.regions[i].bytes;
            bytes.fill(0);
            if cns == 1 {
                bytes[77] = self.mdts; // MDTS
            } else {
                bytes[0..8].copy_from_slice(&self.namespace_blocks.to_le_bytes());
                bytes[26] = 0; // FLBAS -> format 0
                bytes[128 + 2] = self.lbads; // LBADS in descriptor 0
            }
        }
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
        let at = self.acq + (self.admin_cq_tail * 16) as u64;
        let mut raw = [0u8; 16];
        raw[12..14].copy_from_slice(&cid.to_le_bytes());
        raw[14..16].copy_from_slice(&u16::from(self.admin_phase).to_le_bytes());
        self.write_mem(at, &raw).ok();
        self.admin_sq_tail = (slot + 1) % ADMIN_DEPTH;
        self.admin_cq_tail = (self.admin_cq_tail + 1) % ADMIN_DEPTH;
        if self.admin_cq_tail == 0 {
            self.admin_phase = !self.admin_phase;
        }
    }

    /// Decompose a transfer into (address, len) segments, mirroring the PRP
    /// shapes `build_prps` produces: PRP1, optional PRP2, or a page list.
    fn collect_segments(&self, p1: u64, p2: u64, len: usize) -> Vec<(u64, usize)> {
        let mut segs = Vec::new();
        if len == 0 {
            return segs;
        }
        let first = (PAGE_SIZE - (p1 as usize & (PAGE_SIZE - 1))).min(len);
        segs.push((p1, first));
        let mut left = len - first;
        if left == 0 {
            return segs;
        }
        if p2 != 0 && left <= PAGE_SIZE {
            segs.push((p2, left));
            return segs;
        }
        let per = PAGE_SIZE / 8;
        let mut list_page = p2;
        'outer: while left > 0 {
            let entries = match self.region_vec(list_page, PAGE_SIZE) {
                Some(bytes) => bytes,
                None => break,
            };
            for i in 0..per {
                let address = u64::from_le_bytes(entries[i * 8..i * 8 + 8].try_into().unwrap());
                if address == 0 {
                    break 'outer;
                }
                if i == per - 1 && left > PAGE_SIZE {
                    list_page = address; // chain pointer to the next list page
                    continue 'outer;
                }
                let n = left.min(PAGE_SIZE - (address as usize & (PAGE_SIZE - 1)));
                segs.push((address, n));
                left -= n;
                if left == 0 {
                    break 'outer;
                }
            }
        }
        segs
    }

    fn on_io_doorbell(&mut self) {
        let Some(sq) = self.io_sq_base else { return };
        if self.io_depth == 0 {
            return;
        }
        let slot = self.io_sq_tail;
        let cmd = self.peek_command(sq, slot);
        self.io_commands += 1;
        self.io_log.push(cmd);
        let cid = u16::from_le_bytes([cmd[2], cmd[3]]);
        self.io_cids.push(cid);

        let opcode = cmd[0];
        let nsid = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        let p1 = u64::from_le_bytes(cmd[24..32].try_into().unwrap());
        let p2 = u64::from_le_bytes(cmd[32..40].try_into().unwrap());
        let lba = u64::from(u32::from_le_bytes(cmd[40..44].try_into().unwrap()))
            | (u64::from(u32::from_le_bytes(cmd[44..48].try_into().unwrap())) << 32);
        let nlb = u32::from_le_bytes(cmd[48..52].try_into().unwrap()) as usize;
        let len = nlb.saturating_add(1) * self.block_size();
        let bs = self.block_size();

        let mut err = 0u16;
        if nsid != 1 {
            err = 1 << 1;
        }
        match opcode {
            0x01 | 0x02 => {
                let segs = self.collect_segments(p1, p2, len);
                if opcode == 0x01 {
                    let mut flat = vec![0u8; len];
                    let mut done = 0usize;
                    for (address, n) in segs {
                        if done + n > len {
                            break;
                        }
                        let bytes = self.region_vec(address, n).unwrap_or_else(|| vec![0; n]);
                        flat[done..done + n].copy_from_slice(&bytes);
                        done += n;
                    }
                    for b in 0..(len / bs) {
                        self.disk
                            .insert(lba + b as u64, flat[b * bs..(b + 1) * bs].to_vec());
                    }
                } else {
                    let mut flat = vec![0u8; len];
                    for b in 0..(len / bs) {
                        if let Some(block) = self.disk.get(&(lba + b as u64)) {
                            flat[b * bs..(b + 1) * bs].copy_from_slice(block);
                        }
                    }
                    let mut done = 0usize;
                    for (address, n) in segs {
                        if done + n > len {
                            break;
                        }
                        self.write_mem(address, &flat[done..done + n]).ok();
                        done += n;
                    }
                }
            }
            0x00 => {} // Flush: no payload.
            _ => err = 1 << 1,
        }
        self.command_error = err;
        self.push_io_completion(cid);
        self.io_sq_tail = (slot + 1) % self.io_depth;
        self.io_cq_tail = (self.io_cq_tail + 1) % self.io_depth;
        if self.io_cq_tail == 0 {
            self.io_phase = !self.io_phase;
        }
    }

    fn push_io_completion(&mut self, cid: u16) {
        if let Some(base) = self.io_cq_base {
            let at = base + (self.io_cq_tail * 16) as u64;
            let mut raw = [0u8; 16];
            raw[12..14].copy_from_slice(&cid.to_le_bytes());
            let status = u16::from(self.io_phase) | self.completion_status | self.command_error;
            raw[14..16].copy_from_slice(&status.to_le_bytes());
            self.write_mem(at, &raw).ok();
        }
        self.io_completed.push(cid);
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
                self.csts = if value & CC_EN == 0 { 0 } else { CSTS_RDY };
            }
            REG_ASQ => self.asq = (self.asq & 0xffff_ffff_0000_0000) | u64::from(value),
            x if x == REG_ASQ + 4 => {
                self.asq = (self.asq & 0xffff_ffff) | (u64::from(value) << 32);
            }
            REG_ACQ => self.acq = (self.acq & 0xffff_ffff_0000_0000) | u64::from(value),
            x if x == REG_ACQ + 4 => {
                self.acq = (self.acq & 0xffff_ffff) | (u64::from(value) << 32);
            }
            ADMIN_DOORBELL => self.on_admin_doorbell(),
            IO_SQ_DOORBELL => {
                self.io_doorbell_writes += 1;
                self.on_io_doorbell();
            }
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

struct CountingDelay;

impl Delay for CountingDelay {
    fn delay_us(&mut self, _us: u32) {}
}

type Controller = NvmeController<FakeRegs, FakeDma, CountingDelay>;

fn controller_with(namespace_blocks: u64, lbads: u8, mdts: u8) -> (Controller, Shared) {
    let mut dev = Device::new();
    dev.namespace_blocks = namespace_blocks;
    dev.lbads = lbads;
    dev.mdts = mdts;
    let shared: Shared = Rc::new(RefCell::new(dev));
    let regs = FakeRegs {
        shared: shared.clone(),
    };
    let dma = FakeDma {
        shared: shared.clone(),
    };
    let controller =
        NvmeController::init(regs, dma, CountingDelay).expect("controller init should succeed");
    (controller, shared)
}

fn controller() -> (Controller, Shared) {
    controller_with(NS_BLOCKS, 9, 0)
}

fn cdw(cmd: &[u8; 64], dword: usize) -> u32 {
    u32::from_le_bytes(cmd[dword * 4..dword * 4 + 4].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn write_one_block_encodes_opcode_nsid_lba_nlb_and_prp1() {
    let (mut c, shared) = controller();
    c.create_io_queues(4).unwrap();

    let before = shared.borrow().regions.len();
    c.write_blocks(5, &[0xab; BLOCK_SIZE]).unwrap();

    let dev = shared.borrow();
    assert_eq!(dev.io_commands, 1, "one block -> one I/O command");
    let cmd = *dev.io_log.last().unwrap();
    assert_eq!(cmd[0] & 0x7f, 0x01, "NVM Write opcode");
    assert_eq!(cdw(&cmd, 1), 1, "NSID = 1");
    assert_eq!(cdw(&cmd, 10), 5, "CDW10 = LBA low");
    assert_eq!(cdw(&cmd, 11), 0, "CDW11 = LBA high");
    assert_eq!(cdw(&cmd, 12), 0, "CDW12 = NLB = blocks - 1");
    let p1 = u64::from_le_bytes(cmd[24..32].try_into().unwrap());
    let p2 = u64::from_le_bytes(cmd[32..40].try_into().unwrap());
    assert_eq!(p2, 0, "single page transfer has no PRP2");
    assert_eq!(p1 & (PAGE_SIZE as u64 - 1), 0, "PRP1 is page aligned");
    assert_eq!(
        dev.regions[before].base, p1,
        "PRP1 points at the write buffer"
    );
    assert_eq!(dev.regions[before].len, BLOCK_SIZE);
    assert_eq!(dev.io_cids.len(), 1);
}

#[test]
fn write_eight_blocks_is_one_command_with_nlb_seven() {
    let (mut c, shared) = controller();
    c.create_io_queues(4).unwrap();

    let before = shared.borrow().regions.len();
    let data: Vec<u8> = (0..8 * BLOCK_SIZE).map(|i| i as u8).collect();
    c.write_blocks(100, &data).unwrap();

    let dev = shared.borrow();
    assert_eq!(dev.io_commands, 1, "8 blocks fit in one MDTS chunk");
    let cmd = *dev.io_log.last().unwrap();
    assert_eq!(cdw(&cmd, 12), 7, "NLB = 8 - 1");
    assert_eq!(cdw(&cmd, 10), 100, "starting LBA");
    assert_eq!(cdw(&cmd, 1), 1, "NSID = 1");
    let p1 = u64::from_le_bytes(cmd[24..32].try_into().unwrap());
    assert_eq!(dev.regions[before].base, p1);
    assert_eq!(dev.regions[before].len, 8 * BLOCK_SIZE);
}

#[test]
fn offset_write_splits_lba_across_cdw10_and_cdw11() {
    let (mut c, shared) = controller_with(0x1_0000_0010, 9, 0);
    c.create_io_queues(4).unwrap();

    let lba = 0x1_0000_0003u64;
    c.write_blocks(lba, &[0x5a; 2 * BLOCK_SIZE]).unwrap();

    let dev = shared.borrow();
    let cmd = *dev.io_log.last().unwrap();
    let lo = cdw(&cmd, 10);
    let hi = cdw(&cmd, 11);
    assert_eq!(lo, 3, "CDW10 = low 32 bits of LBA");
    assert_eq!(hi, 1, "CDW11 = high 32 bits of LBA");
    assert_eq!(u64::from(lo) | (u64::from(hi) << 32), lba);
    assert_eq!(cdw(&cmd, 12), 1, "NLB for 2 blocks");
}

#[test]
fn write_past_block_count_is_out_of_range_without_io_submission() {
    let (mut c, shared) = controller_with(16, 9, 0);
    c.create_io_queues(4).unwrap();

    let (cmds, doors, allocs) = {
        let dev = shared.borrow();
        (dev.io_commands, dev.io_doorbell_writes, dev.regions.len())
    };

    assert_eq!(
        c.write_blocks(16, &[0u8; BLOCK_SIZE]),
        Err(BlockError::OutOfRange)
    );
    assert_eq!(
        c.write_blocks(15, &[0u8; 2 * BLOCK_SIZE]),
        Err(BlockError::OutOfRange)
    );
    assert_eq!(
        c.write_blocks(u64::MAX, &[0u8; BLOCK_SIZE]),
        Err(BlockError::OutOfRange)
    );

    let dev = shared.borrow();
    assert_eq!(dev.io_commands, cmds, "no I/O command submitted");
    assert_eq!(dev.io_doorbell_writes, doors, "no I/O doorbell rung");
    assert_eq!(
        dev.regions.len(),
        allocs,
        "no DMA allocated for a rejected write"
    );
}

#[test]
fn empty_and_non_block_multiple_buffers_are_invalid_input() {
    let (mut c, shared) = controller();
    c.create_io_queues(4).unwrap();

    let doors = shared.borrow().io_doorbell_writes;
    assert_eq!(c.write_blocks(0, &[]), Err(BlockError::InvalidInput));
    assert_eq!(
        c.write_blocks(0, &[0u8; BLOCK_SIZE + 1]),
        Err(BlockError::InvalidInput)
    );
    assert_eq!(
        c.write_blocks(7, &[0u8; BLOCK_SIZE - 1]),
        Err(BlockError::InvalidInput)
    );
    assert_eq!(
        shared.borrow().io_doorbell_writes,
        doors,
        "invalid input must not reach the doorbell"
    );
    assert_eq!(shared.borrow().io_commands, 0);
}

#[test]
fn each_io_command_gets_a_new_cid_and_completion_is_consumed() {
    let (mut c, shared) = controller();
    c.create_io_queues(4).unwrap();

    c.write_blocks(0, &[1u8; BLOCK_SIZE]).unwrap();
    c.write_blocks(1, &[2u8; 2 * BLOCK_SIZE]).unwrap();
    c.write_blocks(10, &[3u8; BLOCK_SIZE]).unwrap();

    let dev = shared.borrow();
    assert_eq!(dev.io_commands, 3);
    assert_eq!(dev.io_cids.len(), 3, "one CID per submitted command");
    assert_eq!(
        dev.io_completed, dev.io_cids,
        "each completion echoed the submitted CID, so submit_io consumed it"
    );
    for pair in dev.io_cids.windows(2) {
        assert!(pair[0] < pair[1], "CIDs must be fresh and increasing");
    }
    let mut unique = dev.io_cids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), dev.io_cids.len(), "CIDs must never be reused");
}

#[test]
fn nonzero_write_completion_maps_to_device_error() {
    let (mut c, shared) = controller();
    c.create_io_queues(4).unwrap();
    shared.borrow_mut().completion_status = 2; // status >> 1 == 1 -> nonzero

    assert_eq!(
        c.write_blocks(0, &[7u8; BLOCK_SIZE]),
        Err(BlockError::DeviceError)
    );
}

#[test]
fn mdts_chunking_submits_per_chunk_commands_with_correct_lba_and_nlb() {
    let (mut c, shared) = controller();
    c.create_io_queues(4).unwrap();

    let before = shared.borrow().regions.len();
    let blocks = 300usize;
    let data: Vec<u8> = (0..blocks * BLOCK_SIZE).map(|i| (i % 251) as u8).collect();
    c.write_blocks(20, &data).unwrap();

    let dev = shared.borrow();
    assert_eq!(
        dev.io_commands, 2,
        "300 blocks split at the 128 KiB MDTS cap -> 256 + 44"
    );
    let c0 = dev.io_log[0];
    let c1 = dev.io_log[1];
    assert_eq!(cdw(&c0, 12), 255, "first chunk NLB = 256 - 1");
    assert_eq!(cdw(&c1, 12), 43, "second chunk NLB = 44 - 1");
    assert_eq!(cdw(&c0, 10), 20, "first chunk starting LBA");
    assert_eq!(
        cdw(&c1, 10),
        20 + 256,
        "second chunk advances by 256 blocks"
    );
    assert_eq!(
        dev.regions[before].base,
        u64::from_le_bytes(c0[24..32].try_into().unwrap()),
        "first chunk PRP1 points at its own data region"
    );
    let c1_p1 = u64::from_le_bytes(c1[24..32].try_into().unwrap());
    assert!(
        dev.regions.iter().any(|r| r.base == c1_p1),
        "second chunk PRP1 points at its own data region"
    );
    drop(dev);

    let mut out = vec![0u8; data.len()];
    c.read_blocks(20, &mut out).unwrap();
    assert_eq!(out, data, "chunked write round-trips exactly");
}

#[test]
fn written_bytes_read_back_exactly() {
    let (mut c, _shared) = controller();
    c.create_io_queues(4).unwrap();

    let data: Vec<u8> = (0..8 * BLOCK_SIZE).map(|i| (i * 31 + 7) as u8).collect();
    c.write_blocks(1234, &data).unwrap();

    let mut out = vec![0u8; data.len()];
    c.read_blocks(1234, &mut out).unwrap();
    assert_eq!(out, data, "read-back must match the written bytes exactly");

    // A never-written region reads back as zeros.
    let mut zero = [0xffu8; BLOCK_SIZE];
    c.read_blocks(9999, &mut zero).unwrap();
    assert_eq!(zero, [0u8; BLOCK_SIZE]);

    // An offset read returns exactly the bytes written at that offset.
    let mut tail = [0u8; BLOCK_SIZE];
    c.read_blocks(1234 + 7, &mut tail).unwrap();
    assert_eq!(tail, data[7 * BLOCK_SIZE..8 * BLOCK_SIZE]);
}
