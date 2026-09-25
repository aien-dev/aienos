//! D3 adversarial tests for the AIENOS P3 native NVMe **write + flush** lane.
//!
//! Target: `crates/aienos-kernel/tests/nvme_write_prp.rs`. Baseline:
//! aien-dev/aienos @ ef359ec.
//!
//! Pure PRP geometry is asserted against the real
//! `aienos_kernel::nvme::build_prps` with exact expected values. Transfer
//! behavior (one-block writes, page-crossing, MDTS chunk splitting, LBA range
//! rejection, flush) is driven through a self-contained fake controller built
//! only from the public `Registers`/`DmaMemory`/`Delay` traits, which records
//! every I/O command it is handed. No sleeps, no hardware, no repo internals.

use std::cell::RefCell;
use std::rc::Rc;

use aienos_kernel::block::{BlockDevice, BlockError};
use aienos_kernel::nvme::driver::{
    Delay, DmaMemory, DmaRegion, NvmeController, NvmeError, ADMIN_DEPTH, PAGE_SIZE,
};
use aienos_kernel::nvme::{
    build_prps, doorbell_offset, PrpError, Registers, CC_EN, CSTS_RDY, REG_ACQ, REG_ASQ, REG_CC,
    REG_CSTS,
};

const P4K: usize = 4096;
const P64K: usize = 65536;
/// CAP.TO = 1 (500 ms units), MQES = 1023, DSTRD = 0, MPSMIN = 0.
const CAP_LOW: u32 = 0x0100_03ff;
const STRIDE: u32 = 4;
const ADMIN_SQ_DB: u32 = doorbell_offset(0, false, STRIDE);
const IO_SQ_DB: u32 = doorbell_offset(1, false, STRIDE);

// ---------------------------------------------------------------------------
// Fake controller: an in-memory NVMe device answering admin and I/O commands.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IoCommand {
    opcode: u8,
    nsid: u32,
    lba: u64,
    blocks: u16,
    prp1: u64,
    prp2: u64,
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
    namespace_size: u64,
    mdts: u8,
    command_error: u16,
    admin_sq: u64,
    admin_cq: u64,
    admin_sq_tail: usize,
    admin_cq_tail: usize,
    admin_phase: bool,
    io_sq: u64,
    io_cq: u64,
    io_sq_tail: usize,
    io_cq_tail: usize,
    io_phase: bool,
    io_depth: usize,
    io_commands: Vec<IoCommand>,
}

impl Device {
    fn new(namespace_size: u64, mdts: u8) -> Self {
        Self {
            regions: Vec::new(),
            next_phys: 0x1000,
            cc: 0,
            csts: 0,
            namespace_size,
            mdts,
            command_error: 0,
            admin_sq: 0,
            admin_cq: 0,
            admin_sq_tail: 0,
            admin_cq_tail: 0,
            admin_phase: true,
            io_sq: 0,
            io_cq: 0,
            io_sq_tail: 0,
            io_cq_tail: 0,
            io_phase: true,
            io_depth: 0,
            io_commands: Vec::new(),
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

    fn region_index(&self, physical: u64, len: usize) -> Option<usize> {
        self.regions
            .iter()
            .position(|r| physical >= r.base && physical + len as u64 <= r.base + r.len as u64)
    }

    fn read_mem(&mut self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError> {
        match self.region_index(physical, output.len()) {
            Some(i) => {
                output.copy_from_slice(&self.regions[i].bytes[..output.len()]);
                Ok(())
            }
            None => Err(NvmeError::Dma),
        }
    }

    fn write_mem(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> {
        match self.region_index(physical, input.len()) {
            Some(i) => {
                self.regions[i].bytes[..input.len()].copy_from_slice(input);
                Ok(())
            }
            None => Err(NvmeError::Dma),
        }
    }

    fn poke(&mut self, physical: u64, bytes: &[u8]) {
        if let Some(i) = self.region_index(physical, bytes.len()) {
            self.regions[i].bytes[..bytes.len()].copy_from_slice(bytes);
        }
    }

    fn peek_command(&self, base: u64, slot: usize) -> [u8; 64] {
        let addr = base + (slot * 64) as u64;
        let mut out = [0u8; 64];
        if let Some(i) = self.region_index(addr, 64) {
            out.copy_from_slice(&self.regions[i].bytes[..64]);
        }
        out
    }

    fn fill_identify(&mut self, prp: u64, cns: u32) {
        if let Some(i) = self.region_index(prp, PAGE_SIZE) {
            let data = &mut self.regions[i].bytes;
            data.fill(0);
            if cns == 1 {
                data[77] = self.mdts;
            } else {
                data[0..8].copy_from_slice(&self.namespace_size.to_le_bytes());
                data[26] = 0; // FLBAS -> format 0
                data[130] = 9; // LBADS -> 512-byte blocks
            }
        }
    }

    fn run_admin(&mut self) {
        let slot = self.admin_sq_tail;
        let cmd = self.peek_command(self.admin_sq, slot);
        let opcode = cmd[0];
        let cid = u16::from_le_bytes([cmd[2], cmd[3]]);
        let prp = u64::from_le_bytes(cmd[24..32].try_into().unwrap());
        let cdw10 = u32::from_le_bytes(cmd[40..44].try_into().unwrap());
        let cdw11 = u32::from_le_bytes(cmd[44..48].try_into().unwrap());
        self.command_error = 0;
        match opcode {
            0x06 => self.fill_identify(prp, cdw10),
            0x05 => {
                self.io_cq = prp;
                self.io_depth = ((cdw10 >> 16) & 0xffff) as usize + 1;
            }
            0x01 if cdw10 & 0xffff == 1 && cdw11 & 0xffff == 1 => self.io_sq = prp,
            _ => {}
        }
        let at = self.admin_cq + (self.admin_cq_tail * 16) as u64;
        let mut cqe = [0u8; 16];
        cqe[12..14].copy_from_slice(&cid.to_le_bytes());
        cqe[14..16]
            .copy_from_slice(&((self.admin_phase as u16) | self.command_error).to_le_bytes());
        self.poke(at, &cqe);
        self.admin_cq_tail = (self.admin_cq_tail + 1) % ADMIN_DEPTH;
        if self.admin_cq_tail == 0 {
            self.admin_phase = !self.admin_phase;
        }
        self.admin_sq_tail = (self.admin_sq_tail + 1) % ADMIN_DEPTH;
    }

    fn run_io(&mut self) {
        let depth = self.io_depth;
        if depth == 0 {
            return;
        }
        let slot = self.io_sq_tail;
        let cmd = self.peek_command(self.io_sq, slot);
        let opcode = cmd[0];
        let cid = u16::from_le_bytes([cmd[2], cmd[3]]);
        let nsid = u32::from_le_bytes(cmd[4..8].try_into().unwrap());
        let prp1 = u64::from_le_bytes(cmd[24..32].try_into().unwrap());
        let prp2 = u64::from_le_bytes(cmd[32..40].try_into().unwrap());
        let lba = u64::from(u32::from_le_bytes(cmd[40..44].try_into().unwrap()))
            | (u64::from(u32::from_le_bytes(cmd[44..48].try_into().unwrap())) << 32);
        let cdw12 = u32::from_le_bytes(cmd[48..52].try_into().unwrap());
        self.io_commands.push(IoCommand {
            opcode,
            nsid,
            lba,
            blocks: ((cdw12 & 0xffff) as u16).wrapping_add(1),
            prp1,
            prp2,
        });
        let at = self.io_cq + (self.io_cq_tail * 16) as u64;
        let mut cqe = [0u8; 16];
        cqe[12..14].copy_from_slice(&cid.to_le_bytes());
        cqe[14..16].copy_from_slice(&((self.io_phase as u16) | self.command_error).to_le_bytes());
        self.poke(at, &cqe);
        self.io_cq_tail = (self.io_cq_tail + 1) % depth;
        if self.io_cq_tail == 0 {
            self.io_phase = !self.io_phase;
        }
        self.io_sq_tail = (self.io_sq_tail + 1) % depth;
    }
}

// ---------------------------------------------------------------------------
// Public-trait fakes over the shared device.
// ---------------------------------------------------------------------------

type Shared = Rc<RefCell<Device>>;

struct FakeRegs {
    dev: Shared,
}

impl Registers for FakeRegs {
    fn read32(&mut self, offset: u32) -> u32 {
        let dev = self.dev.borrow();
        match offset {
            0 => CAP_LOW,
            4 => 0,
            REG_CC => dev.cc,
            REG_CSTS => dev.csts,
            _ => 0,
        }
    }

    fn write32(&mut self, offset: u32, value: u32) {
        let mut dev = self.dev.borrow_mut();
        match offset {
            REG_CC => {
                dev.cc = value;
                dev.csts = if value & CC_EN == 0 { 0 } else { CSTS_RDY };
            }
            REG_ASQ => dev.admin_sq = (dev.admin_sq & !0xffff_ffff) | u64::from(value),
            x if x == REG_ASQ + 4 => {
                dev.admin_sq = (dev.admin_sq & 0xffff_ffff) | (u64::from(value) << 32)
            }
            REG_ACQ => dev.admin_cq = (dev.admin_cq & !0xffff_ffff) | u64::from(value),
            x if x == REG_ACQ + 4 => {
                dev.admin_cq = (dev.admin_cq & 0xffff_ffff) | (u64::from(value) << 32)
            }
            ADMIN_SQ_DB => dev.run_admin(),
            IO_SQ_DB => dev.run_io(),
            _ => {}
        }
    }
}

struct FakeDma {
    dev: Shared,
}

impl DmaMemory for FakeDma {
    fn allocate(&mut self, size: usize, alignment: usize) -> Result<DmaRegion, NvmeError> {
        let physical = self.dev.borrow_mut().alloc(size, alignment);
        Ok(DmaRegion {
            physical,
            bytes: vec![0; size],
        })
    }

    fn read(&self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError> {
        self.dev.borrow_mut().read_mem(physical, output)
    }

    fn write(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> {
        self.dev.borrow_mut().write_mem(physical, input)
    }
}

/// Host stand-in for a real-time delay: the fake device is always ready, so no
/// wait is ever needed. This keeps the tests free of sleeps.
struct NoDelay;

impl Delay for NoDelay {
    fn delay_us(&mut self, _us: u32) {}
}

type Ctrl = NvmeController<FakeRegs, FakeDma, NoDelay>;

fn make(namespace_size: u64, mdts: u8) -> (Ctrl, Shared) {
    let dev: Shared = Rc::new(RefCell::new(Device::new(namespace_size, mdts)));
    let regs = FakeRegs { dev: dev.clone() };
    let dma = FakeDma { dev: dev.clone() };
    let controller = NvmeController::init(regs, dma, NoDelay).expect("init should succeed");
    (controller, dev)
}

fn io_commands(dev: &Shared) -> Vec<IoCommand> {
    dev.borrow().io_commands.clone()
}

// ---------------------------------------------------------------------------
// PRP geometry: one block, page crossings, PRP lists, chaining.
// ---------------------------------------------------------------------------

#[test]
fn one_block_aligned_write_is_single_prp1_page() {
    // 512 bytes from a 4 KiB-aligned address live entirely in page one:
    // PRP1 is the raw address, PRP2 unused, no list entries consumed.
    let mut list = [0xDEAD_BEEFu64; 4];
    assert_eq!(
        build_prps(0x1000, 512, P4K, 0x8000, &mut list).unwrap(),
        (0x1000, 0, 0)
    );
    assert_eq!(list, [0xDEAD_BEEF; 4], "list must be untouched");
}

#[test]
fn write_crossing_page_boundary_uses_prp1_and_prp2() {
    let mut list = [0u64; 0];
    assert_eq!(
        build_prps(0x1000, 2 * P4K, P4K, 0, &mut list).unwrap(),
        (0x1000, 0x2000, 0)
    );
    // Unaligned start: PRP1 stays raw, PRP2 is the next page boundary.
    assert_eq!(
        build_prps(0x1080, P4K, P4K, 0, &mut list).unwrap(),
        (0x1080, 0x2000, 0)
    );
}

#[test]
fn write_spanning_three_pages_uses_prp_list() {
    let list_at = 0x80_0000u64;
    let mut list = [0u64; 4];
    let (p1, p2, used) = build_prps(0x1000, 3 * P4K, P4K, list_at, &mut list).unwrap();
    assert_eq!((p1, p2, used), (0x1000, list_at, 2));
    assert_eq!(list[..2], [0x2000, 0x3000]);
}

#[test]
fn write_page_list_chains_at_4k_exact_entries() {
    const PER: usize = P4K / 8; // 512 entries per 4 KiB list page
    let list_at = 0x80_0000u64;

    let mut full = vec![0u64; PER];
    let (p1, p2, used) = build_prps(0x1000, (1 + PER) * P4K, P4K, list_at, &mut full).unwrap();
    assert_eq!((p1, p2, used), (0x1000, list_at, PER));
    assert_eq!(full[PER - 1], 0x2000 + ((PER - 1) * P4K) as u64);

    let mut chain = vec![0u64; PER + 2];
    let (p1, p2, used) = build_prps(0x1000, (2 + PER) * P4K, P4K, list_at, &mut chain).unwrap();
    assert_eq!((p1, p2, used), (0x1000, list_at, PER + 2));
    assert_eq!(chain[PER - 1], list_at + P4K as u64, "last slot chains");
    assert_eq!(chain[PER - 2], 0x2000 + ((PER - 2) * P4K) as u64);
    assert_eq!(chain[PER], 0x2000 + ((PER - 1) * P4K) as u64);
    assert_eq!(chain[PER + 1], 0x2000 + (PER * P4K) as u64);
}

#[test]
fn write_page_list_chains_at_64k_exact_entries() {
    const PER: usize = P64K / 8; // 8192 entries per 64 KiB list page
    let list_at = 0x200_0000u64;

    let mut full = vec![0u64; PER];
    let (p1, p2, used) = build_prps(0x10000, (1 + PER) * P64K, P64K, list_at, &mut full).unwrap();
    assert_eq!((p1, p2, used), (0x10000, list_at, PER));
    assert_eq!(full[PER - 1], 0x20000 + ((PER - 1) * P64K) as u64);

    let mut chain = vec![0u64; PER + 2];
    let (p1, p2, used) = build_prps(0x10000, (2 + PER) * P64K, P64K, list_at, &mut chain).unwrap();
    assert_eq!((p1, p2, used), (0x10000, list_at, PER + 2));
    assert_eq!(chain[PER - 1], list_at + P64K as u64, "last slot chains");
    assert_eq!(chain[PER - 2], 0x20000 + ((PER - 2) * P64K) as u64);
    assert_eq!(chain[PER], 0x20000 + ((PER - 1) * P64K) as u64);
    assert_eq!(chain[PER + 1], 0x20000 + (PER * P64K) as u64);
}

// ---------------------------------------------------------------------------
// Overflow and misalignment.
// ---------------------------------------------------------------------------

#[test]
fn address_near_u64_max_is_invalid_without_panic_or_wrap() {
    let outcome = std::panic::catch_unwind(|| {
        let mut list = [0u64; 0];
        build_prps(u64::MAX, 2, P4K, 0, &mut list)
    });
    assert_eq!(
        outcome.ok(),
        Some(Err(PrpError::Invalid)),
        "address=u64::MAX length=2 must be Invalid with no panic"
    );

    // Page-aligned address whose second page would wrap past u64::MAX.
    let outcome = std::panic::catch_unwind(|| {
        let mut list = [0u64; 0];
        build_prps(u64::MAX - (P4K as u64 - 1), 2 * P4K, P4K, 0, &mut list)
    });
    assert_eq!(
        outcome.ok(),
        Some(Err(PrpError::Invalid)),
        "second-page wrap past u64::MAX must be Invalid with no panic"
    );
}

#[test]
fn offset_plus_length_overflow_is_invalid() {
    let mut list = [0u64; 4];
    // Unaligned offset + enormous length overflows the covered span.
    assert_eq!(
        build_prps(0x1080, usize::MAX, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
    // Aligned start, length at usize::MAX: page rounding overflows.
    assert_eq!(
        build_prps(0, usize::MAX, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(u64::MAX, u64::MAX as usize, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
}

#[test]
fn unaligned_prp1_spans_pages_correctly() {
    let list_at = 0x80_0000u64;
    let mut list = [0u64; 4];
    // 0x1080 + (2*P4K + 0x100) ends in the third page from an unaligned start.
    // With 3+ pages the second return is the PRP list pointer, and the first
    // list entry is the next page boundary after the raw PRP1.
    let (p1, p2, used) = build_prps(0x1080, 2 * P4K + 0x100, P4K, list_at, &mut list).unwrap();
    assert_eq!((p1, p2, used), (0x1080, list_at, 2));
    assert_eq!(list[..2], [0x2000, 0x3000]);
}

#[test]
fn list_address_zero_or_unaligned_is_invalid_for_list_cases() {
    let mut list = [0u64; 4];
    assert_eq!(
        build_prps(0x1000, 3 * P4K, P4K, 0, &mut list),
        Err(PrpError::Invalid),
        "zero list address with a required list"
    );
    assert_eq!(
        build_prps(0x1000, 3 * P4K, P4K, 0x8001, &mut list),
        Err(PrpError::Invalid),
        "unaligned list address"
    );
    assert_eq!(
        build_prps(0x1000, 3 * P4K, P4K, 0xFFF, &mut list),
        Err(PrpError::Invalid),
        "list address at the top of a page"
    );
    // A zero list address is fine when no list is needed (two pages -> PRP2).
    assert_eq!(
        build_prps(0x1000, 2 * P4K, P4K, 0, &mut list).unwrap(),
        (0x1000, 0x2000, 0)
    );
}

// ---------------------------------------------------------------------------
// Transfer path through the fake controller.
// ---------------------------------------------------------------------------

#[test]
fn write_one_aligned_block_carries_single_prp1() {
    let (mut c, dev) = make(4096, 0);
    c.create_io_queues(8).unwrap();
    c.write_blocks(0, &[0xABu8; 512]).unwrap();

    let cmds = io_commands(&dev);
    assert_eq!(cmds.len(), 1);
    let cmd = cmds[0];
    assert_eq!(cmd.opcode, 0x01, "write opcode");
    assert_eq!(cmd.nsid, 1);
    assert_eq!(cmd.lba, 0);
    assert_eq!(cmd.blocks, 1);
    assert_eq!(
        cmd.prp1 & (PAGE_SIZE as u64 - 1),
        0,
        "PRP1 must be 4 KiB aligned"
    );
    assert_eq!(cmd.prp2, 0, "single-page write must not use PRP2");
}

#[test]
fn multi_block_write_crossing_page_emits_prp2() {
    let (mut c, dev) = make(4096, 0);
    c.create_io_queues(8).unwrap();
    // Nine 512-byte blocks = 4608 bytes: two pages, one command.
    c.write_blocks(3, &vec![0u8; 9 * 512]).unwrap();

    let cmds = io_commands(&dev);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].blocks, 9);
    assert_eq!(cmds[0].lba, 3);
    assert_eq!(cmds[0].prp2, cmds[0].prp1 + PAGE_SIZE as u64);
}

#[test]
fn write_larger_than_mdts_is_split_into_commands() {
    // MDTS = 1 -> PAGE_SIZE << 1 = 8 KiB per command. A 32 KiB write must be
    // split into four sequential 16-block commands in a namespace big enough.
    let (mut c, dev) = make(100_000, 1);
    c.create_io_queues(8).unwrap();
    c.write_blocks(0, &vec![0u8; 32 * 1024]).unwrap();

    let cmds = io_commands(&dev);
    assert_eq!(cmds.len(), 4, "32 KiB / 8 KiB = four commands");
    for (i, cmd) in cmds.iter().enumerate() {
        assert_eq!(cmd.opcode, 0x01);
        assert_eq!(cmd.blocks, 16, "8 KiB = 16 blocks of 512");
        assert_eq!(cmd.lba, (i as u64) * 16, "chunks advance by 16 LBAs");
    }

    // MDTS = 0 -> 128 KiB cap; the same write fits in a single command.
    let (mut c, dev) = make(100_000, 0);
    c.create_io_queues(8).unwrap();
    c.write_blocks(0, &vec![0u8; 32 * 1024]).unwrap();
    assert_eq!(io_commands(&dev).len(), 1);
}

#[test]
fn write_past_namespace_end_is_rejected_before_any_command() {
    let (mut c, dev) = make(100_000, 0);
    c.create_io_queues(8).unwrap();

    // A write starting exactly at the last valid LBA.
    assert_eq!(
        c.write_blocks(100_000, &[0u8; 512]),
        Err(BlockError::OutOfRange)
    );
    // A write that starts in range but whose end exceeds block_count.
    assert_eq!(
        c.write_blocks(99_999, &[0u8; 1024]),
        Err(BlockError::OutOfRange)
    );

    let dev = dev.borrow();
    assert!(dev.io_commands.is_empty(), "no PRP/command may be built");
    assert_eq!(dev.io_sq_tail, 0, "no I/O doorbell may be rung");
}

#[test]
fn flush_submits_opcode_zero_command() {
    let (mut c, dev) = make(4096, 0);
    c.create_io_queues(8).unwrap();
    assert_eq!(c.flush(), Ok(()));

    let cmds = io_commands(&dev);
    assert_eq!(cmds.len(), 1);
    assert_eq!(cmds[0].opcode, 0x00, "flush opcode");
    assert_eq!(cmds[0].nsid, 1);
    assert_eq!(cmds[0].prp1, 0);
    assert_eq!(cmds[0].prp2, 0);
}
