//! Oracle D2: NVMe Identify (CNS=1 controller, CNS=0 namespace) integration tests.
//!
//! Self-contained external test crate. It implements its own `Registers`,
//! `DmaMemory`, and `Delay` fakes (OracleRegs/OracleDma/OracleDelay) that model
//! an in-memory controller answering admin Identify commands by writing the
//! 4096-byte identify payload into the PRP1 buffer. No hardware, no sleeps.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use aienos_kernel::block::BlockDevice;
use aienos_kernel::nvme::driver::{
    Delay, DmaMemory, DmaRegion, NamespaceInfo, NvmeController, NvmeError,
};
use aienos_kernel::nvme::{Registers, CC_EN, CSTS_RDY, REG_ACQ, REG_ASQ, REG_CC, REG_CSTS};

const ADMIN_DEPTH: usize = 8;
const IO_DEPTH: usize = 8;

// Doorbell offsets for CAP.DSTRD = 0 (stride 4): doorbell_offset() yields these.
const ADMIN_SQ_DB: u32 = 0x1000; // qid 0, submission
const IO_SQ_DB: u32 = 0x1008; // qid 1, submission

type Store = Rc<RefCell<BTreeMap<u64, Vec<u8>>>>;

// ---------------------------------------------------------------------------
// DMA fake: page-aligned bump allocator over a shared physical->bytes map.
// ---------------------------------------------------------------------------

struct OracleDma {
    store: Store,
    next: u64,
}

impl DmaMemory for OracleDma {
    fn allocate(&mut self, size: usize, alignment: usize) -> Result<DmaRegion, NvmeError> {
        let mask = alignment as u64 - 1;
        let physical = (self.next + mask) & !mask;
        self.next = physical + size as u64;
        self.store.borrow_mut().insert(physical, vec![0; size]);
        Ok(DmaRegion {
            physical,
            bytes: vec![0; size],
        })
    }

    fn read(&self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError> {
        let store = self.store.borrow();
        let (base, bytes) = store.range(..=physical).next_back().ok_or(NvmeError::Dma)?;
        let offset = (physical - base) as usize;
        output.copy_from_slice(
            bytes
                .get(offset..offset + output.len())
                .ok_or(NvmeError::Dma)?,
        );
        Ok(())
    }

    fn write(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> {
        let mut store = self.store.borrow_mut();
        let (base, bytes) = store
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

// ---------------------------------------------------------------------------
// Registers fake: executes admin/IO commands when the matching doorbell is rung.
// ---------------------------------------------------------------------------

struct OracleRegs {
    store: Store,
    cc: u32,
    writes: Vec<(u32, u32)>,

    // Canned Identify responses.
    namespace_size: u64,
    flbas: u8,
    lbads: u8,
    mdts: u8,
    nsid_zero_error: bool,

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
}

impl Registers for OracleRegs {
    fn read32(&mut self, offset: u32) -> u32 {
        match offset {
            0 => 0x0100_03ff, // CAP.TO = 1 (500 ms units), DSTRD = 0, MQES = 1023
            4 => 0,
            REG_CC => self.cc,
            REG_CSTS if self.cc & CC_EN != 0 => CSTS_RDY,
            REG_CSTS => 0,
            _ => 0,
        }
    }

    fn write32(&mut self, offset: u32, value: u32) {
        self.writes.push((offset, value));

        match offset {
            REG_CC => self.cc = value,
            REG_ASQ => self.admin_sq = (self.admin_sq & !0xffff_ffff) | value as u64,
            x if x == REG_ASQ + 4 => {
                self.admin_sq = (self.admin_sq & 0xffff_ffff) | ((value as u64) << 32)
            }
            REG_ACQ => self.admin_cq = (self.admin_cq & !0xffff_ffff) | value as u64,
            x if x == REG_ACQ + 4 => {
                self.admin_cq = (self.admin_cq & 0xffff_ffff) | ((value as u64) << 32)
            }
            _ => {}
        }

        if offset == ADMIN_SQ_DB {
            self.run_admin();
        } else if offset == IO_SQ_DB {
            self.run_io();
        }
    }
}

impl OracleRegs {
    fn run_admin(&mut self) {
        let admin_sq = self.admin_sq;
        let admin_cq = self.admin_cq;
        let mut memory = self.store.borrow_mut();

        let at = self.admin_sq_tail * 64;
        let command = memory
            .get(&admin_sq)
            .expect("admin SQ allocated")
            .get(at..at + 64)
            .expect("admin SQE in range")
            .to_vec();

        let opcode = command[0];
        let cid = u16::from_le_bytes(command[2..4].try_into().unwrap());
        let nsid = u32::from_le_bytes(command[4..8].try_into().unwrap());
        let prp = u64::from_le_bytes(command[24..32].try_into().unwrap());
        let cdw10 = u32::from_le_bytes(command[40..44].try_into().unwrap());
        let cdw11 = u32::from_le_bytes(command[44..48].try_into().unwrap());

        self.command_error = 0;

        match opcode {
            0x06 => {
                // Identify: CNS in cdw10; answer into the PRP1 buffer.
                let cns = cdw10;
                let data = memory.get_mut(&prp).expect("identify buffer allocated");
                data.fill(0);
                if cns == 1 {
                    data[77] = self.mdts;
                } else if self.nsid_zero_error && nsid == 0 {
                    self.command_error = 1 << 1;
                } else {
                    data[0..8].copy_from_slice(&self.namespace_size.to_le_bytes());
                    // Descriptor 0 decoy: must be ignored when FLBAS selects another.
                    data[130] = 9;
                    let flbas = (self.flbas & 0x0f) as usize;
                    data[26] = flbas as u8;
                    let descriptor = 128 + flbas * 4;
                    data[descriptor + 2] = self.lbads;
                }
            }
            0x05 => {
                // Create I/O CQ: remember buffer + depth (QID 1).
                self.io_cq = prp;
                self.io_depth = ((cdw10 >> 16) & 0xffff) as usize + 1;
            }
            0x01 if cdw10 & 0xffff == 1 && cdw11 & 0xffff == 1 => {
                // Create I/O SQ: remember buffer (QID 1).
                self.io_sq = prp;
            }
            _ => {}
        }

        {
            let cqe = memory.get_mut(&admin_cq).expect("admin CQ allocated");
            let at = self.admin_cq_tail * 16;
            cqe[at + 12..at + 14].copy_from_slice(&cid.to_le_bytes());
            cqe[at + 14..at + 16]
                .copy_from_slice(&((self.admin_phase as u16) | self.command_error).to_le_bytes());
        }
        self.admin_cq_tail = (self.admin_cq_tail + 1) % ADMIN_DEPTH;
        if self.admin_cq_tail == 0 {
            self.admin_phase = !self.admin_phase;
        }
        self.admin_sq_tail = (self.admin_sq_tail + 1) % ADMIN_DEPTH;
    }

    fn run_io(&mut self) {
        let io_sq = self.io_sq;
        let io_cq = self.io_cq;
        let mut memory = self.store.borrow_mut();

        let at = self.io_sq_tail * 64;
        let command = memory
            .get(&io_sq)
            .expect("I/O SQ allocated")
            .get(at..at + 64)
            .expect("I/O SQE in range")
            .to_vec();
        let cid = u16::from_le_bytes(command[2..4].try_into().unwrap());

        self.command_error = 0;

        let cqe = memory.get_mut(&io_cq).expect("I/O CQ allocated");
        let cq_at = self.io_cq_tail * 16;
        cqe[cq_at + 12..cq_at + 14].copy_from_slice(&cid.to_le_bytes());
        cqe[cq_at + 14..cq_at + 16]
            .copy_from_slice(&((self.io_phase as u16) | self.command_error).to_le_bytes());

        self.io_cq_tail = (self.io_cq_tail + 1) % self.io_depth;
        if self.io_cq_tail == 0 {
            self.io_phase = !self.io_phase;
        }
        self.io_sq_tail = (self.io_sq_tail + 1) % self.io_depth;
    }
}

#[derive(Default)]
struct OracleDelay {
    waited_us: u64,
}

impl Delay for OracleDelay {
    fn delay_us(&mut self, us: u32) {
        self.waited_us += u64::from(us);
    }
}

fn oracle(namespace_size: u64) -> (OracleRegs, OracleDma) {
    let store: Store = Rc::new(RefCell::new(BTreeMap::new()));
    (
        OracleRegs {
            store: store.clone(),
            cc: 0,
            writes: Vec::new(),
            namespace_size,
            flbas: 0,
            lbads: 9,
            mdts: 0,
            nsid_zero_error: false,
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
            io_depth: IO_DEPTH,
        },
        OracleDma {
            store,
            next: 0x1000,
        },
    )
}

type Ctrl = NvmeController<OracleRegs, OracleDma, OracleDelay>;

fn io_submissions(c: &Ctrl) -> usize {
    c.registers
        .writes
        .iter()
        .filter(|(offset, _)| *offset == IO_SQ_DB)
        .count()
}

// ---------------------------------------------------------------------------
// MDTS (Identify Controller, CNS=1): observable via transfer chunk count.
// MDTS is not publicly readable, so byte 77 is asserted through chunking.
// ---------------------------------------------------------------------------

#[test]
fn mdts_byte_77_controls_transfer_chunking() {
    // MDTS = 0 -> 128 KiB cap -> a 32 KiB write is one command.
    let (regs, dma) = oracle(12345);
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();
    c.create_io_queues(IO_DEPTH as u16).unwrap();
    let data = vec![0u8; 32 * 1024];
    c.write_blocks(0, &data).unwrap();
    assert_eq!(
        io_submissions(&c),
        1,
        "MDTS=0 should allow one 32 KiB command"
    );

    // MDTS = 1 -> PAGE_SIZE << 1 = 8 KiB per command -> four commands.
    let (mut regs, dma) = oracle(12345);
    regs.mdts = 1;
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();
    c.create_io_queues(IO_DEPTH as u16).unwrap();
    c.write_blocks(0, &data).unwrap();
    assert_eq!(
        io_submissions(&c),
        4,
        "MDTS=1 should split 32 KiB into 8 KiB chunks"
    );
}

// ---------------------------------------------------------------------------
// Capacity round-trip after init (init runs Identify Controller then Namespace).
// ---------------------------------------------------------------------------

#[test]
fn init_identifies_namespace_and_capacity_round_trips() {
    let (regs, dma) = oracle(4096);
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();
    assert_eq!(
        c.identify_namespace(1).unwrap(),
        NamespaceInfo {
            block_count: 4096,
            block_size: 512,
        }
    );
    assert_eq!(c.block_count(), 4096, "BlockDevice capacity after init");
    assert_eq!(c.block_size(), 512);
}

// ---------------------------------------------------------------------------
// Invalid namespace geometries.
// ---------------------------------------------------------------------------

#[test]
fn zero_block_count_is_invalid_identify() {
    let (regs, dma) = oracle(12345);
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();
    c.registers.namespace_size = 0;
    assert_eq!(c.identify_namespace(1), Err(NvmeError::InvalidIdentify));
}

#[test]
fn lbads_at_or_above_32_is_invalid_identify() {
    let (regs, dma) = oracle(12345);
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();
    for bad in [32u8, 33, 64, 255] {
        c.registers.lbads = bad;
        assert_eq!(
            c.identify_namespace(1),
            Err(NvmeError::InvalidIdentify),
            "lbads {bad} must be rejected"
        );
    }
}

#[test]
fn lbads_9_and_12_map_to_block_sizes() {
    let (regs, dma) = oracle(12345);
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();

    c.registers.lbads = 9;
    assert_eq!(c.identify_namespace(1).unwrap().block_size, 512);

    c.registers.lbads = 12;
    assert_eq!(c.identify_namespace(1).unwrap().block_size, 4096);
}

// ---------------------------------------------------------------------------
// FLBAS selects a nonzero LBA-format descriptor.
// ---------------------------------------------------------------------------

#[test]
fn nonzero_flbas_selects_its_own_descriptor() {
    let (regs, dma) = oracle(12345);
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();

    // Descriptor 0 is a decoy (lbads 9 -> 512). Selecting index 2 with lbads 12
    // must yield 4096, proving descriptor 128 + flbas*4 + 2 is read.
    c.registers.flbas = 2;
    c.registers.lbads = 12;
    assert_eq!(
        c.identify_namespace(1).unwrap(),
        NamespaceInfo {
            block_count: 12345,
            block_size: 4096,
        }
    );

    // Back to descriptor 0.
    c.registers.flbas = 0;
    c.registers.lbads = 9;
    assert_eq!(c.identify_namespace(1).unwrap().block_size, 512);
}

#[test]
fn maximum_flbas_descriptor_offset_stays_in_bounds() {
    // FLBAS is masked with 0x0f, so the largest descriptor is 128 + 15*4 + 2 = 190,
    // always inside the 4096-byte identify buffer. Assert the boundary is safe.
    let (regs, dma) = oracle(12345);
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();
    c.registers.flbas = 0xff; // low nibble 15
    c.registers.lbads = 12;
    assert_eq!(c.identify_namespace(1).unwrap().block_size, 4096);
}

// ---------------------------------------------------------------------------
// Unsupported geometry must not panic.
// ---------------------------------------------------------------------------

#[test]
fn nsid_zero_identify_does_not_panic() {
    let (regs, dma) = oracle(12345);
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();

    // NSID 0 is not a valid target namespace; surface an error, never panic.
    c.registers.nsid_zero_error = true;
    assert!(matches!(
        c.identify_namespace(0),
        Err(NvmeError::CompletionStatus { sc: 1, .. })
    ));
}

#[test]
fn mdts_255_shift_does_not_panic() {
    // MDTS = 255 would make PAGE_SIZE.checked_shl(255) overflow; the driver must
    // fall back (128 KiB) and complete the transfer without panicking.
    let (mut regs, dma) = oracle(12345);
    regs.mdts = 255;
    let mut c: Ctrl = NvmeController::init(regs, dma, OracleDelay::default()).unwrap();
    c.create_io_queues(IO_DEPTH as u16).unwrap();
    let mut buffer = vec![0u8; 512];
    c.read_blocks(0, &mut buffer).unwrap();
}
