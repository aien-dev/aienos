//! Host-testable SMMUv3 descriptors, queues, and register sequencing.
//!
//! This module does not map MMIO. Register access and the cache maintenance
//! that makes CPU-written tables visible to the SMMU both go through the
//! [`Registers`] trait, so the whole bring-up runs against a fake in host
//! tests.
//!
//! Governing rule: no SMMU confinement means no DMA. The bring-up sets
//! GBPA.ABORT before anything else and never clears it, so a disabled SMMU
//! (SMMUEN = 0) aborts every transaction instead of bypassing. Once SMMUEN is
//! acknowledged, each stream follows its own STE, and every STE this module
//! does not configure is an abort STE.

use crate::mem::frame_allocator::PhysAddr;
use crate::mem::pagetable::{FrameSource, MapFlags, PageTableBuilder, PageTableError, TableMemory};

pub const STE_BYTES: usize = 64;
pub const CD_BYTES: usize = 64;
pub const COMMAND_BYTES: usize = 16;
pub const EVENT_BYTES: usize = 32;
pub const CR0: u32 = 0x20;
pub const CR0ACK: u32 = 0x24;
pub const CR1: u32 = 0x28;
pub const CR2: u32 = 0x2c;
pub const IDR0: u32 = 0x00;
pub const IDR1: u32 = 0x04;
pub const IDR2: u32 = 0x08;
pub const IDR3: u32 = 0x0c;
pub const IDR4: u32 = 0x10;
pub const IDR5: u32 = 0x14;
pub const GBPA: u32 = 0x44;
pub const STRTAB_BASE: u32 = 0x80;
pub const STRTAB_BASE_CFG: u32 = 0x88;
pub const CMDQ_BASE: u32 = 0x90;
pub const CMDQ_PROD: u32 = 0x98;
pub const CMDQ_CONS: u32 = 0x9c;
pub const EVENTQ_BASE: u32 = 0xa0;
/// The event queue indexes live in register page 1 (base + 64 KiB).
pub const EVENTQ_PROD: u32 = 0x1_00a8;
pub const EVENTQ_CONS: u32 = 0x1_00ac;

pub const IDR0_S1P: u32 = 1 << 1;
pub const IDR1_SIDSIZE_MASK: u32 = 0x3f;
const IDR1_EVENTQS_SHIFT: u32 = 16;
const IDR1_CMDQS_SHIFT: u32 = 21;
const IDR1_QS_MASK: u32 = 0x1f;

/// GBPA.ABORT: with SMMUEN clear, abort every incoming transaction.
pub const GBPA_ABORT: u32 = 1 << 20;
/// GBPA.UPDATE: set by software to request an update, cleared by the SMMU
/// once the new GBPA value is in effect.
pub const GBPA_UPDATE: u32 = 1 << 31;

pub const CR0_SMMUEN: u32 = 1 << 0;
pub const CR0_EVENTQEN: u32 = 1 << 2;
pub const CR0_CMDQEN: u32 = 1 << 3;
const CR0_ACK_MASK: u32 = 0x0f;

/// CMDQ_CONS.ERR: non-zero when the SMMU stopped on a bad command.
const CMDQ_CONS_ERR_MASK: u32 = 0x7f << 24;
/// EVENTQ_PROD.OVFLG and EVENTQ_CONS.OVACKFLG.
const EVENTQ_OVERFLOW: u32 = 1 << 31;

/// Default poll bound for every SMMU handshake.
pub const DEFAULT_SPINS: usize = 1_000_000;

/// Platform seam for one SMMUv3 instance: 32-bit register access plus the
/// cache maintenance for memory the SMMU reads or writes.
pub trait Registers {
    fn read(&mut self, offset: u32) -> u32;
    fn write(&mut self, offset: u32, value: u32);

    /// Write a 64-bit register as two 32-bit halves, low half first.
    fn write64(&mut self, offset: u32, value: u64) {
        self.write(offset, value as u32);
        self.write(offset + 4, (value >> 32) as u32);
    }

    /// Make CPU writes to `[address, address + bytes)` visible to the SMMU
    /// before the next register write. There is no default: an implementor
    /// that forgets this on a non-coherent system would hand the SMMU stale
    /// tables.
    fn clean_dma(&mut self, address: usize, bytes: usize);

    /// Drop CPU cache lines over `[address, address + bytes)` so the next CPU
    /// read sees what the SMMU wrote.
    fn invalidate_dma(&mut self, address: usize, bytes: usize);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A poll ran out of spins.
    Timeout,
    /// CMDQ_CONS.ERR reported a command error.
    CommandQueue,
    /// A table, queue, stream id or window failed validation.
    InvalidWindow,
    /// The SMMU lacks a feature this bring-up needs (IDR checks).
    Unsupported,
    /// GBPA did not read back with ABORT set after the update completed.
    AbortNotLatched,
    PageTable(PageTableError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ste(pub [u64; 8]);

impl Ste {
    /// V = 1, Config = 0b000: abort every transaction from the stream.
    /// There is deliberately no bypass constructor.
    pub const fn abort() -> Self {
        Self([1, 0, 0, 0, 0, 0, 0, 0])
    }
    /// Stage-1 translate, stage-2 bypass. STE word 0 holds V (bit 0),
    /// Config (bits 3:1, 0b101 = S1 translate / S2 bypass), S1Fmt (bits 5:4,
    /// 0 = linear, one CD) and S1ContextPtr (bits 51:6, 64-byte aligned).
    pub const fn stage1(cd_address: u64) -> Self {
        Self([
            1 | (0b101 << 1) | (cd_address & 0x000f_ffff_ffff_ffc0),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
    }
}

/// Linear-format, 64-byte context descriptor (eight little-endian words).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextDescriptor(pub [u64; 8]);

impl ContextDescriptor {
    pub fn stage1(ttb0: u64, asid: u16, mair: u64, t0sz: u8) -> Result<Self, Error> {
        if t0sz > 39 || ttb0 & 0xfff != 0 {
            return Err(Error::InvalidWindow);
        }
        // CD word 0 carries the TTBR0/TTBR1 configuration and every control
        // bit: T0SZ, TG0, IRGN0, ORGN0, SH0, EPD0, EPD1, V, IPS, AA64, R, A
        // and ASID. EPD0 stays clear so the TTBR0 stage-1 walk runs; EPD1
        // disables the unused TTBR1 walk.
        let word0 = u64::from(t0sz)
            | (0b01 << 8) // IRGN0: write-back
            | (0b01 << 10) // ORGN0: write-back
            | (0b11 << 12) // SH0: inner shareable
            | (1 << 30) // EPD1: TTBR1 walk disabled
            | (1 << 31) // V: descriptor valid
            | (0b101 << 32) // IPS: 5 (48-bit)
            | (1 << 41) // AA64
            | (1 << 45) // R: record faults as events
            | (1 << 46) // A: abort faulting transactions (not RAZ/WI)
            | (u64::from(asid) << 48);
        // CD word 1 is the 4 KiB-aligned TTBR0 (48-bit physical address).
        let word1 = ttb0 & 0x0000_ffff_ffff_fff0;
        // CD word 2 is TTBR1, unused because EPD1 is set.
        let word2 = 0;
        // CD word 3 is MAIR.
        let word3 = mair & 0x0000_0000_0000_ffff;
        Ok(Self([word0, word1, word2, word3, 0, 0, 0, 0]))
    }
}

pub const CMD_CFGI_STE: u8 = 0x03;
pub const CMD_CFGI_ALL: u8 = 0x04;
pub const CMD_TLBI_NSNH_ALL: u8 = 0x30;
pub const CMD_SYNC: u8 = 0x46;

pub const fn command(opcode: u8, sid: u32, leaf: bool) -> [u64; 2] {
    let word0 = opcode as u64 | ((sid as u64) << 32);
    let word1 = if opcode == CMD_CFGI_ALL {
        31
    } else {
        leaf as u64
    };
    [word0, word1]
}

/// SMMUv3 queue index: for a queue of 2^n entries the register holds the
/// index in bits n-1:0 and the wrap flag in bit n.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueCursor {
    pub index: u32,
    pub wrap: bool,
}

impl QueueCursor {
    /// `entries` must be a power of two.
    pub fn encode(self, entries: u32) -> u32 {
        (self.index & (entries - 1)) | ((self.wrap as u32) << entries.trailing_zeros())
    }

    /// `entries` must be a power of two.
    pub fn decode(value: u32, entries: u32) -> Self {
        Self {
            index: value & (entries - 1),
            wrap: value & entries != 0,
        }
    }

    pub fn advance(&mut self, entries: u32) {
        self.index += 1;
        if self.index == entries {
            self.index = 0;
            self.wrap = !self.wrap;
        }
    }
}

/// Register mapping for an identity-mapped SMMUv3 register aperture
/// (both 64 KiB register pages).
pub struct MmioRegisters {
    base: usize,
}

impl MmioRegisters {
    /// # Safety
    /// `base` must address a mapped SMMUv3 register aperture of 128 KiB.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }
}

impl Registers for MmioRegisters {
    fn read(&mut self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + offset as usize) as *const u32) }
    }

    fn write(&mut self, offset: u32, value: u32) {
        unsafe { core::ptr::write_volatile((self.base + offset as usize) as *mut u32, value) }
    }

    fn clean_dma(&mut self, address: usize, bytes: usize) {
        // Ends with DSB, which also orders the clean before the next MMIO write.
        crate::arch::aarch64::clean_dcache_range(address, bytes);
    }

    fn invalidate_dma(&mut self, address: usize, bytes: usize) {
        crate::arch::aarch64::clean_invalidate_dcache_range(address, bytes);
    }
}

/// The memory one SMMU reads and writes in linear stream table mode: the
/// stream table, the command queue, the event queue and one context
/// descriptor. Addresses are identity mapped (virtual == physical).
#[derive(Debug)]
pub struct LinearTables {
    stream_table: *mut [u64; 8],
    stream_entries: u32,
    command_queue: *mut [u64; 2],
    command_entries: u32,
    event_queue: *mut [u64; 4],
    event_entries: u32,
    context: *mut [u64; 8],
}

fn aligned(address: usize, bytes: usize) -> bool {
    address != 0 && address & (bytes.max(32) - 1) == 0
}

impl LinearTables {
    /// Validate the table geometry: every entry count is a power of two, each
    /// queue has at least two entries, and every base is aligned to its own
    /// size (the SMMU ignores low address bits below the size, so a
    /// misaligned queue would overlap its neighbour).
    ///
    /// # Safety
    /// Each pointer must address live, physically contiguous, identity
    /// mapped RAM visible to the SMMU with room for the stated number of
    /// entries, and nothing else may use that memory while this value (or
    /// the SMMU programmed from it) is in use.
    pub unsafe fn new(
        stream_table: *mut [u64; 8],
        stream_entries: u32,
        command_queue: *mut [u64; 2],
        command_entries: u32,
        event_queue: *mut [u64; 4],
        event_entries: u32,
        context: *mut [u64; 8],
    ) -> Result<Self, Error> {
        let pow2 = |n: u32, min: u32| n >= min && n.is_power_of_two();
        if !pow2(stream_entries, 1)
            || !pow2(command_entries, 2)
            || !pow2(event_entries, 2)
            || !aligned(stream_table as usize, stream_entries as usize * STE_BYTES)
            || !aligned(
                command_queue as usize,
                command_entries as usize * COMMAND_BYTES,
            )
            || !aligned(event_queue as usize, event_entries as usize * EVENT_BYTES)
            || !aligned(context as usize, CD_BYTES)
        {
            return Err(Error::InvalidWindow);
        }
        Ok(Self {
            stream_table,
            stream_entries,
            command_queue,
            command_entries,
            event_queue,
            event_entries,
            context,
        })
    }

    pub fn stream_entries(&self) -> u32 {
        self.stream_entries
    }

    pub fn context_address(&self) -> u64 {
        self.context as u64
    }

    fn write_ste_word(&self, sid: u32, word: usize, value: u64) {
        // Safety: `new` established that the table holds `stream_entries`
        // STEs; callers check `sid` first. A 64-bit aligned store is single
        // copy atomic, so the SMMU never sees a torn word 0.
        unsafe {
            core::ptr::write_volatile(
                (self.stream_table.add(sid as usize) as *mut u64).add(word),
                value,
            )
        }
    }

    fn ste_address(&self, sid: u32) -> usize {
        self.stream_table as usize + sid as usize * STE_BYTES
    }
}

/// Wait for any GBPA update in flight, then request `value` and wait for the
/// SMMU to clear GBPA.UPDATE.
fn update_gbpa<R: Registers>(regs: &mut R, value: u32, spins: usize) -> Result<u32, Error> {
    let mut current = poll_gbpa_idle(regs, spins)?;
    current = (current & !GBPA_UPDATE) | value;
    regs.write(GBPA, current | GBPA_UPDATE);
    poll_gbpa_idle(regs, spins)
}

fn poll_gbpa_idle<R: Registers>(regs: &mut R, spins: usize) -> Result<u32, Error> {
    for _ in 0..spins {
        let gbpa = regs.read(GBPA);
        if gbpa & GBPA_UPDATE == 0 {
            return Ok(gbpa);
        }
    }
    Err(Error::Timeout)
}

/// Set GBPA.ABORT so that whenever SMMUEN is clear every transaction aborts.
pub fn set_global_abort<R: Registers>(regs: &mut R, spins: usize) -> Result<(), Error> {
    let gbpa = update_gbpa(regs, GBPA_ABORT, spins)?;
    if gbpa & GBPA_ABORT == 0 {
        return Err(Error::AbortNotLatched);
    }
    Ok(())
}

fn wait_cr0<R: Registers>(regs: &mut R, expected: u32, spins: usize) -> Result<(), Error> {
    for _ in 0..spins {
        // CR0ACK mirrors the enabled queue and SMMU bits from CR0.
        if regs.read(CR0ACK) & CR0_ACK_MASK == expected & CR0_ACK_MASK {
            return Ok(());
        }
    }
    Err(Error::Timeout)
}

fn cmdq_cons<R: Registers>(regs: &mut R, entries: u32) -> Result<QueueCursor, Error> {
    let cons = regs.read(CMDQ_CONS);
    if cons & CMDQ_CONS_ERR_MASK != 0 {
        return Err(Error::CommandQueue);
    }
    Ok(QueueCursor::decode(cons, entries))
}

/// Append `commands` to the command queue and wait until the SMMU has
/// consumed all of them. Each poll is bounded by `spins`; a stuck queue
/// returns `Error::Timeout` and a command error returns
/// `Error::CommandQueue`. End the batch with `CMD_SYNC` when the caller
/// needs every earlier command to have taken effect.
pub fn submit_commands<R: Registers>(
    regs: &mut R,
    tables: &LinearTables,
    commands: &[[u64; 2]],
    spins: usize,
) -> Result<(), Error> {
    let entries = tables.command_entries;
    let mut prod = QueueCursor::decode(regs.read(CMDQ_PROD), entries);
    for &words in commands {
        // Wait for a free slot: the queue is full when the indexes match and
        // the wrap flags differ.
        let mut has_space = false;
        for _ in 0..spins {
            let cons = cmdq_cons(regs, entries)?;
            if !(cons.index == prod.index && cons.wrap != prod.wrap) {
                has_space = true;
                break;
            }
        }
        if !has_space {
            return Err(Error::Timeout);
        }
        // Safety: `new` established that the queue holds `entries` slots and
        // `prod.index < entries`.
        let slot = unsafe { tables.command_queue.add(prod.index as usize) };
        unsafe { core::ptr::write_volatile(slot, words) };
        regs.clean_dma(slot as usize, COMMAND_BYTES);
        prod.advance(entries);
        regs.write(CMDQ_PROD, prod.encode(entries));
    }
    for _ in 0..spins {
        if cmdq_cons(regs, entries)? == prod {
            return Ok(());
        }
    }
    Err(Error::Timeout)
}

/// Point stream `sid` at `ste` and make the SMMU forget any cached copy.
///
/// The old entry is first replaced by an abort STE (one atomic store of word
/// 0) and invalidated, so the SMMU never sees a half-written entry: the new
/// words 1..7 are written behind that abort, then word 0 last. Finally
/// `CMD_CFGI_STE(sid)`, `CMD_TLBI_NSNH_ALL` and `CMD_SYNC` are issued and
/// waited for.
pub fn install_ste<R: Registers>(
    regs: &mut R,
    tables: &LinearTables,
    sid: u32,
    ste: Ste,
    spins: usize,
) -> Result<(), Error> {
    if sid >= tables.stream_entries {
        return Err(Error::InvalidWindow);
    }
    abort_ste(regs, tables, sid, spins)?;
    for (word, value) in ste.0.iter().enumerate().skip(1) {
        tables.write_ste_word(sid, word, *value);
    }
    // Clean (and, through its DSB, order) words 1..7 before word 0 makes the
    // entry live, so a coherent SMMU cannot fetch the new word 0 with stale
    // words behind it.
    regs.clean_dma(tables.ste_address(sid), STE_BYTES);
    tables.write_ste_word(sid, 0, ste.0[0]);
    invalidate_ste(regs, tables, sid, spins)
}

/// Return stream `sid` to abort: write an abort STE, then issue
/// `CMD_CFGI_STE(sid)`, `CMD_TLBI_NSNH_ALL` and `CMD_SYNC` and wait for them.
/// On `Ok` no further DMA from `sid` can translate.
pub fn abort_ste<R: Registers>(
    regs: &mut R,
    tables: &LinearTables,
    sid: u32,
    spins: usize,
) -> Result<(), Error> {
    if sid >= tables.stream_entries {
        return Err(Error::InvalidWindow);
    }
    let abort = Ste::abort();
    // Word 0 first: once V=1 and Config=abort, the other words are ignored.
    tables.write_ste_word(sid, 0, abort.0[0]);
    for (word, value) in abort.0.iter().enumerate().skip(1) {
        tables.write_ste_word(sid, word, *value);
    }
    invalidate_ste(regs, tables, sid, spins)
}

fn invalidate_ste<R: Registers>(
    regs: &mut R,
    tables: &LinearTables,
    sid: u32,
    spins: usize,
) -> Result<(), Error> {
    regs.clean_dma(tables.ste_address(sid), STE_BYTES);
    submit_commands(
        regs,
        tables,
        &[
            command(CMD_CFGI_STE, sid, true),
            command(CMD_TLBI_NSNH_ALL, 0, false),
            command(CMD_SYNC, 0, false),
        ],
        spins,
    )
}

pub const EVENT_F_UUT: u8 = 0x01;
pub const EVENT_C_BAD_STREAMID: u8 = 0x02;
pub const EVENT_F_STE_FETCH: u8 = 0x03;
pub const EVENT_C_BAD_STE: u8 = 0x04;
pub const EVENT_F_STREAM_DISABLED: u8 = 0x06;
pub const EVENT_F_TRANSL_FORBIDDEN: u8 = 0x07;
pub const EVENT_F_CD_FETCH: u8 = 0x09;
pub const EVENT_C_BAD_CD: u8 = 0x0a;
pub const EVENT_F_WALK_EABT: u8 = 0x0b;
pub const EVENT_F_TRANSLATION: u8 = 0x10;
pub const EVENT_F_ADDR_SIZE: u8 = 0x11;
pub const EVENT_F_ACCESS: u8 = 0x12;
pub const EVENT_F_PERMISSION: u8 = 0x13;

/// One decoded 32-byte event queue record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventRecord {
    /// Word 0 bits 7:0 (see the `EVENT_*` constants).
    pub event_type: u8,
    /// Word 0 bits 63:32.
    pub stream_id: u32,
    /// Word 2: the faulting input address for translation-class events
    /// (`EVENT_F_TRANSLATION` through `EVENT_F_PERMISSION`, and walk faults).
    pub input_address: u64,
    pub raw: [u64; 4],
}

impl EventRecord {
    pub fn decode(raw: [u64; 4]) -> Self {
        Self {
            event_type: raw[0] as u8,
            stream_id: (raw[0] >> 32) as u32,
            input_address: raw[2],
            raw,
        }
    }
}

/// Result of one [`read_events`] call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventDrain {
    /// Records written to the front of the output slice.
    pub count: usize,
    /// The SMMU reported an event queue overflow since the last
    /// acknowledgement (some events were lost). It is acknowledged here.
    pub overflowed: bool,
}

/// Consume event records between EVENTQ_CONS and EVENTQ_PROD, oldest first,
/// up to `out.len()`, then publish the new EVENTQ_CONS. Records left over
/// stay queued for the next call.
pub fn read_events<R: Registers>(
    regs: &mut R,
    tables: &LinearTables,
    out: &mut [EventRecord],
) -> EventDrain {
    let entries = tables.event_entries;
    let prod_raw = regs.read(EVENTQ_PROD);
    let cons_raw = regs.read(EVENTQ_CONS);
    let prod = QueueCursor::decode(prod_raw, entries);
    let mut cons = QueueCursor::decode(cons_raw, entries);
    let overflow_flag = prod_raw & EVENTQ_OVERFLOW;
    let mut count = 0;
    while cons != prod && count < out.len() {
        // Safety: `new` established that the queue holds `entries` records
        // and `cons.index < entries`.
        let slot = unsafe { tables.event_queue.add(cons.index as usize) };
        regs.invalidate_dma(slot as usize, EVENT_BYTES);
        let raw = unsafe { core::ptr::read_volatile(slot) };
        out[count] = EventRecord::decode(raw);
        count += 1;
        cons.advance(entries);
    }
    // Copying OVFLG into OVACKFLG acknowledges an overflow.
    regs.write(EVENTQ_CONS, cons.encode(entries) | overflow_flag);
    EventDrain {
        count,
        overflowed: overflow_flag != cons_raw & EVENTQ_OVERFLOW,
    }
}

/// Bring the SMMU up with every stream in abort except `stream_id`, which
/// translates through `cd` (stage 1 only).
///
/// Order, fail closed at every step:
/// 1. Set GBPA.ABORT and wait for the update. From here on a disabled SMMU
///    aborts all DMA. GBPA.ABORT is never cleared.
/// 2. Check the stream id and that IDR0/IDR1 support the geometry.
/// 3. Write the tables (all abort STEs, the CD, then the one live STE) and
///    clean them to the SMMU.
/// 4. Disable the SMMU, program queues and the stream table, enable the
///    queues, invalidate all cached config and TLBs, then set SMMUEN and wait
///    for CR0ACK.
///
/// If step 1 fails the error is returned without touching CR0 (GBPA may
/// not have latched, so the caller must treat the SMMU as unusable). Any
/// later error writes CR0 = 0, which leaves the SMMU disabled behind
/// GBPA.ABORT (and so aborting every stream), and returns the error.
pub fn configure_linear_stream<R: Registers>(
    regs: &mut R,
    tables: &LinearTables,
    stream_id: u32,
    cd: &ContextDescriptor,
    spins: usize,
) -> Result<(), Error> {
    set_global_abort(regs, spins)?;
    let result = check_and_program(regs, tables, stream_id, cd, spins);
    if result.is_err() {
        // Disable translation so that GBPA.ABORT governs every stream. The
        // acknowledgement wait is best effort: the original error is the
        // one reported, and ABORT stays set either way.
        regs.write(CR0, 0);
        let _ = wait_cr0(regs, 0, spins);
    }
    result
}

fn check_and_program<R: Registers>(
    regs: &mut R,
    tables: &LinearTables,
    stream_id: u32,
    cd: &ContextDescriptor,
    spins: usize,
) -> Result<(), Error> {
    if stream_id >= tables.stream_entries {
        return Err(Error::InvalidWindow);
    }
    let sid_bits = tables.stream_entries.trailing_zeros();
    if regs.read(IDR0) & IDR0_S1P == 0 {
        return Err(Error::Unsupported);
    }
    let idr1 = regs.read(IDR1);
    if idr1 & IDR1_SIDSIZE_MASK < sid_bits
        || (idr1 >> IDR1_CMDQS_SHIFT) & IDR1_QS_MASK < tables.command_entries.trailing_zeros()
        || (idr1 >> IDR1_EVENTQS_SHIFT) & IDR1_QS_MASK < tables.event_entries.trailing_zeros()
    {
        return Err(Error::Unsupported);
    }
    program_linear_stream(regs, tables, stream_id, cd, sid_bits, spins)
}

fn program_linear_stream<R: Registers>(
    regs: &mut R,
    tables: &LinearTables,
    stream_id: u32,
    cd: &ContextDescriptor,
    sid_bits: u32,
    spins: usize,
) -> Result<(), Error> {
    for sid in 0..tables.stream_entries {
        for (word, value) in Ste::abort().0.iter().enumerate() {
            tables.write_ste_word(sid, word, *value);
        }
    }
    // Safety: `LinearTables::new` established the CD and queue geometry.
    unsafe {
        core::ptr::write_volatile(tables.context, cd.0);
        for i in 0..tables.command_entries as usize {
            core::ptr::write_volatile(tables.command_queue.add(i), [0; 2]);
        }
        for i in 0..tables.event_entries as usize {
            core::ptr::write_volatile(tables.event_queue.add(i), [0; 4]);
        }
    }
    let ste = Ste::stage1(tables.context_address());
    for (word, value) in ste.0.iter().enumerate().skip(1) {
        tables.write_ste_word(stream_id, word, *value);
    }
    tables.write_ste_word(stream_id, 0, ste.0[0]);

    // Everything the SMMU will fetch is written; clean it before any
    // register points the SMMU at it.
    regs.clean_dma(
        tables.stream_table as usize,
        tables.stream_entries as usize * STE_BYTES,
    );
    regs.clean_dma(tables.context as usize, CD_BYTES);
    regs.clean_dma(
        tables.command_queue as usize,
        tables.command_entries as usize * COMMAND_BYTES,
    );
    // Clean and invalidate: no dirty CPU line may later overwrite an event.
    regs.invalidate_dma(
        tables.event_queue as usize,
        tables.event_entries as usize * EVENT_BYTES,
    );

    regs.write(CR0, 0);
    wait_cr0(regs, 0, spins)?;
    regs.write(CR1, 0x0d75);
    regs.write64(
        CMDQ_BASE,
        tables.command_queue as u64 | u64::from(tables.command_entries.trailing_zeros()),
    );
    regs.write(CMDQ_CONS, 0);
    regs.write(CMDQ_PROD, 0);
    regs.write64(
        EVENTQ_BASE,
        tables.event_queue as u64 | u64::from(tables.event_entries.trailing_zeros()),
    );
    regs.write(EVENTQ_CONS, 0);
    regs.write(EVENTQ_PROD, 0);
    regs.write(STRTAB_BASE_CFG, sid_bits);
    regs.write64(STRTAB_BASE, tables.stream_table as u64);
    regs.write(CR0, CR0_CMDQEN | CR0_EVENTQEN);
    wait_cr0(regs, CR0_CMDQEN | CR0_EVENTQEN, spins)?;

    submit_commands(
        regs,
        tables,
        &[
            command(CMD_CFGI_ALL, 0, false),
            command(CMD_TLBI_NSNH_ALL, 0, false),
            command(CMD_SYNC, 0, false),
        ],
        spins,
    )?;
    let enable = CR0_SMMUEN | CR0_CMDQEN | CR0_EVENTQEN;
    regs.write(CR0, enable);
    wait_cr0(regs, enable, spins)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaWindow {
    pub iova: usize,
    pub pa: PhysAddr,
    pub length: usize,
}

/// The stage-1 translation for one stream: a page table that maps only the
/// allowed windows and the context descriptor that points at it.
pub struct DmaPolicy<F, M> {
    pub stream_id: u32,
    pub cd: ContextDescriptor,
    pub page_table: PageTableBuilder<F, M>,
}

/// Build an identity-policy stage-1 table: only the supplied windows translate.
/// Hand `policy.cd` to [`configure_linear_stream`] after cleaning the page
/// table frames to the SMMU.
pub fn build_dma_policy<F: FrameSource, M: TableMemory>(
    stream_id: u32,
    asid: u16,
    windows: &[DmaWindow],
    frames: F,
    memory: M,
) -> Result<DmaPolicy<F, M>, Error> {
    let mut table = PageTableBuilder::new(frames, memory).map_err(Error::PageTable)?;
    for window in windows {
        if window.iova != window.pa.0 {
            return Err(Error::InvalidWindow);
        }
        table
            .map(window.iova, window.pa, window.length, MapFlags::KERNEL_DATA)
            .map_err(Error::PageTable)?;
    }
    let cd = ContextDescriptor::stage1(table.root().0 as u64, asid, 0x00ff, 16)?;
    Ok(DmaPolicy {
        stream_id,
        cd,
        page_table: table,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{boxed::Box, cell::RefCell, collections::BTreeMap, vec::Vec};

    const SIDS: u32 = 16;
    const QUEUE: u32 = 16;

    #[repr(C, align(1024))]
    struct TestTables {
        stream: [[u64; 8]; SIDS as usize],
        events: [[u64; 4]; QUEUE as usize],
        commands: [[u64; 2]; QUEUE as usize],
        context: [u64; 8],
    }

    fn test_tables() -> (Box<TestTables>, LinearTables) {
        let mut memory = Box::new(TestTables {
            stream: [[0xdead; 8]; SIDS as usize],
            events: [[0; 4]; QUEUE as usize],
            commands: [[0; 2]; QUEUE as usize],
            context: [0; 8],
        });
        let tables = unsafe {
            LinearTables::new(
                memory.stream.as_mut_ptr(),
                SIDS,
                memory.commands.as_mut_ptr(),
                QUEUE,
                memory.events.as_mut_ptr(),
                QUEUE,
                &mut memory.context,
            )
        }
        .unwrap();
        (memory, tables)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        /// Offset, value, and whether GBPA.ABORT was in effect after it.
        Write(u32, u32, bool),
        Clean(usize, usize),
        Invalidate(usize, usize),
    }

    /// Register model: GBPA.UPDATE clears when the update completes (unless
    /// `gbpa_stuck`), CR0ACK follows CR0 except for `ack_never` bits, and the
    /// command queue consumes everything up to CMDQ_PROD (unless
    /// `cmdq_stuck`), recording the commands it read.
    struct Fake {
        values: BTreeMap<u32, u32>,
        log: Vec<Op>,
        gbpa_stuck: bool,
        ack_never: u32,
        cmdq_stuck: bool,
        cmdq_error: bool,
        consumed: Vec<[u64; 2]>,
    }

    impl Fake {
        fn new() -> Self {
            let mut values = BTreeMap::new();
            values.insert(IDR0, IDR0_S1P);
            values.insert(
                IDR1,
                16 | (19 << IDR1_EVENTQS_SHIFT) | (19 << IDR1_CMDQS_SHIFT),
            );
            // Reset GBPA: bypass (ABORT clear).
            values.insert(GBPA, 0x1000);
            Self {
                values,
                log: Vec::new(),
                gbpa_stuck: false,
                ack_never: 0,
                cmdq_stuck: false,
                cmdq_error: false,
                consumed: Vec::new(),
            }
        }
        fn get(&self, offset: u32) -> u32 {
            *self.values.get(&offset).unwrap_or(&0)
        }
        fn abort_in_effect(&self) -> bool {
            let gbpa = self.get(GBPA);
            gbpa & GBPA_UPDATE == 0 && gbpa & GBPA_ABORT != 0
        }
        fn writes(&self) -> Vec<(u32, u32, bool)> {
            self.log
                .iter()
                .filter_map(|op| match *op {
                    Op::Write(o, v, a) => Some((o, v, a)),
                    _ => None,
                })
                .collect()
        }
        fn position(&self, pred: impl Fn(&Op) -> bool) -> Option<usize> {
            self.log.iter().position(pred)
        }
        fn consume_commands(&mut self, prod: u32) {
            let base = u64::from(self.get(CMDQ_BASE)) | (u64::from(self.get(CMDQ_BASE + 4)) << 32);
            let entries = 1u32 << (base & 0x1f);
            let queue = (base & !0x1f) as *const [u64; 2];
            let mut cons = QueueCursor::decode(self.get(CMDQ_CONS), entries);
            let prod = QueueCursor::decode(prod, entries);
            while cons != prod {
                self.consumed
                    .push(unsafe { core::ptr::read_volatile(queue.add(cons.index as usize)) });
                cons.advance(entries);
            }
            self.values.insert(CMDQ_CONS, cons.encode(entries));
        }
    }

    impl Registers for Fake {
        fn read(&mut self, offset: u32) -> u32 {
            self.get(offset)
        }
        fn write(&mut self, offset: u32, value: u32) {
            let mut stored = value;
            if offset == GBPA && !self.gbpa_stuck {
                stored &= !GBPA_UPDATE;
            }
            self.values.insert(offset, stored);
            match offset {
                CR0 => {
                    self.values.insert(CR0ACK, value & !self.ack_never);
                }
                CMDQ_PROD if self.get(CR0ACK) & CR0_CMDQEN != 0 => {
                    if self.cmdq_error {
                        self.values.insert(CMDQ_CONS, 0x01 << 24);
                    } else if !self.cmdq_stuck {
                        self.consume_commands(value);
                    }
                }
                _ => {}
            }
            let abort = self.abort_in_effect();
            self.log.push(Op::Write(offset, value, abort));
        }
        fn clean_dma(&mut self, address: usize, bytes: usize) {
            self.log.push(Op::Clean(address, bytes));
        }
        fn invalidate_dma(&mut self, address: usize, bytes: usize) {
            self.log.push(Op::Invalidate(address, bytes));
        }
    }

    fn cd() -> ContextDescriptor {
        ContextDescriptor::stage1(0x4000, 1, 0x00ff, 16).unwrap()
    }

    fn smmuen_write(regs: &Fake) -> Option<usize> {
        regs.position(|op| matches!(op, Op::Write(CR0, v, _) if v & CR0_SMMUEN != 0))
    }

    #[test]
    fn descriptor_layouts() {
        assert_eq!(Ste::abort().0[0], 1);
        // Review fix: Config 0b101 (S1 translate) and S1ContextPtr in word 0.
        let ste = Ste::stage1(0x1_2345_6780);
        assert_eq!(ste.0[0] & 1, 1, "V");
        assert_eq!(
            (ste.0[0] >> 1) & 0b111,
            0b101,
            "Config = S1 translate, S2 bypass"
        );
        assert_eq!((ste.0[0] >> 4) & 0b11, 0, "S1Fmt linear");
        assert_eq!(
            ste.0[0] & 0x000f_ffff_ffff_ffc0,
            0x1_2345_6780,
            "S1ContextPtr"
        );
        assert_eq!(&ste.0[1..], &[0; 7]);
        let cd = ContextDescriptor::stage1(0x4000, 0x1234, 0xff00, 16).unwrap();
        assert_eq!(
            cd.0[0],
            16 | (1 << 8)
                | (1 << 10)
                | (3 << 12)
                | (1 << 30)
                | (1 << 31)
                | (0b101_u64 << 32)
                | (1 << 41)
                | (1 << 45)
                | (1 << 46)
                | (0x1234_u64 << 48)
        );
        assert_eq!(cd.0[1], 0x4000, "TTBR0");
        assert_eq!(cd.0[2], 0, "TTBR1 unused (EPD1 set)");
        assert_eq!(cd.0[3], 0xff00, "MAIR");
    }

    #[test]
    fn command_words_and_queue_wrap() {
        assert_eq!(
            command(CMD_CFGI_STE, 7, true),
            [CMD_CFGI_STE as u64 | (7 << 32), 1]
        );
        assert_eq!(command(CMD_CFGI_ALL, 0, false), [4, 31]);
        assert_eq!(command(CMD_TLBI_NSNH_ALL, 0, false)[0], 0x30);
        assert_eq!(command(CMD_SYNC, 0, false)[0], 0x46);
        let mut c = QueueCursor {
            index: 1,
            wrap: false,
        };
        c.advance(2);
        assert_eq!(
            c,
            QueueCursor {
                index: 0,
                wrap: true
            }
        );
        // The wrap flag sits just above the index bits, not in bit 31.
        assert_eq!(c.encode(2), 0b10);
        let c = QueueCursor {
            index: 5,
            wrap: true,
        };
        assert_eq!(c.encode(16), 0x15);
        assert_eq!(QueueCursor::decode(0x15, 16), c);
        assert!(!QueueCursor::decode(0x8000_0005, 16).wrap);
    }

    #[test]
    fn tables_reject_misaligned_or_bad_geometry() {
        let (mut memory, _) = test_tables();
        let stream = memory.stream.as_mut_ptr();
        let commands = memory.commands.as_mut_ptr();
        let events = memory.events.as_mut_ptr();
        let context: *mut [u64; 8] = &mut memory.context;
        let new = |s, se, c, ce, e, ee, cd| unsafe { LinearTables::new(s, se, c, ce, e, ee, cd) };
        assert!(new(stream, SIDS, commands, QUEUE, events, QUEUE, context).is_ok());
        assert!(new(stream, 12, commands, QUEUE, events, QUEUE, context).is_err());
        assert!(new(stream, SIDS, commands, 1, events, QUEUE, context).is_err());
        // The event queue base must be aligned to its 512-byte size.
        let shifted = unsafe { (commands as *mut u8).sub(256) }.cast::<[u64; 4]>();
        assert!(new(stream, SIDS, commands, QUEUE, shifted, QUEUE, context).is_err());
        let cd = unsafe { (context as *mut u8).add(8) }.cast::<[u64; 8]>();
        assert!(new(stream, SIDS, commands, QUEUE, events, QUEUE, cd).is_err());
    }

    #[test]
    fn bring_up_keeps_global_abort_through_smmuen() {
        let (memory, tables) = test_tables();
        let mut regs = Fake::new();
        configure_linear_stream(&mut regs, &tables, 3, &cd(), 4).unwrap();

        // The first register write sets GBPA.ABORT, and ABORT is in effect
        // after every register write up to and including SMMUEN.
        let writes = regs.writes();
        assert_eq!(writes[0].0, GBPA);
        assert!(writes.iter().all(|&(_, _, abort)| abort), "{writes:x?}");
        assert!(writes
            .iter()
            .filter(|w| w.0 == GBPA)
            .all(|w| w.1 & GBPA_ABORT != 0));
        let last = *writes.last().unwrap();
        assert_eq!((last.0, last.1), (CR0, 0x0d), "SMMUEN is the final write");
        assert_eq!(regs.get(CR0ACK), 0x0d, "SMMUEN acknowledged");
        assert!(regs.abort_in_effect(), "GBPA still aborts if SMMUEN drops");

        // Only stream 3 translates, through the CD this call wrote.
        for (sid, ste) in memory.stream.iter().enumerate() {
            if sid == 3 {
                assert_eq!(*ste, Ste::stage1(tables.context_address()).0);
            } else {
                assert_eq!(*ste, Ste::abort().0, "sid {sid}");
            }
        }
        assert_eq!(memory.context, cd().0);
        assert_eq!(
            regs.consumed,
            [
                command(CMD_CFGI_ALL, 0, false),
                command(CMD_TLBI_NSNH_ALL, 0, false),
                command(CMD_SYNC, 0, false)
            ]
        );
        assert_eq!(regs.get(STRTAB_BASE_CFG), 4);
    }

    #[test]
    fn bring_up_cleans_tables_after_writing_before_programming() {
        let (memory, tables) = test_tables();
        let mut regs = Fake::new();
        configure_linear_stream(&mut regs, &tables, 3, &cd(), 4).unwrap();
        let stream = memory.stream.as_ptr() as usize;
        let context = &memory.context as *const _ as usize;
        let commands = memory.commands.as_ptr() as usize;
        let events = memory.events.as_ptr() as usize;
        let cleans = [
            regs.position(|op| *op == Op::Clean(stream, SIDS as usize * STE_BYTES)),
            regs.position(|op| *op == Op::Clean(context, CD_BYTES)),
            regs.position(|op| *op == Op::Clean(commands, QUEUE as usize * COMMAND_BYTES)),
            regs.position(|op| *op == Op::Invalidate(events, QUEUE as usize * EVENT_BYTES)),
        ];
        let first_cr0 = regs
            .position(|op| matches!(op, Op::Write(CR0, _, _)))
            .unwrap();
        let first_strtab = regs
            .position(|op| matches!(op, Op::Write(STRTAB_BASE, _, _)))
            .unwrap();
        for clean in cleans {
            let clean = clean.expect("table region cleaned");
            assert!(clean < first_cr0 && clean < first_strtab);
        }
        // Tables are cleaned after GBPA.ABORT, so the cleans cover the final
        // contents (this function writes tables only after that point).
        assert!(regs.position(|op| matches!(op, Op::Write(GBPA, _, _))) < cleans[0]);
    }

    #[test]
    fn gbpa_update_timeout_fails_closed() {
        let (_memory, tables) = test_tables();
        let mut regs = Fake::new();
        regs.gbpa_stuck = true;
        assert_eq!(
            configure_linear_stream(&mut regs, &tables, 3, &cd(), 4),
            Err(Error::Timeout)
        );
        assert_eq!(regs.get(GBPA) & GBPA_ABORT, GBPA_ABORT, "ABORT requested");
        assert!(regs.writes().iter().all(|w| w.0 == GBPA), "nothing else");
    }

    #[test]
    fn smmuen_ack_failure_fails_closed() {
        let (_memory, tables) = test_tables();
        let mut regs = Fake::new();
        regs.ack_never = CR0_SMMUEN;
        assert_eq!(
            configure_linear_stream(&mut regs, &tables, 3, &cd(), 4),
            Err(Error::Timeout)
        );
        assert!(regs.abort_in_effect());
        let last = *regs.writes().last().unwrap();
        assert_eq!((last.0, last.1), (CR0, 0), "SMMU left disabled");
        assert!(regs.writes().iter().all(|&(_, _, abort)| abort));
    }

    #[test]
    fn command_timeout_and_error_fail_closed() {
        for error in [false, true] {
            let (_memory, tables) = test_tables();
            let mut regs = Fake::new();
            regs.cmdq_stuck = !error;
            regs.cmdq_error = error;
            let expected = if error {
                Error::CommandQueue
            } else {
                Error::Timeout
            };
            assert_eq!(
                configure_linear_stream(&mut regs, &tables, 3, &cd(), 4),
                Err(expected)
            );
            assert!(smmuen_write(&regs).is_none(), "SMMUEN never requested");
            assert!(regs.abort_in_effect());
            assert_eq!(regs.get(CR0), 0);
        }
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn unsupported_hardware_or_bad_sid_fails_closed() {
        let cases: [(Box<dyn Fn(&mut Fake)>, u32, Error); 3] = [
            (
                Box::new(|r| {
                    let _ = r.values.insert(IDR1, 2);
                }),
                3,
                Error::Unsupported,
            ),
            (
                Box::new(|r| {
                    let _ = r.values.insert(IDR0, 0);
                }),
                3,
                Error::Unsupported,
            ),
            (Box::new(|_| {}), SIDS, Error::InvalidWindow),
        ];
        for (setup, sid, expected) in cases {
            let (memory, tables) = test_tables();
            let mut regs = Fake::new();
            // Firmware left the SMMU enabled: the error path must disable it
            // so that GBPA.ABORT governs every stream.
            regs.write(CR0, CR0_SMMUEN | CR0_CMDQEN);
            regs.log.clear();
            setup(&mut regs);
            assert_eq!(
                configure_linear_stream(&mut regs, &tables, sid, &cd(), 4),
                Err(expected)
            );
            let writes = regs.writes();
            assert_eq!(writes[0].0, GBPA, "ABORT is requested first");
            assert_eq!(*writes.last().unwrap(), (CR0, 0, true), "{writes:x?}");
            assert!(writes.iter().all(|w| w.0 == GBPA || w.0 == CR0));
            assert!(regs.abort_in_effect());
            assert_eq!(regs.get(CR0ACK), 0, "SMMU disabled");
            assert!(smmuen_write(&regs).is_none());
            // No table was written.
            assert!(memory.stream.iter().all(|ste| *ste == [0xdead; 8]));
        }
    }

    #[test]
    fn gbpa_that_will_not_abort_is_an_error() {
        struct NoAbort(Fake);
        impl Registers for NoAbort {
            fn read(&mut self, offset: u32) -> u32 {
                self.0.read(offset)
            }
            fn write(&mut self, offset: u32, value: u32) {
                let value = if offset == GBPA {
                    value & !GBPA_ABORT
                } else {
                    value
                };
                self.0.write(offset, value)
            }
            fn clean_dma(&mut self, a: usize, b: usize) {
                self.0.clean_dma(a, b)
            }
            fn invalidate_dma(&mut self, a: usize, b: usize) {
                self.0.invalidate_dma(a, b)
            }
        }
        let (_memory, tables) = test_tables();
        let mut regs = NoAbort(Fake::new());
        assert_eq!(
            configure_linear_stream(&mut regs, &tables, 3, &cd(), 4),
            Err(Error::AbortNotLatched)
        );
        assert!(regs.0.writes().iter().all(|w| w.0 == GBPA));
    }

    #[test]
    fn install_and_abort_ste_invalidate_that_stream() {
        let (memory, tables) = test_tables();
        let mut regs = Fake::new();
        configure_linear_stream(&mut regs, &tables, 3, &cd(), 4).unwrap();
        regs.consumed.clear();
        regs.log.clear();

        let ste = Ste::stage1(tables.context_address());
        install_ste(&mut regs, &tables, 7, ste, 4).unwrap();
        assert_eq!(memory.stream[7], ste.0);
        let invalidate = [
            command(CMD_CFGI_STE, 7, true),
            command(CMD_TLBI_NSNH_ALL, 0, false),
            command(CMD_SYNC, 0, false),
        ];
        // Abort first, then the new entry, each invalidated and synced.
        assert_eq!(regs.consumed[..3], invalidate);
        assert_eq!(regs.consumed[3..], invalidate);
        let ste7 = memory.stream.as_ptr() as usize + 7 * STE_BYTES;
        let clean = regs
            .position(|op| *op == Op::Clean(ste7, STE_BYTES))
            .unwrap();
        let prod = regs
            .position(|op| matches!(op, Op::Write(CMDQ_PROD, _, _)))
            .unwrap();
        assert!(clean < prod, "STE cleaned before the SMMU is told");

        regs.consumed.clear();
        abort_ste(&mut regs, &tables, 7, 4).unwrap();
        assert_eq!(memory.stream[7], Ste::abort().0);
        assert_eq!(regs.consumed, invalidate);

        assert_eq!(
            install_ste(&mut regs, &tables, SIDS, ste, 4),
            Err(Error::InvalidWindow)
        );
        assert_eq!(
            abort_ste(&mut regs, &tables, SIDS, 4),
            Err(Error::InvalidWindow)
        );
    }

    #[test]
    fn command_queue_wraps_and_times_out() {
        let (_memory, tables) = test_tables();
        let mut regs = Fake::new();
        configure_linear_stream(&mut regs, &tables, 3, &cd(), 4).unwrap();
        // 3 + 11 * 3 = 36 commands: the 16-entry queue wraps twice.
        for _ in 0..11 {
            abort_ste(&mut regs, &tables, 5, 4).unwrap();
        }
        assert_eq!(regs.consumed.len(), 36);
        assert_eq!(regs.get(CMDQ_PROD), 36 % 16, "two wraps: flag clear");
        for _ in 0..4 {
            abort_ste(&mut regs, &tables, 5, 4).unwrap();
        }
        assert_eq!(
            regs.get(CMDQ_PROD),
            0x10,
            "48 commands, three wraps: flag set"
        );

        regs.cmdq_stuck = true;
        assert_eq!(abort_ste(&mut regs, &tables, 5, 4), Err(Error::Timeout));
    }

    #[test]
    fn submit_refuses_to_overwrite_a_full_queue() {
        let (_memory, tables) = test_tables();
        let mut regs = Fake::new();
        configure_linear_stream(&mut regs, &tables, 3, &cd(), 4).unwrap();
        regs.cmdq_stuck = true;
        let sync = [command(CMD_SYNC, 0, false); QUEUE as usize + 1];
        assert_eq!(
            submit_commands(&mut regs, &tables, &sync, 4),
            Err(Error::Timeout)
        );
        // 16 slots were used from index 3; the 17th would have overwritten
        // an unconsumed command, so it was never published.
        let prod = QueueCursor::decode(regs.get(CMDQ_PROD), QUEUE);
        let cons = QueueCursor::decode(regs.get(CMDQ_CONS), QUEUE);
        assert_eq!(prod.index, cons.index);
        assert_ne!(prod.wrap, cons.wrap);
    }

    fn event(kind: u8, sid: u32, address: u64) -> [u64; 4] {
        [u64::from(kind) | (u64::from(sid) << 32), 0, address, 0]
    }

    #[test]
    fn event_reader_decodes_and_consumes_records() {
        let (mut memory, tables) = test_tables();
        let mut regs = Fake::new();
        configure_linear_stream(&mut regs, &tables, 3, &cd(), 4).unwrap();

        assert_eq!(
            read_events(&mut regs, &tables, &mut []),
            EventDrain::default()
        );
        // Records at 14, 15, 0 (wrapped): PROD index 1 with wrap set.
        memory.events[14] = event(EVENT_F_TRANSLATION, 3, 0x1234_5000);
        memory.events[15] = event(EVENT_C_BAD_STE, 9, 0);
        memory.events[0] = event(EVENT_F_PERMISSION, 3, 0xdead_b000);
        regs.values.insert(EVENTQ_CONS, 14);
        regs.values.insert(EVENTQ_PROD, 0x10 | 1);

        let mut out = [EventRecord::default(); 2];
        let drain = read_events(&mut regs, &tables, &mut out);
        assert_eq!(
            drain,
            EventDrain {
                count: 2,
                overflowed: false
            }
        );
        assert_eq!(out[0].event_type, EVENT_F_TRANSLATION);
        assert_eq!(out[0].stream_id, 3);
        assert_eq!(out[0].input_address, 0x1234_5000);
        assert_eq!(out[1].event_type, EVENT_C_BAD_STE);
        assert_eq!(out[1].stream_id, 9);
        assert_eq!(regs.get(EVENTQ_CONS), 0x10, "index 0, wrapped");
        let slot14 = memory.events.as_ptr() as usize + 14 * EVENT_BYTES;
        assert!(regs
            .position(|op| *op == Op::Invalidate(slot14, EVENT_BYTES))
            .is_some());

        let drain = read_events(&mut regs, &tables, &mut out);
        assert_eq!(drain.count, 1);
        assert_eq!(out[0].event_type, EVENT_F_PERMISSION);
        assert_eq!(out[0].input_address, 0xdead_b000);
        assert_eq!(regs.get(EVENTQ_CONS), 0x11);
        assert_eq!(read_events(&mut regs, &tables, &mut out).count, 0);
    }

    #[test]
    fn event_reader_acknowledges_overflow() {
        let (_memory, tables) = test_tables();
        let mut regs = Fake::new();
        regs.values.insert(EVENTQ_PROD, EVENTQ_OVERFLOW);
        let mut out = [EventRecord::default(); 1];
        assert!(read_events(&mut regs, &tables, &mut out).overflowed);
        assert_eq!(regs.get(EVENTQ_CONS), EVENTQ_OVERFLOW, "OVACKFLG copied");
        assert!(!read_events(&mut regs, &tables, &mut out).overflowed);
    }

    #[test]
    fn policy_maps_only_allowed_windows() {
        struct Frames(usize);
        impl FrameSource for Frames {
            fn allocate_frame(&mut self) -> Option<PhysAddr> {
                let p = PhysAddr(self.0);
                self.0 += 4096;
                Some(p)
            }
            fn deallocate_frame(&mut self, _: PhysAddr) -> bool {
                true
            }
        }
        #[derive(Clone, Default)]
        struct Mem(RefCell<BTreeMap<(usize, usize), u64>>);
        impl TableMemory for Mem {
            fn read_entry(&self, t: PhysAddr, i: usize) -> Option<u64> {
                Some(*self.0.borrow().get(&(t.0, i)).unwrap_or(&0))
            }
            fn write_entry(&mut self, t: PhysAddr, i: usize, v: u64) -> bool {
                self.0.borrow_mut().insert((t.0, i), v);
                true
            }
        }
        let window = DmaWindow {
            iova: 0x1000,
            pa: PhysAddr(0x1000),
            length: 4096,
        };
        let policy = build_dma_policy(9, 1, &[window], Frames(0x100000), Mem::default()).unwrap();
        assert_eq!(policy.stream_id, 9);
        assert_eq!(
            policy.cd,
            ContextDescriptor::stage1(0x100000, 1, 0x00ff, 16).unwrap()
        );
        assert_eq!(
            policy
                .page_table
                .translate(0x1000)
                .unwrap()
                .unwrap()
                .physical_address,
            PhysAddr(0x1000)
        );
        assert!(policy.page_table.translate(0x2000).unwrap().is_none());
        let skewed = DmaWindow {
            iova: 0x2000,
            ..window
        };
        assert!(matches!(
            build_dma_policy(9, 1, &[skewed], Frames(0x100000), Mem::default()),
            Err(Error::InvalidWindow)
        ));
    }
}
