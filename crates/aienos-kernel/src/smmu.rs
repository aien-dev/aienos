//! Host-testable SMMUv3 descriptors, queues, and register sequencing.
//! This module does not map MMIO or perform cache maintenance.

use crate::mem::frame_allocator::PhysAddr;
use crate::mem::pagetable::{FrameSource, MapFlags, PageTableBuilder, PageTableError, TableMemory};

pub const STE_BYTES: usize = 64;
pub const CD_BYTES: usize = 64;
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
pub const STRTAB_BASE: u32 = 0x80;
pub const STRTAB_BASE_CFG: u32 = 0x88;
pub const CMDQ_BASE: u32 = 0x90;
pub const CMDQ_PROD: u32 = 0x98;
pub const CMDQ_CONS: u32 = 0x9c;
pub const EVENTQ_BASE: u32 = 0xa0;
pub const EVENTQ_PROD: u32 = 0xa8;
pub const EVENTQ_CONS: u32 = 0xac;
pub const GBPA: u32 = 0x44;
pub const IDR1_SIDSIZE_MASK: u32 = 0x3f;

pub trait Registers {
    fn read(&mut self, offset: u32) -> u32;
    fn write(&mut self, offset: u32, value: u32);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Timeout,
    CommandQueue,
    InvalidWindow,
    PageTable(PageTableError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ste(pub [u64; 8]);

impl Ste {
    pub const fn abort() -> Self {
        Self([1, 0, 0, 0, 0, 0, 0, 0])
    }
    pub const fn bypass() -> Self {
        Self([1 | (0b100 << 1), 0, 0, 0, 0, 0, 0, 0])
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
            | (1 << 45) // R: record faults
            | (1 << 46) // A: access flag
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

/// Queue index encoding used by SMMUv3: low bits index, bit 31 wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueCursor {
    pub index: u32,
    pub wrap: bool,
}
impl QueueCursor {
    pub fn encode(self) -> u32 {
        (self.index & 0x7fff_ffff) | ((self.wrap as u32) << 31)
    }
    pub fn advance(&mut self, entries: u32) {
        self.index += 1;
        if self.index == entries {
            self.index = 0;
            self.wrap = !self.wrap;
        }
    }
}

pub fn submit_command<R: Registers>(
    regs: &mut R,
    cursor: &mut QueueCursor,
    entries: u32,
    command: [u64; 2],
    write_entry: impl FnOnce(u32, [u64; 2]),
    spins: usize,
) -> Result<(), Error> {
    write_entry(cursor.index, command);
    cursor.advance(entries);
    regs.write(CMDQ_PROD, cursor.encode());
    for _ in 0..spins {
        let cons = regs.read(CMDQ_CONS);
        if cons & 0x7f00_0000 != 0 {
            return Err(Error::CommandQueue);
        }
        if cons & 0x7fff_ffff == cursor.index && (cons >> 31 != 0) == cursor.wrap {
            return Ok(());
        }
    }
    Err(Error::Timeout)
}

/// Keep global abort enabled until command queues and translation state are ready.
pub fn enable<R: Registers>(regs: &mut R, spins: usize) -> Result<(), Error> {
    let gbpa = regs.read(GBPA);
    // GBPA.ABORT is bit 20; bit 31 commits the requested global-bypass update.
    regs.write(GBPA, (gbpa & !(1 << 20)) | (1 << 31));
    regs.write(CR0, 0);
    wait_cr0(regs, 0, spins)?;
    regs.write(CR0, 1);
    wait_cr0(regs, 1, spins)
}

/// Register mapping for an identity-mapped SMMUv3 register aperture.
pub struct MmioRegisters {
    base: usize,
}

impl MmioRegisters {
    /// # Safety
    /// `base` must address a mapped SMMUv3 register aperture.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    pub fn write64(&mut self, offset: u32, value: u64) {
        unsafe {
            core::ptr::write_volatile((self.base + offset as usize) as *mut u32, value as u32);
            core::ptr::write_volatile(
                (self.base + offset as usize + 4) as *mut u32,
                (value >> 32) as u32,
            );
        }
    }
}

impl Registers for MmioRegisters {
    fn read(&mut self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + offset as usize) as *const u32) }
    }

    fn write(&mut self, offset: u32, value: u32) {
        unsafe { core::ptr::write_volatile((self.base + offset as usize) as *mut u32, value) }
    }
}

fn submit_raw<R: Registers>(
    regs: &mut R,
    cursor: &mut QueueCursor,
    entries: u32,
    queue: *mut [u64; 2],
    cmd: [u64; 2],
) -> Result<(), Error> {
    submit_command(
        regs,
        cursor,
        entries,
        cmd,
        |index, words| unsafe { core::ptr::write_volatile(queue.add(index as usize), words) },
        1_000_000,
    )
}

/// Configure one DMA stream to translate only the supplied stream table's PTEs.
/// The linear stream table starts with every stream in abort mode.
///
/// # Safety
/// All descriptor and queue pointers must address live, aligned, physically
/// contiguous RAM visible to the SMMU. `base` must be mapped device memory.
#[allow(clippy::too_many_arguments)]
pub unsafe fn configure_linear_stream(
    regs: &mut MmioRegisters,
    stream_id: u32,
    stream_entries: u32,
    stream_table: *mut [u64; 8],
    command_entries: u32,
    command_queue: *mut [u64; 2],
    event_entries: u32,
    event_queue: *mut [u64; 4],
    context: *mut [u64; 8],
    translation_root: u64,
) -> Result<(), Error> {
    if stream_entries == 0
        || !stream_entries.is_power_of_two()
        || stream_id >= stream_entries
        || command_entries < 2
        || !command_entries.is_power_of_two()
        || event_entries < 2
        || !event_entries.is_power_of_two()
        || stream_table as usize & (stream_entries as usize * STE_BYTES - 1) != 0
        || command_queue as usize & 0x3f != 0
        || event_queue as usize & 0x3f != 0
        || context as usize & 0x3f != 0
        || translation_root & 0xfff != 0
    {
        return Err(Error::InvalidWindow);
    }
    let sid_bits = stream_entries.trailing_zeros();
    if regs.read(IDR1) & IDR1_SIDSIZE_MASK < sid_bits {
        return Err(Error::InvalidWindow);
    }
    let table = unsafe { core::slice::from_raw_parts_mut(stream_table, stream_entries as usize) };
    for entry in table.iter_mut() {
        unsafe { core::ptr::write(entry, Ste::abort().0) };
    }
    unsafe {
        core::ptr::write(
            context,
            ContextDescriptor::stage1(translation_root, 1, 0x00ff, 16)?.0,
        );
        core::ptr::write(
            stream_table.add(stream_id as usize),
            Ste::stage1(context as u64).0,
        );
    }

    let gbpa = regs.read(GBPA);
    regs.write(GBPA, gbpa | (1 << 20) | (1 << 31));
    for _ in 0..1_000_000 {
        if regs.read(GBPA) & (1 << 31) == 0 {
            break;
        }
    }
    regs.write(CR0, 0);
    wait_cr0(regs, 0, 1_000_000)?;
    regs.write(CR1, 0x0d75);
    regs.write64(
        CMDQ_BASE,
        command_queue as u64 | u64::from(command_entries.trailing_zeros()),
    );
    regs.write(CMDQ_CONS, 0);
    regs.write(CMDQ_PROD, 0);
    regs.write64(
        EVENTQ_BASE,
        event_queue as u64 | u64::from(event_entries.trailing_zeros()),
    );
    regs.write(EVENTQ_CONS, 0);
    regs.write(EVENTQ_PROD, 0);
    regs.write(STRTAB_BASE_CFG, sid_bits);
    regs.write64(STRTAB_BASE, stream_table as u64);
    regs.write(CR0, 0x0c); // CMDQEN | EVENTQEN; SMMUEN remains clear.
    wait_cr0(regs, 0x0c, 1_000_000)?;

    let mut cursor = QueueCursor {
        index: 0,
        wrap: false,
    };
    submit_raw(
        regs,
        &mut cursor,
        command_entries,
        command_queue,
        command(CMD_CFGI_STE, stream_id, true),
    )?;
    submit_raw(
        regs,
        &mut cursor,
        command_entries,
        command_queue,
        command(CMD_TLBI_NSNH_ALL, 0, false),
    )?;
    submit_raw(
        regs,
        &mut cursor,
        command_entries,
        command_queue,
        command(CMD_SYNC, 0, false),
    )?;
    let gbpa = regs.read(GBPA);
    regs.write(GBPA, (gbpa & !(1 << 20)) | (1 << 31));
    for _ in 0..1_000_000 {
        if regs.read(GBPA) & (1 << 31) == 0 {
            break;
        }
    }
    regs.write(CR0, 0x0d); // SMMUEN | CMDQEN | EVENTQEN
    wait_cr0(regs, 0x0d, 1_000_000)
}

fn wait_cr0<R: Registers>(regs: &mut R, expected: u32, spins: usize) -> Result<(), Error> {
    for _ in 0..spins {
        // CR0ACK mirrors the enabled queue and SMMU bits from CR0.
        if regs.read(CR0ACK) & 0x0f == expected & 0x0f {
            return Ok(());
        }
    }
    Err(Error::Timeout)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaWindow {
    pub iova: usize,
    pub pa: PhysAddr,
    pub length: usize,
}

pub struct DmaPolicy<F, M> {
    pub stream_id: u32,
    pub ste: Ste,
    pub cd: ContextDescriptor,
    pub page_table: PageTableBuilder<F, M>,
}

/// Build an identity-policy stage-1 table: only the supplied windows translate.
pub fn build_dma_policy<F: FrameSource, M: TableMemory>(
    stream_id: u32,
    cd_address: u64,
    asid: u16,
    windows: &[DmaWindow],
    frames: F,
    memory: M,
) -> Result<DmaPolicy<F, M>, Error> {
    if cd_address & (CD_BYTES as u64 - 1) != 0 {
        return Err(Error::InvalidWindow);
    }
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
        ste: Ste::stage1(cd_address),
        cd,
        page_table: table,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::BTreeMap, vec::Vec};

    #[derive(Default)]
    struct Fake {
        values: BTreeMap<u32, u32>,
        writes: Vec<(u32, u32)>,
    }
    impl Registers for Fake {
        fn read(&mut self, offset: u32) -> u32 {
            *self.values.get(&offset).unwrap_or(&0)
        }
        fn write(&mut self, offset: u32, value: u32) {
            self.writes.push((offset, value));
            self.values.insert(offset, value);
            if offset == CR0 {
                self.values.insert(CR0ACK, value);
            }
        }
    }
    #[test]
    fn descriptor_layouts() {
        assert_eq!(Ste::abort().0[0], 1);
        assert_eq!(Ste::bypass().0[0], 9);
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
    }
    #[test]
    fn enable_handshake_and_abort_default() {
        let mut regs = Fake::default();
        regs.values.insert(GBPA, 0);
        enable(&mut regs, 2).unwrap();
        assert_eq!(&regs.writes[..3], &[(GBPA, 1 << 31), (CR0, 0), (CR0, 1)]);
        assert_eq!(regs.values[&GBPA] & (1 << 20), 0);
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
        let policy = build_dma_policy(
            9,
            0x8000,
            1,
            &[DmaWindow {
                iova: 0x1000,
                pa: PhysAddr(0x1000),
                length: 4096,
            }],
            Frames(0x100000),
            Mem::default(),
        )
        .unwrap();
        assert_eq!(policy.stream_id, 9);
        assert_eq!(policy.ste, Ste::stage1(0x8000));
        assert_eq!(policy.cd.0[1], 0x100000);
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
    }
}
