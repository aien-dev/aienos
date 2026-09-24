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
    pub const fn stage1(cd_address: u64) -> Self {
        Self([
            1 | (0b001 << 1),
            cd_address & 0x000f_ffff_ffff_ffc0,
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
        let word0 = u64::from(t0sz)
            | (0b01 << 8)
            | (0b01 << 10)
            | (0b10 << 12)
            | (1 << 30)
            | (1 << 31)
            | (1 << 41)
            | (u64::from(asid) << 48);
        let word1 = ttb0 & 0x000f_ffff_ffff_fff0;
        Ok(Self([word0, word1, 0, mair, 0, 0, 0, 0]))
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
    regs.write(GBPA, gbpa | 1 | (1 << 31));
    regs.write(CR0, 0);
    wait_cr0(regs, 0, spins)?;
    regs.write(CR0, 1);
    wait_cr0(regs, 1, spins)
}

fn wait_cr0<R: Registers>(regs: &mut R, expected: u32, spins: usize) -> Result<(), Error> {
    for _ in 0..spins {
        if regs.read(CR0ACK) & 1 == expected {
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
    let cd = ContextDescriptor::stage1(table.root().0 as u64, asid, 0xff00, 16)?;
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
        assert_eq!(Ste::stage1(0x12340).0, [3, 0x12340, 0, 0, 0, 0, 0, 0]);
        let cd = ContextDescriptor::stage1(0x4000, 0x1234, 0xff00, 16).unwrap();
        assert_eq!(
            cd.0[0],
            16 | (1 << 8)
                | (1 << 10)
                | (2 << 12)
                | (1 << 30)
                | (1 << 31)
                | (1 << 41)
                | (0x1234_u64 << 48)
        );
        assert_eq!(cd.0[1], 0x4000);
        assert_eq!(cd.0[3], 0xff00);
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
        assert_eq!(
            &regs.writes[..3],
            &[(GBPA, 1 | (1 << 31)), (CR0, 0), (CR0, 1)]
        );
        assert_eq!(regs.values[&GBPA] & 1, 1);
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
