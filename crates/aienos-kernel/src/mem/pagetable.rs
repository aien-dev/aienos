//! Pure AArch64 stage-1, 4 KiB granule, 48-bit address translation tables.
//!
//! This module builds descriptors but does not configure translation registers.

use super::frame_allocator::PhysAddr;

pub const MAIR_NORMAL_WB: u8 = 0;
pub const MAIR_DEVICE_NGNRE: u8 = 1;
const ENTRIES: usize = 512;
const PAGE_SHIFT: usize = 12;
const TABLE: u64 = 0b11;
const BLOCK: u64 = 0b01;
const VALID: u64 = 1;
const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
const PAGE_SIZE_U64: u64 = 1 << PAGE_SHIFT;

/// Supplies physical frames used for page-table pages.
pub trait FrameSource {
    fn allocate_frame(&mut self) -> Option<PhysAddr>;
    fn deallocate_frame(&mut self, frame: PhysAddr) -> bool;
    fn frames_used(&self) -> Option<usize> {
        None
    }
}

/// Monotonic allocator over a firmware-reserved contiguous page pool.
/// Frames are never returned to the pool after allocation.
#[derive(Clone, Copy, Debug)]
pub struct FixedFramePool {
    base: PhysAddr,
    capacity: usize,
    used: usize,
}

impl FixedFramePool {
    pub fn new(base: PhysAddr, capacity: usize) -> Option<Self> {
        if !base.is_page_aligned() || capacity == 0 || capacity > (usize::MAX - base.0) / PAGE_SIZE
        {
            return None;
        }
        Some(Self {
            base,
            capacity,
            used: 0,
        })
    }

    pub const fn used(&self) -> usize {
        self.used
    }
}

impl FrameSource for FixedFramePool {
    fn allocate_frame(&mut self) -> Option<PhysAddr> {
        if self.used == self.capacity {
            return None;
        }
        let frame = PhysAddr(self.base.0 + self.used * PAGE_SIZE);
        self.used += 1;
        Some(frame)
    }

    fn deallocate_frame(&mut self, _frame: PhysAddr) -> bool {
        false
    }
    fn frames_used(&self) -> Option<usize> {
        Some(self.used)
    }
}

impl<const WORDS: usize> FrameSource for super::frame_allocator::BitmapFrameAllocator<WORDS> {
    fn allocate_frame(&mut self) -> Option<PhysAddr> {
        super::frame_allocator::BitmapFrameAllocator::allocate_frame(self)
    }
    fn deallocate_frame(&mut self, frame: PhysAddr) -> bool {
        super::frame_allocator::BitmapFrameAllocator::deallocate_frame(self, frame)
    }
}

/// Reads and writes the descriptors stored in physical page-table frames.
pub trait TableMemory {
    fn read_entry(&self, table: PhysAddr, index: usize) -> Option<u64>;
    fn write_entry(&mut self, table: PhysAddr, index: usize, value: u64) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryAttribute {
    NormalWriteBack,
    DeviceNgnre,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapFlags {
    pub attribute: MemoryAttribute,
    pub writable: bool,
    pub user: bool,
    pub executable: bool,
    pub shareable: bool,
    pub global: bool,
}

impl MapFlags {
    pub const KERNEL_DATA: Self = Self {
        attribute: MemoryAttribute::NormalWriteBack,
        writable: true,
        user: false,
        executable: false,
        shareable: true,
        global: true,
    };
    pub const KERNEL_CODE: Self = Self {
        executable: true,
        writable: false,
        ..Self::KERNEL_DATA
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageTableError {
    Misaligned,
    AddressOutOfRange,
    WritableExecutable,
    DeviceExecutable,
    Overlap,
    NotMapped,
    NoFrames,
    TableMemory,
}

/// One translation result, including the leaf size used by the walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    pub physical_address: PhysAddr,
    pub flags: MapFlags,
    pub page_size: usize,
}

pub struct PageTableBuilder<F, M> {
    frames: F,
    memory: M,
    root: PhysAddr,
}

impl<F: FrameSource, M: TableMemory> PageTableBuilder<F, M> {
    pub fn new(mut frames: F, mut memory: M) -> Result<Self, PageTableError> {
        let root = frames.allocate_frame().ok_or(PageTableError::NoFrames)?;
        if !root.is_page_aligned() {
            let _ = frames.deallocate_frame(root);
            return Err(PageTableError::Misaligned);
        }
        for i in 0..ENTRIES {
            if !memory.write_entry(root, i, 0) {
                let _ = frames.deallocate_frame(root);
                return Err(PageTableError::TableMemory);
            }
        }
        Ok(Self {
            frames,
            memory,
            root,
        })
    }

    pub const fn root(&self) -> PhysAddr {
        self.root
    }

    pub fn frames_used(&self) -> Option<usize> {
        self.frames.frames_used()
    }

    /// Maps a page-aligned range, using 1 GiB or 2 MiB blocks where possible.
    pub fn map(
        &mut self,
        virtual_address: usize,
        physical_address: PhysAddr,
        length: usize,
        flags: MapFlags,
    ) -> Result<(), PageTableError> {
        validate_range(virtual_address, physical_address, length, flags)?;
        let mut offset = 0u64;
        while offset < length as u64 {
            let va = virtual_address as u64 + offset;
            let pa = physical_address.0 as u64 + offset;
            let size = if va.is_multiple_of(1 << 30)
                && pa.is_multiple_of(1 << 30)
                && length as u64 - offset >= 1 << 30
            {
                1 << 30
            } else if va.is_multiple_of(1 << 21)
                && pa.is_multiple_of(1 << 21)
                && length as u64 - offset >= 1 << 21
            {
                1 << 21
            } else {
                PAGE_SIZE_U64
            };
            self.map_leaf(va, pa, size, flags)?;
            offset += size;
        }
        Ok(())
    }

    pub fn unmap(&mut self, virtual_address: usize, length: usize) -> Result<(), PageTableError> {
        validate_virtual_range(virtual_address, length)?;
        let mut offset = 0u64;
        while offset < length as u64 {
            let va = virtual_address as u64 + offset;
            let (table, index, size) = self.find_leaf(va)?.ok_or(PageTableError::NotMapped)?;
            if !va.is_multiple_of(size) || length as u64 - offset < size {
                return Err(PageTableError::Misaligned);
            }
            if !self.memory.write_entry(table, index, 0) {
                return Err(PageTableError::TableMemory);
            }
            offset += size;
        }
        Ok(())
    }

    pub fn translate(&self, virtual_address: usize) -> Result<Option<Translation>, PageTableError> {
        let va = virtual_address as u64;
        if !canonical(va) {
            return Err(PageTableError::AddressOutOfRange);
        }
        let Some((table, index, size)) = self.find_leaf(va)? else {
            return Ok(None);
        };
        let descriptor = self
            .memory
            .read_entry(table, index)
            .ok_or(PageTableError::TableMemory)?;
        let pa = (descriptor & ADDRESS_MASK) + va % size;
        Ok(Some(Translation {
            physical_address: PhysAddr(pa as usize),
            flags: decode_flags(descriptor),
            page_size: size as usize,
        }))
    }

    fn map_leaf(
        &mut self,
        va: u64,
        pa: u64,
        size: u64,
        flags: MapFlags,
    ) -> Result<(), PageTableError> {
        let indices = indexes(va);
        let target_level = match size {
            s if s == 1 << 30 => 1,
            s if s == 1 << 21 => 2,
            _ => 3,
        };
        let mut table = self.root;
        for index in indices.iter().take(target_level).copied() {
            let entry = self
                .memory
                .read_entry(table, index)
                .ok_or(PageTableError::TableMemory)?;
            if entry & VALID == 0 {
                let child = self
                    .frames
                    .allocate_frame()
                    .ok_or(PageTableError::NoFrames)?;
                if !child.is_page_aligned() {
                    let _ = self.frames.deallocate_frame(child);
                    return Err(PageTableError::Misaligned);
                }
                for i in 0..ENTRIES {
                    if !self.memory.write_entry(child, i, 0) {
                        let _ = self.frames.deallocate_frame(child);
                        return Err(PageTableError::TableMemory);
                    }
                }
                if !self
                    .memory
                    .write_entry(table, index, (child.0 as u64 & ADDRESS_MASK) | TABLE)
                {
                    let _ = self.frames.deallocate_frame(child);
                    return Err(PageTableError::TableMemory);
                }
                table = child;
            } else if entry & 0b11 == TABLE {
                table = PhysAddr((entry & ADDRESS_MASK) as usize);
            } else {
                return Err(PageTableError::Overlap);
            }
        }
        let index = indices[target_level];
        if self
            .memory
            .read_entry(table, index)
            .ok_or(PageTableError::TableMemory)?
            & VALID
            != 0
        {
            return Err(PageTableError::Overlap);
        }
        let kind = if target_level == 3 { TABLE } else { BLOCK };
        let descriptor = (pa & ADDRESS_MASK) | leaf_attributes(flags) | kind;
        if !self.memory.write_entry(table, index, descriptor) {
            return Err(PageTableError::TableMemory);
        }
        Ok(())
    }

    fn find_leaf(&self, va: u64) -> Result<Option<(PhysAddr, usize, u64)>, PageTableError> {
        let ix = indexes(va);
        let mut table = self.root;
        for (level, index) in ix.iter().copied().enumerate() {
            let entry = self
                .memory
                .read_entry(table, index)
                .ok_or(PageTableError::TableMemory)?;
            if entry & VALID == 0 {
                return Ok(None);
            }
            if level == 0 || entry & 0b11 == TABLE && level < 3 {
                table = PhysAddr((entry & ADDRESS_MASK) as usize);
                continue;
            }
            if level == 3 && entry & 0b11 == TABLE {
                return Ok(Some((table, index, PAGE_SIZE_U64)));
            }
            let size = match level {
                1 => 1 << 30,
                2 => 1 << 21,
                _ => PAGE_SIZE_U64,
            };
            return Ok(Some((table, index, size)));
        }
        Ok(None)
    }
}

fn validate_range(
    va: usize,
    pa: PhysAddr,
    len: usize,
    flags: MapFlags,
) -> Result<(), PageTableError> {
    validate_virtual_range(va, len)?;
    if !pa.is_page_aligned() || len == 0 || !len.is_multiple_of(PAGE_SIZE) {
        return Err(PageTableError::Misaligned);
    }
    if flags.writable && flags.executable {
        return Err(PageTableError::WritableExecutable);
    }
    if flags.executable && flags.attribute == MemoryAttribute::DeviceNgnre {
        return Err(PageTableError::DeviceExecutable);
    }
    let end = (va as u64)
        .checked_add(len as u64 - 1)
        .ok_or(PageTableError::AddressOutOfRange)?;
    let pend = (pa.0 as u64)
        .checked_add(len as u64 - 1)
        .ok_or(PageTableError::AddressOutOfRange)?;
    if !canonical(end) || pend > ADDRESS_MASK | 0xfff {
        return Err(PageTableError::AddressOutOfRange);
    }
    Ok(())
}

fn validate_virtual_range(va: usize, len: usize) -> Result<(), PageTableError> {
    if len == 0 || !va.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE) {
        return Err(PageTableError::Misaligned);
    }
    let end = (va as u64)
        .checked_add(len as u64 - 1)
        .ok_or(PageTableError::AddressOutOfRange)?;
    if !canonical(va as u64) || !canonical(end) {
        return Err(PageTableError::AddressOutOfRange);
    }
    Ok(())
}

fn canonical(va: u64) -> bool {
    if va & (1 << 47) == 0 {
        va >> 48 == 0
    } else {
        va >> 48 == 0xffff
    }
}
fn indexes(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 511) as usize,
        ((va >> 30) & 511) as usize,
        ((va >> 21) & 511) as usize,
        ((va >> 12) & 511) as usize,
    ]
}

/// Level-3 page descriptor for `frame` with `flags` (same encoding as
/// [`PageTableBuilder::map`] leaves).
pub fn page_descriptor(frame: PhysAddr, flags: MapFlags) -> u64 {
    (frame.0 as u64 & ADDRESS_MASK) | TABLE | leaf_attributes(flags)
}

fn leaf_attributes(flags: MapFlags) -> u64 {
    let attr = match flags.attribute {
        MemoryAttribute::NormalWriteBack => MAIR_NORMAL_WB,
        MemoryAttribute::DeviceNgnre => MAIR_DEVICE_NGNRE,
    } as u64;
    let ap = if flags.user {
        if flags.writable {
            0b01
        } else {
            0b11
        }
    } else if flags.writable {
        0b00
    } else {
        0b10
    };
    (attr << 2)
        | ((ap as u64) << 6)
        | (if flags.shareable { 0b11 << 8 } else { 0 })
        | (1 << 10)
        | (if flags.global { 0 } else { 1 << 11 })
        // PXN (bit 53): the kernel never executes non-executable or user pages.
        | (if !flags.executable || flags.user {
            1 << 53
        } else {
            0
        })
        // UXN (bit 54): EL0 never executes non-executable or kernel pages.
        | (if !flags.executable || !flags.user {
            1 << 54
        } else {
            0
        })
}

fn decode_flags(d: u64) -> MapFlags {
    let ap = (d >> 6) & 3;
    let attr = ((d >> 2) & 7) as u8;
    MapFlags {
        attribute: if attr == MAIR_DEVICE_NGNRE {
            MemoryAttribute::DeviceNgnre
        } else {
            MemoryAttribute::NormalWriteBack
        },
        writable: ap & 2 == 0,
        user: ap & 1 != 0,
        executable: if ap & 1 != 0 {
            d & (1 << 54) == 0
        } else {
            d & (1 << 53) == 0
        },
        shareable: (d >> 8) & 3 == 3,
        global: d & (1 << 11) == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::collections::BTreeMap;

    struct Frames {
        next: usize,
    }
    impl FrameSource for Frames {
        fn allocate_frame(&mut self) -> Option<PhysAddr> {
            let p = PhysAddr(self.next);
            self.next += PAGE_SIZE;
            Some(p)
        }
        fn deallocate_frame(&mut self, _: PhysAddr) -> bool {
            true
        }
    }
    #[derive(Clone, Default)]
    struct Memory(RefCell<BTreeMap<(usize, usize), u64>>);
    impl TableMemory for Memory {
        fn read_entry(&self, table: PhysAddr, index: usize) -> Option<u64> {
            Some(*self.0.borrow().get(&(table.0, index)).unwrap_or(&0))
        }
        fn write_entry(&mut self, table: PhysAddr, index: usize, value: u64) -> bool {
            self.0.borrow_mut().insert((table.0, index), value);
            true
        }
    }
    fn builder() -> PageTableBuilder<Frames, Memory> {
        PageTableBuilder::new(Frames { next: 0x1000 }, Memory::default()).unwrap()
    }

    #[test]
    fn fixed_pool_is_bounded_and_never_reuses_released_frames() {
        let mut pool = FixedFramePool::new(PhysAddr(0x8000), 2).unwrap();
        assert_eq!(pool.allocate_frame(), Some(PhysAddr(0x8000)));
        assert_eq!(pool.allocate_frame(), Some(PhysAddr(0x9000)));
        assert_eq!(pool.allocate_frame(), None);
        assert!(!pool.deallocate_frame(PhysAddr(0x8000)));
        assert_eq!(pool.used(), 2);
        assert!(FixedFramePool::new(PhysAddr(0x8001), 2).is_none());
    }

    #[test]
    fn descriptor_encodes_attributes_exactly() {
        let d = (0x1234_5000u64 & ADDRESS_MASK) | leaf_attributes(MapFlags::KERNEL_DATA) | TABLE;
        assert_eq!(d & 0xfff, 0x703);
        assert_ne!(d & (1 << 53), 0);
        assert_ne!(d & (1 << 54), 0);
        assert_eq!(leaf_attributes(MapFlags::KERNEL_CODE) & (1 << 53), 0);
        assert_eq!(
            leaf_attributes(MapFlags {
                attribute: MemoryAttribute::DeviceNgnre,
                ..MapFlags::KERNEL_DATA
            }) & 0x1c,
            4
        );
    }

    #[test]
    fn maps_and_walks_page() {
        let mut pt = builder();
        pt.map(0x4000, PhysAddr(0x8000), PAGE_SIZE, MapFlags::KERNEL_DATA)
            .unwrap();
        let result = pt.translate(0x4123).unwrap().unwrap();
        assert_eq!(result.physical_address, PhysAddr(0x8123));
        assert_eq!(result.page_size, PAGE_SIZE);
        assert!(result.flags.writable);
    }

    #[test]
    fn chooses_block_and_page_leaves() {
        let mut pt = builder();
        pt.map(
            0x4000_0000,
            PhysAddr(0x8000_0000),
            1 << 30,
            MapFlags::KERNEL_DATA,
        )
        .unwrap();
        let result = pt.translate(0x4000_1234).unwrap().unwrap();
        assert_eq!(result.page_size, 1 << 30);
        assert_eq!(result.physical_address, PhysAddr(0x8000_1234));
    }

    #[test]
    fn rejects_overlap_wx_and_misalignment() {
        let mut pt = builder();
        assert_eq!(
            pt.map(
                0x1000,
                PhysAddr(0x2000),
                PAGE_SIZE,
                MapFlags {
                    writable: true,
                    executable: true,
                    ..MapFlags::KERNEL_DATA
                }
            ),
            Err(PageTableError::WritableExecutable)
        );
        assert_eq!(
            pt.map(0x1001, PhysAddr(0x2000), PAGE_SIZE, MapFlags::KERNEL_DATA),
            Err(PageTableError::Misaligned)
        );
        pt.map(0x1000, PhysAddr(0x2000), PAGE_SIZE, MapFlags::KERNEL_DATA)
            .unwrap();
        assert_eq!(
            pt.map(0x1000, PhysAddr(0x3000), PAGE_SIZE, MapFlags::KERNEL_DATA),
            Err(PageTableError::Overlap)
        );
    }

    #[test]
    fn unmap_removes_leaf() {
        let mut pt = builder();
        pt.map(0x1000, PhysAddr(0x2000), PAGE_SIZE, MapFlags::KERNEL_DATA)
            .unwrap();
        pt.unmap(0x1000, PAGE_SIZE).unwrap();
        assert_eq!(pt.translate(0x1000).unwrap(), None);
    }

    const PXN: u64 = 1 << 53;
    const UXN: u64 = 1 << 54;

    fn user(executable: bool, writable: bool) -> MapFlags {
        MapFlags {
            user: true,
            executable,
            writable,
            global: false,
            ..MapFlags::KERNEL_DATA
        }
    }

    #[test]
    fn execute_never_bits_follow_privilege() {
        // Kernel code: kernel may execute, EL0 may not.
        let d = leaf_attributes(MapFlags::KERNEL_CODE);
        assert_eq!((d & PXN, d & UXN), (0, UXN));
        // User code: EL0 may execute, the kernel must not (no PXN hole).
        let d = leaf_attributes(user(true, false));
        assert_eq!((d & PXN, d & UXN), (PXN, 0));
        // Data, kernel or user: nobody executes.
        for flags in [MapFlags::KERNEL_DATA, user(false, true), user(false, false)] {
            let d = leaf_attributes(flags);
            assert_eq!((d & PXN, d & UXN), (PXN, UXN));
        }
    }

    #[test]
    fn access_permission_and_attribute_bits() {
        let ap = |f: MapFlags| (leaf_attributes(f) >> 6) & 0b11;
        assert_eq!(ap(MapFlags::KERNEL_DATA), 0b00);
        assert_eq!(ap(MapFlags::KERNEL_CODE), 0b10);
        assert_eq!(ap(user(false, true)), 0b01);
        assert_eq!(ap(user(true, false)), 0b11);
        let d = leaf_attributes(MapFlags::KERNEL_DATA);
        assert_eq!((d >> 2) & 0b111, MAIR_NORMAL_WB as u64);
        assert_eq!((d >> 8) & 0b11, 0b11, "inner shareable");
        assert_ne!(d & (1 << 10), 0, "access flag set");
        assert_eq!(d & (1 << 11), 0, "global");
        assert_ne!(
            leaf_attributes(user(false, true)) & (1 << 11),
            0,
            "user pages not global"
        );
    }

    #[test]
    fn flags_round_trip_through_descriptors() {
        let device = MapFlags {
            attribute: MemoryAttribute::DeviceNgnre,
            ..MapFlags::KERNEL_DATA
        };
        for flags in [
            MapFlags::KERNEL_CODE,
            MapFlags::KERNEL_DATA,
            user(true, false),
            user(false, true),
            device,
        ] {
            assert_eq!(decode_flags(leaf_attributes(flags)), flags);
        }
    }

    #[test]
    fn device_memory_is_never_executable() {
        let mut pt = builder();
        let flags = MapFlags {
            attribute: MemoryAttribute::DeviceNgnre,
            writable: false,
            executable: true,
            ..MapFlags::KERNEL_DATA
        };
        assert_eq!(
            pt.map(0x1000, PhysAddr(0x9000_0000), PAGE_SIZE, flags),
            Err(PageTableError::DeviceExecutable)
        );
    }
}
