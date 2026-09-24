//! PCI configuration space enumeration over an ECAM window.
//!
//! Finds functions by vendor and device id, reports each function's
//! bus/device/function, requester id and header type, decodes memory BARs and
//! reads or changes the Command register. Config access goes through the
//! [`ConfigSpace`] trait so the walk is host-tested against a fake config
//! space; [`EcamConfig`] is the real MMIO adapter over an
//! [`EcamWindow`](crate::acpi::EcamWindow).
//!
//! Nothing here enables a device. Turning on memory decode or bus mastering is
//! a decision for the device authority code, which calls [`update_command`].

use crate::acpi::EcamWindow;

/// Config offset of the vendor id (low 16 bits) and device id (high 16 bits).
pub const REG_ID: u16 = 0x00;
/// Config offset of the Command (low 16 bits) and Status (high 16 bits) registers.
pub const REG_COMMAND: u16 = 0x04;
/// Config offset of the revision id and class code dword.
pub const REG_CLASS_REVISION: u16 = 0x08;
/// Config offset of the dword holding the header type (bits 16..24).
pub const REG_HEADER: u16 = 0x0c;
/// Config offset of BAR0. BAR n sits at `REG_BAR0 + 4 * n`.
pub const REG_BAR0: u16 = 0x10;

/// Command register bit: respond to I/O space accesses.
pub const COMMAND_IO_SPACE: u16 = 1 << 0;
/// Command register bit: respond to memory space accesses (MMIO BARs).
pub const COMMAND_MEMORY_SPACE: u16 = 1 << 1;
/// Command register bit: allow the function to issue DMA (bus master).
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Vendor id read back from an absent function.
pub const VENDOR_NONE: u16 = 0xffff;
/// Header type bit that marks function 0 as one of several functions.
const HEADER_MULTI_FUNCTION: u8 = 0x80;
/// Number of BARs in a type 0 (endpoint) header.
pub const TYPE0_BAR_COUNT: u8 = 6;
/// Number of BARs in a type 1 (bridge) header.
pub const TYPE1_BAR_COUNT: u8 = 2;

/// 32-bit PCI configuration space access, addressed by absolute bus number.
///
/// Only aligned dword accesses are used. Reads of an absent function return
/// all ones, as ECAM does.
pub trait ConfigSpace {
    fn read32(&mut self, bdf: Bdf, offset: u16) -> u32;
    fn write32(&mut self, bdf: Bdf, offset: u16, value: u32);
}

/// A bus/device/function address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Bdf {
    /// `None` when `device > 31` or `function > 7`.
    pub const fn new(bus: u8, device: u8, function: u8) -> Option<Self> {
        if device > 31 || function > 7 {
            return None;
        }
        Some(Self {
            bus,
            device,
            function,
        })
    }

    /// PCI requester id: `bus << 8 | device << 3 | function`. This is the
    /// input id that IORT maps to an SMMU stream id
    /// (see [`IortSmmu::stream_id_for`](crate::acpi::IortSmmu::stream_id_for)).
    pub const fn requester_id(self) -> u32 {
        (self.bus as u32) << 8 | (self.device as u32) << 3 | self.function as u32
    }
}

/// One present PCI function found by the walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciFunction {
    pub bdf: Bdf,
    pub vendor_id: u16,
    pub device_id: u16,
    /// Header layout (0 endpoint, 1 PCI bridge, 2 CardBus) without the
    /// multi-function bit.
    pub header_type: u8,
    /// Set on function 0 of a multi-function device.
    pub multi_function: bool,
    /// Class code in bits 8..32, revision id in bits 0..8.
    pub class_revision: u32,
}

impl PciFunction {
    pub const fn requester_id(&self) -> u32 {
        self.bdf.requester_id()
    }

    /// BARs this header layout has: 6 for type 0, 2 for type 1, none otherwise.
    pub const fn bar_count(&self) -> u8 {
        match self.header_type {
            0 => TYPE0_BAR_COUNT,
            1 => TYPE1_BAR_COUNT,
            _ => 0,
        }
    }
}

/// Reads the identity of `bdf`, or `None` when no function answers there.
pub fn read_function<C: ConfigSpace>(config: &mut C, bdf: Bdf) -> Option<PciFunction> {
    let id = config.read32(bdf, REG_ID);
    let vendor_id = id as u16;
    // All ones is ECAM's answer for an absent function; vendor 0 is never valid.
    if vendor_id == VENDOR_NONE || vendor_id == 0 {
        return None;
    }
    let header = (config.read32(bdf, REG_HEADER) >> 16) as u8;
    Some(PciFunction {
        bdf,
        vendor_id,
        device_id: (id >> 16) as u16,
        header_type: header & !HEADER_MULTI_FUNCTION,
        multi_function: header & HEADER_MULTI_FUNCTION != 0,
        class_revision: config.read32(bdf, REG_CLASS_REVISION),
    })
}

/// Walks every present function on buses `start_bus..=end_bus` in bus,
/// device, function order. Functions 1 to 7 are probed only when function 0
/// exists and sets the multi-function bit. Allocates nothing.
pub struct Functions<'a, C: ConfigSpace> {
    config: &'a mut C,
    end_bus: u8,
    /// Next address to probe; `None` once the walk is finished.
    next: Option<Bdf>,
    /// Whether the current device's function 0 set the multi-function bit.
    multi_function: bool,
}

impl<'a, C: ConfigSpace> Functions<'a, C> {
    pub fn new(config: &'a mut C, start_bus: u8, end_bus: u8) -> Self {
        let next = (start_bus <= end_bus).then_some(Bdf {
            bus: start_bus,
            device: 0,
            function: 0,
        });
        Self {
            config,
            end_bus,
            next,
            multi_function: false,
        }
    }

    /// Advance to the next device (function 0), or finish after the last bus.
    fn next_device(&mut self, at: Bdf) {
        self.next = if at.device < 31 {
            Some(Bdf {
                bus: at.bus,
                device: at.device + 1,
                function: 0,
            })
        } else if at.bus < self.end_bus {
            Some(Bdf {
                bus: at.bus + 1,
                device: 0,
                function: 0,
            })
        } else {
            None
        };
    }
}

impl<C: ConfigSpace> Iterator for Functions<'_, C> {
    type Item = PciFunction;

    fn next(&mut self) -> Option<PciFunction> {
        while let Some(at) = self.next {
            let found = read_function(self.config, at);
            if at.function == 0 {
                self.multi_function = found.is_some_and(|f| f.multi_function);
            }
            if at.function < 7 && self.multi_function {
                self.next = Some(Bdf {
                    function: at.function + 1,
                    ..at
                });
            } else {
                self.next_device(at);
            }
            if found.is_some() {
                return found;
            }
        }
        None
    }
}

/// Walks every present function on the buses of an ECAM window.
pub fn functions_in<'a, C: ConfigSpace>(
    config: &'a mut C,
    window: &EcamWindow,
) -> Functions<'a, C> {
    Functions::new(config, window.start_bus, window.end_bus)
}

/// First function on buses `start_bus..=end_bus` with this vendor and device id.
pub fn find_device<C: ConfigSpace>(
    config: &mut C,
    start_bus: u8,
    end_bus: u8,
    vendor_id: u16,
    device_id: u16,
) -> Option<PciFunction> {
    Functions::new(config, start_bus, end_bus)
        .find(|f| f.vendor_id == vendor_id && f.device_id == device_id)
}

/// A decoded Base Address Register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    /// 32-bit memory BAR.
    Memory32 { base: u32, prefetchable: bool },
    /// 64-bit memory BAR; it also uses the next BAR slot for the high half.
    Memory64 { base: u64, prefetchable: bool },
    /// I/O space BAR.
    Io { base: u32 },
}

impl Bar {
    /// Base address as a u64, whatever the BAR kind.
    pub const fn base(&self) -> u64 {
        match *self {
            Bar::Memory32 { base, .. } => base as u64,
            Bar::Memory64 { base, .. } => base,
            Bar::Io { base } => base as u64,
        }
    }

    /// Whether this BAR uses two slots.
    pub const fn is_64bit(&self) -> bool {
        matches!(self, Bar::Memory64 { .. })
    }
}

/// Why a BAR could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarError {
    /// The index is past the last BAR of this header type.
    NoSuchBar,
    /// A 64-bit BAR in the last slot has no slot for its high half.
    MissingHighHalf,
    /// The memory type field holds the reserved value 0b11 (or the legacy
    /// below-1-MiB type 0b01, which PCI Express does not allow).
    ReservedType,
    /// The function did not answer (all ones).
    Absent,
}

/// Memory BAR type field (bits 1..3).
const BAR_IO: u32 = 1 << 0;
const BAR_TYPE_MASK: u32 = 0b11 << 1;
const BAR_TYPE_32: u32 = 0b00 << 1;
const BAR_TYPE_64: u32 = 0b10 << 1;
const BAR_PREFETCHABLE: u32 = 1 << 3;
const BAR_MEMORY_BASE_MASK: u32 = !0xf;
const BAR_IO_BASE_MASK: u32 = !0x3;

/// Decodes a BAR from its low dword and, for a 64-bit memory BAR, the next
/// dword. `high` is ignored for other kinds. Pure: no config access.
pub fn decode_bar(low: u32, high: Option<u32>) -> Result<Bar, BarError> {
    if low & BAR_IO != 0 {
        return Ok(Bar::Io {
            base: low & BAR_IO_BASE_MASK,
        });
    }
    let prefetchable = low & BAR_PREFETCHABLE != 0;
    match low & BAR_TYPE_MASK {
        BAR_TYPE_32 => Ok(Bar::Memory32 {
            base: low & BAR_MEMORY_BASE_MASK,
            prefetchable,
        }),
        BAR_TYPE_64 => {
            let high = high.ok_or(BarError::MissingHighHalf)?;
            Ok(Bar::Memory64 {
                base: u64::from(high) << 32 | u64::from(low & BAR_MEMORY_BASE_MASK),
                prefetchable,
            })
        }
        _ => Err(BarError::ReservedType),
    }
}

/// Reads and decodes BAR `index` of `function`. A 64-bit BAR at `index`
/// also reads slot `index + 1`; the caller skips that slot.
pub fn read_bar<C: ConfigSpace>(
    config: &mut C,
    function: &PciFunction,
    index: u8,
) -> Result<Bar, BarError> {
    if index >= function.bar_count() {
        return Err(BarError::NoSuchBar);
    }
    let bdf = function.bdf;
    let low = config.read32(bdf, bar_offset(index));
    if low == u32::MAX {
        return Err(BarError::Absent);
    }
    let high =
        (index + 1 < function.bar_count()).then(|| config.read32(bdf, bar_offset(index + 1)));
    decode_bar(low, high)
}

/// Size in bytes of memory BAR `index`, found by the standard probe: write
/// all ones, read back the writable bits, restore the original value.
///
/// Memory and I/O decode are switched off for the duration so the device
/// never decodes the all-ones address, then the Command register is put back
/// exactly as it was. Returns `Ok(None)` for an unimplemented (size 0) BAR
/// and `Err(NoSuchBar)` for an I/O BAR, which this kernel does not use.
pub fn probe_bar_size<C: ConfigSpace>(
    config: &mut C,
    function: &PciFunction,
    index: u8,
) -> Result<Option<u64>, BarError> {
    let bar = read_bar(config, function, index)?;
    if let Bar::Io { .. } = bar {
        return Err(BarError::NoSuchBar);
    }
    let bdf = function.bdf;
    let command = read_command(config, bdf);
    write_command(
        config,
        bdf,
        command & !(COMMAND_MEMORY_SPACE | COMMAND_IO_SPACE),
    );
    let low_at = bar_offset(index);
    let low = config.read32(bdf, low_at);
    config.write32(bdf, low_at, u32::MAX);
    let low_mask = config.read32(bdf, low_at) & BAR_MEMORY_BASE_MASK;
    config.write32(bdf, low_at, low);
    let mut mask = u64::from(low_mask) | 0xffff_ffff_0000_0000;
    if bar.is_64bit() {
        let high_at = bar_offset(index + 1);
        let high = config.read32(bdf, high_at);
        config.write32(bdf, high_at, u32::MAX);
        let high_mask = config.read32(bdf, high_at);
        config.write32(bdf, high_at, high);
        mask = u64::from(high_mask) << 32 | u64::from(low_mask);
    }
    write_command(config, bdf, command);
    if mask == 0 || (!bar.is_64bit() && low_mask == 0) {
        return Ok(None);
    }
    // The lowest writable address bit is the size.
    Ok(Some(mask.isolate_lowest_one()))
}

const fn bar_offset(index: u8) -> u16 {
    REG_BAR0 + 4 * index as u16
}

/// Current Command register value of `bdf`.
pub fn read_command<C: ConfigSpace>(config: &mut C, bdf: Bdf) -> u16 {
    config.read32(bdf, REG_COMMAND) as u16
}

/// Writes the Command register. The upper half of the dword is the Status
/// register, whose error bits clear when written with 1, so it is written as
/// zero to leave them alone.
fn write_command<C: ConfigSpace>(config: &mut C, bdf: Bdf, command: u16) {
    config.write32(bdf, REG_COMMAND, u32::from(command));
}

/// Sets the Command bits in `set`, then clears those in `clear`, and returns
/// the value written. Use [`COMMAND_MEMORY_SPACE`] and [`COMMAND_BUS_MASTER`]
/// to grant or revoke MMIO decode and DMA. Status error bits are preserved.
pub fn update_command<C: ConfigSpace>(config: &mut C, bdf: Bdf, set: u16, clear: u16) -> u16 {
    let command = (read_command(config, bdf) | set) & !clear;
    write_command(config, bdf, command);
    command
}

/// Config space through a mapped ECAM window, with volatile dword accesses.
pub struct EcamConfig {
    window: EcamWindow,
}

impl EcamConfig {
    /// # Safety
    /// The whole ECAM range of `window` (1 MiB per bus from `window.base`)
    /// must be mapped as device memory at the same virtual address for as
    /// long as this value is used, and nothing else may drive those config
    /// registers concurrently.
    pub const unsafe fn new(window: EcamWindow) -> Self {
        Self { window }
    }

    pub const fn window(&self) -> &EcamWindow {
        &self.window
    }
}

impl ConfigSpace for EcamConfig {
    fn read32(&mut self, bdf: Bdf, offset: u16) -> u32 {
        match self
            .window
            .config_address(bdf.bus, bdf.device, bdf.function, offset & !0x3)
        {
            // SAFETY: the address lies inside the window that `new` requires
            // to be mapped, and is dword aligned.
            Some(addr) => unsafe { core::ptr::read_volatile(addr as usize as *const u32) },
            None => u32::MAX,
        }
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, value: u32) {
        if let Some(addr) =
            self.window
                .config_address(bdf.bus, bdf.device, bdf.function, offset & !0x3)
        {
            // SAFETY: as for `read32`.
            unsafe { core::ptr::write_volatile(addr as usize as *mut u32, value) }
        }
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::collections::BTreeMap;

    /// A config space holding a few functions. Each function has 64 dwords
    /// of plain storage and optional BAR size masks that emulate the
    /// read-only low bits of a BAR during size probing.
    #[derive(Default)]
    pub struct FakeConfig {
        pub functions: BTreeMap<Bdf, [u32; 64]>,
        /// (bdf, bar index) -> writable address bits of that BAR dword.
        pub bar_masks: BTreeMap<(Bdf, u8), u32>,
        pub reads: usize,
    }

    impl FakeConfig {
        pub fn add(&mut self, bdf: Bdf, vendor: u16, device: u16, header: u8) -> &mut [u32; 64] {
            let space = self.functions.entry(bdf).or_insert([0; 64]);
            space[0] = u32::from(device) << 16 | u32::from(vendor);
            space[3] = u32::from(header) << 16;
            space
        }
    }

    impl ConfigSpace for FakeConfig {
        fn read32(&mut self, bdf: Bdf, offset: u16) -> u32 {
            self.reads += 1;
            self.functions
                .get(&bdf)
                .map_or(u32::MAX, |s| s[usize::from(offset / 4)])
        }

        fn write32(&mut self, bdf: Bdf, offset: u16, value: u32) {
            let Some(space) = self.functions.get_mut(&bdf) else {
                return;
            };
            let slot = usize::from(offset / 4);
            let bar = offset
                .checked_sub(REG_BAR0)
                .map(|o| (o / 4) as u8)
                .filter(|i| *i < TYPE0_BAR_COUNT);
            let value = match bar.and_then(|i| self.bar_masks.get(&(bdf, i))) {
                // Read-only low bits (type, prefetch) keep their value.
                Some(mask) => (value & mask) | (space[slot] & !mask),
                None => value,
            };
            space[slot] = if offset == REG_COMMAND {
                // The Status half is write-1-to-clear: a 1 clears, a 0 keeps.
                let status = (space[slot] >> 16) & !(value >> 16);
                status << 16 | (value & 0xffff)
            } else {
                value
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeConfig;
    use super::*;

    fn bdf(bus: u8, device: u8, function: u8) -> Bdf {
        Bdf::new(bus, device, function).unwrap()
    }

    #[test]
    fn requester_id_packs_bus_device_function() {
        assert_eq!(bdf(0, 0, 0).requester_id(), 0);
        assert_eq!(bdf(0, 2, 0).requester_id(), 0x10);
        assert_eq!(bdf(1, 3, 5).requester_id(), 0x11d);
        assert_eq!(bdf(0xff, 31, 7).requester_id(), 0xffff);
        assert_eq!(Bdf::new(0, 32, 0), None);
        assert_eq!(Bdf::new(0, 0, 8), None);
    }

    #[test]
    fn finds_device_by_vendor_and_device_id() {
        let mut config = FakeConfig::default();
        config.add(bdf(0, 0, 0), 0x1b36, 0x0008, 0);
        config.add(bdf(0, 1, 0), 0x1af4, 0x1000, 0);
        let edu = config.add(bdf(0, 3, 0), 0x1234, 0x11e8, 0);
        edu[2] = 0x00ff_0010;
        let found = find_device(&mut config, 0, 0, 0x1234, 0x11e8).unwrap();
        assert_eq!(found.bdf, bdf(0, 3, 0));
        assert_eq!(found.requester_id(), 0x18);
        assert_eq!(found.header_type, 0);
        assert!(!found.multi_function);
        assert_eq!(found.class_revision, 0x00ff_0010);
        assert_eq!(find_device(&mut config, 0, 0, 0x1234, 0x0001), None);
    }

    #[test]
    fn walk_skips_functions_1_to_7_unless_multi_function() {
        let mut config = FakeConfig::default();
        // Single-function device: a stray function 2 must not be reported.
        config.add(bdf(0, 1, 0), 0x1111, 0x0001, 0);
        config.add(bdf(0, 1, 2), 0x1111, 0x0002, 0);
        // Multi-function device with a hole at function 1.
        config.add(bdf(0, 4, 0), 0x2222, 0x0001, 0x80);
        config.add(bdf(0, 4, 2), 0x2222, 0x0002, 0);
        config.add(bdf(0, 4, 7), 0x2222, 0x0003, 0);
        // Absent function 0: the device is skipped entirely.
        config.add(bdf(0, 6, 1), 0x3333, 0x0001, 0);
        // Bridge on a later bus, reached only when the range covers it.
        config.add(bdf(2, 0, 0), 0x4444, 0x0001, 0x01);
        let found: Vec<_> = Functions::new(&mut config, 0, 2)
            .map(|f| (f.bdf, f.device_id, f.header_type, f.multi_function))
            .collect();
        assert_eq!(
            found,
            [
                (bdf(0, 1, 0), 1, 0, false),
                (bdf(0, 4, 0), 1, 0, true),
                (bdf(0, 4, 2), 2, 0, false),
                (bdf(0, 4, 7), 3, 0, false),
                (bdf(2, 0, 0), 1, 1, false),
            ]
        );
        assert_eq!(Functions::new(&mut config, 0, 1).count(), 4);
    }

    #[test]
    fn walk_covers_last_bus_and_device_without_overflow() {
        let mut config = FakeConfig::default();
        config.add(bdf(255, 31, 0), 0x5555, 0x0001, 0x80);
        config.add(bdf(255, 31, 7), 0x5555, 0x0002, 0);
        let found: Vec<_> = Functions::new(&mut config, 255, 255)
            .map(|f| f.bdf)
            .collect();
        assert_eq!(found, [bdf(255, 31, 0), bdf(255, 31, 7)]);
        // An empty range reads nothing.
        config.reads = 0;
        assert_eq!(Functions::new(&mut config, 5, 4).count(), 0);
        assert_eq!(config.reads, 0);
    }

    #[test]
    fn functions_in_uses_the_window_bus_range() {
        let mut config = FakeConfig::default();
        config.add(bdf(0x10, 0, 0), 0x1234, 0x11e8, 0);
        config.add(bdf(0x20, 0, 0), 0x1234, 0x11e8, 0);
        let window = EcamWindow {
            base: 0x40_1000_0000,
            segment: 0,
            start_bus: 0x10,
            end_bus: 0x1f,
        };
        let found: Vec<_> = functions_in(&mut config, &window).map(|f| f.bdf).collect();
        assert_eq!(found, [bdf(0x10, 0, 0)]);
    }

    #[test]
    fn decodes_32_and_64_bit_memory_bars_and_io_bars() {
        assert_eq!(
            decode_bar(0xfe00_0000, None),
            Ok(Bar::Memory32 {
                base: 0xfe00_0000,
                prefetchable: false
            })
        );
        assert_eq!(
            decode_bar(0x1000_000c, Some(0x80)),
            Ok(Bar::Memory64 {
                base: 0x80_1000_0000,
                prefetchable: true
            })
        );
        assert_eq!(decode_bar(0xc001, None), Ok(Bar::Io { base: 0xc000 }));
        assert_eq!(decode_bar(0x4, None), Err(BarError::MissingHighHalf));
        assert_eq!(decode_bar(0x6, Some(0)), Err(BarError::ReservedType));
        assert_eq!(decode_bar(0x2, None), Err(BarError::ReservedType));
    }

    #[test]
    fn read_bar_respects_header_type_and_slots() {
        let mut config = FakeConfig::default();
        let space = config.add(bdf(0, 2, 0), 0x1234, 0x11e8, 0);
        space[4] = 0x1000_0000; // BAR0, 32-bit
        space[5] = 0x2000_0004; // BAR1, 64-bit low
        space[6] = 0x0000_0001; // BAR2, high half of BAR1
        space[9] = 0x0000_0004; // BAR5, 64-bit with no slot for the high half
        let bridge = config.add(bdf(0, 3, 0), 0x1b36, 0x0001, 1);
        bridge[4] = 0x3000_0000;
        let f = read_function(&mut config, bdf(0, 2, 0)).unwrap();
        let b = read_function(&mut config, bdf(0, 3, 0)).unwrap();
        assert_eq!(read_bar(&mut config, &f, 0).unwrap().base(), 0x1000_0000);
        let bar1 = read_bar(&mut config, &f, 1).unwrap();
        assert!(bar1.is_64bit());
        assert_eq!(bar1.base(), 0x1_2000_0000);
        assert_eq!(read_bar(&mut config, &f, 5), Err(BarError::MissingHighHalf));
        assert_eq!(read_bar(&mut config, &f, 6), Err(BarError::NoSuchBar));
        assert_eq!(read_bar(&mut config, &b, 0).unwrap().base(), 0x3000_0000);
        assert_eq!(read_bar(&mut config, &b, 2), Err(BarError::NoSuchBar));
    }

    #[test]
    fn probes_bar_sizes_and_restores_state() {
        let mut config = FakeConfig::default();
        let at = bdf(0, 2, 0);
        let space = config.add(at, 0x1234, 0x11e8, 0);
        space[1] = u32::from(COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER);
        space[4] = 0x1000_0000; // 1 MiB 32-bit BAR
        space[5] = 0x0000_000c; // 16 KiB 64-bit prefetchable BAR
        space[6] = 0x0000_0080;
        config.bar_masks.insert((at, 0), 0xfff0_0000);
        config.bar_masks.insert((at, 1), 0xffff_c000);
        config.bar_masks.insert((at, 2), 0xffff_ffff);
        config.bar_masks.insert((at, 3), 0);
        let f = read_function(&mut config, at).unwrap();
        assert_eq!(probe_bar_size(&mut config, &f, 0), Ok(Some(1 << 20)));
        assert_eq!(probe_bar_size(&mut config, &f, 1), Ok(Some(16 << 10)));
        assert_eq!(probe_bar_size(&mut config, &f, 3), Ok(None));
        let space = config.functions[&at];
        assert_eq!(space[4], 0x1000_0000);
        assert_eq!(space[5], 0x0000_000c);
        assert_eq!(space[6], 0x0000_0080);
        assert_eq!(
            space[1] as u16,
            COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER,
            "command restored"
        );
    }

    #[test]
    fn update_command_sets_and_clears_bits_without_touching_status() {
        let mut config = FakeConfig::default();
        let at = bdf(0, 2, 0);
        let space = config.add(at, 0x1234, 0x11e8, 0);
        // Status: a latched error bit (Received Master Abort, bit 13) and
        // capabilities list (bit 4). Command: INTx disable (bit 10).
        space[1] = (1 << 13 | 1 << 4) << 16 | 1 << 10;
        let on = update_command(
            &mut config,
            at,
            COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER,
            0,
        );
        assert_eq!(on, 1 << 10 | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER);
        assert_eq!(read_command(&mut config, at), on);
        let off = update_command(&mut config, at, 0, COMMAND_BUS_MASTER);
        assert_eq!(off, 1 << 10 | COMMAND_MEMORY_SPACE);
        assert_eq!(read_command(&mut config, at), off);
        // The fake clears Status bits written with 1, as hardware does, so
        // they survive only if the upper half was written as zero.
        assert_eq!(config.functions[&at][1] >> 16, (1 << 13 | 1 << 4));
    }
}
