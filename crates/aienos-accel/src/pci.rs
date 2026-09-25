//! Pure, read-only decoders for PCI configuration space.
//!
//! Every function in this module interprets a byte slice supplied by the
//! caller. Nothing here performs a PCI configuration read, a PCI configuration
//! write, or an MMIO access. The bytes come from firmware services, from the
//! Linux sysfs `config` file, or from a synthetic fixture; these decoders only
//! interpret them.
//!
//! Malformed input is rejected, never guessed at. A truncated slice, an
//! out-of-bounds offset, an invalid BAR encoding, a capability loop, and an
//! overlong capability chain each return an error. Absence of a capability is
//! not the same as an all-zero capability and is represented as `None`.

pub const CONFIG_HEADER_SIZE: usize = 64;
pub const CONFIG_SPACE_SIZE: usize = 256;
pub const CONFIG_EXTENDED_SIZE: usize = 4096;

/// Status register bit 4: the capability list is present.
pub const STATUS_CAPABILITIES_LIST: u16 = 0x0010;

pub const CAP_ID_POWER_MANAGEMENT: u8 = 0x01;
pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_VENDOR: u8 = 0x09;
pub const CAP_ID_PCIE: u8 = 0x10;
pub const CAP_ID_MSIX: u8 = 0x11;

const MAX_CAPABILITIES: usize = 48;
const MAX_EXTENDED_CAPABILITIES: usize = 64;
const MAX_EXTENDED_WORDS: usize = 64;

/// A rejection reason from a decoder. Distinct variants let a caller tell a
/// truncated read from a genuinely malformed value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PciError {
    /// The supplied slice is shorter than the structure being decoded.
    Truncated,
    /// An offset or capability pointer points outside the supplied slice.
    OutOfBounds,
    /// A BAR encoding is reserved or otherwise impossible.
    InvalidBar,
    /// A capability pointer revisited an offset already visited.
    CapabilityLoop,
    /// More capabilities than the bounded chain permits.
    TooManyCapabilities,
    /// The standard header is not a type 0 endpoint header.
    InvalidHeaderType,
    /// A capability decoder was handed a different capability id.
    WrongCapability,
}

fn add(base: usize, delta: usize) -> Result<usize, PciError> {
    base.checked_add(delta).ok_or(PciError::OutOfBounds)
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, PciError> {
    bytes.get(offset).copied().ok_or(PciError::OutOfBounds)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PciError> {
    let end = add(offset, 2)?;
    let slice = bytes.get(offset..end).ok_or(PciError::OutOfBounds)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PciError> {
    let end = add(offset, 4)?;
    let slice = bytes.get(offset..end).ok_or(PciError::OutOfBounds)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// A decoded Base Address Register. `None` marks an unimplemented or a high
/// dword consumed by the preceding 64-bit BAR.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bar {
    None,
    Memory(MemoryBar),
    Io(IoBar),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MemoryBar {
    pub base: u64,
    pub is_64_bit: bool,
    pub prefetchable: bool,
    pub size: BarSize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IoBar {
    pub base: u32,
    pub size: BarSize,
}

/// A BAR size is only known when a size probe produced it. Probing requires
/// writing all ones to the BAR, so a read-only observation leaves it unknown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BarSize {
    Known(u64),
    Unknown,
}

/// A decoded type 0 PCI header (endpoint).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class_code: u8,
    pub header_type: u8,
    pub multifunction: bool,
    pub bars: [Bar; 6],
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub capability_pointer: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self, PciError> {
        if bytes.len() < CONFIG_HEADER_SIZE {
            return Err(PciError::Truncated);
        }
        let header_type = read_u8(bytes, 0x0e)?;
        if header_type & 0x7f != 0x00 {
            return Err(PciError::InvalidHeaderType);
        }
        Ok(Self {
            vendor_id: read_u16(bytes, 0x00)?,
            device_id: read_u16(bytes, 0x02)?,
            command: read_u16(bytes, 0x04)?,
            status: read_u16(bytes, 0x06)?,
            revision: read_u8(bytes, 0x08)?,
            prog_if: read_u8(bytes, 0x09)?,
            subclass: read_u8(bytes, 0x0a)?,
            class_code: read_u8(bytes, 0x0b)?,
            header_type,
            multifunction: header_type & 0x80 != 0,
            bars: decode_bars(bytes, 0x10)?,
            subsystem_vendor_id: read_u16(bytes, 0x2c)?,
            subsystem_id: read_u16(bytes, 0x2e)?,
            capability_pointer: read_u8(bytes, 0x34)?,
            interrupt_line: read_u8(bytes, 0x3c)?,
            interrupt_pin: read_u8(bytes, 0x3d)?,
        })
    }

    /// Memory decoding enabled (PCI command register bit 1).
    pub fn memory_enabled(&self) -> bool {
        self.command & 0x0002 != 0
    }

    pub fn has_capability_list(&self) -> bool {
        self.status & STATUS_CAPABILITIES_LIST != 0
    }
}

/// Decode the six standard type 0 BAR slots starting at `offset`.
fn decode_bars(bytes: &[u8], offset: usize) -> Result<[Bar; 6], PciError> {
    let mut bars = [Bar::None; 6];
    let mut index = 0usize;
    while index < 6 {
        let low_offset = offset.checked_add(index * 4).ok_or(PciError::OutOfBounds)?;
        let low = read_u32(bytes, low_offset)?;
        if low == 0 {
            index += 1;
            continue;
        }
        if low & 0x1 == 0x1 {
            // IO BAR: bits [2:1] are reserved and must be zero.
            if low & 0x6 != 0 {
                return Err(PciError::InvalidBar);
            }
            bars[index] = Bar::Io(IoBar {
                base: low & !0x3,
                size: BarSize::Unknown,
            });
            index += 1;
            continue;
        }
        match (low >> 1) & 0x3 {
            0b00 => {
                bars[index] = Bar::Memory(MemoryBar {
                    base: u64::from(low & !0xf),
                    is_64_bit: false,
                    prefetchable: low & 0x8 != 0,
                    size: BarSize::Unknown,
                });
                index += 1;
            }
            0b10 => {
                // A 64-bit memory BAR consumes the next slot for its high
                // dword. The last slot cannot start one.
                if index + 1 >= 6 {
                    return Err(PciError::InvalidBar);
                }
                let high = read_u32(bytes, low_offset + 4)?;
                bars[index] = Bar::Memory(MemoryBar {
                    base: (u64::from(high) << 32) | u64::from(low & !0xf),
                    is_64_bit: true,
                    prefetchable: low & 0x8 != 0,
                    size: BarSize::Unknown,
                });
                index += 2;
            }
            // 0b01 and 0b11 are reserved encodings.
            _ => return Err(PciError::InvalidBar),
        }
    }
    Ok(bars)
}

/// Decode a memory BAR size from the all-ones readback a size probe produces.
///
/// This is a pure decoder for a probe result the caller already has. It does
/// not perform the probe: writing all ones to a BAR is a PCI configuration
/// write and lies outside AIENOS's read-only characterization boundary. A
/// non-power-of-two or out-of-range mask returns `None` rather than a size.
pub fn memory_bar_size(low: u32, high: u32, is_64_bit: bool) -> Option<u64> {
    // A probe writes all ones; the device returns ones for every unimplemented
    // bit, so size = !(readback & !0xf) + 1 within the BAR's address width.
    if is_64_bit {
        let mask = (u64::from(high) << 32) | u64::from(low & !0xf);
        if mask == 0 || mask == u64::MAX {
            return None;
        }
        let size = (!mask).checked_add(1)?;
        if !size.is_power_of_two() || size > (1u64 << 46) {
            return None;
        }
        Some(size)
    } else {
        let mask = low & !0xf;
        if mask == 0 || mask == u32::MAX {
            return None;
        }
        let size = u64::from((!mask).checked_add(1)?);
        if !size.is_power_of_two() || size > (1u64 << 32) {
            return None;
        }
        Some(size)
    }
}

/// Decode an IO BAR size from an all-ones readback. See `memory_bar_size`.
pub fn io_bar_size(low: u32) -> Option<u64> {
    let mask = low & !0x3;
    if mask == 0 || mask == u32::MAX {
        return None;
    }
    let size = u64::from((!mask).checked_add(1)?);
    if !size.is_power_of_two() || size > (1u64 << 32) {
        return None;
    }
    Some(size)
}

/// One entry in the standard capability linked list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capability {
    pub id: u8,
    pub offset: u8,
    pub next: u8,
}

/// A bounded, loop-checked standard capability list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapabilityList {
    entries: [Capability; MAX_CAPABILITIES],
    len: usize,
}

impl CapabilityList {
    pub const fn empty() -> Self {
        Self {
            entries: [Capability {
                id: 0,
                offset: 0,
                next: 0,
            }; MAX_CAPABILITIES],
            len: 0,
        }
    }

    pub fn entries(&self) -> &[Capability] {
        &self.entries[..self.len]
    }

    pub fn find(&self, id: u8) -> Option<Capability> {
        self.entries().iter().copied().find(|entry| entry.id == id)
    }

    fn push(&mut self, entry: Capability) -> Result<(), PciError> {
        if self.len == MAX_CAPABILITIES {
            return Err(PciError::TooManyCapabilities);
        }
        self.entries[self.len] = entry;
        self.len += 1;
        Ok(())
    }
}

/// Walk the standard capability linked list in a 256-byte configuration space.
///
/// Returns an empty list when the status register reports no capability list or
/// the capability pointer is zero. Rejects pointers below `0x40`, unaligned
/// pointers, offsets past the end, revisited offsets (loops), and chains
/// longer than the bound.
pub fn walk_capabilities(bytes: &[u8]) -> Result<CapabilityList, PciError> {
    if bytes.len() < CONFIG_SPACE_SIZE {
        return Err(PciError::Truncated);
    }
    let mut list = CapabilityList::empty();
    let status = read_u16(bytes, 0x06)?;
    if status & STATUS_CAPABILITIES_LIST == 0 {
        return Ok(list);
    }
    let mut offset = read_u8(bytes, 0x34)?;
    let mut seen = [0u64; 4];
    while offset != 0 {
        let index = usize::from(offset);
        if index < 0x40 || !index.is_multiple_of(4) {
            return Err(PciError::OutOfBounds);
        }
        if add(index, 2)? > CONFIG_SPACE_SIZE {
            return Err(PciError::OutOfBounds);
        }
        let word = index / 64;
        let bit = 1u64 << (index % 64);
        if seen[word] & bit != 0 {
            return Err(PciError::CapabilityLoop);
        }
        seen[word] |= bit;
        let id = read_u8(bytes, index)?;
        let next = read_u8(bytes, add(index, 1)?)?;
        list.push(Capability { id, offset, next })?;
        offset = next;
    }
    Ok(list)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MsiCapability {
    pub offset: u8,
    pub enabled: bool,
    pub capable_vectors: u16,
    pub enabled_vectors: u16,
    pub is_64_bit: bool,
    pub maskable: bool,
    pub address: u64,
    pub data: u16,
}

impl MsiCapability {
    pub fn decode(bytes: &[u8], capability: Capability) -> Result<Self, PciError> {
        if capability.id != CAP_ID_MSI {
            return Err(PciError::WrongCapability);
        }
        let offset = usize::from(capability.offset);
        let control = read_u16(bytes, add(offset, 2)?)?;
        let is_64_bit = control & 0x0080 != 0;
        let capable_vectors = 1u16 << ((control >> 1) & 0x7);
        let enabled_vectors = 1u16 << ((control >> 4) & 0x7);
        let address_low = read_u32(bytes, add(offset, 4)?)?;
        let (address, data_offset) = if is_64_bit {
            let address_high = read_u32(bytes, add(offset, 8)?)?;
            (
                (u64::from(address_high) << 32) | u64::from(address_low),
                add(offset, 12)?,
            )
        } else {
            (u64::from(address_low), add(offset, 8)?)
        };
        Ok(Self {
            offset: capability.offset,
            enabled: control & 0x0001 != 0,
            capable_vectors,
            enabled_vectors,
            is_64_bit,
            maskable: control & 0x0100 != 0,
            address,
            data: read_u16(bytes, data_offset)?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MsixCapability {
    pub offset: u8,
    pub enabled: bool,
    pub function_masked: bool,
    /// Number of table entries. The configuration field stores N-1.
    pub vectors: u16,
    pub table_bir: u8,
    pub table_offset: u32,
    pub pba_bir: u8,
    pub pba_offset: u32,
}

impl MsixCapability {
    pub fn decode(bytes: &[u8], capability: Capability) -> Result<Self, PciError> {
        if capability.id != CAP_ID_MSIX {
            return Err(PciError::WrongCapability);
        }
        let offset = usize::from(capability.offset);
        let control = read_u16(bytes, add(offset, 2)?)?;
        let table = read_u32(bytes, add(offset, 4)?)?;
        let pba = read_u32(bytes, add(offset, 8)?)?;
        Ok(Self {
            offset: capability.offset,
            enabled: control & 0x8000 != 0,
            function_masked: control & 0x4000 != 0,
            vectors: (control & 0x07ff) + 1,
            table_bir: (table & 0x0000_0007) as u8,
            table_offset: table & !0x0000_0007,
            pba_bir: (pba & 0x0000_0007) as u8,
            pba_offset: pba & !0x0000_0007,
        })
    }
}

/// PCI Express link speed encoding from the Link Capabilities register.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkSpeed {
    Unknown,
    Gen1,
    Gen2,
    Gen3,
    Gen4,
    Gen5,
    Gen6,
}

impl LinkSpeed {
    pub fn from_encoding(encoding: u8) -> Self {
        match encoding {
            1 => LinkSpeed::Gen1,
            2 => LinkSpeed::Gen2,
            3 => LinkSpeed::Gen3,
            4 => LinkSpeed::Gen4,
            5 => LinkSpeed::Gen5,
            6 => LinkSpeed::Gen6,
            _ => LinkSpeed::Unknown,
        }
    }

    pub fn gigatransfers(self) -> Option<u8> {
        match self {
            LinkSpeed::Unknown => None,
            LinkSpeed::Gen1 => Some(2),
            LinkSpeed::Gen2 => Some(5),
            LinkSpeed::Gen3 => Some(8),
            LinkSpeed::Gen4 => Some(16),
            LinkSpeed::Gen5 => Some(32),
            LinkSpeed::Gen6 => Some(64),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PcieLink {
    pub max_speed: LinkSpeed,
    pub max_width: u8,
    /// Raw supported-link-speeds bitmap from Link Capabilities 2, or 0 when the
    /// function does not expose a second link capability register.
    pub supported_speeds: u16,
    pub current_speed: LinkSpeed,
    pub current_width: u8,
    pub downgraded: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PcieCapability {
    pub offset: u8,
    pub version: u8,
    pub device_type: u8,
    pub slot_implemented: bool,
    /// Payload size in bytes derived from the device capabilities field.
    pub max_payload_bytes: u16,
    pub link: Option<PcieLink>,
}

impl PcieCapability {
    pub fn decode(bytes: &[u8], capability: Capability) -> Result<Self, PciError> {
        if capability.id != CAP_ID_PCIE {
            return Err(PciError::WrongCapability);
        }
        let offset = usize::from(capability.offset);
        let cap = read_u16(bytes, add(offset, 2)?)?;
        let device_type = ((cap >> 4) & 0x000f) as u8;
        let device_caps = read_u32(bytes, add(offset, 4)?)?;
        let max_payload_bytes = 128u16 << ((device_caps & 0x7) as u16);
        // Root Complex Integrated Endpoints (8) and Event Collectors (9) do
        // not implement the Link Capabilities register; every other type does.
        let link = if matches!(device_type, 0x8 | 0x9) {
            None
        } else {
            Some(decode_pcie_link(bytes, offset)?)
        };
        Ok(Self {
            offset: capability.offset,
            version: (cap & 0x000f) as u8,
            device_type,
            slot_implemented: cap & 0x0100 != 0,
            max_payload_bytes,
            link,
        })
    }
}

fn decode_pcie_link(bytes: &[u8], offset: usize) -> Result<PcieLink, PciError> {
    let link_caps = read_u32(bytes, add(offset, 0x0c)?)?;
    let link_status = read_u16(bytes, add(offset, 0x12)?)?;
    let max_speed = LinkSpeed::from_encoding((link_caps & 0x000f) as u8);
    let max_width = ((link_caps >> 4) & 0x003f) as u8;
    let current_speed = LinkSpeed::from_encoding((link_status & 0x000f) as u8);
    let current_width = ((link_status >> 4) & 0x003f) as u8;
    let supported_speeds = if add(offset, 0x20)? <= bytes.len() {
        (read_u32(bytes, add(offset, 0x1c)?)? & 0x0000_007f) as u16
    } else {
        0
    };
    let speed_downgraded = max_speed != LinkSpeed::Unknown
        && current_speed != LinkSpeed::Unknown
        && current_speed != max_speed;
    Ok(PcieLink {
        max_speed,
        max_width,
        supported_speeds,
        current_speed,
        current_width,
        downgraded: speed_downgraded || current_width < max_width,
    })
}

/// One extended capability header (PCI Express, configuration offset >= 0x100).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtendedCapability {
    pub id: u16,
    pub version: u8,
    pub offset: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtendedCapabilityList {
    entries: [ExtendedCapability; MAX_EXTENDED_CAPABILITIES],
    len: usize,
}

impl ExtendedCapabilityList {
    pub const fn empty() -> Self {
        Self {
            entries: [ExtendedCapability {
                id: 0,
                version: 0,
                offset: 0,
            }; MAX_EXTENDED_CAPABILITIES],
            len: 0,
        }
    }

    pub fn entries(&self) -> &[ExtendedCapability] {
        &self.entries[..self.len]
    }

    pub fn find(&self, id: u16) -> Option<ExtendedCapability> {
        self.entries().iter().copied().find(|entry| entry.id == id)
    }
}

/// Walk the extended capability list starting at `0x100`.
///
/// Returns an empty list when the slice stops at or before `0x100`, so a
/// 64-byte or 256-byte read yields no extended capabilities rather than an
/// error. Rejects out-of-bounds next pointers, revisited offsets, and chains
/// longer than the bound.
pub fn walk_extended_capabilities(bytes: &[u8]) -> Result<ExtendedCapabilityList, PciError> {
    let mut list = ExtendedCapabilityList::empty();
    if add(CONFIG_SPACE_SIZE, 4)? > bytes.len() {
        return Ok(list);
    }
    let mut offset = CONFIG_SPACE_SIZE;
    let mut seen = [0u64; MAX_EXTENDED_WORDS];
    let mut count = 0usize;
    while offset != 0 {
        if !offset.is_multiple_of(4) || add(offset, 4)? > CONFIG_EXTENDED_SIZE {
            return Err(PciError::OutOfBounds);
        }
        if add(offset, 4)? > bytes.len() {
            return Err(PciError::OutOfBounds);
        }
        let word = offset / 64;
        let bit = 1u64 << (offset % 64);
        if seen[word] & bit != 0 {
            return Err(PciError::CapabilityLoop);
        }
        seen[word] |= bit;
        let header = read_u32(bytes, offset)?;
        let id = (header & 0xffff) as u16;
        let version = ((header >> 16) & 0x000f) as u8;
        let next = ((header >> 20) & 0x0fff) as usize;
        if count == MAX_EXTENDED_CAPABILITIES {
            return Err(PciError::TooManyCapabilities);
        }
        list.entries[list.len] = ExtendedCapability {
            id,
            version,
            offset: offset as u16,
        };
        list.len += 1;
        count += 1;
        if id == 0xffff {
            break;
        }
        offset = next;
    }
    Ok(list)
}

/// A decoded type 1 PCI-to-PCI bridge header, enough to follow a firmware bus
/// window from a root bridge to a downstream device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BridgeHeader {
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub secondary_bus: u8,
    pub subordinate_bus: u8,
}

impl BridgeHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, PciError> {
        if bytes.len() < CONFIG_HEADER_SIZE {
            return Err(PciError::Truncated);
        }
        let header_type = read_u8(bytes, 0x0e)?;
        if header_type & 0x7f != 0x01 {
            return Err(PciError::InvalidHeaderType);
        }
        Ok(Self {
            vendor_id: read_u16(bytes, 0x00)?,
            device_id: read_u16(bytes, 0x02)?,
            class_code: read_u8(bytes, 0x0b)?,
            subclass: read_u8(bytes, 0x0a)?,
            secondary_bus: read_u8(bytes, 0x19)?,
            subordinate_bus: read_u8(bytes, 0x1a)?,
        })
    }

    /// A usable bus window is one where the secondary bus is not zero and the
    /// subordinate bus is at or above it.
    pub fn has_bus_window(&self) -> bool {
        self.secondary_bus != 0 && self.subordinate_bus >= self.secondary_bus
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_header() -> [u8; CONFIG_SPACE_SIZE] {
        let mut bytes = [0u8; CONFIG_SPACE_SIZE];
        bytes[0x00..0x02].copy_from_slice(&0x10deu16.to_le_bytes());
        bytes[0x02..0x04].copy_from_slice(&0x2e12u16.to_le_bytes());
        bytes[0x04..0x06].copy_from_slice(&0x0007u16.to_le_bytes());
        bytes[0x06..0x08].copy_from_slice(&0x0010u16.to_le_bytes());
        bytes[0x08] = 0xa1;
        bytes[0x0b] = 0x03;
        bytes
    }

    #[test]
    fn decodes_standard_header_and_64_bit_bar() {
        let mut bytes = base_header();
        bytes[0x10..0x14].copy_from_slice(&0x2400_000cu32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&0x0000_0001u32.to_le_bytes());
        bytes[0x2c..0x2e].copy_from_slice(&0x10deu16.to_le_bytes());
        let header = Header::parse(&bytes).unwrap();
        assert_eq!(header.vendor_id, 0x10de);
        assert_eq!(header.device_id, 0x2e12);
        assert_eq!(header.class_code, 0x03);
        assert!(header.memory_enabled());
        match header.bars[0] {
            Bar::Memory(bar) => {
                assert_eq!(bar.base, 0x0000_0001_2400_0000);
                assert!(bar.is_64_bit);
                assert!(bar.prefetchable);
            }
            other => panic!("expected memory bar, got {other:?}"),
        }
        assert_eq!(header.bars[1], Bar::None);
    }

    #[test]
    fn rejects_reserved_bar_encodings() {
        let mut bytes = base_header();
        bytes[0x10..0x14].copy_from_slice(&0x0000_0006u32.to_le_bytes());
        assert!(Header::parse(&bytes).is_err());
        let mut bytes = base_header();
        bytes[0x24..0x28].copy_from_slice(&0x0000_000au32.to_le_bytes());
        assert!(Header::parse(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated_header_and_bridge_type() {
        let bytes = [0u8; 16];
        assert_eq!(Header::parse(&bytes), Err(PciError::Truncated));
        let mut bytes = base_header();
        bytes[0x0e] = 0x01;
        assert_eq!(Header::parse(&bytes), Err(PciError::InvalidHeaderType));
    }

    #[test]
    fn rejects_capability_loop_and_out_of_bounds() {
        let mut bytes = base_header();
        bytes[0x34] = 0x40;
        bytes[0x40] = CAP_ID_MSI;
        bytes[0x41] = 0x40; // points at itself
        assert_eq!(walk_capabilities(&bytes), Err(PciError::CapabilityLoop));

        let mut bytes = base_header();
        bytes[0x34] = 0xff;
        assert_eq!(walk_capabilities(&bytes), Err(PciError::OutOfBounds));

        let mut bytes = base_header();
        bytes[0x34] = 0x42; // unaligned
        assert_eq!(walk_capabilities(&bytes), Err(PciError::OutOfBounds));

        let truncated = [0u8; CONFIG_HEADER_SIZE];
        assert_eq!(walk_capabilities(&truncated), Err(PciError::Truncated));
    }

    #[test]
    fn capability_list_absence_is_empty_not_error() {
        let mut bytes = base_header();
        bytes[0x06..0x08].copy_from_slice(&0u16.to_le_bytes());
        assert!(walk_capabilities(&bytes).unwrap().entries().is_empty());
        let bytes = [0u8; CONFIG_SPACE_SIZE];
        assert!(walk_capabilities(&bytes).unwrap().entries().is_empty());
    }

    #[test]
    fn decodes_msi_msix_and_pcie() {
        let mut bytes = base_header();
        bytes[0x34] = 0x40;
        // MSI at 0x40: id 0x05, next 0x50, control 0x0388 (64-bit, maskable).
        bytes[0x40] = CAP_ID_MSI;
        bytes[0x41] = 0x50;
        bytes[0x42..0x44].copy_from_slice(&0x0388u16.to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        bytes[0x4c..0x4e].copy_from_slice(&0x0041u16.to_le_bytes());
        // PCIe at 0x50: id 0x10, next 0x80, cap 0x0002, link caps/status.
        bytes[0x50] = CAP_ID_PCIE;
        bytes[0x51] = 0x80;
        bytes[0x52..0x54].copy_from_slice(&0x0002u16.to_le_bytes());
        bytes[0x54..0x58].copy_from_slice(&0x0000_0003u32.to_le_bytes());
        bytes[0x5c..0x60].copy_from_slice(&0x0045_7901u32.to_le_bytes());
        bytes[0x62..0x64].copy_from_slice(&0x8010u16.to_le_bytes());
        // MSI-X at 0x80: id 0x11, next 0, control 0x8008, table, pba.
        bytes[0x80] = CAP_ID_MSIX;
        bytes[0x81] = 0x00;
        bytes[0x82..0x84].copy_from_slice(&0x8008u16.to_le_bytes());
        bytes[0x84..0x88].copy_from_slice(&0x00b9_0000u32.to_le_bytes());
        bytes[0x88..0x8c].copy_from_slice(&0x00ba_0000u32.to_le_bytes());

        let list = walk_capabilities(&bytes).unwrap();
        assert_eq!(list.entries().len(), 3);
        let msi = MsiCapability::decode(&bytes, list.find(CAP_ID_MSI).unwrap()).unwrap();
        assert!(msi.is_64_bit && msi.maskable && !msi.enabled);
        assert_eq!(msi.capable_vectors, 16);
        assert_eq!(msi.data, 0x0041);
        let pcie = PcieCapability::decode(&bytes, list.find(CAP_ID_PCIE).unwrap()).unwrap();
        let link = pcie.link.unwrap();
        assert_eq!(link.max_speed, LinkSpeed::Gen1);
        assert_eq!(link.max_width, 16);
        assert_eq!(link.current_width, 1);
        assert!(link.downgraded);
        assert_eq!(pcie.max_payload_bytes, 1024);
        let msix = MsixCapability::decode(&bytes, list.find(CAP_ID_MSIX).unwrap()).unwrap();
        assert!(msix.enabled && !msix.function_masked);
        assert_eq!(msix.vectors, 9);
        assert_eq!(msix.table_bir, 0);
        assert_eq!(msix.table_offset, 0x00b9_0000);
        assert_eq!(msix.pba_offset, 0x00ba_0000);

        assert_eq!(
            MsiCapability::decode(&bytes, list.find(CAP_ID_MSIX).unwrap()),
            Err(PciError::WrongCapability)
        );
    }

    #[test]
    fn decodes_bridge_header_and_window() {
        let mut bytes = base_header();
        bytes[0x0e] = 0x01;
        bytes[0x19] = 0x01;
        bytes[0x1a] = 0x0f;
        let bridge = BridgeHeader::parse(&bytes).unwrap();
        assert_eq!(bridge.secondary_bus, 1);
        assert_eq!(bridge.subordinate_bus, 0x0f);
        assert!(bridge.has_bus_window());
        bytes[0x19] = 0x00;
        assert!(!BridgeHeader::parse(&bytes).unwrap().has_bus_window());
        assert_eq!(
            BridgeHeader::parse(&base_header()),
            Err(PciError::InvalidHeaderType)
        );
    }

    #[test]
    fn walks_extended_capabilities_with_loop_and_bounds_checks() {
        let mut bytes = [0u8; CONFIG_EXTENDED_SIZE];
        // Secondary PCI Express (0x19) at 0x100, then AER (0x01) at 0x12c.
        let first = 0x19u32 | (1 << 16) | (0x12cu32 << 20);
        bytes[0x100..0x104].copy_from_slice(&first.to_le_bytes());
        let second = 0x01u32 | (2 << 16);
        bytes[0x12c..0x130].copy_from_slice(&second.to_le_bytes());
        let list = walk_extended_capabilities(&bytes).unwrap();
        assert_eq!(list.entries().len(), 2);
        assert_eq!(list.find(0x19).unwrap().version, 1);
        assert_eq!(list.find(0x01).unwrap().version, 2);

        // A loop: first entry next points at itself.
        let mut bytes = [0u8; CONFIG_EXTENDED_SIZE];
        let looped = 0x19u32 | (0x100u32 << 20);
        bytes[0x100..0x104].copy_from_slice(&looped.to_le_bytes());
        assert_eq!(
            walk_extended_capabilities(&bytes),
            Err(PciError::CapabilityLoop)
        );

        // A next pointer past the 4096-byte space is rejected.
        let mut bytes = [0u8; CONFIG_EXTENDED_SIZE];
        let out = 0x19u32 | (0xfffu32 << 20);
        bytes[0x100..0x104].copy_from_slice(&out.to_le_bytes());
        assert_eq!(
            walk_extended_capabilities(&bytes),
            Err(PciError::OutOfBounds)
        );

        // A slice at or below 0x100 has no extended capabilities.
        assert!(walk_extended_capabilities(&[0u8; CONFIG_SPACE_SIZE])
            .unwrap()
            .entries()
            .is_empty());
    }

    #[test]
    fn decodes_bar_sizes_with_bounds() {
        assert_eq!(
            memory_bar_size(0xf000_0004, 0xffff_ffff, true),
            Some(0x1000_0000)
        );
        assert_eq!(memory_bar_size(0xf000_0004, 0, false), Some(0x1000_0000));
        assert_eq!(
            memory_bar_size(0x0000_0004, 0xffff_ffff, true),
            Some(0x1_0000_0000)
        );
        assert_eq!(
            memory_bar_size(0xfff0_0004, 0xffff_ffff, true),
            Some(0x10_0000)
        );
        assert_eq!(memory_bar_size(0x2400_000c, 0, false), None);
        assert_eq!(memory_bar_size(0x0000_0000, 0, false), None);
        assert_eq!(memory_bar_size(0xffff_f004, 0, false), Some(0x1000));
        assert_eq!(memory_bar_size(0xf000_1004, 0xffff_ffff, true), None);
        assert_eq!(io_bar_size(0xffff_f001), Some(0x1000));
        assert_eq!(io_bar_size(0x0000_0001), None);
    }
}
