//! Typed, provenance-tagged GB10 hardware characterization facts.
//!
//! The profile keeps three states apart instead of collapsing them:
//!
//! - `Observed`: a value read from a named source.
//! - `Derived`: a value computed from observed values, not read directly.
//! - `Unknown`: no value was obtained. Absence of evidence is never a zero or
//!   a default hardware property.
//!
//! Every value also carries its source, and a flag for whether native AIENOS
//! has independently verified it. A value observed through Linux sysfs is not
//! the same claim as a value decoded by native AIENOS PCI enumeration, and the
//! type keeps them distinct.

use crate::pci::{
    Bar, CapabilityList, Header, MsiCapability, MsixCapability, PciError, PcieCapability, PcieLink,
    CAP_ID_MSI, CAP_ID_MSIX, CAP_ID_PCIE,
};
use crate::{Gb10Bar, PciLocation, GB10_DEVICE_ID, NVIDIA_VENDOR_ID};
use core::fmt::{Debug, Write};

/// Where a fact came from. The source is part of the fact, not a footnote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// Read through UEFI firmware services before `ExitBootServices`.
    UefiFirmwareService,
    /// Decoded by native AIENOS PCI enumeration.
    AienosNativePci,
    /// Read from a Linux sysfs attribute.
    LinuxSysfs,
    /// Read from a Linux procfs attribute.
    LinuxProcfs,
    /// Parsed from an ACPI table exposed by the kernel.
    LinuxAcpi,
    /// Built by a test from synthetic bytes.
    SyntheticFixture,
    /// Computed from other facts rather than read from hardware.
    Derived,
}

impl Source {
    pub const fn name(self) -> &'static str {
        match self {
            Source::UefiFirmwareService => "uefi-firmware-service",
            Source::AienosNativePci => "aienos-native-pci",
            Source::LinuxSysfs => "linux-sysfs",
            Source::LinuxProcfs => "linux-procfs",
            Source::LinuxAcpi => "linux-acpi",
            Source::SyntheticFixture => "synthetic-fixture",
            Source::Derived => "derived",
        }
    }

    /// True when Linux, not AIENOS, interpreted the value.
    pub const fn linux_interpreted(self) -> bool {
        matches!(
            self,
            Source::LinuxSysfs | Source::LinuxProcfs | Source::LinuxAcpi
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Observed,
    Derived,
    Unknown,
}

/// One immutable characterization fact.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fact<T: Copy> {
    state: State,
    value: Option<T>,
    source: Option<Source>,
    native_verified: bool,
}

impl<T: Copy> Fact<T> {
    pub const fn unknown() -> Self {
        Self {
            state: State::Unknown,
            value: None,
            source: None,
            native_verified: false,
        }
    }

    pub const fn observed(value: T, source: Source) -> Self {
        Self {
            state: State::Observed,
            value: Some(value),
            source: Some(source),
            native_verified: matches!(source, Source::AienosNativePci),
        }
    }

    pub const fn derived(value: T, source: Source) -> Self {
        Self {
            state: State::Derived,
            value: Some(value),
            source: Some(source),
            native_verified: false,
        }
    }

    pub const fn marked_native_verified(self) -> Self {
        Self {
            state: self.state,
            value: self.value,
            source: self.source,
            native_verified: true,
        }
    }

    pub const fn with_source(self, source: Source) -> Self {
        Self {
            state: self.state,
            value: self.value,
            source: Some(source),
            native_verified: self.native_verified,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn value(&self) -> Option<T> {
        self.value
    }

    pub fn source(&self) -> Option<Source> {
        self.source
    }

    pub fn native_verified(&self) -> bool {
        self.native_verified
    }

    pub fn is_known(&self) -> bool {
        self.value.is_some()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClassCode {
    pub base: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BarKind {
    None,
    Memory,
    Io,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BarFacts {
    pub index: u8,
    pub kind: BarKind,
    pub base: u64,
    pub is_64_bit: bool,
    pub prefetchable: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PcieFacts {
    pub present: bool,
    pub max_payload_bytes: u16,
    pub link: Option<PcieLink>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MsiFacts {
    pub present: bool,
    pub enabled: bool,
    pub is_64_bit: bool,
    pub maskable: bool,
    pub capable_vectors: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MsixFacts {
    pub present: bool,
    pub enabled: bool,
    pub function_masked: bool,
    pub vectors: u16,
    pub table_bir: u8,
    pub table_offset: u32,
    pub pba_bir: u8,
    pub pba_offset: u32,
}

const NO_PCIE: PcieFacts = PcieFacts {
    present: false,
    max_payload_bytes: 0,
    link: None,
};

const NO_MSI: MsiFacts = MsiFacts {
    present: false,
    enabled: false,
    is_64_bit: false,
    maskable: false,
    capable_vectors: 0,
};

const NO_MSIX: MsixFacts = MsixFacts {
    present: false,
    enabled: false,
    function_masked: false,
    vectors: 0,
    table_bir: 0,
    table_offset: 0,
    pba_bir: 0,
    pba_offset: 0,
};

/// The immutable profile. PCI-derived fields come from a configuration-space
/// read; firmware, IOMMU, NUMA, and PMC fields are filled only from sources
/// that actually expose them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Gb10Profile {
    pub location: PciLocation,
    pub vendor_id: Fact<u16>,
    pub device_id: Fact<u16>,
    pub subsystem_vendor_id: Fact<u16>,
    pub subsystem_id: Fact<u16>,
    pub revision: Fact<u8>,
    pub class: Fact<ClassCode>,
    pub command: Fact<u16>,
    pub status: Fact<u16>,
    pub bars: [Fact<BarFacts>; 6],
    pub bar_sizes: [Fact<u64>; 6],
    pub pcie: Fact<PcieFacts>,
    pub msi: Fact<MsiFacts>,
    pub msix: Fact<MsixFacts>,
    pub iommu_group: Fact<u32>,
    pub numa_node: Fact<i32>,
    pub firmware_path: Fact<&'static str>,
    pub pmc_boot_0: Fact<u32>,
    pub pmc_boot_42: Fact<u32>,
}

impl Gb10Profile {
    /// A profile with every fact unknown. Use this when discovery has not run.
    pub const fn unknown(location: PciLocation) -> Self {
        Self {
            location,
            vendor_id: Fact::unknown(),
            device_id: Fact::unknown(),
            subsystem_vendor_id: Fact::unknown(),
            subsystem_id: Fact::unknown(),
            revision: Fact::unknown(),
            class: Fact::unknown(),
            command: Fact::unknown(),
            status: Fact::unknown(),
            bars: [Fact::unknown(); 6],
            bar_sizes: [Fact::unknown(); 6],
            pcie: Fact::unknown(),
            msi: Fact::unknown(),
            msix: Fact::unknown(),
            iommu_group: Fact::unknown(),
            numa_node: Fact::unknown(),
            firmware_path: Fact::unknown(),
            pmc_boot_0: Fact::unknown(),
            pmc_boot_42: Fact::unknown(),
        }
    }

    /// Decode the PCI-derived facts from raw configuration-space bytes. Facts
    /// that configuration space cannot answer stay `Unknown`.
    pub fn from_pci_config(
        location: PciLocation,
        bytes: &[u8],
        source: Source,
    ) -> Result<Self, PciError> {
        let header = Header::parse(bytes)?;
        let mut profile = Self::unknown(location);
        profile.vendor_id = Fact::observed(header.vendor_id, source);
        profile.device_id = Fact::observed(header.device_id, source);
        profile.subsystem_vendor_id = Fact::observed(header.subsystem_vendor_id, source);
        profile.subsystem_id = Fact::observed(header.subsystem_id, source);
        profile.revision = Fact::observed(header.revision, source);
        profile.class = Fact::observed(
            ClassCode {
                base: header.class_code,
                subclass: header.subclass,
                prog_if: header.prog_if,
            },
            source,
        );
        profile.command = Fact::observed(header.command, source);
        profile.status = Fact::observed(header.status, source);
        for (index, bar) in header.bars.iter().enumerate() {
            profile.bars[index] = Fact::observed(bar_facts(index, *bar), source);
        }

        let capabilities = crate::pci::walk_capabilities(bytes)?;
        profile.pcie = Fact::observed(decode_pcie(&capabilities, bytes), source);
        profile.msi = Fact::observed(decode_msi(&capabilities, bytes), source);
        profile.msix = Fact::observed(decode_msix(&capabilities, bytes), source);
        Ok(profile)
    }

    pub fn write(&self, out: &mut impl Write) {
        let _ = writeln!(
            out,
            "gb10.profile.location: segment {} bus {} device {} function {}",
            self.location.segment, self.location.bus, self.location.device, self.location.function
        );
        write_fact(out, "gb10.profile.vendor_id", self.vendor_id);
        write_fact(out, "gb10.profile.device_id", self.device_id);
        write_fact(
            out,
            "gb10.profile.subsystem_vendor_id",
            self.subsystem_vendor_id,
        );
        write_fact(out, "gb10.profile.subsystem_id", self.subsystem_id);
        write_fact(out, "gb10.profile.revision", self.revision);
        write_fact(out, "gb10.profile.class", self.class);
        write_fact(out, "gb10.profile.command", self.command);
        write_fact(out, "gb10.profile.status", self.status);
        for (index, bar) in self.bars.iter().enumerate() {
            write_indexed_fact(out, "gb10.profile.bar", index, *bar);
        }
        for (index, size) in self.bar_sizes.iter().enumerate() {
            write_indexed_fact(out, "gb10.profile.bar_size", index, *size);
        }
        write_fact(out, "gb10.profile.pcie", self.pcie);
        write_fact(out, "gb10.profile.msi", self.msi);
        write_fact(out, "gb10.profile.msix", self.msix);
        write_fact(out, "gb10.profile.iommu_group", self.iommu_group);
        write_fact(out, "gb10.profile.numa_node", self.numa_node);
        write_fact(out, "gb10.profile.firmware_path", self.firmware_path);
        write_fact(out, "gb10.profile.pmc_boot_0", self.pmc_boot_0);
        write_fact(out, "gb10.profile.pmc_boot_42", self.pmc_boot_42);
    }
}

fn bar_facts(index: usize, bar: Bar) -> BarFacts {
    match bar {
        Bar::None => BarFacts {
            index: index as u8,
            kind: BarKind::None,
            base: 0,
            is_64_bit: false,
            prefetchable: false,
        },
        Bar::Memory(memory) => BarFacts {
            index: index as u8,
            kind: BarKind::Memory,
            base: memory.base,
            is_64_bit: memory.is_64_bit,
            prefetchable: memory.prefetchable,
        },
        Bar::Io(io) => BarFacts {
            index: index as u8,
            kind: BarKind::Io,
            base: u64::from(io.base),
            is_64_bit: false,
            prefetchable: false,
        },
    }
}

fn decode_pcie(capabilities: &CapabilityList, bytes: &[u8]) -> PcieFacts {
    match capabilities.find(CAP_ID_PCIE) {
        Some(capability) => match PcieCapability::decode(bytes, capability) {
            Ok(pcie) => PcieFacts {
                present: true,
                max_payload_bytes: pcie.max_payload_bytes,
                link: pcie.link,
            },
            Err(_) => NO_PCIE,
        },
        None => NO_PCIE,
    }
}

fn decode_msi(capabilities: &CapabilityList, bytes: &[u8]) -> MsiFacts {
    match capabilities.find(CAP_ID_MSI) {
        Some(capability) => match MsiCapability::decode(bytes, capability) {
            Ok(msi) => MsiFacts {
                present: true,
                enabled: msi.enabled,
                is_64_bit: msi.is_64_bit,
                maskable: msi.maskable,
                capable_vectors: msi.capable_vectors,
            },
            Err(_) => NO_MSI,
        },
        None => NO_MSI,
    }
}

fn decode_msix(capabilities: &CapabilityList, bytes: &[u8]) -> MsixFacts {
    match capabilities.find(CAP_ID_MSIX) {
        Some(capability) => match MsixCapability::decode(bytes, capability) {
            Ok(msix) => MsixFacts {
                present: true,
                enabled: msix.enabled,
                function_masked: msix.function_masked,
                vectors: msix.vectors,
                table_bir: msix.table_bir,
                table_offset: msix.table_offset,
                pba_bir: msix.pba_bir,
                pba_offset: msix.pba_offset,
            },
            Err(_) => NO_MSIX,
        },
        None => NO_MSIX,
    }
}

fn write_indexed_fact<T: Debug + Copy>(
    out: &mut impl Write,
    prefix: &str,
    index: usize,
    fact: Fact<T>,
) {
    match (fact.state(), fact.value(), fact.source()) {
        (State::Observed, Some(value), Some(source)) => {
            let _ = writeln!(
                out,
                "{prefix}[{index}]: {value:?} [observed source={} native_verified={}]",
                source.name(),
                fact.native_verified()
            );
        }
        (State::Derived, Some(value), Some(source)) => {
            let _ = writeln!(
                out,
                "{prefix}[{index}]: {value:?} [derived source={} native_verified={}]",
                source.name(),
                fact.native_verified()
            );
        }
        _ => {
            let _ = writeln!(out, "{prefix}[{index}]: unknown");
        }
    }
}

fn write_fact<T: Debug + Copy>(out: &mut impl Write, name: &str, fact: Fact<T>) {
    match (fact.state(), fact.value(), fact.source()) {
        (State::Observed, Some(value), Some(source)) => {
            let _ = writeln!(
                out,
                "{name}: {value:?} [observed source={} native_verified={}]",
                source.name(),
                fact.native_verified()
            );
        }
        (State::Derived, Some(value), Some(source)) => {
            let _ = writeln!(
                out,
                "{name}: {value:?} [derived source={} native_verified={}]",
                source.name(),
                fact.native_verified()
            );
        }
        _ => {
            let _ = writeln!(out, "{name}: unknown");
        }
    }
}

/// Why a GB10 candidate did not satisfy the contract. Each variant names the
/// exact property that failed so a report can distinguish a wrong device from
/// a device whose memory decoding or BAR0 is not yet usable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gb10Rejection {
    NotNvidia,
    WrongDevice,
    MemoryDecodeDisabled,
    Bar0Missing,
    Bar0NotMemory,
    Bar0Unprogrammed,
    Bar0Not64Bit,
}

/// A GB10 endpoint that satisfies the typed contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gb10Match {
    pub location: PciLocation,
    pub bar0: crate::pci::MemoryBar,
}

/// Validate a decoded endpoint header against the GB10 contract using device
/// properties only. No bus, device, or function number is assumed: a relocated
/// GB10 matches exactly as the observed one does.
pub fn match_gb10(location: PciLocation, header: &Header) -> Result<Gb10Match, Gb10Rejection> {
    if header.vendor_id != NVIDIA_VENDOR_ID {
        return Err(Gb10Rejection::NotNvidia);
    }
    if header.device_id != GB10_DEVICE_ID {
        return Err(Gb10Rejection::WrongDevice);
    }
    if !header.memory_enabled() {
        return Err(Gb10Rejection::MemoryDecodeDisabled);
    }
    match header.bars[0] {
        Bar::None => Err(Gb10Rejection::Bar0Missing),
        Bar::Io(_) => Err(Gb10Rejection::Bar0NotMemory),
        Bar::Memory(memory) => {
            if memory.base == 0 {
                Err(Gb10Rejection::Bar0Unprogrammed)
            } else if !memory.is_64_bit {
                Err(Gb10Rejection::Bar0Not64Bit)
            } else {
                Ok(Gb10Match {
                    location,
                    bar0: memory,
                })
            }
        }
    }
}

impl Gb10Bar {
    /// Validate the legacy handoff register values against the GB10 contract
    /// and name why a candidate was rejected. Keeping the contract here means
    /// the boot handoff and the host profile check the same properties.
    pub fn from_header(
        location: PciLocation,
        vendor_device: u32,
        command_status: u32,
        bar0_low: u32,
        bar0_high: u32,
    ) -> Result<Self, Gb10Rejection> {
        if (vendor_device & 0xffff) as u16 != NVIDIA_VENDOR_ID {
            return Err(Gb10Rejection::NotNvidia);
        }
        if (vendor_device >> 16) as u16 != GB10_DEVICE_ID {
            return Err(Gb10Rejection::WrongDevice);
        }
        if command_status & 0x0002 == 0 {
            return Err(Gb10Rejection::MemoryDecodeDisabled);
        }
        if bar0_low & 0x1 == 0x1 {
            return Err(Gb10Rejection::Bar0NotMemory);
        }
        if bar0_low == 0 && bar0_high == 0 {
            return Err(Gb10Rejection::Bar0Unprogrammed);
        }
        if bar0_low & 0x7 != 0x4 {
            return Err(Gb10Rejection::Bar0Not64Bit);
        }
        let physical_base = (u64::from(bar0_high) << 32) | u64::from(bar0_low & !0xf);
        if physical_base == 0 {
            return Err(Gb10Rejection::Bar0Unprogrammed);
        }
        Ok(Self {
            location,
            physical_base,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn gb10_config() -> [u8; crate::pci::CONFIG_SPACE_SIZE] {
        let mut bytes = [0u8; crate::pci::CONFIG_SPACE_SIZE];
        bytes[0x00..0x02].copy_from_slice(&0x10deu16.to_le_bytes());
        bytes[0x02..0x04].copy_from_slice(&0x2e12u16.to_le_bytes());
        bytes[0x04..0x06].copy_from_slice(&0x0007u16.to_le_bytes());
        bytes[0x06..0x08].copy_from_slice(&0x0010u16.to_le_bytes());
        bytes[0x08] = 0xa1;
        bytes[0x0b] = 0x03;
        bytes[0x10..0x14].copy_from_slice(&0x2400_000cu32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&0x0000_0000u32.to_le_bytes());
        bytes[0x34] = 0x40;
        bytes[0x40] = CAP_ID_MSI;
        bytes[0x41] = 0x50;
        bytes[0x42..0x44].copy_from_slice(&0x0388u16.to_le_bytes());
        bytes[0x50] = CAP_ID_PCIE;
        bytes[0x51] = 0x80;
        bytes[0x52..0x54].copy_from_slice(&0x0002u16.to_le_bytes());
        bytes[0x54..0x58].copy_from_slice(&0x0000_0003u32.to_le_bytes());
        bytes[0x5c..0x60].copy_from_slice(&0x0045_7901u32.to_le_bytes());
        bytes[0x62..0x64].copy_from_slice(&0x8010u16.to_le_bytes());
        bytes[0x80] = CAP_ID_MSIX;
        bytes[0x81] = 0x00;
        bytes[0x82..0x84].copy_from_slice(&0x8008u16.to_le_bytes());
        bytes[0x84..0x88].copy_from_slice(&0x00b9_0000u32.to_le_bytes());
        bytes[0x88..0x8c].copy_from_slice(&0x00ba_0000u32.to_le_bytes());
        bytes
    }

    fn location() -> PciLocation {
        PciLocation {
            segment: 15,
            bus: 1,
            device: 0,
            function: 0,
        }
    }

    #[test]
    fn profile_classifies_source_and_native_verification() {
        let bytes = gb10_config();
        let linux = Gb10Profile::from_pci_config(location(), &bytes, Source::LinuxSysfs).unwrap();
        assert_eq!(linux.vendor_id.value(), Some(0x10de));
        assert_eq!(linux.vendor_id.source(), Some(Source::LinuxSysfs));
        assert!(!linux.vendor_id.native_verified());
        assert!(Source::LinuxSysfs.linux_interpreted());
        assert!(!Source::AienosNativePci.linux_interpreted());

        let native =
            Gb10Profile::from_pci_config(location(), &bytes, Source::AienosNativePci).unwrap();
        assert!(native.vendor_id.native_verified());
        assert_eq!(native.msix.value().unwrap().vectors, 9);
        assert!(native.pcie.value().unwrap().link.unwrap().downgraded);
        // Sources configuration space cannot answer stay unknown.
        assert_eq!(native.iommu_group.state(), State::Unknown);
        assert_eq!(native.numa_node.state(), State::Unknown);
        assert_eq!(native.bar_sizes[0].state(), State::Unknown);
    }

    #[test]
    fn profile_renders_deterministically() {
        extern crate std;
        use std::string::String;
        let bytes = gb10_config();
        let profile =
            Gb10Profile::from_pci_config(location(), &bytes, Source::AienosNativePci).unwrap();
        let mut text = String::new();
        profile.write(&mut text);
        assert!(text.contains(
            "gb10.profile.vendor_id: 4318 [observed source=aienos-native-pci native_verified=true]"
        ));
        assert!(text.contains("gb10.profile.iommu_group: unknown"));
        assert!(text.contains("gb10.profile.bar_size[0]: unknown"));
    }

    #[test]
    fn match_gb10_is_property_based_not_bdf_based() {
        let bytes = gb10_config();
        let header = Header::parse(&bytes).unwrap();
        // Same device at a completely different location still matches.
        let relocated = PciLocation {
            segment: 0,
            bus: 0x44,
            device: 0x1f,
            function: 7,
        };
        let matched = match_gb10(relocated, &header).unwrap();
        assert_eq!(matched.location, relocated);
        assert_eq!(matched.bar0.base, 0x2400_0000);

        let mut wrong_device = bytes;
        wrong_device[0x02..0x04].copy_from_slice(&0x2684u16.to_le_bytes());
        assert_eq!(
            match_gb10(location(), &Header::parse(&wrong_device).unwrap()),
            Err(Gb10Rejection::WrongDevice)
        );

        let mut forbidden = bytes;
        forbidden[0x00..0x02].copy_from_slice(&0x1234u16.to_le_bytes());
        assert_eq!(
            match_gb10(location(), &Header::parse(&forbidden).unwrap()),
            Err(Gb10Rejection::NotNvidia)
        );

        let mut no_mem = bytes;
        no_mem[0x04..0x06].copy_from_slice(&0x0005u16.to_le_bytes());
        assert_eq!(
            match_gb10(location(), &Header::parse(&no_mem).unwrap()),
            Err(Gb10Rejection::MemoryDecodeDisabled)
        );

        let mut no_bar = bytes;
        no_bar[0x10..0x14].copy_from_slice(&0u32.to_le_bytes());
        no_bar[0x14..0x18].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            match_gb10(location(), &Header::parse(&no_bar).unwrap()),
            Err(Gb10Rejection::Bar0Missing)
        );

        let mut io_bar = bytes;
        io_bar[0x10..0x14].copy_from_slice(&0x0000_c001u32.to_le_bytes());
        assert_eq!(
            match_gb10(location(), &Header::parse(&io_bar).unwrap()),
            Err(Gb10Rejection::Bar0NotMemory)
        );

        let mut bar32 = bytes;
        bar32[0x10..0x14].copy_from_slice(&0x2400_0000u32.to_le_bytes());
        bar32[0x14..0x18].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            match_gb10(location(), &Header::parse(&bar32).unwrap()),
            Err(Gb10Rejection::Bar0Not64Bit)
        );
    }
}
