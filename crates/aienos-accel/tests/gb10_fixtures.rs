//! Synthetic PCI configuration fixtures for GB10 discovery.
//!
//! These tests prove that discovery identifies the GB10 from device
//! properties, not from a hard-coded bus/device/function. They use only
//! in-memory byte fixtures and pure decoders: no physical device, no PCI
//! configuration write, no MMIO, no GPU execution.

use aienos_accel::pci::{
    BridgeHeader, Header, MsiCapability, MsixCapability, PciError, PcieCapability, CAP_ID_MSI,
    CAP_ID_MSIX, CAP_ID_PCIE, CONFIG_EXTENDED_SIZE, CONFIG_SPACE_SIZE,
};
use aienos_accel::profile::{match_gb10, Gb10Profile, Gb10Rejection, Source};
use aienos_accel::PciLocation;

const CONFIG_HEADER: usize = 64;

fn location(segment: u32, bus: u8, device: u8, function: u8) -> PciLocation {
    PciLocation {
        segment,
        bus,
        device,
        function,
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// A GB10-like endpoint: NVIDIA 10de:2e12, 64-bit prefetchable BAR0, PCIe,
/// MSI and MSI-X capabilities.
fn gb10_endpoint() -> [u8; CONFIG_SPACE_SIZE] {
    let mut bytes = [0u8; CONFIG_SPACE_SIZE];
    write_u16(&mut bytes, 0x00, 0x10de);
    write_u16(&mut bytes, 0x02, 0x2e12);
    write_u16(&mut bytes, 0x04, 0x0007); // IO + memory + bus master
    write_u16(&mut bytes, 0x06, 0x0010); // capabilities list present
    bytes[0x08] = 0xa1; // revision
    bytes[0x0b] = 0x03; // class: display controller
    write_u32(&mut bytes, 0x10, 0x2400_000c); // BAR0 low: 64-bit prefetchable
    write_u32(&mut bytes, 0x14, 0x0000_0000); // BAR0 high
    write_u16(&mut bytes, 0x2c, 0x10de); // subsystem vendor
    write_u16(&mut bytes, 0x2e, 0x0000); // subsystem id
    bytes[0x34] = 0x40; // capability pointer

    bytes[0x40] = CAP_ID_MSI;
    bytes[0x41] = 0x50;
    write_u16(&mut bytes, 0x42, 0x0388); // 64-bit, maskable, 16 vectors
    write_u32(&mut bytes, 0x44, 0xfee0_0000);

    bytes[0x50] = CAP_ID_PCIE;
    bytes[0x51] = 0x80;
    write_u16(&mut bytes, 0x52, 0x0002); // version 2, endpoint
    write_u32(&mut bytes, 0x54, 0x0000_0003); // max payload 1024
    write_u32(&mut bytes, 0x5c, 0x0045_7901); // max speed gen1, width x16
    write_u16(&mut bytes, 0x62, 0x8010); // current speed gen1, width x1

    bytes[0x80] = CAP_ID_MSIX;
    bytes[0x81] = 0x00;
    write_u16(&mut bytes, 0x82, 0x8008); // enabled, 9 vectors
    write_u32(&mut bytes, 0x84, 0x00b9_0000); // table in BAR0
    write_u32(&mut bytes, 0x88, 0x00ba_0000); // PBA in BAR0

    bytes
}

#[test]
fn identifies_gb10_from_properties_under_bdf_relocation() {
    let bytes = gb10_endpoint();
    let header = Header::parse(&bytes).unwrap();
    let locations = [
        location(15, 1, 0, 0),
        location(0, 0, 0, 0),
        location(3, 0x44, 0x1f, 7),
        location(0xffff, 0xff, 0x1f, 7),
    ];
    for relocated in locations {
        let matched = match_gb10(relocated, &header).unwrap();
        assert_eq!(matched.location, relocated);
        assert_eq!(matched.bar0.base, 0x2400_0000);
        assert!(matched.bar0.is_64_bit);
        assert!(matched.bar0.prefetchable);
    }
}

#[test]
fn rejects_wrong_vendor_and_wrong_device() {
    let mut wrong_device = gb10_endpoint();
    write_u16(&mut wrong_device, 0x02, 0x2684);
    assert_eq!(
        match_gb10(
            location(15, 1, 0, 0),
            &Header::parse(&wrong_device).unwrap()
        ),
        Err(Gb10Rejection::WrongDevice)
    );

    let mut wrong_vendor = gb10_endpoint();
    write_u16(&mut wrong_vendor, 0x00, 0x1234);
    assert_eq!(
        match_gb10(
            location(15, 1, 0, 0),
            &Header::parse(&wrong_vendor).unwrap()
        ),
        Err(Gb10Rejection::NotNvidia)
    );
}

#[test]
fn rejects_disabled_memory_decoding_unprogrammed_and_32_bit_bar() {
    let mut no_mem = gb10_endpoint();
    write_u16(&mut no_mem, 0x04, 0x0005); // memory bit clear
    assert_eq!(
        match_gb10(location(15, 1, 0, 0), &Header::parse(&no_mem).unwrap()),
        Err(Gb10Rejection::MemoryDecodeDisabled)
    );

    let mut unprogrammed = gb10_endpoint();
    write_u32(&mut unprogrammed, 0x10, 0x0000_0000);
    write_u32(&mut unprogrammed, 0x14, 0x0000_0000);
    assert_eq!(
        match_gb10(
            location(15, 1, 0, 0),
            &Header::parse(&unprogrammed).unwrap()
        ),
        Err(Gb10Rejection::Bar0Missing)
    );

    let mut only_high = gb10_endpoint();
    write_u32(&mut only_high, 0x10, 0x0000_0004);
    write_u32(&mut only_high, 0x14, 0x0000_0000);
    assert_eq!(
        match_gb10(location(15, 1, 0, 0), &Header::parse(&only_high).unwrap()),
        Err(Gb10Rejection::Bar0Unprogrammed)
    );

    let mut bar32 = gb10_endpoint();
    write_u32(&mut bar32, 0x10, 0x2400_0000); // 32-bit memory BAR
    write_u32(&mut bar32, 0x14, 0x0000_0000);
    assert_eq!(
        match_gb10(location(15, 1, 0, 0), &Header::parse(&bar32).unwrap()),
        Err(Gb10Rejection::Bar0Not64Bit)
    );

    let mut io_bar = gb10_endpoint();
    write_u32(&mut io_bar, 0x10, 0x0000_c001);
    assert_eq!(
        match_gb10(location(15, 1, 0, 0), &Header::parse(&io_bar).unwrap()),
        Err(Gb10Rejection::Bar0NotMemory)
    );
}

#[test]
fn selects_the_gb10_among_multiple_nvidia_devices() {
    // A fixture set with a wrong NVIDIA function and the GB10. Only the GB10
    // must satisfy the contract.
    let mut other = gb10_endpoint();
    write_u16(&mut other, 0x02, 0x2684);
    let gb10 = gb10_endpoint();
    let candidates = [
        Header::parse(&other).unwrap(),
        Header::parse(&gb10).unwrap(),
    ];
    let matches: Vec<_> = candidates
        .iter()
        .filter_map(|header| match_gb10(location(15, 1, 0, 0), header).ok())
        .collect();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].bar0.base, 0x2400_0000);
}

#[test]
fn follows_a_secondary_bus_window_to_a_downstream_gb10() {
    // Root bridge bus 0, bridge secondary 1..0x0f, GB10 behind bus 1.
    let mut bridge = [0u8; CONFIG_HEADER];
    write_u16(&mut bridge, 0x00, 0x10de);
    write_u16(&mut bridge, 0x02, 0x22d1);
    bridge[0x0b] = 0x06; // bridge class
    bridge[0x0e] = 0x01; // type 1 header
    bridge[0x19] = 0x01; // secondary bus
    bridge[0x1a] = 0x0f; // subordinate bus
    let bridge = BridgeHeader::parse(&bridge).unwrap();
    assert!(bridge.has_bus_window());
    assert!(bridge.secondary_bus <= 1 && 1 <= bridge.subordinate_bus);

    let downstream = gb10_endpoint();
    let on_bus_one = match_gb10(location(15, 1, 0, 0), &Header::parse(&downstream).unwrap());
    assert!(on_bus_one.is_ok());
}

#[test]
fn rejects_malformed_capability_loops() {
    let mut bytes = gb10_endpoint();
    bytes[0x41] = 0x40; // MSI next points at itself
    assert_eq!(
        aienos_accel::pci::walk_capabilities(&bytes),
        Err(PciError::CapabilityLoop)
    );

    let mut bytes = gb10_endpoint();
    bytes[0x34] = 0x40;
    bytes[0x40] = CAP_ID_MSI;
    bytes[0x41] = 0x30; // below 0x40 header boundary
    assert_eq!(
        aienos_accel::pci::walk_capabilities(&bytes),
        Err(PciError::OutOfBounds)
    );
}

#[test]
fn reports_missing_msi_and_msix_as_absent_not_zero() {
    // Skip the MSI capability: the header pointer goes straight to PCIe.
    let mut no_msi = gb10_endpoint();
    no_msi[0x34] = 0x50;
    let list = aienos_accel::pci::walk_capabilities(&no_msi).unwrap();
    assert!(list.find(CAP_ID_MSI).is_none());
    assert!(list.find(CAP_ID_PCIE).is_some());
    let profile =
        Gb10Profile::from_pci_config(location(15, 1, 0, 0), &no_msi, Source::SyntheticFixture)
            .unwrap();
    assert!(!profile.msi.value().unwrap().present);
    assert_eq!(profile.msix.value().unwrap().vectors, 9);

    // Drop MSI-X: PCIe becomes the last capability in the chain.
    let mut no_msix = gb10_endpoint();
    no_msix[0x51] = 0x00;
    let profile =
        Gb10Profile::from_pci_config(location(15, 1, 0, 0), &no_msix, Source::SyntheticFixture)
            .unwrap();
    assert!(!profile.msix.value().unwrap().present);
    assert!(profile.msi.value().unwrap().present);
    assert_eq!(profile.msix.value().unwrap().vectors, 0);
}

#[test]
fn decodes_capabilities_from_full_config_space() {
    let bytes = gb10_endpoint();
    let list = aienos_accel::pci::walk_capabilities(&bytes).unwrap();
    assert_eq!(list.entries().len(), 3);

    let msi = MsiCapability::decode(&bytes, list.find(CAP_ID_MSI).unwrap()).unwrap();
    assert!(msi.is_64_bit && msi.maskable);
    assert_eq!(msi.capable_vectors, 16);

    let pcie = PcieCapability::decode(&bytes, list.find(CAP_ID_PCIE).unwrap()).unwrap();
    let link = pcie.link.unwrap();
    assert_eq!(link.max_width, 16);
    assert_eq!(link.current_width, 1);
    assert!(link.downgraded);
    assert_eq!(pcie.max_payload_bytes, 1024);

    let msix = MsixCapability::decode(&bytes, list.find(CAP_ID_MSIX).unwrap()).unwrap();
    assert!(msix.enabled);
    assert_eq!(msix.vectors, 9);
    assert_eq!(msix.table_bir, 0);
    assert_eq!(msix.pba_offset, 0x00ba_0000);
}

#[test]
fn handles_large_bar_and_extended_space_bounds() {
    // A 64 GB BAR: probe readback low 0x00000004, high 0xFFFFFFF0.
    let size = aienos_accel::pci::memory_bar_size(0x0000_0004, 0xffff_fff0, true);
    assert_eq!(size, Some(0x10_0000_0000));

    // Extended capability space: a valid chain and a loop.
    let mut extended = [0u8; CONFIG_EXTENDED_SIZE];
    let first = 0x19u32 | (1 << 16) | (0x12cu32 << 20);
    write_u32(&mut extended, 0x100, first);
    let second = 0x01u32 | (2 << 16);
    write_u32(&mut extended, 0x12c, second);
    let list = aienos_accel::pci::walk_extended_capabilities(&extended).unwrap();
    assert_eq!(list.entries().len(), 2);

    let mut looped = [0u8; CONFIG_EXTENDED_SIZE];
    write_u32(&mut looped, 0x100, 0x19u32 | (0x100u32 << 20));
    assert_eq!(
        aienos_accel::pci::walk_extended_capabilities(&looped),
        Err(PciError::CapabilityLoop)
    );
}

#[test]
fn profile_decodes_bar_kinds_and_keeps_sizes_unknown() {
    let bytes = gb10_endpoint();
    let profile =
        Gb10Profile::from_pci_config(location(15, 1, 0, 0), &bytes, Source::SyntheticFixture)
            .unwrap();
    let bar0 = profile.bars[0].value().unwrap();
    assert_eq!(bar0.kind, aienos_accel::profile::BarKind::Memory);
    assert!(bar0.is_64_bit);
    assert!(bar0.prefetchable);
    assert_eq!(bar0.base, 0x2400_0000);
    // Size requires a probe write, so it must stay unknown.
    for size in profile.bar_sizes {
        assert!(!size.is_known());
    }
    // A 64-bit BAR consumed slot 1; it is not an independent BAR.
    assert_eq!(
        profile.bars[1].value().unwrap().kind,
        aienos_accel::profile::BarKind::None
    );
}
