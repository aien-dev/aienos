#![no_std]

use core::fmt::Write;

/// PCI identity observed for the GB10 GPU in the DGX Spark.
pub const NVIDIA_VENDOR_ID: u16 = 0x10de;
pub const GB10_DEVICE_ID: u16 = 0x2e12;
/// Read-only PMC registers used by the Linux Nova driver for identification.
pub const PMC_BOOT_0: u64 = 0;
pub const PMC_BOOT_42: u64 = 0x0a00;

/// PCI location and BAR0 discovered before firmware boot services are exited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciLocation {
    pub segment: u32,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// PCI location and BAR0 discovered before firmware boot services are exited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gb10Bar {
    pub location: PciLocation,
    pub physical_base: u64,
}

impl Gb10Bar {
    /// Accept only a matching GB10 function with a programmed 64-bit memory BAR.
    pub fn from_config(
        location: PciLocation,
        vendor_device: u32,
        command_status: u32,
        bar0_low: u32,
        bar0_high: u32,
    ) -> Option<Self> {
        if vendor_device != (u32::from(GB10_DEVICE_ID) << 16 | u32::from(NVIDIA_VENDOR_ID))
            || command_status & 0x2 == 0
            || bar0_low & 0x7 != 0x4
        {
            return None;
        }
        let physical_base = (u64::from(bar0_high) << 32) | u64::from(bar0_low & !0xf);
        if physical_base == 0 || physical_base.checked_add(PMC_BOOT_42 + 4).is_none() {
            return None;
        }
        Some(Self {
            location,
            physical_base,
        })
    }
}

/// Two GPU register values read through the PCI root bridge before handoff.
/// Their presence proves a register transaction was attempted, not GPU compute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gb10Identity {
    pub bar: Gb10Bar,
    pub pmc_boot_0: u32,
    pub pmc_boot_42: u32,
}

/// Outcome for one PCI root bridge during GB10 discovery, carried into the
/// boot reports so a missed discovery says why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootBridgeOutcome {
    /// The firmware refused the open of `PciRootBridgeIo` (status name).
    OpenRefused(&'static str),
    Scanned(RootBridgeScan),
}

/// What the scan of one PCI root bridge observed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RootBridgeScan {
    pub segment: u32,
    pub devices: u16,
    pub bridges: u16,
    /// Bridges with a valid secondary..subordinate bus window.
    pub windows: u16,
    /// A GB10 vendor/device match that failed the BAR check: raw
    /// command/status and BAR0 low/high, so the report shows the BAR state.
    pub rejected_candidate: Option<(u32, u32, u32)>,
}

/// Report lines explaining why discovery produced no GB10 identity:
/// bridges seen, opens refused, segments, bridge windows, and BAR state.
/// `handles` is the number of `PciRootBridgeIo` handles, if known.
pub fn write_discovery_diagnostics(
    out: &mut impl Write,
    handles: Option<u16>,
    roots: &[Option<RootBridgeOutcome>],
) {
    match handles {
        Some(n) => {
            let _ = writeln!(out, "gb10_pci_root_bridges: {n}");
        }
        None => {
            let _ = writeln!(out, "gb10_pci_root_bridges: lookup failed");
            return;
        }
    }
    for (index, outcome) in roots.iter().flatten().enumerate() {
        match outcome {
            RootBridgeOutcome::OpenRefused(status) => {
                let _ = writeln!(out, "gb10_pci_root_open[{index}]: refused ({status})");
            }
            RootBridgeOutcome::Scanned(scan) => {
                let _ = writeln!(
                    out,
                    "gb10_pci_root[{index}]: segment {} devices {} bridges {} windows {}",
                    scan.segment, scan.devices, scan.bridges, scan.windows
                );
                if let Some((command_status, bar0_low, bar0_high)) = scan.rejected_candidate {
                    let _ = writeln!(
                        out,
                        "gb10_pci_candidate[{index}]: command_status {command_status:#010x} bar0 {bar0_high:#010x}:{bar0_low:#010x}"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;

    #[test]
    fn validates_gb10_memory_bar() {
        let location = PciLocation {
            segment: 15,
            bus: 1,
            device: 0,
            function: 0,
        };
        let bar = Gb10Bar::from_config(location, 0x2e12_10de, 0x6, 0x2400_0004, 0).unwrap();
        assert_eq!(bar.physical_base, 0x2400_0000);
        assert!(Gb10Bar::from_config(location, 0x2e12_10df, 0x6, 0x2400_0004, 0).is_none());
        assert!(Gb10Bar::from_config(location, 0x2e12_10de, 0x4, 0x2400_0004, 0).is_none());
        assert!(Gb10Bar::from_config(location, 0x2e12_10de, 0x6, 0x2400_0000, 0).is_none());
    }

    #[test]
    fn diagnostics_report_refused_opens_segments_and_bar_state() {
        let roots = [
            Some(RootBridgeOutcome::OpenRefused("ACCESS_DENIED")),
            Some(RootBridgeOutcome::Scanned(RootBridgeScan {
                segment: 15,
                devices: 4,
                bridges: 1,
                windows: 1,
                rejected_candidate: Some((0x10_0004, 0, 0)),
            })),
            None,
        ];
        let mut text = String::new();
        write_discovery_diagnostics(&mut text, Some(2), &roots);
        for line in [
            "gb10_pci_root_bridges: 2",
            "gb10_pci_root_open[0]: refused (ACCESS_DENIED)",
            "gb10_pci_root[1]: segment 15 devices 4 bridges 1 windows 1",
            "gb10_pci_candidate[1]: command_status 0x00100004 bar0 0x00000000:0x00000000",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line:?} in:\n{text}");
        }

        let mut text = String::new();
        write_discovery_diagnostics(&mut text, None, &[None]);
        assert_eq!(text, "gb10_pci_root_bridges: lookup failed\n");

        let mut text = String::new();
        write_discovery_diagnostics(&mut text, Some(0), &[None]);
        assert_eq!(text, "gb10_pci_root_bridges: 0\n");
    }
}
