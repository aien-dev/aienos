#![no_std]

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
