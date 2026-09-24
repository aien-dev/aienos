//! USB host support for the early console: an xHCI controller driver and a
//! HID boot-protocol keyboard.
//!
//! After `ExitBootServices` the firmware's USB keyboard support is gone, so
//! AIENOS drives the xHCI controller itself. The driver is deliberately
//! minimal and polled: one slot, one control endpoint and one interrupt-IN
//! endpoint, bounded rings, and every doorbell wait has a limit so a missing
//! or wedged controller degrades the keyboard instead of hanging boot.

pub mod hid;
pub mod xhci;

/// PCI class code for an xHCI USB controller (class 0x0c, subclass 0x03,
/// programming interface 0x30).
pub const XHCI_CLASS_CODE: u32 = 0x0c_03_30;

/// Recognize an xHCI controller from PCI configuration header type 0 fields.
///
/// `vendor_device` is the dword at offset 0x00, `class_code` the dword at
/// 0x08, `bar0_low`/`bar0_high` the dwords at 0x10/0x14. Returns the physical
/// base of the 64-bit MMIO BAR when the header describes an xHCI controller
/// with a programmed 64-bit memory BAR.
pub fn xhci_mmio_base(
    vendor_device: u32,
    class_code: u32,
    bar0_low: u32,
    bar0_high: u32,
) -> Option<u64> {
    if class_code >> 8 != XHCI_CLASS_CODE {
        return None;
    }
    // BAR must be memory space, 64-bit wide, and the read must not have failed.
    if vendor_device == 0xffff_ffff || bar0_low & 0x7 != 0x4 {
        return None;
    }
    let base = u64::from(bar0_high) << 32 | u64::from(bar0_low & !0xf);
    (base != 0).then_some(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_xhci_class_code_and_64_bit_bar() {
        // QEMU qemu-xhci: vendor 0x1b36 device 0x000d, class 0x0c0330.
        assert_eq!(
            xhci_mmio_base(0x000d_1b36, 0x0c03_3000, 0xc020_0004, 0),
            Some(0xc020_0000)
        );
        // 64-bit BAR above 4 GiB.
        assert_eq!(
            xhci_mmio_base(0x2e12_10de, 0x0c03_3000, 0x0000_0004, 0x6),
            Some(0x6_0000_0000)
        );
    }

    #[test]
    fn rejects_other_devices_and_bad_bars() {
        // EHCI (programming interface 0x20) and UHCI (0x00) are not xHCI.
        assert!(xhci_mmio_base(0x000d_1b36, 0x0c03_2000, 0xc020_0004, 0).is_none());
        assert!(xhci_mmio_base(0x000d_1b36, 0x0c03_0000, 0xc020_0004, 0).is_none());
        // Not a USB controller at all.
        assert!(xhci_mmio_base(0x000d_1b36, 0x0600_0000, 0xc020_0004, 0).is_none());
        // 32-bit BAR, I/O BAR, unprogrammed BAR, and a failed read.
        assert!(xhci_mmio_base(0x000d_1b36, 0x0c03_3000, 0xc020_0000, 0).is_none());
        assert!(xhci_mmio_base(0x000d_1b36, 0x0c03_3000, 0xc020_0005, 0).is_none());
        assert!(xhci_mmio_base(0x000d_1b36, 0x0c03_3000, 0x0000_0004, 0).is_none());
        assert!(xhci_mmio_base(0xffff_ffff, 0x0c03_3000, 0xc020_0004, 0).is_none());
    }
}
