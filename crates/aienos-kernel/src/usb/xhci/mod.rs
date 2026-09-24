//! xHCI (USB 3 host controller) building blocks for the polled keyboard
//! driver: PCI recognition, capability decoding, register layout, port
//! status helpers, TRBs, rings and input contexts. All pure data layout and
//! bookkeeping, host-tested against the xHCI 1.2 specification; register
//! access and controller bring-up follow in the next part of the series.

pub mod context;
pub mod ring;
pub mod trb;

/// PCI class code of an xHCI controller: serial bus (0x0c), USB (0x03),
/// programming interface xHCI (0x30).
pub const XHCI_CLASS_CODE: u32 = 0x0c_03_30;
/// PCI command register bits the driver needs: memory decode and DMA.
pub const PCI_COMMAND_MEMORY: u16 = 1 << 1;
pub const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Base of an xHCI controller's register block from its PCI header: the
/// class/revision dword (offset 0x08) and BAR0/BAR1 (offsets 0x10, 0x14).
/// `None` for another device class, an I/O or unprogrammed BAR, or a failed
/// (all-ones) read.
pub fn xhci_mmio_base(class_revision: u32, bar0_low: u32, bar0_high: u32) -> Option<u64> {
    if class_revision == u32::MAX || class_revision >> 8 != XHCI_CLASS_CODE {
        return None;
    }
    let base = match bar0_low & 0x7 {
        // 32-bit memory BAR.
        0b000 => u64::from(bar0_low & !0xf),
        // 64-bit memory BAR (what the xHCI specification requires).
        0b100 => u64::from(bar0_high) << 32 | u64::from(bar0_low & !0xf),
        _ => return None,
    };
    (base != 0 && bar0_low != u32::MAX).then_some(base)
}

/// Operational register offsets from the operational base (CAPLENGTH).
pub mod op {
    pub const USBCMD: usize = 0x00;
    pub const USBSTS: usize = 0x04;
    pub const CRCR: usize = 0x18;
    pub const DCBAAP: usize = 0x30;
    pub const CONFIG: usize = 0x38;
    /// PORTSC of root hub port `port` (1-based).
    pub const fn portsc(port: u8) -> usize {
        0x400 + 0x10 * (port as usize - 1)
    }
    pub const USBCMD_RUN: u32 = 1 << 0;
    pub const USBCMD_RESET: u32 = 1 << 1;
    pub const USBSTS_HALTED: u32 = 1 << 0;
    pub const USBSTS_HOST_ERROR: u32 = 1 << 2;
    pub const USBSTS_NOT_READY: u32 = 1 << 11;
}

/// Interrupter 0 register offsets from the runtime base (RTSOFF). Each
/// interrupter set is 32 bytes and set 0 starts at 0x20.
pub mod rt {
    pub const IMAN: usize = 0x20;
    pub const ERSTSZ: usize = 0x28;
    pub const ERSTBA: usize = 0x30;
    pub const ERDP: usize = 0x38;
    /// ERDP Event Handler Busy, cleared by writing 1.
    pub const ERDP_BUSY: u64 = 1 << 3;
}

/// What the capability registers say about a controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// Offset of the operational registers (CAPLENGTH).
    pub operational_offset: usize,
    pub runtime_offset: usize,
    pub doorbell_offset: usize,
    pub max_slots: u8,
    pub max_ports: u8,
    /// Scratchpad pages the controller asks software to provide.
    pub scratchpad_pages: u16,
    /// HCCPARAMS1.AC64: the controller can reach 64-bit addresses.
    pub addresses_64: bool,
    /// Context entry size, 32 or 64 bytes (HCCPARAMS1.CSZ).
    pub context_bytes: usize,
}

impl Capabilities {
    /// Decode CAPLENGTH/HCIVERSION (offset 0x00), HCSPARAMS1 (0x04),
    /// HCSPARAMS2 (0x08), HCCPARAMS1 (0x10), DBOFF (0x14) and RTSOFF (0x18).
    /// `None` when the block reads as absent or inconsistent.
    pub fn decode(
        version_length: u32,
        hcsparams1: u32,
        hcsparams2: u32,
        hccparams1: u32,
        dboff: u32,
        rtsoff: u32,
    ) -> Option<Self> {
        let cap_length = (version_length & 0xff) as usize;
        let version = version_length >> 16;
        if version_length == u32::MAX || cap_length < 0x20 || version < 0x0090 {
            return None;
        }
        let max_slots = (hcsparams1 & 0xff) as u8;
        let max_ports = (hcsparams1 >> 24) as u8;
        if max_slots == 0 || max_ports == 0 {
            return None;
        }
        let scratchpad_hi = (hcsparams2 >> 21) & 0x1f;
        let scratchpad_lo = (hcsparams2 >> 27) & 0x1f;
        Some(Self {
            operational_offset: cap_length,
            runtime_offset: (rtsoff & !0x1f) as usize,
            doorbell_offset: (dboff & !0x3) as usize,
            max_slots,
            max_ports,
            scratchpad_pages: (scratchpad_hi << 5 | scratchpad_lo) as u16,
            addresses_64: hccparams1 & 1 != 0,
            context_bytes: if hccparams1 & (1 << 2) != 0 { 64 } else { 32 },
        })
    }
}

/// PORTSC bits (xHCI 1.2 section 5.4.8).
pub mod portsc {
    pub const CONNECTED: u32 = 1 << 0;
    pub const ENABLED: u32 = 1 << 1;
    pub const RESET: u32 = 1 << 4;
    pub const POWER: u32 = 1 << 9;
    pub const RESET_CHANGE: u32 = 1 << 21;
    /// Change bits, all write-1-to-clear: CSC, PEC, WRC, OCC, PRC, PLC, CEC.
    pub const CHANGES: u32 = 0x7f << 17;
    /// Bits that keep their value when written back: read-only fields and
    /// the preserved read/write ones (Linux calls this state "neutral").
    const READ_ONLY: u32 = 1 << 0 | 1 << 3 | 0xf << 10 | 1 << 30;
    const PRESERVED: u32 = 0xf << 5 | 1 << 9 | 0x3 << 14 | 0x7 << 25;

    /// A write value that changes nothing: it keeps the preserved fields
    /// and writes 0 to Port Enabled (writing 1 disables the port) and to
    /// every write-1-to-clear change bit.
    pub fn neutral(value: u32) -> u32 {
        value & (READ_ONLY | PRESERVED)
    }

    /// Port speed ID (bits 13:10).
    pub fn speed(value: u32) -> u8 {
        ((value >> 10) & 0xf) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_xhci_class_and_memory_bars() {
        // qemu-xhci as read in the QEMU keyboard test: class 0x0c0330 rev 1,
        // 64-bit BAR at 0x80_0000_4000.
        assert_eq!(
            xhci_mmio_base(0x0c03_3001, 0x0000_4004, 0x80),
            Some(0x80_0000_4000)
        );
        assert_eq!(
            xhci_mmio_base(0x0c03_3000, 0x0000_000c, 0x6),
            Some(0x6_0000_0000)
        );
        // A 32-bit BAR ignores the next dword (it belongs to BAR1).
        assert_eq!(
            xhci_mmio_base(0x0c03_3000, 0xfe00_0000, 0x1234),
            Some(0xfe00_0000)
        );
    }

    #[test]
    fn rejects_other_classes_io_and_unprogrammed_bars() {
        assert!(
            xhci_mmio_base(0x0c03_2000, 0x1000_0004, 0).is_none(),
            "EHCI"
        );
        assert!(
            xhci_mmio_base(0x0c03_0000, 0x1000_0004, 0).is_none(),
            "UHCI"
        );
        assert!(
            xhci_mmio_base(0x0600_0000, 0x1000_0004, 0).is_none(),
            "bridge"
        );
        assert!(
            xhci_mmio_base(u32::MAX, 0x1000_0004, 0).is_none(),
            "failed read"
        );
        assert!(
            xhci_mmio_base(0x0c03_3000, 0x0000_1001, 0).is_none(),
            "I/O BAR"
        );
        assert!(
            xhci_mmio_base(0x0c03_3000, 0x1000_0002, 0).is_none(),
            "below 1 MiB type"
        );
        assert!(
            xhci_mmio_base(0x0c03_3000, 0x0000_0004, 0).is_none(),
            "unprogrammed"
        );
        assert!(xhci_mmio_base(0x0c03_3000, u32::MAX, u32::MAX).is_none());
    }

    #[test]
    fn capabilities_decode_qemu_xhci_registers() {
        // Read from qemu-xhci in QEMU 8.2.2: CAPLENGTH 0x40, version 1.00, 64
        // slots, 16 interrupters, 8 ports, no scratchpad, AC64, 32-byte contexts.
        let caps = Capabilities::decode(
            0x0100_0040,
            0x0800_1040,
            0x0000_000f,
            0x0008_7001,
            0x2000,
            0x1000,
        )
        .unwrap();
        assert_eq!(caps.operational_offset, 0x40);
        assert_eq!(caps.max_slots, 64);
        assert_eq!(caps.max_ports, 8);
        assert_eq!(caps.scratchpad_pages, 0);
        assert!(caps.addresses_64);
        assert_eq!(caps.context_bytes, 32);
        assert_eq!(
            (caps.doorbell_offset, caps.runtime_offset),
            (0x2000, 0x1000)
        );
    }

    #[test]
    fn capabilities_decode_scratchpads_large_contexts_and_reject_absent_blocks() {
        // Scratchpad count hi = 1 (bit 21), lo = 2 (bit 28): 34 pages.
        let caps = Capabilities::decode(
            0x0110_0020,
            0x0400_0020,
            1 << 21 | 2 << 27,
            1 << 2,
            0x3003,
            0x201f,
        )
        .unwrap();
        assert_eq!(caps.scratchpad_pages, 34);
        assert_eq!(caps.context_bytes, 64);
        assert!(!caps.addresses_64);
        assert_eq!(
            (caps.doorbell_offset, caps.runtime_offset),
            (0x3000, 0x2000)
        );
        assert!(Capabilities::decode(u32::MAX, u32::MAX, 0, 0, 0, 0).is_none());
        assert!(Capabilities::decode(0x0100_0010, 0x0800_1040, 0, 0, 0, 0).is_none());
        assert!(
            Capabilities::decode(0x0100_0040, 0x0800_1000, 0, 0, 0, 0).is_none(),
            "0 slots"
        );
    }

    #[test]
    fn portsc_neutral_never_disables_the_port_or_acks_changes() {
        // Connected, enabled, powered, high speed, reset-change pending.
        let value = portsc::CONNECTED
            | portsc::ENABLED
            | portsc::POWER
            | 3 << 10
            | portsc::RESET_CHANGE
            | 1 << 17;
        let neutral = portsc::neutral(value);
        assert_eq!(neutral & portsc::ENABLED, 0, "writing PED=1 would disable");
        assert_eq!(neutral & portsc::CHANGES, 0, "no change bit acknowledged");
        assert_ne!(neutral & portsc::POWER, 0, "power stays on");
        assert_eq!(portsc::speed(value), 3);
        assert_eq!(op::portsc(1), 0x400);
        assert_eq!(op::portsc(3), 0x420);
    }
}
