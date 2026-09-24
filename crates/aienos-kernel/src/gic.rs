//! GICv3 register programming separated from the address and CPU interface.
//! This module configures registers only. It does not unmask CPU interrupts.

/// Register access implemented by volatile MMIO or a host fake.
pub trait GicRegisters {
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
    fn write64(&mut self, offset: usize, value: u64);
}

/// Volatile MMIO adapter for a GIC register frame mapped at its MADT address.
pub struct MmioGicRegisters {
    pub base: usize,
}
impl GicRegisters for MmioGicRegisters {
    fn read32(&mut self, offset: usize) -> u32 {
        crate::arch::MmioReg::<u32>::new(self.base + offset).read()
    }
    fn write32(&mut self, offset: usize, value: u32) {
        crate::arch::MmioReg::<u32>::new(self.base + offset).write(value);
    }
    fn write64(&mut self, offset: usize, value: u64) {
        crate::arch::MmioReg::<u64>::new(self.base + offset).write(value);
    }
}

pub const GICD_CTLR: usize = 0x0000;
pub const GICD_IGROUPR: usize = 0x0080;
pub const GICD_ISENABLER: usize = 0x0100;
pub const GICD_IPRIORITYR: usize = 0x0400;
pub const GICD_IROUTER: usize = 0x6000;
pub const GICR_WAKER: usize = 0x0014;
pub const GICR_IGROUPR0: usize = 0x10080;
pub const GICR_ISENABLER0: usize = 0x10100;
pub const GICR_IPRIORITYR: usize = 0x10400;

/// Distributor register block at the MADT GICD base.
pub struct GicDistributor<R>(pub R);

impl<R: GicRegisters> GicDistributor<R> {
    /// Disable the distributor before configuring it.
    pub fn disable(&mut self) {
        self.0.write32(GICD_CTLR, 0);
    }

    /// Enable affinity routing and non-secure Group 1 delivery at the distributor.
    pub fn enable_group1(&mut self) {
        self.0.write32(GICD_CTLR, (1 << 4) | (1 << 1));
    }

    /// Place an SPI in Group 1, set its priority and affinity route, then enable it.
    pub fn configure_spi(&mut self, intid: u32, priority: u8, affinity: u64) {
        let word = (intid / 32) as usize;
        let group = GICD_IGROUPR + word * 4;
        let group_value = self.0.read32(group);
        self.0.write32(group, group_value | (1 << (intid % 32)));
        let pword = (intid / 4) as usize;
        let shift = (intid % 4) * 8;
        let old = self.0.read32(GICD_IPRIORITYR + pword * 4);
        self.0.write32(
            GICD_IPRIORITYR + pword * 4,
            (old & !(0xff << shift)) | (u32::from(priority) << shift),
        );
        self.0.write64(
            GICD_IROUTER + intid as usize * 8,
            affinity & 0x0000_00ff_00ff_ffff,
        );
        self.0.write32(GICD_ISENABLER + word * 4, 1 << (intid % 32));
    }
}

/// One CPU's redistributor. The register view must start at that CPU's
/// RD_base (the GICR frame base from the MADT), NOT the SGI frame: offsets
/// are RD_base-relative, so `GICR_WAKER` is at +0x14 and the SGI/PPI
/// registers sit in the SGI frame at +0x10000 (`GICR_IGROUPR0` = 0x10080).
pub struct GicRedistributor<R>(pub R);

impl<R: GicRegisters> GicRedistributor<R> {
    /// Wake this redistributor. Returns false if ChildrenAsleep did not clear.
    pub fn wake(&mut self, poll_limit: usize) -> bool {
        let value = self.0.read32(GICR_WAKER) & !(1 << 1);
        self.0.write32(GICR_WAKER, value);
        for _ in 0..poll_limit {
            if self.0.read32(GICR_WAKER) & (1 << 2) == 0 {
                return true;
            }
        }
        false
    }

    /// Put an SGI or PPI in Group 1, set priority, and enable it.
    pub fn configure_ppi(&mut self, intid: u8, priority: u8) {
        assert!(intid < 32);
        let group = self.0.read32(GICR_IGROUPR0);
        self.0.write32(GICR_IGROUPR0, group | (1 << intid));
        let offset = GICR_IPRIORITYR + (intid as usize / 4) * 4;
        let shift = u32::from(intid % 4) * 8;
        let old = self.0.read32(offset);
        self.0.write32(
            offset,
            (old & !(0xff << shift)) | (u32::from(priority) << shift),
        );
        self.0.write32(GICR_ISENABLER0, 1 << intid);
    }
}

/// CPU-interface operations that use ICC_* system registers.
pub trait GicCpuInterface {
    fn enable_group1(&mut self);
    fn set_priority_mask(&mut self, mask: u8);
    fn acknowledge(&mut self) -> u32;
    fn end_interrupt(&mut self, intid: u32);
}

/// No-op CPU interface for host-side sequencing and policy tests.
#[derive(Default)]
pub struct FakeGicCpuInterface;
impl GicCpuInterface for FakeGicCpuInterface {
    fn enable_group1(&mut self) {}
    fn set_priority_mask(&mut self, _: u8) {}
    fn acknowledge(&mut self) -> u32 {
        1023
    }
    fn end_interrupt(&mut self, _: u32) {}
}

/// AArch64 ICC_* CPU-interface register implementation.
#[cfg(target_arch = "aarch64")]
pub struct Aarch64GicCpuInterface;
#[cfg(target_arch = "aarch64")]
impl GicCpuInterface for Aarch64GicCpuInterface {
    fn enable_group1(&mut self) {
        unsafe {
            core::arch::asm!("mov x9, #1", "msr ICC_SRE_EL1, x9", "isb", "msr ICC_IGRPEN1_EL1, x9", "isb", out("x9") _, options(nostack));
        }
    }
    fn set_priority_mask(&mut self, mask: u8) {
        unsafe {
            core::arch::asm!("msr ICC_PMR_EL1, {0}", "isb", in(reg) u64::from(mask), options(nostack));
        }
    }
    fn acknowledge(&mut self) -> u32 {
        let v: u64;
        unsafe {
            core::arch::asm!("mrs {0}, ICC_IAR1_EL1", out(reg) v, options(nomem, nostack));
        }
        v as u32
    }
    fn end_interrupt(&mut self, intid: u32) {
        unsafe {
            core::arch::asm!("msr ICC_EOIR1_EL1, {0}", "isb", in(reg) u64::from(intid), options(nostack));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    #[derive(Default)]
    struct Fake {
        writes: Vec<(usize, u64)>,
        value: u32,
    }
    impl GicRegisters for Fake {
        fn read32(&mut self, _: usize) -> u32 {
            self.value
        }
        fn write32(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, u64::from(value)));
        }
        fn write64(&mut self, offset: usize, value: u64) {
            self.writes.push((offset, value));
        }
    }
    #[test]
    fn distributor_spi_programming_order() {
        let mut gic = GicDistributor(Fake {
            value: 0x8000_0000,
            ..Fake::default()
        });
        gic.configure_spi(40, 0x80, 0x1234);
        assert_eq!(
            gic.0.writes,
            vec![
                (GICD_IGROUPR + 4, 0x8000_0100),
                (GICD_IPRIORITYR + 40, 0x8000_0080),
                (GICD_IROUTER + 320, 0x1234),
                (GICD_ISENABLER + 4, 0x100),
            ]
        );
    }
    #[test]
    fn register_offsets_match_gicv3_spec() {
        // Distributor (GICD_base-relative).
        assert_eq!(
            (GICD_CTLR, GICD_IGROUPR, GICD_ISENABLER, GICD_IPRIORITYR),
            (0x0, 0x80, 0x100, 0x400)
        );
        // GICD_IROUTER<n> is at 0x6000 + 8n; the first SPI (32) is at 0x6100.
        assert_eq!(GICD_IROUTER + 32 * 8, 0x6100);
        // Redistributor (RD_base-relative): WAKER in the RD frame, SGI/PPI
        // registers in the SGI frame at +0x10000.
        assert_eq!(GICR_WAKER, 0x14);
        assert_eq!(
            (GICR_IGROUPR0, GICR_ISENABLER0, GICR_IPRIORITYR),
            (0x1_0080, 0x1_0100, 0x1_0400)
        );
    }

    #[test]
    fn redistributor_wakes_and_sets_ppi() {
        let mut gic = GicRedistributor(Fake::default());
        assert!(gic.wake(1));
        gic.configure_ppi(27, 0xa0);
        assert_eq!(
            gic.0.writes,
            vec![
                (GICR_WAKER, 0),
                (GICR_IGROUPR0, 1 << 27),
                (GICR_IPRIORITYR + 24, 0xa000_0000),
                (GICR_ISENABLER0, 1 << 27),
            ]
        );
    }
}
