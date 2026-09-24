//! AIENOS Bare-Metal Boot Spine (§Step 2 of Systems Integration Sequence).
//!
//! Provides the bare-metal entry path, early serial banner, and BootReceipt.

use crate::acpi::CpuTopology;
use crate::arch::aarch64::{
    counter_ticks, current_el, disable_interrupts, dsb, halt, isb, midr_el1, midr_part, EarlyUart,
    SPARK_16550_UART_BASE,
};
use crate::mem::{BitmapFrameAllocator, PhysAddr, PAGE_SIZE};
use crate::report::ReportBuf;
use crate::sync::spinlock::SpinLock;
use core::fmt::Write;

const EARLY_BITMAP_WORDS: usize = 64;
const MAX_EARLY_FRAMES: usize = EARLY_BITMAP_WORDS * 64;
static EARLY_ALLOCATOR: SpinLock<Option<BitmapFrameAllocator<EARLY_BITMAP_WORDS>>> =
    SpinLock::new(None);

/// Allocate a frame from the first conventional-memory region after handoff.
pub fn allocate_early_frame() -> Option<PhysAddr> {
    EARLY_ALLOCATOR.lock().as_mut()?.allocate_frame()
}

fn initialize_early_allocator(region: BootMemoryRegion) -> Option<(usize, PhysAddr)> {
    let mut allocator = EARLY_ALLOCATOR.lock();
    if allocator.is_some() {
        return None;
    }
    let managed_frames = region.page_count.min(MAX_EARLY_FRAMES);
    *allocator = Some(BitmapFrameAllocator::new(region.start, managed_frames));
    let first_frame = allocator.as_mut()?.allocate_frame()?;
    Some((managed_frames, first_frame))
}

/// A page-aligned conventional-memory region supplied by the firmware map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootMemoryRegion {
    start: PhysAddr,
    page_count: usize,
}

impl BootMemoryRegion {
    /// Validate descriptor arithmetic before the kernel constructs an allocator.
    pub fn new(physical_start: u64, page_count: u64) -> Option<Self> {
        let start = PhysAddr(usize::try_from(physical_start).ok()?);
        let page_count = usize::try_from(page_count).ok()?;
        if !start.is_page_aligned()
            || page_count == 0
            || page_count > (usize::MAX - start.0) / PAGE_SIZE
        {
            return None;
        }
        Some(Self { start, page_count })
    }

    /// Number of 4 KiB pages in this validated region.
    pub const fn page_count(self) -> usize {
        self.page_count
    }
}

/// Counter samples taken by the Rust UEFI entry and passed to the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootTiming {
    pub uefi_entry_ticks: u64,
    pub kernel_handoff_ticks: u64,
    pub counter_frequency_hz: u64,
}

impl BootTiming {
    /// Convert elapsed architectural counter ticks to milliseconds.
    pub fn elapsed_ms(start: u64, end: u64, frequency_hz: u64) -> Option<u64> {
        if frequency_hz == 0 || end < start {
            return None;
        }
        let elapsed = (u128::from(end - start) * 1000) / u128::from(frequency_hz);
        u64::try_from(elapsed).ok()
    }
}

/// Deterministic, immutable boot receipt emitted by the native boot spine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootReceipt {
    pub boot_epoch: u64,
    pub arch_magic: u32, // 0xAA64_0001
    pub exception_level: u8,
    pub entry_status: u8, // 0 = Clean Entry
    pub exit_status: u8,  // 0 = Clean Halt
    pub memory_detected_kb: u64,
    pub kernel_sha256_prefix: [u8; 8],
}

impl BootReceipt {
    pub const ARCH_AARCH64: u32 = 0xAA64_0001;

    pub const fn new(epoch: u64, el: u8, mem_kb: u64, hash_prefix: [u8; 8]) -> Self {
        Self {
            boot_epoch: epoch,
            arch_magic: Self::ARCH_AARCH64,
            exception_level: el,
            entry_status: 0,
            exit_status: 0,
            memory_detected_kb: mem_kb,
            kernel_sha256_prefix: hash_prefix,
        }
    }
}

/// Early kernel boot initialization executed directly from UEFI or reset vector.
pub fn early_kernel_init(conventional_memory_kb: u64) -> ! {
    early_kernel_init_with_timing(conventional_memory_kb, None)
}

/// Early kernel entry with firmware-entry and handoff timing samples.
pub fn early_kernel_init_with_timing(
    conventional_memory_kb: u64,
    boot_timing: Option<BootTiming>,
) -> ! {
    early_kernel_init_with_memory(conventional_memory_kb, None, boot_timing)
}

/// Early kernel entry with a validated conventional-memory region.
pub fn early_kernel_init_with_memory(
    conventional_memory_kb: u64,
    memory_region: Option<BootMemoryRegion>,
    boot_timing: Option<BootTiming>,
) -> ! {
    early_kernel_init_with_gpu(conventional_memory_kb, memory_region, boot_timing, None)
}

/// Capacity of the native boot report shared by every output.
pub const REPORT_CAPACITY: usize = 2048;
pub type BootReport = ReportBuf<REPORT_CAPACITY>;

/// Facts the kernel reports after taking control from firmware.
pub struct BootFacts {
    pub conventional_memory_kb: u64,
    /// `(managed_frames, reserved_frame)` or `None` if no usable region.
    pub allocator: Option<(usize, PhysAddr)>,
    pub timing: Option<BootTiming>,
    pub kernel_entry_ticks: u64,
    pub gb10: Option<aienos_accel::Gb10Identity>,
    /// Core inventory from the firmware MADT, if it was found and valid.
    pub cpu: Option<CpuTopology>,
    /// MIDR of the core running the boot path.
    pub boot_midr: u64,
    pub exception_level: u8,
}

/// Formats the report. Returns false if boot cannot continue (no allocator).
pub fn write_boot_report(out: &mut impl Write, facts: &BootFacts) -> bool {
    let _ = writeln!(out, "AIENOS");
    let _ = writeln!(out, "arch: aarch64");
    let _ = writeln!(out, "boot: native");
    let _ = writeln!(
        out,
        "conventional_memory_kb: {}",
        facts.conventional_memory_kb
    );
    match facts.gb10 {
        Some(g) => {
            let _ = writeln!(out, "gb10_segment: {}", g.bar.location.segment);
            let _ = writeln!(out, "gb10_bar0_phys: {:#x}", g.bar.physical_base);
            let _ = writeln!(out, "gb10_pmc_boot_0: {:#010x}", g.pmc_boot_0);
            let _ = writeln!(out, "gb10_pmc_boot_42: {:#010x}", g.pmc_boot_42);
        }
        None => {
            let _ = writeln!(out, "gb10: unavailable");
        }
    }
    match facts.cpu {
        Some(t) => {
            let _ = writeln!(out, "cpu_cores: {}", t.cores);
            for (class, count) in t.classes() {
                let _ = writeln!(out, "cpu_efficiency_class_{class}: {count}");
            }
            if t.unknown_class > 0 {
                let _ = writeln!(out, "cpu_efficiency_class_unknown: {}", t.unknown_class);
            }
        }
        None => {
            let _ = writeln!(out, "cpu_topology: unavailable");
        }
    }
    let _ = writeln!(
        out,
        "boot_cpu_midr: {:#x} (part {:#05x})",
        facts.boot_midr,
        midr_part(facts.boot_midr)
    );
    let Some((managed_frames, first_frame)) = facts.allocator else {
        let _ = writeln!(out, "allocator: unavailable; boot halted");
        return false;
    };
    let _ = writeln!(out, "allocator_managed_frames: {managed_frames}");
    let _ = writeln!(out, "allocator_reserved_frame_phys: {:#x}", first_frame.0);
    if let Some(t) = facts.timing {
        let hz = t.counter_frequency_hz;
        if let Some(ms) = BootTiming::elapsed_ms(t.uefi_entry_ticks, t.kernel_handoff_ticks, hz) {
            let _ = writeln!(out, "uefi_entry_to_handoff_ms: {ms}");
        }
        if let Some(ms) =
            BootTiming::elapsed_ms(t.kernel_handoff_ticks, facts.kernel_entry_ticks, hz)
        {
            let _ = writeln!(out, "handoff_to_kernel_entry_ms: {ms}");
        }
    }
    let _ = writeln!(out, "exception_level: EL{}", facts.exception_level);
    let _ = writeln!(out, "kernel: alive");
    true
}

/// Kernel entry after firmware exit: interrupts off, barriers, early
/// allocator, then the report. Returns the report and whether boot may
/// continue; the caller chooses where to send it.
pub fn early_kernel_enter(
    conventional_memory_kb: u64,
    memory_region: Option<BootMemoryRegion>,
    boot_timing: Option<BootTiming>,
    gb10: Option<aienos_accel::Gb10Identity>,
    cpu: Option<CpuTopology>,
) -> (BootReport, bool) {
    let kernel_entry_ticks = counter_ticks();
    disable_interrupts();
    dsb();
    isb();
    // Retain the initial bitmap in kernel state and manage at most 16 MiB.
    // This reserves an address in bookkeeping only; it does not dereference RAM.
    let facts = BootFacts {
        conventional_memory_kb,
        allocator: memory_region.and_then(initialize_early_allocator),
        timing: boot_timing,
        kernel_entry_ticks,
        gb10,
        cpu,
        boot_midr: midr_el1(),
        exception_level: current_el(),
    };
    let mut report = BootReport::new();
    let ok = write_boot_report(&mut report, &facts);
    (report, ok)
}

/// Native entry carrying read-only GB10 BAR0 identity sampled before firmware exit.
/// Sends the report to the Spark UART only, then halts.
pub fn early_kernel_init_with_gpu(
    conventional_memory_kb: u64,
    memory_region: Option<BootMemoryRegion>,
    boot_timing: Option<BootTiming>,
    gb10: Option<aienos_accel::Gb10Identity>,
) -> ! {
    let (report, ok) = early_kernel_enter(
        conventional_memory_kb,
        memory_region,
        boot_timing,
        gb10,
        None,
    );
    let uart = EarlyUart::new(SPARK_16550_UART_BASE);
    uart.write_str("\n");
    uart.write_str(report.as_str());
    if ok {
        uart.write_str("halt: clean\n");
    }
    halt();
}

#[cfg(test)]
mod tests {
    use super::{allocate_early_frame, initialize_early_allocator, BootMemoryRegion, BootTiming};

    #[test]
    fn boot_counter_conversion_rejects_invalid_samples() {
        assert_eq!(BootTiming::elapsed_ms(100, 150, 1000), Some(50));
        assert_eq!(BootTiming::elapsed_ms(150, 100, 1000), None);
        assert_eq!(BootTiming::elapsed_ms(100, 150, 0), None);
    }

    #[test]
    fn firmware_region_requires_aligned_nonoverflowing_pages() {
        assert_eq!(
            BootMemoryRegion::new(0x1000_0000, 4096).unwrap().page_count,
            4096
        );
        assert!(BootMemoryRegion::new(0x1000_0001, 1).is_none());
        assert!(BootMemoryRegion::new(0x1000_0000, 0).is_none());
        assert!(BootMemoryRegion::new(u64::MAX - 4095, 2).is_none());
    }

    #[test]
    fn report_lists_gpu_allocator_timing_and_liveness() {
        use super::{write_boot_report, BootFacts, BootReport};
        use crate::mem::PhysAddr;
        let gb10 = aienos_accel::Gb10Identity {
            bar: aienos_accel::Gb10Bar {
                location: aienos_accel::PciLocation {
                    segment: 15,
                    bus: 1,
                    device: 0,
                    function: 0,
                },
                physical_base: 0x6_5000_0000,
            },
            pmc_boot_0: 0x1b00_00a1,
            pmc_boot_42: 0x1b0a_0000,
        };
        let facts = BootFacts {
            conventional_memory_kb: 4096,
            allocator: Some((128, PhysAddr(0x1000_0000))),
            timing: Some(BootTiming {
                uefi_entry_ticks: 0,
                kernel_handoff_ticks: 1_000,
                counter_frequency_hz: 1_000_000,
            }),
            kernel_entry_ticks: 3_000,
            gb10: Some(gb10),
            cpu: Some(crate::acpi::CpuTopology {
                cores: 20,
                classes: [
                    (0, 10),
                    (1, 10),
                    (0, 0),
                    (0, 0),
                    (0, 0),
                    (0, 0),
                    (0, 0),
                    (0, 0),
                ],
                distinct_classes: 2,
                unknown_class: 0,
                first_mpidr: Some(0x8100_0000),
            }),
            boot_midr: 0x410f_d870,
            exception_level: 2,
        };
        let mut report = BootReport::new();
        assert!(write_boot_report(&mut report, &facts));
        let text = report.as_str();
        for line in [
            "gb10_segment: 15",
            "gb10_bar0_phys: 0x650000000",
            "gb10_pmc_boot_0: 0x1b0000a1",
            "cpu_cores: 20",
            "cpu_efficiency_class_0: 10",
            "cpu_efficiency_class_1: 10",
            "boot_cpu_midr: 0x410fd870 (part 0xd87)",
            "allocator_reserved_frame_phys: 0x10000000",
            "uefi_entry_to_handoff_ms: 1",
            "handoff_to_kernel_entry_ms: 2",
            "exception_level: EL2",
            "kernel: alive",
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "missing {line:?} in:\n{text}"
            );
        }

        let halted = BootFacts {
            allocator: None,
            ..facts
        };
        let mut report = BootReport::new();
        assert!(!write_boot_report(&mut report, &halted));
        assert!(report
            .as_str()
            .ends_with("allocator: unavailable; boot halted\n"));
    }

    #[test]
    fn early_allocator_retains_region_after_initialization() {
        let region = BootMemoryRegion::new(0x1000_0000, 128).unwrap();
        let (managed, reserved) = initialize_early_allocator(region).unwrap();
        assert_eq!(managed, 128);
        assert_eq!(reserved.0, 0x1000_0000);
        assert_eq!(allocate_early_frame().unwrap().0, 0x1000_1000);
        assert!(initialize_early_allocator(region).is_none());
    }
}

/// Canonical bare-metal entry point when compiling for `#![no_std]` targets.
#[cfg(all(target_os = "none", not(feature = "std"), not(test)))]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    early_kernel_init(0);
}
