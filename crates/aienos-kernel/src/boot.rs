//! AIENOS Bare-Metal Boot Spine (§Step 2 of Systems Integration Sequence).
//!
//! Provides the bare-metal entry path, early serial banner, and BootReceipt.

use crate::acpi::CpuTopology;
use crate::arch::aarch64::{
    counter_ticks, current_el, disable_interrupts, dsb, halt, isb, midr_el1, midr_part, EarlyUart,
    SPARK_16550_UART_BASE,
};
use crate::console::EarlyConsole;
use crate::display::{FramebufferInfo, Screen, ACCENT, ERROR, FOREGROUND};
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

    /// Physical start address of the region.
    pub const fn start(self) -> u64 {
        self.start.0 as u64
    }
}

/// What the firmware memory map contained and what the kernel accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryMapSummary {
    pub descriptors: u64,
    pub conventional_regions: u64,
    pub conventional_pages: u64,
    /// Conventional regions that failed `BootMemoryRegion::new` validation.
    pub rejected_regions: u64,
    pub largest: Option<BootMemoryRegion>,
}

impl MemoryMapSummary {
    /// Account for one firmware memory descriptor.
    pub fn add(&mut self, conventional: bool, physical_start: u64, page_count: u64) {
        self.descriptors += 1;
        if !conventional {
            return;
        }
        self.conventional_regions += 1;
        self.conventional_pages = self.conventional_pages.saturating_add(page_count);
        match BootMemoryRegion::new(physical_start, page_count) {
            Some(region) => {
                if self
                    .largest
                    .is_none_or(|l| region.page_count() > l.page_count())
                {
                    self.largest = Some(region);
                }
            }
            None => self.rejected_regions += 1,
        }
    }

    pub fn conventional_kb(&self) -> u64 {
        self.conventional_pages.saturating_mul(4)
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
    /// Firmware memory map validation, when the caller walked the map.
    pub memory_map: Option<MemoryMapSummary>,
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
    pub pre_transition_exception_level: Option<u8>,
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
    if let Some(m) = facts.memory_map {
        let _ = writeln!(out, "memory_map_descriptors: {}", m.descriptors);
        let _ = writeln!(
            out,
            "memory_map_conventional_regions: {}",
            m.conventional_regions
        );
        let _ = writeln!(out, "memory_map_rejected_regions: {}", m.rejected_regions);
        match m.largest {
            Some(r) => {
                let _ = writeln!(
                    out,
                    "memory_map_largest_region: {:#x} pages {}",
                    r.start(),
                    r.page_count()
                );
            }
            None => {
                let _ = writeln!(out, "memory_map_largest_region: none");
            }
        }
    }
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
            let _ = writeln!(
                out,
                "cpu_boot_core_listed: {}",
                if t.boot_core_listed { "yes" } else { "no" }
            );
            match t.boot_class {
                Some(class) => {
                    let _ = writeln!(out, "cpu_boot_core_class: {class}");
                }
                None => {
                    let _ = writeln!(out, "cpu_boot_core_class: unknown");
                }
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
    if let Some(pre_el) = facts.pre_transition_exception_level {
        let _ = writeln!(out, "pre_transition_exception_level: EL{pre_el}");
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
    memory_map: Option<MemoryMapSummary>,
    boot_timing: Option<BootTiming>,
    gb10: Option<aienos_accel::Gb10Identity>,
    cpu: Option<CpuTopology>,
    pre_transition_el: Option<u8>,
) -> (BootReport, bool) {
    let kernel_entry_ticks = counter_ticks();
    disable_interrupts();
    dsb();
    isb();
    // Retain the initial bitmap in kernel state and manage at most 16 MiB.
    // This reserves an address in bookkeeping only; it does not dereference RAM.
    let facts = BootFacts {
        conventional_memory_kb,
        memory_map,
        allocator: memory_region.and_then(initialize_early_allocator),
        timing: boot_timing,
        kernel_entry_ticks,
        gb10,
        cpu,
        boot_midr: midr_el1(),
        exception_level: current_el(),
        pre_transition_exception_level: pre_transition_el,
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
        None,
        boot_timing,
        gb10,
        None,
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


/// One-way immutable context passed from EL2 bootstrap to EL1h kernel entry.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelHandoffContext {
    pub conventional_memory_kb: u64,
    pub memory_region: Option<BootMemoryRegion>,
    pub memory_map: Option<MemoryMapSummary>,
    pub timing: Option<BootTiming>,
    pub gb10: Option<aienos_accel::Gb10Identity>,
    pub cpu: Option<CpuTopology>,
    pub spcr_uart: Option<crate::acpi::UartKind>,
    pub framebuffer: Option<FramebufferInfo>,
    pub pre_transition_el: u8,
    pub progress_saved: bool,
    pub pre_file_saved: bool,
    pub restart_secs: u64,
    pub commit: &'static str,
}

/// Core kernel entry at EL1h following the EL2 to EL1h eret transition.
/// Never returns.
///
/// # Safety
///
/// `context_ptr` must point to an initialized, valid `KernelHandoffContext`
/// located in persistent memory that remains valid for kernel execution.
#[no_mangle]
pub unsafe extern "C" fn early_kernel_el1_enter(context_ptr: *const KernelHandoffContext) -> ! {
    if context_ptr.is_null() {
        crate::arch::aarch64::halt();
    }
    let context = unsafe { &*context_ptr };

    // 1. Enter kernel core and initialize frame allocator
    let (kernel_report, boot_ok) = early_kernel_enter(
        context.conventional_memory_kb,
        context.memory_region,
        context.memory_map,
        context.timing,
        context.gb10,
        context.cpu,
        Some(context.pre_transition_el),
    );

    // 2. Assemble the final boot report
    let mut report = crate::report::ReportBuf::<3072>::new();
    let _ = writeln!(report, "report_version: 1");
    let _ = writeln!(report, "aienos_commit: {}", context.commit);
    let _ = writeln!(report, "report_kind: final");
    let _ = writeln!(report, "last_stage: kernel_entered");
    let _ = write!(report, "{}", kernel_report.as_str());
    if context.progress_saved {
        let _ = writeln!(report, "progress_record: saved");
    } else {
        let _ = writeln!(report, "progress_record: not saved");
    }
    if context.pre_file_saved {
        let _ = writeln!(report, "pre_exit_file: saved");
    } else {
        let _ = writeln!(report, "pre_exit_file: not saved");
    }

    // 3. Render report to screen if framebuffer is available
    let mut screen = context.framebuffer.and_then(|fb| unsafe { Screen::new(fb) });
    if let Some(s) = screen.as_mut() {
        s.clear();
        s.set_color(ACCENT);
        let _ = writeln!(s, "AIENOS NATIVE BOOT REPORT");
        s.set_color(FOREGROUND);
        let _ = write!(s, "{}", report.as_str());
    }

    // 4. Send report to serial console
    let uart_status = match context.spcr_uart.and_then(EarlyConsole::from_kind) {
        Some(console) => {
            console.write_str("\n");
            console.write_str(report.as_str());
            if console.is_dead() {
                "no response"
            } else {
                "sent"
            }
        }
        None => "no drivable console",
    };

    // 5. Append screen and console outcomes
    let mut outcomes = crate::report::ReportBuf::<256>::new();
    match context.framebuffer.filter(|_| screen.is_some()) {
        Some(f) => {
            let _ = writeln!(outcomes, "screen_report: drawn {}x{}", f.width, f.height);
        }
        None => {
            let _ = writeln!(outcomes, "screen_report: unavailable");
        }
    }
    let _ = writeln!(outcomes, "uart_report: {uart_status}");
    let _ = write!(report, "{}", outcomes.as_str());
    if let Some(s) = screen.as_mut() {
        let _ = write!(s, "{}", outcomes.as_str());
    }
    if let Some(console) = context.spcr_uart.and_then(EarlyConsole::from_kind) {
        console.write_str(outcomes.as_str());
    }

    if !boot_ok {
        if let Some(s) = screen.as_mut() {
            s.set_color(ERROR);
            let _ = writeln!(s, "boot halted: no usable memory region");
        }
    }

    // 6. Countdown and reset
    let hz = context.timing.map(|t| t.counter_frequency_hz).unwrap_or(0);
    if let Some(s) = screen.as_mut() {
        let _ = writeln!(s);
        s.set_color(ACCENT);
        for remaining in (1..=context.restart_secs).rev() {
            s.clear_row();
            let _ = write!(s, "restarting in {remaining} s");
            crate::arch::aarch64::wait_seconds(1, hz);
        }
    } else {
        crate::arch::aarch64::wait_seconds(context.restart_secs, hz);
    }

    crate::arch::aarch64::psci_system_reset();
    crate::arch::aarch64::halt();
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
        let mut memory_map = super::MemoryMapSummary::default();
        memory_map.add(false, 0x0, 16);
        memory_map.add(true, 0x1000_0000, 128);
        memory_map.add(true, 0x2000_0001, 64);
        let facts = BootFacts {
            conventional_memory_kb: 4096,
            memory_map: Some(memory_map),
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
                boot_core_listed: true,
                boot_class: Some(0),
            }),
            boot_midr: 0x410f_d870,
            exception_level: 1,
            pre_transition_exception_level: Some(2),
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
            "cpu_boot_core_listed: yes",
            "cpu_boot_core_class: 0",
            "boot_cpu_midr: 0x410fd870 (part 0xd87)",
            "memory_map_descriptors: 3",
            "memory_map_conventional_regions: 2",
            "memory_map_rejected_regions: 1",
            "memory_map_largest_region: 0x10000000 pages 128",
            "allocator_reserved_frame_phys: 0x10000000",
            "uefi_entry_to_handoff_ms: 1",
            "handoff_to_kernel_entry_ms: 2",
            "pre_transition_exception_level: EL2",
            "exception_level: EL1",
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
