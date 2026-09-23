//! AIENOS Bare-Metal Boot Spine (§Step 2 of Systems Integration Sequence).
//!
//! Provides the bare-metal entry path, early serial banner, and BootReceipt.

use crate::arch::aarch64::{
    counter_ticks, current_el, disable_interrupts, dsb, halt, isb, EarlyUart, SPARK_16550_UART_BASE,
};
use crate::mem::{BitmapFrameAllocator, PhysAddr, PAGE_SIZE};
use crate::sync::spinlock::SpinLock;

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
    let kernel_entry_ticks = counter_ticks();
    // 1. Disable maskable interrupts
    disable_interrupts();

    // 2. Memory and instruction synchronization barriers
    dsb();
    isb();

    // 3. Early console UART output on DGX Spark MMIO (0x16A00000)
    // Strictly unadorned console telemetry per Gate 2 specification
    let uart = EarlyUart::new(SPARK_16550_UART_BASE);
    uart.write_str("\nAIENOS\n");
    uart.write_str("arch: aarch64\n");
    uart.write_str("boot: native\n");
    uart.write_str("conventional_memory_kb: ");
    uart.write_u64(conventional_memory_kb);
    uart.write_str("\n");

    // Retain the initial bitmap in kernel state and manage at most 16 MiB.
    // This reserves an address in bookkeeping only; it does not dereference RAM.
    match memory_region.and_then(initialize_early_allocator) {
        Some((managed_frames, first_frame)) => {
            uart.write_str("allocator_managed_frames: ");
            uart.write_u64(managed_frames as u64);
            uart.write_str("\nallocator_reserved_frame_phys: ");
            uart.write_u64(first_frame.0 as u64);
            uart.write_str("\n");
        }
        None => {
            uart.write_str("allocator: unavailable; boot halted\n");
            halt();
        }
    }

    if let Some(timing) = boot_timing {
        if let Some(milliseconds) = BootTiming::elapsed_ms(
            timing.uefi_entry_ticks,
            timing.kernel_handoff_ticks,
            timing.counter_frequency_hz,
        ) {
            uart.write_str("uefi_entry_to_handoff_ms: ");
            uart.write_u64(milliseconds);
            uart.write_str("\n");
        }
        if let Some(milliseconds) = BootTiming::elapsed_ms(
            timing.kernel_handoff_ticks,
            kernel_entry_ticks,
            timing.counter_frequency_hz,
        ) {
            uart.write_str("handoff_to_kernel_entry_ms: ");
            uart.write_u64(milliseconds);
            uart.write_str("\n");
        }
    }

    let el = current_el();
    uart.write_str("exception_level: EL");
    uart.write_byte(b'0' + el);
    uart.write_str("\n");

    uart.write_str("kernel: alive\n");
    uart.write_str("halt: clean\n");

    // 4. Deterministic non-model halt loop
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
