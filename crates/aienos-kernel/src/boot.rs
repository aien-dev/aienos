//! AIENOS Bare-Metal Boot Spine (§Step 2 of Systems Integration Sequence).
//!
//! Provides the bare-metal entry path, early serial banner, and BootReceipt.

use crate::arch::aarch64::{
    counter_ticks, current_el, disable_interrupts, dsb, halt, isb, EarlyUart, SPARK_16550_UART_BASE,
};

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
    use super::BootTiming;

    #[test]
    fn boot_counter_conversion_rejects_invalid_samples() {
        assert_eq!(BootTiming::elapsed_ms(100, 150, 1000), Some(50));
        assert_eq!(BootTiming::elapsed_ms(150, 100, 1000), None);
        assert_eq!(BootTiming::elapsed_ms(100, 150, 0), None);
    }
}

/// Canonical bare-metal entry point when compiling for `#![no_std]` targets.
#[cfg(all(target_os = "none", not(feature = "std"), not(test)))]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    early_kernel_init(0);
}
