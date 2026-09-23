//! AIENOS Bare-Metal Boot Spine (§Step 2 of Systems Integration Sequence).
//!
//! Provides the canonical reset vector / UEFI entry point `_start`,
//! the unadorned console banner, and the structured BootReceipt definition.

use crate::arch::aarch64::{
    current_el, disable_interrupts, dsb, halt, isb, EarlyUart, SPARK_PL011_UART_BASE,
};

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
pub fn early_kernel_init() -> ! {
    // 1. Disable maskable interrupts
    disable_interrupts();

    // 2. Memory and instruction synchronization barriers
    dsb();
    isb();

    // 3. Early console UART output on DGX Spark MMIO (0x16A00000)
    // Strictly unadorned console telemetry per Gate 2 specification
    let uart = EarlyUart::new(SPARK_PL011_UART_BASE);
    uart.write_str("\r\nAIENOS\r\n");
    uart.write_str("arch: aarch64\r\n");
    uart.write_str("boot: native\r\n");

    let el = current_el();
    uart.write_str("exception_level: EL");
    uart.write_byte(b'0' + el);
    uart.write_str("\r\n");

    uart.write_str("kernel: alive\r\n");
    uart.write_str("halt: clean\r\n");

    // 4. Deterministic non-model halt loop
    halt();
}

/// Canonical bare-metal entry point when compiling for `#![no_std]` targets.
#[cfg(all(not(feature = "std"), not(test)))]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    early_kernel_init();
}
