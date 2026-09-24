//! AIENOS Bare-Metal Kernel Substrate for AArch64 (DGX Spark).
//!
//! Provides minimal, sovereign, deterministic primitives:
//! - AArch64 MMIO, UART, and exception-level access
//! - Physical memory addressing and bitmap frame allocation
//! - Pure-Rust cryptographic hashing (SHA-256)
//! - Bare-metal synchronization (`SpinLock`)

#![cfg_attr(not(feature = "std"), no_std)]

pub mod acpi;
pub mod arch;
pub mod boot;
pub mod console;
pub mod crypto;
pub mod display;
pub mod fatal;
pub mod gic;
pub mod mem;
pub mod recovery;
pub mod report;
pub mod store;
pub mod sync;
pub mod timer;
pub mod usb;

#[cfg(all(target_os = "none", not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    arch::aarch64::halt();
}
