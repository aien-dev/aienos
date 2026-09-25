//! AIENOS Bare-Metal Kernel Substrate for AArch64 (DGX Spark).
//!
//! Provides minimal, sovereign, deterministic primitives:
//! - AArch64 MMIO, UART, and exception-level access
//! - Physical memory addressing and bitmap frame allocation
//! - Pure-Rust cryptographic hashing (SHA-256)
//! - Bare-metal synchronization (`SpinLock`)

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod abi;
pub mod acpi;
pub mod admission;
pub mod arch;
pub mod artifact_loader;
pub mod block;
pub mod boot;
pub mod budget;
pub mod caps;
pub mod console;
pub mod crypto;
pub mod device;
pub mod display;
pub mod dma_gate;
pub mod edu;
pub mod fatal;
pub mod gic;
pub mod infer;
pub mod ipc;
pub mod mem;
pub mod net;
pub mod nvme;
pub mod pci;
pub mod pe;
pub mod recovery;
pub mod report;
pub mod scheduler;
pub mod shell;
pub mod smmu;
pub mod store;
pub mod sync;
pub mod task_runtime;
pub mod thread;
pub mod timer;
pub mod uefi;
pub mod usb;
pub mod user;
pub mod virtio_net;

#[cfg(all(target_os = "none", not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    arch::aarch64::halt();
}
