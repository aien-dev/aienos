#![no_std]
#![no_main]

use uefi::mem::memory_map::{MemoryMap, MemoryType};
use uefi::prelude::*;

/// Explicit native handoff image. Building it does not install or boot it.
#[entry]
fn main() -> Status {
    let uefi_entry_ticks = aienos_kernel::arch::aarch64::counter_ticks();
    let counter_frequency_hz = aienos_kernel::arch::aarch64::counter_frequency_hz();
    uefi::println!("AIENOS: exiting firmware boot services");

    // No UEFI protocol, allocator, console, or boot-service reference is used
    // after this point. The returned map owns its backing allocation and stays
    // live while the early kernel path executes.
    let memory_map = unsafe { uefi::boot::exit_boot_services(None) };
    let conventional_pages = memory_map
        .entries()
        .filter(|descriptor| descriptor.ty == MemoryType::CONVENTIONAL)
        .fold(0u64, |total, descriptor| {
            total.saturating_add(descriptor.page_count)
        });

    let timing = aienos_kernel::boot::BootTiming {
        uefi_entry_ticks,
        kernel_handoff_ticks: aienos_kernel::arch::aarch64::counter_ticks(),
        counter_frequency_hz,
    };
    aienos_kernel::boot::early_kernel_init_with_timing(
        conventional_pages.saturating_mul(4),
        Some(timing),
    )
}
