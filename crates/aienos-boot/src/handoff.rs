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
    let mut conventional_pages = 0u64;
    let mut largest_region = None;
    for descriptor in memory_map.entries() {
        if descriptor.ty != MemoryType::CONVENTIONAL {
            continue;
        }
        conventional_pages = conventional_pages.saturating_add(descriptor.page_count);
        if let Some(region) =
            aienos_kernel::boot::BootMemoryRegion::new(descriptor.phys_start, descriptor.page_count)
        {
            if largest_region.is_none_or(|largest: aienos_kernel::boot::BootMemoryRegion| {
                region.page_count() > largest.page_count()
            }) {
                largest_region = Some(region);
            }
        }
    }

    let timing = aienos_kernel::boot::BootTiming {
        uefi_entry_ticks,
        kernel_handoff_ticks: aienos_kernel::arch::aarch64::counter_ticks(),
        counter_frequency_hz,
    };
    aienos_kernel::boot::early_kernel_init_with_memory(
        conventional_pages.saturating_mul(4),
        largest_region,
        Some(timing),
    )
}
