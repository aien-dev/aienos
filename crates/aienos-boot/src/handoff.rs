#![no_std]
#![no_main]

use uefi::mem::memory_map::{MemoryMap, MemoryType};
use uefi::prelude::*;
use uefi::proto::pci::root_bridge::PciRootBridgeIo;
use uefi::proto::pci::PciIoAddress;

fn probe_gb10(
    root: &mut PciRootBridgeIo,
    address: PciIoAddress,
) -> Option<aienos_accel::Gb10Identity> {
    let config = |offset| address.with_register(offset);
    let vendor_device = root.pci().read_one::<u32>(config(0)).ok()?;
    if vendor_device != 0x2e12_10de {
        return None;
    }
    let command_status = root.pci().read_one::<u32>(config(4)).ok()?;
    let bar0_low = root.pci().read_one::<u32>(config(0x10)).ok()?;
    let bar0_high = root.pci().read_one::<u32>(config(0x14)).ok()?;
    let bar = aienos_accel::Gb10Bar::from_config(
        aienos_accel::PciLocation {
            segment: root.segment_nr(),
            bus: address.bus,
            device: address.dev,
            function: address.fun,
        },
        vendor_device,
        command_status,
        bar0_low,
        bar0_high,
    )?;
    let pmc_boot_0 = root
        .memory()
        .read_one::<u32>(bar.physical_base + aienos_accel::PMC_BOOT_0)
        .ok()?;
    let pmc_boot_42 = root
        .memory()
        .read_one::<u32>(bar.physical_base + aienos_accel::PMC_BOOT_42)
        .ok()?;
    Some(aienos_accel::Gb10Identity {
        bar,
        pmc_boot_0,
        pmc_boot_42,
    })
}

fn discover_gb10() -> Option<aienos_accel::Gb10Identity> {
    let handles = uefi::boot::find_handles::<PciRootBridgeIo>().ok()?;
    for handle in handles {
        let Ok(mut root) = uefi::boot::open_protocol_exclusive::<PciRootBridgeIo>(handle) else {
            continue;
        };
        // Config A puts GB10 at segment 15, bus 1, device 0, function 0.
        // Try that first so the common boot path does not enumerate every bus.
        if root.segment_nr() == 15 {
            if let Some(identity) = probe_gb10(&mut root, PciIoAddress::new(1, 0, 0)) {
                return Some(identity);
            }
        }
        let Ok(tree) = root.enumerate() else {
            continue;
        };
        for address in tree {
            if let Some(identity) = probe_gb10(&mut root, address) {
                return Some(identity);
            }
        }
    }
    None
}

/// Explicit native handoff image. Building it does not install or boot it.
#[entry]
fn main() -> Status {
    let uefi_entry_ticks = aienos_kernel::arch::aarch64::counter_ticks();
    let counter_frequency_hz = aienos_kernel::arch::aarch64::counter_frequency_hz();
    uefi::println!("AIENOS: exiting firmware boot services");
    let gb10 = discover_gb10();
    uefi::println!(
        "GB10 BAR0 register discovery: {}",
        if gb10.is_some() { "ok" } else { "unavailable" }
    );

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
    aienos_kernel::boot::early_kernel_init_with_gpu(
        conventional_pages.saturating_mul(4),
        largest_region,
        Some(timing),
        gb10,
    )
}
