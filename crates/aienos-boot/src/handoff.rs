#![no_std]
#![no_main]

//! Native handoff image with a boot report that does not depend on a serial
//! cable being attached.
//!
//! Before firmware exit it prints a pre-exit report on the firmware console and
//! saves it to `\EFI\AIENOS\BOOTREPORT.TXT` on the boot volume. After exit the
//! kernel's report is drawn on the firmware-configured screen, stored in the
//! `AienosBootReport` firmware variable, and sent to the Spark UART (bounded).
//! The image then counts down and cold-resets, so a one-time boot entry
//! returns the machine to its normal boot order without a power cycle.
//! Linux reads both reports after reboot:
//!   /boot/efi/EFI/AIENOS/BOOTREPORT.TXT
//!   /sys/firmware/efi/efivars/AienosBootReport-a1e05b0e-7c3d-4f51-9b6a-2d8e4c1f0a37

use aienos_kernel::acpi;
use aienos_kernel::arch::aarch64::{
    counter_frequency_hz, counter_ticks, EarlyUart, SPARK_16550_UART_BASE,
};
use aienos_kernel::display::{FramebufferInfo, PixelOrder, Screen, ACCENT, FOREGROUND};
use aienos_kernel::report::ReportBuf;
use core::fmt::Write;
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::mem::memory_map::{MemoryMap, MemoryType};
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::pci::root_bridge::PciRootBridgeIo;
use uefi::proto::pci::PciIoAddress;
use uefi::runtime::{ResetType, VariableAttributes, VariableVendor};
use uefi::table::cfg::ConfigTableEntry;
use uefi::{cstr16, guid};

const REPORT_VENDOR: VariableVendor = VariableVendor(guid!("a1e05b0e-7c3d-4f51-9b6a-2d8e4c1f0a37"));
const RESTART_AFTER_SECS: u64 = 30;

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

/// Reads a firmware ACPI table whose header is at `addr`.
///
/// # Safety
/// `addr` must be zero or point to a mapped ACPI table left by firmware.
unsafe fn table_at<'a>(addr: usize) -> Option<&'a [u8]> {
    if addr == 0 {
        return None;
    }
    let header = unsafe { core::slice::from_raw_parts(addr as *const u8, acpi::SDT_HEADER_LEN) };
    let len = acpi::sdt_length(header)?;
    if !(acpi::SDT_HEADER_LEN..=1 << 20).contains(&len) {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(addr as *const u8, len) })
}

/// Core inventory from the firmware MADT (RSDP, then XSDT, then "APIC").
fn discover_cpu_topology() -> Option<acpi::CpuTopology> {
    let rsdp = uefi::system::with_config_table(|entries| {
        entries
            .iter()
            .find(|e| e.guid == ConfigTableEntry::ACPI2_GUID)
            .map(|e| e.address as usize)
    })?;
    // SAFETY: firmware published this ACPI 2.0 RSDP, which is 36 bytes long.
    let rsdp = unsafe { core::slice::from_raw_parts(rsdp as *const u8, 36) };
    if &rsdp[..8] != b"RSD PTR " {
        return None;
    }
    let xsdt_addr = u64::from_le_bytes(rsdp[24..32].try_into().ok()?) as usize;
    // SAFETY: the RSDP points at the XSDT; its checksum is validated below.
    let xsdt = acpi::checked_table(unsafe { table_at(xsdt_addr) }?, b"XSDT").ok()?;
    for addr in acpi::xsdt_entries(xsdt) {
        // SAFETY: XSDT entries point at firmware ACPI tables.
        let Some(table) = (unsafe { table_at(addr as usize) }) else {
            continue;
        };
        if &table[..4] == b"APIC" {
            return acpi::madt_cpu_topology(table).ok();
        }
    }
    None
}

/// Geometry of the display mode the firmware already configured.
fn discover_framebuffer() -> Option<FramebufferInfo> {
    let handle = uefi::boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    // Shared open: an exclusive open would disconnect the firmware console.
    let mut gop = unsafe {
        uefi::boot::open_protocol::<GraphicsOutput>(
            OpenProtocolParams {
                handle,
                agent: uefi::boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    let mode = gop.current_mode_info();
    let order = match mode.pixel_format() {
        PixelFormat::Rgb => PixelOrder::Rgb,
        PixelFormat::Bgr => PixelOrder::Bgr,
        _ => return None,
    };
    let (width, height) = mode.resolution();
    let mut fb = gop.frame_buffer();
    FramebufferInfo {
        base: fb.as_mut_ptr() as u64,
        size_bytes: fb.size() as u64,
        width,
        height,
        stride: mode.stride(),
        order,
    }
    .validated()
}

/// Replace `\EFI\AIENOS\BOOTREPORT.TXT` on the volume this image was loaded from.
fn save_report_file(text: &str) -> uefi::Result {
    let mut fs = uefi::boot::get_image_file_system(uefi::boot::image_handle())?;
    let mut root = fs.open_volume()?;
    root.open(
        cstr16!("\\EFI\\AIENOS"),
        FileMode::CreateReadWrite,
        FileAttribute::DIRECTORY,
    )?;
    let path = cstr16!("\\EFI\\AIENOS\\BOOTREPORT.TXT");
    if let Ok(old) = root.open(path, FileMode::ReadWrite, FileAttribute::empty()) {
        old.delete()?;
    }
    let mut file = root
        .open(path, FileMode::CreateReadWrite, FileAttribute::empty())?
        .into_regular_file()
        .ok_or_else(|| uefi::Error::from(Status::UNSUPPORTED))?;
    file.write(text.as_bytes())
        .map_err(|e| uefi::Error::from(e.status()))?;
    file.flush()
}

fn wait_seconds(seconds: u64, frequency_hz: u64) {
    let start = counter_ticks();
    let ticks = seconds.saturating_mul(frequency_hz);
    while counter_ticks().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// Explicit native handoff image. Building it does not install or boot it.
#[entry]
fn main() -> Status {
    let uefi_entry_ticks = counter_ticks();
    let frequency_hz = counter_frequency_hz();
    let gb10 = discover_gb10();
    let framebuffer = discover_framebuffer();
    let cpu = discover_cpu_topology();
    let boot_midr = aienos_kernel::arch::aarch64::midr_el1();

    let mut pre = ReportBuf::<1024>::new();
    let _ = writeln!(pre, "AIENOS pre-exit report");
    let _ = writeln!(pre, "firmware_vendor: {}", uefi::system::firmware_vendor());
    let _ = writeln!(
        pre,
        "firmware_revision: {:#x}",
        uefi::system::firmware_revision()
    );
    let _ = writeln!(pre, "counter_frequency_hz: {frequency_hz}");
    match gb10 {
        Some(g) => {
            let _ = writeln!(pre, "gb10_bar0_phys: {:#x}", g.bar.physical_base);
            let _ = writeln!(pre, "gb10_pmc_boot_0: {:#010x}", g.pmc_boot_0);
            let _ = writeln!(pre, "gb10_pmc_boot_42: {:#010x}", g.pmc_boot_42);
        }
        None => {
            let _ = writeln!(pre, "gb10: unavailable");
        }
    }
    match cpu {
        Some(t) => {
            let _ = writeln!(pre, "cpu_cores: {}", t.cores);
            for (class, count) in t.classes() {
                let _ = writeln!(pre, "cpu_efficiency_class_{class}: {count}");
            }
            if t.unknown_class > 0 {
                let _ = writeln!(pre, "cpu_efficiency_class_unknown: {}", t.unknown_class);
            }
        }
        None => {
            let _ = writeln!(pre, "cpu_topology: unavailable");
        }
    }
    let _ = writeln!(
        pre,
        "boot_cpu_midr: {:#x} (part {:#05x})",
        boot_midr,
        aienos_kernel::arch::aarch64::midr_part(boot_midr)
    );
    match framebuffer {
        Some(f) => {
            let _ = writeln!(
                pre,
                "framebuffer: {}x{} stride {} {:?} base {:#x} size {}",
                f.width, f.height, f.stride, f.order, f.base, f.size_bytes
            );
        }
        None => {
            let _ = writeln!(pre, "framebuffer: unavailable");
        }
    }
    let _ = writeln!(pre, "exiting firmware boot services");
    uefi::println!("{}", pre.as_str());
    match save_report_file(pre.as_str()) {
        Ok(()) => uefi::println!("report file: \\EFI\\AIENOS\\BOOTREPORT.TXT saved"),
        Err(e) => uefi::println!("report file: not saved ({:?})", e.status()),
    }

    // No UEFI protocol, allocator, console, or boot-service reference is used
    // after this point; only runtime services (variables, reset) remain. The
    // returned map owns its backing allocation and stays live below.
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
        kernel_handoff_ticks: counter_ticks(),
        counter_frequency_hz: frequency_hz,
    };
    let (report, boot_ok) = aienos_kernel::boot::early_kernel_enter(
        conventional_pages.saturating_mul(4),
        largest_region,
        Some(timing),
        gb10,
        cpu,
    );

    // 1. Screen: the display mode firmware set up, written directly.
    // SAFETY: firmware reported this buffer for the active mode, and nothing
    // else draws to it after boot services have exited.
    let mut screen = framebuffer.and_then(|info| unsafe { Screen::new(info) });
    if let Some(s) = screen.as_mut() {
        s.clear();
        s.set_color(ACCENT);
        let _ = writeln!(s, "AIENOS NATIVE BOOT REPORT");
        s.set_color(FOREGROUND);
        let _ = write!(s, "{}", report.as_str());
    }

    // 2. Firmware variable, readable from Linux after the reset below.
    let nvram = uefi::runtime::set_variable(
        cstr16!("AienosBootReport"),
        &REPORT_VENDOR,
        VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS,
        report.as_bytes(),
    );
    if let Some(s) = screen.as_mut() {
        match &nvram {
            Ok(()) => {
                let _ = writeln!(s, "nvram_report: saved");
            }
            Err(e) => {
                let _ = writeln!(s, "nvram_report: failed ({:?})", e.status());
            }
        }
    }

    // 3. Serial, only where the Spark's UART is known to exist, and bounded.
    if gb10.is_some() {
        let uart = EarlyUart::new(SPARK_16550_UART_BASE);
        uart.write_str("\n");
        uart.write_str(report.as_str());
        if let Some(s) = screen.as_mut() {
            let _ = writeln!(
                s,
                "uart_report: {}",
                if uart.is_dead() {
                    "no response"
                } else {
                    "sent"
                }
            );
        }
    }

    if let Some(s) = screen.as_mut() {
        if !boot_ok {
            let _ = writeln!(s, "boot halted: no usable memory region");
        }
        let _ = writeln!(s);
        s.set_color(ACCENT);
        for remaining in (1..=RESTART_AFTER_SECS).rev() {
            s.clear_row();
            let _ = write!(s, "restarting in {remaining} s");
            wait_seconds(1, frequency_hz);
        }
    } else {
        wait_seconds(RESTART_AFTER_SECS, frequency_hz);
    }
    uefi::runtime::reset(ResetType::COLD, Status::SUCCESS, None)
}
