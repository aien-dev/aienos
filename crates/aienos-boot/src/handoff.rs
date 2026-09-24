#![no_std]
#![no_main]

//! First-boot evidence image for Machine 1.
//!
//! Before firmware exit it discovers the GB10, the CPU topology (ACPI MADT),
//! and the firmware display mode, prints a pre-exit report on the firmware
//! console, and saves it to `\EFI\AIENOS\BOOTREPORT.TXT`.
//!
//! After `ExitBootServices` it installs AIENOS exception vectors, writes an
//! early progress record, enters the kernel, and reports the result on the
//! screen, in the `AienosBootReportV1` firmware variable and on the Spark UART
//! (bounded). A panic or CPU fault takes the same reporting path with the last
//! boot stage and fault registers. It then counts down and cold-resets, so a
//! one-time boot entry returns to the normal boot order.
//!
//! The post-handoff firmware variable write is a temporary bootstrap exception
//! (ADR 0008): versioned name, at most `MAX_VAR_WRITES` writes of at most
//! `MAX_VAR_BYTES` each, diagnostics only, and a failed write never stops boot.
//! Linux reads the evidence after reboot:
//!   /boot/efi/EFI/AIENOS/BOOTREPORT.TXT
//!   /sys/firmware/efi/efivars/AienosBootReportV1-a1e05b0e-7c3d-4f51-9b6a-2d8e4c1f0a37

use aienos_kernel::acpi;
use aienos_kernel::arch::aarch64::{
    counter_frequency_hz, counter_ticks, midr_el1, midr_part, mpidr_el1, psci_system_reset,
};
use aienos_kernel::boot::{BootTiming, MemoryMapSummary};
use aienos_kernel::console::EarlyConsole;
use aienos_kernel::display::{FramebufferInfo, PixelOrder, Screen, ACCENT, FOREGROUND};
use aienos_kernel::fatal::{self, FaultInfo};
use aienos_kernel::report::ReportBuf;
use aienos_kernel::sync::spinlock::SpinLock;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::mem::memory_map::{MemoryMap, MemoryType};
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::pci::configuration::ResourceRangeType;
use uefi::proto::pci::root_bridge::PciRootBridgeIo;
use uefi::proto::pci::PciIoAddress;
use uefi::runtime::{ResetType, VariableAttributes, VariableVendor};
use uefi::table::cfg::ConfigTableEntry;
use uefi::{cstr16, guid, CStr16};

/// Commit this image was built from; `scripts/stage_one_time_boot.sh` sets it.
const COMMIT: &str = match option_env!("AIENOS_COMMIT") {
    Some(commit) => commit,
    None => "unknown",
};
const REPORT_VERSION: u32 = 1;
const REPORT_VAR: &CStr16 = cstr16!("AienosBootReportV1");
const REPORT_VENDOR: VariableVendor = VariableVendor(guid!("a1e05b0e-7c3d-4f51-9b6a-2d8e4c1f0a37"));
/// ADR 0008 bounds on the post-handoff firmware variable.
const MAX_VAR_WRITES: u8 = 3;
const MAX_VAR_BYTES: usize = 3072;
/// Countdown before reset; `AIENOS_RESTART_SECS` at build time shortens it for emulator tests.
fn restart_after_secs() -> u64 {
    option_env!("AIENOS_RESTART_SECS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}
const ERROR: (u8, u8, u8) = (0xff, 0x6b, 0x6b);

type Report = ReportBuf<MAX_VAR_BYTES>;

const STAGES: [&str; 12] = [
    "firmware_entry",
    "gb10_discovery",
    "acpi_topology",
    "framebuffer_discovery",
    "pre_exit_report_saved",
    "exit_boot_services",
    "exception_vectors_installed",
    "kernel_entered",
    "screen_report_drawn",
    "final_report_saved",
    "uart_report_sent",
    "countdown",
];
const FIRMWARE_ENTRY: u8 = 0;
const GB10_DISCOVERY: u8 = 1;
const ACPI_TOPOLOGY: u8 = 2;
const FRAMEBUFFER_DISCOVERY: u8 = 3;
const PRE_EXIT_SAVED: u8 = 4;
const EXIT_BOOT_SERVICES: u8 = 5;
const VECTORS_INSTALLED: u8 = 6;
const KERNEL_ENTERED: u8 = 7;
const SCREEN_DRAWN: u8 = 8;
const FINAL_SAVED: u8 = 9;
const UART_SENT: u8 = 10;
const COUNTDOWN: u8 = 11;

static STAGE: AtomicU8 = AtomicU8::new(FIRMWARE_ENTRY);
static EXITED: AtomicBool = AtomicBool::new(false);
static IN_FATAL: AtomicBool = AtomicBool::new(false);
static VAR_WRITES: AtomicU8 = AtomicU8::new(0);
/// Serial console from the firmware SPCR table (independent of GB10 discovery).
static CONSOLE: SpinLock<Option<acpi::UartKind>> = SpinLock::new(None);
static FREQUENCY_HZ: AtomicU64 = AtomicU64::new(0);
static FRAMEBUFFER: SpinLock<Option<FramebufferInfo>> = SpinLock::new(None);

fn stage(s: u8) {
    STAGE.store(s, Ordering::SeqCst);
}

fn stage_name() -> &'static str {
    STAGES
        .get(STAGE.load(Ordering::SeqCst) as usize)
        .copied()
        .unwrap_or("unknown")
}

fn header(out: &mut impl Write, kind: &str) {
    let _ = writeln!(out, "report_version: {REPORT_VERSION}");
    let _ = writeln!(out, "aienos_commit: {COMMIT}");
    let _ = writeln!(out, "report_kind: {kind}");
    let _ = writeln!(out, "last_stage: {}", stage_name());
}

/// Bounded report write (ADR 0008). Failure is reported, never fatal.
fn save_report_var(bytes: &[u8]) -> Result<u8, &'static str> {
    if bytes.len() > MAX_VAR_BYTES {
        return Err("report larger than the bound");
    }
    let n = VAR_WRITES.fetch_add(1, Ordering::SeqCst);
    if n >= MAX_VAR_WRITES {
        return Err("write budget for this boot spent");
    }
    uefi::runtime::set_variable(
        REPORT_VAR,
        &REPORT_VENDOR,
        VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS,
        bytes,
    )
    .map(|()| n + 1)
    .map_err(|_| "firmware refused the write")
}

type BridgeScan = aienos_accel::RootBridgeScan;
type RootOutcome = aienos_accel::RootBridgeOutcome;

/// Outcome of pre-exit GB10 discovery: the identity when found, plus a
/// bounded record of why it was not (bridges seen, opens refused, segments,
/// BAR state) so the pre-exit and final reports can say what happened.
struct Gb10Discovery {
    identity: Option<aienos_accel::Gb10Identity>,
    /// Number of handles carrying the `PciRootBridgeIo` protocol, when the
    /// handle database answered.
    handles: Option<u16>,
    roots: [Option<RootOutcome>; MAX_ROOT_BRIDGES],
}

/// At most this many root bridges are recorded; extras are still searched.
const MAX_ROOT_BRIDGES: usize = 4;

/// Compact status names for the report (no `Debug` tables in the image).
fn status_name(status: Status) -> &'static str {
    match status {
        Status::ACCESS_DENIED => "ACCESS_DENIED",
        Status::NOT_FOUND => "NOT_FOUND",
        Status::INVALID_PARAMETER => "INVALID_PARAMETER",
        Status::OUT_OF_RESOURCES => "OUT_OF_RESOURCES",
        Status::UNSUPPORTED => "UNSUPPORTED",
        _ => "OTHER",
    }
}

impl Gb10Discovery {
    /// Record the outcome of one root bridge, bounded by `MAX_ROOT_BRIDGES`.
    fn record(&mut self, outcome: RootOutcome) {
        if let Some(slot) = self.roots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(outcome);
        }
    }

    /// Report lines explaining why no GB10 identity was produced.
    fn write_diagnostics(&self, out: &mut Report) {
        aienos_accel::write_discovery_diagnostics(out, self.handles, &self.roots);
    }
}

/// Read the config registers needed for the BAR check. `None` when the
/// vendor/device pair does not match the GB10 or a config read failed.
fn read_candidate(
    root: &mut PciRootBridgeIo,
    address: PciIoAddress,
) -> Option<(u32, u32, u32, u32)> {
    let config = |offset| address.with_register(offset);
    let vendor_device = root.pci().read_one::<u32>(config(0)).ok()?;
    if vendor_device != 0x2e12_10de {
        return None;
    }
    let command_status = root.pci().read_one::<u32>(config(4)).ok()?;
    let bar0_low = root.pci().read_one::<u32>(config(0x10)).ok()?;
    let bar0_high = root.pci().read_one::<u32>(config(0x14)).ok()?;
    Some((vendor_device, command_status, bar0_low, bar0_high))
}

fn probe_gb10(
    root: &mut PciRootBridgeIo,
    address: PciIoAddress,
    scan: &mut BridgeScan,
) -> Option<aienos_accel::Gb10Identity> {
    let (vendor_device, command_status, bar0_low, bar0_high) = read_candidate(root, address)?;
    let bar = match aienos_accel::Gb10Bar::from_config(
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
    ) {
        Some(bar) => bar,
        None => {
            // The GB10 was found but its BAR or command register was not
            // usable; keep the raw values so the report shows the BAR state.
            scan.rejected_candidate = Some((command_status, bar0_low, bar0_high));
            return None;
        }
    };
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

/// Walk every function on one bus of this root bridge.
/// Returns the GB10 identity when the GB10 is found here.
fn scan_bus(root: &mut PciRootBridgeIo, bus: u8, scan: &mut BridgeScan) -> Option<aienos_accel::Gb10Identity> {
    for dev in 0..32u8 {
        for fun in 0..8u8 {
            let address = PciIoAddress::new(bus, dev, fun);
            let config = |offset| address.with_register(offset);
            let Ok(vendor_device) = root.pci().read_one::<u32>(config(0)) else {
                continue;
            };
            if vendor_device & 0xffff == 0xffff {
                if fun == 0 {
                    break; // no function 0: no further functions on this device
                }
                continue;
            }
            scan.devices += 1;
            if vendor_device == 0x2e12_10de {
                if let Some(identity) = probe_gb10(root, address, scan) {
                    return Some(identity);
                }
            }
            let header_type = root
                .pci()
                .read_one::<u32>(config(0x0c))
                .map(|v| ((v >> 16) & 0xff) as u8)
                .unwrap_or(0);
            if header_type & 0x7f == 0x01 {
                scan.bridges += 1;
                let window = root
                    .pci()
                    .read_one::<u32>(config(0x18))
                    .map(|v| (((v >> 8) & 0xff) as u8, ((v >> 16) & 0xff) as u8))
                    .unwrap_or((0, 0));
                if window.0 != 0 && window.1 >= window.0 {
                    scan.windows += 1;
                }
            }
            if fun == 0 && header_type & 0x80 == 0 {
                break; // single-function device: skip functions 1..8
            }
        }
    }
    None
}

/// Read the bus-range resource descriptors of this root bridge, or `None`.
fn bus_ranges(root: &mut PciRootBridgeIo) -> Option<(u8, u8)> {
    let mut range: Option<(u8, u8)> = None;
    for descriptor in root.configuration().ok()? {
        if descriptor.resource_range_type == ResourceRangeType::Bus {
            let min = u8::try_from(descriptor.address_min).unwrap_or(u8::MAX);
            let max = u8::try_from(descriptor.address_max).unwrap_or(u8::MAX);
            range = Some(match range {
                Some((lo, hi)) => (lo.min(min), hi.max(max)),
                None => (min, max),
            });
        }
    }
    range
}

/// Scan one root bridge. Returns the GB10 identity and the outcome to record.
fn scan_root(root: &mut PciRootBridgeIo) -> (Option<aienos_accel::Gb10Identity>, RootOutcome) {
    let mut scan = BridgeScan {
        segment: root.segment_nr(),
        devices: 0,
        bridges: 0,
        windows: 0,
        rejected_candidate: None,
    };
    // Config A puts GB10 at segment 15, bus 1, device 0, function 0.
    // Try that first so the common boot path does not walk every bus.
    if scan.segment == 15 {
        if let Some(identity) = probe_gb10(root, PciIoAddress::new(1, 0, 0), &mut scan) {
            return (Some(identity), RootOutcome::Scanned(scan));
        }
    }
    // No firmware bus descriptors: fall back to the root bus so the scan
    // still sees devices whose bus numbers firmware never published.
    let (bus_min, bus_max) = bus_ranges(root).unwrap_or((0, 0));
    for bus in bus_min..=bus_max {
        if let Some(identity) = scan_bus(root, bus, &mut scan) {
            return (Some(identity), RootOutcome::Scanned(scan));
        }
    }
    (None, RootOutcome::Scanned(scan))
}

fn discover_gb10() -> Gb10Discovery {
    let mut discovery = Gb10Discovery {
        identity: None,
        handles: None,
        roots: [const { None }; MAX_ROOT_BRIDGES],
    };
    let handles = match uefi::boot::find_handles::<PciRootBridgeIo>() {
        Ok(handles) => handles,
        Err(_) => return discovery,
    };
    discovery.handles = Some(u16::try_from(handles.len()).unwrap_or(u16::MAX));
    for handle in handles {
        // Shared (GetProtocol) open: the firmware PCI bus driver holds this
        // protocol open ByDriver, so an exclusive open is refused with
        // ACCESS_DENIED. Shared reads are safe here: this boot code only
        // reads through the protocol, and firmware keeps the protocol
        // installed until boot services are exited.
        let mut root = match unsafe {
            uefi::boot::open_protocol::<PciRootBridgeIo>(
                OpenProtocolParams {
                    handle,
                    agent: uefi::boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        } {
            Ok(root) => root,
            Err(e) => {
                discovery.record(RootOutcome::OpenRefused(status_name(e.status())));
                continue;
            }
        };
        let (found, outcome) = scan_root(&mut root);
        discovery.record(outcome);
        if let Some(identity) = found {
            discovery.identity = Some(identity);
            return discovery;
        }
    }
    discovery
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

/// Firmware ACPI facts read before exit: core inventory (MADT) and the serial
/// console (SPCR), found by walking RSDP, then XSDT.
#[derive(Default)]
struct AcpiFacts {
    cpu: Option<acpi::CpuTopology>,
    spcr: Option<acpi::SpcrConsole>,
}

fn discover_acpi(boot_mpidr: u64) -> AcpiFacts {
    let mut facts = AcpiFacts::default();
    let Some(rsdp) = uefi::system::with_config_table(|entries| {
        entries
            .iter()
            .find(|e| e.guid == ConfigTableEntry::ACPI2_GUID)
            .map(|e| e.address as usize)
    }) else {
        return facts;
    };
    // SAFETY: firmware published this ACPI 2.0 RSDP, which is 36 bytes long.
    let rsdp = unsafe { core::slice::from_raw_parts(rsdp as *const u8, 36) };
    if &rsdp[..8] != b"RSD PTR " {
        return facts;
    }
    let Some(xsdt_addr) = rsdp[24..32].try_into().ok().map(u64::from_le_bytes) else {
        return facts;
    };
    // SAFETY: the RSDP points at the XSDT; its checksum is validated below.
    let Some(xsdt) = (unsafe { table_at(xsdt_addr as usize) })
        .and_then(|t| acpi::checked_table(t, b"XSDT").ok())
    else {
        return facts;
    };
    for addr in acpi::xsdt_entries(xsdt) {
        // SAFETY: XSDT entries point at firmware ACPI tables.
        let Some(table) = (unsafe { table_at(addr as usize) }) else {
            continue;
        };
        match &table[..4] {
            b"APIC" => facts.cpu = acpi::madt_cpu_topology_for(table, Some(boot_mpidr)).ok(),
            b"SPCR" => facts.spcr = acpi::spcr_console(table).ok(),
            _ => {}
        }
    }
    facts
}

fn write_uart_line(out: &mut impl Write, spcr: Option<acpi::SpcrConsole>) {
    let _ = match spcr {
        None => writeln!(out, "uart: none (no SPCR)"),
        Some(s) => match s.kind() {
            acpi::UartKind::Ns16550Mmio32(base) => {
                writeln!(
                    out,
                    "uart: 16550 mmio32 at {base:#x} (spcr type {:#04x})",
                    s.interface_type
                )
            }
            acpi::UartKind::Pl011(base) => {
                writeln!(
                    out,
                    "uart: pl011 at {base:#x} (spcr type {:#04x})",
                    s.interface_type
                )
            }
            acpi::UartKind::Unsupported => writeln!(
                out,
                "uart: unsupported (spcr type {:#04x}, space {}, width {})",
                s.interface_type, s.address_space, s.register_bit_width
            ),
        },
    };
}

/// Send text to the SPCR console, bounded. Returns the outcome for the report.
fn send_to_console(text: &str) -> &'static str {
    let kind = CONSOLE.try_lock().and_then(|k| *k);
    match kind.and_then(EarlyConsole::from_kind) {
        Some(console) => {
            console.write_str("\n");
            console.write_str(text);
            if console.is_dead() {
                "no response"
            } else {
                "sent"
            }
        }
        None => "no drivable console",
    }
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
    let path = cstr16!("\\EFI\\AIENOS\\BOOTREPORT.TXT");
    if let Ok(old) = root.open(path, FileMode::ReadWrite, FileAttribute::empty()) {
        let _ = old.delete();
    }
    let mut file = root
        .open(path, FileMode::CreateReadWrite, FileAttribute::empty())?
        .into_regular_file()
        .ok_or_else(|| uefi::Error::from(Status::UNSUPPORTED))?;
    file.write(text.as_bytes())
        .map_err(|e| uefi::Error::from(e.status()))?;
    file.flush()
}

fn wait_seconds(seconds: u64) {
    let frequency_hz = FREQUENCY_HZ.load(Ordering::SeqCst);
    let start = counter_ticks();
    let ticks = seconds.saturating_mul(frequency_hz);
    while counter_ticks().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

fn screen() -> Option<Screen> {
    let info = (*FRAMEBUFFER.try_lock()?)?;
    // SAFETY: firmware reported this buffer for the active mode, and nothing
    // else draws to it after boot services have exited.
    unsafe { Screen::new(info) }
}

fn write_cpu(
    out: &mut impl Write,
    cpu: Option<acpi::CpuTopology>,
    boot_midr: u64,
    boot_mpidr: u64,
) {
    match cpu {
        Some(t) => {
            let _ = writeln!(out, "cpu_cores: {}", t.cores);
            for (class, count) in t.classes() {
                let _ = writeln!(out, "cpu_efficiency_class_{class}: {count}");
            }
            if t.unknown_class > 0 {
                let _ = writeln!(out, "cpu_efficiency_class_unknown: {}", t.unknown_class);
            }
            match t.boot_class {
                Some(class) => {
                    let _ = writeln!(out, "cpu_boot_core_class: {class}");
                }
                None => {
                    let _ = writeln!(
                        out,
                        "cpu_boot_core_class: unknown (listed: {})",
                        if t.boot_core_listed { "yes" } else { "no" }
                    );
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
        boot_midr,
        midr_part(boot_midr)
    );
    let _ = writeln!(out, "boot_cpu_mpidr: {boot_mpidr:#x}");
}

/// Reset after firmware exit: PSCI first (not a UEFI runtime service). UEFI
/// ResetSystem is used only if PSCI returns without resetting (ADR 0008).
fn reset_after_exit(status: Status) -> ! {
    psci_system_reset();
    uefi::runtime::reset(ResetType::COLD, status, None)
}

/// Line recording which bounded firmware-variable write this report will be.
fn write_index_line(out: &mut impl Write) {
    let _ = writeln!(
        out,
        "nvram_write_index: {} of {MAX_VAR_WRITES}",
        VAR_WRITES.load(Ordering::SeqCst) + 1
    );
}

/// Count down on screen, then reset.
fn finish(mut screen: Option<Screen>) -> ! {
    stage(COUNTDOWN);
    match screen.as_mut() {
        Some(s) => {
            let _ = writeln!(s);
            s.set_color(ACCENT);
            for remaining in (1..=restart_after_secs()).rev() {
                s.clear_row();
                let _ = write!(s, "restarting in {remaining} s");
                wait_seconds(1);
            }
        }
        None => wait_seconds(restart_after_secs()),
    }
    reset_after_exit(Status::SUCCESS)
}

/// Shared path for panics and CPU faults.
fn fatal_report(kind: &str, detail: &dyn Fn(&mut Report)) -> ! {
    if IN_FATAL.swap(true, Ordering::SeqCst) {
        // A fault while reporting a fault: firmware services are suspect, so
        // only the architected PSCI reset is tried before parking the core.
        psci_system_reset();
        aienos_kernel::arch::aarch64::halt();
    }
    let mut report = Report::new();
    header(&mut report, kind);
    if EXITED.load(Ordering::SeqCst) {
        write_index_line(&mut report);
    }
    detail(&mut report);

    if !EXITED.load(Ordering::SeqCst) {
        uefi::println!("{}", report.as_str());
        let _ = save_report_file(report.as_str());
        wait_seconds(restart_after_secs());
        uefi::runtime::reset(ResetType::COLD, Status::ABORTED, None)
    }

    let mut screen = screen();
    if let Some(s) = screen.as_mut() {
        s.clear();
        s.set_color(ERROR);
        let _ = writeln!(s, "AIENOS BOOT STOPPED: {kind}");
        s.set_color(FOREGROUND);
        let _ = write!(s, "{}", report.as_str());
    }
    let uart = send_to_console(report.as_str());
    let _ = writeln!(report, "uart_report: {uart}");
    let saved = save_report_var(report.as_bytes());
    if let Some(s) = screen.as_mut() {
        let _ = writeln!(s, "uart_report: {uart}");
        match saved {
            Ok(n) => {
                let _ = writeln!(s, "nvram_report: saved (write {n} of {MAX_VAR_WRITES})");
            }
            Err(e) => {
                let _ = writeln!(s, "nvram_report: not saved ({e})");
            }
        }
    }
    finish(screen)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    fatal_report("panic", &|r| {
        let _ = writeln!(r, "panic: {}", info.message());
        if let Some(loc) = info.location() {
            let _ = writeln!(r, "panic_location: {}:{}", loc.file(), loc.line());
        }
    })
}

fn on_fault(info: &FaultInfo) -> ! {
    fatal_report("fault", &|r| {
        let _ = write!(r, "{info}");
    })
}

/// First-boot evidence image. Building it does not install or boot it.
#[entry]
fn main() -> Status {
    let uefi_entry_ticks = counter_ticks();
    FREQUENCY_HZ.store(counter_frequency_hz(), Ordering::SeqCst);
    stage(FIRMWARE_ENTRY);

    stage(GB10_DISCOVERY);
    let gb10_discovery = discover_gb10();
    let gb10 = gb10_discovery.identity;

    stage(ACPI_TOPOLOGY);
    let boot_midr = midr_el1();
    let boot_mpidr = mpidr_el1();
    let acpi_facts = discover_acpi(boot_mpidr);
    let cpu = acpi_facts.cpu;
    *CONSOLE.lock() = acpi_facts.spcr.map(|s| s.kind());

    stage(FRAMEBUFFER_DISCOVERY);
    let framebuffer = discover_framebuffer();
    *FRAMEBUFFER.lock() = framebuffer;

    let mut pre = Report::new();
    header(&mut pre, "pre_exit");
    let _ = writeln!(pre, "firmware_vendor: {}", uefi::system::firmware_vendor());
    let _ = writeln!(
        pre,
        "firmware_revision: {:#x}",
        uefi::system::firmware_revision()
    );
    let _ = writeln!(
        pre,
        "counter_frequency_hz: {}",
        FREQUENCY_HZ.load(Ordering::SeqCst)
    );
    match gb10 {
        Some(g) => {
            let _ = writeln!(
                pre,
                "gb10_pci: {:04x}:{:02x}:{:02x}.{}",
                g.bar.location.segment,
                g.bar.location.bus,
                g.bar.location.device,
                g.bar.location.function
            );
            let _ = writeln!(pre, "gb10_bar0_phys: {:#x}", g.bar.physical_base);
            let _ = writeln!(pre, "gb10_pmc_boot_0: {:#010x}", g.pmc_boot_0);
            let _ = writeln!(pre, "gb10_pmc_boot_42: {:#010x}", g.pmc_boot_42);
        }
        None => {
            let _ = writeln!(pre, "gb10: unavailable");
            gb10_discovery.write_diagnostics(&mut pre);
        }
    }
    write_cpu(&mut pre, cpu, boot_midr, boot_mpidr);
    write_uart_line(&mut pre, acpi_facts.spcr);
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
    let pre_file = save_report_file(pre.as_str()).map_err(|e| e.status());
    match pre_file {
        Ok(()) => uefi::println!("report file: \\EFI\\AIENOS\\BOOTREPORT.TXT saved"),
        Err(status) => uefi::println!("report file: not saved ({status:?})"),
    }
    stage(PRE_EXIT_SAVED);

    // After this point only runtime services (variables, reset) are used. The
    // returned map owns its backing allocation and stays live below.
    stage(EXIT_BOOT_SERVICES);
    let memory_map = unsafe { uefi::boot::exit_boot_services(None) };
    EXITED.store(true, Ordering::SeqCst);

    fatal::set_fault_hook(on_fault);
    fatal::install_exception_vectors();
    stage(VECTORS_INSTALLED);

    // Early progress record: proves native AIENOS code ran after firmware exit
    // even if a later step hangs.
    let mut progress = Report::new();
    header(&mut progress, "progress");
    write_index_line(&mut progress);
    let _ = writeln!(progress, "firmware_exit: ok");
    let progress_saved = save_report_var(progress.as_bytes());

    let mut summary = MemoryMapSummary::default();
    for descriptor in memory_map.entries() {
        summary.add(
            descriptor.ty == MemoryType::CONVENTIONAL,
            descriptor.phys_start,
            descriptor.page_count,
        );
    }
    let timing = BootTiming {
        uefi_entry_ticks,
        kernel_handoff_ticks: counter_ticks(),
        counter_frequency_hz: FREQUENCY_HZ.load(Ordering::SeqCst),
    };

    stage(KERNEL_ENTERED);
    let (kernel_report, boot_ok) = aienos_kernel::boot::early_kernel_enter(
        summary.conventional_kb(),
        summary.largest,
        Some(summary),
        Some(timing),
        gb10,
        cpu,
    );

    let mut report = Report::new();
    header(&mut report, "final");
    write_index_line(&mut report);
    let _ = write!(report, "{}", kernel_report.as_str());
    if gb10.is_none() {
        gb10_discovery.write_diagnostics(&mut report);
    }
    match progress_saved {
        Ok(_) => {
            let _ = writeln!(report, "progress_record: saved");
        }
        Err(e) => {
            let _ = writeln!(report, "progress_record: not saved ({e})");
        }
    }
    match pre_file {
        Ok(()) => {
            let _ = writeln!(report, "pre_exit_file: saved");
        }
        Err(status) => {
            let _ = writeln!(report, "pre_exit_file: not saved ({status:?})");
        }
    }

    // Draw and send first, then record both outcomes in the saved report.
    let mut screen = screen();
    if let Some(s) = screen.as_mut() {
        s.clear();
        s.set_color(ACCENT);
        let _ = writeln!(s, "AIENOS NATIVE BOOT REPORT");
        s.set_color(FOREGROUND);
        let _ = write!(s, "{}", report.as_str());
        stage(SCREEN_DRAWN);
    }
    let uart = send_to_console(report.as_str());
    stage(UART_SENT);

    let mut outcomes = ReportBuf::<256>::new();
    match framebuffer.filter(|_| screen.is_some()) {
        Some(f) => {
            let _ = writeln!(outcomes, "screen_report: drawn {}x{}", f.width, f.height);
        }
        None => {
            let _ = writeln!(outcomes, "screen_report: unavailable");
        }
    }
    let _ = writeln!(outcomes, "uart_report: {uart}");
    let _ = write!(report, "{}", outcomes.as_str());
    if report.truncated() {
        let _ = writeln!(report, "truncated: yes");
    }
    if let Some(s) = screen.as_mut() {
        let _ = write!(s, "{}", outcomes.as_str());
    }

    let saved = save_report_var(report.as_bytes());
    stage(FINAL_SAVED);
    if let Some(s) = screen.as_mut() {
        match saved {
            Ok(n) => {
                let _ = writeln!(s, "nvram_report: saved (write {n} of {MAX_VAR_WRITES})");
            }
            Err(e) => {
                let _ = writeln!(s, "nvram_report: not saved ({e})");
            }
        }
    }

    if !boot_ok {
        if let Some(s) = screen.as_mut() {
            s.set_color(ERROR);
            let _ = writeln!(s, "boot halted: no usable memory region");
        }
    }
    finish(screen)
}
