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

extern crate alloc;

use aienos_kernel::acpi;
use aienos_kernel::arch::aarch64::{
    counter_frequency_hz, counter_ticks, midr_el1, midr_part, mpidr_el1, psci_system_reset,
};
use aienos_kernel::boot::{BootTiming, MemoryMapSummary};
use aienos_kernel::console::EarlyConsole;
use aienos_kernel::display::{FramebufferInfo, PixelOrder, Screen, ACCENT, FOREGROUND};
use aienos_kernel::fatal::{self, FaultInfo};
use aienos_kernel::mem::frame_allocator::PhysAddr;
use aienos_kernel::mem::map_plan::{self, AddressRange, EfiMemoryDescriptor};
use aienos_kernel::mem::pagetable::{FixedFramePool, MapFlags, PageTableBuilder, TableMemory};
use aienos_kernel::report::ReportBuf;
use aienos_kernel::sync::spinlock::SpinLock;
use core::alloc::{GlobalAlloc, Layout};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::mem::memory_map::{MemoryMap, MemoryType};
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::proto::pci::configuration::ResourceRangeType;
use uefi::proto::pci::root_bridge::PciRootBridgeIo;
use uefi::proto::pci::PciIoAddress;
use uefi::runtime::{ResetType, VariableAttributes, VariableVendor};
use uefi::table::cfg::ConfigTableEntry;
use uefi::{cstr16, guid, CStr16};

const PT_POOL_PAGES: usize = 256;
const POST_EXIT_HEAP_PAGES: usize = 1024;
static POST_EXIT_HEAP: AtomicU64 = AtomicU64::new(0);
static POST_EXIT_HEAP_USED: AtomicU64 = AtomicU64::new(0);
static BOOT_SERVICES_LIVE: AtomicBool = AtomicBool::new(true);

#[cfg(feature = "usb-keyboard")]
#[repr(C)]
struct SmmuTables {
    stream_table: [[u64; 8]; 4096],
    command_queue: [[u64; 2]; 16],
    event_queue: [[u64; 4]; 16],
    context: [u64; 8],
}

#[cfg(feature = "usb-keyboard")]
const STREAM_ENTRIES: u32 = 4096;

// The linear stream table base must be aligned to its size (4096 * 64 bytes =
// 256 KiB) or QEMU truncates it before fetching the STE. COFF/PE cannot encode
// section alignment above 8192, so a 256 KiB-aligned static is unbuildable for
// aarch64-unknown-uefi; allocate the tables at runtime with an over-aligned
// Layout and hand out one shared pointer to every user instead.
#[cfg(feature = "usb-keyboard")]
const SMMU_TABLES_ALIGN: usize = 262144;

#[cfg(feature = "usb-keyboard")]
static SMMU_TABLES_PTR: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "usb-keyboard")]
fn smmu_tables() -> *mut SmmuTables {
    let existing = SMMU_TABLES_PTR.load(Ordering::Acquire);
    if existing != 0 {
        return existing as *mut SmmuTables;
    }
    let layout = Layout::from_size_align(core::mem::size_of::<SmmuTables>(), SMMU_TABLES_ALIGN)
        .expect("smmu tables layout");
    let raw = unsafe { ALLOCATOR.alloc(layout) };
    assert!(!raw.is_null(), "smmu tables allocation failed");
    unsafe { core::ptr::write_bytes(raw, 0, layout.size()) };
    SMMU_TABLES_PTR.store(raw as usize, Ordering::Release);
    raw.cast::<SmmuTables>()
}

struct BootHeap;
unsafe impl GlobalAlloc for BootHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if BOOT_SERVICES_LIVE.load(Ordering::Acquire) {
            return unsafe { GlobalAlloc::alloc(&uefi::allocator::Allocator, layout) };
        }
        let base = POST_EXIT_HEAP.load(Ordering::Acquire) as usize;
        if base == 0 {
            return core::ptr::null_mut();
        }
        let mut old = POST_EXIT_HEAP_USED.load(Ordering::Relaxed) as usize;
        loop {
            let aligned = match (base + old).checked_add(layout.align() - 1) {
                Some(v) => v & !(layout.align() - 1),
                None => return core::ptr::null_mut(),
            };
            let next = match aligned.checked_add(layout.size()) {
                Some(v) => v - base,
                None => return core::ptr::null_mut(),
            };
            if next > POST_EXIT_HEAP_PAGES * 4096 {
                return core::ptr::null_mut();
            }
            match POST_EXIT_HEAP_USED.compare_exchange_weak(
                old as u64,
                next as u64,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(v) => old = v as usize,
            }
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if BOOT_SERVICES_LIVE.load(Ordering::Acquire) {
            unsafe { GlobalAlloc::dealloc(&uefi::allocator::Allocator, ptr, layout) };
        }
    }
}
#[global_allocator]
static ALLOCATOR: BootHeap = BootHeap;

struct PhysicalTableMemory;
impl TableMemory for PhysicalTableMemory {
    fn read_entry(&self, table: PhysAddr, index: usize) -> Option<u64> {
        if index >= 512 {
            return None;
        }
        Some(unsafe { core::ptr::read_volatile((table.0 as *const u64).add(index)) })
    }
    fn write_entry(&mut self, table: PhysAddr, index: usize, value: u64) -> bool {
        if index >= 512 {
            return false;
        }
        unsafe { core::ptr::write_volatile((table.0 as *mut u64).add(index), value) };
        true
    }
}

fn runtime_attributes() -> Option<alloc::vec::Vec<aienos_kernel::mem::map_plan::RuntimeAttributes>>
{
    let mut table = None;
    uefi::system::with_config_table(|entries| {
        if let Some(entry) = entries
            .iter()
            .find(|e| e.guid == ConfigTableEntry::MEMORY_ATTRIBUTES_GUID)
        {
            table = Some(entry.address.cast::<u8>());
        }
    });
    let ptr = table?;
    let header = unsafe { core::slice::from_raw_parts(ptr, 16) };
    let count = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    let stride = u32::from_le_bytes(header[8..12].try_into().ok()?) as usize;
    let length = 16usize.checked_add(count.checked_mul(stride)?)?;
    if length > 1 << 20 {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, length) };
    aienos_kernel::uefi::parse_memory_attributes_table(bytes).ok()
}

fn clean_table_pool(base: usize, bytes: usize) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let ctr: u64;
        core::arch::asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack));
        let line = 4usize << ((ctr >> 16) & 0xf);
        for address in (base..base + bytes).step_by(line) {
            core::arch::asm!("dc cvac, {0}", in(reg) address, options(nostack));
        }
        core::arch::asm!("dsb ish", options(nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = (base, bytes);
}

#[cfg(feature = "usb-keyboard")]
fn configure_smmu_for_xhci(
    iort: Option<&acpi::IortSmmu>,
    xhci: Option<usb_keyboard::XhciLocation>,
    pool_base: usize,
    frames_used: usize,
) -> Result<u32, aienos_kernel::smmu::Error> {
    let iort = iort.ok_or(aienos_kernel::smmu::Error::InvalidWindow)?;
    let xhci = xhci.ok_or(aienos_kernel::smmu::Error::InvalidWindow)?;
    let stream_id = xhci
        .stream_id(iort)
        .ok_or(aienos_kernel::smmu::Error::InvalidWindow)?;
    let (dma_base, dma_length) = xhci.dma_window();
    let remaining = PT_POOL_PAGES.saturating_sub(frames_used);
    let next = pool_base
        .checked_add(
            frames_used
                .checked_mul(4096)
                .ok_or(aienos_kernel::smmu::Error::InvalidWindow)?,
        )
        .ok_or(aienos_kernel::smmu::Error::InvalidWindow)?;
    let frames = FixedFramePool::new(PhysAddr(next), remaining)
        .ok_or(aienos_kernel::smmu::Error::InvalidWindow)?;
    let mut page_table = PageTableBuilder::new(frames, PhysicalTableMemory)
        .map_err(aienos_kernel::smmu::Error::PageTable)?;
    page_table
        .map(
            dma_base as usize,
            PhysAddr(dma_base as usize),
            dma_length,
            MapFlags::KERNEL_DATA,
        )
        .map_err(aienos_kernel::smmu::Error::PageTable)?;
    let dma_root = page_table.root().0;
    let table_frames = page_table.frames_used().unwrap_or(0);
    clean_table_pool(next, table_frames * 4096);

    let tables = smmu_tables();
    assert_eq!(
        core::mem::size_of::<[[u64; 8]; STREAM_ENTRIES as usize]>(),
        SMMU_TABLES_ALIGN,
        "stream table must be exactly 256 KiB"
    );
    assert_eq!(STREAM_ENTRIES.trailing_zeros(), 12, "LOG2SIZE must be 12");
    assert!(stream_id < STREAM_ENTRIES, "SID outside the stream table");
    assert_eq!(
        tables as usize % SMMU_TABLES_ALIGN,
        0,
        "SMMU stream table is not 256 KiB aligned"
    );
    clean_table_pool(tables as usize, core::mem::size_of::<SmmuTables>());
    let mut regs = unsafe { aienos_kernel::smmu::MmioRegisters::new(iort.base as usize) };
    unsafe {
        aienos_kernel::smmu::configure_linear_stream(
            &mut regs,
            stream_id,
            STREAM_ENTRIES,
            core::ptr::addr_of_mut!((*tables).stream_table).cast(),
            16,
            core::ptr::addr_of_mut!((*tables).command_queue).cast(),
            16,
            core::ptr::addr_of_mut!((*tables).event_queue).cast(),
            core::ptr::addr_of_mut!((*tables).context),
            dma_root as u64,
        )?;
    }
    Ok(stream_id)
}

fn enter_kernel_mmu(
    memory_map: &impl MemoryMap,
    pool_base: usize,
    image: AddressRange,
    sections: &[aienos_kernel::mem::map_plan::PeSection],
    attrs: Option<&[aienos_kernel::mem::map_plan::RuntimeAttributes]>,
    framebuffer: Option<FramebufferInfo>,
    uart: Option<acpi::SpcrConsole>,
    xhci_mmio: Option<u64>,
    ecam: Option<AddressRange>,
    gic: Option<acpi::GicBases>,
    smmu_mmio: Option<u64>,
) -> (usize, usize, bool) {
    let descriptors: alloc::vec::Vec<_> = memory_map
        .entries()
        .map(|d| EfiMemoryDescriptor {
            memory_type: d.ty.0,
            phys_start: d.phys_start,
            page_count: d.page_count,
            attribute: d.att.bits(),
        })
        .collect();
    let mut mmio = alloc::vec::Vec::new();
    if let Some(fb) = framebuffer {
        mmio.push(AddressRange {
            start: fb.base & !4095,
            length: (fb.size_bytes + (fb.base & 4095) + 4095) & !4095,
        });
    }
    if let Some(console) = uart {
        mmio.push(AddressRange {
            start: console.base & !4095,
            length: 4096,
        });
    }
    if let Some(base) = xhci_mmio {
        mmio.push(AddressRange {
            start: base & !4095,
            length: 0x10000,
        });
    }
    if let Some(range) = ecam {
        mmio.push(range);
    }
    if let Some(gic) = gic {
        if let Some(base) = gic.distributor {
            mmio.push(AddressRange {
                start: base,
                length: 0x10000,
            });
        }
        if let Some((base, size)) = gic.redistributor {
            mmio.push(AddressRange {
                start: base,
                length: u64::from(size).max(0x20000),
            });
        }
    }
    if let Some(base) = smmu_mmio {
        mmio.push(AddressRange {
            start: base & !4095,
            length: 0x20000,
        });
    }
    let (plan, decision) =
        map_plan::build_map_plan(&descriptors, image.start, image, sections, attrs, &mmio)
            .expect("identity map plan rejected firmware layout");
    let pool =
        FixedFramePool::new(PhysAddr(pool_base), PT_POOL_PAGES).expect("invalid page table pool");
    let mut tables = PageTableBuilder::new(pool, PhysicalTableMemory)
        .expect("page table root allocation failed");
    for mapping in plan {
        tables
            .map(
                mapping.range.start as usize,
                PhysAddr(mapping.range.start as usize),
                mapping.range.length as usize,
                mapping.flags,
            )
            .expect("identity mapping failed");
    }
    let root = tables.root().0;
    let used = tables.frames_used().unwrap_or(0);
    clean_table_pool(pool_base, PT_POOL_PAGES * 4096);
    let parange: u64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mrs {0}, id_aa64mmfr0_el1", out(reg) parange, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        parange = 5;
    }
    let entered = unsafe {
        aienos_kernel::arch::aarch64::enter_el1h_mmu(
            root,
            map_plan::mair_el1(),
            map_plan::tcr_el1((parange & 0xf) as u8),
            map_plan::sctlr_el1(),
        )
    };
    if !entered {
        // Fail closed with evidence: the kernel must not continue on
        // firmware's translation, and the reason must survive the halt.
        let mut halt_report = Report::new();
        header(&mut halt_report, "halt");
        write_index_line(&mut halt_report);
        let el = aienos_kernel::arch::aarch64::current_el();
        let _ = writeln!(
            halt_report,
            "el1_switch: refused (current EL{el}, expected EL2)"
        );
        let _ = writeln!(halt_report, "boot: halted before kernel entry");
        let _ = send_to_console(halt_report.as_str());
        let _ = save_report_var(halt_report.as_bytes());
        aienos_kernel::arch::aarch64::halt();
    }
    fatal::install_exception_vectors();
    (
        used,
        root,
        decision == Some(map_plan::RuntimeDecision::RuntimeCodeRxUnsplit),
    )
}

#[cfg(feature = "usb-keyboard")]
mod usb_keyboard;

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
static IRQ_TICKS: AtomicU64 = AtomicU64::new(0);
static TIMER_DEADLINE: AtomicU64 = AtomicU64::new(0);

extern "C" fn timer_irq() {
    let mut cpu = aienos_kernel::gic::Aarch64GicCpuInterface;
    let id = aienos_kernel::gic::GicCpuInterface::acknowledge(&mut cpu);
    if id == 30 {
        IRQ_TICKS.fetch_add(1, Ordering::Relaxed);
        let next = TIMER_DEADLINE.load(Ordering::Relaxed);
        let frequency = aienos_kernel::timer::TimerRegisters::frequency(
            &aienos_kernel::timer::Aarch64TimerRegisters,
        );
        let deadline = next.wrapping_add(frequency / 100);
        TIMER_DEADLINE.store(deadline, Ordering::Relaxed);
        let mut timer = aienos_kernel::timer::Aarch64TimerRegisters;
        aienos_kernel::timer::TimerRegisters::set_compare(&mut timer, deadline);
        aienos_kernel::timer::TimerRegisters::enable_timer(&mut timer, true);
    }
    // End every acknowledged interrupt (not just the timer), or it stays
    // active in the GIC and blocks its priority level. INTIDs 1020-1023 are
    // special/spurious and must not be ended.
    if id < 1020 {
        aienos_kernel::gic::GicCpuInterface::end_interrupt(&mut cpu, id);
    }
}

fn run_timer_window(gic: Option<acpi::GicBases>) -> Option<(u64, u64)> {
    let bases = gic?;
    let distributor = bases.distributor? as usize;
    let (redistributor, _) = bases.redistributor?;
    let mut rd = aienos_kernel::gic::GicRedistributor(aienos_kernel::gic::MmioGicRegisters {
        base: redistributor as usize,
    });
    if !rd.wake(1_000_000) {
        return None;
    }
    rd.configure_ppi(30, 0x80);
    let mut dist = aienos_kernel::gic::GicDistributor(aienos_kernel::gic::MmioGicRegisters {
        base: distributor,
    });
    dist.enable_group1();
    let mut cpu = aienos_kernel::gic::Aarch64GicCpuInterface;
    aienos_kernel::gic::GicCpuInterface::set_priority_mask(&mut cpu, 0xff);
    aienos_kernel::gic::GicCpuInterface::enable_group1(&mut cpu);
    let _ = distributor;
    let mut timer = aienos_kernel::timer::Aarch64TimerRegisters;
    let hz = aienos_kernel::timer::TimerRegisters::frequency(&timer);
    let start = aienos_kernel::timer::TimerRegisters::counter(&timer);
    let deadline = start.wrapping_add(hz / 100);
    TIMER_DEADLINE.store(deadline, Ordering::Relaxed);
    aienos_kernel::timer::TimerRegisters::set_compare(&mut timer, deadline);
    aienos_kernel::timer::TimerRegisters::enable_timer(&mut timer, true);
    aienos_kernel::fatal::set_irq_hook(timer_irq);
    unsafe {
        core::arch::asm!("msr daifclr, #2", "isb", options(nostack));
    }
    while aienos_kernel::timer::TimerRegisters::counter(&timer).wrapping_sub(start) < hz / 5 {
        core::hint::spin_loop();
    }
    unsafe {
        core::arch::asm!("msr daifset, #2", "isb", options(nostack));
    }
    aienos_kernel::timer::TimerRegisters::enable_timer(&mut timer, false);
    Some((IRQ_TICKS.load(Ordering::Relaxed), 200))
}

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
fn scan_bus(
    root: &mut PciRootBridgeIo,
    bus: u8,
    scan: &mut BridgeScan,
) -> Option<aienos_accel::Gb10Identity> {
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
    gic: Option<acpi::GicBases>,
    #[cfg(feature = "usb-keyboard")]
    mcfg: Option<&'static [u8]>,
    #[cfg(feature = "usb-keyboard")]
    iort: Option<acpi::IortSmmu>,
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
            b"APIC" => {
                facts.cpu = acpi::madt_cpu_topology_for(table, Some(boot_mpidr)).ok();
                facts.gic = acpi::madt_gic_bases(table).ok();
            }
            b"SPCR" => facts.spcr = acpi::spcr_console(table).ok(),
            #[cfg(feature = "usb-keyboard")]
            b"MCFG" => facts.mcfg = Some(table),
            #[cfg(feature = "usb-keyboard")]
            b"IORT" => facts.iort = acpi::iort_smmuv3(table).ok().flatten(),
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
    let (loaded_base, loaded_size) =
        uefi::boot::open_protocol_exclusive::<LoadedImage>(uefi::boot::image_handle())
            .expect("LoadedImage protocol unavailable")
            .info();
    let loaded_base = loaded_base as usize;
    let loaded_size = usize::try_from(loaded_size).expect("loaded image too large");
    let image_bytes = unsafe { core::slice::from_raw_parts(loaded_base as *const u8, loaded_size) };
    let sections = aienos_kernel::pe::parse_pe_sections(image_bytes, loaded_base as u64)
        .expect("loaded PE section table invalid");
    let runtime_attrs = runtime_attributes();
    let pt_pool = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        PT_POOL_PAGES,
    )
    .expect("page table pool allocation failed")
    .as_ptr() as usize;
    let post_exit_heap = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        POST_EXIT_HEAP_PAGES,
    )
    .expect("post-exit heap allocation failed")
    .as_ptr() as usize;
    POST_EXIT_HEAP.store(post_exit_heap as u64, Ordering::Release);
    #[cfg(feature = "usb-keyboard")]
    let xhci = usb_keyboard::find_xhci();

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

    // The firmware map and every buffer used below remain identity-mapped.
    stage(EXIT_BOOT_SERVICES);
    let memory_map = unsafe { uefi::boot::exit_boot_services(None) };
    BOOT_SERVICES_LIVE.store(false, Ordering::Release);
    EXITED.store(true, Ordering::SeqCst);

    let (pt_frames_used, _, runtime_rx_unsplit) = enter_kernel_mmu(
        &memory_map,
        pt_pool,
        AddressRange {
            start: loaded_base as u64,
            length: loaded_size as u64,
        },
        &sections,
        runtime_attrs.as_deref(),
        framebuffer,
        acpi_facts.spcr,
        #[cfg(feature = "usb-keyboard")]
        xhci.map(|x| x.mmio_base()),
        #[cfg(not(feature = "usb-keyboard"))]
        None,
        #[cfg(feature = "usb-keyboard")]
        xhci.and_then(|x| {
            let (segment, bus) = x.ecam_location();
            acpi_facts.mcfg.and_then(|t| {
                acpi::mcfg_window(t, segment, bus)
                    .ok()
                    .flatten()
                    .map(|w| AddressRange {
                        start: w.base,
                        length: (u64::from(w.end_bus) - u64::from(w.start_bus) + 1) << 20,
                    })
            })
        }),
        #[cfg(not(feature = "usb-keyboard"))]
        None,
        acpi_facts.gic,
        #[cfg(feature = "usb-keyboard")]
        acpi_facts.iort.as_ref().map(|i| i.base),
        #[cfg(not(feature = "usb-keyboard"))]
        None,
    );

    #[cfg(feature = "usb-keyboard")]
    let smmu_result =
        configure_smmu_for_xhci(acpi_facts.iort.as_ref(), xhci, pt_pool, pt_frames_used);

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
    let irq_result = run_timer_window(acpi_facts.gic);

    let mut report = Report::new();
    header(&mut report, "final");
    write_index_line(&mut report);
    // Measured, not asserted: read the live exception level and SCTLR_EL1.M.
    let el = aienos_kernel::arch::aarch64::current_el();
    if el == 1 {
        let _ = writeln!(report, "kernel_el: EL1h");
    } else {
        let _ = writeln!(report, "kernel_el: unexpected EL{el}");
    }
    let mmu_on = aienos_kernel::arch::aarch64::el1_mmu_enabled();
    let _ = writeln!(
        report,
        "mmu: {}",
        if mmu_on { "enabled" } else { "disabled" }
    );
    let _ = writeln!(report, "pt_frames_used: {pt_frames_used}");
    #[cfg(feature = "usb-keyboard")]
    match smmu_result {
        Ok(stream_id) => {
            let _ = writeln!(
                report,
                "smmu: enabled base={:#x} stream_id={stream_id:#x}",
                acpi_facts.iort.as_ref().map_or(0, |i| i.base)
            );
            let _ = writeln!(report, "smmu_dma_window: xhci only, translation active");
        }
        Err(error) => {
            let _ = writeln!(report, "smmu: unavailable ({error:?})");
        }
    }
    // Cooperative threads at EL1 (issue #29): two workers each record a tag and
    // yield five times; the line reports the order actually observed.
    let (trace, trace_len) = unsafe { aienos_kernel::thread::run_demo() };
    let observed = core::str::from_utf8(&trace[..trace_len]).unwrap_or("?");
    let _ = writeln!(
        report,
        "threads: {} interleave={observed}",
        if observed == "ABABABABAB" {
            "ok"
        } else {
            "unexpected"
        }
    );
    let _ = writeln!(
        report,
        "runtime_code: {}",
        if runtime_rx_unsplit {
            "rx-unsplit"
        } else {
            "mat-split"
        }
    );
    let _ = write!(report, "{}", kernel_report.as_str());
    if let Some((ticks, ms)) = irq_result {
        let _ = writeln!(report, "gic: v3\ntimer_irq: {ticks} ticks in {ms} ms");
    } else {
        let _ = writeln!(report, "gic: unavailable\ntimer_irq: unavailable");
    }
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
    #[cfg(feature = "usb-keyboard")]
    usb_keyboard::run(
        xhci,
        acpi_facts.mcfg,
        &mut screen,
        summary.conventional_kb(),
        el,
        report.as_str(),
        smmu_result.is_ok(),
        acpi_facts.iort.as_ref().map(|s| s.base),
        smmu_result.ok(),
        unsafe { core::ptr::addr_of_mut!((*smmu_tables()).event_queue).cast_const() },
    );
    finish(screen)
}
