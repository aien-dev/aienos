//! P3 native NVMe read substrate (read-only qualification).
//!
//! Built only with the `nvme-read` feature, which `scripts/qemu_nvme_test.sh`
//! enables and hardware staging never does. After firmware exit this module
//! drives a PCIe NVMe controller with the polled, host-tested
//! [`aienos_kernel::nvme`] driver over a native MMIO adapter and a static DMA
//! arena, then reads one sentinel LBA and verifies it natively.
//!
//! Read-only: this module issues Identify (admin, 0x06) and Read (I/O, 0x02)
//! only. It never calls `write_blocks`, `flush`, format, or any mutating
//! command. Write and flush are not claimed here.
//!
//! DMA rule (M3): no SMMU confinement means no DMA. [`take_over_dma`] clears
//! Bus Master Enable on every endpoint of the controller's PCI segment before
//! any SMMU or driver setup, and [`run`] sets it again only when
//! [`dma_gate::dma_grant`] allows it.

use aienos_kernel::acpi::{self, EcamWindow};
use aienos_kernel::arch::aarch64::{
    clean_dcache_range, clean_invalidate_dcache_range, counter_frequency_hz, counter_ticks, MmioReg,
};
use aienos_kernel::block::BlockDevice;
use aienos_kernel::console::EarlyConsole;
use aienos_kernel::display::Screen;
use aienos_kernel::dma_gate::{self, BusMasterSweep, DmaGrant, PciConfig, PCI_COMMAND};
use aienos_kernel::nvme::atomicity::AtomicityDecision;
use aienos_kernel::nvme::driver::{Delay, DmaMemory, DmaRegion, NvmeController, NvmeError};
use aienos_kernel::nvme::Registers;
use core::fmt::Write;
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::pci::root_bridge::PciRootBridgeIo;
use uefi::proto::pci::PciIoAddress;

/// Printed on every boot of an image built with the unsafe NVMe DMA bypass.
const UNSAFE_NVME_BANNER: &str =
    "\nWARNING: UNSAFE NVME DMA BYPASS BUILD (unsafe-debug-nvme-dma-without-smmu): \
    NVMe DMA may run WITHOUT SMMU confinement. Debug only, QEMU only.\n";

/// Sentinel the qualification image holds: 32 repeats of a 16-byte magic in
/// one 512-byte LBA.
pub const SENTINEL_MAGIC: &[u8; 16] = b"AIENOS-NVME-SENT";
pub const SENTINEL_LBA: u64 = 2048;

/// Write/durability target: a deterministic read-write LBA distinct from the
/// read-only sentinel, and the 512-byte pattern written and verified there.
#[cfg(feature = "nvme-write")]
const RW_LBA: u64 = 4096;
#[cfg(feature = "nvme-write")]
const RW_MAGIC: &[u8; 16] = b"AIENOS-NVME-RW01";

const ARENA_BYTES: usize = 128 * 1024;

#[repr(C, align(4096))]
struct DmaArena([u8; ARENA_BYTES]);

static mut DMA_ARENA: DmaArena = DmaArena([0; ARENA_BYTES]);

/// Where the NVMe controller sits, found before firmware exit.
#[derive(Clone, Copy)]
pub struct NvmeLocation {
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    vendor: u16,
    device_id: u16,
    mmio: u64,
}

impl NvmeLocation {
    pub fn mmio_base(self) -> u64 {
        self.mmio
    }
    pub fn ecam_location(self) -> (u16, u8) {
        (self.segment, self.bus)
    }
    pub fn requester_id(self) -> u32 {
        (u32::from(self.bus) << 8) | (u32::from(self.device) << 3) | u32::from(self.function)
    }
    pub fn stream_id(self, iort: &acpi::IortSmmu) -> Option<u32> {
        iort.stream_id_for(self.requester_id())
    }
    pub fn dma_window(self) -> (u64, usize) {
        let base = core::ptr::addr_of!(DMA_ARENA) as u64;
        (base & !0xfff, core::mem::size_of::<DmaArena>())
    }
}

/// Walk every root bridge for the first NVMe controller (class base 0x01,
/// sub-class 0x08). Pre-exit only; read-only config access.
pub fn find_nvme() -> Option<NvmeLocation> {
    for handle in uefi::boot::find_handles::<PciRootBridgeIo>().ok()? {
        let params = OpenProtocolParams {
            handle,
            agent: uefi::boot::image_handle(),
            controller: None,
        };
        let Ok(mut root) = (unsafe {
            uefi::boot::open_protocol::<PciRootBridgeIo>(
                params,
                OpenProtocolAttributes::GetProtocol,
            )
        }) else {
            continue;
        };
        let (bus_min, bus_max) = crate::bus_ranges(&mut root).unwrap_or((0, 0));
        for bus in bus_min..=bus_max {
            for device in 0..32u8 {
                for function in 0..8u8 {
                    let address = PciIoAddress::new(bus, device, function);
                    let mut read = |offset| {
                        root.pci()
                            .read_one::<u32>(address.with_register(offset))
                            .ok()
                    };
                    let Some(id) = read(0).filter(|id| id & 0xffff != 0xffff) else {
                        if function == 0 {
                            break;
                        }
                        continue;
                    };
                    if let (Some(class), Some(low), Some(high)) =
                        (read(0x08), read(0x10), read(0x14))
                    {
                        // Config dword 0x08 is base<<24 | subclass<<16 | prog_if<<8 | rev.
                        let class_code = class >> 16;
                        // 0x0108: mass storage, NVM. Accept any programming
                        // interface (QEMU reports 0x010802).
                        if class_code == 0x0108 && low & 0x1 == 0 {
                            let is_64 = low & 0x7 == 0x4;
                            let mmio = if is_64 {
                                (u64::from(high) << 32) | u64::from(low & !0xf)
                            } else {
                                u64::from(low & !0xf)
                            };
                            if mmio != 0 {
                                return Some(NvmeLocation {
                                    segment: root.segment_nr() as u16,
                                    bus,
                                    device,
                                    function,
                                    vendor: (id & 0xffff) as u16,
                                    device_id: (id >> 16) as u16,
                                    mmio,
                                });
                            }
                        }
                    }
                    let multi = read(0x0c).is_some_and(|v| v & 0x80_0000 != 0);
                    if function == 0 && !multi {
                        break;
                    }
                }
            }
        }
    }
    None
}

fn console() -> Option<EarlyConsole> {
    crate::CONSOLE
        .try_lock()
        .and_then(|k| *k)
        .and_then(EarlyConsole::from_kind)
}

/// Write `text` to the SPCR console and the screen.
fn say(screen: &mut Option<Screen>, text: &str) {
    if let Some(console) = console() {
        console.write_str(text);
    }
    if let Some(s) = screen.as_mut() {
        let _ = s.write_str(text);
    }
}

/// Config space of one ECAM window, reached through the kernel identity map.
struct Ecam(EcamWindow);

impl PciConfig for Ecam {
    fn read32(&mut self, bus: u8, device: u8, function: u8, offset: u16) -> Option<u32> {
        let addr = self.0.config_address(bus, device, function, offset)?;
        Some(MmioReg::<u32>::new(addr as usize).read())
    }
    fn write16(&mut self, bus: u8, device: u8, function: u8, offset: u16, value: u16) {
        if let Some(addr) = self.0.config_address(bus, device, function, offset) {
            MmioReg::<u16>::new(addr as usize).write(value);
        }
    }
}

impl Ecam {
    fn command(&mut self, at: &NvmeLocation) -> Option<u16> {
        self.read32(at.bus, at.device, at.function, PCI_COMMAND)
            .map(|v| v as u16)
    }
    fn set_command(&mut self, at: &NvmeLocation, value: u16) {
        self.write16(at.bus, at.device, at.function, PCI_COMMAND, value);
    }
}

/// What [`take_over_dma`] did to the controller's PCI segment.
#[derive(Clone, Copy)]
pub struct DmaTakeover {
    window: EcamWindow,
    sweep: BusMasterSweep,
}

/// Post-exit, before any SMMU or driver setup: clear Bus Master Enable on
/// every endpoint in the NVMe ECAM window.
pub fn take_over_dma(nvme: Option<NvmeLocation>, mcfg: Option<&[u8]>) -> Option<DmaTakeover> {
    let at = nvme?;
    let window = acpi::mcfg_window(mcfg?, at.segment, at.bus)
        .ok()
        .flatten()?;
    let sweep = dma_gate::sweep_bus_master(&mut Ecam(window), window.start_bus, window.end_bus);
    Some(DmaTakeover { window, sweep })
}

fn report_takeover(screen: &mut Option<Screen>, takeover: &DmaTakeover) {
    let (w, s) = (&takeover.window, &takeover.sweep);
    let mut line = aienos_kernel::report::ReportBuf::<256>::new();
    let _ = writeln!(
        line,
        "dma_sweep: seg {:04x} bus {:02x}-{:02x} functions={} bridges={} bridges_bme={} \
         endpoints_bme_found={} still_enabled={}",
        w.segment,
        w.start_bus,
        w.end_bus,
        s.functions,
        s.bridges,
        s.bridges_bus_master,
        s.endpoints_bus_master,
        s.still_enabled
    );
    say(screen, line.as_str());
}

/// Clear Bus Master Enable on the controller again (revoke its DMA).
fn revoke_dma(screen: &mut Option<Screen>, ecam: &mut Ecam, at: &NvmeLocation) {
    if let Some(command) = ecam.command(at) {
        ecam.set_command(at, dma_gate::without_bus_master(command));
    }
    let off = ecam
        .command(at)
        .is_some_and(|c| !dma_gate::bus_master_enabled(c));
    say(
        screen,
        if off {
            "dma_gate: nvme bus master revoked\n"
        } else {
            "dma_gate: nvme bus master revoke FAILED\n"
        },
    );
}

/// Registers adapter over the controller's MMIO BAR.
struct NativeRegisters {
    base: usize,
}

impl Registers for NativeRegisters {
    fn read32(&mut self, offset: u32) -> u32 {
        MmioReg::<u32>::new(self.base + offset as usize).read()
    }
    fn write32(&mut self, offset: u32, value: u32) {
        MmioReg::<u32>::new(self.base + offset as usize).write(value);
    }
}

/// Bump allocator over the static, identity-mapped, cache-coherent DMA arena.
struct NativeDma {
    cursor: usize,
    end: usize,
}

impl NativeDma {
    fn new() -> Self {
        let base = core::ptr::addr_of!(DMA_ARENA) as usize;
        Self {
            cursor: base,
            end: base + ARENA_BYTES,
        }
    }

    fn offset_of(physical: u64) -> Option<usize> {
        let base = core::ptr::addr_of!(DMA_ARENA) as u64;
        let offset = physical.checked_sub(base)?;
        (offset < ARENA_BYTES as u64).then_some(offset as usize)
    }
}

impl DmaMemory for NativeDma {
    fn allocate(&mut self, size: usize, alignment: usize) -> Result<DmaRegion, NvmeError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(NvmeError::Dma);
        }
        let aligned = self
            .cursor
            .checked_add(alignment - 1)
            .map(|v| v & !(alignment - 1))
            .ok_or(NvmeError::Dma)?;
        if aligned.checked_add(size).is_none_or(|end| end > self.end) {
            return Err(NvmeError::Dma);
        }
        self.cursor = aligned + size;
        // SAFETY: bump-allocated inside the live static arena, never shared.
        unsafe { core::ptr::write_bytes(aligned as *mut u8, 0, size) };
        Ok(DmaRegion {
            physical: aligned as u64,
            bytes: alloc::vec![0u8; size],
        })
    }

    fn read(&self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError> {
        let offset = Self::offset_of(physical).ok_or(NvmeError::Dma)?;
        if offset + output.len() > ARENA_BYTES {
            return Err(NvmeError::Dma);
        }
        // The device wrote this memory; drop stale cache lines before reading.
        let base = core::ptr::addr_of!(DMA_ARENA) as usize;
        clean_invalidate_dcache_range(base + offset, output.len());
        // SAFETY: in-bounds inside the live arena; copy into the caller buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (base + offset) as *const u8,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        Ok(())
    }

    fn write(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> {
        let offset = Self::offset_of(physical).ok_or(NvmeError::Dma)?;
        if offset + input.len() > ARENA_BYTES {
            return Err(NvmeError::Dma);
        }
        let base = core::ptr::addr_of!(DMA_ARENA) as usize;
        // SAFETY: in-bounds inside the live arena; copy from the caller buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(input.as_ptr(), (base + offset) as *mut u8, input.len())
        };
        // Make the CPU writes visible to the controller before it reads them.
        clean_dcache_range(base + offset, input.len());
        Ok(())
    }
}

/// Real-time delay bounded by the architectural counter.
struct NativeDelay;

impl Delay for NativeDelay {
    fn delay_us(&mut self, us: u32) {
        let hz = counter_frequency_hz();
        if hz == 0 {
            for _ in 0..us {
                core::hint::spin_loop();
            }
            return;
        }
        let ticks = hz.saturating_mul(u64::from(us)) / 1_000_000;
        let start = counter_ticks();
        while counter_ticks().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }
}

fn hex_digest(out: &mut impl Write, digest: &[u8; 32]) {
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
}

/// Post-exit: bring up the controller, read the sentinel LBA, and report.
#[allow(clippy::too_many_arguments)]
/// Render a power-fail atomicity decision into a report line.
fn describe_atomicity(buf: &mut aienos_kernel::report::ReportBuf<512>, d: AtomicityDecision) {
    match d {
        AtomicityDecision::Atomic { effective_blocks } => {
            let _ = write!(buf, "atomic(effective={effective_blocks})");
        }
        AtomicityDecision::NotAtomic(reason) => {
            let _ = write!(buf, "not_atomic({reason:?})");
        }
        AtomicityDecision::Unknown(reason) => {
            let _ = write!(buf, "unknown({reason:?})");
        }
    }
}

pub fn run(
    nvme: Option<NvmeLocation>,
    takeover: Option<DmaTakeover>,
    screen: &mut Option<Screen>,
    smmu_ready: bool,
    smmu_base: Option<u64>,
    smmu_stream_id: Option<u32>,
    smmu_events: *const [[u64; 4]; 16],
) {
    if aienos_boot::UNSAFE_NVME_DMA_BYPASS {
        say(screen, UNSAFE_NVME_BANNER);
    }
    let Some(at) = nvme else {
        say(
            screen,
            "NVME_DISCOVERY_QEMU: FAIL (no class 0x0108 function)\n",
        );
        return;
    };
    let mut line = aienos_kernel::report::ReportBuf::<256>::new();
    let _ = writeln!(
        line,
        "NVME_DISCOVERY_QEMU: PASS (class=0x0108 seg={:04x} bus={:02x} device={:02x} function={:02x} bar0={:#x})",
        at.segment, at.bus, at.device, at.function, at.mmio
    );
    say(screen, line.as_str());
    let Some(takeover) = takeover else {
        say(
            screen,
            "nvme: unavailable (no ECAM window for the controller; DMA not granted)\n",
        );
        return;
    };
    report_takeover(screen, &takeover);
    let mut ecam = Ecam(takeover.window);
    let Some(command) = ecam.command(&at) else {
        say(screen, "nvme: unavailable (config space unreadable)\n");
        return;
    };
    if dma_gate::bus_master_enabled(command) {
        say(screen, "nvme: unavailable (bus master would not clear)\n");
        return;
    }
    let grant = match dma_gate::dma_grant(
        smmu_ready,
        smmu_base.is_some(),
        aienos_boot::UNSAFE_NVME_DMA_BYPASS,
    ) {
        Ok(grant) => grant,
        Err(denied) => {
            let mut msg = aienos_kernel::report::ReportBuf::<200>::new();
            let _ = writeln!(
                msg,
                "dma_gate: nvme denied ({denied:?}), bus master stays off\n\
                 nvme: unavailable (SMMU DMA isolation not active)"
            );
            say(screen, msg.as_str());
            return;
        }
    };
    let dma_mode = match grant {
        DmaGrant::Confined => {
            let mut smmu_line = aienos_kernel::report::ReportBuf::<160>::new();
            let _ = writeln!(
                smmu_line,
                "smmu: enabled base={:#x} stream_id={:#x}",
                smmu_base.unwrap_or(0),
                smmu_stream_id.unwrap_or(0)
            );
            say(screen, smmu_line.as_str());
            say(screen, "smmu_dma_window: nvme only, translation active\n");
            "smmu-translated"
        }
        DmaGrant::UnsafeBypass => {
            say(
                screen,
                "WARNING: UNSAFE NVME DMA BYPASS ACTIVE: no SMMU on this machine, NVMe DMA \
                 reaches physical memory UNCONFINED (QEMU debug only)\n",
            );
            "UNSAFE-identity-no-smmu"
        }
    };
    let mut mode = aienos_kernel::report::ReportBuf::<256>::new();
    let _ = writeln!(
        mode,
        "dma_gate: nvme granted ({grant:?}), bus master on\n\
         nvme_debug: dma_mode={dma_mode} dma_base={:#x} bytes={}",
        core::ptr::addr_of!(DMA_ARENA) as usize,
        ARENA_BYTES
    );
    ecam.set_command(&at, dma_gate::with_bus_master(command));
    say(screen, mode.as_str());

    let registers = NativeRegisters {
        base: at.mmio as usize,
    };
    let dma = NativeDma::new();
    let mut controller = match NvmeController::init(registers, dma, NativeDelay) {
        Ok(controller) => controller,
        Err(error) => {
            let mut msg = aienos_kernel::report::ReportBuf::<256>::new();
            let _ = writeln!(msg, "NVME_IDENTIFY_QEMU: FAIL (init {error:?})");
            say(screen, msg.as_str());
            revoke_dma(screen, &mut ecam, &at);
            report_smmu_fault(screen, smmu_base, smmu_stream_id, smmu_events);
            return;
        }
    };
    let mut identified = aienos_kernel::report::ReportBuf::<256>::new();
    let _ = writeln!(
        identified,
        "NVME_IDENTIFY_QEMU: PASS (vid={:#06x} did={:#06x} nsid=1)",
        at.vendor, at.device_id
    );
    say(screen, identified.as_str());

    let block_count = controller.block_count();
    let block_size = controller.block_size();
    let mut geometry = aienos_kernel::report::ReportBuf::<256>::new();
    let _ = writeln!(
        geometry,
        "NVME_GEOMETRY_QEMU: PASS (nsid=1 block_count={block_count} block_size={block_size})"
    );
    say(screen, geometry.as_str());

    // NVMe 1.4 power-fail atomicity observation and System Store root-write
    // eligibility. The acceptance marker is emitted only when both Store
    // superblock slots satisfy the complete predicate.
    if let Some(a) = controller.atomicity() {
        let mut fields = aienos_kernel::report::ReportBuf::<512>::new();
        let _ = writeln!(
            fields,
            "NVME_ATOMICITY_IDENTIFY_QEMU: block_size={} awupf_raw={} nawupf_raw={} nabspf_raw={} nabo_blocks={} effective_pf_blocks={} boundary_blocks={}",
            a.lba_bytes,
            a.awupf_raw.map_or(-1, i32::from),
            a.nawupf_raw.map_or(-1, i32::from),
            a.nabspf_raw.map_or(-1, i32::from),
            a.nabo_blocks,
            a.effective_power_fail_blocks().map_or(-1, |v| v as i64),
            a.boundary_blocks().map_or(-1, |v| v as i64),
        );
        say(screen, fields.as_str());

        let slot0 = a.store_root_decision(0);
        let slot1 = a.store_root_decision(1);
        let both_atomic = matches!(slot0, AtomicityDecision::Atomic { .. })
            && matches!(slot1, AtomicityDecision::Atomic { .. });
        let mut decision = aienos_kernel::report::ReportBuf::<512>::new();
        let _ = write!(
            decision,
            "NVME_STORE_ROOT_ATOMICITY_QEMU: {} (slot0=",
            if both_atomic { "PASS" } else { "FAIL" }
        );
        describe_atomicity(&mut decision, slot0);
        let _ = write!(decision, " slot1=");
        describe_atomicity(&mut decision, slot1);
        let _ = writeln!(decision, ")");
        say(screen, decision.as_str());
    }

    if let Err(error) = controller.create_io_queues(4) {
        let mut msg = aienos_kernel::report::ReportBuf::<256>::new();
        let _ = writeln!(msg, "NVME_READ_QEMU: FAIL (create_io_queues {error:?})");
        say(screen, msg.as_str());
        revoke_dma(screen, &mut ecam, &at);
        return;
    }

    // Read the sentinel LBA and verify it natively.
    let mut buffer = [0u8; 512];
    match controller.read_blocks(SENTINEL_LBA, &mut buffer) {
        Ok(()) => {
            let digest = aienos_kernel::crypto::sha256::hash(&buffer);
            let mut expected = [0u8; 512];
            for chunk in expected.as_chunks_mut::<16>().0 {
                chunk.copy_from_slice(SENTINEL_MAGIC);
            }
            let mut read_line = aienos_kernel::report::ReportBuf::<320>::new();
            if buffer == expected {
                let _ = write!(
                    read_line,
                    "NVME_READ_QEMU: PASS (lba={SENTINEL_LBA} blocks=1 bytes=512 sha256="
                );
                hex_digest(&mut read_line, &digest);
                let _ = writeln!(read_line, ")");
            } else {
                let _ = writeln!(
                    read_line,
                    "NVME_READ_QEMU: FAIL (sentinel mismatch at lba {SENTINEL_LBA})"
                );
            }
            say(screen, read_line.as_str());
        }
        Err(error) => {
            let mut msg = aienos_kernel::report::ReportBuf::<256>::new();
            let _ = writeln!(msg, "NVME_READ_QEMU: FAIL (read {error:?})");
            say(screen, msg.as_str());
        }
    }

    // Bounds: one read past the end must be rejected before any command.
    let mut bounds = aienos_kernel::report::ReportBuf::<256>::new();
    match controller.read_blocks(block_count, &mut buffer) {
        Err(aienos_kernel::block::BlockError::OutOfRange) => {
            let _ = writeln!(
                bounds,
                "NVME_BOUNDS_QEMU: PASS (lba={block_count} rejected OutOfRange no_command)"
            );
        }
        other => {
            let _ = writeln!(bounds, "NVME_BOUNDS_QEMU: FAIL (got {other:?})");
        }
    }
    say(screen, bounds.as_str());

    // Error path: identify an unallocated namespace must surface a nonzero
    // completion status rather than being swallowed.
    let mut error_line = aienos_kernel::report::ReportBuf::<256>::new();
    match controller.identify_namespace(0xffff_ffff) {
        Err(NvmeError::CompletionStatus { sct, sc }) => {
            let _ = writeln!(
                error_line,
                "NVME_ERROR_QEMU: PASS (identify nsid=0xffffffff rejected status=nonzero sct={sct} sc={sc})"
            );
        }
        other => {
            let _ = writeln!(error_line, "NVME_ERROR_QEMU: FAIL (got {other:?})");
        }
    }
    say(screen, error_line.as_str());

    #[cfg(feature = "nvme-write")]
    run_write_phase(screen, &mut controller, block_count);

    revoke_dma(screen, &mut ecam, &at);
}

/// Write + flush qualification, exercised only in `nvme-write` builds.
///
/// Read-only callers never reach this. The phase proves: a write past the end
/// is rejected before any command; a known pattern is written, flushed, and
/// read back byte-for-byte; a later boot that already holds the pattern
/// reports cross-restart durability; and an explicit invalid-namespace write
/// surfaces a device error rather than being swallowed.
#[cfg(feature = "nvme-write")]
fn run_write_phase<R: Registers, D: DmaMemory, T: Delay>(
    screen: &mut Option<Screen>,
    controller: &mut NvmeController<R, D, T>,
    block_count: u64,
) {
    use aienos_kernel::block::BlockError;

    let mut new = [0u8; 512];
    for chunk in new.as_chunks_mut::<16>().0 {
        chunk.copy_from_slice(RW_MAGIC);
    }
    let new_digest = aienos_kernel::crypto::sha256::hash(&new);

    // A write past the namespace end must be rejected before any command.
    let mut bounds = aienos_kernel::report::ReportBuf::<256>::new();
    match controller.write_blocks(block_count, &new) {
        Err(BlockError::OutOfRange) => {
            let _ = writeln!(
                bounds,
                "NVME_WRITE_BOUNDS_QEMU: PASS (lba={block_count} rejected OutOfRange no_command)"
            );
        }
        other => {
            let _ = writeln!(bounds, "NVME_WRITE_BOUNDS_QEMU: FAIL (got {other:?})");
        }
    }
    say(screen, bounds.as_str());

    // If the target already holds the expected bytes, this boot is a restart
    // after a prior successful write: report durability across the restart.
    let mut readback = [0u8; 512];
    let persisted = controller.read_blocks(RW_LBA, &mut readback).is_ok() && readback == new;
    if persisted {
        let mut line = aienos_kernel::report::ReportBuf::<320>::new();
        let _ = write!(
            line,
            "NVME_DURABILITY_QEMU: PASS (persisted lba={RW_LBA} blocks=1 bytes=512 sha256="
        );
        hex_digest(&mut line, &new_digest);
        let _ = writeln!(line, ")");
        say(screen, line.as_str());
    } else {
        let mut write_line = aienos_kernel::report::ReportBuf::<320>::new();
        match controller.write_blocks(RW_LBA, &new) {
            Ok(()) => {
                let _ = write!(
                    write_line,
                    "NVME_WRITE_QEMU: PASS (lba={RW_LBA} blocks=1 bytes=512 sha256="
                );
                hex_digest(&mut write_line, &new_digest);
                let _ = writeln!(write_line, ")");
            }
            Err(error) => {
                let _ = writeln!(write_line, "NVME_WRITE_QEMU: FAIL (write {error:?})");
            }
        }
        say(screen, write_line.as_str());

        let mut flush_line = aienos_kernel::report::ReportBuf::<160>::new();
        match controller.flush() {
            Ok(()) => {
                let _ = writeln!(flush_line, "NVME_FLUSH_QEMU: PASS (nsid=1)");
            }
            Err(error) => {
                let _ = writeln!(flush_line, "NVME_FLUSH_QEMU: FAIL (flush {error:?})");
            }
        }
        say(screen, flush_line.as_str());

        let mut durability = aienos_kernel::report::ReportBuf::<320>::new();
        let mut readback = [0u8; 512];
        match controller.read_blocks(RW_LBA, &mut readback) {
            Ok(()) if readback == new => {
                let _ = write!(
                    durability,
                    "NVME_DURABILITY_QEMU: PASS (lba={RW_LBA} blocks=1 bytes=512 sha256="
                );
                hex_digest(&mut durability, &new_digest);
                let _ = writeln!(durability, ")");
            }
            Ok(()) => {
                let _ = writeln!(durability, "NVME_DURABILITY_QEMU: FAIL (readback mismatch)");
            }
            Err(error) => {
                let _ = writeln!(durability, "NVME_DURABILITY_QEMU: FAIL (read {error:?})");
            }
        }
        say(screen, durability.as_str());
    }

    // An explicit invalid namespace write must surface a device error.
    let mut error_line = aienos_kernel::report::ReportBuf::<256>::new();
    match controller.write_blocks_nsid(0xffff_ffff, RW_LBA, &new) {
        Err(BlockError::DeviceError) => {
            let _ = writeln!(
                error_line,
                "NVME_WRITE_ERROR_QEMU: PASS (write nsid=0xffffffff rejected status=nonzero)"
            );
        }
        other => {
            let _ = writeln!(error_line, "NVME_WRITE_ERROR_QEMU: FAIL (got {other:?})");
        }
    }
    say(screen, error_line.as_str());
}

fn report_smmu_fault(
    screen: &mut Option<Screen>,
    smmu_base: Option<u64>,
    smmu_stream_id: Option<u32>,
    smmu_events: *const [[u64; 4]; 16],
) {
    let Some(base) = smmu_base else {
        return;
    };
    let reg = |offset| MmioReg::<u32>::new(base as usize + offset).read();
    clean_invalidate_dcache_range(smmu_events as usize, core::mem::size_of::<[[u64; 4]; 16]>());
    let events = unsafe { core::ptr::read_volatile(smmu_events) };
    let mut fault = aienos_kernel::report::ReportBuf::<512>::new();
    let _ = writeln!(
        fault,
        "smmu_fault: GERROR={:#x} GERRORN={:#x} events={events:016x?}",
        reg(0x60),
        reg(0x64)
    );
    say(screen, fault.as_str());
    if let Some(sid) = smmu_stream_id {
        let table_base = (u64::from(reg(0x84)) << 32 | u64::from(reg(0x80))) & !0x3f;
        let ste_addr = table_base + u64::from(sid) * 64;
        let ste0 = unsafe { core::ptr::read_volatile(ste_addr as *const u64) };
        let ste1 = unsafe { core::ptr::read_volatile((ste_addr + 8) as *const u64) };
        let mut entry = aienos_kernel::report::ReportBuf::<192>::new();
        let _ = writeln!(
            entry,
            "smmu_ste: base={table_base:#x} sid={sid:#x} addr={ste_addr:#x} words=[{ste0:#x},{ste1:#x}]"
        );
        say(screen, entry.as_str());
    }
}
