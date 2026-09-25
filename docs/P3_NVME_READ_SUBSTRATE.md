# D5  -  P3 Native NVMe Read Substrate: adapter and wiring design

Baseline: `aien-dev/aienos` @ `ff5de9c` (mirror `/Users/drakestapleton/aienos-p3`).
Lane: P3 Native NVMe Read Substrate. Deliverable: the native adapter/wiring that
lets the AIENOS handoff image drive an NVMe controller directly after firmware
exit, plus the QEMU harness `scripts/qemu_nvme_test.sh` (this directory's
`qemu_nvme_test.sh`). **Read-only qualification.**

> **Status: implemented and passing in QEMU (2026-09-25).** The module
> `crates/aienos-boot/src/nvme_read.rs`, the `nvme-read` feature, the handoff
> wiring, and `scripts/qemu_nvme_test.sh` are in this branch. The SMMU-confined
> run and the fail-closed run both pass; see
> [`evidence/p3_nvme_read_qemu_2026-09-25.md`](../evidence/p3_nvme_read_qemu_2026-09-25.md).
> `scripts/verify_all.sh` is intentionally not edited; wiring the harness and
> the `nvme-read` clippy check into it remains a small follow-up.

## 0. Scope and explicit non-claims

- The substrate issues **only** Identify (admin, opcode 0x06) and Read
  (I/O, opcode 0x02) commands. The `nvme-read` build never calls
  `write_blocks`, `flush`, format, namespace management, or set-features with
  side effects.
- **Write and flush are NOT claimed, proven, or exercised.** The driver's
  `BlockDevice` impl (`crates/aienos-kernel/src/nvme/driver.rs:401`) does
  expose `write_blocks`/`flush`; this lane deliberately leaves them untested.
  The QEMU harness attaches a disposable raw image and the guest only reads it.
- **No dependency on Store v1 or any Store file.** The module reads the raw
  namespace through `aienos_kernel::nvme` only; nothing imports
  `aienos_kernel::store` (see `crates/aienos-kernel/src/lib.rs:42`).
- The device is a native PCIe function discovered through ECAM and driven with
  MMIO + polled queues, mirroring the xHCI keyboard candidate
  (`crates/aienos-boot/src/usb_keyboard.rs`), not a UEFI Block I/O protocol.

## 1. Feature gating

Mirror the `usb-keyboard` gating exactly
(`crates/aienos-boot/Cargo.toml:18-38`).

`crates/aienos-boot/Cargo.toml`:

```toml
# SEED/P3 candidate: polled native NVMe read after firmware exit.
# Only scripts/qemu_nvme_test.sh enables it; hardware staging never does.
nvme-read = ["handoff"]
# UNSAFE. DEBUG ONLY. QEMU ONLY. Lets the NVMe function DMA straight to
# physical memory with NO SMMU confinement when the platform has no SMMU.
# Never compiled with hardware-staging; prints a warning on every boot.
unsafe-debug-nvme-dma-without-smmu = ["nvme-read"]
```

`crates/aienos-boot/src/lib.rs` adds, next to the existing xHCI guard
(`crates/aienos-boot/src/lib.rs:12-19`):

```rust
#[cfg(all(
    feature = "unsafe-debug-nvme-dma-without-smmu",
    feature = "hardware-staging"
))]
compile_error!(
    "feature `unsafe-debug-nvme-dma-without-smmu` (unconfined DMA, QEMU debug \
     only) cannot be combined with `hardware-staging`: no SMMU confinement \
     means no DMA"
);

/// Whether this build carries the unsafe, QEMU-only NVMe DMA bypass.
pub const UNSAFE_NVME_DMA_BYPASS: bool = cfg!(feature = "unsafe-debug-nvme-dma-without-smmu");
```

The module is declared in the handoff binary next to the keyboard module
(`crates/aienos-boot/src/handoff.rs:469-470`):

```rust
#[cfg(feature = "nvme-read")]
mod nvme_read;
```

## 2. New module `crates/aienos-boot/src/nvme_read.rs`

The module's shape is a direct sibling of `usb_keyboard.rs`: pre-exit discovery,
post-exit confinement, then `run()`.

### 2.1 `NvmeLocation`  -  ECAM discovery of class 0x0108 and BAR0

Pre-exit (`find_nvme()`), walk every `PciRootBridgeIo` handle exactly like
`find_xhci()` (`usb_keyboard.rs:72-126`):

- Read config dword 0 for the present check (`id & 0xffff != 0xffff`).
- Read class/revision at offset `0x08`; the class code is bits 8..32.
  NVMe is base class `0x01` (mass storage), sub-class `0x08` (NVM),
  programming interface `0x02`. QEMU's `-device nvme` reports `0x010802`,
  so match `(class_revision >> 8) & 0xffff == 0x0108` (accept any prog-if).
  (Constants: `crates/aienos-kernel/src/pci.rs:20` defines `REG_CLASS_REVISION`.)
- Decode a 64-bit memory BAR0 from config offsets `0x10` (low) and `0x14`
  (high) into the MMIO base, as the xHCI walk reads its BAR pair
  (`usb_keyboard.rs:104-114`). Reject an I/O-space BAR (low bit 0).

```rust
#[derive(Clone, Copy)]
pub struct NvmeLocation {
    segment: u16, bus: u8, device: u8, function: u8, mmio: u64,
}

impl NvmeLocation {
    pub fn mmio_base(self) -> u64 { self.mmio }
    pub fn ecam_location(self) -> (u16, u8) { (self.segment, self.bus) }
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
```

`requester_id` / `stream_id` / `dma_window` mirror `XhciLocation`
(`usb_keyboard.rs:59-68`). `requester_id` is exactly `Bdf::requester_id`
(`crates/aienos-kernel/src/pci.rs:75`); `stream_id` uses
`IortSmmu::stream_id_for` (`crates/aienos-kernel/src/acpi.rs:286`).

### 2.2 `NativeRegisters`  -  Registers MMIO adapter

The kernel driver is generic over `Registers`
(`crates/aienos-kernel/src/nvme.rs:22`), which this adapter implements over
`MmioReg` (`crates/aienos-kernel/src/arch/aarch64.rs:8-31`):

```rust
pub struct NativeRegisters { base: usize }

impl aienos_kernel::nvme::Registers for NativeRegisters {
    fn read32(&mut self, offset: u32) -> u32 {
        MmioReg::<u32>::new(self.base + offset as usize).read()
    }
    fn write32(&mut self, offset: u32, value: u32) {
        MmioReg::<u32>::new(self.base + offset as usize).write(value);
    }
}
```

### 2.3 `NativeDma`  -  static DMA arena implementing `DmaMemory`

The driver owns DMA through the `DmaMemory` trait
(`crates/aienos-kernel/src/nvme/driver.rs:63-67`), whose regions carry a
physical address and a CPU byte view. The handoff identity-maps conventional
memory, so the arena's virtual address **is** its physical address (the same
assumption as `XhciLocation::dma_window`, `usb_keyboard.rs:65-68`).

```rust
const ARENA_BYTES: usize = 128 * 1024; // admin + I/O queues + transfer pages

#[repr(C, align(4096))]
struct DmaArena([u8; ARENA_BYTES]);

static mut DMA_ARENA: DmaArena = DmaArena([0; ARENA_BYTES]);

struct NativeDma { next: usize, end: usize }

impl aienos_kernel::nvme::driver::DmaMemory for NativeDma {
    fn allocate(&mut self, size: usize, alignment: usize) -> Result<DmaRegion, NvmeError> {
        let base = core::ptr::addr_of_mut!(DMA_ARENA) as usize;
        let aligned = (self.next + alignment - 1) & !(alignment - 1);
        if aligned.checked_add(size).is_none_or(|e| e > self.end) {
            return Err(NvmeError::Dma);
        }
        self.next = aligned + size;
        let ptr = aligned as *mut u8;
        // SAFETY: bump-allocated from the zeroed static arena, page aligned.
        unsafe { core::ptr::write_bytes(ptr, 0, size) };
        Ok(DmaRegion { physical: aligned as u64, bytes: unsafe {
            core::slice::from_raw_parts_mut(ptr, size) }.to_vec() })
    }
    fn read(&self, physical: u64, output: &mut [u8]) -> Result<(), NvmeError> { /* copy from identity */ }
    fn write(&mut self, physical: u64, input: &[u8]) -> Result<(), NvmeError> { /* copy to identity */ }
}
```

`#[repr(C, align(4096))]` on the arena mirrors `DmaPage`
(`crates/aienos-kernel/src/usb/xhci/controller.rs:38-41`). 128 KiB covers the
driver's bounded allocations: admin SQ/CQ/Identify 3 x 4096
(`driver.rs:112-114`), I/O CQ `depth*16` and SQ `depth*64` for `depth = 4`
(`driver.rs:178-183`), a transfer region plus PRP list for a single 512-byte
read (`driver.rs:307-324`).

### 2.4 `NativeDelay`  -  bounded real-time waits

`Delay::delay_us` (`driver.rs:18`) spins on the architectural counter using
`counter_frequency_hz()` / `counter_ticks()`
(`crates/aienos-kernel/src/arch/aarch64.rs:130,204`), so every controller wait
is bounded in real time, matching the kernel's own design note
(`driver.rs:14-15`).

### 2.5 SMMU + `dma_gate` confinement

Post-exit, in order (mirrors `usb_keyboard.rs:182-345` and
`handoff.rs:1665-1672`):

1. **Bus-master sweep before anything else.** `take_over_dma(nvme, mcfg)` builds
   an `Ecam` adapter over the MCFG window
   (`crates/aienos-kernel/src/acpi.rs:380`, adapter pattern
   `usb_keyboard.rs:147-169`) and calls
   `dma_gate::sweep_bus_master` (`dma_gate.rs:150`) so every endpoint's Bus
   Master Enable starts clear.
2. **SMMU domain for the NVMe stream.** `configure_smmu_for_nvme` is a
   parameterized twin of `configure_smmu_for_xhci` (`handoff.rs:206-282`):
   resolve `stream_id` from IORT (`acpi.rs:286`), build policy with
   `aienos_kernel::smmu::build_dma_policy` over the **NVMe arena window**
   (`dma_window()` above) only, then `configure_linear_stream`. The report
   line is `smmu_dma_window: nvme only, translation active`.
3. **Gate.** `dma_gate::dma_grant(smmu_ready, smmu_present, UNSAFE_NVME_DMA_BYPASS)`
   (`dma_gate.rs:68`). Only on `Ok(Confined)` (or `Ok(UnsafeBypass)`) is
   `dma_gate::with_bus_master(command)` written. On denial the module logs
   `dma_gate: nvme denied ({denied:?}), bus master stays off` and
   `nvme: unavailable (SMMU DMA isolation not active)`, then returns with the
   controller never enabled.
4. **Revocation.** After the phase, clear Bus Master Enable again and emit
   `dma_gate: nvme bus master revoked` (pattern `usb_keyboard.rs:226-241`).

Unsafe bypass announcement (QEMU only), mirroring
`usb_keyboard.rs:35-37,257-259,326-331`:

```rust
const UNSAFE_NVME_BANNER: &str =
    "\nWARNING: UNSAFE NVME DMA BYPASS BUILD (unsafe-debug-nvme-dma-without-smmu): \
    NVMe DMA may run WITHOUT SMMU confinement. Debug only, QEMU only.\n";
// on UnsafeBypass grant:
"WARNING: UNSAFE NVME DMA BYPASS ACTIVE: no SMMU on this machine, NVMe DMA \
 reaches physical memory UNCONFINED (QEMU debug only)\n"
```

### 2.6 `run()`  -  the read phase and the six markers

`run(nvme, takeover, &mut screen, smmu_ready, smmu_base, smmu_stream_id, events)`
uses the same `say()` console+screen helper as `usb_keyboard.rs:136-143`.

Controller bring-up: `NvmeController::init(NativeRegisters, NativeDma,
NativeDelay)` (`driver.rs:106`) performs the reset/ready handshake, builds the
admin queues, and runs Identify Controller + Identify Namespace 1
(`driver.rs:144-171`). Then `create_io_queues(4)` (`driver.rs:174`) creates the
polled QID-1 CQ/SQ (`create_io_cq` sets PC=1, IEN=0; `nvme.rs:106`).

Read: `BlockDevice::read_blocks(sentinel_lba, &mut [u8; 512])`
(`driver.rs:408`) issues a single Read (opcode 0x02, `nvme.rs:128`) over the
identity-mapped arena. The module then verifies the bytes **natively** against
the expected 512-byte sentinel and computes the SHA-256 with
`aienos_kernel::crypto::sha256::hash` (`crypto/mod.rs:9`,
`aienos-crypto/src/sha256.rs:198`). No host round-trip is trusted.

## 3. Handoff wiring (`crates/aienos-boot/src/handoff.rs`)

- **Pre-exit:** `let nvme = nvme_read::find_nvme();` beside the xHCI discovery
  (`handoff.rs:1551-1552`). BAR0 must be mapped before post-exit MMIO.
- **MMU map:** extend `enter_kernel_mmu`'s device list
  (`handoff.rs:307-348`) with the NVMe BAR0 range (0x10000 bytes, as the xHCI
  BAR uses) and the NVMe ECAM window, and with the SMMU page when present.
  Because the current signature has one `xhci_mmio` slot, generalize it to a
  caller-built `&[AddressRange]` (`extra_mmio`) so `usb-keyboard` and
  `nvme-read` can coexist; the ECAM window is derived exactly as at
  `handoff.rs:1640-1652`.
- **Post-exit:** after `configure_smmu_for_xhci` (`handoff.rs:1670-1672`),
  run `nvme_read::take_over_dma(nvme, acpi_facts.mcfg)` and
  `configure_smmu_for_nvme(...)`, then call `nvme_read::run(...)` after the
  final report and the optional keyboard phase (`handoff.rs:1975-1987`).

Pre-exit facts reused unchanged: MCFG table + ECAM window (`acpi.rs:380`),
IORT SMMUv3 (`acpi.rs:297`), and `bus_ranges` (`handoff.rs:840`).

## 4. Serial markers (exact strings the kernel emits)

Emitted through `say()` to the SPCR console during the NVMe phase. The six
required markers, with their detail (PASS shown; on failure the same prefix is
printed with `FAIL` and the reason):

```text
NVME_DISCOVERY_QEMU: PASS (class=0x0108 seg=0000 bus=00 device=02 function=00 bar0=0x10010000)
NVME_IDENTIFY_QEMU: PASS (vid=0x1b36 did=0x0010 nsid=1)
NVME_GEOMETRY_QEMU: PASS (nsid=1 block_count=131072 block_size=512)
NVME_READ_QEMU: PASS (lba=2048 blocks=1 bytes=512 sha256=8b688adcb13bef657e868313fb149e7e92e664b5f09fbd32f99d9cabf756fdf1)
NVME_BOUNDS_QEMU: PASS (lba=131072 rejected OutOfRange no_command)
NVME_ERROR_QEMU: PASS (identify nsid=0xffffffff rejected status=nonzero)
```

Supporting lines (not required, used by the harness for isolation):

```text
nvme: class=0x0108 seg=0000 bus=00 device=02 function=00 bar0=0x...         # discovery detail
dma_sweep: seg 0000 bus 00-ff ...                                          # dma_gate::sweep_bus_master
dma_gate: nvme granted (Confined), bus master on                           # or UnsafeBypass / denied
smmu: enabled base=0x... stream_id=0x...
smmu_dma_window: nvme only, translation active
dma_gate: nvme bus master revoked
nvme: unavailable (SMMU DMA isolation not active)
```

Marker semantics:

| Marker | Kernel action |
| --- | --- |
| `NVME_DISCOVERY_QEMU` | ECAM walk found a function whose class code is base/sub `0x0108`; BAR0 decoded. PASS = found + BAR0 mapped. |
| `NVME_IDENTIFY_QEMU` | `NvmeController::init` reached CSTS.RDY and Identify Controller + Identify Namespace 1 returned status 0 (`driver.rs:144-171`). |
| `NVME_GEOMETRY_QEMU` | Namespace 1 reports `block_count == 131072`, `block_size == 512`, exactly the image geometry. |
| `NVME_READ_QEMU` | Read of LBA 2048 returned 512 bytes byte-identical to the sentinel, and `sha256 == 8b688adc…`. |
| `NVME_BOUNDS_QEMU` | `read_blocks(131072, …)` returned `BlockError::OutOfRange` with **no** I/O doorbell write (client-side bounds, `driver.rs:284-290`). |
| `NVME_ERROR_QEMU` | Identify Namespace for unallocated NSID `0xffffffff` returned a non-zero completion status (`NvmeError::CompletionStatus`, `driver.rs:236-239`); proves the device error path is surfaced, not swallowed. |

## 5. Exact expected sentinel geometry

| Property | Value |
| --- | --- |
| Image size | 64 MiB = 67,108,864 bytes, disposable raw |
| LBA size | 512 bytes |
| Total LBAs | 131,072 |
| Sentinel LBA | 2048 (byte offset 1,048,576 = 1 MiB) |
| Sentinel length | 1 LBA = 512 bytes |
| Sentinel payload | 16-byte magic `AIENOS-NVME-SENT` repeated 32 times (no newline) |
| Sentinel SHA-256 | `8b688adcb13bef657e868313fb149e7e92e664b5f09fbd32f99d9cabf756fdf1` |
| Bounds LBA (out of range) | 131072 (== block_count) |
| Error NSID | 0xffffffff (unallocated) |

The host harness builds the same payload with `printf` + `truncate` + `dd`,
hashes it with `sha256sum`, and requires the kernel's `NVME_READ_QEMU` line to
contain that host-computed hash, so a wrong or stale image cannot pass.

## 6. Harness mapping (`qemu_nvme_test.sh`)

- Builds `-p aienos-boot --target aarch64-unknown-uefi --features nvme-read
  --bin aienos-handoff --target-dir target/qemu-nvme` with `AIENOS_COMMIT`
  and `AIENOS_RESTART_SECS=1` (as `qemu_keyboard_test.sh:65-68`).
- Boots the same AAVMF image and `virt,virtualization=on,gic-version=3`
  machine, defaulting to `iommu=smmuv3`; attaches the sentinel image as
  `-device nvme,drive=nvme0,serial=aienos-nvme-test`.
- Waits for `report_kind: pre_exit`, then for `NVME_ERROR_QEMU: PASS` (or a
  panic/fault), then checks the six markers plus the SMMU/`dma_gate` lines and
  prints `QEMU_NVME: PASS`/`FAIL` with a non-zero exit on failure.
- Fail-closed mode (`AIENOS_QEMU_SMMU=0`, normal build) requires the six
  markers to be **absent** and the denial lines to be present. Unsafe mode
  (`AIENOS_UNSAFE_DMA_BYPASS=1`) requires the bypass banners plus the six
  markers and prints a warning.

## 7. Follow-ups (not done in this lane)

- **`scripts/verify_all.sh` is not edited.** Adding a QEMU step for this
  harness and `nvme-read` to the aarch64 clippy feature loop
  (`verify_all.sh:70-73`) is a separate integration change.
- **Host unit tests:** add `aienos-boot`/kernel tests for the class-0x0108
  match and the arena bump allocator; the kernel `nvme` module already has a
  full fake-controller suite (`driver.rs:425-977`) the native adapter must not
  disturb.
- **Write/flush stay out of scope** until a separate lane can prove
  confinement end-to-end for mutating media commands.
