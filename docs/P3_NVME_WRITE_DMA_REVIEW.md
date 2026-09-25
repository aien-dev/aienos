# D6  -  SMMU / DMA review: P3 Native NVMe Write + Flush lane

Repo: `aien-dev/aienos`, base `ef359ec` (mirror `/Users/drakestapleton/aienos-nvme-rw`).
Scope: read-only review of the DMA/SMMU authority that a future write+flush lane
would inherit from the existing read substrate. No edits, no cargo, no hardware.

Verdict up front: the read lane already establishes a single, confined DMA
authority. Because write and read share the same driver `transfer()` and the
same `NativeDma`/`DmaMemory` implementation, a write lane that reuses the
existing module inherits that authority unchanged. There is **no write lane in
this tree yet** (`crates/aienos-kernel/src/nvme/` contains only `driver.rs`; no
`nvme_write.rs`), so the lane must be added without introducing a second window,
a second SMMU policy, or a second BME toggle.

---

## 1. Write DMA uses the SAME confined authority as read DMA

### 1.1 One static arena window for both directions

- `ARENA_BYTES = 128 * 1024` and the single `static mut DMA_ARENA: DmaArena`
  are defined once  -  `crates/aienos-boot/src/nvme_read.rs:43`, `:45-48`.
- `NvmeLocation::dma_window()` returns exactly that static, page-aligned:
  `nvme_read.rs:75-78` (`base & !0xfff`, `size_of::<DmaArena>()`).
- There is no second arena and no per-direction window. `grep` for
  `DMA_ARENA`/`dma_window` finds only this one definition plus its users
  (`nvme_read.rs:76,271,279,313,331,457`).
- The SMMU Stage-1 policy is built from that same call:
  `configure_smmu_for_nvme` takes `nvme.dma_window()` (`handoff.rs:305`) and
  passes a **single** `DmaWindow { iova: dma_base, pa: dma_base, length }` to
  `build_dma_policy`  -  `handoff.rs:317-327`.
- `build_dma_policy` requires identity (`window.iova != window.pa.0` →
  `InvalidWindow`) and maps only the supplied windows; anything else does not
  translate  -  `crates/aienos-kernel/src/smmu.rs:739-746`.

### 1.2 Same `dma_gate` decision for the whole phase

- The gate is evaluated **once**, before any command, in `run`:
  `dma_gate::dma_grant(smmu_ready, smmu_base.is_some(), UNSAFE_NVME_DMA_BYPASS)`
   -  `nvme_read.rs:413-417`. Its result gates the entire run (read today, write
  later); there is no second grant call.
- Decision logic is direction-agnostic: confined iff `smmu_ready`, bypass only
  when no SMMU exists AND the unsafe feature is compiled, never a fallback after
  a failed SMMU  -  `crates/aienos-kernel/src/dma_gate.rs:68-82`, test
  `failed_smmu_never_falls_back_to_bypass` `:279-282`.
- `nvme_read::run` is invoked with `nvme_smmu_result.is_ok()` as `smmu_ready`
  (`handoff.rs:2111-2117`), i.e. the grant is tied to the same
  `configure_smmu_for_nvme` result (`handoff.rs:1794`).

### 1.3 Same allocator and same `DmaMemory` path

- `NativeDma` bump-allocates only inside `DMA_ARENA`, bounds-checked against
  `ARENA_BYTES`  -  `nvme_read.rs:269-283`, `:286-305`.
- Write and read commands both flow through `NvmeController::transfer(write, …)`
  (`crates/aienos-kernel/src/nvme/driver.rs:293-362`): writes copy data into
  `region.bytes` then `dma.write(...)` (`driver.rs:325-330`); reads call
  `dma.read(...)` (`driver.rs:354-357`). Both go through the same
  `D: DmaMemory` = `NativeDma`.
- `write_blocks` is a thin wrapper over the same `transfer(true, …)`
  (`driver.rs:428-431`); `flush` uses the same `submit_io`
  (`driver.rs:432-439`). No separate DMA authority exists for writes.

**Confirmed:** one window, one SMMU policy, one gate decision, one allocator.
No separate or widened window for writes.

---

## 2. No unconstrained bus mastering

- Bus Master Enable is cleared on the controller's whole ECAM segment **before**
  any SMMU or driver setup: `take_over_dma` → `dma_gate::sweep_bus_master`
  (`nvme_read.rs:201-210`), called at `handoff.rs:1790` (and the sweep clears
  every endpoint with BME set  -  `dma_gate.rs:150-218`).
- `run` refuses to proceed if BME did not clear:
  `if dma_gate::bus_master_enabled(command) { … return; }`
  (`nvme_read.rs:409-412`).
- BME is set **only after** `dma_grant` returns `Ok`:
  `ecam.set_command(&at, dma_gate::with_bus_master(command))` at
  `nvme_read.rs:460`, which is after the `match dma_gate::dma_grant(...)` at
  `:413-429`. On denial it returns with BME still off (`:419-428`).
- BME is revoked after the phase: `revoke_dma` clears BME and re-reads to
  confirm (`nvme_read.rs:232-247`), called on every post-grant exit:
  init failure `:473`, queue failure `:499`, normal completion `:566`.
- Only one `with_bus_master` call site exists for NVMe
  (`nvme_read.rs:460`); the only other is xHCI (`usb_keyboard.rs:341`), and the
  two features are documented as mutually exclusive builds
  (`handoff.rs:1785-1786`).

**Confirmed:** BME set only after `dma_grant` `Ok`; revoked after the phase.

---

## 3. Unsafe QEMU bypass cannot enter a hardware-staging image

- Feature definition: `unsafe-debug-nvme-dma-without-smmu = ["nvme-read"]`
  (`crates/aienos-boot/Cargo.toml:42-48`); `hardware-staging = ["handoff"]`
  (`:32`).
- Compile guard: `#[cfg(all(feature = "unsafe-debug-nvme-dma-without-smmu",
  feature = "hardware-staging"))] compile_error!(...)`  -  `src/lib.rs:26-33`.
  The xHCI bypass has the equivalent guard  -  `lib.rs:12-19`.
- Banner: `UNSAFE_NVME_BANNER` is printed on every boot of such an image
  (`nvme_read.rs:33-36`, `:379-381`), and the active-grant warning is printed
  when the bypass actually grants DMA (`nvme_read.rs:443-450`).
- The bypass cannot be requested silently: the QEMU harness requires
  `AIENOS_UNSAFE_DMA_BYPASS=1` and refuses the feature otherwise
  (`scripts/qemu_nvme_test.sh:49-71`); the SMMU harness forces it off
  (`scripts/qemu_smmu_test.sh:3,8`). The hardware staging script builds
  `handoff,hardware-staging` with no bypass (`scripts/stage_one_time_boot.sh:32`).
- The harness asserts the confined path: denied without SMMU
  (`qemu_nvme_test.sh:246-248`), confined grant + revoke (`:252-261`), and
  `check_absent "no unsafe DMA bypass in this image"` on non-bypass runs
  (`:263-264`).

**Confirmed:** unbuildable with `hardware-staging`; banner on every boot; loud
warning when active.

---

## 4. Cache maintenance on the write path

CPU-writes-cleaned-to-device and device-writes-invalidated-before-CPU-read are
both present, and both are issued with a trailing `dsb`.

- `clean_dcache_range` = `dc cvac` per line + `dsb`  -  `arch/aarch64.rs:270-278`,
  helper ends with `dsb()` at `:291-301`.
- `clean_invalidate_dcache_range` = `dc civac` per line + `dsb`  - 
  `arch/aarch64.rs:282-289` (clean-first so no CPU write in a shared line is
  lost; documented `:279-281`).
- Write direction: `NativeDma::write` copies into the arena then calls
  `clean_dcache_range`  -  `nvme_read.rs:326-339`. In `transfer`, write payloads
  reach the device only via `dma.write` (`driver.rs:325-330`).
- Read direction: `NativeDma::read` calls `clean_invalidate_dcache_range`
  **before** the CPU copy  -  `nvme_read.rs:307-324`; used at
  `driver.rs:354-357`.
- Queue traffic is on the same discipline: SQ command written via `dma.write`
  (clean) before the doorbell (`driver.rs:372-378`); CQ read via `dma.read`
  (clean+invalidate) before inspecting phase/status (`driver.rs:380-383`,
  admin `:240-243`).
- Host tests exercise the write path end-to-end, including PRP-list and MDTS
  chunking (`driver.rs:917-945`) and write-completion-error propagation
  (`driver.rs:947-977`).

**Confirmed:** correct direction of maintenance for write (clean) and read
(clean+invalidate), each fenced with `dsb`.

---

## 5. Gaps / risks specific to the write+flush lane

1. **No write lane exists.** `nvme_read.rs` is explicitly read-only and claims
   no write/flush (`nvme_read.rs:9-11`). The lane must add a new module/feature
   (e.g. `nvme-write`) and QEMU harness; it must not simply call
   `write_blocks` from the read qualification path without its own evidence
   gates. `driver.rs` already implements `write_blocks`/`flush`, so the driver
   side is ready.

2. **Arena exhaustion (functional, fail-closed).** `NativeDma` never frees
   (`nvme_read.rs:269-305`), and `transfer`'s MDTS chunk cap is 128 KiB
   (`driver.rs:308-316`)  -  exactly `ARENA_BYTES` (`nvme_read.rs:43`). Admin
   queues + identify + I/O queues already consume part of the arena
   (`driver.rs:125-127,196-200`), so a maximum-size transfer cannot fit. The
   write lane must bound per-command chunk size well below the arena (or add
   arena reuse/free), otherwise writes fail with `NvmeError::Dma`. Fail-closed,
   but it caps the lane's usefulness and must be an explicit, tested limit.

3. **BME is not revoked on a panic/fault during the phase.** Revocation happens
   only on the enumerated normal/error returns (`nvme_read.rs:473,499,566`).
   `fatal_report` resets without clearing BME (`handoff.rs:1571+`), so a fault
   mid-write leaves BME set until the cold reset. The write lane should clear
   BME in the fault path (or explicitly accept reset as the only containment).

4. **Flush has no durable evidence yet.** `flush()` submits opcode 0 with
   `cdw10=1` through `submit_io` (`driver.rs:432-439`), which only distinguishes
   `Ok`/`DeviceError` (`driver.rs:399-403`). The lane must emit a distinct
   `NVME_FLUSH_*` evidence line and must only claim durability after a
   successful flush completion; it should also record that all prior writes were
   submitted serially (they are: each `submit_io` waits for completion  - 
   `driver.rs:379-404`).

5. **Namespace bounds are enforced before any command** (`driver.rs:301-307`,
   `OutOfRange`), so a write cannot escape the namespace. Keep this invariant:
   do not add a raw command path that bypasses `transfer`.

6. **Cache-maintenance caveat.** The maintenance is unconditional. If the arena
   mapping were ever Device-nGnRnE rather than Normal memory, `dc cvac`/`civac`
   semantics would be wrong. Today the arena is Normal identity-mapped
   (`handoff.rs:266-270` comment; `map_plan` identity path). The lane must not
   change the arena mapping attributes.

### Invariants the write+flush lane MUST preserve

- Reuse `NvmeLocation` / `DMA_ARENA` / `NvmeLocation::dma_window()` unchanged  - 
  no new static arena, no second window.
- Reuse `configure_smmu_for_nvme` and its single `DmaWindow`  -  no second
  `build_dma_policy` call, no widened policy.
- Reuse the single `dma_gate::dma_grant` result  -  no second grant, and no BME
  write anywhere outside `dma_gate::with_bus_master`/`without_bus_master`.
- Keep BME set only between the post-grant point and revocation, including on
  fault.
- Keep all data movement through `DmaMemory`/`NativeDma` (clean on write,
  clean+invalidate on read)  -  no direct MMIO or cache-bypassing copies.
- Keep the `unsafe-debug-nvme-dma-without-smmu` compile_error + banner contract
  and the `hardware-staging` incompatibility.

---

## Evidence index (file:line)

| Claim | Evidence |
|---|---|
| Single arena | `nvme_read.rs:43,45-48,75-78` |
| Single SMMU window | `handoff.rs:305,317-327`; `smmu.rs:713-717,739-746` |
| Single gate decision | `nvme_read.rs:413-429`; `dma_gate.rs:68-82,279-282` |
| BME off before setup | `nvme_read.rs:201-210`; `handoff.rs:1790` |
| BME set only after grant | `nvme_read.rs:409-412,460` |
| BME revoked | `nvme_read.rs:232-247,473,499,566` |
| Bypass compile guard | `lib.rs:26-33` (and `:12-19`) |
| Bypass banner | `nvme_read.rs:33-36,379-381,443-450` |
| Cache write/read | `nvme_read.rs:307-324,326-339`; `arch/aarch64.rs:270-289,291-301` |
| Write/flush driver | `driver.rs:293-362,428-439`; tests `:917-977` |
| No write lane yet | `nvme_read.rs:9-11`; `nvme/` contains only `driver.rs` |
