# Boot handoff contract: loader -> C kernel (`ck_handoff`)

Status: **SPEC, NOT_RUN.** Documentation only. No code in this change, no
test run. Nothing here is qualified on QEMU or on Machine 1.

Authority: aien-architecture ADR 0024 (`docs/adr/0024-rust-scaffolding-omega-destination.md`,
read at 64b800b), operator decision **Q3**: the Rust loader `crates/aienos-boot`
is temporary scaffolding and reference; it has no slot-based A/B selection and
no signed boot manifest; do not port it to C now; loader expansion is frozen;
"the loader to C-kernel handoff contract is to be defined"; the existing QEMU
fallback and rollback tests are preserved; permanent boot ownership is
deferred to Atlas and TRUST-1.

Vocabulary used below:

- **CODE**: the statement is what the current code does, cited `file:line`
  (aienos `origin/main` at 4a116e5).
- **MISSING**: the contract needs it and no code exists.
- **PROPOSED**: a name, value or rule this document introduces. Nothing
  PROPOSED exists in code until a follow-up cut adds it.
- **UNVERIFIED**: taken from an outside spec and not re-read for this cut.

## 1. Ground truth: what hands off to the C kernel today

There is **no Rust loader to C kernel handoff in the code**. Three facts:

1. The only producer of `struct ck_handoff` is the C UEFI stub
   `native/boot/efi_main.c` (fills it at `efi_main.c:60-76,126-129`, calls
   `ck_kernel_entry(h)` at `efi_main.c:144`). The stub and the kernel are
   linked into **one PE image** (`native/boot/README.md`; `efi_main.c:3-9`:
   "Loads nothing and checks nothing: the image already contains the
   kernel"). The handoff is an ordinary C call inside one binary.
2. The Rust loader binaries in `crates/aienos-boot` never start the C kernel.
   `aienos-boot` (`src/main.rs:10`) prints `kernel handoff: not implemented`.
   `aienos-handoff` (`src/handoff.rs`) is the first-boot evidence image: it
   enters the **Rust** kernel in the same image through
   `enter_kernel_mmu(...)` (`src/handoff.rs:362`) with Rust types
   (framebuffer, SPCR console, GIC, SMMU, NVMe and ECAM bases). Its only
   `#[repr(C)]` type (`src/handoff.rs:64`) is the SMMU table block, not a
   handoff record.
3. The rollback behaviour the QEMU test shows (`scripts/qemu_native_rollback_test.sh`)
   is UEFI **BootNext** one-time boot of a mock candidate
   (`aienos-rollback-mock`, built at line 36 of that script), with the
   firmware returning to the default `BootOrder` entry. No slot selection
   exists anywhere (ADR 0024 Q3).

So this contract freezes the record the C kernel already accepts
(`ck_handoff`, magic `CHANDOF1`) as the **one** entry ABI. Any loader (the C
stub today; the Rust loader only if Q3 is reopened; Atlas later) must produce
exactly this record. The Rust loader is not extended by this document.

## 2. Entry ABI

| Item | Value | Source |
| --- | --- | --- |
| Entry symbol | `ck_kernel_entry(struct ck_handoff *h)`, `noreturn` | CODE `native/boot/handoff.h:31`, `native/kernel/core/kmain.c:160` |
| Calling convention | AAPCS64: `x0` = physical address of the record (identity mapped, see section 3) | CODE: plain C call `efi_main.c:144` |
| Other registers | none defined; the kernel reads nothing else | CODE `kmain.c:160-187` |
| Stack | the firmware's UEFI stack, still in use; the kernel switches to its own stack on the EL1 entry | CODE `efi_entry.S` runs on firmware stack (`efi_entry.S:1-5` header comment), new stack from `ck_mm_build` (`kmain.c:178`, `mm/mmu.c:155-162`) |
| Record location | inside the loaded image BSS (`static struct ck_handoff handoff`, `efi_main.c:20`); memory map copy in the image BSS too (`efi_main.c:19`) | CODE |
| Separate kernel binary entry | **MISSING.** A loader that is not linked into the kernel image has no symbol to call and no load format for the kernel. PROPOSED: not added while Q3 freezes loader expansion. | |

## 3. Record layout (`struct ck_handoff`, `native/boot/handoff.h:11-28`)

Offsets below are derived by hand from AAPCS64 natural alignment (LP64,
little endian). **They are not compiler-checked**: the code cut in section
9 adds `_Static_assert`s for every offset and the total size.

| Off | Size | Field | Meaning | Producer | Kernel reads it? |
| --- | --- | --- | --- | --- | --- |
| 0 | 8 | `magic` | `CK_HANDOFF_MAGIC` = `0x31464f444e414843`, ASCII `CHANDOF1` little endian (`handoff.h:9`) | `efi_main.c:62` | yes, `kmain.c:174` |
| 8 | 4 | `firmware_el` | `CurrentEL` at UEFI entry | `efi_main.c:61,63` | yes, report only `kmain.c:57` |
| 12 | 4 | `desc_version` | UEFI memory descriptor version from `GetMemoryMap` | `efi_main.c:128` | **no** (never checked) |
| 16 | 8 | `firmware_ttbr0` | `TTBR0_EL2` (or EL1) of the firmware regime | `efi_main.c:67,70` | yes, report only `kmain.c:53` |
| 24 | 8 | `firmware_sctlr` | `SCTLR_EL2` (or EL1) of the firmware regime | `efi_main.c:68,71` | yes, report only `kmain.c:57` |
| 32 | 8 | `rsdp` | ACPI 2.0 RSDP physical address, 0 if absent | `efi_main.c:86-88` | yes, `kmain.c:20`, `mm/mmu.c:124-125,189-196` |
| 40 | 8 | `memory_map` | physical address of the final UEFI memory map copy | `efi_main.c:76` | yes, `mm/mmu.c:113,120,130-131` |
| 48 | 8 | `map_size` | bytes in that copy | `efi_main.c:126` | yes, same lines |
| 56 | 8 | `desc_size` | stride of one descriptor | `efi_main.c:127` | yes, `mm/frames.c:95` refuses `< sizeof(struct ck_efi_desc)` (40 bytes, `mm/frames.h:38-45`) |
| 64 | 8 | `image_base` | loaded image start (`__image_base`, `image.ld:20`) | `efi_main.c:73` | yes, reserved `mm/mmu.c:118` |
| 72 | 8 | `image_end` | loaded image end, exclusive | `efi_main.c:74` | yes, `mm/mmu.c:118` |
| 80 | 8 | `counter_freq_hz` | `CNTFRQ_EL0` at entry | `efi_main.c:65` | **no** (kernel rereads the counter itself) |
| 88 | 8 | `uefi_entry_ticks` | `CNTPCT_EL0` at UEFI entry | `efi_main.c:64` | **no** |
| 96 | 4 | `exit_attempts` | `ExitBootServices` calls until success (1..8) | `efi_main.c:129` | yes, report only `kmain.c:66` |
| 100 | 4 | `reserved0` | zero (BSS) | `efi_main.c:20` (static, zeroed by `efi_entry.S` BSS clear) | **no** (not checked to be zero) |
| 104 | 8 | `commit` | pointer to the build commit string | `efi_main.c:75` | **no** (kernel calls `ck_commit()` directly, `core/report.c` `ck_report_header`) |
| 112 | | end | total size 112 bytes (hand derived) | | |

### 3.1 Inputs the task asked about that are not in the record

| Input | Status today | Where it comes from instead |
| --- | --- | --- |
| Version field | **MISSING** as a field. The version is the trailing `1` inside the magic `CHANDOF1` (`handoff.h:9`). PROPOSED rule: a new layout gets a new magic (`CHANDOF2`, ...); there is no separate version number. | |
| Record size field | **MISSING.** PROPOSED: not added in v1 (adding it changes the frozen layout); the magic fixes the size at 112. | |
| DTB pointer | **MISSING.** The C kernel is ACPI only (no `fdt`/`dtb` symbol anywhere in `native/`). Not part of v1. | |
| Framebuffer (GOP) | **MISSING** in `ck_handoff`. The Rust loader captures one (`crates/aienos-boot/src/handoff.rs:1170-1178`, type `crates/aienos-kernel/src/display/mod.rs:22-30`), the C stub does not. Not part of v1. | |
| Console UART | Not in the record. The stub parses SPCR and configures the console **inside the shared image** (`efi_main.c:91-95`); the kernel inherits that state through static variables, not through the record. A separately linked kernel would get no console. **MISSING** for that case. | |
| Entropy | Not in the record. The kernel probes `RNDR` itself and fails closed (`kmain.c:121-132`, `arch/rndr.c`). No loader-supplied seed; PROPOSED: never accept one (a loader seed would be an unverified input). | |
| Owner key material (after #215) | Not in the record. Owner **public** keys and machine id are compiled into the hardware staging image at build time (`native/kernel/Makefile:97-125`, `CK_OWNER_PUBKEYS`, `CK_MACHINE_ID`). PROPOSED: the handoff never carries key material. | |
| Boot disk identity | **MISSING.** The kernel binds the first PCI function of class `0x010802` (`native/kernel/dev/nvme_bind.c:141`) and calls it the boot disk (`dev/devices.c:12`). The loader does not tell the kernel which disk it booted from. | |
| Image / artifact info | Image range only (`image_base`/`image_end`). Artifacts are read by the kernel from the boot disk Store (`kmain.c:141-144`), not passed by the loader. | |
| Boot attempt / rollback state | **MISSING**, and PROPOSED to stay out of the record (section 7). | |

## 4. CPU state at entry

| Property | State | Source |
| --- | --- | --- |
| Exception level | the firmware EL, EL2 or EL1. EL2 -> `ck_enter_el1`, EL1 -> `ck_switch_el1`, anything else panics `kernel entry at unsupported EL%u` | CODE `kmain.c:163-186` |
| MMU | the firmware's translation regime, unchanged by the stub; its TTBR0/SCTLR are recorded | CODE `efi_main.c:66-72` |
| Address map | identity (VA = PA) for the image, the record, the map copy and the stack | CODE relies on it (`mm/mmu.c:110-196` uses physical addresses as pointers); UEFI requires an identity map on AArch64 (UEFI spec section 2.3.6, UNVERIFIED in this cut, confidence high) |
| Caches | firmware state, not changed by the stub; the kernel cleans and invalidates its DMA pool before changing attributes | CODE `mm/mmu.c:173-186` |
| Interrupts (DAIF) | **not masked by our code before the kernel switches regime**: no `daifset` in `native/boot/`; the actual value at entry is whatever the firmware left (UEFI runs boot services with interrupts enabled, UNVERIFIED in this cut, confidence medium-high). The kernel masks all four (`msr daifset, #0xf`) only in `ck_enter_el1`/`ck_switch_el1` (`arch/vectors.S:176,233`), after `ck_mm_build`. PROPOSED rule: the loader masks DAIF before the call; the kernel masks DAIF as its first instruction (open item, section 10). | |
| Vectors | the firmware's until the kernel writes `VBAR_EL2`/`VBAR_EL1` | CODE `kmain.c:164-168` |
| Boot services | gone: `ExitBootServices` succeeded before the call; on failure the stub returns to firmware and never calls the kernel | CODE `efi_main.c:115-144` |
| Runtime services | not used by the C stub or the kernel (`RuntimeServices` appears only in the type `efi.h:90`) | CODE (grep) |
| Watchdog | disabled by the stub (`SetWatchdogTimer(0,...)`) | CODE `efi_main.c:82-83` |
| Other CPUs | not started (single core) | CODE `core/m3.c:12` comment "Single core" |

## 5. Memory ownership and fencing

**Owned by the kernel after the call:** every `EfiConventionalMemory`
descriptor in the map copy (`mm/frames.c:93-108`), minus the reserved ranges
below. The kernel maps (but does not hand out) RAM types 1-7, 9, 10, 14 with
the WB attribute (`mm/mmu.c:56-59,130-143`).

**Must stay intact and is reserved by the kernel** (`mm/mmu.c:118-125`):
the image `[image_base, image_end)`, the record itself, the map copy
`[memory_map, memory_map + map_size)`, and every ACPI table reachable from
`rsdp`.

**Loader obligations (frozen):**

1. `ExitBootServices` returned success with the key of the map in the
   record (CODE `efi_main.c:117-135`). No boot-service call after that.
2. The map copy is the final map, at most 64 KiB in the C stub
   (`efi_main.c:14`). PROPOSED rule for any loader: at most 64 KiB.
3. The record, the map copy and every page the record points at lie inside
   memory typed `EfiLoaderCode`/`EfiLoaderData` or ACPI types, never inside
   `EfiConventionalMemory` (otherwise the allocator hands them out). CODE
   reserves them explicitly anyway (`mm/mmu.c:118-120`), so a violation is
   survived today but is a contract breach.
4. **DMA:** the loader has no means to fence devices after
   `ExitBootServices`; UEFI drivers are expected to stop DMA on that event
   (UEFI spec, UNVERIFIED in this cut). The kernel does **not** fence
   firmware-left DMA at entry: the SMMU is brought up lazily on the first
   `ck_dma_confine` in the devices stage (`core/smmu_svc.c:57-95`, global
   abort latched in `ck_smmu_enable`, `core/smmu.c:261-266`). Between the
   handoff and that point an uncontained device could still write RAM.
   **GAP, MISSING:** PROPOSED rule: the kernel sets `GBPA.ABORT` on every
   SMMU named by the IORT and clears bus master on every PCI function it
   does not own before the first frame allocation. `GBPA` only governs traffic while `CR0.SMMUEN` is 0, so if the firmware left an SMMU enabled the rule must also latch `GBPA.ABORT` and then clear `SMMUEN` (the order `ck_smmu_enable` already uses on its failure path, `core/smmu.c:265-273`). Until a cut does that,
   the contract records the window, it does not claim it closed.

## 6. What the kernel must refuse, and its serial lines

The kernel reports refusals through `ck_panic`, which prints a report header
and `panic: <reason>` on the UART set up from SPCR, then resets through PSCI
(`core/report.c:63-77`, header `core/report.c:20-24`):

```
report_version: 1
aienos_commit: <commit>
report_kind: panic
last_stage: <stage>
panic: <reason>
```

| Condition | Today | Required line |
| --- | --- | --- |
| `h == NULL` | **not checked**: `kmain.c:174` dereferences | PROPOSED `panic: handoff: null record` |
| bad magic | CODE `kmain.c:174-175` | `panic: handoff: bad magic` (exists, frozen) |
| unknown newer magic `CHANDOF<n>` | refused as bad magic (same line) | PROPOSED `panic: handoff: unsupported version <n>` |
| `reserved0 != 0` | **not checked** | PROPOSED `panic: handoff: reserved field nonzero` |
| `desc_size < 40` or not a multiple of 8 | partly: `< 40` makes `ck_frames_from_efi` return -1 and the kernel panics `mm: no usable memory in the UEFI map` (`mm/frames.c:95`, `mm/mmu.c:113-116`) | PROPOSED `panic: handoff: bad descriptor size <n>` |
| `desc_version != 1` | **not checked** | PROPOSED `panic: handoff: bad descriptor version <n>` (value 1 per UEFI `EFI_MEMORY_DESCRIPTOR_VERSION`, UNVERIFIED in this cut) |
| `map_size == 0`, `map_size % desc_size != 0`, `map_size > 65536` | **not checked** (loop just stops, `mm/mmu.c:130`) | PROPOSED `panic: handoff: bad map size <n>` |
| `memory_map == 0` | partly (`mm/frames.c:95` refuses NULL, generic panic) | PROPOSED `panic: handoff: missing memory map` |
| `image_base >= image_end`, or not 4 KiB aligned | **not checked** | PROPOSED `panic: handoff: bad image range` |
| two map descriptors overlap | **not checked** | PROPOSED `panic: handoff: overlapping map descriptors` |
| record, map copy or image overlaps `EfiConventionalMemory` | **not checked** (survived by reservation, `mm/mmu.c:118-120`) | PROPOSED `panic: handoff: record region in free memory` |
| `rsdp == 0` | **not refused**: boot continues, then panics later `gic: no usable ACPI MADT` (`kmain.c:87-90`) | PROPOSED `panic: handoff: missing rsdp` |
| `firmware_el` not 1 or 2 | CODE `kmain.c:186` uses live `CurrentEL`, not the field | PROPOSED `panic: handoff: firmware_el mismatch` when the field disagrees with live `CurrentEL` |

Every PROPOSED check runs **before** `ck_mm_build` (before the first frame
is handed out) and after the vectors are installed, so a refusal can print.

## 7. Rollback without A/B slots

There are no slots and, per Q3, none will be added to this loader. Rollback
is the firmware's **one-time BootNext** rule, already the subject of
`docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md` (section 2 invariant: "A candidate may
consume exactly one boot attempt. It may never promote itself into the
persistent default boot path."):

1. A stager writes `BootNext` = the candidate entry; `BootOrder` is not
   changed (`docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md` section 3.2).
2. Firmware deletes `BootNext` before starting the candidate (same document
   section 3.3, citing UEFI section 3.1.1).
3. The candidate is the **C kernel image** (stub + kernel, one PE). It never
   touches UEFI variables: the C path has no runtime-service calls (section
   4). Its end states fall in two groups:
   - **Reset** (after `ExitBootServices`): normal end `ck_reset`
     (`kmain.c:157`); refusal or panic `ck_panic` -> `ck_reset`
     (`core/report.c:63-77`); CPU fault `ck_fault_report` -> `ck_reset`
     (`core/report.c:79-89`); hang -> external watchdog or operator reset
     (the stub disables the UEFI watchdog, `efi_main.c:82-83`, so a hang
     after `ExitBootServices` needs an outside reset).
   - **Return to firmware** (boot services still alive, the kernel never
     ran): `GetMemoryMap` failure returns its status (`efi_main.c:121-124`);
     `ExitBootServices` failing 8 times returns its status
     (`efi_main.c:136-139`); an unexpected relocation type returns
     `EFI_LOAD_ERROR` from the entry code (`native/boot/efi_entry.S:32-35`).
     Control goes back to the firmware boot manager, which continues with
     the next `BootOrder` entry or its boot menu
     (`docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md` section 3.4, "drops to the
     next option in `BootOrder` or returns to BDS"). `BootNext` was already
     consumed (step 2) and nothing was written, so rollback still holds.
     NOT_RUN: no test drives these three paths today.
4. The next boot therefore follows the unchanged `BootOrder`: the previous
   default. That **is** the rollback. "Previous good" means "the default
   entry the operator set", nothing the candidate wrote.
5. The handoff record carries no rollback state, and PROPOSED: never will.
   A kernel that could see or change attempt counters could promote itself.

### 7.1 What M0_ROLLBACK rows 42-46 must become

Today they test the Rust mock candidate and are NOT_RUN for the C path
(`native/kernel/GATES.md` rows 42-46). How the script works now
(`scripts/qemu_native_rollback_test.sh`): one Rust program,
`aienos-rollback-mock` (built at line 36), is copied in as stager
(`BOOTAA64.EFI`), candidate (`candidate.efi`) and default (`default.efi`)
(e.g. lines 78-80). Each subtest writes a mode word to
`\EFI\AIENOS\ROLLBACK_MODE.TXT` (lines 81, 128, 160, 221, 250, 277); the
mock reads it both to stage and to choose how the candidate behaves
(`crates/aienos-boot/src/rollback_mock.rs:91-93,184-186`). The pass
conditions grep markers that only the mock prints as candidate:
`AIENOS_CANDIDATE: NORMAL_TERMINATION_REQUESTED` (line 105),
`AIENOS_CANDIDATE: INDUCED_FAULT_PANIC` (line 138),
`ENTERING_HANG_SPIN_LOOP` (line 181, the cue for the forced reset).

The C image reads no mode file and prints none of those markers. So the C
path needs script changes. All of the following is PROPOSED (MISSING in
code); the Rust mock stays as stager and default (Q3: preserve the existing
tests, the current Rust-mock run keeps its own markers):

| Row | Becomes | Script change needed (PROPOSED) | Kernel/build change needed (PROPOSED) |
| --- | --- | --- | --- |
| 42 | `NATIVE_ROLLBACK_NORMAL`: BootNext starts the C image, it ends with the `final` report and resets; next boot is Default | copy the normal C image as `candidate.efi`; replace the line 105 grep with C markers (`report_kind: final` and `note: QEMU qualifies nothing physical`, `kmain.c:154-156`) | none; but whether every stage reaches `final` on this script's QEMU line (no NVMe disk, no `iommu=smmuv3`) is UNVERIFIED, the store stage may print `FAIL` (reported, not fatal: `kmain.c:23-36`) |
| 43 | `NATIVE_ROLLBACK_FAULT`: the C image refuses its handoff and resets; next boot is Default | per-subtest candidate = the TEST bad-magic image; replace the line 138 grep with `report_kind: panic` and `panic: handoff: bad magic` | a TEST-only build flag that corrupts the magic, refused by `CK_HARDWARE_STAGING` |
| 44 | `NATIVE_ROLLBACK_TIMEOUT`: TEST-only C image hangs after `ExitBootServices`, host forces reset; next boot is Default | per-subtest candidate = the TEST hang image; replace the line 181 cue with a C hang marker printed before the spin | a TEST-only hang flag (prints one marker, then spins with DAIF masked), refused by `CK_HARDWARE_STAGING` |
| 45 | `NATIVE_ROLLBACK_REJECTED` and absent image | none: the malformed file (line 219, junk bytes) and the absent file never run, so the C image is not involved; the row only moves with the rest of the gate | none |
| 46 | `NATIVE_ROLLBACK_BOOTNEXT_CONSUMED` / `_DEFAULT_UNCHANGED` | copy the normal C image as `candidate.efi` in subtest 6 (lines 270-276); the pass greps are on Default-boot logs printed by the mock (lines 286-292) and stay | none |

Also PROPOSED for the script: build the C images itself (via
`native/kernel` make targets) next to the mock build at line 36, and run the
C variant as a separate labelled mode so the Rust-mock result is not
replaced. All five rows stay **NOT_RUN** until a forge receipt covers them.
QEMU only; Machine 1 is NOT_RUN.

## 8. Frozen forever vs extensible

**Frozen (v1, `CHANDOF1`):** the magic value; the 112-byte layout and every
offset in section 3; the meaning of every field; `x0` = record address;
`ExitBootServices` done before the call; the reserved-range rules in
section 5; the `panic: handoff: bad magic` line; "no rollback state and no
key material in the record".

**Extensible only by a new magic (PROPOSED):** any added field (framebuffer,
boot disk identity, UART, a record size field) means a new struct with a new
magic `CHANDOF2`; the kernel accepts exactly the magics it was built for and
refuses the rest with the `unsupported version` line. No in-place growth of
v1, no use of `reserved0` for data (it must stay zero).

## 9. Negative tests the follow-up code cut must add

Host unit tests (no QEMU) against a PROPOSED pure validator, each with the
exact refusal line from section 6:

1. NULL record.
2. Magic off by one bit; magic `CHANDOF2`.
3. `reserved0 = 1`.
4. `desc_size` 0, 39, 41 (not a multiple of 8).
5. `desc_version` 0 and 2.
6. `map_size` 0, not a multiple of `desc_size`, 65544.
7. `memory_map = 0` with `map_size > 0`.
8. `image_base == image_end`; `image_base > image_end`; unaligned base.
9. Two descriptors that overlap by one page.
10. Record address inside an `EfiConventionalMemory` descriptor.
11. `rsdp = 0`.
12. `firmware_el = 3`.
13. Positive control: the record `efi_main.c` builds on QEMU passes.

QEMU (TEST-only builds, refused by `CK_HARDWARE_STAGING`):

14. Corrupted magic image prints `panic: handoff: bad magic` and resets.
15. Rows 42-46 per section 7.1.

Layout:

16. `_Static_assert` on `sizeof(struct ck_handoff) == 112` and on every
    offset in section 3, so a field reorder fails the build.

## 10. Open items (not decided here)

- Whether a non-C loader (Rust or Atlas) ever starts a separately linked
  C kernel. Today it cannot (section 2, separate entry MISSING); Q3 freezes
  loader expansion, so this stays open until Atlas/TRUST-1.
- The DMA window between handoff and SMMU bring-up (section 5, item 4).
- Boot disk identity: binding "first NVMe class device" (`nvme_bind.c:141`)
  is not the same as "the disk the firmware booted from".
- DAIF at entry: neither the stub nor the first kernel instructions mask
  interrupts today (section 4); the PROPOSED rule needs its own small cut.
- `native/boot/efi_main.c:8-9` (comment) says the Rust `aienos-boot` crate
  holds "A/B slots"; that contradicts ADR 0024 Q3 and the crate. A code
  comment, out of scope for this docs change; the follow-up validator cut
  should correct it.
