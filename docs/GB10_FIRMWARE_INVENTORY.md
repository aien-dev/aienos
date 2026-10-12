# GB10 firmware inventory (aienos#286 cut C, host work only)

Report plus one hosted checker. No firmware was loaded, no device was touched,
no QEMU run was made. This is the "inventory of firmware and protocol sources,
parsers and refusal tests for firmware metadata. No loading" item of
docs/GB10_NATIVE_DEPENDENCY_MAP.md section 7. Any firmware load or GSP handoff
on the real machine stays an OPERATOR STEP (same document, section 7).

Tags: [OBSERVED] read on the Spark (spark-b87b, Linux 7.0.0-1019-nvidia,
nvidia-open 580.173.02) on 2026-10-12. [SOURCE file:line] read in the named
file of NVIDIA/open-gpu-kernel-modules at tag `580.173.02` (the same version as
the driver on the box; fetched read-only into a scratch directory, not vendored).
[DOCUMENTED] quoted from a licence or manual. [INFERRED] reasoned from sources.
[UNKNOWN] nothing read answers it.

## 1. Plain-English summary

- The GPU in the Spark is NVIDIA's "GB10B" chip (the integrated variant of the
  GB10 family). To run it, three pieces of NVIDIA code have to be put in place
  in a fixed order: a small signed "first stage" (GSP-FMC) that the SEC2
  security engine on the chip verifies and starts, which then unpacks and starts
  the big GSP-RM firmware (the GPU's own resource manager, 75 MB on disk), after
  which the host talks to the GPU through message queues the GSP-RM serves.
- Only the big piece is a file on disk. The first stage, its hash, its signature
  and its public key are compiled into the Linux driver module as byte arrays
  (open source, MIT licence, in the public driver repository). The GB10B has no
  separate "FSP" security processor on the GSP boot path and runs no VBIOS
  FWSEC step; SEC2 does the work. [SOURCE, section 4]
- Everything AIENOS would need to *hand* to the chip is public and
  redistributable unmodified under NVIDIA's firmware licence and the driver's
  MIT licence. What is not public is what the chip's boot ROM, SEC2 firmware,
  ACR and GSP-RM *do* internally, and the signing keys. [DOCUMENTED, section 6]
- A hosted checker now exists: `make -C native/kernel gsp-fw-inspect-test`
  (tool native/kernel/tools/ck_gsp_fw_inspect.c). It parses the firmware
  container exactly as the driver does, refuses every malformed shape it was
  given in its self-test (22 mutations plus every truncation), and proves the
  file on this box matches the pinned digest. It never loads anything.
- The largest remaining unknowns for a native bring-up (section 8) are the
  SEC2 command protocol details beyond what the driver source shows, the
  exact GspFwWprMeta/boot-argument layout expected by this GSP-FMC build, and
  the state the SoC firmware (UEFI) leaves SEC2 and the GPU in at AIENOS entry.
  Do not attach a calendar to cut C/D until those are measured on the machine.

## 2. Identity of the device and the driver on the box [OBSERVED]

| Fact | Value |
|---|---|
| PCI address, id | `000f:01:00.0`, 10de:2e12 rev a1, subsystem 10de:21ec |
| Driver's supported-gpus entry | `{"devid":"0x2E12","subdevid":"0x21EC","subvendorid":"0x10DE","name":"NVIDIA GB10","features":[...,"kernelopen"]}` |
| nvidia-smi | Product NVIDIA GB10, Architecture Blackwell, VBIOS 9A.0B.2D.00.00, driver 580.173.02 |
| /proc/driver/nvidia/gpus/*/information | GPU Firmware 580.173.02, Video BIOS 9a.0b.2d.00.00, DMA 41 bits, IRQ 427 |
| Kernel module | /lib/modules/7.0.0-1019-nvidia/kernel/nvidia-580-open/nvidia.ko, 19,231,198 bytes, `license: Dual MIT/GPL`, declares `firmware: nvidia/580.173.02/gsp_ga10x.bin` and `firmware: nvidia/580.173.02/gsp_tu10x.bin` (modinfo) |
| Chip arch/impl in the driver | GB10B is `GPU_ARCHITECTURE_BLACKWELL_GB1XX` (0x01A0) implementation `GPU_IMPLEMENTATION_GB10B` (0x0B) [SOURCE src/common/inc/swref/published/nv_arch.h:51,111] |

## 3. The firmware pieces, their identity and where each one lives

### 3.1 GSP-RM container on disk (the only file-based piece)

Package `nvidia-firmware-580-580.173.02`, directory `/lib/firmware/nvidia/580.173.02/`. [OBSERVED]

| File | Bytes | SHA-256 | Used by GB10? |
|---|---|---|---|
| gsp_ga10x.bin | 75,012,080 | `32cb7cf3e77f97e92f6e92135939ccb3ba382748144569c0dfccf3338d43d963` | yes (section 3.2) |
| gsp_tu10x.bin | 30,471,256 | `6f3ccbd570c7ac2a7ea910d9d87fc3d23db9ae3dfe82020ea07b17a30954495e` | no (Turing/GA100 only) |

Container layout of gsp_ga10x.bin, as printed by `ck_gsp_fw_inspect inspect`
[OBSERVED]: ELF64, little-endian, type REL, machine RISC-V, 17 sections.

| Section | Offset | Size | Note |
|---|---|---|---|
| .fwimage | 64 | 74,969,088 | GSP-RM image; SHA-256 `931add19204a5f0240442272f58fb2bc5db6cec4dd6f6341c1d888754146aa07` |
| .note.gnu.build-id | 74,969,152 | 36 | NT_GNU_BUILD_ID `b96f53b91f7ff27613d8afe25762756a42a4dc1e` |
| .fwversion | 74,969,188 | 11 | `580.173.02` plus NUL |
| .fwsignature_gb20y, _cc_gb20x, _gb20x, _cc_gb10x, **_gb10y**, _gb10x, _cc_gh100, _gh100, _ad10x, _ga10x | 74,969,199 onward | 4,096 each | one per chip family; GB10B uses `.fwsignature_gb10y`, SHA-256 `08541c3a909f8fd21c3eaf55fbe6c6c30ff2b7729e885417f3fcb06a4d108f2d` |
| .symtab, .strtab, .shstrtab | 75,010,160 onward | 96, 466, 265 | ELF bookkeeping |

### 3.2 How the driver picks that file and that signature section [SOURCE]

- File name: `#define NV_FIRMWARE_FOR_NAME(name) "nvidia/" NV_VERSION_STRING "/" name ".bin"` [kernel-open/nvidia/nv.c:27]; loaded with `request_firmware(&fw, nv_firmware_for_chip_family(fw_type, fw_chip_family), nvl->dev)`, "path is relative to /lib/firmware" [nv.c:4058-4062].
- Chip family: `case GPU_ARCHITECTURE_BLACKWELL_GB1XX: if (gpuImpl == GPU_IMPLEMENTATION_GB10B) return NV_FIRMWARE_CHIP_FAMILY_GB10Y; else return NV_FIRMWARE_CHIP_FAMILY_GB10X;` [src/nvidia/arch/nvalloc/common/inc/nv-firmware-chip-family-select.h:58-62]. Family string: `case NV_FIRMWARE_CHIP_FAMILY_GB10Y: return "gb10y";` [kernel-open/common/inc/nv-firmware.h:63].
- File for the family: GB10X, GB10Y, GB20Y, GB20X, GH100, AD10X all `return NV_FIRMWARE_FOR_NAME("gsp_ga10x");` [nv-firmware.h:95-102]; GA100, TU11X, TU10X get `gsp_tu10x` [nv-firmware.h:104-107]. So the file is `nvidia/580.173.02/gsp_ga10x.bin`.
- Section names: `GSP_VERSION_SECTION_NAME ".fwversion"`, `GSP_IMAGE_SECTION_NAME ".fwimage"`, `GSP_SIGNATURE_SECTION_NAME_PREFIX ".fwsignature_"`, `GSP_BUILD_ID_SECTION_NAME ".note.gnu.build-id"`, `GSP_CC_SIGNATURE_SECTION_NAME_PREFIX ".fwsignature_cc_"` [src/nvidia/generated/g_kernel_gsp_nvoc.h:269-274].
- Signature prefix for GB10B: the HAL table assigns `kgspGetSignatureSectionNamePrefix_GB100` to "GB100 | GB102 | GB10B | ..." [g_kernel_gsp_nvoc.c:1809-1813]; that function returns the `_cc_` prefix only when confidential computing is enabled, else `GSP_SIGNATURE_SECTION_NAME_PREFIX` [src/nvidia/src/kernel/gpu/gsp/arch/blackwell/kernel_gsp_gb100.c:94-108]. The section name is prefix + family [kernel_gsp.c:4805-4840]. Confidential computing is not enabled on this box [INFERRED (high): nvidia-smi reports no CC mode; not separately verified], so the section is `.fwsignature_gb10y`.
- Version check: `.fwversion` must be nonzero, shorter than 64 bytes, NUL-terminated and equal to `NV_VERSION_STRING`, else `NV_ERR_INVALID_DATA` [kernel_gsp.c:4762-4786].
- Section lookup bounds checks: ELF identifier, section header table validity, name index inside the names table, `portSafeAddU64(offset, size - 1)` inside the buffer [kernel_gsp.c:5115-5166].
- What the driver then does with the pieces (not reproduced here): copies the signature into its own memory descriptor (`_kgspCreateSignatureMemdesc`), builds a radix-3 page table over `.fwimage` for the GSP's DMA (`kgspCreateRadix3`), keeps the build id [kernel_gsp.c:4871-4905].

### 3.3 GSP-FMC first stage and the boot descriptor, compiled into the driver [SOURCE]

The driver embeds these as C byte arrays ("bindata") with an MIT licence header
("THIS FILE IS AUTOMATICALLY GENERATED"). For GB10B the HAL table selects
`kgspGetBinArchiveGspRmBoot_GB10B` [g_kernel_gsp_nvoc.c:788-790] and
`kgspGetBinArchiveGspRmFmcGfwProdSigned_GB10B` [g_kernel_gsp_nvoc.c:924-926]
(debug-fused parts use the `...DebugSigned_GB10B` archive, [889-891]).

| Archive label | Original file name (NVIDIA internal) | Bytes |
|---|---|---|
| GspRmBoot_GB10B UCODE_IMAGE_PROD | kernel/inc/gspcc/bin/g_gsp_gb10b_dyn_prd_image.bin | 196,608 |
| GspRmBoot_GB10B UCODE_DESC_PROD | kernel/inc/gspcc/bin/g_gsp_gb10b_dyn_prd_desc.bin | 84 (RM_RISCV_UCODE_DESC) |
| GspRmBoot_GB10B UCODE_IMAGE_DBG / DESC_DBG | ..._dbg_image.bin / ..._dbg_desc.bin | 196,608 / 84 |
| GspRmFmcGfwProdSigned_GB10B UCODE_IMAGE | kernel/inc/gspcc/bin/g_gsp_gb10b_dyn_prd_gfw_image.bin | 195,912 |
| GspRmFmcGfwProdSigned_GB10B UCODE_HASH | g_gsp_gb10b_dyn_prd_gfw_hash.bin | 48 (SHA-384) |
| GspRmFmcGfwProdSigned_GB10B UCODE_SIG | g_gsp_gb10b_dyn_prd_gfw_sig.bin | 384 |
| GspRmFmcGfwProdSigned_GB10B UCODE_PKEY | g_gsp_gb10b_dyn_prd_gfw_pub_key.bin | 384 |

Source files: `src/nvidia/generated/g_bindata_kgspGetBinArchiveGspRmBoot_GB10B.c`
(2,466,261 bytes of C) and
`g_bindata_kgspGetBinArchiveGspRmFmcGfwProdSigned_GB10B.c` (1,238,060 bytes),
metadata comments at lines 31-40 and the storage records near the end of each
file. The README says the `nouveau/` script "is used to extract some of the
firmware binary images (and related data) encoded in the source code and store
them as distinct files. These files are used by the Nouveau device driver"
[README.md:170-173]; that script knows gh100, gb100 and gb202 FMC images, not
gb10b [nouveau/extract-firmware-nouveau.py:655-662,775-781]. Extracting the
GB10B arrays would be our own small step over the same public source.
[INFERRED (high)]

### 3.4 Pieces that are NOT on the host side at all

- SEC2's own firmware and the chip boot ROM: not loaded by the driver on GB10B.
  The driver only sends SEC2 commands through its EMEM queue (section 4). Who
  loads SEC2 firmware before Linux starts (SoC boot chain, UEFI) is [UNKNOWN]
  from these sources.
- ACR (the access-control ucode that sets up the protected region WPR2) and
  anything inside GSP-FMC and GSP-RM: NVIDIA binaries, run on the chip, not
  readable by us (licence section 6).
- Booter Load/Unload ucodes (older dGPU path) and VBIOS FWSEC: not used on
  GB10B (section 4).

## 4. The loading path the pinned driver uses on GB10B [SOURCE]

This is the order the native kernel would have to reproduce. Only the parts
visible in the open driver are listed; what the chip does in between is
inferred from the driver's comments.

1. **No FSP on this chip.** `PDB_PROP_KFSP_IS_MISSING` is false only for
   "GH100 | GB100 | GB102 | GB110 | GB112 | GB202 | GB203 | GB205 | GB206 |
   GB207"; GB10B falls to the default, true [g_kern_fsp_nvoc.c:227-236].
2. **SEC2 boots the GSP-FMC.** `PDB_PROP_KSEC2_BOOT_GSPFMC` is true exactly for
   "GB10B | GB20B | GB20C" [g_kernel_sec2_nvoc.c:446-450]. The GSP code takes the
   SEC2 branch when there is no FSP: `ksec2PrepareBootCommands_HAL`
   [kernel_gsp_gh100.c:803-808] and "Starting to boot GSP via SEC2" then
   `ksec2SendBootCommands_HAL` [kernel_gsp_gh100.c:868-872].
3. **No VBIOS FWSEC step.** `kgspExtractVbiosFromRom` for GB10B is the stub
   `_395e98` [g_kernel_gsp_nvoc.c:1300], which returns `NV_ERR_NOT_SUPPORTED`
   [g_kernel_gsp_nvoc.h:1803-1805]; the init code treats that as "Extracting
   VBIOS image from ROM is not supported" and continues [kernel_gsp.c:4053-4058].
   The VBIOS version string nvidia-smi shows therefore comes from elsewhere
   (GSP-RM at runtime) [INFERRED (medium)].
4. **No Booter ucodes.** `bPartitionedFmc` is true for "GH100 | GB100 | GB102 |
   GB10B | ..." [g_kernel_gsp_nvoc.c:447-451]; with it set, "The secure boot
   ucode is included in the partitioned FMC, no need for separate Booter
   ucodes" [kernel_gsp.c:4076-4082].
5. **Host-side preparation** (`kgspInitRm`): prepare the boot binary (copy the
   GspRmBoot image into 4 KiB-aligned system memory flagged
   `MEMDESC_FLAGS_ALLOC_IN_UNPROTECTED_MEMORY`, keep the 84-byte descriptor)
   [kernel_gsp.c:4583-4640]; prepare the GSP-RM image (version check, `.fwimage`,
   signature section, radix-3 page table, build id) [kernel_gsp.c:4848-4905];
   logging structures; wait for `GFW_BOOT` OK (`kgspWaitForGfwBootOk_HAL`); set
   GPU time; libos init args and message-queue init args [kernel_gsp.c:4108-4165].
6. **WPR meta for an integrated GPU.** `kgspPopulateWprMeta_GB10B` reuses the
   GH100 layout, then sets `vgaWorkspaceSize = 0`, `pmuReservedSize = 0`,
   `nonWprHeapSize = 0`, with the comment "For GB10Y, unlike on dGPU, this
   structure is in sysmem" and the WPR2 layout diagram (WPR/LSB header, ACR
   metadata, GSP FW heap, GSP FW ELF, boot bin) [kernel_gsp_gb10b.c:32-90].
   "The actual offsets are determined by secure ACR ucode and patched into the
   GspFwWprMeta structure" [kernel_gsp_gb10b.c:33-35].
7. **SEC2 command.** `ksec2SetupGspImages_GB10B` copies the FMC image into
   system memory, writes its physical address into an `NVDM_PAYLOAD_COT`
   (`gspFmcSysmemOffset`, `frtsSysmemSize` = image size), copies the 48-byte
   hash, the 384-byte signature and the 384-byte public key into the payload,
   and points `gspBootArgsSysmemOffset` at the cached GSP-FMC arguments
   [kernel_sec2_gb10b.c:438-535]. `ksec2PrepareBootCommands_GB10B` allocates
   the payload with `version = cotPayloadVersion` [561-583];
   `ksec2SendBootCommands_GB10B` sends it as `NVDM_TYPE_COT` through
   `ksec2SendMessage` [612-623]. Transport: an MCTP/NVDM packet written a DWORD
   at a time into SEC2 EMEM channel 0 (1 KiB) via `NV_PSEC_EMEMC`/`NV_PSEC_EMEMD`,
   then queue head/tail writes (`NV_PSEC_QUEUE_TAIL` before `NV_PSEC_QUEUE_HEAD`
   "because it will interrupt SEC2") [kernel_sec2_gb10b.c:36-210]. Register
   definitions come from `published/blackwell/gb10b/dev_sec_pri.h`,
   `dev_gsp.h`, `dev_falcon_v4.h` [kernel_sec2_gb10b.c:30-32].
8. **Wait and hand over.** Wait for SEC2 to release the GSP target mask
   (`ksec2WaitForGspTargetMaskReleased_HAL`), then for lockdown release or an
   FMC error in `NV_PFALCON_FALCON_MAILBOX0`, program `NV_PFALCON_FALCON_OS`
   with the descriptor's `appVersion`, confirm the RISC-V core is active, init
   the status queue, wait for `kgspWaitForRmInitDone` [kernel_gsp_gh100.c:874-982].
   From then on the host talks to GSP-RM over the RPC message queues.
9. **Teardown and reset.** `kgspResetHw_GB100` (waits for reset access, then
   resets the engine) [kernel_gsp_gb100.c:46-88]; `kgspTeardown_GH100`
   [kernel_gsp_gh100.c:995]. Not read in detail here.

## 5. Hosted checker: ck_gsp_fw_inspect

`native/kernel/tools/ck_gsp_fw_inspect.c`; Makefile targets `gsp-fw-inspect`
and `gsp-fw-inspect-test` (the latter is part of `make -C native/kernel test`,
so CI runs the self-test on every PR; the real-file step prints NOT_RUN when
`/lib/firmware/nvidia/580.173.02/gsp_ga10x.bin` is absent, as it is in CI).

- `inspect FILE [--family NAME] [--expect-version V]`: the driver's checks
  from section 3.2 plus a bounds check on the build-id note, then SHA-256 of the
  whole file, of `.fwimage` and of the selected signature section. Exit 0 and
  `RESULT OK`, or exit 2 and `RESULT REFUSED <reason>`.
- `selftest`: a 640-byte valid container built in memory, then 22 single-field
  mutations (bad magic, 32-bit, big-endian, wrong type, wrong machine, wrong
  shentsize, zero sections, shstrndx out of range, table past end, string
  table without NUL, name index past table, section past end, offset overflow
  near 2^64, empty image, version without NUL, version text mismatch, 64-byte
  version, empty signature, signature for another family only, wrong note
  type, descriptor past section, truncated note) plus every truncation from 0
  to 639 bytes; each must be refused for the named reason.
- Result on the box, 2026-10-12 [OBSERVED]: `CK_GSP_FW_INSPECT_SELFTEST: PASS
  (22 mutations)`; `CK_GSP_FW_INSPECT_PIN: PASS` with the file digest equal to
  the pin in the Makefile (`GSP_FW_SHA256`).
- It does not verify NVIDIA's signature over `.fwimage` (that is the chip's
  job; format and keys are not ours) and it never loads anything.

## 6. Licence limits [DOCUMENTED]

Firmware package: `/usr/share/doc/nvidia-firmware-580-580.173.02/copyright`,
"License: NVIDIA-graphics-drivers" (NVIDIA Driver License Agreement):

- 1.1(d): may "Distribute the SOFTWARE ... for use with operating system
  kernels distributed under the terms of an OSI-approved open source license
  ... provided that (i) the binary files thereof are not modified in any way
  ... and (ii) this Agreement is provided to each SOFTWARE recipient". AIENOS is
  AGPL-3.0, an OSI-approved licence, so shipping the unmodified file plus the
  agreement text is within this clause [INFERRED (high): plain reading, not
  legal advice].
- 2.1: firmware only on NVIDIA platforms; no translation to another
  architecture or language. 2.2: no reverse engineering, decompiling or
  disassembly of binaries. 2.3: no derivative works of binaries. 2.6: no
  bypassing authentication or security mechanisms. 2.9: may not cause the
  SOFTWARE to become subject to an open source licence.
- Consequence for this project: we may ship and load the bytes as they are,
  parse their public container format (the driver does exactly that, in MIT
  source), and must never patch, unpack `.fwimage`, or work around the
  signature checks. A SEC2 refusal is final and is reported, never bypassed.

Driver source: `COPYING` says "Except where noted otherwise, the individual
files within this package are licensed as MIT"; every file read here carries
`SPDX-License-Identifier: MIT` (including the bindata arrays and
`kernel_sec2_gb10b.c`). The kernel module reports `Dual MIT/GPL`. Reading and
reimplementing the host-side protocol from MIT source is permitted; copying
code into AIENOS would require carrying the MIT notice (none was copied here).

## 7. What this means for cut C and cut D

- Cut C "inventory" is done by this document; "parsers and refusal tests for
  firmware metadata" by `ck_gsp_fw_inspect`. The next host-only steps that do
  not need the machine: (a) a small extractor over the two public
  `g_bindata_*_GB10B.c` files that writes the eight arrays as files with
  digests (our own tool, no Python); (b) a C struct definition and encoder for
  `NVDM_PAYLOAD_COT` and the MCTP/NVDM headers with fixture tests, from
  `src/nvidia/inc/kernel/gpu/fsp/kern_fsp_cot_payload.h`,
  `fsp/fsp_nvdm_format.h`, `fsp/fsp_mctp_format.h` (not yet read); (c) the
  `GspFwWprMeta` and GSP-FMC argument layouts from the same source tree.
- The machine-side part of cut C (first SEC2 command, FMC boot, GSP-RM init
  done) is an attended-window item under the P08 rules: documented cold power
  state, no prior Linux GPU initialization, camera, abort rule, and the
  B7b-style one-time boot entry. Nothing in this document authorizes it.

## 8. Known unknowns

1. [UNKNOWN] The exact `NVDM_PAYLOAD_COT` field layout, `cotPayloadVersion`,
   `cotPayloadSignatureSize` and `cotPayloadPublicKeySize` values for GB10B
   (set in the SEC2 object constructor; not read).
2. [UNKNOWN] The `GspFwWprMeta`, GSP-FMC argument block (`pGspFmcArgumentsCached`)
   and libos init-argument layouts this FMC build expects.
3. [UNKNOWN] What SEC2 requires to be already true when the first command
   arrives (its own firmware loaded by the SoC boot chain? clocks? power
   state?), and whether UEFI leaves the GPU in that state at AIENOS entry.
   On Linux the driver finds "GFW_BOOT" complete before it starts
   (`kgspWaitForGfwBootOk_HAL`); who completes it without Linux is not shown.
4. [UNKNOWN] The message-queue (RPC) format and the init sequence after
   `RmInitDone`; the native kernel needs only a subset (device init, memory
   mapping, channel, submit) but which RPCs are mandatory is not established.
5. [UNKNOWN] Whether the confidential-computing (`_cc_`) sections or the SPDM
   session are ever required on this platform. Assumed not [INFERRED (high)].
6. [UNKNOWN] The exact meaning of the `GspRmBoot_GB10B` image versus the
   `GspRmFmcGfwProdSigned_GB10B` image (both ~196 KiB): the SEC2 path sends the
   FMC archive, the boot-binary preparation copies the GspRmBoot image and its
   RM_RISCV_UCODE_DESC; which one the GSP's boot ROM consumes on GB10B, and how
   the descriptor offsets are used, was not traced end to end.
7. [UNKNOWN] Reset and re-open behavior on GB10B after a failed FMC boot
   (`kgspResetHw_GB100` waits for "reset access"); needed for the
   resource-incarnation protection (#285) before any repeated attempt.

## 9. Scope and limits of this document

Read: nv-firmware.h, nv-firmware-chip-family-select.h, nv_arch.h, nv.c (the
firmware load function only), kernel_gsp.c (init, container parsing, boot
binary), kernel_gsp_gh100.c (prepare, bootstrap), kernel_gsp_gb100.c,
kernel_gsp_gb10b.c, kernel_gsp_booter.c and kernel_gsp_fwsec.c (grep only),
kernel_sec2_gb10b.c, g_kernel_gsp_nvoc.c/.h, g_kernel_sec2_nvoc.c,
g_kern_fsp_nvoc.c (property tables only), the two GB10B bindata files
(metadata comments only), README.md, COPYING, the firmware copyright file. Not
read: kern_fsp_cot_payload.h, the NVDM/MCTP format headers, kernel_sec2.c
(`ksec2SendMessage`), the GSP RPC layer, dev_sec_pri.h register values, ACR or
GSP internals (not available). No Context7 or web manual covers this layer; the
DGX Spark user guide is silent on GSP firmware loading (DOCS SILENT on native
GSP bring-up).
