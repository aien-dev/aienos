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
- Two more hosted tools, same rule (nothing is ever sent to the chip):
  `ck_gsp_cot_encode` builds and checks the exact message the driver sends to
  SEC2 (section 10), and `ck_gsp_bindata_extract` reads the eight GB10B
  firmware arrays out of the public driver source with our own inflater and
  hash code, cross-checks every size, record and digest, and writes them as
  files (section 11). `make -C native/kernel test` runs all three self-tests.
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

| Archive label | Original file name (NVIDIA internal) | Bytes | Stored as | sha256 of the bytes [OBSERVED] |
|---|---|---|---|---|
| GspRmBoot_GB10B UCODE_IMAGE_PROD | kernel/inc/gspcc/bin/g_gsp_gb10b_dyn_prd_image.bin | 196,608 | raw | 427a691d8453f02548d395f40ac900eb0d5b8ea864e8f14f958eef890ba400a2 |
| GspRmBoot_GB10B UCODE_DESC_PROD | kernel/inc/gspcc/bin/g_gsp_gb10b_dyn_prd_desc.bin | 84 (RM_RISCV_UCODE_DESC) | deflate, 28 bytes | 8371a29f1c68da89b73bdc87af477c37f0b4e05939c58379d0e3d29efc5575b5 |
| GspRmBoot_GB10B UCODE_IMAGE_DBG | kernel/inc/gspcc/bin/g_gsp_gb10b_dyn_dbg_image.bin | 196,608 | raw | 709b88a88fc7ae9bd56b010bcc0a8269d4d40b3c0454aa5b366e8d562d83a404 |
| GspRmBoot_GB10B UCODE_DESC_DBG | kernel/inc/gspcc/bin/g_gsp_gb10b_dyn_dbg_desc.bin | 84 | deflate, 28 bytes | 8371a29f... (byte-identical to DESC_PROD) |
| GspRmFmcGfwProdSigned_GB10B UCODE_IMAGE | kernel/inc/gspcc/bin/g_gsp_gb10b_dyn_prd_gfw_image.bin | 195,912 | raw | b13ead4b9a6b8a0d268f3094cc4f4521d6be8a9a525edbc9a8f3f397c86f1f2e |
| GspRmFmcGfwProdSigned_GB10B UCODE_HASH | g_gsp_gb10b_dyn_prd_gfw_hash.bin | 48 (SHA-384) | raw | f0389f3a9ce3bb6093e80bfc924bbe2a4ece0199b080a37f64bc1fef63f7500c |
| GspRmFmcGfwProdSigned_GB10B UCODE_SIG | g_gsp_gb10b_dyn_prd_gfw_sig.bin | 384 | raw | 9db429257a18e7c5c1a3df185001c671e21bec4e94c719a574d2ce72e2e07272 |
| GspRmFmcGfwProdSigned_GB10B UCODE_PKEY | g_gsp_gb10b_dyn_prd_gfw_pub_key.bin | 384 | raw | e9bbc669c27ad8827b5bbc2b2f52fdb47718659a651088869a5f3b11d2df7816 |

Digests measured 2026-10-12 by `ck_gsp_bindata_extract` over the two files
fetched from the 580.173.02 tag (raw.githubusercontent.com, path
`src/nvidia/generated/<file>`); the 580.173.02 Makefile pin
(`make -C native/kernel gsp-bindata-test`) checks the two image digests and
the decoded descriptor on every run. `UCODE_HASH` equals SHA-384 of
`UCODE_IMAGE` [OBSERVED, checked by the tool].

Array storage format [SOURCE]: each array is a `BINDATA_STORAGE_PVT` record
(uncompressed size, compressed size, data pointer, bCompressed,
bFileOverride, bReferencedDuringLoad) and an archive table
(`BINDATA_ARCHIVE` with `entryNum` and label/storage pairs) [bin_data_pvt.h,
bin_data.h]. A compressed array is a gzip member without the 10-byte gzip
header: raw DEFLATE, then CRC-32 and ISIZE, little endian. The driver inflates
it with its own zlib-style decoder (`utilGzAllocate`/`utilGzGetData`,
bin_data.c:36-45,96); the nouveau extractor prepends exactly that header
before `gzip.decompress` [nouveau/extract-firmware-nouveau.py:107-108].
The 28-byte descriptor is 20 bytes of fixed-Huffman DEFLATE plus the two
trailers [OBSERVED]; our decoder verifies both.

Source files: `src/nvidia/generated/g_bindata_kgspGetBinArchiveGspRmBoot_GB10B.c`
(2,466,261 bytes of C) and
`g_bindata_kgspGetBinArchiveGspRmFmcGfwProdSigned_GB10B.c` (1,238,060 bytes),
metadata comments at lines 31-40 and the storage records near the end of each
file. The README says the `nouveau/` script "is used to extract some of the
firmware binary images (and related data) encoded in the source code and store
them as distinct files. These files are used by the Nouveau device driver"
[README.md:170-173]; that script knows gh100, gb100 and gb202 FMC images, not
gb10b [nouveau/extract-firmware-nouveau.py:655-662,775-781]. DONE
2026-10-12: `ck_gsp_bindata_extract` (section 11) is that step, written
against the generated-file grammar and the storage records, not against the
nouveau script.

Descriptor decode [SOURCE rmRiscvUcode.h:36-87, 21 u32 fields; OBSERVED
values]: version 5; bootloader/riscvElf/swbrom offsets and sizes 0;
manifest at 0x0 size 0xa00; monitorData at 0xa00 size 0xa600; monitorCode at
0xb000 size 0x24d00 (ends at 0x2fd00, inside the 196,608-byte image);
bIsMonitorEnabled 1; appVersion 0; fbReservedSize 0; bSignedAsCode 0. The
driver shifts these offsets by `RISCV_BR_ADDR_ALIGNMENT` = 8 bits when it
programs them [kernel_gsp_gh100.c:47, kernel_gsp_ga102.c:44], so the tool
refuses any region that is not 256-byte aligned.

Which archive the driver picks for GB10B [SOURCE]: the HAL dispatch for
`kgspGetGspRmBootUcodeStorage` lands on the GB100 variant
[kernel_gsp_gb100.c:115-149], which outside confidential computing calls the
GA102 variant [kernel_gsp_ga102.c:101-120]: the `GspRmBoot` archive's
`UCODE_IMAGE_PROD` and `UCODE_DESC_PROD` (the DBG pair only on a debug-fused
part). The `GspRmFmcGfwProdSigned` quartet goes into the SEC2 chain-of-trust
payload (section 10).

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
  not need the machine: (a) DONE 2026-10-12: `ck_gsp_bindata_extract`
  (section 11) writes the eight arrays as files with digests, own DEFLATE and
  SHA-384, `make -C native/kernel gsp-bindata-test`; (b) DONE 2026-10-12: the encoder, decoder
  and refusal tests for `NVDM_PAYLOAD_COT`, the MCTP/NVDM headers, the EMEM
  packet and `GSP_FMC_BOOT_PARAMS` are `ck_gsp_cot_encode` (section 10);
  (c) remaining: an encoder for `GspFwWprMeta` (256 bytes, layout known, the
  GH100 populate values not yet traced) and the libos init-argument block.
- The machine-side part of cut C (first SEC2 command, FMC boot, GSP-RM init
  done) is an attended-window item under the P08 rules: documented cold power
  state, no prior Linux GPU initialization, camera, abort rule, and the
  B7b-style one-time boot entry. Nothing in this document authorizes it.

## 8. Known unknowns

1. RESOLVED 2026-10-12 [SOURCE]: the `NVDM_PAYLOAD_COT` layout is 860 packed
   bytes, GB10B uses version 1, signature and key sizes 384, hash 48; the
   whole wire format is in section 10 and checked by `ck_gsp_cot_encode`.
2. [PARTLY RESOLVED 2026-10-12] `GSP_FMC_BOOT_PARAMS` (88 bytes, section 10)
   and the `GspFwWprMeta` struct (256 bytes, `gsp/gsp_fw_wpr_meta.h`, magic
   `0xdc3aae21371a60b3`, revision 1; GB10B zeroes `vgaWorkspaceSize`,
   `pmuReservedSize` and `nonWprHeapSize`, kernel_gsp_gb10b.c:32-55) are
   known. [UNKNOWN] the values `kgspPopulateWprMeta_GH100` computes (radix3
   ELF placement, heap sizes, WPR carveout) and the libos init-argument block
   (`gsp_init_args.h` gives `GSP_ARGUMENTS_CACHED`; the libos block itself not
   traced).
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
6. [RESOLVED on the host side 2026-10-12, SOURCE; consumer side INFERRED
   (medium)] `GspRmFmcGfwProdSigned_GB10B` (image, hash, signature, public
   key) is what SEC2 receives in the chain-of-trust payload (section 10).
   `GspRmBoot_GB10B` (image plus RM_RISCV_UCODE_DESC) is what
   `kgspPopulateWprMeta_GH100` describes to the FMC as the "GSP-FMC ucode"
   bootloader: `sizeOfBootloader`, `sysmemAddrOfBootloader`,
   `bootloaderCodeOffset`/`DataOffset`/`ManifestOffset` come from that image
   and the descriptor's monitorCode/monitorData/manifest offsets
   [kernel_gsp_gh100.c:295-335]; the direct boot-ROM path programs the same
   three regions into `NV_PGSP_FALCON_BCR_DMAADDR_*` [kernel_gsp_gh100.c:
   `_kgspBootstrapGspFmc_GH100`], which GB10B does not take (section 11).
   Who reads the WprMeta bootloader fields on the SEC2 path (FMC or ACR) runs
   inside NVIDIA code and is not readable.
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
(metadata comments only), README.md, COPYING, the firmware copyright file;
for section 10 also kern_fsp_cot_payload.h, fsp_nvdm_format.h,
fsp_mctp_format.h, fsp_emem_channels.h, kernel_sec2.c (`ksec2SendMessage`,
`ksec2PollForCanSend`), g_kernel_sec2_nvoc.c/.h (version, sizes, SEID),
gspifpub.h, gsp_init_args.h, gsp_fw_wpr_meta.h, kernel_gsp_gh100.c
(`kgspSetupGspFmcArgs`), and published/blackwell/gb10b dev_sec_pri.h,
dev_gsp.h, dev_falcon_v4.h; for sections 3.3 and 11 also rmRiscvUcode.h,
bin_data.c, bin_data.h, bin_data_pvt.h, kernel_gsp_ga102.c,
nouveau/extract-firmware-nouveau.py (lines 82-114 only), kernel_gsp_gh100.c
(`kgspBootstrap_GH100`, `_kgspLockdownReleasedOrFmcError`,
`kgspPopulateWprMeta_GH100`, `_kgspBootstrapGspFmc_GH100`), g_kern_fsp_nvoc.c
(the `PDB_PROP_KFSP_IS_MISSING` chip list), and the full bindata record
tables of both GB10B files. Not read: the GSP RPC layer, the libos
init-argument block, ACR or GSP internals (not available). No Context7 or web manual covers this layer; the
DGX Spark user guide is silent on GSP firmware loading (DOCS SILENT on native
GSP bring-up).

## 10. The SEC2 chain-of-trust message, byte for byte [SOURCE]

Everything in this section is read from open-gpu-kernel-modules tag
580.173.02 and mirrored by `native/kernel/tools/ck_gsp_cot_encode.c`
(`make -C native/kernel gsp-cot-test`, part of `make test`). Nothing here was
sent to the device.

Transport. NVDM (NVIDIA Data Model) over MCTP over SEC2 EMEM channel 0,
1024 bytes (`fsp/fsp_emem_channels.h:9-11`; `kernel_sec2_gb10b.c:36-41`,
`:322-333`). A packet is two header dwords then the payload
(`kernel_sec2.c:50-52`, `:305-325`):

| dword | field | value for the boot message | source |
|---|---|---|---|
| 0 | MCTP transport header: SOM bit 31, EOM bit 30, SEQ 29:28, TO 27, TAG 26:24, SEID 23:16, DEID 15:8, RSVD 7:4, VERSION 3:0 | `0xC0000000` (SOM=1, EOM=1, SEQ=0, SEID=0; the driver sets only those four) | `fsp_mctp_format.h:8-16`; `kernel_sec2.c:319-321`; SEID 0 for GB10B `g_kernel_sec2_nvoc.c:879-888`, `g_kernel_sec2_nvoc.h:907-909` |
| 1 | NVDM header: TYPE 6:0 = 0x7e (vendor PCI), IC 7 = 0, VENDOR_ID 23:8 = 0x10de, NVDM_TYPE 31:24 | `0x1410DE7E` (NVDM_TYPE_COT = 0x14) | `fsp_mctp_format.h:17-22`; `fsp_nvdm_format.h:14`; `kernel_sec2_gb10b.c:391-402` |

A message longer than 1016 bytes would continue in packets that carry only
the MCTP dword with SOM=0 and SEQ = (n mod 4) (`kernel_sec2.c:330-357`); the
boot message is 860 bytes, so it is always one packet, and the driver sends
only this one command on the channel (`kernel_sec2_gb10b.c:719-722`).

Payload `NVDM_PAYLOAD_COT`, `#pragma pack(1)`, 860 bytes
(`src/nvidia/inc/kernel/gpu/fsp/kern_fsp_cot_payload.h:12-29`):

| offset | size | field | GB10B value | source |
|---|---|---|---|---|
| 0 | 2 | version | 1 | `g_kernel_sec2_nvoc.c:478-482` |
| 2 | 2 | size | 860 (`sizeof`) | `kernel_sec2_gb10b.c:580-581` |
| 4 | 8 | gspFmcSysmemOffset | physical address of the GSP-FMC image in system memory | `:507` |
| 12 | 8 | frtsSysmemOffset | 0 (never set) | `:578` zero-fill |
| 20 | 4 | frtsSysmemSize | the GSP-FMC image size (195,912), sic | `:508` |
| 24 | 8 | frtsVidmemOffset | 0 | `:578` |
| 32 | 4 | frtsVidmemSize | 0 | `:578` |
| 36 | 48 | hash384 | `UCODE_HASH` array | `:514` |
| 84 | 384 | publicKey | `UCODE_PKEY` array | `:526-527`; size `g_kernel_sec2_nvoc.c:475-476` |
| 468 | 384 | signature | `UCODE_SIG` array | `:519-520`; size `g_kernel_sec2_nvoc.c:472-473` |
| 852 | 8 | gspBootArgsSysmemOffset | physical address of `GSP_FMC_BOOT_PARAMS` | `:532`, `:241-258` |

The packet is therefore 868 bytes. It is written at EMEM offset 0 with the
write auto-increment bit, one dword at a time, then QUEUE_HEAD(0) = 0 and
QUEUE_TAIL(0) = 864 (padded size minus one dword) (`kernel_sec2_gb10b.c:
700-732`, `:108-152`, `:160-210`). The channel may be written only while
HEAD == TAIL (`:344-356`, polled `kernel_sec2.c:605-640`); the command counts
as handled once FALCON_MAILBOX0 no longer reads `0xc001cafe` (`:285-297`);
before the boot the driver also waits until the GSP falcon's HWCFG2 register
reads non-zero and not the `0xBADF41xx` "target locked" pattern (`:262-281`).
Register addresses for GB10B: `published/blackwell/gb10b/dev_sec_pri.h`
(MAILBOX0/1, QUEUE_HEAD/TAIL(i), EMEMC(i), EMEMD(i)), `dev_gsp.h` (NV_PGSP
base), `dev_falcon_v4.h` (HWCFG2); the tool does not use them.

Boot arguments the payload points at: `GSP_FMC_BOOT_PARAMS`
(`src/nvidia/arch/nvalloc/common/inc/gsp/gspifpub.h`), natural C layout, 88
bytes on the LP64 ABI the driver and this host share (the self-test checks the
offsets against the compiler); filled by `kgspSetupGspFmcArgs_GH100`
(`kernel_gsp_gh100.c:415-470`), allocated 4 KiB aligned (`:164`):

| offset | size | field | fresh-boot value |
|---|---|---|---|
| 0 | 4 | initParams.regkeys | 0 unless CC or NVLink proxy keys |
| 8 | 4 | bootGspRmParams.target | DMA target of the descriptor (0 FB, 1 coherent sysmem, 2 non-coherent sysmem) |
| 12 | 4 | bootGspRmParams.gspRmDescSize | 256 (`sizeof GspFwWprMeta`) |
| 16 | 8 | bootGspRmParams.gspRmDescOffset | physical address of the `GspFwWprMeta` |
| 24 | 8 | bootGspRmParams.wprCarveoutOffset | not set by the driver (0) |
| 32 | 4 | bootGspRmParams.wprCarveoutSize | not set (0) |
| 36 | 1 | bootGspRmParams.bIsGspRmBoot | 1 |
| 40 | 4 | gspRmParams.target | DMA target of the libos init arguments |
| 48 | 8 | gspRmParams.bootArgsOffset | physical address of the libos init arguments |
| 56 | 24 | gspSpdmParams | only with SPDM (assumed off) |
| 80 | 8 | gspRmMemParams.flushSysmemAddrVal{Lo,Hi} | only with CC (0) |

INFERRED, enforced by the tool but not a driver check: the image address is
4 KiB aligned (the driver maps `NV_ALIGN_UP(size, 0x1000)` bytes of
page-granular system memory, `kernel_sec2_gb10b.c:489-495`) and every
system address fits the 41-bit DMA window `/proc/driver/nvidia/gpus` reports
for this GPU (section 2; `--dma-bits` overrides).

Evidence 2026-10-12 on the box: `CK_GSP_COT_ENCODE_SELFTEST: PASS` (80 checks:
both layouts against the compiler, golden header words, encode/decode round
trips, 46 field mutations and every header truncation refused by name), same
under ASan/UBSan.

## 11. Extracted arrays and the GB10B boot decision [SOURCE]

Tool: `native/kernel/tools/ck_gsp_bindata_extract.c` (hosted C, no
dependencies beyond our own `native/argus/sha256.c`; SHA-384, CRC-32 and the
raw-DEFLATE decoder, stored/fixed/dynamic blocks, are in the tool).
`make -C native/kernel gsp-bindata-extract` builds it;
`make -C native/kernel gsp-bindata-test` runs the self-test and, when the two
driver files are present under `GSP_BINDATA_DIR` (default
`~/.cache/aienos/open-gpu-kernel-modules-580.173.02`), the pin check; it is
part of `make test`. Without the files the pin line reads `NOT_RUN`, never
PASS.

What it checks before it writes a byte: the generated-file grammar
(`FUNCTION`, `FILE NAME`, `FILE TYPE BINARY`, `COMPRESSION`, `COMPLEX_STRUCT
NO`, `DATA SIZE`, `COMPRESSED SIZE`), the array identifier
`kgspBinArchive<stem>_BINDATA_LABEL_<label>_data`, the storage record
(both sizes, the data pointer, `bCompressed`), the archive table (`entryNum`,
order, labels), duplicate labels, more than 16 arrays or 8 MiB per array;
for compressed arrays the DEFLATE stream, the CRC-32 and the ISIZE trailer;
then the meaning: `UCODE_DESC_*` is 84 bytes, version 5, monitor enabled,
with manifest/monitor regions inside the matching `UCODE_IMAGE_*` and
256-byte aligned; `UCODE_HASH` is 48 bytes and equals SHA-384 of
`UCODE_IMAGE`; `UCODE_SIG` and `UCODE_PKEY` are 384 bytes; any other label is
refused. Any failure prints `REFUSED: <reason>` and exits 2.

Usage: `ck_gsp_bindata_extract extract FILE [--out DIR]` prints one
`array <function> <label> file=... stored=N compressed=yes|no size=N
sha256=...` line per array, the decoded descriptors, `hash384 ... equals
sha384(UCODE_IMAGE)` and `RESULT OK arrays=N`; `selftest` prints
`CK_GSP_BINDATA_EXTRACT_SELFTEST: PASS|FAIL (N checks, M failures)`.

Evidence 2026-10-12 on the box: `CK_GSP_BINDATA_EXTRACT_SELFTEST: PASS (124
checks, 0 failures)`, same under ASan/UBSan; both GB10B files extract with
`RESULT OK arrays=4` and the digests in section 3.3;
`CK_GSP_BINDATA_PIN: PASS`; a foreign C file is refused ("no arrays found").

The boot decision the driver makes for GB10B, as the native kernel would have
to mirror it [SOURCE kernel_gsp_gh100.c:833-995 `kgspBootstrap_GH100`,
reached for GB10B through the dispatch else-branch, g_kernel_gsp_nvoc.c:719]:

1. If a KernelFsp object exists and `PDB_PROP_KFSP_DISABLE_GSPFMC` is not
   set: "boot GSP via FSP" (`kfspSendBootCommands`). GB10B is not in the
   FSP-present chip list ("GH100 | GB100 | GB102 | GB110 | GB112 | GB202 |
   GB203 | GB205 | GB206 | GB207"), so `PDB_PROP_KFSP_IS_MISSING` is true
   [g_kern_fsp_nvoc.c:227-236]: not this branch.
2. Else if a KernelSec2 object has `PDB_PROP_KSEC2_BOOT_GSPFMC`: "boot GSP
   via SEC2" (`ksec2SendBootCommands`, section 10). True for "GB10B | GB20B |
   GB20C" [g_kernel_sec2_nvoc.c:446-450]: **this is the GB10B path.**
3. Else the direct path `_kgspBootstrapGspFmc_GH100`: program
   `NV_PGSP_FALCON_BCR_DMAADDR_FMCCODE/FMCDATA/PKCPARAM` from the GspRmBoot
   image and the descriptor's monitorCode/monitorData/manifest offsets, then
   `NV_PGSP_FALCON_CPUCTL_STARTCPU`. Not taken on GB10B.

After the SEC2 send, in order: `ksec2WaitForGspTargetMaskReleased`
(conditional on `PDB_PROP_KSEC2_GSP_MODE_GSPRM`, kernel_sec2_gb10b.c:368 and
:224/:250/:469); `gpuTimeoutCondWait(_kgspLockdownReleasedOrFmcError)`
(kernel_gsp_gh100.c:492 onward: `NV_PFALCON_FALCON_MAILBOX0` carries ACR/FMC
error codes, treated as fatal; the boot-argument address may still sit in the
mailboxes until the FMC clears them); then any non-zero MAILBOX0 is "GSP-FMC
reported an error"; `kflcnIsRiscvActive`; then "Waiting for GSP fw RM to be
ready" (the RPC init handshake, section 8 item 4). Each of these is a
measurable checkpoint for the attended window, with its own timeout and its
own refusal line. Nothing in this section has been run on the chip.

