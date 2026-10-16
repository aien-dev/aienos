# GB10 native execution status

The `aienos-handoff` AArch64 UEFI image now checks the DGX Spark's observed
GB10 PCI location first, then walks every bus in each root bridge's
firmware-declared bus range. It opens the UEFI PCI root bridge protocol with a
shared (`GetProtocol`) open. The leading hypothesis for the first native
boot's `gb10: unavailable` is that the firmware PCI bus driver holds the
protocol `ByDriver` and refuses an exclusive open with `ACCESS_DENIED`; this is
unconfirmed on hardware, and the next native boot's `gb10_pci_root_open[..]`
lines will confirm or rule it out. It accepts only
NVIDIA `10de:2e12` with a programmed 64-bit memory BAR and PCI memory
decoding enabled. Through the UEFI PCI root bridge protocol, it reads the
read-only PMC `BOOT_0` and `BOOT_42` registers from BAR0. It carries the
location, BAR address, and register values across `ExitBootServices` into the
AIENOS kernel's serial boot report. No Linux service is involved in that image.

When the GB10 is not found, the pre-exit report and the final
firmware-variable report record why: how many root bridges carry the protocol
(`gb10_pci_root_bridges`), any refused opens (`gb10_pci_root_open[i]`), and
per scanned bridge the segment number, device count, bridge count, and valid
bridge bus windows (`gb10_pci_root[i]`). If the GB10 vendor/device pair was
seen but rejected, its command/status and BAR0 values are recorded
(`gb10_pci_candidate[i]`), distinguishing an unprogrammed BAR from a missed
match.

This image has been built but the fixed discovery path **has not been booted
on hardware**. These register reads still use firmware services before
handoff. They establish a device identity path; they do not initialize the
GPU or execute a GPU command.

To reach independent GPU execution, AIENOS still needs a native MMU mapping for
GPU MMIO, GPU resource and interrupt management, GB10/GSP firmware loading and
RPC, GPU memory allocation and synchronization, a command submission path, a
GPU code toolchain, and an inference runtime. Each stage needs hardware
evidence before the next can be claimed. The UEFI boot path is only a loader;
the intended runtime owner is the AIENOS kernel on Arm with GB10 as the primary
compute device.

The image has not been installed, selected as the host boot target, or allowed
to modify the existing Linux server. Host verification is `bash
scripts/verify_all.sh`; a passing result proves build and unit-test readiness,
not a successful native boot or model execution.

## KV memory ownership on the native path

Added 2026-10-16 for aien-spark/aien-architecture#233 (lane P1). The full
source map for KV ownership, write rules, GPU visibility, queue bounds,
cancellation, reuse and restart recovery lives with the code that owns the
pool, in sovereign-core
[`crates/aien-kv-cache/OWNERSHIP.md`](https://github.com/aien-spark/aien-sovereign-core/blob/a78ee68ab9a1285a7d4e8a983a7738ff2e1b7d4a/crates/aien-kv-cache/OWNERSHIP.md)
(aien-spark/aien-sovereign-core#588). What it says about AIENOS, at aienos
`b7ebf7c`:

- Native GB10 GPU: no KV code exists. Nothing above allocates GPU memory,
  so there is no native KV buffer, no visibility rule and no evidence.
  NOT_RUN; the native GB10 model is aienos#327.
- Native Pi 5 CPU: `aienos-infer` keeps one dense f32 cache per session,
  `[layer][pos][kv_dim]`, allocated once
  (`crates/aienos-infer/src/decode.rs` L21, L56-L62). `reset` only sets
  `pos = 0` and keeps the buffers (L93-L96). No paging, no sharing, no
  persistence. Native-hardware-tested for inference only:
  `docs/native/PI5-6-INFER-RUNS.md` (1.20 tok/s, KV capacity 64 in that
  probe).
- Native storage: the NVMe driver allows one outstanding command, and
  "Every request goes through the bounce buffer"
  (`native/disk/disk_nvme.h` L17-L19). The planned KV slab, its step-budgeted
  pump and the export/import calls are design only (sovereign-core ADR 0003
  section 9); no code, NOT_RUN, tracked in aienos#367.
- Emulator / QEMU: the native KV slab tests are PLANNED (ADR 0003 section
  11); nothing runs yet.

The Linux-hosted Spark results in that page (GB10 through the NVIDIA Linux
driver) are not native evidence and are not claimed here.
