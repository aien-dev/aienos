# GB10 native execution status

The `aienos-handoff` AArch64 UEFI image now checks the DGX Spark's observed
GB10 PCI location first, then walks every bus in each root bridge's
firmware-declared bus range. It opens the UEFI PCI root bridge protocol with a
shared (`GetProtocol`) open, because the firmware PCI bus driver holds the
protocol `ByDriver` and refuses an exclusive open with `ACCESS_DENIED` — the
reason the first native boot reported `gb10: unavailable`. It accepts only
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
