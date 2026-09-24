# GB10 native execution status

The `aienos-handoff` AArch64 UEFI image now checks the DGX Spark's observed
GB10 PCI location first, then searches other root bridges if needed. It accepts
only NVIDIA `10de:2e12` with a programmed 64-bit memory BAR and PCI memory
decoding enabled. Through the UEFI PCI root bridge protocol, it reads the
read-only PMC `BOOT_0` and `BOOT_42` registers from BAR0. It carries the
location, BAR address, and register values across `ExitBootServices` into the
AIENOS kernel's serial boot report. No Linux service is involved in that image.

This image has been built but **has not been booted on hardware**. These
register reads still use firmware services before handoff. They establish a
device identity path; they do not initialize the GPU or execute a GPU command.

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
