# GB10 hardware qualification procedure (prepared, not executed)

This procedure prepares the eventual attended, read-only GB10 characterization
on Machine 1. It is not to be executed as part of this characterization phase.
It exists so the operator run, when authorized, collects only approved
read-only facts and returns the machine to Linux unchanged.

Governing: issue [#36](https://github.com/aien-dev/aienos/issues/36),
[NATIVE_BOOT_ONE_TIME.md](NATIVE_BOOT_ONE_TIME.md),
[HARDWARE_TEST_RIG.md](HARDWARE_TEST_RIG.md),
[GB10_PLATFORM_TOPOLOGY.md](GB10_PLATFORM_TOPOLOGY.md).

## Scope

Read-only characterization only:

- `scripts/gb10_profile.sh` run against the running Linux system;
- the existing `aienos-handoff` pre-exit report, if and when a separate native
  boot milestone authorizes a boot, which this procedure does not;
- collection of the pre-run and post-run Linux state listed below.

This procedure does not initialize the GPU, contact GSP, submit a command,
allocate GPU memory, execute a kernel, perform inference, write PCI
configuration space, change a command bit, resize a BAR, reset the GPU, perform
FLR, unbind or rebind the NVIDIA driver, change power state, write MMIO, access
`/dev/mem`, load firmware, create GPU channels, map GPU memory, or change the
SMMU configuration.

## Preconditions

1. The operator approves the run. It runs under
   `aien-proof hold --resource machine-1`.
2. Secure Boot stays on. TPM state is untouched.
3. Linux storage is untouched. The procedure writes only to a temporary
   directory and to the evidence output paths the operator names.
4. BootOrder is untouched. No boot entry is created, removed, or reordered.
5. The checkout is clean and maps to one commit. The run records that commit.

## Steps

1. Record the pre-run state:

   ```bash
   cd <checkout>
   git rev-parse HEAD
   git status --porcelain
   cat /proc/sys/kernel/osrelease
   cat /proc/cmdline
   ```

2. Collect the read-only GB10 profile. Both invocations are read-only; the
   second uses the documented `sudo -n` reads for configuration space above 64
   bytes and the ACPI table copies.

   ```bash
   bash scripts/gb10_profile.sh \
       --json evidence/gb10_linux_profile_<date>.json \
       --report evidence/gb10_linux_report_<date>.txt

   bash scripts/gb10_profile.sh --allow-sudo \
       --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
       --json evidence/gb10_linux_profile_full_<date>.json \
       --report evidence/gb10_linux_report_full_<date>.txt
   ```

3. Verify the structured output parses and that the expected device is present:

   ```bash
   jq -e '.schema == "aienos.gb10.profile.v1"' evidence/gb10_linux_profile_full_<date>.json
   jq -e '.gb10_device_count >= 1' evidence/gb10_linux_profile_full_<date>.json
   ```

4. Record the image or tool digest. If the existing handoff image is involved
   in a separately authorized native boot, record the image SHA-256 and the
   commit, and compare them with `\EFI\AIENOS\STAGED.TXT` exactly as
   [NATIVE_BOOT_ONE_TIME.md](NATIVE_BOOT_ONE_TIME.md) specifies.

5. Record the post-run state, identical to step 1, and confirm it is unchanged.

6. Return normally. The machine stays in Linux. Nothing reboots it.

## Evidence to record

| Evidence | Source |
| --- | --- |
| Exact commit | `git rev-parse HEAD` before and after |
| Working tree clean | `git status --porcelain` empty |
| Kernel and command line | `/proc/sys/kernel/osrelease`, `/proc/cmdline` |
| GB10 identity and location | structured profile `gb10_devices[].vendor_id`, `.device_id`, `.location` |
| BAR layout | structured profile `gb10_devices[].bars` |
| PCIe capability and link | structured profile `gb10_devices[].pcie`, `current_link_speed` |
| MSI / MSI-X | structured profile `gb10_devices[].msi`, `.msix` |
| IOMMU grouping | structured profile `gb10_devices[].iommu_group` |
| ACPI table hashes | structured profile `acpi_tables` |
| MCFG segment map | structured profile `mcfg_segments` |
| Privilege used | structured profile `collector.sudo_used` |
| Pre and post Linux state | the two state captures |

The full `aien-proof hold` output is the ledger event, as with every Machine 1
hardware run.

## Facts that are out of scope and marked NOT QUALIFIED

Anything that would require a write, reset, driver unbind, arbitrary MMIO read,
or trust mutation is marked:

`NOT QUALIFIED - REQUIRES LATER DEVICE-OWNERSHIP MILESTONE`

This includes, without exception:

- the PMC `BOOT_0` and `BOOT_42` values read natively by AIENOS (only the UEFI
  handoff path may read them, and only in a separately authorized native boot);
- any BAR MMIO read outside the established safe set;
- any GPU reset, FLR, or power state change;
- any NVIDIA driver unbind or rebind;
- any PCI configuration write, command bit change, or BAR resize;
- any GSP contact, firmware load, GPU channel, or GPU memory mapping.

The procedure does not work around that boundary. It records the boundary as
the answer.
