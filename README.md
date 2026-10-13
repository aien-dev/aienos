# AIENOS

> **Status: experimental / pre-alpha. Nothing here is physically qualified.** The first native boot on the NVIDIA DGX Spark passed on 2026-09-24 ([evidence](evidence/m2_first_boot_2026-09-24.md)). Since then most of the work has run in an emulator (QEMU); the C kernel has also run on a Raspberry Pi 5 (see Current state). No support, stability or compatibility promises. Expect breaking changes.

AIENOS is our own operating system kernel, built to replace Linux on the DGX Spark. It is agent-native: the agent is the control plane, and the model is never the kernel. The kernel stays small, deterministic and non-intelligent, and the agent is never the root of trust.

```text
Firmware -> AIEN Boot -> AIEN Kernel -> AIEN Runtime -> AIEN Agent -> You
```

## Current state

The kernel is being rewritten in C (the `native/` directory) and is IMPLEMENTED / NOT QUALIFIED: all 24 emulator gates pass in the [newest receipt](evidence/ck_gates_29ed03c97454354a18676f768273dd7f7a8e15462c4be1939d9994d277d0d639.json) (run at 7f0de7e on 2026-10-09, QEMU only), and `scripts/ck_gates.sh` now lists 26 gates, so a newer receipt is owed. It has not been booted on the DGX Spark. Its first runs on real hardware were on a Raspberry Pi 5 on 2026-10-13: a bring-up run that reached interrupts, four cores, user-mode tasks, scheduling and message passing and wrote its log to the SD card, then two runs that wrote and re-read a test region on the card's AIENOS partition (pull requests [#345](https://github.com/aien-dev/aienos/pull/345) and [#346](https://github.com/aien-dev/aienos/pull/346); the run logs are not stored in this repository). The earlier Rust kernel in `crates/` is legacy and is being replaced; it is not extended. Trust-chain and encrypted-storage work (TRUST-1 and M5) is NOT_QUALIFIED, with hardware and operator steps outstanding. Do not trust any number in this file over the live documents:

- [ROADMAP.md](ROADMAP.md): component status (its newest status block is dated 2026-10-01)
- [native/kernel/GATES.md](native/kernel/GATES.md): what each emulator gate checks
- [docs/TRUST-1-M5-GATE-MATRIX.md](docs/TRUST-1-M5-GATE-MATRIX.md) and [docs/TRUST-1-OPERATOR-STEPS.md](docs/TRUST-1-OPERATOR-STEPS.md)
- [docs/PLAN_AUTHORITY.md](docs/PLAN_AUTHORITY.md): how this repository's plans relate to the whole-system plan in [aien-architecture](https://github.com/aien-dev/aien-architecture)

## How this fits with the other repositories

AIENOS owns the trusted operating substrate. [omega](https://github.com/aien-dev/omega) (the C reaction runtime and compiler) runs on top of it, [physics](https://github.com/aien-dev/physics) holds machine realization (FORGE), and [aien-architecture](https://github.com/aien-dev/aien-architecture) is the authority for status and sequencing. An optional compatibility island (for example Linux with vendor drivers) may sit beside AIENOS while native support is built; it shrinks over time.

## Principles

- **Sovereignty:** no outside organization is required to boot the machine, access your data, authenticate you, authorize the agent, build the trusted core, recover, change models, move hardware or keep operating.
- **Open trusted base:** boot, kernel, memory, scheduling, storage, cryptography, identity, AEGIS, capability enforcement, update verification and recovery build from inspectable source, offline, with a reproducible toolchain.
- **Fastest thing possible:** close to the metal, measured, with evidence.
- **Free inside reversible state; explicit authorization at irreversible boundaries.**

## Standing rules

Language rule: Rust is scaffolding, Omega is the destination, and C or assembly stay only where hardware, boot, ABI or measurement justifies them (aien-architecture ADR 0024, which supersedes the old "C is the target, no new Rust" rule). No Python, no CUDA toolkit, no CUDA-shaped APIs, no systemd or Linux init in boot, services or tooling. Dependencies in the trusted base are rare and built offline.

## Build and verify

The C kernel needs only gcc, binutils, make and a shell. Host tests need nothing else.

```bash
make -C native/kernel test        # C kernel host tests
make -C native/kernel sanitize    # same under ASan and UBSan
make -C native/capability test    # capability authority (production ABI; docs/CAPABILITY_ABI.md)
bash scripts/cap_abi_isolation_test.sh  # C and Rust capability ABIs stay separate
make -C native/store test mutants # torn-write-safe Store record
```

The emulator gates need `qemu-system-aarch64` and the AAVMF firmware (Ubuntu packages: `qemu-system-arm`, `qemu-efi-aarch64`):

```bash
bash scripts/ck_gates.sh          # runs the C gates, writes a content-addressed receipt; refuses a dirty tree; its child scripts take a gate lock and report NOT_RUN while another gate run holds it or the machine quiet flag is set
bash scripts/ck_pi5_build_check.sh  # builds the Raspberry Pi 5 image and checks the default image carries none of it (build only; the Pi image cannot boot in QEMU)
```

The legacy Rust workspace is still checked by `bash scripts/verify_all.sh` (needs a Rust toolchain with the `aarch64-unknown-uefi` and `aarch64-unknown-none` targets) until it is retired. Anything that needs the real DGX Spark is labelled `needs-hardware` and is run by maintainers.

## Contributing

Start with [issues labelled `good first issue`](https://github.com/aien-dev/aienos/labels/good%20first%20issue) or [`emulator-ok`](https://github.com/aien-dev/aienos/labels/emulator-ok): they need no special hardware. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Open pull requests against `main` (protected; five checks must pass: `Analyze (c-cpp)`, `Analyze (actions)`, `crumb`, `AIEN Verification` and `workflow files accepted`) and lead with the commands you ran and their output. Questions go in [Discussions](https://github.com/aien-dev/aienos/discussions). Report vulnerabilities privately through GitHub security advisories.

## License

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contact: aien@aienos.com.
