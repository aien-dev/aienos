# AIENOS

> **Status: experimental / pre-alpha.** Nothing here boots yet. No support, stability, or compatibility promises. Expect breaking changes.

AIENOS is an agent-native operating system designed around continuous logical agent existence: the agent persists while models, kernels, inference state, power states, and physical machines change beneath it. You turn the machine on, the agent wakes up, knows the machine and your history, operates nearly everything inside it, and asks you only before crossing a boundary you have told it not to cross alone.

AIEN is provisioned once. After that, boot, reboot, sleep, model reload, kernel restart, hardware failure, and migration are execution-state transitions—not agent creation events.

The kernel stays small, deterministic, and non-intelligent. The model is never the kernel, and the agent is never the root of trust.

```text
Firmware
  -> AIEN Boot
  -> AIEN Kernel
  -> AIEN Runtime
  -> AIEN Agent
  -> You
```

An optional compatibility island (for example, Linux with vendor drivers) may sit beside AIENOS while native support is built. It shrinks over time and AIENOS is never designed around it.

## First milestone

Power on, AIENOS boots directly on the NVIDIA DGX Spark (no Linux host), the AIEN agent starts on a local console, a local model loads, you talk to it, and its state persists across reboot. CPU inference is acceptable for this milestone.

Two UEFI images are available. The default diagnostic prints a banner and returns to firmware. The separate handoff image exits UEFI boot services, counts conventional-memory pages, enters the early kernel UART path, and halts. Neither image has been booted on the DGX Spark. The handoff does not yet initialize the frame allocator, mount storage, recover agent state, or load a model, so this milestone remains open. Host verification checks their AArch64 EFI image format without changing the boot configuration.

The AIENOS boot path is a native Rust UEFI entry followed by the AIENOS kernel. It does not use systemd or a Linux init system. The handoff image emits counter-based timings for UEFI entry to kernel handoff and handoff to kernel entry once it runs on hardware. These timings do not include platform firmware time before UEFI starts the image.

AEGIS currently checks capability scope and uses HMAC-SHA256 for capability tokens and operator grants. The broker can own an in-memory J-Space World delta and route `fs.write` and `fs.delete` into it without invoking host handlers; these effects can run without an operator grant only while that World is active. A claimed World ID alone grants nothing. World storage and recovery are still prototypes. Filesystem scope checks enforce lexical path boundaries; native handlers must also resolve symlinks safely before filesystem effects can be considered contained.

## Principles

- **Sovereignty:** no outside organization is required to boot the machine, access your data, authenticate you, authorize the agent, build the trusted core, recover, change models, move hardware, or keep operating.
- **Continuous existence:** the agent is provisioned once; power and substrate changes reconstruct execution, they do not recreate identity.
- **Open trusted base:** boot, kernel, memory management, scheduling, storage, cryptography, identity, AEGIS, capability enforcement, update verification, recovery, and provenance build from inspectable source with a reproducible toolchain. Opaque software may accelerate AIENOS; it may never be required to trust, build, boot, recover, or control it.
- **Fastest thing possible:** close to the metal, measured, with evidence.
- **Free inside reversible state; explicit authorization at irreversible boundaries.**

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for governing design, [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the 37-section blueprint, [docs/MILESTONES.md](docs/MILESTONES.md) for the phased milestone matrix, [docs/CONTINUOUS_EXISTENCE_AMENDMENT.md](docs/CONTINUOUS_EXISTENCE_AMENDMENT.md) for the continuous-existence amendment, and [docs/adr/README.md](docs/adr/README.md) for architectural decision records and technical specifications.

## License

Apache-2.0 WITH LLVM-exception. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
