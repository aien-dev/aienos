# AIENOS

> **Status: experimental / pre-alpha.** Nothing here boots yet. No support, stability, or compatibility promises. Expect breaking changes.

AIENOS is an operating system in which the AIEN agent is the primary interface. It is not a desktop OS with an assistant installed on top: you turn the machine on, the agent wakes up, knows the machine and your history, operates nearly everything inside it, and asks you only before crossing a boundary you have told it not to cross alone.

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

## Principles

- **Sovereignty:** no outside organization is required to boot the machine, access your data, authenticate you, authorize the agent, build the trusted core, recover, change models, move hardware, or keep operating.
- **Open trusted base:** boot, kernel, memory management, scheduling, storage, cryptography, identity, AEGIS, capability enforcement, update verification, recovery, and provenance build from inspectable source with a reproducible toolchain. Opaque software may accelerate AIENOS; it may never be required to trust, build, boot, recover, or control it.
- **Fastest thing possible:** close to the metal, measured, with evidence.
- **Free inside reversible state; explicit authorization at irreversible boundaries.**

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the governing design, [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the 37-section blueprint, [docs/MILESTONES.md](docs/MILESTONES.md) for the phased milestone matrix, and [docs/adr/README.md](docs/adr/README.md) for architectural decision records and technical specifications.

## License

Apache-2.0 WITH LLVM-exception. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
