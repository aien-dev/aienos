# ADR 0001: Native boot with CPU inference stays the next milestone; minimal Linux is only Benchmark Config B

Status: accepted by the operator, 2026-09-23.

## Context

An outside proposal ("Spark Native Boot v0") suggested making the next target a minimal Linux kernel that boots straight into `aien-init` as PID 1, keeps the NVIDIA kernel modules for the GPU, and runs the frozen inference stack with no general-purpose Linux userspace.

Useful parts of the proposal:

- AIEN owns the hot path: no HTTP/JSON between internal components, fewer copies, resident models, direct accelerator-memory management, copy-on-write agent state.
- Removing the general-purpose OS does not make GPU matrix multiplication faster. The likely gains are boot-to-ready time, freed memory, lower jitter, determinism, and multi-agent density.
- Run the same machine in comparable configurations and measure the difference.

Parts that conflict with the governing architecture ([ARCHITECTURE.md](../ARCHITECTURE.md)):

- It makes Linux the substrate of the destination. The first milestone says Linux is not the host (section 6), and the kernel, agent, storage, and capabilities must never depend on Linux (section 3).
- Its GPU path relies on NVIDIA userspace (`libcuda`, the PTX JIT). Those components are opaque and may not be in the trusted base.
- Adopting it as the next milestone would delay native AIENOS boot and put effort into the compatibility layer, which risks that layer becoming the architecture by inertia.

## Decision

Keep **native AIENOS boot on the Spark with CPU inference** as the next primary milestone.

Build the minimal-Linux configuration only as **Benchmark Config B** and as the temporary **Era II GPU compatibility island**. This does not change the sovereignty requirement, the native-kernel trajectory, or the ban on Linux and CUDA dependencies in the trusted native path.

### Three configurations

| Config | Stack | Role |
|---|---|---|
| A: Ubuntu reference | Ubuntu, services, AIEN runtime, model, GPU | Frozen Linux reference baseline (roadmap step 1) and its measurements |
| B: minimal-Linux GPU island | minimal Linux kernel, `aien-init` as PID 1, only the Linux/NVIDIA machinery the current GPU path needs | Control experiment; temporary accelerator performance while the native stack matures |
| C: native AIENOS | AIENOS owns boot, CPU, memory, interrupts, storage, console, recovery, Cortex persistence, CPU inference | The main engineering milestone |

### B must never become a prerequisite for C

C may not depend on Linux abstractions, Linux drivers, CUDA, NVIDIA userspace, or artifacts that can only be produced through the Linux island. Removing A and B must leave C buildable, bootable, and recoverable.

### Scope of "fastest wins"

For a capability AIENOS natively owns, the fastest correct implementation wins. A compatibility island may outperform the native path for a while, but it does not define the trusted base or the destination.

### Benchmark protocol

A, B, and C run the same frozen workload (same model weights, prompts, sampling settings, and correctness envelope) and emit the same receipt format. Report each metric separately; never collapse them into one "faster" number:

1. boot to AIEN ready
2. AIEN ready to model ready
3. time to first token (TTFT)
4. steady-state throughput (tokens/s)
5. idle memory
6. available memory
7. scheduler jitter
8. power
9. branch cost (creation latency and memory overhead)

Expected shape: B may beat C on model throughput for some time because NVIDIA's stack is mature. C may already beat A and B on boot time, memory overhead, jitter, and determinism. These are separate engineering results.

## Consequences

- Kernel, boot, storage, and console work for C continues as planned. It is not blocked on B.
- B is built only when a benchmark or GPU performance needs it, and it is kept deliberately small.
- Every A/B/C comparison is rerun and reproduced before its figures are reported.
- If B's convenience ever starts pulling C design toward Linux interfaces, that is a violation of this ADR and goes back to the operator.
