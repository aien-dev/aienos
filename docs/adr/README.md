# Architectural Decision Records (ADRs) & Specifications

This directory documents the key architectural decisions and formal technical specifications for AIENOS. Each record captures the context, decision, invariants, consequences, and operator approval.

## 1. Master Index of Architectural Decision Records

| ADR | Title | Status | Date | Primary Cross-References |
|---|---|---|---|---|
| [ADR 0001](0001-native-boot-milestone-and-linux-island.md) | Native boot with CPU inference stays the next milestone; minimal Linux is only Benchmark Config B | Accepted | 2026-09-23 | [`ARCHITECTURE.md` §3, §7](../ARCHITECTURE.md); [`BLUEPRINT.md` §8, §15, §16, §19, §31](../BLUEPRINT.md); [`MILESTONES.md` Phase 1, 2, 5](../MILESTONES.md) |
| [ADR 0002](0002-incumbent-os-as-migration-environment.md) | Incumbent operating systems are bootstrap and migration environments | Accepted | 2026-09-23 | [`ARCHITECTURE.md` §3](../ARCHITECTURE.md); [`BLUEPRINT.md` §20, §21, §22, §23, §34](../BLUEPRINT.md); [`MILESTONES.md` Phase 1, 6](../MILESTONES.md) |
| [ADR 0003](0003-bootstrap-firmware-handoff-and-minimal-object-store.md) | Bootstrap Firmware Handoff and Minimal Persistent Object Store | Accepted | 2026-09-23 | [`ARCHITECTURE.md` §3](../ARCHITECTURE.md); [`BLUEPRINT.md` §5, §15, §17](../BLUEPRINT.md); [`MILESTONES.md` Phase 2, 3](../MILESTONES.md); [`PHASE_3_TO_5_SPECIFICATION.md` §2](../PHASE_3_TO_5_SPECIFICATION.md#2-phase-3-the-persistent-agent-wakes-up); [ADR 0001](0001-native-boot-milestone-and-linux-island.md) |
| [ADR 0004](0004-reversibility-definition-and-network-effect-boundary.md) | Reversibility Definition and Network Effect Boundary | Accepted | 2026-09-23 | [`ARCHITECTURE.md` §5](../ARCHITECTURE.md); [`BLUEPRINT.md` §5, §12, §13](../BLUEPRINT.md); [`MILESTONES.md` Phase 4](../MILESTONES.md); [`PHASE_3_TO_5_SPECIFICATION.md` §3](../PHASE_3_TO_5_SPECIFICATION.md#3-phase-4-native-system-intelligence-aegis-worlds-capabilities) |
| [ADR 0005](0005-unified-memory-c1-cow-and-reservation-accounting.md) | Unified Memory C1 Copy-On-Write and Reservation Accounting | Accepted | 2026-09-23 | [`ARCHITECTURE.md` §2, §7](../ARCHITECTURE.md); [`BLUEPRINT.md` §9, §10, §28](../BLUEPRINT.md); [`MILESTONES.md` Phase 4, 5](../MILESTONES.md); [`PHASE_3_TO_5_SPECIFICATION.md` §4](../PHASE_3_TO_5_SPECIFICATION.md#4-phase-5-native-hardware-acceleration--hardware-bound-c1-compute) |
| [ADR 0006](0006-deterministic-recovery-core-and-offline-operator-authority.md) | Deterministic Recovery Core and Offline Operator Authority | Accepted | 2026-09-23 | [`ARCHITECTURE.md` §1, §4, §6](../ARCHITECTURE.md); [`BLUEPRINT.md` §5, §6, §33](../BLUEPRINT.md); [`MILESTONES.md` Phase 2, 6](../MILESTONES.md); [`SYSTEMS_INTEGRATION_SEQUENCE.md` §2.5](../SYSTEMS_INTEGRATION_SEQUENCE.md#step-5-prove-recovery-core-before-the-model-adr-0006) |
| [ADR 0007](0007-continuous-existence-provisioning-once.md) | Continuous Existence and Provisioning-Once | Accepted | 2026-09-23 | [`CONTINUOUS_EXISTENCE_AMENDMENT.md`](../CONTINUOUS_EXISTENCE_AMENDMENT.md); [`ARCHITECTURE.md` §1, §10](../ARCHITECTURE.md); [`SYSTEMS_INTEGRATION_SEQUENCE.md` Steps 1–10](../SYSTEMS_INTEGRATION_SEQUENCE.md); [`MILESTONES.md` Phase 3, 6, 8](../MILESTONES.md); [ADR 0005](0005-unified-memory-c1-cow-and-reservation-accounting.md); [ADR 0006](0006-deterministic-recovery-core-and-offline-operator-authority.md) |
| [ADR 0008](0008-temporary-bring-up-firmware-report-exception.md) | Temporary bring-up exception: post-handoff firmware report (trigger 11) | Accepted (temporary) | 2026-09-24 | [ADR 0003](0003-bootstrap-firmware-handoff-and-minimal-object-store.md); [`MILESTONES.md` section 0](../MILESTONES.md); [`NATIVE_BOOT_ONE_TIME.md`](../NATIVE_BOOT_ONE_TIME.md) |
| [ADR 0009](0009-el2-bootstrap-to-el1h-kernel-transition.md) | Two-Stage Exception Level Architecture (EL2 Bootstrap to EL1h Kernel) | Accepted | 2026-09-24 | [`ARCHITECTURE.md` §3, §6](../ARCHITECTURE.md); [`BLUEPRINT.md` §8, §15](../BLUEPRINT.md); [`MILESTONES.md` Phase 2, 3](../MILESTONES.md) |
| [ADR 0010](0010-fabric-machine-identity-and-capability-advertisement.md) | Fabric Machine Identity and Capability Advertisement | Proposed (post-M6) | 2026-09-24 | [`ARCHITECTURE.md` §2](../ARCHITECTURE.md); [`BLUEPRINT.md` §21, §25, §26](../BLUEPRINT.md); [`MILESTONES.md` Phase 8](../MILESTONES.md); [ADR 0004](0004-reversibility-definition-and-network-effect-boundary.md); [ADR 0007](0007-continuous-existence-provisioning-once.md); [issue #37](https://github.com/aien-dev/aienos/issues/37) |
| [ADR 0011](0011-machine-1-hardware-test-rig.md) | Machine 1 Hardware Test Rig (Power, Capture, Input) | Proposed | 2026-09-24 | [`MILESTONES.md` section 0, gate M2C](../MILESTONES.md); [`HARDWARE_TEST_RIG.md`](../HARDWARE_TEST_RIG.md); [`NATIVE_BOOT_ONE_TIME.md`](../NATIVE_BOOT_ONE_TIME.md) |
| [ADR 0012](0012-self-construction-capability-growth-and-generations.md) | Self-Construction, Capability Growth, and Reversible System Generations | Accepted | 2026-09-24 | [ADR 0002](0002-incumbent-os-as-migration-environment.md); [ADR 0006](0006-deterministic-recovery-core-and-offline-operator-authority.md); [ADR 0007](0007-continuous-existence-provisioning-once.md); [`ROADMAP.md`](../../ROADMAP.md) (SEED-0A, SEED-0B) |
| [ADR 0013](0013-aienos-abi-v1.md) | AIENOS ABI v1 | Proposed | 2026-09-24 | [ADR 0012](0012-self-construction-capability-growth-and-generations.md); [ADR 0004](0004-reversibility-definition-and-network-effect-boundary.md); [issue #30](https://github.com/aien-dev/aienos/issues/30); [PR #106](https://github.com/aien-dev/aienos/pull/106); [`abi.rs`](../../crates/aienos-kernel/src/abi.rs) |

---

## 2. Architectural Specifications & Integration Frameworks

In addition to discrete decision records, AIENOS maintains formal technical specifications and execution sequences that govern phased implementation:

| Document | Scope | Status | Authority | Target Phases |
|---|---|---|---|---|
| [AIENOS Technical Specification & Contracts (Phases 3 – 5)](../PHASE_3_TO_5_SPECIFICATION.md) | Agent State ABI, Model ABI, Cortex Epistemic Store, AEGIS Effect Intent Pipeline, J-Space Worlds, and C1 CoW Prefix Tree | Confirmed Specification | Blueprint §§ 9–14, 17–19, 28 | Phases 3, 4, 5 |
| [AIENOS Systems Integration Sequence & Epistemic Calibration](../SYSTEMS_INTEGRATION_SEQUENCE.md) | 10-step empirical hardware integration sequence, epistemic claim precision, and host-tested vs. native-qualified gates | Governing Framework | Operator Directive (2026-09-23) | Phases 1 – 8 |
| [AIENOS Continuous-Existence Amendment](../CONTINUOUS_EXISTENCE_AMENDMENT.md) | Provisioning-once lifecycle, power states, state classes A/B/C, continuous-existence acceptance criteria for Gates 1–10 | Operator-Approved Governing Amendment | Operator Directive (2026-09-23); ADR 0007 | All Phases |
| [AIENOS Final Architectural Blueprint](../BLUEPRINT.md) | Complete 37-section architectural foundation, core principles, and final success definitions | Immutable Foundation | Operator Directive | All Phases |
| [AIENOS Architectural Milestones Matrix](../MILESTONES.md) | 8-phase execution roadmap, deliverables, invariant contracts, and escalation triggers | Confirmed Specification | Blueprint §36 | Phases 1 – 8 |
| [AIENOS Governing Architecture](../ARCHITECTURE.md) | High-level system overview, stack, trusted base, agent authority, security, and roadmap | Confirmed Architecture | Operator Directive | All Phases |

---

## 3. Operator Invariant Freeze Summary (2026-09-23)

The operator confirmed immutable architectural invariants in ADR 0003–0007:

1. **ADR 0003 (Firmware Handoff & AIEN System Store)**: Firmware loads the immutable boot bundle only. Firmware services are bootstrap machinery, never a runtime dependency. Phase 3 introduces a minimal native AIEN System Store (immutable content-addressed extents `model/<hash>`, Cortex WAL + checkpoints, agent branches) rather than a general-purpose POSIX filesystem.
2. **ADR 0004 (Reversibility & AEGIS Egress Boundary)**: Reversibility requires that all observable state changes remain under AIENOS transactional control. Outbound network packets, telemetry, and external device state are external effects (`EffectIntent`) crossing into AEGIS even when read-only. Reversibility and authorization are decoupled via Standing Capabilities; network access never bypasses AEGIS under the guise of "reversible research."
3. **ADR 0005 (Unified Memory & C1 Block Accounting)**: Unified memory (NVLink-C2C) requires explicit block ownership across System, Model, KV Pool, Agent State, and Cortex budgets. C1 CoW prefix tree uses shared immutable blocks (`refcount > 1`) and private blocks (`refcount == 1`). Multi-branch divergence mandates transactional KV reservations prior to step admission to prevent mid-step OOM corruption. Logical identity survives; physical state is expendable.
4. **ADR 0006 (Recovery Core & Offline Authority)**: Recovery Core is an autonomous, deterministic subsystem operating completely outside the model, neural runtime, and network stack. Root authority and authentication are strictly local (offline physical credentials/passphrase). System updates use transactional A/B slot switching with deterministic kernel health milestone verification. Kernel panics write deterministic crash records to raw storage, and Cortex corruption is resolved via WAL truncation without semantic AI dependencies.
5. **ADR 0007 (Continuous Existence & Provisioning-Once)**: AIEN is provisioned once. Boot, reboot, sleep, model reload, kernel restart, hardware failure, and migration are execution-state transitions—not agent creation events. Cold boot initializes hardware and never silently mints a replacement `LogicalAgentId`. Uncertain identity fails toward Recovery Core and operator decision, never toward false continuity. Gate order (1–10) is unchanged; continuous-existence acceptance criteria bind every gate.

---

## 4. Governance

ADRs reflect decisions confirmed by the operator. Changes to the core decisions, invariants, or specifications documented here require operator escalation and approval per [`docs/ARCHITECTURE.md` §9](../ARCHITECTURE.md).
