# ADR 0003: Bootstrap Firmware Handoff and Minimal Persistent Object Store

Status: accepted by the operator, 2026-09-23.
Governing: [ARCHITECTURE.md §3](../ARCHITECTURE.md), [BLUEPRINT.md §5, §15, §17](../BLUEPRINT.md), [ADR 0001](0001-native-boot-milestone-and-linux-island.md), [MILESTONES.md Phase 2, 3](../MILESTONES.md).
Specification: [PHASE_3_TO_5_SPECIFICATION.md §2](../PHASE_3_TO_5_SPECIFICATION.md#2-phase-3-the-persistent-agent-wakes-up).

## Context

Firmware (UEFI) services provide early machine initialization and hardware discovery. However, relying on UEFI runtime services creates a permanent foreign dependency on platform firmware code of unknown provenance, quality, and security posture. Similarly, general-purpose POSIX filesystems (ext4, btrfs, ZFS) introduce massive metadata overhead, journal complexity, and foreign driver dependencies into the trusted computing base.

## Decision

Firmware (UEFI) loads the immutable AIENOS boot bundle into memory; firmware storage services are strictly bootstrap machinery and never part of the permanent runtime. Persistent AIEN state (model weights, Cortex database, agent state) is loaded only after AIENOS owns a native block device path.

Rather than implementing a complex general-purpose POSIX filesystem (e.g. ext4, btrfs), Phase 3 introduces a minimal, native persistent object store designed around immutable content-addressed extents (`model/<hash>`), journaled append-only state (`cortex/` WAL + checkpoints), and committed agent branches.

## Consequences

- Firmware handoff is one-way: once the native kernel initializes CPU and memory, firmware runtime calls are terminated.
- AIENOS boot does not depend on host partition schemes or complex POSIX filesystems.
- Persistent state is stored in content-addressed extents and append-only WAL streams, guaranteeing deterministic verification and crash recovery.
