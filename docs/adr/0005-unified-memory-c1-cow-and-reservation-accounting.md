# ADR 0005: Unified Memory C1 Copy-On-Write and Reservation Accounting

Status: accepted by the operator, 2026-09-23.
Governing: [ARCHITECTURE.md §2, §7](../ARCHITECTURE.md), [BLUEPRINT.md §9, §10, §28](../BLUEPRINT.md), [MILESTONES.md Phase 4, 5](../MILESTONES.md).
Specification: [PHASE_3_TO_5_SPECIFICATION.md §4](../PHASE_3_TO_5_SPECIFICATION.md#4-phase-5-native-hardware-acceleration-hardware-bound-c1-compute).

## Context

On architectures with unified physical memory between CPU and GPU (such as NVLink-C2C on NVIDIA DGX Spark), address spaces are physically unified. Without explicit ownership and strict accounting, multi-branch agent reasoning can exhaust memory mid-step, corrupt shared KV cache prefixes, or allow memory churn across speculative branches to starve core system processes.

## Decision

Hardware unified addressability (NVLink-C2C on DGX Spark) does not mean unstructured ownership: AIENOS explicitly owns, tracks, and accounts for every physical inference KV block with distinct memory budgets (System, Model, KV Pool, Agent State, Cortex).

Branches hold block tables mapping to shared physical prefix blocks (`refcount > 1`, immutable) and private blocks (`refcount == 1`). Multi-branch divergence is managed via transactional KV reservations prior to step admission to prevent out-of-memory mid-step corruption.

Under memory pressure, physical state is reclaimed according to a value-preserving hierarchy (completed private state -> suspended private suffixes -> suspended shared prefix leases -> reconstructible state); logical agent identity and token lineage survive indefinitely while physical state is reconstructed from canonical history if evicted.

## Consequences

- Prefix sharing achieves sublinear physical memory scaling across concurrent reasoning branches.
- Physical memory exhaustion causes transactional admission denial or graceful eviction, never corrupted state or lost agent identity.
- Explicit refcounting prevents child branch mutations from corrupting parent or sibling KV state.
