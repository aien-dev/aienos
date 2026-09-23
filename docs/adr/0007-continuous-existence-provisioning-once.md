# ADR 0007: Continuous Existence and Provisioning-Once

Status: accepted by the operator, 2026-09-23.
Governing: [ARCHITECTURE.md §1, §10](../ARCHITECTURE.md), [BLUEPRINT.md §2, §9, §17, §33](../BLUEPRINT.md), [MILESTONES.md Phase 3, 6, 8](../MILESTONES.md).
Sequence: [SYSTEMS_INTEGRATION_SEQUENCE.md Steps 1–10](../SYSTEMS_INTEGRATION_SEQUENCE.md) (acceptance criteria amended; gate order unchanged).
Full text: [CONTINUOUS_EXISTENCE_AMENDMENT.md](../CONTINUOUS_EXISTENCE_AMENDMENT.md).

## Context

Boot, reboot, sleep, model reload, kernel restart, hardware failure, and migration were at risk of being treated as agent-creation events. That would make logical identity depend on execution substrates (process, model, KV, RAM, kernel, boot session, machine) and would weaken the C1 rule that physical loss costs computation, not identity.

## Decision

AIEN is provisioned once. After initial provisioning creates the durable `LogicalAgentId` and agent root, every later machine start is an execution-state transition that must locate, verify, and resume that identity—or stop in the deterministic Recovery Core. Cold boot initializes hardware; it does not create AIEN.

State is classified Class A (durable semantic), Class B (reconstructible physical), or Class C (ephemeral scratch). Commit-before-observation binds externally visible semantic transitions. Wake is reconstruction, not revival. Model, kernel, and hardware lifecycle events never implicitly mint a replacement identity.

The locked 10-gate Systems-Integration Sequence keeps its order. Continuous-existence acceptance criteria are inserted into Gates 1–10 as specified in the amendment. Failure semantics fail toward preservation: uncertain continuity never auto-creates a new agent.

## Consequences

- Cold boot, sleep, deep sleep, cold recovery, runtime/kernel restart, model replace, and migration are lifecycle transitions with auditable continuity receipts—not agent creation.
- Gate 4 becomes the first durable continuity foundation; Gate 6 is the first empirical power-cycle identity proof; Gate 7 proves model replaceability under one identity.
- Recovery Core must refuse silent identity replacement when durable state cannot be verified (extends ADR 0006).
- C1 physical discard/reconstruct cases (extends ADR 0005) bind to native lifecycle semantics.
- Lifecycle metrics (wake-to-continuation, reconstruction latencies) join Config A/B/C benchmarks without replacing boot metrics.
