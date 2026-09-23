# Architectural Decision Records (ADRs)

This directory documents the key architectural decisions for AIENOS. Each record captures the context, decision, invariants, consequences, and operator approval.

## Index of Decisions

| ADR | Title | Status | Date | Primary Cross-References |
|---|---|---|---|---|
| [ADR 0001](0001-native-boot-milestone-and-linux-island.md) | Native boot with CPU inference stays the next milestone; minimal Linux is only Benchmark Config B | Accepted | 2026-09-23 | `ARCHITECTURE.md` §3, §7; `BLUEPRINT.md` §8, §15, §16, §19, §31; `MILESTONES.md` Phase 1, 2, 5 |
| [ADR 0002](0002-incumbent-os-as-migration-environment.md) | Incumbent operating systems are bootstrap and migration environments | Accepted | 2026-09-23 | `ARCHITECTURE.md` §3; `BLUEPRINT.md` §20, §21, §22, §23, §34; `MILESTONES.md` Phase 1, 6 |

## Governance

ADRs reflect decisions confirmed by the operator. Changes to the core decisions or invariants documented here require operator escalation and approval per `docs/ARCHITECTURE.md` §9.
