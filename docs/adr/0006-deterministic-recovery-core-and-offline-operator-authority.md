# ADR 0006: Deterministic Recovery Core and Offline Operator Authority

Status: accepted by the operator, 2026-09-23.
Governing: [ARCHITECTURE.md §1, §4, §6](../ARCHITECTURE.md), [BLUEPRINT.md §5, §6, §33](../BLUEPRINT.md), [MILESTONES.md Phase 2, 6](../MILESTONES.md).
Sequence: [SYSTEMS_INTEGRATION_SEQUENCE.md Step 5](../SYSTEMS_INTEGRATION_SEQUENCE.md#step-5-prove-recovery-core-before-the-model-adr-0006).

## Context

If an operating system relies on an AI model or remote cloud network services to diagnose panics, verify boot health, authenticate operators, or repair corrupted persistent journals, any model hallucination, weight corruption, or network outage could render the machine permanently unbootable and irrecoverable.

## Decision

AIENOS incorporates an autonomous, deterministic Recovery Core operating completely outside the model, neural runtime, and network dependency chain.

Root authority and authentication are entirely local (supporting offline physical credentials such as hardware/FIDO keys or local human passphrase key derivation via Argon2id before challenge-response, with zero reliance on cloud identity or AI verification; bare SHA-256 for password verification is strictly prohibited).

System updates employ transactional A/B slot switching with deterministic kernel health milestone verification rather than subjective model assertions. Kernel panics capture deterministic crash records to dedicated raw storage, model weights are verified against cryptographic content hashes, and Cortex corruption is resolved via WAL truncation to the last valid committed record without requiring semantic model understanding.

## Consequences

- Machine survival and operator access never depend on model availability, inference correctness, or network connectivity.
- Corrupted WAL or model files are deterministically recovered or rolled back to verified states.
- System updates are atomic and safely reversible via hardware-backed A/B slots.
