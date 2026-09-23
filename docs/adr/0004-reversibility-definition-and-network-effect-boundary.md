# ADR 0004: Reversibility Definition and Network Effect Boundary

Status: accepted by the operator, 2026-09-23.
Governing: [ARCHITECTURE.md §5](../ARCHITECTURE.md), [BLUEPRINT.md §5, §12, §13](../BLUEPRINT.md), [MILESTONES.md Phase 4](../MILESTONES.md).
Specification: [PHASE_3_TO_5_SPECIFICATION.md §3](../PHASE_3_TO_5_SPECIFICATION.md#3-phase-4-native-system-intelligence-aegis-worlds-capabilities).

## Context

Agent autonomy requires sandbox environments ("Worlds" / J-Space) where speculative reasoning, exploratory code execution, and intermediate computations can be evaluated safely. If effects inside a World cannot be rolled back, speculative execution risks leaking or corrupting persistent state. Outbound network traffic, DNS requests, and external device mutations leave irreversible traces in the external world.

## Decision

An action inside a World is reversible if and only if every externally observable state change caused by the action remains under AIENOS's transactional control, such that prior observable state can be restored without external cooperation.

Because outbound network packets, telemetry, and external device state leave permanent externally observable artifacts (DNS logs, server connection logs, metadata disclosure), all outbound network access is classified as an external effect (`EffectIntent`) crossing into AEGIS, even when read-only.

Reversibility and authorization are decoupled: agents may execute network fetches autonomously via pre-authorized standing capabilities, but network traffic never bypasses AEGIS capability evaluation under the guise of being "reversible research."

## Consequences

- Reversible execution is strictly confined to local transactional boundaries (memory and snapshot-capable local storage).
- Outbound network requests and hardware device state mutations are never classified as reversible; they require AEGIS policy evaluation and capability authorization.
- Agents cannot evade capability gates by labeling external communication as speculative or exploratory.
