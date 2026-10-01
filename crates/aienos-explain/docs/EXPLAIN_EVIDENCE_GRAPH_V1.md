# Evidence graph contract `aien.explain.evidence-graph` v1

Language-neutral input of the explanation bridge. Any producer (Rust, C, Omega)
writes this JSON document; `aienos-explain` turns it into a grounded explanation
path. Field names, codes and meanings below are the contract; the Rust structs in
`src/contract.rs` are one implementation of it.

## Document

| field | type | meaning |
|---|---|---|
| `format` | string | always `aien.explain.evidence-graph` |
| `version` | u16 | `1` |
| `producer` | string | who wrote it, e.g. `spark-rsi/explain` |
| `nodes` | array of node | at most 65536 |
| `truncated_at` | array of string | node ids whose parents the producer did not expand because of its own limits (optional) |
| `scope` | object | optional `{ "branch": id, "referenced": [ids] }`: records a reasoning branch referenced directly |

## Node

| field | type | meaning |
|---|---|---|
| `id` | string | unique; namespaced by source, e.g. `cortex:<32 hex>`, `branch:<64 hex>`, `rsi:hypothesis:<id>` |
| `kind` | u16 | artifact kind code (below) |
| `status` | u8 | epistemic status code (below) |
| `statement` | string | the claim or record, as recorded by the source |
| `source` | object | `{ system, artifact, reference, digest? }`; `digest` is lowercase hex |
| `confidence_permille` | u16 0..=1000 | only where the source has the concept (optional) |
| `confidence_basis` | string | where that number came from, e.g. "declared, not measured" (optional) |
| `recorded_at_utc` | u64 | informational only; never used for ordering or linking (optional) |
| `parents` | array of `{ to, relation }` | at most 1024; explicit links only |
| `measurements` | array of `{ name, value, unit }` | `value` is a decimal string formatted by the producer |
| `missing` | array of `{ expected, reason }` | links the producer knows should exist but has no artifact for |
| `notes` | array of string | caveats from the producer |

## Codes

Status (`status`), identical to aienos Cortex `EpistemicStatus` for 1..6:
0 Unclassified, 1 DirectObservation, 2 VerifiedFact, 3 Inference, 4 Hypothesis,
5 Contradiction, 6 OperatorDecision. Grounding statuses: 1, 2, 6.

Kind (`kind`): 1 CortexRecord, 2 CapabilityMetric, 3 CapabilityAnalysis,
4 Diagnostic, 5 Hypothesis, 6 Prediction, 7 Falsification, 8 EvaluationReceipt,
9 PromotionState, 10 OperatorDecision, 11 AgentBranch, 12 Conclusion, 13 Alternative.

Relation (`parents[].relation`), from the node to the parent:
1 SupportedBy, 2 Evaluates, 3 PartOf, 4 Contradicts, 5 AlternativeTo, 6 References.
Only 1, 2, 3 and 6 are support and are walked. 4 and 5 are disclosed (conflicts,
alternatives) and never count as support.
References (6) is the weak form of support: the producer uses it when a link is
inferred from matching content rather than a recorded id, and should also declare
the missing recorded link in `missing`.

Errors (stable numeric codes): 1 BadFormat, 2 UnsupportedVersion, 3 UnknownCode,
4 DuplicateNodeId, 5 TargetNotFound, 6 GraphTooLarge, 7 StepOutOfRange,
8 NotInBranchScope, 9 Journal, 10 InvalidLimits.

## Builder guarantees

- Bounded: `max_depth` (default 32, cap 256) and `max_nodes` (default 256, cap 4096).
- Breadth-first walk from the target over support edges, parents in (relation, id)
  order; grounding nodes end the walk.
- Loops are cut and reported (`Cycle`); unknown parents are reported
  (`MissingParent`), never filled in; producer `missing` entries become `MissingLink`.
- A Contradicts edge is disclosed when either end is on the path, whatever the status
  of the node carrying it (`ConflictingEvidence`). Contradicting nodes are never walked.
- Every visited node listed in `truncated_at` is reported as `Truncated`.
- Linear order: every step after the steps it rests on; ties by narrative role
  (Observed, Analysis, Hypothesis, Prediction, Falsification, Evaluation, Decision,
  Conclusion), then by id. The target is last.
- Deterministic: same document and limits give the same bundle and digest.
- The bundle has no field for prose or analogies and grants no authority.

## Versioning

Any change to a field meaning or a code is a new `version`. Adding an optional field
with a default is allowed within v1 only if old readers can ignore it safely.
