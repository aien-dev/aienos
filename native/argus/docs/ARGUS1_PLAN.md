# ARGUS-1 (containment) execution plan

Spec: native/argus/docs/ARGUS1_SPEC.md (pre-registered 2026-09-29 on feat/argus-1-spec, base a64bc55).
Code held until ARGUS_PERFORMANCE_GATE passes (FAIL at a64bc55).
Everything in C. No GPU use anywhere. Reports go to ~/workspace/argus-reports/<lane>.md.

## 0. Preconditions (orchestrator; no ARGUS-1 code before all hold)

1. ARGUS-0 closed: integrator round 3 finished on feat/argus-0 (WIP be2814d is unverified),
   ARGUS0_GATES.md written, draft PR open. Handoff rule: ARGUS-1 code only if all ARGUS-0 gates
   pass; otherwise spec only.
2. DONE: authority observer hook 12add16 (feat/capability-observer) merged to aienos main
   (d39dd5b); lane G bases on it.
3. Record the ARGUS-0 closing commit hash + its Spark bench numbers: this is G8's baseline.
4. Decisions D1-D5 answered (done 2026-09-29, spec section 0), then the spec commit (done).
5. ARGUS_PERFORMANCE_GATE: PASS-WITH-DOCUMENTED-LIMITS at omega cf6f45d (requires spare core;
   unpinned FAIL). Was FAIL at a64bc55: R8 wall +6.2%.

## 1. Lanes

No two lanes touch the same production file. argus_abi.h is orchestrator-only.
Worktrees: ~/workspace/aienos-argus1-<lane> on branches feat/argus-1-<lane>, cut from the spec
commit (after the header commit). Omega lane: ~/workspace/omega-argus1-o.

| Lane | Owner files | Needs | Where | Size |
|---|---|---|---|---|
| L0 orchestrator | argus_abi.h (v1.2), Makefile, docs/ARGUS1_SPEC.md, tests/test_argus_integration.c | preconditions | Mac | ~150 header lines |
| B event/ring | argus_event.c, argus_ring.c, tests/test_argus_event.c, tests/fuzz_argus_event.c, tests/test_argus_ring.c | L0 header | Mac, then Spark (fuzz/TSan) | ~250 + 300 test |
| D core | argus_core.c, argus_core.h, tests/test_argus_core.c, tests/test_argus_determinism.c | L0 | Mac, then Spark | ~80 + 150 test |
| C contain (new) | argus_contain.c, argus_contain.h, tests/test_argus_contain.c | L0 (B for request encode) | Mac, then Spark | ~600 + 800 test |
| E corpus | tests/stub_state.c, tests/stub_state.h (containment scenario generators) | L0 | Mac | ~300 |
| G AEGIS gate (new) | native/capability/aienos_contain.c/.h, native/capability/tests/contain_test.c, native/capability/Makefile | observer hook; L0 for the layout twin | Mac, then Spark | ~500 + 600 test |
| X bridge (new) | native/argus/bridge/argus_aegis_bridge.c/.h, tests/test_argus_containment_e2e.c | B, C, D, G | Spark (links the authority, pthread) | ~300 + 600 test |
| H hostile | tests/test_argus_contain_hostile.c, docs/HOSTILE_REVIEW.md (containment section) | X | Spark | ~700 |
| F perf + FP | tests/bench_argus_contain.c, docs/ARGUS1_GATES.md | X, H | Spark only, quiet | ~250 |
| O Omega binding (optional) | omega src/runtime/rx_aegis_contain.c/.h + test (new files only) | G merged | Spark | ~250 |
| A ADR amend | aien-architecture docs/adr/0017 §4, §5, §13, §16 | spec final | Mac | ~150 doc lines |

### Lane briefs

L0: Write the spec commit. Then header v1.2: kinds 90-93 + field conventions (spec §3); codes
17-20, F_MAX 20, KIND_MAX 93; request struct append + ARGUS_CONTAIN_REQUEST_SIZE 152 +
encode/decode/digest declarations; ArgusContainHealth; argus_core_incident declaration; table
constants. Makefile targets for the new tests. After X: extend test_argus_integration.c with
the G2/G6 end-to-end runs and GATE lines. Owns all merges and the final PR.

B: Validate kinds 90-93 (status/outcome pairs, CRITICAL floor, CONSUMER iff kind in {80,90}).
argus_ring_push refuses kind 90 (MALFORMED). Request encode/decode/digest (152 bytes, known
answers). Extend the fuzz run to requests. Prove the ARGUS-0 event/chain vectors are unchanged.

D: The core accepts kinds 90-93: validated, chained, counted, no shadow change; detectors never
see them as triggers. Implement argus_core_incident(). Determinism test gains a recorded
containment stream. Core state digest stays v3 (no new state).

C: New module per spec §4: observe/propose API, pending 32 / recent 128 / window budget,
state machine 4.1, proposal rules 4.2 (incl. the never-propose filter), codes 17-21, health,
state digest. No authority include. Unit tests for every transition and every suppression.

E: Corpus generators: finding storm (G5), 256-principal amplifier, cap-0 framing streams,
table saturation, and a benign stream with healthy grant/revoke churn (G10). No production code.

G: New AEGIS containment gate per spec §5 inside native/capability (authority file untouched):
authorizer interface + table policy, REVOKE-only executor cap minted at create, protected
list, request_id/decision_id rules, budget, secret-gated resolve, UNAVAILABLE for non-LIVE types,
sink, lineage index fed by the observer (leaf check, I1), re-check before revoke. Test seams to
disable the protected list (for G9's layer tests) and to mint a child between decide and execute. The layout twin
AienosContainRequest + an offsetof test. Validate instruction count re-checked (179).

X: The trusted glue per spec §6. The e2e tests for G3/G4/G6: real authority + observer + gate +
ARGUS in one process, a single bridge thread, the order 90,91,4..,92 asserted. An offline
chain checker (G6) as a test helper.

H: Read-only hostile pass over spec + code first, then the G9 test list; each test labelled
DEFENDED/EXPECTED-FAIL like ARGUS-0; HOSTILE_REVIEW.md containment section with verdicts.

F: Take ~/workspace/.argus-bench.lock (flock); refuse to start while ~/workspace/.spark-quiet
exists. Interleaved A/B x5 against the ARGUS-0 closing commit (G8). G10 over the benign corpus
x9 and the recorded R7/R8/R9 streams. Write ARGUS1_GATES.md with every GATE line.

O (optional, own gate O-G1): Bind AienosContainAuthorizer to Omega's policy faculty: a new
rx_aegis_contain file calling rx_aegis_evaluate-style rules for containment, plus kind 93 on
grant ESCALATE (closes ADR §16.4 in the runtime). Pinned to aienos via argus.lock like lane H.
Follows the omega session rules (one merge + one heavy test at a time). May slip to ARGUS-2
without blocking ARGUS-1.

A: Amend ADR 0017: §4 chain now concrete (spec §1, §5); §5 sync table ratified, none wired;
§13 ladder reconciled (see risks); §16.4 closed by kinds 91/93. Local commit only, push per D6.

## 2. Ordering

```
wave 0  preconditions -> spec commit -> L0 header v1.2
wave 1  B, D, C, E, G in parallel (C uses B's encode via the header declaration; stub until B lands)
wave 2  merge B, D, C, E, G -> X bridge + e2e; O may start once G merges
wave 3  H hostile, then F perf + FP (Spark, quiet), then L0 integration + G12 full run
wave 4  A ADR amend; PR (aienos: argus + capability parts together, or gate as its own PR)
```

Gate-to-lane: G1 B+L0, G2 C+D+L0, G3/G4/G6 X, G5 C+E, G7 C+G, G8 F, G9 H, G10 F+E, G11 L0,
G12 L0, G13 (invariants I1-I5) H+X.

## 3. Mac vs Spark

Mac (rsync + `make test`, arm64 clang): all unit work in waves 0-1 and plain `make test`.
Spark: sanitizers (Linux-only `make sanitize`), TSan, the bridge (pthread + authority),
hostile, all benches, the G10 runtime streams. Only while no .spark-quiet file exists, and under
the bench lock. No GPU seat is used by any lane.

## 4. Estimated size

~4,500 lines total (about 1,900 production, 2,600 tests), 9 workers + the orchestrator,
3-4 waves. The largest lanes are C and X.

## 5. Risks

- G-5 (no producer identity): a trusted producer can frame a principal and trigger a freeze
  request. Bounded by "ask" policy + budget; closed only by producer attestation (later rung).
- Only 1 of 10 containment types is live; reviewers may read "ARGUS-1 containment" as more.
  Every SYNTH path carries the SYNTHETIC flag and the gates label it.
- The authority itself allows an office-rights holder to revoke slot 0. The REVOKE-only
  executor cap is the structural defence; G9 layer 3 must prove it.
- The observer runs outside the table lock; multi-thread ordering is not guaranteed. The bridge
  serializes on one thread; any other admin caller in the process can interleave (documented).
- Revoke's observer snapshot is ~23 KB of stack: the bridge thread needs a normal stack.
- G8 depends on a quiet Spark; the other session's omega runs can block it (do not wait: report
  BLOCKED, not FAIL).
- Ladder mismatch: brief §4 lists containment as ARGUS-2, brief §9 as ARGUS-1; ADR 0017 §13
  puts ARGUS-1 = containment, ARGUS-3 = evidence, ARGUS-7 = Fabric, while the handoff says
  producer attestation is ARGUS-3 and this task calls Fabric quarantine ARGUS-2. Lane A
  reconciles §13 to one table; nothing in ARGUS-1 depends on the numbering.
- H2 (omega producer redesign) is WIP and unverified; its numbers are not used as a baseline.

## 6. Decisions

Decided by Drake 2026-09-29 and encoded as binding invariants I1-I5 in ARGUS1_SPEC.md section 0,
each with hostile tests in gate G13:

- D1 DECIDED (I1): automatic action = revoking ONE ordinary, narrowly scoped capability from ONE
  subject: a leaf (no live descendants), non-privileged cap of a non-privileged subject, on a
  DETERMINISTIC finding for that exact (cap_id, generation). No cascades. Attributable,
  generation-bound, receipted, recoverable by operator re-mint. Everything else waits for Drake.
- D2 DECIDED: Drake is the "human" for ESCALATE; ARGUS-1 uses a test stub holding the owner
  secret; unanswered requests expire until a real approval screen exists (later rung).
- D3 DECIDED (I2): FreezePrincipal stays a synthetic stand-in until a real qualified suspension/
  isolation primitive exists; nothing may imply a real freeze exists.
- D4 DECIDED (I3): whole-system actions (shutdown, global quarantine, trust-root replacement,
  mass revocation, whole-machine rollback, promotion/recovery authority) are never ARGUS actions;
  operator/governance/AEGIS path only.
- D5 DECIDED (I4): no synchronous blocking in ARGUS-1; the table is ratified as data only.
- Extra rule (I5): ARGUS never expands its own authority; it uses only the pre-granted
  REVOKE-only executor cap, and every use is independently auditable.
- D6 OPEN: ADR 0017 push + PR to aien-architecture (the harness refused the worker's push before;
  needs Drake's OK).
- D7 OPEN: MachineId/Fabric identity. Until decided, machine quarantine and re-attestation stay
  synthetic, and producer attestation cannot start.

Orchestrator calls (not Drake): the gate lives in native/capability behind an authorizer
interface (Omega cannot be linked from aienos); the gate ships in the same PR as argus or as
its own capability PR; the Omega lane O stays optional.
