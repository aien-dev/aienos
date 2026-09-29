# ARGUS-1 gate evidence (2026-09-29)

This file records the gates measured by lanes F and H. The full pre-registered criteria
remain in `ARGUS1_SPEC.md`; unmeasured gates are not counted as passed here.

## G8 — hot-path non-regression: PASS

DGX Spark, GCC 13.3.0, core 7 pinned, paired A/B x5, each timing round processes 5,000
identical benign events in 100-event batches. Measurements ran with
`/home/drakestapleton/workspace/.argus-bench.lock` held and no `.spark-quiet` marker.

| Measurement | ARGUS-0 reference (`a64bc55`) | ARGUS-1 | Result |
|---|---:|---:|---|
| Ring push, single-thread p50 | 4.00 ns | 4.00 ns | Same median (0.00 ns change; within 0.5 ns limit) |
| Ring push, single-thread p99 | 5.00 ns | 6.00 ns | +1 ns observed; p99 is reported, not the registered median gate |
| Core ingest p50 | 1,055 ns/event | 1,070 ns/event with containment observe/propose attached | +1.42% (within +3% limit) |
| Core ingest p99 | 1,076 ns/event | 1,092 ns/event with containment observe/propose attached | Reported for context |
| `aienos_cap_validate` instruction count | — | 179 | Matches the registered count |

The authority implementation file has no diff from the ARGUS-1 main base. The ring source
is unchanged; the ring benchmark was re-run on both commits under the same pin and lock.
Benchmark numbers vary with host scheduling, so the registered comparisons are the result.
The two-thread ring throughput output is not used as a gate because pinning both worker
threads to one core measures scheduler contention rather than the normal two-core path.

Reproduce with `make -C native/argus bench`. The target refuses to run if
`~/workspace/.spark-quiet` exists, takes the lock, and pins the benchmark to core 7.

## G10 — false-positive containment: PASS

`make -C native/argus test-contain-fp` processed the nine benign generated corpora
(45,000 events total) and the recorded R7/R8/R9 streams (2,283 events total) through the
real core and containment proposal path while a real AEGIS gate and capability authority
with an observer and auto-grant policy were active. Each candidate proposal would be
submitted to the gate; the test found none. Result:

`GATE ARGUS1_FALSE_POSITIVE_PASS PASS events=47283 proposals=0 authority_calls=0`

The authority observer count was unchanged after gate creation, so the replay caused no
mint, revoke, decision, or execution. The recorded streams were captured from the
observer-backed runtime runs listed in the fixture README. They are replayed through an
isolated core because their original authority slot numbers cannot be transplanted into a
new authority instance. The streams are fixed test fixtures under
`tests/fixtures/argus1/`; their source and SHA-256 values are in that directory's README.

## Lane H hostile evidence

The current hostile containment suite reports 103 checks, 0 failures. See the containment
section in `HOSTILE_REVIEW.md` for defended cases and limits. Correct-secret human resolve
remains untested because the office secret is not exposed to the harness. Producer
attestation and validator enforcement of reserved stream 16383 remain outside ARGUS-1.

## G11 — synchronous policy and dependency direction: implementation check PASS

The full `make test` integration run reports the sync table equal to its ratified mask:
`0x453e == 0x453e`. The dependency-direction check runs through
`make -C native/argus test-contain-symbols`; it inspects the event, ring, and capability
authority objects and reports `GATE ARGUS1_AUTHORITY_DIRECTION PASS`. The authority, event,
and ring objects have no references into detection, containment, the gate, or bridge. The
capability gate's own `contain-checks` also verifies the opposite direction.

## G12 — regression and sanitizers: Linux PASS, Mac pending

On the DGX Spark, `make -C native/argus test` and `make -C native/argus sanitize` both pass,
including the authority containment suite, ARGUS containment tests, bridge tests, and hostile
tests. The sanitizer run includes ASan/UBSan and TSan; the bridge TSan run passed. The separate
capability suite passes 664 checks in regular and ASan/UBSan builds. The registered Mac `make
test` run has not been performed, so G12 is not yet closed.

## G13 — invariants I1–I5: partial, dependency G6 open

`make -C native/capability test-contain` prints PASS for its implemented I1/I2/I3/I4/I5
checks and reports 664 checks with 0 failures. I1.c/I1.d evidence correlation and I5.d's
observer-only independent audit still depend on the unimplemented G6 offline checker. G13
therefore remains open until G6 is delivered and the full invariant set is rerun together.
