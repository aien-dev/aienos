# ARGUS-0 exit gates

**ARGUS-0 verdict:** 8 of 10 gates PASS (hostile = PASS-WITH-DOCUMENTED-LIMITS), RUNTIME_INTEGRATION **PASS-WITH-OPEN-FINDINGS**, PERFORMANCE **FAIL**. ARGUS-0 is **NOT** claimed complete; ARGUS-1 is spec-only until the performance gate passes. Runtime and performance evidence: omega `feat/argus-producer` @ `20e84b8`, draft PR https://github.com/aien-dev/omega/pull/70.

One row per exit gate from the ARGUS-0 brief. Each gate has a definition (what must
hold), a measurement (the command), the result, the commit and the environment. A gate
line printed by the tests has the form `GATE <NAME> PASS|FAIL <evidence>`; this file
copies the evidence, it does not replace it.

Code commit measured: **`b375dca`** on `feat/argus-0` (header `argus_abi.h` v1.1 =
`398cfb9`, byte-identical since; round-3 code commits `df27200`, `62e5163`, `ee87069`).
Measured 2026-09-29 00:15-00:20 CDT.
Re-run 2026-09-29 00:31 CDT on the Spark at `a77ce9d` plus the reconcile docs commit (code
unchanged): `make test` exit 0, every gate line and the hostile summary identical.

Environments:
- **Spark**: NVIDIA DGX Spark, aarch64, Linux 7.0.0-1019-nvidia, gcc 13.3.0 (Ubuntu
  13.3.0-6ubuntu2~24.04.1), `-std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong`.
  No `.spark-quiet` flag present. Bench taken under `flock ~/workspace/.argus-bench.lock`;
  no omega R8/bench process running, load average 0.76 / 0.91 / 0.87 right after the bench
  (not measured under concurrent load).
- **Mac**: MacBook, arm64, Apple clang 17.0.0 (clang-1700.6.4.2), same flags, `make test`
  only (ASan/TSan runtimes hang on that host; `make sanitize` is Linux-only).

Commands (from the repository root):
- `make -C native/argus test` (all lane tests + integration gates + hostile review)
- `make -C native/argus sanitize` (integration gates under ASan+UBSan and TSan, hostile
  under ASan+UBSan, ring under TSan, detectors under ASan)
- `flock ~/workspace/.argus-bench.lock make -C native/argus bench`

| Gate | Definition (what must hold) | Measured by | Result | Commit | Env |
|---|---|---|---|---|---|
| ARGUS_EVENT_ABI_PASS | The 128-byte v1 event encodes/decodes deterministically: known-answer digests for event, chain (x2) and finding match; every corpus event round-trips encode -> decode -> re-encode byte-identical with digest == SHA-256(bytes); a version-2 byte is rejected; validate rejects every malformed field value; fuzzed buffers agree with an independent byte oracle. | `make test`: integration gate + `test_argus_event` + `fuzz_argus_event` | **PASS**. Known-answer 4/4; round trips benign 5000/5000, hostile 5000/5000, bad 0; v2 rejected. Lane B: 48 kind x class round trips, 206,363 malformed field values; fuzz 1,000,000 buffers, 0 oracle violations (also under ASan+UBSan). | `b375dca` | Spark + Mac |
| ARGUS_EVENT_SECRET_NEGATIVE_PASS | No authority secret can travel in or be named by ARGUS: the authority's secret word and its length macro appear in no file under `native/argus/` (recursive, docs and tests included, build output excluded); no event field is secret-sized except the two 32-byte digest/identity slots. | `make test`: integration gate (recursive scan + static layout check) | **PASS**. 29 files in 3 dirs at `b375dca` (30 with this file, re-run after writing it: still 0 hits), 0 hits, 0 scan errors; 15 fields != 32 B, only `machine_id`/`evidence_digest` are 32 B, field sum 128. Residual: those two opaque slots could carry a secret if a producer misuses them (hostile G-12, WEAK, producer-side guard). | `b375dca` | Spark + Mac |
| ARGUS_EVENT_TRANSPORT_PASS | The bounded ring loses nothing silently: every push attempt is accounted as pushed or refused (per class), every refusal is reported by a consumer TELEMETRY_DROPPED, and that report produces the expected TELEMETRY_LOSS findings; a fast consumer sees zero refusals. | `make test`: integration gate (hostile corpus seed 1, ring 1024) + `test_argus_ring` (+ TSan in `sanitize`) | **PASS**. Fast consumer: 5000 = 5000 pushed + 0 refused. Burst: 5000 = 1094 pushed + 3906 refused, 5 drop events reporting 3906 lost, TELEMETRY_LOSS 3/3 expected, identity holds (burst split varies run to run: threaded). Ring: 10M attempts, identity holds, FIFO per class, TSan clean. | `b375dca` | Spark + Mac (TSan Spark) |
| ARGUS_TRANSPORT_SATURATION_PASS | Class watermarks hold under a stalled consumer: INFORMATIONAL refused at 50%, SECURITY at 90%, CRITICAL only at 100%; SECURITY is never refused while INFORMATIONAL is still accepted; nothing is refused below its limit; every drop is reported with the right severity. | `make test`: integration gate (200,000 attempts, ring 1024) + ring bench saturation table | **PASS**. Refused below limit INF/SEC/CRIT 0/0/0; SEC refused while INF accepting 0; CRIT refused below 100% 0; drop events 87 -> TELEMETRY_LOSS 58/58 expected, wrong severity 0. Bench (cap 4096): measured refusal depths 4096/3687/3072/2048 match the design points. | `b375dca` | Spark + Mac |
| ARGUS_CORE_DETERMINISM_PASS | Same event stream => byte-identical finding sequence, state digest and evidence chain, whether events go directly into the core or through the ring, and across fresh cores, chunkings and snapshot copies. | `make test`: integration gate + `test_argus_determinism` | **PASS**. Hostile seed 1, 5000 events: direct vs ring findings 100 vs 100 byte-identical, state digest equal, chain equal, third fresh core identical (state 70e0106d.., chain b0297a7f.., findings-bytes 216396f9..). Lane D: 13/13 (10,000 events, 1,653 findings). | `b375dca` | Spark + Mac |
| ARGUS_HARD_INVARIANTS_PASS | Every injected hard-invariant violation in the hostile corpus is found by the real core + real detectors with the exact expected code, and nothing else fires: no unexpected hard finding, no spurious sequence (12) or telemetry-loss (11) finding, no table-full return. | `make test`: integration gate (hostile seed 1) + `test_argus_detect` | **PASS**. 100/100 injected found; per code 1:15 2:8 3:5 4:4 5:9 6:12 7:12 8:8 9:4 10:8 14:8 15:7 (13 and 16: 0/0); unexpected 0; code 12: 0; code 11: 0; FULL 0. Lane E: 377,307 checks, 0 failures (plain, UBSan, ASan). | `b375dca` | Spark + Mac |
| ARGUS_FALSE_POSITIVE_BASELINE_PASS | A benign synthetic corpus (9 seeds x 5000 events, all v1.1 kinds incl. USE_SUMMARY, per-store Worlds) produces zero findings through the real core. Synthetic only: the live omega baseline is part of RUNTIME_INTEGRATION. | `make test`: integration gate | **PASS**. 45,000 events, findings per seed [0,0,0,0,0,0,0,0,0], total 0; FULL 0. | `b375dca` | Spark + Mac |
| ARGUS_RUNTIME_INTEGRATION_PASS | ARGUS runs inside the live AIEN runtime: the omega producer emits real events from AEGIS/runtime hooks, the consumer ingests them, the omega regression tests still pass, and a normal run yields no unexplained findings. | omega producer lane H2 verification (`evidence/ARGUS/h2-verify/VERIFY.md` on omega `feat/argus-producer`, draft PR aien-dev/omega#70): RX_ARGUS=2 ingest, ARGUS_AUTH=observer, detectors `b375dca` | **PASS-WITH-OPEN-FINDINGS** (not a bare PASS). Mechanics pass: live producer hooks in `rx_aegis`/`rx_native_bind`/`rx_generation`/`rx_world`; RX_ARGUS=2 ingest with the authority observer backported onto `c8ab65e`; 0 refused/lost/late; every stream replays twice to the same digest (R7 live byte-identical across runs; R8/R9 live streams differ by flush timing, each deterministic on replay); RX_ARGUS undefined build objdump-identical to omega main `bba3bd3`. R8 0 findings; R9 0 findings (old code 9 fixed by v1.1 store ids on WORLD_COMMITTED); R7 2 findings, code 13 AUTHORITY_REPLAY, **OPEN** (root-caused): the test starts a second authority instance in one process and slots restart at boot generation 2, so cap 3/2 is granted again; the gap is ABI-level and also reachable via `aienos_cap_restart`; fix needs an authority-instance id in capability identity (ABI v2 field, or a producer namespace per authority start). R8 use representation: 205,082 uses -> 1,463 summaries, 100% represented, 0 refused (first producer `527a721` refused 184k of 204k). | omega `20e84b8` (producer `746b30b`, `argus.lock` -> aienos `b375dca`, header byte-identical to `270c6f8`) | Spark (GB10, gcc 13.3.0, kernel 7.0.0-1019-nvidia) |
| ARGUS_PERFORMANCE_GATE_PASS | ARGUS adds acceptable overhead to the runtime hot path (micro-op and R8 wall clock) against the brief's budget. Isolated ARGUS micro-numbers below are context, not this gate. | omega producer lane H2 verification (`tools/argus/bench_micro.sh`, `r8_wall.sh`, interleaved, under `flock ~/workspace/.argus-bench.lock`). Criterion stated before measuring: RX_ARGUS=2 micro-op median throughput loss <= 5% AND RX_ARGUS=2 R8 mean wall clock <= +5% vs RX_ARGUS=0 | **FAIL**. Micro-op (`rx_aegis_evaluate` + `rx_world_validate_cap`, X925 core 7, 22 interleaved rounds, 20M ops/run, median ops/s): RX_ARGUS=0 41.57M; =1 43.75M (+5.2%); =2 discard 38.92M (-6.4% median, -3.1% mean); =2 ingest 40.34M (-3.0%); op p50/p99 48/64 ns in all modes; emit alone 2.25 ns p50; spread +-7% (wider than the 5% line), so this sub-criterion is not cleanly resolved (ingest passes on median). R8 wall clock: off 36.00 ms (sd 1.39) vs RX_ARGUS=2 38.23 ms (sd 1.45) = **+6.2%** (95% CI ~+4..+8%, 30 rounds); repeat +6.1%; RX_ARGUS=1 +0.5%; discard +3.4% -> over the 5% line. Prior design (lane H `527a721`) was -60% throughput, so the v1.1 redesign recovered most of the cost. Remaining cost appears only while a consumer thread runs alongside the workload; likely (unprofiled) the park flush under the world mutex (`rx_world.c:1299`) + in-process SHA-256 ingest. Next iteration: flush after unlock, move ingest out of process, profile (needs `perf_event_paranoid` lowered: Drake's call), re-measure against the same criterion. | omega `20e84b8` (producer `746b30b`) | Spark (GB10, X925 cores, no `.spark-quiet`) |
| ARGUS_HOSTILE_REVIEW_PASS | See the definition below the table. | `make test` (and `make sanitize`): `test_argus_hostile` + `docs/HOSTILE_REVIEW.md` | **PASS-WITH-DOCUMENTED-LIMITS** (not a bare PASS). 63 tests: 58 defended, 3 expected-fail, 2 N/A-v1, 0 xpass, 0 unexpected; sections DEFENDED 20, WEAK 4, OPEN 1, N/A-v1 1 (OPEN: G-5; WEAK: G-9, G-12, G-17, G-21; N/A-v1: G-6; counted from the section verdicts in `HOSTILE_REVIEW.md`, the test prints per-test verdicts only). Limits listed below. | `b375dca` | Spark (+ASan/UBSan) + Mac |

Extra (not a brief gate, printed by the same run): `ARGUS_MEMORY` **PASS**. Core footprint
60,296 B, ring(1024) 131,456 B (128 B per slot); library objects import no heap, I/O or
clock (`nm -u`, 5 objects, 0 forbidden imports). `test_argus_core` 1707/1707.

Isolated ARGUS micro-numbers (Spark, `make bench`, context for PERFORMANCE_GATE, not the
gate itself): push single thread p50/p99/p99.9 4.0/8.5/12.0 ns; push with a live consumer
thread 27.5/35.5/65.5 ns; push+pop bulk 18.9 ns/event; two-thread bulk 15.1 M pops/s.
Consumer ingest (real core + detectors + SHA-256 chain, benign seed 1) p50/p99/p99.9
1072/1248/1984 ns per event, mean 1057 ns: the SHA-256 evidence chain dominates, so one
consumer tops out below ~1 M events/s (consumer-side cost, not on the producer's hot path).

## Hostile gate: definition

`ARGUS_HOSTILE_REVIEW_PASS` prints:
- **PASS** only if every hostile test is defended (no EXPECTED-FAIL, no N/A-v1) and no
  section is OPEN or WEAK.
- **PASS-WITH-DOCUMENTED-LIMITS** if (1) `test_argus_hostile` exits 0 with **0 unexpected
  failures** (a test marked defended that fails breaks the build) and **0 unexplained
  XPASS**, under the plain build and under ASan+UBSan; (2) every EXPECTED-FAIL and N/A-v1
  test maps to a named section in `HOSTILE_REVIEW.md` with a written ruling and a named
  closing milestone or design reason; (3) every OPEN/WEAK section is listed below; and (4)
  no limit is a CRITICAL-severity code bug (only ABI-v1 or design limits are allowed).
- **FAIL** otherwise.

Result at `b375dca`: conditions 1-4 hold -> **PASS-WITH-DOCUMENTED-LIMITS**.

Documented limits (all ABI v1 or design limits, none a code bug):
1. EXPECTED-FAIL `unattributed_grant_masks_forged_use`: G-5, OPEN (HIGH). No producer
   identity in ABI v1; any pusher can pre-announce a GRANTED. Mitigation: the ring is inside
   the trusted process boundary (AEGIS/runtime code only). Closes with producer attestation
   (ARGUS-3).
2. EXPECTED-FAIL `replay_evades_by_rekeying_stream`: G-21, WEAK (MEDIUM; this rekey variant is the G-5 ABI v1 limit). A byte
   replay under another machine_id/stream id is a new stream. Same root and milestone as 1.
3. EXPECTED-FAIL `provider_substitution_escapes_quarantine`: G-9, WEAK (LOW). No stable
   provider identity in v1 (no C provider registry: N/A-ARGUS-0).
4. N/A-v1 `sequence_gap_unflagged`: G-6. Gaps are legitimate ring refusals in v1 (ruling c).
5. N/A-v1 `critical_self_label_starves_security`: G-7. Producers inside the trusted boundary
   may strengthen a class; the kind table is a floor.
6. WEAK, no test: G-12. The two opaque 32-byte slots could carry a secret; the guard is
   producer-side.
7. WEAK, no test: G-17. The ring is SPSC by contract only (v1.1: one ring per producer
   thread).
8. Bounded, loud once, counted: producer table 256 (streams beyond it replay-blind) and
   machine table 64 (a 65th machine's quarantine cannot be recorded; its use is still
   code 7).

## Non-claims

- RUNTIME_INTEGRATION and PERFORMANCE are measured by the omega producer lane
  (`feat/argus-producer` @ `20e84b8`, omega PR #70), not by this branch's tests; they are
  copied here from its H2 verification. PERFORMANCE is FAIL and RUNTIME_INTEGRATION has an
  open finding (R7 code 13), so ARGUS-0 is not claimed complete.
- FALSE_POSITIVE is a synthetic-corpus baseline, not a live-runtime baseline.
- Detectors 4-8 and 10 have synthetic producers only in ARGUS-0 (no C producer exists for
  leases, providers, artifacts or machine identity yet).
- `argus_event_validate` is stricter than the v1.1 header comment on one point: a
  CAPABILITY_USE_SUMMARY whose MIN generation (`world_generation`) is above its MAX
  (`cap_generation`) is malformed. The header was not edited (v1.1 frozen); the wording is
  queued for the next ABI window. The omega producer does not emit such summaries.
