# ARGUS-0 hostile review (lane G)

Reviewer: lane G (hostile). Date: 2026-09-28. **Re-verdicted by the integrator,
round 2 (2026-09-29)** after lanes B `58d5a99`, D `57a7bea`, E `a33c1e0` were merged
into `feat/argus-0` on top of the ABI rules commit `4cd73cc` (`b6c782a`).
**Re-verdicted again by the integrator, round 3 (2026-09-29)** after the ABI v1.1 lane
(`92277dd`, header `398cfb9`) was merged and rulings (a) and (c) were applied.

## Status after integrator round 3 (final for ARGUS-0)

Result on the Spark (see `docs/ARGUS0_GATES.md` for commit and command): **63 tests:
58 defended, 3 expected-fail, 2 N/A-v1, 0 xpass, 0 unexpected, exit 0.**

What changed in round 3:
- ABI v1.1 merged: stream id in flag bits 2-15, sequence streams keyed by
  (machine_id, stream, CONSUMER); cap 0 is the authority OFFICE capability (a real
  slot, checked like any other) and "no capability" is `ARGUS_CAP_NONE`;
  CAPABILITY_USE_SUMMARY (kind 81) with MAX generation in cap_generation and MIN
  generation in world_generation (64-bit, header `398cfb9`); per-store World shadows (8).
  Validate now also rejects a summary whose MIN (world_generation) is above its MAX
  (cap_generation); object_id is left unchecked for forward compatibility.
- Test harness follows v1.1: `ev0()` sends `cap_id = ARGUS_CAP_NONE`; every
  `use(0, ...)` that meant "no capability" is now `use(ARGUS_CAP_NONE, ...)`; the World
  shadow is read per store (`world(view, 0, &w)`).
- `zero_machine_id_escapes_attribution` now passes only for the right reason: it
  requires code 7 (MACHINE_IDENTITY_MISMATCH). Under v1.1 a use of cap 0 would have
  "passed" through code 1 (forged: cap 0 never granted), which would hide a regression
  in the zero-machine rule. Checked: the finding is code 7.
- Ruling (a), G-20: "loud once" now holds for EVERY shadow table (machines, leases,
  providers, artifacts, worlds), not only producers. First overflow of a table =
  ERR_FULL + one CRITICAL TELEMETRY_LOSS; later overflows of that table = ERR_FULL, no
  finding, counted in `tables_full` and `events_not_applied`. The latch is per table, so
  one saturated table does not silence another. ARGUS-1 turns a saturated table into a
  ContainmentRequest (state is bounded by design). Tests: `machine_table_exhaustion_hides_quarantine`
  and `lease_table_exhaustion` now also assert the quiet, counted second overflow; new
  test `every_table_loud_once` (providers, artifacts, worlds in one core).
- Ruling (c): `sequence_gap_unflagged` is N/A-v1 (gaps are legitimate ring refusals;
  exempt from the exit code); `replay_evades_by_rekeying_stream` (machine_id variant)
  is EXPECTED-FAIL under G-5 (no producer identity in v1).

### Remaining open after round 3 (ABI v1 limits)

| # | Sev | Section | Status | What is still possible |
|---|---|---|---|---|
| 1 | HIGH | G-5 | OPEN, ABI v1 limit (EXPECTED-FAIL `unattributed_grant_masks_forged_use`) | No producer identity: anything that can push can announce a GRANTED that makes its own later use look legitimate. Mitigated only by the v1 trust boundary (push reachable only from AEGIS/runtime code). Producer attestation is ARGUS-3. |
| 2 | MEDIUM | G-21 under G-5 | WEAK, ABI v1 limit (EXPECTED-FAIL `replay_evades_by_rekeying_stream`, ruling c) | A byte replay with a different machine_id is a new sequence stream and escapes the replay check. Same root as #1. |
| 3 | LOW | G-9 | WEAK, ABI v1 limit (EXPECTED-FAIL `provider_substitution_escapes_quarantine`) | A quarantined provider that reappears under a new digest is clean. |
| 4 | LOW | G-21 / G-8 / G-20 | WEAK, bounded, loud once per table | Streams beyond the 256-entry producer table are replay-blind; a machine beyond the 64-entry table cannot carry a quarantine (its use is still code 7); any full table stops mirroring new entries (one CRITICAL, then counted). |
| 5 | LOW | G-12 | WEAK, unchanged | Two opaque 32-byte slots can carry a secret; the guard must be producer-side. |
| 6 | LOW | G-17 | WEAK, unchanged | The ring is SPSC by contract only; a second producer loses events silently. |
| 7 | N/A-v1 | G-6 | documented limitation (N/A-v1 `sequence_gap_unflagged`, ruling c) | A stream jumping from 1 to 100 with no drop report is not a finding. |
| 8 | N/A-v1 | G-7 | documented limitation (N/A-v1 `critical_self_label_starves_security`) | Low-value kinds self-labelled CRITICAL can fill the ring and starve SECURITY. |

Verdict counts after round 3 (26 sections): **DEFENDED 20, WEAK 4, OPEN 1, N/A-v1 1**
(OPEN: G-5; WEAK: G-9, G-12, G-17, G-21; N/A-v1: G-6). Changes from round 2: G-20
WEAK -> DEFENDED (ruling a); G-6 OPEN -> N/A-v1 (ruling c); G-21 OPEN -> WEAK (its
remaining open variant is the G-5 limit, ruling c; the overflow residue is bounded).

## Status after integrator round 2 (superseded by round 3 above)

Tests: `tests/test_argus_hostile.c`, now part of `make test` (built from `out/libargus.a`
only; the exit code counts). Each prints `HOSTILE <name> PASS|FAIL`. Three modes:
expected-defended (a FAIL is UNEXPECTED and fails the build), EXPECTED-FAIL (a known
open item, reported, does not fail the build), and N/A-v1 (an attack ABI v1 accepts by
design; reported, exempt from the exit code).

Result on the Spark (gcc, aarch64) and on the MacBook (Apple clang 17, macOS 26.6), and
under ASan+UBSan on the Spark: **62 tests: 57 defended, 4 expected-fail, 1 N/A-v1,
0 xpass, 0 unexpected, exit 0.**

Attribution rule for "fixed in": the commit whose component holds the logic that now
defends the test (validate/ring = B `58d5a99`, core apply/lifecycle/tables = D `57a7bea`,
detectors = E `a33c1e0`, ABI rules/codes/table sizes = `4cd73cc`). It was checked by
rebuilding the hostile test with one lane reverted to `4cd73cc` at a time: the tests that
fall back to FAIL are that lane's. Tests marked "D + E" pass if either lane is present.

Rulings applied to the test file in round 2 (orchestrator):
- `ev0()` sends each kind at `argus_event_min_class(kind)` (SECURITY for an unknown
  kind); tests that relied on a weaker class were written before the class floor existed.
- Code 16 (MALFORMED_EVENT) is an accepted defended outcome where validate now rejects
  first (`cap_id_out_of_range_use_is_forged`, `effect_kind_mislabelled`,
  `replay_rekeyed_by_consumer_flag`).
- INFORMATIONAL/AUDIT ring floods use the non-v1 kind `0x7FFF`: no v1 kind has an
  INFORMATIONAL floor (design fact), and the ring is transport with no floor for an
  unknown kind.
- `critical_self_label_starves_security` is N/A-v1: producers are inside the trusted
  boundary in v1 and may strengthen a class (the table is a floor, not a ceiling).
- `world_skip_flagged` rollback case is World 1, 2, 1. `world_repeat_silent` is
  re-scoped: a repeat with the same generation and digest is idempotent and silent
  (RULED); a repeat with a different digest must be code 9. **ADR 0017 row 9 must be
  amended** to read "repeated a generation with a different digest".
- Table-exhaustion tests fill the new sizes exactly and overshoot them (machines 64,
  producers 256, incidents 256, leases 256; a lease test was added). Producer overflow
  follows the RATIFIED rule: the first untracked event returns ERR_FULL with one CRITICAL
  TELEMETRY_LOSS, later ones return OK and are counted in `producers_untracked`.
- `zero_machine_id_escapes_attribution` sends flags 0: the zero-machine rule exempts
  SYNTHETIC and CONSUMER events, which is what the old test sent.
- `replay_evades_by_rekeying_stream` was split: the CONSUMER-flag variant is now
  defended (code 16, new test `replay_rekeyed_by_consumer_flag`); the machine_id variant
  keeps the old name and stays EXPECTED-FAIL.
- Fixed a test bug: `state_digest_sensitive_to_every_table` variant 7 turned an
  ADMITTED into a REJECTED without raising its class to the CRITICAL floor, so the
  variant was rejected as malformed and did not test the artifact table.

### Remaining open in ARGUS-0

| # | Sev | Section | Status | What is still possible |
|---|---|---|---|---|
| 1 | HIGH | G-5 | OPEN, ABI v1 limit (EXPECTED-FAIL `unattributed_grant_masks_forged_use`) | No producer identity: anything that can push can announce a GRANTED that makes its own later use look legitimate. Mitigated only by the v1 trust boundary (push reachable only from AEGIS/runtime code). Producer attestation is ARGUS-3. |
| 2 | MEDIUM | G-21 | OPEN, no ruling (EXPECTED-FAIL `replay_evades_by_rekeying_stream`) | A byte replay with a different machine_id is a new sequence stream and escapes the replay check. Same root as #1. |
| 3 | MEDIUM | G-20 | WEAK, no ruling, found in round 2 (no test) | Only the producer table got the "loud once" rule. Every event beyond a full machine (64), lease (256), provider (32) or artifact (256) table still returns ERR_FULL with its own CRITICAL TELEMETRY_LOSS (measured: 6 extra JOINED = 6 CRITICAL; same for leases, providers, artifacts). Machine and lease tables never free, so once full this is a per-event CRITICAL amplifier. |
| 4 | MEDIUM | G-6 | OPEN, no ruling (EXPECTED-FAIL `sequence_gap_unflagged`) | A stream jumping from 1 to 100 with no drop report is not a finding (the core documents "gaps are not findings"). |
| 5 | LOW | G-9 | WEAK, ABI v1 limit (EXPECTED-FAIL `provider_substitution_escapes_quarantine`) | A quarantined provider that reappears under a new digest is clean: no provider identity continuity in v1 (registry is N/A-ARGUS-0). |
| 6 | LOW | G-21 / G-8 | WEAK, bounded | Streams beyond the 256-entry producer table are replay-blind (loud once, counted); the 65th machine's quarantine cannot be recorded (loud, and its use is still code 7). |
| 7 | LOW | G-12 | WEAK, unchanged | Two opaque 32-byte slots can carry a secret; the guard must be producer-side. |
| 8 | LOW | G-17 | WEAK, unchanged | The ring is SPSC by contract only; a second producer loses events silently. |
| 9 | N/A-v1 | G-7 | documented limitation (N/A-v1 `critical_self_label_starves_security`) | Low-value kinds self-labelled CRITICAL can fill the ring and starve SECURITY. |

Verdict counts after round 2 (26 sections): **DEFENDED 19, WEAK 4, OPEN 3, N/A-v1 0**
as whole-section verdicts (OPEN: G-5, G-6, G-21; WEAK: G-9, G-12, G-17, G-20). Sub-items
that are N/A-v1 or N/A-ARGUS-0 are marked inside their sections (G-2, G-7, G-9, G-10,
G-15, G-21). See each section's "Round 2" line.

### Ranked list as first found (at `e16ba31`), with round-2 status

| # | Sev | Section | One line (as found) | Round 2 |
|---|---|---|---|---|
| 1 | CRITICAL | G-5 OPEN | No producer identity: any holder of the ring (or caller of ingest) sets principal, outcome, machine_id, class and even the CONSUMER ("ARGUS itself") flag. | CONSUMER flag and class floor DEFENDED (`58d5a99`); producer identity OPEN (ABI v1 limit) |
| 2 | CRITICAL | G-3 OPEN | A replayed or forged GRANTED at the same generation revives a REVOKED shadow slot; byte-exact replays are flagged and then applied anyway. | DEFENDED (`57a7bea` code 13, anomalous events not applied; `a33c1e0` code 14) |
| 3 | HIGH | G-8 OPEN | Quarantine laundering: REMOVED then JOINED; self-announced TRUSTED; zero machine_id escapes; machine table full drops the quarantine. | DEFENDED (`57a7bea` tombstones, trust down only, table 64; `a33c1e0`: code 15 on trust escalation, code 7 on a zero machine_id); table limit WEAK, bounded |
| 4 | HIGH | G-4 OPEN | Future generation use unflagged; forged REVOKED at UINT64_MAX poisons a slot forever. | DEFENDED (`a33c1e0`, `57a7bea`) |
| 5 | HIGH | G-20 OPEN | Free CRITICAL amplifiers: cap_id >= 256, 33rd producer, 17th machine, forged TELEMETRY_DROPPED. | cap_id and forged drop DEFENDED (`58d5a99`); producer overflow RATIFIED (`57a7bea`); per-event amplifier remains on machine/lease/provider/artifact overflow: WEAK |
| 6 | HIGH | G-13 OPEN | Incident table fills with junk; saturation invisible in health. | DEFENDED (`57a7bea`: table 256, `incidents_untracked` in health; still no eviction) |
| 7 | HIGH | G-7 WEAK / G-6 OPEN | Class not bound to kind: security event lost as INFORMATIONAL; junk labelled CRITICAL starves SECURITY. | lost-as-INFORMATIONAL DEFENDED (`58d5a99`); CRITICAL self-label N/A-v1 (ruled) |
| 8 | HIGH | G-26 OPEN | Second LEASE_CREATED rewrites a live lease. | DEFENDED (`57a7bea` not applied; `a33c1e0` code 6) |
| 9 | MEDIUM | G-21 OPEN | UINT64_MAX sequence poison; rekeyed replays; producer table never frees. | poison DEFENDED (`58d5a99`); CONSUMER rekey DEFENDED (`58d5a99`); machine_id rekey OPEN; overflow RATIFIED, replay-blind beyond 256 WEAK |
| 10 | MEDIUM | G-10 OPEN | TRUST_CHANGED before JOINED bricks a machine; JOINED declares its own trust. | DEFENDED (`57a7bea`, `a33c1e0`) |
| 11 | MEDIUM | G-15 OPEN | Flagged World skip still adopted; UINT64_MAX freezes World tracking. | DEFENDED (`57a7bea`); repeat RULED idempotent, ADR row 9 to amend |
| 12 | MEDIUM | G-24 OPEN | Mislabelled effect kind; EVIDENCE under READ-only. | DEFENDED (`58d5a99` validate, code 16; `a33c1e0` detector 8) |
| 13 | MEDIUM | G-6 OPEN | Sequence gaps undetected; malformed events leave no evidence. | malformed evidence DEFENDED (`57a7bea` code 16); gaps OPEN, no ruling |
| 14 | MEDIUM | G-14 OPEN | Policy/runtime digests never checked; INTEGRITY_VIOLATION ignored. | DEFENDED at announcement level (`a33c1e0`: digest overwrite and INTEGRITY_VIOLATION raise code 5, sync 0) |
| 15 | MEDIUM | G-2 WEAK | Self-reports yield sync-eligible FREEZE_PRINCIPAL against any principal. | DEFENDED (`a33c1e0`: uncorroborated self-reports sync 0, containment NONE) |
| 16 | LOW | G-9 WEAK | Provider substitution; never-discovered provider use. | undiscovered use DEFENDED (`a33c1e0`); substitution WEAK, ABI v1 limit |
| 17 | LOW | G-12 WEAK | Two opaque 32-byte slots could carry a secret. | unchanged, WEAK |
| 18 | LOW | G-17 WEAK | SPSC by contract only. | unchanged, WEAK |

## Original review (lane G, at `e16ba31`)

Code reviewed: `argus_abi.h`, `argus_event.c`, `argus_ring.c`, `argus_core.c`,
`argus_detect.c`, plus ADR 0017 (aien-architecture branch `docs/adr-0017-argus`) and
`native/capability/aienos_capability.h`. Line numbers in the sections below are for
`e16ba31` and are historical. Original results: 60 tests, 27 defended, 33 expected-fail,
0 unexpected. Original verdict counts: DEFENDED 8, WEAK 5, OPEN 13.

Original bottom line: the substrate mechanics are sound (the ring never blocks, drop
accounting is exact, the core is deterministic and snapshot-safe, the state digest covers
every shadow field) but ARGUS-0 believed every field of every event and applied events it
had itself flagged as replays. The mandatory header changes below were adopted in
`4cd73cc` (items 1 to 6; item 6's reporter identity is ARGUS-1 ABI v2) and implemented in
the three lane commits.

## Header changes I consider mandatory before a hostile gate can pass

1. **Consumer voice separated from the wire.** `argus_event_validate` rejects
   `ARGUS_FLAG_CONSUMER` on any kind other than `TELEMETRY_DROPPED`, and the core raises
   TELEMETRY_LOSS only for CONSUMER-flagged drops (better: a separate
   `argus_core_ingest_drops()` entry so pushed events can never carry that flag).
2. **Bounds in the ABI.** Add `ARGUS_CAP_MAX` (= `AIENOS_CAP_MAX`, 256) and make
   `cap_id >= ARGUS_CAP_MAX` MALFORMED (or a FORGED finding), never ERR_FULL.
3. **Kind to minimum class table** in the header, enforced by validate and by
   `argus_ring_push` (e.g. CAPABILITY_*, CREDENTIAL_*, MACHINE_TRUST_CHANGED, WORLD_COMMITTED
   >= SECURITY; FORGED_CAPABILITY, INTEGRITY_VIOLATION, SIGNATURE_FAILURE, STALE_GENERATION
   = CRITICAL; nothing informational may claim CRITICAL).
4. **Health exposes saturation.** `ArgusCoreHealth` gains `incidents_untracked`,
   `producers_untracked`, and a per-table `table_full` count. Appending fields changes the
   struct, so do it now, before any consumer depends on it.
5. **Replay/anomaly semantics.** Replace the convention "the core reports a
   repeat/decrease as SEQUENCE_ANOMALY and still applies the event" with "an anomalous
   event is detected but never applied", and state that a GRANTED whose generation is not
   strictly greater than the shadow's generation for that slot is never applied (and is a
   finding). Same for REVOKED of a never-granted slot at an unseen generation.
6. **Machine lifecycle conventions.** REMOVED keeps a tombstone (trust and quarantine
   survive rejoin); TRUST_CHANGED for an unknown machine is a finding and creates nothing;
   JOINED initial trust is capped at OBSERVED. Longer term the event needs a reporter
   identity distinct from the subject machine (ARGUS-1 ABI v2).

Items 1 to 5 are small; without them the ARGUS-0 hard invariants can be disabled by a
single event.

---

## G-1 ARGUS minting authority accidentally: DEFENDED

**Round 2:** unchanged. The suggested `nm -u` on every ARGUS object is now the ARGUS_MEMORY integration gate (5 objects, 0 forbidden imports).

As found at `e16ba31`:

Tried: looked for any path from `native/argus` to `aienos_cap_mint`, the admin handle,
`aienos_cap_authorize`, or the office secret.
Evidence: no ARGUS source includes `aienos_capability.h`; `argus_detect.h` mirrors five
constants only (`argus_detect.h:20-26`); lane D's `check-core-symbols` restricts
`argus_core.o` imports to four ARGUS calls plus `mem*` (`lane_d.mk`). The ABI has no
admin, view, or secret type.
Test: the hostile test binary links without `libaienos_capability.a`; any `aienos_cap_*`
reference from ARGUS objects fails the link. Add `nm -u` on all ARGUS objects to the
integration gate (currently only `argus_core.o` is checked).

## G-2 ARGUS-to-AEGIS confused deputy: DEFENDED (containment action N/A-ARGUS-0)

**Round 2:** DEFENDED by `a33c1e0`: a finding derived only from a self-report (kinds 60-63) carries `sync_allowed 0` and containment NONE unless the shadow corroborates it for the same principal. `reported_forgery_names_arbitrary_victim` PASS. ARGUS-1 AEGIS must still bind any freeze to the principal a reporting producer may speak for.

As found at `e16ba31`:

Tried: can a Finding or ContainmentRequest act as authority, and can an attacker aim one?
Evidence: `ArgusContainmentRequest` is a type with no consumer in ARGUS-0 (ADR 0017 §4,
"ARGUS-0 defines the request type only"): the action path is **N/A-ARGUS-0**. But the
findings that will feed it are aimable today. Detector 1 fires on `kind ==
FORGED_CAPABILITY` with any outcome and no shadow check (`argus_detect.c:134-135`) and
emits CRITICAL, `sync_allowed=1`, FREEZE_PRINCIPAL with `principal` copied from the event
(`:145`, `:103`); the same holds for detector 2 on STALE_GENERATION (`:169-170`) and
detector 5 on SIGNATURE_FAILURE (`:242`). ADR §5 says sync-eligible refusal must rest on
a deterministic hard invariant; a producer's say-so about a third principal is hearsay.
Test: `reported_forgery_names_arbitrary_victim` (EXPECTED-FAIL): one FORGED_CAPABILITY
event naming principal 1 yields a sync-eligible FREEZE_PRINCIPAL finding.
Fix: findings derived only from a self-reported kind carry `sync_allowed=0`; ARGUS-1 AEGIS
must bind any freeze to the principal that the reporting producer is authorized to speak for.

## G-3 Capability replay: DEFENDED

**Round 2:** DEFENDED by `57a7bea` (GRANTED applies only when UNSEEN or strictly above the shadow generation, otherwise AUTHORITY_REPLAY code 13; anomalous events are detected but not applied) and `a33c1e0` (SUBJECT_MISMATCH code 14 on use by another principal). PASS: `grant_replay_revives_revoked`, `exact_replay_still_applied`, `use_by_other_subject_unflagged`.

As found at `e16ba31`:

Tried: replay a GRANTED after REVOKED; replay byte-exact; use by another principal.
Evidence: `apply_cap` only ignores a generation strictly lower than stored
(`argus_core.c:387`); an equal-generation GRANTED overwrites a REVOKED slot as LIVE
(`:399-404`). No detector examines GRANTED events (`argus_detect.c:122-125` says so).
The core's sequence check flags a replay (`:583`) but by header convention the event is
still applied (`argus_abi.h` conventions; `argus_core.c:597`). Detector 3 then sees LIVE.
Separately, the shadow stores the granted subject (`:400`) but no detector compares it with
the event principal on use.
Tests (all EXPECTED-FAIL): `grant_replay_revives_revoked`, `exact_replay_still_applied`,
`use_by_other_subject_unflagged`. DEFENDED neighbours: `revoked_use_flagged`,
`revoked_use_denied_is_quiet`.

## G-4 Stale generation acceptance: DEFENDED

**Round 2:** DEFENDED: `future_generation_use_unflagged` PASS (`a33c1e0`, a generation above the shadow is FORGED), `revoke_gen_max_poisons_slot` PASS (`57a7bea`, REVOKED of an unseen slot is code 13 and creates nothing).

As found at `e16ba31`:

Tried: lower, higher, and extreme generations.
Evidence: lower generation with outcome OK is caught (`argus_detect.c:174`), DEFENDED.
Higher-than-ever-granted is not: detector 1 checks only UNSEEN (`:140`), detector 2 only
`<` (`:174`), so a reference ARGUS never saw minted passes if the slot exists. A REVOKED
for an unseen slot is created at whatever generation it claims (`argus_core.c:388-398`);
at UINT64_MAX every later real GRANTED is ignored as stale (`:387`) and every real use
yields REVOKED_CAPABILITY_USED CRITICAL + STALE_GENERATION HIGH, permanently.
Tests: `future_generation_use_unflagged` (EXPECTED-FAIL), `revoke_gen_max_poisons_slot`
(EXPECTED-FAIL), `stale_generation_use_flagged` (PASS).

## G-5 Event forgery: OPEN (ABI v1 limit; validation parts DEFENDED)

**Round 2:** the pure-validation parts are DEFENDED by `58d5a99`: CONSUMER only on TELEMETRY_DROPPED, and a producer TELEMETRY_DROPPED is rejected (`forged_telemetry_dropped`, `consumer_flag_accepted_from_wire` PASS); class floor per kind. Producer identity stays OPEN as an ABI v1 limit, documented in the header (`4cd73cc`: push reachable only from AEGIS/runtime code inside the trusted process; attestation is ARGUS-3). `unattributed_grant_masks_forged_use` stays EXPECTED-FAIL on purpose.

As found at `e16ba31`:

Tried: who can call `argus_ring_push` / `argus_core_ingest`, and what binds the fields.
Evidence: anyone with the ring pointer may push (`argus_ring.c:126`); push checks only the
class byte (`:130`). The event has no producer field; the ADR's "producer copies the
authority's result" is trust, not verification. `argus_event_validate` accepts
`ARGUS_FLAG_CONSUMER` from anyone (`argus_event.c:81`), and the core treats any
TELEMETRY_DROPPED as a real loss report regardless of flag or outcome
(`argus_core.c:601-605`). A GRANTED with a zero machine_id triggers nothing, so any pusher
can pre-announce grants that make its own later uses look legitimate.
Tests (EXPECTED-FAIL): `forged_telemetry_dropped`, `consumer_flag_accepted_from_wire`,
`unattributed_grant_masks_forged_use`.
Note: full producer authentication is out of ARGUS-0 scope, but items 1 and 3 of the
mandatory list close the parts that are pure validation.

## G-6 Event omission: N/A-v1 (gaps; ruling c, round 3)

**Round 3:** ruled N/A-v1 (ruling c): sequence gaps are legitimate in v1 (ring refusals leave them by design; the drop report travels on the consumer stream). `sequence_gap_unflagged` is N/A-v1, exempt from the exit code. Every other G-6 item stays DEFENDED.

**Round 2:** `malformed_event_leaves_no_evidence` PASS (`57a7bea`: MALFORMED_EVENT code 16 raised by the core, with the event digest); `security_event_lost_as_informational` PASS (`58d5a99`: a revocation cannot be labelled INFORMATIONAL, validate and ring refuse it). Sequence gaps remain undetected by design of the current core ("gaps are not findings"); `sequence_gap_unflagged` stays EXPECTED-FAIL, no ruling yet.

As found at `e16ba31`:

Tried: can a producer drop events without ARGUS noticing?
Evidence: the sequence check detects repeats and decreases only (`argus_core.c:360`);
a jump from 1 to 100 is silent although the header promises streams "strictly increasing
from 1" and refusals are separately counted, so a gap without a matching
TELEMETRY_DROPPED is detectable in principle. A malformed event returns before the
sequence check and before `argus_chain_extend` (`:571-574`, chain at `:610`): it is only
`events_rejected++`. A security event mislabelled INFORMATIONAL is dropped and reported
as an INFORMATIONAL drop, which by design raises nothing (`:601-603`).
Tests (EXPECTED-FAIL): `sequence_gap_unflagged`, `malformed_event_leaves_no_evidence`,
`security_event_lost_as_informational`.

## G-7 Telemetry saturation: DEFENDED (CRITICAL self-label N/A-v1)

**Round 2:** `security_event_lost_as_informational` PASS (`58d5a99`). `critical_self_label_starves_security` is N/A-v1 by ruling: producers are inside the trusted boundary and may strengthen a class. Drop reports are now always CRITICAL by design (`58d5a99`). The flood tests use the non-v1 kind 0x7FFF for INFORMATIONAL/AUDIT (no v1 kind has an INFORMATIONAL floor).

As found at `e16ba31`:

Tried: INFORMATIONAL flood vs SECURITY; CRITICAL overflow accounting; drain correctness.
Evidence (DEFENDED): watermarks 50/75/90/100% (`argus_ring.c:67-77`); refusal is counted
per class, CRITICAL overflow is sticky (`:133-141`); `drain_drops` exchanges exactly what it
reports and preserves the rest when `max` is small (`:197-217`); drop events bypass the ring.
Weakness: the class is the producer's claim. Nothing binds kind to class, so the watermark
policy protects only honest labels (see G-6 for the silent-loss direction). Also, once any
CRITICAL overflow occurred, every later drop report is labelled CRITICAL (`:202-203`);
harmless to the core (it reads object_id) but noisy for anything keyed on class.
Tests: PASS `info_flood_cannot_starve_security`, `critical_overflow_accounting`,
`drain_partial_preserves_pending`, `attempt_conservation`; EXPECTED-FAIL
`critical_self_label_starves_security`, `security_event_lost_as_informational`.

## G-8 Quarantine bypass: DEFENDED (table limit WEAK, bounded)

**Round 3:** unchanged verdict. `zero_machine_id_escapes_attribution` now requires code 7 itself (it sends `ARGUS_CAP_NONE`; under v1.1 a cap-0 use would have passed through code 1 instead). The machine-table overflow follows ruling (a): loud once, then quiet and counted.

**Round 2:** DEFENDED: `quarantine_laundered_by_remove_rejoin` (`57a7bea`, REMOVED leaves a tombstone), `quarantined_machine_self_upgrades` (D + E: trust moves only down, upward is code 15 and ignored), `zero_machine_id_escapes_attribution` (`a33c1e0`: a live event with a zero machine_id is code 7; SYNTHETIC/CONSUMER are exempt), `machine_table_exhaustion_hides_quarantine` (`57a7bea`: table 64; the 65th JOINED is refused loudly and its later use is still code 7). Residual WEAK: a machine beyond the table cannot carry a quarantine.

As found at `e16ba31`:

Tried: rediscovery, rejoin, trust ordering, table limits, anonymity.
Evidence: provider rediscovery never clears quarantine (`argus_core.c:502`), DEFENDED.
Machines: MACHINE_REMOVED deletes the entry (`:462-471`); the next JOINED creates a fresh
machine (`:480-487`) and detector 7 sees an unknown machine joining, which is not a
finding (`argus_detect.c:295-296`). Lifecycle kinds are exempt from detector 10
(`:405-407`), and TRUST_CHANGED is applied from any sender (`argus_core.c:492`), so a
quarantined machine may send its own QUARANTINED -> TRUSTED. An all-zero machine_id is
"not attributed" and skips detectors 7 and 10 (`argus_detect.c:290`, `:407`). With 16
machines joined, a quarantine for the 17th is dropped with ERR_FULL (`argus_core.c:478`).
Tests: PASS `quarantined_machine_use_flagged`, `provider_rediscovery_keeps_quarantine`;
EXPECTED-FAIL `quarantine_laundered_by_remove_rejoin`, `quarantined_machine_self_upgrades`,
`zero_machine_id_escapes_attribution`, `machine_table_exhaustion_hides_quarantine`.

## G-9 Provider identity substitution: WEAK (ABI v1 limit; registry N/A-ARGUS-0)

**Round 2:** `undiscovered_provider_use_unflagged` PASS (`a33c1e0`). `provider_substitution_escapes_quarantine` stays EXPECTED-FAIL: ABI v1 has no provider identity continuity.

As found at `e16ba31`:

Evidence: provider id = evidence_digest (`argus_abi.h` PROVIDER_* convention). No
provider registry exists in C (ADR §14.4), so stable identity is **N/A-ARGUS-0**. But
PROVIDER_CHANGED is ignored by the core (`argus_core.c:556`, default) and no detector, so a
quarantined provider re-appearing under a new digest is clean; PROVIDER_USED of a
never-discovered provider is not a finding (`argus_detect.c:396-403`).
Tests (EXPECTED-FAIL): `provider_substitution_escapes_quarantine`,
`undiscovered_provider_use_unflagged`.

## G-10 Machine identity spoofing (the 32-byte provisional slot): DEFENDED (spoofing a joined machine accepted in v1)

**Round 2:** the code bugs are DEFENDED: `trust_before_join_bricks_machine` (`57a7bea`: TRUST_CHANGED on an unknown machine creates nothing), `join_declares_own_trust` (D + E: JOINED capped at OBSERVED, code 15). Spoofing a joined machine's id remains accepted by design of the provisional slot.

As found at `e16ba31`:

Evidence: the slot is opaque and producer-claimed (`argus_abi.h:21-22`, ADR §14.3), so
spoofing a joined machine is undetectable by design; that part is accepted. The code bugs
on top are not accepted: TRUST_CHANGED for an unknown machine creates an entry with
`joined_sequence 0` (`argus_core.c:476-487`, `:492`); the machine's real JOINED is then
ignored as a rejoin (`:489-490`), so it can never be "joined" and every event it sends is
MACHINE_IDENTITY_MISMATCH (`argus_detect.c:298`). JOINED takes its initial trust from its
own `object_id` (`argus_core.c:484`), so a joiner can declare itself TRUSTED. The pre-join
TRUST_CHANGED is at least reported (unknown machine), so pre-seeding trust is detected.
Tests: EXPECTED-FAIL `trust_before_join_bricks_machine`, `join_declares_own_trust`; PASS
`trust_preseed_skips_observation` (detected, not prevented).

## G-11 Credential metadata leakage: DEFENDED

**Round 2:** unchanged.

As found at `e16ba31`:

Evidence: lease shadow keeps id, subject, 64-bit scope, state, sequence only
(`argus_abi.h:259-265`); findings carry principal, cap ref, machine_id and event digest
(`argus_abi.h:199-213`), never scope or lease contents. No credential material has a field.
Test: covered structurally by `event_has_only_two_32byte_slots`; lease integrity is G-26.

## G-12 Secret leakage into event payload: WEAK

**Round 2:** unchanged; the guard must be producer-side.

As found at `e16ba31`:

Tried: any 32-byte field that could carry the authority's 32-byte office secret.
Evidence: exactly two 32-byte fields exist, `machine_id` (off 64) and `evidence_digest`
(off 96). Both are opaque and unvalidated. `machine_id` is copied verbatim into every
finding (`argus_core.c` `core_finding`, `argus_detect.c:106-107`), into the producer table
and into the state digest records; `evidence_digest` into artifact/provider/world/policy
shadows. A producer bug that passes the office secret where a digest is expected would be
propagated and chained forever; nothing in ARGUS can tell the difference. The README's
"no event field is secret-sized except digests" is true only if machine_id counts as a
digest; it is not one today.
Test: `event_has_only_two_32byte_slots` (PASS: no third slot appears). The real guard
must be producer-side: machine_id := SHA-256(domain || identity), evidence_digest only from
`sha256_*`, plus the existing grep gate extended to producer code that fills events.

## G-13 Incident table poisoning: DEFENDED (no eviction)

**Round 2:** DEFENDED by `57a7bea`: table 256 and `incidents_untracked` in `ArgusCoreHealth`. The test now overshoots 256 junk pairs and requires the real incident to be delivered and the saturation to be visible in health. Still no eviction (a CRITICAL cannot displace HIGH junk).

As found at `e16ba31`:

Tried: 64 slots, key (principal, code), severity >= HIGH.
Evidence: principal is attacker-chosen; SIGNATURE_FAILURE (any outcome, no state) yields
HIGH (`argus_detect.c:242`). 64 such events with distinct principals fill the table
(`argus_core.c:327-348`); further incidents go to `incidents_untracked` (`:340`), which
`argus_core_health` does not return (`:761-774`; `incidents_open` = `n_incidents`, `:771`).
The real finding is still delivered to the caller, so it is hidden from the health summary,
not from the finding stream. With 12 principals x 12 codes = 144 legitimate pairs the table
can saturate without an attacker. No eviction: CRITICAL cannot displace HIGH junk.
Test: `incident_table_poisoning` (EXPECTED-FAIL: health does not change after a real
CRITICAL incident once the table is full).

## G-14 Policy-digest mismatch: DEFENDED (announcement level)

**Round 2:** DEFENDED by `a33c1e0`: POLICY_CHANGED / RUNTIME_BUILD_CHANGED over a stored digest and any INTEGRITY_VIOLATION raise code 5 (HIGH, sync 0, containment NONE). `policy_digest_overwrite_silent`, `integrity_violation_report_ignored` PASS. Comparing a running policy with the announced one is still undefined in v1 (no event carries the in-use digest).

As found at `e16ba31`:

Evidence: `op_policy_digest` / `op_runtime_digest` exist (`argus_core.c` ops) but no
detector calls them; `argus_detect_run` does not even require them non-null. POLICY_CHANGED
and RUNTIME_BUILD_CHANGED from any sender overwrite the expected digest (`:550`, `:554`).
None of the 12 finding codes covers "running policy differs from announced policy", and no
event kind carries the in-use digest to compare against, so the invariant is undefined.
INTEGRITY_VIOLATION (kind 60) reaches no detector and produces nothing.
Tests (EXPECTED-FAIL): `policy_digest_overwrite_silent`, `integrity_violation_report_ignored`.
Fix: either declare policy mismatch out of ARGUS-0 scope in the ADR and stop storing the
digests, or route INTEGRITY_VIOLATION to a finding and define which event carries the
in-use policy digest.

## G-15 Provenance spoofing (WORLD_COMMITTED): DEFENDED (forged digest at prior+1 N/A-ARGUS-0)

**Round 2:** DEFENDED by `57a7bea`: a flagged commit is not adopted (`world_inconsistent_commit_adopted` PASS). Rollback case now World 1, 2, 1 (`world_skip_flagged` PASS). Repeat RULED idempotent: same generation and digest is silent, a different digest is code 9 (`world_repeat_silent` re-scoped, PASS). ADR 0017 row 9 must be amended accordingly.

As found at `e16ba31`:

Evidence: skip, rollback and same-generation conflict are detected (`argus_detect.c:367-370`),
DEFENDED. A forged digest at exactly prior+1 is undetectable with one source
(**N/A-ARGUS-0**: needs a second attestation). The bug: the core adopts any higher
generation even when detector 9 fired (`argus_core.c:542-546`), so after one forged skip the
shadow follows the attacker and the next legitimate commit is the one flagged; a commit at
UINT64_MAX leaves no successor and freezes World tracking. The first commit after start is
accepted at any generation (restart gap, ARGUS-3). ADR §3 row 9 says a repeated generation
is a finding; the detector treats same-digest repeats as idempotent.
Tests: PASS `world_skip_flagged`, `world_same_generation_conflict_flagged`; EXPECTED-FAIL
`world_inconsistent_commit_adopted`, `world_repeat_silent`.

## G-16 Recursive containment storms: DEFENDED

**Round 2:** unchanged.

As found at `e16ba31`:

Evidence: drop reports are handed to the consumer directly and never re-enter the ring
(`argus_ring.c` header comment, `:190-219`); the core emits findings, never events; a
TELEMETRY_DROPPED yields exactly one TELEMETRY_LOSS (`argus_core.c:601-605`), and lane E
never raises it. No loop exists in ARGUS-0. ARGUS-1 must keep containment results out of
the ring, or loss -> finding -> request -> event can cycle.
Test: `drop_report_does_not_recurse` (PASS).

## G-17 ARGUS deadlock / SPSC misuse: WEAK

**Round 2:** unchanged. The threaded integration test now also runs under TSan (`make sanitize`), clean, but it uses one producer as the contract says.

As found at `e16ba31`:

Evidence: the ring has no locks and never waits (`argus_ring.c:126-146`); the core is
single-threaded with no locks: deadlock is impossible. Multi-producer misuse is not guarded:
two producers load the same `head` (`:131`) and write the same slot, losing one event with
no counter and no finding. The contract is documentation only.
Test that would prove it: lane B's TSAN harness with two producer threads must report a
race (not expressible deterministically against the header API; not in the hostile file).
Fix options: a producer-id word in the ring checked on push (debug builds), or MPSC via
fetch-add reservation.

## G-18 ARGUS crash preventing AIEN progress: DEFENDED

**Round 2:** unchanged.

As found at `e16ba31`:

Evidence: with no consumer, push returns ERR_FULL immediately at the class limit and
counts it (`argus_ring.c:133-141`). There is no liveness signal: a dead consumer is only
visible when someone drains; if the ring memory dies with ARGUS, the gap is never recorded
(restart reconstruction is ARGUS-3, ADR §13).
Test: `push_never_blocks_without_consumer` (PASS, 100,000 pushes, 16 accepted, rest counted).

## G-19 Backpressure freezing the runtime: DEFENDED

**Round 2:** unchanged.

As found at `e16ba31`:

Evidence: same as G-18; there is no blocking path, no allocation, no syscall on push
(`argus_ring.c:1-12`). Covered by the same test.

## G-20 DoS by intentionally generating security events: DEFENDED (round 3, ruling a: loud once per table)

**Round 3:** DEFENDED. Ruling (a) applied in `argus_core.c`: every shadow table (machines 64, leases 256, providers 32, artifacts 256, World stores 8) reports its FIRST overflow as ERR_FULL + one CRITICAL TELEMETRY_LOSS and every later overflow of the same table as ERR_FULL with no finding, counted in `tables_full` and `events_not_applied` (per-table latch, so one full table cannot mask another). No per-event CRITICAL amplifier remains. Residue (WEAK, bounded, listed under G-21/G-8): a full table stops mirroring new entries; ARGUS-1 turns that into a ContainmentRequest. Tests: `machine_table_exhaustion_hides_quarantine`, `lease_table_exhaustion` (both now assert the quiet, counted second overflow), new `every_table_loud_once`.

**Round 2:** `cap_id_out_of_range_is_critical_loss` PASS (`58d5a99`: cap_id >= ARGUS_CAP_MAX is malformed, code 16, never ERR_FULL); `forged_telemetry_dropped` PASS (`58d5a99`); `producer_table_exhaustion` PASS against the RATIFIED rule (`57a7bea`: first untracked event ERR_FULL + one CRITICAL loss, later ones OK + `producers_untracked`). Found in round 2, no ruling yet: the "loud once" rule covers only the producer table. Each event beyond a full machine (64), lease (256), provider (32) or artifact (256) table still returns ERR_FULL with its own CRITICAL TELEMETRY_LOSS (probe: 6 extra JOINED = 6 CRITICAL, same for the other three tables), and the machine and lease tables never free. `machine_table_exhaustion_hides_quarantine` and `lease_table_exhaustion` assert only that the first overflow is loud.

As found at `e16ba31`:

Tried: the cap_id >= 256 path and every other ERR_FULL path.
Evidence: `argus_event_validate` accepts any cap_id (`argus_event.c:73-83`); GRANTED or
REVOKED with cap_id >= 256 returns ERR_FULL from `apply_cap` (`argus_core.c:383-384`) and the
core adds a CRITICAL TELEMETRY_LOSS (`:606-607`), mis-labelling a forged reference as
ARGUS's own evidence gap, at the attacker's chosen principal (feeds G-13). Same amplifier
from the 33rd producer stream (`:368`), the 17th machine (`:478`), and a forged
TELEMETRY_DROPPED (G-5). The ingest return code ERR_FULL on each of these tells an
integrator "ARGUS is saturated" when it is not. A USED with cap_id >= 256 is correctly
FORGED (`argus_detect.c:140`).
Tests: EXPECTED-FAIL `cap_id_out_of_range_is_critical_loss`, `producer_table_exhaustion`,
`forged_telemetry_dropped`; PASS `cap_id_out_of_range_use_is_forged`.

## G-21 Sequence-anomaly abuse: WEAK (machine_id rekey = G-5 ABI v1 limit; restart handling N/A-ARGUS-0)

**Round 3:** ruling (c): the machine_id rekey (`replay_evades_by_rekeying_stream`) is EXPECTED-FAIL under G-5 (no producer identity in v1). v1.1 keys streams by (machine_id, stream id, CONSUMER), all sender-chosen, so the same limit covers a stream-id rekey. Streams beyond the 256-entry producer table stay replay-blind (loud once, counted). Section verdict WEAK.

**Round 2:** `sequence_high_water_poison` PASS (`58d5a99`: sequence UINT64_MAX is malformed). CONSUMER-flag rekey DEFENDED (`58d5a99`, new test `replay_rekeyed_by_consumer_flag`). machine_id rekey stays OPEN (`replay_evades_by_rekeying_stream` EXPECTED-FAIL, no ruling; same root as G-5). Producer table 256 with the ratified overflow rule; streams beyond it stay replay-blind (WEAK, counted).

As found at `e16ba31`:

Evidence: stream key = (machine_id, CONSUMER bit) (`argus_core.c:354-375`), both chosen by
the sender, so a replay escapes by flipping either. One event at UINT64_MAX raises the
high-water mark to the top with no finding; every later event on that stream is an anomaly
forever (no epoch field; producer restart does the same, which is **N/A-ARGUS-0** until
ARGUS-3 defines restart). The producer table (32) is never freed, not even on
MACHINE_REMOVED; beyond it, streams are not tracked at all. Anomalous events are applied
(G-3). Wraparound itself cannot happen (64-bit, never reached honestly).
Tests: PASS `sequence_replay_flagged`; EXPECTED-FAIL `sequence_high_water_poison`,
`replay_evades_by_rekeying_stream`, `producer_table_exhaustion`.

## G-22 Determinism breakers: DEFENDED

**Round 2:** unchanged.

As found at `e16ba31`:

Tried: caller buffer size, memory contents, snapshot copies, uninitialised memory,
detector truncation.
Evidence: findings are collected in an internal scratch and state is applied regardless of
the caller's `cap` (`argus_core.c:612-625`); encoding is field-by-field (`argus_event.c`
`encode_raw`), so struct padding never reaches a digest; `ArgusEvent` and `ArgusFinding`
have no padding; the core holds no pointers; the magic word rejects uninitialised memory;
`argus_detect_run` stops at the first overflow, giving a prefix of the full result.
No clock, no allocation, no global mutable state in core or detectors.
Tests (PASS): `same_stream_same_output`, `buffer_size_does_not_change_state`,
`snapshot_copy_equivalent`, `uninitialized_core_rejected`, `detect_run_prefix_under_small_cap`.

## G-23 State digest collisions: DEFENDED (fragile)

**Round 2:** unchanged. Test bug fixed: variant 7 now sends REJECTED at its CRITICAL floor, so it actually reaches the artifact table.

As found at `e16ba31`:

Tried: two different states hashing equal via the fake-event packing.
Evidence: every field of every shadow table is written into a record
(`argus_core.c:659-758`); each table has its own kind and `code` tag; the header record
carries all table counts; values fit their record fields without truncation. So the
encoding is injective and collisions reduce to SHA-256. Fragilities: (a) the event chain and
the state digest use the same construction from the same zero start; they are separated only
because the state digest's first record has sequence 0, which validate rejects for real
events. The core comment claiming the records "pass argus_event_validate" is false for that
reason. Add an explicit domain tag. (b) Machine records follow insertion order, so the same
set of machines joined in a different order hashes differently: fine for replay
determinism, wrong if the digest is ever compared across independently built cores.
Tests (PASS): `state_digest_sensitive_to_every_table`, `state_digest_domain_separated`.

## G-24 Effect-class bypass (found during review): DEFENDED

**Round 2:** `effect_kind_mislabelled` PASS (`58d5a99`: EXTERNAL_EFFECT_* with effect_class != EXTERNAL is malformed, code 16); `evidence_write_with_read_only_right` PASS (`a33c1e0`).

As found at `e16ba31`:

Evidence: detector 8 decides from the producer's `effect_class` byte, not the kind: an
EXTERNAL_EFFECT_COMMITTED with `effect_class NONE` and no capability passes
(`argus_detect.c:327-328`). Only EXTERNAL vs RIGHT_EFFECT is checked (`:331-332`), although
ADR §3 row 8 says "beyond what the capability's rights permit": an EVIDENCE (durable) write
under a READ-only capability passes.
Tests: EXPECTED-FAIL `effect_kind_mislabelled`, `evidence_write_with_read_only_right`;
PASS `external_effect_without_right_flagged`.

## G-25 Artifacts (found during review): DEFENDED

**Round 2:** unchanged.

As found at `e16ba31`:

Evidence: rejection is sticky (`argus_core.c:450-456`); ADMITTED needs outcome OK and code 0
(`:530`); activation of a non-admitted digest is CRITICAL (`argus_detect.c:218-225`). ADR row 4
"an admitted digest changed" cannot be expressed because the artifact is keyed by its
digest; it needs an artifact id field (ARGUS-4).
Test: `artifact_rejection_sticky` (PASS).

## G-26 Credential lease re-creation hijack (found during review): DEFENDED

**Round 2:** DEFENDED (D + E): a LEASE_CREATED on a known lease id is not applied (`57a7bea`, lease ids never reused) and is code 6 (`a33c1e0`). `lease_recreate_hijacks_subject` PASS. New `lease_table_exhaustion` PASS (256 leases, the 257th refused loudly).

As found at `e16ba31`:

Evidence: `apply_lease` overwrites subject and scope of any non-revoked lease on a second
CREATED (`argus_core.c:427-431`); detector 6 then compares the use against the attacker's
subject and scope. Revocation is sticky (DEFENDED).
Tests: EXPECTED-FAIL `lease_recreate_hijacks_subject`; PASS `lease_other_subject_flagged`.

## Test index (round 3)

63 tests. Expected-defended, PASS (58): every test not listed below, including the
round-3 addition `every_table_loud_once`.

EXPECTED-FAIL (3): `unattributed_grant_masks_forged_use` (G-5, ABI v1 limit),
`replay_evades_by_rekeying_stream` (G-21 machine_id variant, under G-5, ruling c),
`provider_substitution_escapes_quarantine` (G-9, ABI v1 limit).

N/A-v1 (2, exempt from the exit code): `critical_self_label_starves_security` (G-7),
`sequence_gap_unflagged` (G-6, ruling c).

Rewritten in round 3: `zero_machine_id_escapes_attribution` (code 7 required),
`machine_table_exhaustion_hides_quarantine` and `lease_table_exhaustion` (second
overflow quiet + counted), `world_inconsistent_commit_adopted` (per-store World read),
and every test using `ev0()`/`use()` without a capability (`ARGUS_CAP_NONE`).

## Test index (round 2)

Expected-defended, PASS (57): every test not listed below, including the round-2
additions `replay_rekeyed_by_consumer_flag` and `lease_table_exhaustion`.

EXPECTED-FAIL (4), each documented above: `unattributed_grant_masks_forged_use` (G-5, ABI
v1 limit), `provider_substitution_escapes_quarantine` (G-9, ABI v1 limit),
`sequence_gap_unflagged` (G-6, no ruling), `replay_evades_by_rekeying_stream` (G-21,
machine_id variant, no ruling).

N/A-v1 (1, exempt from the exit code): `critical_self_label_starves_security` (G-7).

Flipped from EXPECTED-FAIL to expected-defended in round 2 (28):
grant_replay_revives_revoked, exact_replay_still_applied, future_generation_use_unflagged,
use_by_other_subject_unflagged, revoke_gen_max_poisons_slot,
cap_id_out_of_range_is_critical_loss, effect_kind_mislabelled,
evidence_write_with_read_only_right, reported_forgery_names_arbitrary_victim,
forged_telemetry_dropped, consumer_flag_accepted_from_wire, sequence_high_water_poison,
producer_table_exhaustion, quarantine_laundered_by_remove_rejoin,
quarantined_machine_self_upgrades, join_declares_own_trust, trust_before_join_bricks_machine,
machine_table_exhaustion_hides_quarantine, zero_machine_id_escapes_attribution,
undiscovered_provider_use_unflagged, lease_recreate_hijacks_subject,
world_inconsistent_commit_adopted, world_repeat_silent, policy_digest_overwrite_silent,
integrity_violation_report_ignored, incident_table_poisoning,
malformed_event_leaves_no_evidence, security_event_lost_as_informational.

Some tests were rewritten, not only flipped (see "Rulings applied" at the top):
cap_id_out_of_range_use_is_forged, effect_kind_mislabelled, producer_table_exhaustion,
machine_table_exhaustion_hides_quarantine, zero_machine_id_escapes_attribution,
world_skip_flagged, world_repeat_silent, incident_table_poisoning,
info_flood_cannot_starve_security, drain_partial_preserves_pending,
security_event_lost_as_informational, critical_self_label_starves_security,
state_digest_sensitive_to_every_table.

## Test index (original, at `e16ba31`)

PASS today (27): stale_generation_use_flagged, revoked_use_flagged,
revoked_use_denied_is_quiet, cap_id_out_of_range_use_is_forged,
external_effect_without_right_flagged, sequence_replay_flagged,
quarantined_machine_use_flagged, trust_preseed_skips_observation,
provider_rediscovery_keeps_quarantine, lease_other_subject_flagged, world_skip_flagged,
world_same_generation_conflict_flagged, artifact_rejection_sticky,
info_flood_cannot_starve_security, critical_overflow_accounting,
drain_partial_preserves_pending, attempt_conservation, push_never_blocks_without_consumer,
drop_report_does_not_recurse, same_stream_same_output, buffer_size_does_not_change_state,
snapshot_copy_equivalent, uninitialized_core_rejected, detect_run_prefix_under_small_cap,
state_digest_sensitive_to_every_table, state_digest_domain_separated,
event_has_only_two_32byte_slots.

EXPECTED-FAIL today (33): grant_replay_revives_revoked, exact_replay_still_applied,
future_generation_use_unflagged, use_by_other_subject_unflagged, revoke_gen_max_poisons_slot,
cap_id_out_of_range_is_critical_loss, effect_kind_mislabelled,
evidence_write_with_read_only_right, reported_forgery_names_arbitrary_victim,
forged_telemetry_dropped, consumer_flag_accepted_from_wire,
unattributed_grant_masks_forged_use, sequence_high_water_poison, sequence_gap_unflagged,
replay_evades_by_rekeying_stream, producer_table_exhaustion,
quarantine_laundered_by_remove_rejoin, quarantined_machine_self_upgrades,
join_declares_own_trust, trust_before_join_bricks_machine,
machine_table_exhaustion_hides_quarantine, zero_machine_id_escapes_attribution,
provider_substitution_escapes_quarantine, undiscovered_provider_use_unflagged,
lease_recreate_hijacks_subject, world_inconsistent_commit_adopted, world_repeat_silent,
policy_digest_overwrite_silent, integrity_violation_report_ignored,
incident_table_poisoning, malformed_event_leaves_no_evidence,
security_event_lost_as_informational, critical_self_label_starves_security.

Some EXPECTED-FAIL tests encode a judgment the integrator may reject (for example
`unattributed_grant_masks_forged_use` cannot pass without producer identity, and
`world_repeat_silent` depends on whether the ADR or the detector is right). Flipping one
to a documented accepted risk is fine; deleting it silently is not.
