# ARGUS-0 hostile review (lane G)

Reviewer: lane G (hostile). Date: 2026-09-28.
Code reviewed: integration branch `feat/argus-0` at `e16ba31` (lanes B, D, E merged):
`argus_abi.h`, `argus_event.c`, `argus_ring.c`, `argus_core.c`, `argus_detect.c`,
plus ADR 0017 (aien-architecture branch `docs/adr-0017-argus`) and
`native/capability/aienos_capability.h`. Line numbers below are for that commit.

Tests: `tests/test_argus_hostile.c` (60 tests). Each prints `HOSTILE <name> PASS|FAIL`.
Tests for OPEN/WEAK items are marked EXPECTED-FAIL and fail today on purpose; the
binary exits nonzero only on an unexpected failure. Results at `e16ba31`:
27 defended, 33 expected-fail, 0 unexpected, on Apple clang 17 arm64 and on gcc 13
(also clean under `-fsanitize=address,undefined`).

Build line (from `native/argus`, CFLAGS of `../capability/Makefile`):

    cc -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -I. \
       -o out/test_argus_hostile tests/test_argus_hostile.c \
       argus_core.c argus_event.c argus_ring.c sha256.c argus_detect.c

## Bottom line

The substrate mechanics are sound: the ring never blocks, drop accounting is exact,
the core is deterministic and snapshot-safe, and the state digest covers every shadow
field. The security model is not. ARGUS-0 believes every field of every event, from
anyone who can push, and it applies events it has itself flagged as replays. That
turns the hard invariants into invariants an attacker can switch off (replay a grant,
remove and rejoin a machine, relabel an event's class) or turn against the system
(forge a revocation at generation 2^64-1, forge a loss report, fill the incident table).
Several of these are plain code bugs independent of the missing producer identity.

Verdict counts (26 sections: the 23 requested attacks + 2 found while reviewing
+ 1 split out): **DEFENDED 8, WEAK 5, OPEN 13, N/A-ARGUS-0 0** (four sub-items are
N/A-ARGUS-0 and are marked inside their sections).

## Ranked OPEN / WEAK list

| # | Sev | Section | One line |
|---|---|---|---|
| 1 | CRITICAL | G-5 OPEN | No producer identity: any holder of the ring (or caller of ingest) sets principal, outcome, machine_id, class and even the CONSUMER ("ARGUS itself") flag. |
| 2 | CRITICAL | G-3 OPEN | A replayed or forged GRANTED at the same generation revives a REVOKED shadow slot; the next use of the revoked reference raises nothing. Byte-exact replays are flagged as SEQUENCE_ANOMALY and then applied anyway. |
| 3 | HIGH | G-8 OPEN | Quarantine laundering: MACHINE_REMOVED then MACHINE_JOINED gives a clean machine; a quarantined machine can announce its own TRUSTED; zero machine_id escapes detectors 7 and 10; machine table full drops the quarantine. |
| 4 | HIGH | G-4 OPEN | A use at a generation higher than any granted is not flagged; one forged REVOKED at generation UINT64_MAX poisons a slot forever (every later legitimate use = CRITICAL + FREEZE_PRINCIPAL). |
| 5 | HIGH | G-20 OPEN | Free CRITICAL amplifiers: cap_id >= 256 on GRANTED/REVOKED, 33rd producer stream, 17th machine, or a forged TELEMETRY_DROPPED each yield ERR_FULL/CRITICAL TELEMETRY_LOSS per event, mis-attributed as ARGUS's own evidence gap. |
| 6 | HIGH | G-13 OPEN | Incident table (64, keyed by attacker-chosen principal) fills with junk; later real incidents are counted only in `incidents_untracked`, which `argus_core_health` does not expose. |
| 7 | HIGH | G-7 WEAK / G-6 OPEN | Class is producer-chosen and not bound to kind: a revocation labelled INFORMATIONAL is dropped first and reported as an INFORMATIONAL drop, which raises no TELEMETRY_LOSS (silent evidence gap); junk labelled CRITICAL fills 100% and starves SECURITY. |
| 8 | HIGH | G-26 OPEN | A second CREDENTIAL_LEASE_CREATED for a live lease rewrites its subject and scope; the hijacker's use is then clean. |
| 9 | MEDIUM | G-21 OPEN | Sequence abuse: one event at UINT64_MAX makes a stream anomalous forever; replays evade by flipping the CONSUMER bit or machine_id; the producer table never frees and an untracked stream is replay-blind; no restart/epoch field. |
| 10 | MEDIUM | G-10 OPEN | Machine identity: TRUST_CHANGED before JOINED bricks the machine (never joinable, every event = IDENTITY_MISMATCH); JOINED may declare its own initial trust (TRUSTED); reporter and subject are the same field. |
| 11 | MEDIUM | G-15 OPEN | A flagged World commit (skip) is still adopted by the shadow; the legitimate next commit is then the one flagged; a commit at UINT64_MAX freezes World tracking. |
| 12 | MEDIUM | G-24 OPEN | Effect class: EXTERNAL_EFFECT_COMMITTED labelled effect_class NONE escapes detector 8; EVIDENCE writes under READ-only rights are not checked. |
| 13 | MEDIUM | G-6 OPEN | Omission: sequence gaps without a matching drop report are not detected; malformed events are a counter only (not chained, no finding). |
| 14 | MEDIUM | G-14 OPEN | Policy/runtime digests are stored but never checked by any detector; POLICY_CHANGED from anyone rewrites the expected digest; INTEGRITY_VIOLATION (kind 60) produces no finding. |
| 15 | MEDIUM (HIGH at ARGUS-1) | G-2 WEAK | Self-reported kinds (FORGED_CAPABILITY, STALE_GENERATION, SIGNATURE_FAILURE) produce CRITICAL/HIGH findings with `sync_allowed=1` and FREEZE_PRINCIPAL against any principal named in the event, with no shadow evidence. |
| 16 | LOW | G-9 WEAK | Provider identity = digest; a quarantined provider re-appearing under a new digest is clean; use of a never-discovered provider is not flagged. |
| 17 | LOW | G-12 WEAK | Two opaque 32-byte slots (machine_id, evidence_digest) are exactly the office secret's length and are copied verbatim into findings, producer table and state digest; nothing structural keeps a secret out. |
| 18 | LOW | G-17 WEAK | The ring is SPSC by contract only; a second producer silently corrupts/loses events with no guard or detection. |

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

Tried: looked for any path from `native/argus` to `aienos_cap_mint`, the admin handle,
`aienos_cap_authorize`, or the office secret.
Evidence: no ARGUS source includes `aienos_capability.h`; `argus_detect.h` mirrors five
constants only (`argus_detect.h:20-26`); lane D's `check-core-symbols` restricts
`argus_core.o` imports to four ARGUS calls plus `mem*` (`lane_d.mk`). The ABI has no
admin, view, or secret type.
Test: the hostile test binary links without `libaienos_capability.a`; any `aienos_cap_*`
reference from ARGUS objects fails the link. Add `nm -u` on all ARGUS objects to the
integration gate (currently only `argus_core.o` is checked).

## G-2 ARGUS-to-AEGIS confused deputy: WEAK (containment action N/A-ARGUS-0)

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

## G-3 Capability replay: OPEN

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

## G-4 Stale generation acceptance: OPEN

Tried: lower, higher, and extreme generations.
Evidence: lower generation with outcome OK is caught (`argus_detect.c:174`), DEFENDED.
Higher-than-ever-granted is not: detector 1 checks only UNSEEN (`:140`), detector 2 only
`<` (`:174`), so a reference ARGUS never saw minted passes if the slot exists. A REVOKED
for an unseen slot is created at whatever generation it claims (`argus_core.c:388-398`);
at UINT64_MAX every later real GRANTED is ignored as stale (`:387`) and every real use
yields REVOKED_CAPABILITY_USED CRITICAL + STALE_GENERATION HIGH, permanently.
Tests: `future_generation_use_unflagged` (EXPECTED-FAIL), `revoke_gen_max_poisons_slot`
(EXPECTED-FAIL), `stale_generation_use_flagged` (PASS).

## G-5 Event forgery: OPEN

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

## G-6 Event omission: OPEN

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

## G-7 Telemetry saturation: WEAK

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

## G-8 Quarantine bypass: OPEN

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

## G-9 Provider identity substitution: WEAK (registry N/A-ARGUS-0)

Evidence: provider id = evidence_digest (`argus_abi.h` PROVIDER_* convention). No
provider registry exists in C (ADR §14.4), so stable identity is **N/A-ARGUS-0**. But
PROVIDER_CHANGED is ignored by the core (`argus_core.c:556`, default) and no detector, so a
quarantined provider re-appearing under a new digest is clean; PROVIDER_USED of a
never-discovered provider is not a finding (`argus_detect.c:396-403`).
Tests (EXPECTED-FAIL): `provider_substitution_escapes_quarantine`,
`undiscovered_provider_use_unflagged`.

## G-10 Machine identity spoofing (the 32-byte provisional slot): OPEN

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

Evidence: lease shadow keeps id, subject, 64-bit scope, state, sequence only
(`argus_abi.h:259-265`); findings carry principal, cap ref, machine_id and event digest
(`argus_abi.h:199-213`), never scope or lease contents. No credential material has a field.
Test: covered structurally by `event_has_only_two_32byte_slots`; lease integrity is G-26.

## G-12 Secret leakage into event payload: WEAK

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

## G-13 Incident table poisoning: OPEN

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

## G-14 Policy-digest mismatch: OPEN

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

## G-15 Provenance spoofing (WORLD_COMMITTED): OPEN

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

Evidence: drop reports are handed to the consumer directly and never re-enter the ring
(`argus_ring.c` header comment, `:190-219`); the core emits findings, never events; a
TELEMETRY_DROPPED yields exactly one TELEMETRY_LOSS (`argus_core.c:601-605`), and lane E
never raises it. No loop exists in ARGUS-0. ARGUS-1 must keep containment results out of
the ring, or loss -> finding -> request -> event can cycle.
Test: `drop_report_does_not_recurse` (PASS).

## G-17 ARGUS deadlock / SPSC misuse: WEAK

Evidence: the ring has no locks and never waits (`argus_ring.c:126-146`); the core is
single-threaded with no locks: deadlock is impossible. Multi-producer misuse is not guarded:
two producers load the same `head` (`:131`) and write the same slot, losing one event with
no counter and no finding. The contract is documentation only.
Test that would prove it: lane B's TSAN harness with two producer threads must report a
race (not expressible deterministically against the header API; not in the hostile file).
Fix options: a producer-id word in the ring checked on push (debug builds), or MPSC via
fetch-add reservation.

## G-18 ARGUS crash preventing AIEN progress: DEFENDED

Evidence: with no consumer, push returns ERR_FULL immediately at the class limit and
counts it (`argus_ring.c:133-141`). There is no liveness signal: a dead consumer is only
visible when someone drains; if the ring memory dies with ARGUS, the gap is never recorded
(restart reconstruction is ARGUS-3, ADR §13).
Test: `push_never_blocks_without_consumer` (PASS, 100,000 pushes, 16 accepted, rest counted).

## G-19 Backpressure freezing the runtime: DEFENDED

Evidence: same as G-18; there is no blocking path, no allocation, no syscall on push
(`argus_ring.c:1-12`). Covered by the same test.

## G-20 DoS by intentionally generating security events: OPEN

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

## G-21 Sequence-anomaly abuse: OPEN (restart handling N/A-ARGUS-0)

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

## G-24 Effect-class bypass (found during review): OPEN

Evidence: detector 8 decides from the producer's `effect_class` byte, not the kind: an
EXTERNAL_EFFECT_COMMITTED with `effect_class NONE` and no capability passes
(`argus_detect.c:327-328`). Only EXTERNAL vs RIGHT_EFFECT is checked (`:331-332`), although
ADR §3 row 8 says "beyond what the capability's rights permit": an EVIDENCE (durable) write
under a READ-only capability passes.
Tests: EXPECTED-FAIL `effect_kind_mislabelled`, `evidence_write_with_read_only_right`;
PASS `external_effect_without_right_flagged`.

## G-25 Artifacts (found during review): DEFENDED

Evidence: rejection is sticky (`argus_core.c:450-456`); ADMITTED needs outcome OK and code 0
(`:530`); activation of a non-admitted digest is CRITICAL (`argus_detect.c:218-225`). ADR row 4
"an admitted digest changed" cannot be expressed because the artifact is keyed by its
digest; it needs an artifact id field (ARGUS-4).
Test: `artifact_rejection_sticky` (PASS).

## G-26 Credential lease re-creation hijack (found during review): OPEN

Evidence: `apply_lease` overwrites subject and scope of any non-revoked lease on a second
CREATED (`argus_core.c:427-431`); detector 6 then compares the use against the attacker's
subject and scope. Revocation is sticky (DEFENDED).
Tests: EXPECTED-FAIL `lease_recreate_hijacks_subject`; PASS `lease_other_subject_flagged`.

## Test index

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
