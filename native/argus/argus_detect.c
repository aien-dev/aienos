/*
 * argus_detect.c -- ARGUS-0 hard-invariant detectors (lane E).
 *
 * Twelve deterministic detectors, one per stable finding code ARGUS_F_1..10,
 * 14 and 15 (11 TELEMETRY_LOSS, 12 SEQUENCE_ANOMALY, 13 AUTHORITY_REPLAY and
 * 16 MALFORMED_EVENT are raised by the core, which sees history and
 * validation). Each detector sees the event and the shadow state BEFORE the
 * core applies the event (argus_abi.h), reads the shadow only through
 * ArgusStateOps, and is pure: no allocation, no I/O, no globals written, no
 * clock, no calls into the authority. ARGUS never re-validates a capability:
 * detectors compare the authority's decision (ev->outcome, ev->code, copied by
 * the producer) with what ARGUS itself has already seen. A finding is
 * evidence, never authority; `containment` is a recommendation to AEGIS, never
 * an action.
 *
 * Shared conventions (argus_abi.h, agreed with lane D, the shadow-state core):
 *   - CAPABILITY_GRANTED: cap_id/cap_generation = the NEW reference,
 *     resource = authority resource, object_id = AIENOS_CAP_RIGHT_* mask,
 *     principal = authority subject, code = authority result code.
 *   - "Capability use" events: CAPABILITY_USED, CAPABILITY_USE_SUMMARY (v1.1),
 *     EXTERNAL_EFFECT_REQUESTED, EXTERNAL_EFFECT_COMMITTED, CREDENTIAL_LEASE_USED,
 *     PROVIDER_USED, when they carry cap_id != ARGUS_CAP_NONE (is_cap_use below;
 *     one definition for all). cap_id 0 is the authority OFFICE slot and is
 *     checked like any other (v1.1).
 *   - A USE_SUMMARY is a USED spanning generations: MAX in cap_generation, MIN in
 *     world_generation (64-bit; object_id unused = 0) (use_gen_max/use_gen_min).
 *     Detector 1 checks the max, detector 2 the min, detector 3 the max
 *     (<= the revoked generation), 8 and 14 as a USED.
 *   - A machine is "joined" when machine() finds it AND joined_sequence != 0.
 *     MACHINE_REMOVED leaves a tombstone (joined_sequence 0, trust kept).
 *   - Machine trust rank (argus_trust_rank): TRUSTED < OBSERVED <
 *     REATTESTATION_REQUIRED < RESTRICTED < QUARANTINED < UNTRUSTED.
 *   - PROVIDER_*: evidence_digest = provider id. Shadow state REVOKED means
 *     the provider is quarantined.
 *   - CREDENTIAL_LEASE_*: object_id = lease id, resource = scope (created) or
 *     requested resource bits (used), principal = subject. Lease ids are never
 *     reused (orchestrator ruling A).
 *   - ARTIFACT_*: evidence_digest = artifact digest.
 *   - world(store_id): ARGUS_ERR_STATE is treated as "no World committed yet" for
 *     that store (WORLD_COMMITTED object_id = store id, v1.1).
 *   - policy_digest()/runtime_digest(): an all-zero digest means "none stored".
 *
 * Self-reports (G-2): kinds 60-63 are a producer's say-so, not evidence. A
 * finding derived only from one carries sync_allowed 0 and containment NONE.
 * It keeps the detector's default sync/containment only when the shadow
 * independently corroborates the same violation FOR THE SAME PRINCIPAL:
 *   62 STALE_GENERATION  slot seen, shadow subject == principal, and
 *                        cap_generation < shadow generation;
 *   63 FORGED_CAPABILITY slot seen, shadow subject == principal, and
 *                        cap_generation > shadow generation (never minted);
 *   60 INTEGRITY_VIOLATION, 61 SIGNATURE_FAILURE: nothing in the v1 shadow can
 *                        corroborate them; always sync 0 / NONE.
 * An unseen slot does not corroborate a forgery report: anyone can name an
 * unseen slot together with any victim principal.
 *
 * Every finding: confidence DETERMINISTIC, detector == code, sequence = the
 * triggering event, principal/cap_id/cap_generation/machine_id copied from
 * the event, event_digest left zero (the core fills it).
 *
 * Freestanding: only argus_abi.h (<stdint.h>, <stddef.h>). No libc calls.
 */
#include "argus_detect.h"

/* ---- helpers --------------------------------------------------------------- */

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}

static int bytes_zero(const uint8_t *a, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= a[i];
    return acc == 0;
}

static int is_cap_use(const ArgusEvent *ev)
{
    if (ev->cap_id == ARGUS_CAP_NONE)
        return 0;
    switch (ev->kind) {
    case ARGUS_EV_CAPABILITY_USED:
    case ARGUS_EV_CAPABILITY_USE_SUMMARY:
    case ARGUS_EV_EXTERNAL_EFFECT_REQUESTED:
    case ARGUS_EV_EXTERNAL_EFFECT_COMMITTED:
    case ARGUS_EV_CREDENTIAL_LEASE_USED:
    case ARGUS_EV_PROVIDER_USED:
        return 1;
    default:
        return 0;
    }
}

static int outcome_ok(const ArgusEvent *ev)
{
    return ev->outcome == ARGUS_OUTCOME_OK;
}

/* Generation span of a use (v1.1). A USED carries one generation. A
 * CAPABILITY_USE_SUMMARY carries the MAX generation seen in cap_generation and
 * the MIN in world_generation (64-bit, header v1.1; object_id is unused = 0). */
static uint64_t use_gen_max(const ArgusEvent *ev) { return ev->cap_generation; }
static uint64_t use_gen_min(const ArgusEvent *ev)
{
    return ev->kind == ARGUS_EV_CAPABILITY_USE_SUMMARY ? ev->world_generation : ev->cap_generation;
}

static int cap_lookup(const ArgusStateOps *ops, const ArgusStateView *v, uint32_t id, ArgusCapShadow *s)
{
    return ops->cap(v, id, s) == ARGUS_OK && s->state != ARGUS_SHADOW_UNSEEN;
}

static int machine_joined(const ArgusStateOps *ops, const ArgusStateView *v,
                          const uint8_t id[ARGUS_MACHINE_ID_LEN], ArgusMachineShadow *m)
{
    return ops->machine(v, id, m) == ARGUS_OK && m->joined_sequence != 0;
}

/* Trust rank of a shadow value; UNKNOWN (0) or garbage counts as OBSERVED. */
static int shadow_rank(uint32_t trust)
{
    int r = argus_trust_rank(trust);
    return r < 0 ? argus_trust_rank(ARGUS_TRUST_OBSERVED) : r;
}

/* Append one finding into out[*n]; ARGUS_ERR_OVERFLOW when there is no room. */
static int emit(ArgusFinding *out, size_t cap, size_t *n, const ArgusEvent *ev,
                uint16_t code, uint8_t severity, uint8_t sync_allowed, uint8_t containment,
                uint64_t prior_sequence)
{
    if (*n >= cap)
        return ARGUS_ERR_OVERFLOW;
    ArgusFinding *f = &out[*n];
    f->code = code;
    f->severity = severity;
    f->confidence = ARGUS_CONF_DETERMINISTIC;
    f->sync_allowed = sync_allowed;
    f->containment = containment;
    f->detector = code;
    f->sequence = ev->sequence;
    f->prior_sequence = prior_sequence;
    f->principal = ev->principal;
    f->cap_id = ev->cap_id;
    f->cap_generation = ev->cap_generation;
    for (size_t i = 0; i < ARGUS_MACHINE_ID_LEN; i++)
        f->machine_id[i] = ev->machine_id[i];
    for (size_t i = 0; i < ARGUS_DIGEST_LEN; i++)
        f->event_digest[i] = 0;
    (*n)++;
    return ARGUS_OK;
}

/* ---- 1 FORGED_CAPABILITY ---------------------------------------------------
 * Trigger:  (a) kind == FORGED_CAPABILITY, any outcome (self-report, see the
 *           G-2 rule at the top: sync 0 / NONE unless the shadow shows the
 *           reported principal holds the slot and the generation was never
 *           minted); or
 *           (b) a capability use with outcome OK whose slot ARGUS has never
 *           seen granted (shadow UNSEEN); or
 *           (c) a capability use with outcome OK at a generation ABOVE the
 *           shadow generation for a seen slot (summary: its MAX generation;
 *           a future generation was never minted, G-4); or
 *           (d) a capability use with outcome OK but code ERR_BOUNDS or
 *           ERR_CHAIN (the authority's own code contradicts the outcome).
 * Evidence: ev kind/outcome/code/cap_id/cap_generation; cap shadow.
 * NOT triggered by CAPABILITY_GRANTED: its cap_id is the new reference and is
 *           legitimately unseen (grant replays are the core's code 13). The
 *           event has no parent-reference field, so "granted from a forged
 *           parent" is not detectable in ABI v1.
 * Code ARGUS_F_FORGED_CAPABILITY, CRITICAL, sync_allowed 1,
 * containment FREEZE_PRINCIPAL. prior_sequence = the grant when the slot is seen.
 */
static int det_forged_capability(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                 ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    ArgusCapShadow s = {0};
    int seen = ev->cap_id != ARGUS_CAP_NONE && cap_lookup(ops, v, ev->cap_id, &s);
    uint64_t prior = seen ? s.granted_sequence : 0;
    if (ev->kind == ARGUS_EV_FORGED_CAPABILITY) {
        int corroborated = seen && s.subject == ev->principal && ev->cap_generation > s.generation;
        return emit(out, cap, n_out, ev, ARGUS_F_FORGED_CAPABILITY, ARGUS_SEV_CRITICAL,
                    corroborated ? 1 : 0,
                    corroborated ? ARGUS_CONTAIN_FREEZE_PRINCIPAL : ARGUS_CONTAIN_NONE, prior);
    }
    if (!is_cap_use(ev) || !outcome_ok(ev))
        return ARGUS_OK;
    int hit = ev->code == ARGUS_AUTH_ERR_BOUNDS || ev->code == ARGUS_AUTH_ERR_CHAIN || !seen ||
              use_gen_max(ev) > s.generation;
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_FORGED_CAPABILITY, ARGUS_SEV_CRITICAL, 1,
                ARGUS_CONTAIN_FREEZE_PRINCIPAL, prior);
}

/* ---- 2 STALE_GENERATION ----------------------------------------------------
 * Trigger:  (a) kind == STALE_GENERATION, any outcome (self-report: sync 0 /
 *           NONE unless the shadow shows the reported principal holds the slot
 *           at a newer generation). A normal authority refusal of an old
 *           reference is CAPABILITY_USED/DENIED code ERR_STALE_GEN, which does
 *           NOT trigger; or
 *           (b) a capability use with outcome OK and cap_generation (summary:
 *           its MIN generation, world_generation) lower than the shadow's current
 *           generation for that slot; or
 *           (c) a capability use with outcome OK but code ERR_STALE_GEN.
 * Evidence: ev cap_id/cap_generation/outcome/code; cap shadow generation.
 * Code ARGUS_F_STALE_GENERATION, HIGH, sync_allowed 1, containment
 * REVOKE_CAPABILITY. prior_sequence = shadow granted_sequence when known.
 */
static int det_stale_generation(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    ArgusCapShadow s = {0};
    int seen = ev->cap_id != ARGUS_CAP_NONE && cap_lookup(ops, v, ev->cap_id, &s);
    uint64_t prior = seen ? s.granted_sequence : 0;
    if (ev->kind == ARGUS_EV_STALE_GENERATION) {
        int corroborated = seen && s.subject == ev->principal && ev->cap_generation < s.generation;
        return emit(out, cap, n_out, ev, ARGUS_F_STALE_GENERATION, ARGUS_SEV_HIGH,
                    corroborated ? 1 : 0,
                    corroborated ? ARGUS_CONTAIN_REVOKE_CAPABILITY : ARGUS_CONTAIN_NONE, prior);
    }
    if (!is_cap_use(ev) || !outcome_ok(ev))
        return ARGUS_OK;
    int hit = ev->code == ARGUS_AUTH_ERR_STALE_GEN || (seen && use_gen_min(ev) < s.generation);
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_STALE_GENERATION, ARGUS_SEV_HIGH, 1,
                ARGUS_CONTAIN_REVOKE_CAPABILITY, prior);
}

/* ---- 3 REVOKED_CAPABILITY_USED ---------------------------------------------
 * Trigger:  a capability use with outcome OK where (a) the shadow says the
 *           slot is REVOKED and cap_generation (summary: MAX) <= the shadow
 *           generation (v1.1: a use above it was never minted, detector 1), or
 *           (b) the code is ERR_REVOKED (contradiction).
 *           A use with outcome DENIED and code ERR_REVOKED is the authority
 *           behaving correctly and never triggers.
 * Evidence: ev cap_id/outcome/code; cap shadow state + revoked_sequence.
 * Code ARGUS_F_REVOKED_CAPABILITY_USED, CRITICAL, sync_allowed 1,
 * containment FREEZE_PRINCIPAL. prior_sequence = shadow revoked_sequence.
 */
static int det_revoked_capability_used(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                       ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (!is_cap_use(ev) || !outcome_ok(ev))
        return ARGUS_OK;
    ArgusCapShadow s = {0};
    /* v1.1: a use ABOVE the revoked generation was never minted: detector 1, not 3. */
    int revoked = cap_lookup(ops, v, ev->cap_id, &s) && s.state == ARGUS_SHADOW_REVOKED &&
                  use_gen_max(ev) <= s.generation;
    if (!revoked && ev->code != ARGUS_AUTH_ERR_REVOKED)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_REVOKED_CAPABILITY_USED, ARGUS_SEV_CRITICAL, 1,
                ARGUS_CONTAIN_FREEZE_PRINCIPAL, revoked ? s.revoked_sequence : 0);
}

/* ---- 4 ARTIFACT_DIGEST_UNEXPECTED ------------------------------------------
 * Trigger:  ARTIFACT_ACTIVATED with outcome OK whose evidence_digest is not
 *           LIVE (admitted) in the artifact shadow: never seen, or rejected.
 * Evidence: ev evidence_digest/outcome; artifact shadow state + sequence.
 * Code ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED, CRITICAL, sync_allowed 1,
 * containment REJECT_ARTIFACT. prior_sequence = the rejection, 0 if unseen.
 */
static int det_artifact_digest_unexpected(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                          ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (ev->kind != ARGUS_EV_ARTIFACT_ACTIVATED || !outcome_ok(ev))
        return ARGUS_OK;
    ArgusArtifactShadow a = {0};
    int found = ops->artifact(v, ev->evidence_digest, &a) == ARGUS_OK;
    if (found && a.state == ARGUS_SHADOW_LIVE)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED, ARGUS_SEV_CRITICAL, 1,
                ARGUS_CONTAIN_REJECT_ARTIFACT, found ? a.sequence : 0);
}

/* ---- 5 SIGNATURE_INVALID (also: integrity reports, trusted-digest changes) --
 * Trigger:  (a) kind == SIGNATURE_FAILURE, any outcome: self-report, HIGH,
 *           sync 0, containment NONE (G-2); or
 *           (b) kind == INTEGRITY_VIOLATION, any outcome: self-report, HIGH,
 *           sync 0, containment NONE (G-14: a report reaches a finding, but a
 *           report is not evidence); or
 *           (c) ARTIFACT_ADMITTED with outcome OK but a nonzero code (admitted
 *           despite an error): the event contradicts itself, HIGH, sync 1,
 *           REJECT_ARTIFACT; or
 *           (d) POLICY_CHANGED / RUNTIME_BUILD_CHANGED with outcome OK whose
 *           evidence_digest differs from the stored expected digest, when one
 *           is stored (nonzero): HIGH, sync 0, containment NONE (G-14).
 *           ABI v1 has no signed policy-change path and no finding code for
 *           "trusted digest replaced", so SIGNATURE_INVALID is the closest v1
 *           code: every change after the first announcement is surfaced for
 *           review; re-announcing the stored digest is silent.
 * Evidence: ev kind/outcome/code/evidence_digest; stored policy/runtime digest.
 * Default (table): sync_allowed 1, containment REJECT_ARTIFACT (case c).
 * prior_sequence 0 (the digest store keeps no sequence).
 */
static int det_signature_invalid(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                 ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (ev->kind == ARGUS_EV_SIGNATURE_FAILURE || ev->kind == ARGUS_EV_INTEGRITY_VIOLATION)
        return emit(out, cap, n_out, ev, ARGUS_F_SIGNATURE_INVALID, ARGUS_SEV_HIGH, 0, ARGUS_CONTAIN_NONE, 0);
    if (ev->kind == ARGUS_EV_ARTIFACT_ADMITTED && outcome_ok(ev) && ev->code != 0)
        return emit(out, cap, n_out, ev, ARGUS_F_SIGNATURE_INVALID, ARGUS_SEV_HIGH, 1,
                    ARGUS_CONTAIN_REJECT_ARTIFACT, 0);
    if ((ev->kind == ARGUS_EV_POLICY_CHANGED || ev->kind == ARGUS_EV_RUNTIME_BUILD_CHANGED) && outcome_ok(ev)) {
        uint8_t stored[ARGUS_DIGEST_LEN];
        int rc = ev->kind == ARGUS_EV_POLICY_CHANGED ? ops->policy_digest(v, stored)
                                                     : ops->runtime_digest(v, stored);
        if (rc == ARGUS_OK && !bytes_zero(stored, ARGUS_DIGEST_LEN) &&
            !bytes_equal(stored, ev->evidence_digest, ARGUS_DIGEST_LEN))
            return emit(out, cap, n_out, ev, ARGUS_F_SIGNATURE_INVALID, ARGUS_SEV_HIGH, 0, ARGUS_CONTAIN_NONE, 0);
    }
    return ARGUS_OK;
}

/* ---- 6 CREDENTIAL_SCOPE_VIOLATION ------------------------------------------
 * Trigger:  (a) CREDENTIAL_LEASE_USED with outcome OK where the lease
 *           (object_id) is unseen, not LIVE (revoked), held by another subject
 *           (lease.subject != principal), or the requested resource bits
 *           exceed the lease scope ((resource & ~scope) != 0); or
 *           (b) CREDENTIAL_LEASE_CREATED with outcome OK for a lease id the
 *           shadow already holds (LIVE or REVOKED): lease ids are never reused
 *           (ruling A, G-26); the core does not apply it.
 * Evidence: ev kind/object_id/principal/resource/outcome; lease shadow.
 * Code ARGUS_F_CREDENTIAL_SCOPE_VIOLATION, HIGH, sync_allowed 0,
 * containment REVOKE_CREDENTIAL_LEASE. prior_sequence = lease sequence.
 */
static int det_credential_scope_violation(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                          ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if ((ev->kind != ARGUS_EV_CREDENTIAL_LEASE_USED && ev->kind != ARGUS_EV_CREDENTIAL_LEASE_CREATED) ||
        !outcome_ok(ev))
        return ARGUS_OK;
    ArgusLeaseShadow l = {0};
    int found = ops->lease(v, ev->object_id, &l) == ARGUS_OK && l.state != ARGUS_SHADOW_UNSEEN;
    int hit;
    if (ev->kind == ARGUS_EV_CREDENTIAL_LEASE_CREATED)
        hit = found;
    else
        hit = !(found && l.state == ARGUS_SHADOW_LIVE && l.subject == ev->principal &&
                (ev->resource & ~l.scope) == 0);
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION, ARGUS_SEV_HIGH, 0,
                ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE, found ? l.sequence : 0);
}

/* ---- 7 MACHINE_IDENTITY_MISMATCH -------------------------------------------
 * Trigger:  (a) any event other than MACHINE_JOINED carrying a nonzero
 *           machine_id that is not a joined machine (unknown, or a REMOVED
 *           tombstone); this includes MACHINE_TRUST_CHANGED for an unknown
 *           machine (the core creates no entry); or
 *           (b) MACHINE_JOINED with outcome OK for a machine that is already
 *           joined (re-join without MACHINE_REMOVED in between); or
 *           (c) an all-zero machine_id on any event that is neither
 *           ARGUS_FLAG_SYNTHETIC nor ARGUS_FLAG_CONSUMER: a live producer must
 *           always attribute its events (G-8/G-10). Test/replay streams
 *           (SYNTHETIC) and ARGUS's own events (CONSUMER, e.g. TELEMETRY_DROPPED)
 *           are exempt, because they have no producing machine.
 * Evidence: ev machine_id/kind/outcome/flags; machine shadow joined_sequence.
 * Code ARGUS_F_MACHINE_IDENTITY_MISMATCH, HIGH, sync_allowed 0,
 * containment REQUIRE_REATTESTATION. prior_sequence = earlier join, if any.
 * MachineId is PROVISIONAL (opaque 32 bytes); this is an identity-consistency
 * check only, not cryptographic attestation.
 */
static int det_machine_identity_mismatch(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                         ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    ArgusMachineShadow m = {0};
    int joined = 0;
    int hit;
    if (bytes_zero(ev->machine_id, ARGUS_MACHINE_ID_LEN)) {
        hit = (ev->flags & (ARGUS_FLAG_SYNTHETIC | ARGUS_FLAG_CONSUMER)) == 0;
    } else {
        joined = machine_joined(ops, v, ev->machine_id, &m);
        if (ev->kind == ARGUS_EV_MACHINE_JOINED)
            hit = outcome_ok(ev) && joined;
        else
            hit = !joined;
    }
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_MACHINE_IDENTITY_MISMATCH, ARGUS_SEV_HIGH, 0,
                ARGUS_CONTAIN_REQUIRE_REATTESTATION, joined ? m.joined_sequence : 0);
}

/* ---- 8 EFFECT_CLASS_UNAUTHORIZED -------------------------------------------
 * The effective effect class of an event is EXTERNAL for the kinds
 * EXTERNAL_EFFECT_REQUESTED / EXTERNAL_EFFECT_COMMITTED whatever the producer
 * wrote in effect_class (G-24: the kind wins over the label), otherwise the
 * event's effect_class.
 * Trigger:  outcome OK and
 *           (a) cap_id == ARGUS_CAP_NONE, effective class EXTERNAL, on
 *           EXTERNAL_EFFECT_* or CAPABILITY_USED (an irreversible effect with no capability); or
 *           (b) a capability use (is_cap_use) whose granted rights in the
 *           shadow lack AIENOS_CAP_RIGHT_EFFECT for effective class EXTERNAL,
 *           or lack AIENOS_CAP_RIGHT_WRITE for effective class EVIDENCE (a
 *           durable write under a read-only capability).
 *           An unseen cap_id is left to detector 1 (no double report).
 * Evidence: ev kind/effect_class/cap_id/outcome; cap shadow rights.
 * Code ARGUS_F_EFFECT_CLASS_UNAUTHORIZED, CRITICAL, sync_allowed 1,
 * containment PAUSE_EXTERNAL_EFFECTS. prior_sequence = the grant.
 */
static int det_effect_class_unauthorized(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                         ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (!outcome_ok(ev))
        return ARGUS_OK;
    int effect_kind = ev->kind == ARGUS_EV_EXTERNAL_EFFECT_REQUESTED || ev->kind == ARGUS_EV_EXTERNAL_EFFECT_COMMITTED;
    uint8_t eff = effect_kind ? (uint8_t)ARGUS_EFFECT_EXTERNAL : ev->effect_class;
    uint32_t need;
    if (eff == ARGUS_EFFECT_EXTERNAL)
        need = ARGUS_AUTH_RIGHT_EFFECT;
    else if (eff == ARGUS_EFFECT_EVIDENCE)
        need = ARGUS_AUTH_RIGHT_WRITE;
    else
        return ARGUS_OK;
    uint64_t prior = 0;
    int hit = 0;
    if (ev->cap_id == ARGUS_CAP_NONE) {
        hit = eff == ARGUS_EFFECT_EXTERNAL && (effect_kind || ev->kind == ARGUS_EV_CAPABILITY_USED);
    } else if (is_cap_use(ev)) {
        ArgusCapShadow s = {0};
        if (cap_lookup(ops, v, ev->cap_id, &s) && (s.rights & need) == 0) {
            hit = 1;
            prior = s.granted_sequence;
        }
    }
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_EFFECT_CLASS_UNAUTHORIZED, ARGUS_SEV_CRITICAL, 1,
                ARGUS_CONTAIN_PAUSE_EXTERNAL_EFFECTS, prior);
}

/* ---- 9 WORLD_PROVENANCE_INCONSISTENT ---------------------------------------
 * Trigger:  WORLD_COMMITTED with outcome OK, when a World has already been
 *           committed FOR THE SAME STORE (object_id; world(v, store_id), v1.1;
 *           shadow generation != 0), and either
 *           (a) world_generation == shadow generation with a different
 *           evidence_digest (two different Worlds claim one generation), or
 *           (b) world_generation != shadow generation + 1 otherwise (skip or
 *           rollback). Equal generation with the SAME digest is an idempotent
 *           replay and does not trigger (orchestrator brief, wave 2); the core
 *           does not re-apply it. The first commit ever is accepted.
 *           Generations are 64-bit; a shadow at UINT64_MAX has no legal
 *           successor, so any different generation after it triggers.
 * Evidence: ev world_generation/evidence_digest; world shadow.
 * Code ARGUS_F_WORLD_PROVENANCE_INCONSISTENT, HIGH, sync_allowed 0,
 * containment RAISE_EFFECT_CLASS. prior_sequence = the last commit.
 */
static int det_world_provenance_inconsistent(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                             ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (ev->kind != ARGUS_EV_WORLD_COMMITTED || !outcome_ok(ev))
        return ARGUS_OK;
    ArgusWorldShadow w = {0};
    if (ops->world(v, ev->object_id, &w) != ARGUS_OK || w.generation == 0)   /* per store (v1.1) */
        return ARGUS_OK;
    int hit;
    if (ev->world_generation == w.generation)
        hit = !bytes_equal(ev->evidence_digest, w.digest, ARGUS_DIGEST_LEN);
    else
        hit = w.generation == UINT64_MAX || ev->world_generation != w.generation + 1u;
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_WORLD_PROVENANCE_INCONSISTENT, ARGUS_SEV_HIGH, 0,
                ARGUS_CONTAIN_RAISE_EFFECT_CLASS, w.sequence);
}

/* ---- 10 QUARANTINED_USE ----------------------------------------------------
 * Trigger:  (a) PROVIDER_USED with outcome OK whose provider (evidence_digest)
 *           is quarantined (shadow REVOKED): CRITICAL, sync 1,
 *           QUARANTINE_PROVIDER, prior = the quarantine;
 *           (a') PROVIDER_USED with outcome OK whose provider was never
 *           discovered (unseen, G-9): HIGH, sync 0, QUARANTINE_PROVIDER,
 *           prior 0 (weaker evidence: the discovery may have been lost);
 *           (b) any event with outcome OK carrying a nonzero machine_id whose
 *           machine shadow trust is QUARANTINED (joined or tombstone):
 *           CRITICAL, sync 1, QUARANTINE_MACHINE, prior = changed_sequence.
 *           MACHINE_JOINED / MACHINE_TRUST_CHANGED / MACHINE_REMOVED are
 *           exempt from (b): they are the lifecycle of the quarantine itself
 *           (an upward TRUST_CHANGED is detector 15's).
 *           Can emit two findings for one event ((a) or (a') plus (b)).
 * Evidence: ev kind/outcome/evidence_digest/machine_id; provider + machine shadows.
 * Code ARGUS_F_QUARANTINED_USE.
 */
static int det_quarantined_use(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                               ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (!outcome_ok(ev))
        return ARGUS_OK;
    int rc;
    if (ev->kind == ARGUS_EV_PROVIDER_USED) {
        ArgusProviderShadow p = {0};
        int found = ops->provider(v, ev->evidence_digest, &p) == ARGUS_OK && p.state != ARGUS_SHADOW_UNSEEN;
        if (found && p.state == ARGUS_SHADOW_REVOKED)
            rc = emit(out, cap, n_out, ev, ARGUS_F_QUARANTINED_USE, ARGUS_SEV_CRITICAL, 1,
                      ARGUS_CONTAIN_QUARANTINE_PROVIDER, p.sequence);
        else if (!found)
            rc = emit(out, cap, n_out, ev, ARGUS_F_QUARANTINED_USE, ARGUS_SEV_HIGH, 0,
                      ARGUS_CONTAIN_QUARANTINE_PROVIDER, 0);
        else
            rc = ARGUS_OK;
        if (rc != ARGUS_OK)
            return rc;
    }
    int lifecycle = ev->kind == ARGUS_EV_MACHINE_JOINED || ev->kind == ARGUS_EV_MACHINE_TRUST_CHANGED ||
                    ev->kind == ARGUS_EV_MACHINE_REMOVED;
    if (!lifecycle && !bytes_zero(ev->machine_id, ARGUS_MACHINE_ID_LEN)) {
        ArgusMachineShadow m = {0};
        if (ops->machine(v, ev->machine_id, &m) == ARGUS_OK && m.trust == ARGUS_TRUST_QUARANTINED) {
            rc = emit(out, cap, n_out, ev, ARGUS_F_QUARANTINED_USE, ARGUS_SEV_CRITICAL, 1,
                      ARGUS_CONTAIN_QUARANTINE_MACHINE, m.changed_sequence);
            if (rc != ARGUS_OK)
                return rc;
        }
    }
    return ARGUS_OK;
}

/* ---- 14 SUBJECT_MISMATCH ---------------------------------------------------
 * Trigger:  a capability use with outcome OK on a slot the shadow has seen
 *           (LIVE or REVOKED) whose principal differs from the granted
 *           subject (G-3). An UNSEEN slot is detector 1's.
 * Evidence: ev principal/cap_id/outcome; cap shadow subject.
 * Code ARGUS_F_SUBJECT_MISMATCH, HIGH, sync_allowed 1, containment
 * FREEZE_PRINCIPAL. prior_sequence = the grant.
 */
static int det_subject_mismatch(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (!is_cap_use(ev) || !outcome_ok(ev))
        return ARGUS_OK;
    ArgusCapShadow s = {0};
    if (!cap_lookup(ops, v, ev->cap_id, &s) || s.subject == ev->principal)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_SUBJECT_MISMATCH, ARGUS_SEV_HIGH, 1,
                ARGUS_CONTAIN_FREEZE_PRINCIPAL, s.granted_sequence);
}

/* ---- 15 TRUST_ESCALATION ---------------------------------------------------
 * Trigger:  (a) MACHINE_TRUST_CHANGED with outcome OK for a JOINED machine
 *           whose object_id (a valid ARGUS_TRUST_*, 1..6) ranks better than
 *           the machine's current trust (an upward move; the core ignores
 *           it). Unknown machines are detector 7's; values outside 1..6 are
 *           ignored by the header and never trigger; or
 *           (b) MACHINE_JOINED with outcome OK, for a machine that is not
 *           currently joined, whose object_id (1..6) ranks better than the
 *           baseline: OBSERVED for a new machine, or the worse of OBSERVED
 *           and the tombstone's preserved trust after MACHINE_REMOVED
 *           (a machine cannot declare itself TRUSTED, G-10, nor launder a
 *           quarantine by re-joining, G-8). object_id 0 means "default"
 *           (no claim) and never triggers. A re-join of a joined machine is
 *           detector 7's.
 * Evidence: ev kind/object_id/machine_id/outcome; machine shadow trust.
 * Code ARGUS_F_TRUST_ESCALATION, HIGH, sync_allowed 0, containment
 * REQUIRE_REATTESTATION. prior_sequence = machine changed_sequence (0 if new).
 */
static int det_trust_escalation(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if ((ev->kind != ARGUS_EV_MACHINE_TRUST_CHANGED && ev->kind != ARGUS_EV_MACHINE_JOINED) || !outcome_ok(ev))
        return ARGUS_OK;
    int claim = argus_trust_rank(ev->object_id);
    if (claim < 0)
        return ARGUS_OK;
    ArgusMachineShadow m = {0};
    int found = ops->machine(v, ev->machine_id, &m) == ARGUS_OK;
    int joined = found && m.joined_sequence != 0;
    int baseline;
    if (ev->kind == ARGUS_EV_MACHINE_TRUST_CHANGED) {
        if (!joined)
            return ARGUS_OK;
        baseline = shadow_rank(m.trust);
    } else {
        if (joined)
            return ARGUS_OK;
        baseline = argus_trust_rank(ARGUS_TRUST_OBSERVED);
        if (found && shadow_rank(m.trust) > baseline)
            baseline = shadow_rank(m.trust);
    }
    if (claim >= baseline)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_TRUST_ESCALATION, ARGUS_SEV_HIGH, 0,
                ARGUS_CONTAIN_REQUIRE_REATTESTATION, found ? m.changed_sequence : 0);
}

/* ---- table + runner -------------------------------------------------------- */

const ArgusDetector argus_hard_detectors[ARGUS_HARD_DETECTOR_COUNT] = {
    { ARGUS_F_FORGED_CAPABILITY, 1, ARGUS_CONTAIN_FREEZE_PRINCIPAL, "forged_capability", det_forged_capability },
    { ARGUS_F_STALE_GENERATION, 1, ARGUS_CONTAIN_REVOKE_CAPABILITY, "stale_generation", det_stale_generation },
    { ARGUS_F_REVOKED_CAPABILITY_USED, 1, ARGUS_CONTAIN_FREEZE_PRINCIPAL, "revoked_capability_used",
      det_revoked_capability_used },
    { ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED, 1, ARGUS_CONTAIN_REJECT_ARTIFACT, "artifact_digest_unexpected",
      det_artifact_digest_unexpected },
    { ARGUS_F_SIGNATURE_INVALID, 1, ARGUS_CONTAIN_REJECT_ARTIFACT, "signature_invalid", det_signature_invalid },
    { ARGUS_F_CREDENTIAL_SCOPE_VIOLATION, 0, ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE, "credential_scope_violation",
      det_credential_scope_violation },
    { ARGUS_F_MACHINE_IDENTITY_MISMATCH, 0, ARGUS_CONTAIN_REQUIRE_REATTESTATION, "machine_identity_mismatch",
      det_machine_identity_mismatch },
    { ARGUS_F_EFFECT_CLASS_UNAUTHORIZED, 1, ARGUS_CONTAIN_PAUSE_EXTERNAL_EFFECTS, "effect_class_unauthorized",
      det_effect_class_unauthorized },
    { ARGUS_F_WORLD_PROVENANCE_INCONSISTENT, 0, ARGUS_CONTAIN_RAISE_EFFECT_CLASS, "world_provenance_inconsistent",
      det_world_provenance_inconsistent },
    { ARGUS_F_QUARANTINED_USE, 1, ARGUS_CONTAIN_QUARANTINE_PROVIDER, "quarantined_use", det_quarantined_use },
    { ARGUS_F_SUBJECT_MISMATCH, 1, ARGUS_CONTAIN_FREEZE_PRINCIPAL, "subject_mismatch", det_subject_mismatch },
    { ARGUS_F_TRUST_ESCALATION, 0, ARGUS_CONTAIN_REQUIRE_REATTESTATION, "trust_escalation", det_trust_escalation },
};

const size_t argus_hard_detector_count = ARGUS_HARD_DETECTOR_COUNT;

int argus_detect_run(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                     ArgusFinding *out, size_t cap, size_t *n_out)
{
    if (n_out == NULL)
        return ARGUS_ERR_ARG;
    *n_out = 0;
    if (ops == NULL || v == NULL || ev == NULL || (out == NULL && cap != 0))
        return ARGUS_ERR_ARG;
    if (ops->cap == NULL || ops->machine == NULL || ops->artifact == NULL || ops->lease == NULL ||
        ops->provider == NULL || ops->world == NULL || ops->policy_digest == NULL || ops->runtime_digest == NULL)
        return ARGUS_ERR_ARG;
    size_t n = 0;
    for (size_t i = 0; i < argus_hard_detector_count; i++) {
        size_t k = 0;
        ArgusFinding *slot = out != NULL ? out + n : NULL;
        int rc = argus_hard_detectors[i].fn(ops, v, ev, slot, cap - n, &k);
        n += k;
        if (rc != ARGUS_OK) {
            *n_out = n;
            return rc;
        }
    }
    *n_out = n;
    return ARGUS_OK;
}
