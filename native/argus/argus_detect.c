/*
 * argus_detect.c -- ARGUS-0 hard-invariant detectors (lane E).
 *
 * Ten deterministic detectors, one per stable finding code ARGUS_F_1..10.
 * Each one sees the event and the shadow state BEFORE the core applies the
 * event (argus_abi.h), reads the shadow only through ArgusStateOps, and is
 * pure: no allocation, no I/O, no globals written, no clock, no calls into
 * the authority. ARGUS never re-validates a capability: detectors compare the
 * authority's decision (ev->outcome, ev->code, copied by the producer) with
 * what ARGUS itself has already seen. A finding is evidence, never authority;
 * `containment` is a recommendation to AEGIS, never an action.
 *
 * Shared conventions (agreed with lane D, the shadow-state core):
 *   - CAPABILITY_GRANTED: cap_id/cap_generation = the NEW reference,
 *     resource = authority resource, object_id = AIENOS_CAP_RIGHT_* mask,
 *     principal = authority subject, code = authority result code.
 *   - "Capability use" events: CAPABILITY_USED, EXTERNAL_EFFECT_REQUESTED,
 *     EXTERNAL_EFFECT_COMMITTED, CREDENTIAL_LEASE_USED, PROVIDER_USED, when
 *     they carry cap_id != 0 (is_cap_use below; one definition for all).
 *   - A machine is "joined" when machine() finds it AND joined_sequence != 0.
 *     MACHINE_REMOVED must either drop the entry or zero joined_sequence.
 *   - PROVIDER_*: evidence_digest = provider id. Shadow state REVOKED means
 *     the provider is quarantined.
 *   - CREDENTIAL_LEASE_*: object_id = lease id, resource = scope (created) or
 *     requested resource bits (used), principal = subject.
 *   - ARTIFACT_*: evidence_digest = artifact digest.
 *   - world(): ARGUS_ERR_STATE is treated as "no World committed yet".
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
    if (ev->cap_id == 0)
        return 0;
    switch (ev->kind) {
    case ARGUS_EV_CAPABILITY_USED:
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

static int cap_lookup(const ArgusStateOps *ops, const ArgusStateView *v, uint32_t id, ArgusCapShadow *s)
{
    return ops->cap(v, id, s) == ARGUS_OK;
}

static int machine_joined(const ArgusStateOps *ops, const ArgusStateView *v,
                          const uint8_t id[ARGUS_MACHINE_ID_LEN], ArgusMachineShadow *m)
{
    return ops->machine(v, id, m) == ARGUS_OK && m->joined_sequence != 0;
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
 * Trigger:  (a) kind == FORGED_CAPABILITY (any outcome: the producer itself
 *           reports a forgery attempt); or
 *           (b) a capability use with cap_id != 0 and outcome OK whose slot
 *           ARGUS has never seen granted (shadow UNSEEN); or
 *           (c) a capability use with outcome OK but code ERR_BOUNDS or
 *           ERR_CHAIN (the authority's own code contradicts the outcome).
 * Evidence: ev kind/outcome/code/cap_id; cap shadow existence.
 * NOT triggered by CAPABILITY_GRANTED: its cap_id is the new reference and is
 *           legitimately unseen. The event has no parent-reference field, so
 *           "granted from a forged parent" is not detectable in ABI v1
 *           (see the header proposal in the lane E report).
 * Code ARGUS_F_FORGED_CAPABILITY, CRITICAL, sync_allowed 1,
 * containment FREEZE_PRINCIPAL (then revoke the reference). prior_sequence 0.
 */
static int det_forged_capability(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                 ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    int hit = 0;
    if (ev->kind == ARGUS_EV_FORGED_CAPABILITY) {
        hit = 1;
    } else if (is_cap_use(ev) && outcome_ok(ev)) {
        ArgusCapShadow s;
        if (ev->code == ARGUS_AUTH_ERR_BOUNDS || ev->code == ARGUS_AUTH_ERR_CHAIN)
            hit = 1;
        else if (!cap_lookup(ops, v, ev->cap_id, &s) || s.state == ARGUS_SHADOW_UNSEEN)
            hit = 1;
    }
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_FORGED_CAPABILITY, ARGUS_SEV_CRITICAL, 1,
                ARGUS_CONTAIN_FREEZE_PRINCIPAL, 0);
}

/* ---- 2 STALE_GENERATION ----------------------------------------------------
 * Trigger:  (a) kind == STALE_GENERATION (any outcome: an explicit integrity
 *           report from the producer; a normal authority refusal of an old
 *           reference is reported as CAPABILITY_USED/DENIED code ERR_STALE_GEN,
 *           which does NOT trigger); or
 *           (b) a capability use with outcome OK and cap_generation lower than
 *           the shadow's current generation for that slot; or
 *           (c) a capability use with outcome OK but code ERR_STALE_GEN.
 * Evidence: ev cap_id/cap_generation/outcome/code; cap shadow generation.
 * Code ARGUS_F_STALE_GENERATION, HIGH, sync_allowed 1, containment
 * REVOKE_CAPABILITY. prior_sequence = shadow granted_sequence when known.
 */
static int det_stale_generation(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    ArgusCapShadow s;
    int found = ev->cap_id != 0 && cap_lookup(ops, v, ev->cap_id, &s);
    uint64_t prior = found ? s.granted_sequence : 0;
    int hit = 0;
    if (ev->kind == ARGUS_EV_STALE_GENERATION) {
        hit = 1;
    } else if (is_cap_use(ev) && outcome_ok(ev)) {
        if (ev->code == ARGUS_AUTH_ERR_STALE_GEN)
            hit = 1;
        else if (found && s.state != ARGUS_SHADOW_UNSEEN && ev->cap_generation < s.generation)
            hit = 1;
    }
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_STALE_GENERATION, ARGUS_SEV_HIGH, 1,
                ARGUS_CONTAIN_REVOKE_CAPABILITY, prior);
}

/* ---- 3 REVOKED_CAPABILITY_USED ---------------------------------------------
 * Trigger:  a capability use with outcome OK where (a) the shadow says the
 *           slot is REVOKED, or (b) the code is ERR_REVOKED (contradiction).
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
    ArgusCapShadow s;
    int found = cap_lookup(ops, v, ev->cap_id, &s);
    int revoked = found && s.state == ARGUS_SHADOW_REVOKED;
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
    ArgusArtifactShadow a;
    int found = ops->artifact(v, ev->evidence_digest, &a) == ARGUS_OK;
    if (found && a.state == ARGUS_SHADOW_LIVE)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED, ARGUS_SEV_CRITICAL, 1,
                ARGUS_CONTAIN_REJECT_ARTIFACT, found ? a.sequence : 0);
}

/* ---- 5 SIGNATURE_INVALID ---------------------------------------------------
 * Trigger:  (a) kind == SIGNATURE_FAILURE, any outcome (a failed signature
 *           on a trusted path is always evidence); or (b) ARTIFACT_ADMITTED
 *           with outcome OK but a nonzero code (admitted despite an error).
 * Evidence: ev kind/outcome/code. No shadow lookup.
 * Code ARGUS_F_SIGNATURE_INVALID, HIGH, sync_allowed 1, containment
 * REJECT_ARTIFACT. prior_sequence 0.
 */
static int det_signature_invalid(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                 ArgusFinding *out, size_t cap, size_t *n_out)
{
    (void)ops;
    (void)v;
    *n_out = 0;
    int hit = ev->kind == ARGUS_EV_SIGNATURE_FAILURE ||
              (ev->kind == ARGUS_EV_ARTIFACT_ADMITTED && outcome_ok(ev) && ev->code != 0);
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_SIGNATURE_INVALID, ARGUS_SEV_HIGH, 1,
                ARGUS_CONTAIN_REJECT_ARTIFACT, 0);
}

/* ---- 6 CREDENTIAL_SCOPE_VIOLATION ------------------------------------------
 * Trigger:  CREDENTIAL_LEASE_USED with outcome OK where the lease (object_id)
 *           is unseen, not LIVE (revoked), held by another subject
 *           (lease.subject != principal), or the requested resource bits
 *           exceed the lease scope ((resource & ~scope) != 0).
 * Evidence: ev object_id/principal/resource/outcome; lease shadow.
 * Code ARGUS_F_CREDENTIAL_SCOPE_VIOLATION, HIGH, sync_allowed 0,
 * containment REVOKE_CREDENTIAL_LEASE. prior_sequence = lease sequence.
 */
static int det_credential_scope_violation(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                          ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (ev->kind != ARGUS_EV_CREDENTIAL_LEASE_USED || !outcome_ok(ev))
        return ARGUS_OK;
    ArgusLeaseShadow l;
    int found = ops->lease(v, ev->object_id, &l) == ARGUS_OK;
    if (found && l.state == ARGUS_SHADOW_LIVE && l.subject == ev->principal &&
        (ev->resource & ~l.scope) == 0)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION, ARGUS_SEV_HIGH, 0,
                ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE, found ? l.sequence : 0);
}

/* ---- 7 MACHINE_IDENTITY_MISMATCH -------------------------------------------
 * Trigger:  (a) any event other than MACHINE_JOINED carrying a nonzero
 *           machine_id that is not a joined machine (unknown, or removed); or
 *           (b) MACHINE_JOINED with outcome OK for a machine that is already
 *           joined (re-join without MACHINE_REMOVED in between).
 *           Zero machine_id = "not attributed to a machine", never triggers.
 * Evidence: ev machine_id/kind/outcome; machine shadow joined_sequence.
 * Code ARGUS_F_MACHINE_IDENTITY_MISMATCH, HIGH, sync_allowed 0,
 * containment REQUIRE_REATTESTATION. prior_sequence = earlier join, if any.
 * MachineId is PROVISIONAL (opaque 32 bytes); this is an identity-consistency
 * check only, not cryptographic attestation.
 */
static int det_machine_identity_mismatch(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                         ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (bytes_zero(ev->machine_id, ARGUS_MACHINE_ID_LEN))
        return ARGUS_OK;
    ArgusMachineShadow m;
    int joined = machine_joined(ops, v, ev->machine_id, &m);
    int hit;
    if (ev->kind == ARGUS_EV_MACHINE_JOINED)
        hit = outcome_ok(ev) && joined;
    else
        hit = !joined;
    if (!hit)
        return ARGUS_OK;
    return emit(out, cap, n_out, ev, ARGUS_F_MACHINE_IDENTITY_MISMATCH, ARGUS_SEV_HIGH, 0,
                ARGUS_CONTAIN_REQUIRE_REATTESTATION, joined ? m.joined_sequence : 0);
}

/* ---- 8 EFFECT_CLASS_UNAUTHORIZED -------------------------------------------
 * Trigger:  outcome OK on EXTERNAL_EFFECT_REQUESTED / EXTERNAL_EFFECT_COMMITTED
 *           (or CAPABILITY_USED with effect_class EXTERNAL) where
 *           (a) cap_id == 0 and effect_class == EXTERNAL (irreversible effect
 *           with no capability at all), or (b) the capability's granted rights
 *           in the shadow lack AIENOS_CAP_RIGHT_EFFECT.
 *           An unseen cap_id is left to detector 1 (no double report).
 * Evidence: ev kind/effect_class/cap_id/outcome; cap shadow rights.
 * Code ARGUS_F_EFFECT_CLASS_UNAUTHORIZED, CRITICAL, sync_allowed 1,
 * containment PAUSE_EXTERNAL_EFFECTS. prior_sequence = the grant.
 */
static int det_effect_class_unauthorized(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                                         ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    int effect_kind = ev->kind == ARGUS_EV_EXTERNAL_EFFECT_REQUESTED ||
                      ev->kind == ARGUS_EV_EXTERNAL_EFFECT_COMMITTED ||
                      (ev->kind == ARGUS_EV_CAPABILITY_USED && ev->effect_class == ARGUS_EFFECT_EXTERNAL);
    if (!effect_kind || !outcome_ok(ev))
        return ARGUS_OK;
    uint64_t prior = 0;
    int hit = 0;
    if (ev->cap_id == 0) {
        hit = ev->effect_class == ARGUS_EFFECT_EXTERNAL;
    } else {
        ArgusCapShadow s;
        if (cap_lookup(ops, v, ev->cap_id, &s) && s.state != ARGUS_SHADOW_UNSEEN &&
            (s.rights & ARGUS_AUTH_RIGHT_EFFECT) == 0) {
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
 *           committed (shadow generation != 0), and either
 *           (a) world_generation == shadow generation with a different
 *           evidence_digest (two different Worlds claim one generation), or
 *           (b) world_generation != shadow generation + 1 otherwise (skip or
 *           rollback). Equal generation with the SAME digest is an idempotent
 *           replay and does not trigger. The first commit ever is accepted.
 *           Generations are 64-bit (ABI 13f05f6); a shadow at UINT64_MAX has no
 *           legal successor, so any different generation after it triggers.
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
    ArgusWorldShadow w;
    if (ops->world(v, &w) != ARGUS_OK || w.generation == 0)
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
 *           is quarantined (shadow REVOKED) -> containment QUARANTINE_PROVIDER;
 *           (b) any event with outcome OK carrying a nonzero machine_id whose
 *           machine shadow trust is QUARANTINED -> QUARANTINE_MACHINE.
 *           MACHINE_JOINED / MACHINE_TRUST_CHANGED / MACHINE_REMOVED are
 *           exempt from (b): they are the lifecycle of the quarantine itself.
 *           Can emit two findings for one event (both clauses).
 * Evidence: ev kind/outcome/evidence_digest/machine_id; provider + machine shadows.
 * Code ARGUS_F_QUARANTINED_USE, CRITICAL, sync_allowed 1. prior_sequence =
 * the quarantine (provider sequence / machine changed_sequence).
 */
static int det_quarantined_use(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                               ArgusFinding *out, size_t cap, size_t *n_out)
{
    *n_out = 0;
    if (!outcome_ok(ev))
        return ARGUS_OK;
    int rc;
    if (ev->kind == ARGUS_EV_PROVIDER_USED) {
        ArgusProviderShadow p;
        if (ops->provider(v, ev->evidence_digest, &p) == ARGUS_OK && p.state == ARGUS_SHADOW_REVOKED) {
            rc = emit(out, cap, n_out, ev, ARGUS_F_QUARANTINED_USE, ARGUS_SEV_CRITICAL, 1,
                      ARGUS_CONTAIN_QUARANTINE_PROVIDER, p.sequence);
            if (rc != ARGUS_OK)
                return rc;
        }
    }
    int lifecycle = ev->kind == ARGUS_EV_MACHINE_JOINED || ev->kind == ARGUS_EV_MACHINE_TRUST_CHANGED ||
                    ev->kind == ARGUS_EV_MACHINE_REMOVED;
    if (!lifecycle && !bytes_zero(ev->machine_id, ARGUS_MACHINE_ID_LEN)) {
        ArgusMachineShadow m;
        if (ops->machine(v, ev->machine_id, &m) == ARGUS_OK && m.trust == ARGUS_TRUST_QUARANTINED) {
            rc = emit(out, cap, n_out, ev, ARGUS_F_QUARANTINED_USE, ARGUS_SEV_CRITICAL, 1,
                      ARGUS_CONTAIN_QUARANTINE_MACHINE, m.changed_sequence);
            if (rc != ARGUS_OK)
                return rc;
        }
    }
    return ARGUS_OK;
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
        ops->provider == NULL || ops->world == NULL)
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
