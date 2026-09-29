/*
 * test_argus_hostile.c -- ARGUS-0 hostile review (lane G): negative tests.
 *
 * Every test is written against the public contract in argus_abi.h only
 * (argus_core_*, argus_ring_*, argus_event_*, argus_detect_run). Each prints
 *     HOSTILE <name> PASS|FAIL
 * where PASS means "the defended behavior was observed". Tests for issues the
 * review found OPEN or WEAK are marked EXPECTED-FAIL below and in the output:
 * they FAIL today on purpose, so the integrator sees the hole. When one starts
 * passing it prints XPASS: update docs/HOSTILE_REVIEW.md and drop the marker.
 * The process exits nonzero only on an UNEXPECTED failure (a test that should
 * pass and did not), so "OPEN as documented" and "regression" stay distinct.
 * A third mode, N/A-v1, marks an attack that ABI v1 accepts by design (a
 * documented limitation, not a defect): it prints PASS|FAIL with an [N/A-v1]
 * marker, is counted separately, and never affects the exit code.
 *
 * Integrator round 2 (after lanes B 58d5a99, D 57a7bea, E a33c1e0): every
 * test that became defended was flipped from EXPECTED-FAIL to expected-pass;
 * the ruled corrections (ev0 class floor, code-16 outcomes, 0x7FFF flood kind,
 * world rollback case, table sizes, ratified producer overflow, zero-machine
 * flags, idempotent World repeat) are applied and commented where they occur.
 *
 * Section numbers (G-x) refer to docs/HOSTILE_REVIEW.md.
 *
 * Build: `make test-hostile` (part of `make test`; links out/libargus.a only).
 * By hand (from native/argus, same CFLAGS as ../capability/Makefile):
 *   cc -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -I. \
 *      -o out/test_argus_hostile tests/test_argus_hostile.c \
 *      argus_core.c argus_event.c argus_ring.c sha256.c argus_detect.c
 * It deliberately does NOT link the capability authority: if any ARGUS
 * object ever referenced an aienos_cap_* symbol, this link would fail (G-1).
 */
#include "../argus_abi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mirrors of argus_core.h capacities (lane D, 57a7bea). The exhaustion tests
 * fill each table exactly and then overshoot it, so they test the limit itself;
 * if a size changes, change it here (the tests then still overshoot). */
#define H_MACHINES   64u
#define H_PRODUCERS  256u
#define H_INCIDENTS  256u
#define H_LEASES     256u

/* A kind value outside ABI v1. argus_event_min_class() returns 0 for it, so the
 * ring (transport only) accepts it at any class, while the core's validate
 * rejects it. Used wherever a test needs INFORMATIONAL/AUDIT ring traffic:
 * no v1 kind has an INFORMATIONAL floor (design fact, argus_event.c). */
#define K_NON_V1     0x7FFFu
#define H_FBUF       64u

/* ---- reporting ------------------------------------------------------------ */

static int n_pass, n_xfail, n_xpass, n_unexpected, n_na;

enum { EXPECT_DEFENDED = 0, EXPECT_FAIL = 1, NA_V1 = 2 };

static void result(const char *name, int defended, int expected_fail, const char *why)
{
    printf("HOSTILE %s %s", name, defended ? "PASS" : "FAIL");
    if (expected_fail == NA_V1) {
        n_na++;
        printf("  [N/A-v1: documented limitation, exempt from exit code: %s]", why);
    } else if (expected_fail && !defended) {
        n_xfail++;
        printf("  [EXPECTED-FAIL: %s]", why);
    } else if (expected_fail) {
        n_xpass++;
        printf("  [XPASS: was OPEN/WEAK, now defended; update HOSTILE_REVIEW.md]");
    } else if (defended) {
        n_pass++;
    } else {
        n_unexpected++;
        printf("  [UNEXPECTED: %s]", why);
    }
    printf("\n");
}

/* ---- harness -------------------------------------------------------------- */

static uint64_t g_seq;

typedef struct {
    void *mem;
    ArgusCore *c;
    ArgusFinding f[H_FBUF];
    size_t n;
    int rc;
} H;

static void *alloc64(size_t bytes)
{
    size_t b = (bytes + 63u) & ~(size_t)63u;
    void *p = aligned_alloc(64, b);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        exit(2);
    }
    memset(p, 0, b);
    return p;
}

static void h_new(H *h)
{
    memset(h, 0, sizeof *h);
    g_seq = 0;
    size_t fp = argus_core_footprint();
    h->mem = alloc64(fp);
    if (argus_core_init(&h->c, h->mem, fp) != ARGUS_OK) {
        fprintf(stderr, "argus_core_init failed\n");
        exit(2);
    }
}

static void h_free(H *h)
{
    free(h->mem);
    h->mem = NULL;
    h->c = NULL;
}

static void mid(uint8_t id[ARGUS_MACHINE_ID_LEN], uint32_t n)
{
    memset(id, 0, ARGUS_MACHINE_ID_LEN);
    if (n) {
        id[0] = 0x4D;
        id[1] = (uint8_t)n;
        id[2] = (uint8_t)(n >> 8);
    }
}

static void dg(uint8_t d[ARGUS_DIGEST_LEN], uint32_t n)
{
    memset(d, 0, ARGUS_DIGEST_LEN);
    d[0] = 0xD1;
    d[1] = (uint8_t)n;
    d[2] = (uint8_t)(n >> 8);
}

static ArgusEvent ev0(uint16_t kind)
{
    ArgusEvent e;
    memset(&e, 0, sizeof e);
    e.version = ARGUS_ABI_VERSION;
    /* Weakest class the kind may carry (validate rejects anything weaker);
     * 0 = unknown kind -> SECURITY. */
    e.class_ = argus_event_min_class(kind);
    if (e.class_ == 0)
        e.class_ = ARGUS_CLASS_SECURITY;
    e.kind = kind;
    e.effect_class = ARGUS_EFFECT_NONE;
    e.outcome = ARGUS_OUTCOME_OK;
    e.flags = ARGUS_FLAG_SYNTHETIC;
    return e;
}

static ArgusEvent grant(uint32_t cap, uint64_t gen, uint32_t subject, uint32_t rights)
{
    ArgusEvent e = ev0(ARGUS_EV_CAPABILITY_GRANTED);
    e.cap_id = cap;
    e.cap_generation = gen;
    e.principal = subject;
    e.object_id = rights;
    e.resource = 0x10;
    return e;
}

static ArgusEvent revoke(uint32_t cap, uint64_t gen)
{
    ArgusEvent e = ev0(ARGUS_EV_CAPABILITY_REVOKED);
    e.cap_id = cap;
    e.cap_generation = gen;
    return e;
}

static ArgusEvent use(uint32_t cap, uint64_t gen, uint32_t principal, uint8_t outcome, int32_t code)
{
    ArgusEvent e = ev0(ARGUS_EV_CAPABILITY_USED);
    e.cap_id = cap;
    e.cap_generation = gen;
    e.principal = principal;
    e.outcome = outcome;
    e.code = code;
    e.resource = 0x10;
    return e;
}

/* MACHINE_*: trust travels in object_id (ABI b75d357); 0 on JOINED = OBSERVED. */
static ArgusEvent machine_ev(uint16_t kind, uint32_t m, uint32_t trust)
{
    ArgusEvent e = ev0(kind);
    mid(e.machine_id, m);
    e.object_id = trust;
    return e;
}

/* Ingest; assigns the next sequence if the event has none. */
static int feed(H *h, ArgusEvent *e)
{
    if (e->sequence == 0)
        e->sequence = ++g_seq;
    h->n = 0;
    h->rc = argus_core_ingest(h->c, e, h->f, H_FBUF, &h->n);
    return h->rc;
}

static size_t count(const H *h, uint16_t code)
{
    size_t k = 0;
    for (size_t i = 0; i < h->n; i++)
        if (h->f[i].code == code)
            k++;
    return k;
}

static int cap_state(const H *h, uint32_t cap, ArgusCapShadow *s)
{
    return argus_core_ops()->cap(argus_core_view(h->c), cap, s);
}

static int machine_trust(const H *h, uint32_t m, uint32_t *trust)
{
    ArgusMachineShadow ms;
    uint8_t id[ARGUS_MACHINE_ID_LEN];
    mid(id, m);
    if (argus_core_ops()->machine(argus_core_view(h->c), id, &ms) != ARGUS_OK)
        return 0;
    *trust = ms.trust;
    return 1;
}

/* Rights / result codes: the authority's values (lane E's tests assert its
 * mirrors equal aienos_capability.h). Mirrored here so this file does not
 * include or link the authority. */
#define R_READ   0x1u
#define R_WRITE  0x2u
#define R_EFFECT 0x4u
#define AUTH_ERR_STALE_GEN (-2)
#define AUTH_ERR_REVOKED   (-3)

/* ==== G-3 / G-4: capability replay, stale and future generations ==== */

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-3, OPEN): a replayed GRANTED for an (id, generation) the
 * shadow already saw revoked brings the slot back to LIVE, so a later
 * successful use of the revoked reference raises nothing. */
static void t_grant_replay_revives_revoked(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 1, 7, R_READ);
    feed(&h, &e);
    e = revoke(5, 1); feed(&h, &e);
    e = grant(5, 1, 7, R_READ); feed(&h, &e);           /* replay, fresh sequence */
    size_t on_replay = h.n;
    e = use(5, 1, 7, ARGUS_OUTCOME_OK, 0); feed(&h, &e);
    int defended = on_replay > 0 || count(&h, ARGUS_F_REVOKED_CAPABILITY_USED) > 0;
    result("grant_replay_revives_revoked", defended, EXPECT_DEFENDED,
           "apply_cap overwrites a REVOKED slot on an equal-generation GRANTED; no detector looks at GRANTED");
    h_free(&h);
}

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-3, OPEN): even a byte-exact replay (same sequence) is only
 * flagged as SEQUENCE_ANOMALY and is then applied, reviving the slot. */
static void t_exact_replay_still_applied(void)
{
    H h; h_new(&h);
    ArgusEvent g = grant(5, 1, 7, R_READ);
    feed(&h, &g);
    ArgusEvent e = revoke(5, 1); feed(&h, &e);
    ArgusEvent again = g;                                 /* identical bytes */
    feed(&h, &again);
    int anomaly = count(&h, ARGUS_F_SEQUENCE_ANOMALY) == 1;
    ArgusCapShadow s;
    int still_revoked = cap_state(&h, 5, &s) == ARGUS_OK && s.state == ARGUS_SHADOW_REVOKED;
    result("exact_replay_still_applied", anomaly && still_revoked, EXPECT_DEFENDED,
           "anomalous (replayed) events are still applied to shadow state");
    h_free(&h);
}

/* DEFENDED since a33c1e0; the attack as first found, EXPECTED-FAIL (G-4, OPEN): a use with a generation HIGHER than any ever
 * granted for the slot is a reference ARGUS never saw minted; no finding. */
static void t_future_generation_use_unflagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 3, 7, R_READ); feed(&h, &e);
    e = use(5, 4, 7, ARGUS_OUTCOME_OK, 0); feed(&h, &e);
    int defended = count(&h, ARGUS_F_FORGED_CAPABILITY) + count(&h, ARGUS_F_STALE_GENERATION) > 0;
    result("future_generation_use_unflagged", defended, EXPECT_DEFENDED,
           "detector 1 checks only UNSEEN slots, detector 2 only lower generations");
    h_free(&h);
}

static void t_stale_generation_use_flagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 3, 7, R_READ); feed(&h, &e);
    e = revoke(5, 3); feed(&h, &e);
    e = grant(5, 4, 7, R_READ); feed(&h, &e);            /* legitimate slot reuse */
    e = use(5, 3, 7, ARGUS_OUTCOME_OK, 0); feed(&h, &e);
    result("stale_generation_use_flagged", count(&h, ARGUS_F_STALE_GENERATION) == 1, EXPECT_DEFENDED,
           "old generation used with outcome OK was not reported");
    h_free(&h);
}

static void t_revoked_use_flagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 1, 7, R_READ); feed(&h, &e);
    e = revoke(5, 1); feed(&h, &e);
    e = use(5, 1, 7, ARGUS_OUTCOME_OK, 0); feed(&h, &e);
    int ok = count(&h, ARGUS_F_REVOKED_CAPABILITY_USED) == 1 && h.n >= 1 && h.f[0].prior_sequence == 2;
    result("revoked_use_flagged", ok, EXPECT_DEFENDED, "revoked reference used OK was not reported with its revocation");
    h_free(&h);
}

/* False-positive guard: the authority refusing a revoked reference is correct. */
static void t_revoked_use_denied_is_quiet(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 1, 7, R_READ); feed(&h, &e);
    e = revoke(5, 1); feed(&h, &e);
    e = use(5, 1, 7, ARGUS_OUTCOME_DENIED, AUTH_ERR_REVOKED); feed(&h, &e);
    result("revoked_use_denied_is_quiet", h.n == 0 && h.rc == ARGUS_OK, EXPECT_DEFENDED, "authority behaving correctly raised a finding");
    h_free(&h);
}

/* DEFENDED since a33c1e0; the attack as first found, EXPECTED-FAIL (G-3, OPEN): the shadow records the subject at grant, but a
 * successful use by a different principal is not cross-checked. */
static void t_use_by_other_subject_unflagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 1, 7, R_READ); feed(&h, &e);
    e = use(5, 1, 9, ARGUS_OUTCOME_OK, 0); feed(&h, &e);
    result("use_by_other_subject_unflagged", h.n > 0, EXPECT_DEFENDED,
           "no detector compares event principal with the granted subject");
    h_free(&h);
}

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-4, OPEN): one forged REVOKED at generation UINT64_MAX for
 * a never-granted slot is accepted silently and poisons the slot forever:
 * every later legitimate grant is ignored and every legitimate use becomes a
 * CRITICAL REVOKED_CAPABILITY_USED (FREEZE_PRINCIPAL). */
static void t_revoke_gen_max_poisons_slot(void)
{
    H h; h_new(&h);
    ArgusEvent e = revoke(5, UINT64_MAX); feed(&h, &e);
    size_t on_forged = h.n;
    e = grant(5, 1, 7, R_READ); feed(&h, &e);
    e = use(5, 1, 7, ARGUS_OUTCOME_OK, 0); feed(&h, &e);
    int false_critical = count(&h, ARGUS_F_REVOKED_CAPABILITY_USED) > 0;
    result("revoke_gen_max_poisons_slot", on_forged > 0 || !false_critical, EXPECT_DEFENDED,
           "revocation of an unseen reference creates sticky REVOKED state at any generation");
    h_free(&h);
}

/* DEFENDED since 58d5a99; the attack as first found, EXPECTED-FAIL (G-20, OPEN): cap_id >= AIENOS_CAP_MAX on GRANTED is a
 * reference the authority can never produce, but it is reported as ARGUS's
 * own telemetry loss (ERR_FULL + CRITICAL) instead of malformed/forged.
 * One event = one CRITICAL, at the attacker's chosen principal. */
static void t_cap_id_out_of_range_is_critical_loss(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(300, 1, 1234, R_READ); feed(&h, &e);
    int defended = h.rc != ARGUS_ERR_FULL && count(&h, ARGUS_F_TELEMETRY_LOSS) == 0;
    result("cap_id_out_of_range_is_critical_loss", defended, EXPECT_DEFENDED,
           "validate accepts any cap_id; core maps cap_id>=256 to ERR_FULL + CRITICAL TELEMETRY_LOSS");
    h_free(&h);
}

static void t_cap_id_out_of_range_use_is_forged(void)
{
    H h; h_new(&h);
    ArgusEvent e = use(300, 1, 7, ARGUS_OUTCOME_OK, 0); feed(&h, &e);
    /* Ruled: validate rejects cap_id >= ARGUS_CAP_MAX first, so the defended
     * outcome is MALFORMED_EVENT (16), or FORGED (1) from the detectors. */
    result("cap_id_out_of_range_use_is_forged",
           count(&h, ARGUS_F_FORGED_CAPABILITY) == 1 || count(&h, ARGUS_F_MALFORMED_EVENT) == 1, EXPECT_DEFENDED,
           "out-of-range reference used OK was not reported as forged");
    h_free(&h);
}

/* ==== G-24 effect class ==================================================== */

/* DEFENDED since 58d5a99; the attack as first found, EXPECTED-FAIL (G-24, OPEN): an EXTERNAL_EFFECT_COMMITTED labelled
 * effect_class NONE with no capability escapes detector 8. */
static void t_effect_kind_mislabelled(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_EXTERNAL_EFFECT_COMMITTED);
    e.effect_class = ARGUS_EFFECT_NONE;
    feed(&h, &e);
    /* Ruled: validate rejects an effect kind labelled NONE (code 16). */
    result("effect_kind_mislabelled",
           count(&h, ARGUS_F_EFFECT_CLASS_UNAUTHORIZED) == 1 || count(&h, ARGUS_F_MALFORMED_EVENT) == 1, EXPECT_DEFENDED,
           "detector 8 trusts the producer's effect_class over the event kind");
    h_free(&h);
}

static void t_external_effect_without_right_flagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 1, 7, R_READ); feed(&h, &e);
    e = use(5, 1, 7, ARGUS_OUTCOME_OK, 0);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    feed(&h, &e);
    result("external_effect_without_right_flagged", count(&h, ARGUS_F_EFFECT_CLASS_UNAUTHORIZED) == 1, EXPECT_DEFENDED,
           "external effect under a capability without RIGHT_EFFECT not reported");
    h_free(&h);
}

/* DEFENDED since a33c1e0; the attack as first found, EXPECTED-FAIL (G-24, WEAK): a durable EVIDENCE write under a READ-only
 * capability is "beyond what the rights permit" (ADR 0017 sec 3, row 8). */
static void t_evidence_write_with_read_only_right(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 1, 7, R_READ); feed(&h, &e);
    e = use(5, 1, 7, ARGUS_OUTCOME_OK, 0);
    e.effect_class = ARGUS_EFFECT_EVIDENCE;
    feed(&h, &e);
    result("evidence_write_with_read_only_right", count(&h, ARGUS_F_EFFECT_CLASS_UNAUTHORIZED) == 1, EXPECT_DEFENDED,
           "detector 8 only checks EXTERNAL vs RIGHT_EFFECT");
    h_free(&h);
}

/* ==== G-2 confused deputy ================================================== */

/* DEFENDED since a33c1e0; the attack as first found, EXPECTED-FAIL (G-2, WEAK now, OPEN at ARGUS-1): a single producer-reported
 * FORGED_CAPABILITY event, with no shadow evidence at all, yields a CRITICAL
 * finding against an arbitrary principal with FREEZE_PRINCIPAL and
 * sync_allowed=1. Once ARGUS-1 wires containment, whoever can push events
 * can nominate any principal (including the office holder) for freezing. */
static void t_reported_forgery_names_arbitrary_victim(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_FORGED_CAPABILITY);
    e.outcome = ARGUS_OUTCOME_DENIED;
    e.principal = 1;                                      /* the victim */
    e.cap_id = 1;
    e.cap_generation = 1;
    feed(&h, &e);
    int sync_on_hearsay = 0;
    for (size_t i = 0; i < h.n; i++)
        if (h.f[i].sync_allowed && h.f[i].containment == ARGUS_CONTAIN_FREEZE_PRINCIPAL)
            sync_on_hearsay = 1;
    result("reported_forgery_names_arbitrary_victim", !sync_on_hearsay, EXPECT_DEFENDED,
           "self-reported kinds (FORGED/STALE/SIGNATURE) emit sync-eligible findings with no shadow evidence");
    h_free(&h);
}

/* ==== G-5 event forgery and ARGUS's own voice ======================== */

/* DEFENDED since 58d5a99; the attack as first found, EXPECTED-FAIL (G-5 / G-20, OPEN): a producer (no CONSUMER flag, INFORMATIONAL
 * class, outcome OK) can forge TELEMETRY_DROPPED and get a CRITICAL
 * TELEMETRY_LOSS finding per event. */
static void t_forged_telemetry_dropped(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_TELEMETRY_DROPPED);
    e.class_ = ARGUS_CLASS_INFORMATIONAL;
    e.flags = 0;
    e.object_id = ARGUS_CLASS_CRITICAL;
    e.resource = 1;
    feed(&h, &e);
    result("forged_telemetry_dropped", count(&h, ARGUS_F_TELEMETRY_LOSS) == 0, EXPECT_DEFENDED,
           "core raises TELEMETRY_LOSS for any TELEMETRY_DROPPED, whoever sent it");
    h_free(&h);
}

/* DEFENDED since 58d5a99; the attack as first found, EXPECTED-FAIL (G-5, OPEN): the CONSUMER flag ("synthesized by ARGUS") is
 * accepted from the wire on any kind. */
static void t_consumer_flag_accepted_from_wire(void)
{
    ArgusEvent e = grant(5, 1, 7, R_READ);
    e.sequence = 1;
    e.flags = ARGUS_FLAG_CONSUMER;
    result("consumer_flag_accepted_from_wire", argus_event_validate(&e) != ARGUS_OK, EXPECT_DEFENDED,
           "validate accepts FLAG_CONSUMER on producer kinds");
}

/* EXPECTED-FAIL, ABI v1 LIMIT (no producer identity; G-5, OPEN by design of ABI v1): an unattributed GRANTED
 * (zero machine_id, no producer identity) is enough to make a forged use of
 * that reference look legitimate. ARGUS-0 cannot tell the authority's grant
 * from anyone else's. */
static void t_unattributed_grant_masks_forged_use(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(9, 1, 66, R_READ | R_WRITE | R_EFFECT); feed(&h, &e);
    size_t on_grant = h.n;
    e = use(9, 1, 66, ARGUS_OUTCOME_OK, 0);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    feed(&h, &e);
    result("unattributed_grant_masks_forged_use", on_grant + h.n > 0, EXPECT_FAIL,
           "no producer identity: any pusher can announce grants");
    h_free(&h);
}

/* ==== G-21 sequence abuse ================================================== */

static void t_sequence_replay_flagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = use(0, 0, 7, ARGUS_OUTCOME_DENIED, 0);
    e.sequence = 5; feed(&h, &e);
    ArgusEvent r = e; feed(&h, &r);
    result("sequence_replay_flagged",
           count(&h, ARGUS_F_SEQUENCE_ANOMALY) == 1 && h.n >= 1 && h.f[0].prior_sequence == 5, EXPECT_DEFENDED,
           "replayed sequence not reported");
    h_free(&h);
}

/* DEFENDED since 58d5a99; the attack as first found, EXPECTED-FAIL (G-21, OPEN): one event with sequence UINT64_MAX is accepted
 * silently and moves the stream's high-water mark to the top; every later
 * legitimate event on that stream is a SEQUENCE_ANOMALY forever. */
static void t_sequence_high_water_poison(void)
{
    H h; h_new(&h);
    ArgusEvent e = use(0, 0, 7, ARGUS_OUTCOME_DENIED, 0);
    e.sequence = 1; feed(&h, &e);
    e.sequence = UINT64_MAX; feed(&h, &e);
    size_t on_poison = h.n;
    size_t later = 0;
    for (uint64_t s = 2; s < 5; s++) {
        e.sequence = s; feed(&h, &e);
        later += count(&h, ARGUS_F_SEQUENCE_ANOMALY);
    }
    result("sequence_high_water_poison", on_poison > 0 || later == 0, EXPECT_DEFENDED,
           "implausible jump not flagged; high-water mark is permanent, no epoch/restart field");
    h_free(&h);
}

/* EXPECTED-FAIL, still OPEN, no ruling (the core documents "gaps are not
 * findings"; G-6, OPEN): omission. A producer stream jumping from 1 to
 * 100 with no TELEMETRY_DROPPED in between is not reported. */
static void t_sequence_gap_unflagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = use(0, 0, 7, ARGUS_OUTCOME_DENIED, 0);
    e.sequence = 1; feed(&h, &e);
    e.sequence = 100; feed(&h, &e);
    result("sequence_gap_unflagged", h.n > 0, EXPECT_FAIL, "gaps are not detected; only repeats/decreases are");
    h_free(&h);
}

/* DEFENDED since 58d5a99 (G-21 first variant): re-keying a byte replay with
 * the CONSUMER flag. Validate now rejects CONSUMER on any kind but
 * TELEMETRY_DROPPED, so the replay is MALFORMED_EVENT (16) and not applied. */
static void t_replay_rekeyed_by_consumer_flag(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 1, 7, R_READ);
    e.sequence = 10; feed(&h, &e);
    ArgusEvent r = e;
    r.flags = ARGUS_FLAG_CONSUMER;                        /* new stream, same sequence */
    feed(&h, &r);
    result("replay_rekeyed_by_consumer_flag",
           count(&h, ARGUS_F_SEQUENCE_ANOMALY) > 0 || count(&h, ARGUS_F_MALFORMED_EVENT) == 1, EXPECT_DEFENDED,
           "CONSUMER-flag re-keyed replay accepted");
    h_free(&h);
}

/* EXPECTED-FAIL, still OPEN, no ruling (G-21 second variant): a byte replay
 * escapes the sequence check by re-keying the stream with another machine_id.
 * Same root as G-5: ABI v1 has no producer identity, so the stream key is
 * chosen by the sender. (Attribution by the machine table does not help for
 * events that do not name a joined machine.) */
static void t_replay_evades_by_rekeying_stream(void)
{
    H h; h_new(&h);
    ArgusEvent e = grant(5, 1, 7, R_READ);
    e.sequence = 10; feed(&h, &e);
    ArgusEvent r = e;
    mid(r.machine_id, 4242);                              /* new stream, same sequence */
    feed(&h, &r);
    result("replay_evades_by_rekeying_stream", count(&h, ARGUS_F_SEQUENCE_ANOMALY) > 0, EXPECT_FAIL,
           "stream key (machine_id) is chosen by the sender");
    h_free(&h);
}

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-21 / G-20, OPEN): 33 distinct machine_ids exhaust the
 * never-freed producer table; after that, a new stream is not sequence-checked
 * at all (replay-blind) and every one of its events costs a CRITICAL. */
/* Now: RATIFIED overflow rule (57a7bea, argus_core.c step 1). The table holds
 * H_PRODUCERS streams; the FIRST untracked event returns ERR_FULL with exactly
 * one CRITICAL TELEMETRY_LOSS, later untracked events return OK (no per-event
 * CRITICAL amplifier) and are counted in health.producers_untracked. Streams
 * beyond the table remain replay-blind: that residual is documented WEAK in
 * HOSTILE_REVIEW.md (bounded, loud once, counted), not asserted here. */
static void t_producer_table_exhaustion(void)
{
    H h; h_new(&h);
    int ok = 1;
    for (uint32_t m = 0; m < H_PRODUCERS; m++) {         /* fill exactly */
        ArgusEvent e = use(0, 0, 7, ARGUS_OUTCOME_DENIED, 0);
        mid(e.machine_id, 1000u + m);
        feed(&h, &e);
        if (h.rc != ARGUS_OK || count(&h, ARGUS_F_TELEMETRY_LOSS) != 0)
            ok = 0;
    }
    ArgusCoreHealth before;
    argus_core_health(h.c, &before);
    int first_loud = 0, later_quiet = 1;
    for (uint32_t m = 0; m < 8u; m++) {                  /* overshoot */
        ArgusEvent e = use(0, 0, 7, ARGUS_OUTCOME_DENIED, 0);
        mid(e.machine_id, 1000u + H_PRODUCERS + m);
        feed(&h, &e);
        if (m == 0)
        {
            first_loud = h.rc == ARGUS_ERR_FULL && count(&h, ARGUS_F_TELEMETRY_LOSS) == 1;
            for (size_t i = 0; i < h.n; i++)
                if (h.f[i].code == ARGUS_F_TELEMETRY_LOSS && h.f[i].severity != ARGUS_SEV_CRITICAL)
                    first_loud = 0;
        }
        else if (h.rc != ARGUS_OK || count(&h, ARGUS_F_TELEMETRY_LOSS) != 0)
            later_quiet = 0;
    }
    ArgusCoreHealth after;
    argus_core_health(h.c, &after);
    int counted = after.producers_untracked - before.producers_untracked == 8u;
    result("producer_table_exhaustion", ok && first_loud && later_quiet && counted, EXPECT_DEFENDED,
           "producer overflow does not follow the ratified rule (first ERR_FULL + CRITICAL loss, later OK + counter)");
    h_free(&h);
}

/* ==== G-8 / G-10 machines: quarantine bypass and identity ======================== */

static void t_quarantined_machine_use_flagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0); feed(&h, &e);
    e = machine_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, 3, ARGUS_TRUST_QUARANTINED); feed(&h, &e);
    e = use(0, 0, 7, ARGUS_OUTCOME_OK, 0); mid(e.machine_id, 3); feed(&h, &e);
    result("quarantined_machine_use_flagged", count(&h, ARGUS_F_QUARANTINED_USE) == 1, EXPECT_DEFENDED,
           "use by a quarantined machine not reported");
    h_free(&h);
}

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-8, OPEN): REMOVED then JOINED launders a quarantine:
 * the entry is deleted and the rejoin creates a fresh machine (OBSERVED, or
 * whatever trust the JOINED's object_id claims). */
static void t_quarantine_laundered_by_remove_rejoin(void)
{
    H h; h_new(&h);
    ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0); feed(&h, &e);
    e = machine_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, 3, ARGUS_TRUST_QUARANTINED); feed(&h, &e);
    e = machine_ev(ARGUS_EV_MACHINE_REMOVED, 3, 0); feed(&h, &e);
    size_t n_removed = h.n;
    e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0); feed(&h, &e);
    size_t n_rejoin = h.n;
    e = use(0, 0, 7, ARGUS_OUTCOME_OK, 0); mid(e.machine_id, 3); feed(&h, &e);
    int defended = n_removed + n_rejoin > 0 || count(&h, ARGUS_F_QUARANTINED_USE) > 0;
    result("quarantine_laundered_by_remove_rejoin", defended, EXPECT_DEFENDED,
           "MACHINE_REMOVED deletes the quarantined entry; rejoin starts clean");
    h_free(&h);
}

/* DEFENDED since 57a7bea + a33c1e0; the attack as first found, EXPECTED-FAIL (G-8 / G-10, OPEN): the machine being described and the machine
 * reporting are the same field, so a quarantined machine can announce its
 * own trust upgrade; lifecycle kinds are exempt from detector 10. */
static void t_quarantined_machine_self_upgrades(void)
{
    H h; h_new(&h);
    ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0); feed(&h, &e);
    e = machine_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, 3, ARGUS_TRUST_QUARANTINED); feed(&h, &e);
    e = machine_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, 3, ARGUS_TRUST_TRUSTED); feed(&h, &e);
    size_t on_upgrade = h.n;
    e = use(0, 0, 7, ARGUS_OUTCOME_OK, 0); mid(e.machine_id, 3); feed(&h, &e);
    result("quarantined_machine_self_upgrades", on_upgrade + h.n > 0, EXPECT_DEFENDED,
           "no reporter/subject split; QUARANTINED -> TRUSTED accepted from anyone");
    h_free(&h);
}

/* DEFENDED since 57a7bea + a33c1e0; the attack as first found, EXPECTED-FAIL (G-10, OPEN): a machine's own JOINED may declare its initial
 * trust (object_id = TRUSTED) and is recorded as such, with no finding. */
static void t_join_declares_own_trust(void)
{
    H h; h_new(&h);
    ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, ARGUS_TRUST_TRUSTED); feed(&h, &e);
    uint32_t t = 0;
    int trusted = machine_trust(&h, 3, &t) && t == ARGUS_TRUST_TRUSTED;
    result("join_declares_own_trust", h.n > 0 || !trusted, EXPECT_DEFENDED,
           "JOINED object_id sets initial trust; the joiner is the reporter");
    h_free(&h);
}

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-10, OPEN): TRUST_CHANGED for a machine that has not
 * joined creates it with joined_sequence 0; the real JOIN is then ignored
 * ("rejoin never launders"), so the machine can never be joined and every
 * event it sends is a MACHINE_IDENTITY_MISMATCH. */
static void t_trust_before_join_bricks_machine(void)
{
    H h; h_new(&h);
    ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, 3, ARGUS_TRUST_OBSERVED); feed(&h, &e);
    e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0); feed(&h, &e);
    e = use(0, 0, 7, ARGUS_OUTCOME_OK, 0); mid(e.machine_id, 3); feed(&h, &e);
    result("trust_before_join_bricks_machine", count(&h, ARGUS_F_MACHINE_IDENTITY_MISMATCH) == 0, EXPECT_DEFENDED,
           "pre-join TRUST_CHANGED leaves joined_sequence 0 permanently");
    h_free(&h);
}

/* DEFENDED by detection (G-10): the same ordering pre-seeds TRUSTED and the
 * later JOIN keeps it, but the pre-join TRUST_CHANGED itself is reported as
 * MACHINE_IDENTITY_MISMATCH (unknown machine). The lasting damage is the
 * bricking covered by trust_before_join_bricks_machine. */
static void t_trust_preseed_skips_observation(void)
{
    H h; h_new(&h);
    ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, 3, ARGUS_TRUST_TRUSTED); feed(&h, &e);
    size_t on_preseed = h.n;
    e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0); feed(&h, &e);
    uint32_t t = 0;
    int trusted = machine_trust(&h, 3, &t) && t == ARGUS_TRUST_TRUSTED;
    result("trust_preseed_skips_observation", on_preseed > 0 || !trusted, EXPECT_DEFENDED,
           "TRUST_CHANGED on an unknown machine is applied, and JOIN keeps it");
    h_free(&h);
}

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-8 / G-20, WEAK): with the 16-entry machine table full,
 * a quarantine for the 17th machine cannot be recorded; its later use is
 * reported only as identity mismatch + telemetry loss, never as QUARANTINED_USE. */
/* Now (57a7bea): table of 64 (tombstones included, never freed). Filled
 * exactly, the 65th JOINED is refused LOUDLY (ERR_FULL + one CRITICAL
 * TELEMETRY_LOSS), its quarantine cannot be recorded, and its later use is
 * still flagged (unknown machine -> MACHINE_IDENTITY_MISMATCH, code 7) rather
 * than passing clean. Defended = the limit is loud and the use is not silent;
 * QUARANTINED_USE itself is not possible for an unrecorded machine (WEAK,
 * documented). */
static void t_machine_table_exhaustion_hides_quarantine(void)
{
    H h; h_new(&h);
    int fill_ok = 1;
    for (uint32_t m = 1; m <= H_MACHINES; m++) {
        ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_JOINED, 100u + m, 0); feed(&h, &e);
        if (h.rc != ARGUS_OK) fill_ok = 0;
    }
    ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0); feed(&h, &e);   /* 65th */
    int loud = h.rc == ARGUS_ERR_FULL && count(&h, ARGUS_F_TELEMETRY_LOSS) == 1;
    e = machine_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, 3, ARGUS_TRUST_QUARANTINED); feed(&h, &e);
    e = use(0, 0, 7, ARGUS_OUTCOME_OK, 0); mid(e.machine_id, 3); feed(&h, &e);
    int flagged = count(&h, ARGUS_F_QUARANTINED_USE) + count(&h, ARGUS_F_MACHINE_IDENTITY_MISMATCH) > 0;
    result("machine_table_exhaustion_hides_quarantine", fill_ok && loud && flagged, EXPECT_DEFENDED,
           "machine table (64) full: overflow silent or later use unflagged");
    h_free(&h);
}

/* DEFENDED since a33c1e0 (live events only: the rule exempts SYNTHETIC and
 * CONSUMER, so this test sends flags 0); the attack as first found,
 * EXPECTED-FAIL (G-8 / G-10, OPEN): once a fabric exists (a machine has joined),
 * an event with an all-zero machine_id is unattributed and escapes detectors
 * 7 and 10 entirely; a quarantined machine only has to omit its id. */
static void t_zero_machine_id_escapes_attribution(void)
{
    H h; h_new(&h);
    ArgusEvent e = machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0); feed(&h, &e);
    e = machine_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, 3, ARGUS_TRUST_QUARANTINED); feed(&h, &e);
    e = use(0, 0, 7, ARGUS_OUTCOME_OK, 0);                 /* machine_id all zero */
    e.flags = 0;   /* ruled: the zero-machine rule exempts SYNTHETIC/CONSUMER events */
    feed(&h, &e);
    result("zero_machine_id_escapes_attribution", h.n > 0, EXPECT_DEFENDED,
           "zero machine_id means 'not attributed' and never triggers");
    h_free(&h);
}

/* ==== G-9 providers ======================================================== */

static void t_provider_rediscovery_keeps_quarantine(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_PROVIDER_DISCOVERED); dg(e.evidence_digest, 1); feed(&h, &e);
    e = ev0(ARGUS_EV_PROVIDER_QUARANTINED); dg(e.evidence_digest, 1); feed(&h, &e);
    e = ev0(ARGUS_EV_PROVIDER_DISCOVERED); dg(e.evidence_digest, 1); feed(&h, &e);
    e = ev0(ARGUS_EV_PROVIDER_USED); dg(e.evidence_digest, 1); feed(&h, &e);
    result("provider_rediscovery_keeps_quarantine", count(&h, ARGUS_F_QUARANTINED_USE) == 1, EXPECT_DEFENDED,
           "rediscovery cleared a provider quarantine");
    h_free(&h);
}

/* EXPECTED-FAIL, ABI v1 LIMIT (no provider identity continuity; G-9, WEAK): provider identity is its digest; a quarantined
 * provider that re-appears under a new digest (PROVIDER_CHANGED is
 * observation-only) is a fresh, clean provider. */
static void t_provider_substitution_escapes_quarantine(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_PROVIDER_DISCOVERED); dg(e.evidence_digest, 1); feed(&h, &e);
    e = ev0(ARGUS_EV_PROVIDER_QUARANTINED); dg(e.evidence_digest, 1); feed(&h, &e);
    e = ev0(ARGUS_EV_PROVIDER_CHANGED); dg(e.evidence_digest, 2); feed(&h, &e);
    e = ev0(ARGUS_EV_PROVIDER_DISCOVERED); dg(e.evidence_digest, 2); feed(&h, &e);
    e = ev0(ARGUS_EV_PROVIDER_USED); dg(e.evidence_digest, 2); feed(&h, &e);
    result("provider_substitution_escapes_quarantine", count(&h, ARGUS_F_QUARANTINED_USE) == 1, EXPECT_FAIL,
           "no stable provider identity in ABI v1; PROVIDER_CHANGED ignored");
    h_free(&h);
}

/* DEFENDED since a33c1e0; the attack as first found, EXPECTED-FAIL (G-9, OPEN): using a provider ARGUS never saw discovered. */
static void t_undiscovered_provider_use_unflagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_PROVIDER_USED); dg(e.evidence_digest, 9); feed(&h, &e);
    result("undiscovered_provider_use_unflagged", h.n > 0, EXPECT_DEFENDED, "detector 10 only checks quarantined providers");
    h_free(&h);
}

/* ==== G-11 / G-26 credential leases =============================================== */

static void t_lease_other_subject_flagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_CREDENTIAL_LEASE_CREATED);
    e.object_id = 11; e.principal = 7; e.resource = 0x1; feed(&h, &e);
    e = ev0(ARGUS_EV_CREDENTIAL_LEASE_USED);
    e.object_id = 11; e.principal = 9; e.resource = 0x1; feed(&h, &e);
    result("lease_other_subject_flagged", count(&h, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION) == 1, EXPECT_DEFENDED,
           "lease used by another subject not reported");
    h_free(&h);
}

/* DEFENDED since 57a7bea + a33c1e0; the attack as first found, EXPECTED-FAIL (G-26, OPEN): a second LEASE_CREATED for a live lease id
 * silently rewrites its subject and scope; the hijacker's use is then clean. */
static void t_lease_recreate_hijacks_subject(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_CREDENTIAL_LEASE_CREATED);
    e.object_id = 11; e.principal = 7; e.resource = 0x1; feed(&h, &e);
    e = ev0(ARGUS_EV_CREDENTIAL_LEASE_CREATED);
    e.object_id = 11; e.principal = 9; e.resource = UINT64_MAX; feed(&h, &e);
    size_t on_recreate = h.n;
    e = ev0(ARGUS_EV_CREDENTIAL_LEASE_USED);
    e.object_id = 11; e.principal = 9; e.resource = 0xFF; feed(&h, &e);
    result("lease_recreate_hijacks_subject", on_recreate > 0 || count(&h, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION) > 0, EXPECT_DEFENDED,
           "apply_lease overwrites subject/scope of a LIVE lease");
    h_free(&h);
}

/* Lease table (57a7bea): 256 entries, lease ids never reused, so the table
 * only grows. Filled exactly, the next LEASE_CREATED must be refused loudly
 * (ERR_FULL + one CRITICAL TELEMETRY_LOSS), never dropped silently. */
static void t_lease_table_exhaustion(void)
{
    H h; h_new(&h);
    int fill_ok = 1;
    for (uint32_t l = 0; l < H_LEASES; l++) {
        ArgusEvent e = ev0(ARGUS_EV_CREDENTIAL_LEASE_CREATED);
        e.object_id = 1000u + l; e.principal = 7; e.resource = 0x1; feed(&h, &e);
        if (h.rc != ARGUS_OK || h.n != 0) fill_ok = 0;
    }
    ArgusEvent e = ev0(ARGUS_EV_CREDENTIAL_LEASE_CREATED);
    e.object_id = 1000u + H_LEASES; e.principal = 7; e.resource = 0x1; feed(&h, &e);
    int loud = h.rc == ARGUS_ERR_FULL && count(&h, ARGUS_F_TELEMETRY_LOSS) == 1;
    result("lease_table_exhaustion", fill_ok && loud, EXPECT_DEFENDED,
           "lease table (256) overflow not loud");
    h_free(&h);
}

/* ==== G-15 World provenance ================================================ */

static ArgusEvent world(uint64_t gen, uint32_t d)
{
    ArgusEvent e = ev0(ARGUS_EV_WORLD_COMMITTED);
    e.world_generation = gen;
    dg(e.evidence_digest, d);
    return e;
}

static void t_world_skip_flagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = world(1, 1); feed(&h, &e);
    e = world(3, 3); feed(&h, &e);                        /* skip: flagged, not adopted (57a7bea) */
    size_t skip = count(&h, ARGUS_F_WORLD_PROVENANCE_INCONSISTENT);
    h_free(&h);
    /* Rollback case (ruled): World 1, 2, then 1 again. Since a skip is no
     * longer adopted, the old case (1, 3, 2) made 2 the legitimate next
     * commit; this one really goes below the shadow. */
    h_new(&h);
    e = world(1, 1); feed(&h, &e);
    e = world(2, 2); feed(&h, &e);
    size_t clean = h.n;
    e = world(1, 1); feed(&h, &e);                        /* rollback below the shadow */
    size_t rollback = count(&h, ARGUS_F_WORLD_PROVENANCE_INCONSISTENT);
    result("world_skip_flagged", skip == 1 && clean == 0 && rollback == 1, EXPECT_DEFENDED,
           "skip or rollback not reported");
    h_free(&h);
}

static void t_world_same_generation_conflict_flagged(void)
{
    H h; h_new(&h);
    ArgusEvent e = world(1, 1); feed(&h, &e);
    e = world(1, 2); feed(&h, &e);
    result("world_same_generation_conflict_flagged", count(&h, ARGUS_F_WORLD_PROVENANCE_INCONSISTENT) == 1, EXPECT_DEFENDED,
           "two digests for one generation not reported");
    h_free(&h);
}

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-15, OPEN): an inconsistent (skipping) commit is reported
 * but still adopted by the shadow; the legitimate next commit is then the one
 * flagged, and a commit at UINT64_MAX freezes World tracking permanently. */
static void t_world_inconsistent_commit_adopted(void)
{
    H h; h_new(&h);
    ArgusEvent e = world(1, 1); feed(&h, &e);
    e = world(UINT64_MAX, 99); feed(&h, &e);
    e = world(2, 2); feed(&h, &e);
    int legit_flagged = count(&h, ARGUS_F_WORLD_PROVENANCE_INCONSISTENT) > 0;
    ArgusWorldShadow w;
    int frozen = argus_core_ops()->world(argus_core_view(h.c), &w) == ARGUS_OK && w.generation == UINT64_MAX;
    result("world_inconsistent_commit_adopted", !legit_flagged && !frozen, EXPECT_DEFENDED,
           "apply keeps any higher generation even when detector 9 fired");
    h_free(&h);
}

/* DEFENDED since 57a7bea (re-scoped, see below); the attack as first found, EXPECTED-FAIL (G-15, WEAK): ADR 0017 row 9 says a commit that "repeated a
 * generation" is a finding; the detector treats same-generation same-digest
 * as an idempotent replay. */
/* RULED (integrator round 2): a repeat with the same generation AND the same
 * digest is idempotent and silent (argus_core.c step 2). Re-scoped: the repeat
 * must be silent, and a repeat of the current generation with a DIFFERENT
 * digest must be code 9. ADR 0017 row 9 ("repeated a generation") must be
 * amended to say "repeated a generation with a different digest". */
static void t_world_repeat_silent(void)
{
    H h; h_new(&h);
    ArgusEvent e = world(1, 1); feed(&h, &e);
    e = world(1, 1); feed(&h, &e);
    size_t on_repeat = h.n;
    e = world(1, 7); feed(&h, &e);
    result("world_repeat_silent",
           on_repeat == 0 && count(&h, ARGUS_F_WORLD_PROVENANCE_INCONSISTENT) == 1, EXPECT_DEFENDED,
           "identical repeat not silent, or repeat with a different digest not code 9");
    h_free(&h);
}

/* ==== G-25 artifacts ======================================================= */

static void t_artifact_rejection_sticky(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_ARTIFACT_REJECTED); dg(e.evidence_digest, 4); e.outcome = ARGUS_OUTCOME_DENIED; feed(&h, &e);
    e = ev0(ARGUS_EV_ARTIFACT_ADMITTED); dg(e.evidence_digest, 4); feed(&h, &e);
    e = ev0(ARGUS_EV_ARTIFACT_ACTIVATED); dg(e.evidence_digest, 4); feed(&h, &e);
    result("artifact_rejection_sticky", count(&h, ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED) == 1, EXPECT_DEFENDED,
           "a later ADMITTED un-rejected an artifact");
    h_free(&h);
}

/* ==== G-14 policy digest / integrity reports =============================== */

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-14, OPEN): POLICY_CHANGED from any sender silently
 * replaces the expected policy digest; no detector reads policy_digest. */
static void t_policy_digest_overwrite_silent(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_POLICY_CHANGED); dg(e.evidence_digest, 1); feed(&h, &e);
    e = ev0(ARGUS_EV_POLICY_CHANGED); e.class_ = ARGUS_CLASS_INFORMATIONAL; dg(e.evidence_digest, 2); feed(&h, &e);
    result("policy_digest_overwrite_silent", h.n > 0, EXPECT_DEFENDED, "no policy invariant exists in ARGUS-0");
    h_free(&h);
}

/* DEFENDED since a33c1e0; the attack as first found, EXPECTED-FAIL (G-14, OPEN): a producer's INTEGRITY_VIOLATION report
 * (kind 60) produces no finding at all. */
static void t_integrity_violation_report_ignored(void)
{
    H h; h_new(&h);
    ArgusEvent e = ev0(ARGUS_EV_INTEGRITY_VIOLATION); e.outcome = ARGUS_OUTCOME_ERROR; feed(&h, &e);
    result("integrity_violation_report_ignored", h.n > 0, EXPECT_DEFENDED, "no detector handles INTEGRITY_VIOLATION");
    h_free(&h);
}

/* ==== G-13 incident table poisoning ======================================== */

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-13, OPEN): 64 junk (principal, code) pairs filled the old
 * incident table; a real CRITICAL incident afterwards is still delivered as
 * a finding but does not change health.incidents_open, and the untracked
 * count is not exposed by argus_core_health. */
static void t_incident_table_poisoning(void)
{
    H h; h_new(&h);
    for (uint32_t p = 0; p < H_INCIDENTS + 6u; p++) {
        ArgusEvent e = ev0(ARGUS_EV_SIGNATURE_FAILURE);
        e.outcome = ARGUS_OUTCOME_ERROR;
        e.principal = 1000u + p;
        feed(&h, &e);
    }
    ArgusCoreHealth before, after;
    argus_core_health(h.c, &before);
    ArgusEvent e = grant(5, 1, 7, R_READ); feed(&h, &e);
    e = revoke(5, 1); feed(&h, &e);
    e = use(5, 1, 7, ARGUS_OUTCOME_OK, 0); feed(&h, &e);
    int delivered = count(&h, ARGUS_F_REVOKED_CAPABILITY_USED) == 1;
    argus_core_health(h.c, &after);
    /* Table overshot (H_INCIDENTS + 6): the real incident is still delivered and
     * the saturation is visible in health (incidents_untracked, 57a7bea). */
    int visible = before.incidents_untracked > 0 &&
                  (after.incidents_open > before.incidents_open ||
                   after.incidents_untracked > before.incidents_untracked);
    result("incident_table_poisoning", delivered && visible, EXPECT_DEFENDED,
           "incidents keyed by attacker-chosen principal; saturation invisible in health");
    h_free(&h);
}

/* ==== G-6 omission: malformed input leaves no evidence ===================== */

/* DEFENDED since 57a7bea; the attack as first found, EXPECTED-FAIL (G-6, WEAK): a malformed event is only a counter; it enters
 * neither the chain nor the findings, so a flood of garbage is invisible in
 * the tamper-evident record. */
static void t_malformed_event_leaves_no_evidence(void)
{
    H h; h_new(&h);
    ArgusCoreHealth a, b;
    argus_core_health(h.c, &a);
    ArgusEvent e = use(5, 1, 7, ARGUS_OUTCOME_OK, 0);
    e.version = 9;
    feed(&h, &e);
    argus_core_health(h.c, &b);
    int counted = h.rc == ARGUS_ERR_MALFORMED && b.events_rejected == a.events_rejected + 1;
    int evidenced = memcmp(a.chain, b.chain, ARGUS_DIGEST_LEN) != 0 || h.n > 0;
    result("malformed_event_leaves_no_evidence", counted && evidenced, EXPECT_DEFENDED,
           "MALFORMED is counted but not chained and raises no finding");
    h_free(&h);
}

/* ==== G-7 / G-16 / G-18 / G-19: ring saturation, liveness =================== */

typedef struct {
    void *mem;
    ArgusRing *r;
} R;

static void r_new(R *r, uint32_t cap)
{
    size_t fp = argus_ring_footprint(cap);
    r->mem = alloc64(fp);
    if (argus_ring_init(&r->r, r->mem, fp, cap) != ARGUS_OK) {
        fprintf(stderr, "argus_ring_init failed\n");
        exit(2);
    }
}

static ArgusEvent cls_ev(uint16_t kind, uint8_t cls, uint64_t seq)
{
    ArgusEvent e = ev0(kind);
    e.class_ = cls;
    e.sequence = seq;
    return e;
}

static void t_info_flood_cannot_starve_security(void)
{
    R r; r_new(&r, 64);
    uint64_t s = 0;
    int info_refused = 0;
    for (int i = 0; i < 200; i++) {
        /* ruled: no v1 kind has an INFORMATIONAL floor -> non-v1 kind */
        ArgusEvent e = cls_ev(K_NON_V1, ARGUS_CLASS_INFORMATIONAL, ++s);
        if (argus_ring_push(r.r, &e) == ARGUS_ERR_FULL)
            info_refused++;
    }
    /* a SECURITY-floor kind at SECURITY (REVOKED is CRITICAL-floor since 58d5a99) */
    ArgusEvent sec = cls_ev(ARGUS_EV_CAPABILITY_GRANTED, ARGUS_CLASS_SECURITY, ++s);
    ArgusEvent crit = cls_ev(ARGUS_EV_FORGED_CAPABILITY, ARGUS_CLASS_CRITICAL, ++s);
    int ok = info_refused > 0 && argus_ring_push(r.r, &sec) == ARGUS_OK && argus_ring_push(r.r, &crit) == ARGUS_OK;
    result("info_flood_cannot_starve_security", ok, EXPECT_DEFENDED, "INFORMATIONAL flood consumed SECURITY/CRITICAL headroom");
    free(r.mem);
}

static void t_critical_overflow_accounting(void)
{
    R r; r_new(&r, 16);
    uint64_t s = 0;
    int full = 0;
    for (int i = 0; i < 17; i++) {
        ArgusEvent e = cls_ev(ARGUS_EV_FORGED_CAPABILITY, ARGUS_CLASS_CRITICAL, ++s);
        if (argus_ring_push(r.r, &e) == ARGUS_ERR_FULL)
            full++;
    }
    ArgusRingStats st;
    argus_ring_stats(r.r, &st);
    ArgusEvent d[8];
    uint64_t ns = 1;
    size_t nd = argus_ring_drain_drops(r.r, d, 4, &ns);
    size_t nd2 = argus_ring_drain_drops(r.r, d + 4, 4, &ns);
    int ok = full == 1 && st.pushed == 16 && st.critical_overflow == 1 && st.refused[ARGUS_CLASS_CRITICAL] == 0 &&
             nd == 1 && nd2 == 0 && d[0].kind == ARGUS_EV_TELEMETRY_DROPPED && d[0].class_ == ARGUS_CLASS_CRITICAL &&
             d[0].object_id == ARGUS_CLASS_CRITICAL && d[0].resource == 1 && (d[0].flags & ARGUS_FLAG_CONSUMER) &&
             argus_event_validate(&d[0]) == ARGUS_OK;
    /* and the core turns it into exactly one CRITICAL loss finding */
    H h; h_new(&h);
    if (nd == 1)
        feed(&h, &d[0]);
    ok = ok && count(&h, ARGUS_F_TELEMETRY_LOSS) == 1 && h.f[0].severity == ARGUS_SEV_CRITICAL;
    result("critical_overflow_accounting", ok, EXPECT_DEFENDED, "CRITICAL overflow not counted/drained/reported exactly once");
    h_free(&h);
    free(r.mem);
}

static void t_drain_partial_preserves_pending(void)
{
    R r; r_new(&r, 16);
    uint64_t s = 0;
    uint64_t info_ref = 0, audit_ref = 0;
    /* ruled: INFORMATIONAL/AUDIT flood uses the non-v1 kind (no v1 kind has an
     * INFORMATIONAL floor; PROVIDER_CHANGED is SECURITY-floor since 58d5a99) */
    for (int i = 0; i < 20; i++) {                        /* INFO limit 8 of 16 */
        ArgusEvent e = cls_ev(K_NON_V1, ARGUS_CLASS_INFORMATIONAL, ++s);
        if (argus_ring_push(r.r, &e) == ARGUS_ERR_FULL) info_ref++;
    }
    for (int i = 0; i < 10; i++) {                        /* AUDIT limit 12 of 16 */
        ArgusEvent e = cls_ev(K_NON_V1, ARGUS_CLASS_AUDIT, ++s);
        if (argus_ring_push(r.r, &e) == ARGUS_ERR_FULL) audit_ref++;
    }
    ArgusEvent d[4];
    uint64_t ns = 0;
    size_t a = argus_ring_drain_drops(r.r, d, 1, &ns);
    size_t b = argus_ring_drain_drops(r.r, d + 1, 3, &ns);
    int ok = a == 1 && b == 1 && d[0].object_id == ARGUS_CLASS_AUDIT && d[0].resource == audit_ref &&
             d[1].object_id == ARGUS_CLASS_INFORMATIONAL && d[1].resource == info_ref &&
             d[0].sequence == 1 && d[1].sequence == 2 && info_ref > 0 && audit_ref > 0;
    result("drain_partial_preserves_pending", ok, EXPECT_DEFENDED, "drain with small max lost or merged pending counts");
    free(r.mem);
}

static void t_attempt_conservation(void)
{
    R r; r_new(&r, 32);
    uint64_t s = 0, attempts = 0;
    uint32_t x = 12345u;
    for (int i = 0; i < 500; i++) {
        x = x * 1103515245u + 12345u;
        uint8_t cls = (uint8_t)(1u + ((x >> 16) & 3u));
        ArgusEvent e = cls_ev(ARGUS_EV_CAPABILITY_USED, cls, ++s);
        (void)argus_ring_push(r.r, &e);
        attempts++;
        if ((x >> 8) % 7u == 0) {                         /* occasional consumer */
            ArgusEvent o;
            (void)argus_ring_pop(r.r, &o);
        }
    }
    ArgusRingStats st;
    argus_ring_stats(r.r, &st);
    uint64_t refused = 0;
    for (unsigned c = 0; c <= ARGUS_CLASS_MAX; c++) refused += st.refused[c];
    result("attempt_conservation", attempts == st.pushed + refused + st.critical_overflow, EXPECT_DEFENDED,
           "attempts != accepted + refused + critical_overflow");
    free(r.mem);
}

/* DEFENDED since 58d5a99; the attack as first found, EXPECTED-FAIL (G-6 / G-7, OPEN): class is chosen by the producer and not bound
 * to kind. A revocation labelled INFORMATIONAL is refused first, reported as
 * an INFORMATIONAL drop, and the core raises no TELEMETRY_LOSS: a silent gap. */
static void t_security_event_lost_as_informational(void)
{
    R r; r_new(&r, 16);
    uint64_t s = 0;
    for (int i = 0; i < 8; i++) {
        ArgusEvent e = cls_ev(K_NON_V1, ARGUS_CLASS_INFORMATIONAL, ++s);
        (void)argus_ring_push(r.r, &e);
    }
    ArgusEvent rev = cls_ev(ARGUS_EV_CAPABILITY_REVOKED, ARGUS_CLASS_INFORMATIONAL, ++s);
    rev.cap_id = 5; rev.cap_generation = 1;
    int rejected_by_validate = argus_event_validate(&rev) != ARGUS_OK;
    int refused = argus_ring_push(r.r, &rev) == ARGUS_ERR_FULL;
    ArgusEvent d[4];
    uint64_t ns = 1;
    size_t nd = argus_ring_drain_drops(r.r, d, 4, &ns);
    H h; h_new(&h);
    size_t loss = 0;
    for (size_t i = 0; i < nd; i++) {
        feed(&h, &d[i]);
        loss += count(&h, ARGUS_F_TELEMETRY_LOSS);
    }
    result("security_event_lost_as_informational", rejected_by_validate || (refused && loss > 0), EXPECT_DEFENDED,
           "no kind->minimum-class binding; INFORMATIONAL drops never raise TELEMETRY_LOSS");
    h_free(&h);
    free(r.mem);
}

/* N/A-v1, documented limitation (ruled, integrator round 2): the mirror image
 * of G-6/G-7. Low-value events self-labelled CRITICAL fill 100% of the ring and
 * a real SECURITY event is refused. Producers sit inside the trusted boundary
 * in v1 and may STRENGTHEN class (argus_event_min_class is a floor, not a
 * ceiling), so this is accepted by design. Kept as a test so the behavior is
 * visible; exempt from the exit code. */
static void t_critical_self_label_starves_security(void)
{
    R r; r_new(&r, 16);
    uint64_t s = 0;
    ArgusEvent junk = cls_ev(ARGUS_EV_PROVIDER_CHANGED, ARGUS_CLASS_CRITICAL, 1);
    int rejected_by_validate = argus_event_validate(&junk) != ARGUS_OK;
    for (int i = 0; i < 16; i++) {
        ArgusEvent e = cls_ev(ARGUS_EV_PROVIDER_CHANGED, ARGUS_CLASS_CRITICAL, ++s);
        (void)argus_ring_push(r.r, &e);
    }
    ArgusEvent rev = cls_ev(ARGUS_EV_CAPABILITY_GRANTED, ARGUS_CLASS_SECURITY, ++s);  /* SECURITY-floor kind */
    int accepted = argus_ring_push(r.r, &rev) == ARGUS_OK;
    result("critical_self_label_starves_security", rejected_by_validate || accepted, NA_V1,
           "any kind may claim CRITICAL and use the full ring");
    free(r.mem);
}

/* ARGUS dead / consumer never runs: the producer is never blocked. */
static void t_push_never_blocks_without_consumer(void)
{
    R r; r_new(&r, 16);
    uint64_t s = 0;
    int ok_n = 0, full_n = 0, other = 0;
    for (int i = 0; i < 100000; i++) {
        ArgusEvent e = cls_ev(ARGUS_EV_CAPABILITY_USED, ARGUS_CLASS_CRITICAL, ++s);
        int rc = argus_ring_push(r.r, &e);
        if (rc == ARGUS_OK) ok_n++;
        else if (rc == ARGUS_ERR_FULL) full_n++;
        else other++;
    }
    ArgusRingStats st;
    argus_ring_stats(r.r, &st);
    result("push_never_blocks_without_consumer",
           ok_n == 16 && other == 0 && full_n == 100000 - 16 && st.depth == 16 &&
               st.critical_overflow == (uint64_t)full_n, EXPECT_DEFENDED,
           "push did not return FULL immediately with a dead consumer");
    free(r.mem);
}

/* No containment storm: a loss report yields one finding and no new events. */
static void t_drop_report_does_not_recurse(void)
{
    R r; r_new(&r, 16);
    H h; h_new(&h);
    ArgusEvent d = ev0(ARGUS_EV_TELEMETRY_DROPPED);
    d.class_ = ARGUS_CLASS_CRITICAL; d.flags = ARGUS_FLAG_CONSUMER; d.outcome = ARGUS_OUTCOME_ERROR;
    d.object_id = ARGUS_CLASS_SECURITY; d.resource = 3;
    feed(&h, &d);
    size_t n1 = h.n;
    ArgusEvent out[4];
    uint64_t ns = 1;
    size_t nd = argus_ring_drain_drops(r.r, out, 4, &ns);
    ArgusRingStats st;
    argus_ring_stats(r.r, &st);
    result("drop_report_does_not_recurse", n1 == 1 && nd == 0 && st.pushed == 0, EXPECT_DEFENDED,
           "a telemetry-loss report produced further events");
    h_free(&h);
    free(r.mem);
}

/* ==== G-22 determinism ===================================================== */

static size_t build_stream(ArgusEvent *s)
{
    size_t n = 0;
    uint64_t q = 0;
#define PUSH(e) do { s[n] = (e); s[n].sequence = ++q; n++; } while (0)
    PUSH(machine_ev(ARGUS_EV_MACHINE_JOINED, 3, 0));
    PUSH(grant(5, 1, 7, R_READ));
    PUSH(revoke(5, 1));
    PUSH(use(5, 1, 7, ARGUS_OUTCOME_OK, 0));                         /* revoked use */
    PUSH(use(6, 1, 7, ARGUS_OUTCOME_OK, AUTH_ERR_STALE_GEN));         /* forged + stale */
    PUSH(world(1, 1));
    PUSH(world(4, 4));                                               /* skip */
    { ArgusEvent e = ev0(ARGUS_EV_SIGNATURE_FAILURE); e.principal = 8; PUSH(e); }
    { ArgusEvent e = ev0(ARGUS_EV_CREDENTIAL_LEASE_CREATED); e.object_id = 11; e.principal = 7; e.resource = 1; PUSH(e); }
    { ArgusEvent e = ev0(ARGUS_EV_CREDENTIAL_LEASE_USED); e.object_id = 11; e.principal = 9; e.resource = 1; PUSH(e); }
    { ArgusEvent e = use(0, 0, 7, ARGUS_OUTCOME_OK, 0); mid(e.machine_id, 77); PUSH(e); }  /* unknown machine */
    { ArgusEvent e = ev0(ARGUS_EV_TELEMETRY_DROPPED); e.flags = ARGUS_FLAG_CONSUMER; e.object_id = 1; e.resource = 2; PUSH(e); }
#undef PUSH
    s[n] = s[1];                                                     /* exact replay */
    n++;
    return n;
}

typedef struct {
    uint8_t state[ARGUS_DIGEST_LEN];
    ArgusCoreHealth health;
    uint8_t fchain[ARGUS_DIGEST_LEN];   /* chain over the digest of every finding copied out */
} Run;

static void run_stream(const ArgusEvent *s, size_t n, size_t cap, Run *out)
{
    H h; h_new(&h);
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < n; i++) {
        ArgusEvent e = s[i];
        h.n = 0;
        (void)argus_core_ingest(h.c, &e, cap ? h.f : NULL, cap, &h.n);
        for (size_t k = 0; k < h.n; k++) {
            uint8_t fd[ARGUS_DIGEST_LEN];
            argus_finding_digest(&h.f[k], fd);
            ArgusEvent carrier = ev0(ARGUS_EV_NONE);
            memcpy(carrier.evidence_digest, fd, ARGUS_DIGEST_LEN);
            argus_chain_extend(out->fchain, &carrier);
        }
    }
    argus_core_state_digest(h.c, out->state);
    argus_core_health(h.c, &out->health);
    h_free(&h);
}

static void t_same_stream_same_output(void)
{
    ArgusEvent s[32];
    size_t n = build_stream(s);
    Run a, b;
    run_stream(s, n, H_FBUF, &a);
    run_stream(s, n, H_FBUF, &b);
    int ok = memcmp(a.state, b.state, ARGUS_DIGEST_LEN) == 0 && memcmp(a.fchain, b.fchain, ARGUS_DIGEST_LEN) == 0 &&
             memcmp(a.health.chain, b.health.chain, ARGUS_DIGEST_LEN) == 0 && a.health.findings_emitted > 5;
    result("same_stream_same_output", ok, EXPECT_DEFENDED, "identical streams gave different findings/state");
}

/* The caller's buffer size may truncate findings but never changes state. */
static void t_buffer_size_does_not_change_state(void)
{
    ArgusEvent s[32];
    size_t n = build_stream(s);
    Run a, b;
    run_stream(s, n, 0, &a);
    run_stream(s, n, H_FBUF, &b);
    int ok = memcmp(a.state, b.state, ARGUS_DIGEST_LEN) == 0 &&
             memcmp(a.health.chain, b.health.chain, ARGUS_DIGEST_LEN) == 0 &&
             a.health.findings_emitted == b.health.findings_emitted && a.health.incidents_open == b.health.incidents_open;
    result("buffer_size_does_not_change_state", ok, EXPECT_DEFENDED, "state depends on the caller's findings buffer size");
}

/* The core holds no pointers: a byte copy is a valid, equivalent snapshot. */
static void t_snapshot_copy_equivalent(void)
{
    ArgusEvent s[32];
    size_t n = build_stream(s);
    H a; h_new(&a);
    for (size_t i = 0; i < n / 2; i++) { ArgusEvent e = s[i]; feed(&a, &e); }
    size_t fp = argus_core_footprint();
    void *copy = alloc64(fp);
    memcpy(copy, a.mem, fp);
    ArgusCore *b = (ArgusCore *)copy;
    ArgusFinding fb[H_FBUF];
    int same = 1;
    for (size_t i = n / 2; i < n; i++) {
        ArgusEvent e1 = s[i], e2 = s[i];
        size_t nb = 0;
        feed(&a, &e1);
        (void)argus_core_ingest(b, &e2, fb, H_FBUF, &nb);
        if (nb != a.n || (nb && memcmp(fb, a.f, nb * sizeof fb[0]) != 0))
            same = 0;
    }
    uint8_t da[ARGUS_DIGEST_LEN], db[ARGUS_DIGEST_LEN];
    argus_core_state_digest(a.c, da);
    argus_core_state_digest(b, db);
    result("snapshot_copy_equivalent", same && memcmp(da, db, ARGUS_DIGEST_LEN) == 0, EXPECT_DEFENDED,
           "a byte copy of the core diverged from the original");
    free(copy);
    h_free(&a);
}

static void t_uninitialized_core_rejected(void)
{
    size_t fp = argus_core_footprint();
    void *mem = alloc64(fp);
    memset(mem, 0xAB, fp);
    ArgusEvent e = use(5, 1, 7, ARGUS_OUTCOME_OK, 0);
    e.sequence = 1;
    ArgusFinding f[4];
    size_t n = 99;
    int rc = argus_core_ingest((ArgusCore *)mem, &e, f, 4, &n);
    uint8_t d[ARGUS_DIGEST_LEN], z[ARGUS_DIGEST_LEN];
    memset(z, 0, sizeof z);
    argus_core_state_digest((ArgusCore *)mem, d);
    result("uninitialized_core_rejected", rc == ARGUS_ERR_ARG && memcmp(d, z, sizeof z) == 0, EXPECT_DEFENDED,
           "garbage memory treated as a live core");
    free(mem);
}

/* argus_detect_run with a small buffer returns a prefix of the full result. */
static void t_detect_run_prefix_under_small_cap(void)
{
    H h; h_new(&h);
    ArgusEvent e = use(6, 1, 7, ARGUS_OUTCOME_OK, AUTH_ERR_STALE_GEN);  /* unseen + stale code: 2 findings */
    e.sequence = 1;
    ArgusFinding full[16], small[1];
    size_t nf = 0, ns = 0;
    int rf = argus_detect_run(argus_core_ops(), argus_core_view(h.c), &e, full, 16, &nf);
    int rs = argus_detect_run(argus_core_ops(), argus_core_view(h.c), &e, small, 1, &ns);
    int ok = rf == ARGUS_OK && nf >= 2 && rs == ARGUS_ERR_OVERFLOW && ns == 1 &&
             memcmp(&full[0], &small[0], sizeof small[0]) == 0;
    result("detect_run_prefix_under_small_cap", ok, EXPECT_DEFENDED, "truncated detector output is not a prefix of the full output");
    h_free(&h);
}

/* ==== G-23 state digest collisions ======================================== */

static void digest_of(const ArgusEvent *s, size_t n, uint8_t out[ARGUS_DIGEST_LEN])
{
    H h; h_new(&h);
    for (size_t i = 0; i < n; i++) { ArgusEvent e = s[i]; feed(&h, &e); }
    argus_core_state_digest(h.c, out);
    h_free(&h);
}

/* Each variant changes exactly one shadow field; every digest must differ. */
static void t_state_digest_sensitive_to_every_table(void)
{
    enum { NV = 9 };
    uint8_t d[NV][ARGUS_DIGEST_LEN];
    for (int v = 0; v < NV; v++) {
        ArgusEvent s[8];
        size_t n = 0;
        s[n] = grant(5, 1, 7, R_READ); s[n].resource = v == 1 ? 0x20 : 0x10; s[n].sequence = 1; n++;
        s[n] = machine_ev(ARGUS_EV_MACHINE_JOINED, v == 2 ? 4 : 3, 0); s[n].sequence = 2; n++;
        s[n] = ev0(ARGUS_EV_CREDENTIAL_LEASE_CREATED); s[n].object_id = 11; s[n].principal = 7;
        s[n].resource = v == 3 ? 3 : 1; s[n].sequence = 3; n++;
        s[n] = world(1, v == 4 ? 2 : 1); s[n].sequence = 4; n++;
        s[n] = ev0(ARGUS_EV_POLICY_CHANGED); dg(s[n].evidence_digest, v == 5 ? 9 : 8); s[n].sequence = 5; n++;
        s[n] = ev0(ARGUS_EV_PROVIDER_DISCOVERED); dg(s[n].evidence_digest, v == 6 ? 31 : 30); s[n].sequence = 6; n++;
        s[n] = ev0(ARGUS_EV_ARTIFACT_ADMITTED); dg(s[n].evidence_digest, 40);
        if (v == 7) { s[n].kind = ARGUS_EV_ARTIFACT_REJECTED; s[n].class_ = ARGUS_CLASS_CRITICAL; }
        s[n].sequence = 7; n++;
        s[n] = ev0(ARGUS_EV_SIGNATURE_FAILURE); s[n].principal = v == 8 ? 12 : 11; s[n].sequence = 8; n++;
        digest_of(s, n, d[v]);
    }
    int distinct = 1;
    for (int i = 0; i < NV; i++)
        for (int j = i + 1; j < NV; j++)
            if (memcmp(d[i], d[j], ARGUS_DIGEST_LEN) == 0)
                distinct = 0;
    result("state_digest_sensitive_to_every_table", distinct, EXPECT_DEFENDED, "two different shadow states hashed equal");
}

/* The event chain and the state digest share one hash construction. They are
 * kept apart today only because the state digest's first record has sequence
 * 0, which no ingested event may have (see G-23). */
static void t_state_digest_domain_separated(void)
{
    H h; h_new(&h);
    uint8_t sd[ARGUS_DIGEST_LEN];
    ArgusCoreHealth hl;
    argus_core_state_digest(h.c, sd);
    argus_core_health(h.c, &hl);
    int differ_empty = memcmp(sd, hl.chain, ARGUS_DIGEST_LEN) != 0;
    ArgusEvent e = grant(5, 1, 7, R_READ); feed(&h, &e);
    argus_core_state_digest(h.c, sd);
    argus_core_health(h.c, &hl);
    int differ_one = memcmp(sd, hl.chain, ARGUS_DIGEST_LEN) != 0;
    ArgusEvent seq0 = e; seq0.sequence = 0;
    int seq0_rejected = argus_event_validate(&seq0) != ARGUS_OK;
    result("state_digest_domain_separated", differ_empty && differ_one && seq0_rejected, EXPECT_DEFENDED,
           "state digest can coincide with the event chain");
    h_free(&h);
}

/* ==== G-12 secret-sized slots ============================================== */

/* The only 32-byte fields in an event are machine_id and evidence_digest, at
 * the documented offsets; no other field can carry a 32-byte office secret. */
static void t_event_has_only_two_32byte_slots(void)
{
    int ok = sizeof(ArgusEvent) == ARGUS_EVENT_SIZE &&
             offsetof(ArgusEvent, machine_id) == 64 && offsetof(ArgusEvent, evidence_digest) == 96 &&
             sizeof(((ArgusEvent *)0)->machine_id) == 32 && sizeof(((ArgusEvent *)0)->evidence_digest) == 32 &&
             offsetof(ArgusEvent, resource) + sizeof(uint64_t) == 64;
    result("event_has_only_two_32byte_slots", ok, EXPECT_DEFENDED, "event layout grew another secret-sized field");
}

int main(void)
{
    /* capability replay / generations / forgery */
    t_grant_replay_revives_revoked();
    t_exact_replay_still_applied();
    t_future_generation_use_unflagged();
    t_stale_generation_use_flagged();
    t_revoked_use_flagged();
    t_revoked_use_denied_is_quiet();
    t_use_by_other_subject_unflagged();
    t_revoke_gen_max_poisons_slot();
    t_cap_id_out_of_range_is_critical_loss();
    t_cap_id_out_of_range_use_is_forged();
    /* effect class */
    t_effect_kind_mislabelled();
    t_external_effect_without_right_flagged();
    t_evidence_write_with_read_only_right();
    /* confused deputy, forgery */
    t_reported_forgery_names_arbitrary_victim();
    t_forged_telemetry_dropped();
    t_consumer_flag_accepted_from_wire();
    t_unattributed_grant_masks_forged_use();
    /* sequence */
    t_sequence_replay_flagged();
    t_sequence_high_water_poison();
    t_sequence_gap_unflagged();
    t_replay_rekeyed_by_consumer_flag();
    t_replay_evades_by_rekeying_stream();
    t_producer_table_exhaustion();
    /* machines */
    t_quarantined_machine_use_flagged();
    t_quarantine_laundered_by_remove_rejoin();
    t_quarantined_machine_self_upgrades();
    t_join_declares_own_trust();
    t_trust_before_join_bricks_machine();
    t_trust_preseed_skips_observation();
    t_machine_table_exhaustion_hides_quarantine();
    t_zero_machine_id_escapes_attribution();
    /* providers, leases, world, artifacts, policy */
    t_provider_rediscovery_keeps_quarantine();
    t_provider_substitution_escapes_quarantine();
    t_undiscovered_provider_use_unflagged();
    t_lease_other_subject_flagged();
    t_lease_recreate_hijacks_subject();
    t_lease_table_exhaustion();
    t_world_skip_flagged();
    t_world_same_generation_conflict_flagged();
    t_world_inconsistent_commit_adopted();
    t_world_repeat_silent();
    t_artifact_rejection_sticky();
    t_policy_digest_overwrite_silent();
    t_integrity_violation_report_ignored();
    /* incidents, omission */
    t_incident_table_poisoning();
    t_malformed_event_leaves_no_evidence();
    /* ring: saturation, liveness, recursion */
    t_info_flood_cannot_starve_security();
    t_critical_overflow_accounting();
    t_drain_partial_preserves_pending();
    t_attempt_conservation();
    t_security_event_lost_as_informational();
    t_critical_self_label_starves_security();
    t_push_never_blocks_without_consumer();
    t_drop_report_does_not_recurse();
    /* determinism, digests, layout */
    t_same_stream_same_output();
    t_buffer_size_does_not_change_state();
    t_snapshot_copy_equivalent();
    t_uninitialized_core_rejected();
    t_detect_run_prefix_under_small_cap();
    t_state_digest_sensitive_to_every_table();
    t_state_digest_domain_separated();
    t_event_has_only_two_32byte_slots();

    printf("test_argus_hostile: %d defended, %d expected-fail (open/weak), %d N/A-v1 (documented, exempt), "
           "%d xpass, %d unexpected failures\n",
           n_pass, n_xfail, n_na, n_xpass, n_unexpected);
    return n_unexpected ? 1 : 0;
}
