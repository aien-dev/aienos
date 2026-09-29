/*
 * test_argus_detect.c -- lane E tests for the ARGUS-0 hard-invariant detectors.
 *
 * For every detector: positive cases (the violation fires, fields correct) and
 * negative cases (legal behavior, including correct authority refusals, stays
 * silent). Then the synthetic legal-day corpus (must yield zero findings) and
 * the hostile corpus (detected findings == injected list, exactly).
 * Shadow state is the in-memory stub (tests/stub_state.c), not the core.
 */
#include "../argus_abi.h"
#include "../argus_detect.h"
#include "../../capability/aienos_capability.h"
#include "stub_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;
static int pos[ARGUS_F_MAX + 1];
static int neg[ARGUS_F_MAX + 1];

#define CHECK(cond, ...)                                                   \
    do {                                                                   \
        checks++;                                                          \
        if (!(cond)) {                                                     \
            failures++;                                                    \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);           \
            fprintf(stderr, __VA_ARGS__);                                  \
            fprintf(stderr, "\n");                                         \
        }                                                                  \
    } while (0)

static StubState st;
static const ArgusStateView *V;
static const ArgusStateOps *OPS;

static uint8_t MA[ARGUS_MACHINE_ID_LEN], MQ[ARGUS_MACHINE_ID_LEN], MU[ARGUS_MACHINE_ID_LEN];
static uint8_t AL[ARGUS_DIGEST_LEN], AR[ARGUS_DIGEST_LEN], AU[ARGUS_DIGEST_LEN];
static uint8_t PL[ARGUS_DIGEST_LEN], PQ[ARGUS_DIGEST_LEN], PN[ARGUS_DIGEST_LEN];
static uint8_t WD[ARGUS_DIGEST_LEN], WX[ARGUS_DIGEST_LEN];

static void pattern(uint8_t *b, uint8_t tag)
{
    for (size_t i = 0; i < 32; i++)
        b[i] = (uint8_t)(tag + i * 7u);
}

/* Fixture:
 *  cap 1 LIVE gen 3 subject 7 rights R|W|EFFECT (granted @10)
 *  cap 2 REVOKED gen 1 subject 7 rights R|W (revoked @20)
 *  cap 3 LIVE gen 1 subject 7 rights R only (granted @30)
 *  machine MA joined TRUSTED (@5), MQ joined QUARANTINED (changed @40), MU unknown
 *  artifact AL admitted (@50), AR rejected (@51), AU unknown
 *  lease 1 LIVE subject 7 scope 0xF0 (@60), lease 2 REVOKED (@61)
 *  provider PL live (@70), PQ quarantined (@71), PN unknown
 *  world gen 5 digest WD (@80) */
static void reset(void)
{
    stub_state_init(&st);
    V = stub_state_view(&st);
    OPS = stub_state_ops();
    pattern(MA, 0x11); pattern(MQ, 0x12); pattern(MU, 0x13);
    pattern(AL, 0x21); pattern(AR, 0x22); pattern(AU, 0x23);
    pattern(PL, 0x31); pattern(PQ, 0x32); pattern(PN, 0x33);
    pattern(WD, 0x41); pattern(WX, 0x42);

    ArgusCapShadow c = {0};
    c.cap_id = 1; c.generation = 3; c.state = ARGUS_SHADOW_LIVE; c.subject = 7;
    c.rights = AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE | AIENOS_CAP_RIGHT_EFFECT;
    c.resource = 0x100; c.granted_sequence = 10;
    stub_put_cap(&st, &c);
    c.cap_id = 2; c.generation = 1; c.state = ARGUS_SHADOW_REVOKED;
    c.rights = AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE; c.granted_sequence = 11; c.revoked_sequence = 20;
    stub_put_cap(&st, &c);
    c.cap_id = 3; c.generation = 1; c.state = ARGUS_SHADOW_LIVE; c.rights = AIENOS_CAP_RIGHT_READ;
    c.granted_sequence = 30; c.revoked_sequence = 0;
    stub_put_cap(&st, &c);

    ArgusMachineShadow m = {0};
    memcpy(m.machine_id, MA, 32); m.trust = ARGUS_TRUST_TRUSTED; m.joined_sequence = 5; m.changed_sequence = 5;
    stub_put_machine(&st, &m);
    memcpy(m.machine_id, MQ, 32); m.trust = ARGUS_TRUST_QUARANTINED; m.joined_sequence = 6; m.changed_sequence = 40;
    stub_put_machine(&st, &m);

    ArgusArtifactShadow a = {0};
    memcpy(a.digest, AL, 32); a.state = ARGUS_SHADOW_LIVE; a.sequence = 50;
    stub_put_artifact(&st, &a);
    memcpy(a.digest, AR, 32); a.state = ARGUS_SHADOW_REJECTED; a.sequence = 51;
    stub_put_artifact(&st, &a);

    ArgusLeaseShadow l = {0};
    l.lease_id = 1; l.subject = 7; l.scope = 0xF0; l.state = ARGUS_SHADOW_LIVE; l.sequence = 60;
    stub_put_lease(&st, &l);
    l.lease_id = 2; l.state = ARGUS_SHADOW_REVOKED; l.sequence = 61;
    stub_put_lease(&st, &l);

    ArgusProviderShadow p = {0};
    memcpy(p.provider_id, PL, 32); p.state = ARGUS_SHADOW_LIVE; p.sequence = 70;
    stub_put_provider(&st, &p);
    memcpy(p.provider_id, PQ, 32); p.state = ARGUS_SHADOW_REVOKED; p.sequence = 71;
    stub_put_provider(&st, &p);

    stub_set_world(&st, 0, 5, WD, 80);
}

static uint64_t next_seq = 1000;

static ArgusEvent mk(uint16_t kind, uint8_t outcome, int32_t code)
{
    ArgusEvent e;
    memset(&e, 0, sizeof e);
    e.version = ARGUS_ABI_VERSION;
    e.class_ = ARGUS_CLASS_SECURITY;
    e.kind = kind;
    e.outcome = outcome;
    e.code = code;
    e.flags = ARGUS_FLAG_SYNTHETIC;
    e.cap_id = ARGUS_CAP_NONE;   /* v1.1: cap_id 0 is the office slot, "none" is CAP_NONE */
    e.sequence = ++next_seq;
    e.tick = e.sequence;
    return e;
}

static ArgusEvent use(uint16_t kind, uint8_t outcome, int32_t code, uint32_t cap_id, uint64_t gen)
{
    ArgusEvent e = mk(kind, outcome, code);
    e.cap_id = cap_id;
    e.cap_generation = gen;
    e.principal = 7;
    return e;
}

static ArgusFinding F[32];
static size_t NF;

static int run(const ArgusEvent *e)
{
    StubState before = st;
    int rc = argus_detect_run(OPS, V, e, F, 32, &NF);
    CHECK(memcmp(&before, &st, sizeof st) == 0, "detectors modified shadow state");
    return rc;
}

/* Table entry for a finding code (ids are 1..10, 14, 15; not index + 1). */
static const ArgusDetector *det_of(uint16_t id)
{
    for (size_t i = 0; i < argus_hard_detector_count; i++)
        if (argus_hard_detectors[i].id == id)
            return &argus_hard_detectors[i];
    return NULL;
}

/* Exactly one finding, with code `det`; checks the common fields. sync/contain
 * < 0 means "the detector table default". */
static void expect_only_as(uint16_t det, const ArgusEvent *e, const char *what, int sync, int contain)
{
    int rc = run(e);
    CHECK(rc == ARGUS_OK, "[%u %s] rc %d", det, what, rc);
    CHECK(NF == 1, "[%u %s] expected 1 finding, got %zu (first code %u)", det, what, NF, NF ? F[0].code : 0);
    const ArgusDetector *d = det_of(det);
    CHECK(d != NULL, "[%u %s] no detector", det, what);
    if (NF >= 1 && d != NULL) {
        const ArgusFinding *f = &F[0];
        CHECK(f->code == det, "[%u %s] code %u", det, what, f->code);
        CHECK(f->detector == det, "[%u %s] detector %u", det, what, f->detector);
        CHECK(f->confidence == ARGUS_CONF_DETERMINISTIC, "[%u %s] confidence", det, what);
        CHECK(f->sync_allowed == (sync < 0 ? d->sync_allowed : sync), "[%u %s] sync %u", det, what, f->sync_allowed);
        if (contain >= 0)
            CHECK(f->containment == contain, "[%u %s] containment %u", det, what, f->containment);
        CHECK(f->sequence == e->sequence, "[%u %s] sequence", det, what);
        CHECK(f->principal == e->principal, "[%u %s] principal", det, what);
        CHECK(f->cap_id == e->cap_id && f->cap_generation == e->cap_generation, "[%u %s] cap", det, what);
        CHECK(memcmp(f->machine_id, e->machine_id, 32) == 0, "[%u %s] machine", det, what);
        static const uint8_t zero[32];
        CHECK(memcmp(f->event_digest, zero, 32) == 0, "[%u %s] event_digest must stay zero", det, what);
    }
    pos[det]++;
}

static void expect_only(uint16_t det, const ArgusEvent *e, const char *what)
{
    expect_only_as(det, e, what, -1, -1);
}

/* Self-report without shadow corroboration (G-2): sync 0, containment NONE. */
static void expect_hearsay(uint16_t det, const ArgusEvent *e, const char *what)
{
    expect_only_as(det, e, what, 0, ARGUS_CONTAIN_NONE);
}

static void expect_none(uint16_t det, const ArgusEvent *e, const char *what)
{
    int rc = run(e);
    CHECK(rc == ARGUS_OK, "[%u %s] rc %d", det, what, rc);
    CHECK(NF == 0, "[%u %s] expected no finding, got %zu (first code %u)", det, what, NF, NF ? F[0].code : 0);
    neg[det]++;
}

/* Detect on pre-state, then apply: the core's order. */
static size_t step(const ArgusEvent *e)
{
    run(e);
    size_t n = NF;
    stub_state_apply(&st, e);
    return n;
}

/* ---- per-detector ---------------------------------------------------------- */

static void t_forged(void)
{
    ArgusEvent e;
    reset();
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 99, 1);
    expect_only(1, &e, "unseen ref used OK");
    CHECK(F[0].severity == ARGUS_SEV_CRITICAL && F[0].containment == ARGUS_CONTAIN_FREEZE_PRINCIPAL, "d1 sev/contain");
    e = mk(ARGUS_EV_FORGED_CAPABILITY, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_BOUNDS);
    expect_hearsay(1, &e, "producer reports forgery, no ref");
    e = use(ARGUS_EV_FORGED_CAPABILITY, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_BOUNDS, 99, 1);
    e.principal = 1;
    expect_hearsay(1, &e, "forgery report names unseen slot + victim (G-2)");
    e = use(ARGUS_EV_FORGED_CAPABILITY, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_BOUNDS, 1, 9);
    e.principal = 8;
    expect_hearsay(1, &e, "forgery report, principal is not the slot's subject");
    e = use(ARGUS_EV_FORGED_CAPABILITY, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_BOUNDS, 1, 3);
    expect_hearsay(1, &e, "forgery report at the minted generation");
    e = use(ARGUS_EV_FORGED_CAPABILITY, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_BOUNDS, 1, 9);
    expect_only_as(1, &e, "forgery report corroborated (subject's slot, unminted gen)", 1,
                   ARGUS_CONTAIN_FREEZE_PRINCIPAL);
    CHECK(F[0].prior_sequence == 10, "d1 corroborated prior = grant");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 4);
    expect_only(1, &e, "future generation used OK (G-4)");
    CHECK(F[0].prior_sequence == 10 && F[0].containment == ARGUS_CONTAIN_FREEZE_PRINCIPAL, "d1 future fields");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 2, 5);
    expect_only(1, &e, "future gen of a revoked slot: 1 only (v1.1: 3 needs gen <= shadow)");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, AIENOS_CAP_ERR_BOUNDS, 1, 3);
    expect_only(1, &e, "OK with ERR_BOUNDS");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, AIENOS_CAP_ERR_CHAIN, 1, 3);
    expect_only(1, &e, "OK with ERR_CHAIN");
    e = use(ARGUS_EV_EXTERNAL_EFFECT_COMMITTED, ARGUS_OUTCOME_OK, 0, 99, 1);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    expect_only(1, &e, "unseen ref commits effect");

    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    expect_none(1, &e, "live ref used OK");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_BOUNDS, 99, 1);
    expect_none(1, &e, "unseen ref refused by authority");
    e = use(ARGUS_EV_CAPABILITY_GRANTED, ARGUS_OUTCOME_OK, 0, 99, 1);
    e.object_id = AIENOS_CAP_RIGHT_READ;
    expect_none(1, &e, "new grant of unseen slot");
    CHECK(step(&e) == 0, "grant step");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 99, 1);
    expect_none(1, &e, "use after grant");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, ARGUS_CAP_NONE, 0);
    expect_none(1, &e, "use with no cap reference");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_STALE_GEN, 1, 4);
    expect_none(1, &e, "future generation refused");
    e = use(ARGUS_EV_CAPABILITY_GRANTED, ARGUS_OUTCOME_OK, 0, 1, 4);
    e.object_id = AIENOS_CAP_RIGHT_READ;
    expect_none(1, &e, "re-grant at a higher generation");
}

static void t_stale(void)
{
    ArgusEvent e;
    reset();
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 2);
    expect_only(2, &e, "old gen accepted");
    CHECK(F[0].prior_sequence == 10 && F[0].severity == ARGUS_SEV_HIGH &&
          F[0].containment == ARGUS_CONTAIN_REVOKE_CAPABILITY, "d2 fields");
    e = mk(ARGUS_EV_STALE_GENERATION, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_STALE_GEN);
    expect_hearsay(2, &e, "producer reports stale gen, no ref");
    e = use(ARGUS_EV_STALE_GENERATION, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_STALE_GEN, 1, 2);
    e.principal = 9;
    expect_hearsay(2, &e, "stale report names another principal");
    e = use(ARGUS_EV_STALE_GENERATION, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_STALE_GEN, 1, 2);
    expect_only_as(2, &e, "stale report corroborated", 1, ARGUS_CONTAIN_REVOKE_CAPABILITY);
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, AIENOS_CAP_ERR_STALE_GEN, 1, 3);
    expect_only(2, &e, "OK with ERR_STALE_GEN");

    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_STALE_GEN, 1, 2);
    expect_none(2, &e, "old gen refused");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    expect_none(2, &e, "current gen accepted");
    e = use(ARGUS_EV_CAPABILITY_GRANTED, ARGUS_OUTCOME_OK, 0, 1, 4);
    e.object_id = AIENOS_CAP_RIGHT_READ;
    expect_none(2, &e, "re-grant at next gen");
    CHECK(step(&e) == 0, "regrant step");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 4);
    expect_none(2, &e, "use at new gen after re-grant");
}

static void t_revoked(void)
{
    ArgusEvent e;
    reset();
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 2, 1);
    expect_only(3, &e, "revoked ref accepted");
    CHECK(F[0].prior_sequence == 20 && F[0].severity == ARGUS_SEV_CRITICAL &&
          F[0].containment == ARGUS_CONTAIN_FREEZE_PRINCIPAL, "d3 fields");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, AIENOS_CAP_ERR_REVOKED, 1, 3);
    expect_only(3, &e, "OK with ERR_REVOKED");
    /* revoke via apply, then accepted use */
    e = use(ARGUS_EV_CAPABILITY_REVOKED, ARGUS_OUTCOME_OK, 0, 3, 1);
    CHECK(step(&e) == 0, "revoke step");
    e = use(ARGUS_EV_EXTERNAL_EFFECT_REQUESTED, ARGUS_OUTCOME_OK, 0, 3, 1);
    e.effect_class = ARGUS_EFFECT_EPHEMERAL;
    run(&e);
    CHECK(NF == 2 && F[0].code == 3 && F[1].code == 8, "revoked + no effect right: 3 then 8 in id order (%zu)", NF);
    pos[3]++;

    reset();
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_REVOKED, 2, 1);
    expect_none(3, &e, "revoked ref refused");
    e = use(ARGUS_EV_CAPABILITY_REVOKED, ARGUS_OUTCOME_OK, 0, 1, 3);
    expect_none(3, &e, "revocation itself");
    e = use(ARGUS_EV_CAPABILITY_GRANTED, ARGUS_OUTCOME_OK, 0, 2, 2);
    e.object_id = AIENOS_CAP_RIGHT_READ;
    CHECK(step(&e) == 0, "regrant revoked slot");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 2, 2);
    expect_none(3, &e, "use of re-granted slot");
}

static void t_artifact(void)
{
    ArgusEvent e;
    reset();
    e = mk(ARGUS_EV_ARTIFACT_ACTIVATED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, AU, 32);
    expect_only(4, &e, "unknown digest activated");
    CHECK(F[0].prior_sequence == 0 && F[0].containment == ARGUS_CONTAIN_REJECT_ARTIFACT, "d4 fields");
    memcpy(e.evidence_digest, AR, 32);
    expect_only(4, &e, "rejected digest activated");
    CHECK(F[0].prior_sequence == 51, "d4 prior = rejection");

    memcpy(e.evidence_digest, AL, 32);
    expect_none(4, &e, "admitted digest activated");
    e = mk(ARGUS_EV_ARTIFACT_ACTIVATED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_UNAUTHORIZED);
    memcpy(e.evidence_digest, AU, 32);
    expect_none(4, &e, "unknown digest refused");
    e = mk(ARGUS_EV_ARTIFACT_ADMITTED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, AU, 32);
    expect_none(4, &e, "admission of new digest");
    CHECK(step(&e) == 0, "admit step");
    e = mk(ARGUS_EV_ARTIFACT_ACTIVATED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, AU, 32);
    expect_none(4, &e, "activation after admission");
}

static void t_signature(void)
{
    ArgusEvent e;
    reset();
    e = mk(ARGUS_EV_SIGNATURE_FAILURE, ARGUS_OUTCOME_DENIED, 0);
    expect_hearsay(5, &e, "signature failure (denied)");
    CHECK(F[0].severity == ARGUS_SEV_HIGH, "d5 severity");
    e = mk(ARGUS_EV_SIGNATURE_FAILURE, ARGUS_OUTCOME_OK, 0);
    expect_hearsay(5, &e, "signature failure (ok)");
    e = mk(ARGUS_EV_ARTIFACT_ADMITTED, ARGUS_OUTCOME_OK, AIENOS_CAP_ERR_RIGHTS);
    memcpy(e.evidence_digest, AU, 32);
    expect_only_as(5, &e, "admitted despite error code", 1, ARGUS_CONTAIN_REJECT_ARTIFACT);
    e = mk(ARGUS_EV_INTEGRITY_VIOLATION, ARGUS_OUTCOME_ERROR, 0);
    expect_hearsay(5, &e, "integrity violation reported (G-14)");
    e = mk(ARGUS_EV_INTEGRITY_VIOLATION, ARGUS_OUTCOME_DENIED, 0);
    expect_hearsay(5, &e, "integrity violation reported, denied");
    /* stored policy / runtime digests (G-14) */
    memcpy(st.policy, WD, 32);
    memcpy(st.runtime, AL, 32);
    e = mk(ARGUS_EV_POLICY_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, WX, 32);
    expect_hearsay(5, &e, "policy digest replaced");
    e = mk(ARGUS_EV_RUNTIME_BUILD_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, WX, 32);
    expect_hearsay(5, &e, "runtime digest replaced");

    e = mk(ARGUS_EV_POLICY_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, WD, 32);
    expect_none(5, &e, "policy re-announced unchanged");
    e = mk(ARGUS_EV_RUNTIME_BUILD_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, AL, 32);
    expect_none(5, &e, "runtime re-announced unchanged");
    e = mk(ARGUS_EV_POLICY_CHANGED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_UNAUTHORIZED);
    memcpy(e.evidence_digest, WX, 32);
    expect_none(5, &e, "policy change refused");
    memset(st.policy, 0, 32);
    memset(st.runtime, 0, 32);
    e = mk(ARGUS_EV_POLICY_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, WX, 32);
    expect_none(5, &e, "first policy announcement (nothing stored)");
    e = mk(ARGUS_EV_RUNTIME_BUILD_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, WX, 32);
    expect_none(5, &e, "first runtime announcement (nothing stored)");
    CHECK(step(&e) == 0, "announce runtime");
    CHECK(memcmp(st.runtime, WX, 32) == 0, "runtime digest stored");

    e = mk(ARGUS_EV_ARTIFACT_ADMITTED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, AU, 32);
    expect_none(5, &e, "clean admission");
    e = mk(ARGUS_EV_ARTIFACT_REJECTED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_RIGHTS);
    memcpy(e.evidence_digest, AU, 32);
    expect_none(5, &e, "rejection");
    e = mk(ARGUS_EV_ARTIFACT_ADMITTED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_RIGHTS);
    memcpy(e.evidence_digest, AU, 32);
    expect_none(5, &e, "admission refused with code");
}

static ArgusEvent lease_ev(uint16_t kind, uint8_t outcome, int32_t code, uint32_t id, uint32_t subj, uint64_t res)
{
    ArgusEvent e = mk(kind, outcome, code);
    e.object_id = id;
    e.principal = subj;
    e.resource = res;
    return e;
}

static void t_lease(void)
{
    ArgusEvent e;
    reset();
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0, 1, 8, 0x10);
    expect_only(6, &e, "other subject");
    CHECK(F[0].prior_sequence == 60 && F[0].sync_allowed == 0 &&
          F[0].containment == ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE, "d6 fields");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0, 1, 7, 0x110);
    expect_only(6, &e, "out of scope");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0, 2, 7, 0x10);
    expect_only(6, &e, "revoked lease");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0, 9, 7, 0x10);
    expect_only(6, &e, "unknown lease");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0, 1, 9, UINT64_MAX);
    expect_only(6, &e, "CREATED re-uses a LIVE lease id (G-26)");
    CHECK(F[0].prior_sequence == 60, "d6 recreate prior = existing lease");
    CHECK(step(&e) == 1, "recreate step");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0, 1, 9, 0xFF);
    expect_only(6, &e, "hijacker's use after a refused re-create");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0, 2, 7, 0x10);
    expect_only(6, &e, "CREATED re-uses a REVOKED lease id (ruling A)");
    CHECK(F[0].prior_sequence == 61, "d6 revive prior = revocation");
    CHECK(step(&e) == 1, "revive step");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0, 2, 7, 0x10);
    expect_only(6, &e, "revoked lease stays revoked after a refused re-create");

    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0, 1, 7, 0x30);
    expect_none(6, &e, "in scope by holder");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_REVOKED, 2, 7, 0x10);
    expect_none(6, &e, "revoked lease refused");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_RIGHTS, 1, 7, 0x110);
    expect_none(6, &e, "out of scope refused");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0, 9, 3, 0xFF);
    expect_none(6, &e, "lease creation");
    CHECK(step(&e) == 0, "create step");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0, 9, 3, 0x0F);
    expect_none(6, &e, "use after creation");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_UNAUTHORIZED, 1, 9, 0xFF);
    expect_none(6, &e, "re-create refused by the authority");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0, 10, 7, 0xFF);
    expect_none(6, &e, "fresh lease id");
}

static void t_machine(void)
{
    ArgusEvent e;
    reset();
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    memcpy(e.machine_id, MU, 32);
    expect_only(7, &e, "unknown machine");
    CHECK(F[0].sync_allowed == 0 && F[0].containment == ARGUS_CONTAIN_REQUIRE_REATTESTATION, "d7 fields");
    e = mk(ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MA, 32);
    expect_only(7, &e, "re-join without removal");
    CHECK(F[0].prior_sequence == 5, "d7 prior = first join");
    e = mk(ARGUS_EV_MACHINE_REMOVED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MA, 32);
    CHECK(step(&e) == 0, "remove step");
    e = mk(ARGUS_EV_WORLD_COMMITTED, ARGUS_OUTCOME_OK, 0);
    e.world_generation = 6;
    memcpy(e.evidence_digest, WX, 32);
    memcpy(e.machine_id, MA, 32);
    expect_only(7, &e, "removed machine acts");
    e = mk(ARGUS_EV_MACHINE_TRUST_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MU, 32);
    e.object_id = ARGUS_TRUST_RESTRICTED;
    expect_only(7, &e, "TRUST_CHANGED for an unknown machine (G-10)");
    CHECK(step(&e) == 1, "unknown trust change step");
    ArgusMachineShadow ms;
    CHECK(OPS->machine(V, MU, &ms) != ARGUS_OK, "unknown machine gets no entry from TRUST_CHANGED");
    e.object_id = ARGUS_TRUST_TRUSTED;
    expect_only(7, &e, "upward TRUST_CHANGED for an unknown machine is 7, not 15");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    e.flags = 0;
    expect_only(7, &e, "live producer event with zero machine_id (G-8)");
    CHECK(F[0].prior_sequence == 0, "d7 zero id prior");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_RIGHTS, 1, 3);
    e.flags = 0;
    expect_only(7, &e, "live refused event with zero machine_id");
    e = mk(ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_OK, 0);
    e.flags = 0;
    expect_only(7, &e, "live JOINED with zero machine_id");

    reset();
    e = mk(ARGUS_EV_TELEMETRY_DROPPED, ARGUS_OUTCOME_OK, 0);
    e.flags = ARGUS_FLAG_CONSUMER;
    e.class_ = ARGUS_CLASS_CRITICAL;
    e.object_id = ARGUS_CLASS_SECURITY;
    e.resource = 3;
    expect_none(7, &e, "ARGUS's own TELEMETRY_DROPPED has no machine");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    e.flags = 0;
    memcpy(e.machine_id, MA, 32);
    expect_none(7, &e, "live producer event attributed to a joined machine");
    e = mk(ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MU, 32);
    expect_none(7, &e, "new machine joins");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    memcpy(e.machine_id, MA, 32);
    expect_none(7, &e, "joined machine acts");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    expect_none(7, &e, "no machine attribution");
    e = mk(ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_UNAUTHORIZED);
    memcpy(e.machine_id, MA, 32);
    expect_none(7, &e, "refused re-join");
    e = mk(ARGUS_EV_MACHINE_REMOVED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MA, 32);
    CHECK(step(&e) == 0, "remove");
    e = mk(ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MA, 32);
    expect_none(7, &e, "re-join after removal");
    CHECK(step(&e) == 0, "rejoin");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    memcpy(e.machine_id, MA, 32);
    expect_none(7, &e, "acts after re-join");
}

static void t_effect(void)
{
    ArgusEvent e;
    reset();
    e = use(ARGUS_EV_EXTERNAL_EFFECT_COMMITTED, ARGUS_OUTCOME_OK, 0, 3, 1);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    expect_only(8, &e, "committed without effect right");
    CHECK(F[0].prior_sequence == 30 && F[0].severity == ARGUS_SEV_CRITICAL &&
          F[0].containment == ARGUS_CONTAIN_PAUSE_EXTERNAL_EFFECTS, "d8 fields");
    e = use(ARGUS_EV_EXTERNAL_EFFECT_REQUESTED, ARGUS_OUTCOME_OK, 0, ARGUS_CAP_NONE, 0);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    expect_only(8, &e, "external effect with no cap");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 3, 1);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    expect_only(8, &e, "use tagged external without right");

    e = use(ARGUS_EV_EXTERNAL_EFFECT_COMMITTED, ARGUS_OUTCOME_OK, 0, 1, 3);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    expect_none(8, &e, "committed with effect right");
    e = use(ARGUS_EV_EXTERNAL_EFFECT_REQUESTED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_RIGHTS, 3, 1);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    expect_none(8, &e, "request refused");
    e = use(ARGUS_EV_EXTERNAL_EFFECT_DENIED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_RIGHTS, 3, 1);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    expect_none(8, &e, "effect denied event");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 3, 1);
    e.effect_class = ARGUS_EFFECT_EPHEMERAL;
    expect_none(8, &e, "ephemeral use without effect right");

    /* G-24: the kind wins over the label; EVIDENCE needs WRITE */
    e = use(ARGUS_EV_EXTERNAL_EFFECT_COMMITTED, ARGUS_OUTCOME_OK, 0, ARGUS_CAP_NONE, 0);
    e.effect_class = ARGUS_EFFECT_NONE;
    expect_only(8, &e, "EXTERNAL_EFFECT_COMMITTED labelled NONE, no cap");
    e = use(ARGUS_EV_EXTERNAL_EFFECT_REQUESTED, ARGUS_OUTCOME_OK, 0, 3, 1);
    e.effect_class = ARGUS_EFFECT_EVIDENCE;
    expect_only(8, &e, "EXTERNAL_EFFECT_REQUESTED labelled EVIDENCE, cap without EFFECT");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 3, 1);
    e.effect_class = ARGUS_EFFECT_EVIDENCE;
    expect_only(8, &e, "EVIDENCE write under READ-only cap");
    CHECK(F[0].prior_sequence == 30, "d8 evidence prior = grant");
    e = use(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0, 3, 1);
    memcpy(e.evidence_digest, PL, 32);
    e.effect_class = ARGUS_EFFECT_EVIDENCE;
    expect_only(8, &e, "provider use writes EVIDENCE under READ-only cap");

    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    e.effect_class = ARGUS_EFFECT_EVIDENCE;
    expect_none(8, &e, "EVIDENCE write under WRITE cap");
    e = use(ARGUS_EV_EXTERNAL_EFFECT_COMMITTED, ARGUS_OUTCOME_OK, 0, 1, 3);
    e.effect_class = ARGUS_EFFECT_NONE;
    expect_none(8, &e, "mislabelled commit under EFFECT cap");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_RIGHTS, 3, 1);
    e.effect_class = ARGUS_EFFECT_EVIDENCE;
    expect_none(8, &e, "EVIDENCE write refused");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, ARGUS_CAP_NONE, 0);
    e.effect_class = ARGUS_EFFECT_EVIDENCE;
    expect_none(8, &e, "EVIDENCE with no capability is out of scope");
}

static ArgusEvent world_ev(uint8_t outcome, uint64_t gen, const uint8_t *digest)
{
    ArgusEvent e = mk(ARGUS_EV_WORLD_COMMITTED, outcome, 0);
    e.world_generation = gen;
    memcpy(e.evidence_digest, digest, 32);
    return e;
}

static void t_world(void)
{
    ArgusEvent e;
    reset();
    e = world_ev(ARGUS_OUTCOME_OK, 7, WX);
    expect_only(9, &e, "skip");
    CHECK(F[0].prior_sequence == 80 && F[0].sync_allowed == 0 &&
          F[0].containment == ARGUS_CONTAIN_RAISE_EFFECT_CLASS, "d9 fields");
    e = world_ev(ARGUS_OUTCOME_OK, 4, WX);
    expect_only(9, &e, "rollback");
    e = world_ev(ARGUS_OUTCOME_OK, 5, WX);
    expect_only(9, &e, "same gen, different digest");
    e = world_ev(ARGUS_OUTCOME_OK, 0x100000006ull, WX);
    expect_only(9, &e, "64-bit: high bits differ");
    stub_set_world(&st, 0, UINT64_MAX, WD, 81);
    e = world_ev(ARGUS_OUTCOME_OK, 0, WX);
    expect_only(9, &e, "wrap at UINT64_MAX");

    reset();
    e = world_ev(ARGUS_OUTCOME_OK, 6, WX);
    expect_none(9, &e, "next generation");
    e = world_ev(ARGUS_OUTCOME_OK, 5, WD);
    expect_none(9, &e, "idempotent replay");
    e = world_ev(ARGUS_OUTCOME_DENIED, 9, WX);
    expect_none(9, &e, "refused commit");
    stub_state_init(&st);
    e = world_ev(ARGUS_OUTCOME_OK, 42, WX);
    expect_none(9, &e, "first commit ever");
    CHECK(step(&e) == 0, "first commit step");
    e = world_ev(ARGUS_OUTCOME_OK, 43, WD);
    expect_none(9, &e, "then +1");
    stub_set_world(&st, 0, 0xFFFFFFFFull, WD, 90);
    e = world_ev(ARGUS_OUTCOME_OK, 0x100000000ull, WX);
    expect_none(9, &e, "64-bit: +1 across 2^32");
}

static void t_quarantine(void)
{
    ArgusEvent e;
    reset();
    e = mk(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PQ, 32);
    expect_only(10, &e, "quarantined provider used");
    CHECK(F[0].prior_sequence == 71 && F[0].containment == ARGUS_CONTAIN_QUARANTINE_PROVIDER, "d10 provider fields");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    memcpy(e.machine_id, MQ, 32);
    expect_only(10, &e, "quarantined machine acts");
    CHECK(F[0].prior_sequence == 40 && F[0].containment == ARGUS_CONTAIN_QUARANTINE_MACHINE, "d10 machine fields");
    e = mk(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PQ, 32);
    memcpy(e.machine_id, MQ, 32);
    run(&e);
    CHECK(NF == 2 && F[0].code == 10 && F[1].code == 10 &&
          F[0].containment == ARGUS_CONTAIN_QUARANTINE_PROVIDER &&
          F[1].containment == ARGUS_CONTAIN_QUARANTINE_MACHINE, "d10 both clauses (%zu)", NF);
    pos[10]++;

    e = mk(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PL, 32);
    expect_none(10, &e, "live provider used");
    e = mk(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_UNAUTHORIZED);
    memcpy(e.evidence_digest, PQ, 32);
    expect_none(10, &e, "quarantined provider refused");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_UNAUTHORIZED, 1, 3);
    memcpy(e.machine_id, MQ, 32);
    expect_none(10, &e, "quarantined machine refused");
    e = mk(ARGUS_EV_MACHINE_TRUST_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MQ, 32);
    e.object_id = ARGUS_TRUST_UNTRUSTED;
    expect_none(10, &e, "quarantined machine lowered further (lifecycle exempt)");
    e.object_id = ARGUS_TRUST_TRUSTED;
    run(&e);
    CHECK(NF == 1 && F[0].code == ARGUS_F_TRUST_ESCALATION, "self-release from quarantine is 15, not 10 (%zu)", NF);
    neg[10]++;
    e = mk(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PN, 32);
    expect_only_as(10, &e, "never-discovered provider used (G-9)", 0, ARGUS_CONTAIN_QUARANTINE_PROVIDER);
    CHECK(F[0].severity == ARGUS_SEV_HIGH && F[0].prior_sequence == 0, "d10 unseen provider fields");
    e = mk(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_UNAUTHORIZED);
    memcpy(e.evidence_digest, PN, 32);
    expect_none(10, &e, "never-discovered provider refused");
    e = mk(ARGUS_EV_PROVIDER_CHANGED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PN, 32);
    expect_none(10, &e, "PROVIDER_CHANGED is observation only");
    /* provider used before quarantine: silent; after: fires */
    e = mk(ARGUS_EV_PROVIDER_DISCOVERED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PN, 32);
    CHECK(step(&e) == 0, "discover");
    e = mk(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PN, 32);
    expect_none(10, &e, "provider used before quarantine");
    e = mk(ARGUS_EV_PROVIDER_QUARANTINED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PN, 32);
    CHECK(step(&e) == 0, "quarantine");
    e = mk(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PN, 32);
    expect_only(10, &e, "provider used after quarantine");
}

static void t_subject(void)
{
    ArgusEvent e;
    reset();
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    e.principal = 8;
    expect_only(14, &e, "live ref used OK by another principal (G-3)");
    CHECK(F[0].prior_sequence == 10 && F[0].severity == ARGUS_SEV_HIGH &&
          F[0].containment == ARGUS_CONTAIN_FREEZE_PRINCIPAL, "d14 fields");
    e = use(ARGUS_EV_EXTERNAL_EFFECT_COMMITTED, ARGUS_OUTCOME_OK, 0, 1, 3);
    e.effect_class = ARGUS_EFFECT_EXTERNAL;
    e.principal = 8;
    expect_only(14, &e, "effect committed by another principal");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 2, 1);
    e.principal = 8;
    run(&e);
    CHECK(NF == 2 && F[0].code == 3 && F[1].code == 14, "revoked ref by another principal: 3 then 14 (%zu)", NF);
    pos[14]++;

    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    expect_none(14, &e, "used by its subject");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_SUBJECT, 1, 3);
    e.principal = 8;
    expect_none(14, &e, "other principal refused by the authority");
    e = use(ARGUS_EV_CAPABILITY_DENIED, ARGUS_OUTCOME_DENIED, AIENOS_CAP_ERR_SUBJECT, 1, 3);
    e.principal = 8;
    expect_none(14, &e, "CAPABILITY_DENIED for another principal");
    e = use(ARGUS_EV_CAPABILITY_GRANTED, ARGUS_OUTCOME_OK, 0, 1, 4);
    e.principal = 8;
    e.object_id = AIENOS_CAP_RIGHT_READ;
    expect_none(14, &e, "re-grant to a new subject");
    CHECK(step(&e) == 0, "re-grant step");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 4);
    e.principal = 8;
    expect_none(14, &e, "new subject uses its grant");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 99, 1);
    e.principal = 8;
    run(&e);
    CHECK(NF == 1 && F[0].code == 1, "unseen slot is detector 1's only (%zu)", NF);
    neg[14]++;
}

static ArgusEvent trust_ev(uint16_t kind, const uint8_t *id, uint32_t trust)
{
    ArgusEvent e = mk(kind, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, id, 32);
    e.object_id = trust;
    return e;
}

static void t_trust(void)
{
    ArgusEvent e;
    ArgusMachineShadow ms;
    reset();
    e = trust_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, MQ, ARGUS_TRUST_TRUSTED);
    expect_only(15, &e, "QUARANTINED -> TRUSTED (G-8)");
    CHECK(F[0].prior_sequence == 40 && F[0].sync_allowed == 0 &&
          F[0].containment == ARGUS_CONTAIN_REQUIRE_REATTESTATION, "d15 fields");
    CHECK(step(&e) == 1, "escalation step");
    CHECK(OPS->machine(V, MQ, &ms) == ARGUS_OK && ms.trust == ARGUS_TRUST_QUARANTINED, "escalation ignored by apply");
    e = trust_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, MQ, ARGUS_TRUST_REATTESTATION_REQUIRED);
    expect_only(15, &e, "QUARANTINED -> REATTESTATION_REQUIRED (rank, not enum order)");
    e = trust_ev(ARGUS_EV_MACHINE_JOINED, MU, ARGUS_TRUST_TRUSTED);
    expect_only(15, &e, "new machine declares itself TRUSTED (G-10)");
    CHECK(F[0].prior_sequence == 0, "d15 new machine prior");
    CHECK(step(&e) == 1, "declared join step");
    CHECK(OPS->machine(V, MU, &ms) == ARGUS_OK && ms.trust == ARGUS_TRUST_OBSERVED && ms.joined_sequence != 0,
          "JOINED capped at OBSERVED");
    e = mk(ARGUS_EV_MACHINE_REMOVED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MQ, 32);
    CHECK(step(&e) == 0, "remove quarantined machine");
    CHECK(OPS->machine(V, MQ, &ms) == ARGUS_OK && ms.joined_sequence == 0 && ms.trust == ARGUS_TRUST_QUARANTINED,
          "tombstone keeps quarantine");
    e = trust_ev(ARGUS_EV_MACHINE_JOINED, MQ, ARGUS_TRUST_OBSERVED);
    expect_only(15, &e, "re-join over a quarantined tombstone claims OBSERVED (G-8)");
    CHECK(F[0].prior_sequence == 40, "d15 tombstone prior");

    reset();
    e = trust_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, MQ, ARGUS_TRUST_UNTRUSTED);
    expect_none(15, &e, "downward move");
    e = trust_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, MQ, ARGUS_TRUST_QUARANTINED);
    expect_none(15, &e, "same trust");
    e = trust_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, MQ, 0);
    expect_none(15, &e, "UNKNOWN value ignored");
    e = trust_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, MQ, 7);
    expect_none(15, &e, "out-of-range value ignored");
    e = trust_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, MA, ARGUS_TRUST_OBSERVED);
    expect_none(15, &e, "TRUSTED -> OBSERVED");
    e = trust_ev(ARGUS_EV_MACHINE_TRUST_CHANGED, MQ, ARGUS_TRUST_TRUSTED);
    e.outcome = ARGUS_OUTCOME_DENIED;
    expect_none(15, &e, "upward move refused");
    e = trust_ev(ARGUS_EV_MACHINE_JOINED, MU, 0);
    expect_none(15, &e, "join with no claim");
    e = trust_ev(ARGUS_EV_MACHINE_JOINED, MU, ARGUS_TRUST_OBSERVED);
    expect_none(15, &e, "join claiming OBSERVED");
    e = trust_ev(ARGUS_EV_MACHINE_JOINED, MU, ARGUS_TRUST_RESTRICTED);
    expect_none(15, &e, "join claiming RESTRICTED");
    e = trust_ev(ARGUS_EV_MACHINE_JOINED, MU, ARGUS_TRUST_TRUSTED);
    e.outcome = ARGUS_OUTCOME_DENIED;
    expect_none(15, &e, "refused join claiming TRUSTED");
    e = trust_ev(ARGUS_EV_MACHINE_JOINED, MA, ARGUS_TRUST_TRUSTED);
    run(&e);
    CHECK(NF == 1 && F[0].code == 7, "re-join of a joined machine is 7 only (%zu)", NF);
    neg[15]++;
    e = mk(ARGUS_EV_MACHINE_REMOVED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.machine_id, MQ, 32);
    CHECK(step(&e) == 0, "remove quarantined machine");
    e = trust_ev(ARGUS_EV_MACHINE_JOINED, MQ, 0);
    expect_none(15, &e, "re-join over tombstone without a claim");
    CHECK(step(&e) == 0, "re-join step");
    CHECK(OPS->machine(V, MQ, &ms) == ARGUS_OK && ms.trust == ARGUS_TRUST_QUARANTINED && ms.joined_sequence != 0,
          "re-join does not launder the quarantine");
}

/* Stub apply follows the argus_abi.h apply rules (so stub-clean == core-clean). */
static void t_apply(void)
{
    ArgusEvent e;
    ArgusCapShadow cs;
    ArgusLeaseShadow ls;
    ArgusWorldShadow ws;
    ArgusProviderShadow ps;
    reset();
    e = use(ARGUS_EV_CAPABILITY_GRANTED, ARGUS_OUTCOME_OK, 0, 2, 1);   /* replay of the revoked grant */
    e.object_id = AIENOS_CAP_RIGHT_READ;
    stub_state_apply(&st, &e);
    CHECK(OPS->cap(V, 2, &cs) == ARGUS_OK && cs.state == ARGUS_SHADOW_REVOKED, "GRANTED at shadow gen not applied");
    e = use(ARGUS_EV_CAPABILITY_REVOKED, ARGUS_OUTCOME_OK, 0, 77, UINT64_MAX);
    stub_state_apply(&st, &e);
    CHECK(OPS->cap(V, 77, &cs) != ARGUS_OK, "REVOKED of an unseen slot creates nothing");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0, 1, 9, UINT64_MAX);
    stub_state_apply(&st, &e);
    CHECK(OPS->lease(V, 1, &ls) == ARGUS_OK && ls.subject == 7 && ls.scope == 0xF0, "LIVE lease not rewritten");
    e = lease_ev(ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0, 2, 7, 1);
    stub_state_apply(&st, &e);
    CHECK(OPS->lease(V, 2, &ls) == ARGUS_OK && ls.state == ARGUS_SHADOW_REVOKED, "REVOKED lease not revived");
    e = world_ev(ARGUS_OUTCOME_OK, 7, WX);
    stub_state_apply(&st, &e);
    CHECK(OPS->world(V, 0, &ws) == ARGUS_OK && ws.generation == 5, "skipping commit not adopted");
    e = world_ev(ARGUS_OUTCOME_OK, 6, WX);
    stub_state_apply(&st, &e);
    CHECK(OPS->world(V, 0, &ws) == ARGUS_OK && ws.generation == 6, "+1 commit adopted");
    e = mk(ARGUS_EV_PROVIDER_DISCOVERED, ARGUS_OUTCOME_OK, 0);
    memcpy(e.evidence_digest, PQ, 32);
    stub_state_apply(&st, &e);
    CHECK(OPS->provider(V, PQ, &ps) == ARGUS_OK && ps.state == ARGUS_SHADOW_REVOKED, "rediscovery keeps quarantine");
    CHECK(stub_min_class(ARGUS_EV_CAPABILITY_REVOKED) == ARGUS_CLASS_CRITICAL &&
          stub_min_class(ARGUS_EV_WORLD_COMMITTED) == ARGUS_CLASS_SECURITY &&
          stub_min_class(ARGUS_EV_PROVIDER_USED) == ARGUS_CLASS_AUDIT &&
          stub_min_class(ARGUS_EV_POLICY_CHANGED) == ARGUS_CLASS_CRITICAL, "min class table spot checks");
}

/* ---- table, mirrors, runner ------------------------------------------------ */

static void t_table(void)
{
    static const uint16_t ids[ARGUS_HARD_DETECTOR_COUNT] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 15 };
    static const uint8_t sync[ARGUS_HARD_DETECTOR_COUNT] = { 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0 };
    static const uint8_t contain[ARGUS_HARD_DETECTOR_COUNT] = {
        ARGUS_CONTAIN_FREEZE_PRINCIPAL, ARGUS_CONTAIN_REVOKE_CAPABILITY, ARGUS_CONTAIN_FREEZE_PRINCIPAL,
        ARGUS_CONTAIN_REJECT_ARTIFACT, ARGUS_CONTAIN_REJECT_ARTIFACT, ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE,
        ARGUS_CONTAIN_REQUIRE_REATTESTATION, ARGUS_CONTAIN_PAUSE_EXTERNAL_EFFECTS, ARGUS_CONTAIN_RAISE_EFFECT_CLASS,
        ARGUS_CONTAIN_QUARANTINE_PROVIDER, ARGUS_CONTAIN_FREEZE_PRINCIPAL, ARGUS_CONTAIN_REQUIRE_REATTESTATION,
    };
    CHECK(argus_hard_detector_count == ARGUS_HARD_DETECTOR_COUNT && argus_hard_detector_count == 12,
          "detector count %zu", argus_hard_detector_count);
    for (size_t i = 0; i < argus_hard_detector_count; i++) {
        const ArgusDetector *d = &argus_hard_detectors[i];
        CHECK(d->id == ids[i], "table order at %zu (id %u)", i, d->id);
        CHECK(d->id != ARGUS_F_TELEMETRY_LOSS && d->id != ARGUS_F_SEQUENCE_ANOMALY &&
              d->id != ARGUS_F_AUTHORITY_REPLAY && d->id != ARGUS_F_MALFORMED_EVENT, "core-only code %u in table", d->id);
        CHECK(d->sync_allowed == sync[i], "sync_allowed of %u", d->id);
        CHECK(d->containment == contain[i], "containment of %u", d->id);
        CHECK(d->name != NULL && d->fn != NULL, "name/fn of %u", d->id);
    }
    CHECK(argus_trust_rank(ARGUS_TRUST_TRUSTED) < argus_trust_rank(ARGUS_TRUST_OBSERVED) &&
          argus_trust_rank(ARGUS_TRUST_OBSERVED) < argus_trust_rank(ARGUS_TRUST_REATTESTATION_REQUIRED) &&
          argus_trust_rank(ARGUS_TRUST_REATTESTATION_REQUIRED) < argus_trust_rank(ARGUS_TRUST_RESTRICTED) &&
          argus_trust_rank(ARGUS_TRUST_RESTRICTED) < argus_trust_rank(ARGUS_TRUST_QUARANTINED) &&
          argus_trust_rank(ARGUS_TRUST_QUARANTINED) < argus_trust_rank(ARGUS_TRUST_UNTRUSTED) &&
          argus_trust_rank(ARGUS_TRUST_UNKNOWN) < 0 && argus_trust_rank(7) < 0, "trust rank order (header)");
    CHECK(ARGUS_AUTH_RIGHT_WRITE == AIENOS_CAP_RIGHT_WRITE, "mirror RIGHT_WRITE");
    CHECK(ARGUS_AUTH_OK == AIENOS_CAP_OK, "mirror OK");
    CHECK(ARGUS_AUTH_ERR_BOUNDS == AIENOS_CAP_ERR_BOUNDS, "mirror BOUNDS");
    CHECK(ARGUS_AUTH_ERR_STALE_GEN == AIENOS_CAP_ERR_STALE_GEN, "mirror STALE_GEN");
    CHECK(ARGUS_AUTH_ERR_REVOKED == AIENOS_CAP_ERR_REVOKED, "mirror REVOKED");
    CHECK(ARGUS_AUTH_ERR_CHAIN == AIENOS_CAP_ERR_CHAIN, "mirror CHAIN");
    CHECK(ARGUS_AUTH_RIGHT_EFFECT == AIENOS_CAP_RIGHT_EFFECT, "mirror RIGHT_EFFECT");
    CHECK(sizeof(ArgusCapRef) == 16 && offsetof(ArgusCapRef, generation) == 8, "cap ref layout");
}

static void t_runner(void)
{
    ArgusEvent e;
    size_t n = 99;
    reset();
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 1, 3);
    CHECK(argus_detect_run(OPS, V, &e, F, 4, NULL) == ARGUS_ERR_ARG, "null n_out");
    CHECK(argus_detect_run(NULL, V, &e, F, 4, &n) == ARGUS_ERR_ARG && n == 0, "null ops");
    CHECK(argus_detect_run(OPS, NULL, &e, F, 4, &n) == ARGUS_ERR_ARG, "null view");
    CHECK(argus_detect_run(OPS, V, NULL, F, 4, &n) == ARGUS_ERR_ARG, "null event");
    CHECK(argus_detect_run(OPS, V, &e, NULL, 4, &n) == ARGUS_ERR_ARG, "null out with cap");
    ArgusStateOps holed = *OPS;
    holed.lease = NULL;
    CHECK(argus_detect_run(&holed, V, &e, F, 4, &n) == ARGUS_ERR_ARG, "missing op");
    holed = *OPS;
    holed.policy_digest = NULL;
    CHECK(argus_detect_run(&holed, V, &e, F, 4, &n) == ARGUS_ERR_ARG, "missing policy_digest op");
    holed = *OPS;
    holed.runtime_digest = NULL;
    CHECK(argus_detect_run(&holed, V, &e, F, 4, &n) == ARGUS_ERR_ARG, "missing runtime_digest op");
    CHECK(argus_detect_run(OPS, V, &e, NULL, 0, &n) == ARGUS_OK && n == 0, "clean event, no room needed");

    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 99, 1);
    CHECK(argus_detect_run(OPS, V, &e, NULL, 0, &n) == ARGUS_ERR_OVERFLOW && n == 0, "overflow at cap 0");
    /* quarantined provider used from a quarantined machine with an unseen ref:
     * findings 1, 10, 10 */
    e = use(ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0, 99, 1);
    memcpy(e.evidence_digest, PQ, 32);
    memcpy(e.machine_id, MQ, 32);
    CHECK(argus_detect_run(OPS, V, &e, F, 32, &n) == ARGUS_OK && n == 3 && F[0].code == 1 && F[1].code == 10,
          "three findings in id order (%zu)", n);
    CHECK(argus_detect_run(OPS, V, &e, F, 2, &n) == ARGUS_ERR_OVERFLOW && n == 2, "truncated at 2");
    CHECK(argus_detect_run(OPS, V, &e, F, 1, &n) == ARGUS_ERR_OVERFLOW && n == 1 && F[0].code == 1, "truncated at 1");
}

/* ---- v1.1: cap 0, CAP_NONE, CAPABILITY_USE_SUMMARY, per-store World -------- */

static ArgusEvent summ(uint32_t cap_id, uint64_t max_gen, uint32_t min_gen, uint32_t principal)
{
    ArgusEvent e = use(ARGUS_EV_CAPABILITY_USE_SUMMARY, ARGUS_OUTCOME_OK, 0, cap_id, max_gen);
    e.class_ = ARGUS_CLASS_AUDIT;
    e.tick = 0;
    e.object_id = min_gen;
    e.resource = 4096;
    e.principal = principal;
    return e;
}

static void expect_codes(const ArgusEvent *e, uint16_t a, uint16_t b, const char *what)
{
    int rc = run(e);
    size_t want = (a ? 1u : 0u) + (b ? 1u : 0u);
    CHECK(rc == ARGUS_OK && NF == want, "[%s] expected %zu findings, got %zu (first %u)", what, want, NF, NF ? F[0].code : 0);
    if (a && NF >= 1) CHECK(F[0].code == a, "[%s] first code %u want %u", what, F[0].code, a);
    if (b && NF >= 2) CHECK(F[1].code == b, "[%s] second code %u want %u", what, F[1].code, b);
}

static void t_v11_cap0(void)
{
    ArgusEvent e;
    reset();
    ArgusCapShadow c = {0};
    c.cap_id = 0; c.generation = 2; c.state = ARGUS_SHADOW_LIVE; c.subject = 7;
    c.rights = AIENOS_CAP_RIGHT_READ; c.granted_sequence = 9;
    stub_put_cap(&st, &c);
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 0, 2);
    expect_codes(&e, 0, 0, "cap 0 used by its subject");
    neg[1]++; neg[14]++;
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 0, 2); e.principal = 8;
    expect_only(14, &e, "cap 0 used by the wrong subject");
    CHECK(F[0].cap_id == 0 && F[0].prior_sequence == 9, "d14 on cap 0 fields");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 0, 3);
    expect_only(1, &e, "cap 0 above its generation");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 0, 1);
    expect_only(2, &e, "cap 0 stale generation");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 0, 2); e.effect_class = ARGUS_EFFECT_EVIDENCE;
    expect_only(8, &e, "cap 0 EVIDENCE without WRITE");
    e = use(ARGUS_EV_CAPABILITY_REVOKED, ARGUS_OUTCOME_OK, 0, 0, 2);
    CHECK(step(&e) == 0, "revoke cap 0");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 0, 2);
    expect_only(3, &e, "revoked cap 0 accepted");
    /* cap 0 unseen: a use is a forgery like any other slot */
    reset();
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 0, 1);
    expect_only(1, &e, "unseen cap 0 used");
    /* CAP_NONE: not a capability use (1, 2, 3, 14 silent) */
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, ARGUS_CAP_NONE, 5);
    expect_none(1, &e, "CAP_NONE use");
    e = summ(ARGUS_CAP_NONE, 5, 1, 99);
    expect_none(14, &e, "CAP_NONE summary");
    /* USED above a REVOKED generation: detector 1 only (v1.1 precision rule) */
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 2, 2);
    expect_only(1, &e, "use above the revoked generation");
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, AIENOS_CAP_ERR_REVOKED, 2, 2);
    expect_codes(&e, 1, 3, "above revoked + ERR_REVOKED contradiction still 3");
}

static void t_v11_summary(void)
{
    ArgusEvent e;
    reset();
    /* cap 1 LIVE gen 3 subject 7; cap 2 REVOKED gen 1; cap 3 LIVE gen 1 rights R */
    e = summ(1, 3, 3, 7);
    expect_codes(&e, 0, 0, "consistent summary");
    neg[1]++; neg[2]++; neg[3]++; neg[14]++;
    e = summ(3, 1, 1, 7); e.effect_class = ARGUS_EFFECT_NONE;
    expect_none(8, &e, "summary with no effect class");
    e = summ(1, 4, 3, 7);
    expect_only(1, &e, "summary max above shadow");
    CHECK(F[0].cap_generation == 4 && F[0].prior_sequence == 10, "d1 summary fields");
    e = summ(1, 3, 2, 7);
    expect_only(2, &e, "summary min stale");
    CHECK(F[0].prior_sequence == 10 && F[0].containment == ARGUS_CONTAIN_REVOKE_CAPABILITY, "d2 summary fields");
    e = summ(1, 4, 2, 7);
    expect_codes(&e, 1, 2, "summary above and below");
    e = summ(2, 1, 1, 7);
    expect_only(3, &e, "summary max hits revoked slot");
    CHECK(F[0].prior_sequence == 20, "d3 summary prior = revocation");
    e = summ(2, 2, 2, 7);
    expect_only(1, &e, "summary above revoked generation: 1, not 3");
    e = summ(2, 1, 0, 7);
    expect_codes(&e, 2, 3, "summary on revoked slot spanning an older generation");
    e = summ(1, 3, 3, 8);
    expect_only(14, &e, "summary by the wrong subject");
    e = summ(150, 1, 1, 7);
    expect_only(1, &e, "summary of a slot never granted");
    e = summ(3, 1, 1, 7); e.effect_class = ARGUS_EFFECT_EXTERNAL;
    expect_only(8, &e, "summary labelled EXTERNAL without EFFECT right");
    e = summ(1, 3, 3, 7); e.outcome = ARGUS_OUTCOME_DENIED;
    expect_none(1, &e, "non-OK summary (malformed for validate) is not a use");
    e = summ(1, 3, 3, 7); memcpy(e.machine_id, MQ, 32);
    expect_only(10, &e, "summary from a quarantined machine");
    e = summ(1, 3, 3, 7); memcpy(e.machine_id, MU, 32);
    expect_only(7, &e, "summary from an unknown machine");
    /* stub apply: a summary changes nothing */
    StubState before = st;
    e = summ(1, 3, 3, 7);
    CHECK(stub_state_apply(&st, &e) == ARGUS_OK && memcmp(&before, &st, sizeof st) == 0, "summary applies nothing");
}

static void t_v11_world_stores(void)
{
    ArgusEvent e;
    reset();   /* store 0 at gen 5 */
    e = world_ev(ARGUS_OUTCOME_OK, 1, WX); e.object_id = 3;
    expect_none(9, &e, "first commit of another store");
    CHECK(step(&e) == 0, "store 3 first commit");
    e = world_ev(ARGUS_OUTCOME_OK, 6, WD); e.object_id = 0;
    expect_none(9, &e, "store 0 +1 while store 3 exists");
    CHECK(step(&e) == 0, "store 0 advances");
    e = world_ev(ARGUS_OUTCOME_OK, 2, WD); e.object_id = 3;
    expect_none(9, &e, "store 3 +1 interleaved");
    CHECK(step(&e) == 0, "store 3 advances");
    e = world_ev(ARGUS_OUTCOME_OK, 3, WX); e.object_id = 0;
    expect_only(9, &e, "store 0 rollback (store 3 is at 2, irrelevant)");
    e = world_ev(ARGUS_OUTCOME_OK, 7, WX); e.object_id = 3;
    expect_only(9, &e, "store 3 skip");
    ArgusWorldShadow w;
    CHECK(OPS->world(V, 0, &w) == ARGUS_OK && w.generation == 6 && w.store_id == 0, "store 0 shadow");
    CHECK(OPS->world(V, 3, &w) == ARGUS_OK && w.generation == 2 && w.store_id == 3, "store 3 shadow");
    CHECK(OPS->world(V, 4, &w) == ARGUS_ERR_STATE, "unknown store");
    /* stub table: ARGUS_WORLD_STORES stores, then FULL */
    for (uint32_t s = 10; s < 10 + ARGUS_WORLD_STORES - 2; s++)
        CHECK(stub_set_world(&st, s, 1, WD, 100 + s) == ARGUS_OK, "store %u fits", s);
    CHECK(stub_set_world(&st, 99, 1, WD, 200) == ARGUS_ERR_FULL, "9th store is FULL");
}

/* ---- corpora ---------------------------------------------------------------- */

#define CORPUS_N 5000

static ArgusEvent corpus[CORPUS_N];
static ArgusEvent corpus2[CORPUS_N];

static size_t replay(const ArgusEvent *evs, size_t n, ArgusFinding *all, size_t all_max, size_t *codes)
{
    size_t total = 0;
    stub_state_init(&st);
    V = stub_state_view(&st);
    for (size_t i = 0; i < n; i++) {
        size_t k = 0;
        StubState before = st;
        int rc = argus_detect_run(OPS, V, &evs[i], F, 32, &k);
        CHECK(rc == ARGUS_OK, "replay rc %d at %zu", rc, i);
        CHECK(memcmp(&before, &st, sizeof st) == 0, "detectors modified state at %zu", i);
        for (size_t j = 0; j < k; j++) {
            if (codes && F[j].code <= ARGUS_F_MAX) codes[F[j].code]++;
            if (all && total < all_max) all[total] = F[j];
            total++;
        }
        CHECK(stub_state_apply(&st, &evs[i]) == ARGUS_OK, "apply at %zu", i);
    }
    return total;
}

/* Stream obeys the argus_abi.h validate rules and the corpus conventions:
 * class never weaker than the kind minimum, no CONSUMER flag, cap_id <
 * ARGUS_CAP_MAX, EXTERNAL_EFFECT_* labelled EXTERNAL, every event attributed
 * to a machine, and (benign only) every LEASE_CREATED on a fresh id. */
static void check_stream_shape(const ArgusEvent *evs, size_t n, int benign)
{
    static uint8_t lease_seen[1u << 16];
    memset(lease_seen, 0, sizeof lease_seen);
    static const uint8_t zero[ARGUS_MACHINE_ID_LEN];
    size_t bad = 0, lease_reuse = 0, lease_ids = 0, n_summary = 0, n_cap0 = 0, n_store[2] = {0, 0}, n_mach = 0;
    static uint8_t mach[16][32];
    uint32_t streams[16] = {0};
    for (size_t i = 0; i < n; i++) {
        const ArgusEvent *e = &evs[i];
        int ok = e->version == ARGUS_ABI_VERSION && e->sequence == i + 1 && e->kind != 0 &&
                 e->outcome >= 1 && e->outcome <= ARGUS_OUTCOME_MAX &&
                 (e->flags & (uint16_t)~ARGUS_FLAG_STREAM_MASK) == ARGUS_FLAG_SYNTHETIC &&
                 e->class_ >= 1 && e->class_ <= stub_min_class(e->kind) &&
                 (e->cap_id < ARGUS_CAP_MAX || e->cap_id == ARGUS_CAP_NONE) &&
                 memcmp(e->machine_id, zero, sizeof zero) != 0;
        if ((e->kind == ARGUS_EV_EXTERNAL_EFFECT_REQUESTED || e->kind == ARGUS_EV_EXTERNAL_EFFECT_DENIED ||
             e->kind == ARGUS_EV_EXTERNAL_EFFECT_COMMITTED) && e->effect_class != ARGUS_EFFECT_EXTERNAL)
            ok = 0;
        /* v1.1: summaries are outcome OK with tick 0 and min <= max; USED carries tick 0 */
        if (e->kind == ARGUS_EV_CAPABILITY_USE_SUMMARY &&
            (e->outcome != ARGUS_OUTCOME_OK || e->tick != 0 || e->resource == 0 || e->object_id > e->cap_generation))
            ok = 0;
        if (e->kind == ARGUS_EV_CAPABILITY_USED && e->tick != 0)
            ok = 0;
        if (e->kind == ARGUS_EV_CAPABILITY_USE_SUMMARY) n_summary++;
        if (e->cap_id == 0 && e->kind == ARGUS_EV_CAPABILITY_GRANTED) n_cap0++;
        if (e->kind == ARGUS_EV_WORLD_COMMITTED) { if (e->object_id == 0) n_store[0]++; else if (e->object_id == 5) n_store[1]++; }
        for (size_t m = 0; m < n_mach; m++)
            if (memcmp(mach[m], e->machine_id, 32) == 0) { streams[m] |= 1u << (ARGUS_STREAM_OF(e->flags) & 31u); goto seen; }
        if (n_mach < 16) { memcpy(mach[n_mach], e->machine_id, 32); streams[n_mach++] = 1u << (ARGUS_STREAM_OF(e->flags) & 31u); }
    seen:;
        if (!ok && bad++ < 5)
            CHECK(0, "stream shape at %zu (kind %u class %u)", i, e->kind, e->class_);
        if (e->kind == ARGUS_EV_CREDENTIAL_LEASE_CREATED && e->outcome == ARGUS_OUTCOME_OK) {
            CHECK(e->object_id != 0 && e->object_id < (1u << 16), "lease id range at %zu", i);
            if (e->object_id < (1u << 16)) {
                if (lease_seen[e->object_id]) lease_reuse++;
                else lease_ids++;
                lease_seen[e->object_id] = 1;
            }
        }
    }
    CHECK(bad == 0, "%zu events break the stream shape", bad);
    CHECK(n_summary > 0 && n_cap0 > 0 && n_store[0] > 1 && n_store[1] > 1,
          "v1.1 content: %zu summaries, %zu cap-0 grants, stores %zu/%zu", n_summary, n_cap0, n_store[0], n_store[1]);
    size_t multi = 0;
    for (size_t m = 0; m < n_mach; m++) multi += __builtin_popcount(streams[m]) >= 3;
    CHECK(multi >= 3, "only %zu machines use >= 3 streams", multi);
    CHECK(lease_ids <= 56, "distinct lease ids %zu exceed the core's table margin", lease_ids);
    if (benign)
        CHECK(lease_reuse == 0, "benign stream re-uses %zu lease ids (ruling A)", lease_reuse);
}

static size_t benign_findings_seed1;

static void t_benign(void)
{
    size_t kinds[ARGUS_EV_KIND_MAX + 1] = {0};
    size_t outcomes[4] = {0};
    size_t n = argus_corpus_benign(corpus, CORPUS_N, 1);
    CHECK(n == CORPUS_N, "benign size %zu", n);
    check_stream_shape(corpus, n, 1);
    for (size_t i = 0; i < n; i++) { kinds[corpus[i].kind]++; outcomes[corpus[i].outcome]++; }
    size_t codes[ARGUS_F_MAX + 1] = {0};
    benign_findings_seed1 = replay(corpus, n, NULL, 0, codes);
    CHECK(benign_findings_seed1 == 0, "benign corpus seed 1: %zu findings", benign_findings_seed1);
    for (int c = 1; c <= ARGUS_F_MAX; c++)
        if (codes[c]) fprintf(stderr, "  benign FP code %d: %zu\n", c, codes[c]);
    printf("benign corpus seed 1: %zu events, %zu findings; OK %zu DENIED %zu; kinds:", n, benign_findings_seed1,
           outcomes[ARGUS_OUTCOME_OK], outcomes[ARGUS_OUTCOME_DENIED]);
    size_t distinct = 0;
    for (int k = 0; k <= ARGUS_EV_KIND_MAX; k++)
        if (kinds[k]) { printf(" %d:%zu", k, kinds[k]); distinct++; }
    printf(" (%zu distinct)\n", distinct);
    for (uint64_t seed = 1; seed <= 9; seed++) {
        n = argus_corpus_benign(corpus, CORPUS_N, seed);
        check_stream_shape(corpus, n, 1);
        size_t f = replay(corpus, n, NULL, 0, NULL);
        CHECK(f == 0, "benign corpus seed %llu: %zu findings", (unsigned long long)seed, f);
        /* the same day from a live producer (no SYNTHETIC flag): the zero
         * machine_id rule must not fire, every event is attributed */
        for (size_t i = 0; i < n; i++) corpus[i].flags &= (uint16_t)~ARGUS_FLAG_SYNTHETIC;   /* keep stream ids */
        size_t fl = replay(corpus, n, NULL, 0, NULL);
        CHECK(fl == 0, "benign corpus seed %llu as live producer: %zu findings", (unsigned long long)seed, fl);
        printf("benign seed %llu: %zu events, %zu findings (synthetic), %zu findings (live flags)\n",
               (unsigned long long)seed, n, f, fl);
    }
    /* determinism of the generator */
    argus_corpus_benign(corpus, CORPUS_N, 7);
    argus_corpus_benign(corpus2, CORPUS_N, 7);
    CHECK(memcmp(corpus, corpus2, sizeof corpus) == 0, "benign generator deterministic");
    argus_corpus_benign(corpus2, CORPUS_N, 8);
    CHECK(memcmp(corpus, corpus2, sizeof corpus) != 0, "seed changes the stream");
}

static ArgusFinding hf1[512], hf2[512];

static void t_hostile(void)
{
    static ArgusExpectedFinding ex[512];
    size_t nex = 0;
    size_t n = argus_corpus_hostile(corpus, CORPUS_N, 1, ex, 512, &nex);
    CHECK(n == CORPUS_N, "hostile size");
    check_stream_shape(corpus, n, 0);
    size_t exp_codes[ARGUS_F_MAX + 1] = {0}, got_codes[ARGUS_F_MAX + 1] = {0};
    for (size_t i = 0; i < nex; i++) exp_codes[ex[i].code]++;
    /* v1.1 injections present: summaries hitting codes 1, 2, 3 and cap 0 used by the wrong subject */
    size_t sum_code[ARGUS_F_MAX + 1] = {0}, cap0_14 = 0;
    for (size_t i = 0; i < nex && i < 512; i++) {
        const ArgusEvent *ie = &corpus[ex[i].sequence - 1];
        if (ie->kind == ARGUS_EV_CAPABILITY_USE_SUMMARY) sum_code[ex[i].code]++;
        if (ie->cap_id == 0 && ex[i].code == ARGUS_F_SUBJECT_MISMATCH) cap0_14++;
    }
    CHECK(sum_code[1] > 0 && sum_code[2] > 0 && sum_code[3] > 0 && cap0_14 > 0,
          "v1.1 hostile injections: summary codes 1:%zu 2:%zu 3:%zu, cap-0 code 14: %zu", sum_code[1], sum_code[2], sum_code[3], cap0_14);
    printf("hostile v1.1 injections: summaries -> code 1:%zu 2:%zu 3:%zu; cap 0 wrong subject -> 14:%zu\n",
           sum_code[1], sum_code[2], sum_code[3], cap0_14);
    size_t nf = replay(corpus, n, hf1, 512, got_codes);
    CHECK(nf == nex, "hostile: expected %zu findings, detected %zu", nex, nf);
    size_t match = 0;
    for (size_t i = 0; i < nf && i < nex && i < 512; i++) {
        if (hf1[i].sequence == ex[i].sequence && hf1[i].code == ex[i].code) match++;
        else CHECK(0, "hostile mismatch at %zu: got (%llu,%u) want (%llu,%u)", i,
                   (unsigned long long)hf1[i].sequence, hf1[i].code, (unsigned long long)ex[i].sequence, ex[i].code);
    }
    printf("hostile corpus seed 1: %zu events, expected %zu, detected %zu, exact matches %zu; per code:", n, nex, nf, match);
    for (size_t k = 0; k < argus_hard_detector_count; k++) {
        uint16_t c = argus_hard_detectors[k].id;
        printf(" %u:%zu/%zu", c, got_codes[c], exp_codes[c]);
        CHECK(exp_codes[c] > 0, "hostile corpus injects code %u", c);
        CHECK(got_codes[c] == exp_codes[c], "hostile code %u: detected %zu expected %zu", c, got_codes[c], exp_codes[c]);
    }
    printf("\n");
    /* determinism: same stream twice -> byte-identical findings */
    size_t nex2 = 0;
    argus_corpus_hostile(corpus2, CORPUS_N, 1, ex, 512, &nex2);
    CHECK(memcmp(corpus, corpus2, sizeof corpus) == 0 && nex2 == nex, "hostile generator deterministic");
    size_t nf2 = replay(corpus2, n, hf2, 512, NULL);
    CHECK(nf2 == nf && memcmp(hf1, hf2, sizeof(ArgusFinding) * (nf < 512 ? nf : 512)) == 0,
          "findings byte-identical across replays");
    for (uint64_t seed = 2; seed <= 5; seed++) {
        n = argus_corpus_hostile(corpus, CORPUS_N, seed, ex, 512, &nex);
        nf = replay(corpus, n, hf1, 512, NULL);
        int ok = nf == nex;
        for (size_t i = 0; ok && i < nf; i++)
            ok = hf1[i].sequence == ex[i].sequence && hf1[i].code == ex[i].code;
        CHECK(ok, "hostile seed %llu: expected %zu detected %zu", (unsigned long long)seed, nex, nf);
    }
}

int main(void)
{
    t_table();
    t_runner();
    t_forged();
    t_stale();
    t_revoked();
    t_artifact();
    t_signature();
    t_lease();
    t_machine();
    t_effect();
    t_world();
    t_quarantine();
    t_subject();
    t_trust();
    t_apply();
    t_v11_cap0();
    t_v11_summary();
    t_v11_world_stores();
    t_benign();
    t_hostile();

    printf("per-detector cases (positive/negative):\n");
    for (size_t k = 0; k < argus_hard_detector_count; k++) {
        uint16_t d = argus_hard_detectors[k].id;
        printf("  %2u %-30s %d/%d\n", d, argus_hard_detectors[k].name, pos[d], neg[d]);
        CHECK(pos[d] >= 1 && neg[d] >= 2, "coverage for detector %u", d);
    }
    printf("%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("ARGUS_DETECT_FAIL\n");
        return 1;
    }
    printf("ARGUS_DETECT_PASS ARGUS_FALSE_POSITIVE_BASELINE(synthetic)=%zu\n", benign_findings_seed1);
    return 0;
}
