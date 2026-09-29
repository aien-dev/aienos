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

    stub_set_world(&st, 5, WD, 80);
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

/* Exactly one finding, with code `det`; checks the common fields. */
static void expect_only(uint16_t det, const ArgusEvent *e, const char *what)
{
    int rc = run(e);
    CHECK(rc == ARGUS_OK, "[%u %s] rc %d", det, what, rc);
    CHECK(NF == 1, "[%u %s] expected 1 finding, got %zu", det, what, NF);
    if (NF >= 1) {
        const ArgusFinding *f = &F[0];
        const ArgusDetector *d = &argus_hard_detectors[det - 1];
        CHECK(f->code == det, "[%u %s] code %u", det, what, f->code);
        CHECK(f->detector == det, "[%u %s] detector %u", det, what, f->detector);
        CHECK(f->confidence == ARGUS_CONF_DETERMINISTIC, "[%u %s] confidence", det, what);
        CHECK(f->sync_allowed == d->sync_allowed, "[%u %s] sync", det, what);
        CHECK(f->sequence == e->sequence, "[%u %s] sequence", det, what);
        CHECK(f->principal == e->principal, "[%u %s] principal", det, what);
        CHECK(f->cap_id == e->cap_id && f->cap_generation == e->cap_generation, "[%u %s] cap", det, what);
        CHECK(memcmp(f->machine_id, e->machine_id, 32) == 0, "[%u %s] machine", det, what);
        static const uint8_t zero[32];
        CHECK(memcmp(f->event_digest, zero, 32) == 0, "[%u %s] event_digest must stay zero", det, what);
    }
    pos[det]++;
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
    expect_only(1, &e, "producer reports forgery");
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
    e = use(ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0, 0, 0);
    expect_none(1, &e, "use with no cap reference");
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
    expect_only(2, &e, "producer reports stale gen");
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
    expect_only(5, &e, "signature failure (denied)");
    CHECK(F[0].severity == ARGUS_SEV_HIGH && F[0].containment == ARGUS_CONTAIN_REJECT_ARTIFACT, "d5 fields");
    e = mk(ARGUS_EV_SIGNATURE_FAILURE, ARGUS_OUTCOME_OK, 0);
    expect_only(5, &e, "signature failure (ok)");
    e = mk(ARGUS_EV_ARTIFACT_ADMITTED, ARGUS_OUTCOME_OK, AIENOS_CAP_ERR_RIGHTS);
    memcpy(e.evidence_digest, AU, 32);
    expect_only(5, &e, "admitted despite error code");

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

    reset();
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
    e = use(ARGUS_EV_EXTERNAL_EFFECT_REQUESTED, ARGUS_OUTCOME_OK, 0, 0, 0);
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
    stub_set_world(&st, UINT64_MAX, WD, 81);
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
    stub_set_world(&st, 0xFFFFFFFFull, WD, 90);
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
    e.object_id = ARGUS_TRUST_TRUSTED;
    expect_none(10, &e, "release from quarantine");
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

/* ---- table, mirrors, runner ------------------------------------------------ */

static void t_table(void)
{
    static const uint8_t sync[11] = { 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1 };
    static const uint8_t contain[11] = {
        0, ARGUS_CONTAIN_FREEZE_PRINCIPAL, ARGUS_CONTAIN_REVOKE_CAPABILITY, ARGUS_CONTAIN_FREEZE_PRINCIPAL,
        ARGUS_CONTAIN_REJECT_ARTIFACT, ARGUS_CONTAIN_REJECT_ARTIFACT, ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE,
        ARGUS_CONTAIN_REQUIRE_REATTESTATION, ARGUS_CONTAIN_PAUSE_EXTERNAL_EFFECTS, ARGUS_CONTAIN_RAISE_EFFECT_CLASS,
        ARGUS_CONTAIN_QUARANTINE_PROVIDER,
    };
    CHECK(argus_hard_detector_count == 10, "detector count %zu", argus_hard_detector_count);
    for (size_t i = 0; i < argus_hard_detector_count; i++) {
        const ArgusDetector *d = &argus_hard_detectors[i];
        CHECK(d->id == i + 1, "table order at %zu", i);
        CHECK(d->sync_allowed == sync[i + 1], "sync_allowed of %u", d->id);
        CHECK(d->containment == contain[i + 1], "containment of %u", d->id);
        CHECK(d->name != NULL && d->fn != NULL, "name/fn of %u", d->id);
    }
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

static void check_stream_shape(const ArgusEvent *evs, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        CHECK(evs[i].version == ARGUS_ABI_VERSION && evs[i].sequence == i + 1 && evs[i].kind != 0 &&
              evs[i].outcome >= 1 && evs[i].outcome <= ARGUS_OUTCOME_MAX && evs[i].flags == ARGUS_FLAG_SYNTHETIC,
              "stream shape at %zu", i);
    }
}

static size_t benign_findings_seed1;

static void t_benign(void)
{
    size_t kinds[ARGUS_EV_KIND_MAX + 1] = {0};
    size_t outcomes[4] = {0};
    size_t n = argus_corpus_benign(corpus, CORPUS_N, 1);
    CHECK(n == CORPUS_N, "benign size %zu", n);
    check_stream_shape(corpus, n);
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
    for (uint64_t seed = 2; seed <= 9; seed++) {
        n = argus_corpus_benign(corpus, CORPUS_N, seed);
        size_t f = replay(corpus, n, NULL, 0, NULL);
        CHECK(f == 0, "benign corpus seed %llu: %zu findings", (unsigned long long)seed, f);
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
    check_stream_shape(corpus, n);
    size_t exp_codes[ARGUS_F_MAX + 1] = {0}, got_codes[ARGUS_F_MAX + 1] = {0};
    for (size_t i = 0; i < nex; i++) exp_codes[ex[i].code]++;
    size_t nf = replay(corpus, n, hf1, 512, got_codes);
    CHECK(nf == nex, "hostile: expected %zu findings, detected %zu", nex, nf);
    size_t match = 0;
    for (size_t i = 0; i < nf && i < nex && i < 512; i++) {
        if (hf1[i].sequence == ex[i].sequence && hf1[i].code == ex[i].code) match++;
        else CHECK(0, "hostile mismatch at %zu: got (%llu,%u) want (%llu,%u)", i,
                   (unsigned long long)hf1[i].sequence, hf1[i].code, (unsigned long long)ex[i].sequence, ex[i].code);
    }
    printf("hostile corpus seed 1: %zu events, expected %zu, detected %zu, exact matches %zu; per code:", n, nex, nf, match);
    for (int c = 1; c <= 10; c++) {
        printf(" %d:%zu/%zu", c, got_codes[c], exp_codes[c]);
        CHECK(exp_codes[c] > 0, "hostile corpus injects code %d", c);
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
    t_benign();
    t_hostile();

    printf("per-detector cases (positive/negative):\n");
    for (int d = 1; d <= 10; d++) {
        printf("  %2d %-30s %d/%d\n", d, argus_hard_detectors[d - 1].name, pos[d], neg[d]);
        CHECK(pos[d] >= 1 && neg[d] >= 2, "coverage for detector %d", d);
    }
    printf("%d checks, %d failures\n", checks, failures);
    if (failures) {
        printf("ARGUS_DETECT_FAIL\n");
        return 1;
    }
    printf("ARGUS_DETECT_PASS ARGUS_FALSE_POSITIVE_BASELINE(synthetic)=%zu\n", benign_findings_seed1);
    return 0;
}
