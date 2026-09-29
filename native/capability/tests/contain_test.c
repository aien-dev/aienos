/*
 * contain_test.c -- AEGIS containment gate (ARGUS-1 lane G): positive path,
 * hostile negatives for invariants I1-I5, receipts, determinism.
 *
 * The test plays the bridge: it sets the authority observer and forwards
 * every call to aienos_contain_lineage_observe, and it records receipts from
 * the gate sink. argus_abi.h is included only to prove the layout twin and
 * the mirrored constants; nothing from libargus is linked.
 */
#include "../aienos_capability.h"
#include "../aienos_contain.h"
#include "../../argus/argus_abi.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Layout twin and mirrors (compile time) ---- */
#define SAME_OFF(f) _Static_assert(offsetof(AienosContainRequest, f) == offsetof(ArgusContainmentRequest, f), "twin offset " #f)
SAME_OFF(incident_id); SAME_OFF(containment); SAME_OFF(severity); SAME_OFF(finding_code);
SAME_OFF(principal); SAME_OFF(target); SAME_OFF(machine_id); SAME_OFF(finding_digest);
SAME_OFF(request_id); SAME_OFF(finding_sequence); SAME_OFF(target_object);
SAME_OFF(target_rights); SAME_OFF(target_digest); SAME_OFF(flags); SAME_OFF(version);
SAME_OFF(reserved);
_Static_assert(sizeof(AienosContainRequest) == sizeof(ArgusContainmentRequest), "twin size");
_Static_assert(offsetof(AienosCapRef, generation) == offsetof(ArgusCapRef, generation), "capref");
_Static_assert(sizeof(AienosCapRef) == sizeof(ArgusCapRef), "capref size");
_Static_assert(AIENOS_CONTAIN_REQUEST_SIZE == ARGUS_CONTAIN_REQUEST_SIZE, "size");
_Static_assert(AIENOS_CONTAIN_REQUEST_VERSION == ARGUS_CONTAIN_REQUEST_VERSION, "version");
_Static_assert(AIENOS_CREQ_SYNTHETIC == ARGUS_CREQ_SYNTHETIC && AIENOS_CREQ_SATURATION == ARGUS_CREQ_SATURATION &&
               AIENOS_CREQ_KNOWN == ARGUS_CREQ_KNOWN, "flags");
_Static_assert((int)AIENOS_CONTAIN_GRANT == (int)ARGUS_CSTATUS_GRANT && (int)AIENOS_CONTAIN_DENY == (int)ARGUS_CSTATUS_DENY &&
               (int)AIENOS_CONTAIN_ESCALATE == (int)ARGUS_CSTATUS_ESCALATE && (int)AIENOS_CONTAIN_DONE == (int)ARGUS_CSTATUS_DONE &&
               (int)AIENOS_CONTAIN_PARTIAL == (int)ARGUS_CSTATUS_PARTIAL && (int)AIENOS_CONTAIN_FAILED == (int)ARGUS_CSTATUS_FAILED &&
               (int)AIENOS_CONTAIN_UNAVAILABLE == (int)ARGUS_CSTATUS_UNAVAILABLE &&
               (int)AIENOS_CONTAIN_FAILED_SCOPE == (int)ARGUS_CSTATUS_FAILED_SCOPE, "status");
_Static_assert((int)AIENOS_CONTAIN_KIND_DECIDED == (int)ARGUS_EV_CONTAINMENT_DECIDED &&
               (int)AIENOS_CONTAIN_KIND_EXECUTED == (int)ARGUS_EV_CONTAINMENT_EXECUTED, "kinds");
_Static_assert((int)AIENOS_CONTAIN_REVOKE_CAPABILITY == (int)ARGUS_CONTAIN_REVOKE_CAPABILITY &&
               (int)AIENOS_CONTAIN_FREEZE_PRINCIPAL == (int)ARGUS_CONTAIN_FREEZE_PRINCIPAL && /* stand-in */
               (int)AIENOS_CONTAIN_RESTRICT_PRINCIPAL == (int)ARGUS_CONTAIN_RESTRICT_PRINCIPAL &&
               (int)AIENOS_CONTAIN_TYPE_MAX == (int)ARGUS_CONTAIN_MAX, "types");
_Static_assert(ARGUS_CAP_RIGHT_REVOKE == AIENOS_CAP_RIGHT_REVOKE &&
               ARGUS_CAP_RIGHT_PRIVILEGED == AIENOS_CAP_RIGHT_PRIVILEGED, "rights mirrors");
_Static_assert(ARGUS_SUBJ_AEGIS == AIENOS_CONTAIN_SUBJ_AEGIS && ARGUS_SUBJ_AEGIS_ROOT == AIENOS_CONTAIN_SUBJ_AEGIS_ROOT &&
               AIENOS_CONTAIN_SUBJ != ARGUS_SUBJ_AEGIS && AIENOS_CONTAIN_SUBJ != ARGUS_SUBJ_AEGIS_ROOT, "subjects");
_Static_assert(AIENOS_CONTAIN_CAP_NONE == ARGUS_CAP_NONE, "cap none");

/* ---- Check plumbing ---- */
static int failures;
static int checks;
#define CHECK(c)                                                                      \
    do {                                                                              \
        checks++;                                                                     \
        if (!(c)) {                                                                   \
            failures++;                                                               \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);              \
        }                                                                             \
    } while (0)
static int inv_fail_mark;
static void inv_begin(void) { inv_fail_mark = failures; }
static void inv_end(const char *name) {
    printf("INV %s %s\n", name, failures == inv_fail_mark ? "PASS" : "FAIL");
}

/* ---- A bridge stand-in: observer log + gate feed + receipt log ---- */
#define LOG_MAX 4096
typedef struct {
    uint32_t op;
    int rc;
    int has;
    AienosCapEntry e;
} ObsRec;

typedef struct {
    AienosCapAdmin *admin;
    AienosCapView *view;
    AienosCapRef office;
    AienosContain *gate; /* set by aienos_contain_create before its mint */
    int feed;            /* forward observer calls to the gate */
    uint32_t nobs;
    ObsRec obs[LOG_MAX];
    uint32_t nrec;
    AienosContainReceipt rec[LOG_MAX];
    AienosContainTablePolicy policy;
    _Alignas(16) unsigned char mem[32 * 1024];
} Rig;

static void rig_observer(void *ctx, uint32_t op, const AienosCapEntry *e, int rc) {
    Rig *r = ctx;
    if (r->nobs < LOG_MAX) {
        ObsRec *o = &r->obs[r->nobs++];
        o->op = op;
        o->rc = rc;
        o->has = e != NULL;
        if (e) o->e = *e;
    }
    if (r->feed && r->gate) aienos_contain_lineage_observe(r->gate, op, e, rc);
}

static void rig_sink(void *ctx, const AienosContainReceipt *rc) {
    Rig *r = ctx;
    if (r->nrec < LOG_MAX) r->rec[r->nrec++] = *rc;
}

static void policy_all(Rig *r, uint32_t v) {
    for (uint32_t t = 0; t <= AIENOS_CONTAIN_TYPE_MAX; t++) r->policy.verdict[t] = v;
}

/* Starts an authority; optionally mints `pre` READ caps before the gate exists. */
static Rig *rig_new(int feed, int create_gate) {
    Rig *r = calloc(1, sizeof *r);
    if (!r || aienos_cap_start(&r->admin, &r->view) != AIENOS_CAP_OK) abort();
    aienos_cap_office(r->admin, &r->office);
    r->feed = feed;
    aienos_cap_set_observer(r->admin, rig_observer, r);
    policy_all(r, AIENOS_CONTAIN_GRANT);
    if (create_gate) {
        AienosContainAuthorizer az = {aienos_contain_table_decide, &r->policy};
        int rc = aienos_contain_create(&r->gate, r->mem, sizeof r->mem, r->admin, r->view,
                                       r->office, &az);
        if (rc != AIENOS_CONTAIN_OK) {
            fprintf(stderr, "create failed %d\n", rc);
            abort();
        }
        aienos_contain_set_sink(r->gate, rig_sink, r);
    }
    return r;
}

static void rig_free(Rig *r) {
    aienos_cap_set_observer(r->admin, NULL, NULL);
    if (r->gate) aienos_contain_destroy(r->gate);
    aienos_cap_stop(r->admin, r->view);
    free(r);
}

static AienosCapRef mint_root(Rig *r, uint32_t subject, uint32_t rights) {
    AienosCapMint m = {0, subject, 0x1000u + subject, rights, 0, {AIENOS_CAP_PARENT_NONE, 0}, r->office};
    AienosCapRef out = {AIENOS_CAP_PARENT_NONE, 0};
    int rc = aienos_cap_mint(r->admin, &m, &out);
    if (rc != AIENOS_CAP_OK) fprintf(stderr, "mint_root rc %d\n", rc);
    return out;
}

static AienosCapRef mint_child(Rig *r, AienosCapRef parent, uint32_t subject) {
    AienosCapEntry pe;
    aienos_cap_inspect(r->view, parent, &pe);
    AienosCapMint m = {pe.subject, subject, pe.resource, AIENOS_CAP_RIGHT_READ, 0, parent, parent};
    AienosCapRef out = {AIENOS_CAP_PARENT_NONE, 0};
    int rc = aienos_cap_mint(r->admin, &m, &out);
    if (rc != AIENOS_CAP_OK) fprintf(stderr, "mint_child rc %d\n", rc);
    return out;
}

static uint64_t next_request_id = 1;

static AienosContainRequest req_make(uint8_t type, uint32_t principal, AienosCapRef target) {
    AienosContainRequest q;
    memset(&q, 0, sizeof q);
    q.incident_id = 77;
    q.containment = type;
    q.severity = 5;
    q.finding_code = 2; /* STALE_GENERATION */
    q.principal = principal;
    q.target = target;
    for (int i = 0; i < 32; i++) q.finding_digest[i] = (uint8_t)(0xA0 + i);
    q.request_id = next_request_id++;
    q.finding_sequence = 1000 + q.request_id;
    q.version = AIENOS_CONTAIN_REQUEST_VERSION;
    return q;
}

static AienosContainDecision submit(Rig *r, const AienosContainRequest *q) {
    uint8_t d[32];
    aienos_contain_request_digest(q, d);
    AienosContainDecision out;
    memset(&out, 0, sizeof out);
    CHECK(aienos_contain_submit(r->gate, q, d, &out) == AIENOS_CONTAIN_OK);
    return out;
}

static uint32_t count_obs(const Rig *r, uint32_t from, uint32_t op, int with_entry) {
    uint32_t n = 0;
    for (uint32_t i = from; i < r->nobs; i++)
        if (r->obs[i].op == op && (!with_entry || r->obs[i].has)) n++;
    return n;
}

static uint32_t count_subject_mints(const Rig *r, uint32_t from, uint32_t subject) {
    uint32_t n = 0;
    for (uint32_t i = from; i < r->nobs; i++)
        if (r->obs[i].op == AIENOS_CAP_OBS_MINT && r->obs[i].has && r->obs[i].e.subject == subject) n++;
    return n;
}

static int executor_intact(Rig *r, AienosCapRef ex0) {
    AienosCapRef ex;
    aienos_contain_executor(r->gate, &ex);
    AienosCapEntry e;
    return ex.cap_id == ex0.cap_id && ex.generation == ex0.generation &&
           aienos_cap_inspect(r->view, ex, &e) == AIENOS_CAP_OK && e.rights == AIENOS_CAP_RIGHT_REVOKE &&
           e.subject == AIENOS_CONTAIN_SUBJ && e.parent_id == AIENOS_CAP_PARENT_NONE;
}

static int is_live(Rig *r, AienosCapRef c) {
    AienosCapEntry e;
    return aienos_cap_inspect(r->view, c, &e) == AIENOS_CAP_OK && e.state == AIENOS_CAP_STATE_LIVE;
}

/* Receipt log is complete and ordered: every returned receipt reached the sink, seq +1 each. */
static int receipts_ordered(const Rig *r) {
    for (uint32_t i = 0; i < r->nrec; i++)
        if (r->rec[i].seq != (uint64_t)i + 1) return 0;
    return 1;
}

/* ---- SHA-256 and encoding ---- */
static int hex_eq(const uint8_t d[32], const char *hex) {
    char buf[65];
    for (int i = 0; i < 32; i++) snprintf(buf + 2 * i, 3, "%02x", d[i]);
    return strcmp(buf, hex) == 0;
}

static void test_sha_and_encoding(void) {
    uint8_t d[32];
    aienos_contain_sha256((const uint8_t *)"", 0, d);
    CHECK(hex_eq(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    aienos_contain_sha256((const uint8_t *)"abc", 3, d);
    CHECK(hex_eq(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const char *m2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    aienos_contain_sha256((const uint8_t *)m2, strlen(m2), d);
    CHECK(hex_eq(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    /* Wire offsets (spec 2): each field lands where the spec says. */
    AienosContainRequest q;
    memset(&q, 0, sizeof q);
    q.incident_id = 0x0102030405060708ull;
    q.containment = 1;
    q.severity = 4;
    q.finding_code = 0x0002;
    q.principal = 0x21222324;
    q.target.cap_id = 0x31;
    q.target.generation = 0x4142434445464748ull;
    for (int i = 0; i < 32; i++) {
        q.machine_id[i] = (uint8_t)(0xA0 + i);
        q.finding_digest[i] = (uint8_t)(0xC0 + i);
        q.target_digest[i] = (uint8_t)(0xE0 - i);
    }
    q.request_id = 0x5152535455565758ull;
    q.finding_sequence = 0x6162636465666768ull;
    q.target_object = 0x71727374;
    q.target_rights = 0x81828384;
    q.flags = 0x0003;
    q.version = 2;
    uint8_t b[AIENOS_CONTAIN_REQUEST_SIZE];
    aienos_contain_request_encode(&q, b);
    CHECK(b[0] == 0x08 && b[7] == 0x01 && b[8] == 1 && b[9] == 4 && b[10] == 2 && b[11] == 0);
    CHECK(b[12] == 0x24 && b[15] == 0x21 && b[16] == 0x31 && b[20] == 0x48 && b[27] == 0x41);
    CHECK(b[28] == 0xA0 && b[59] == 0xBF && b[60] == 0xC0 && b[91] == 0xDF);
    CHECK(b[92] == 0x58 && b[99] == 0x51 && b[100] == 0x68 && b[107] == 0x61);
    CHECK(b[108] == 0x74 && b[111] == 0x71 && b[112] == 0x84 && b[115] == 0x81);
    CHECK(b[116] == 0xE0 && b[147] == 0xC1 && b[148] == 3 && b[150] == 2 && b[151] == 0);
    aienos_contain_request_digest(&q, d);
    CHECK(hex_eq(d, "e7b9720638cb215683fe4a5944efb630fa96a023d1afb7dd575ceebbed1204a6"));

    /* 10,000 random round trips, byte identical. */
    uint64_t s = 0x9E3779B97F4A7C15ull;
    int ok = 1;
    for (int n = 0; n < 10000; n++) {
        uint8_t in[AIENOS_CONTAIN_REQUEST_SIZE], again[AIENOS_CONTAIN_REQUEST_SIZE];
        for (size_t i = 0; i < sizeof in; i++) {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            in[i] = (uint8_t)s;
        }
        in[8] = (uint8_t)(1 + in[8] % 10);
        in[9] = (uint8_t)(1 + in[9] % 5);
        in[148] &= 0x03; in[149] = 0; in[150] = 2; in[151] = 0;
        in[92] |= 1; in[100] |= 1;
        AienosContainRequest r;
        if (aienos_contain_request_decode(in, &r) != AIENOS_CONTAIN_OK) ok = 0;
        aienos_contain_request_encode(&r, again);
        if (memcmp(in, again, sizeof in) != 0) ok = 0;
    }
    CHECK(ok);
    printf("GATE CONTAIN_ENCODING %s sha256 KAT 3/3, round trips 10000\n", ok ? "PASS" : "FAIL");
}

/* ---- Positive path (I1 accepted leaf revoke, receipts, I1.f recovery) ---- */
static void test_positive_path(void) {
    Rig *r = rig_new(1, 1);
    AienosCapRef ex0;
    aienos_contain_executor(r->gate, &ex0);
    CHECK(ex0.cap_id != AIENOS_CONTAIN_CAP_NONE);
    CHECK(count_subject_mints(r, 0, AIENOS_CONTAIN_SUBJ) == 1); /* the executor, at create */
    uint32_t after_create = r->nobs;

    AienosCapRef keep = mint_root(r, 8, AIENOS_CAP_RIGHT_READ);
    AienosCapRef target = mint_root(r, 7, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE);
    AienosContainRequest q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, target);
    uint8_t dig[32];
    aienos_contain_request_digest(&q, dig);
    uint32_t obs0 = r->nobs;
    AienosContainDecision d = submit(r, &q);
    inv_begin();
    CHECK(d.kind == AIENOS_CONTAIN_KIND_DECIDED && d.status == AIENOS_CONTAIN_GRANT);
    CHECK(d.why == AIENOS_CONTAIN_WHY_POLICY_GRANT && d.decision_id == 1 && d.resource == 1);
    CHECK(d.seq == 1 && d.request_id == q.request_id && d.finding_sequence == q.finding_sequence);
    CHECK(d.target.cap_id == target.cap_id && d.target.generation == target.generation);
    CHECK(d.principal == 7 && d.actor == AIENOS_CONTAIN_ACTOR_GATE && d.type == AIENOS_CONTAIN_REVOKE_CAPABILITY);
    CHECK(d.executor.cap_id == ex0.cap_id && d.executor.generation == ex0.generation);
    CHECK(memcmp(d.request_digest, dig, 32) == 0);
    CHECK(count_obs(r, obs0, AIENOS_CAP_OBS_REVOKE, 0) == 0); /* deciding changes nothing */

    AienosContainResult x;
    CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_OK);
    CHECK(x.kind == AIENOS_CONTAIN_KIND_EXECUTED && x.status == AIENOS_CONTAIN_DONE);
    CHECK(x.resource == 1 && x.rc == 0 && x.seq == 2 && x.decision_id == d.decision_id);
    CHECK(memcmp(x.request_digest, dig, 32) == 0 && x.target.generation == target.generation);
    CHECK(count_obs(r, obs0, AIENOS_CAP_OBS_REVOKE, 1) == 1);
    uint32_t last = r->nobs - 1;
    CHECK(r->obs[last].op == AIENOS_CAP_OBS_REVOKE && r->obs[last].e.cap_id == target.cap_id &&
          r->obs[last].e.generation == target.generation);
    CHECK(aienos_cap_validate(r->view, target, 7, 0x1007u, AIENOS_CAP_RIGHT_READ, NULL) == AIENOS_CAP_ERR_REVOKED);
    CHECK(aienos_cap_validate(r->view, keep, 8, 0x1008u, AIENOS_CAP_RIGHT_READ, NULL) == AIENOS_CAP_OK);
    CHECK(is_live(r, r->office) && executor_intact(r, ex0));
    CHECK(r->nrec == 2 && receipts_ordered(r) && memcmp(&r->rec[0], &d, sizeof d) == 0 &&
          memcmp(&r->rec[1], &x, sizeof x) == 0);
    inv_end("I1.a accepted-leaf-revoke");

    /* I1.f recoverable: the operator re-mints through the office. */
    inv_begin();
    AienosCapRef again = mint_root(r, 7, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_WRITE);
    CHECK(aienos_cap_validate(r->view, again, 7, 0x1007u, AIENOS_CAP_RIGHT_READ, NULL) == AIENOS_CAP_OK);
    CHECK(count_subject_mints(r, after_create, AIENOS_CONTAIN_SUBJ) == 0);
    inv_end("I1.f re-mint-recovers");

    /* Second execute of the same GRANT: refused and announced, still one revoke. */
    inv_begin();
    uint32_t o1 = r->nobs;
    CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_ERR_REFUSED);
    CHECK(x.status == AIENOS_CONTAIN_FAILED && x.why == AIENOS_CONTAIN_WHY_DECISION_REPLAY &&
          (x.gate_flags & AIENOS_CONTAIN_RF_REFUSED_CALL) && r->nrec == 3);
    CHECK(count_obs(r, o1, AIENOS_CAP_OBS_REVOKE, 0) == 0);
    CHECK(aienos_contain_execute(r->gate, 999, &x) == AIENOS_CONTAIN_ERR_UNKNOWN && r->nrec == 4);
    inv_end("I1.e double-execute-refused");
    printf("GATE CONTAIN_POSITIVE %s footprint %zu bytes\n", failures ? "FAIL" : "PASS",
           aienos_contain_footprint());
    rig_free(r);
}

/* ---- I1 hostile ---- */
static void test_i1_hostile(void) {
    /* (a) cascade attempt: target has a live descendant -> ESCALATE 1114, nothing revoked. */
    inv_begin();
    Rig *r = rig_new(1, 1);
    AienosCapRef parent = mint_root(r, 7, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE);
    AienosCapRef child = mint_child(r, parent, 7);
    CHECK(child.cap_id != AIENOS_CAP_PARENT_NONE);
    uint32_t o0 = r->nobs;
    AienosContainDecision d = submit(r, &(AienosContainRequest){0});
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    AienosContainRequest q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, parent);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_NOT_LEAF);
    AienosContainResult x;
    CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_ERR_REFUSED);
    CHECK(count_obs(r, o0, AIENOS_CAP_OBS_REVOKE, 0) == 0 && is_live(r, parent) && is_live(r, child));
    inv_end("I1.a cascade-target-escalates");

    /* (b) descendant minted between decide and execute -> re-check refuses, zero revokes. */
    inv_begin();
    AienosCapRef leaf = mint_root(r, 9, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 9, leaf);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_GRANT);
    mint_child(r, leaf, 9);
    o0 = r->nobs;
    CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_OK);
    CHECK(x.status == AIENOS_CONTAIN_FAILED && x.why == AIENOS_CONTAIN_WHY_NOT_LEAF && x.resource == 0);
    CHECK(count_obs(r, o0, AIENOS_CAP_OBS_REVOKE, 0) == 0 && is_live(r, leaf));
    inv_end("I1.a recheck-before-revoke");

    /* (d) generation-bound: wrong or stale generation -> DENY 1104, no revoke. */
    inv_begin();
    AienosCapRef t = mint_root(r, 11, AIENOS_CAP_RIGHT_READ);
    AienosCapRef wrong = {t.cap_id, t.generation + 1};
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 11, wrong);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_TARGET_NOT_LIVE);
    CHECK(d.target.generation == wrong.generation);
    /* stale: revoke + reclaim + re-mint the slot, then ask for the old generation. */
    CHECK(aienos_cap_revoke(r->admin, r->office, t) == AIENOS_CAP_OK);
    CHECK(aienos_cap_reclaim(r->admin, r->office, t.cap_id) == AIENOS_CAP_OK);
    AienosCapRef t2 = mint_root(r, 11, AIENOS_CAP_RIGHT_READ);
    CHECK(t2.cap_id == t.cap_id && t2.generation > t.generation);
    o0 = r->nobs;
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 11, t);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_TARGET_NOT_LIVE);
    CHECK(count_obs(r, o0, AIENOS_CAP_OBS_REVOKE, 0) == 0 && is_live(r, t2));
    /* generation checked again at execute: granted at g, slot moved on before execute. */
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 11, t2);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_GRANT);
    CHECK(aienos_cap_revoke(r->admin, r->office, t2) == AIENOS_CAP_OK);
    CHECK(aienos_cap_reclaim(r->admin, r->office, t2.cap_id) == AIENOS_CAP_OK);
    AienosCapRef t3 = mint_root(r, 11, AIENOS_CAP_RIGHT_READ);
    o0 = r->nobs;
    CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_OK);
    CHECK(x.status == AIENOS_CONTAIN_FAILED && x.why == AIENOS_CONTAIN_WHY_TARGET_NOT_LIVE);
    CHECK(count_obs(r, o0, AIENOS_CAP_OBS_REVOKE, 0) == 0 && is_live(r, t3));
    inv_end("I1.d generation-bound");

    /* (e) not auto-eligible: SATURATION or SYNTHETIC -> ESCALATE 1116 even if policy grants. */
    inv_begin();
    AienosCapRef s1 = mint_root(r, 12, AIENOS_CAP_RIGHT_READ);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 12, s1);
    q.flags = AIENOS_CREQ_SATURATION;
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_NOT_AUTO_ELIGIBLE);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 12, s1);
    q.flags = AIENOS_CREQ_SYNTHETIC;
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_NOT_AUTO_ELIGIBLE);
    /* subject mismatch -> DENY 1105 */
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 13, s1);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_SUBJECT_MISMATCH);
    /* privileged target, and ordinary cap of a subject that holds a privileged cap -> DENY 1103 */
    AienosCapRef priv = mint_root(r, 14, AIENOS_CAP_RIGHT_REVOKE);
    AienosCapRef ord = mint_root(r, 14, AIENOS_CAP_RIGHT_READ);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 14, priv);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 14, ord);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 0, ord); /* principal unset: still protected */
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
    /* policy DENY / ESCALATE are honoured */
    policy_all(r, AIENOS_CONTAIN_DENY);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 12, s1);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_POLICY_DENY);
    policy_all(r, AIENOS_CONTAIN_ESCALATE);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 12, s1);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_POLICY_ESCALATE);
    policy_all(r, AIENOS_CONTAIN_GRANT);
    CHECK(is_live(r, s1) && is_live(r, priv) && is_live(r, ord));
    inv_end("I1.a sweep-not-auto");
    rig_free(r);

    /* (c) forced cascade via seam: a child appears after the re-check -> FAILED_SCOPE, inert. */
    inv_begin();
    r = rig_new(1, 1);
    AienosCapRef c = mint_root(r, 7, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, c);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_GRANT);
    struct { Rig *r; AienosCapRef p; } hctx = {r, c};
    void hook(void *ctx);
    AienosContainSeams seams = {0, hook, &hctx, NULL, NULL};
    CHECK(aienos_contain_set_seams(r->gate, &seams, NULL, r->office) == AIENOS_CONTAIN_ERR_REFUSED);
    CHECK(aienos_contain_set_seams(r->gate, &seams, r->admin, r->office) == AIENOS_CONTAIN_OK);
    o0 = r->nobs;
    CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_OK);
    CHECK(x.status == AIENOS_CONTAIN_FAILED_SCOPE && (x.resource & 0xFFFFFFFFu) == 2 && x.rc == 0);
    CHECK((x.gate_flags & AIENOS_CONTAIN_RF_INERT) && (x.gate_flags & AIENOS_CONTAIN_RF_SEAM));
    CHECK(aienos_contain_inert(r->gate) == 1 && count_obs(r, o0, AIENOS_CAP_OBS_REVOKE, 1) == 2);
    aienos_contain_set_seams(r->gate, NULL, r->admin, r->office);
    AienosCapRef n1 = mint_root(r, 7, AIENOS_CAP_RIGHT_READ);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, n1);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_LINEAGE_UNTRUSTED &&
          (d.gate_flags & AIENOS_CONTAIN_RF_INERT));
    inv_end("I1.b forced-cascade-goes-inert");
    rig_free(r);

    /* Lineage honesty: a target minted before the gate, an unwired feed, an epoch bump. */
    inv_begin();
    r = rig_new(1, 0);
    AienosCapRef early = mint_root(r, 7, AIENOS_CAP_RIGHT_READ);
    AienosContainAuthorizer az = {aienos_contain_table_decide, &r->policy};
    CHECK(aienos_contain_create(&r->gate, r->mem, sizeof r->mem, r->admin, r->view, r->office, &az) == AIENOS_CONTAIN_OK);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, early);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_LINEAGE_UNTRUSTED);
    AienosCapRef late = mint_root(r, 7, AIENOS_CAP_RIGHT_READ);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, late);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_GRANT);
    CHECK(aienos_cap_bump_epoch(r->admin, r->office) == AIENOS_CAP_OK);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, late);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_LINEAGE_UNTRUSTED);
    rig_free(r);
    r = rig_new(0, 1); /* feed not wired: the gate never saw its own executor mint */
    AienosCapRef nf = mint_root(r, 7, AIENOS_CAP_RIGHT_READ);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, nf);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_LINEAGE_UNTRUSTED);
    CHECK(is_live(r, nf));
    inv_end("I1.a lineage-must-be-seen");
    rig_free(r);
}

void hook(void *ctx) {
    struct { Rig *r; AienosCapRef p; } *h = ctx;
    mint_child(h->r, h->p, 7);
}

/* ---- I5.b / root and admin targets, protection layers ---- */
static void test_protected(void) {
    inv_begin();
    Rig *r = rig_new(1, 1);
    AienosCapRef ex0;
    aienos_contain_executor(r->gate, &ex0);
    uint32_t o0 = r->nobs;
    AienosContainRequest q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 0, r->office);
    AienosContainDecision d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, AIENOS_CONTAIN_SUBJ, ex0);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 0, ex0);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
    uint32_t subs[3] = {AIENOS_CONTAIN_SUBJ_AEGIS, AIENOS_CONTAIN_SUBJ_AEGIS_ROOT, AIENOS_CONTAIN_SUBJ};
    for (int i = 0; i < 3; i++) {
        AienosCapRef c = mint_root(r, subs[i], AIENOS_CAP_RIGHT_READ);
        q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, subs[i], c);
        d = submit(r, &q);
        CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
        q = req_make(AIENOS_CONTAIN_FREEZE_PRINCIPAL, subs[i], (AienosCapRef){AIENOS_CONTAIN_CAP_NONE, 0}); /* stand-in type */
        d = submit(r, &q);
        CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
    }
    CHECK(count_obs(r, o0, AIENOS_CAP_OBS_REVOKE, 0) == 0 && is_live(r, r->office) && executor_intact(r, ex0));
    inv_end("I5.b protected-targets-deny");

    /* Layer 3 alone (protected list off by seam): the authority refuses the office, -15. */
    inv_begin();
    AienosContainSeams seams = {AIENOS_CONTAIN_SEAM_NO_PROTECTED, NULL, NULL, NULL, NULL};
    CHECK(aienos_contain_set_seams(r->gate, &seams, r->admin, r->office) == AIENOS_CONTAIN_OK);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 0, r->office);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_GRANT && (d.gate_flags & AIENOS_CONTAIN_RF_SEAM));
    AienosContainResult x;
    CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_OK);
    CHECK(x.status == AIENOS_CONTAIN_FAILED && x.rc == AIENOS_CAP_ERR_UNAUTHORIZED && x.resource == (1ull << 32));
    CHECK(is_live(r, r->office) && executor_intact(r, ex0) && !aienos_contain_inert(r->gate));
    aienos_contain_set_seams(r->gate, NULL, r->admin, r->office);
    inv_end("I5.b layer3-office-refused");
    rig_free(r);
}

/* ---- I3: whole-system never autonomous; budget ---- */
static void test_i3(void) {
    inv_begin();
    Rig *r = rig_new(1, 1);
    uint32_t o0 = r->nobs;
    for (uint8_t t = 2; t <= AIENOS_CONTAIN_TYPE_MAX; t++) {
        AienosContainRequest q = req_make(t, 20 + t, (AienosCapRef){AIENOS_CONTAIN_CAP_NONE, 0});
        AienosContainDecision d = submit(r, &q);
        CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_NOT_AUTO_ELIGIBLE);
        AienosContainResult x;
        CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_ERR_REFUSED);
        CHECK(x.status != AIENOS_CONTAIN_DONE);
    }
    /* No encodable type outside 1..10 */
    AienosContainRequest q = req_make(0, 5, (AienosCapRef){AIENOS_CONTAIN_CAP_NONE, 0});
    CHECK(submit(r, &q).why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    q = req_make(11, 5, (AienosCapRef){AIENOS_CONTAIN_CAP_NONE, 0});
    CHECK(submit(r, &q).why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    CHECK(count_obs(r, o0, AIENOS_CAP_OBS_REVOKE, 0) == 0 && count_obs(r, o0, AIENOS_CAP_OBS_MINT, 0) == 0);
    inv_end("I3.c non-revoke-types-never-granted");
    rig_free(r);

    /* Storm on distinct leaf caps: at most 8 executed per 64 decisions. */
    inv_begin();
    r = rig_new(1, 1);
    AienosCapRef caps[200];
    for (int i = 0; i < 200; i++) caps[i] = mint_root(r, 100 + (uint32_t)i, AIENOS_CAP_RIGHT_READ);
    uint32_t per_window[8] = {0};
    uint32_t executed = 0, budget_esc = 0;
    o0 = r->nobs;
    for (int i = 0; i < 200; i++) {
        q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 100 + (uint32_t)i, caps[i]);
        AienosContainDecision d = submit(r, &q);
        if (d.status == AIENOS_CONTAIN_GRANT) {
            AienosContainResult x;
            aienos_contain_execute(r->gate, d.decision_id, &x);
            if (x.status == AIENOS_CONTAIN_DONE) {
                executed++;
                per_window[(d.decision_id - 1) / 64]++;
            }
        } else {
            CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_BUDGET);
            budget_esc++;
        }
    }
    for (int w = 0; w < 4; w++) CHECK(per_window[w] <= AIENOS_CONTAIN_BUDGET);
    CHECK(executed == 32 && budget_esc == 168);
    CHECK(count_obs(r, o0, AIENOS_CAP_OBS_REVOKE, 1) == executed);
    CHECK(count_obs(r, o0, AIENOS_CAP_OBS_MINT, 0) == 0);
    inv_end("I3.b budget-8-per-64");
    printf("GATE CONTAIN_BUDGET %s executed %u escalated %u of 200\n",
           executed == 32 ? "PASS" : "FAIL", executed, budget_esc);
    rig_free(r);
}

/* ---- I2: the stand-in type is never executed, never reported done ---- */
static void test_i2(void) {
    inv_begin();
    Rig *r = rig_new(1, 1);
    AienosCapRef c = mint_root(r, 7, AIENOS_CAP_RIGHT_READ);
    AienosContainRequest q = req_make(AIENOS_CONTAIN_FREEZE_PRINCIPAL, 7, c); /* stand-in type */
    AienosContainDecision d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_NOT_AUTO_ELIGIBLE);
    printf("SYNTHETIC-STAND-IN type %u decided %u why %u (recorded only; nothing is suspended)\n",
           (unsigned)q.containment, (unsigned)d.status, (unsigned)d.why);
    uint8_t wrong[AIENOS_CONTAIN_SECRET_LEN];
    memset(wrong, 0x5A, sizeof wrong);
    AienosContainDecision h;
    CHECK(aienos_contain_resolve(r->gate, d.decision_id, 1, wrong, &h) == AIENOS_CONTAIN_ERR_REFUSED);
    CHECK(h.why == AIENOS_CONTAIN_WHY_BAD_SECRET && h.status == AIENOS_CONTAIN_ESCALATE &&
          (h.gate_flags & AIENOS_CONTAIN_RF_REFUSED_CALL) && h.actor == AIENOS_CONTAIN_ACTOR_OFFICE);
    CHECK(aienos_contain_resolve(r->gate, d.decision_id, 1, NULL, &h) == AIENOS_CONTAIN_ERR_REFUSED);
    CHECK(aienos_contain_resolve(r->gate, 4242, 1, wrong, &h) == AIENOS_CONTAIN_ERR_UNKNOWN);
    AienosContainResult x;
    CHECK(aienos_contain_execute(r->gate, d.decision_id, &x) == AIENOS_CONTAIN_ERR_REFUSED);
    printf("SYNTHETIC-STAND-IN type %u execute status %u (never DONE)\n", (unsigned)q.containment,
           (unsigned)x.status);
    int any_done = 0;
    for (uint32_t i = 0; i < r->nrec; i++)
        if (r->rec[i].status == AIENOS_CONTAIN_DONE || r->rec[i].status == AIENOS_CONTAIN_PARTIAL) any_done = 1;
    CHECK(!any_done && is_live(r, c) && receipts_ordered(r));
    inv_end("I2 stand-in-never-done");
    rig_free(r);
}

/* ---- I5: no self-expansion; replay; malformed; second create; executor gone ---- */
static void test_i5_and_replay(void) {
    inv_begin();
    Rig *r = rig_new(1, 1);
    AienosCapRef ex0;
    aienos_contain_executor(r->gate, &ex0);
    uint32_t after_create = r->nobs;
    /* Self-grant shapes: rights on a revoke, unknown rights on restrict, executor / own subject. */
    AienosCapRef c = mint_root(r, 7, AIENOS_CAP_RIGHT_READ);
    AienosContainRequest q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, c);
    q.target_rights = AIENOS_CAP_RIGHT_MINT;
    CHECK(submit(r, &q).why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    q = req_make(AIENOS_CONTAIN_RESTRICT_PRINCIPAL, 7, c);
    q.target_rights = 0x80000000u;
    CHECK(submit(r, &q).why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    q = req_make(AIENOS_CONTAIN_RESTRICT_PRINCIPAL, AIENOS_CONTAIN_SUBJ, ex0);
    q.target_rights = AIENOS_CAP_RIGHT_REVOKE;
    CHECK(submit(r, &q).why == AIENOS_CONTAIN_WHY_PROTECTED_TARGET);
    /* Second create for the same authority: refused, no mint. */
    static _Alignas(16) unsigned char mem2[32 * 1024];
    AienosContain *g2 = NULL;
    AienosContainAuthorizer az = {aienos_contain_table_decide, &r->policy};
    uint32_t o0 = r->nobs;
    CHECK(aienos_contain_create(&g2, mem2, sizeof mem2, r->admin, r->view, r->office, &az) == AIENOS_CONTAIN_ERR_EXISTS);
    CHECK(g2 == NULL && r->nobs == o0);
    CHECK(count_subject_mints(r, after_create, AIENOS_CONTAIN_SUBJ) == 0 && executor_intact(r, ex0));
    inv_end("I5.a no-self-expansion-second-create-refused");

    /* Replay, tamper, malformed, oversized. */
    inv_begin();
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, c);
    policy_all(r, AIENOS_CONTAIN_ESCALATE);
    AienosContainDecision d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE);
    d = submit(r, &q); /* same bytes, same digest */
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_REPLAYED_REQUEST);
    AienosContainRequest older = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, c);
    AienosContainRequest newer = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, c);
    CHECK(submit(r, &newer).status == AIENOS_CONTAIN_ESCALATE);
    CHECK(submit(r, &older).why == AIENOS_CONTAIN_WHY_REPLAYED_REQUEST);
    /* tampered after digest */
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, c);
    uint8_t dig[32];
    aienos_contain_request_digest(&q, dig);
    q.target.generation ^= 1;
    CHECK(aienos_contain_submit(r->gate, &q, dig, &d) == AIENOS_CONTAIN_OK);
    CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    /* malformed fields */
    for (int k = 0; k < 8; k++) {
        q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, c);
        switch (k) {
        case 0: q.version = 1; break;
        case 1: q.reserved = 1; break;
        case 2: q.flags = 0x4; break;
        case 3: q.request_id = 0; break;
        case 4: q.finding_sequence = 0; break;
        case 5: q.severity = 0; break;
        case 6: q.severity = 6; break;
        case 7: q.target.cap_id = AIENOS_CAP_MAX; break;
        }
        d = submit(r, &q);
        CHECK(d.status == AIENOS_CONTAIN_DENY && d.why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    }
    /* canonical bytes: oversized, short, good */
    uint8_t big[AIENOS_CONTAIN_REQUEST_SIZE + 1];
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, c);
    aienos_contain_request_encode(&q, big);
    big[AIENOS_CONTAIN_REQUEST_SIZE] = 0;
    CHECK(aienos_contain_submit_bytes(r->gate, big, sizeof big, &d) == AIENOS_CONTAIN_OK && d.why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    CHECK(aienos_contain_submit_bytes(r->gate, big, AIENOS_CONTAIN_REQUEST_SIZE - 1, &d) == AIENOS_CONTAIN_OK && d.why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    CHECK(aienos_contain_submit_bytes(r->gate, big, 0, &d) == AIENOS_CONTAIN_OK && d.why == AIENOS_CONTAIN_WHY_BAD_REQUEST);
    CHECK(aienos_contain_submit_bytes(r->gate, big, AIENOS_CONTAIN_REQUEST_SIZE, &d) == AIENOS_CONTAIN_OK &&
          d.status == AIENOS_CONTAIN_ESCALATE && d.request_id == q.request_id);
    CHECK(is_live(r, c) && receipts_ordered(r));
    inv_end("I5.d replay-tamper-malformed-refused-and-receipted");

    /* Executor revoked by the operator: gate never re-mints, escalates, execute UNAVAILABLE. */
    inv_begin();
    policy_all(r, AIENOS_CONTAIN_GRANT);
    AienosCapRef c2 = mint_root(r, 8, AIENOS_CAP_RIGHT_READ);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 8, c2);
    AienosContainDecision granted = submit(r, &q);
    CHECK(granted.status == AIENOS_CONTAIN_GRANT);
    CHECK(aienos_cap_revoke(r->admin, r->office, ex0) == AIENOS_CAP_OK);
    o0 = r->nobs;
    AienosContainResult x;
    CHECK(aienos_contain_execute(r->gate, granted.decision_id, &x) == AIENOS_CONTAIN_OK);
    CHECK(x.status == AIENOS_CONTAIN_UNAVAILABLE && x.why == AIENOS_CONTAIN_WHY_NO_EXECUTOR);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 8, c2);
    d = submit(r, &q);
    CHECK(d.status == AIENOS_CONTAIN_ESCALATE && d.why == AIENOS_CONTAIN_WHY_NO_EXECUTOR);
    CHECK(r->nobs == o0 && is_live(r, c2));
    CHECK(count_subject_mints(r, after_create, AIENOS_CONTAIN_SUBJ) == 0);
    inv_end("I5.a executor-gone-no-remint");
    rig_free(r);
}

/* ---- I4: validate never reaches the gate ---- */
static void test_i4(void) {
    inv_begin();
    Rig *r = rig_new(1, 1);
    AienosCapRef c = mint_root(r, 7, AIENOS_CAP_RIGHT_READ);
    uint32_t n0 = r->nrec;
    for (int i = 0; i < 1000; i++) {
        aienos_cap_validate(r->view, c, 7, 0x1007u, AIENOS_CAP_RIGHT_READ, NULL);
        aienos_cap_validate(r->view, c, 99, 0x1007u, AIENOS_CAP_RIGHT_WRITE, NULL); /* denied */
    }
    CHECK(r->nrec == n0 && is_live(r, c));
    inv_end("I4 validate-never-reaches-gate");
    rig_free(r);
}

/* Destroy cannot enable a second executor mint from the same authority. */
static void test_destroy_recreate(void) {
    inv_begin();
    Rig *r = rig_new(1, 1);
    AienosCapRef ex;
    CHECK(aienos_contain_executor(r->gate, &ex) == AIENOS_CONTAIN_OK);
    uint32_t mints = count_subject_mints(r, 0, AIENOS_CONTAIN_SUBJ);
    CHECK(mints == 1);
    aienos_contain_destroy(r->gate);
    r->gate = NULL;
    static _Alignas(16) unsigned char mem[32 * 1024];
    AienosContain *again = NULL;
    AienosContainAuthorizer az = {aienos_contain_table_decide, &r->policy};
    uint32_t obs = r->nobs;
    CHECK(aienos_contain_create(&again, mem, sizeof mem, r->admin, r->view, r->office, &az) ==
          AIENOS_CONTAIN_ERR_EXISTS);
    CHECK(again == NULL && r->nobs == obs);
    CHECK(count_subject_mints(r, 0, AIENOS_CONTAIN_SUBJ) == mints);
    AienosCapEntry entry;
    CHECK(aienos_cap_inspect(r->view, ex, &entry) == AIENOS_CAP_OK &&
          entry.state == AIENOS_CAP_STATE_LIVE && entry.rights == AIENOS_CAP_RIGHT_REVOKE);
    inv_end("I5.a destroy-does-not-enable-remint");
    rig_free(r);
}

/* ---- Determinism: same request sequence -> same receipts ---- */
typedef struct {
    uint32_t n;
    AienosContainReceipt rec[256];
} Run;

static void scenario(Run *out) {
    next_request_id = 1;
    Rig *r = rig_new(1, 1);
    uint64_t base = r->office.generation;
    AienosCapRef leaf = mint_root(r, 7, AIENOS_CAP_RIGHT_READ);
    AienosCapRef par = mint_root(r, 9, AIENOS_CAP_RIGHT_READ | AIENOS_CAP_RIGHT_DELEGATE);
    mint_child(r, par, 9);
    AienosContainRequest q;
    AienosContainDecision d;
    AienosContainResult x;
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 7, leaf); d = submit(r, &q);
    aienos_contain_execute(r->gate, d.decision_id, &x);
    aienos_contain_execute(r->gate, d.decision_id, &x);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 9, par); submit(r, &q);
    q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 0, r->office); submit(r, &q);
    submit(r, &q);
    q = req_make(AIENOS_CONTAIN_FREEZE_PRINCIPAL, 41, (AienosCapRef){AIENOS_CONTAIN_CAP_NONE, 0}); submit(r, &q); /* stand-in */
    q = req_make(AIENOS_CONTAIN_QUARANTINE_MACHINE, 5, (AienosCapRef){AIENOS_CONTAIN_CAP_NONE, 0}); submit(r, &q);
    for (int i = 0; i < 20; i++) {
        AienosCapRef c = mint_root(r, 50 + (uint32_t)i, AIENOS_CAP_RIGHT_READ);
        q = req_make(AIENOS_CONTAIN_REVOKE_CAPABILITY, 50 + (uint32_t)i, c);
        d = submit(r, &q);
        if (d.status == AIENOS_CONTAIN_GRANT) aienos_contain_execute(r->gate, d.decision_id, &x);
    }
    out->n = r->nrec < 256 ? r->nrec : 256;
    for (uint32_t i = 0; i < out->n; i++) {
        AienosContainReceipt c = r->rec[i];
        /* Each authority starts on its own boot generation: compare generations relative to it,
         * and digests (which cover the generation) by recomputation, not across runs. */
        if (c.target.cap_id < AIENOS_CAP_MAX) c.target.generation -= base;
        c.executor.generation -= base;
        memset(c.request_digest, 0, sizeof c.request_digest);
        out->rec[i] = c;
    }
    rig_free(r);
}

static void test_determinism(void) {
    inv_begin();
    static Run a, b;
    scenario(&a);
    scenario(&b);
    CHECK(a.n == b.n && a.n > 20);
    CHECK(memcmp(a.rec, b.rec, a.n * sizeof a.rec[0]) == 0);
    for (uint32_t i = 0; i < a.n && i < b.n; i++)
        if (memcmp(&a.rec[i], &b.rec[i], sizeof a.rec[0]) != 0) {
            const unsigned char *pa = (const void *)&a.rec[i], *pb = (const void *)&b.rec[i];
            for (size_t k = 0; k < sizeof a.rec[0]; k++)
                if (pa[k] != pb[k]) fprintf(stderr, "DET diff receipt %u byte %zu\n", i, k);
        }
    inv_end("DET same-requests-same-receipts");
    printf("GATE CONTAIN_DETERMINISM %s receipts %u\n", failures == inv_fail_mark ? "PASS" : "FAIL", a.n);
}

int main(void) {
    test_sha_and_encoding();
    test_positive_path();
    test_i1_hostile();
    test_protected();
    test_i3();
    test_i2();
    test_i5_and_replay();
    test_i4();
    test_destroy_recreate();
    test_determinism();
    CHECK(aienos_contain_footprint() <= 24u * 1024u);
    printf("contain_test: %d checks, %d failures, footprint %zu bytes (<= 24576)\n", checks, failures,
           aienos_contain_footprint());
    printf("GATE CONTAIN_TEST %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
