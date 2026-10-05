/* test_continuity_subject_provision.c -- host tests of
 * svc/continuity_subject_provision.c (ALLEN genesis at identity provisioning;
 * ARCH-0035 / OS-0018, PROPOSED) over the REAL sealed Store in a file with the
 * real ck_rng over a mocked RNDR.
 *
 *   genesis       cs_provision writes identity + subject in ONE transaction of
 *                 four objects; reopened, both resolve; the subject is
 *                 sequence 1, bound to this root and agent, lineage and
 *                 provenance as requested
 *   exactly once  a second cs_provision is CR_ALREADY_PROVISIONED and writes
 *                 nothing; a standing intent then advances the chain (seq 2)
 *   refusals      zero provenance / lineage, bad origin, subject objects
 *                 without a root, a failing Store: nothing written
 *   no minting    a Store provisioned WITHOUT a subject (cr_provision alone)
 *                 resolves ABSENT and nothing here writes one
 *   power cuts    a cut at every Store checkpoint and at every block boundary
 *                 of the provisioning write leaves exactly the old state
 *                 (unprovisioned, no subject object) or exactly the new one
 *                 (identity WITH its genesis subject); never one without the
 *                 other
 * Mutant (Makefile continuity-subject-provision-mutants):
 *   CS_MUTANT_PROVISION_SPLIT_TXN  subject in a second transaction */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ck_test.h"
#include "continuity_resolve_sealed.h"
#include "continuity_subject_provision.h"
#include "disk_file.h"
#include "../argus/sha256.h"

#define CK_(c, ...)                                                            \
    do {                                                                       \
        ck_t_run++;                                                            \
        if (!(c)) {                                                            \
            ck_t_fail++;                                                       \
            printf("  FAIL %s:%d: %s: ", __FILE__, __LINE__, #c);              \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

#define A_UNITS 4u
#define S_UNITS 512u
#define IMG_BYTES ((size_t)(A_UNITS + S_UNITS) * 4096u)

static ss_workspace g_ws;
static ss_store g_s;
static disk_file g_f;
static disk_dev g_d;
static st_disk g_sd;
static st_dev g_sdev;
static ts_device g_tdev;
static ss_keys g_k;
static uint32_t g_bs;
static char g_path[256];
static struct cr_work g_w;
static struct cr_txwork g_tw;
static struct cr_view g_v, g_v2;
static struct cr_source g_src;
static struct cr_sink g_snk;
static struct cr_sealed_sink g_sk;
static struct cs_subject g_subj, g_subj2;
static uint8_t g_sid[32], g_sid2[32];
static const uint8_t RUUID[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
static uint8_t base_img[IMG_BYTES], snap_img[IMG_BYTES];
static struct cs_genesis G;

static int g_open;
static void dev_close(void)
{
    if (g_open) disk_file_close(&g_f);
    g_open = 0;
}
static int dev_open(int create)
{
    dev_close();
    uint32_t bpu = 4096u / g_bs;
    if (create) unlink(g_path);
    memset(&g_f, 0, sizeof g_f);
    if (disk_file_open(&g_f, &g_d, g_path, g_bs, (uint64_t)(A_UNITS + S_UNITS) * bpu, create) != 0) return -1;
    g_open = 1;
    if (st_disk_bind(&g_sd, &g_d, (uint64_t)A_UNITS * bpu, S_UNITS, &g_sdev) != 0) return -2;
    ss_ts_device(&g_d, &g_tdev);
    return 0;
}
static void make_keys(void)
{
    uint8_t kvol[32];
    memset(kvol, 0x77, 32);
    m5_subkeys sk;
    m5_derive_subkeys(kvol, M5_ID_TEST, 0, &sk);
    memset(&g_k, 0, sizeof g_k);
    g_k.identity_class = M5_ID_TEST;
    g_k.key_generation = 1;
    memcpy(g_k.k_root_auth, sk.k_root_auth, 32);
    memcpy(g_k.k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);
}

/* Counting sink in front of the sealed sink: how many Store transactions
 * the operation made, and how many objects the last one carried. */
static int g_tx, g_tx_objs, g_tx_kind24, g_fail_store;
static int count_transact(void *ctx, const struct cr_wobj *objs, size_t n)
{
    struct cr_sink *inner = ctx;
    g_tx++;
    g_tx_objs = (int)n;
    g_tx_kind24 = 0;
    for (size_t i = 0; i < n; i++) g_tx_kind24 += objs[i].kind == CC_KIND_SUBJECT;
    if (g_fail_store) return -42;
    return inner->transact(inner->ctx, objs, n);
}
static struct cr_sink g_sealed, g_count;
static void bind(st_hook hook)
{
    g_sk.s = &g_s;
    g_sk.hook = hook;
    g_sk.hook_arg = NULL;
    cr_bind_sealed(&g_src, &g_s);
    cr_bind_sealed_sink(&g_sealed, &g_sk);
    g_count.ctx = &g_sealed;
    g_count.transact = count_transact;
    g_snk = g_count;
    g_tx = g_tx_objs = g_tx_kind24 = 0;
}
static void fresh(void)
{
    CK_(dev_open(1) == 0, "rig create");
    CK_(ss_format(&g_sdev, &g_tdev, 0, RUUID, &g_k, &g_ws) == 0, "format");
    CK_(ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws) == 0, "open genesis");
    bind(NULL);
}
static int reopen(void)
{
    if (dev_open(0) != 0) return -9999;
    memset(&g_s, 0, sizeof g_s);
    int rc = ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws);
    bind(NULL);
    return rc;
}
static int file_load(uint8_t *dst)
{
    FILE *f = fopen(g_path, "rb");
    if (!f) return -1;
    size_t n = fread(dst, 1, IMG_BYTES, f);
    fclose(f);
    return n == IMG_BYTES ? 0 : -2;
}
static int file_store(const uint8_t *src)
{
    FILE *f = fopen(g_path, "wb");
    if (!f) return -1;
    size_t n = fwrite(src, 1, IMG_BYTES, f);
    fclose(f);
    return n == IMG_BYTES ? 0 : -2;
}
static void snapshot(void)
{
    dev_close();
    CK_(file_load(snap_img) == 0, "snapshot");
    CK_(reopen() == 0, "reopen after snapshot");
}
static int unchanged(void)
{
    static uint8_t now[IMG_BYTES];
    dev_close();
    int same = file_load(now) == 0 && memcmp(now, snap_img, IMG_BYTES) == 0;
    (void)reopen();
    return same;
}

/* ---- mocked RNDR ---- */
struct mock {
    int present;
    uint64_t ctr;
};
static struct mock g_m;
static struct ck_rng_ops g_ops;
static struct ck_rng g_rng;
static int m_present(void *c) { return ((struct mock *)c)->present; }
static int m_read(void *c, uint64_t *out)
{
    struct mock *m = c;
    uint64_t z = (m->ctr += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    *out = z ^ (z >> 31);
    return 1;
}
static void rng_init(uint64_t seed)
{
    g_m.present = 1;
    g_m.ctr = seed;
    g_ops.present = m_present;
    g_ops.read = m_read;
    g_ops.ctx = &g_m;
    memset(&g_rng, 0, sizeof g_rng);
    CK_(ck_rng_probe(&g_rng, &g_ops) == CK_RNG_OK, "rng probe");
}

static int do_cs_provision(const char **why, int *rc)
{
    return cs_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, CC_SOURCE_QUALIFICATION, &G, &g_v,
                        &g_subj, g_sid, why, rc);
}
static uint32_t count_kind24(void)
{
    uint32_t n = g_src.count(g_src.ctx), k = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint16_t kind = 0, ver = 0;
        if (g_src.entry(g_src.ctx, i, &kind, &ver) == 0 && kind == CC_KIND_SUBJECT) k++;
    }
    return k;
}

/* ---- 1. genesis ---- */
static void t_genesis(void)
{
    const char *why = NULL;
    int rc = 0;
    fresh();
    rng_init(11);
    int o = do_cs_provision(&why, &rc);
    CK_(o == CR_RESOLVED, "cs_provision: %s (%s rc=%d)", cr_outcome_name(o), why ? why : "-", rc);
    CK_(g_tx == 1, "exactly one Store transaction (%d)", g_tx);
    CK_(g_tx_objs == 4 && g_tx_kind24 == 1, "the transaction carries AgentRoot, AgentState, Manifest and the subject (%d objects, %d subject)",
        g_tx_objs, g_tx_kind24);
    CK_(g_subj.sequence == 1 && sv1_all_zero(g_subj.previous, 32), "genesis is sequence 1 with no previous");
    CK_(memcmp(g_subj.root, g_v.root_id, 32) == 0 && memcmp(g_subj.agent, g_v.root.agent_id, 32) == 0,
        "subject bound to this root and agent");
    CK_(memcmp(g_subj.cortex, G.cortex, 32) == 0, "memory lineage as requested");
    CK_(memcmp(g_subj.provenance, G.provenance, 32) == 0 && g_subj.origin == CS_ORIGIN_OPERATOR, "provenance and origin");
    CK_(g_subj.n_intents == 0 && g_subj.n_knowledge == 0, "no intents, no knowledge at genesis");

    /* Another process: reopen the image and resolve both chains. */
    dev_close();
    CK_(reopen() == 0, "reopen");
    CK_(cr_resolve(&g_src, &g_w, &g_v2, &why, &rc) == CR_RESOLVED, "identity resolves after reopen");
    CK_(memcmp(g_v2.root.agent_id, g_v.root.agent_id, 32) == 0, "same agent");
    CK_(cs_resolve(&g_src, &g_w, &g_v2, &g_subj2, g_sid2, &why, &rc) == CS_RESOLVED, "subject resolves: %s", why ? why : "-");
    CK_(memcmp(g_sid2, g_sid, 32) == 0 && g_subj2.sequence == 1, "same subject object, sequence 1");
    CK_(count_kind24() == 1, "exactly one subject object in the Store");
}

/* ---- 2. exactly once, then a standing intent ---- */
static void t_exactly_once(void)
{
    const char *why = NULL;
    int rc = 0;
    fresh();
    rng_init(12);
    CK_(do_cs_provision(&why, &rc) == CR_RESOLVED, "provision");
    snapshot();
    rng_init(13);
    int o = do_cs_provision(&why, &rc);
    CK_(o == CR_ALREADY_PROVISIONED, "second provisioning refused: %s", cr_outcome_name(o));
    CK_(g_tx == 0, "nothing sent to the Store");
    CK_(unchanged(), "image unchanged");
    CK_(count_kind24() == 1, "still one subject object");

    /* The standing intent through the ALLEN commit path. */
    CK_(cr_resolve(&g_src, &g_w, &g_v2, &why, &rc) == CR_RESOLVED, "resolve");
    CK_(cs_resolve(&g_src, &g_w, &g_v2, &g_subj2, g_sid2, &why, &rc) == CS_RESOLVED, "subject");
    uint8_t prov[32], iid[32];
    memset(prov, 0x31, 32);
    cs_subject_advance(&g_subj2, g_sid2, prov, CS_ORIGIN_OPERATOR);
    const uint64_t p[2] = {7, 1000};
    CK_(cs_subject_intend(&g_subj2, CS_INTENT_GOAL_LATENCY, p, iid, &why) == CC_OK, "intend");
    CK_(cs_commit(&g_src, &g_snk, &g_w, &g_v2, &g_subj2, g_sid, &why, &rc) == CS_RESOLVED, "commit seq 2: %s", why ? why : "-");
    dev_close();
    CK_(reopen() == 0, "reopen");
    CK_(cr_resolve(&g_src, &g_w, &g_v2, &why, &rc) == CR_RESOLVED, "resolve after reopen");
    CK_(cs_resolve(&g_src, &g_w, &g_v2, &g_subj, g_sid2, &why, &rc) == CS_RESOLVED, "subject after reopen");
    CK_(g_subj.sequence == 2 && memcmp(g_sid2, g_sid, 32) == 0, "head is the sequence-2 object");
    const struct cs_intent *a = cs_subject_active(&g_subj, CS_INTENT_GOAL_LATENCY, 7);
    CK_(a && memcmp(a->id, iid, 32) == 0 && a->payload[1] == 1000, "standing intent survives reopen");
    CK_(count_kind24() == 2, "two subject objects: genesis and one successor");
}

/* ---- 3. refusals: nothing written ---- */
static void t_refusals(void)
{
    const char *why = NULL;
    int rc = 0;
    struct cs_genesis keep = G;
    fresh();
    snapshot();
    rng_init(21);
    memset(G.provenance, 0, 32);
    CK_(do_cs_provision(&why, &rc) == CR_E_ARG && why && !strcmp(why, "subject genesis needs a provenance"), "zero provenance");
    G = keep;
    memset(G.cortex, 0, 32);
    CK_(do_cs_provision(&why, &rc) == CR_E_ARG && why && !strcmp(why, "subject genesis needs a memory lineage reference"), "zero lineage");
    G = keep;
    G.origin = 9;
    CK_(do_cs_provision(&why, &rc) == CR_E_ARG, "bad origin");
    G = keep;
    CK_(cs_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, CC_SOURCE_QUALIFICATION, NULL, &g_v, &g_subj, g_sid, &why, &rc) == CR_E_ARG,
        "null genesis");
    G = keep;
    fresh();
    snapshot();
    rng_init(22);
    g_fail_store = 1;
    int o = do_cs_provision(&why, &rc);
    g_fail_store = 0;
    CK_(o == CR_STORE, "failing Store: %s", cr_outcome_name(o));
    CK_(unchanged(), "failing Store: image unchanged");
    CK_(cr_resolve(&g_src, &g_w, &g_v2, &why, &rc) == CR_UNPROVISIONED && count_kind24() == 0, "still unprovisioned, no subject");

    /* A subject object with no agent root is never provisioned over. */
    fresh();
    {
        static struct cs_subject f;
        static uint8_t b[CS_MAX_BYTES];
        size_t len = 0;
        memset(&f, 0, sizeof f);
        memset(f.root, 0x44, 32);
        memset(f.agent, 0x45, 32);
        f.sequence = 1;
        memset(f.provenance, 0x46, 32);
        f.origin = CS_ORIGIN_OPERATOR;
        memset(f.cortex, 0x47, 32);
        CK_(cs_subject_encode(&f, b, sizeof b, &len, &why) == CC_OK, "encode orphan");
        struct cr_wobj ob = {CC_KIND_SUBJECT, CC_STORE_OBJECT_VERSION, b, len};
        CK_(g_sealed.transact(g_sealed.ctx, &ob, 1) == 0, "plant orphan subject");
    }
    snapshot();
    rng_init(23);
    o = do_cs_provision(&why, &rc);
    CK_(o == CR_CORRUPT && why && !strcmp(why, "subject objects without an agent root"), "orphan subject: %s (%s)",
        cr_outcome_name(o), why ? why : "-");
    CK_(g_tx == 0 && unchanged(), "orphan subject: nothing written");
}

/* ---- 4. a Store provisioned without a subject resolves ABSENT ---- */
static void t_absent_never_minted(void)
{
    const char *why = NULL;
    int rc = 0;
    fresh();
    rng_init(31);
    CK_(cr_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, CC_SOURCE_QUALIFICATION, &g_v, &why, &rc) == CR_RESOLVED,
        "identity-only provisioning");
    snapshot();
    CK_(cs_resolve(&g_src, &g_w, &g_v, &g_subj, g_sid, &why, &rc) == CS_ABSENT, "subject ABSENT");
    rng_init(32);
    CK_(do_cs_provision(&why, &rc) == CR_ALREADY_PROVISIONED, "cs_provision does not add a subject to a provisioned identity");
    CK_(unchanged() && count_kind24() == 0, "nothing written; still no subject object");
}

/* ---- 5. power cuts during the provisioning write ---- */
static int g_cp_target, g_cp_fired;
static void cp_hook(void *arg, int cp)
{
    (void)arg;
    if (cp == g_cp_target && !g_cp_fired) {
        g_cp_fired = 1;
        disk_file_arm_cut(&g_f, 0);
    }
}
enum { CUT_CHECKPOINTS = 9 };
static const int CPS[CUT_CHECKPOINTS] = {ST_CP_BEFORE_FIRST_WRITE, ST_CP_AFTER_PAYLOAD_OBJECTS, ST_CP_AFTER_CATALOG,
                                         ST_CP_AFTER_COMMIT_RECORD, ST_CP_AFTER_FIRST_FLUSH,
                                         ST_CP_AFTER_INACTIVE_SUPERBLOCK, ST_CP_AFTER_FINAL_FLUSH,
                                         SS_CP_BEFORE_ANCHOR, SS_CP_AFTER_ANCHOR};
static const char *cp_name(int cp)
{
    return cp >= 100 ? (cp == SS_CP_BEFORE_ANCHOR ? "before_anchor" : "after_anchor") : st_checkpoint_name(cp);
}
static uint8_t g_agent_new[32], g_sid_new[32];

/* 1 = old (unprovisioned, no subject object), 2 = new (identity + its
 * genesis subject, the same objects as the uncut run), 0 = anything else. */
static int classify(const char *what)
{
    const char *why = NULL;
    int rc = reopen();
    CK_(rc == 0, "%s: reopen after the cut: %d", what, rc);
    if (rc) return 0;
    int o = cr_resolve(&g_src, &g_w, &g_v2, &why, &rc);
    if (o == CR_UNPROVISIONED) {
        uint32_t k = count_kind24();
        CK_(k == 0, "%s: unprovisioned but %u subject objects", what, k);
        return k == 0 ? 1 : 0;
    }
    if (o != CR_RESOLVED) {
        CK_(0, "%s: identity %s (%s)", what, cr_outcome_name(o), why ? why : "-");
        return 0;
    }
    int s = cs_resolve(&g_src, &g_w, &g_v2, &g_subj2, g_sid2, &why, &rc);
    int ok = s == CS_RESOLVED && g_subj2.sequence == 1 && memcmp(g_sid2, g_sid_new, 32) == 0 &&
             memcmp(g_v2.root.agent_id, g_agent_new, 32) == 0 && count_kind24() == 1;
    CK_(ok, "%s: identity present but subject %s (%s)", what, s == CS_ABSENT ? "ABSENT" : cr_outcome_name(s),
        why ? why : "-");
    return ok ? 2 : 0;
}

static void t_power_cuts(void)
{
    const char *why = NULL;
    int rc = 0, old = 0, neu = 0, bad = 0;
    fresh();
    dev_close();
    CK_(file_load(base_img) == 0, "save base");
    CK_(reopen() == 0, "reopen base");
    uint64_t w0 = g_f.blocks_written;
    rng_init(777);
    CK_(do_cs_provision(&why, &rc) == CR_RESOLVED, "uncut provisioning");
    uint64_t W = g_f.blocks_written - w0;
    memcpy(g_agent_new, g_v.root.agent_id, 32);
    memcpy(g_sid_new, g_sid, 32);
    dev_close();
    for (int i = 0; i < CUT_CHECKPOINTS; i++) {
        char what[96];
        snprintf(what, sizeof what, "bs=%u cp %s", g_bs, cp_name(CPS[i]));
        CK_(file_store(base_img) == 0, "restore");
        CK_(reopen() == 0, "reopen base");
        g_cp_target = CPS[i];
        g_cp_fired = 0;
        bind(cp_hook);
        rng_init(777);
        (void)do_cs_provision(&why, &rc);
        CK_(g_cp_fired == 1, "%s: checkpoint never reached", what);
        disk_file_disarm(&g_f);
        int v = classify(what);
        if (CPS[i] <= ST_CP_AFTER_FIRST_FLUSH) CK_(v == 1, "%s: expected unprovisioned", what);
        if (CPS[i] == ST_CP_AFTER_FINAL_FLUSH || CPS[i] >= SS_CP_BEFORE_ANCHOR) CK_(v == 2, "%s: expected identity + subject", what);
        old += v == 1;
        neu += v == 2;
        bad += v == 0;
    }
    for (uint64_t k = 0; k <= W; k++) {
        char what[96];
        snprintf(what, sizeof what, "bs=%u block cut %llu/%llu", g_bs, (unsigned long long)k, (unsigned long long)W);
        CK_(file_store(base_img) == 0, "restore");
        CK_(reopen() == 0, "reopen base");
        disk_file_arm_cut(&g_f, k);
        rng_init(777);
        (void)do_cs_provision(&why, &rc);
        disk_file_disarm(&g_f);
        int v = classify(what);
        if (k == 0) CK_(v == 1, "%s: cut 0 must be unprovisioned", what);
        if (k == W) CK_(v == 2, "%s: full write must be identity + subject", what);
        old += v == 1;
        neu += v == 2;
        bad += v == 0;
    }
    printf("power cut, ALLEN genesis, %4u-byte blocks: %d checkpoints + %llu block boundaries: %d unprovisioned, "
           "%d identity+subject, %d other\n",
           g_bs, CUT_CHECKPOINTS, (unsigned long long)W + 1, old, neu, bad);
    CK_(bad == 0, "never an identity without its subject, never a stray subject");
}

int main(void)
{
    make_keys();
    memset(G.provenance, 0xa5, 32);
    memset(G.cortex, 0xc0, 32);
    G.origin = CS_ORIGIN_OPERATOR;
    snprintf(g_path, sizeof g_path, "/tmp/ck_csp_test_%d.img", (int)getpid());
    static const uint32_t geos[2] = {4096u, 512u};
    for (int g = 0; g < 2; g++) {
        g_bs = geos[g];
        t_genesis();
        t_exactly_once();
        t_refusals();
        t_absent_never_minted();
        t_power_cuts();
    }
    dev_close();
    unlink(g_path);
    return ck_t_verdict("test_continuity_subject_provision");
}
