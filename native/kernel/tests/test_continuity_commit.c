/* test_continuity_commit.c -- host tests of svc/continuity_commit.c (C
 * continuity port, cut 4: provision, commit, resume; contract
 * native/kernel/CONTINUITY_RECOVERY_CONTRACT.md, aienos#222). Oracle:
 * crates/aienos-kernel/src/continuity.rs `provision`/`commit`/`resume`
 * (:712-868), continuity_tests.rs, scripts/qemu_continuity_test.sh.
 *
 * Storage: the REAL sealed Store (native/store, M5 envelopes, anchor) in a
 * file, at 512 and 4096 byte blocks. Entropy: the real ck_rng over a mocked
 * RNDR (core/entropy.c).
 *
 * 1. Provision, resume N times, remember (INV-8..INV-10, markers).
 * 2. Refusals: Unprovisioned resume, provision with a root / two roots /
 *    orphans, degraded mount, K-1 size, no entropy.
 * 3. Power cut at every checkpoint (ST_CP_* 0-6, SS_CP_BEFORE_ANCHOR,
 *    SS_CP_AFTER_ANCHOR) AND at every block boundary, for commit and for
 *    provisioning: the store resolves to exactly the old or the new state.
 * Mutants (make continuity-mutants) must each turn this test FAIL. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ck_test.h"
#include "continuity_resolve_sealed.h"
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
#define T_UNITS (A_UNITS + S_UNITS)
static uint32_t g_su = S_UNITS; /* Store region units (K-2 full run enlarges it) */
#define IMG_BYTES ((size_t)T_UNITS * 4096u)

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
static const uint8_t RUUID[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
static uint8_t base_img[IMG_BYTES], snap_img[IMG_BYTES];

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
    if (disk_file_open(&g_f, &g_d, g_path, g_bs, (uint64_t)(A_UNITS + g_su) * bpu, create) != 0) return -1;
    g_open = 1;
    if (st_disk_bind(&g_sd, &g_d, (uint64_t)A_UNITS * bpu, g_su, &g_sdev) != 0) return -2;
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
static void bind(st_hook hook)
{
    g_sk.s = &g_s;
    g_sk.hook = hook;
    g_sk.hook_arg = NULL;
    cr_bind_sealed(&g_src, &g_s);
    cr_bind_sealed_sink(&g_snk, &g_sk);
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
/* The image must be byte for byte what it was (a refusal writes nothing). */
static void snapshot(void) { CK_(file_load(snap_img) == 0, "snapshot"); }
static int unchanged(void)
{
    static uint8_t now[IMG_BYTES];
    return file_load(now) == 0 && memcmp(now, snap_img, IMG_BYTES) == 0;
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
static void rng_init(uint64_t seed, int present)
{
    g_m.present = present;
    g_m.ctr = seed;
    g_ops.present = m_present;
    g_ops.read = m_read;
    g_ops.ctx = &g_m;
    memset(&g_rng, 0, sizeof g_rng);
    (void)ck_rng_probe(&g_rng, &g_ops);
}

static int do_provision(const char **why, int *rc)
{
    return cr_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, CC_SOURCE_QUALIFICATION, &g_v, why, rc);
}
static int do_resume(int *committed)
{
    return cr_resume(&g_src, &g_snk, &g_w, &g_tw, &g_v, committed, NULL, NULL);
}
static int do_resolve(void)
{
    return cr_resolve(&g_src, &g_w, &g_v2, NULL, NULL);
}
static void hex(const uint8_t *p, size_t n, char *o)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        o[2 * i] = H[p[i] >> 4];
        o[2 * i + 1] = H[p[i] & 15];
    }
    o[2 * n] = 0;
}

static void check_marker(const char *word, const struct cr_view *v)
{
    char got[300], want[300], ag[65], mem[17];
    hex(v->root.agent_id, 32, ag);
    hex(v->memory, 8, mem);
    snprintf(want, sizeof want, "CONTINUITY: %s agent=%s incarnation=%llu sequence=%llu cortex=%llu branches=%u memory=%s",
             word, ag, (unsigned long long)v->manifest.incarnation, (unsigned long long)v->manifest.sequence,
             (unsigned long long)v->cortex_count, v->state.n, mem);
    size_t n = cr_marker_view(got, sizeof got, word, v);
    CK_(n == strlen(want) && strcmp(got, want) == 0, "marker: got '%s' want '%s'", got, want);
    CK_(cr_marker_view(got, 20, word, v) == 0, "marker too small buffer refused");
}

/* ---- 1. provision, resume, remember ---- */

static struct cc_record fact(const char *s)
{
    struct cc_record r;
    memset(&r, 0, sizeof r);
    r.status = CC_EPI_DIRECT_OBSERVATION;
    r.len = (uint16_t)strlen(s);
    r.statement = (const uint8_t *)s;
    return r;
}

static uint8_t g_agent_a[32];

static void t_provision_resume(void)
{
    fresh();
    rng_init(1001, 1);
    uint64_t gen0 = ss_generation(&g_s);
    const char *why = NULL;
    int rc = 0;
    int o = do_provision(&why, &rc);
    CK_(o == CR_RESOLVED, "bs=%u provision: %s %s", g_bs, cr_outcome_name(o), why ? why : "-");
    CK_(g_v.manifest.incarnation == 1 && g_v.manifest.sequence == 1 && g_v.cortex_count == 0 && g_v.state.n == 1,
        "provisioned view");
    CK_(g_v.state.written_at == 1 && g_v.root.source == CC_SOURCE_QUALIFICATION, "genesis written_at 1, source");
    CK_(g_v.root.provisioned_generation == gen0 + 1 && ss_generation(&g_s) == gen0 + 1,
        "provisioned_generation = generation + 1, one transaction");
    CK_(memcmp(g_v.root.store_uuid, RUUID, 16) == 0, "store uuid");
    static const uint8_t Z[32];
    CK_(memcmp(g_v.root.agent_id, Z, 32) != 0, "agent id is not zero");
    /* contract 1.7: the agent id is the four RNDR words, little-endian, word 0 first (UNVERIFIED on
     * hardware; here the mocked words are what ck_rng_fill returned). */
    {
        struct mock m2 = {1, 1001};
        struct ck_rng_ops o2 = {m_present, m_read, &m2};
        struct ck_rng r2;
        memset(&r2, 0, sizeof r2);
        ck_rng_probe(&r2, &o2);
        uint8_t want[32];
        CK_(ck_rng_fill(&r2, want, 32) == 0 && memcmp(want, g_v.root.agent_id, 32) == 0,
            "agent id = ck_rng_fill output");
    }
    check_marker("PROVISIONED", &g_v);
    {
        char mem[17];
        hex(g_v.memory, 8, mem);
        CK_(strcmp(mem, "e3b0c44298fc1c14") == 0, "no records: memory= is SHA-256 of nothing, got %s", mem);
    }
    memcpy(g_agent_a, g_v.root.agent_id, 32);

    /* Second provision: AlreadyProvisioned, nothing written (83a). */
    snapshot();
    rng_init(2002, 1);
    o = do_provision(&why, &rc);
    CK_(o == CR_ALREADY_PROVISIONED, "second provision: %s", cr_outcome_name(o));
    CK_(unchanged(), "second provision changed the image");
    char mk[200];
    cr_marker_outcome(mk, sizeof mk, o, why, rc);
    CK_(strcmp(mk, "CONTINUITY: STOP (AlreadyProvisioned)") == 0, "marker '%s'", mk);

    /* Cold restart, resume N times: same agent, incarnation +1 each, memory preserved (84, 85, 85a). */
    CK_(reopen() == 0, "reopen");
    int committed = 0;
    CK_(do_resume(&committed) == CR_RESOLVED && committed == 1, "resume 1");
    CK_(g_v.manifest.incarnation == 2 && g_v.manifest.sequence == 2 && g_v.cortex_count == 0 && g_v.state.n == 1,
        "RESUMED incarnation=2 sequence=2");
    CK_(memcmp(g_v.root.agent_id, g_agent_a, 32) == 0, "same agent");
    check_marker("RESUMED", &g_v);

    /* remember: fork the root branch and append one record, in ONE transaction (REMEMBERED). */
    static struct cc_state st;
    memcpy(&st, &g_v.state, sizeof st);
    uint8_t child[32];
    CK_(cc_state_fork(&st, g_v.root.root_branch, child, NULL) == CC_OK, "fork");
    struct cc_record r1 = fact("qemu: the operator asked AIEN to remember this");
    struct cr_update up = {&st, &r1, 1};
    static struct cr_view cur;
    memcpy(&cur, &g_v, sizeof cur);
    uint64_t g1 = ss_generation(&g_s);
    o = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &up, 0, &g_v, &why, &rc);
    CK_(o == CR_RESOLVED, "remember: %s %s", cr_outcome_name(o), why ? why : "-");
    CK_(ss_generation(&g_s) == g1 + 1, "remember is ONE transaction (INV-8): gen %llu -> %llu",
        (unsigned long long)g1, (unsigned long long)ss_generation(&g_s));
    CK_(g_v.manifest.incarnation == 2 && g_v.manifest.sequence == 3 && g_v.cortex_count == 1 && g_v.state.n == 2,
        "REMEMBERED incarnation=2 sequence=3 cortex=1 branches=2");
    CK_(g_v.state.written_at == 3, "state.written_at = new sequence (INV-9)");
    check_marker("REMEMBERED", &g_v);
    uint8_t mem1[32];
    memcpy(mem1, g_v.memory, 32);

    uint64_t inc = 2, seq = 3;
    for (int i = 0; i < 6; i++) {
        CK_(reopen() == 0, "cold restart %d", i);
        CK_(do_resume(&committed) == CR_RESOLVED && committed == 1, "resume %d", i);
        inc++;
        seq++;
        CK_(g_v.manifest.incarnation == inc && g_v.manifest.sequence == seq, "cold restart %d: inc %llu seq %llu", i,
            (unsigned long long)g_v.manifest.incarnation, (unsigned long long)g_v.manifest.sequence);
        CK_(memcmp(g_v.root.agent_id, g_agent_a, 32) == 0 && memcmp(g_v.memory, mem1, 32) == 0 &&
                g_v.cortex_count == 1 && g_v.state.n == 2,
            "same agent, same memory, same branches");
        CK_(do_resolve() == CR_RESOLVED && g_v2.manifest.incarnation == inc, "stored view agrees");
    }
    /* Independent provisioning draws another agent (83b). */
    fresh();
    rng_init(3003, 1);
    CK_(do_provision(&why, &rc) == CR_RESOLVED, "provision B");
    CK_(memcmp(g_v.root.agent_id, g_agent_a, 32) != 0, "independent provisioning gives a different agent (MC-10)");
}

/* ---- 2. refusals ---- */

static void t_unprovisioned_resume(void)
{
    fresh();
    CK_(reopen() == 0, "reopen");
    snapshot();
    uint64_t gen0 = ss_generation(&g_s);
    int committed = 7;
    int o = do_resume(&committed);
    CK_(o == CR_UNPROVISIONED && committed == 0, "bs=%u resume on Unprovisioned: %s", g_bs, cr_outcome_name(o));
    CK_(ss_generation(&g_s) == gen0 && unchanged(), "resume minted nothing (INV-4, MC-1)");
    CK_(reopen() == 0 && do_resolve() == CR_UNPROVISIONED, "still Unprovisioned after reopen");
    char mk[100];
    cr_marker_outcome(mk, sizeof mk, o, NULL, 0);
    CK_(strcmp(mk, "CONTINUITY: UNPROVISIONED") == 0, "marker '%s'", mk);
}

/* An object committed straight to the Store, to build hostile states. */
static int raw_commit(uint16_t kind, const uint8_t *b, size_t n)
{
    ss_object so = {kind, 1, b, n};
    return ss_transact(&g_s, &so, 1, NULL, NULL, NULL);
}

static void t_provision_refusals(void)
{
    const char *why = NULL;
    int rc = 0, o;
    /* with a root (MC-7) was covered in t_provision_resume; here: two roots and orphans. */
    fresh();
    rng_init(11, 1);
    CK_(do_provision(&why, &rc) == CR_RESOLVED, "provision");
    /* a second, foreign root written behind the layer's back -> Conflict -> provision refuses */
    struct cc_root r;
    memset(&r, 0, sizeof r);
    memset(r.agent_id, 0x77, 32);
    cc_root_branch_id(r.agent_id, r.root_branch);
    r.provisioned_generation = 9;
    r.source = CC_SOURCE_OPERATOR;
    static uint8_t b[CC_MAX_OBJECT_BYTES];
    size_t n = 0;
    CK_(cc_root_encode(&r, b, sizeof b, &n, NULL) == CC_OK && raw_commit(CC_KIND_AGENT_ROOT, b, n) == 0, "second root");
    CK_(do_resolve() == CR_CONFLICT, "two roots resolve to Conflict");
    snapshot();
    rng_init(12, 1);
    o = do_provision(&why, &rc);
    CK_(o == CR_ALREADY_PROVISIONED, "provision on Conflict: %s", cr_outcome_name(o));
    CK_(unchanged(), "refusal wrote nothing");

    /* orphan manifest only: provision must refuse (never provision over orphans). */
    fresh();
    struct cc_manifest m;
    memset(&m, 0, sizeof m);
    memset(m.root, 0x55, 32);
    m.sequence = 1;
    m.incarnation = 1;
    memset(m.agent_state, 0x66, 32);
    CK_(cc_manifest_encode(&m, b, sizeof b, &n, NULL) == CC_OK && raw_commit(CC_KIND_MANIFEST, b, n) == 0, "orphan manifest");
    snapshot();
    rng_init(13, 1);
    o = do_provision(&why, &rc);
    CK_(o == CR_CORRUPT && why && !strcmp(why, "continuity objects without an agent root"),
        "provision over orphans: %s %s", cr_outcome_name(o), why ? why : "-");
    CK_(unchanged(), "orphans: nothing written");
    int committed = 0;
    CK_(do_resume(&committed) == CR_CORRUPT && committed == 0, "resume over orphans is Corrupt, not Unprovisioned");
    CK_(unchanged(), "resume over orphans wrote nothing");

    /* no entropy: absent, then never probed; nothing written, no fallback */
    fresh();
    snapshot();
    rng_init(14, 0);
    o = do_provision(&why, &rc);
    CK_(o == CR_NO_ENTROPY && unchanged(), "no RNDR: %s", cr_outcome_name(o));
    char mk[100];
    cr_marker_outcome(mk, sizeof mk, o, NULL, 0);
    CK_(strcmp(mk, "CONTINUITY: NO_ENTROPY") == 0, "marker '%s'", mk);
    memset(&g_rng, 0, sizeof g_rng);
    o = do_provision(&why, &rc);
    CK_(o == CR_NO_ENTROPY && unchanged(), "unprobed rng: %s", cr_outcome_name(o));
    CK_(do_resolve() == CR_UNPROVISIONED, "still Unprovisioned");

    /* caller bugs */
    CK_(cr_provision(NULL, &g_snk, &g_w, &g_tw, &g_rng, RUUID, 1, &g_v, NULL, NULL) == CR_E_ARG, "NULL src");
    rng_init(15, 1);
    CK_(cr_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, 0, &g_v, NULL, NULL) == CR_E_ARG, "bad source");
    CK_(cr_provision(&g_src, &g_snk, &g_w, &g_tw, NULL, RUUID, 1, &g_v, NULL, NULL) == CR_E_ARG, "NULL rng");
    CK_(unchanged(), "caller bugs wrote nothing");
}

static void junk_inactive(void)
{
    uint32_t active = st_active_slot(&g_s.st);
    dev_close();
    FILE *f = fopen(g_path, "r+b");
    CK_(f != NULL, "open image");
    static uint8_t junk[4096];
    for (size_t i = 0; i < sizeof junk; i++) junk[i] = (uint8_t)(i * 37u + 11u);
    if (f) {
        fseek(f, (long)((A_UNITS + (1u - active)) * 4096u), SEEK_SET);
        CK_(fwrite(junk, 1, sizeof junk, f) == sizeof junk, "write junk");
        fclose(f);
    }
}

static void t_degraded(void)
{
    const char *why = NULL;
    int rc = 0, o;
    /* provisioned store, malformed peer: resume is read only (INV-11), commit and provision are ReadOnly */
    fresh();
    rng_init(21, 1);
    CK_(do_provision(&why, &rc) == CR_RESOLVED, "provision");
    int committed = 0;
    CK_(do_resume(&committed) == CR_RESOLVED && committed == 1, "resume");
    uint8_t agent[32], mem[32];
    memcpy(agent, g_v.root.agent_id, 32);
    memcpy(mem, g_v.memory, 32);
    uint64_t inc = g_v.manifest.incarnation;
    junk_inactive();
    CK_(reopen() == 0 && g_s.st.state == ST_DEGRADED_RECOVERY, "degraded mount (K-5)");
    snapshot();
    uint64_t gen = ss_generation(&g_s);
    o = do_resume(&committed);
    CK_(o == CR_RESOLVED && committed == 0, "bs=%u degraded resume: %s committed=%d", g_bs, cr_outcome_name(o), committed);
    CK_(memcmp(g_v.root.agent_id, agent, 32) == 0 && memcmp(g_v.memory, mem, 32) == 0 && g_v.manifest.incarnation == inc,
        "RESUMED_READONLY: same agent, memory, incarnation");
    check_marker("RESUMED_READONLY", &g_v);
    struct cc_record r1 = fact("x");
    struct cr_update up = {NULL, &r1, 1};
    static struct cr_view cur;
    memcpy(&cur, &g_v, sizeof cur);
    o = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &up, 1, &g_v2, &why, &rc);
    CK_(o == CR_READ_ONLY, "commit on a degraded mount: %s (MC-9)", cr_outcome_name(o));
    CK_(ss_generation(&g_s) == gen && unchanged(), "nothing written");
    cr_marker_outcome((char[64]){0}, 64, o, NULL, 0);
    char mk[100];
    cr_marker_outcome(mk, sizeof mk, o, NULL, 0);
    CK_(strcmp(mk, "CONTINUITY: STOP (ReadOnly)") == 0, "marker '%s'", mk);

    /* degraded and unprovisioned: provision refuses ReadOnly (never mints on a degraded mount) */
    fresh();
    static uint8_t b[16];
    memset(b, 1, sizeof b);
    CK_(raw_commit(0x0B01, b, sizeof b) == 0, "unrelated object (second generation)");
    junk_inactive();
    CK_(reopen() == 0 && g_s.st.state == ST_DEGRADED_RECOVERY, "degraded");
    snapshot();
    rng_init(22, 1);
    o = do_provision(&why, &rc);
    CK_(o == CR_READ_ONLY, "provision on a degraded mount: %s (MC-9)", cr_outcome_name(o));
    CK_(unchanged(), "provision wrote nothing");
    CK_(do_resolve() == CR_UNPROVISIONED, "still Unprovisioned");
}

static void t_size_bound(void)
{
    const char *why = NULL;
    int rc = 0, o;
    fresh();
    rng_init(31, 1);
    CK_(do_provision(&why, &rc) == CR_RESOLVED, "provision");
    static struct cr_view cur;
    memcpy(&cur, &g_v, sizeof cur);

    /* K-1: 205 branches = 16464 bytes is Limit, nothing written; 204 = 16384 fits. */
    static struct cc_state st;
    memcpy(&st, &cur.state, sizeof st);
    uint8_t child[32];
    for (int i = 0; i < 203; i++) CK_(cc_state_fork(&st, cur.root.root_branch, child, NULL) == CC_OK, "fork");
    CK_(st.n == 204, "204 branches");
    snapshot();
    uint64_t gen0 = ss_generation(&g_s);
    struct cr_update up = {&st, NULL, 0};
    o = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &up, 0, &g_v, &why, &rc);
    CK_(o == CR_RESOLVED && ss_generation(&g_s) == gen0 + 1, "204 branches commit: %s %s", cr_outcome_name(o), why ? why : "-");
    memcpy(&cur, &g_v, sizeof cur);
    memcpy(&st, &cur.state, sizeof st);
    CK_(cc_state_fork(&st, cur.root.root_branch, child, NULL) == CC_OK && st.n == 205, "205 branches");
    snapshot();
    gen0 = ss_generation(&g_s);
    o = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &up, 0, &g_v, &why, &rc);
    CK_(o == CR_LIMIT && why && !strcmp(why, "continuity object exceeds the 16384-byte sealed Store cap"),
        "205 branches: %s %s (K-1)", cr_outcome_name(o), why ? why : "-");
    CK_(ss_generation(&g_s) == gen0 && unchanged(), "K-1: nothing written");

    /* 64 records of 1024 bytes = 67872 bytes: Limit, never truncated (MC-11). */
    static uint8_t stmt[1024];
    memset(stmt, 'm', sizeof stmt);
    static struct cc_record recs[64];
    for (int i = 0; i < 64; i++) {
        recs[i] = fact("");
        recs[i].len = 1024;
        recs[i].statement = stmt;
    }
    struct cr_update w64 = {NULL, recs, 64};
    snapshot();
    o = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &w64, 0, &g_v2, &why, &rc);
    CK_(o == CR_LIMIT, "64 x 1024 byte WAL: %s (K-1, MC-11)", cr_outcome_name(o));
    CK_(unchanged(), "oversize WAL: nothing written, nothing truncated");
    struct cr_update w65 = {NULL, recs, 65};
    o = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &w65, 0, &g_v2, &why, &rc);
    CK_(o == CR_LIMIT && why && !strcmp(why, "WAL segment record count"), "65 records: %s", cr_outcome_name(o));
    /* 15 records of 1024 bytes = 15.9 KiB fits and reads back whole. */
    struct cr_update w15 = {NULL, recs, 15};
    o = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &w15, 0, &g_v2, &why, &rc);
    CK_(o == CR_RESOLVED && g_v2.cortex_count == 15, "15 x 1024 fits and is read back whole: %s %llu", cr_outcome_name(o),
        (unsigned long long)g_v2.cortex_count);
}

/* K-2: the catalog bound. */
static void t_catalog_bound(void)
{
    const char *why = NULL;
    int rc = 0;
    fresh();
    rng_init(41, 1);
    CK_(do_provision(&why, &rc) == CR_RESOLVED, "provision");
    uint32_t n;
    st_catalog(&g_s.st, &n);
    uint32_t after_prov = n;
    struct cc_record r1 = fact("k2");
    struct cr_update up = {NULL, &r1, 1};
    static struct cr_view cur;
    int ok = 1;
    for (int i = 0; i < 64 && ok; i++) {
        memcpy(&cur, &g_v, sizeof cur);
        ok = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &up, 0, &g_v2, &why, &rc) == CR_RESOLVED;
        memcpy(&g_v, &g_v2, sizeof g_v);
    }
    CK_(ok && g_v.manifest.n_wal == 64, "64 WAL commits");
    st_catalog(&g_s.st, &n);
    printf("K-2 (bs=%u): catalog entries after provision = %u; after provision + 64 one-record WAL commits = %u "
           "(%.2f entries per transaction; bound %u)\n",
           g_bs, after_prov, n, (double)(n - after_prov) / 64.0, (unsigned)SV1_MAX_CATALOG_ENTRIES);
    CK_(n == after_prov + 64u * 3u, "each WAL commit adds WAL + manifest + transaction record (3 entries), got %u", n);
    memcpy(&cur, &g_v, sizeof cur);
    uint64_t gen0 = ss_generation(&g_s);
    int o = cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &up, 0, &g_v2, &why, &rc);
    CK_(o == CR_LIMIT && why && !strcmp(why, "cortex WAL needs compaction"), "65th WAL segment: %s", cr_outcome_name(o));
    CK_(ss_generation(&g_s) == gen0, "nothing written");
}

/* K-2 run to exhaustion (slow, CK_K2_FULL=1): resumes add manifest + transaction record = 2 entries. */
static void t_catalog_full(void)
{
    const char *why = NULL;
    int rc = 0, committed = 0, oo;
    uint32_t n;
    g_su = 16384;
    fresh();
    rng_init(51, 1);
    CK_(do_provision(&why, &rc) == CR_RESOLVED, "provision");
    unsigned resumes = 0;
    while ((oo = cr_resume(&g_src, &g_snk, &g_w, &g_tw, &g_v2, &committed, &why, &rc)) == CR_RESOLVED) resumes++;
    st_catalog(&g_s.st, &n);
    printf("K-2 full (bs=4096, %u-unit Store region): %u resumes after provisioning, then %s rc=%d (%s); catalog entries %u of %u\n",
           g_su, resumes, cr_outcome_name(oo), rc, rc ? st_strerror(rc) : "-", n, (unsigned)SV1_MAX_CATALOG_ENTRIES);
    CK_(oo == CR_STORE && (rc == ST_E_CATALOG_FULL || rc == ST_E_NO_SPACE), "stops with a Store refusal (catalog full or no space), not a wrong result");
    g_su = S_UNITS;
}

/* ---- 3. power cuts ---- */

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

struct pc_stats {
    int old, neu, other_bad, degraded;
};

/* The operation under test. */
enum { OP_COMMIT, OP_PROVISION };
static uint64_t g_gen_old;
static uint8_t g_agent_exp[32]; /* provisioning: the agent the mocked RNDR yields */
static struct cr_view g_old_view, g_new_view;

static int run_op(int op)
{
    const char *why = NULL;
    int rc = 0;
    if (op == OP_PROVISION) {
        rng_init(777, 1);
        return do_provision(&why, &rc);
    }
    static struct cc_state st;
    memcpy(&st, &g_old_view.state, sizeof st);
    uint8_t child[32];
    (void)cc_state_fork(&st, g_old_view.root.root_branch, child, NULL);
    struct cc_record r1 = fact("remember across the crash");
    struct cr_update up = {&st, &r1, 1};
    return cr_commit(&g_src, &g_snk, &g_w, &g_tw, &g_old_view, &up, 1, &g_v, &why, &rc);
}

/* Verdict after the cut: exactly the old state or exactly the new one. Returns 1 old, 2 new, 0 bad. */
static int classify(int op, const char *what)
{
    int rc = reopen();
    CK_(rc == 0, "%s: reopen after the cut: %s (%d)", what, rc ? ss_strerror(rc) : "ok", rc);
    if (rc != 0) return 0;
    uint64_t gen = ss_generation(&g_s);
    int o = do_resolve();
    if (op == OP_PROVISION) {
        if (o == CR_UNPROVISIONED) {
            CK_(gen == g_gen_old, "%s: old state but generation %llu", what, (unsigned long long)gen);
            return gen == g_gen_old ? 1 : 0;
        }
        int ok = o == CR_RESOLVED && gen == g_gen_old + 1 && memcmp(g_v2.root.agent_id, g_agent_exp, 32) == 0 &&
                 g_v2.manifest.sequence == 1 && g_v2.manifest.incarnation == 1 && g_v2.state.n == 1;
        CK_(ok, "%s: neither Unprovisioned nor the full genesis: %s gen %llu", what, cr_outcome_name(o), (unsigned long long)gen);
        return ok ? 2 : 0;
    }
    if (o != CR_RESOLVED) {
        CK_(0, "%s: resolve after cut: %s", what, cr_outcome_name(o));
        return 0;
    }
    CK_(memcmp(g_v2.root.agent_id, g_old_view.root.agent_id, 32) == 0, "%s: identity changed", what);
    if (g_v2.manifest.sequence == g_old_view.manifest.sequence) {
        int ok = gen == g_gen_old && g_v2.manifest.incarnation == g_old_view.manifest.incarnation &&
                 g_v2.cortex_count == g_old_view.cortex_count && memcmp(g_v2.memory, g_old_view.memory, 32) == 0 &&
                 g_v2.state.n == g_old_view.state.n;
        CK_(ok, "%s: sequence old but content mixed (gen %llu)", what, (unsigned long long)gen);
        return ok ? 1 : 0;
    }
    int ok = gen == g_gen_old + 1 && g_v2.manifest.sequence == g_new_view.manifest.sequence &&
             g_v2.manifest.incarnation == g_new_view.manifest.incarnation && g_v2.cortex_count == g_new_view.cortex_count &&
             memcmp(g_v2.memory, g_new_view.memory, 32) == 0 && g_v2.state.n == g_new_view.state.n;
    CK_(ok, "%s: third state: seq %llu inc %llu gen %llu", what, (unsigned long long)g_v2.manifest.sequence,
        (unsigned long long)g_v2.manifest.incarnation, (unsigned long long)gen);
    return ok ? 2 : 0;
}

/* After a cut the store must keep working: provision again (old) / resume (any). */
static void still_works(int op, int verdict, const char *what)
{
    if (!verdict) return;
    if (g_s.st.state != ST_VALID) return; /* degraded: read only, the Recovery Core's case, not this layer's */
    int committed = 0;
    if (op == OP_PROVISION && verdict == 1) {
        const char *why = NULL;
        int rc = 0;
        rng_init(888, 1);
        int o = do_provision(&why, &rc);
        CK_(o == CR_RESOLVED, "%s: provisioning again after a cut that left the old state: %s %s", what, cr_outcome_name(o),
            why ? why : "-");
        return;
    }
    int o = do_resume(&committed);
    CK_(o == CR_RESOLVED && committed == 1, "%s: resume after the cut: %s", what, cr_outcome_name(o));
}

static void cut_campaign(int op, const char *label)
{
    /* Base state for this op. */
    fresh();
    if (op == OP_COMMIT) {
        rng_init(999, 1);
        const char *why = NULL;
        int rc = 0;
        CK_(do_provision(&why, &rc) == CR_RESOLVED, "provision (base)");
        int committed = 0;
        CK_(do_resume(&committed) == CR_RESOLVED, "resume (base)");
        memcpy(&g_old_view, &g_v, sizeof g_old_view);
    }
    dev_close();
    CK_(file_load(base_img) == 0, "save base");

    /* Learn the new state and the block count with an uncut run. */
    CK_(reopen() == 0, "reopen base");
    g_gen_old = ss_generation(&g_s);
    uint64_t w0 = g_f.blocks_written;
    int o = run_op(op);
    CK_(o == CR_RESOLVED, "%s uncut: %s", label, cr_outcome_name(o));
    uint64_t W = g_f.blocks_written - w0;
    memcpy(&g_new_view, &g_v, sizeof g_new_view);
    if (op == OP_PROVISION) memcpy(g_agent_exp, g_v.root.agent_id, 32);
    dev_close();

    struct pc_stats cp = {0}, bl = {0};
    /* Every checkpoint. */
    for (int i = 0; i < CUT_CHECKPOINTS; i++) {
        char what[96];
        snprintf(what, sizeof what, "%s bs=%u cp %s", label, g_bs, cp_name(CPS[i]));
        CK_(file_store(base_img) == 0, "restore");
        CK_(reopen() == 0, "reopen base");
        g_cp_target = CPS[i];
        g_cp_fired = 0;
        bind(cp_hook);
        (void)run_op(op);
        CK_(g_cp_fired == 1, "%s: checkpoint never reached", what);
        disk_file_disarm(&g_f);
        int v = classify(op, what);
        /* Expected by the Rust oracle and the sealed-store rule (contract 6.1). */
        if (CPS[i] <= ST_CP_AFTER_FIRST_FLUSH) CK_(v == 1, "%s: expected the old state", what);
        if (CPS[i] == ST_CP_AFTER_FINAL_FLUSH || CPS[i] >= SS_CP_BEFORE_ANCHOR)
            CK_(v == 2, "%s: expected the new state", what);
        if (CPS[i] == SS_CP_BEFORE_ANCHOR) CK_(g_s.rb == SS_RB_PREPARED_ADVANCE, "%s: anchor one behind (rb=%d)", what, g_s.rb);
        cp.old += v == 1;
        cp.neu += v == 2;
        cp.other_bad += v == 0;
        cp.degraded += g_s.st.state == ST_DEGRADED_RECOVERY;
        still_works(op, v, what);
    }
    /* Every block boundary of the write sequence. */
    for (uint64_t k = 0; k <= W; k++) {
        char what[96];
        snprintf(what, sizeof what, "%s bs=%u block cut %llu/%llu", label, g_bs, (unsigned long long)k, (unsigned long long)W);
        CK_(file_store(base_img) == 0, "restore");
        CK_(reopen() == 0, "reopen base");
        disk_file_arm_cut(&g_f, k);
        (void)run_op(op);
        disk_file_disarm(&g_f);
        int v = classify(op, what);
        if (k == 0) CK_(v == 1, "%s: cut 0 must be old", what);
        if (k == W) CK_(v == 2, "%s: full write must be new", what);
        bl.old += v == 1;
        bl.neu += v == 2;
        bl.other_bad += v == 0;
        bl.degraded += g_s.st.state == ST_DEGRADED_RECOVERY;
        still_works(op, v, what);
    }
    printf("power cut, %s, %4u-byte blocks: %d checkpoints (%d old, %d new, %d bad), %llu block boundaries "
           "(%d old, %d new, %d bad, %d read-only degraded)\n",
           label, g_bs, CUT_CHECKPOINTS, cp.old, cp.neu, cp.other_bad, (unsigned long long)W + 1, bl.old, bl.neu,
           bl.other_bad, bl.degraded);
    CK_(cp.other_bad == 0 && bl.other_bad == 0, "no mixed state");
    CK_(cp.old + cp.neu == CUT_CHECKPOINTS, "every checkpoint classified");
    CK_(bl.old + bl.neu == (int)W + 1, "every block cut classified");
}

int main(void)
{
    make_keys();
    snprintf(g_path, sizeof g_path, "/tmp/ck_cm_test_%d.img", (int)getpid());
    static const uint32_t geos[2] = {4096u, 512u};
    for (int g = 0; g < 2; g++) {
        g_bs = geos[g];
        t_provision_resume();
        t_unprovisioned_resume();
        t_provision_refusals();
        t_degraded();
        t_size_bound();
        t_catalog_bound();
        if (g_bs == 4096 && getenv("CK_K2_FULL")) t_catalog_full();
        cut_campaign(OP_COMMIT, "commit");
        cut_campaign(OP_PROVISION, "provision");
    }
    dev_close();
    unlink(g_path);
    return ck_t_verdict("test_continuity_commit");
}
