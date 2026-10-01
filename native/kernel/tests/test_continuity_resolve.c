/* test_continuity_resolve.c -- host tests of svc/continuity_resolve.c (C
 * continuity port, cut 3; contract native/kernel/CONTINUITY_RECOVERY_CONTRACT.md,
 * aienos#222). Oracle: crates/aienos-kernel/src/continuity.rs `resolve`
 * (:637-710), recovery_core.rs (:94-133), recovery.rs (:103, :124-140).
 *
 * Storage: the REAL sealed Store (native/store, M5 envelopes, anchor) in a
 * file, at 512 and 4096 byte blocks; a fake cr_source only for the cases the
 * real Store cannot produce (an oversize object, a read error).
 *
 * 1. Challenge, operator response, deferred D-1 fixture lines (byte for byte).
 * 2. One resolve outcome per case, including the hostile ones.
 * 3. K-5: a degraded mount through ss_open, answered by running it.
 * Mutants (make continuity-mutants) must each turn this test FAIL. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ck_test.h"
#include "continuity_resolve_sealed.h"
#include "disk_file.h"
#include "aienos_crypto.h"
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

static int hexv(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }
static void unhex(const char *h, uint8_t *o)
{
    for (size_t i = 0; h[2 * i]; i++) o[i] = (uint8_t)(hexv(h[2 * i]) << 4 | hexv(h[2 * i + 1]));
}

/* ------------------------------------------------------------------ */
/* 1. challenge, response, fixtures                                    */
/* ------------------------------------------------------------------ */

static uint8_t UUID[16], DIGEST[32], KEY0F[32];

static void test_challenge_kat(void)
{
    /* Rust-emitted values (fixture lines of cut 2); also recomputed with sha256sum
     * over printf-built input (domain, uuid 5a x16, generation 7 LE, action, digest 33 x32). */
    uint8_t c[32], e[32];
    cr_challenge(UUID, 7, CR_ACTION_REPAIR_DEGRADED_PEER, DIGEST, c);
    unhex("7dfd4366095705ca21c81268752c14bf8961d000ed1a276d9dcf0753c0f2f4b5", e);
    CK_(memcmp(c, e, 32) == 0, "repair challenge KAT");
    cr_challenge(UUID, 7, CR_ACTION_PROVISION_IDENTITY, DIGEST, c);
    unhex("91fe9cff4a2afe23d343ae77c5530bed2c3115bea3df648562b6c19004b184fc", e);
    CK_(memcmp(c, e, 32) == 0, "provision challenge KAT");
}

/* recovery.rs:206-235: KEY 00..1f, CHALLENGE a0..bf, openssl-computed answer. */
static void test_operator_kat(void)
{
    uint8_t key[32], ch[32], r[32], want[32];
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
        ch[i] = (uint8_t)(0xa0 + i);
    }
    unhex("f6162da5f879e9bd4defc7108c463b5d164f4db68ae991781bf798fc14907aaa", want);
    cr_operator_response(key, ch, r);
    CK_(memcmp(r, want, 32) == 0, "operator response KAT (rs recovery.rs:231)");
    CK_(cr_operator_verify(key, ch, want) == 1, "verify accepts the KAT");

    /* rs :269: any single-bit flip of response, challenge or key is refused. */
    int bad = 0;
    for (int byte = 0; byte < 32; byte++)
        for (int bit = 0; bit < 8; bit++) {
            uint8_t m = (uint8_t)(1u << bit), x[32], k2[32], c2[32];
            memcpy(x, want, 32);
            x[byte] ^= m;
            bad += cr_operator_verify(key, ch, x);
            memcpy(c2, ch, 32);
            c2[byte] ^= m;
            bad += cr_operator_verify(key, c2, want);
            memcpy(k2, key, 32);
            k2[byte] ^= m;
            bad += cr_operator_verify(k2, ch, want);
        }
    CK_(bad == 0, "%d bit flips accepted (MR-4: bytes 16-31 of the response)", bad);

    /* rs :299, :311: bare SHA-256, un-domained HMAC and zero are refused. */
    uint8_t legacy[32], undom[32], z[32] = {0};
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, key, 32);
    sha256_update(&h, ch, 32);
    sha256_final(&h, legacy);
    CK_(cr_operator_verify(key, ch, legacy) == 0, "legacy bare SHA-256 refused (MR-8)");
    aienos_hmac_sha256(key, ch, 32, undom);
    CK_(cr_operator_verify(key, ch, undom) == 0, "undomained HMAC refused (MR-8)");
    CK_(cr_operator_verify(key, ch, z) == 0, "zero response refused");
    uint8_t zk[32] = {0};
    CK_(cr_operator_verify(zk, zk, z) == 0, "all-zero key and challenge still need the MAC");
    /* flipping only byte 16..31 of the response must fail on its own (MR-4). */
    uint8_t hi[32];
    memcpy(hi, want, 32);
    hi[31] ^= 1;
    CK_(cr_operator_verify(key, ch, hi) == 0, "flip in the last byte refused");
}

static void test_challenge_binding(void) /* rs recovery_core_tests.rs:300-315 (91k) */
{
    uint8_t base[32], c[32], d2[32];
    cr_challenge(UUID, 7, 1, DIGEST, base);
    cr_challenge(UUID, 7, 2, DIGEST, c);
    CK_(memcmp(base, c, 32) != 0, "challenge binds the action (MR-3)");
    memcpy(d2, DIGEST, 32);
    d2[0] ^= 1;
    cr_challenge(UUID, 7, 1, d2, c);
    CK_(memcmp(base, c, 32) != 0, "challenge binds the state digest (MR-2)");
    cr_challenge(UUID, 8, 1, DIGEST, c);
    CK_(memcmp(base, c, 32) != 0, "challenge binds the generation");
    uint8_t u2[16];
    memcpy(u2, UUID, 16);
    u2[15] ^= 1;
    cr_challenge(u2, 7, 1, DIGEST, c);
    CK_(memcmp(base, c, 32) != 0, "challenge binds the store uuid");
    /* An authorisation for one action does not verify for the other. */
    uint8_t ch1[32], ch2[32], resp1[32];
    cr_challenge(UUID, 7, 1, DIGEST, ch1);
    cr_challenge(UUID, 7, 2, DIGEST, ch2);
    cr_operator_response(KEY0F, ch1, resp1);
    CK_(cr_operator_verify(KEY0F, ch1, resp1) == 1, "own challenge verifies");
    CK_(cr_operator_verify(KEY0F, ch2, resp1) == 0, "response replayed on the other action refused");
    CK_(cr_operator_verify(KEY0F, ch1, resp1) == 1, "and still verifies on its own");
}

static void test_state_digest(void)
{
    static uint8_t u0[4096], u1[4096];
    uint8_t a[32], b[32];
    memset(u0, 0xa5, sizeof u0);
    memset(u1, 0x5a, sizeof u1);
    cr_state_digest(u0, u1, a);
    uint8_t both[8192];
    memcpy(both, u0, 4096);
    memcpy(both + 4096, u1, 4096);
    sha256_hash(both, sizeof both, b);
    CK_(memcmp(a, b, 32) == 0, "state digest = SHA-256(unit0 || unit1)");
    cr_state_digest(u1, u0, b);
    CK_(memcmp(a, b, 32) != 0, "unit order matters");
}

/* The deferred lines of cut 2: Rust-emitted challenges and responses for the
 * system record {uuid 5a x16, generation 7, digest 33 x32, key 0f x32}. */
static int fx_checked;
static int test_fixture(const char *dir)
{
    char path[512], line[1024];
    snprintf(path, sizeof path, "%s/continuity_vectors.txt", dir);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    uint8_t ch[2][32], rs[2][32];
    int seen = 0;
    while (fgets(line, sizeof line, f)) {
        char kw[32], name[64], hex[128];
        if (sscanf(line, "%31s %63s %127s", kw, name, hex) != 3 || strcmp(kw, "deferred")) continue;
        uint8_t want[32], got[32];
        unhex(hex, want);
        int act = strstr(name, "repair_degraded_peer") ? 1 : strstr(name, "provision_identity") ? 2 : 0;
        if (!act) continue;
        cr_challenge(UUID, 7, (uint8_t)act, DIGEST, ch[act - 1]);
        cr_operator_response(KEY0F, ch[act - 1], rs[act - 1]);
        memcpy(got, !strncmp(name, "challenge_", 10) ? ch[act - 1] : rs[act - 1], 32);
        CK_(memcmp(got, want, 32) == 0, "fixture %s differs from the Rust oracle", name);
        seen++;
        fx_checked++;
    }
    fclose(f);
    CK_(seen == 4, "fixture has %d deferred lines, want 4", seen);
    return 1;
}

/* ------------------------------------------------------------------ */
/* 2. a real sealed Store in a file                                    */
/* ------------------------------------------------------------------ */

#define A_UNITS 4u
#define S_UNITS 512u
#define T_UNITS (A_UNITS + S_UNITS)

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
static struct cr_view g_v;

static const uint8_t RUUID[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

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
    if (disk_file_open(&g_f, &g_d, g_path, g_bs, (uint64_t)T_UNITS * bpu, create) != 0) return -1;
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

/* New formatted, opened Store. */
static void fresh(void)
{
    CK_(dev_open(1) == 0, "rig create");
    CK_(ss_format(&g_sdev, &g_tdev, 0, RUUID, &g_k, &g_ws) == 0, "format");
    CK_(ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws) == 0, "open genesis");
}
static int reopen(void)
{
    if (dev_open(0) != 0) return -9999;
    memset(&g_s, 0, sizeof g_s);
    return ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws);
}

struct obj {
    uint16_t kind, ver;
    uint8_t b[CC_MAX_OBJECT_BYTES];
    size_t n;
    uint8_t id[32];
};
static struct obj O[8];

static uint8_t AG[32], AG2[32];

static void fin(struct obj *o, uint16_t kind)
{
    o->kind = kind;
    o->ver = 1;
    CK_(cc_object_id(kind, o->b, o->n, o->id) == CC_OK, "object id");
}
static void mk_root(struct obj *o, const uint8_t agent[32], uint8_t source)
{
    struct cc_root r;
    memset(&r, 0, sizeof r);
    memcpy(r.agent_id, agent, 32);
    memcpy(r.store_uuid, RUUID, 16);
    cc_root_branch_id(agent, r.root_branch);
    r.provisioned_generation = 2;
    r.source = source;
    CK_(cc_root_encode(&r, o->b, sizeof o->b, &o->n, NULL) == CC_OK, "root encode");
    fin(o, CC_KIND_AGENT_ROOT);
}
static void mk_state(struct obj *o, const uint8_t agent[32], uint64_t written_at)
{
    static struct cc_state s;
    cc_state_genesis(&s, agent, written_at);
    CK_(cc_state_encode(&s, o->b, sizeof o->b, &o->n, NULL) == CC_OK, "state encode");
    fin(o, CC_KIND_AGENT_STATE);
}
static void mk_man(struct obj *o, const uint8_t root[32], const uint8_t *prev, uint64_t seq,
                   uint64_t inc, const uint8_t *state, const uint8_t (*wal)[32], uint32_t nwal)
{
    static struct cc_manifest m;
    memset(&m, 0, sizeof m);
    memcpy(m.root, root, 32);
    if (prev) memcpy(m.previous, prev, 32);
    m.sequence = seq;
    m.incarnation = inc;
    if (state) memcpy(m.agent_state, state, 32);
    m.n_wal = nwal;
    for (uint32_t i = 0; i < nwal; i++) memcpy(m.wal[i], wal[i], 32);
    int rc = cc_manifest_encode(&m, o->b, sizeof o->b, &o->n, NULL);
    CK_(rc == CC_OK, "manifest encode rc=%d", rc);
    fin(o, CC_KIND_MANIFEST);
}
static void mk_wal(struct obj *o, uint64_t seq, const char *const *stmts, uint32_t n)
{
    static struct cc_wal w;
    memset(&w, 0, sizeof w);
    w.sequence = seq;
    w.n = n;
    for (uint32_t i = 0; i < n; i++) {
        w.rec[i].status = CC_EPI_DIRECT_OBSERVATION;
        memset(w.rec[i].evidence_hash, (int)(0x40 + i), 32);
        w.rec[i].len = (uint16_t)strlen(stmts[i]);
        w.rec[i].statement = (const uint8_t *)stmts[i];
    }
    CK_(cc_wal_encode(&w, o->b, sizeof o->b, &o->n, NULL) == CC_OK, "wal encode");
    fin(o, CC_KIND_CORTEX_WAL);
}

static int commit(struct obj **os, size_t n)
{
    ss_object so[SS_MAX_OBJECTS];
    for (size_t i = 0; i < n; i++) {
        so[i].kind = os[i]->kind;
        so[i].version = os[i]->ver;
        so[i].bytes = os[i]->b;
        so[i].len = os[i]->n;
    }
    return ss_transact(&g_s, so, n, NULL, NULL, NULL);
}
static int commit1(struct obj *o)
{
    struct obj *a[1] = {o};
    return commit(a, 1);
}

static int do_resolve(const char **why, int *rc)
{
    struct cr_source src;
    cr_bind_sealed(&src, &g_s);
    return cr_resolve(&src, &g_w, &g_v, why, rc);
}

#define EXPECT(outcome, reason)                                                          \
    do {                                                                                 \
        const char *w_ = NULL, *r_ = (reason);                                           \
        int rc_ = 0, o_ = do_resolve(&w_, &rc_);                                         \
        CK_(o_ == (outcome) && (!r_ || (w_ && !strcmp(w_, r_))),                       \
            "bs=%u %s: got %s (%s), want %s (%s)", g_bs, __func__, cr_outcome_name(o_),  \
            w_ ? w_ : "-", cr_outcome_name(outcome), r_ ? r_ : "-");                     \
    } while (0)

/* Genesis, as provision would write it (INV-8): root, state(written_at 1),
 * manifest 1 in one transaction. ids in O[0..3]. */
static void genesis(void)
{
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    mk_state(&O[1], AG, 1);
    mk_man(&O[2], O[0].id, NULL, 1, 1, O[1].id, NULL, 0);
    struct obj *a[3] = {&O[0], &O[1], &O[2]};
    CK_(commit(a, 3) == 0, "commit genesis");
}

static void t_unprovisioned(void)
{
    fresh();
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_UNPROVISIONED, NULL);
    /* kind 19 (CortexCheckpoint) is ignored by Rust (no code reads it): still Unprovisioned. */
    memset(&O[7], 0, sizeof O[7]);
    memcpy(O[7].b, "stray", 5);
    O[7].n = 5;
    O[7].kind = 19;
    O[7].ver = 1;
    CK_(commit1(&O[7]) == 0, "kind 19 write");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_UNPROVISIONED, NULL);
    /* an unrelated application kind is ignored as well */
    O[7].kind = 0x0B00;
    CK_(commit1(&O[7]) == 0, "boot kind write");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_UNPROVISIONED, NULL);
}

/* The memory digest of {alpha, bravo!}, computed with sha256sum outside C. */
#define MEM_AB "d6ac0e5f36b30cbac775b60eb8beccb8260390e26373cbec5613ef8f157e922c"
#define MEM_EMPTY "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

static void t_resolved(void)
{
    fresh();
    genesis();
    CK_(reopen() == 0, "reopen");
    const char *w = NULL;
    int rc = 0, o = do_resolve(&w, &rc);
    CK_(o == CR_RESOLVED, "genesis resolves: %s %s", cr_outcome_name(o), w ? w : "-");
    uint8_t want[32];
    CK_(memcmp(g_v.root.agent_id, AG, 32) == 0, "agent id");
    CK_(g_v.manifest.sequence == 1 && g_v.manifest.incarnation == 1, "sequence/incarnation");
    CK_(g_v.state.n == 1 && g_v.cortex_count == 0, "branches/cortex");
    unhex(MEM_EMPTY, want);
    CK_(memcmp(g_v.memory, want, 32) == 0, "empty memory digest");
    CK_(memcmp(g_v.root_id, O[0].id, 32) == 0 && memcmp(g_v.manifest_id, O[2].id, 32) == 0, "ids");

    /* manifest 2 (+WAL seq 2, 2 records), manifest 3 (+WAL seq 3, 1 record, state rewritten) */
    const char *s1[] = {"alpha", "bravo!"};
    mk_wal(&O[3], 2, s1, 2);
    uint8_t wl[2][32];
    memcpy(wl[0], O[3].id, 32);
    mk_man(&O[4], O[0].id, O[2].id, 2, 2, O[1].id, wl, 1);
    struct obj *a1[2] = {&O[3], &O[4]};
    CK_(commit(a1, 2) == 0, "commit 2");
    CK_(reopen() == 0, "reopen");
    o = do_resolve(&w, &rc);
    CK_(o == CR_RESOLVED, "chain of 2 resolves: %s %s", cr_outcome_name(o), w ? w : "-");
    CK_(g_v.manifest.sequence == 2 && g_v.manifest.incarnation == 2 && g_v.cortex_count == 2, "view 2");
    unhex(MEM_AB, want);
    CK_(memcmp(g_v.memory, want, 32) == 0, "memory digest of {alpha, bravo!}");

    const char *s2[] = {"charlie"};
    mk_wal(&O[5], 3, s2, 1);
    memcpy(wl[1], O[5].id, 32);
    mk_man(&O[6], O[0].id, O[4].id, 3, 3, O[1].id, wl, 2);
    struct obj *a2[2] = {&O[5], &O[6]};
    CK_(commit(a2, 2) == 0, "commit 3");
    CK_(reopen() == 0, "reopen");
    o = do_resolve(&w, &rc);
    CK_(o == CR_RESOLVED, "chain of 3 resolves: %s %s", cr_outcome_name(o), w ? w : "-");
    CK_(g_v.manifest.sequence == 3 && g_v.cortex_count == 3 && g_v.manifest.n_wal == 2, "view 3");
    CK_(memcmp(g_v.manifest_id, O[6].id, 32) == 0, "current manifest is the highest sequence");
    /* memory digest over all three records, streamed in commit order */
    uint8_t m3[32];
    {
        static const char *all[] = {"alpha", "bravo!", "charlie"};
        sha256_ctx h;
        sha256_init(&h);
        for (int i = 0; i < 3; i++) {
            uint8_t l4[4] = {(uint8_t)strlen(all[i]), 0, 0, 0};
            sha256_update(&h, l4, 4);
            sha256_update(&h, (const uint8_t *)all[i], strlen(all[i]));
        }
        sha256_final(&h, m3);
    }
    CK_(memcmp(g_v.memory, m3, 32) == 0, "memory digest over three records");
}

static void t_resolve_never_writes(void)
{
    fresh();
    genesis();
    CK_(reopen() == 0, "reopen");
    static uint8_t a[T_UNITS * 4096u], b[T_UNITS * 4096u];
    FILE *f = fopen(g_path, "rb");
    CK_(f && fread(a, 1, sizeof a, f) == sizeof a, "read image");
    if (f) fclose(f);
    uint64_t w0 = g_f.blocks_written, f0 = g_f.flushes;
    EXPECT(CR_RESOLVED, NULL);
    CK_(g_f.blocks_written == w0 && g_f.flushes == f0, "no block written, no flush");
    f = fopen(g_path, "rb");
    CK_(f && fread(b, 1, sizeof b, f) == sizeof b, "reread image");
    if (f) fclose(f);
    CK_(memcmp(a, b, sizeof a) == 0, "image unchanged after resolve");
}

/* INV-5 / MC-2: continuity objects with no root are Corrupt, never Unprovisioned. */
static void t_orphans(void)
{
    static const char *WHY = "continuity objects without an agent root";
    uint8_t rootid[32];
    memset(rootid, 0xee, 32);
    /* orphan manifest */
    fresh();
    mk_state(&O[1], AG, 1);
    mk_man(&O[2], rootid, NULL, 1, 1, O[1].id, NULL, 0);
    CK_(commit1(&O[2]) == 0, "write orphan manifest");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, WHY);
    /* orphan agent state */
    fresh();
    CK_(commit1(&O[1]) == 0, "write orphan state");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, WHY);
    /* orphan WAL */
    fresh();
    const char *s[] = {"x"};
    mk_wal(&O[3], 1, s, 1);
    CK_(commit1(&O[3]) == 0, "write orphan wal");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, WHY);
}

static void t_conflict(void) /* INV-5, MC-12: two roots */
{
    fresh();
    genesis();
    mk_root(&O[5], AG2, CC_SOURCE_QUALIFICATION);
    CK_(commit1(&O[5]) == 0, "second root");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CONFLICT, NULL);
}

static void t_duplicate_id(void) /* P-3 */
{
    fresh();
    genesis();
    CK_(commit1(&O[0]) == 0, "same root bytes written twice (sealed store allows it)");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "duplicate logical object id");
    /* the duplicate is detected before the root count: it is not a Conflict */
}

static void t_chain(void) /* INV-6, MC-4 */
{
    /* previous names a wrong id (an object that exists, but is not manifest 1) */
    fresh();
    genesis();
    mk_man(&O[3], O[0].id, O[1].id, 2, 2, O[1].id, NULL, 0);
    CK_(commit1(&O[3]) == 0, "manifest 2 with wrong previous");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "manifest chain is broken");
    /* previous = an id that exists nowhere */
    fresh();
    genesis();
    uint8_t nowhere[32];
    memset(nowhere, 0xcd, 32);
    mk_man(&O[3], O[0].id, nowhere, 2, 2, O[1].id, NULL, 0);
    CK_(commit1(&O[3]) == 0, "manifest 2 with absent previous");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "manifest chain is broken");
    /* gap: sequence 3 after 1 */
    fresh();
    genesis();
    mk_man(&O[3], O[0].id, O[2].id, 3, 2, O[1].id, NULL, 0);
    CK_(commit1(&O[3]) == 0, "manifest with sequence 3");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "manifest sequence gap or fork");
    /* fork: two manifests with sequence 2 */
    fresh();
    genesis();
    mk_man(&O[3], O[0].id, O[2].id, 2, 2, O[1].id, NULL, 0);
    mk_man(&O[4], O[0].id, O[2].id, 2, 3, O[1].id, NULL, 0);
    struct obj *a[2] = {&O[3], &O[4]};
    CK_(commit(a, 2) == 0, "two manifests with sequence 2");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "manifest sequence gap or fork");
    /* foreign root */
    fresh();
    genesis();
    uint8_t other[32];
    memset(other, 0x99, 32);
    mk_man(&O[3], other, O[2].id, 2, 2, O[1].id, NULL, 0);
    CK_(commit1(&O[3]) == 0, "manifest naming a foreign root");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "manifest names a foreign root");
    /* root and state but no manifest */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    mk_state(&O[1], AG, 1);
    struct obj *b[2] = {&O[0], &O[1]};
    CK_(commit(b, 2) == 0, "root + state only");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "agent root has no manifest");
}

static void t_references(void) /* INV-7: kinds, absence, order */
{
    /* manifest names a WAL object as its agent state (wrong kind) */
    const char *s[] = {"w"};
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    mk_wal(&O[3], 1, s, 1);
    mk_man(&O[2], O[0].id, NULL, 1, 1, O[3].id, NULL, 0);
    struct obj *a[3] = {&O[0], &O[3], &O[2]};
    CK_(commit(a, 3) == 0, "wrong-kind state reference");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "referenced object has the wrong kind");
    /* WAL list names a state object (wrong kind) */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    mk_state(&O[1], AG, 1);
    uint8_t wl[2][32];
    memcpy(wl[0], O[1].id, 32);
    mk_man(&O[2], O[0].id, NULL, 1, 1, O[1].id, wl, 1);
    struct obj *b[3] = {&O[0], &O[1], &O[2]};
    CK_(commit(b, 3) == 0, "state named as WAL");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "referenced object has the wrong kind");
    /* absent state */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    uint8_t gone[32];
    memset(gone, 0xab, 32);
    mk_man(&O[2], O[0].id, NULL, 1, 1, gone, NULL, 0);
    struct obj *c[2] = {&O[0], &O[2]};
    CK_(commit(c, 2) == 0, "absent state reference");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "referenced object is absent");
    /* zero state id */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    mk_man(&O[2], O[0].id, NULL, 1, 1, NULL, NULL, 0);
    struct obj *d[2] = {&O[0], &O[2]};
    CK_(commit(d, 2) == 0, "no agent state");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "manifest has no agent state");
    /* state of another agent */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    mk_state(&O[1], AG2, 1);
    mk_man(&O[2], O[0].id, NULL, 1, 1, O[1].id, NULL, 0);
    struct obj *e[3] = {&O[0], &O[1], &O[2]};
    CK_(commit(e, 3) == 0, "state of another agent");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "agent state belongs to another agent");
    /* WAL segments out of order (sequence 2 then 1) and beyond the manifest */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    mk_state(&O[1], AG, 1);
    mk_man(&O[2], O[0].id, NULL, 1, 1, O[1].id, NULL, 0);
    mk_wal(&O[3], 2, s, 1);
    mk_wal(&O[4], 1, s, 1);
    memcpy(wl[0], O[3].id, 32);
    memcpy(wl[1], O[4].id, 32);
    mk_man(&O[5], O[0].id, O[2].id, 2, 2, O[1].id, wl, 2);
    struct obj *f[5] = {&O[0], &O[1], &O[2], &O[3], &O[4]};
    CK_(commit(f, 5) == 0, "genesis + two wal");
    CK_(commit1(&O[5]) == 0, "manifest 2 with WAL order 2,1");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "WAL segments out of order");
    /* WAL sequence beyond the manifest sequence */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    mk_state(&O[1], AG, 1);
    mk_wal(&O[3], 5, s, 1);
    memcpy(wl[0], O[3].id, 32);
    mk_man(&O[2], O[0].id, NULL, 1, 1, O[1].id, wl, 1);
    struct obj *g[4] = {&O[0], &O[1], &O[3], &O[2]};
    CK_(commit(g, 4) == 0, "WAL from the future");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "WAL segments out of order");
}

static void t_versions_and_decode(void)
{
    /* a root stored with Store version 2 counts as a root but cannot be read as one */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    O[0].ver = 2;
    CK_(commit1(&O[0]) == 0, "root v2");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "referenced object has the wrong kind");
    /* bad magic root */
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    O[0].b[0] ^= 1;
    CK_(commit1(&O[0]) == 0, "root with bad magic");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_CORRUPT, "bad magic");
    /* empty object: a continuity kind with zero bytes cannot have a logical id */
    fresh();
    memset(&O[6], 0, sizeof O[6]);
    O[6].kind = CC_KIND_MANIFEST;
    O[6].ver = 1;
    O[6].n = 0;
    ss_object so = {CC_KIND_MANIFEST, 1, O[6].b, 0};
    int rc = ss_transact(&g_s, &so, 1, NULL, NULL, NULL);
    if (rc == 0) {
        CK_(reopen() == 0, "reopen");
        EXPECT(CR_CORRUPT, "continuity object has no valid id");
    } else {
        printf("note: sealed store refuses a zero-length object (rc=%d)\n", rc);
    }
}

/* K-1 (contract 5.3): 16384 bytes is the sealed Store bound. The largest legal
 * branch table (204 branches) goes through the whole pipeline; one object past
 * the bound cannot be written to the sealed Store at all. */
static void t_size_bound(void)
{
    static struct cc_state s;
    fresh();
    mk_root(&O[0], AG, CC_SOURCE_OPERATOR);
    cc_state_genesis(&s, AG, 1);
    uint8_t child[32];
    for (int i = 1; i < (int)CC_MAX_BRANCHES_IN_CAP; i++)
        CK_(cc_state_fork(&s, s.br[0].id, child, NULL) == CC_OK, "fork %d", i);
    CK_(cc_state_encode(&s, O[1].b, sizeof O[1].b, &O[1].n, NULL) == CC_OK, "encode 204 branches");
    CK_(O[1].n == CC_MAX_OBJECT_BYTES, "204 branches are exactly %u bytes (got %zu)", CC_MAX_OBJECT_BYTES, O[1].n);
    fin(&O[1], CC_KIND_AGENT_STATE);
    mk_man(&O[2], O[0].id, NULL, 1, 1, O[1].id, NULL, 0);
    struct obj *a[3] = {&O[0], &O[1], &O[2]};
    CK_(commit(a, 3) == 0, "commit 16384-byte state");
    CK_(reopen() == 0, "reopen");
    EXPECT(CR_RESOLVED, NULL);
    CK_(g_v.state.n == CC_MAX_BRANCHES_IN_CAP, "204 branches read back");

    /* one byte past the bound: the sealed Store refuses to write it */
    fresh();
    uint64_t gen0 = ss_generation(&g_s);
    static uint8_t big[SS_MAX_PLAINTEXT + 1];
    memset(big, 0x41, sizeof big);
    ss_object so = {CC_KIND_AGENT_STATE, 1, big, sizeof big};
    int rc = ss_transact(&g_s, &so, 1, NULL, NULL, NULL);
    CK_(rc != 0, "sealed Store accepted %zu bytes", sizeof big);
    CK_(ss_generation(&g_s) == gen0, "nothing committed");
    CK_(reopen() == 0, "reopen");
    CK_(ss_generation(&g_s) == gen0, "generation unchanged after reopen");
    EXPECT(CR_UNPROVISIONED, NULL);
}

/* K-5: does ss_open return 0 on a DegradedRecovery mount with a malformed
 * peer? Answered here by running it; the result is printed and checked. */
static void t_degraded(void)
{
    fresh();
    genesis();
    const char *s[] = {"alpha", "bravo!"};
    mk_wal(&O[3], 2, s, 2);
    uint8_t wl[1][32];
    memcpy(wl[0], O[3].id, 32);
    mk_man(&O[4], O[0].id, O[2].id, 2, 2, O[1].id, wl, 1);
    struct obj *a[2] = {&O[3], &O[4]};
    CK_(commit(a, 2) == 0, "commit 2");
    CK_(reopen() == 0, "reopen valid");
    EXPECT(CR_RESOLVED, NULL);
    uint8_t agent[32], mem[32];
    memcpy(agent, g_v.root.agent_id, 32);
    memcpy(mem, g_v.memory, 32);
    struct cr_source src;
    cr_bind_sealed(&src, &g_s);
    CK_(g_s.st.state == ST_VALID, "valid mount");
    CK_(cr_writable(&src) == CR_RESOLVED, "valid mount is writable");
    uint32_t active = st_active_slot(&g_s.st);
    uint64_t gen = ss_generation(&g_s);

    /* Fill the inactive superblock slot (Store-region unit 1 - active) with garbage. */
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
    int orc = reopen();
    printf("K-5 answer: ss_open rc=%d, state=%d (1 = DegradedRecovery), peer=%d (2 = Malformed), "
           "generation %llu -> %llu\n",
           orc, g_s.st.state, g_s.st.peer, (unsigned long long)gen,
           (unsigned long long)ss_generation(&g_s));
    CK_(orc == 0, "K-5: ss_open returns 0 on a degraded mount with a malformed peer");
    CK_(g_s.st.state == ST_DEGRADED_RECOVERY && g_s.st.peer == ST_PEER_MALFORMED, "degraded, malformed peer");
    CK_(ss_generation(&g_s) == gen, "same generation");
    cr_bind_sealed(&src, &g_s);
    CK_(cr_writable(&src) == CR_READ_ONLY, "degraded mount is not writable (INV-11)");
    const char *w = NULL;
    int rc = 0, o = do_resolve(&w, &rc);
    CK_(o == CR_RESOLVED, "degraded mount still resolves the verified view: %s %s", cr_outcome_name(o), w ? w : "-");
    CK_(memcmp(g_v.root.agent_id, agent, 32) == 0 && memcmp(g_v.memory, mem, 32) == 0, "same agent and memory");
    CK_(g_v.manifest.incarnation == 2 && g_v.cortex_count == 2, "same view");
    /* The raw state digest reads the junk unit as it is (not repaired, not decoded). */
    uint8_t dg[32], expect[32];
    cr_state_digest_dev(&g_sdev, dg);
    static uint8_t raw[2 * 4096];
    f = fopen(g_path, "rb");
    CK_(f && fseek(f, (long)(A_UNITS * 4096u), SEEK_SET) == 0 && fread(raw, 1, sizeof raw, f) == sizeof raw,
        "read raw units");
    if (f) fclose(f);
    sha256_hash(raw, sizeof raw, expect);
    CK_(memcmp(dg, expect, 32) == 0, "cr_state_digest_dev = SHA-256 of the two raw Store units");
}

/* ---- fake source: the cases the real Store cannot produce ---- */
struct fake {
    uint16_t kind[4];
    size_t len[4];
    int rc[4];
    uint32_t n;
    int mount;
};
static uint32_t fk_count(void *c) { return ((struct fake *)c)->n; }
static int fk_entry(void *c, uint32_t i, uint16_t *k, uint16_t *v)
{
    struct fake *f = c;
    *k = f->kind[i];
    *v = 1;
    return 0;
}
static int fk_read(void *c, uint32_t i, uint8_t *out, size_t cap, size_t *len)
{
    struct fake *f = c;
    if (f->rc[i]) return f->rc[i];
    *len = f->len[i];
    memset(out, 0x55, *len < cap ? *len : cap);
    return 0;
}
static int fk_mount(void *c) { return ((struct fake *)c)->mount; }

static void t_fake(void)
{
    struct fake f;
    memset(&f, 0, sizeof f);
    struct cr_source src = {&f, fk_count, fk_entry, fk_read, fk_mount, NULL};
    const char *w = NULL;
    int rc = 0;
    /* oversize (K-1): Limit, never decoded, never truncated */
    f.n = 1;
    f.kind[0] = CC_KIND_AGENT_STATE;
    f.len[0] = CC_MAX_OBJECT_BYTES + 1;
    int o = cr_resolve(&src, &g_w, &g_v, &w, &rc);
    CK_(o == CR_LIMIT && w && !strcmp(w, "continuity object exceeds the size bound"), "oversize: %s", cr_outcome_name(o));
    f.len[0] = CC_MAX_OBJECT_BYTES; /* at the bound: read, then refused by the decoder as Corrupt */
    o = cr_resolve(&src, &g_w, &g_v, &w, &rc);
    CK_(o == CR_CORRUPT, "bound-sized garbage is Corrupt, not Limit: %s", cr_outcome_name(o));
    /* read error passes through as Store */
    f.rc[0] = -4242;
    o = cr_resolve(&src, &g_w, &g_v, &w, &rc);
    CK_(o == CR_STORE && rc == -4242, "store error passes through: %s %d", cr_outcome_name(o), rc);
    /* untracked kinds are never read */
    f.kind[0] = 0x0B00;
    f.rc[0] = -1;
    o = cr_resolve(&src, &g_w, &g_v, &w, &rc);
    CK_(o == CR_UNPROVISIONED, "unrelated kind never read: %s", cr_outcome_name(o));
    /* mount state */
    f.mount = CR_MOUNT_DEGRADED;
    CK_(cr_writable(&src) == CR_READ_ONLY, "degraded fake is read only");
    f.mount = CR_MOUNT_VALID;
    CK_(cr_writable(&src) == CR_RESOLVED, "valid fake is writable");
    struct cr_source bad = src;
    bad.mount_state = NULL;
    CK_(cr_writable(&bad) == CR_READ_ONLY, "no mount_state fails closed");
    CK_(cr_resolve(NULL, &g_w, &g_v, &w, &rc) == CR_E_ARG, "NULL source");
    CK_(cr_resolve(&src, NULL, &g_v, &w, &rc) == CR_E_ARG, "NULL work");
}

static const char *fixture_dir;

int main(int argc, char **argv)
{
    memset(UUID, 0x5a, 16);
    memset(DIGEST, 0x33, 32);
    memset(KEY0F, 0x0f, 32);
    memset(AG, 0x11, 32);
    memset(AG2, 0x22, 32);
#ifdef CR_FIXTURE_DIR
    fixture_dir = argc > 1 ? argv[1] : CR_FIXTURE_DIR;
#else
    fixture_dir = argc > 1 ? argv[1] : NULL;
#endif
    test_challenge_kat();
    test_operator_kat();
    test_challenge_binding();
    test_state_digest();
    CK_(fixture_dir && test_fixture(fixture_dir) && fx_checked == 4, "deferred fixture lines compared: %d", fx_checked);

    make_keys();
    snprintf(g_path, sizeof g_path, "/tmp/ck_cr_test_%d.img", (int)getpid());
    t_fake();
    static const uint32_t geos[2] = {4096u, 512u};
    for (int g = 0; g < 2; g++) {
        g_bs = geos[g];
        t_unprovisioned();
        t_resolved();
        t_resolve_never_writes();
        t_orphans();
        t_conflict();
        t_duplicate_id();
        t_chain();
        t_references();
        t_versions_and_decode();
        t_size_bound();
        t_degraded();
    }
    dev_close();
    unlink(g_path);
    return ck_t_verdict("test_continuity_resolve");
}
