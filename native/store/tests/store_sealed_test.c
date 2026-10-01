/* Sealed store tests (M5 envelopes + transaction records + torn_slot anchor),
 * file-backed through native/disk disk_file, 512 and 4096 geometry. */
#include "store_test_util.h"
#include "store_rig.h"
#include "../argus/sha256.h"
#include "store_v1.h"

#define SCHECK_EQ(got, want, what)                                                    \
    do {                                                                              \
        long long g_ = (long long)(got), w_ = (long long)(want);                      \
        CHECK(g_ == w_, "%s: got %lld (%s), want %lld (%s)", what, g_, ss_strerror((int)g_), \
              w_, ss_strerror((int)w_));                                              \
    } while (0)

static ss_workspace g_ws;
static uint8_t img_a[RIG_BYTES], img_b[RIG_BYTES], img_c[RIG_BYTES];
static char g_path[512];
static uint32_t g_bs;
static ss_keys K, K_TEST, K_OTHER;

static uint8_t P1[700], P2[9000], P3[16384], P4[1];

static void fill(uint8_t *p, size_t n, uint32_t seed)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)((i * 131u + seed * 7u + (i >> 9)) & 0xff);
}

static int sopen(rig *r, ss_store *s, const ss_keys *k)
{
    if (rig_open(r, g_path, g_bs, 0) != 0) return -9999;
    int rc = ss_open(s, &r->sdev, &r->tdev, 0, k, &g_ws);
    return rc;
}

/* region helpers: anchor = units 0..3, store = units 4.. */
static void copy_anchor(uint8_t *dst, const uint8_t *src)
{
    memcpy(dst, src, (size_t)RIG_ANCHOR_UNITS * 4096u);
}
static void copy_store(uint8_t *dst, const uint8_t *src)
{
    memcpy(dst + RIG_ANCHOR_UNITS * 4096u, src + RIG_ANCHOR_UNITS * 4096u,
           (size_t)RIG_STORE_UNITS * 4096u);
}

static int check_read(ss_store *s, const uint8_t sid[32], const uint8_t *want, size_t n, uint16_t kind)
{
    static uint8_t out[SS_MAX_PLAINTEXT];
    size_t len = 0;
    uint16_t k = 0;
    int rc = ss_read(s, sid, out, sizeof out, &len, &k);
    if (rc != 0) return rc;
    if (len != n || k != kind || memcmp(out, want, n) != 0) return -1;
    return 0;
}

/* Format, commit gen 2 {P1 kind 40, P2 kind 41}. */
static void make_gen2(uint8_t ids[][32])
{
    rig r;
    CHECK(rig_open(&r, g_path, g_bs, 1) == 0, "rig create");
    SCHECK_EQ(ss_format(&r.sdev, &r.tdev, 0, RIG_UUID, &K, &g_ws), 0, "format");
    ss_store s;
    SCHECK_EQ(ss_open(&s, &r.sdev, &r.tdev, 0, &K, &g_ws), 0, "open genesis");
    SCHECK_EQ(s.rb, SS_RB_VALID_RESUME, "genesis anchor resumes");
    ss_object o[2] = {{40, 1, P1, sizeof P1}, {41, 2, P2, sizeof P2}};
    SCHECK_EQ(ss_transact(&s, o, 2, NULL, NULL, ids), 0, "gen 2 transact");
    rig_close(&r);
}

static void advance(const ss_keys *k, uint16_t kind, const uint8_t *p, size_t n, uint8_t id[32], int want)
{
    rig r;
    ss_store s;
    SCHECK_EQ(sopen(&r, &s, k), 0, "open for advance");
    ss_object o = {kind, 1, p, n};
    uint8_t ids[1][32];
    SCHECK_EQ(ss_transact(&s, &o, 1, NULL, NULL, ids), want, "advance");
    if (id) memcpy(id, ids[0], 32);
    rig_close(&r);
}

static int open_rc(const ss_keys *k)
{
    rig r;
    ss_store s;
    int rc = sopen(&r, &s, k);
    rig_close(&r);
    return rc;
}

static void test_basic(void)
{
    uint8_t ids[2][32];
    make_gen2(ids);
    rig r;
    ss_store s;
    SCHECK_EQ(sopen(&r, &s, &K), 0, "reopen gen 2");
    SCHECK_EQ(ss_generation(&s), 2, "generation 2");
    SCHECK_EQ(s.rb, SS_RB_VALID_RESUME, "anchor current");
    SCHECK_EQ(check_read(&s, ids[0], P1, sizeof P1, 40), 0, "read P1");
    SCHECK_EQ(check_read(&s, ids[1], P2, sizeof P2, 41), 0, "read P2");
    /* every catalog object is sealed: envelopes or one record per generation */
    uint32_t n;
    const sv1_entry *e = st_catalog(&s.st, &n);
    int nenv = 0, ntx = 0;
    for (uint32_t i = 0; i < n; i++) {
        nenv += e[i].kind == SS_KIND_ENVELOPE;
        ntx += e[i].kind == SS_KIND_TXREC;
    }
    CHECK(nenv == 2 && ntx == 1 && n == 3, "catalog holds 2 envelopes + 1 record (%d %d %u)", nenv, ntx, n);
    /* plaintext is not on disk */
    rig_close(&r);
    CHECK(file_load(g_path, img_a, RIG_BYTES) == 0, "load");
    int found = 0;
    for (size_t i = 0; i + 64 <= RIG_BYTES; i += 1)
        if (memcmp(img_a + i, P2 + 100, 64) == 0) { found = 1; break; }
    CHECK(!found, "plaintext bytes absent from the image");
    /* arguments */
    SCHECK_EQ(sopen(&r, &s, &K), 0, "reopen");
    uint8_t out[16];
    size_t len;
    SCHECK_EQ(ss_read(&s, ids[1], out, sizeof out, &len, NULL), SS_E_ARG, "read cap too small");
    uint8_t bogus[32] = {1};
    SCHECK_EQ(ss_read(&s, bogus, out, sizeof out, &len, NULL), ST_E_INVALID_OBJECT, "read unknown id");
    ss_object many[SS_MAX_OBJECTS + 1];
    for (unsigned i = 0; i <= SS_MAX_OBJECTS; i++) many[i] = (ss_object){50, 1, P4, 1};
    SCHECK_EQ(ss_transact(&s, many, 0, NULL, NULL, NULL), SS_E_ARG, "zero objects");
    SCHECK_EQ(ss_transact(&s, many, SS_MAX_OBJECTS + 1, NULL, NULL, NULL), SS_E_ARG, "too many objects");
    static uint8_t big[SS_MAX_PLAINTEXT + 1];
    ss_object ob = {50, 1, big, sizeof big};
    SCHECK_EQ(ss_transact(&s, &ob, 1, NULL, NULL, NULL), SS_E_ARG, "object too large");
    ss_object oz = {0, 1, P4, 1};
    SCHECK_EQ(ss_transact(&s, &oz, 1, NULL, NULL, NULL), SS_E_ARG, "kind zero");
    /* max objects, empty and max-size plaintext */
    for (unsigned i = 0; i < SS_MAX_OBJECTS; i++) many[i] = (ss_object){(uint16_t)(60 + i), 1, P3, i == 0 ? 0 : sizeof P3 / (i + 1)};
    many[SS_MAX_OBJECTS - 1].len = sizeof P3;
    uint8_t mids[SS_MAX_OBJECTS][32];
    SCHECK_EQ(ss_transact(&s, many, SS_MAX_OBJECTS, NULL, NULL, mids), 0, "8-object transaction");
    rig_close(&r);
    SCHECK_EQ(sopen(&r, &s, &K), 0, "reopen gen 3");
    SCHECK_EQ(ss_generation(&s), 3, "generation 3");
    for (unsigned i = 0; i < SS_MAX_OBJECTS; i++)
        SCHECK_EQ(check_read(&s, mids[i], P3, many[i].len, (uint16_t)(60 + i)), 0, "read max transaction");
    SCHECK_EQ(check_read(&s, ids[0], P1, sizeof P1, 40), 0, "gen 2 object still readable");
    rig_close(&r);
    /* genesis with an empty anchor region is accepted only at generation 1 */
    CHECK(rig_open(&r, g_path, g_bs, 1) == 0, "rig create");
    SCHECK_EQ(st_format(&r.sdev, RIG_UUID), 0, "store-only genesis");
    SCHECK_EQ(ss_open(&s, &r.sdev, &r.tdev, 0, &K, &g_ws), 0, "empty anchor at genesis");
    SCHECK_EQ(s.rb, SS_RB_GENESIS, "genesis decision");
    ss_object o1 = {40, 1, P1, sizeof P1};
    SCHECK_EQ(ss_transact(&s, &o1, 1, NULL, NULL, NULL), 0, "first transaction catches the anchor up");
    rig_close(&r);
    SCHECK_EQ(open_rc(&K), 0, "reopen after genesis catch-up");
}

static void test_rollback(void)
{
    uint8_t ids[2][32];
    make_gen2(ids);
    CHECK(file_load(g_path, img_a, RIG_BYTES) == 0, "snapshot gen 2");
    advance(&K, 42, P1, 10, NULL, 0); /* gen 3 */
    CHECK(file_load(g_path, img_b, RIG_BYTES) == 0, "snapshot gen 3");
    advance(&K, 43, P1, 20, NULL, 0); /* gen 4 */
    CHECK(file_load(g_path, img_c, RIG_BYTES) == 0, "snapshot gen 4");
    SCHECK_EQ(open_rc(&K), 0, "gen 4 mounts");

    /* Store rolled back one generation under the current anchor */
    static uint8_t t[RIG_BYTES];
    memcpy(t, img_c, RIG_BYTES);
    copy_store(t, img_b);
    CHECK(file_save(g_path, t, RIG_BYTES) == 0, "write");
    SCHECK_EQ(open_rc(&K), SS_E_ROLLBACK, "store gen 3 under anchor 4");
    memcpy(t, img_c, RIG_BYTES);
    copy_store(t, img_a);
    CHECK(file_save(g_path, t, RIG_BYTES) == 0, "write");
    SCHECK_EQ(open_rc(&K), SS_E_ROLLBACK, "store gen 2 under anchor 4");
    /* anchor replayed: one behind is a crash window (accepted), two behind is not */
    memcpy(t, img_c, RIG_BYTES);
    copy_anchor(t, img_b);
    CHECK(file_save(g_path, t, RIG_BYTES) == 0, "write");
    {
        rig r;
        ss_store s;
        SCHECK_EQ(sopen(&r, &s, &K), 0, "anchor one behind");
        SCHECK_EQ(s.rb, SS_RB_PREPARED_ADVANCE, "prepared advance");
        rig_close(&r);
    }
    memcpy(t, img_c, RIG_BYTES);
    copy_anchor(t, img_a);
    CHECK(file_save(g_path, t, RIG_BYTES) == 0, "write");
    SCHECK_EQ(open_rc(&K), SS_E_INCONSISTENT, "replayed anchor two behind");
    /* anchor missing after genesis */
    memcpy(t, img_c, RIG_BYTES);
    memset(t, 0, (size_t)RIG_ANCHOR_UNITS * 4096u);
    CHECK(file_save(g_path, t, RIG_BYTES) == 0, "write");
    SCHECK_EQ(open_rc(&K), SS_E_ROLLBACK, "missing anchor at gen 4");
    /* whole-disk rollback (both regions) is NOT detected: documented limit */
    CHECK(file_save(g_path, img_a, RIG_BYTES) == 0, "write");
    SCHECK_EQ(open_rc(&K), 0, "whole-disk rollback mounts (needs TPM NV, TRUST-1)");

    /* forked anchor: same counter, different digest, valid MAC */
    CHECK(file_save(g_path, img_c, RIG_BYTES) == 0, "write");
    {
        rig r;
        ss_store s;
        SCHECK_EQ(sopen(&r, &s, &K), 0, "open gen 4");
        uint8_t *rec = g_ws.tsrec;
        memset(rec, 0, 4096);
        memcpy(rec, "AIENSAN1", 8);
        rec[8] = 1;
        rec[10] = K.identity_class;
        memcpy(rec + 16, RIG_UUID, 16);
        m5_anchor a = {0};
        a.identity_class = K.identity_class;
        memcpy(a.store_uuid, RIG_UUID, 16);
        a.store_generation = 4;
        a.key_generation = 1;
        a.counter = 4;
        memset(a.commit_digest, 0x77, 32);
        CHECK(m5_anchor_seal(&a, K.k_root_auth, rec + 32, M5_ANCHOR_LEN) == M5_OK, "seal");
        CHECK(ts_commit(&s.ts, rec) == TS_OK, "commit forked anchor");
        rig_close(&r);
    }
    SCHECK_EQ(open_rc(&K), SS_E_ROLLBACK, "forked anchor at the same counter");

    /* anchor record naming another store around a valid M5 anchor */
    CHECK(file_save(g_path, img_c, RIG_BYTES) == 0, "write");
    {
        rig r;
        ss_store s;
        SCHECK_EQ(sopen(&r, &s, &K), 0, "open gen 4");
        uint8_t *rec = g_ws.tsrec;
        memset(rec, 0, 4096);
        memcpy(rec, "AIENSAN1", 8);
        rec[8] = 1;
        rec[10] = K.identity_class;
        memcpy(rec + 16, RIG_UUID, 16);
        rec[16] ^= 1;
        m5_anchor a = {0};
        a.identity_class = K.identity_class;
        memcpy(a.store_uuid, RIG_UUID, 16);
        a.store_generation = 4;
        a.key_generation = 1;
        a.counter = 4;
        memcpy(a.commit_digest, s.last_tx_digest, 32);
        CHECK(m5_anchor_seal(&a, K.k_root_auth, rec + 32, M5_ANCHOR_LEN) == M5_OK, "seal");
        CHECK(ts_commit(&s.ts, rec) == TS_OK, "commit relabelled anchor");
        rig_close(&r);
    }
    SCHECK_EQ(open_rc(&K), SS_E_IDENTITY, "anchor record names another store");

    /* replayed anchor seq: two valid torn_slot slots claiming one sequence */
    CHECK(file_save(g_path, img_c, RIG_BYTES) == 0, "write");
    {
        rig r;
        ss_store s;
        SCHECK_EQ(sopen(&r, &s, &K), 0, "open gen 4");
        uint8_t rec[4096];
        uint64_t seq;
        CHECK(ts_recover(&s.ts, rec, &seq, NULL) == TS_OK, "recover");
        int other = s.ts.newest_slot == 0 ? 1 : 0;
        uint8_t hdr[4096];
        memset(hdr, 0, sizeof hdr);
        ts_encode_commit(hdr, other, seq, rec);
        uint64_t base = (uint64_t)other * 2u * r.bpu;
        CHECK(r.d.write(r.d.ctx, base, r.bpu, rec) == 0, "body");
        CHECK(r.d.write(r.d.ctx, base + r.bpu, r.bpu, hdr) == 0, "header");
        rig_close(&r);
    }
    SCHECK_EQ(open_rc(&K), SS_E_ANCHOR, "duplicate anchor sequence");
}

static void test_identity(void)
{
    uint8_t ids[2][32];
    make_gen2(ids);
    SCHECK_EQ(open_rc(&K_TEST), SS_E_IDENTITY, "PRODUCTION store, TEST keys");
    SCHECK_EQ(open_rc(&K_OTHER), SS_E_TXREC, "same class, other volume key");
    /* anchor region of another store (other uuid) */
    CHECK(file_load(g_path, img_a, RIG_BYTES) == 0, "load");
    {
        rig r;
        static const uint8_t U2[16] = {9, 9, 9};
        CHECK(rig_open(&r, g_path, g_bs, 1) == 0, "create");
        SCHECK_EQ(ss_format(&r.sdev, &r.tdev, 0, U2, &K, &g_ws), 0, "format other store");
        rig_close(&r);
        CHECK(file_load(g_path, img_b, RIG_BYTES) == 0, "load");
    }
    copy_anchor(img_a, img_b);
    CHECK(file_save(g_path, img_a, RIG_BYTES) == 0, "write");
    SCHECK_EQ(open_rc(&K), SS_E_IDENTITY, "anchor of another store");
    /* TEST-class store refused by PRODUCTION keys at genesis too */
    rig r;
    CHECK(rig_open(&r, g_path, g_bs, 1) == 0, "create");
    SCHECK_EQ(ss_format(&r.sdev, &r.tdev, 0, RIG_UUID, &K_TEST, &g_ws), 0, "format TEST store");
    rig_close(&r);
    SCHECK_EQ(open_rc(&K), SS_E_IDENTITY, "TEST genesis, PRODUCTION keys");
    SCHECK_EQ(open_rc(&K_TEST), 0, "TEST genesis, TEST keys");
}

/* Forge helper: prepare one object, let edit() change the workspace, commit
 * with the real Store engine, then return the next mount's result. */
typedef void (*forge_fn)(ss_store *s, void *arg);
static int forge(forge_fn edit, void *arg)
{
    rig r;
    ss_store s;
    int rc = sopen(&r, &s, &K);
    if (rc != 0) { rig_close(&r); return -8888; }
    ss_object o[2] = {{44, 1, P1, 300}, {45, 1, P2, 5000}};
    rc = ss_prepare(&s, o, 2);
    if (rc == 0) {
        edit(&s, arg);
        rc = ss_commit_prepared(&s, NULL, NULL);
    }
    rig_close(&r);
    if (rc != 0) return -7777;
    return open_rc(&K);
}

static void put64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void ed_flip_env(ss_store *s, void *a) { (void)a; s->ws->env[0][100] ^= 1; }
static void ed_flip_env_rebind(ss_store *s, void *a)
{
    (void)a;
    ss_workspace *w = s->ws;
    w->env[0][100] ^= 1; /* ciphertext byte: AEAD tag will fail */
    uint8_t *e = w->tx + SS_TX_HDR;
    sv1_object_id(SS_KIND_ENVELOPE, 1, w->env[0], w->env_len[0], e);
    m5_commit c;
    m5_commit_open(e + 32, M5_COMMIT_LEN, K.k_root_auth, K.identity_class, &c);
    sha256_hash(w->env[0], w->env_len[0], c.object_id);
    m5_commit_seal(&c, K.k_root_auth, e + 32);
    ss_tx_remac(s);
}
static uint8_t junk[5000];
static void ed_extra_env(ss_store *s, void *a)
{
    (void)a;
    s->ws->objs[s->ws->nobjs++] = (st_object){SS_KIND_ENVELOPE, 1, junk, sizeof junk};
}
static void ed_plain(ss_store *s, void *a)
{
    (void)a;
    s->ws->objs[s->ws->nobjs++] = (st_object){3, 1, junk, 100};
}
static void ed_gen_skip(ss_store *s, void *a)
{
    (void)a;
    uint64_t g = ss_generation(s) + 2;
    put64le(s->ws->tx + 32, g);
    put64le(s->ws->tx + 40, g);
    ss_tx_remac(s);
}
static void ed_counter(ss_store *s, void *a)
{
    (void)a;
    put64le(s->ws->tx + 40, ss_generation(s) + 2);
    ss_tx_remac(s);
}
static uint8_t saved_tx[SS_TX_MAX];
static size_t saved_tx_len;
static void ed_stale_commit(ss_store *s, void *a)
{
    (void)a; /* entry 0 carries the previous generation's commit record */
    memcpy(s->ws->tx + SS_TX_HDR + 32, saved_tx + SS_TX_HDR + 32, M5_COMMIT_LEN);
    ss_tx_remac(s);
}
static void ed_replay_record(ss_store *s, void *a)
{
    (void)a; /* the previous record replayed whole: the Store deduplicates it */
    memcpy(s->ws->tx, saved_tx, saved_tx_len);
    s->ws->tx_len = saved_tx_len;
    s->ws->objs[s->ws->nobjs - 1].len = saved_tx_len;
}
static void ed_chain(ss_store *s, void *a)
{
    (void)a;
    s->ws->tx[56] ^= 1;
    ss_tx_remac(s);
}
static void ed_bad_mac(ss_store *s, void *a) { (void)a; s->ws->tx[s->ws->tx_len - 1] ^= 1; }
static void ed_bad_magic(ss_store *s, void *a) { (void)a; s->ws->tx[0] = 'X'; ss_tx_remac(s); }
static void ed_tx_class(ss_store *s, void *a) { (void)a; s->ws->tx[10] = M5_ID_TEST; ss_tx_remac(s); }
static void ed_seq(ss_store *s, void *a)
{
    (void)a; /* swap the two commit records: object_sequence no longer matches */
    uint8_t t[M5_COMMIT_LEN];
    uint8_t *e0 = s->ws->tx + SS_TX_HDR + 32, *e1 = e0 + SS_TX_ENTRY;
    memcpy(t, e0, sizeof t);
    memcpy(e0, e1, sizeof t);
    memcpy(e1, t, sizeof t);
    ss_tx_remac(s);
}
static uint8_t dup_tx[SS_TX_MAX];
static void ed_dup_gen(ss_store *s, void *a)
{
    (void)a; /* a second, different, validly MACed record for the same generation */
    ss_workspace *w = s->ws;
    memcpy(dup_tx, w->tx, w->tx_len);
    w->tx[56] ^= 1;
    ss_tx_remac(s);
    uint8_t t[SS_TX_MAX];
    memcpy(t, w->tx, w->tx_len);
    memcpy(w->tx, dup_tx, w->tx_len);
    memcpy(dup_tx, t, w->tx_len);
    w->objs[w->nobjs++] = (st_object){SS_KIND_TXREC, 1, dup_tx, w->tx_len};
}
static uint8_t old_sid[32];
static m5_commit old_commit;
static void ed_claim_twice(ss_store *s, void *a)
{
    (void)a; /* entry 0 re-claims a generation-2 envelope with a fresh, valid commit */
    m5_commit c = old_commit;
    c.store_generation = ss_generation(s) + 1;
    c.counter = c.store_generation;
    c.object_sequence = 0;
    uint8_t *e = s->ws->tx + SS_TX_HDR;
    memcpy(e, old_sid, 32);
    m5_commit_seal(&c, K.k_root_auth, e + 32);
    ss_tx_remac(s);
}

/* re-seal entry i's M5 commit record after an edit, then re-MAC the record */
static void reseal(ss_store *s, uint32_t i, void (*fix)(m5_commit *))
{
    uint8_t *e = s->ws->tx + SS_TX_HDR + (size_t)i * SS_TX_ENTRY;
    m5_commit c;
    m5_commit_open(e + 32, M5_COMMIT_LEN, K.k_root_auth, K.identity_class, &c);
    fix(&c);
    m5_commit_seal(&c, K.k_root_auth, e + 32);
    ss_tx_remac(s);
}
static void fx_store(m5_commit *c) { c->obj.store_uuid[0] ^= 1; }
static void fx_gen(m5_commit *c) { c->store_generation += 1; }
static void fx_counter(m5_commit *c) { c->counter += 1; }
static void fx_digest(m5_commit *c) { c->object_id[0] ^= 1; }
static void fx_huge(m5_commit *c) { c->store_generation = c->counter = UINT64_C(1) << 40; }
static void ed_commit_store(ss_store *s, void *a) { (void)a; reseal(s, 0, fx_store); }
static void ed_commit_gen(ss_store *s, void *a) { (void)a; reseal(s, 0, fx_gen); }
static void ed_commit_counter(ss_store *s, void *a) { (void)a; reseal(s, 0, fx_counter); }
static void ed_commit_digest(ss_store *s, void *a) { (void)a; reseal(s, 0, fx_digest); }
static void ed_gen_huge(ss_store *s, void *a)
{
    (void)a; /* self-consistent record, generation far beyond the Store's */
    put64le(s->ws->tx + 32, UINT64_C(1) << 40);
    put64le(s->ws->tx + 40, UINT64_C(1) << 40);
    reseal(s, 0, fx_huge);
    reseal(s, 1, fx_huge);
}
static void ed_tx_store(ss_store *s, void *a) { (void)a; s->ws->tx[16] ^= 1; ss_tx_remac(s); }
static void ed_tx_long(ss_store *s, void *a)
{
    (void)a; /* 32 trailing bytes inside a valid MAC */
    ss_workspace *w = s->ws;
    memset(w->tx + w->tx_len, 0, 32);
    w->tx_len += 32;
    w->objs[w->nobjs - 1].len = w->tx_len;
    ss_tx_remac(s);
}

static void test_forgery(void)
{
    struct { const char *name; forge_fn fn; int want_open; } cases[] = {
        {"envelope swapped after sealing", ed_flip_env, SS_E_ENVELOPE},
        {"unclaimed envelope", ed_extra_env, SS_E_ENVELOPE},
        {"plaintext object in sealed store", ed_plain, SS_E_FOREIGN_KIND},
        {"generation skip", ed_gen_skip, SS_E_ORDER},
        {"counter not the generation", ed_counter, SS_E_ORDER},
        {"stale commit record", ed_stale_commit, SS_E_ORDER},
        {"replayed transaction record", ed_replay_record, SS_E_ORDER},
        {"broken record chain", ed_chain, SS_E_ORDER},
        {"record MAC", ed_bad_mac, SS_E_TXREC},
        {"record magic", ed_bad_magic, SS_E_TXREC},
        {"record identity class", ed_tx_class, SS_E_IDENTITY},
        {"commit sequence order", ed_seq, SS_E_ORDER},
        {"two records for one generation", ed_dup_gen, SS_E_DUPLICATE},
        {"envelope claimed twice", ed_claim_twice, SS_E_DUPLICATE},
        {"record longer than its count", ed_tx_long, SS_E_TXREC},
        {"record names another store", ed_tx_store, SS_E_IDENTITY},
        {"commit names another store", ed_commit_store, SS_E_IDENTITY},
        {"commit generation not the record's", ed_commit_gen, SS_E_ORDER},
        {"commit counter not the record's", ed_commit_counter, SS_E_ORDER},
        {"commit digest not the envelope's", ed_commit_digest, SS_E_ENVELOPE},
        {"record generation beyond the Store", ed_gen_huge, SS_E_ORDER},
    };
    uint8_t ids[2][32];
    make_gen2(ids);
    {
        rig r;
        ss_store s;
        SCHECK_EQ(sopen(&r, &s, &K), 0, "open gen 2");
        /* the gen 2 record and one of its claims, for replay cases */
        uint32_t n;
        const sv1_entry *e = st_catalog(&s.st, &n);
        for (uint32_t i = 0; i < n; i++)
            if (e[i].kind == SS_KIND_TXREC)
                CHECK(st_read_object(&s.st, e[i].object_id, saved_tx, sizeof saved_tx, &saved_tx_len) == 0, "read rec");
        memcpy(old_sid, g_ws.claims[0].sid, 32);
        old_commit = g_ws.claims[0].c;
        rig_close(&r);
    }
    CHECK(file_load(g_path, img_a, RIG_BYTES) == 0, "snapshot gen 2");
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        CHECK(file_save(g_path, img_a, RIG_BYTES) == 0, "restore");
        int rc = forge(cases[i].fn, NULL);
        SCHECK_EQ(rc, cases[i].want_open, cases[i].name);
    }
    /* digest-consistent but tampered ciphertext: mounts, refused at read */
    CHECK(file_save(g_path, img_a, RIG_BYTES) == 0, "restore");
    SCHECK_EQ(forge(ed_flip_env_rebind, NULL), 0, "tampered ciphertext with rebound digest mounts");
    {
        rig r;
        ss_store s;
        SCHECK_EQ(sopen(&r, &s, &K), 0, "open");
        uint8_t out[SS_MAX_PLAINTEXT];
        size_t len;
        int refused = 0, ok = 0;
        for (uint32_t k = 0; k < s.nclaims; k++) {
            int rc = ss_read(&s, g_ws.claims[k].sid, out, sizeof out, &len, NULL);
            refused += rc == SS_E_ENVELOPE;
            ok += rc == 0;
        }
        CHECK(refused == 1 && ok == 3, "AEAD refuses exactly the tampered envelope (%d refused, %d ok)", refused, ok);
        CHECK(len == 0 || ok, "len");
        rig_close(&r);
    }
    /* defence in depth at read: a claim whose digest no longer matches the
     * envelope (here corrupted in memory after mount) is refused */
    CHECK(file_save(g_path, img_a, RIG_BYTES) == 0, "restore");
    {
        rig r;
        ss_store s;
        SCHECK_EQ(sopen(&r, &s, &K), 0, "open gen 2");
        uint8_t out[SS_MAX_PLAINTEXT];
        size_t len;
        g_ws.claims[0].c.object_id[0] ^= 1;
        SCHECK_EQ(ss_read(&s, g_ws.claims[0].sid, out, sizeof out, &len, NULL), SS_E_ENVELOPE,
                  "read refuses a claim digest mismatch");
        rig_close(&r);
    }
    /* on-disk envelope corruption. In the newest generation only: the Store
     * falls back to the older root and the anchor refuses that as a rollback.
     * In both roots: the Store itself refuses. */
    for (int both = 0; both < 2; both++) {
    CHECK(file_save(g_path, img_a, RIG_BYTES) == 0, "restore");
    if (both) advance(&K, 47, P1, 50, NULL, 0);
    {
        rig r;
        ss_store s;
        SCHECK_EQ(sopen(&r, &s, &K), 0, "open");
        uint32_t n;
        const sv1_entry *e = st_catalog(&s.st, &n);
        uint64_t unit = 0;
        for (uint32_t i = 0; i < n; i++)
            if (e[i].kind == SS_KIND_ENVELOPE && (unit == 0 || e[i].first_unit < unit)) unit = e[i].first_unit;
        rig_close(&r);
        CHECK(file_load(g_path, img_b, RIG_BYTES) == 0, "load");
        img_b[(RIG_ANCHOR_UNITS + unit) * 4096u + 200] ^= 0x10;
        CHECK(file_save(g_path, img_b, RIG_BYTES) == 0, "write");
    }
    SCHECK_EQ(open_rc(&K), both ? ST_M_CORRUPT_RECOVERY_REQUIRED : SS_E_ROLLBACK,
              both ? "corrupted envelope in both roots" : "corrupted envelope in newest root");
    }
}

static rig *g_cut_rig;
static void cut_before_anchor(void *arg, int cp)
{
    (void)arg;
    if (cp == SS_CP_BEFORE_ANCHOR) disk_file_arm_cut(&g_cut_rig->f, 0);
}

static void test_anchor_crash(void)
{
    uint8_t ids[2][32];
    make_gen2(ids);
    rig r;
    ss_store s;
    SCHECK_EQ(sopen(&r, &s, &K), 0, "open");
    g_cut_rig = &r;
    ss_object o = {46, 1, P1, 123};
    uint8_t nid[1][32];
    SCHECK_EQ(ss_transact(&s, &o, 1, cut_before_anchor, NULL, nid), SS_E_IO, "anchor write cut");
    disk_file_disarm(&r.f);
    SCHECK_EQ(ss_transact(&s, &o, 1, NULL, NULL, NULL), SS_E_NEEDS_REOPEN, "needs reopen");
    rig_close(&r);
    SCHECK_EQ(sopen(&r, &s, &K), 0, "reopen after crash between Store and anchor");
    SCHECK_EQ(ss_generation(&s), 3, "Store commit survived");
    SCHECK_EQ(s.rb, SS_RB_PREPARED_ADVANCE, "anchor one behind");
    SCHECK_EQ(check_read(&s, nid[0], P1, 123, 46), 0, "new object readable");
    /* a second crash at the same point: the catch-up keeps the anchor one behind */
    g_cut_rig = &r;
    SCHECK_EQ(ss_transact(&s, &o, 1, cut_before_anchor, NULL, NULL), SS_E_IO, "second anchor write cut");
    disk_file_disarm(&r.f);
    rig_close(&r);
    SCHECK_EQ(sopen(&r, &s, &K), 0, "reopen after second crash");
    SCHECK_EQ(ss_generation(&s), 4, "second Store commit survived");
    SCHECK_EQ(s.rb, SS_RB_PREPARED_ADVANCE, "anchor still only one behind");
    SCHECK_EQ(ss_transact(&s, &o, 1, NULL, NULL, NULL), 0, "next transaction catches up");
    rig_close(&r);
    SCHECK_EQ(sopen(&r, &s, &K), 0, "reopen");
    SCHECK_EQ(s.rb, SS_RB_VALID_RESUME, "anchor current again");
    SCHECK_EQ(ss_generation(&s), 5, "generation 5");
    rig_close(&r);
}

static void test_kinds(void)
{
    static const uint16_t taken[] = {1, 2, 16, 17, 18, 19, 20, 21, 22, 23};
    for (size_t i = 0; i < sizeof taken / sizeof taken[0]; i++)
        CHECK(taken[i] != SS_KIND_ENVELOPE && taken[i] != SS_KIND_TXREC, "kind collides with %u", taken[i]);
    CHECK(SS_KIND_ENVELOPE != SS_KIND_TXREC, "distinct kinds");
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";
    fill(P1, sizeof P1, 1);
    fill(P2, sizeof P2, 2);
    fill(P3, sizeof P3, 3);
    P4[0] = 0x5a;
    fill(junk, sizeof junk, 9);
    rig_keys(M5_ID_PRODUCTION, 0x11, &K);
    rig_keys(M5_ID_TEST, 0x11, &K_TEST);
    rig_keys(M5_ID_PRODUCTION, 0x22, &K_OTHER);
    test_kinds();
    static const uint32_t sizes[2] = {512, 4096};
    for (int k = 0; k < 2; k++) {
        g_bs = sizes[k];
        snprintf(g_path, sizeof g_path, "%s/sealed_%u.img", dir, g_bs);
        int before = g_failed;
        test_basic();
        test_rollback();
        test_identity();
        test_forgery();
        test_anchor_crash();
        printf("sealed store, %u-byte blocks: %s\n", g_bs, g_failed == before ? "ok" : "FAILED");
        unlink(g_path);
    }
    printf("store sealed: %d checks, %d failed\n", g_checks, g_failed);
    printf("STORE_SEALED: %s\n", g_failed ? "FAIL" : "PASS");
    return g_failed ? 1 : 0;
}
