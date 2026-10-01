/* Power cut at every block boundary of one transaction, plain Store and
 * sealed store, 512- and 4096-byte geometry, file-backed (disk_file). After
 * each cut the device is reopened and must show exactly the old state or
 * exactly the new state. */
#include "store_test_util.h"
#include "store_rig.h"
#include "store_v1.h"

static ss_workspace g_ws;
static uint8_t base_img[RIG_BYTES];
static char g_path[512];
static uint8_t A[3000], B[9000], C[100];

static void fill(uint8_t *p, size_t n, uint32_t seed)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)((i * 37u + seed * 11u + (i >> 8)) & 0xff);
}

static int plain_has(st_store *s, uint16_t kind, const uint8_t *p, size_t n)
{
    uint8_t id[32];
    static uint8_t out[16384];
    size_t len;
    if (sv1_object_id(kind, 1, p, n, id) != 0) return 0;
    if (st_read_object(s, id, out, sizeof out, &len) != 0) return 0;
    return len == n && memcmp(out, p, n) == 0;
}

static int sealed_has(ss_store *s, const uint8_t sid[32], const uint8_t *p, size_t n)
{
    static uint8_t out[SS_MAX_PLAINTEXT];
    size_t len;
    if (ss_read(s, sid, out, sizeof out, &len, NULL) != 0) return 0;
    return len == n && memcmp(out, p, n) == 0;
}

/* ---- plain ---- */
static void plain_base(uint32_t bs)
{
    rig r;
    CHECK(rig_open(&r, g_path, bs, 1) == 0, "create");
    CHECK_EQ(st_format(&r.sdev, RIG_UUID), 0, "format");
    st_store s;
    CHECK_EQ(st_open(&s, &r.sdev, &g_ws.st), 0, "open");
    st_object o = {30, 1, A, sizeof A};
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "gen 2");
    rig_close(&r);
    CHECK(file_load(g_path, base_img, RIG_BYTES) == 0, "snapshot");
}

static int plain_tx(rig *r)
{
    st_store s;
    int rc = st_open(&s, &r->sdev, &g_ws.st);
    if (rc != 0) return rc;
    st_object o[2] = {{31, 1, B, sizeof B}, {32, 1, C, sizeof C}};
    return st_transact(&s, o, 2, NULL, NULL);
}

static void plain_cuts(uint32_t bs)
{
    plain_base(bs);
    rig r;
    CHECK(rig_open(&r, g_path, bs, 0) == 0, "open");
    uint64_t w0 = r.f.blocks_written;
    CHECK_EQ(plain_tx(&r), 0, "uncut transaction");
    uint64_t W = r.f.blocks_written - w0;
    rig_close(&r);
    int nold = 0, nnew = 0, ndeg = 0;
    for (uint64_t cut = 0; cut <= W; cut++) {
        CHECK(file_save(g_path, base_img, RIG_BYTES) == 0, "restore");
        CHECK(rig_open(&r, g_path, bs, 0) == 0, "open");
        disk_file_arm_cut(&r.f, cut);
        (void)plain_tx(&r);
        disk_file_disarm(&r.f);
        rig_close(&r);
        CHECK(rig_open(&r, g_path, bs, 0) == 0, "reopen");
        st_store s;
        int rc = st_open(&s, &r.sdev, &g_ws.st);
        CHECK(rc == 0, "plain %u cut %llu: mount %s", bs, (unsigned long long)cut, st_strerror(rc));
        if (rc == 0) {
            uint32_t n;
            st_catalog(&s, &n);
            int a = plain_has(&s, 30, A, sizeof A), b = plain_has(&s, 31, B, sizeof B),
                c = plain_has(&s, 32, C, sizeof C);
            int old = st_generation(&s) == 2 && n == 1 && a;
            int neu = st_generation(&s) == 3 && n == 3 && a && b && c;
            CHECK(old || neu, "plain %u cut %llu: neither old nor new (gen %llu n %u)", bs,
                  (unsigned long long)cut, (unsigned long long)st_generation(&s), n);
            if (cut == 0) CHECK(old, "cut 0 must be old");
            if (cut == W) CHECK(neu, "full write must be new");
            nold += old;
            nnew += neu;
            ndeg += s.state == ST_DEGRADED_RECOVERY;
        }
        rig_close(&r);
    }
    printf("power cut, plain,  %4u-byte blocks: %llu block boundaries, %d old, %d new (%d of them read-only degraded)\n",
           bs, (unsigned long long)W + 1, nold, nnew, ndeg);
}

/* ---- sealed ---- */
static ss_keys K;
static uint8_t g_ids[2][32], a_id[32];

static void sealed_base(uint32_t bs)
{
    rig r;
    CHECK(rig_open(&r, g_path, bs, 1) == 0, "create");
    CHECK_EQ(ss_format(&r.sdev, &r.tdev, 0, RIG_UUID, &K, &g_ws), 0, "format");
    ss_store s;
    CHECK_EQ(ss_open(&s, &r.sdev, &r.tdev, 0, &K, &g_ws), 0, "open");
    ss_object o = {30, 1, A, sizeof A};
    uint8_t id[1][32];
    CHECK_EQ(ss_transact(&s, &o, 1, NULL, NULL, id), 0, "gen 2");
    memcpy(a_id, id[0], 32);
    rig_close(&r);
    CHECK(file_load(g_path, base_img, RIG_BYTES) == 0, "snapshot");
}

static int sealed_tx(rig *r)
{
    ss_store s;
    int rc = ss_open(&s, &r->sdev, &r->tdev, 0, &K, &g_ws);
    if (rc != 0) return rc;
    ss_object o[2] = {{31, 1, B, sizeof B}, {32, 1, C, sizeof C}};
    return ss_transact(&s, o, 2, NULL, NULL, g_ids);
}

static void sealed_cuts(uint32_t bs)
{
    sealed_base(bs);
    rig r;
    CHECK(rig_open(&r, g_path, bs, 0) == 0, "open");
    uint64_t w0 = r.f.blocks_written;
    CHECK_EQ(sealed_tx(&r), 0, "uncut transaction");
    uint64_t W = r.f.blocks_written - w0;
    rig_close(&r);
    int nold = 0, nnew = 0, nprep = 0, ndeg = 0, ncatch = 0;
    for (uint64_t cut = 0; cut <= W; cut++) {
        CHECK(file_save(g_path, base_img, RIG_BYTES) == 0, "restore");
        CHECK(rig_open(&r, g_path, bs, 0) == 0, "open");
        disk_file_arm_cut(&r.f, cut);
        (void)sealed_tx(&r);
        disk_file_disarm(&r.f);
        rig_close(&r);
        CHECK(rig_open(&r, g_path, bs, 0) == 0, "reopen");
        ss_store s;
        int rc = ss_open(&s, &r.sdev, &r.tdev, 0, &K, &g_ws);
        CHECK(rc == 0, "sealed %u cut %llu: mount %s", bs, (unsigned long long)cut, ss_strerror(rc));
        if (rc == 0) {
            int a = sealed_has(&s, a_id, A, sizeof A);
            int b = sealed_has(&s, g_ids[0], B, sizeof B), c = sealed_has(&s, g_ids[1], C, sizeof C);
            int old = ss_generation(&s) == 2 && s.nclaims == 1 && a && s.rb == SS_RB_VALID_RESUME;
            int neu = ss_generation(&s) == 3 && s.nclaims == 3 && a && b && c &&
                      (s.rb == SS_RB_VALID_RESUME || s.rb == SS_RB_PREPARED_ADVANCE);
            CHECK(old || neu, "sealed %u cut %llu: neither old nor new (gen %llu claims %u rb %d)", bs,
                  (unsigned long long)cut, (unsigned long long)ss_generation(&s), s.nclaims, s.rb);
            if (cut == 0) CHECK(old, "cut 0 must be old");
            if (cut == W) CHECK(neu && s.rb == SS_RB_VALID_RESUME, "full write must be new and anchored");
            nold += old;
            nnew += neu;
            nprep += neu && s.rb == SS_RB_PREPARED_ADVANCE;
            ndeg += s.st.state == ST_DEGRADED_RECOVERY;
            /* the store keeps working: one more transaction, then reopen */
            if (s.st.state == ST_VALID) {
                ss_object o = {33, 1, C, 10};
                CHECK_EQ(ss_transact(&s, &o, 1, NULL, NULL, NULL), 0, "follow-up transaction");
                uint64_t g = ss_generation(&s);
                rig_close(&r);
                CHECK(rig_open(&r, g_path, bs, 0) == 0, "reopen");
                rc = ss_open(&s, &r.sdev, &r.tdev, 0, &K, &g_ws);
                CHECK(rc == 0 && ss_generation(&s) == g && s.rb == SS_RB_VALID_RESUME,
                      "sealed %u cut %llu: follow-up reopen %s", bs, (unsigned long long)cut, ss_strerror(rc));
                ncatch++;
            } else {
                ss_object o = {33, 1, C, 10};
                CHECK_EQ(ss_transact(&s, &o, 1, NULL, NULL, NULL), ST_E_READ_ONLY_DEGRADED, "degraded is read-only");
            }
        }
        rig_close(&r);
    }
    printf("power cut, sealed, %4u-byte blocks: %llu block boundaries, %d old, %d new (%d anchor one behind), "
           "%d read-only degraded, %d follow-ups ok\n",
           bs, (unsigned long long)W + 1, nold, nnew, nprep, ndeg, ncatch);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";
    fill(A, sizeof A, 1);
    fill(B, sizeof B, 2);
    fill(C, sizeof C, 3);
    rig_keys(M5_ID_PRODUCTION, 0x33, &K);
    static const uint32_t sizes[2] = {512, 4096};
    for (int k = 0; k < 2; k++) {
        snprintf(g_path, sizeof g_path, "%s/powercut_%u.img", dir, sizes[k]);
        plain_cuts(sizes[k]);
        sealed_cuts(sizes[k]);
        unlink(g_path);
    }
    printf("store power cut: %d checks, %d failed\n", g_checks, g_failed);
    printf("STORE_POWERCUT: %s\n", g_failed ? "FAIL" : "PASS");
    return g_failed ? 1 : 0;
}
