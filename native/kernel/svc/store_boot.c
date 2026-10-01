/* store_boot.c -- see store_boot.h. */
#include "store_boot.h"
#include <stddef.h>
#include "ck.h"
#include "disk_layout.h"
#include "m5.h"
#include "sha256.h"

#define LABEL_KVOL "AIENOS-LANE18-TEST-KVOL-NOT-SECRET"

const uint8_t ck_store_test_uuid[16] = {'A', 'I', 'E', 'N', '-', 'T', 'E', 'S',
                                        'T', '-', 'B', 'O', 'O', 'T', '0', '1'};

static void bz(void *p, size_t n)
{
    volatile uint8_t *b = p;
    while (n--) *b++ = 0;
}
static void bcp(void *d, const void *s, size_t n)
{
    uint8_t *o = d;
    const uint8_t *i = s;
    while (n--) *o++ = *i++;
}
static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void ck_store_test_keys(ss_keys *k)
{
    uint8_t kvol[32];
    m5_subkeys sk;
    sha256_hash((const uint8_t *)LABEL_KVOL, sizeof LABEL_KVOL - 1, kvol);
    bz(k, sizeof *k);
    m5_derive_subkeys(kvol, M5_ID_TEST, 0, &sk);
    k->identity_class = M5_ID_TEST;
    k->key_generation = 1;
    bcp(k->k_root_auth, sk.k_root_auth, 32);
    bcp(k->k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);
    bz(kvol, sizeof kvol);
}

static int fail(ck_store_report *r, const char *proof, const char *step, int rc)
{
    r->verdict = CK_SB_REFUSED;
    r->proof = proof;
    r->step = step;
    r->rc = rc;
    return rc ? rc : -1;
}

/* Blank = anchor units and the first two Store units read back all zero. */
static int is_blank(const disk_dev *d, uint32_t bpu, uint8_t *buf, int *blank)
{
    *blank = 1;
    for (uint64_t u = 0; u < CK_LAYOUT_ANCHOR_UNITS + 2u; u++) {
        int rc = disk_read(d, u * bpu, bpu, buf);
        if (rc) return rc;
        for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++)
            if (buf[i]) {
                *blank = 0;
                return 0;
            }
    }
    return 0;
}

static const char *classify(int rc)
{
    switch (rc) {
    case SS_E_ROLLBACK:
    case SS_E_INCONSISTENT:
    case SS_E_ANCHOR:
        return "rollback";
    case SS_E_IO:
    case ST_M_IO:
        return "io";
    default:
        return (rc <= -101 && rc >= -107) ? "structural" : "keyed";
    }
}

/* Workspace lives across boots of the host test; the kernel uses it once. */
static ss_workspace *g_ws;
static ss_store *g_ss;

int store_boot_run(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                   ck_store_report *r)
{
    bz(r, sizeof *r);
    bcp(r->prev_commit, "none", 5);
    if (!d || !keys || !uuid || !commit) return fail(r, "geometry", "arguments", -1);
    if (d->block_size != 512 && d->block_size != 4096) return fail(r, "geometry", "block size", -1);
    uint32_t bpu = CK_LAYOUT_UNIT / d->block_size;
    uint64_t units = d->block_count / bpu;
    if (units < CK_LAYOUT_ANCHOR_UNITS + CK_LAYOUT_MIN_STORE_UNITS + CK_LAYOUT_PROBE_UNITS)
        return fail(r, "geometry", "disk too small", -1);
    r->anchor_lba = 0;
    r->store_base_lba = (uint64_t)CK_LAYOUT_ANCHOR_UNITS * bpu;
    r->store_units = units - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS;

    if (!g_ws) g_ws = ck_alloc(sizeof *g_ws);
    if (!g_ss) g_ss = ck_alloc(sizeof *g_ss);
    if (!g_ws || !g_ss) return fail(r, "io", "allocate workspace", -1);
    bz(g_ss, sizeof *g_ss);

    st_disk sd;
    st_dev sdev;
    ts_device tdev;
    int rc = st_disk_bind(&sd, d, r->store_base_lba, r->store_units, &sdev);
    if (rc) return fail(r, "geometry", "st_disk_bind", rc);
    ss_ts_device(d, &tdev);

    int blank = 0;
    rc = is_blank(d, bpu, g_ws->rd, &blank);
    if (rc) return fail(r, "io", "blank check read", rc);
    if (blank) {
        rc = ss_format(&sdev, &tdev, r->anchor_lba, uuid, keys, g_ws);
        if (rc) return fail(r, "commit", "format blank disk", rc);
        r->formatted = 1;
    }

    /* Proof 1: structural, unkeyed. */
    rc = st_open(&g_ss->st, &sdev, &g_ws->st);
    if (rc) return fail(r, rc == ST_M_IO ? "io" : "structural", "st_open (unkeyed)", rc);
    /* Proofs 2 and 3: keyed M5 + anti-rollback anchor. */
    bz(g_ss, sizeof *g_ss);
    rc = ss_open(g_ss, &sdev, &tdev, r->anchor_lba, keys, g_ws);
    if (rc) return fail(r, classify(rc), "ss_open (keyed + anchor)", rc);
    r->rb = g_ss->rb;
    r->gen_open = ss_generation(g_ss);

    /* Latest boot record = highest store generation among boot-kind claims. */
    int best = -1;
    for (uint32_t k = 0; k < g_ss->nclaims; k++) {
        const ss_claim *c = &g_ws->claims[k];
        if (c->c.obj.object_kind != CK_BOOT_KIND) continue;
        if (best < 0 || c->c.store_generation > g_ws->claims[best].c.store_generation) best = (int)k;
    }
    uint8_t rec[CK_BOOT_RECORD_LEN];
    if (best >= 0) {
        uint8_t sid[32];
        size_t len = 0;
        uint16_t kind = 0;
        bcp(sid, g_ws->claims[best].sid, 32);
        rc = ss_read(g_ss, sid, rec, sizeof rec, &len, &kind);
        if (rc) return fail(r, classify(rc), "read boot record", rc);
        if (len != CK_BOOT_RECORD_LEN || kind != CK_BOOT_KIND || get64(rec) != get64((const uint8_t *)"AIENBOOT") ||
            get32(rec + 8) != CK_BOOT_VERSION)
            return fail(r, "record", "boot record malformed (authenticated, wrong layout)", -1);
        r->boot_count_prev = get64(rec + 16);
        size_t i = 0;
        for (; i < CK_BOOT_COMMIT_MAX && rec[24 + i]; i++) r->prev_commit[i] = (char)rec[24 + i];
        r->prev_commit[i] = 0;
    } else if (!r->formatted && r->gen_open > 1) {
        return fail(r, "record", "store has history but no boot record", -1);
    }

    r->boot_count_new = r->boot_count_prev + 1;
    bz(rec, sizeof rec);
    bcp(rec, "AIENBOOT", 8);
    put32(rec + 8, CK_BOOT_VERSION);
    put64(rec + 16, r->boot_count_new);
    for (size_t i = 0; i < CK_BOOT_COMMIT_MAX && commit[i]; i++) rec[24 + i] = (uint8_t)commit[i];
    ss_object obj = {CK_BOOT_KIND, CK_BOOT_VERSION, rec, sizeof rec};
    rc = ss_transact(g_ss, &obj, 1, 0, 0, 0);
    if (rc) return fail(r, "commit", "ss_transact", rc);
    rc = disk_flush(d);
    if (rc) return fail(r, "io", "flush", rc);
    r->gen_commit = ss_generation(g_ss);
    if (r->gen_commit != r->gen_open + 1) return fail(r, "commit", "generation did not advance by one", -1);
    r->verdict = CK_SB_COMMITTED;
    return 0;
}

static const char *rb_name(int rb)
{
    return rb == SS_RB_VALID_RESUME ? "valid-resume" : rb == SS_RB_PREPARED_ADVANCE ? "prepared-advance" :
           rb == SS_RB_GENESIS ? "genesis" : "?";
}

static const char *err_name(int rc)
{
    if (rc <= -301 && rc >= -313) return ss_strerror(rc);
    if (rc <= -101 && rc >= -212) return st_strerror(rc);
    return "error";
}

void store_boot_print(const ck_store_report *r)
{
    ck_printf("store: TEST identity, TEST keys (public label, not secret, not production); "
              "anchor lba=%llu store lba=%llu units=%llu\n",
              (unsigned long long)r->anchor_lba, (unsigned long long)r->store_base_lba,
              (unsigned long long)r->store_units);
    if (r->formatted) ck_printf("store: blank disk (all-zero anchor + Store head): formatted TEST store\n");
    if (r->verdict != CK_SB_COMMITTED) {
        ck_printf("store: REFUSED proof=%s step=\"%s\" rc=%d (%s); disk left as found, not reformatted\n",
                  r->proof, r->step, r->rc, err_name(r->rc));
        return;
    }
    ck_printf("store: opened generation=%llu boot_count=%llu prev_commit=%s anchor=%s\n",
              (unsigned long long)r->gen_open, (unsigned long long)r->boot_count_prev, r->prev_commit,
              rb_name(r->rb));
    ck_printf("store: committed generation=%llu boot_count=%llu\n", (unsigned long long)r->gen_commit,
              (unsigned long long)r->boot_count_new);
    ck_printf("store: limit: anchor shares this disk, so a whole-disk rollback is not detectable "
              "(needs TPM NV or another external counter)\n");
}

/* Kernel stage. ck_dev_boot_disk comes from dev/devices.c. */
const disk_dev *ck_dev_boot_disk(void);

int ck_stage_store(void)
{
    const disk_dev *d = ck_dev_boot_disk();
    if (!d) {
        ck_printf("store: REFUSED proof=io step=\"no boot disk\" (NVMe not bound; see nvme/dma_gate lines)\n");
        return -1;
    }
    ss_keys keys;
    ck_store_report r;
    ck_store_test_keys(&keys);
    const char *commit = ck_commit();
    int rc = store_boot_run(d, &keys, ck_store_test_uuid, commit ? commit : "unknown", &r);
    bz(&keys, sizeof keys);
    store_boot_print(&r);
    return rc;
}
