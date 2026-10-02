/* test_continuity_geometry.c -- host test of contract item K-6 (Region geometry,
 * native/kernel/CONTINUITY_RECOVERY_CONTRACT.md K-6 and section 1.7, aienos#222,
 * cut 7). Harness helpers are copied from test_continuity_recovery.c (not shared).
 *
 * Proves, on the REAL sealed Store in a file (anchor units 0-3, Store region
 * after them, as dev/disk_layout.h):
 *   (1) rc state_digest == SHA-256 over Store-region units 0 and 1 (read straight
 *       from the image at offsets A_UNITS and A_UNITS+1), and is NOT the digest of
 *       the anchor units (image units 0 and 1);
 *   (2) flipping a byte in Store-region unit 0, and separately unit 1, changes the
 *       digest (and the challenge where a challenge exists);
 *   (3) flipping a byte in each anchor unit 0..3 leaves the digest unchanged;
 *   (4) the dev/disk_layout.h constants and the Store-region arithmetic for U units.
 * Each check has a counterexample: the digest must DIFFER after a store flip,
 * and must DIFFER from the anchor-unit digest, so a hardcoded value cannot pass.
 * Status: written in cut 7, NOT_RUN until the forge reports. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ck_test.h"
#include "continuity_recovery.h"
#include "disk_file.h"
#include "disk_layout.h"

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

#define A_UNITS CK_LAYOUT_ANCHOR_UNITS
#define S_UNITS 512u
#define T_UNITS (A_UNITS + S_UNITS)
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
static struct rc_env E;
static const uint8_t RUUID[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};
static uint8_t img[IMG_BYTES];

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
static void bind(void)
{
    g_sk.s = &g_s;
    g_sk.hook = NULL;
    g_sk.hook_arg = NULL;
    cr_bind_sealed(&g_src, &g_s);
    cr_bind_sealed_sink(&g_snk, &g_sk);
}
static void fresh(void)
{
    CK_(dev_open(1) == 0, "rig create");
    CK_(ss_format(&g_sdev, &g_tdev, 0, RUUID, &g_k, &g_ws) == 0, "format");
    CK_(ss_open(&g_s, &g_sdev, &g_tdev, 0, &g_k, &g_ws) == 0, "open genesis");
    bind();
}
static void env_open(void)
{
    CK_(dev_open(0) == 0, "reopen rig");
    E.dev = &g_sdev;
    E.anchor = &g_tdev;
    E.anchor_lba = 0;
    E.keys = &g_k;
    E.ws = &g_ws;
    E.store = &g_s;
    E.w = &g_w;
    E.tw = &g_tw;
    E.view = &g_v2;
}
static int file_load(uint8_t *dst)
{
    dev_close();
    FILE *f = fopen(g_path, "rb");
    if (!f) return -1;
    size_t n = fread(dst, 1, IMG_BYTES, f);
    fclose(f);
    return n == IMG_BYTES ? 0 : -2;
}
/* Flip one byte of ABSOLUTE image unit `abs_unit` (anchor units are 0..A_UNITS-1,
 * Store-region unit u is A_UNITS + u). */
static void flip_abs(uint64_t abs_unit, unsigned off)
{
    dev_close();
    FILE *f = fopen(g_path, "r+b");
    CK_(f != NULL, "open image");
    if (!f) return;
    long pos = (long)(abs_unit * 4096u + off);
    uint8_t b = 0;
    fseek(f, pos, SEEK_SET);
    CK_(fread(&b, 1, 1, f) == 1, "read byte");
    b ^= 0xff;
    fseek(f, pos, SEEK_SET);
    CK_(fwrite(&b, 1, 1, f) == 1, "write byte");
    fclose(f);
}

static struct cc_record fact(const char *s)
{
    struct cc_record r;
    memset(&r, 0, sizeof r);
    r.status = CC_EPI_DIRECT_OBSERVATION;
    r.len = (uint16_t)strlen(s);
    r.statement = (const uint8_t *)s;
    return r;
}

/* Two mocked-RNDR helpers, as test_continuity_recovery.c. */
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

/* Provisioned with one remembered fact (two generations). */
static void remembered(void)
{
    fresh();
    rng_init(5005, 1);
    const char *why = NULL;
    int rc = 0;
    CK_(cr_provision(&g_src, &g_snk, &g_w, &g_tw, &g_rng, RUUID, CC_SOURCE_QUALIFICATION, &g_v, &why, &rc) == CR_RESOLVED,
        "provision");
    struct cc_record r1 = fact("keep this");
    struct cr_update up = {NULL, &r1, 1};
    static struct cr_view cur;
    memcpy(&cur, &g_v, sizeof cur);
    CK_(cr_commit(&g_src, &g_snk, &g_w, &g_tw, &cur, &up, 0, &g_v, &why, &rc) == CR_RESOLVED, "remember");
}

static struct rc_record R, R2;
static void inspect(struct rc_record *r)
{
    env_open();
    CK_(rc_inspect(&E, r) == 0, "inspect");
}
/* SHA-256 over two units of the image, by the same primitive the Recovery Core uses. */
static void digest_of_image_units(uint64_t ua, uint64_t ub, uint8_t out[32])
{
    CK_(file_load(img) == 0, "load image");
    cr_state_digest(img + ua * 4096u, img + ub * 4096u, out);
}

/* (1) digest comes from Store-region units 0 and 1, not from anchor units. */
static void t_source(void)
{
    remembered();
    uint8_t want[32], anchor_d[32];
    inspect(&R);
    digest_of_image_units(A_UNITS, A_UNITS + 1u, want);
    digest_of_image_units(0, 1, anchor_d);
    CK_(memcmp(R.state_digest, want, 32) == 0, "state_digest == SHA-256(store unit 0, store unit 1)");
    CK_(memcmp(R.state_digest, anchor_d, 32) != 0, "state_digest is not the digest of anchor units 0,1");
    /* counterexample: swapping the two units gives a different digest, so order is bound too */
    uint8_t swapped[32];
    CK_(file_load(img) == 0, "load");
    cr_state_digest(img + (A_UNITS + 1u) * 4096u, img + A_UNITS * 4096u, swapped);
    CK_(memcmp(swapped, want, 32) != 0, "unit order matters (swap differs)");
    dev_close();
}

/* (2) a flip in Store-region unit 0, and separately unit 1, changes the digest. */
static void t_store_flip(unsigned u)
{
    remembered();
    inspect(&R);
    uint8_t c0[32];
    int have0 = rc_challenge(&R, CR_ACTION_REPAIR_DEGRADED_PEER, c0);
    flip_abs(A_UNITS + u, 100);
    inspect(&R2);
    uint8_t c1[32];
    int have1 = rc_challenge(&R2, CR_ACTION_REPAIR_DEGRADED_PEER, c1);
    CK_(memcmp(R.state_digest, R2.state_digest, 32) != 0, "flip in store unit %u changes the digest", u);
    uint8_t want[32];
    digest_of_image_units(A_UNITS, A_UNITS + 1u, want);
    CK_(memcmp(R2.state_digest, want, 32) == 0, "new digest still equals SHA-256 of store units 0,1");
    if (have0 == 1 && have1 == 1) CK_(memcmp(c0, c1, 32) != 0, "challenge changes with store unit %u", u);
    /* Which slot is inactive is known only after the fact: the digest check above is
     * the load-bearing one; the challenge is compared whenever both exist. */
    dev_close();
}

/* The inactive slot is Store unit 1 - active; flipping it is a degraded mount that still
 * yields a challenge (contract K-5), so the challenge change is asserted unconditionally. */
static void t_inactive_challenge(void)
{
    remembered();
    inspect(&R);
    uint32_t inactive = 1u - st_active_slot(&g_s.st);
    uint8_t c0[32], c1[32];
    CK_(R.have_uuid && R.have_mount, "baseline has uuid and mount");
    int a = rc_challenge(&R, CR_ACTION_REPAIR_DEGRADED_PEER, c0);
    flip_abs(A_UNITS + inactive, 100);
    inspect(&R2);
    int b = rc_challenge(&R2, CR_ACTION_REPAIR_DEGRADED_PEER, c1);
    CK_(a == 1 && b == 1, "challenge exists before and after an inactive-slot flip");
    CK_(memcmp(c0, c1, 32) != 0, "challenge changes after flipping the inactive slot (store unit %u)", inactive);
    dev_close();
}

/* (3) a flip in any anchor unit leaves the digest unchanged. */
static void t_anchor_flip(unsigned a)
{
    remembered();
    inspect(&R);
    uint8_t before[32];
    memcpy(before, R.state_digest, 32);
    uint8_t keep[4096];
    CK_(file_load(img) == 0, "load");
    memcpy(keep, img + (size_t)a * 4096u, 4096);
    flip_abs(a, 100);
    /* counterexample: the flip is not a no-op */
    CK_(file_load(img) == 0 && memcmp(keep, img + (size_t)a * 4096u, 4096) != 0, "anchor unit %u byte really flips", a);
    inspect(&R2);
    CK_(memcmp(before, R2.state_digest, 32) == 0, "anchor unit %u flip does not change the digest", a);
    dev_close();
}

/* (4) layout constants and Store-region arithmetic (dev/disk_layout.h). */
static void t_layout(void)
{
    CK_(CK_LAYOUT_UNIT == 4096u, "unit 4096");
    CK_(CK_LAYOUT_ANCHOR_UNITS == 4u, "anchor 4 units");
    CK_(CK_LAYOUT_PROBE_UNITS == 1u, "probe 1 unit");
    CK_(CK_LAYOUT_MIN_STORE_UNITS == 64u, "min store 64 units");
    static const uint32_t Us[] = {CK_LAYOUT_ANCHOR_UNITS + CK_LAYOUT_MIN_STORE_UNITS + CK_LAYOUT_PROBE_UNITS, 1000u, 65536u};
    for (unsigned i = 0; i < sizeof Us / sizeof Us[0]; i++) {
        uint32_t U = Us[i];
        uint32_t first = CK_LAYOUT_ANCHOR_UNITS;                    /* store region 4..U-2 */
        uint32_t last = U - CK_LAYOUT_PROBE_UNITS - 1u;             /* U-2 */
        uint32_t n = U - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS;
        CK_(first == 4u, "store region starts at unit 4 (U=%u)", U);
        CK_(last == U - 2u, "store region ends at unit U-2 (U=%u)", U);
        CK_(last - first + 1u == n, "store region has U-5 units (U=%u)", U);
        CK_(n == U - 5u, "U-5 (U=%u)", U);
        CK_(n >= CK_LAYOUT_MIN_STORE_UNITS, "meets the 64 unit minimum (U=%u)", U);
        /* store unit 0 is image unit 4 (first raw unit hashed), probe is unit U-1 */
        CK_(first + 0u == 4u && first + 1u == 5u, "raw units 0,1 are partition units 4,5");
    }
    /* counterexample: one unit fewer than the minimum is below it */
    uint32_t Ubad = CK_LAYOUT_ANCHOR_UNITS + CK_LAYOUT_MIN_STORE_UNITS + CK_LAYOUT_PROBE_UNITS - 1u;
    CK_(Ubad - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS < CK_LAYOUT_MIN_STORE_UNITS, "U-1 is below the minimum");
    /* this test's own rig: anchor units, then the Store region, as the layout */
    CK_(T_UNITS == A_UNITS + S_UNITS && S_UNITS >= CK_LAYOUT_MIN_STORE_UNITS, "rig geometry");
}

int main(void)
{
    make_keys();
    snprintf(g_path, sizeof g_path, "/tmp/ck_geo_test_%d.img", (int)getpid());
    t_layout();
    static const uint32_t geos[2] = {4096u, 512u};
    for (int g = 0; g < 2; g++) {
        g_bs = geos[g];
        t_source();
        t_store_flip(0);
        t_store_flip(1);
        t_inactive_challenge();
        for (unsigned a = 0; a < A_UNITS; a++) t_anchor_flip(a);
    }
    dev_close();
    unlink(g_path);
    return ck_t_verdict("test_continuity_geometry");
}
