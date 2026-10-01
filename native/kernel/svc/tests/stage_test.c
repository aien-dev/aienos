/* stage_test.c -- host tests for the Lane 18 boot stages (devices,
 * security, Store). Hosted test code: libc, pthreads, disk_file. Host
 * results qualify nothing physical; they check the logic only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ck.h"
#include "ck_host.h"
#include "devices.h"
#include "disk_file.h"
#include "disk_layout.h"
#include "m5.h"
#include "nvme_bind.h"
#include "pci.h"
#include "security.h"
#include "store_boot.h"

static int checks, failures;
#define CHECK(c)                                                                 \
    do {                                                                         \
        checks++;                                                                \
        if (!(c)) {                                                              \
            failures++;                                                          \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                \
        }                                                                        \
    } while (0)

/* ---------------- MCFG + fake ECAM ---------------- */

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

/* MCFG with n allocations. */
static size_t mk_mcfg(uint8_t *t, int n, const uint64_t *base, const uint16_t *seg, const uint8_t *sb, const uint8_t *eb)
{
    size_t len = 44u + 16u * (size_t)n;
    memset(t, 0, len);
    memcpy(t, "MCFG", 4);
    put32(t + 4, (uint32_t)len);
    t[8] = 1;
    memcpy(t + 10, "AIENOS", 6);
    for (int i = 0; i < n; i++) {
        uint8_t *a = t + 44 + 16 * i;
        put64(a, base[i]);
        put16(a + 8, seg[i]);
        a[10] = sb[i];
        a[11] = eb[i];
    }
    uint8_t sum = 0;
    for (size_t i = 0; i < len; i++) sum = (uint8_t)(sum + t[i]);
    t[9] = (uint8_t)(0u - sum);
    return len;
}

static void test_mcfg(void)
{
    uint8_t t[256];
    pci_ecam e;
    uint64_t b[2] = {0x4010000000ull, 0x3f000000ull};
    uint16_t s[2] = {0, 0};
    uint8_t sb[2] = {0, 0}, eb[2] = {0xff, 0x0f};
    size_t len = mk_mcfg(t, 1, b, s, sb, eb);
    CHECK(pci_mcfg_parse(t, len, &e) == PCI_OK && e.base == 0x4010000000ull && e.end_bus == 0xff);
    CHECK(pci_mcfg_parse(t, len - 1, &e) == PCI_E_MCFG);            /* length field mismatch */
    CHECK(pci_mcfg_parse(t, 44, &e) == PCI_E_MCFG);                 /* no allocation */
    t[0] = 'X';
    CHECK(pci_mcfg_parse(t, len, &e) == PCI_E_MCFG);                /* signature */
    uint64_t bad = 0x4010080000ull;
    len = mk_mcfg(t, 1, &bad, s, sb, eb);
    CHECK(pci_mcfg_parse(t, len, &e) == PCI_E_MCFG);                /* base not 1 MiB aligned */
    uint8_t sb2 = 5, eb2 = 4;
    len = mk_mcfg(t, 1, b, s, &sb2, &eb2);
    CHECK(pci_mcfg_parse(t, len, &e) == PCI_E_MCFG);                /* start > end */
    uint16_t s1[2] = {1, 0};
    len = mk_mcfg(t, 2, b, s1, sb, eb);
    CHECK(pci_mcfg_parse(t, len, &e) == PCI_OK && e.base == 0x3f000000ull && e.segment == 0); /* picks segment 0 */
    uint16_t s11[1] = {1};
    len = mk_mcfg(t, 1, b, s11, sb, eb);
    CHECK(pci_mcfg_parse(t, len, &e) == PCI_E_MCFG);                /* no segment 0 */
    put32(t + 4, 44 + 8);
    CHECK(pci_mcfg_parse(t, 44 + 8, &e) == PCI_E_MCFG);             /* (len-44) % 16 */
    CHECK(pci_mcfg_parse(NULL, 60, &e) == PCI_E_ARG);
}

static uint8_t *cfgp(uint8_t *ecam, int bus, int dev, int fn) { return ecam + ((size_t)bus << 20 | (size_t)dev << 15 | (size_t)fn << 12); }
static void mkfn(uint8_t *c, uint16_t vid, uint16_t did, uint32_t cls, uint8_t htype)
{
    put16(c, vid);
    put16(c + 2, did);
    put32(c + 8, cls << 8 | 1u);
    c[0x0e] = htype;
}

static void test_pci_bars(void)
{
    CHECK(pci_bar_size(0xffffc000u, 0, 0) == 0x4000u);
    CHECK(pci_bar_size(0xfffff00cu, 0xffffffffu, 1) == 0x1000u);
    CHECK(pci_bar_size(0x0000000cu, 0xfffffff0u, 1) == 0x1000000000ull);
    CHECK(pci_bar_size(0, 0, 0) == 0);
    pci_window w = {0x10000000u, 0x10010000u, 0x10000000u};
    CHECK(pci_window_alloc(&w, 0x4000) == 0x10000000u);
    CHECK(pci_window_alloc(&w, 0x1000) == 0x10004000u);
    CHECK(pci_window_alloc(&w, 0x8000) == 0x10008000u);
    CHECK(pci_window_alloc(&w, 0x1000) == 0);                       /* exhausted */
    CHECK(pci_window_alloc(&w, 0x3000) == 0);                       /* not a power of two */
}

static void test_pci_enum(void)
{
    const size_t buses = 2;
    uint8_t *ecam = aligned_alloc(1u << 20, buses << 20);
    CHECK(ecam != NULL);
    if (!ecam) return;
    memset(ecam, 0xff, buses << 20); /* absent functions read all ones */
    uint8_t *c;
    memset(c = cfgp(ecam, 0, 0, 0), 0, 4096); mkfn(c, 0x1b36, 0x0008, 0x060000, 0);
    memset(c = cfgp(ecam, 0, 1, 0), 0, 4096); mkfn(c, 0x1b36, 0x000c, 0x060400, 1);
    c[0x18] = 0; c[0x19] = 1; c[0x1a] = 1;                          /* primary 0, secondary 1 */
    memset(c = cfgp(ecam, 0, 2, 0), 0, 4096); mkfn(c, 0x8086, 0x10d3, 0x020000, 0x80);
    put32(c + 0x10, 0x4);                                           /* BAR0 64-bit memory */
    memset(c = cfgp(ecam, 0, 2, 1), 0, 4096); mkfn(c, 0x8086, 0x10d3, 0x020000, 0);
    memset(c = cfgp(ecam, 1, 0, 0), 0, 4096); mkfn(c, 0x1af4, 0x1041, 0x020000, 0);
    put32(c + 0x10, 0x10200000u);                                   /* firmware-assigned BAR0 */
    uint8_t t[64];
    uint64_t base = (uint64_t)(uintptr_t)ecam;
    uint16_t seg = 0;
    uint8_t sb = 0, eb = (uint8_t)(buses - 1);
    size_t len = mk_mcfg(t, 1, &base, &seg, &sb, &eb);

    static pci_system s;
    memset(&s, 0, sizeof s);
    CHECK(pci_mcfg_parse(t, len, &s.ecam) == PCI_OK);
    s.acc.ecam = ecam;
    s.acc.start_bus = 0;
    s.acc.end_bus = eb;
    pci_window w = {0x10000000u, 0x3eff0000u, 0x10000000u};
    CHECK(pci_enumerate(&s, &w) == PCI_OK);
    CHECK(s.n == 5);
    CHECK(s.bridges_followed == 1);
    const pci_func *nic = pci_find_id(&s, 0x8086, 0x10d3);
    CHECK(nic && nic->bar[0].is64 && nic->bar[0].assigned_here && nic->bar[0].addr >= 0x10200010u &&
          (nic->bar[0].addr & 0xf) == 0 && nic->bars_ok);
    const pci_func *vn = pci_find_id(&s, 0x1af4, 0x1041);
    CHECK(vn && vn->bus == 1 && vn->bar[0].addr == 0x10200000u && !vn->bar[0].assigned_here);
    CHECK(pci_find_class(&s, 0x010802, 0xffffff) == NULL);
    CHECK(strcmp(pci_class_name(0x010802), "nvme") == 0);

    /* Whole devices stage on the fake ECAM: no NVMe, so nvme unbound and rc 0. */
    ck_host_mcfg = t;
    ck_host_quiet = 0;
    printf("  [devices stage on fake ECAM, host, not hardware]\n");
    CHECK(ck_stage_devices() == 0);
    CHECK(ck_dev_boot_disk() == NULL);
    ck_host_mcfg = NULL;
    free(ecam);
}

/* ---------------- Store boot ---------------- */

#define T_UNITS 128u
#define T_BS 512u
#define T_BPU (4096u / T_BS)
#define T_BYTES ((size_t)T_UNITS * 4096u)

static char img[256];
static disk_file g_f;
static disk_dev g_d;

static int dopen(int create)
{
    if (create) unlink(img);
    return disk_file_open(&g_f, &g_d, img, T_BS, (uint64_t)T_UNITS * T_BPU, create);
}
static void dclose(void) { disk_file_close(&g_f); }
static int load(uint8_t *buf)
{
    FILE *f = fopen(img, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, T_BYTES, f);
    fclose(f);
    return n == T_BYTES ? 0 : -1;
}
static int save(const uint8_t *buf, size_t off, size_t len)
{
    FILE *f = fopen(img, "r+b");
    if (!f) return -1;
    fseek(f, (long)off, SEEK_SET);
    size_t n = fwrite(buf + off, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}
static int boot(const ss_keys *k, const char *commit, ck_store_report *r)
{
    if (dopen(0)) return -999;
    int rc = store_boot_run(&g_d, k, ck_store_test_uuid, commit, r);
    store_boot_print(r);
    dclose();
    return rc;
}

static void test_store(void)
{
    snprintf(img, sizeof img, "/tmp/ck_stage_store_%d.img", (int)getpid());
    ss_keys k;
    ck_store_test_keys(&k);
    ck_store_report r;
    uint8_t *snap = malloc(T_BYTES), *now = malloc(T_BYTES), *after = malloc(T_BYTES);
    CHECK(snap && now && after);
    if (!snap || !now || !after) return;

    /* rw probe writes the last unit only */
    CHECK(dopen(1) == 0);
    uint64_t plba = 0;
    CHECK(ck_disk_rw_probe(&g_d, 7, &plba) == 0 && plba == (uint64_t)(T_UNITS - 1) * T_BPU);
    dclose();
    /* the probe left non-zero data in the last unit only; the disk still counts as blank */

    printf("  [store boot 1: blank disk]\n");
    CHECK(boot(&k, "commit-one", &r) == 0);
    CHECK(r.formatted == 1 && r.verdict == CK_SB_COMMITTED && r.boot_count_prev == 0 && r.boot_count_new == 1);
    CHECK(strcmp(r.prev_commit, "none") == 0 && r.gen_commit == r.gen_open + 1);
    CHECK(r.store_units == T_UNITS - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS);

    printf("  [store boots 2..4]\n");
    const char *commits[3] = {"commit-two", "commit-three", "commit-four"};
    for (int i = 0; i < 3; i++) {
        uint64_t g0 = r.gen_commit;
        const char *prev = i == 0 ? "commit-one" : commits[i - 1];
        CHECK(boot(&k, commits[i], &r) == 0);
        CHECK(r.formatted == 0 && r.boot_count_prev == (uint64_t)i + 1 && r.boot_count_new == (uint64_t)i + 2);
        CHECK(r.gen_open == g0 && r.gen_commit == g0 + 1 && strcmp(r.prev_commit, prev) == 0);
        CHECK(r.rb == SS_RB_VALID_RESUME);
        if (i == 1) CHECK(load(snap) == 0); /* image after boot 3 */
    }

    printf("  [store: wrong key (TEST class, other key)]\n");
    ss_keys wrong = k;
    wrong.k_root_auth[0] ^= 1;
    wrong.k_domain[0] ^= 1;
    CHECK(load(now) == 0);
    CHECK(boot(&wrong, "x", &r) != 0);
    CHECK(r.verdict == CK_SB_REFUSED);
    printf("  wrong key -> proof=%s rc=%d\n", r.proof, r.rc);
    CHECK(strcmp(r.proof, "keyed") == 0 && r.rc == SS_E_TXREC);
    CHECK(load(after) == 0 && memcmp(now, after, T_BYTES) == 0);   /* refusal wrote nothing */

    printf("  [store: PRODUCTION identity class against a TEST store]\n");
    ss_keys prod;
    uint8_t kv[32];
    memset(kv, 0x11, 32);
    m5_subkeys sk;
    m5_derive_subkeys(kv, M5_ID_PRODUCTION, 0, &sk);
    memset(&prod, 0, sizeof prod);
    prod.identity_class = M5_ID_PRODUCTION;
    prod.key_generation = 1;
    memcpy(prod.k_root_auth, sk.k_root_auth, 32);
    memcpy(prod.k_domain, sk.k_artifact, 32);
    CHECK(boot(&prod, "x", &r) != 0 && r.verdict == CK_SB_REFUSED);
    printf("  production keys -> proof=%s rc=%d\n", r.proof, r.rc);
    CHECK(strcmp(r.proof, "keyed") == 0 && r.rc == SS_E_IDENTITY);
    CHECK(load(after) == 0 && memcmp(now, after, T_BYTES) == 0);

    printf("  [store: Store-only rollback (Store region from boot 3, anchor from boot 4)]\n");
    size_t soff = (size_t)CK_LAYOUT_ANCHOR_UNITS * 4096u;
    size_t slen = (size_t)(T_UNITS - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS) * 4096u;
    CHECK(save(snap, soff, slen) == 0);
    CHECK(load(now) == 0);
    CHECK(boot(&k, "x", &r) != 0 && r.verdict == CK_SB_REFUSED && strcmp(r.proof, "rollback") == 0 &&
          r.rc == SS_E_ROLLBACK);
    CHECK(load(after) == 0 && memcmp(now, after, T_BYTES) == 0);

    printf("  [store: whole-image rollback to boot 3 (same-disk anchor limit)]\n");
    CHECK(save(snap, 0, T_BYTES) == 0);
    CHECK(boot(&k, "commit-replay", &r) == 0);
    /* Honest: undetectable without an external counter. The count goes back. */
    CHECK(r.boot_count_prev == 3 && r.boot_count_new == 4);
    printf("  whole-image rollback NOT detected (expected; anchor on the same disk): boot_count went 4 -> back to 3\n");

    printf("  [store: corrupted superblock]\n");
    CHECK(load(now) == 0);
    memcpy(after, now, T_BYTES);
    for (size_t i = 0; i < 2u * 4096u; i++) after[soff + i] ^= 0xa5;
    CHECK(save(after, soff, 2u * 4096u) == 0);
    CHECK(load(now) == 0);
    CHECK(boot(&k, "x", &r) != 0 && r.verdict == CK_SB_REFUSED && strcmp(r.proof, "structural") == 0 &&
          r.formatted == 0);
    CHECK(load(after) == 0 && memcmp(now, after, T_BYTES) == 0);   /* not reformatted */

    printf("  [store: anchor present, Store region zeroed (not blank, must not format)]\n");
    memset(now + soff, 0, slen);
    CHECK(save(now, soff, slen) == 0);
    CHECK(boot(&k, "x", &r) != 0 && r.verdict == CK_SB_REFUSED && r.formatted == 0 &&
          strcmp(r.proof, "structural") == 0);
    CHECK(load(after) == 0 && memcmp(now, after, T_BYTES) == 0);

    printf("  [store: disk too small]\n");
    unlink(img);
    CHECK(disk_file_open(&g_f, &g_d, img, T_BS, 32u * T_BPU, 1) == 0);
    CHECK(store_boot_run(&g_d, &k, ck_store_test_uuid, "x", &r) != 0 && strcmp(r.proof, "geometry") == 0);
    dclose();
    unlink(img);
    free(snap);
    free(now);
    free(after);
}

/* ---------------- security ---------------- */

static void test_security(void)
{
    ck_sec_report r;
    int rc = ck_security_run(&r);
    if (rc) printf("  security fail step: %s\n", r.fail ? r.fail : "?");
    CHECK(rc == 0 && r.caps_ok && r.argus_ok);
    CHECK(r.caps_granted && r.caps_attenuated && r.caps_amplify_denied && r.caps_forged_denied && r.caps_revoked_denied);
    CHECK(r.trigger_findings == 1 && r.revokes_during == 1 && r.mints_during == 0 && r.executor_mints == 0);
    CHECK(r.target_denied_code != 0 && r.unrelated_same_subject == 0 && r.unrelated_other_subject == 0);
    CHECK(r.executor_unchanged && r.health_ok && r.bridge_ok);
    ck_security_shutdown();
    printf("  [security stage output, host]\n");
    CHECK(ck_stage_security() == 0);
    ck_security_shutdown();
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("ck stage host tests (host logic only; qualifies nothing physical)\n");
    test_mcfg();
    test_pci_bars();
    test_pci_enum();
    test_store();
    test_security();
    printf("CK_STAGE_HOST: %s checks=%d failures=%d\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
