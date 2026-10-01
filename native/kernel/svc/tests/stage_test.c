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
#include "nvme_shutdown.h"
#include "disk_file.h"
#include "disk_layout.h"
#include "m5.h"
#include "nvme_bind.h"
#include "pci.h"
#include "security.h"
#include "store_boot.h"
#include "artifact_store.h"
#include "sha256.h"
#include "net_bind.h"
#include "net_udp.h"

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
    /* the probe restored the unit it wrote: the fresh image is still all zero */
    CHECK(load(now) == 0);
    {
        size_t nz = 0;
        for (size_t i = 0; i < T_BYTES; i++) nz += now[i] != 0;
        CHECK(nz == 0);
    }

    printf("  [hardware staging policy: TEST keys refused, blank disk not formatted]\n");
    {
        ss_keys pk;
        memset(&pk, 0xEE, sizeof pk);
        CHECK(ck_store_production_keys(&pk) == CK_SB_E_BLOCKED_OPERATOR);
        size_t nz = 0;
        for (size_t i = 0; i < sizeof pk; i++) nz += ((const uint8_t *)&pk)[i] != 0;
        CHECK(nz == 0); /* BLOCKED_OPERATOR: no key bytes handed out */
        CHECK(ck_store_keys_admissible(&k, 0) == 1 && ck_store_keys_admissible(&k, 1) == 0);
        ss_keys prod = k;
        prod.identity_class = M5_ID_PRODUCTION;
        CHECK(ck_store_keys_admissible(&prod, 1) == 1 && ck_store_keys_admissible(&prod, 0) == 1);
        ss_keys odd = k;
        odd.identity_class = 0;
        CHECK(ck_store_keys_admissible(&odd, 0) == 0 && ck_store_keys_admissible(0, 0) == 0);
        CHECK(dopen(0) == 0);
        int rc = store_boot_run_policy(&g_d, &k, ck_store_test_uuid, "hw-test", 1, &r);
        store_boot_print(&r);
        dclose();
        CHECK(rc == CK_SB_E_TEST_KEYS && r.verdict == CK_SB_REFUSED && r.formatted == 0);
        CHECK(r.proof && strcmp(r.proof, "keyed") == 0 && r.identity_class == M5_ID_TEST);
        CHECK(load(now) == 0);
        nz = 0;
        for (size_t i = 0; i < T_BYTES; i++) nz += now[i] != 0;
        CHECK(nz == 0); /* the disk was not touched */
    }

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


/* ---- NVMe normal shutdown (dev/nvme_shutdown.c) against a model controller */
struct shut_model {
    uint32_t cc, csts;
    int done_after;     /* polls until SHST = 10b; -1 never */
    int polls, cc_writes, gone;
    int cfs_after;      /* polls until CFS = 1; 0 never */
    int rdy_drop_after; /* polls after EN = 0 until RDY = 0; -1 never */
    int dpolls;
    uint32_t log_off[8];
    int nlog;
};
static uint32_t sm_r32(void *ctx, uint32_t off)
{
    struct shut_model *m = ctx;
    if (m->gone) return 0xffffffffu;
    if (off == CK_NVME_REG_CC) return m->cc;
    if (off == CK_NVME_REG_CSTS) {
        if (!(m->cc & CK_NVME_CC_EN) && m->rdy_drop_after >= 0 && m->dpolls++ >= m->rdy_drop_after)
            m->csts &= ~CK_NVME_CSTS_RDY;
        if (m->cc & CK_NVME_CC_SHN_MASK) {
            int p = m->polls++;
            if (m->done_after >= 0 && p >= m->done_after)
                m->csts = (m->csts & ~CK_NVME_CSTS_SHST_MASK) | CK_NVME_CSTS_SHST_DONE;
            if (m->cfs_after > 0 && p >= m->cfs_after)
                m->csts |= CK_NVME_CSTS_CFS;
        }
        return m->csts;
    }
    return 0;
}
static void sm_w32(void *ctx, uint32_t off, uint32_t v)
{
    struct shut_model *m = ctx;
    if (m->nlog < 8) m->log_off[m->nlog++] = off;
    if (off == CK_NVME_REG_CC) { m->cc = v; m->cc_writes++; }
}
static void sm_delay(void *ctx, uint32_t us) { (void)ctx; (void)us; }

static void test_nvme_shutdown(void)
{
    struct shut_model m;
    struct ck_nvme_shut_ops o = {&m, sm_r32, sm_w32, 0, sm_delay};
    struct ck_nvme_shut_result r;
    /* Normal: EN=1, IOSQES/IOCQES kept, SHN=01 written once, SHST reached. */
    memset(&m, 0, sizeof m);
    m.cc = 0x00460001u; m.csts = 1; m.done_after = 3;
    CHECK(ck_nvme_shutdown(&o, 1000, &r) == CK_NVME_SHUT_OK);
    CHECK(m.cc == (0x00460001u | CK_NVME_CC_SHN_NORMAL) && m.cc_writes == 1 && m.log_off[0] == CK_NVME_REG_CC);
    CHECK(r.cc_before == 0x00460001u && (r.cc_after & CK_NVME_CC_SHN_MASK) == CK_NVME_CC_SHN_NORMAL);
    CHECK((r.csts & CK_NVME_CSTS_SHST_MASK) == CK_NVME_CSTS_SHST_DONE && r.waited_us == 3 * CK_NVME_SHUT_POLL_US);
    /* An abrupt-shutdown request already in CC is replaced by normal. */
    memset(&m, 0, sizeof m);
    m.cc = 0x00468001u; m.csts = 1; m.done_after = 1; /* not yet complete at entry */
    CHECK(ck_nvme_shutdown(&o, 1000, &r) == CK_NVME_SHUT_OK && (m.cc & CK_NVME_CC_SHN_MASK) == CK_NVME_CC_SHN_NORMAL);
    /* Never completes: bounded, reports TIMEOUT. */
    memset(&m, 0, sizeof m);
    m.cc = 1; m.csts = 1; m.done_after = -1;
    CHECK(ck_nvme_shutdown(&o, 1000, &r) == CK_NVME_SHUT_TIMEOUT && r.waited_us == 1000 && m.cc_writes == 1);
    /* Disabled controller: nothing written. */
    memset(&m, 0, sizeof m);
    CHECK(ck_nvme_shutdown(&o, 1000, &r) == CK_NVME_SHUT_NOT_ENABLED && m.cc_writes == 0);
    /* Device not answering. */
    memset(&m, 0, sizeof m);
    m.gone = 1;
    CHECK(ck_nvme_shutdown(&o, 1000, &r) == CK_NVME_SHUT_GONE && m.cc_writes == 0);
    CHECK(ck_nvme_shutdown(0, 1000, &r) == CK_NVME_SHUT_EARG);
    CHECK(ck_nvme_shutdown(&o, 1000, 0) == CK_NVME_SHUT_EARG);
    CHECK(ck_nvme_shutdown_str(CK_NVME_SHUT_OK)[0] == 'c');
    /* Fatal controller (CFS at entry): nothing written, needs disable. */
    memset(&m, 0, sizeof m);
    m.cc = 1; m.csts = 1 | CK_NVME_CSTS_CFS;
    CHECK(ck_nvme_shutdown(&o, 1000, &r) == CK_NVME_SHUT_FATAL && m.cc_writes == 0
          && ck_nvme_shutdown_needs_disable(CK_NVME_SHUT_FATAL));
    /* CFS raised while polling: stop at once, not after the full bound. */
    memset(&m, 0, sizeof m);
    m.cc = 1; m.csts = 1; m.done_after = -1; m.cfs_after = 2;
    CHECK(ck_nvme_shutdown(&o, 1000000, &r) == CK_NVME_SHUT_FATAL && r.waited_us == 2 * CK_NVME_SHUT_POLL_US);
    /* Enabled but not ready: SHN must not be written. */
    memset(&m, 0, sizeof m);
    m.cc = 1; m.csts = 0;
    CHECK(ck_nvme_shutdown(&o, 1000, &r) == CK_NVME_SHUT_NOT_READY && m.cc_writes == 0);
    /* Already shut down: nothing written, no disable needed. */
    memset(&m, 0, sizeof m);
    m.cc = 1 | CK_NVME_CC_SHN_NORMAL; m.csts = 1 | CK_NVME_CSTS_SHST_DONE;
    CHECK(ck_nvme_shutdown(&o, 1000, &r) == CK_NVME_SHUT_ALREADY && m.cc_writes == 0
          && !ck_nvme_shutdown_needs_disable(CK_NVME_SHUT_ALREADY) && !ck_nvme_shutdown_needs_disable(CK_NVME_SHUT_OK));
    /* Disable fallback: EN and SHN cleared, other CC fields kept, RDY drops. */
    memset(&m, 0, sizeof m);
    m.cc = 0x00464001u; m.csts = 1; m.rdy_drop_after = 2;
    CHECK(ck_nvme_disable(&o, 1000, &r) == CK_NVME_SHUT_OK && m.cc == 0x00460000u && m.cc_writes == 1
          && !(r.csts & CK_NVME_CSTS_RDY) && r.waited_us == 2 * CK_NVME_SHUT_POLL_US);
    /* Disable that never drops RDY is bounded; gone device is reported. */
    memset(&m, 0, sizeof m);
    m.cc = 1; m.csts = 1; m.rdy_drop_after = -1;
    CHECK(ck_nvme_disable(&o, 1000, &r) == CK_NVME_SHUT_TIMEOUT && r.waited_us == 1000);
    memset(&m, 0, sizeof m);
    m.gone = 1;
    CHECK(ck_nvme_disable(&o, 1000, &r) == CK_NVME_SHUT_GONE && m.cc_writes == 0);
    CHECK(ck_nvme_disable(0, 1000, &r) == CK_NVME_SHUT_EARG);
}
/* ---------------- virtio-net UDP round trip frames + fail-closed bind ---------------- */

static ck_net_peer peer_guest(void)
{
    ck_net_peer p;
    memset(&p, 0, sizeof p);
    static const uint8_t mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    memcpy(p.mac.b, mac, 6);
    p.ip = (net_ipv4){{10, 0, 2, 15}};
    p.gw_ip = (net_ipv4){{10, 0, 2, 2}};
    p.lport = CK_NET_LOCAL_PORT;
    p.rport = CK_NET_ECHO_PORT;
    return p;
}
static const net_mac k_gw_mac = {{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}};

/* An ARP frame as the gateway would send it. */
static size_t gw_arp(uint16_t op, net_mac eth_dst, net_mac smac, net_ipv4 sip, net_mac tmac, net_ipv4 tip,
                     uint8_t *out, size_t cap)
{
    net_arp_packet a = {op, smac, sip, tmac, tip};
    uint8_t body[64];
    size_t w = 0, fw = 0;
    if (net_arp_build(&a, body, sizeof body, &w) != NET_OK) return 0;
    net_eth_frame f = {eth_dst, smac, NET_ETHERTYPE_ARP, body, w};
    return net_eth_build(&f, out, cap, &fw) == NET_OK ? fw : 0;
}

static void test_net_udp(void)
{
    ck_net_peer p = peer_guest();
    static uint8_t f[1600];
    net_eth_frame e;
    net_arp_packet a;
    net_mac m;
    const uint8_t *pl = 0;
    size_t pn = 0;
    int cs = -1;

    /* ARP request: broadcast, who-has gateway tell us. */
    size_t w = ck_net_arp_request(&p, f, sizeof f);
    CHECK(w == 42 && net_eth_parse(f, w, &e) == NET_OK && e.ethertype == NET_ETHERTYPE_ARP);
    CHECK(memcmp(e.destination.b, "\xff\xff\xff\xff\xff\xff", 6) == 0);
    CHECK(net_arp_parse(e.payload, e.payload_len, &a) == NET_OK && a.operation == NET_ARP_REQUEST &&
          memcmp(a.target_ip.b, p.gw_ip.b, 4) == 0 && memcmp(a.sender_ip.b, p.ip.b, 4) == 0 &&
          memcmp(a.sender_mac.b, p.mac.b, 6) == 0);
    CHECK(ck_net_arp_request(&p, f, 41) == 0);

    /* ARP reply from the gateway is learned; look-alikes are not. */
    w = gw_arp(NET_ARP_REPLY, p.mac, k_gw_mac, p.gw_ip, p.mac, p.ip, f, sizeof f);
    memset(&m, 0, sizeof m);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_ARP_GW && memcmp(m.b, k_gw_mac.b, 6) == 0);
    CHECK(ck_net_classify(&p, f, w - 1, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED); /* truncated */
    net_ipv4 other = {{10, 0, 2, 3}};
    w = gw_arp(NET_ARP_REPLY, p.mac, k_gw_mac, other, p.mac, p.ip, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED); /* not the gateway */
    net_mac bc = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, zero = {{0}}, mc = {{0x01, 0, 0x5e, 0, 0, 1}};
    w = gw_arp(NET_ARP_REPLY, p.mac, bc, p.gw_ip, p.mac, p.ip, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED); /* broadcast sender MAC */
    w = gw_arp(NET_ARP_REPLY, p.mac, zero, p.gw_ip, p.mac, p.ip, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED); /* zero sender MAC */
    w = gw_arp(NET_ARP_REPLY, p.mac, mc, p.gw_ip, p.mac, p.ip, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED); /* multicast sender MAC */
    w = gw_arp(NET_ARP_REPLY, k_gw_mac, k_gw_mac, p.gw_ip, p.mac, p.ip, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED); /* not addressed to us */
    w = gw_arp(NET_ARP_REPLY, bc, k_gw_mac, p.gw_ip, p.mac, p.ip, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED); /* broadcast reply */

    /* ARP request for our address is answered to its sender. */
    w = gw_arp(NET_ARP_REQUEST, bc, k_gw_mac, p.gw_ip, zero, p.ip, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_ARP_ASK);
    w = ck_net_arp_reply(&p, &a, f, sizeof f);
    net_arp_packet r;
    CHECK(w == 42 && net_eth_parse(f, w, &e) == NET_OK && memcmp(e.destination.b, k_gw_mac.b, 6) == 0 &&
          net_arp_parse(e.payload, e.payload_len, &r) == NET_OK && r.operation == NET_ARP_REPLY &&
          memcmp(r.target_ip.b, p.gw_ip.b, 4) == 0 && memcmp(r.sender_mac.b, p.mac.b, 6) == 0);
    w = gw_arp(NET_ARP_REQUEST, bc, k_gw_mac, p.gw_ip, zero, other, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED); /* asks for someone else */

    /* UDP out: refused before the gateway MAC is known, then well formed. */
    static const char ping[] = "AIENOS-CK-NET ping nonce=0123abcd";
    CHECK(ck_net_udp_frame(&p, 1, (const uint8_t *)ping, sizeof ping - 1, f, sizeof f) == 0);
    p.gw_mac = k_gw_mac;
    w = ck_net_udp_frame(&p, 1, (const uint8_t *)ping, sizeof ping - 1, f, sizeof f);
    CHECK(w == 14 + 20 + 8 + sizeof ping - 1);
    CHECK(ck_net_udp_frame(&p, 1, f, 1473, f + 0, sizeof f) == 0); /* > 1500-byte IP datagram buffer */
    net_ipv4_header ih;
    const uint8_t *ipl = 0;
    size_t ipn = 0;
    net_udp_header uh;
    CHECK(net_eth_parse(f, w, &e) == NET_OK && memcmp(e.destination.b, k_gw_mac.b, 6) == 0 &&
          net_ipv4_parse(e.payload, e.payload_len, &ih, &ipl, &ipn) == NET_OK && ih.protocol == NET_IPPROTO_UDP &&
          net_udp_parse(ipl, ipn, p.ip, p.gw_ip, &uh, &pl, &pn) == NET_OK && uh.destination_port == CK_NET_ECHO_PORT &&
          pn == sizeof ping - 1 && memcmp(pl, ping, pn) == 0);

    /* UDP back: the gateway's reply, built with the roles swapped. */
    ck_net_peer g;
    memset(&g, 0, sizeof g);
    g.mac = k_gw_mac;
    g.ip = p.gw_ip;
    g.gw_mac = p.mac;
    g.gw_ip = p.ip;
    g.lport = CK_NET_ECHO_PORT;
    g.rport = CK_NET_LOCAL_PORT;
    static const char pong[] = "AIENOS-CK-NET pong token=feedf00d echo=AIENOS-CK-NET ping nonce=0123abcd";
    w = ck_net_udp_frame(&g, 7, (const uint8_t *)pong, sizeof pong - 1, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_UDP_REPLY && cs == 1 &&
          pn == sizeof pong - 1 && memcmp(pl, pong, pn) == 0);
    size_t udp_off = 14 + 20;
    f[udp_off + 8] ^= 1; /* corrupt payload: checksum must refuse it */
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED);
    f[udp_off + 8] ^= 1;
    f[udp_off + 6] = f[udp_off + 7] = 0; /* no checksum: allowed, reported */
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_UDP_REPLY && cs == 0);
    g.lport = 9999; /* wrong source port */
    w = ck_net_udp_frame(&g, 7, (const uint8_t *)pong, sizeof pong - 1, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED);
    g.lport = CK_NET_ECHO_PORT;
    g.ip = other; /* wrong source address */
    w = ck_net_udp_frame(&g, 7, (const uint8_t *)pong, sizeof pong - 1, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED);
    g.ip = p.gw_ip;
    g.gw_mac = k_gw_mac; /* not addressed to our MAC */
    w = ck_net_udp_frame(&g, 7, (const uint8_t *)pong, sizeof pong - 1, f, sizeof f);
    CHECK(ck_net_classify(&p, f, w, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED);
    CHECK(ck_net_classify(&p, f, 13, &m, &a, &pl, &pn, &cs) == CK_NET_IGNORED);

    char s[8];
    ck_net_printable((const uint8_t *)"a\"b\\\x01\x7f" "cdef", 10, s, sizeof s);
    CHECK(strcmp(s, "a'b'..c") == 0);

    /* Bind without an SMMU (host shim: CK_SMMU_ABSENT) fails closed: the
     * function's command register never gets memory decode or bus master. */
    static uint8_t cfg[4096];
    static pci_func vf;
    memset(cfg, 0, sizeof cfg);
    memset(&vf, 0, sizeof vf);
    vf.vendor = 0x1af4;
    vf.device = 0x1041;
    vf.cfg = cfg;
    vf.bar[4].addr = 0x10000000u;
    vf.bar[4].size = 0x4000u;
    virtio_pci_caps caps;
    memset(&caps, 0, sizeof caps);
    caps.common_cfg = (virtio_pci_region){1, 4, 0, 0x1000};
    caps.isr_cfg = (virtio_pci_region){1, 4, 0x1000, 0x1000};
    caps.device_cfg = (virtio_pci_region){1, 4, 0x2000, 0x1000};
    caps.notify_cfg = (virtio_pci_region){1, 4, 0x3000, 0x1000};
    caps.has_notify_off_multiplier = 1;
    caps.notify_off_multiplier = 4;
    printf("  [virtio-net bind without SMMU, host, not hardware]\n");
    CHECK(ck_net_bind_selftest(&vf, &caps) == CK_NET_E_DENIED);
    CHECK((pci_r16(vf.cfg, 4) & 0x6u) == 0); /* no MEM, no BM */
    CHECK(ck_net_live() == 0);
    ck_net_release(); /* idempotent */
    CHECK(ck_net_bind_selftest(NULL, &caps) == CK_NET_E_ARG);
}


/* ---------------- signed-artifact objects in the boot disk Store ---------------- */

#define A_UNITS 2048u
static char aimg[256];

static int a_boot(disk_file *f, disk_dev *d, ck_store_report *r)
{
    ss_keys k;
    ck_store_test_keys(&k);
    if (disk_file_open(f, d, aimg, T_BS, (uint64_t)A_UNITS * T_BPU, 0)) return -999;
    return store_boot_run(d, &k, ck_store_test_uuid, "art-test", r);
}

static void test_artifact_store(void)
{
    snprintf(aimg, sizeof aimg, "/tmp/ck_stage_art_%d.img", (int)getpid());
    unlink(aimg);
    disk_file f;
    disk_dev d;
    ck_store_report r;
    CHECK(disk_file_open(&f, &d, aimg, T_BS, (uint64_t)A_UNITS * T_BPU, 1) == 0);
    disk_file_close(&f);

    static uint8_t big[40000], big2[40000];
    for (size_t i = 0; i < sizeof big; i++) {
        big[i] = (uint8_t)(i * 7 + 3);
        big2[i] = (uint8_t)(i * 13 + 1);
    }
    const uint8_t small[10] = "0123456789";
    ck_art_input in[3] = {{"A.AIEN", big, sizeof big, 0}, {"B.AIEN", small, sizeof small, 0},
                          {"C-MISSING.AIEN", 0, 100, 1}};
    ck_art_set *set = calloc(1, sizeof *set);
    CHECK(set != NULL);
    if (!set) return;
    const char *why = 0;

    printf("  [artifact store: write at image build, read back at boot]\n");
    CHECK(a_boot(&f, &d, &r) == 0 && r.formatted == 1);
    CHECK(ck_art_collect(store_boot_store(), set, &why) == 0 && set->found == 0); /* no index yet */
    ck_art_input longname = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", small, sizeof small, 0};
    ck_art_input empty = {"E.AIEN", small, 0, 0};
    ck_art_input dup[2] = {{"B.AIEN", small, sizeof small, 0}, {"B.AIEN", small, sizeof small, 0}};
    CHECK(ck_art_write(store_boot_store(), &longname, 1) != 0);
    CHECK(ck_art_write(store_boot_store(), &empty, 1) != 0);
    CHECK(ck_art_write(store_boot_store(), dup, 2) != 0);
    CHECK(ck_art_write(store_boot_store(), in, 3) == 0);
    disk_flush(&d);
    disk_file_close(&f);

    CHECK(a_boot(&f, &d, &r) == 0 && r.formatted == 0 && r.boot_count_prev == 1);
    CHECK(ck_art_collect(store_boot_store(), set, &why) == 0 && set->found == 1 && set->count == 3);
    uint8_t h[32];
    sha256_hash(big, sizeof big, h);
    CHECK(set->e[0].state == CK_ART_OK && set->e[0].len == sizeof big && set->e[0].chunks == 3);
    CHECK(set->e[0].bytes && memcmp(set->e[0].bytes, big, sizeof big) == 0 && memcmp(set->e[0].sha256, h, 32) == 0);
    CHECK(set->e[1].state == CK_ART_OK && set->e[1].len == 10 && memcmp(set->e[1].bytes, small, 10) == 0);
    CHECK(set->e[2].state == CK_ART_MISSING && set->e[2].present == 0 && set->e[2].bytes == NULL);
    CHECK(strcmp(set->e[0].name, "A.AIEN") == 0 && strcmp(set->e[2].name, "C-MISSING.AIEN") == 0);
    ck_art_set_free(set);

    /* the stage hook hands the same bytes to the loader */
    struct ck_disk_artifacts da;
    ck_art_stage_load(store_boot_store(), 0);
    CHECK(ck_stage_disk_artifacts(&da) == 0 && da.available == 1 && da.count == 3);
    CHECK(da.a[0].state == CK_DISK_ART_OK && da.a[0].len == sizeof big && memcmp(da.a[0].bytes, big, sizeof big) == 0);
    CHECK(da.a[2].state == CK_DISK_ART_MISSING && da.a[2].bytes == NULL);

    printf("  [artifact store: a newer index and chunks win]\n");
    in[0].bytes = big2;
    CHECK(ck_art_write(store_boot_store(), in, 2) == 0);
    CHECK(ck_art_collect(store_boot_store(), set, &why) == 0 && set->count == 2);
    CHECK(set->e[0].state == CK_ART_OK && memcmp(set->e[0].bytes, big2, sizeof big2) == 0);
    ck_art_set_free(set);


    printf("  [artifact store: chunks of another write are never spliced in]\n");
    ck_art_input again = {"A.AIEN", 0, sizeof big2, 1}; /* same name and length, no bytes */
    CHECK(ck_art_write(store_boot_store(), &again, 1) == 0);
    CHECK(ck_art_collect(store_boot_store(), set, &why) == 0 && set->count == 1);
    CHECK(set->e[0].state == CK_ART_MISSING && set->e[0].present == 0 && set->e[0].bytes == NULL);
    ck_art_set_free(set);
    /* a chunk that names B and B's digest but carries other bytes */
    static uint8_t fake[CK_ART_CHUNK_HDR + 10], fix[CK_ART_INDEX_HDR + CK_ART_INDEX_ENTRY];
    uint8_t dg[32];
    sha256_hash(small, sizeof small, dg);
    memcpy(fake, "AIENACH1\x01\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x01\x00\x06\x00\x00\x00", 24);
    memcpy(fake + 24, "B.AIEN", 6);
    memcpy(fake + 56, dg, 32);
    memcpy(fake + CK_ART_CHUNK_HDR, "9876543210", 10);
    memcpy(fix, "AIENAIX1\x01\x00\x00\x00\x01\x00\x00\x00", 16);
    fix[16] = 6;
    memcpy(fix + 20, "B.AIEN", 6);
    fix[16 + 36] = 10;
    fix[16 + 40] = 1;
    memcpy(fix + 16 + 48, dg, 32);
    ss_object fo[2] = {{CK_ART_CHUNK_KIND, 1, fake, sizeof fake}, {CK_ART_INDEX_KIND, 1, fix, sizeof fix}};
    CHECK(ss_transact(store_boot_store(), fo, 2, 0, 0, 0) == 0);
    CHECK(ck_art_collect(store_boot_store(), set, &why) == 0 && set->count == 1);
    CHECK(set->e[0].state == CK_ART_MISMATCH && set->e[0].present == 1 && set->e[0].bytes == NULL);
    ck_art_set_free(set);
    ck_art_stage_load(store_boot_store(), 0);
    CHECK(ck_stage_disk_artifacts(&da) == 0 && da.available == 1 && da.a[0].state == CK_DISK_ART_MISSING);
    ck_stage_disk_artifacts_free();
    CHECK(ck_stage_disk_artifacts(&da) == 0 && da.available == 0 && da.count == 0);
    printf("  [artifact store: malformed index refused]\n");
    uint8_t badix[16] = {'A', 'I', 'E', 'N', 'A', 'I', 'X', '1', 2, 0, 0, 0, 0, 0, 0, 0};
    ss_object ob = {CK_ART_INDEX_KIND, 1, badix, sizeof badix};
    CHECK(ss_transact(store_boot_store(), &ob, 1, 0, 0, 0) == 0);
    CHECK(ck_art_collect(store_boot_store(), set, &why) < 0 && set->found == 0);
    ck_art_stage_load(store_boot_store(), 0);
    CHECK(ck_stage_disk_artifacts(&da) == 0 && da.available == 0);
    /* a valid index again, then the disk is corrupted under one chunk */
    CHECK(ck_art_write(store_boot_store(), in, 2) == 0);
    ss_store *s = store_boot_store();
    uint64_t off = 0, elen = 0;
    for (uint32_t k = 0; k < s->nclaims && !off; k++) {
        if (s->ws->claims[k].c.obj.object_kind != CK_ART_CHUNK_KIND) continue;
        for (uint32_t i = 0; i < s->st.root.n; i++) {
            const sv1_entry *e = &s->st.ws->cat[s->st.root.cat_index][i];
            if (memcmp(e->object_id, s->ws->claims[k].sid, 32)) continue;
            off = r.store_base_lba * T_BS + e->first_unit * 4096u;
            elen = e->byte_length;
        }
    }
    disk_flush(&d);
    disk_file_close(&f);
    CHECK(off != 0 && elen > 0);

    printf("  [artifact store: corrupted chunk on disk refuses the Store, no artifact used]\n");
    FILE *fp = fopen(aimg, "r+b");
    CHECK(fp != NULL);
    if (fp) {
        uint8_t b = 0;
        fseek(fp, (long)(off + elen / 2), SEEK_SET);
        CHECK(fread(&b, 1, 1, fp) == 1);
        b ^= 0xa5;
        fseek(fp, (long)(off + elen / 2), SEEK_SET);
        CHECK(fwrite(&b, 1, 1, fp) == 1);
        fclose(fp);
    }
    CHECK(a_boot(&f, &d, &r) != 0 && r.verdict == CK_SB_REFUSED);
    disk_file_close(&f);
    ck_art_stage_load(r.verdict == CK_SB_COMMITTED ? store_boot_store() : 0, r.step);
    CHECK(ck_stage_disk_artifacts(&da) == 0 && da.available == 0 && da.count == 0);
    free(set);
    unlink(aimg);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("ck stage host tests (host logic only; qualifies nothing physical)\n");
    test_mcfg();
    test_pci_bars();
    test_pci_enum();
    test_store();
    test_artifact_store();
    test_security();
    test_nvme_shutdown();
    test_net_udp();
    printf("CK_STAGE_HOST: %s checks=%d failures=%d\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
