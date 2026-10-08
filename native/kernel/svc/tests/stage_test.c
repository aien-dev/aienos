/* stage_test.c -- host tests for the Lane 18 boot stages (devices,
 * security, Store). Hosted test code: libc, pthreads, disk_file. Host
 * results qualify nothing physical; they check the logic only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "ck.h"
#include "ck_host.h"
#include "devices.h"
#include "nvme_shutdown.h"
#include "disk_file.h"
#include "disk_layout.h"
#include "m5.h"
#include "nvme_bind.h"
#include "pci.h"
#include "mmio_window.h"
#include "security.h"
#include "store_boot.h"
#include "artifact_store.h"
#include "sha256.h"
#include "net_bind.h"
#include "net_udp.h"
#include "xhci_fence.h"
#include "usb_hid.h"
#include <stdarg.h>

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

/* ---------------- Multi-segment MCFG + read-only discovery ---------------- */

/* The recorded GB10 Spark MCFG: 16 allocations, 300 bytes.
 * Source: docs/GB10_PLATFORM_TOPOLOGY.md, "ACPI MCFG / ECAM". */
static size_t mk_gb10_mcfg(uint8_t *t)
{
    uint64_t b[16];
    uint16_t sg[16];
    uint8_t sb[16], eb[16];
    for (int i = 0; i < 16; i++) {
        sg[i] = (uint16_t)i;
        sb[i] = 0;
        if (i < 15) {
            b[i] = 0xF300000000ull + (uint64_t)i * 0x10000000ull;
            eb[i] = i <= 10 ? 15 : 255;
        } else {
            b[i] = 0x29000000ull;
            eb[i] = 1;
        }
    }
    return mk_mcfg(t, 16, b, sg, sb, eb);
}

static void test_mcfg_all(void)
{
    uint8_t t[44 + 16 * 16];
    pci_ecam e[16];
    uint32_t n = 99;
    size_t len = mk_gb10_mcfg(t);
    CHECK(len == 300);
    CHECK(pci_mcfg_parse_all(t, len, e, 16, &n) == PCI_OK && n == 16);
    CHECK(e[0].segment == 0 && e[0].base == 0xF300000000ull && e[0].end_bus == 15);
    CHECK(e[10].segment == 10 && e[10].base == 0xF300000000ull + 10 * 0x10000000ull && e[10].end_bus == 15);
    CHECK(e[11].segment == 11 && e[11].end_bus == 255);
    CHECK(e[14].segment == 14 && e[14].end_bus == 255);
    CHECK(e[15].segment == 15 && e[15].base == 0x29000000ull && e[15].start_bus == 0 && e[15].end_bus == 1);
    CHECK(pci_mcfg_parse_all(t, len, e, 15, &n) == PCI_E_FULL);     /* never truncates */
    CHECK(pci_mcfg_parse_all(t, len, e, 16, NULL) == PCI_E_ARG);
    CHECK(pci_mcfg_parse_all(NULL, len, e, 16, &n) == PCI_E_ARG);
    CHECK(pci_mcfg_parse_all(t, len, NULL, 16, &n) == PCI_E_ARG);
    CHECK(pci_mcfg_parse_all(t, len - 1, e, 16, &n) == PCI_E_MCFG); /* length field mismatch */
    CHECK(pci_mcfg_parse_all(t, 44, e, 16, &n) == PCI_E_MCFG);      /* no allocation */

    uint64_t b[2] = {0x4010000000ull, 0x4020000000ull};
    uint16_t s[2] = {3, 3};
    uint8_t sb[2] = {0, 0}, eb[2] = {7, 7};
    len = mk_mcfg(t, 2, b, s, sb, eb);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_E_MCFG);      /* exact duplicate range */
    sb[1] = 7; eb[1] = 9;
    len = mk_mcfg(t, 2, b, s, sb, eb);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_E_MCFG);      /* overlap on bus 7 */
    sb[1] = 8;
    len = mk_mcfg(t, 2, b, s, sb, eb);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_OK && n == 2); /* adjacent ranges are fine */
    s[1] = 4; sb[1] = 0; eb[1] = 7;
    len = mk_mcfg(t, 2, b, s, sb, eb);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_OK && n == 2); /* same range, other segment */
    sb[0] = 2; sb[1] = 0;
    len = mk_mcfg(t, 2, b, s, sb, eb);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_OK && e[0].start_bus == 2 && e[0].end_bus == 7);
    uint64_t ov[1] = {0xfffffffffff00000ull};
    uint16_t s0[1] = {0};
    uint8_t sbo[1] = {0}, ebo[1] = {1};
    len = mk_mcfg(t, 1, ov, s0, sbo, ebo);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_E_MCFG);      /* base + span wraps u64 */
    uint64_t z[1] = {0};
    len = mk_mcfg(t, 1, z, s0, sbo, ebo);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_E_MCFG);      /* zero base */
    uint64_t mis[1] = {0x4010080000ull};
    len = mk_mcfg(t, 1, mis, s0, sbo, ebo);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_E_MCFG);      /* not 1 MiB aligned */
    uint8_t sbb[1] = {5}, ebb[1] = {4};
    len = mk_mcfg(t, 1, b, s0, sbb, ebb);
    CHECK(pci_mcfg_parse_all(t, len, e, 4, &n) == PCI_E_MCFG);      /* start > end */
}

#define FAKE_SEG 15u
#define FAKE_BUSES 2u
#define FAKE_BYTES ((size_t)FAKE_BUSES << 20)

/* Fake segment-15 ECAM: root bridge 00:00.0 (secondary 1) and the GB10 at
 * 01:00.0. The bridge device id is SYNTHETIC (the topology doc does not
 * record it); the BAR raw values are SYNTHETIC too. */
static uint8_t *mk_fake_seg15(void)
{
    uint8_t *ecam = mmap(NULL, FAKE_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ecam == MAP_FAILED) return NULL;
    memset(ecam, 0xff, FAKE_BYTES);
    uint8_t *c;
    memset(c = cfgp(ecam, 0, 0, 0), 0, 4096);
    mkfn(c, 0x10de, 0x7777 /* SYNTHETIC bridge id */, 0x060400, 1);
    c[0x18] = 0; c[0x19] = 1; c[0x1a] = 1;
    memset(c = cfgp(ecam, 1, 0, 0), 0, 4096);
    mkfn(c, 0x10de, 0x2e12, 0x030000, 0);
    c[0x08] = 0xa1;                                                 /* revision */
    put32(c + 0x10, 0x0000000cu);                                   /* SYNTHETIC raw BARs */
    put32(c + 0x14, 0x00000001u);
    put32(c + 0x18, 0x00000004u);
    put32(c + 0x2c, 0x000010deu);                                   /* subsys 10de:0000 */
    return ecam;
}

static void acc_for(pci_bus_access *a, uint8_t *ecam, uint8_t sb, uint8_t eb)
{
    a->ecam = ecam;
    a->start_bus = sb;
    a->end_bus = eb;
}

static void test_discover_seg15(void)
{
    uint8_t *ecam = mk_fake_seg15();
    CHECK(ecam != NULL);
    if (!ecam) return;
    static uint8_t copy[FAKE_BYTES];
    memcpy(copy, ecam, FAKE_BYTES);
    CHECK(mprotect(ecam, FAKE_BYTES, PROT_READ) == 0);
    pci_bus_access a;
    acc_for(&a, ecam, 0, 1);
    pci_found f[8];
    uint32_t n = 0, br = 0;
    CHECK(pci_discover(&a, FAKE_SEG, f, 8, &n, &br) == PCI_OK);
    CHECK(n == 2 && br == 1);
    const pci_found *g = NULL;
    for (uint32_t i = 0; i < n; i++)
        if (f[i].vendor == 0x10de && f[i].device == 0x2e12) g = &f[i];
    CHECK(g != NULL);
    if (g) {
        CHECK(g->segment == FAKE_SEG && g->bus == 1 && g->dev == 0 && g->fn == 0);
        CHECK(g->class_code == 0x030000 && g->revision == 0xa1 && g->header_type == 0);
        CHECK(g->subsys_vendor == 0x10de && g->subsys_id == 0);
        CHECK(g->bar_raw[0] == 0xcu && g->bar_raw[1] == 1u && g->bar_raw[2] == 4u && g->bar_raw[3] == 0);
    }
    CHECK(f[0].bus == 0 && (f[0].header_type & 0x7f) == 1 && f[0].secondary == 1 && f[0].subordinate == 1);
    CHECK(memcmp(ecam, copy, FAKE_BYTES) == 0);                     /* zero writes */
    munmap(ecam, FAKE_BYTES);
}

/* Run fn in a child; return 1 when it died of SIGSEGV/SIGBUS. */
static int child_died_on_write(void (*fn)(uint8_t *), uint8_t *ecam)
{
    fflush(stdout);
    pid_t p = fork();
    if (p < 0) return 0;
    if (p == 0) {
        signal(SIGSEGV, SIG_DFL); /* sanitizer builds install their own handler */
        signal(SIGBUS, SIG_DFL);
        fn(ecam);
        _exit(0); /* survived the write: the trap did not fire */
    }
    int st = 0;
    if (waitpid(p, &st, 0) != p) return 0;
    return WIFSIGNALED(st) && (WTERMSIG(st) == SIGSEGV || WTERMSIG(st) == SIGBUS);
}

static void child_enumerate(uint8_t *ecam)
{
    static pci_system s;
    memset(&s, 0, sizeof s);
    s.ecam.segment = FAKE_SEG;
    s.acc.ecam = ecam;
    s.acc.start_bus = 0;
    s.acc.end_bus = 1;
    (void)pci_enumerate(&s, NULL); /* sizes BARs: must write */
}
static void child_w32(uint8_t *ecam) { pci_w32(cfgp(ecam, 1, 0, 0), 0x10, 0xffffffffu); }

/* Negative control: the read-only page trap must catch real writes. */
static void test_discover_trap(void)
{
    uint8_t *ecam = mk_fake_seg15();
    CHECK(ecam != NULL);
    if (!ecam) return;
    CHECK(mprotect(ecam, FAKE_BYTES, PROT_READ) == 0);
    CHECK(child_died_on_write(child_enumerate, ecam));
    CHECK(child_died_on_write(child_w32, ecam));
    munmap(ecam, FAKE_BYTES);
}

static void test_discover_edges(void)
{
    pci_found f[8];
    uint32_t n = 9, br = 9;
    pci_bus_access a;
    uint8_t *ecam = mmap(NULL, 4u << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(ecam != MAP_FAILED);
    if (ecam == MAP_FAILED) return;
    uint8_t *c;

    memset(ecam, 0xff, 4u << 20);                                   /* empty bus */
    acc_for(&a, ecam, 0, 3);
    CHECK(pci_discover(&a, 0, f, 8, &n, &br) == PCI_OK && n == 0 && br == 0);
    CHECK(pci_discover(NULL, 0, f, 8, &n, &br) == PCI_E_ARG);
    CHECK(pci_discover(&a, 0, f, 8, NULL, &br) == PCI_E_ARG);

    /* Loop: bridge on bus 1 whose secondary points back to bus 0. */
    memset(c = cfgp(ecam, 0, 0, 0), 0, 4096); mkfn(c, 0x1b36, 1, 0x060400, 1);
    c[0x19] = 1; c[0x1a] = 3;
    memset(c = cfgp(ecam, 1, 0, 0), 0, 4096); mkfn(c, 0x1b36, 2, 0x060400, 1);
    c[0x19] = 0; c[0x1a] = 3;
    CHECK(pci_discover(&a, 0, f, 8, &n, &br) == PCI_OK);
    CHECK(n == 2 && br == 1);                                       /* back-edge not followed, counted once */

    /* Secondary beyond end_bus: not followed. */
    memset(ecam, 0xff, 4u << 20);
    memset(c = cfgp(ecam, 0, 0, 0), 0, 4096); mkfn(c, 0x1b36, 1, 0x060400, 1);
    c[0x19] = 5; c[0x1a] = 5;
    memset(c = cfgp(ecam, 1, 0, 0), 0, 4096); mkfn(c, 0x1b36, 3, 0x020000, 0);
    CHECK(pci_discover(&a, 0, f, 8, &n, &br) == PCI_OK && n == 1 && br == 0);
    c = cfgp(ecam, 0, 0, 0); c[0x19] = 2; c[0x1a] = 1;              /* subordinate < secondary */
    CHECK(pci_discover(&a, 0, f, 8, &n, &br) == PCI_OK && n == 1 && br == 0);

    /* Multi-function and fn0-absent handling on bus 0. */
    memset(ecam, 0xff, 4u << 20);
    memset(c = cfgp(ecam, 0, 1, 0), 0, 4096); mkfn(c, 0x8086, 1, 0x020000, 0x80);
    memset(c = cfgp(ecam, 0, 1, 3), 0, 4096); mkfn(c, 0x8086, 2, 0x020000, 0);
    memset(c = cfgp(ecam, 0, 2, 1), 0, 4096); mkfn(c, 0x8086, 3, 0x020000, 0); /* fn0 absent: skipped */
    memset(c = cfgp(ecam, 0, 3, 0), 0, 4096); mkfn(c, 0x8086, 4, 0x020000, 0);
    memset(c = cfgp(ecam, 0, 3, 1), 0, 4096); mkfn(c, 0x8086, 5, 0x020000, 0); /* not multi-fn: skipped */
    CHECK(pci_discover(&a, 0, f, 8, &n, &br) == PCI_OK && n == 3);

    /* Capacity exhaustion. */
    CHECK(pci_discover(&a, 0, f, 2, &n, &br) == PCI_E_FULL);

    /* Nonzero start_bus accessor: ecam maps bus 2 at offset 0. */
    memset(ecam, 0xff, 4u << 20);
    memset(c = cfgp(ecam, 0, 4, 0), 0, 4096); mkfn(c, 0x1af4, 9, 0x020000, 0);
    acc_for(&a, ecam, 2, 3);
    CHECK(pci_discover(&a, 7, f, 8, &n, &br) == PCI_OK && n == 1);
    CHECK(f[0].segment == 7 && f[0].bus == 2 && f[0].dev == 4 && f[0].device == 9);
    munmap(ecam, 4u << 20);
}

/* ---------------- Boot discovery report (pci_stage_discover_report) ---------------- */

/* 1 MiB aligned anonymous map (the fake ECAM base must be the address itself
 * and ECAM bases are 1 MiB aligned). */
static uint8_t *map_aligned(size_t bytes)
{
    size_t slack = 1u << 20;
    uint8_t *raw = mmap(NULL, bytes + slack, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) return NULL;
    uintptr_t a = ((uintptr_t)raw + slack - 1) & ~(uintptr_t)(slack - 1);
    return (uint8_t *)a;
}

/* Fake segment 0 (SYNTHETIC ids, QEMU-style): host bridge 00:00.0 and a
 * virtio NIC 00:01.0, two buses. */
static uint8_t *mk_fake_seg0(void)
{
    uint8_t *ecam = map_aligned(FAKE_BYTES);
    if (!ecam) return NULL;
    memset(ecam, 0xff, FAKE_BYTES);
    uint8_t *c;
    memset(c = cfgp(ecam, 0, 0, 0), 0, 4096); mkfn(c, 0x1b36, 0x0008, 0x060000, 0);
    memset(c = cfgp(ecam, 0, 1, 0), 0, 4096); mkfn(c, 0x1af4, 0x1041, 0x020000, 0);
    return ecam;
}

/* Segment-15 fake, copied to a 1 MiB aligned map (same content as mk_fake_seg15). */
static uint8_t *mk_fake_seg15_aligned(void)
{
    uint8_t *src = mk_fake_seg15();
    uint8_t *dst = map_aligned(FAKE_BYTES);
    if (src && dst) memcpy(dst, src, FAKE_BYTES);
    if (src) munmap(src, FAKE_BYTES);
    return dst;
}

static size_t mk_two_seg_mcfg(uint8_t *t, uint8_t *e0, uint8_t *e15)
{
    uint64_t b[2] = {(uint64_t)(uintptr_t)e0, (uint64_t)(uintptr_t)e15};
    uint16_t s[2] = {0, FAKE_SEG};
    uint8_t sb[2] = {0, 0}, eb[2] = {1, 1};
    return mk_mcfg(t, 2, b, s, sb, eb);
}

static int has(const char *text, const char *needle) { return strstr(text, needle) != NULL; }

static void test_discover_report(void)
{
    uint8_t *e0 = mk_fake_seg0(), *e15 = mk_fake_seg15_aligned();
    CHECK(e0 && e15);
    if (!e0 || !e15) return;
    static uint8_t c0[FAKE_BYTES], c15[FAKE_BYTES];
    memcpy(c0, e0, FAKE_BYTES);
    memcpy(c15, e15, FAKE_BYTES);
    CHECK(mprotect(e0, FAKE_BYTES, PROT_READ) == 0);
    CHECK(mprotect(e15, FAKE_BYTES, PROT_READ) == 0);
    uint8_t t[44 + 32];
    size_t len = mk_two_seg_mcfg(t, e0, e15);
    ck_host_mcfg = t;
    ck_host_try_map_ok = 1;
    ck_host_try_map_fail = 0;

    /* Both segments mapped read-only: a config write would kill the process. */
    ck_host_capture_start();
    CHECK(pci_stage_discover_report() == PCI_OK);
    ck_host_capture_stop();
    const char *x = ck_host_capture_text();
    CHECK(has(x, "pci_disc: seg 0000 bus 00-01 functions=2 bridges=0 rc=0\n"));
    CHECK(has(x, "pci_disc: seg 000f bus 00-01 functions=2 bridges=1 rc=0\n"));
    CHECK(has(x, "pci_disc: 000f:01:00.0 10de:2e12 class=030000 rev=a1\n"));
    CHECK(has(x, "pci_disc: 0000:00:01.0 1af4:1041 class=020000 rev=01\n"));
    CHECK(has(x, "pci_disc: segments=2 functions=4 (read-only, no config writes)\n"));
    CHECK(memcmp(e0, c0, FAKE_BYTES) == 0 && memcmp(e15, c15, FAKE_BYTES) == 0);

    /* Segment 15 map refused: that segment is reported as refused, segment 0 still scanned, no fallback. */
    ck_host_try_map_fail = (uint64_t)(uintptr_t)e15;
    ck_host_capture_start();
    CHECK(pci_stage_discover_report() == PCI_OK);
    ck_host_capture_stop();
    x = ck_host_capture_text();
    CHECK(has(x, "pci_disc: seg 000f bus 00-01 REFUSED"));
    CHECK(!has(x, "10de:2e12"));
    CHECK(has(x, "pci_disc: seg 0000 bus 00-01 functions=2"));
    CHECK(has(x, "pci_disc: segments=1 functions=2 (read-only, no config writes)\n"));

    /* Mapping unavailable for every segment (the host default): all refused. */
    ck_host_try_map_ok = 0;
    ck_host_try_map_fail = 0;
    ck_host_capture_start();
    CHECK(pci_stage_discover_report() == PCI_OK);
    ck_host_capture_stop();
    x = ck_host_capture_text();
    CHECK(has(x, "pci_disc: segments=0 functions=0 (read-only, no config writes)\n"));

    /* Malformed MCFG: error returned, one line. */
    ck_host_try_map_ok = 1;
    t[4] = (uint8_t)(len - 1);
    ck_host_capture_start();
    CHECK(pci_stage_discover_report() == PCI_E_MCFG);
    ck_host_capture_stop();
    CHECK(has(ck_host_capture_text(), "pci_disc: MCFG malformed"));
    ck_host_mcfg = NULL;
    ck_host_capture_start();
    CHECK(pci_stage_discover_report() == PCI_E_NO_MCFG);
    ck_host_capture_stop();
    CHECK(has(ck_host_capture_text(), "pci_disc: no ACPI MCFG table\n"));
    ck_host_try_map_ok = 0;
    munmap(e0, FAKE_BYTES);
    munmap(e15, FAKE_BYTES);
}

/* The devices stage runs the report after pci: probe, ignores its result, and
 * leaves the report's segments untouched (segment 15 is read-only here). */
static void test_discover_in_stage(void)
{
    uint8_t *e0 = mk_fake_seg0(), *e15 = mk_fake_seg15_aligned();
    CHECK(e0 && e15);
    if (!e0 || !e15) return;
    static uint8_t c15[FAKE_BYTES];
    memcpy(c15, e15, FAKE_BYTES);
    CHECK(mprotect(e15, FAKE_BYTES, PROT_READ) == 0);
    uint8_t t[44 + 32];
    size_t len = mk_two_seg_mcfg(t, e0, e15);
    ck_host_mcfg = t;
    ck_host_try_map_ok = 1;
    ck_host_quiet = 1;
    ck_host_capture_start();
    CHECK(ck_stage_devices() == 0);
    ck_host_capture_stop();
    const char *x = ck_host_capture_text();
    const char *p = strstr(x, "pci: ecam base="), *d = strstr(x, "pci_disc: seg 0000"), *v = strstr(x, "devices: pci=ok");
    CHECK(p && d && v && p < d && d < v);                           /* probe, then report, then the rest */
    CHECK(has(x, "pci_disc: 000f:01:00.0 10de:2e12 class=030000 rev=a1\n"));
    CHECK(memcmp(e15, c15, FAKE_BYTES) == 0);

    /* Report fails (segment 0 allocated twice: pci_mcfg_parse takes the first,
     * pci_mcfg_parse_all refuses the table): the stage still completes. */
    uint64_t b[2] = {(uint64_t)(uintptr_t)e0, (uint64_t)(uintptr_t)e0};
    uint16_t s[2] = {0, 0};
    uint8_t sb[2] = {0, 0}, eb[2] = {1, 1};
    (void)len;
    mk_mcfg(t, 2, b, s, sb, eb);
    ck_host_capture_start();
    CHECK(ck_stage_devices() == 0);
    ck_host_capture_stop();
    x = ck_host_capture_text();
    CHECK(has(x, "pci_disc: MCFG malformed") && has(x, "devices: pci=ok"));
    ck_host_capture_stop();
    ck_host_quiet = 0;
    ck_host_try_map_ok = 0;
    ck_host_mcfg = NULL;
    munmap(e0, FAKE_BYTES);
    munmap(e15, FAKE_BYTES);
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


/* ---------------- post-exit bus-master sweep + xHCI DMA fence ---------------- */

static void test_xhci_fence(void)
{
    /* Sweep on a fake ECAM: endpoints with BME are cleared and read back,
     * bridges are counted and left untouched, functions 1-7 are walked only
     * when function 0 is marked multi-function (Rust dma_gate tests). */
    const size_t buses = 2;
    uint8_t *ecam = aligned_alloc(1u << 20, buses << 20);
    CHECK(ecam != NULL);
    if (!ecam) return;
    memset(ecam, 0xff, buses << 20);
    uint8_t *c;
    memset(c = cfgp(ecam, 0, 0, 0), 0, 4096); mkfn(c, 0x1b36, 0x0008, 0x060000, 0); put16(c + 4, 0x0002);
    memset(c = cfgp(ecam, 0, 1, 0), 0, 4096); mkfn(c, 0x1b36, 0x000c, 0x060400, 1); put16(c + 4, 0x0007);
    memset(c = cfgp(ecam, 0, 2, 0), 0, 4096); mkfn(c, 0x1b36, 0x000d, 0x0c0330, 0x80); put16(c + 4, 0x0006);
    memset(c = cfgp(ecam, 0, 2, 3), 0, 4096); mkfn(c, 0x8086, 0x10d3, 0x020000, 0); put16(c + 4, 0x0004);
    memset(c = cfgp(ecam, 0, 3, 0), 0, 4096); mkfn(c, 0x1af4, 0x1041, 0x020000, 0); put16(c + 4, 0x0006);
    /* function 3 of a single-function device: never walked, BME stays */
    memset(c = cfgp(ecam, 0, 3, 3), 0, 4096); mkfn(c, 0x1af4, 0x1041, 0x020000, 0); put16(c + 4, 0x0004);
    memset(c = cfgp(ecam, 1, 0, 0), 0, 4096); mkfn(c, 0x144d, 0xa808, 0x010802, 0); put16(c + 4, 0x0006);
    pci_bus_access acc = {ecam, 0, (uint8_t)(buses - 1)};
    pci_sweep sw;
    pci_sweep_bus_master(&acc, &sw);
    CHECK(sw.functions == 6);
    CHECK(sw.bridges == 1 && sw.bridges_bme == 1);
    CHECK(sw.endpoints_bme == 4 && sw.still_enabled == 0);
    CHECK(sw.f[0].bus == 0 && sw.f[0].dev == 2 && sw.f[0].fn == 0 && sw.f[0].command_before == 0x0006 &&
          sw.f[0].command_after == 0x0002);
    CHECK(pci_r16(cfgp(ecam, 0, 1, 0), 4) == 0x0007);           /* bridge untouched */
    CHECK((pci_r16(cfgp(ecam, 0, 2, 3), 4) & 0x4u) == 0);       /* multi-function walked */
    CHECK((pci_r16(cfgp(ecam, 1, 0, 0), 4) & 0x4u) == 0);       /* every bus in the window */
    CHECK((pci_r16(cfgp(ecam, 0, 3, 3), 4) & 0x4u) == 0x4u);    /* not walked: single-function */
    CHECK(pci_r16(cfgp(ecam, 0, 0, 0), 4) == 0x0002);           /* no BME: untouched */
    pci_ecam e = {0, 0, 0, (uint8_t)(buses - 1)};
    pci_sweep_report(&e, &sw);
    /* Counter-example: a sweep that skipped bus 1 would leave its BME set. */
    put16(cfgp(ecam, 1, 0, 0) + 4, 0x0006);
    pci_bus_access bus0 = {ecam, 0, 0};
    pci_sweep_bus_master(&bus0, &sw);
    CHECK((pci_r16(cfgp(ecam, 1, 0, 0), 4) & 0x4u) == 0x4u && sw.endpoints_bme == 0);

    /* xHCI fence on the host shim (no IORT: CK_SMMU_ABSENT): fail closed,
     * the command register never gets memory decode or bus master. */
    static pci_system s;
    memset(&s, 0, sizeof s);
    printf("  [xHCI fence, no xHCI, host, not hardware]\n");
    CHECK(ck_xhci_fence(&s) == CK_XHCI_ABSENT && strcmp(ck_xhci_state(), "absent") == 0);
    static uint8_t cfg[4096];
    memset(cfg, 0, sizeof cfg);
    s.n = 1;
    s.f[0].vendor = 0x1b36;
    s.f[0].device = 0x000d;
    s.f[0].class_code = 0x0c0330;
    s.f[0].cfg = cfg;
    s.f[0].bar[0].addr = 0x10000000u;
    s.f[0].bar[0].size = 0x4000u;
    s.f[0].bar[0].is64 = 1;
    printf("  [xHCI fence without SMMU, host, not hardware]\n");
    CHECK(ck_xhci_fence(&s) == CK_XHCI_E_DENIED);
    CHECK((pci_r16(cfg, 4) & 0x6u) == 0); /* no MEM, no BM */
    CHECK(ck_xhci_live() == 0 && strcmp(ck_xhci_state(), "denied") == 0);
    ck_xhci_release(); /* idempotent */
    CHECK((pci_r16(cfg, 4) & 0x6u) == 0);
    /* Bus master still on before the gate: no gate at all. */
    put16(cfg + 4, 0x0004);
    printf("  [xHCI fence with BME left on, host, not hardware]\n");
    CHECK(ck_xhci_fence(&s) == CK_XHCI_E_BME && strcmp(ck_xhci_state(), "bme-stuck") == 0);
    CHECK(ck_xhci_live() == 0 && (pci_r16(cfg, 4) & 0x2u) == 0);
    put16(cfg + 4, 0);
    free(ecam);
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

/* ---------------- operator input pure logic (dev/usb_hid.c) ---------------- */

static char g_echo[256];
static size_t g_echo_n;
static void t_echo(char c) { if (g_echo_n < sizeof g_echo - 1) g_echo[g_echo_n++] = c; }
static char g_sh[512];
static void t_out(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t n = strlen(g_sh);
    vsnprintf(g_sh + n, sizeof g_sh - n, fmt, ap);
    va_end(ap);
}

static void test_usb_hid(void)
{
    /* keymap */
    CHECK(ck_hid_usage(0x04, 0).kind == CK_KEY_CHAR && ck_hid_usage(0x04, 0).c == 'a');
    CHECK(ck_hid_usage(0x1d, 1).c == 'Z');
    CHECK(ck_hid_usage(0x1e, 0).c == '1' && ck_hid_usage(0x27, 0).c == '0');
    CHECK(ck_hid_usage(0x1e, 1).kind == CK_KEY_NONE); /* shifted digit: not in the keymap */
    CHECK(ck_hid_usage(0x28, 0).kind == CK_KEY_ENTER && ck_hid_usage(0x2a, 0).kind == CK_KEY_BACKSPACE);
    CHECK(ck_hid_usage(0x29, 0).kind == CK_KEY_ESCAPE && ck_hid_usage(0x2c, 0).c == ' ');
    CHECK(ck_hid_usage(0x3a, 0).kind == CK_KEY_NONE); /* F1 */

    /* decode: new usages only, rollover ignored, wrong length ignored */
    ck_hid_decoder d = {{0}};
    ck_key_event ev[CK_HID_MAX_KEYS];
    uint8_t r1[8] = {0, 0, 0x04, 0, 0, 0, 0, 0};
    CHECK(ck_hid_decode(&d, r1, 8, ev) == 1 && ev[0].c == 'a');
    CHECK(ck_hid_decode(&d, r1, 8, ev) == 0); /* still held: no repeat */
    uint8_t r2[8] = {0x02, 0, 0x04, 0x05, 0, 0, 0, 0};
    CHECK(ck_hid_decode(&d, r2, 8, ev) == 1 && ev[0].c == 'B');
    uint8_t roll[8] = {0, 0, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    CHECK(ck_hid_decode(&d, roll, 8, ev) == 0);
    CHECK(ck_hid_decode(&d, r2, 8, ev) == 0); /* rollover kept the previous state */
    uint8_t up[8] = {0};
    CHECK(ck_hid_decode(&d, up, 8, ev) == 0);
    CHECK(ck_hid_decode(&d, r1, 8, ev) == 1 && ev[0].c == 'a'); /* pressed again after release */
    CHECK(ck_hid_decode(&d, r1, 7, ev) == 0);

    /* configuration descriptor (same fixtures as the Rust descriptor.rs tests) */
    static const uint8_t kbd[34] = {9, 2, 34, 0, 1, 1, 8, 0xa0, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0,
                                    9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0, 7, 5, 0x81, 3, 8, 0, 7};
    ck_boot_kbd bk;
    CHECK(ck_usb_find_boot_kbd(kbd, sizeof kbd, &bk) == 0 && bk.configuration == 1 && bk.interface == 0 &&
          bk.endpoint == 0x81 && bk.max_packet == 8 && bk.interval == 7);
    static const uint8_t comp[50] = {9, 2, 50, 0, 2, 2, 0, 0xa0, 50, 9, 4, 0, 0, 1, 3, 1, 2, 0, 7, 5, 0x81, 3, 4, 0, 10,
                                     9, 4, 1, 0, 2, 3, 1, 1, 0, 7, 5, 0x02, 3, 8, 0, 10, 7, 5, 0x83, 3, 8, 0, 4, 0, 0};
    CHECK(ck_usb_find_boot_kbd(comp, sizeof comp, &bk) == 0 && bk.interface == 1 && bk.endpoint == 0x83 && bk.interval == 4);
    uint8_t bad[34];
    memcpy(bad, kbd, sizeof bad);
    bad[27] = 40; /* endpoint length runs past wTotalLength */
    CHECK(ck_usb_find_boot_kbd(bad, sizeof bad, &bk) == -1);
    memcpy(bad, kbd, sizeof bad);
    bad[16] = 2; /* protocol mouse: no keyboard */
    CHECK(ck_usb_find_boot_kbd(bad, sizeof bad, &bk) == -1);
    CHECK(ck_usb_find_boot_kbd(kbd, 8, &bk) == -1);
    memcpy(bad, kbd, sizeof bad);
    bad[9] = 1; /* zero-progress descriptor length */
    CHECK(ck_usb_find_boot_kbd(bad, sizeof bad, &bk) == -1);

    /* line editor: echo, backspace, Enter, fail closed on overflow */
    ck_line l;
    ck_line_reset(&l);
    g_echo_n = 0;
    ck_key_event a = {CK_KEY_CHAR, 'a'}, b = {CK_KEY_CHAR, 'b'}, bs = {CK_KEY_BACKSPACE, 0}, en = {CK_KEY_ENTER, 0};
    CHECK(ck_line_feed(&l, a, t_echo) == CK_LINE_MORE && ck_line_feed(&l, b, t_echo) == CK_LINE_MORE);
    CHECK(ck_line_feed(&l, bs, t_echo) == CK_LINE_MORE && l.len == 1);
    CHECK(ck_line_feed(&l, en, t_echo) == CK_LINE_DONE && strcmp(l.buf, "a") == 0);
    CHECK(g_echo_n == 3 && g_echo[0] == 'a' && g_echo[1] == 'b' && g_echo[2] == '\b');
    ck_line_reset(&l);
    ck_key_event x = {CK_KEY_CHAR, 'x'};
    for (unsigned i = 0; i < CK_LINE_CAP; i++) CHECK(ck_line_feed(&l, x, 0) == CK_LINE_MORE);
    CHECK(l.len == CK_LINE_CAP && !l.overflow);
    CHECK(ck_line_feed(&l, x, 0) == CK_LINE_MORE && l.overflow && l.len == CK_LINE_CAP);
    CHECK(ck_line_feed(&l, bs, 0) == CK_LINE_MORE && l.len == CK_LINE_CAP); /* no backing out of an overflow */
    CHECK(ck_line_feed(&l, en, 0) == CK_LINE_OVERFLOW && l.len == 0 && l.buf[0] == 0 && l.typed == CK_LINE_CAP + 1);
    ck_line_reset(&l);
    for (unsigned i = 0; i < CK_LINE_CAP; i++) (void)ck_line_feed(&l, x, 0);
    CHECK(ck_line_feed(&l, en, 0) == CK_LINE_DONE && l.len == CK_LINE_CAP); /* exactly at the bound is accepted */

    /* console session: source ownership of the shared line and the drop count */
    {
        ck_src_gate g;
        ck_src_gate_reset(&g);
        ck_key_event ca = {CK_KEY_CHAR, 'a'}, cb = {CK_KEY_CHAR, 'b'}, cn = {CK_KEY_NONE, 0}, ce = {CK_KEY_ESCAPE, 0};
        CHECK(g.owner == CK_SRC_NONE);
        CHECK(ck_src_gate_accept(&g, CK_SRC_SERIAL, ca) == 1 && g.owner == CK_SRC_SERIAL); /* first source claims */
        CHECK(ck_src_gate_accept(&g, CK_SRC_SERIAL, cb) == 1); /* owner keeps typing */
        CHECK(ck_src_gate_accept(&g, CK_SRC_USB, ca) == 0 && ck_src_gate_accept(&g, CK_SRC_USB, cb) == 0);
        CHECK(ck_src_gate_accept(&g, CK_SRC_USB, en) == 0); /* other source's Enter is dropped too */
        CHECK(g.dropped == 3 && g.dropped_all == 3 && g.owner == CK_SRC_SERIAL);
        CHECK(ck_src_gate_accept(&g, CK_SRC_SERIAL, cn) == 0 && g.dropped == 3); /* NONE is never counted */
        CHECK(ck_src_gate_accept(&g, 7, ca) == 0 && g.dropped == 3); /* unknown source: refused, not counted */
        CHECK(ck_src_gate_release(&g) == 3 && g.owner == CK_SRC_NONE && g.dropped == 0 && g.dropped_all == 3);
        CHECK(ck_src_gate_accept(&g, CK_SRC_USB, ca) == 1 && g.owner == CK_SRC_USB); /* now USB claims */
        CHECK(ck_src_gate_accept(&g, CK_SRC_SERIAL, ca) == 0 && g.dropped == 1 && g.dropped_all == 4);
        CHECK(ck_src_gate_accept(&g, CK_SRC_SERIAL, ce) == 0 && g.dropped == 2); /* Escape of the non-owner cannot clear it */
        CHECK(ck_src_gate_release(&g) == 2);
        /* only a printable key claims: Backspace, Escape and Enter on an empty line do not lock the other source out */
        ck_src_gate_reset(&g);
        ck_key_event cbs = {CK_KEY_BACKSPACE, 0};
        CHECK(ck_src_gate_accept(&g, CK_SRC_USB, cbs) == 1 && g.owner == CK_SRC_NONE);
        CHECK(ck_src_gate_accept(&g, CK_SRC_USB, ce) == 1 && g.owner == CK_SRC_NONE);
        CHECK(ck_src_gate_accept(&g, CK_SRC_USB, en) == 1 && g.owner == CK_SRC_NONE);
        CHECK(ck_src_gate_accept(&g, CK_SRC_SERIAL, ca) == 1 && g.owner == CK_SRC_SERIAL && g.dropped_all == 0);
        CHECK(ck_src_gate_accept(&g, CK_SRC_USB, cbs) == 0 && g.dropped == 1); /* once owned, the other source's Backspace is dropped */
        (void)ck_src_gate_release(&g);
        /* end to end with the line editor: only the owner's keys reach the line */
        ck_line ln;
        ck_line_reset(&ln);
        ck_src_gate_reset(&g);
        int seq[8] = {CK_SRC_SERIAL, CK_SRC_USB, CK_SRC_SERIAL, CK_SRC_USB, CK_SRC_SERIAL};
        const char keys[8] = {'h', 'x', 'e', 'y', 'l'};
        for (int i = 0; i < 5; i++) {
            ck_key_event k = {CK_KEY_CHAR, keys[i]};
            if (ck_src_gate_accept(&g, seq[i], k)) (void)ck_line_feed(&ln, k, 0);
        }
        CHECK(ck_src_gate_accept(&g, CK_SRC_SERIAL, en) == 1 && ck_line_feed(&ln, en, 0) == CK_LINE_DONE);
        CHECK(strcmp(ln.buf, "hel") == 0 && ck_src_gate_release(&g) == 2);
        /* serial bytes to keys */
        uint8_t pv = 0;
        CHECK(ck_serial_key('a', &pv).kind == CK_KEY_CHAR && ck_serial_key('Z', &pv).c == 'Z');
        CHECK(ck_serial_key('7', &pv).c == '7' && ck_serial_key(' ', &pv).c == ' ' && ck_serial_key('-', &pv).c == '-');
        CHECK(ck_serial_key('\r', &pv).kind == CK_KEY_ENTER);
        CHECK(ck_serial_key('\n', &pv).kind == CK_KEY_NONE); /* LF right after CR: one Enter */
        CHECK(ck_serial_key('\n', &pv).kind == CK_KEY_ENTER); /* a lone LF is an Enter */
        CHECK(ck_serial_key(0x7f, &pv).kind == CK_KEY_BACKSPACE && ck_serial_key(0x08, &pv).kind == CK_KEY_BACKSPACE);
        CHECK(ck_serial_key(0x1b, &pv).kind == CK_KEY_ESCAPE);
        CHECK(ck_serial_key(';', &pv).kind == CK_KEY_NONE && ck_serial_key(0x00, &pv).kind == CK_KEY_NONE &&
              ck_serial_key(0xc3, &pv).kind == CK_KEY_NONE && ck_serial_key('"', &pv).kind == CK_KEY_NONE);
    }

    /* shell (Rust shell.rs texts) */
    ck_shell_ctx ctx = {42, 1, 7, "c0ffee"};
    g_sh[0] = 0;
    CHECK(ck_shell_run("help", &ctx, t_out) == 0 && strcmp(g_sh, "commands: help mem el report uptime exit\n") == 0);
    g_sh[0] = 0;
    CHECK(ck_shell_run("el", &ctx, t_out) == 0 && strcmp(g_sh, "EL1\n") == 0);
    g_sh[0] = 0;
    CHECK(ck_shell_run(" mem ", &ctx, t_out) == 0 && strcmp(g_sh, "conventional_memory_kb: 42\n") == 0);
    g_sh[0] = 0;
    CHECK(ck_shell_run("uptime", &ctx, t_out) == 0 && strcmp(g_sh, "uptime_ms: 7\n") == 0);
    g_sh[0] = 0;
    CHECK(ck_shell_run("report", &ctx, t_out) == 0 && strstr(g_sh, "aienos_commit: c0ffee") != NULL);
    g_sh[0] = 0;
    CHECK(ck_shell_run("wat", &ctx, t_out) == 0 && strcmp(g_sh, "unknown command: wat\n") == 0);
    g_sh[0] = 0;
    CHECK(ck_shell_run("x a b", &ctx, t_out) == 0 && strcmp(g_sh, "invalid command line\n") == 0);
    g_sh[0] = 0;
    CHECK(ck_shell_run("x 12345678901234567", &ctx, t_out) == 0 && strcmp(g_sh, "invalid command line\n") == 0);
    g_sh[0] = 0;
    CHECK(ck_shell_run("exit", &ctx, t_out) == 1 && g_sh[0] == 0);
    CHECK(ck_shell_parse("", 0) == CK_SH_EMPTY && ck_shell_parse("unknown abc", 11) == CK_SH_UNKNOWN);

    /* recovery decision and identity digest */
    ck_key_event r = {CK_KEY_CHAR, 'r'}, R = {CK_KEY_CHAR, 'R'};
    CHECK(ck_recovery_decide(0, r) == CK_RECOVERY_NORMAL_TIMEOUT);
    CHECK(ck_recovery_decide(1, r) == CK_RECOVERY_CONSOLE && ck_recovery_decide(1, R) == CK_RECOVERY_CONSOLE);
    CHECK(ck_recovery_decide(1, a) == CK_RECOVERY_NORMAL_KEY && ck_recovery_decide(1, en) == CK_RECOVERY_NORMAL_KEY);
    CHECK(strcmp(ck_recovery_name(CK_RECOVERY_CONSOLE), "recovery reason=key-r") == 0);
    uint8_t id[32], want[32];
    static const char msg[] = "AIENOS-CK-RECOVERY-IDENTITY-V1\0abc";
    sha256_hash((const uint8_t *)msg, sizeof msg - 1, want);
    ck_recovery_identity("abc", id);
    CHECK(memcmp(id, want, 32) == 0);
    ck_recovery_identity("abd", want);
    CHECK(memcmp(id, want, 32) != 0);
}

/* ---------------- Capability-bound read-only MMIO window (cut B3) ---------------- */

#define WIN_BYTES 4096u
static uint8_t win_pat(size_t i) { return (uint8_t)(i * 7u + 3u); }
static uint64_t win_expect(uint64_t off, unsigned w)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < w; i++) v |= (uint64_t)win_pat(off + i) << (8 * i);
    return v;
}

/* Fake BAR window: pattern bytes, then PROT_READ so any stray write traps. */
static uint8_t *mk_fake_bar(void)
{
    uint8_t *m = mmap(NULL, WIN_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return NULL;
    for (size_t i = 0; i < WIN_BYTES; i++) m[i] = win_pat(i);
    if (mprotect(m, WIN_BYTES, PROT_READ) != 0) return NULL;
    return m;
}

static void child_write_window(uint8_t *p) { *(volatile uint8_t *)p = 0x5a; }

static void test_mmio_window(void)
{
    uint8_t *bar = mk_fake_bar();
    uint8_t *ecam = mk_fake_seg15();
    CHECK(bar && ecam);
    if (!bar || !ecam) return;
    static uint8_t copy[WIN_BYTES];
    memcpy(copy, bar, WIN_BYTES);
    pci_bus_access a;
    acc_for(&a, ecam, 0, 1);
    pci_found f[8];
    uint32_t n = 0, br = 0;
    CHECK(pci_discover(&a, FAKE_SEG, f, 8, &n, &br) == PCI_OK);
    const pci_found *g = NULL;
    for (uint32_t i = 0; i < n; i++)
        if (f[i].vendor == 0x10de && f[i].device == 0x2e12) g = &f[i];
    CHECK(g != NULL);
    if (!g) return;

    /* BAR decode: bar0 is a 64-bit pair (0x0c, 0x01) = 0x1_0000_0000; bar2 is
     * a 64-bit BAR whose halves are both 0 (address 0). */
    uint64_t ad = 0;
    CHECK(ck_mmio_bar_addr(g, 0, &ad) == CK_MMIO_OK && ad == 0x100000000ull);
    CHECK(ck_mmio_bar_addr(g, 2, &ad) == CK_MMIO_E_BAR);            /* address 0 refused */
    CHECK(ck_mmio_bar_addr(g, 3, &ad) == CK_MMIO_E_BAR);            /* unused register */
    CHECK(ck_mmio_bar_addr(g, 1, &ad) == CK_MMIO_E_BAR);            /* raw value 1: I/O BAR */
    CHECK(ck_mmio_bar_addr(g, 6, &ad) == CK_MMIO_E_ARG);
    CHECK(ck_mmio_bar_addr(NULL, 0, &ad) == CK_MMIO_E_ARG);
    pci_found syn = *g;
    memset(syn.bar_raw, 0, sizeof syn.bar_raw);
    syn.bar_raw[0] = 0x10000008u;                                   /* 32-bit prefetchable memory */
    CHECK(ck_mmio_bar_addr(&syn, 0, &ad) == CK_MMIO_OK && ad == 0x10000000ull);
    syn.bar_raw[0] = 0x10000002u;                                   /* reserved type 1 */
    CHECK(ck_mmio_bar_addr(&syn, 0, &ad) == CK_MMIO_E_BAR);
    syn.bar_raw[5] = 0x1000000cu;                                   /* 64-bit at the last register: no upper half */
    CHECK(ck_mmio_bar_addr(&syn, 5, &ad) == CK_MMIO_E_BAR);

    struct ck_mmio_registry reg;
    struct ck_cap_table tab;
    struct ck_cap_table *const tabs[1] = {&tab};
    ck_mmio_registry_init(&reg);
    ck_cap_init(&tab, 1, CK_CAP_SLOTS);
    struct ck_handle h, h2;

    /* Creation refusals: write (and every right outside READ|DERIVE|REVOKE). */
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_R_READ | CK_R_WRITE, &h) == CK_MMIO_E_RIGHTS);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_R_ALL, &h) == CK_MMIO_E_RIGHTS);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_R_READ | CK_R_MAP, &h) == CK_MMIO_E_RIGHTS);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_R_READ | CK_R_GRANT, &h) == CK_MMIO_E_RIGHTS);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_R_WRITE, &h) == CK_MMIO_E_RIGHTS);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_R_DERIVE, &h) == CK_MMIO_E_RIGHTS); /* no READ */
    /* Other creation refusals. */
    CHECK(ck_mmio_window_create(&reg, &tab, g, 2, WIN_BYTES, bar, CK_MMIO_RIGHTS, &h) == CK_MMIO_E_BAR);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, 0, bar, CK_MMIO_RIGHTS, &h) == CK_MMIO_E_ARG);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, NULL, CK_MMIO_RIGHTS, &h) == CK_MMIO_E_ARG);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_MMIO_RIGHTS, NULL) == CK_MMIO_E_ARG);
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, 0xffffffffffffffffull, bar, CK_MMIO_RIGHTS, &h) == CK_MMIO_E_RANGE); /* wraps */
    CHECK(reg.next == 0);                                           /* refusals consumed nothing */

    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_MMIO_RIGHTS, &h) == CK_MMIO_OK);
    CHECK(reg.next == 1 && reg.w[0].bus_addr == 0x100000000ull && reg.w[0].size == WIN_BYTES);

    /* In-range reads return fixture values (all widths, edges). */
    uint64_t v = 0;
    static const unsigned widths[4] = {1, 2, 4, 8};
    for (unsigned k = 0; k < 4; k++) {
        unsigned w = widths[k];
        const uint64_t offs[4] = {0, 8, 64, WIN_BYTES - w};
        for (unsigned j = 0; j < 4; j++) {
            v = ~0ull;
            CHECK(ck_mmio_read(&reg, &tab, h, offs[j], w, &v) == CK_MMIO_OK && v == win_expect(offs[j], w));
        }
    }

    /* Refusals: out of range, oversize, unaligned, bad width. *value untouched. */
    v = 0xdeadbeefull;
    CHECK(ck_mmio_read(&reg, &tab, h, WIN_BYTES, 1, &v) == CK_MMIO_E_RANGE);
    CHECK(ck_mmio_read(&reg, &tab, h, WIN_BYTES - 4, 8, &v) == CK_MMIO_E_ALIGN); /* 8-byte access must be 8-aligned */
    CHECK(ck_mmio_read(&reg, &tab, h, WIN_BYTES + 8, 8, &v) == CK_MMIO_E_RANGE);
    CHECK(ck_mmio_read(&reg, &tab, h, 0xfffffffffffffff8ull, 8, &v) == CK_MMIO_E_RANGE); /* offset + width wraps */
    CHECK(ck_mmio_read(&reg, &tab, h, 0xffffffffffffffffull, 1, &v) == CK_MMIO_E_RANGE);
    CHECK(ck_mmio_read(&reg, &tab, h, 1, 2, &v) == CK_MMIO_E_ALIGN);
    CHECK(ck_mmio_read(&reg, &tab, h, 2, 4, &v) == CK_MMIO_E_ALIGN);
    CHECK(ck_mmio_read(&reg, &tab, h, 4, 8, &v) == CK_MMIO_E_ALIGN);
    CHECK(ck_mmio_read(&reg, &tab, h, 0, 3, &v) == CK_MMIO_E_ALIGN);
    CHECK(ck_mmio_read(&reg, &tab, h, 0, 0, &v) == CK_MMIO_E_ALIGN);
    CHECK(ck_mmio_read(&reg, &tab, h, 0, 16, &v) == CK_MMIO_E_ALIGN);
    CHECK(ck_mmio_read(&reg, &tab, h, 0, 4, NULL) == CK_MMIO_E_ARG);
    CHECK(v == 0xdeadbeefull);

    /* Rights: a child without READ cannot read; a child cannot gain WRITE. */
    struct ck_handle noread, rd;
    CHECK(ck_cap_derive(&tab, h, CK_R_DERIVE, &noread) == CK_CAP_OK);
    CHECK(ck_mmio_read(&reg, &tab, noread, 0, 4, &v) == CK_CAP_MISSING_RIGHTS);
    CHECK(v == 0xdeadbeefull);
    CHECK(ck_cap_derive(&tab, h, CK_R_READ | CK_R_WRITE, &h2) == CK_CAP_ESCALATION);
    CHECK(ck_cap_derive(&tab, h, CK_R_READ, &rd) == CK_CAP_OK);
    CHECK(ck_mmio_read(&reg, &tab, rd, 16, 4, &v) == CK_CAP_OK && v == win_expect(16, 4));

    /* A live handle for some other resource names no window. */
    struct ck_handle other;
    CHECK(ck_cap_insert(&tab, 0x12345u, CK_R_READ, &other) == CK_CAP_OK);
    CHECK(ck_mmio_read(&reg, &tab, other, 0, 4, &v) == CK_MMIO_E_RESOURCE);
    CHECK(ck_mmio_read(&reg, &tab, (struct ck_handle){6, 1}, 0, 4, &v) == CK_CAP_INVALID); /* empty slot */
    struct ck_handle stale = h;
    stale.generation += 1;                                          /* generation not issued */
    CHECK(ck_mmio_read(&reg, &tab, stale, 0, 4, &v) == CK_CAP_INVALID);

    /* Revoke the parent: parent and derived children all refused. */
    CHECK(ck_cap_revoke(tab.id, h, tabs, 1) == CK_CAP_OK);
    v = 0xdeadbeefull;
    CHECK(ck_mmio_read(&reg, &tab, h, 0, 4, &v) == CK_CAP_INVALID);
    CHECK(ck_mmio_read(&reg, &tab, rd, 16, 4, &v) == CK_CAP_INVALID);
    CHECK(ck_mmio_read(&reg, &tab, noread, 0, 4, &v) == CK_CAP_INVALID);
    for (unsigned k = 0; k < 4; k++)
        CHECK(ck_mmio_read(&reg, &tab, h, 0, widths[k], &v) == CK_CAP_INVALID);
    CHECK(v == 0xdeadbeefull);

    /* A new window never reuses the number; the old handle stays refused even
     * though its table slot is reused with a higher generation. */
    CHECK(ck_mmio_window_create(&reg, &tab, g, 0, WIN_BYTES, bar, CK_MMIO_RIGHTS, &h2) == CK_MMIO_OK);
    CHECK(reg.next == 2 && reg.w[1].resource != reg.w[0].resource);
    CHECK(h2.index == h.index && h2.generation > h.generation);
    CHECK(ck_mmio_read(&reg, &tab, h, 0, 4, &v) == CK_CAP_INVALID);
    CHECK(ck_mmio_read(&reg, &tab, h2, 0, 4, &v) == CK_CAP_OK && v == win_expect(0, 4));

    /* Registry full: windows are never freed. */
    ck_mmio_registry_init(&reg);
    struct ck_cap_table big;
    ck_cap_init(&big, 2, CK_CAP_SLOTS);
    for (unsigned i = 0; i < CK_MMIO_WINDOWS; i++)
        CHECK(ck_mmio_window_create(&reg, &big, g, 0, WIN_BYTES, bar, CK_MMIO_RIGHTS, &h) == CK_MMIO_OK);
    CHECK(ck_mmio_window_create(&reg, &big, g, 0, WIN_BYTES, bar, CK_MMIO_RIGHTS, &h) == CK_MMIO_E_FULL);

    /* The fake BAR bytes never changed; the write trap is live. */
    CHECK(memcmp(bar, copy, WIN_BYTES) == 0);
    CHECK(child_died_on_write(child_write_window, bar) == 1);       /* NEGATIVE CONTROL */
    CHECK(memcmp(bar, copy, WIN_BYTES) == 0);
    munmap(bar, WIN_BYTES);
    munmap(ecam, FAKE_BYTES);
}

/* The stage report binds a window to a discovered NVMe BAR0, reads VS
 * through the capability, and shows the read refused after revoke. */
static void test_mmio_stage_report(void)
{
    uint8_t *ecam = map_aligned(FAKE_BYTES);
    uint8_t *regs = mmap(NULL, WIN_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(ecam && regs != MAP_FAILED);
    if (!ecam || regs == MAP_FAILED) return;
    memset(ecam, 0xff, FAKE_BYTES);
    put32(regs + 0x08, 0x00010400u);                                /* NVMe VS 1.4.0 */
    uint8_t *c;
    memset(c = cfgp(ecam, 0, 0, 0), 0, 4096); mkfn(c, 0x1b36, 0x0008, 0x060000, 0);
    memset(c = cfgp(ecam, 0, 2, 0), 0, 4096); mkfn(c, 0x1b36, 0x0010, 0x010802, 0);
    uint64_t a = (uint64_t)(uintptr_t)regs;
    put32(c + 0x10, (uint32_t)a | 4u);                              /* 64-bit memory BAR0 */
    put32(c + 0x14, (uint32_t)(a >> 32));
    uint8_t t[44 + 16];
    uint64_t b[1] = {(uint64_t)(uintptr_t)ecam};
    uint16_t s[1] = {0};
    uint8_t sb[1] = {0}, eb[1] = {1};
    mk_mcfg(t, 1, b, s, sb, eb);
    ck_host_mcfg = t;
    ck_host_try_map_ok = 1;
    ck_host_try_map_fail = 0;
    ck_host_capture_start();
    CHECK(pci_stage_discover_report() == PCI_OK);
    CHECK(ck_mmio_stage_report() == CK_MMIO_OK);
    ck_host_capture_stop();
    const char *x = ck_host_capture_text();
    CHECK(has(x, "mmio_win: 0000:00:02.0 bar0 addr=0x"));
    CHECK(has(x, "size=0x1000 create=0 read(VS)=0 value=0x10400 past-end=-504 revoke=0 after-revoke=-2 (read-only, report-only)\n"));
    /* Map refused: reported, nothing bound. */
    ck_host_try_map_ok = 0;
    ck_host_capture_start();
    CHECK(ck_mmio_stage_report() == CK_MMIO_E_BAR);
    ck_host_capture_stop();
    CHECK(has(ck_host_capture_text(), "BAR0 map refused (report-only)\n"));
    /* No NVMe discovered (the NVMe has BAR0 0). */
    put32(c + 0x10, 0);
    put32(c + 0x14, 0);
    ck_host_try_map_ok = 1;
    ck_host_capture_start();
    CHECK(pci_stage_discover_report() == PCI_OK);
    CHECK(ck_mmio_stage_report() == CK_MMIO_E_BAR);
    ck_host_capture_stop();
    CHECK(has(ck_host_capture_text(), "mmio_win: no discovered NVMe function with a firmware-assigned BAR0 (report-only)\n"));
    ck_host_mcfg = NULL;
    ck_host_try_map_ok = 0;
    munmap(regs, WIN_BYTES);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("ck stage host tests (host logic only; qualifies nothing physical)\n");
    test_mcfg();
    test_pci_bars();
    test_pci_enum();
    test_mcfg_all();
    test_discover_seg15();
    test_discover_trap();
    test_discover_edges();
    test_discover_report();
    test_discover_in_stage();
    test_mmio_window();
    test_mmio_stage_report();
    test_store();
    test_artifact_store();
    test_security();
    test_nvme_shutdown();
    test_net_udp();
    test_xhci_fence();
    test_usb_hid();
    printf("CK_STAGE_HOST: %s checks=%d failures=%d\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
