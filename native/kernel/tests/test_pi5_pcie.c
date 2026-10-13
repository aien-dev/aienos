/* test_pi5_pcie.c -- Pi 5 PCIe root complex access, RP1 enumerator and inbound
 * window verdict (dev/pi5_pcie.c) over a FAKE register file. Hosted: this
 * proves the decisions, NOT the hardware. Run under ASan/UBSan and with each
 * CK_PCIE_MUTANT_* (make pi5-pcie-mutants); every mutant must make it FAIL. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "pi5_pcie.h"

#define MiB (1ull << 20)
#define GiB (1ull << 30)

/* The fake root complex: one register page, a root-port config space at the
 * base, and a 4 KiB data window that shows RP1 only while INDEX selects 01:00.0. */
struct fake {
    uint32_t regs[0xa000 / 4];
    uint32_t rp1[1024];
    uint32_t reads, writes, last_write_off, last_write_val;
};

static uint32_t f_rd(void *c, uint32_t off)
{
    struct fake *f = c;
    f->reads++;
    if (off >= 0x8000 && off < 0x9000) {
        if (f->regs[0x9000 / 4] == 0x00100000u)
            return f->rp1[(off - 0x8000) / 4];
        return 0xffffffffu; /* nothing at the selected function */
    }
    return f->regs[off / 4];
}

static void f_wr(void *c, uint32_t off, uint32_t v)
{
    struct fake *f = c;
    f->writes++;
    f->last_write_off = off;
    f->last_write_val = v;
    f->regs[off / 4] = v;
}

static struct fake fk;
static struct ck_pi5pcie_io io = {f_rd, f_wr, &fk};

static void fresh(void)
{
    memset(&fk, 0, sizeof fk);
    fk.regs[0] = 0x271214e4u;     /* root port: vendor 14e4 device 2712 */
    fk.regs[1] = 0x00100006u;
    fk.regs[2] = 0x06040001u;     /* class 060400 rev 01 */
    fk.regs[3] = 0x00010000u;     /* header type 1 */
    fk.regs[6] = 0x00010100u;     /* primary 0, secondary 1, subordinate 1 */
    fk.rp1[0] = 0x00011de4u;      /* vendor 1de4 device 0001 */
    fk.rp1[1] = 0x00000000u;
    fk.rp1[2] = 0x02000000u | 0x1u; /* class 020000 rev 01 */
    fk.rp1[3] = 0x00800000u;      /* header type 0, multifunction bit set */
    fk.rp1[4] = 0;                /* BAR0: empty */
    fk.rp1[5] = 0x1f000000u | 0x4u;          /* BAR1: mem64 */
    fk.rp1[6] = 0x1u;                         /* BAR1 upper = 1 */
}

static void t_cfg_access(void)
{
    uint32_t v = 0;
    fresh();
    CHECK(ck_pi5pcie_cfg_read32(&io, 0, 0, 0, 0, &v) == 0 && v == 0x271214e4u);
    CHECK(fk.writes == 0); /* bus 0 is the RC page: no INDEX write */
    CHECK(ck_pi5pcie_cfg_read32(&io, 1, 0, 0, 0, &v) == 0 && v == 0x00011de4u);
    CHECK(fk.writes == 1 && fk.last_write_off == 0x9000 && fk.last_write_val == 0x00100000u);
    /* fn 1 selects a different function: INDEX is bus<<20 | fn<<12, shows nothing */
    CHECK(ck_pi5pcie_cfg_read32(&io, 1, 0, 1, 0, &v) == 0 && v == 0xffffffffu);
    CHECK(fk.last_write_val == 0x00101000u);
    /* addresses the root complex cannot reach touch nothing */
    fresh();
    CHECK(ck_pi5pcie_cfg_read32(&io, 0, 1, 0, 0, &v) == CK_PI5PCIE_E_ADDR);
    CHECK(ck_pi5pcie_cfg_read32(&io, 0, 0, 1, 0, &v) == CK_PI5PCIE_E_ADDR);
    CHECK(ck_pi5pcie_cfg_read32(&io, 1, 1, 0, 0, &v) == CK_PI5PCIE_E_ADDR);
    CHECK(ck_pi5pcie_cfg_read32(&io, 2, 0, 0, 0, &v) == CK_PI5PCIE_E_ADDR);
    CHECK(ck_pi5pcie_cfg_read32(&io, 1, 0, 8, 0, &v) == CK_PI5PCIE_E_ADDR);
    CHECK(ck_pi5pcie_cfg_read32(&io, 1, 0, 0, 4096, &v) == CK_PI5PCIE_E_ADDR);
    CHECK(ck_pi5pcie_cfg_read32(&io, 1, 0, 0, 2, &v) == CK_PI5PCIE_E_ADDR);
    CHECK(ck_pi5pcie_cfg_read32(&io, 1, 0, 0, 0, NULL) == CK_PI5PCIE_E_ARG);
    CHECK(fk.reads == 0 && fk.writes == 0);
}

static void t_probe_rp1(void)
{
    struct ck_pi5pcie_func root, rp1;
    int rc;
    fresh();
    rc = ck_pi5pcie_read_func(&io, 0, 0, 0, &root);
    CHECK(rc == 0 && root.vendor == 0x14e4 && root.device == 0x2712 && root.class_code == 0x060400 &&
          root.header_type == 1 && root.nbars == 2 && root.primary == 0 && root.secondary == 1 && root.subordinate == 1);
    rc = ck_pi5pcie_read_func(&io, 1, 0, 0, &rp1);
    CHECK(rc == 0 && rp1.vendor == 0x1de4 && rp1.device == 0x0001 && rp1.class_code == 0x020000 && rp1.revision == 1);
    CHECK(rp1.header_type == 0 && rp1.nbars == 6); /* multifunction bit masked out of the type */
    CHECK(ck_pi5pcie_rp1_check(rc, &rp1) == CK_PI5PCIE_RP1_OK);
    /* wrong ID */
    fk.rp1[0] = 0x00011de5u;
    rc = ck_pi5pcie_read_func(&io, 1, 0, 0, &rp1);
    CHECK(ck_pi5pcie_rp1_check(rc, &rp1) == CK_PI5PCIE_RP1_MISMATCH);
    fk.rp1[0] = 0x00021de4u;
    rc = ck_pi5pcie_read_func(&io, 1, 0, 0, &rp1);
    CHECK(ck_pi5pcie_rp1_check(rc, &rp1) == CK_PI5PCIE_RP1_MISMATCH);
    /* absent: all ones, then vendor 0 */
    fk.rp1[0] = 0xffffffffu;
    rc = ck_pi5pcie_read_func(&io, 1, 0, 0, &rp1);
    CHECK(rc == 1 && ck_pi5pcie_rp1_check(rc, &rp1) == CK_PI5PCIE_RP1_ABSENT);
    fk.rp1[0] = 0;
    rc = ck_pi5pcie_read_func(&io, 1, 0, 0, &rp1);
    CHECK(rc == 1 && ck_pi5pcie_rp1_check(rc, &rp1) == CK_PI5PCIE_RP1_ABSENT);
    /* an address error is also "absent", never a match */
    rc = ck_pi5pcie_read_func(&io, 3, 0, 0, &rp1);
    CHECK(rc == CK_PI5PCIE_E_ADDR && ck_pi5pcie_rp1_check(rc, &rp1) == CK_PI5PCIE_RP1_ABSENT);
}

static void t_probe_needs_index(void)
{
    /* If INDEX points elsewhere first (firmware left it at another function),
     * the probe must still land on 01:00.0 by writing INDEX itself. */
    struct ck_pi5pcie_func rp1;
    fresh();
    fk.regs[0x9000 / 4] = 0x00000000u;
    CHECK(ck_pi5pcie_read_func(&io, 1, 0, 0, &rp1) == 0 && rp1.vendor == 0x1de4);
}

static void t_bar(void)
{
    struct ck_pi5pcie_bar b;
    uint32_t raw[6];
    memset(raw, 0, sizeof raw);
    CHECK(ck_pi5pcie_bar_decode(raw, 0, 6, &b) == 1 && b.kind == CK_PI5PCIE_BAR_EMPTY);
    raw[0] = 0xe0000008u; /* mem32 prefetch */
    CHECK(ck_pi5pcie_bar_decode(raw, 0, 6, &b) == 1 && b.kind == CK_PI5PCIE_BAR_MEM32 && b.prefetch && b.addr == 0xe0000000u);
    raw[1] = 0x1f000000u | 0x4u; /* mem64, upper in raw[2] */
    raw[2] = 0x1u;
    CHECK(ck_pi5pcie_bar_decode(raw, 1, 6, &b) == 2 && b.kind == CK_PI5PCIE_BAR_MEM64 && !b.prefetch &&
          b.addr == 0x11f000000ull);
    raw[3] = 0xc001u; /* io */
    CHECK(ck_pi5pcie_bar_decode(raw, 3, 6, &b) == 1 && b.kind == CK_PI5PCIE_BAR_IO && b.addr == 0xc000u);
    raw[4] = 0x2u; /* legacy below-1MiB type: refused */
    CHECK(ck_pi5pcie_bar_decode(raw, 4, 6, &b) == 1 && b.kind == CK_PI5PCIE_BAR_BAD);
    raw[5] = 0x4u | 0x1000u; /* 64-bit at the last register has no upper half */
    CHECK(ck_pi5pcie_bar_decode(raw, 5, 6, &b) == 1 && b.kind == CK_PI5PCIE_BAR_BAD);
    CHECK(ck_pi5pcie_bar_decode(raw, 6, 6, &b) == 1 && b.kind == CK_PI5PCIE_BAR_BAD);
    raw[1] = 0x4u | 0x1000u; /* type-1 header has two BARs: a 64-bit BAR at 1 is BAD */
    CHECK(ck_pi5pcie_bar_decode(raw, 1, 2, &b) == 1 && b.kind == CK_PI5PCIE_BAR_BAD);
}

static void t_ib_size(void)
{
    uint64_t s = 0;
    CHECK(ck_pi5pcie_ib_size_decode(0, &s) == 0);
    CHECK(ck_pi5pcie_ib_size_decode(1, &s) == 1 && s == 64 * 1024);
    CHECK(ck_pi5pcie_ib_size_decode(6, &s) == 1 && s == 2 * MiB);
    CHECK(ck_pi5pcie_ib_size_decode(21, &s) == 1 && s == 64 * GiB);
    CHECK(ck_pi5pcie_ib_size_decode(0x1c, &s) == 1 && s == 4096);
    CHECK(ck_pi5pcie_ib_size_decode(0x1f, &s) == 1 && s == 32768);
    CHECK(ck_pi5pcie_ib_size_decode(22, &s) == -1);
    CHECK(ck_pi5pcie_ib_size_decode(0x1b, &s) == -1);
    CHECK(ck_pi5pcie_ib_size_decode(0x20, &s) == -1);
}

static void t_ib_read(void)
{
    struct ck_pi5pcie_ibwin w;
    /* what the frozen firmware programs: bus 0 -> CPU 0, 64 GiB, remap on */
    fresh();
    fk.regs[0x4034 / 4] = 21;
    fk.regs[0x4038 / 4] = 0;
    fk.regs[0x40b4 / 4] = 1;
    fk.regs[0x40b8 / 4] = 0;
    CHECK(ck_pi5pcie_ib_read(&io, 0, &w) == 0 && w.enabled && w.size_valid && w.remap_en && w.size == 64 * GiB &&
          w.bus_base == 0 && w.cpu_base == 0);
    /* a 2 MiB window at bus 0x40200000 mapped to CPU 0x1_4020_0000 */
    fk.regs[0x40d4 / 4] = 0x40200000u | 6;
    fk.regs[0x40d8 / 4] = 0;
    fk.regs[0x410c / 4] = 0x40200000u | 1;
    fk.regs[0x4110 / 4] = 1;
    CHECK(ck_pi5pcie_ib_read(&io, 1, &w) == 0 && w.enabled && w.size_valid && w.size == 2 * MiB &&
          w.bus_base == 0x40200000u && w.cpu_base == 0x140200000ull);
    /* window 7 lives at its own offsets and does not alias window 6 */
    fk.regs[0x4104 / 4] = 0x80000000u | 16; /* code 16 = 2 GiB */
    fk.regs[0x413c / 4] = 1;
    CHECK(ck_pi5pcie_ib_read(&io, 7, &w) == 0 && w.enabled && w.size == 2 * GiB && w.bus_base == 0x80000000u && w.remap_en);
    CHECK(ck_pi5pcie_ib_read(&io, 6, &w) == 0 && !w.enabled);
    /* disabled, misaligned, bad code, remap off */
    CHECK(ck_pi5pcie_ib_read(&io, 2, &w) == 0 && !w.enabled && !w.size_valid);
    fk.regs[0x40dc / 4] = 0x00010000u | 6; /* 2 MiB window at a 64 KiB aligned base */
    CHECK(ck_pi5pcie_ib_read(&io, 2, &w) == 0 && w.enabled && !w.size_valid);
    fk.regs[0x40e4 / 4] = 22;
    CHECK(ck_pi5pcie_ib_read(&io, 3, &w) == 0 && w.enabled && !w.size_valid);
    CHECK(ck_pi5pcie_ib_read(&io, 8, &w) == CK_PI5PCIE_E_ARG);
}

static struct ck_pi5pcie_ibwin mk(uint64_t bus, uint64_t size, uint64_t cpu, int remap)
{
    struct ck_pi5pcie_ibwin w = {0};
    w.enabled = 1;
    w.size_valid = 1;
    w.remap_en = (uint8_t)remap;
    w.bus_base = bus;
    w.size = size;
    w.cpu_base = cpu;
    return w;
}

#define B 0x4600000ull /* bounce region used below: 2 MiB at 0x4600000 */
#define BS (2 * MiB)

static void t_verdict(void)
{
    struct ck_pi5pcie_ibwin w[8];
    struct ck_pi5pcie_dmav d;
    memset(w, 0, sizeof w);
    /* what the firmware programs today: all of RAM */
    w[0] = mk(0, 64 * GiB, 0, 1);
    CHECK(ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d) == 0);
    CHECK(d.verdict == CK_PI5PCIE_DMA_WIDER && d.reach_bytes == 64 * GiB && d.inside_bytes == BS &&
          d.outside_bytes == 64 * GiB - BS && d.windows == 1);
    /* exactly the bounce block: confined */
    w[0] = mk(B, BS, B, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_CONFINED && d.outside_bytes == 0 && d.inside_bytes == BS);
    /* confined by remap: bus 0 -> CPU B */
    w[0] = mk(0, BS, B, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_CONFINED);
    /* two windows that together are exactly the block, and an overlapping duplicate: still confined */
    w[0] = mk(B, MiB, B, 1);
    w[1] = mk(B + MiB, MiB, B + MiB, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_CONFINED && d.reach_bytes == BS && d.windows == 2);
    w[2] = mk(B, MiB, B, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_CONFINED && d.reach_bytes == BS); /* union, not a sum */
    memset(w, 0, sizeof w);
    /* only half the block reachable: partial, the driver must not use the rest */
    w[0] = mk(B, MiB, B, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_PARTIAL && d.inside_bytes == MiB && d.outside_bytes == 0);
    /* partial cover plus reach elsewhere is still partial (cover is the first problem) */
    w[1] = mk(0, 64 * 1024, 0, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_PARTIAL && d.outside_bytes == 64 * 1024);
    memset(w, 0, sizeof w);
    /* disjoint window: miss */
    w[0] = mk(0x10000000u, 2 * MiB, 0x10000000u, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_MISS);
    /* a window that ends exactly where the block starts does not touch it */
    w[0] = mk(B - BS, BS, B - BS, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_MISS);
    /* no window enabled: DMA cannot reach memory */
    memset(w, 0, sizeof w);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_NO_WINDOW && d.windows == 0);
    /* remap off: where it lands is not known */
    w[0] = mk(B, BS, B, 0);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_UNKNOWN);
    /* invalid window */
    w[0] = mk(B, BS, B, 1);
    w[0].size_valid = 0;
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_UNKNOWN);
    /* an enabled window outside the model (GISB/SCB) cannot be called confined */
    w[0] = mk(B, BS, B, 1);
    ck_pi5pcie_ib_verdict(w, 8, 1, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_UNKNOWN);
    w[0] = mk(0, 64 * GiB, 0, 1);
    ck_pi5pcie_ib_verdict(w, 8, 1, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_WIDER); /* already known to be wider */
    /* wrap: a window whose end passes 2^64 is refused, not folded */
    w[0] = mk(0, 64 * GiB, 0xfffffffff0000000ull, 1);
    ck_pi5pcie_ib_verdict(w, 8, 0, B, BS, &d);
    CHECK(d.verdict == CK_PI5PCIE_DMA_UNKNOWN);
    /* bad arguments */
    CHECK(ck_pi5pcie_ib_verdict(w, 8, 0, B, 0, &d) == CK_PI5PCIE_E_ARG);
    CHECK(ck_pi5pcie_ib_verdict(w, 8, 0, 0xfffffffffff00000ull, 2 * MiB, &d) == CK_PI5PCIE_E_ARG);
    CHECK(ck_pi5pcie_ib_verdict(w, 9, 0, B, BS, &d) == CK_PI5PCIE_E_ARG);
    CHECK(!strcmp(ck_pi5pcie_verdict_name(CK_PI5PCIE_DMA_WIDER), "NOT_CONFINED"));
}

static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

static size_t mcfg(uint8_t *t, int n, const uint64_t *base, const uint16_t *seg, const uint8_t *bmax)
{
    size_t len = 44 + 16u * (size_t)n;
    memset(t, 0, len);
    memcpy(t, "MCFG", 4);
    put32(t + 4, (uint32_t)len);
    for (int i = 0; i < n; i++) {
        uint8_t *e = t + 44 + 16 * i;
        put32(e, (uint32_t)base[i]);
        put32(e + 4, (uint32_t)(base[i] >> 32));
        e[8] = (uint8_t)seg[i];
        e[9] = (uint8_t)(seg[i] >> 8);
        e[10] = 0;
        e[11] = bmax[i];
    }
    return len;
}

static void t_door(void)
{
    uint8_t t[44 + 16 * 3];
    struct ck_pi5pcie_door d;
    /* exactly what Mcfg.aslc:26-48 declares for the three controllers */
    uint64_t base[3] = {0x1000100000ull + 0x8000, 0x1000110000ull + 0x8000, 0x1000120000ull + 0x8000};
    uint16_t seg[3] = {0, 1, 2};
    uint8_t bmax[3] = {0, 0, 0};
    size_t len = mcfg(t, 3, base, seg, bmax);
    ck_pi5pcie_door_decide(NULL, 0, 2, 0x1000120000ull, &d);
    CHECK(d.why == CK_PI5PCIE_WHY_NO_MCFG);
    ck_pi5pcie_door_decide(t, len, 2, 0x1000120000ull, &d);
    CHECK(d.why == CK_PI5PCIE_WHY_DATA_WINDOW && d.base == 0x1000128000ull && d.bus_max == 0);
    ck_pi5pcie_door_decide(t, len, 7, 0x1000120000ull, &d);
    CHECK(d.why == CK_PI5PCIE_WHY_NO_SEGMENT);
    ck_pi5pcie_door_decide(t, len - 1, 2, 0x1000120000ull, &d);
    CHECK(d.why == CK_PI5PCIE_WHY_MALFORMED);
    t[0] = 0; /* hidden: signature zeroed, as the default firmware mode does */
    ck_pi5pcie_door_decide(t, len, 2, 0x1000120000ull, &d);
    CHECK(d.why == CK_PI5PCIE_WHY_MALFORMED);
    t[0] = 'M';
    /* a narrow bus range that is not the data window */
    base[2] = 0x2000000000ull;
    len = mcfg(t, 3, base, seg, bmax);
    ck_pi5pcie_door_decide(t, len, 2, 0x1000120000ull, &d);
    CHECK(d.why == CK_PI5PCIE_WHY_NARROW);
    /* a real-looking ECAM: still reported as a candidate, never silently chosen */
    bmax[2] = 1;
    len = mcfg(t, 3, base, seg, bmax);
    ck_pi5pcie_door_decide(t, len, 2, 0x1000120000ull, &d);
    CHECK(d.why == CK_PI5PCIE_WHY_ECAM_CANDIDATE && d.base == 0x2000000000ull);
    CHECK(strcmp(ck_pi5pcie_why_name(d.why), "?") != 0);
}

int main(void)
{
    t_cfg_access();
    t_probe_rp1();
    t_probe_needs_index();
    t_bar();
    t_ib_size();
    t_ib_read();
    t_verdict();
    t_door();
    return ck_t_verdict("test_pi5_pcie");
}
