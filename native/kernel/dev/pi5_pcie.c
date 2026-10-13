/* pi5_pcie.c -- see pi5_pcie.h. The decision and parsing logic is hosted-testable
 * (tests/test_pi5_pcie.c); the MMIO glue at the bottom is the CK_PI5_PCIE image only. */
#include "pi5_pcie.h"

/* TEST-only mutants (make pi5-pcie-mutants): each removes one decision and
 * must make test_pi5_pcie FAIL. Host builds only; never part of an image. */
#if defined(CK_PCIE_MUTANT_NO_OUTSIDE) || defined(CK_PCIE_MUTANT_NO_FULLCOVER) || \
    defined(CK_PCIE_MUTANT_NO_REMAP) || defined(CK_PCIE_MUTANT_NO_INDEX) || defined(CK_PCIE_MUTANT_NO_ALIGN) || \
    defined(CK_PCIE_MUTANT_NO_MERGE)
#if !__STDC_HOSTED__
#error "CK_PCIE_MUTANT_* are host test mutants only"
#endif
#endif

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int ck_pi5pcie_cfg_read32(const struct ck_pi5pcie_io *io, uint8_t bus, uint8_t dev, uint8_t fn, uint32_t reg,
                          uint32_t *out)
{
    if (!io || !io->rd || !io->wr || !out)
        return CK_PI5PCIE_E_ARG;
    if (reg >= 4096u || (reg & 3u) != 0 || fn > 7u)
        return CK_PI5PCIE_E_ADDR;
    if (bus == 0) { /* the root port only (PciSegmentLib.c:96-98) */
        if (dev != 0 || fn != 0)
            return CK_PI5PCIE_E_ADDR;
        *out = io->rd(io->ctx, reg);
        return CK_PI5PCIE_OK;
    }
    if (bus != 1 || dev != 0) /* one device on bus 1 (PciSegmentLib.c:101-104) */
        return CK_PI5PCIE_E_ADDR;
#ifndef CK_PCIE_MUTANT_NO_INDEX
    io->wr(io->ctx, CK_PI5PCIE_EXT_CFG_INDEX, ((uint32_t)bus << 20) | ((uint32_t)dev << 15) | ((uint32_t)fn << 12));
#endif
    *out = io->rd(io->ctx, CK_PI5PCIE_EXT_CFG_DATA + reg);
    return CK_PI5PCIE_OK;
}

int ck_pi5pcie_read_func(const struct ck_pi5pcie_io *io, uint8_t bus, uint8_t dev, uint8_t fn,
                         struct ck_pi5pcie_func *f)
{
    uint32_t v, i;
    int rc;
    if (!f)
        return CK_PI5PCIE_E_ARG;
    *f = (struct ck_pi5pcie_func){0};
    f->bus = bus;
    f->dev = dev;
    f->fn = fn;
    rc = ck_pi5pcie_cfg_read32(io, bus, dev, fn, 0, &v);
    if (rc)
        return rc;
    f->vendor = (uint16_t)(v & 0xffffu);
    f->device = (uint16_t)(v >> 16);
    if (f->vendor == 0xffffu || f->vendor == 0)
        return 1;
    if (ck_pi5pcie_cfg_read32(io, bus, dev, fn, 4, &v))
        return CK_PI5PCIE_E_ADDR;
    f->command = (uint16_t)(v & 0xffffu);
    if (ck_pi5pcie_cfg_read32(io, bus, dev, fn, 8, &v))
        return CK_PI5PCIE_E_ADDR;
    f->class_code = v >> 8;
    f->revision = (uint8_t)(v & 0xffu);
    if (ck_pi5pcie_cfg_read32(io, bus, dev, fn, 0xc, &v))
        return CK_PI5PCIE_E_ADDR;
    f->header_type = (uint8_t)((v >> 16) & 0x7fu);
    f->nbars = f->header_type == 0 ? 6 : f->header_type == 1 ? 2 : 0;
    for (i = 0; i < f->nbars; i++)
        if (ck_pi5pcie_cfg_read32(io, bus, dev, fn, 0x10 + 4 * i, &f->bar_raw[i]))
            return CK_PI5PCIE_E_ADDR;
    if (f->header_type == 1 && !ck_pi5pcie_cfg_read32(io, bus, dev, fn, 0x18, &v)) {
        f->primary = (uint8_t)(v & 0xffu);
        f->secondary = (uint8_t)((v >> 8) & 0xffu);
        f->subordinate = (uint8_t)((v >> 16) & 0xffu);
    }
    return 0;
}

int ck_pi5pcie_rp1_check(int read_rc, const struct ck_pi5pcie_func *f)
{
    if (read_rc != 0 || !f)
        return CK_PI5PCIE_RP1_ABSENT;
    if (f->vendor != CK_PI5PCIE_RP1_VENDOR || f->device != CK_PI5PCIE_RP1_DEVICE)
        return CK_PI5PCIE_RP1_MISMATCH;
    return CK_PI5PCIE_RP1_OK;
}

uint32_t ck_pi5pcie_bar_decode(const uint32_t *raw, uint32_t idx, uint32_t nbars, struct ck_pi5pcie_bar *b)
{
    uint32_t r;
    b->kind = CK_PI5PCIE_BAR_BAD;
    b->prefetch = 0;
    b->addr = 0;
    if (!raw || idx >= nbars)
        return 1;
    r = raw[idx];
    if (r == 0) {
        b->kind = CK_PI5PCIE_BAR_EMPTY;
        return 1;
    }
    if (r & 1u) {
        b->kind = CK_PI5PCIE_BAR_IO;
        b->addr = r & ~3u;
        return 1;
    }
    b->prefetch = (uint8_t)((r >> 3) & 1u);
    switch ((r >> 1) & 3u) {
    case 0:
        b->kind = CK_PI5PCIE_BAR_MEM32;
        b->addr = r & ~0xfu;
        return 1;
    case 2:
        if (idx + 1 >= nbars)
            return 1; /* a 64-bit BAR needs its upper half: BAD */
        b->kind = CK_PI5PCIE_BAR_MEM64;
        b->addr = (uint64_t)(r & ~0xfu) | ((uint64_t)raw[idx + 1] << 32);
        return 2;
    default:
        return 1; /* 1 = below-1MiB legacy, 3 = reserved */
    }
}

int ck_pi5pcie_ib_size_decode(uint32_t code, uint64_t *size)
{
    if (code == 0)
        return 0;
    if (code >= 1 && code <= 21) {
        *size = 1ull << (code + 15);
        return 1;
    }
    if (code >= 0x1c && code <= 0x1f) {
        *size = 1ull << (code - 0x1c + 12);
        return 1;
    }
    return -1;
}

/* Register offsets: Bcm2712Pcie.h:161-185 (PCIE_IB_WIN_LO/HI, PCIE_IB_WIN_REMAP_LO/HI). */
static uint32_t ib_lo(uint32_t i) { return i == 0 ? 0x4034u : 0x40d4u + (i - 1) * 8u; }
static uint32_t ib_remap_lo(uint32_t i) { return i == 0 ? 0x40b4u : 0x410cu + (i - 1) * 8u; }

int ck_pi5pcie_ib_read(const struct ck_pi5pcie_io *io, uint32_t idx, struct ck_pi5pcie_ibwin *w)
{
    uint32_t lo, hi, rlo, rhi;
    uint64_t size = 0;
    int sd;
    if (!io || !io->rd || !w || idx >= CK_PI5PCIE_IB_WINDOWS)
        return CK_PI5PCIE_E_ARG;
    *w = (struct ck_pi5pcie_ibwin){0};
    w->idx = idx;
    lo = io->rd(io->ctx, ib_lo(idx));
    hi = io->rd(io->ctx, ib_lo(idx) + 4);
    rlo = io->rd(io->ctx, ib_remap_lo(idx));
    rhi = io->rd(io->ctx, ib_remap_lo(idx) + 4);
    sd = ck_pi5pcie_ib_size_decode(lo & CK_PI5PCIE_BAR_SIZE_MASK, &size);
    w->enabled = sd != 0;
    w->bus_base = ((uint64_t)hi << 32) | (lo & ~CK_PI5PCIE_BAR_SIZE_MASK);
    w->remap_en = (uint8_t)(rlo & 1u);
    w->cpu_base = (uint64_t)(rlo & 0xfffff000u) | ((uint64_t)(rhi & 0xffu) << 32);
    if (sd > 0) {
        w->size = size;
        w->size_valid = 1;
#ifndef CK_PCIE_MUTANT_NO_ALIGN
        if ((w->bus_base & (size - 1)) != 0)
            w->size_valid = 0; /* base not aligned to size: not a window the model understands */
#endif
    }
    return 0;
}

struct iv {
    uint64_t s, e; /* [s, e) */
};

int ck_pi5pcie_ib_verdict(const struct ck_pi5pcie_ibwin *w, uint32_t n, uint32_t unmodelled, uint64_t b_cpu,
                          uint64_t b_size, struct ck_pi5pcie_dmav *out)
{
    struct iv v[CK_PI5PCIE_IB_WINDOWS];
    uint32_t cnt = 0, i, j;
    uint64_t b_end, reach = 0, inside = 0;
    if (!out)
        return CK_PI5PCIE_E_ARG;
    *out = (struct ck_pi5pcie_dmav){0};
    out->verdict = CK_PI5PCIE_DMA_UNKNOWN;
    if ((n && !w) || n > CK_PI5PCIE_IB_WINDOWS || b_size == 0 || b_cpu > UINT64_MAX - b_size)
        return CK_PI5PCIE_E_ARG;
    b_end = b_cpu + b_size;
    for (i = 0; i < n; i++) {
        if (!w[i].enabled)
            continue;
        out->windows++;
        if (!w[i].size_valid)
            return 0; /* UNKNOWN */
#ifndef CK_PCIE_MUTANT_NO_REMAP
        if (!w[i].remap_en)
            return 0; /* where the window lands in memory is not known: UNKNOWN */
#endif
        if (w[i].cpu_base > UINT64_MAX - w[i].size)
            return 0;
        v[cnt].s = w[i].cpu_base;
        v[cnt].e = w[i].cpu_base + w[i].size;
        cnt++;
    }
    if (cnt == 0) {
        out->verdict = CK_PI5PCIE_DMA_NO_WINDOW;
        return 0;
    }
    for (i = 1; i < cnt; i++) { /* insertion sort by start */
        struct iv t = v[i];
        for (j = i; j > 0 && v[j - 1].s > t.s; j--)
            v[j] = v[j - 1];
        v[j] = t;
    }
#ifndef CK_PCIE_MUTANT_NO_MERGE
    for (i = 0, j = 0; i < cnt; i++) { /* union: overlapping or touching ranges merge */
        if (j > 0 && v[i].s <= v[j - 1].e) {
            if (v[i].e > v[j - 1].e)
                v[j - 1].e = v[i].e;
        } else {
            v[j++] = v[i];
        }
    }
    cnt = j;
#endif
    for (i = 0; i < cnt; i++) {
        uint64_t lo = v[i].s > b_cpu ? v[i].s : b_cpu;
        uint64_t hi = v[i].e < b_end ? v[i].e : b_end;
        reach += v[i].e - v[i].s;
        if (hi > lo)
            inside += hi - lo;
    }
    out->reach_bytes = reach;
    out->inside_bytes = inside;
    out->outside_bytes = reach - inside;
    if (inside == 0) {
        out->verdict = CK_PI5PCIE_DMA_MISS;
        return 0;
    }
#ifndef CK_PCIE_MUTANT_NO_FULLCOVER
    if (inside < b_size) {
        out->verdict = CK_PI5PCIE_DMA_PARTIAL;
        return 0;
    }
#endif
#ifndef CK_PCIE_MUTANT_NO_OUTSIDE
    if (out->outside_bytes != 0) {
        out->verdict = CK_PI5PCIE_DMA_WIDER;
        return 0;
    }
#endif
    out->verdict = unmodelled ? CK_PI5PCIE_DMA_UNKNOWN : CK_PI5PCIE_DMA_CONFINED;
    return 0;
}

const char *ck_pi5pcie_verdict_name(int v)
{
    switch (v) {
    case CK_PI5PCIE_DMA_NO_WINDOW: return "NO_WINDOW";
    case CK_PI5PCIE_DMA_MISS: return "MISS";
    case CK_PI5PCIE_DMA_PARTIAL: return "PARTIAL_COVER";
    case CK_PI5PCIE_DMA_WIDER: return "NOT_CONFINED";
    case CK_PI5PCIE_DMA_CONFINED: return "CONFINED";
    default: return "UNKNOWN";
    }
}

void ck_pi5pcie_door_decide(const uint8_t *t, size_t len, uint16_t segment, uint64_t rc_phys,
                            struct ck_pi5pcie_door *out)
{
    size_t off;
    out->why = CK_PI5PCIE_WHY_NO_MCFG;
    out->base = 0;
    out->bus_min = out->bus_max = 0;
    if (!t)
        return;
    out->why = CK_PI5PCIE_WHY_MALFORMED;
    if (len < 44u + 16u || t[0] != 'M' || t[1] != 'C' || t[2] != 'F' || t[3] != 'G' || le32(t + 4) != len ||
        (len - 44u) % 16u != 0)
        return;
    out->why = CK_PI5PCIE_WHY_NO_SEGMENT;
    for (off = 44; off + 16u <= len; off += 16u) {
        const uint8_t *e = t + off;
        uint64_t base = (uint64_t)le32(e) | ((uint64_t)le32(e + 4) << 32);
        if ((uint16_t)(e[8] | (e[9] << 8)) != segment)
            continue;
        out->base = base;
        out->bus_min = e[10];
        out->bus_max = e[11];
        if (base == rc_phys + CK_PI5PCIE_EXT_CFG_DATA)
            out->why = CK_PI5PCIE_WHY_DATA_WINDOW;
        else if (e[11] < 1 || e[10] > 1)
            out->why = CK_PI5PCIE_WHY_NARROW;
        else
            out->why = CK_PI5PCIE_WHY_ECAM_CANDIDATE;
        return;
    }
}

const char *ck_pi5pcie_why_name(int why)
{
    switch (why) {
    case CK_PI5PCIE_WHY_NO_MCFG: return "no_mcfg";
    case CK_PI5PCIE_WHY_MALFORMED: return "mcfg_malformed";
    case CK_PI5PCIE_WHY_NO_SEGMENT: return "no_segment_2_entry";
    case CK_PI5PCIE_WHY_DATA_WINDOW: return "entry_is_the_4k_data_window";
    case CK_PI5PCIE_WHY_NARROW: return "entry_bus_range_excludes_bus_1";
    case CK_PI5PCIE_WHY_ECAM_CANDIDATE: return "ecam_candidate_unverified_not_used";
    default: return "?";
    }
}

#ifdef CK_PI5_PCIE
#include "ck.h"
#include "dma_window.h"

static volatile uint8_t *rc;

static uint32_t mm_rd(void *c, uint32_t off) { (void)c; return *(volatile uint32_t *)(rc + off); }
static void mm_wr(void *c, uint32_t off, uint32_t v) { (void)c; *(volatile uint32_t *)(rc + off) = v; }

static void print_bar(const struct ck_pi5pcie_func *f, uint32_t i, struct ck_pi5pcie_bar *b)
{
    static const char *const k[] = {"empty", "mem32", "mem64", "io", "bad"};
    ck_printf("pi5_pcie: rp1 bar%u raw=0x%08x kind=%s%s addr=0x%llx size=unsized (read-only)\n", i, f->bar_raw[i],
              k[b->kind], b->prefetch ? " prefetch" : "", (unsigned long long)b->addr);
}

void ck_pi5pcie_report(void)
{
    static const struct ck_pi5pcie_io io = {mm_rd, mm_wr, 0};
    struct ck_pi5pcie_func root, rp1;
    struct ck_pi5pcie_door door;
    struct ck_pi5pcie_ibwin win[CK_PI5PCIE_IB_WINDOWS];
    struct ck_pi5pcie_dmav dv;
    struct ck_dmaw dw;
    int rrc, rrp1, ver, n_en = 0;
    uint32_t i, unmodelled = 0, idx_before;
    uint64_t b_phys = 0;
    void *bounce;
    const uint8_t *mcfg = (const uint8_t *)ck_acpi_find("MCFG");

    ck_printf("pi5_pcie: PCIe2 root complex 0x%llx (RP1 host), software-only DMA confinement (Pi 5, weaker than the Spark)\n",
              (unsigned long long)CK_PI5PCIE_RC2_PHYS);
    ck_pi5pcie_door_decide(mcfg, mcfg ? (size_t)le32(mcfg + 4) : 0, CK_PI5PCIE_SEGMENT, CK_PI5PCIE_RC2_PHYS, &door);
    ck_printf("pi5_pcie: door=rc_window (index 0x%x, data 0x%x); ecam not used: %s mcfg_seg2_base=0x%llx bus=%u-%u\n",
              CK_PI5PCIE_EXT_CFG_INDEX, CK_PI5PCIE_EXT_CFG_DATA, ck_pi5pcie_why_name(door.why),
              (unsigned long long)door.base, door.bus_min, door.bus_max);
    rc = (volatile uint8_t *)ck_mmio_try_map(CK_PI5PCIE_RC2_PHYS, CK_PI5PCIE_RC_BYTES);
    if (!rc) {
        ck_printf("pi5_pcie: FAIL map 0x%llx (refused); nothing read\n", (unsigned long long)CK_PI5PCIE_RC2_PHYS);
        return;
    }
    idx_before = mm_rd(0, CK_PI5PCIE_EXT_CFG_INDEX);
    rrc = ck_pi5pcie_read_func(&io, 0, 0, 0, &root);
    if (rrc == 0)
        ck_printf("pi5_pcie: root 00:00.0 %04x:%04x class=%06x rev=%02x type=%u sec=%u sub=%u cmd=0x%04x\n", root.vendor,
                  root.device, root.class_code, root.revision, root.header_type, root.secondary, root.subordinate,
                  root.command);
    else
        ck_printf("pi5_pcie: root 00:00.0 read rc=%d\n", rrc);
    rrp1 = ck_pi5pcie_read_func(&io, 1, 0, 0, &rp1);
    ver = ck_pi5pcie_rp1_check(rrp1, &rp1);
    ck_printf("pi5_pcie: index_before=0x%08x index_now=0x%08x (selected 01:00.0)\n", idx_before,
              mm_rd(0, CK_PI5PCIE_EXT_CFG_INDEX));
    if (ver == CK_PI5PCIE_RP1_ABSENT)
        ck_printf("pi5_pcie: rp1 01:00.0 ABSENT (read rc=%d vendor=%04x)\n", rrp1, rp1.vendor);
    else {
        ck_printf("pi5_pcie: rp1 01:00.0 %04x:%04x %s (expected %04x:%04x) class=%06x rev=%02x type=%u cmd=0x%04x\n",
                  rp1.vendor, rp1.device, ver == CK_PI5PCIE_RP1_OK ? "MATCH" : "MISMATCH", CK_PI5PCIE_RP1_VENDOR,
                  CK_PI5PCIE_RP1_DEVICE, rp1.class_code, rp1.revision, rp1.header_type, rp1.command);
        for (i = 0; i < rp1.nbars;) {
            struct ck_pi5pcie_bar b;
            uint32_t used = ck_pi5pcie_bar_decode(rp1.bar_raw, i, rp1.nbars, &b);
            print_bar(&rp1, i, &b);
            i += used;
        }
    }
    for (i = 0; i < CK_PI5PCIE_IB_WINDOWS; i++) {
        if (ck_pi5pcie_ib_read(&io, i, &win[i]))
            continue;
        if (win[i].enabled) {
            n_en++;
            ck_printf("pi5_pcie: inbound win%u bus=0x%llx size=0x%llx cpu=0x%llx remap=%u valid=%u\n", i,
                      (unsigned long long)win[i].bus_base, (unsigned long long)win[i].size,
                      (unsigned long long)win[i].cpu_base, win[i].remap_en, win[i].size_valid);
        }
    }
    if (mm_rd(0, CK_PI5PCIE_RC_BAR1_LO) & CK_PI5PCIE_BAR_SIZE_MASK)
        unmodelled++;
    if (mm_rd(0, CK_PI5PCIE_RC_BAR3_LO) & CK_PI5PCIE_BAR_SIZE_MASK)
        unmodelled++;
    ck_printf("pi5_pcie: inbound enabled=%d other_bar_windows=%u (gisb/scb; 0 = disabled)\n", n_en, unmodelled);
    bounce = ck_dma_alloc(CK_DMAW_MAX_BYTES, CK_DMAW_MAX_BYTES, &b_phys);
    if (!bounce || ck_dmaw_init(&dw, bounce, b_phys, CK_DMAW_MAX_BYTES) != CK_DMAW_OK) {
        ck_printf("pi5_dma: FAIL no bounce window (alloc/init); verdict not computed\n");
        return;
    }
    ck_pi5pcie_ib_verdict(win, CK_PI5PCIE_IB_WINDOWS, unmodelled, b_phys, CK_DMAW_MAX_BYTES, &dv);
    ck_printf("pi5_dma: bounce cpu=0x%llx size=0x%llx (ADR 0020 rule 1, zeroed, bus==cpu per ck_dma_alloc)\n",
              (unsigned long long)b_phys, (unsigned long long)dw.size);
    ck_printf("pi5_dma: hw_window=%s reach=0x%llx inside=0x%llx outside=0x%llx\n", ck_pi5pcie_verdict_name(dv.verdict),
              (unsigned long long)dv.reach_bytes, (unsigned long long)dv.inside_bytes,
              (unsigned long long)dv.outside_bytes);
    if (dv.verdict == CK_PI5PCIE_DMA_CONFINED)
        ck_printf("pi5_dma: hardware window confines DMA to the bounce region\n");
    else
        ck_printf("pi5_dma: hardware window does NOT confine DMA to the bounce region (%s): software checks only\n",
                  ck_pi5pcie_verdict_name(dv.verdict));
}
#endif
