/* smmu_svc.c -- the ck.h DMA isolation services (ck_dma_confine and
 * friends) over core/smmu.c, the IORT parser and the DMA pool. Kernel only
 * (the host tests drive core/smmu.c directly against a model SMMU).
 *
 * Memory: stream table (two-level when the SMMU supports it: an L1 table of
 * at most 128 KiB plus one 4 KiB L2 page per granted span; else linear, 4096
 * STEs, 256 KiB), command and event queues, the
 * context descriptors and every stage-1 table come from ck_dma_alloc, which
 * is Normal Non-cacheable, so a dsb orders them before register writes. */
#include "ck_internal.h"
#include "pt.h"
#include "smmu.h"

#define STE_N 4096u /* stream ids 0..4095: PCI buses 0..15 (QEMU virt uses bus 0) */
#define QUEUE_N 16u
/* Window leaf: Normal Non-cacheable (same as the CPU's DMA pool mapping),
 * read/write, AP[1] = 1 so unprivileged device transactions are allowed
 * (PCIe requests are usually unprivileged), never executable. */
#define WINDOW_ATTRS (CK_PT_NORMAL_NC | (1ull << 6))

static struct {
    int state; /* 0 not tried, 1 up, CK_SMMU_ABSENT / CK_SMMU_FAILED */
    uint64_t base;
    struct ck_iort_smmu iort;
    struct ck_smmu_tables t;
    uint64_t *cds; /* CK_DMA_MAX_STREAMS context descriptors, one page */
    uint32_t sid[CK_DMA_MAX_STREAMS];
    int used[CK_DMA_MAX_STREAMS];
} g;

static uint32_t r_rd32(void *ctx, uint32_t off)
{
    (void)ctx;
    return *(volatile uint32_t *)(uintptr_t)(g.base + off);
}
static void r_wr32(void *ctx, uint32_t off, uint32_t v)
{
    (void)ctx;
    *(volatile uint32_t *)(uintptr_t)(g.base + off) = v;
}
static void r_wr64(void *ctx, uint32_t off, uint64_t v)
{
    (void)ctx;
    *(volatile uint64_t *)(uintptr_t)(g.base + off) = v;
}
static void r_bar(void *ctx)
{
    (void)ctx;
    ck_mb();
}
static const struct ck_smmu_regs regs = { 0, r_rd32, r_wr32, r_wr64, r_bar };

static int pt_alloc(void *ctx, uint64_t *phys)
{
    (void)ctx;
    return ck_dma_alloc(4096, 4096, phys) ? 0 : -1;
}

static int l2_alloc(void *ctx, uint64_t **page)
{
    (void)ctx;
    uint64_t p;
    *page = ck_dma_alloc(CK_SMMU_L2_BYTES, CK_SMMU_L2_BYTES, &p);
    return *page ? 0 : -1;
}

/* Stream table format: two-level when the SMMU supports it
 * (IDR0.ST_LEVEL == 0b01), sized to MIN(IDR1.SIDSIZE, CK_SMMU_L2_MAX_BITS)
 * StreamID bits, so the DGX Spark's PCI streams (up to 0xfffff, MEASURED
 * from its IORT) fit; L2 spans are allocated per grant. Otherwise the
 * linear table of STE_N entries. 0 ok, -1 allocation failed. */
static int alloc_strtab(void)
{
    uint64_t p;
    uint32_t idr0 = r_rd32(0, CK_SMMU_IDR0), sidsize = r_rd32(0, CK_SMMU_IDR1) & CK_SMMU_IDR1_SIDSIZE_MASK;
    if (((idr0 >> CK_SMMU_IDR0_ST_LEVEL_SHIFT) & CK_SMMU_IDR0_ST_LEVEL_MASK) == 1u && sidsize >= CK_SMMU_L2_MIN_BITS) {
        uint32_t bits = sidsize < CK_SMMU_L2_MAX_BITS ? sidsize : CK_SMMU_L2_MAX_BITS;
        uint32_t l1_bytes = (1u << (bits - CK_SMMU_SPLIT)) * 8u;
        if (l1_bytes < 64u)
            l1_bytes = 64u;
        g.t.sid_bits = bits;
        g.t.l2_alloc = l2_alloc;
        g.t.l1 = ck_dma_alloc(l1_bytes, l1_bytes, &p);
        ck_printf("smmu: stream table 2-level log2size=%u split=%u (spans allocated per grant)\n", bits,
                  CK_SMMU_SPLIT);
        return g.t.l1 ? 0 : -1;
    }
    g.t.ste_n = STE_N;
    g.t.strtab = ck_dma_alloc(STE_N * CK_SMMU_STE_BYTES, STE_N * CK_SMMU_STE_BYTES, &p);
    ck_printf("smmu: stream table linear entries=%u\n", STE_N);
    return g.t.strtab ? 0 : -1;
}

static int bring_up(void)
{
    if (g.state)
        return g.state == 1 ? 0 : g.state;
    g.state = CK_SMMU_ABSENT;
    const void *iort = ck_acpi_find("IORT");
    if (!iort)
        return g.state;
    int rc = ck_iort_parse(iort, &g.iort);
    if (rc == 0)
        return g.state;
    g.state = CK_SMMU_FAILED;
    if (rc < 0) {
        ck_printf("smmu: IORT malformed, SMMU unusable (fail closed)\n");
        return g.state;
    }
    g.base = g.iort.base;
    ck_mmio_map(g.base, CK_SMMU_MMIO_BYTES);
    uint64_t p;
    int st = alloc_strtab(); /* first, as before: the largest aligned block */
    g.t.cmd_n = QUEUE_N;
    g.t.evt_n = QUEUE_N;
    g.t.cmdq = ck_dma_alloc(4096, 4096, &p);
    g.t.evtq = ck_dma_alloc(4096, 4096, &p);
    g.cds = ck_dma_alloc(4096, 4096, &p);
    if (st || !g.t.cmdq || !g.t.evtq || !g.cds) {
        ck_printf("smmu: table allocation failed (fail closed)\n");
        return g.state;
    }
    rc = ck_smmu_enable(&regs, &g.t, CK_SMMU_DEFAULT_SPINS);
    if (rc) {
        ck_printf("smmu: bring-up failed rc=%d base=0x%llx (fail closed)\n", rc, (unsigned long long)g.base);
        return g.state;
    }
    g.state = 1;
    return 0;
}

static int confine_sid(uint32_t sid, uint64_t phys, uint64_t len, struct ck_dma_confinement *out);

int ck_dma_confine(uint32_t segment, uint32_t rid, uint64_t phys, uint64_t len, struct ck_dma_confinement *out)
{
    if (!len || (phys & 0xfffu) || (len & 0xfffu) || phys + len < phys)
        return CK_SMMU_EARG;
    int rc = bring_up();
    if (rc)
        return rc;
    uint32_t sid;
    if (ck_iort_stream_id(&g.iort, segment, rid, &sid)) {
        /* Behind an SMMUv3 this kernel does not drive (Spark: the GB10,
         * segment 15, on the IORT's second SMMUv3): refused as
         * CK_SMMU_OTHER with that SMMU and stream named, len 0, exactly
         * as the named-component path does. Never granted unconfined. */
        uint64_t other_base;
        if (ck_iort_other_stream(&g.iort, segment, rid, &sid, &other_base) == 0) {
            out->smmu_base = other_base; /* reported, never used */
            out->stream_id = sid;
            out->iova = out->len = 0;
            return CK_SMMU_OTHER;
        }
        return CK_SMMU_NOSTREAM;
    }
    return confine_sid(sid, phys, len, out);
}

int ck_dma_confine_named(const char *acpi_name, uint64_t phys, uint64_t len, struct ck_dma_confinement *out)
{
    if (!acpi_name || !len || (phys & 0xfffu) || (len & 0xfffu) || phys + len < phys)
        return CK_SMMU_EARG;
    int rc = bring_up();
    if (rc)
        return rc;
    const void *iort = ck_acpi_find("IORT");
    struct ck_iort_named nc;
    int nrc = iort ? ck_iort_named(iort, acpi_name, &nc) : 0;
    if (nrc != 1 || !nc.target_off)
        return nrc == -2 ? CK_SMMU_EARG : CK_SMMU_NOSTREAM;
    /* Only the SMMU this kernel drives (the IORT's first SMMUv3 node) can
     * confine a stream; a stream behind another SMMU is refused, never
     * granted unconfined. */
    if (nc.target_off != g.iort.node_off) {
        out->smmu_base = nc.target_base; /* reported, never used */
        out->stream_id = nc.stream_id;
        out->iova = out->len = 0;
        return CK_SMMU_OTHER;
    }
    return confine_sid(nc.stream_id, phys, len, out);
}

/* Stage-1 window [phys, phys+len) for stream sid on the SMMU brought up. */
static int confine_sid(uint32_t sid, uint64_t phys, uint64_t len, struct ck_dma_confinement *out)
{
    int rc;
    if (!ck_smmu_sid_in_range(&g.t, sid))
        return CK_SMMU_NOSTREAM; /* beyond the stream table this SMMU runs */
    int slot = -1;
    for (int i = 0; i < CK_DMA_MAX_STREAMS; i++) {
        if (g.used[i] && g.sid[i] == sid)
            return CK_SMMU_EARG;
        if (!g.used[i] && slot < 0)
            slot = i;
    }
    if (slot < 0)
        return CK_SMMU_EARG;
    struct ck_pt pt;
    if (ck_pt_init(&pt, pt_alloc, 0) || ck_pt_map(&pt, phys, phys, len, WINDOW_ATTRS))
        return CK_SMMU_FAILED;
    uint64_t *cd = g.cds + (uint64_t)slot * 8u;
    if (ck_smmu_cd_stage1(cd, pt.root, (uint16_t)(slot + 1), CK_MAIR_VALUE, 16))
        return CK_SMMU_FAILED;
    uint64_t ste[8];
    ck_smmu_ste_stage1(ste, (uint64_t)(uintptr_t)cd);
    ck_mb(); /* tables and CD written before the STE goes live */
    rc = ck_smmu_install_ste(&regs, &g.t, sid, ste, CK_SMMU_DEFAULT_SPINS);
    if (rc) {
        (void)ck_smmu_abort_ste(&regs, &g.t, sid, CK_SMMU_DEFAULT_SPINS);
        ck_printf("smmu: stream 0x%x install failed rc=%d (stream aborts)\n", sid, rc);
        return CK_SMMU_FAILED;
    }
    g.used[slot] = 1;
    g.sid[slot] = sid;
    out->smmu_base = g.base;
    out->stream_id = sid;
    out->iova = phys;
    out->len = len;
    return 0;
}

int ck_dma_unconfine(uint32_t stream_id)
{
    for (int i = 0; i < CK_DMA_MAX_STREAMS; i++) {
        if (!g.used[i] || g.sid[i] != stream_id)
            continue;
        if (ck_smmu_abort_ste(&regs, &g.t, stream_id, CK_SMMU_DEFAULT_SPINS))
            return CK_SMMU_FAILED;
        g.used[i] = 0;
        return 0;
    }
    return CK_SMMU_EARG;
}

int ck_dma_faults(uint32_t stream_id, struct ck_dma_fault *first)
{
    if (g.state != 1)
        return -1;
    int matched = 0, ovf = 0, n;
    struct ck_smmu_event ev[4];
    do {
        int o = 0;
        n = ck_smmu_read_events(&regs, &g.t, ev, 4, &o);
        ovf |= o;
        for (int i = 0; i < n; i++) {
            if (ev[i].sid != stream_id)
                continue;
            if (!matched && first) {
                first->type = ev[i].type;
                first->stream_id = ev[i].sid;
                first->addr = ev[i].addr;
            }
            matched++;
        }
    } while (n == 4);
    if (first)
        first->overflow = ovf;
    return matched;
}
