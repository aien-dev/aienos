/* smmu_svc.c -- the ck.h DMA isolation services (ck_dma_confine and
 * friends) over core/smmu.c, the IORT parser and the DMA pool. Kernel only
 * (the host tests drive core/smmu.c directly against a model SMMU).
 *
 * One instance block per SMMUv3 node the IORT lists (cut B7a, aienos#286):
 * a requester is routed to the node its root complex or named component
 * maps it to (ck_iort_route / ck_iort_named), and that node is brought up
 * the first time a stream behind it is confined. The DGX Spark lists three
 * (docs/GB10_IORT_DECODE.md): A at 0x13800000 (PCI segments 0..14, the
 * USB controllers), B at 0x13000000 (segment 15: the GB10, stream 0x100,
 * and HDA0), C for the small platform peripherals. QEMU virt lists one.
 *
 * Firmware-reserved ranges (IORT RMR nodes): a stream the RMR names gets
 * its ranges identity-mapped in the same stage-1 table as its DMA window,
 * so the device keeps reaching what the firmware set up for it while
 * everything else still faults and aborts. Only Normal memory attributes
 * (Non-cacheable, or Inner/Outer Write-back, both mapped Normal
 * Non-cacheable like the window) are honoured; any other attribute refuses
 * the confinement (fail closed). A stream the RMR names but nobody confines
 * stays aborted like every other stream.
 *
 * Memory: per instance a stream table (two-level when the SMMU supports it:
 * an L1 table of at most 128 KiB plus one 4 KiB L2 page per granted span;
 * else linear, 4096 STEs, 256 KiB), command and event queues, the context
 * descriptors and every stage-1 table come from ck_dma_alloc, which is
 * Normal Non-cacheable, so a dsb orders them before register writes. */
#include "ck_internal.h"
#include "pt.h"
#include "smmu.h"

#define STE_N 4096u /* stream ids 0..4095: PCI buses 0..15 (QEMU virt uses bus 0) */
#define QUEUE_N 16u
/* Window leaf: Normal Non-cacheable (same as the CPU's DMA pool mapping),
 * read/write, AP[1] = 1 so unprivileged device transactions are allowed
 * (PCIe requests are usually unprivileged), never executable. */
#define WINDOW_ATTRS (CK_PT_NORMAL_NC | (1ull << 6))

struct inst {
    int state; /* 0 not tried, 1 up, CK_SMMU_FAILED */
    uint32_t index; /* position in g.iort.smmus */
    uint64_t base;
    uint32_t node_off;
    struct ck_smmu_regs regs; /* ctx = this instance */
    struct ck_smmu_tables t;
    uint64_t *cds; /* CK_DMA_MAX_STREAMS context descriptors, one page */
    uint32_t sid[CK_DMA_MAX_STREAMS];
    int used[CK_DMA_MAX_STREAMS];
};

static struct {
    int state; /* IORT: 0 not read, 1 parsed, CK_SMMU_ABSENT / CK_SMMU_FAILED */
    struct ck_iort_smmu iort;
    struct inst inst[CK_IORT_MAX_SMMUS];
} g;

static uint32_t r_rd32(void *ctx, uint32_t off)
{
    return *(volatile uint32_t *)(uintptr_t)(((struct inst *)ctx)->base + off);
}
static void r_wr32(void *ctx, uint32_t off, uint32_t v)
{
    *(volatile uint32_t *)(uintptr_t)(((struct inst *)ctx)->base + off) = v;
}
static void r_wr64(void *ctx, uint32_t off, uint64_t v)
{
    *(volatile uint64_t *)(uintptr_t)(((struct inst *)ctx)->base + off) = v;
}
static void r_bar(void *ctx)
{
    (void)ctx;
    ck_mb();
}

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
static int alloc_strtab(struct inst *in)
{
    uint64_t p;
    uint32_t idr0 = r_rd32(in, CK_SMMU_IDR0), sidsize = r_rd32(in, CK_SMMU_IDR1) & CK_SMMU_IDR1_SIDSIZE_MASK;
    if (((idr0 >> CK_SMMU_IDR0_ST_LEVEL_SHIFT) & CK_SMMU_IDR0_ST_LEVEL_MASK) == 1u && sidsize >= CK_SMMU_L2_MIN_BITS) {
        uint32_t bits = sidsize < CK_SMMU_L2_MAX_BITS ? sidsize : CK_SMMU_L2_MAX_BITS;
        uint32_t l1_bytes = (1u << (bits - CK_SMMU_SPLIT)) * 8u;
        if (l1_bytes < 64u)
            l1_bytes = 64u;
        in->t.sid_bits = bits;
        in->t.l2_alloc = l2_alloc;
        in->t.l1 = ck_dma_alloc(l1_bytes, l1_bytes, &p);
        ck_printf("smmu: stream table 2-level log2size=%u split=%u (spans allocated per grant)\n", bits,
                  CK_SMMU_SPLIT);
        return in->t.l1 ? 0 : -1;
    }
    in->t.ste_n = STE_N;
    in->t.strtab = ck_dma_alloc(STE_N * CK_SMMU_STE_BYTES, STE_N * CK_SMMU_STE_BYTES, &p);
    ck_printf("smmu: stream table linear entries=%u\n", STE_N);
    return in->t.strtab ? 0 : -1;
}

/* Read and parse the IORT once per boot. 0 parsed, else CK_SMMU_ABSENT /
 * CK_SMMU_FAILED (fail closed). */
static int parse_iort(void)
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
    if (rc < 0) {
        g.state = CK_SMMU_FAILED;
        ck_printf("smmu: IORT malformed, SMMU unusable (fail closed)\n");
        return g.state;
    }
    g.state = 1;
    return 0;
}

/* Bring up the SMMUv3 node at g.iort.smmus[index] the first time it is
 * needed. 0 up, else CK_SMMU_FAILED (fail closed). */
static int bring_up(uint32_t index)
{
    struct inst *in = &g.inst[index];
    if (in->state)
        return in->state == 1 ? 0 : in->state;
    in->state = CK_SMMU_FAILED;
    in->index = index;
    in->base = g.iort.smmus[index].base;
    in->node_off = g.iort.smmus[index].off;
    in->regs.ctx = in;
    in->regs.rd32 = r_rd32;
    in->regs.wr32 = r_wr32;
    in->regs.wr64 = r_wr64;
    in->regs.barrier = r_bar;
    ck_mmio_map(in->base, CK_SMMU_MMIO_BYTES);
    uint64_t p;
    int st = alloc_strtab(in); /* first, as before: the largest aligned block */
    in->t.cmd_n = QUEUE_N;
    in->t.evt_n = QUEUE_N;
    in->t.cmdq = ck_dma_alloc(4096, 4096, &p);
    in->t.evtq = ck_dma_alloc(4096, 4096, &p);
    in->cds = ck_dma_alloc(4096, 4096, &p);
    if (st || !in->t.cmdq || !in->t.evtq || !in->cds) {
        ck_printf("smmu: table allocation failed (fail closed)\n");
        return in->state;
    }
    int rc = ck_smmu_enable(&in->regs, &in->t, CK_SMMU_DEFAULT_SPINS);
    if (rc) {
        ck_printf("smmu: bring-up failed rc=%d base=0x%llx (fail closed)\n", rc, (unsigned long long)in->base);
        return in->state;
    }
    if (index)
        ck_printf("smmu: instance %u up base=0x%llx\n", index, (unsigned long long)in->base);
    in->state = 1;
    return 0;
}

static int confine_sid(uint32_t index, uint32_t sid, uint64_t phys, uint64_t len, const struct ck_iort_route *rt,
                       struct ck_dma_confinement *out);

int ck_dma_confine(uint32_t segment, uint32_t rid, uint64_t phys, uint64_t len, struct ck_dma_confinement *out)
{
    if (!len || (phys & 0xfffu) || (len & 0xfffu) || phys + len < phys)
        return CK_SMMU_EARG;
    int rc = parse_iort();
    if (rc)
        return rc;
    struct ck_iort_route rt;
    if (ck_iort_route(&g.iort, segment, rid, &rt))
        return CK_SMMU_NOSTREAM;
    rc = bring_up(rt.smmu_index);
    if (rc)
        return rc;
    return confine_sid(rt.smmu_index, rt.sid, phys, len, &rt, out);
}

int ck_dma_confine_named(const char *acpi_name, uint64_t phys, uint64_t len, struct ck_dma_confinement *out)
{
    if (!acpi_name || !len || (phys & 0xfffu) || (len & 0xfffu) || phys + len < phys)
        return CK_SMMU_EARG;
    int rc = parse_iort();
    if (rc)
        return rc;
    const void *iort = ck_acpi_find("IORT");
    struct ck_iort_named nc;
    int nrc = iort ? ck_iort_named(iort, acpi_name, &nc) : 0;
    if (nrc != 1 || !nc.target_off)
        return nrc == -2 ? CK_SMMU_EARG : CK_SMMU_NOSTREAM;
    /* The SMMUv3 node the component maps to; one the parser did not keep
     * (beyond CK_IORT_MAX_SMMUS) is refused, never granted unconfined. */
    uint32_t index;
    for (index = 0; index < g.iort.nsmmus; index++)
        if (g.iort.smmus[index].off == nc.target_off)
            break;
    if (index == g.iort.nsmmus) {
        out->smmu_base = nc.target_base; /* reported, never used */
        out->stream_id = nc.stream_id;
        out->iova = out->len = 0;
        return CK_SMMU_OTHER;
    }
    rc = bring_up(index);
    if (rc)
        return rc;
    struct ck_iort_route rt = { 0 };
    (void)ck_iort_rmr_for(&g.iort, nc.target_off, nc.stream_id, &rt);
    return confine_sid(index, nc.stream_id, phys, len, &rt, out);
}

/* Identity-map every firmware-reserved range the IORT names for this
 * stream into pt, Normal Non-cacheable. 0 ok (ranges mapped in *n), -1 an
 * attribute this kernel does not honour or a range that collides with the
 * window (fail closed). */
static int map_reserved(struct ck_pt *pt, const struct ck_iort_route *rt, uint32_t sid, uint32_t *n)
{
    *n = 0;
    for (uint32_t i = 0; i < rt->nrmr; i++) {
        const struct ck_iort_rmr *r = rt->rmr[i];
        uint32_t attr = CK_IORT_RMR_ATTR(r->flags);
        if (attr != CK_IORT_RMR_ATTR_NORMAL_NC && attr != CK_IORT_RMR_ATTR_NORMAL_IWB_OWB) {
            ck_printf("smmu: stream 0x%x reserved range attr %u unsupported (fail closed)\n", sid, attr);
            return -1;
        }
        for (uint32_t k = 0; k < r->nranges; k++) {
            if (ck_pt_map(pt, r->range[k].base, r->range[k].base, r->range[k].len, WINDOW_ATTRS)) {
                ck_printf("smmu: stream 0x%x reserved range 0x%llx+0x%llx not mappable (fail closed)\n", sid,
                          (unsigned long long)r->range[k].base, (unsigned long long)r->range[k].len);
                return -1;
            }
            (*n)++;
        }
    }
    return 0;
}

/* Stage-1 window [phys, phys+len) (plus the stream's reserved ranges) for
 * stream sid on instance index, which is up. */
static int confine_sid(uint32_t index, uint32_t sid, uint64_t phys, uint64_t len, const struct ck_iort_route *rt,
                       struct ck_dma_confinement *out)
{
    struct inst *in = &g.inst[index];
    int rc;
    if (!ck_smmu_sid_in_range(&in->t, sid))
        return CK_SMMU_NOSTREAM; /* beyond the stream table this SMMU runs */
    int slot = -1;
    for (int i = 0; i < CK_DMA_MAX_STREAMS; i++) {
        if (in->used[i] && in->sid[i] == sid)
            return CK_SMMU_EARG;
        if (!in->used[i] && slot < 0)
            slot = i;
    }
    if (slot < 0)
        return CK_SMMU_EARG;
    struct ck_pt pt;
    uint32_t reserved;
    if (ck_pt_init(&pt, pt_alloc, 0) || ck_pt_map(&pt, phys, phys, len, WINDOW_ATTRS) ||
        map_reserved(&pt, rt, sid, &reserved))
        return CK_SMMU_FAILED;
    uint64_t *cd = in->cds + (uint64_t)slot * 8u;
    if (ck_smmu_cd_stage1(cd, pt.root, (uint16_t)(slot + 1), CK_MAIR_VALUE, 16))
        return CK_SMMU_FAILED;
    uint64_t ste[8];
    ck_smmu_ste_stage1(ste, (uint64_t)(uintptr_t)cd);
    ck_mb(); /* tables and CD written before the STE goes live */
    rc = ck_smmu_install_ste(&in->regs, &in->t, sid, ste, CK_SMMU_DEFAULT_SPINS);
    if (rc) {
        (void)ck_smmu_abort_ste(&in->regs, &in->t, sid, CK_SMMU_DEFAULT_SPINS);
        ck_printf("smmu: stream 0x%x install failed rc=%d (stream aborts)\n", sid, rc);
        return CK_SMMU_FAILED;
    }
    if (reserved)
        ck_printf("smmu: stream 0x%x on 0x%llx: %u firmware-reserved range(s) identity-mapped beside the window\n",
                  sid, (unsigned long long)in->base, reserved);
    in->used[slot] = 1;
    in->sid[slot] = sid;
    out->smmu_base = in->base;
    out->stream_id = sid;
    out->iova = phys;
    out->len = len;
    return 0;
}

/* The one live instance holding stream_id confined, or NULL. Two instances
 * holding the same stream id (the namespace is per SMMU) is ambiguous:
 * *ambiguous is set and NULL returned. */
static struct inst *holder(uint32_t stream_id, int *slot, int *ambiguous)
{
    struct inst *found = 0;
    *ambiguous = 0;
    for (uint32_t k = 0; k < CK_IORT_MAX_SMMUS; k++) {
        struct inst *in = &g.inst[k];
        if (in->state != 1)
            continue;
        for (int i = 0; i < CK_DMA_MAX_STREAMS; i++) {
            if (!in->used[i] || in->sid[i] != stream_id)
                continue;
            if (found) {
                *ambiguous = 1;
                return 0;
            }
            found = in;
            *slot = i;
        }
    }
    return found;
}

int ck_dma_unconfine(uint32_t stream_id)
{
    int slot = 0, amb;
    struct inst *in = holder(stream_id, &slot, &amb);
    if (!in)
        return CK_SMMU_EARG; /* not confined, or confined on two SMMUs */
    if (ck_smmu_abort_ste(&in->regs, &in->t, stream_id, CK_SMMU_DEFAULT_SPINS))
        return CK_SMMU_FAILED;
    in->used[slot] = 0;
    return 0;
}

int ck_dma_faults(uint32_t stream_id, struct ck_dma_fault *first)
{
    int matched = 0, ovf = 0, any = 0;
    for (uint32_t k = 0; k < CK_IORT_MAX_SMMUS; k++) {
        struct inst *in = &g.inst[k];
        if (in->state != 1)
            continue;
        any = 1;
        int n;
        struct ck_smmu_event ev[4];
        do {
            int o = 0;
            n = ck_smmu_read_events(&in->regs, &in->t, ev, 4, &o);
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
    }
    if (!any)
        return -1;
    if (first)
        first->overflow = ovf;
    return matched;
}

#ifdef CK_B7B_PROBE
/* Cut B7b preparation (aienos#286; Drake's ruling of 2026-10-10 authorizes the
 * preparation, not the boot): a probe build (make CK_B7B_PROBE=1, own OUT)
 * that, once per boot, confines PCI segment 15 requester 0x100 (the GB10, IORT
 * stream 0x100 on SMMUv3 B at 0x13000000 on the DGX Spark, docs/GB10_IORT_DECODE.md)
 * on a one-page DMA window, reports the route, the RMR count and SMMU_IDR0 /
 * SMMU_IDR1 of the node it came up on (read only: "Access to this field is RO",
 * IHI0070H.a 6.3.1 / 6.3.2), unconfines, and prints one summary line. No DMA is
 * started; the window page is never handed to a device. After the probe the
 * node stays enabled with every stream aborting (as after any unconfine).
 * QEMU virt has no segment 15, so there the expected result is a fail-closed
 * refusal. CK_B7B_PROBE_TEST_SEGMENT0=1 (TEST-ONLY, QEMU positive path,
 * refused with CK_HARDWARE_STAGING) probes segment 0 instead.
 * Lines judged by scripts/qemu_ck_b7b_probe_test.sh. */
#if defined(CK_B7B_PROBE_TEST_SEGMENT0) && defined(CK_HARDWARE_STAGING)
#error "CK_B7B_PROBE_TEST_SEGMENT0 (TEST-only QEMU positive path) cannot be combined with CK_HARDWARE_STAGING"
#endif
#ifdef CK_B7B_PROBE_TEST_SEGMENT0
#define B7B_SEGMENT 0u
#else
#define B7B_SEGMENT 15u
#endif
#define B7B_RID 0x100u

static const char *b7b_rc(int rc)
{
    switch (rc) {
    case 0: return "ok";
    case CK_SMMU_ABSENT: return "absent";
    case CK_SMMU_FAILED: return "failed";
    case CK_SMMU_NOSTREAM: return "nostream";
    case CK_SMMU_EARG: return "earg";
    case CK_SMMU_OTHER: return "other";
    default: return "unknown";
    }
}

void ck_b7b_probe(void)
{
#ifdef CK_B7B_PROBE_TEST_SEGMENT0
    ck_puts("b7b_probe: TEST-ONLY B7b probe on PCI segment 0 (QEMU positive path); never hardware evidence\n");
#endif
    ck_printf("b7b_probe: start segment=%u rid=0x%x window_bytes=4096 no_dma=yes\n", B7B_SEGMENT, B7B_RID);
    int rc = parse_iort();
    struct ck_iort_route rt;
    if (rc) {
        ck_printf("b7b_probe: iort rc=%d (%s)\n", rc, b7b_rc(rc));
    } else if (ck_iort_route(&g.iort, B7B_SEGMENT, B7B_RID, &rt)) {
        ck_printf("b7b_probe: route none (smmus=%u)\n", g.iort.nsmmus);
    } else {
        ck_printf("b7b_probe: route instance=%u base=0x%llx stream=0x%x rmr_nodes=%u (smmus=%u)\n", rt.smmu_index,
                  (unsigned long long)rt.smmu_base, rt.sid, rt.nrmr, g.iort.nsmmus);
    }
    uint64_t phys = 0;
    if (!ck_dma_alloc(4096, 4096, &phys)) {
        ck_puts("b7b_probe: no DMA page\nAIENOS_B7B_PROBE: FAIL\n");
        return;
    }
    struct ck_dma_confinement cf;
    rc = ck_dma_confine(B7B_SEGMENT, B7B_RID, phys, 4096, &cf);
    if (rc) {
        ck_printf("b7b_probe: confine refused rc=%d (%s); nothing granted\n", rc, b7b_rc(rc));
        ck_puts("AIENOS_B7B_PROBE: REFUSED\n");
        return;
    }
    ck_printf("b7b_probe: confined stream=0x%x smmu_base=0x%llx iova=0x%llx len=0x%llx\n", cf.stream_id,
              (unsigned long long)cf.smmu_base, (unsigned long long)cf.iova, (unsigned long long)cf.len);
    int idr_ok = 0;
    for (uint32_t k = 0; k < CK_IORT_MAX_SMMUS; k++) {
        struct inst *in = &g.inst[k];
        if (in->state != 1 || in->base != cf.smmu_base)
            continue;
        uint32_t idr0 = r_rd32(in, CK_SMMU_IDR0), idr1 = r_rd32(in, CK_SMMU_IDR1);
        ck_printf("b7b_probe: instance=%u idr0=0x%08x idr1=0x%08x st_level=%u sidsize=%u\n", k, idr0, idr1,
                  (idr0 >> CK_SMMU_IDR0_ST_LEVEL_SHIFT) & CK_SMMU_IDR0_ST_LEVEL_MASK,
                  idr1 & CK_SMMU_IDR1_SIDSIZE_MASK);
        idr_ok = 1;
        break;
    }
    if (!idr_ok)
        ck_puts("b7b_probe: no live instance at the confined base\n");
    int urc = ck_dma_unconfine(cf.stream_id);
    ck_printf("b7b_probe: unconfine rc=%d (%s); stream 0x%x aborts again\n", urc, b7b_rc(urc), cf.stream_id);
    ck_puts(urc || !idr_ok ? "AIENOS_B7B_PROBE: FAIL\n" : "AIENOS_B7B_PROBE: CONFINED_AND_RELEASED\n");
}
#endif
