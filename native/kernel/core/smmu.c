/* smmu.c -- see smmu.h. Port of crates/aienos-kernel/src/smmu.rs. */
#include "smmu.h"

/* TEST-only two-level stream table mutants (make smmu-l2-mutants): each
 * must make test_smmu FAIL. Host builds only; never part of an image. */
#if defined(CK_SMMU_MUTANT_SPAN_OVERFLOW) || defined(CK_SMMU_MUTANT_UNGRANTED_VALID) || \
    defined(CK_SMMU_MUTANT_BAD_L1_PTR) || defined(CK_SMMU_MUTANT_L2_NO_FILL)
#if !__STDC_HOSTED__
#error "CK_SMMU_MUTANT_* are host test mutants only"
#endif
#ifdef CK_HARDWARE_STAGING
#error "CK_SMMU_MUTANT_* cannot be combined with CK_HARDWARE_STAGING"
#endif
#endif

#define IDR1_SIDSIZE_MASK 0x3fu
#define IDR1_EVENTQS_SHIFT 16u
#define IDR1_CMDQS_SHIFT 21u
#define IDR1_QS_MASK 0x1fu
#define CR0_ACK_MASK 0x0fu
#define CMDQ_CONS_ERR_MASK (0x7fu << 24)
#define EVENTQ_OVERFLOW (1u << 31)

static uint32_t rd(const struct ck_smmu_regs *r, uint32_t off) { return r->rd32(r->ctx, off); }
static void wr(const struct ck_smmu_regs *r, uint32_t off, uint32_t v) { r->wr32(r->ctx, off, v); }
static void wr64(const struct ck_smmu_regs *r, uint32_t off, uint64_t v) { r->wr64(r->ctx, off, v); }
static void bar(const struct ck_smmu_regs *r) { r->barrier(r->ctx); }

static int pow2(uint32_t n, uint32_t min) { return n >= min && (n & (n - 1)) == 0; }
static uint32_t log2u(uint32_t n)
{
    uint32_t s = 0;
    while (n > 1u) {
        n >>= 1;
        s++;
    }
    return s;
}
static int aligned(const void *p, uint64_t bytes)
{
    uint64_t a = (uint64_t)(uintptr_t)p;
    if (bytes < 32u) bytes = 32u;
    return a != 0 && (a & (bytes - 1u)) == 0;
}

static uint32_t l1_n(const struct ck_smmu_tables *t) { return 1u << (t->sid_bits - CK_SMMU_SPLIT); }

int ck_smmu_tables_check(const struct ck_smmu_tables *t)
{
    if (!pow2(t->cmd_n, 2) || !pow2(t->evt_n, 2) || t->cmd_n > (1u << 19) || t->evt_n > (1u << 19) ||
        !aligned(t->cmdq, (uint64_t)t->cmd_n * CK_SMMU_CMD_BYTES) ||
        !aligned(t->evtq, (uint64_t)t->evt_n * CK_SMMU_EVT_BYTES))
        return CK_SMMU_EINVAL;
    if (t->l1) {
        if (t->sid_bits < CK_SMMU_L2_MIN_BITS || t->sid_bits > CK_SMMU_L2_MAX_BITS || !t->l2_alloc)
            return CK_SMMU_EINVAL;
        /* IHI 0070 6.3.24: 2-level base aligned to max(64 bytes, L1 size). */
        uint64_t l1_bytes = (uint64_t)l1_n(t) * 8u;
#ifndef CK_SMMU_MUTANT_BAD_L1_PTR
        if (!aligned(t->l1, l1_bytes < 64u ? 64u : l1_bytes) ||
            ((uint64_t)(uintptr_t)t->l1 & ~CK_SMMU_L1STD_L2PTR_MASK))
            return CK_SMMU_EINVAL;
#else
        (void)l1_bytes; /* TEST mutant: any L1 pointer accepted */
#endif
        return 0;
    }
    if (!pow2(t->ste_n, 1) || t->ste_n > (1u << 16) || !aligned(t->strtab, (uint64_t)t->ste_n * CK_SMMU_STE_BYTES))
        return CK_SMMU_EINVAL;
    return 0;
}

int ck_smmu_sid_in_range(const struct ck_smmu_tables *t, uint32_t sid)
{
    if (t->l1)
        return t->sid_bits <= CK_SMMU_L2_MAX_BITS && (sid >> t->sid_bits) == 0;
    return sid < t->ste_n;
}

uint64_t ck_smmu_l1std(const struct ck_smmu_tables *t, uint32_t sid)
{
    if (!t->l1 || !ck_smmu_sid_in_range(t, sid))
        return 0;
    return ((volatile const uint64_t *)t->l1)[sid >> CK_SMMU_SPLIT];
}

/* The STE of `sid`, or NULL when out of range or (two-level) its span has
 * no L2 table yet (or a descriptor this code did not write: wrong Span or a
 * zero L2Ptr, which the callers refuse). */
static volatile uint64_t *ste_at(const struct ck_smmu_tables *t, uint32_t sid)
{
    if (!ck_smmu_sid_in_range(t, sid))
        return 0;
    if (!t->l1)
        return (volatile uint64_t *)t->strtab + (uint64_t)sid * 8u;
    uint64_t d = ck_smmu_l1std(t, sid);
    if ((d & CK_SMMU_L1STD_SPAN_MASK) != CK_SMMU_L1STD_SPAN || !(d & CK_SMMU_L1STD_L2PTR_MASK))
        return 0;
    return (volatile uint64_t *)(uintptr_t)(d & CK_SMMU_L1STD_L2PTR_MASK) +
           (uint64_t)(sid & (CK_SMMU_L2_STES - 1u)) * 8u;
}

void ck_smmu_ste_abort(uint64_t ste[8])
{
    /* V = 1, Config = 0b000: abort every transaction. No bypass builder. */
    ste[0] = 1;
    for (int i = 1; i < 8; i++)
        ste[i] = 0;
}

void ck_smmu_ste_stage1(uint64_t ste[8], uint64_t cd_addr)
{
    /* V (bit 0), Config 0b101 (S1 translate, S2 bypass) in bits 3:1,
     * S1Fmt 0 (linear, one CD), S1ContextPtr bits 51:6. */
    ste[0] = 1u | (0x5ull << 1) | (cd_addr & 0x000fffffffffffc0ull);
    for (int i = 1; i < 8; i++)
        ste[i] = 0;
}

int ck_smmu_cd_stage1(uint64_t cd[8], uint64_t ttb0, uint16_t asid, uint64_t mair, uint8_t t0sz)
{
    if (t0sz > 39u || (ttb0 & 0xfffu))
        return CK_SMMU_EINVAL;
    /* T0SZ, TG0 = 0 (4 KiB), IRGN0/ORGN0 = 0 and SH0 = 0 (Non-cacheable
     * walks: the tables are in Non-cacheable memory; the Rust reference
     * uses write-back walks over cleaned write-back memory), EPD1, V,
     * IPS = 5 (48-bit), AA64, R (record faults), A (abort faulting
     * transactions), ASID. */
    cd[0] = (uint64_t)t0sz | (1ull << 30) | (1ull << 31) | (0x5ull << 32) | (1ull << 41) | (1ull << 45) |
            (1ull << 46) | ((uint64_t)asid << 48);
    cd[1] = ttb0 & 0x0000fffffffffff0ull;
    cd[2] = 0;
    cd[3] = mair;
    for (int i = 4; i < 8; i++)
        cd[i] = 0;
    return 0;
}

void ck_smmu_cmd(uint64_t w[2], uint8_t opcode, uint32_t sid, int leaf)
{
    w[0] = (uint64_t)opcode | ((uint64_t)sid << 32);
    w[1] = opcode == CK_SMMU_CMD_CFGI_ALL ? 31u : (leaf ? 1u : 0u);
}

uint32_t ck_smmu_q_encode(uint32_t index, int wrap, uint32_t entries)
{
    return (index & (entries - 1u)) | ((wrap ? 1u : 0u) << log2u(entries));
}

struct qc {
    uint32_t index;
    int wrap;
};
static struct qc q_decode(uint32_t v, uint32_t entries)
{
    struct qc c = { v & (entries - 1u), (v & entries) != 0 };
    return c;
}
static void q_advance(struct qc *c, uint32_t entries)
{
    if (++c->index == entries) {
        c->index = 0;
        c->wrap = !c->wrap;
    }
}

static int cmdq_cons(const struct ck_smmu_regs *r, uint32_t entries, struct qc *out)
{
    uint32_t v = rd(r, CK_SMMU_CMDQ_CONS);
    if (v & CMDQ_CONS_ERR_MASK)
        return CK_SMMU_ECMDQ;
    *out = q_decode(v, entries);
    return 0;
}

int ck_smmu_submit(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, const uint64_t (*cmds)[2],
                   uint32_t n, uint32_t spins)
{
    uint32_t entries = t->cmd_n;
    struct qc prod = q_decode(rd(r, CK_SMMU_CMDQ_PROD), entries), cons;
    for (uint32_t k = 0; k < n; k++) {
        /* Full when the indexes match and the wrap flags differ. */
        int space = 0;
        for (uint32_t i = 0; i < spins; i++) {
            int rc = cmdq_cons(r, entries, &cons);
            if (rc)
                return rc;
            if (!(cons.index == prod.index && cons.wrap != prod.wrap)) {
                space = 1;
                break;
            }
        }
        if (!space)
            return CK_SMMU_ETIMEOUT;
        volatile uint64_t *slot = t->cmdq + (uint64_t)prod.index * 2u;
        slot[0] = cmds[k][0];
        slot[1] = cmds[k][1];
        bar(r);
        q_advance(&prod, entries);
        wr(r, CK_SMMU_CMDQ_PROD, ck_smmu_q_encode(prod.index, prod.wrap, entries));
    }
    for (uint32_t i = 0; i < spins; i++) {
        int rc = cmdq_cons(r, entries, &cons);
        if (rc)
            return rc;
        if (cons.index == prod.index && cons.wrap == prod.wrap)
            return 0;
    }
    return CK_SMMU_ETIMEOUT;
}

static int poll_gbpa_idle(const struct ck_smmu_regs *r, uint32_t spins, uint32_t *out)
{
    for (uint32_t i = 0; i < spins; i++) {
        uint32_t g = rd(r, CK_SMMU_GBPA);
        if (!(g & CK_SMMU_GBPA_UPDATE)) {
            *out = g;
            return 0;
        }
    }
    return CK_SMMU_ETIMEOUT;
}

static int set_global_abort(const struct ck_smmu_regs *r, uint32_t spins)
{
    uint32_t g;
    int rc = poll_gbpa_idle(r, spins, &g);
    if (rc)
        return rc;
    g = (g & ~CK_SMMU_GBPA_UPDATE) | CK_SMMU_GBPA_ABORT;
    wr(r, CK_SMMU_GBPA, g | CK_SMMU_GBPA_UPDATE);
    rc = poll_gbpa_idle(r, spins, &g);
    if (rc)
        return rc;
    return (g & CK_SMMU_GBPA_ABORT) ? 0 : CK_SMMU_ENOABORT;
}

static int wait_cr0(const struct ck_smmu_regs *r, uint32_t want, uint32_t spins)
{
    for (uint32_t i = 0; i < spins; i++)
        if ((rd(r, CK_SMMU_CR0ACK) & CR0_ACK_MASK) == (want & CR0_ACK_MASK))
            return 0;
    return CK_SMMU_ETIMEOUT;
}

static void write_ste_word(volatile uint64_t *ste, int word, uint64_t v)
{
    /* A 64-bit aligned store is single-copy atomic: no torn word 0. */
    ste[word] = v;
}

static int invalidate_ste(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                          uint32_t spins)
{
    /* STE, every cached CD of this stream (the CD page is reused when a
     * stream is re-confined), then the TLBs. */
    uint64_t c[4][2];
    ck_smmu_cmd(c[0], CK_SMMU_CMD_CFGI_STE, sid, 1);
    ck_smmu_cmd(c[1], CK_SMMU_CMD_CFGI_CD_ALL, sid, 0);
    ck_smmu_cmd(c[2], CK_SMMU_CMD_TLBI_NSNH_ALL, 0, 0);
    ck_smmu_cmd(c[3], CK_SMMU_CMD_SYNC, 0, 0);
    bar(r);
    return ck_smmu_submit(r, t, (const uint64_t (*)[2])c, 4, spins);
}

static int program(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t spins)
{
    uint32_t sid_bits = t->l1 ? t->sid_bits : log2u(t->ste_n);
    uint32_t idr0 = rd(r, CK_SMMU_IDR0);
    if (!(idr0 & CK_SMMU_IDR0_S1P))
        return CK_SMMU_EUNSUP;
    if (t->l1 && ((idr0 >> CK_SMMU_IDR0_ST_LEVEL_SHIFT) & CK_SMMU_IDR0_ST_LEVEL_MASK) != 1u)
        return CK_SMMU_EUNSUP;
    uint32_t idr1 = rd(r, CK_SMMU_IDR1);
    if ((idr1 & IDR1_SIDSIZE_MASK) < sid_bits ||
        ((idr1 >> IDR1_CMDQS_SHIFT) & IDR1_QS_MASK) < log2u(t->cmd_n) ||
        ((idr1 >> IDR1_EVENTQS_SHIFT) & IDR1_QS_MASK) < log2u(t->evt_n))
        return CK_SMMU_EUNSUP;
    if (t->l1) {
        /* Every span invalid (Span 0): its StreamIDs are terminated. */
        volatile uint64_t *l1 = t->l1;
        for (uint32_t i = 0; i < l1_n(t); i++)
#ifndef CK_SMMU_MUTANT_UNGRANTED_VALID
            l1[i] = 0;
#else
            l1[i] = CK_SMMU_L1STD_SPAN; /* TEST mutant: valid span, L2Ptr 0 */
#endif
    } else {
        uint64_t abort[8];
        ck_smmu_ste_abort(abort);
        for (uint32_t sid = 0; sid < t->ste_n; sid++)
            for (int w = 0; w < 8; w++)
                write_ste_word((volatile uint64_t *)t->strtab + (uint64_t)sid * 8u, w, abort[w]);
    }
    volatile uint64_t *cq = t->cmdq, *eq = t->evtq;
    for (uint64_t i = 0; i < (uint64_t)t->cmd_n * 2u; i++)
        cq[i] = 0;
    for (uint64_t i = 0; i < (uint64_t)t->evt_n * 4u; i++)
        eq[i] = 0;
    bar(r); /* everything the SMMU will fetch is written */

    wr(r, CK_SMMU_CR0, 0);
    int rc = wait_cr0(r, 0, spins);
    if (rc)
        return rc;
    /* CR1 = 0: queue and table fetches Non-cacheable, matching the
     * Non-cacheable DMA pool (the Rust reference uses 0x0d75, write-back). */
    wr(r, CK_SMMU_CR1, 0);
    wr64(r, CK_SMMU_CMDQ_BASE, (uint64_t)(uintptr_t)t->cmdq | log2u(t->cmd_n));
    wr(r, CK_SMMU_CMDQ_CONS, 0);
    wr(r, CK_SMMU_CMDQ_PROD, 0);
    wr64(r, CK_SMMU_EVENTQ_BASE, (uint64_t)(uintptr_t)t->evtq | log2u(t->evt_n));
    wr(r, CK_SMMU_EVENTQ_CONS, 0);
    wr(r, CK_SMMU_EVENTQ_PROD, 0);
    if (t->l1) {
        wr(r, CK_SMMU_STRTAB_BASE_CFG, CK_SMMU_STRTAB_FMT_2LVL | (CK_SMMU_SPLIT << 6) | sid_bits);
        wr64(r, CK_SMMU_STRTAB_BASE, (uint64_t)(uintptr_t)t->l1);
    } else {
        wr(r, CK_SMMU_STRTAB_BASE_CFG, sid_bits); /* FMT = 0: linear */
        wr64(r, CK_SMMU_STRTAB_BASE, (uint64_t)(uintptr_t)t->strtab);
    }
    wr(r, CK_SMMU_CR0, CK_SMMU_CR0_CMDQEN | CK_SMMU_CR0_EVENTQEN);
    rc = wait_cr0(r, CK_SMMU_CR0_CMDQEN | CK_SMMU_CR0_EVENTQEN, spins);
    if (rc)
        return rc;
    uint64_t c[3][2];
    ck_smmu_cmd(c[0], CK_SMMU_CMD_CFGI_ALL, 0, 0);
    ck_smmu_cmd(c[1], CK_SMMU_CMD_TLBI_NSNH_ALL, 0, 0);
    ck_smmu_cmd(c[2], CK_SMMU_CMD_SYNC, 0, 0);
    rc = ck_smmu_submit(r, t, (const uint64_t (*)[2])c, 3, spins);
    if (rc)
        return rc;
    uint32_t en = CK_SMMU_CR0_SMMUEN | CK_SMMU_CR0_CMDQEN | CK_SMMU_CR0_EVENTQEN;
    wr(r, CK_SMMU_CR0, en);
    return wait_cr0(r, en, spins);
}

int ck_smmu_enable(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t spins)
{
    if (ck_smmu_tables_check(t))
        return CK_SMMU_EINVAL;
    int rc = set_global_abort(r, spins);
    if (rc)
        return rc; /* ABORT may not have latched: caller treats the SMMU as unusable */
    rc = program(r, t, spins);
    if (rc) {
        /* SMMU off behind GBPA.ABORT: every stream aborts. Best effort ack. */
        wr(r, CK_SMMU_CR0, 0);
        (void)wait_cr0(r, 0, spins);
    }
    return rc;
}

/* Two-level: give the span of `sid` its L2 table. The page is checked
 * (non-zero, aligned to CK_SMMU_L2_BYTES, inside L2Ptr bits 55:6), filled
 * with abort STEs, made visible, and only then published in the L1STD
 * (Span = SPLIT + 1). IHI 0070 5.1.1: an L1STD going from Span 0 to active
 * needs the non-leaf CMD_CFGI_STE only. */
static int attach_span(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                       uint32_t spins)
{
    if (ck_smmu_l1std(t, sid) != 0)
        return CK_SMMU_EINVAL; /* a descriptor we did not write: refuse, do not overwrite */
    uint64_t *page = 0;
    if (t->l2_alloc(t->l2_ctx, &page) || !page)
        return CK_SMMU_EINVAL;
    uint64_t a = (uint64_t)(uintptr_t)page;
    if ((a & (CK_SMMU_L2_BYTES - 1u)) || (a & ~CK_SMMU_L1STD_L2PTR_MASK))
        return CK_SMMU_EINVAL;
#ifndef CK_SMMU_MUTANT_L2_NO_FILL
    uint64_t abort[8];
    ck_smmu_ste_abort(abort);
    for (uint32_t i = 0; i < CK_SMMU_L2_STES; i++)
        for (int w = 0; w < 8; w++)
            write_ste_word((volatile uint64_t *)page + (uint64_t)i * 8u, w, abort[w]);
#endif
    bar(r); /* every STE of the span is abort before the span goes live */
#ifndef CK_SMMU_MUTANT_SPAN_OVERFLOW
    uint64_t d = a | CK_SMMU_L1STD_SPAN;
#else
    uint64_t d = a | (CK_SMMU_L1STD_SPAN + 1u); /* TEST mutant: Span past SPLIT + 1 */
#endif
    ((volatile uint64_t *)t->l1)[sid >> CK_SMMU_SPLIT] = d;
    uint64_t c[2][2];
    ck_smmu_cmd(c[0], CK_SMMU_CMD_CFGI_STE, sid, 0); /* non-leaf: the L1STD */
    ck_smmu_cmd(c[1], CK_SMMU_CMD_SYNC, 0, 0);
    bar(r);
    return ck_smmu_submit(r, t, (const uint64_t (*)[2])c, 2, spins);
}

int ck_smmu_abort_ste(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                      uint32_t spins)
{
    if (!ck_smmu_sid_in_range(t, sid))
        return CK_SMMU_EINVAL;
    volatile uint64_t *e = ste_at(t, sid);
    if (!e) {
        /* Two-level span without an L2 table: Span 0, every StreamID of it
         * is already terminated. Anything else is not ours: refuse. */
        return ck_smmu_l1std(t, sid) == 0 ? 0 : CK_SMMU_EINVAL;
    }
    uint64_t abort[8];
    ck_smmu_ste_abort(abort);
    /* Word 0 first: once V = 1 and Config = abort the rest is ignored. */
    for (int w = 0; w < 8; w++)
        write_ste_word(e, w, abort[w]);
    return invalidate_ste(r, t, sid, spins);
}

int ck_smmu_install_ste(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                        const uint64_t ste[8], uint32_t spins)
{
    if (!ck_smmu_sid_in_range(t, sid))
        return CK_SMMU_EINVAL;
    int rc;
    if (t->l1 && !ste_at(t, sid) && (rc = attach_span(r, t, sid, spins)))
        return rc;
    volatile uint64_t *e = ste_at(t, sid);
    if (!e)
        return CK_SMMU_EINVAL;
    rc = ck_smmu_abort_ste(r, t, sid, spins);
    if (rc)
        return rc;
    for (int w = 1; w < 8; w++)
        write_ste_word(e, w, ste[w]);
    bar(r); /* words 1..7 visible before word 0 makes the entry live */
    write_ste_word(e, 0, ste[0]);
    return invalidate_ste(r, t, sid, spins);
}

int ck_smmu_read_events(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t,
                        struct ck_smmu_event *out, int n, int *overflowed)
{
    uint32_t entries = t->evt_n;
    uint32_t prod_raw = rd(r, CK_SMMU_EVENTQ_PROD), cons_raw = rd(r, CK_SMMU_EVENTQ_CONS);
    struct qc prod = q_decode(prod_raw, entries), cons = q_decode(cons_raw, entries);
    uint32_t ovf = prod_raw & EVENTQ_OVERFLOW;
    int count = 0;
    bar(r);
    while ((cons.index != prod.index || cons.wrap != prod.wrap) && count < n) {
        volatile const uint64_t *slot = t->evtq + (uint64_t)cons.index * 4u;
        struct ck_smmu_event *e = &out[count++];
        for (int w = 0; w < 4; w++)
            e->raw[w] = slot[w];
        e->type = (uint8_t)e->raw[0];
        e->sid = (uint32_t)(e->raw[0] >> 32);
        e->addr = e->raw[2];
        q_advance(&cons, entries);
    }
    /* Copying OVFLG into OVACKFLG acknowledges an overflow. */
    wr(r, CK_SMMU_EVENTQ_CONS, ck_smmu_q_encode(cons.index, cons.wrap, entries) | ovf);
    if (overflowed)
        *overflowed = ovf != (cons_raw & EVENTQ_OVERFLOW);
    return count;
}
