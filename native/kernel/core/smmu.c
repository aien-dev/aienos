/* smmu.c -- see smmu.h. Port of crates/aienos-kernel/src/smmu.rs. */
#include "smmu.h"

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

int ck_smmu_tables_check(const struct ck_smmu_tables *t)
{
    if (!pow2(t->ste_n, 1) || !pow2(t->cmd_n, 2) || !pow2(t->evt_n, 2) || t->ste_n > (1u << 16) ||
        t->cmd_n > (1u << 19) || t->evt_n > (1u << 19) ||
        !aligned(t->strtab, (uint64_t)t->ste_n * CK_SMMU_STE_BYTES) ||
        !aligned(t->cmdq, (uint64_t)t->cmd_n * CK_SMMU_CMD_BYTES) ||
        !aligned(t->evtq, (uint64_t)t->evt_n * CK_SMMU_EVT_BYTES))
        return CK_SMMU_EINVAL;
    return 0;
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

static void write_ste_word(const struct ck_smmu_tables *t, uint32_t sid, int word, uint64_t v)
{
    /* A 64-bit aligned store is single-copy atomic: no torn word 0. */
    ((volatile uint64_t *)t->strtab)[(uint64_t)sid * 8u + (uint64_t)word] = v;
}

static int invalidate_ste(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                          uint32_t spins)
{
    uint64_t c[3][2];
    ck_smmu_cmd(c[0], CK_SMMU_CMD_CFGI_STE, sid, 1);
    ck_smmu_cmd(c[1], CK_SMMU_CMD_TLBI_NSNH_ALL, 0, 0);
    ck_smmu_cmd(c[2], CK_SMMU_CMD_SYNC, 0, 0);
    bar(r);
    return ck_smmu_submit(r, t, (const uint64_t (*)[2])c, 3, spins);
}

static int program(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t spins)
{
    uint32_t sid_bits = log2u(t->ste_n);
    if (!(rd(r, CK_SMMU_IDR0) & CK_SMMU_IDR0_S1P))
        return CK_SMMU_EUNSUP;
    uint32_t idr1 = rd(r, CK_SMMU_IDR1);
    if ((idr1 & IDR1_SIDSIZE_MASK) < sid_bits ||
        ((idr1 >> IDR1_CMDQS_SHIFT) & IDR1_QS_MASK) < log2u(t->cmd_n) ||
        ((idr1 >> IDR1_EVENTQS_SHIFT) & IDR1_QS_MASK) < log2u(t->evt_n))
        return CK_SMMU_EUNSUP;
    uint64_t abort[8];
    ck_smmu_ste_abort(abort);
    for (uint32_t sid = 0; sid < t->ste_n; sid++)
        for (int w = 0; w < 8; w++)
            write_ste_word(t, sid, w, abort[w]);
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
    wr(r, CK_SMMU_STRTAB_BASE_CFG, sid_bits); /* FMT = 0: linear */
    wr64(r, CK_SMMU_STRTAB_BASE, (uint64_t)(uintptr_t)t->strtab);
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

int ck_smmu_abort_ste(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                      uint32_t spins)
{
    if (sid >= t->ste_n)
        return CK_SMMU_EINVAL;
    uint64_t abort[8];
    ck_smmu_ste_abort(abort);
    /* Word 0 first: once V = 1 and Config = abort the rest is ignored. */
    for (int w = 0; w < 8; w++)
        write_ste_word(t, sid, w, abort[w]);
    return invalidate_ste(r, t, sid, spins);
}

int ck_smmu_install_ste(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                        const uint64_t ste[8], uint32_t spins)
{
    if (sid >= t->ste_n)
        return CK_SMMU_EINVAL;
    int rc = ck_smmu_abort_ste(r, t, sid, spins);
    if (rc)
        return rc;
    for (int w = 1; w < 8; w++)
        write_ste_word(t, sid, w, ste[w]);
    bar(r); /* words 1..7 visible before word 0 makes the entry live */
    write_ste_word(t, sid, 0, ste[0]);
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
