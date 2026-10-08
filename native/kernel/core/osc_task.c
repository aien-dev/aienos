/* osc_task.c -- launch an admitted OSC unit as an EL0 task. See osc_task.h and docs/osc-launch.md.
 *
 * Address space of the task (all user VAs are base + offset, base = a free L0 slot of the kernel root, so
 * kernel mappings stay EL1-only; every user page is non-global):
 *   0x001000  OscRt table      EL0 read-only, never executable   (13 pointers into the runtime stubs)
 *   0x002000  runtime stubs    EL0 read, execute, never writable (`svc #i`; the only SVCs a unit may reach)
 *   0x010000  unit code        EL0 read, execute, never writable
 *   0x200000  input window     EL0 read-only, never executable   (the `bytes` arguments)
 *   0x210000  workspace        EL0 read-write, never executable  (the `cells` arguments, caller-owned, 0..32 pages)
 *   ..0x400000 stack           EL0 read-write, never executable  (top down; the page below it is unmapped)
 * Writable and executable never coincide (W^X). Everything the task can reach is private to the slot
 * except the caller's workspace. */
#include "arch.h"
#include "ck_internal.h"
#include "fmt.h"
#include "osc_task.h"
#include "pt.h"
#include "sha256.h"


/* ---- vector hooks (arch/exception.c) and asm (arch/m3.S) ---- */
extern struct ck_frame *(*ck_tick_switch)(struct ck_frame *f);
extern int (*ck_lower_sync)(struct ck_frame *f, uint64_t esr);
void ck_el0_enter(uint64_t entry, uint64_t user_sp, const uint64_t regs[31]);
void ck_el0_resume(void);

#define PTE_TABLE 3ull
#define PTE_PAGE 3ull
#define PTE_AP_EL0_RW (1ull << 6)
#define PTE_AP_EL0_RO (3ull << 6)
#define PTE_NG (1ull << 11)

#define OFF_RT_TAB 0x001000ull
#define OFF_RT_CODE 0x002000ull
#define OFF_CODE 0x010000ull
#define OFF_IN 0x200000ull
#define OFF_WS 0x210000ull
#define OFF_STACK_TOP 0x400000ull

struct slot {
    uint64_t l0[512], l1[512], l2[512], l3a[512], l3b[512];
    uint8_t rt_tab[4096], rt_code[4096], in[4096];
    uint8_t code[CK_OSC_CODE_MAX_BYTES];
    uint8_t stack[CK_OSC_STACK_MAX_BYTES];
    int used;
} __attribute__((aligned(4096)));
static struct slot slot0;

static uint64_t base_va;

static uint64_t get_base(void)
{
    if (base_va)
        return base_va;
    const uint64_t *l0 = (const uint64_t *)(uintptr_t)ck_mm_report()->root;
    for (unsigned i = 1; i < 256; i++)
        if (!l0[i]) {
            base_va = (uint64_t)i << 39;
            break;
        }
    return base_va;
}

uint64_t ck_osc_va_in(void) { return get_base() ? base_va + OFF_IN : 0; }
uint64_t ck_osc_va_ws(void) { return get_base() ? base_va + OFF_WS : 0; }

static void clean_range(const void *p, size_t len, int icache)
{
    uint64_t ctr = ck_rd(ctr_el0);
    uint64_t dline = 4ull << ((ctr >> 16) & 0xf), iline = 4ull << (ctr & 0xf);
    uint64_t a = (uint64_t)(uintptr_t)p, end = a + len;
    for (uint64_t x = a & ~(dline - 1); x < end; x += dline)
        __asm__ volatile("dc civac, %0" ::"r"(x) : "memory");
    ck_dsb_ish();
    if (icache) {
        for (uint64_t x = a & ~(iline - 1); x < end; x += iline)
            __asm__ volatile("ic ivau, %0" ::"r"(x) : "memory");
        ck_dsb_ish();
    }
    ck_isb();
}

static void swap_ttbr0(uint64_t ttbr0)
{
    ck_dsb_ish();
    ck_wr(ttbr0_el1, ttbr0);
    ck_isb();
    __asm__ volatile("tlbi vmalle1" ::: "memory");
    ck_dsb_ish();
    ck_isb();
}

/* ---- page attributes: the W^X rules live here ---- */
#define COMMON (CK_PTE_ATTRIDX(CK_MAIR_IDX_NORMAL) | CK_PTE_SH_INNER | CK_PTE_AF | PTE_NG | CK_PTE_PXN)
#define DATA_XN CK_PTE_UXN /* data, stack and input are never executable at EL0 */
#define ATTR_RX (PTE_PAGE | PTE_AP_EL0_RO | COMMON)               /* read + execute */
#define ATTR_RO (PTE_PAGE | PTE_AP_EL0_RO | COMMON | DATA_XN)      /* read only, no execute */
#define ATTR_RW (PTE_PAGE | PTE_AP_EL0_RW | COMMON | DATA_XN)      /* read + write, no execute */

static void map(uint64_t *l3, unsigned idx, const void *page, uint64_t attr)
{
    l3[idx] = (uint64_t)(uintptr_t)page | attr;
}

static unsigned count_mapped(const struct slot *s)
{
    unsigned n = 0;
    for (unsigned i = 0; i < 512; i++)
        n += (unsigned)((s->l3a[i] & 1) + (s->l3b[i] & 1));
    return n;
}

/* ---- the run ---- */
static struct {
    int active, done;
    uint64_t ticks, budget, rt_code_va;
    struct osc_result res;
} run;

static void end_task(struct ck_frame *f, const struct osc_event *e)
{
    osc_launch_classify(e, run.rt_code_va, &run.res);
    run.done = 1;
    f->elr = (uint64_t)(uintptr_t)ck_el0_resume;
    f->spsr = 0x3c5; /* EL1h, DAIF masked */
}

static int launch_sync(struct ck_frame *f, uint64_t esr)
{
    if (!run.active || run.done || (f->spsr & 0xf) != 0)
        return -1;
    struct osc_event e = { ((esr >> 26) & 0x3f) == 0x15 ? OSC_EV_SVC : OSC_EV_SYNC, esr, f->elr, f->x[0],
                           f->x[1] };
    end_task(f, &e);
    return 0;
}

static struct ck_frame *launch_tick(struct ck_frame *f)
{
    if (!run.active || run.done || (f->spsr & 0xf) != 0)
        return f;
    run.ticks++;
    if (osc_launch_budget_expired(run.ticks, run.budget)) {
        struct osc_event e = { OSC_EV_BUDGET, 0, f->elr, 0, 0 };
        end_task(f, &e);
    }
    return f;
}

static void refuse(struct osc_result *res, unsigned code)
{
    memset(res, 0, sizeof *res);
    res->cls = OSC_RES_REFUSED;
    res->refused_code = (uint8_t)code;
}

void ck_osc_launch(const uint8_t *unit, size_t unit_len, const struct osc_accept *a,
                   const struct ck_osc_launch_req *rq, struct osc_result *res, struct ck_osc_launch_info *info)
{
    struct ck_osc_launch_info local;
    if (!info)
        info = &local;
    memset(info, 0, sizeof *info);
    info->slot_free_after = 1;
    info->tables_zeroed = 1; /* a refusal built no tables */
    refuse(res, OSC_RESOURCE_UNAVAILABLE);
    int fi = osc_unit_lookup(a, rq->name, rq->name_len);
    if (fi < 0) {
        refuse(res, OSC_LAUNCH_BAD_ENTRY);
        return;
    }
    const struct osc_entry *e = &a->entry[fi];
    /* spec 8.2 step 16: a signer-declared budget above a launcher hard maximum is LIMIT_EXCEEDED, before any
     * reservation. max_stack_bytes is the only declared budget the launcher bounds: cpu_ticks is only lowered by
     * the caller cap (max_ticks), and pool_slots is not bounded because no pool service is provided (a call to
     * one ends OUTCOME_UNKNOWN). Real reservation failures below keep 30. */
    if (!osc_launch_stack_ok(a->max_stack_bytes, CK_OSC_STACK_MAX_BYTES)) {
        refuse(res, OSC_LIMIT_EXCEEDED);
        return;
    }
    uint64_t in_va = ck_osc_va_in(), ws_va = ck_osc_va_ws();
    /* The workspace is mapped read-write into EL0, so it must be memory the caller owns: refuse (30, nothing
     * mapped) a range over the cap, null, not page aligned, or overlapping the launcher's own state (slot0: page
     * tables, code copy, runtime, stack) or the caller's input buffer. The kernel has no allowed region for
     * workspaces, so ownership beyond that is the caller's promise (osc_task.h). */
    if (rq->ws && rq->ws->pages && osc_launch_ws_pages_ok(rq->ws->pages) && rq->ws->mem &&
        (!osc_launch_disjoint((uintptr_t)rq->ws->mem, (uint64_t)rq->ws->pages * CK_OSC_PAGE, (uintptr_t)&slot0, sizeof slot0) ||
         !osc_launch_disjoint((uintptr_t)rq->ws->mem, (uint64_t)rq->ws->pages * CK_OSC_PAGE, (uintptr_t)rq->in, rq->in_len))) {
        refuse(res, OSC_RESOURCE_UNAVAILABLE);
        return;
    }
    if (rq->ws && (!osc_launch_ws_pages_ok(rq->ws->pages) || (rq->ws->pages && (!rq->ws->mem || ((uintptr_t)rq->ws->mem & 4095))))) {
        refuse(res, OSC_RESOURCE_UNAVAILABLE); /* workspace over the cap or unusable: nothing ran */
        return;
    }
    uint64_t ws_len = rq->ws ? (uint64_t)rq->ws->pages * CK_OSC_PAGE : 0;
    if (rq->nargs > 6 || !osc_launch_args_ok(e->reg_kind, e->nregs, rq->args, rq->nargs) ||
        !osc_launch_ranges_owned(e->reg_kind, e->nregs, rq->args, in_va, rq->in_len, ws_va, ws_len)) {
        refuse(res, OSC_LAUNCH_ARG_SHAPE);
        return;
    }
    /* reservation: code size, input size, busy slot, no base: RESOURCE_UNAVAILABLE and nothing runs */
    uint64_t base = get_base();
    uint32_t stack = a->max_stack_bytes;
    if (!base || slot0.used || run.active || a->code_len > CK_OSC_CODE_MAX_BYTES ||
        rq->in_len > CK_OSC_IN_MAX_BYTES || (rq->in_len && !rq->in) || (uint64_t)a->code_off + a->code_len > unit_len ||
        e->code_offset >= a->code_len || (e->code_offset & 3))
        return;
    struct slot *s = &slot0;
    s->used = 1;
    /* private copy of the code, hashed again before it is made executable (spec 8.2) */
    memset(s->code, 0, sizeof s->code);
    memcpy(s->code, unit + a->code_off, a->code_len);
    uint8_t dig[32];
    sha256_hash(s->code, a->code_len, dig);
    if (memcmp(dig, a->code_sha256, 32) != 0) {
        memset(s->code, 0, sizeof s->code);
        s->used = 0;
        refuse(res, OSC_CODE_HASH_MISMATCH);
        return;
    }
    /* tables: kernel root copied (EL1-only), one free L0 slot chained to two L3 tables */
    memcpy(s->l0, (const void *)(uintptr_t)ck_mm_report()->root, sizeof s->l0);
    unsigned idx = (unsigned)(base >> 39);
    memset(s->l1, 0, sizeof s->l1);
    memset(s->l2, 0, sizeof s->l2);
    memset(s->l3a, 0, sizeof s->l3a);
    memset(s->l3b, 0, sizeof s->l3b);
    s->l0[idx] = (uint64_t)(uintptr_t)s->l1 | PTE_TABLE;
    s->l1[0] = (uint64_t)(uintptr_t)s->l2 | PTE_TABLE;
    s->l2[0] = (uint64_t)(uintptr_t)s->l3a | PTE_TABLE;
    s->l2[1] = (uint64_t)(uintptr_t)s->l3b | PTE_TABLE;
    uint64_t rt_code_va = base + OFF_RT_CODE, code_va = base + OFF_CODE, stack_top = base + OFF_STACK_TOP;
    /* runtime: OscRt table (13 pointers) and the stubs `svc #i` */
    memset(s->rt_tab, 0, sizeof s->rt_tab);
    memset(s->rt_code, 0, sizeof s->rt_code);
    for (unsigned i = 0; i < OSC_RT_SERVICES; i++)
        ((uint64_t *)(void *)s->rt_tab)[i] = rt_code_va + (uint64_t)i * OSC_RT_STUB_BYTES;
    for (unsigned i = 0; i < OSC_RT_STUBS; i++)
        ((uint32_t *)(void *)s->rt_code)[2 * i] = 0xd4000001u | (i << 5); /* svc #i */
    memset(s->in, 0, sizeof s->in);
    if (rq->in_len)
        memcpy(s->in, rq->in, rq->in_len);
    memset(s->stack, 0, sizeof s->stack);
    unsigned spages = (stack + CK_OSC_PAGE - 1) / CK_OSC_PAGE, cpages = (a->code_len + CK_OSC_PAGE - 1) / CK_OSC_PAGE;
    map(s->l3a, 1, s->rt_tab, ATTR_RO);
    map(s->l3a, 2, s->rt_code, ATTR_RX);
    for (unsigned i = 0; i < cpages; i++)
        map(s->l3a, 16 + i, s->code + i * CK_OSC_PAGE, ATTR_RX);
    map(s->l3b, 0, s->in, ATTR_RO);
    if (rq->ws)
        for (unsigned i = 0; i < rq->ws->pages; i++)
            map(s->l3b, 16 + i, rq->ws->mem + i * CK_OSC_PAGE, ATTR_RW);
    for (unsigned i = 0; i < spages; i++)
        map(s->l3b, 512 - spages + i, s->stack + (CK_OSC_STACK_MAX_BYTES / CK_OSC_PAGE - spages + i) * CK_OSC_PAGE,
            ATTR_RW);
    info->pages_mapped = count_mapped(s);
    clean_range(s, 5 * 4096, 0);
    clean_range(s->rt_tab, sizeof s->rt_tab, 0);
    clean_range(s->rt_code, sizeof s->rt_code, 1);
    clean_range(s->in, sizeof s->in, 0);
    clean_range(s->code, sizeof s->code, 1);
    clean_range(s->stack, sizeof s->stack, 0);
    if (rq->ws)
        clean_range(rq->ws->mem, (size_t)rq->ws->pages * CK_OSC_PAGE, 0);

    /* registers: arguments in x0..x5, OscRt in x7, return stub in x30; nothing else */
    uint64_t regs[31] = { 0 };
    for (unsigned i = 0; i < e->nregs; i++)
        regs[i] = rq->args[i];
    regs[7] = base + OFF_RT_TAB;
    regs[30] = rt_code_va + (uint64_t)OSC_SVC_RETURN * OSC_RT_STUB_BYTES;
    info->budget = osc_launch_budget(a->cpu_ticks, rq->max_ticks);

    int (*old_sync)(struct ck_frame *, uint64_t) = ck_lower_sync;
    struct ck_frame *(*old_tick)(struct ck_frame *) = ck_tick_switch;
    uint64_t kttbr = ck_rd(ttbr0_el1), cpacr = ck_rd(cpacr_el1), cntkctl = ck_rd(cntkctl_el1);
    memset(&run, 0, sizeof run);
    run.budget = info->budget;
    run.rt_code_va = rt_code_va;
    ck_lower_sync = launch_sync;
    ck_tick_switch = launch_tick;
    uint64_t hz = ck_rd(cntfrq_el0);
    ck_wr(cpacr_el1, (cpacr & ~(3ull << 20)) | (1ull << 20)); /* FP/SIMD traps at EL0 */
    /* EL0 must not touch the timers or counters: the budget timer is the kernel's, whatever firmware left in
     * CNTKCTL_EL1. Clear EL0PCTEN/EL0VCTEN (bits 0,1: counter reads), EVNTEN/EVNTDIR (2,3: event stream) and
     * EL0VTEN/EL0PTEN (8,9: timer registers); the loader clears only 8 and 9 (artifact_loader.c). */
    ck_wr(cntkctl_el1, cntkctl & ~0x30Full);
    swap_ttbr0((uint64_t)(uintptr_t)s->l0);
    ck_wr(cntp_cval_el0, ck_rd(cntpct_el0) + (hz ? hz / 100 : 625000));
    ck_wr(cntp_ctl_el0, 1);
    ck_isb();
    run.active = 1;
    ck_el0_enter(code_va + e->code_offset, stack_top, regs);
    run.active = 0;
    ck_wr(cntp_ctl_el0, 0);
    ck_isb();
    swap_ttbr0(kttbr);
    ck_wr(cpacr_el1, cpacr);
    ck_wr(cntkctl_el1, cntkctl);
    ck_isb();
    ck_lower_sync = old_sync;
    ck_tick_switch = old_tick;
    if (run.done) {
        *res = run.res;
    } else { /* the task came back without an event the kernel saw */
        struct osc_event lost = { OSC_EV_LOST, 0, 0, 0, 0 };
        osc_launch_classify(&lost, rt_code_va, res);
    }
    if (res->cls == OSC_RES_RETURNED && e->ret_kind == 0)
        res->value = 0; /* a void function reports 0 (spec 9.3) */
    res->ticks = run.ticks;

    /* teardown: tables, runtime, input, code and stack are cleared; the caller's workspace stays */
    memset(s->l0, 0, sizeof s->l0);
    memset(s->l1, 0, sizeof s->l1);
    memset(s->l2, 0, sizeof s->l2);
    memset(s->l3a, 0, sizeof s->l3a);
    memset(s->l3b, 0, sizeof s->l3b);
    memset(s->rt_tab, 0, sizeof s->rt_tab);
    memset(s->rt_code, 0, sizeof s->rt_code);
    memset(s->in, 0, sizeof s->in);
    memset(s->code, 0, sizeof s->code);
    memset(s->stack, 0, sizeof s->stack);
    clean_range(s, sizeof *s, 1);
    info->tables_zeroed = count_mapped(s) + (unsigned)(s->l0[idx] != 0) == 0;
    s->used = 0;
    info->slot_free_after = !s->used;
}

int ck_osc_result_str(const struct osc_result *r, char *buf, size_t n)
{
    switch (r->cls) {
    case OSC_RES_RETURNED:
        return ck_snprintf(buf, n, "RETURNED value=%llu", (unsigned long long)r->value);
    case OSC_RES_TRAPPED:
        return ck_snprintf(buf, n, "TRAPPED trap_code=%u", (unsigned)r->trap_code);
    case OSC_RES_UNKNOWN:
        return ck_snprintf(buf, n, "OUTCOME_UNKNOWN unknown_reason=%u", (unsigned)r->unknown_reason);
    case OSC_RES_REFUSED:
        return ck_snprintf(buf, n, "REFUSED_AT_ADMISSION code=%u name=%s", (unsigned)r->refused_code,
                           osc_code_name(r->refused_code));
    default:
        return ck_snprintf(buf, n, "UNCLASSIFIED");
    }
}

/* Where the launcher keeps its own state, so the selftest can aim a workspace at it. */
void ck_osc_state_range(uint64_t *addr, uint64_t *len)
{
    *addr = (uint64_t)(uintptr_t)&slot0;
    *len = sizeof slot0;
}
