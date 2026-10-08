/* osc_launch.c -- see osc_launch.h. Pure. */
#include "osc_launch.h"

#define MAXR 6u

static int is_slice(unsigned k) { return k == 11 || k == 12; }

static int fits(unsigned k, uint64_t v)
{
    switch (k) {
    case 1: return v <= 1;
    case 2: return v <= 0xff;
    case 3: return v <= 0xffff;
    case 4: return v <= 0xffffffffull;
    case 6: return (int64_t)v == (int8_t)v;
    case 7: return (int64_t)v == (int16_t)v;
    case 8: return (int64_t)v == (int32_t)v;
    default: return 1; /* 5, 9 and the two registers of a slice */
    }
}

int osc_launch_args_ok(const uint8_t *kinds, unsigned nregs, const uint64_t *args, unsigned nargs)
{
    if (nregs > MAXR || nargs != nregs)
        return 0;
    for (unsigned p = 0; p < nregs; p++)
        if (!is_slice(kinds[p]) && !fits(kinds[p], args[p]))
            return 0;
    for (unsigned p = 0; p + 1 < nregs; p++) {
        if (!is_slice(kinds[p]))
            continue;
        uint64_t ptr = args[p], n = args[p + 1], sz = n * (kinds[p] == 12 ? 8u : 1u);
        if (kinds[p] == 12 && (n > UINT64_MAX / 8 || (n && (ptr & 7))))
            return 0;
        if ((n && !ptr) || sz > UINT64_MAX - ptr)
            return 0;
        for (unsigned q = 0; q + 1 < nregs; q++) {
            if (q == p || !is_slice(kinds[q]))
                continue;
            if (kinds[p] != 12 && kinds[q] != 12)
                continue;
            uint64_t qn = args[q + 1], qsz = qn * (kinds[q] == 12 ? 8u : 1u);
            if (!sz || !qn || (kinds[q] == 12 && qn > UINT64_MAX / 8) || qsz > UINT64_MAX - args[q])
                continue;
            if (ptr < args[q] + qsz && args[q] < ptr + sz)
                return 0;
        }
    }
    return 1;
}

static int inside(uint64_t ptr, uint64_t size, uint64_t base, uint64_t len)
{
    return ptr >= base && ptr - base <= len && size <= len - (ptr - base);
}

int osc_launch_ranges_owned(const uint8_t *kinds, unsigned nregs, const uint64_t *args, uint64_t in_va,
                            uint64_t in_len, uint64_t ws_va, uint64_t ws_len)
{
    for (unsigned p = 0; p + 1 < nregs; p++) {
        if (!is_slice(kinds[p]))
            continue;
        uint64_t ptr = args[p], n = args[p + 1];
        if (n == 0)
            continue; /* a zero-length range is never dereferenced */
        if (kinds[p] == 12) {
            if (n > UINT64_MAX / 8 || !inside(ptr, n * 8, ws_va, ws_len))
                return 0;
        } else if (!inside(ptr, n, in_va, in_len)) {
            return 0;
        }
    }
    return 1;
}

uint64_t osc_launch_budget(uint64_t unit_ticks, uint64_t caller_cap)
{
    return caller_cap && caller_cap < unit_ticks ? caller_cap : unit_ticks;
}

int osc_launch_budget_expired(uint64_t seen, uint64_t budget)
{
    return seen >= budget;
}

static int fault_class(uint64_t ec)
{
    switch (ec) {
    case 0x00: /* unknown / undefined instruction */
    case 0x07: /* FP or SIMD access */
    case 0x0e: /* illegal execution state */
    case 0x18: /* MSR, MRS or system instruction */
    case 0x20: /* instruction abort from EL0 */
    case 0x22: /* PC alignment */
    case 0x24: /* data abort from EL0 */
    case 0x26: /* SP alignment */
    case 0x3c: /* brk */
        return 1;
    default:
        return 0;
    }
}

static void unknown(struct osc_result *r, uint8_t why)
{
    r->cls = OSC_RES_UNKNOWN;
    r->unknown_reason = why;
}

void osc_launch_classify(const struct osc_event *e, uint64_t rt_code_va, struct osc_result *r)
{
    r->cls = 0;
    r->trap_code = r->unknown_reason = r->refused_code = 0;
    r->value = 0;
    switch (e->kind) {
    case OSC_EV_SVC: {
        uint64_t imm = e->esr & 0xffff, ec = (e->esr >> 26) & 0x3f;
        uint64_t site = e->elr - 4;
        uint64_t off = site - rt_code_va;
        if (ec != 0x15 || e->elr < 4 || site < rt_code_va || off >= (uint64_t)OSC_RT_STUBS * OSC_RT_STUB_BYTES ||
            off % OSC_RT_STUB_BYTES || imm != off / OSC_RT_STUB_BYTES) {
            unknown(r, OSC_UNK_FAULT); /* an SVC outside the runtime entry stubs is refused (9.1.1 item 1) */
            return;
        }
        if (imm == OSC_SVC_RETURN) {
            r->cls = OSC_RES_RETURNED;
            r->value = e->x0;
        } else if (imm == OSC_SVC_TRAP) {
            if (e->x1 >= 1 && e->x1 <= OSC_TRAP_MAX) {
                r->cls = OSC_RES_TRAPPED;
                r->trap_code = (uint8_t)e->x1;
            } else {
                unknown(r, OSC_UNK_TRAP_CODE_UNKNOWN);
            }
        } else {
            unknown(r, OSC_UNK_OTHER); /* alloc, arenas, pools: not provided by this cut */
        }
        return;
    }
    case OSC_EV_SYNC:
        unknown(r, fault_class((e->esr >> 26) & 0x3f) ? OSC_UNK_FAULT : OSC_UNK_OTHER);
        return;
    case OSC_EV_BUDGET:
        unknown(r, OSC_UNK_TICK_OVERRUN);
        return;
    case OSC_EV_LOST:
        unknown(r, OSC_UNK_LAUNCH_LOST);
        return;
    default:
        unknown(r, OSC_UNK_OTHER);
        return;
    }
}
