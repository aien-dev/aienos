/* osc_launch.h -- the pure parts of launching an admitted OSC unit (OSC_UNIT_ARTIFACT.md section 9):
 * the argument rule (9.2), range ownership (9.1.1 item 4), the ticks budget, and the classification
 * of what an EL0 unit did into the four result classes (9.3). No globals, no I/O, no MMU: host tested
 * (tests/test_osc_launch.c) and used by core/osc_launch.c, which maps and runs the task.
 * QEMU only so far; nothing here is physical. */
#ifndef AIENOS_CK_OSC_LAUNCH_H
#define AIENOS_CK_OSC_LAUNCH_H
#include <stddef.h>
#include <stdint.h>

/* The OscRt vtable of runtime_abi_version 1 has 13 entries at offsets 0..96 (osc_rt.h); entry i is
 * reached through the runtime stub i. Stub 2 is `trap` (offset 16). Stub 13 is not in the vtable: it is
 * the return address the launcher hands the entry function in x30. */
#define OSC_RT_SERVICES 13u
#define OSC_SVC_TRAP 2u
#define OSC_SVC_RETURN 13u
#define OSC_RT_STUBS 14u
#define OSC_RT_STUB_BYTES 8u /* `svc #i` then a spare word */
#define OSC_TRAP_MAX 14u

/* Kernel cap on a caller-owned workspace: 32 pages = 128 KiB. It bounds the user pages and page-table slots one
 * task can map (the workspace window is 32 of the 512 leaf entries of its L3 table, clear of the stack), and the
 * bss a caller must set aside. Large enough for the OSH resumable workspace (11,456 cells = 23 pages). The size is
 * the caller's choice and never comes from the container. */
#define OSC_WS_MAX_PAGES 32u

/* Section 9.3: four classes, closed. */
enum { OSC_RES_RETURNED = 1, OSC_RES_TRAPPED = 2, OSC_RES_REFUSED = 3, OSC_RES_UNKNOWN = 4 };
/* unknown_reason, section 9.3 (diagnostic only; never changes the class). */
enum { OSC_UNK_FAULT = 1, OSC_UNK_TICK_OVERRUN = 2, OSC_UNK_LAUNCH_LOST = 3, OSC_UNK_TRAP_CODE_UNKNOWN = 4,
       OSC_UNK_OTHER = 255 };

struct osc_result {
    uint8_t cls;            /* OSC_RES_* */
    uint8_t trap_code;      /* TRAPPED: 1..14 */
    uint8_t unknown_reason; /* OUTCOME_UNKNOWN: OSC_UNK_*; 0 for every other class */
    uint8_t refused_code;   /* REFUSED_AT_ADMISSION: section 8.3 code (40, 41, 30...) */
    uint64_t value;         /* RETURNED: x0 */
    uint64_t ticks;         /* scheduler ticks the unit ran (diagnostic) */
};

/* Section 9.2 items 1 to 4, exactly the rule of tools/osc-launch-check.c. kinds are the entry
 * record's reg_kind[0..nregs); args are the register values in order; nargs must equal nregs.
 * 1 = acceptable, 0 = LAUNCH_ARG_SHAPE (41). */
int osc_launch_args_ok(const uint8_t *kinds, unsigned nregs, const uint64_t *args, unsigned nargs);

/* Section 9.1.1 item 4 (ownership, after the shape check passes): every non-empty `bytes` range lies
 * wholly in the read-only input window [in_va, in_va+in_len), every non-empty `cells` range wholly in the
 * caller's writable workspace window [ws_va, ws_va+ws_len). 1 = owned. */
int osc_launch_ranges_owned(const uint8_t *kinds, unsigned nregs, const uint64_t *args, uint64_t in_va,
                            uint64_t in_len, uint64_t ws_va, uint64_t ws_len);

/* 1 if the byte ranges [a, a+alen) and [b, b+blen) do not overlap (an empty range overlaps nothing; a
 * range that wraps the address space overlaps everything, so 0). */
int osc_launch_disjoint(uint64_t a, uint64_t alen, uint64_t b, uint64_t blen);

/* 1 if a signer-declared max_stack_bytes is within the launcher hard maximum (else LIMIT_EXCEEDED, 14). */
int osc_launch_stack_ok(uint64_t declared, uint64_t hard_max);

/* 1 if a workspace of this many pages is allowed (0 = none, up to OSC_WS_MAX_PAGES). */
int osc_launch_ws_pages_ok(uint64_t pages);

/* The ticks the task may run: the unit's declared cpu_ticks, lowered (never raised) by a nonzero caller
 * cap. One tick is one scheduler timer interrupt (10 ms, CNTFRQ/100). */
uint64_t osc_launch_budget(uint64_t unit_ticks, uint64_t caller_cap);
/* 1 once `seen` ticks have been delivered while the unit ran and that reaches the budget. */
int osc_launch_budget_expired(uint64_t seen, uint64_t budget);

/* What the kernel observed while the unit ran. */
enum { OSC_EV_SVC = 1, OSC_EV_SYNC = 2, OSC_EV_BUDGET = 3, OSC_EV_LOST = 4 };
struct osc_event {
    unsigned kind;      /* OSC_EV_* */
    uint64_t esr, elr;  /* ESR_EL1 and ELR_EL1 of the exception (SVC and SYNC) */
    uint64_t x0, x1;    /* unit registers at the exception */
};
/* Section 9.3 and 9.1.1: classify one terminating event into *r (cls, trap_code, unknown_reason, value).
 * rt_code_va is the unit-space address of runtime stub 0.
 *   - SVC from a runtime stub (elr-4 is stub i and the immediate is i): return stub -> RETURNED(x0);
 *     trap stub with x1 in 1..14 -> TRAPPED(x1); with another x1 -> UNKNOWN(TRAP_CODE_UNKNOWN); any
 *     other stub (a runtime service this cut does not provide) -> UNKNOWN(OTHER).
 *   - SVC from anywhere else: refused, UNKNOWN(FAULT). The unit has no system calls (9.1.1 item 1).
 *   - SYNC with a CPU fault class (data or instruction abort, brk, undefined, alignment, FP, system
 *     register) -> UNKNOWN(FAULT). A brk reached directly is a fault, never TRAPPED (8.4).
 *   - SYNC with any other class -> UNKNOWN(OTHER); BUDGET -> UNKNOWN(TICK_OVERRUN);
 *     LOST -> UNKNOWN(LAUNCH_LOST).
 * Nothing is ever mapped to RETURNED except the return stub. */
void osc_launch_classify(const struct osc_event *e, uint64_t rt_code_va, struct osc_result *r);

#endif
