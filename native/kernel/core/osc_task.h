/* osc_task.h -- launch an admitted OSC unit as an EL0 task (OSC_UNIT_ARTIFACT.md section 9), C3-3a.
 * Admission (osc_admit.c) never maps anything; this does, for one function call at a time. QEMU only:
 * nothing here is physical. See docs/osc-launch.md. */
#ifndef AIENOS_CK_OSC_TASK_H
#define AIENOS_CK_OSC_TASK_H
#include <stddef.h>
#include <stdint.h>
#include "osc_launch.h"
#include "osc_unit.h"

#define CK_OSC_PAGE 4096u
#define CK_OSC_CODE_MAX_BYTES (16u * CK_OSC_PAGE)  /* launcher hard maximum (stricter than the spec's 262144) */
#define CK_OSC_STACK_MAX_BYTES (16u * CK_OSC_PAGE) /* a unit declaring more is refused RESOURCE_UNAVAILABLE */
#define CK_OSC_IN_MAX_BYTES CK_OSC_PAGE

/* A caller-owned workspace for `cells` arguments: `pages` 4 KiB pages of page-aligned caller memory starting at
 * `mem`, 0 to OSC_WS_MAX_PAGES (0 = no workspace). It is mapped read-write (never executable) into the task for the
 * call and is NOT cleared by teardown: state a unit leaves in it is there for the next call that is given the same
 * workspace. A workspace over the cap, or with unaligned or null memory, is refused 30 before the first instruction. */
/* A workspace is mapped read-write (never executable) into EL0 as it is, so it MUST be memory the caller owns
 * and nothing else uses: page aligned, not null, not overlapping the launcher's own state or the input buffer
 * (refused 30, nothing mapped). The kernel has no region it restricts workspaces to, so beyond those checks it
 * trusts the caller. It is not cleared at teardown. */
struct ck_osc_ws {
    uint8_t *mem;
    uint32_t pages;
};

struct ck_osc_launch_req {
    const char *name; /* exact function name (osc_unit_lookup) */
    size_t name_len;
    unsigned nargs;
    uint64_t args[6]; /* a bytes slice is (ck_osc_va_in() + k, len), a cells slice (ck_osc_va_ws() + k, n) */
    const uint8_t *in; /* read-only input, copied to the task's input window; at most CK_OSC_IN_MAX_BYTES */
    size_t in_len;
    struct ck_osc_ws *ws; /* caller-owned workspace, or NULL */
    uint64_t max_ticks;   /* caller cap on the budget, 0 = the unit's declared cpu_ticks only */
};

struct ck_osc_launch_info {
    uint64_t budget;          /* ticks granted */
    unsigned pages_mapped;    /* user pages that were mapped while the task existed */
    int tables_zeroed;        /* after teardown every page-table entry of the task is zero and its L0 slot is clear (says nothing about frame contents) */
    int slot_free_after;      /* the task slot is reusable */
};

/* Unit-space addresses of the input window and the workspace window (the same for every launch). 0 if the
 * kernel has no free address-space slot to build them in. */
uint64_t ck_osc_va_in(void);
uint64_t ck_osc_va_ws(void);

/* Launch the function rq->name of the accepted unit (bytes `unit`, verdict *a from osc_unit_admit on the
 * same bytes) and wait for it. *res is always filled. Refusals (40 unknown name, 41 argument shape or
 * range, 30 resources, 16 code hash) mean no unit instruction ran. */
void ck_osc_launch(const uint8_t *unit, size_t unit_len, const struct osc_accept *a,
                   const struct ck_osc_launch_req *rq, struct osc_result *res, struct ck_osc_launch_info *info);

/* "RETURNED value=..", "TRAPPED trap_code=..", "OUTCOME_UNKNOWN reason=..", "REFUSED code=.." */
int ck_osc_result_str(const struct osc_result *r, char *buf, size_t n);
#endif
