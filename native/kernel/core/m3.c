/* m3.c -- M3 isolation checks in the C kernel core (port of the Rust kernel's
 * thread.rs, user.rs and ipc.rs demos as driven by aienos-boot handoff.rs).
 * Prints, in the Rust order:
 *   threads:   two cooperative EL1 threads on the core/sched.c run queue
 *   el0:       an EL0 task in its own address space: capability-checked write,
 *              forged handle refused, kernel-address read faults and is contained
 *   preempt:   two spinning EL1 workers switched only by the timer IRQ
 *   placement: workers placed on cores from the MADT efficiency classes
 *              (pure computation: neither kernel starts a secondary core)
 *   ipc:       two EL0 principals, typed message, attenuated delegation,
 *              forged handle refused, revoked handle refused
 * Single core, EL1h; runs with IRQs masked except inside the preempt check
 * and while EL0 runs. */
#include "acpi.h"
#include "arch.h"
#include "ck_internal.h"
#include "ipc.h"
#include "pt.h"
#include "sched.h"

#define DENIED 0xffffffffffffffffull

/* ---- vector hooks (arch/exception.c) ---- */
extern struct ck_frame *(*ck_tick_switch)(struct ck_frame *f);
extern int (*ck_lower_sync)(struct ck_frame *f, uint64_t esr);

/* ---- asm (arch/m3.S) ---- */
struct ck_ctx {
    uint64_t x19_x30[12];
    uint64_t sp;
};
void ck_ctx_switch(struct ck_ctx *from, const struct ck_ctx *to);
void ck_thread_start(void);
void ck_thread_exit(void);
void ck_el0_enter(uint64_t entry, uint64_t user_sp, const uint64_t regs[31]);
void ck_el0_resume(void);
extern const char ck_el0_demo_start[], ck_el0_demo_end[];
extern const char ck_ipc_prog_start[], ck_ipc_prog_end[];

/* ===================== cooperative threads (thread.rs) ===================== */
#define TMAX 4
static struct ck_ctx contexts[TMAX], main_ctx;
static int runnable[TMAX];
static unsigned current = TMAX;
static struct ck_sched sched;
static uint8_t thread_stack[2][8192] __attribute__((aligned(16)));
static char trace[10];
static unsigned trace_len;
static uint64_t thread_floor[TMAX]; /* stack base per thread, for the vector stack guard */
static uint64_t kernel_floor;

static void yield_now(void)
{
    unsigned from = current, target = TMAX;
    for (unsigned i = 0; i < TMAX; i++) {
        uint32_t id;
        if (ck_sched_tick(&sched, 0, &id) == 1 && id < TMAX && runnable[id] && id != from) {
            target = id;
            break;
        }
    }
    if (target == from)
        return;
    current = target;
    /* keep the vector stack guard on the stack that will run */
    ck_stack_floor = target == TMAX ? kernel_floor : thread_floor[target];
    ck_ctx_switch(from == TMAX ? &main_ctx : &contexts[from],
                  target == TMAX ? &main_ctx : &contexts[target]);
}

void ck_thread_exit(void)
{
    runnable[current] = 0;
    ck_sched_remove(&sched, current);
    for (;;)
        yield_now();
}

static int spawn(uint8_t *stack, size_t len, void (*entry)(uint64_t), uint64_t arg)
{
    for (unsigned slot = 0; slot < TMAX; slot++) {
        if (runnable[slot] || ck_sched_task(&sched, slot))
            continue;
        uint64_t sp = (((uint64_t)(uintptr_t)stack + len) & ~15ull) - 16;
        contexts[slot] = (struct ck_ctx){ .sp = sp };
        thread_floor[slot] = (uint64_t)(uintptr_t)stack;
        contexts[slot].x19_x30[0] = arg;
        contexts[slot].x19_x30[1] = (uint64_t)(uintptr_t)entry;
        contexts[slot].x19_x30[11] = (uint64_t)(uintptr_t)ck_thread_start;
        if (ck_sched_enqueue(&sched, slot, CK_PRIO_NORMAL) < 0)
            return -1;
        runnable[slot] = 1;
        return (int)slot;
    }
    return -1;
}

static void thread_worker(uint64_t tag)
{
    for (int i = 0; i < 5; i++) {
        if (trace_len < sizeof trace)
            trace[trace_len++] = tag == 0 ? 'A' : 'B';
        yield_now();
    }
}

static void check_threads(void)
{
    static const uint8_t one_class[1] = { 0 };
    ck_sched_init(&sched, 1, one_class, TMAX, 8);
    trace_len = 0;
    current = TMAX;
    int ok = spawn(thread_stack[0], sizeof thread_stack[0], thread_worker, 0) >= 0 &&
             spawn(thread_stack[1], sizeof thread_stack[1], thread_worker, 1) >= 0;
    while (ok && (runnable[0] || runnable[1] || runnable[2] || runnable[3]))
        yield_now();
    char seen[sizeof trace + 1];
    memcpy(seen, trace, trace_len);
    seen[trace_len] = 0;
    ck_printf("threads: %s interleave=%s\n",
              trace_len == 10 && !memcmp(seen, "ABABABABAB", 10) ? "ok" : "unexpected", seen);
}

/* ======================= timer preemption (thread.rs) ====================== */
static uint8_t preempt_stack[2][16384] __attribute__((aligned(16)));
static volatile uint64_t counter_a, counter_b;
static volatile int preempt_active, preempt_done;
static uint64_t preempt_switches;
static struct ck_frame *worker_frame[2], *main_frame;
static unsigned preempt_cur;

static void preempt_worker(uint64_t which)
{
    for (;;) {
        if (which)
            counter_b = counter_b + 1;
        else
            counter_a = counter_a + 1;
    }
}

/* A worker function never returns; if one did, its x30 lands here. */
static void preempt_worker_exit(void)
{
    ck_panic("preempt: worker returned");
}

static struct ck_frame *prepare_frame(uint8_t *stack, size_t len, void (*entry)(uint64_t),
                                      uint64_t arg)
{
    uint64_t top = ((uint64_t)(uintptr_t)stack + len) & ~15ull;
    struct ck_frame *f = (struct ck_frame *)(uintptr_t)(top - sizeof(struct ck_frame));
    memset(f, 0, sizeof *f);
    f->x[0] = arg;
    f->x[30] = (uint64_t)(uintptr_t)preempt_worker_exit;
    f->elr = (uint64_t)(uintptr_t)entry;
    f->spsr = 0x5; /* EL1h, DAIF clear: the next tick preempts it */
    f->vector = 5;
    return f;
}

/* Called by ck_irq_dispatch after the timer tick was re-armed and EOId.
 * Returns the frame the vector exit restores (SP moves onto that stack). */
static struct ck_frame *preempt_tick(struct ck_frame *f)
{
    if (!preempt_active)
        return f;
    if (!main_frame) {
        main_frame = f;
        preempt_cur = 0;
        ck_stack_floor = (uint64_t)(uintptr_t)preempt_stack[0];
        return worker_frame[0];
    }
    worker_frame[preempt_cur] = f;
    if (preempt_switches >= 4 && counter_a > 0 && counter_b > 0) {
        preempt_active = 0;
        preempt_done = 1;
        struct ck_frame *t = main_frame;
        main_frame = 0;
        ck_stack_floor = kernel_floor;
        return t;
    }
    preempt_cur ^= 1;
    preempt_switches++;
    ck_stack_floor = (uint64_t)(uintptr_t)preempt_stack[preempt_cur];
    return worker_frame[preempt_cur];
}

static void check_preempt(void)
{
    counter_a = counter_b = 0;
    preempt_switches = 0;
    main_frame = 0;
    preempt_done = 0;
    worker_frame[0] = prepare_frame(preempt_stack[0], sizeof preempt_stack[0], preempt_worker, 0);
    worker_frame[1] = prepare_frame(preempt_stack[1], sizeof preempt_stack[1], preempt_worker, 1);
    uint64_t hz = ck_rd(cntfrq_el0);
    int timed_out = 0;
    if (hz) {
        preempt_active = 1;
        ck_tick_switch = preempt_tick;
        uint64_t start = ck_rd(cntpct_el0);
        ck_wr(cntp_cval_el0, start + hz / 100);
        ck_wr(cntp_ctl_el0, 1);
        ck_isb();
        ck_irq_on();
        ck_isb();
        /* Main resumes only when the dispatcher hands its frame back. The
         * timeout covers a timer that never fires (main never left). */
        while (!preempt_done) {
            if (ck_rd(cntpct_el0) - start > hz * 2) {
                timed_out = 1;
                break;
            }
        }
        ck_irq_off();
        ck_isb();
        preempt_active = 0;
        ck_tick_switch = 0;
        ck_wr(cntp_ctl_el0, 0);
        ck_isb();
        ck_stack_floor = kernel_floor;
    }
    uint64_t a = counter_a, b = counter_b;
    int ok = !timed_out && a > 0 && b > 0 && preempt_switches >= 4;
    ck_printf("preempt: %s a=%llu b=%llu switches=%llu\n", ok ? "ok" : "failed",
              (unsigned long long)a, (unsigned long long)b, (unsigned long long)preempt_switches);
}

/* ============================ placement (MADT) ============================= */
static void check_placement(void)
{
    const void *madt = ck_acpi_find("APIC");
    struct ck_cpu_topology topo;
    if (!madt || ck_madt_cpu_topology(madt, &topo)) {
        ck_puts("placement: unavailable\n");
        return;
    }
    char line[128];
    size_t n = 0;
    static const char *const names[2] = { "worker0", "worker1" };
    n += (size_t)ck_snprintf(line, sizeof line, "placement:");
    for (uint32_t i = 0; i < 2; i++) {
        uint8_t cls;
        uint32_t core;
        if (ck_place_task(&topo, i, &cls, &core) == 0)
            n += (size_t)ck_snprintf(line + n, sizeof line - n, " %s=class%u/core%u", names[i],
                                     (unsigned)cls, (unsigned)core);
        else
            n += (size_t)ck_snprintf(line + n, sizeof line - n, " %s=unplaced", names[i]);
    }
    ck_printf("%s\n", line);
}

/* ===================== EL0 address spaces (user.rs) ======================== */
struct el0_window {
    uint64_t l0[512], l1[512], l2[512], l3[512];
    uint8_t code[4096];
    uint8_t stack[4096];
} __attribute__((aligned(4096)));
static struct el0_window demo_window, ipc_window[2];

#define PTE_TABLE 3ull
#define PTE_PAGE 3ull
#define PTE_AP_EL0_RW (1ull << 6)
#define PTE_AP_EL0_RO (3ull << 6)
#define PTE_NG (1ull << 11)

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

/* Kernel L0 copied (kernel mappings stay EL1-only: AP[1] = 0), one free
 * L0 slot in the lower half chained to: page 0 = code (EL0 read-only,
 * executable at EL0, never at EL1), page 1 = stack (EL0 read-write, never
 * executable). nG: the user pages are not global. Returns the user base, 0 if
 * no L0 slot is free or the image does not fit. */
static uint64_t build_window(struct el0_window *w, const char *img, size_t len, uint64_t kroot)
{
    if (len > sizeof w->code)
        return 0;
    memcpy(w->l0, (const void *)(uintptr_t)kroot, sizeof w->l0);
    unsigned idx = 0;
    for (unsigned i = 1; i < 256 && !idx; i++)
        if (!w->l0[i])
            idx = i;
    if (!idx)
        return 0;
    memset(w->l1, 0, sizeof w->l1);
    memset(w->l2, 0, sizeof w->l2);
    memset(w->l3, 0, sizeof w->l3);
    w->l0[idx] = (uint64_t)(uintptr_t)w->l1 | PTE_TABLE;
    w->l1[0] = (uint64_t)(uintptr_t)w->l2 | PTE_TABLE;
    w->l2[0] = (uint64_t)(uintptr_t)w->l3 | PTE_TABLE;
    uint64_t common = CK_PTE_ATTRIDX(CK_MAIR_IDX_NORMAL) | CK_PTE_SH_INNER | CK_PTE_AF | PTE_NG |
                      CK_PTE_PXN;
    w->l3[0] = (uint64_t)(uintptr_t)w->code | PTE_PAGE | PTE_AP_EL0_RO | common;
    w->l3[1] = (uint64_t)(uintptr_t)w->stack | PTE_PAGE | PTE_AP_EL0_RW | common | CK_PTE_UXN;
    memset(w->code, 0, sizeof w->code);
    memcpy(w->code, img, len);
    memset(w->stack, 0, sizeof w->stack);
    clean_range(w->l0, 4 * 4096, 0);
    clean_range(w->code, sizeof w->code, 1);
    clean_range(w->stack, sizeof w->stack, 0);
    return (uint64_t)idx << 39;
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

enum { EL0_NONE, EL0_DEMO, EL0_IPC };
static int el0_mode;
static uint64_t el0_exit;
static uint64_t el0_code_base;  /* user VA of the running task's code page */
static const uint8_t *el0_code; /* kernel view of that page */

static void el0_to_kernel(struct ck_frame *f, uint64_t code)
{
    el0_exit = code;
    f->elr = (uint64_t)(uintptr_t)ck_el0_resume;
    f->spsr = 0x3c5; /* EL1h, DAIF masked (the Rust kernel resumes with 0x5) */
}

/* Runs one EL0 task to its exit on the given address space. */
static uint64_t run_el0(uint64_t root, uint64_t base, const struct el0_window *w, int mode,
                        const uint64_t regs[31])
{
    uint64_t kttbr = ck_rd(ttbr0_el1), cpacr = ck_rd(cpacr_el1);
    el0_mode = mode;
    el0_exit = DENIED;
    el0_code_base = base;
    el0_code = w->code;
    ck_wr(cpacr_el1, (cpacr & ~(3ull << 20)) | (1ull << 20)); /* FP/SIMD traps at EL0 */
    swap_ttbr0(root);
    ck_el0_enter(base, base + 0x2000, regs);
    swap_ttbr0(kttbr);
    ck_wr(cpacr_el1, cpacr);
    ck_isb();
    el0_mode = EL0_NONE;
    return el0_exit;
}

/* ---- el0 check (user.rs run_demo) ---- */
#define CONSOLE_RESOURCE 1u
static struct ck_cap_table user_caps;
static uint64_t authorized_raw;
static int write_granted, forged_denied, fault_contained;
static uint64_t el0_probe_addr; /* the one kernel address the demo task is expected to fault on */
#define EL0_FAULT_KILLED 0xfa17ull /* exit code of a task killed by an unexpected fault */

static int user_bytes(uint64_t addr, uint64_t len, const uint8_t **out)
{
    if (addr < el0_code_base || len > 4096 || addr - el0_code_base > 4096 - len)
        return -1;
    *out = el0_code + (addr - el0_code_base);
    return 0;
}

static void demo_write(struct ck_frame *f)
{
    uint64_t raw = f->x[0];
    struct ck_handle h;
    if (ck_handle_from_raw(raw, &h)) {
        forged_denied = 1;
        f->x[0] = DENIED;
        return;
    }
    uint32_t res = 0;
    int allowed = ck_cap_lookup(&user_caps, h, CK_R_WRITE, &res) == 0 && res == CONSOLE_RESOURCE;
    const uint8_t *bytes;
    if (allowed && user_bytes(f->x[1], f->x[2], &bytes) == 0) {
        char chunk[65];
        for (uint64_t at = 0; at < f->x[2]; at += 64) {
            uint64_t n = f->x[2] - at < 64 ? f->x[2] - at : 64;
            memcpy(chunk, bytes + at, n);
            chunk[n] = 0;
            ck_puts(chunk);
        }
        write_granted = 1;
        f->x[0] = 0;
        return;
    }
    if (raw != authorized_raw)
        forged_denied = 1;
    f->x[0] = DENIED;
}

static void check_el0(uint64_t kroot)
{
    write_granted = forged_denied = fault_contained = 0;
    ck_cap_init(&user_caps, 0x454c3001u, 4);
    struct ck_handle h;
    uint64_t base = build_window(&demo_window, ck_el0_demo_start,
                                 (size_t)(ck_el0_demo_end - ck_el0_demo_start), kroot);
    if (ck_cap_insert(&user_caps, CONSOLE_RESOURCE, CK_R_WRITE, &h) || !base) {
        ck_puts("el0: failed setup\n");
        return;
    }
    authorized_raw = ck_handle_raw(h);
    uint64_t regs[31] = { 0 };
    regs[0] = authorized_raw;
    regs[3] = (uint64_t)(uintptr_t)ck_el0_enter; /* kernel text: EL1-only */
    el0_probe_addr = regs[3];
    uint64_t code = run_el0((uint64_t)(uintptr_t)demo_window.l0, base, &demo_window, EL0_DEMO, regs);
    int ok = write_granted && forged_denied && fault_contained && code == 0;
    ck_printf("el0: %s write=%s forged=%s fault=%s exit=%llu\n", ok ? "ok" : "failed",
              write_granted ? "granted" : "denied", forged_denied ? "denied" : "accepted",
              fault_contained ? "contained" : "uncontained", (unsigned long long)code);
}

/* ---- ipc check (user.rs run_ipc_demo) ---- */
static struct ck_ipc ipc;
static unsigned ipc_principal, ipc_phase;
static int msg_delivered, cap_delegated, rights_attenuated, ipc_forged, ipc_revoked;
static uint64_t sent_kind, sent_p0, sent_p1, sent_obj, child_raw;

static void ipc_handle_refused(void)
{
    if (ipc_phase)
        ipc_revoked = 1;
    else
        ipc_forged = 1;
}

static void dispatch_ipc(struct ck_frame *f)
{
    struct ck_handle h;
    uint64_t nr = f->x[8];
    if (nr == 2) { /* exit */
        el0_to_kernel(f, f->x[0]);
        return;
    }
    if (nr < 3 || nr > 7) {
        f->x[0] = DENIED;
        return;
    }
    if (ck_handle_from_raw(f->x[0], &h)) {
        if (nr == 6)
            ipc_handle_refused();
        f->x[0] = DENIED;
        return;
    }
    switch (nr) {
    case 3: { /* channel send */
        struct ck_msg m = { 0 };
        m.kind = (uint32_t)f->x[1];
        m.payload[0] = f->x[2];
        m.payload[1] = f->x[3];
        m.payload[2] = f->x[4];
        m.region_base = f->x[5];
        m.region_pages = (uint32_t)f->x[6];
        m.object = f->x[7];
        if (ck_ipc_send(&ipc, ipc_principal, h, &m) == 0) {
            sent_kind = f->x[1];
            sent_p0 = f->x[2];
            sent_p1 = f->x[3];
            sent_obj = f->x[7];
            f->x[0] = 0;
        } else {
            f->x[0] = DENIED;
        }
        break;
    }
    case 4: { /* channel receive */
        struct ck_msg m;
        if (ck_ipc_recv(&ipc, ipc_principal, h, &m)) {
            f->x[0] = DENIED;
            break;
        }
        if (m.kind == sent_kind && m.payload[0] == sent_p0 && m.payload[1] == sent_p1 &&
            m.object == sent_obj)
            msg_delivered = 1;
        f->x[0] = 0;
        f->x[1] = m.kind;
        f->x[2] = m.payload[0];
        f->x[3] = m.payload[1];
        f->x[4] = m.payload[2];
        f->x[5] = m.object;
        break;
    }
    case 5: { /* delegate: x1 = target principal index, x2 = wire rights */
        struct ck_handle child;
        if ((f->x[2] & ~(uint64_t)CK_R_ALL) || f->x[1] > 1 ||
            ck_ipc_delegate(&ipc, ipc_principal, h, (unsigned)f->x[1], (unsigned)f->x[2], &child)) {
            f->x[0] = DENIED;
            break;
        }
        cap_delegated = 1;
        child_raw = ck_handle_raw(child);
        f->x[0] = 0;
        break;
    }
    case 6: { /* object read */
        uint64_t v;
        int r = ck_ipc_object_read(&ipc, ipc_principal, h, f->x[1], &v);
        if (r == 0) {
            f->x[0] = v;
        } else {
            if (r == CK_IPC_INVALID_HANDLE)
                ipc_handle_refused();
            f->x[0] = DENIED;
        }
        break;
    }
    case 7: { /* object write */
        int r = ck_ipc_object_write(&ipc, ipc_principal, h, f->x[1], f->x[2]);
        if (r == CK_IPC_MISSING_RIGHTS)
            rights_attenuated = 1;
        f->x[0] = r ? DENIED : 0;
        break;
    }
    }
}

static int lower_sync(struct ck_frame *f, uint64_t esr)
{
    if (el0_mode == EL0_NONE || (f->spsr & 0xf) != 0)
        return -1; /* not from an M3 EL0 task: fatal path */
    uint64_t ec = (esr >> 26) & 0x3f;
    if (ec == 0x15 && (esr & 0xffff) == 0) {
        if (el0_mode == EL0_IPC)
            dispatch_ipc(f);
        else if (f->x[8] == 1)
            demo_write(f);
        else if (f->x[8] == 2)
            el0_to_kernel(f, f->x[0]);
        else
            f->x[0] = DENIED;
    } else if (ec == 0x24) { /* data abort from EL0 */
        uint64_t far;
        __asm__ volatile("mrs %0, far_el1" : "=r"(far));
        if (el0_mode == EL0_DEMO && !fault_contained && far == el0_probe_addr) {
            /* the demo's one expected probe of kernel memory: contained,
             * the load is skipped and the task continues to its exit */
            fault_contained = 1;
            f->elr += 4;
        } else {
            /* any other EL0 fault kills the task; the kernel keeps running */
            el0_to_kernel(f, EL0_FAULT_KILLED);
        }
    } else {
        el0_to_kernel(f, DENIED);
    }
    return 0;
}

static void check_ipc(uint64_t kroot)
{
    msg_delivered = cap_delegated = rights_attenuated = ipc_forged = ipc_revoked = 0;
    child_raw = 0;
    struct ck_handle a_send, a_obj, b_recv;
    ck_ipc_reset(&ipc, &a_send, &a_obj, &b_recv);
    size_t len = (size_t)(ck_ipc_prog_end - ck_ipc_prog_start);
    uint64_t base_a = build_window(&ipc_window[0], ck_ipc_prog_start, len, kroot);
    uint64_t base_b = build_window(&ipc_window[1], ck_ipc_prog_start, len, kroot);
    if (!base_a || !base_b) {
        ck_puts("ipc: failed setup\n");
        return;
    }
    uint64_t root_a = (uint64_t)(uintptr_t)ipc_window[0].l0;
    uint64_t root_b = (uint64_t)(uintptr_t)ipc_window[1].l0;
    uint64_t regs[31] = { 0 };

    /* principal A: send the typed message, delegate an attenuated copy */
    ipc_principal = 0;
    ipc_phase = 0;
    regs[0] = regs[22] = 1;
    regs[20] = ck_handle_raw(a_send);
    regs[21] = ck_handle_raw(a_obj);
    uint64_t exit_a = run_el0(root_a, base_a, &ipc_window[0], EL0_IPC, regs);

    /* principal B, phase 0: receive, read, attempt write, forge */
    ipc_principal = 1;
    regs[0] = regs[22] = 2;
    regs[20] = ck_handle_raw(b_recv);
    regs[21] = child_raw;
    uint64_t exit_b0 = run_el0(root_b, base_b, &ipc_window[1], EL0_IPC, regs);

    /* the kernel revokes A's ancestor; B's derived handle must die */
    int revoke = ck_ipc_revoke(&ipc, 0, a_obj);

    /* principal B, phase 1: the derived handle no longer resolves */
    ipc_phase = 1;
    regs[0] = regs[22] = 0x102;
    uint64_t exit_b1 = run_el0(root_b, base_b, &ipc_window[1], EL0_IPC, regs);

    int ok = msg_delivered && cap_delegated && rights_attenuated && ipc_forged && ipc_revoked &&
             revoke == 0 && exit_a == 0 && exit_b0 == 0 && exit_b1 == 0;
    ck_printf("ipc: %s message=%s cap=%s rights=%s forged=%s revoked=%s\n", ok ? "ok" : "failed",
              msg_delivered ? "delivered" : "missed", cap_delegated ? "delegated" : "failed",
              rights_attenuated ? "attenuated" : "escalated", ipc_forged ? "denied" : "accepted",
              ipc_revoked ? "denied" : "accepted");
    ck_printf("ipc_detail: exit_a=0x%llx exit_b0=0x%llx exit_b1=0x%llx child=0x%llx revoke=%d\n",
              (unsigned long long)exit_a, (unsigned long long)exit_b0,
              (unsigned long long)exit_b1, (unsigned long long)child_raw, revoke);
}

void ck_m3_run(void)
{
    kernel_floor = ck_stack_floor;
    uint64_t kroot = ck_mm_report()->root;
    ck_lower_sync = lower_sync;
    ck_set_stage("m3_threads");
    check_threads();
    ck_set_stage("m3_el0");
    check_el0(kroot);
    ck_set_stage("m3_preempt");
    check_preempt();
    ck_set_stage("m3_placement");
    check_placement();
    ck_set_stage("m3_ipc");
    check_ipc(kroot);
    ck_lower_sync = 0;
}
