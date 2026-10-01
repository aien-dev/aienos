/* exception.c -- synchronous exceptions, FIQ/SError, and the IRQ dispatcher.
 * Any exception other than an armed probe or an IRQ is fatal: it prints
 * "report_kind: fault" with ESR/FAR/ELR and resets. */
#include "arch.h"
#include "ck_internal.h"

struct ck_probe ck_probe_state;

void ck_exception(struct ck_frame *f, uint64_t vector);
void ck_irq_dispatch(struct ck_frame *f);
void ck_el2_fatal(uint64_t vector);

static const char *const vec_names[16] = {
    "sync_el_sp0", "irq_el_sp0", "fiq_el_sp0", "serror_el_sp0",
    "sync_el_spx", "irq_el_spx", "fiq_el_spx", "serror_el_spx",
    "sync_lower64", "irq_lower64", "fiq_lower64", "serror_lower64",
    "sync_lower32", "irq_lower32", "fiq_lower32", "serror_lower32",
};

void ck_exception(struct ck_frame *f, uint64_t vector)
{
    /* Only VBAR_EL1 points here (EL2 uses ck_vectors_el2). */
    unsigned el = ck_current_el();
    uint64_t esr = ck_rd(esr_el1), far = ck_rd(far_el1), elr = f->elr;
    uint64_t ec = (esr >> 26) & 0x3f;
    /* Armed probe: a data abort at the probing load on the current EL. */
    if (el == 1 && vector == 4 && ec == 0x25 && ck_probe_state.fixup &&
        elr == ck_probe_state.insn) {
        ck_probe_state.esr = esr;
        ck_probe_state.far = far;
        f->elr = ck_probe_state.fixup;
        ck_probe_state.fixup = 0;
        return;
    }
    ck_fault_report(vector < 16 ? vec_names[vector] : "unknown", esr, far, elr, el);
}

/* Any exception taken to EL2 before the drop to EL1 (ck_vectors_el2). */
void ck_el2_fatal(uint64_t vector)
{
    ck_fault_report(vector < 16 ? vec_names[vector] : "unknown", ck_rd(esr_el2), ck_rd(far_el2),
                    ck_rd(elr_el2), 2);
}

/* ---- IRQ registration (ck.h additions) ---- */
#define CK_IRQ_MAX 1020u
static struct {
    void (*fn)(void *);
    void *arg;
} irq_table[CK_IRQ_MAX];

int ck_irq_register(uint32_t intid, void (*fn)(void *arg), void *arg)
{
    if (intid >= CK_IRQ_MAX || intid == 30 || !fn)
        return -1;
    if (irq_table[intid].fn)
        return -2;
    irq_table[intid].arg = arg;
    irq_table[intid].fn = fn;
    return 0;
}

static uint64_t spurious, unhandled;

void ck_irq_dispatch(struct ck_frame *f)
{
    (void)f;
    uint32_t id = (uint32_t)ck_rd_s(ICC_IAR1_EL1) & 0xffffff;
    if (id >= 1020) {
        spurious++;
        return;
    }
    if (id == 30)
        ck_timer_tick(); /* re-arms before EOI */
    else if (irq_table[id].fn)
        irq_table[id].fn(irq_table[id].arg);
    else
        unhandled++;
    ck_wr_s(ICC_EOIR1_EL1, id);
    ck_isb();
}

void ck_irq_cpu_enable(int on)
{
    if (on)
        ck_irq_on();
    else
        ck_irq_off();
    ck_isb();
}
