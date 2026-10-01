/* timer.c -- EL1 physical generic timer (CNTP, PPI INTID 30) and the
 * monotonic time services. Tick semantics match the Rust kernel: the IRQ
 * re-arms CNTP_CVAL 10 ms after "now", then records the interval since the
 * previous tick (the first interval is measured from arming). */
#include "arch.h"
#include "ck_internal.h"

static volatile uint64_t ticks, last, tmin, tmax;

static uint64_t counter(void)
{
    ck_isb();
    return ck_rd(cntpct_el0);
}

uint64_t ck_counter_to_us(uint64_t c, uint64_t f)
{
    if (!f)
        return 0;
    /* floor(c * 1e6 / f) without 128-bit division. */
    return (c / f) * 1000000u + ((c % f) * 1000000u) / f;
}

uint64_t ck_time_us(void)
{
    return ck_counter_to_us(counter(), ck_rd(cntfrq_el0));
}

void ck_udelay(uint32_t us)
{
    uint64_t f = ck_rd(cntfrq_el0), start = counter();
    uint64_t need = (uint64_t)us * (f / 1000000u) + ((uint64_t)us * (f % 1000000u)) / 1000000u;
    while (counter() - start < need)
        ;
}

void ck_timer_tick(void)
{
    uint64_t hz = ck_rd(cntfrq_el0);
    uint64_t now = counter();
    ck_wr(cntp_cval_el0, now + (hz ? hz / 100 : 625000));
    ck_wr(cntp_ctl_el0, 1);
    ck_isb();
    ticks++;
    uint64_t t = counter();
    uint64_t interval = t - last;
    last = t;
    if (interval < tmin)
        tmin = interval;
    if (interval > tmax)
        tmax = interval;
}

int ck_timer_window(uint32_t ms, struct ck_timer_window *w)
{
    uint64_t hz = ck_rd(cntfrq_el0);
    if (!hz)
        return -1;
    uint64_t start = counter();
    ticks = 0;
    last = start;
    tmin = ~0ull;
    tmax = 0;
    ck_wr(cntp_cval_el0, start + hz / 100);
    ck_wr(cntp_ctl_el0, 1); /* ENABLE, IMASK clear */
    ck_isb();
    ck_irq_on();
    ck_isb();
    uint64_t window = hz / 1000 * ms;
    while (counter() - start < window)
        ;
    ck_irq_off();
    ck_isb();
    ck_wr(cntp_ctl_el0, 0);
    ck_isb();
    w->ticks = ticks;
    w->ms = ms;
    w->freq_hz = hz;
    w->min_interval = ticks ? tmin : 0;
    w->max_interval = tmax;
    w->span = ticks ? last - start : 0;
    return 0;
}
