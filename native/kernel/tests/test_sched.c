/* test_sched.c -- host tests for core/sched.c (the scheduler.rs test list,
 * plus the cooperative-thread order the M3 boot check expects). */
#include "ck_test.h"
#include "sched.h"

static uint32_t tick(struct ck_sched *s, unsigned cpu)
{
    uint32_t id = 0;
    int r = ck_sched_tick(s, cpu, &id);
    return r == 1 ? id : (r == 0 ? 0 : 0xffffffffu);
}

int main(void)
{
    struct ck_sched s;
    uint8_t c0011[4] = { 0, 0, 1, 1 }, c0[1] = { 0 }, c01[2] = { 0, 1 }, c00[2] = { 0, 0 };

    /* placement: latency on fast cores, background on efficient ones */
    ck_sched_init(&s, 4, c0011, 8, 8);
    int cpu = ck_sched_enqueue(&s, 1, CK_PRIO_LATENCY);
    CHECK(cpu == 2 || cpu == 3);
    cpu = ck_sched_enqueue(&s, 2, CK_PRIO_BACKGROUND);
    CHECK(cpu == 0 || cpu == 1);

    /* equal priority tasks share ticks fairly */
    ck_sched_init(&s, 1, c0, 4, 8);
    ck_sched_enqueue(&s, 1, CK_PRIO_NORMAL);
    ck_sched_enqueue(&s, 2, CK_PRIO_NORMAL);
    for (int i = 0; i < 20; i++)
        tick(&s, 0);
    CHECK(ck_sched_task(&s, 1)->ticks == 10);
    CHECK(ck_sched_task(&s, 2)->ticks == 10);

    /* fair order alternates (the threads demo relies on it) */
    ck_sched_init(&s, 1, c0, 4, 8);
    ck_sched_enqueue(&s, 0, CK_PRIO_NORMAL);
    ck_sched_enqueue(&s, 1, CK_PRIO_NORMAL);
    char order[9] = { 0 };
    for (int i = 0; i < 8; i++)
        order[i] = (char)('A' + tick(&s, 0));
    CHECK(order[0] == 'A' && order[1] == 'B' && order[6] == 'A' && order[7] == 'B');

    /* priority prevents basic inversion */
    ck_sched_init(&s, 1, c0, 4, 8);
    ck_sched_enqueue(&s, 1, CK_PRIO_BACKGROUND);
    ck_sched_enqueue(&s, 2, CK_PRIO_LATENCY);
    CHECK(tick(&s, 0) == 2);

    /* background runs within the configured interval under latency load */
    ck_sched_init(&s, 1, c0, 2, 7);
    ck_sched_enqueue(&s, 1, CK_PRIO_BACKGROUND);
    ck_sched_enqueue(&s, 2, CK_PRIO_LATENCY);
    int bg = 0;
    for (int i = 0; i < 7; i++)
        bg |= tick(&s, 0) == 1;
    CHECK(bg);

    /* latency keeps a large majority with a background budget */
    ck_sched_init(&s, 1, c0, 2, 8);
    ck_sched_enqueue(&s, 1, CK_PRIO_BACKGROUND);
    ck_sched_enqueue(&s, 2, CK_PRIO_LATENCY);
    for (int i = 0; i < 80; i++)
        tick(&s, 0);
    CHECK(ck_sched_task(&s, 2)->ticks > 80 * 3 / 4);
    CHECK(ck_sched_task(&s, 2)->ticks > ck_sched_task(&s, 1)->ticks);

    /* idle cpu steals and runs work */
    ck_sched_init(&s, 2, c01, 4, 8);
    ck_sched_enqueue(&s, 1, CK_PRIO_BACKGROUND);
    ck_sched_enqueue(&s, 2, CK_PRIO_BACKGROUND);
    CHECK(ck_sched_steal(&s, 1) == 1);
    CHECK(ck_sched_task(&s, 1)->cpu == 1 || ck_sched_task(&s, 2)->cpu == 1);
    uint32_t id;
    CHECK(ck_sched_tick(&s, 1, &id) == 1);

    /* empty queues and invalid cpu */
    ck_sched_init(&s, 2, c01, 2, 8);
    CHECK(ck_sched_tick(&s, 0, &id) == 0);
    CHECK(ck_sched_steal(&s, 1) == 0);
    CHECK(ck_sched_tick(&s, 2, &id) == CK_SCHED_INVALID_CPU);

    /* round-robin placement and duplicate rejection */
    ck_sched_init(&s, 2, c00, 4, 8);
    CHECK(ck_sched_enqueue(&s, 1, CK_PRIO_NORMAL) == 0);
    CHECK(ck_sched_enqueue(&s, 2, CK_PRIO_NORMAL) == 1);
    CHECK(ck_sched_enqueue(&s, 1, CK_PRIO_NORMAL) == CK_SCHED_DUPLICATE);

    /* removed tasks free their slot and leave the queue */
    ck_sched_init(&s, 1, c0, 2, 8);
    ck_sched_enqueue(&s, 1, CK_PRIO_NORMAL);
    ck_sched_enqueue(&s, 2, CK_PRIO_NORMAL);
    CHECK(ck_sched_enqueue(&s, 3, CK_PRIO_NORMAL) == CK_SCHED_FULL);
    CHECK(ck_sched_remove(&s, 1) == 0);
    CHECK(s.queue_len[0] == 1);
    CHECK(ck_sched_task(&s, 1) == 0);
    CHECK(ck_sched_enqueue(&s, 3, CK_PRIO_NORMAL) == 0);
    for (int i = 0; i < 4; i++)
        CHECK(tick(&s, 0) != 1);
    CHECK(ck_sched_remove(&s, 1) == CK_SCHED_UNKNOWN);

    /* no cpus, oversize */
    CHECK(ck_sched_init(&s, 0, c0, 2, 8) == 0);
    CHECK(ck_sched_enqueue(&s, 1, CK_PRIO_NORMAL) == CK_SCHED_NO_CPUS);
    CHECK(ck_sched_init(&s, CK_SCHED_MAX_CPUS + 1, c0, 2, 8) == -1);
    CHECK(ck_sched_init(&s, 1, c0, CK_SCHED_MAX_TASKS + 1, 8) == -1);
    return ck_t_verdict("test_sched");
}
