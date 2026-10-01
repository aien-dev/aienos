/* sched.c -- see sched.h. Same decisions as scheduler.rs, step for step. */
#include "sched.h"

int ck_sched_init(struct ck_sched *s, unsigned cpus, const uint8_t *classes, unsigned tasks,
                  unsigned bg_interval)
{
    if (cpus > CK_SCHED_MAX_CPUS || tasks > CK_SCHED_MAX_TASKS)
        return -1;
    s->cpus = cpus;
    s->ntasks = tasks;
    for (unsigned c = 0; c < CK_SCHED_MAX_CPUS; c++) {
        s->classes[c] = c < cpus ? classes[c] : 0;
        s->queue_len[c] = 0;
        s->bg_wait[c] = 0;
        for (unsigned t = 0; t < CK_SCHED_MAX_TASKS; t++)
            s->queues[c][t] = -1;
    }
    for (unsigned t = 0; t < CK_SCHED_MAX_TASKS; t++) {
        s->used[t] = 0;
        s->tasks[t] = (struct ck_task){ 0 };
    }
    s->bg_interval = bg_interval ? bg_interval : 1;
    s->cursor = 0;
    return 0;
}

int ck_sched_place(const struct ck_sched *s, enum ck_prio prio)
{
    if (s->cpus == 0)
        return CK_SCHED_NO_CPUS;
    unsigned start = s->cursor % s->cpus;
    if (prio == CK_PRIO_NORMAL) {
        unsigned best = start;
        for (unsigned off = 1; off < s->cpus; off++) {
            unsigned cpu = (start + off) % s->cpus;
            if (s->queue_len[cpu] < s->queue_len[best])
                best = cpu;
        }
        return (int)best;
    }
    uint8_t want = s->classes[0];
    for (unsigned c = 1; c < s->cpus; c++) {
        if (prio == CK_PRIO_LATENCY ? s->classes[c] > want : s->classes[c] < want)
            want = s->classes[c];
    }
    for (unsigned off = 0; off < s->cpus; off++) {
        unsigned cpu = (start + off) % s->cpus;
        if (s->classes[cpu] == want)
            return (int)cpu;
    }
    return CK_SCHED_NO_CPUS; /* unreachable */
}

static int slot_of(const struct ck_sched *s, uint32_t id)
{
    for (unsigned t = 0; t < s->ntasks; t++)
        if (s->used[t] && s->tasks[t].id == id)
            return (int)t;
    return -1;
}

int ck_sched_enqueue(struct ck_sched *s, uint32_t id, enum ck_prio prio)
{
    if (slot_of(s, id) >= 0)
        return CK_SCHED_DUPLICATE;
    int slot = -1;
    for (unsigned t = 0; t < s->ntasks; t++)
        if (!s->used[t]) {
            slot = (int)t;
            break;
        }
    if (slot < 0)
        return CK_SCHED_FULL;
    int cpu = ck_sched_place(s, prio);
    if (cpu < 0)
        return cpu;
    s->cursor = ((unsigned)cpu + 1) % s->cpus;
    s->queues[cpu][s->queue_len[cpu]++] = slot;
    s->used[slot] = 1;
    s->tasks[slot] = (struct ck_task){ .id = id, .prio = prio, .cpu = (unsigned)cpu, .ticks = 0 };
    return cpu;
}

static void queue_drop(struct ck_sched *s, unsigned cpu, unsigned at)
{
    unsigned len = s->queue_len[cpu];
    for (unsigned i = at; i + 1 < len; i++)
        s->queues[cpu][i] = s->queues[cpu][i + 1];
    s->queues[cpu][len - 1] = -1;
    s->queue_len[cpu] = len - 1;
}

int ck_sched_remove(struct ck_sched *s, uint32_t id)
{
    int slot = slot_of(s, id);
    if (slot < 0)
        return CK_SCHED_UNKNOWN;
    for (unsigned cpu = 0; cpu < s->cpus; cpu++) {
        for (unsigned i = 0; i < s->queue_len[cpu]; i++) {
            if (s->queues[cpu][i] == slot) {
                queue_drop(s, cpu, i);
                goto done;
            }
        }
    }
done:
    s->used[slot] = 0;
    return CK_SCHED_OK;
}

int ck_sched_steal(struct ck_sched *s, unsigned idle)
{
    if (idle >= s->cpus)
        return CK_SCHED_INVALID_CPU;
    if (s->queue_len[idle] != 0)
        return 0;
    int donor = -1;
    for (unsigned cpu = 0; cpu < s->cpus; cpu++)
        if (cpu != idle && s->queue_len[cpu] > 1 &&
            (donor < 0 || s->queue_len[cpu] > s->queue_len[donor]))
            donor = (int)cpu;
    if (donor < 0)
        return 0;
    /* Candidate: lowest priority, then most ticks (first wins ties). */
    unsigned pick = 0;
    for (unsigned i = 1; i < s->queue_len[donor]; i++) {
        const struct ck_task *t = &s->tasks[s->queues[donor][i]];
        const struct ck_task *p = &s->tasks[s->queues[donor][pick]];
        if (t->prio < p->prio || (t->prio == p->prio && t->ticks > p->ticks))
            pick = i;
    }
    int slot = s->queues[donor][pick];
    queue_drop(s, (unsigned)donor, pick);
    s->queues[idle][0] = slot;
    s->queue_len[idle] = 1;
    s->tasks[slot].cpu = idle;
    return 1;
}

int ck_sched_tick(struct ck_sched *s, unsigned cpu, uint32_t *id)
{
    if (cpu >= s->cpus)
        return CK_SCHED_INVALID_CPU;
    if (s->queue_len[cpu] == 0) {
        int st = ck_sched_steal(s, cpu);
        if (st < 0)
            return st;
        if (!st)
            return 0;
    }
    unsigned len = s->queue_len[cpu];
    int has_bg = 0, has_higher = 0;
    for (unsigned i = 0; i < len; i++) {
        enum ck_prio p = s->tasks[s->queues[cpu][i]].prio;
        if (p == CK_PRIO_BACKGROUND)
            has_bg = 1;
        else
            has_higher = 1;
    }
    int force_bg = 0;
    if (has_bg && has_higher) {
        s->bg_wait[cpu]++;
        force_bg = s->bg_wait[cpu] >= s->bg_interval;
    } else {
        s->bg_wait[cpu] = 0;
    }
    int sel = s->queues[cpu][0];
    for (unsigned i = 1; i < len; i++) {
        int slot = s->queues[cpu][i];
        const struct ck_task *t = &s->tasks[slot], *p = &s->tasks[sel];
        int wins;
        if (force_bg)
            wins = (t->prio == CK_PRIO_BACKGROUND && p->prio != CK_PRIO_BACKGROUND) ||
                   (t->prio == p->prio && t->ticks < p->ticks);
        else
            wins = t->prio > p->prio || (t->prio == p->prio && t->ticks < p->ticks);
        if (wins)
            sel = slot;
    }
    if (s->tasks[sel].prio == CK_PRIO_BACKGROUND)
        s->bg_wait[cpu] = 0;
    s->tasks[sel].ticks++;
    *id = s->tasks[sel].id;
    return 1;
}

const struct ck_task *ck_sched_task(const struct ck_sched *s, uint32_t id)
{
    int slot = slot_of(s, id);
    return slot < 0 ? 0 : &s->tasks[slot];
}
