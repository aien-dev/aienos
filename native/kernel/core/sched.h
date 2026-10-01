/* sched.h -- run-queue scheduler, port of crates/aienos-kernel/src/scheduler.rs.
 * Pure logic (no hardware): per-CPU queues, three priorities, fair ticks
 * among equal priorities, a background budget under higher-priority load,
 * placement by CPU efficiency class and work stealing. Host-tested in
 * tests/test_sched.c; the M3 threads use it with one CPU. */
#ifndef AIENOS_CK_SCHED_H
#define AIENOS_CK_SCHED_H

#include <stdint.h>

#define CK_SCHED_MAX_CPUS 8
#define CK_SCHED_MAX_TASKS 16

enum ck_prio { CK_PRIO_BACKGROUND = 0, CK_PRIO_NORMAL = 1, CK_PRIO_LATENCY = 2 };

enum ck_sched_err {
    CK_SCHED_OK = 0,
    CK_SCHED_NO_CPUS = -1,
    CK_SCHED_FULL = -2,
    CK_SCHED_DUPLICATE = -3,
    CK_SCHED_INVALID_CPU = -4,
    CK_SCHED_UNKNOWN = -5,
};

struct ck_task {
    uint32_t id;
    enum ck_prio prio;
    unsigned cpu;
    uint64_t ticks;
};

struct ck_sched {
    unsigned cpus, ntasks;
    uint8_t classes[CK_SCHED_MAX_CPUS];
    uint8_t used[CK_SCHED_MAX_TASKS];
    struct ck_task tasks[CK_SCHED_MAX_TASKS];
    int queues[CK_SCHED_MAX_CPUS][CK_SCHED_MAX_TASKS]; /* task slots, -1 empty */
    unsigned queue_len[CK_SCHED_MAX_CPUS];
    unsigned bg_wait[CK_SCHED_MAX_CPUS];
    unsigned bg_interval;
    unsigned cursor;
};

/* cpus 0 is allowed (every placement then fails with CK_SCHED_NO_CPUS).
 * Returns -1 if cpus or tasks exceed the maximums. Interval 0 means 1. */
int ck_sched_init(struct ck_sched *s, unsigned cpus, const uint8_t *classes, unsigned tasks,
                  unsigned bg_interval);
/* CPU for a new task: Latency -> highest class, Background -> lowest class,
 * Normal -> shortest queue; ties from the round-robin cursor. */
int ck_sched_place(const struct ck_sched *s, enum ck_prio prio);
/* Returns the CPU it was queued on, or an error. */
int ck_sched_enqueue(struct ck_sched *s, uint32_t id, enum ck_prio prio);
int ck_sched_remove(struct ck_sched *s, uint32_t id);
/* Picks the next task on cpu (stealing if idle): 1 and *id set, 0 if none,
 * or an error. The picked task's tick count increases. */
int ck_sched_tick(struct ck_sched *s, unsigned cpu, uint32_t *id);
/* 1 if a task moved to idle_cpu, 0 if not, or an error. */
int ck_sched_steal(struct ck_sched *s, unsigned idle_cpu);
const struct ck_task *ck_sched_task(const struct ck_sched *s, uint32_t id);

#endif
