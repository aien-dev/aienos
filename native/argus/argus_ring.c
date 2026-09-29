/*
 * argus_ring.c -- ARGUS single-producer / single-consumer bounded event ring.
 *
 * One producer thread calls argus_ring_push. One consumer thread calls
 * argus_ring_pop, argus_ring_pop_batch and argus_ring_drain_drops.
 * argus_ring_stats may be called from either. The ring lives entirely in
 * caller-provided memory (argus_ring_footprint bytes, 64-byte aligned); it
 * never allocates, never locks, never makes a system call, and never blocks.
 * Synchronisation is two C11 atomic indices (head written only by the
 * producer with release, tail written only by the consumer with release),
 * each on its own cache line, plus per-class atomic refusal counters.
 *
 * WHAT HAPPENS WHEN THE CONSUMER FALLS BEHIND
 *   Push never waits. As the ring fills, lower classes are refused first so
 *   that room is always kept for the events that matter most:
 *     INFORMATIONAL  refused once depth >= 50% of capacity
 *     AUDIT          refused once depth >= 75%
 *     SECURITY       refused once depth >= 90% (rounded up to a whole slot)
 *     CRITICAL       may use 100%; refused only when the ring is truly full
 *   A refused push returns ARGUS_ERR_FULL and the event is NOT stored; the
 *   producer keeps running. Nothing is ever lost silently:
 *     - a refused SECURITY/AUDIT/INFORMATIONAL event adds 1 to refused[class]
 *       (cumulative, in argus_ring_stats) and to a pending per-class count;
 *     - a refused CRITICAL event adds 1 to critical_overflow (cumulative and
 *       sticky: it is never reset, it marks a permanent evidence gap) and to a
 *       pending critical count. refused[CRITICAL] therefore always stays 0,
 *       and for every attempt: attempts = accepted + sum(refused) + critical_overflow.
 *   The consumer calls argus_ring_drain_drops to turn the pending counts into
 *   ARGUS_EV_TELEMETRY_DROPPED events (flag ARGUS_FLAG_CONSUMER,
 *   object_id = the class that lost events, resource = how many, outcome
 *   ERROR, code ARGUS_ERR_FULL), one per class with a nonzero pending count,
 *   CRITICAL first. It resets exactly the pending counts it reported
 *   (atomic exchange, so refusals racing with the drain are never lost; they
 *   show up in the next drain). Each synthesized event has class CRITICAL if
 *   critical_overflow has ever been nonzero on this ring, else SECURITY: once
 *   a critical event has been lost, every later drop report is critical too.
 *   The synthesized events are handed to the consumer directly; they do not
 *   go through the ring, so reporting a loss can never itself be refused.
 *   Accepted events are delivered in exact push order (FIFO overall, hence
 *   also FIFO within each class).
 */
#include "argus_abi.h"
#include <stdatomic.h>

#define ARGUS_RING_MIN_CAPACITY 4u
#define ARGUS_RING_MAX_CAPACITY (1u << 30)
#define ARGUS_RING_ALIGN 64u

struct ArgusRing {
    /* producer cache line */
    _Alignas(64) _Atomic uint64_t head;       /* next slot to write == events accepted */
    uint64_t tail_cache;                      /* producer's last view of tail */
    /* consumer cache line */
    _Alignas(64) _Atomic uint64_t tail;       /* next slot to read == events popped */
    uint64_t head_cache;                      /* consumer's last view of head */
    /* counters (producer increments, consumer exchanges pending) */
    _Alignas(64) _Atomic uint64_t refused[ARGUS_CLASS_MAX + 1];
    _Atomic uint64_t critical_overflow;
    _Atomic uint64_t pending[ARGUS_CLASS_MAX + 1];   /* index CRITICAL = pending overflow */
    /* immutable after init */
    _Alignas(64) uint32_t capacity, mask;
    uint32_t limit[ARGUS_CLASS_MAX + 1];      /* push accepted iff depth < limit[class] */
    _Alignas(64) ArgusEvent slots[];
};

/* Depth at which a class starts being refused (see top of file). */
static uint32_t class_limit(uint32_t cap, unsigned cls)
{
    uint64_t c = cap;
    switch (cls) {
    case ARGUS_CLASS_CRITICAL:      return cap;
    case ARGUS_CLASS_SECURITY:      return (uint32_t)((c * 9u + 9u) / 10u);   /* ceil(0.9 cap) */
    case ARGUS_CLASS_AUDIT:         return (uint32_t)((c * 3u + 3u) / 4u);    /* ceil(0.75 cap) */
    case ARGUS_CLASS_INFORMATIONAL: return (uint32_t)((c + 1u) / 2u);         /* ceil(0.5 cap) */
    default:                        return 0;
    }
}

static int capacity_ok(uint32_t cap)
{
    return cap >= ARGUS_RING_MIN_CAPACITY && cap <= ARGUS_RING_MAX_CAPACITY && (cap & (cap - 1u)) == 0;
}

/* Not in argus_abi.h yet (proposed addition): the ring depth at which pushes of
 * `class_` start being refused, for a ring of the given capacity. 0 if invalid. */
uint32_t argus_ring_saturation_point(uint32_t capacity_pow2, uint8_t class_);
uint32_t argus_ring_saturation_point(uint32_t capacity_pow2, uint8_t class_)
{
    if (!capacity_ok(capacity_pow2)) return 0;
    return class_limit(capacity_pow2, class_);
}

size_t argus_ring_footprint(uint32_t capacity_pow2)
{
    if (!capacity_ok(capacity_pow2)) return 0;
    size_t slots = (size_t)capacity_pow2;
    if (slots > (SIZE_MAX - sizeof(struct ArgusRing)) / sizeof(ArgusEvent)) return 0;
    return sizeof(struct ArgusRing) + slots * sizeof(ArgusEvent);
}

int argus_ring_init(ArgusRing **ring, void *memory, size_t bytes, uint32_t capacity_pow2)
{
    if (!ring || !memory) return ARGUS_ERR_ARG;
    size_t need = argus_ring_footprint(capacity_pow2);
    if (need == 0 || bytes < need) return ARGUS_ERR_ARG;
    if (((uintptr_t)memory & (ARGUS_RING_ALIGN - 1u)) != 0) return ARGUS_ERR_ARG;
    struct ArgusRing *r = (struct ArgusRing *)memory;
    atomic_init(&r->head, 0);
    atomic_init(&r->tail, 0);
    r->tail_cache = 0;
    r->head_cache = 0;
    for (unsigned c = 0; c <= ARGUS_CLASS_MAX; c++) {
        atomic_init(&r->refused[c], 0);
        atomic_init(&r->pending[c], 0);
        r->limit[c] = class_limit(capacity_pow2, c);
    }
    atomic_init(&r->critical_overflow, 0);
    r->capacity = capacity_pow2;
    r->mask = capacity_pow2 - 1u;
    *ring = r;
    return ARGUS_OK;
}

static void bump(_Atomic uint64_t *a) { atomic_fetch_add_explicit(a, 1, memory_order_relaxed); }

int argus_ring_push(ArgusRing *r, const ArgusEvent *ev)
{
    if (!r || !ev) return ARGUS_ERR_ARG;
    unsigned cls = ev->class_;
    if (cls < ARGUS_CLASS_CRITICAL || cls > ARGUS_CLASS_MAX) return ARGUS_ERR_MALFORMED;
    uint64_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint64_t limit = r->limit[cls];
    if (h - r->tail_cache >= limit) {
        /* Cached view says too full: refresh from the consumer before refusing. */
        r->tail_cache = atomic_load_explicit(&r->tail, memory_order_acquire);
        if (h - r->tail_cache >= limit) {
            if (cls == ARGUS_CLASS_CRITICAL) bump(&r->critical_overflow);
            else bump(&r->refused[cls]);
            bump(&r->pending[cls]);
            return ARGUS_ERR_FULL;
        }
    }
    r->slots[h & r->mask] = *ev;
    atomic_store_explicit(&r->head, h + 1, memory_order_release);
    return ARGUS_OK;
}

size_t argus_ring_pop_batch(ArgusRing *r, ArgusEvent *out, size_t max)
{
    if (!r || !out || max == 0) return 0;
    uint64_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint64_t avail = r->head_cache - t;
    if (avail < max) {
        r->head_cache = atomic_load_explicit(&r->head, memory_order_acquire);
        avail = r->head_cache - t;
    }
    if (avail == 0) return 0;
    size_t n = avail < max ? (size_t)avail : max;
    for (size_t i = 0; i < n; i++) out[i] = r->slots[(t + i) & r->mask];
    atomic_store_explicit(&r->tail, t + n, memory_order_release);
    return n;
}

int argus_ring_pop(ArgusRing *r, ArgusEvent *out)
{
    if (!r || !out) return ARGUS_ERR_ARG;
    return argus_ring_pop_batch(r, out, 1) == 1 ? ARGUS_OK : ARGUS_ERR_STATE;
}

void argus_ring_stats(const ArgusRing *ring, ArgusRingStats *out)
{
    if (!out) return;
    struct ArgusRing *r = (struct ArgusRing *)ring;   /* atomic loads need non-const in C11 */
    for (unsigned c = 0; c <= ARGUS_CLASS_MAX; c++) out->refused[c] = 0;
    out->pushed = out->popped = out->critical_overflow = 0;
    out->depth = out->capacity = 0;
    if (!r) return;
    uint64_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
    uint64_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    out->pushed = h;
    out->popped = t;
    for (unsigned c = 0; c <= ARGUS_CLASS_MAX; c++)
        out->refused[c] = atomic_load_explicit(&r->refused[c], memory_order_relaxed);
    out->critical_overflow = atomic_load_explicit(&r->critical_overflow, memory_order_relaxed);
    uint64_t d = h >= t ? h - t : 0;
    out->depth = (uint32_t)(d > r->capacity ? r->capacity : d);
    out->capacity = r->capacity;
}

size_t argus_ring_drain_drops(ArgusRing *r, ArgusEvent *out, size_t max, uint64_t *next_sequence)
{
    static const uint8_t order[ARGUS_CLASS_MAX] = {
        ARGUS_CLASS_CRITICAL, ARGUS_CLASS_SECURITY, ARGUS_CLASS_AUDIT, ARGUS_CLASS_INFORMATIONAL
    };
    if (!r || !out || !next_sequence) return 0;
    size_t n = 0;
    for (unsigned i = 0; i < ARGUS_CLASS_MAX && n < max; i++) {
        unsigned cls = order[i];
        if (atomic_load_explicit(&r->pending[cls], memory_order_relaxed) == 0) continue;
        uint64_t count = atomic_exchange_explicit(&r->pending[cls], 0, memory_order_relaxed);
        if (count == 0) continue;
        uint8_t ev_class = atomic_load_explicit(&r->critical_overflow, memory_order_relaxed) > 0
                               ? ARGUS_CLASS_CRITICAL : ARGUS_CLASS_SECURITY;
        if (*next_sequence == 0) *next_sequence = 1;
        ArgusEvent *e = &out[n++];
        *e = (ArgusEvent){0};
        e->version = ARGUS_ABI_VERSION;
        e->class_ = ev_class;
        e->kind = ARGUS_EV_TELEMETRY_DROPPED;
        e->effect_class = ARGUS_EFFECT_NONE;
        e->outcome = ARGUS_OUTCOME_ERROR;
        e->flags = ARGUS_FLAG_CONSUMER;
        e->sequence = (*next_sequence)++;
        e->code = ARGUS_ERR_FULL;
        e->object_id = cls;
        e->resource = count;
    }
    return n;
}
