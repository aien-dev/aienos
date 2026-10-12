/* slot_update.c -- the inactive-slot updater (contract in slot_update.h). */
#include "slot_update.h"

static void zero(uint8_t *p, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++)
        p[i] = 0;
}

static int refuse(const char **why, const char *w)
{
    if (why)
        *why = w;
    return -1;
}

/* Write count units starting at unit u of the slots partition, refusing any
 * unit outside the target slot [lo, hi). */
static int put_units(const struct ck_slot_update_io *io, uint64_t lo, uint64_t hi, uint64_t u, uint64_t count,
                     const uint8_t *src)
{
    uint32_t bpu = CK_SLOT_UNIT / io->slots->block_size;
    if (u < lo || count > hi - u || count == 0)
        return -2;
    return disk_write(io->slots, u * bpu, (uint32_t)(count * bpu), src) == DISK_OK ? 0 : -1;
}

static int get_units(const disk_dev *d, uint64_t u, uint64_t count, uint8_t *dst)
{
    uint32_t bpu = CK_SLOT_UNIT / d->block_size;
    return disk_read(d, u * bpu, (uint32_t)(count * bpu), dst) == DISK_OK ? 0 : -1;
}

static int step(const struct ck_slot_update_io *io, const char *name, uint64_t done, uint64_t total)
{
    return io->progress ? io->progress(io->ctx, name, done, total) : 0;
}

/* Units per write call: bounded so one call never asks the backend for more
 * than 64 units (256 KiB); disk_write splits further by max_blocks_per_io. */
#define CHUNK_UNITS 64u

int ck_slot_update(const struct ck_slot_update_io *io, struct ck_slot_update_result *res, const char **why)
{
    static struct ck_slot_manifest man, back;
    static struct ck_slot_control staged;
    struct ck_slot_eval ev;
    const char *w = 0;
    if (!res)
        return refuse(why, "no result");
    zero((uint8_t *)res, sizeof *res);
    if (!io || !io->slots || !io->inbox || !io->control || !io->buf || !io->keys)
        return refuse(why, "update arguments");
    if (io->nkeys == 0)
        return refuse(why, "this image trusts no slot signing key");
    const struct ck_slot_control *ctl = io->ctl;
    if (!ctl || ck_slot_control_check(ctl, &w) != 0)
        return refuse(why, ctl ? w : "no control record on disk");
    if (ctl->candidate_slot != CK_SLOT_NONE)
        return refuse(why, "a candidate is already staged: boot it (promote or abandon) first");
    if (io->booted_slot >= CK_SLOT_COUNT || io->booted_slot != ctl->active_slot)
        return refuse(why, "the booted slot is not the active slot");
    for (const disk_dev *d = io->slots;; d = io->inbox) {
        if (disk_check(d) != DISK_OK || (d->block_size != 512 && d->block_size != 4096))
            return refuse(why, "partition geometry");
        if (d == io->inbox)
            break;
    }
    unsigned t = 1u - ctl->active_slot;
    uint64_t units = io->slots->block_count / (CK_SLOT_UNIT / io->slots->block_size);
    uint64_t cap = ck_slot_cap_units(units);
    uint64_t in_units = io->inbox->block_count / (CK_SLOT_UNIT / io->inbox->block_size);
    if (cap < CK_SLOT_MIN_CAP_UNITS || in_units < 2)
        return refuse(why, "slots or inbox partition too small");
    uint64_t lo = ck_slot_manifest_unit(t, cap), hi = lo + cap;
    res->target = t;

    /* 2. Read and verify; nothing is written before this passes. */
    if (get_units(io->inbox, 0, 1, (uint8_t *)&man) != 0)
        return refuse(why, "inbox manifest read failed");
    if (ck_slot_manifest_check(&man, &w) != 0)
        return refuse(why, w);
    uint64_t len = man.image_len, n = (len + CK_SLOT_UNIT - 1) / CK_SLOT_UNIT;
    if (n > cap - 1)
        return refuse(why, "image larger than the slot");
    if (n > in_units - 1)
        return refuse(why, "image longer than the inbox (truncated package)");
    if (n * CK_SLOT_UNIT > io->buf_cap)
        return refuse(why, "image larger than the update buffer");
    for (uint64_t u = 0; u < n; u += CHUNK_UNITS) {
        uint64_t c = n - u < CHUNK_UNITS ? n - u : CHUNK_UNITS;
        if (get_units(io->inbox, 1 + u, c, io->buf + u * CK_SLOT_UNIT) != 0)
            return refuse(why, "inbox image read failed");
    }
    if (!ck_slot_verify(&man, io->buf, (cap - 1) * CK_SLOT_UNIT, io->keys, io->nkeys, &ev))
        return refuse(why, ev.why ? ev.why : "inbox image refused");
    for (uint64_t i = 0; i < sizeof staged; i++)
        ((uint8_t *)&staged)[i] = ((const uint8_t *)ctl)[i];
    if (ck_slot_stage_candidate(&staged, t, man.generation, &w) != 0)
        return refuse(why, w);
    if (step(io, "verified", 0, n))
        return refuse(why, "stopped before writing");

    /* 3. Invalidate the target first. */
    static uint8_t zu[CK_SLOT_UNIT];
    res->wrote = 1;
    if (put_units(io, lo, hi, lo, 1, zu) != 0 || disk_flush(io->slots) != DISK_OK)
        return refuse(why, "invalidating the target slot failed");
    if (step(io, "invalidated", 0, n))
        return refuse(why, "stopped after invalidating the target slot");

    /* 4. Image units. */
    for (uint64_t u = 0; u < n; u += CHUNK_UNITS) {
        uint64_t c = n - u < CHUNK_UNITS ? n - u : CHUNK_UNITS;
        if (put_units(io, lo, hi, lo + 1 + u, c, io->buf + u * CK_SLOT_UNIT) != 0)
            return refuse(why, "image write failed (target slot left invalid)");
        res->units_written += c;
        if (step(io, "image", u + c, n))
            return refuse(why, "stopped while writing the image (target slot left invalid)");
    }
    if (disk_flush(io->slots) != DISK_OK)
        return refuse(why, "image flush failed (target slot left invalid)");

    /* 5. Manifest last, then read everything back and verify again. */
    if (put_units(io, lo, hi, lo, 1, (const uint8_t *)&man) != 0 || disk_flush(io->slots) != DISK_OK)
        return refuse(why, "manifest write failed (target slot left invalid)");
    res->units_written++;
    if (step(io, "manifest", n, n))
        return refuse(why, "stopped after the manifest (slot valid, not staged)");
    int ok = get_units(io->slots, lo, 1, (uint8_t *)&back) == 0;
    for (uint64_t u = 0; ok && u < n; u += CHUNK_UNITS) {
        uint64_t c = n - u < CHUNK_UNITS ? n - u : CHUNK_UNITS;
        ok = get_units(io->slots, lo + 1 + u, c, io->buf + u * CK_SLOT_UNIT) == 0;
    }
    if (!ok || !ck_slot_verify(&back, io->buf, (cap - 1) * CK_SLOT_UNIT, io->keys, io->nkeys, &ev)) {
        (void)put_units(io, lo, hi, lo, 1, zu);
        (void)disk_flush(io->slots);
        return refuse(why, "read-back verification of the written slot failed (slot invalidated)");
    }

    /* 6. Stage. */
    int crc = ck_slot_control_commit(io->control, &staged, &res->seq);
    if (crc != TS_OK)
        return refuse(why, "staging commit failed (slot written and valid, not staged)");
    res->generation = man.generation;
    res->image_len = len;
    return 0;
}
