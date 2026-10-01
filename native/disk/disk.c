/*
 * disk.c -- checked entry points and bounded request queue (see disk.h).
 * Freestanding: no libc, no heap, no clock, no I/O except through the
 * backend callbacks.
 */
#include "disk.h"

int disk_check(const disk_dev *d)
{
    if (!d || !d->read || !d->write || !d->flush)
        return DISK_EARG;
    if (d->block_size != 512u && d->block_size != 4096u)
        return DISK_EGEOMETRY;
    if (d->block_count == 0 || d->max_blocks_per_io == 0)
        return DISK_EGEOMETRY;
    return DISK_OK;
}

static int range_ok(const disk_dev *d, uint64_t lba, uint32_t count)
{
    if (count == 0)
        return DISK_EARG;
    if (lba >= d->block_count) /* GUARD:disk-lba */
        return DISK_ERANGE;
    if ((uint64_t)count > d->block_count - lba) /* GUARD:disk-end */
        return DISK_ERANGE;
    return DISK_OK;
}

int disk_read(const disk_dev *d, uint64_t lba, uint32_t count, uint8_t *buf)
{
    int rc = disk_check(d);
    if (rc != DISK_OK)
        return rc;
    if (!buf)
        return DISK_EARG;
    if ((rc = range_ok(d, lba, count)) != DISK_OK)
        return rc;
    while (count) {
        uint32_t n = count < d->max_blocks_per_io ? count : d->max_blocks_per_io;
        if (d->read(d->ctx, lba, n, buf) != 0)
            return DISK_EIO;
        lba += n;
        count -= n;
        buf += (size_t)n * d->block_size;
    }
    return DISK_OK;
}

int disk_write(const disk_dev *d, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    int rc = disk_check(d);
    if (rc != DISK_OK)
        return rc;
    if (!buf)
        return DISK_EARG;
    if ((rc = range_ok(d, lba, count)) != DISK_OK)
        return rc;
    while (count) {
        uint32_t n = count < d->max_blocks_per_io ? count : d->max_blocks_per_io;
        int brc = d->write(d->ctx, lba, n, buf);
        if (brc != 0)
            return brc == DISK_EPOWER ? DISK_EPOWER : DISK_EIO;
        lba += n;
        count -= n;
        buf += (size_t)n * d->block_size;
    }
    return DISK_OK;
}

int disk_flush(const disk_dev *d)
{
    int rc = disk_check(d);
    if (rc != DISK_OK)
        return rc;
    rc = d->flush(d->ctx);
    if (rc != 0)
        return rc == DISK_EPOWER ? DISK_EPOWER : DISK_EIO;
    return DISK_OK;
}

void disk_queue_init(disk_queue *q, const disk_dev *dev)
{
    q->dev = dev;
    q->head = 0;
    q->len = 0;
    q->failed = 0;
}

int disk_queue_push(disk_queue *q, disk_op op, uint64_t lba, uint32_t count, uint8_t *buf)
{
    if (!q || !q->dev)
        return DISK_EARG;
    if (q->failed)
        return DISK_ESTATE;
    if (op != DISK_OP_READ && op != DISK_OP_WRITE && op != DISK_OP_FLUSH)
        return DISK_EARG;
    if (q->len >= DISK_QUEUE_DEPTH) /* GUARD:queue-bound */
        return DISK_EFULL;
    if (op != DISK_OP_FLUSH) {
        int rc;
        if (!buf)
            return DISK_EARG;
        if ((rc = range_ok(q->dev, lba, count)) != DISK_OK)
            return rc;
    }
    disk_req *r = &q->req[(q->head + q->len) % DISK_QUEUE_DEPTH];
    r->op = op;
    r->lba = lba;
    r->count = count;
    r->buf = buf;
    r->status = 1; /* pending */
    q->len++;
    return DISK_OK;
}

int disk_queue_drain(disk_queue *q)
{
    if (!q || !q->dev)
        return DISK_EARG;
    if (q->failed)
        return DISK_ESTATE;
    while (q->len) {
        disk_req *r = &q->req[q->head];
        int rc;
        if (r->op == DISK_OP_READ)
            rc = disk_read(q->dev, r->lba, r->count, r->buf);
        else if (r->op == DISK_OP_WRITE)
            rc = disk_write(q->dev, r->lba, r->count, r->buf);
        else
            rc = disk_flush(q->dev);
        r->status = rc;
        q->head = (q->head + 1) % DISK_QUEUE_DEPTH;
        q->len--;
        if (rc != DISK_OK) { /* GUARD:queue-failstop */
            q->failed = 1;
            return rc;
        }
    }
    return DISK_OK;
}

void disk_queue_reset(disk_queue *q)
{
    q->head = 0;
    q->len = 0;
    q->failed = 0;
}
