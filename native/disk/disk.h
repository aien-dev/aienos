/*
 * disk.h -- AIENOS native block-device interface (C, no outside library).
 *
 * One narrow interface between the Store engine (native/store) and a block
 * device backend. Backends:
 *   disk_file.c  hosted file-backed backend for tests (libc; never linked
 *                into a freestanding image), with power-cut injection.
 *   disk_nvme.c  freestanding NVMe driver ported from the audited Rust path
 *                (crates/aienos-kernel/src/nvme*, docs/P3_NVME_*.md). No libc.
 *
 * Geometry. The interface sector is 512 bytes (DISK_SECTOR_BYTES). A backend
 * reports its logical block size (512 or 4096); lba and count are in logical
 * blocks of that size. The Store sees 4096-byte units on top.
 *
 * Contract (every backend):
 *   - read/write return only after the transfer completed or failed.
 *   - flush returns only after every previously acknowledged write is
 *     persistent (NVMe Flush with a volatile write cache, or no cache).
 *   - count is 1..max_blocks_per_io; lba + count <= block_count. disk_read /
 *     disk_write / disk_flush below check these before calling the backend.
 *
 * The field order of disk_dev's first six members matches ts_device in
 * native/store/torn_slot.h so a disk_dev converts to a ts_device by copy.
 */
#ifndef AIENOS_DISK_H
#define AIENOS_DISK_H

#include <stddef.h>
#include <stdint.h>

#define DISK_SECTOR_BYTES 512u
#define DISK_QUEUE_DEPTH 32u /* bounded request queue, see disk_queue */

enum {
    DISK_OK = 0,
    DISK_EIO = -1,       /* the backend reported an error */
    DISK_ERANGE = -2,    /* lba/count out of bounds or overflow */
    DISK_EARG = -3,      /* NULL pointer, zero count, bad parameter */
    DISK_EGEOMETRY = -4, /* block size not 512 or 4096, or zero blocks */
    DISK_EFULL = -5,     /* queue full */
    DISK_EPOWER = -6,    /* hosted test backend: simulated power cut */
    DISK_ESTATE = -7,    /* backend not ready / failed closed */
};

typedef struct {
    void *ctx;
    uint32_t block_size;  /* logical block size: 512 or 4096 */
    uint64_t block_count; /* blocks in the device */
    int (*read)(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf);
    int (*write)(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf);
    int (*flush)(void *ctx);
    uint32_t max_blocks_per_io; /* backend transfer limit, >= 1 */
} disk_dev;

/* Checked entry points: validate geometry and bounds, then call the backend.
 * Transfers larger than max_blocks_per_io are split. */
int disk_check(const disk_dev *d);
int disk_read(const disk_dev *d, uint64_t lba, uint32_t count, uint8_t *buf);
int disk_write(const disk_dev *d, uint64_t lba, uint32_t count, const uint8_t *buf);
int disk_flush(const disk_dev *d);

/* Bounded request queue: at most DISK_QUEUE_DEPTH outstanding requests,
 * drained in submission order; a FLUSH is a barrier (everything queued before
 * it completes before it is issued). disk_queue_push refuses with DISK_EFULL
 * instead of growing. The first failing request stops the drain; the queue is
 * then failed closed until disk_queue_reset. */
typedef enum { DISK_OP_READ = 1, DISK_OP_WRITE = 2, DISK_OP_FLUSH = 3 } disk_op;

typedef struct {
    disk_op op;
    uint64_t lba;
    uint32_t count;
    uint8_t *buf; /* read target or write source (cast away const on write) */
    int status;   /* filled by drain */
} disk_req;

typedef struct {
    const disk_dev *dev;
    disk_req req[DISK_QUEUE_DEPTH];
    uint32_t head, len;
    int failed;
} disk_queue;

void disk_queue_init(disk_queue *q, const disk_dev *dev);
int disk_queue_push(disk_queue *q, disk_op op, uint64_t lba, uint32_t count, uint8_t *buf);
int disk_queue_drain(disk_queue *q); /* DISK_OK or the first error */
void disk_queue_reset(disk_queue *q);

#endif /* AIENOS_DISK_H */
