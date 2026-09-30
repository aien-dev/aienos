/*
 * torn_slot.h -- torn-write-safe 4096-byte record over 512- or 4096-byte
 * logical blocks (host reference, C, no outside library).
 *
 * Problem. A Store record is 4096 bytes (OS-0015). On a device whose
 * logical block is 512 bytes, one record spans 8 blocks, and a power cut can
 * persist any subset of those 8 blocks. On a 4096-byte device the unit is one
 * block, but a device can still tear inside a block if it breaks its own
 * contract. The Spark's SSD reports 512-byte logical and physical blocks and a
 * 512-byte atomic write unit; ARCH-0021 decision 2 keeps it that way.
 *
 * Protocol (dual slot, commit sector last):
 *
 *   region, in 4096-byte units:  0 = body A   1 = commit A
 *                                2 = body B   3 = commit B
 *
 *   commit(record):
 *     target = the slot that does NOT hold the newest valid record
 *     1. write record to body[target]                 (all blocks)
 *     2. FLUSH                                         (barrier)
 *     3. write commit header to commit[target]         (seq = newest + 1)
 *     4. FLUSH                                         (durability point)
 *
 *   The commit header's non-zero bytes all lie in bytes 0..87 of the commit
 *   unit, which is inside logical block 0 for both 512 and 4096 geometry.
 *   It holds the sequence number, a SHA-256 over (slot, seq, all 4096 record
 *   bytes), and a SHA-256 over the header itself.
 *
 *   recover():
 *     a slot is valid only if its header is well formed, its header digest
 *     verifies, bytes 88..4095 of the commit unit are zero, and the record
 *     digest recomputed from all 4096 body bytes matches. The newest valid
 *     slot wins. Nothing partial is ever returned. recover() never writes.
 *
 * Why it holds. commit() only ever writes the slot that is NOT the newest
 * valid one, so the complete old record is never touched. A torn body fails
 * the record digest (the old header's digest names the old body); a torn
 * header fails the header digest; the flush in step 2 keeps the new header
 * from becoming durable before the whole new body. The device must honour
 * FLUSH (NVMe Flush with a volatile write cache, or no volatile cache); a
 * device that acknowledges FLUSH without persisting is outside this model.
 *
 * Relationship to the Rust Store engine: OS-0015 already uses two
 * superblock slots with a CRC. This file is a C reference for the 4096-byte
 * record over non-atomic 512-byte blocks; it does not change the v1 format
 * and is not linked into the kernel.
 */
#ifndef AIENOS_TORN_SLOT_H
#define AIENOS_TORN_SLOT_H

#include <stdint.h>

#define TS_RECORD_BYTES 4096u
#define TS_UNITS 4u /* body A, commit A, body B, commit B */
#define TS_HEADER_BYTES 88u

/* Result codes. */
enum {
    TS_OK = 0,          /* a committed record was recovered */
    TS_EMPTY = 1,       /* no record was ever committed: slot B never written, slot A blank or torn first write */
    TS_CORRUPT = -1,    /* damage or a slot state that crashes cannot produce (see ts_recover) */
    TS_CONFLICT = -2,   /* two valid slots claim the same seq (media damage) */
    TS_EIO = -3,        /* the device reported an error */
    TS_EGEOMETRY = -4,  /* unsupported block size or region too small */
    TS_ESTATE = -5,     /* commit without a successful recover, or seq exhausted */
};

/* Device callbacks. lba is absolute; count is in logical blocks. Return 0 on
 * success, nonzero on device error. flush must not return until every
 * previously acknowledged write is persistent. */
typedef struct {
    void *ctx;
    uint32_t block_size;  /* reported logical block size: 512 or 4096 */
    uint64_t block_count; /* blocks in the device */
    int (*read)(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf);
    int (*write)(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf);
    int (*flush)(void *ctx);
} ts_device;

typedef struct {
    ts_device dev;
    uint64_t base_lba;
    uint32_t blocks_per_unit;
    int known;         /* recover() has run and the state is usable */
    int newest_slot;   /* -1 when no committed record */
    uint64_t newest_seq;
} ts_region;

/* Per-slot diagnosis from the last recover(). */
typedef enum {
    TS_SLOT_BLANK = 0,     /* commit unit is all zero (never committed) */
    TS_SLOT_VALID = 1,
    TS_SLOT_INVALID = 2,   /* non-blank but fails a check */
} ts_slot_state;

/* Bind a region of TS_UNITS units starting at base_lba. The block size must
 * be 512 or 4096, and the region must fit the device. Does not touch media. */
int ts_open(ts_region *r, const ts_device *dev, uint64_t base_lba);

/* Recover the newest committed record. On TS_OK, out receives all 4096
 * bytes and *seq_out the sequence number. On TS_EMPTY, out is zeroed.
 * slot_states (optional, 2 entries) receives the per-slot diagnosis.
 * Never writes to the device. */
int ts_recover(ts_region *r, uint8_t out[TS_RECORD_BYTES], uint64_t *seq_out,
               ts_slot_state slot_states[2]);

/* Commit a new record. Requires a prior ts_recover() that returned TS_OK or
 * TS_EMPTY (fail closed on TS_CORRUPT or TS_CONFLICT). Returns TS_OK only
 * after the final flush. On any error the region must be recovered again. */
int ts_commit(ts_region *r, const uint8_t rec[TS_RECORD_BYTES]);

/* Encode a commit header into a zeroed 4096-byte commit unit (exposed for
 * tests). */
void ts_encode_commit(uint8_t unit[TS_RECORD_BYTES], int slot, uint64_t seq,
                      const uint8_t rec[TS_RECORD_BYTES]);

#endif /* AIENOS_TORN_SLOT_H */
