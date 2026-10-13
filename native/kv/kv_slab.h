/* Native persistent-KV slab format, header-last slot state machine, and
 * bounded header-only recovery (sovereign-core ADR 0003 sections 2.5, 3.3,
 * 3.4, 4.2, 9; aienos#367 cut N2).
 *
 * C11, freestanding-compatible: no heap, no clock, no libc I/O. All block I/O
 * goes through ../disk/disk.h one command at a time within max_blocks_per_io.
 */
#ifndef AIENOS_KV_SLAB_H
#define AIENOS_KV_SLAB_H

#include <stddef.h>
#include <stdint.h>
#include "kv_record.h"
#include "../disk/disk.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KV_HASH_LEN 32u

/* Slab error codes (continuing from KV_E_SLOT_INDEX = -30 in kv_record.h). */
enum {
    KV_E_IO            = -31, /* disk_read, disk_write, or disk_flush failed */
    KV_E_SLAB_GEOMETRY = -32, /* bad block size, alignment, unit count, or slot geometry */
    KV_E_SLAB_OVERLAP  = -33, /* slab overlaps Store or anchor range, or peers overlap */
    KV_E_SLAB_BOUNDS   = -34, /* unit offset/count outside the bound slab region */
    KV_E_EMPTY_SLOT    = -35, /* slot is empty or key not found in local namespace */
    KV_E_LATE_CANCEL   = -36  /* cancel attempted at or after KV_STAGE_PUBLISHED */
};

/* Half-open LBA range [base_lba, base_lba + block_count) on disk_dev. */
typedef struct {
    uint64_t base_lba;
    uint64_t block_count;
} kv_lba_range;

/* Bound slab partition view over a disk_dev (ADR 2.5, 9.4). */
typedef struct {
    const disk_dev *disk;
    uint64_t base_lba;
    uint32_t blocks_per_unit; /* 8 for 512-byte blocks, 1 for 4096-byte blocks */
    uint64_t region_units;    /* 4096-byte units inside this slab region */
} kv_disk;

/* Bind a contiguous slab region of `units` 4096-byte units starting at
 * `base_lba`. Refuses block sizes other than 512 or 4096, unaligned base_lba,
 * zero units, out-of-disk bounds, empty or out-of-disk store/anchor ranges,
 * and any LBA overlap with store_range or anchor_range (ADR 2.5, 9.4). */
int kv_disk_bind(kv_disk *out,
                 const disk_dev *disk,
                 uint64_t base_lba,
                 uint64_t units,
                 kv_lba_range store_range,
                 kv_lba_range anchor_range);

/* Bounded multi-unit I/O over a bound kv_disk. Transfers larger than
 * disk->max_blocks_per_io are split into sequential single-command calls. */
int kv_disk_read_units(const kv_disk *kd, uint64_t unit_offset, uint32_t unit_count, uint8_t *out);
int kv_disk_write_units(const kv_disk *kd, uint64_t unit_offset, uint32_t unit_count, const uint8_t *in);
int kv_disk_flush(const kv_disk *kd);

/* Detailed slot payload geometry derived from payload_len (ADR 2.5). */
typedef struct {
    uint64_t sealed_len;      /* payload_len + 16 * ceil(payload_len / 4080) */
    uint32_t sealed_units;    /* ceil(sealed_len / 4096) */
    uint32_t envelope_len;    /* 64 + sealed_len */
    uint32_t last_unit_bytes; /* 1..4096 occupied bytes in the last payload unit */
    uint32_t last_unit_pad;   /* 0..4095 trailing zero bytes in the last payload unit */
} kv_slot_payload_geom;

int kv_slot_payload_geometry(uint64_t payload_len, kv_slot_payload_geom *out);

/* Caller-provided index entry (one per slot in the slab, ADR 4.2). */
typedef struct {
    uint8_t valid;             /* 1 if slot holds a validated header, 0 if empty */
    uint8_t foreign_namespace; /* 1 if valid but hdr.rec.chunk.namespace_id != local_namespace */
    uint8_t reserved[6];
    kv_slot_header hdr;
} kv_slab_entry;

/* In-memory slab state and accounting (caller provides entries[slot_count] and
 * unit_scratch[4096]; no dynamic allocation). */
typedef struct {
    kv_disk dev;
    uint32_t slot_count;
    uint32_t slot_units; /* 1 header unit + max_sealed_units payload units (>= 2) */
    uint8_t local_namespace[KV_HASH_LEN];
    kv_slab_entry *entries;
    uint8_t *unit_scratch;
    uint64_t used_bytes;       /* valid_slots * slot_units * 4096 across all namespaces (ADR 4.2) */
    uint64_t payload_bytes;    /* sum of hdr.rec.chunk.payload_len across all namespaces */
    uint64_t next_incarnation; /* 1 + max(valid slot_incarnation seen) */
    uint32_t valid_slots;      /* count of valid slots (all namespaces) */
    uint32_t foreign_slots;    /* count of valid slots from a foreign namespace */
    uint32_t empty_slots;      /* slot_count - valid_slots */
    uint8_t fail_stop;         /* 1 if a device write or flush failed since open */
} kv_slab;

/* Initialize the in-memory slab handle without performing disk I/O. */
int kv_slab_init(kv_slab *slab,
                 const kv_disk *dev,
                 uint32_t slot_count,
                 uint32_t slot_units,
                 const uint8_t local_namespace[KV_HASH_LEN],
                 kv_slab_entry *entries,
                 uint8_t unit_scratch[KV_SLOT_UNIT]);

/* Format the slab on disk: zeroes all N slot header units and flushes once,
 * leaving every slot provably empty (ADR 2.5). */
int kv_slab_format(kv_slab *slab);

/* Bounded recovery (ADR 4.2): reads the N slot header units in order (one
 * 4 KiB read each, nothing else), validates each header unit without key
 * material, populates entries[0..N), and computes used_bytes across all valid
 * slots regardless of namespace. A torn or corrupt header is an empty slot. */
int kv_slab_recover(kv_slab *slab);

/* Lookup a chunk_key in the local namespace. Foreign-namespace slots are
 * never returned. If multiple slots hold the same key, selects the highest
 * slot_incarnation. Returns KV_OK or KV_E_EMPTY_SLOT. */
int kv_slab_lookup(const kv_slab *slab, const uint8_t chunk_key[KV_HASH_LEN], uint32_t *slot_out);

/* Completion stages for a native slot write (ADR 3.3, 9.2). */
typedef enum {
    KV_STAGE_SUBMITTED = 0, /* accepted; header unit not yet written */
    KV_STAGE_COMPLETED = 1, /* payload units written and disk_flush returned */
    KV_STAGE_PUBLISHED = 2, /* header unit written and index updated */
    KV_STAGE_DURABLE   = 3  /* disk_flush after header returned */
} kv_job_stage;

/* Internal command-stepped phases of a header-last slot write (ADR 2.5). */
typedef enum {
    KV_SLOT_PHASE_ZERO_HDR      = 0, /* write 4096 zero bytes to unit 0 of slot */
    KV_SLOT_PHASE_FLUSH_ZERO    = 1, /* disk_flush after zeroing header */
    KV_SLOT_PHASE_WRITE_PAYLOAD = 2, /* write sealed payload units 1..sealed_units */
    KV_SLOT_PHASE_FLUSH_PAYLOAD = 3, /* disk_flush after payload -> KV_STAGE_COMPLETED */
    KV_SLOT_PHASE_WRITE_HDR     = 4, /* write encoded slot header -> KV_STAGE_PUBLISHED */
    KV_SLOT_PHASE_FLUSH_HDR     = 5, /* disk_flush after header -> KV_STAGE_DURABLE */
    KV_SLOT_PHASE_DONE          = 6,
    KV_SLOT_PHASE_CANCELLED     = 7,
    KV_SLOT_PHASE_FAILED        = 8
} kv_slot_write_phase;

/* Step-able slot writer state machine. Each kv_slot_write_step call issues at
 * most one disk_write or disk_flush command. */
typedef struct {
    kv_slab *slab;
    uint32_t slot_index;
    kv_slot_header hdr;
    kv_slot_payload_geom geom;
    const uint8_t *sealed_body;
    size_t sealed_body_len;
    uint32_t payload_units_done;
    kv_job_stage stage;
    kv_slot_write_phase phase;
    uint8_t hdr_unit[KV_SLOT_UNIT];
} kv_slot_writer;

/* Validate header/geometry and prepare a header-last slot write without
 * touching the disk. sealed_body holds the M5 ciphertext+tag chunks (without
 * the 64-byte M5 header), of length geom.sealed_len (or geom.sealed_units * 4096
 * with zero tail padding). */
int kv_slot_write_begin(kv_slot_writer *w,
                        kv_slab *slab,
                        uint32_t slot_index,
                        const kv_slot_header *hdr,
                        const uint8_t *sealed_body,
                        size_t sealed_body_len);

/* Execute one command step of the header-last write order. Returns KV_OK while
 * progressing or when phase reaches KV_SLOT_PHASE_DONE. On device failure,
 * marks the writer KV_SLOT_PHASE_FAILED, sets slab->fail_stop = 1, and returns
 * KV_E_IO. */
int kv_slot_write_step(kv_slot_writer *w);

/* Cancel an in-flight slot write at KV_STAGE_SUBMITTED or KV_STAGE_COMPLETED.
 * Refuses with KV_E_LATE_CANCEL once KV_STAGE_PUBLISHED is reached. If the
 * slot header was not yet zeroed on disk, zeroes and flushes it so the slot
 * remains provably empty. */
int kv_slot_write_cancel(kv_slot_writer *w);

/* Run a complete header-last slot write to KV_STAGE_DURABLE. */
int kv_slab_write_slot(kv_slab *slab,
                       uint32_t slot_index,
                       const kv_slot_header *hdr,
                       const uint8_t *sealed_body,
                       size_t sealed_body_len);

/* Read and validate slot_index from disk: reads unit 0, validates the slot
 * header unit and slab bounds, reads units 1..sealed_units, and checks that
 * any trailing padding in the final unit is all zero (ADR 2.5). */
int kv_slab_read_slot(kv_slab *slab,
                      uint32_t slot_index,
                      kv_slot_header *hdr_out,
                      uint8_t *sealed_body_out,
                      size_t body_cap,
                      size_t *sealed_len_out);

#ifdef __cplusplus
}
#endif

#endif /* AIENOS_KV_SLAB_H */
