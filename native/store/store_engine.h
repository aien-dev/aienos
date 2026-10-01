/*
 * store_engine.h -- C twin of the Store v1 mount and transaction engine
 * (crates/aienos-kernel/src/store/{engine,device,checkpoint}.rs).
 *
 * The engine sees only 4096-byte Store units through st_dev. st_disk binds
 * st_dev to a native/disk disk_dev (512-byte blocks: 8 per unit; 4096-byte
 * blocks: 1 per unit; anything else refused; never read-modify-write).
 *
 * No heap: every catalog, plan and scratch buffer lives in a caller-provided
 * st_workspace (about 0.9 MiB; place it in static storage). No clock. All
 * I/O goes through st_dev.
 */
#ifndef AIENOS_STORE_ENGINE_H
#define AIENOS_STORE_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "disk.h"
#include "store_v1.h"

/* MountState */
enum { ST_VALID = 0, ST_DEGRADED_RECOVERY = 1 };
/* PeerCondition */
enum { ST_PEER_ZERO = 0, ST_PEER_VALID, ST_PEER_MALFORMED, ST_PEER_GRAPH_BAD_NEWER,
       ST_PEER_GRAPH_BAD_OLDER };

/* MountError (returned by st_open). */
enum {
    ST_M_IO = -101,
    ST_M_UNFORMATTED = -102,
    ST_M_FOREIGN = -103,
    ST_M_UNSUPPORTED_VERSION = -104,
    ST_M_CORRUPT_RECOVERY_REQUIRED = -105,
    ST_M_CONFLICTING_ROOTS = -106,
    ST_M_INCONSISTENT_HISTORY = -107,
};

/* StoreError. StoreError::Format(e) is returned as the SV1_E_* value. */
enum {
    ST_E_IO = -201,
    ST_E_CORRUPT = -202,
    ST_E_READ_ONLY_DEGRADED = -203,
    ST_E_DUPLICATE_OBJECT_CONFLICT = -204,
    ST_E_NO_SPACE = -205,
    ST_E_CATALOG_FULL = -206,
    ST_E_GENERATION_EXHAUSTED = -207,
    ST_E_TRANSACTION_LIMIT = -208,
    ST_E_INVALID_OBJECT = -209,
    ST_E_NEEDS_REOPEN = -210,
    /* C only */
    ST_E_ARG = -211,      /* NULL pointer or caller buffer too small */
    ST_E_GEOMETRY = -212, /* st_disk: block size, alignment or region bounds */
};

const char *st_strerror(int e);

/* Checkpoints (checkpoint.rs), observed in this order by a hook. */
enum {
    ST_CP_BEFORE_FIRST_WRITE = 0,
    ST_CP_AFTER_PAYLOAD_OBJECTS,
    ST_CP_AFTER_CATALOG,
    ST_CP_AFTER_COMMIT_RECORD,
    ST_CP_AFTER_FIRST_FLUSH,
    ST_CP_AFTER_INACTIVE_SUPERBLOCK,
    ST_CP_AFTER_FINAL_FLUSH,
};
const char *st_checkpoint_name(int cp);
typedef void (*st_hook)(void *arg, int checkpoint);

/* StoreDevice: bounded 4096-byte unit I/O. Callbacks return 0 on success. */
typedef struct {
    void *ctx;
    uint64_t region_units;
    int (*read_unit)(void *ctx, uint64_t unit, uint8_t out[SV1_UNIT]);
    int (*write_unit)(void *ctx, uint64_t unit, const uint8_t in[SV1_UNIT]);
    int (*flush)(void *ctx);
} st_dev;

/* ---- geometry adapter over native/disk ---- */
typedef struct {
    const disk_dev *disk;
    uint64_t base_lba;
    uint32_t blocks_per_unit;
    uint64_t region_units;
} st_disk;

/* Bind region [base_lba, base_lba + units * blocks_per_unit) of disk.
 * region_units == 0 means every whole unit to the end of the device.
 * Refuses (ST_E_GEOMETRY) a block size other than 512/4096, a base_lba not
 * aligned to a unit, or a region past the device end. Touches no media. */
int st_disk_bind(st_disk *a, const disk_dev *disk, uint64_t base_lba, uint64_t region_units,
                 st_dev *out);

/* ---- engine ---- */
#define ST_CAT_CAP (SV1_MAX_CATALOG_ENTRIES + SV1_MAX_TRANSACTION_OBJECTS)

typedef struct {
    uint16_t kind;
    uint16_t version;
    const uint8_t *bytes; /* must stay valid for the transaction */
    uint64_t len;
} st_object;

typedef struct {
    uint8_t id[32];
    uint16_t kind, version;
    const uint8_t *bytes;
    uint64_t len;
    uint32_t units;
    uint64_t first_unit;
    int append; /* 1 if written by this transaction */
} st_req;

typedef struct {
    sv1_entry cat[2][ST_CAT_CAP];         /* active root, spare (open: slot A, slot B) */
    uint8_t catbuf[SV1_MAX_CATALOG_UNITS * SV1_UNIT];
    uint8_t unit[SV1_UNIT];
    uint8_t unit2[SV1_UNIT];
    uint8_t plan_commit[SV1_UNIT]; /* commit unit of the transaction being written */
    uint8_t plan_sb[SV1_UNIT];     /* superblock of the transaction being written */
    sv1_extent ext[ST_CAT_CAP];
    st_req req[SV1_MAX_TRANSACTION_OBJECTS];
} st_workspace;

typedef struct {
    sv1_superblock sb;
    sv1_commit commit;
    uint8_t commit_id[32];
    uint32_t cat_index; /* which ws->cat[] holds the entries */
    uint32_t n;
} st_root;

typedef struct {
    st_dev dev;
    st_workspace *ws;
    st_root root;
    int state;
    int peer;
    int poisoned;
} st_store;

/* Store::open. Never writes or flushes. Returns 0 or ST_M_*. */
int st_open(st_store *s, const st_dev *dev, st_workspace *ws);
/* Store::transact / transact_with_hook (hook may be NULL). */
int st_transact(st_store *s, const st_object *objects, size_t n, st_hook hook, void *arg);
/* Store::read_object into out (cap bytes). On any error out is zeroed. */
int st_read_object(st_store *s, const uint8_t id[32], uint8_t *out, size_t cap, size_t *len);

static inline uint64_t st_generation(const st_store *s) { return s->root.commit.generation; }
static inline uint64_t st_high_water(const st_store *s) { return s->root.commit.committed_high_water; }
static inline uint32_t st_active_slot(const st_store *s) { return s->root.sb.slot_id; }
static inline const sv1_entry *st_catalog(const st_store *s, uint32_t *n)
{
    *n = s->root.n;
    return s->ws->cat[s->root.cat_index];
}

/* Format a blank region: genesis units 2, 3, a zero slot B, flush, then
 * superblock A, flush (the same bytes as genesis.rs genesis_units). */
int st_format(const st_dev *dev, const uint8_t uuid[16]);

#endif /* AIENOS_STORE_ENGINE_H */
