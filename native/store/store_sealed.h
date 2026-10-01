/* store_sealed.h -- M5 "sealed store" over the C Store v1 engine.
 *
 * Every application object is stored as an M5 envelope (AES-256-GCM-SIV,
 * native/m5) in a Store object of kind SS_KIND_ENVELOPE. Each Store
 * transaction carries exactly one sealed transaction record (kind
 * SS_KIND_TXREC, magic "AIENSTX1") that holds one M5 commit record per
 * envelope and binds them to the Store generation, the Store ObjectIds, the
 * identity class and the previous transaction record (a hash chain). The
 * record is MACed with k_root_auth.
 *
 * The anti-rollback anchor (m5_anchor, counter = Store generation) lives in
 * a separate 4-unit torn_slot region outside the Store region.
 *
 * Mount:  st_open -> ts_recover -> m5 open (verify every transaction record,
 *         the chain 2..G and every envelope digest) -> m5_evaluate_anti_rollback.
 * Commit: (catch the anchor up to G if it lags) -> seal envelopes + record
 *         -> st_transact (Store generation G+1 durable) -> ts_commit anchor G+1.
 * A crash after the Store commit and before the anchor commit leaves the
 * anchor one behind: mount reports SS_RB_PREPARED_ADVANCE and the next
 * transaction first catches the anchor up. Deterministic either way.
 *
 * Envelope ids and nonce prefixes are a keyed function of the plaintext
 * (record version 2, see README), so a rewrite after a whole-disk rollback
 * never reuses an AES-GCM-SIV (key, nonce) pair for different bytes.
 *
 * Limitation: the anchor sits on the same disk as the Store. It refuses a
 * Store-only rollback, a stale anchor more than one step behind and any
 * forged or replayed record, but an attacker who rolls back BOTH regions
 * together is not detected. That needs TPM NV (TRUST-1), not done here.
 *
 * No heap, no clock, no I/O except through disk_dev / st_dev.
 */
#ifndef AIENOS_STORE_SEALED_H
#define AIENOS_STORE_SEALED_H

#include <stddef.h>
#include <stdint.h>

#include "../m5/m5.h"
#include "store_engine.h"
#include "torn_slot.h"

#define SS_KIND_ENVELOPE 0x0510u /* M5 envelope of one application object */
#define SS_KIND_TXREC 0x0511u    /* sealed transaction record */
#define SS_MAX_OBJECTS 8u        /* application objects per transaction */
#define SS_MAX_PLAINTEXT 16384u  /* bytes per application object */
#define SS_CHUNK 4096u           /* envelope chunk size */
#define SS_ENV_CAP (M5_ENV_HEADER_LEN + SS_MAX_PLAINTEXT + (SS_MAX_PLAINTEXT / SS_CHUNK) * M5_TAG_LEN)
#define SS_TX_HDR 88u
#define SS_TX_ENTRY (32u + M5_COMMIT_LEN)
#define SS_TX_MAX (SS_TX_HDR + SS_MAX_OBJECTS * SS_TX_ENTRY + 32u)

/* Sealed errors. Store errors (ST_M_*, ST_E_*) pass through unchanged. */
enum {
    SS_E_ARG = -301,          /* NULL, bad count/size, unknown identity class */
    SS_E_IDENTITY = -302,     /* PRODUCTION/TEST class or store identity mismatch */
    SS_E_ROLLBACK = -303,     /* Store older than the anchor, fork, or missing anchor */
    SS_E_INCONSISTENT = -304, /* Store more than one generation ahead of the anchor */
    SS_E_ANCHOR = -305,       /* anchor region corrupt, conflicting, or record malformed */
    SS_E_IO = -306,           /* anchor region device error */
    SS_E_ENVELOPE = -307,     /* envelope torn, unbound, unclaimed or failed to open */
    SS_E_TXREC = -308,        /* transaction record malformed or MAC failed */
    SS_E_ORDER = -309,        /* generation skip, gap, stale record, broken chain */
    SS_E_DUPLICATE = -310,    /* two records for one generation, envelope claimed twice */
    SS_E_FOREIGN_KIND = -311, /* plaintext (non-sealed) object inside a sealed store */
    SS_E_CRYPTO = -312,       /* sealing failed */
    SS_E_NEEDS_REOPEN = -313, /* an anchor write failed; reopen */
    SS_E_FORMAT_VERSION = -314, /* version-1 record (predictable envelope ids): reformat */
};
const char *ss_strerror(int e);

/* Anti-rollback decision reported by ss_open. */
enum { SS_RB_VALID_RESUME = 1, SS_RB_PREPARED_ADVANCE = 2, SS_RB_GENESIS = 3 };

/* Extra checkpoints passed to the hook around the anchor commit. */
enum { SS_CP_BEFORE_ANCHOR = 100, SS_CP_AFTER_ANCHOR = 101 };

typedef struct {
    uint8_t identity_class;     /* M5_ID_PRODUCTION or M5_ID_TEST */
    uint64_t key_generation;
    uint8_t k_root_auth[32];    /* MAC key: records, anchor */
    uint8_t k_domain[32];       /* envelope domain key (k_artifact) */
} ss_keys;

typedef struct {
    uint16_t kind;              /* application kind, carried in the M5 binding */
    uint16_t version;
    const uint8_t *bytes;
    size_t len;                 /* 0 .. SS_MAX_PLAINTEXT */
} ss_object;

/* One verified envelope: its Store ObjectId and its M5 commit record. */
typedef struct {
    uint8_t sid[32];
    m5_commit c; /* verified at open or commit */
} ss_claim;

typedef struct {
    uint64_t gen;
    uint8_t digest[32];
    uint8_t prev[32];
} ss_txinfo;

typedef struct {
    st_workspace st;
    uint8_t rd[SS_ENV_CAP];
    uint8_t tsrec[TS_RECORD_BYTES];
    uint8_t env[SS_MAX_OBJECTS][SS_ENV_CAP];
    size_t env_len[SS_MAX_OBJECTS];
    uint8_t tx[SS_TX_MAX];
    size_t tx_len;
    st_object objs[SS_MAX_OBJECTS + 1];
    size_t nobjs;
    ss_claim claims[ST_CAT_CAP];
    ss_txinfo txs[ST_CAT_CAP];
    uint32_t bygen[ST_CAT_CAP]; /* generation - 2 -> index in txs */
    uint8_t used[ST_CAT_CAP];   /* catalog entry already claimed */
} ss_workspace;

typedef struct {
    st_store st;
    ts_region ts;
    ss_keys keys;
    ss_workspace *ws;
    uint8_t uuid[16];
    uint64_t anchor_gen;        /* 0: anchor region empty */
    uint8_t last_tx_digest[32]; /* SHA-256 of the record of generation G (zero at G = 1) */
    uint32_t nclaims;
    int rb;                     /* SS_RB_* from the last open */
    int needs_reopen;
} ss_store;

/* torn_slot device over a disk_dev (adds the disk layer's I/O splitting). */
void ss_ts_device(const disk_dev *disk, ts_device *out);

/* Zero the anchor region, write a fresh Store at genesis, then commit a
 * generation-1 anchor. anchor_lba is the first
 * block of the 4-unit anchor region (outside the Store region). */
int ss_format(const st_dev *store, const ts_device *anchor_dev, uint64_t anchor_lba,
              const uint8_t uuid[16], const ss_keys *keys, ss_workspace *ws);
/* Mount. Never writes. Returns 0 or an ST_M_* / SS_E_* error. */
int ss_open(ss_store *s, const st_dev *store, const ts_device *anchor_dev, uint64_t anchor_lba,
            const ss_keys *keys, ss_workspace *ws);
/* Seal and commit n objects as one Store transaction. ids_out (optional)
 * receives each envelope's Store ObjectId. */
int ss_transact(ss_store *s, const ss_object *objs, size_t n, st_hook hook, void *arg,
                uint8_t (*ids_out)[32]);
/* Decrypt one envelope by its Store ObjectId. */
int ss_read(ss_store *s, const uint8_t sid[32], uint8_t *out, size_t cap, size_t *len,
            uint16_t *kind);
static inline uint64_t ss_generation(const ss_store *s) { return st_generation(&s->st); }

/* Split form of ss_transact, exposed for tests that forge records:
 * ss_prepare seals into ws (env[], tx); ss_tx_remac recomputes the record
 * MAC after a test edits ws->tx; ss_commit_prepared writes it. */
int ss_prepare(ss_store *s, const ss_object *objs, size_t n);
void ss_tx_remac(ss_store *s);
int ss_commit_prepared(ss_store *s, st_hook hook, void *arg);

#endif /* AIENOS_STORE_SEALED_H */
