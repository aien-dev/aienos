/*
 * rx_cortex.h -- Cortex, AIEN's durable typed memory. CANONICAL (M20).
 *
 * AUTHORITY (M20, 2026-09-30). This file is the one canonical Cortex
 * contract. Every authoritative Cortex write goes through cx_append or
 * cx_append_as on a CxStore defined here, and a store has at most one writer:
 * cx_claim_writer inside a process, an exclusive lock on the journal across
 * processes. Chosen because it is the C implementation in the runtime tree
 * that owns World (rx_world.c), the one the runtime already calls
 * (rx_projection.c), and the only one the no-Rust rule allows to grow.
 *
 * Non-authoritative implementations (not edited here, never a second writer):
 *
 *   aien-sovereign-core crates/cortex-rs   Linux LLM-stack memory service
 *                                          (HTTP :18080; callers aien-cli
 *                                          src/cortex.rs, spark-mail-rs
 *                                          src/cortex_sync.rs).
 *   aienos crates/aienos-cortex            Rust epistemic store (callers
 *                                          aienos-aegis, aienos-kernel
 *                                          src/continuity.rs).
 *
 * Their records are not AIEN memory until they enter this store, and they
 * enter only as CX_K_IMPORTED claims whose tag names the source (CX_SRC_*):
 * never as facts and never by writing a journal directly. Removal path, per
 * aien-architecture docs/plans/RUST_TO_C_MIGRATION.md §6 ("port or retire"):
 * both are retired, not ported. (1) No new caller may be added to either.
 * (2) Whatever is worth keeping is imported as CX_K_IMPORTED records through
 * cx_append_as. (3) The crates are deleted. Until step 3 nothing may treat
 * them as a source of truth.
 *
 * Cortex holds what the machine has seen, done, claimed and proven. It is
 * append-only: an object, once recorded, never changes, and its digest says
 * so. Nothing in Cortex is text. Every object is a fixed header plus a
 * payload of 64-bit words.
 *
 * Two axes, never merged:
 *
 *   content class  what the object IS: one of the nine memory classes of
 *                  doctrine AIEN.md §8.2 (entity, claim, observation, ...).
 *   treatment      how one cognitive operation may use it (pinned, live,
 *                  compressible, ...). Treatment is not stored here. It is
 *                  decided per operation by the state projection
 *                  (rx_projection.h).
 *
 * Protection bits are the one treatment fact Cortex does own: authority,
 * commit receipts, verification evidence, generation identity and effect
 * receipts may never be summarized, whatever an operation asks for.
 *
 * Cortex does not hand out its history. It answers typed queries: one
 * subject, one time range, one class and kind. The indexes are per subject
 * and time ordered, so a query costs the objects in its range, not the size
 * of the store. `examined` counts every object a query touched.
 *
 * Tiers: one in-memory tier, optionally backed by an append-only journal
 * file (cx_open) that is replayed and verified on reopen. Doctrine's L1/L2/L3
 * tiers (accelerator memory, host memory, NVMe) are not implemented here.
 * Cortex is memory and evidence; runtime state-space material is J-Space
 * (rx_jspace.h), not this.
 */
#ifndef RX_CORTEX_H
#define RX_CORTEX_H

#include <stddef.h>
#include <stdint.h>

/* Content axis: the nine memory classes of doctrine AIEN.md §8.2. */
typedef enum {
    CX_ENTITY = 1, CX_CLAIM, CX_OBSERVATION, CX_EXECUTION, CX_FAILURE,
    CX_EVIDENCE, CX_PLAN, CX_REALIZATION, CX_RELATIONSHIP,
    CX_CLASS_END
} CxClass;

/* State that may never be summarized, derived away or dropped for budget. */
enum {
    CX_PROT_AUTHORITY       = 1u << 0,
    CX_PROT_COMMIT_RECEIPT  = 1u << 1,
    CX_PROT_VERIFY_EVIDENCE = 1u << 2,
    CX_PROT_GENERATION_ID   = 1u << 3,
    CX_PROT_EFFECT_RECEIPT  = 1u << 4,
    CX_PROT_ALL             = 0x1fu
};

/* ---- canonical record kinds ---------------------------------------------
 * `kind` numbering below CX_K_BASE belongs to the writer (rx_projection's
 * workloads use it). Kinds from CX_K_BASE up are the canonical contract and
 * mean the same thing to every reader. Each canonical kind lives in exactly
 * one class, given in the comment.
 */
#define CX_K_BASE 0x10000u
enum {
    /* World execution (written only by rx_cortex_record.c, payload CX_WREC_*) */
    CX_K_WORK_ACCEPTED = CX_K_BASE + 1, /* OBSERVATION: outside input admitted into a World */
    CX_K_ENTITY_CREATED,                /* ENTITY: a World object came to life */
    CX_K_ENTITY_RETIRED,                /* ENTITY: a World object was retired */
    CX_K_EXEC_COMMIT,                   /* EXECUTION: work ran and committed a result */
    CX_K_EXEC_NOOP,                     /* EXECUTION: work ran and proposed no change */
    CX_K_EXEC_FAILED,                   /* FAILURE: failed, rejected, blocked, invalidated,
                                           contained; tag = World crumb kind */
    /* Epistemic records (any claimed writer) */
    CX_K_CLAIM = CX_K_BASE + 0x10,      /* CLAIM: asserted fact */
    CX_K_CANDIDATE,                     /* CLAIM: summary or memory candidate, not yet fact */
    CX_K_EVIDENCE_REF,                  /* EVIDENCE: reference to a receipt / digest */
    CX_K_PROMOTION,                     /* EVIDENCE: candidate promoted; links[0] = candidate,
                                           links[1] = evidence (cx_promote) */
    CX_K_ADMISSION,                     /* EVIDENCE: admission decision; links name its inputs */
    CX_K_IMPORTED = CX_K_BASE + 0x20    /* CLAIM: record from a non-authoritative store;
                                           tag = CX_SRC_* */
};

/* Sources of CX_K_IMPORTED records (see AUTHORITY above). */
enum { CX_SRC_CORTEX_RS = 1, CX_SRC_AIENOS_CORTEX = 2 };

#define CX_LINKS 4u

typedef struct {
    uint64_t id;             /* 1-based and dense: object id == index + 1 */
    uint32_t cls;            /* CxClass */
    uint32_t kind;           /* fact type within the class; see CX_K_BASE */
    uint64_t subject;        /* the entity the object is about */
    uint64_t t;              /* logical time of the fact */
    uint64_t generation;     /* generation the fact was recorded under */
    uint32_t branch;         /* 0 = the main line; else a hypothetical branch */
    uint32_t protect;        /* CX_PROT_* */
    uint64_t tag;            /* one small header value (cause code, condition key, ...) */
    uint64_t links[CX_LINKS];/* ids of related objects, 0 = none (provenance) */
    uint32_t n;              /* payload words */
    uint64_t off;            /* payload offset in the arena */
    uint8_t digest[32];      /* SHA-256 of the canonical encoding */
} CxObject;

typedef struct {
    uint64_t *ids;
    uint32_t n, cap;
} CxIdList;

typedef struct CxStore {
    CxObject *obj;
    uint64_t n, cap;
    uint64_t *arena;
    uint64_t arena_n, arena_cap;
    CxIdList *by_subject;    /* per subject, in append (= time) order */
    uint64_t n_subjects;
    uint8_t chain[32];       /* running hash over every digest in append order */
    uint64_t examined;       /* objects touched by queries, cumulative */
    /* Journal backing (cx_open_with). jops NULL: memory only. */
    const struct CxJournalOps *jops;
    void *jctx;              /* backend context, handed back to every op */
    void *jh;                /* the open journal, owned by the backend */
    uint32_t open_flags;
    /* The one writer, 0 = unclaimed. While claimed, only cx_append_as with
     * the same token appends. */
    uint64_t writer;
} CxStore;

/* What a writer supplies; id, offset and digest are Cortex's. */
typedef struct {
    uint32_t cls, kind;
    uint64_t subject, t, generation;
    uint32_t branch, protect;
    uint64_t tag;
    uint64_t links[CX_LINKS];
} CxHeader;

enum {
    CX_OK = 0, CX_ERR_ARG = -1, CX_ERR_NOMEM = -2, CX_ERR_ORDER = -3, CX_ERR_DIGEST = -4,
    CX_ERR_WRITER = -5,      /* another writer holds this store or its journal */
    CX_ERR_IO = -6,          /* journal read/write failed; memory state unchanged */
    CX_ERR_FORMAT = -7,      /* not a Cortex journal, or another subject count */
    CX_ERR_TORN = -8         /* journal ends inside a record (see CX_OPEN_REPAIR_TAIL) */
};

int  cx_init(CxStore *s, uint64_t n_subjects);
void cx_free(CxStore *s);    /* also closes and unlocks a journal */

/* Append one object. Per subject, time may not go backwards (CX_ERR_ORDER).
 * CX_ERR_WRITER while a writer has claimed the store. */
int  cx_append(CxStore *s, const CxHeader *h, const uint64_t *payload, uint32_t n, uint64_t *out_id);

/* ---- single writer ------------------------------------------------------ */

/* Claim the store for `token` (nonzero). CX_ERR_WRITER if another token
 * holds it; claiming again with the same token is CX_OK. */
int  cx_claim_writer(CxStore *s, uint64_t token);
void cx_release_writer(CxStore *s, uint64_t token);
/* cx_append for the claimed writer (token 0 = unclaimed store). */
int  cx_append_as(CxStore *s, uint64_t token, const CxHeader *h, const uint64_t *payload,
                  uint32_t n, uint64_t *out_id);

/* ---- journal ------------------------------------------------------------
 * File: 32-byte header (magic, version, n_subjects, reserved) then one
 * record per object: 13 header words, n payload words, 4 digest words, all
 * little-endian. Reopen replays every record through the append path and
 * refuses the journal if any recomputed digest differs from the stored one.
 * Subject numbers are whatever the writer used; for World records they are
 * local object slots (rx_cortex_record.h), runtime indices, not machine or
 * object identity. The reserved header word is kept for that identity.
 */
enum {
    CX_OPEN_READONLY    = 1u << 0,  /* no lock, no writes; for inspection */
    CX_OPEN_SYNC        = 1u << 1,  /* fdatasync after every append */
    CX_OPEN_REPAIR_TAIL = 1u << 2   /* truncate one incomplete trailing record */
};

/* ---- journal backend ------------------------------------------------------
 * The store reaches its journal only through this table. cx_journal_posix is
 * the file backend (one file, flock for the writer lock); it is the default
 * of cx_open and is compiled out under CX_NO_POSIX, where a freestanding host
 * (AIENOS: sealed Store objects, P06 adapter) supplies its own table through
 * cx_open_with. Memory comes from CX_MALLOC / CX_REALLOC / CX_FREE, which a
 * config header named by CX_CONFIG_H may define; the default is libc.
 * The record format, the digests, the chain and every check in cx_open are
 * the same under every backend: a backend stores bytes, it never interprets
 * them. */
typedef struct CxJournalOps {
    /* Open the journal `name`. ro: no lock, no writes, must exist. Writable:
     * create when absent and take the one-writer lock, CX_ERR_WRITER when
     * another writer holds it. *h receives the backend's handle. */
    int  (*open)(void *ctx, const char *name, int ro, void **h);
    /* Current length in bytes. */
    int  (*size)(void *ctx, void *h, size_t *len);
    /* Exactly n bytes at offset off, or an error. */
    int  (*read)(void *ctx, void *h, size_t off, uint8_t *out, size_t n);
    /* Append n bytes as ONE unit: on return either all of them are in the
     * journal (durable when sync != 0) or none of them is, and the length is
     * as before. A partial write is the backend's to undo. */
    int  (*append)(void *ctx, void *h, const uint8_t *b, size_t n, int sync);
    /* Cut the journal back to len bytes, durably (CX_OPEN_REPAIR_TAIL). A
     * backend whose appends are atomic never holds a torn tail and may
     * answer CX_ERR_IO. */
    int  (*truncate)(void *ctx, void *h, size_t len);
    /* Release the handle; a writer's lock drops here. */
    void (*close)(void *ctx, void *h);
} CxJournalOps;

#ifndef CX_NO_POSIX
extern const CxJournalOps cx_journal_posix;
#endif

/* cx_open through an explicit backend; the contract below is unchanged. */
int  cx_open_with(CxStore *s, const CxJournalOps *ops, void *ctx, const char *name,
                  uint64_t n_subjects, uint32_t flags);

/* Open (creating if absent and writable) a journal-backed store. A writable
 * open takes an exclusive lock; a second writable open of the same file,
 * from this or any process, gets CX_ERR_WRITER. n_subjects must match a
 * nonempty journal's. On error the store is left freed.
 *
 * cx_open is the single seam where integrity is established. At open, for
 * every record: the magic word, the id equal to its position (1, 2, 3, ...),
 * and the per-record digest recomputed from header plus payload and compared
 * to the stored one (rx_cortex.c replay). The chain is rebuilt from those
 * digests, not read from disk. Also checked: the subject count against the
 * file header, an incomplete trailing record (CX_ERR_TORN, or truncated when
 * CX_OPEN_REPAIR_TAIL is set), and the writer lock.
 * After a CX_OK open, callers may assume the objects in memory equal the
 * journal, and that cx_verify on an object read from this store cannot fail
 * except through memory corruption or a later in-memory edit.
 * NOT checked by cx_open: a journal cut exactly at a record boundary looks like a
 * shorter valid journal (the file holds no record count or head marker). That
 * cut is detected by rx_compose, which records the Cortex record count and head
 * record digest in the J-Space checkpoint anchor and cross-checks it at open.
 * KNOWN LIMIT: if both the Cortex journal and the J-Space checkpoint roll back
 * together, nothing local detects it (an external anchor problem). */
#ifndef CX_NO_POSIX
int  cx_open(CxStore *s, const char *path, uint64_t n_subjects, uint32_t flags);
#endif
void cx_close(CxStore *s);   /* = cx_free */

const CxObject *cx_get(const CxStore *s, uint64_t id);
const uint64_t *cx_payload(const CxStore *s, const CxObject *o);

/* Recompute an object's digest and compare: CX_OK or CX_ERR_DIGEST. */
int  cx_verify(const CxStore *s, uint64_t id);

/* AUDIT entry point, not needed after cx_open (which already verified every
 * record). Re-hashes every in-memory object, compares each to its stored
 * digest, replays the running hash and compares it to `chain`: CX_OK if all
 * match. For audits and tests. */
int  cx_verify_chain(const CxStore *s);

/* Canonical digest of a header plus payload. */
void cx_digest(const CxObject *o, const uint64_t *payload, uint8_t out[32]);

/* Record that a candidate (CX_CLAIM / CX_K_CANDIDATE) was promoted on the
 * strength of an evidence object (class CX_EVIDENCE). Appends a protected
 * CX_K_PROMOTION about the candidate's subject with links {candidate,
 * evidence}. CX_ERR_ARG if either id is missing or of the wrong kind. */
int  cx_promote(CxStore *s, uint64_t token, uint64_t candidate, uint64_t evidence,
                uint64_t t, uint64_t *out_id);

/* ---- typed queries (every touched object is counted in s->examined) ---- */

/* Matches cls/kind (0 = any), and branch unless branch_any. */
typedef struct {
    uint32_t cls, kind;
    uint32_t branch;
    int branch_any;
} CxFilter;

typedef int (*CxVisit)(void *user, const CxObject *o);

/* Objects of `subject` with t in [t0, t1], oldest first. The visitor returns
 * nonzero to stop. Returns the number visited. */
uint64_t cx_range(CxStore *s, uint64_t subject, uint64_t t0, uint64_t t1,
                  const CxFilter *f, CxVisit visit, void *user);

/* The newest matching object of `subject` with t <= t_max, or 0. */
uint64_t cx_latest(CxStore *s, uint64_t subject, uint64_t t_max, const CxFilter *f);

/* Count of `subject`'s objects with t < t0 (index arithmetic, no scan). */
uint64_t cx_count_before(const CxStore *s, uint64_t subject, uint64_t t0);
uint64_t cx_count_subject(const CxStore *s, uint64_t subject);

/* ---- recall: typed, provenanced records ---------------------------------- */

typedef struct {
    CxObject hdr;               /* copy of the header, links = provenance */
    const uint64_t *payload;    /* valid while the store is unchanged */
    int verified;               /* digest recomputed and matched */
} CxRecord;

/* Like cx_range, but fills up to `max` records (oldest first), each digest
 * checked. Returns the number filled. */
uint32_t cx_recall(CxStore *s, uint64_t subject, uint64_t t0, uint64_t t1,
                   const CxFilter *f, CxRecord *out, uint32_t max);

/* One record by id (CX_OK, CX_ERR_ARG, or CX_ERR_DIGEST with *out still set). */
int  cx_recall_id(const CxStore *s, uint64_t id, CxRecord *out);

/* Every object `id` derives from through links, nearest first, no repeats,
 * at most `max`. Returns the number written. */
uint32_t cx_provenance(const CxStore *s, uint64_t id, uint64_t *out, uint32_t max);

/* ---- World execution record payload (CX_K_WORK_ACCEPTED .. EXEC_FAILED) --
 * Written by rx_cortex_record.c from one World causal crumb. Defined here so
 * a reader needs no World header.
 */
enum {
    CX_WREC_SESSION = 0,  /* World session the writer was attached under */
    CX_WREC_CRUMB,        /* crumb id in that session's causal log */
    CX_WREC_CRUMB_KIND,   /* RxCrumbKind */
    CX_WREC_REACTION,     /* reaction id, UINT32_MAX for outside / create */
    CX_WREC_FACULTY,
    CX_WREC_EPISODE,      /* crumb id of the outside input the episode started from */
    CX_WREC_REASON,       /* crumb reason (sign-extended) */
    CX_WREC_OBJ,          /* object slot, UINT64_MAX = none */
    CX_WREC_OBJ_GEN,
    CX_WREC_OBJ_VERSION,
    CX_WREC_FIELD0,       /* 8 field values of the object after the crumb */
    CX_WREC_DIGEST0 = CX_WREC_FIELD0 + 8, /* crumb digest, 4 little-endian words */
    CX_WREC_N_INPUTS = CX_WREC_DIGEST0 + 4,
    CX_WREC_N_OUTPUTS,
    CX_WREC_T_START_NS,
    CX_WREC_T_END_NS,
    CX_WREC_WORDS
};

typedef struct {
    uint64_t cx_id;
    uint32_t kind;          /* CX_K_* */
    uint64_t session, crumb, episode, obj, obj_gen, obj_version;
    uint32_t crumb_kind, reaction, faculty;
    int32_t reason;
    uint64_t field[8];
    uint8_t crumb_digest[32];
    uint32_t n_inputs, n_outputs;
    uint64_t cause;         /* Cortex id of the record of the crumb that caused it, 0 = none */
} CxWorldRecord;

/* Decode a World execution record: CX_OK, or CX_ERR_ARG if `r` is not one. */
int  cx_world_decode(const CxRecord *r, CxWorldRecord *out);

/* Test hook: overwrite one payload word without updating the digest. */
void cx_tamper(CxStore *s, uint64_t id, uint32_t word, uint64_t value);

#endif /* RX_CORTEX_H */
