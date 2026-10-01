/* continuity_codec.h -- C port, cut 1: canonical encodings of the four M4
 * continuity objects (AgentRoot, ContinuityManifest, AgentState branch table,
 * CortexWalSegment), the branch-id derivations and the logical ObjectId.
 *
 * Contract: native/kernel/CONTINUITY_RECOVERY_CONTRACT.md (aienos#222,
 * SPEC/PROPOSED), sections 1.1-1.7 and INV-1..INV-3. Oracle: the Rust kernel,
 * crates/aienos-kernel/src/continuity.rs at aienos 4a116e5 ("continuity.rs"
 * below). Every layout here cites the Rust line it must match byte for byte.
 *
 * Properties:
 * - No allocation, no globals, no libc: caller-owned structs and buffers.
 *   Needs only native/argus/sha256.{c,h}.
 * - No dependence on the Store. The logical ObjectId is computed here with the
 *   Store v1 rule (crates/aienos-kernel/src/store/v1.rs:27, :63-78); the host
 *   test cross-checks it against sv1_object_id (native/store/store_v1.h:132).
 * - Strict decoders (continuity.rs:97-166): every read bounds checked
 *   ("truncated object"), reserved bytes zero ("nonzero reserved"), the whole
 *   input consumed ("trailing bytes"). The error class and the Rust "why" text
 *   are both returned.
 * - K-1 (contract 5.3, PROPOSED): no continuity object larger than
 *   CC_MAX_OBJECT_BYTES (16384, SS_MAX_PLAINTEXT, native/store/store_sealed.h:46)
 *   is encoded or decoded; both refuse with CC_E_LIMIT, never truncate.
 *
 * QEMU and hardware: nothing here is wired into the kernel yet (cut 1). */
#ifndef CK_CONTINUITY_CODEC_H
#define CK_CONTINUITY_CODEC_H

#include <stddef.h>
#include <stdint.h>

/* TEST-only mutants for the host mutation run (Makefile continuity-mutants).
 * A mutant build exists only to prove the host test fails; it must never be
 * part of a hardware staging image. */
#if defined(CK_HARDWARE_STAGING) && \
    (defined(CC_MUTANT_SKIP_TAKE_BOUND) || defined(CC_MUTANT_ACCEPT_RESERVED) || \
     defined(CC_MUTANT_CHILD_INDEX_LE) || defined(CC_MUTANT_TRUNCATE_AT_CAP) || \
     defined(CC_MUTANT_UNCHECKED_FORK_SUM) || defined(CC_MUTANT_MANIFEST_LAST_WAL_ZERO))
#error "continuity codec mutants are TEST-only and refused under CK_HARDWARE_STAGING"
#endif

/* Store kinds (continuity.rs:19-22) and versions (:24, :26). */
#define CC_KIND_AGENT_ROOT 16u
#define CC_KIND_MANIFEST 17u
#define CC_KIND_AGENT_STATE 18u
#define CC_KIND_CORTEX_WAL 20u
#define CC_STORE_OBJECT_VERSION 1u
#define CC_FORMAT_VERSION 0u

/* Rust bounds (continuity.rs:28-31). */
#define CC_MAX_WAL_SEGMENTS 64u
#define CC_MAX_BRANCHES 256u
#define CC_MAX_WAL_RECORDS 64u
#define CC_MAX_STATEMENT_BYTES 1024u

#define CC_HEADER_BYTES 16u                       /* continuity.rs:33 */
#define CC_ROOT_BYTES (CC_HEADER_BYTES + 96u)     /* ROOT_BODY, continuity.rs:202 */
#define CC_BRANCH_BYTES 80u                       /* BRANCH_BYTES, continuity.rs:340 */
#define CC_WAL_RECORD_FIXED 36u                   /* status, reserved, len, hash: :545-548 */
/* K-1 (PROPOSED): the sealed Store's plaintext cap. */
#define CC_MAX_OBJECT_BYTES 16384u
/* Largest branch table that fits K-1: (16384 - 64) / 80 = 204. */
#define CC_MAX_BRANCHES_IN_CAP ((CC_MAX_OBJECT_BYTES - CC_HEADER_BYTES - 48u) / CC_BRANCH_BYTES)

/* Error classes (ContinuityError, continuity.rs:40-55; only those a codec
 * can return). CC_E_ARG is C-only: a caller bug (NULL, output buffer too
 * small, a value Rust's types cannot hold); nothing is written. */
enum {
    CC_OK = 0,
    CC_E_CORRUPT = 1, /* ContinuityError::Corrupt(why) */
    CC_E_LIMIT = 2,   /* ContinuityError::Limit(why) */
    CC_E_ARG = 3,
};

/* ProvisionSource (continuity.rs:186-191). */
#define CC_SOURCE_OPERATOR 1u
#define CC_SOURCE_QUALIFICATION 2u

/* Epistemic (continuity.rs:490-511). */
#define CC_EPI_DIRECT_OBSERVATION 1u
#define CC_EPI_OPERATOR_DECISION 6u

/* An absent optional id (Option<ObjectId> None, parent None) is all zero,
 * exactly as Rust encodes it (continuity.rs:38, :173-179, :403). */

struct cc_root { /* AgentRoot, continuity.rs:194-200 */
    uint8_t agent_id[32];
    uint8_t store_uuid[16];
    uint8_t root_branch[32];
    uint64_t provisioned_generation;
    uint8_t source; /* CC_SOURCE_* */
};

struct cc_manifest { /* Manifest, continuity.rs:254-261 */
    uint8_t root[32];
    uint8_t previous[32];    /* zero = none */
    uint64_t sequence;
    uint64_t incarnation;
    uint8_t agent_state[32]; /* zero = none */
    uint32_t n_wal;          /* <= CC_MAX_WAL_SEGMENTS */
    uint8_t wal[CC_MAX_WAL_SEGMENTS][32];
};

struct cc_branch { /* Branch, continuity.rs:322-329 */
    uint8_t id[32];
    uint8_t parent[32]; /* zero = root branch */
    uint32_t depth;
    uint64_t forks;
};

struct cc_state { /* AgentState, continuity.rs:332-338; ~20 KiB, caller owned */
    uint8_t agent_id[32];
    uint64_t written_at;
    uint32_t n; /* 1..CC_MAX_BRANCHES */
    struct cc_branch br[CC_MAX_BRANCHES]; /* strictly ascending by id */
};

struct cc_record { /* CortexRecord, continuity.rs:514-518 */
    uint8_t status; /* CC_EPI_* 1..6 */
    uint8_t evidence_hash[32];
    uint16_t len;   /* 1..CC_MAX_STATEMENT_BYTES */
    /* Decode: points into the decoded input buffer (no copy, no
     * allocation); valid only while that buffer is. Encode: read only. */
    const uint8_t *statement;
};

struct cc_wal { /* WalSegment, continuity.rs:521-525 */
    uint64_t sequence;
    uint32_t n; /* 1..CC_MAX_WAL_RECORDS */
    struct cc_record rec[CC_MAX_WAL_RECORDS];
};

/* ---- derivations (contract 1.7, INV-3) ---- */
/* SHA-256("AIENOS_ROOT_BRANCH_v1:" || agent), continuity.rs:69-75. */
void cc_root_branch_id(const uint8_t agent[32], uint8_t out[32]);
/* SHA-256("AIENOS_CHILD_BRANCH_v1:" || parent || index u64 BIG-endian),
 * continuity.rs:77-84. */
void cc_child_branch_id(const uint8_t parent[32], uint64_t index, uint8_t out[32]);
/* Logical ObjectId = ObjectId::calculate(kind, 1, bytes), store/v1.rs:63-78
 * (contract P-2). CC_E_ARG for kind 0 or len 0 (v1.rs:64). */
int cc_object_id(uint16_t kind, const uint8_t *bytes, size_t len, uint8_t out[32]);

/* ---- codecs ----
 * Encoders write the canonical bytes into out[0..cap) and set *len. On any
 * error nothing useful is in out and *len is 0; an object that would exceed
 * CC_MAX_OBJECT_BYTES is CC_E_LIMIT (K-1), an out buffer smaller than the
 * object is CC_E_ARG. Decoders write *v as they read; on error *v holds
 * no meaningful value (no copy: AgentState is ~20 KiB). *why (may be NULL)
 * gets the Rust reason text on CC_E_CORRUPT / CC_E_LIMIT. */
int cc_root_encode(const struct cc_root *v, uint8_t *out, size_t cap, size_t *len,
                   const char **why);
int cc_root_decode(const uint8_t *in, size_t len, struct cc_root *v, const char **why);

int cc_manifest_encode(const struct cc_manifest *v, uint8_t *out, size_t cap, size_t *len,
                       const char **why);
int cc_manifest_decode(const uint8_t *in, size_t len, struct cc_manifest *v, const char **why);

int cc_state_encode(const struct cc_state *v, uint8_t *out, size_t cap, size_t *len,
                    const char **why);
int cc_state_decode(const uint8_t *in, size_t len, struct cc_state *v, const char **why);

int cc_wal_encode(const struct cc_wal *v, uint8_t *out, size_t cap, size_t *len,
                  const char **why);
int cc_wal_decode(const uint8_t *in, size_t len, struct cc_wal *v, const char **why);

/* ---- branch table (continuity.rs:342-482) ---- */
/* AgentState::genesis: only the root branch (continuity.rs:344-355). */
void cc_state_genesis(struct cc_state *s, const uint8_t agent[32], uint64_t written_at);
/* AgentState::validate (continuity.rs:447-481). */
int cc_state_validate(const struct cc_state *s, const char **why);
/* AgentState::fork (continuity.rs:365-390): child id into child_out. */
int cc_state_fork(struct cc_state *s, const uint8_t parent[32], uint8_t child_out[32],
                  const char **why);

#endif /* CK_CONTINUITY_CODEC_H */
