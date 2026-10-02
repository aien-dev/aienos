/* continuity_commit.h -- C port, cut 4: provision, commit and resume of the
 * continuity objects over the sealed Store (contract section 1.3-1.5, INV-4,
 * INV-8..INV-11, K-1, K-2, P-1, P-2).
 *
 * Contract: native/kernel/CONTINUITY_RECOVERY_CONTRACT.md. Oracle: the Rust
 * kernel at aienos 4a116e5: continuity.rs `provision` (:712-772), `commit_with_hook`
 * (:786-855), `resume` (:859-868), nvme_read.rs `summary`/`stop` (:1118-1155).
 *
 * Writes go through cr_sink, one call = ONE Store transaction (INV-8): payload
 * objects and the manifest together, in the order AgentState, WAL, Manifest.
 * continuity_resolve_sealed.c binds it to ss_transact (<= SS_MAX_OBJECTS = 8,
 * this layer writes <= 3). Cross references are logical ObjectIds (P-2).
 *
 * Nothing here is wired into the kernel. */
#ifndef CK_CONTINUITY_COMMIT_H
#define CK_CONTINUITY_COMMIT_H

#include <stddef.h>
#include <stdint.h>

#include "continuity_resolve.h"
#include "entropy.h"

/* TEST-only mutants for the host mutation run (Makefile continuity-mutants).
 * MC-11 (silent truncation) is CC_MUTANT_TRUNCATE_AT_CAP in continuity_codec.h. */
#if defined(CK_HARDWARE_STAGING) &&                                                          \
    (defined(CM_MUTANT_RESUME_PROVISIONS) || defined(CM_MUTANT_RESUME_NO_COMMIT) ||          \
     defined(CM_MUTANT_PROVISION_WITH_ROOT) || defined(CM_MUTANT_SPLIT_TXN) ||               \
     defined(CM_MUTANT_NO_WRITABLE_CHECK) || defined(CM_MUTANT_FIXED_AGENT))
#error "continuity commit mutants are TEST-only and refused under CK_HARDWARE_STAGING"
#endif

/* One object of a transaction (an application object, not an envelope). */
struct cr_wobj {
    uint16_t kind, version;
    const uint8_t *bytes;
    size_t len;
};

/* Write interface: all n objects commit atomically in one Store transaction
 * or none do. Returns 0 or a store error (passed through as CR_STORE). */
struct cr_sink {
    void *ctx;
    int (*transact)(void *ctx, const struct cr_wobj *objs, size_t n);
};

/* rs `Update` (continuity.rs:178-184): optional new branch table, optional new
 * Cortex records (one WAL segment). Records are only read. */
struct cr_update {
    const struct cc_state *state; /* NULL = keep the current one */
    const struct cc_record *rec;  /* NULL / n_rec 0 = no WAL segment */
    uint32_t n_rec;
};

/* Caller-owned scratch for the objects of one transaction (static storage). */
struct cr_txwork {
    uint8_t b[3][CC_MAX_OBJECT_BYTES];
    struct cc_state state;
    struct cc_manifest man;
    struct cc_wal wal;
    struct cr_view tmp;
};

/* rs `provision`. Order of refusals: not writable (CR_READ_ONLY, INV-11);
 * a root exists (CR_ALREADY_PROVISIONED, also on Conflict); orphans or any
 * other unreadable state (the resolve outcome: Corrupt, Limit, Store);
 * no entropy (CR_NO_ENTROPY, nothing written, no fallback); zero agent
 * (CR_CORRUPT). Writes AgentRoot + genesis AgentState + Manifest 1 in ONE
 * transaction and returns the resolved view (CR_RESOLVED). `source` is
 * CC_SOURCE_*. store_uuid is the Store's uuid. */
int cr_provision(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
                 struct cr_txwork *tw, struct ck_rng *rng, const uint8_t store_uuid[16],
                 uint8_t source, struct cr_view *out, const char **why, int *store_rc);

/* rs `commit`: one transaction for the optional state, the optional WAL
 * segment and the new manifest; then re-resolve into out (must not alias cur).
 * K-1: an object over 16384 bytes is CR_LIMIT and nothing is written. */
int cr_commit(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
              struct cr_txwork *tw, const struct cr_view *cur, const struct cr_update *up,
              int new_incarnation, struct cr_view *out, const char **why, int *store_rc);

/* rs `resume`: resolve; on a mount that is not Valid return the view with
 * *committed = 0 (INV-11); else commit incarnation + 1 before returning
 * (INV-10). Never mints an identity: Unprovisioned stays CR_UNPROVISIONED (INV-4). */
int cr_resume(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
              struct cr_txwork *tw, struct cr_view *out, int *committed, const char **why,
              int *store_rc);

/* ---- serial markers (contract section 3, nvme_read.rs:1118-1155) ----
 * Write the NUL-terminated line, without newline, into out[0..cap). Return the
 * length, or 0 when cap is too small. word: "PROVISIONED", "RESUMED",
 * "RESUMED_READONLY", "REMEMBERED", "COMMITTED". */
size_t cr_marker_view(char *out, size_t cap, const char *word, const struct cr_view *v);
/* UNPROVISIONED, CONFLICT, CORRUPT (why), NO_ENTROPY, else STOP (<Rust spelling>).
 * For CR_STORE the text is `STOP (Store(<rc>))` (rc decimal; Rust prints the
 * Debug of its own error, which differs). */
size_t cr_marker_outcome(char *out, size_t cap, int outcome, const char *why, int store_rc);

#endif /* CK_CONTINUITY_COMMIT_H */
