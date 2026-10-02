/* continuity_resolve.h -- C port, cut 3: boot resolution of the continuity
 * objects (INV-4..INV-7, contract section 3), the Recovery Core challenge and
 * the operator response (INV-15/16 inputs, contract 1.7 and 5.2).
 *
 * Contract: native/kernel/CONTINUITY_RECOVERY_CONTRACT.md. Oracle: the Rust
 * kernel at aienos 4a116e5: continuity.rs `resolve` (:637-710, "rs:" below),
 * recovery_core.rs `challenge` (:94-104) and `inspect` digest (:109-133),
 * recovery.rs `OperatorAuth` (:103, :124-140).
 *
 * Resolve only. No provision, no commit, no resume (cut 4). Nothing here
 * writes: the storage interface (cr_source) has no write call.
 *
 * Storage access goes through cr_source. continuity_resolve_sealed.c binds it
 * to the real sealed Store (ss_store); the host test drives the real sealed
 * Store in a file and also a fake source for cases the real Store cannot make.
 *
 * Lookup (contract P-3): the table of (kind, version, logical id) is built once
 * per resolve by reading every continuity object of kinds 16, 17, 18, 20 and
 * hashing the plaintext (Store v1 ObjectId rule). The Rust code never sees a
 * logical id twice (Store v1 dedups); the sealed Store gives every write its
 * own envelope, so a logical id that appears twice is Corrupt here.
 *
 * Memory: the Rust Continuity view keeps every Cortex record. The C view keeps
 * the record count and the streamed SHA-256 `memory` digest (contract 1.7),
 * which is all the QEMU markers and a resume need; no record is stored.
 *
 * Nothing here is wired into the kernel. */
#ifndef CK_CONTINUITY_RESOLVE_H
#define CK_CONTINUITY_RESOLVE_H

#include <stddef.h>
#include <stdint.h>

#include "continuity_codec.h"

/* TEST-only mutants for the host mutation run (Makefile continuity-mutants). */
#if defined(CK_HARDWARE_STAGING) &&                                                        \
    (defined(CR_MUTANT_NO_ORPHAN_CHECK) || defined(CR_MUTANT_IGNORE_PREVIOUS) ||           \
     defined(CR_MUTANT_SKIP_CONFLICT) || defined(CR_MUTANT_CHALLENGE_NO_DIGEST) ||         \
     defined(CR_MUTANT_CHALLENGE_NO_ACTION) || defined(CR_MUTANT_COMPARE_16) ||            \
     defined(CR_MUTANT_BARE_SHA256) || defined(CR_MUTANT_NO_DOMAIN))
#error "continuity resolve mutants are TEST-only and refused under CK_HARDWARE_STAGING"
#endif

/* ---- outcomes (ContinuityError, continuity.rs:40-55) ---- */
enum {
    CR_RESOLVED = 0,         /* Ok(Continuity) */
    CR_UNPROVISIONED = 1,    /* ContinuityError::Unprovisioned */
    CR_CONFLICT = 2,         /* ContinuityError::Conflict */
    CR_CORRUPT = 3,          /* ContinuityError::Corrupt(why) */
    CR_LIMIT = 4,            /* ContinuityError::Limit(why) */
    CR_STORE = 5,            /* ContinuityError::Store(e): *store_rc has the error */
    CR_ALREADY_PROVISIONED = 6, /* provision only (cut 4); never returned by resolve */
    CR_READ_ONLY = 7,        /* cr_writable on a mount that is not Valid */
    CR_E_ARG = 8,            /* C only: caller bug (NULL); nothing read */
};
const char *cr_outcome_name(int outcome); /* Rust spelling: "Unprovisioned", ... */

/* Entry reason for a degraded mount: the Recovery Core uses these (cut 5). */
#define CR_MOUNT_VALID 0
#define CR_MOUNT_DEGRADED 1

/* ---- storage interface (read only) ---- */
struct cr_source {
    void *ctx;
    /* Number of verified application objects (sealed claims). */
    uint32_t (*count)(void *ctx);
    /* Application kind and version of object i (no decryption), and nothing
     * else. Returns 0 or a store error. */
    int (*entry)(void *ctx, uint32_t i, uint16_t *kind, uint16_t *version);
    /* Plaintext of object i into out[0..cap). *len is the true length; if it
     * exceeds cap the object is oversize and out is not meaningful. Returns 0
     * or a store error (nonzero, passed through as CR_STORE). */
    int (*read)(void *ctx, uint32_t i, uint8_t *out, size_t cap, size_t *len);
    /* CR_MOUNT_VALID or CR_MOUNT_DEGRADED. */
    int (*mount_state)(void *ctx);
};

/* Objects this layer tracks: kinds 16, 17, 18, 20 (kind 19 is ignored, as in Rust). */
#define CR_TABLE_CAP 4096u /* SV1_MAX_CATALOG_ENTRIES (store/v1.rs:12) */

struct cr_entry {
    uint8_t id[32]; /* logical ObjectId (store v1 rule, kind, claim version) */
    uint64_t seq;   /* manifests: sequence */
    uint8_t root[32];     /* manifests: root */
    uint8_t previous[32]; /* manifests: previous */
    uint32_t src;   /* index in the source */
    uint16_t kind, version;
};

/* Caller-owned scratch, ~0.5 MiB: static storage. */
struct cr_work {
    struct cr_entry t[CR_TABLE_CAP];
    uint32_t n;
    uint32_t mi[CR_TABLE_CAP]; /* manifest table indices, sorted by sequence */
    uint8_t buf[CC_MAX_OBJECT_BYTES];
    struct cc_wal wal;
};

/* The verified continuity view (rs `Continuity`, continuity.rs:726-736). */
struct cr_view {
    uint8_t root_id[32];
    struct cc_root root;
    uint8_t manifest_id[32];
    struct cc_manifest manifest;
    struct cc_state state;
    uint64_t cortex_count;   /* records over all segments */
    uint8_t memory[32];      /* SHA-256 over (len u32 LE || statement) per record; marker prints [0..8) */
};

/* Locate and verify the continuity view without writing. Never creates an
 * identity. Returns a CR_* outcome. For CR_CORRUPT / CR_LIMIT *why (optional)
 * is the Rust reason text (or a C-only reason, see contract section 9); for
 * CR_STORE *store_rc (optional) is the store error. */
int cr_resolve(const struct cr_source *src, struct cr_work *w, struct cr_view *v, const char **why,
               int *store_rc);

/* rs `writable` (continuity.rs:776-781): CR_RESOLVED when the mount is Valid,
 * else CR_READ_ONLY (INV-11). */
int cr_writable(const struct cr_source *src);

/* ---- Recovery Core challenge and operator response ---- */
#define CR_ACTION_REPAIR_DEGRADED_PEER 1u /* recovery_core.rs:38-44 */
#define CR_ACTION_PROVISION_IDENTITY 2u

/* state_digest = SHA-256(unit 0 || unit 1), 4096 bytes each; a unit that could
 * not be read is passed as 4096 zero bytes (recovery_core.rs:109-133). */
void cr_state_digest(const uint8_t unit0[4096], const uint8_t unit1[4096], uint8_t out[32]);
/* SHA-256("AIENOS-RECOVERY-CHALLENGE-v1\0" || uuid || generation u64 LE ||
 * action u8 || state_digest), recovery_core.rs:94-104. */
void cr_challenge(const uint8_t uuid[16], uint64_t generation, uint8_t action,
                  const uint8_t state_digest[32], uint8_t out[32]);
/* HMAC-SHA256(key, "AIENOS-RECOVERY-OPERATOR-AUTH-v1\0" || challenge),
 * recovery.rs:103, :124-140. */
void cr_operator_response(const uint8_t key[32], const uint8_t challenge[32], uint8_t out[32]);
/* 1 if response is the operator response, compared in constant time (all 32 bytes). */
int cr_operator_verify(const uint8_t key[32], const uint8_t challenge[32],
                       const uint8_t response[32]);

#endif /* CK_CONTINUITY_RESOLVE_H */
