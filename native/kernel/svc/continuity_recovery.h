/* continuity_recovery.h -- C port, cut 5: the Recovery Core over the sealed
 * Store: read-only inspection, entry reasons, the one action each state admits,
 * and the operator-authorised actions (contract section 4, INV-13..INV-18,
 * MR-1..MR-9, K-3/K-4 notes).
 *
 * Contract: native/kernel/CONTINUITY_RECOVERY_CONTRACT.md. Oracle: the Rust
 * kernel crates/aienos-kernel/src/recovery_core.rs (`inspect` :107-187,
 * `applicable` :79-90, `challenge` :94-104, `repair_degraded_peer` :244-257,
 * `provision_identity` :262-273).
 *
 * No model, no network, no clock. Inspection NEVER writes (INV-13): it reads
 * units 0 and 1 of the Store region and opens the sealed Store, which does not
 * write. Every write is an explicit operator action; each one re-inspects, requires
 * rc_applicable() == action (else RC_NOT_APPLICABLE), then a verifying operator
 * response (else RC_UNAUTHORISED), and only then writes (INV-16).
 *
 * The operator key is a parameter. The TEST-only key of the Rust qualification
 * (0x0f x 32) is the caller's business; this file contains no key.
 *
 * Status: host PASS over the real sealed Store in a file. Not wired into the
 * kernel; no QEMU run (M4_RECOVERY stays NOT_RUN). */
#ifndef CK_CONTINUITY_RECOVERY_H
#define CK_CONTINUITY_RECOVERY_H

#include <stddef.h>
#include <stdint.h>

#include "continuity_commit.h"
#include "continuity_resolve_sealed.h"

/* TEST-only mutants for the host mutation run (Makefile continuity-mutants).
 * MR-1 inspection writes (repairs on inspect), MR-5 applicable() treats a
 * degraded mount as Unprovisioned (the fe2c2bd bug), MR-6 repair zeroes the
 * active slot, MR-7 repair offered without a resolved identity, MR-9 operator
 * provisioning writes source Qualification. */
#if defined(CK_HARDWARE_STAGING) &&                                                          \
    (defined(RC_MUTANT_INSPECT_WRITES) || defined(RC_MUTANT_DEGRADED_IS_UNPROVISIONED) ||    \
     defined(RC_MUTANT_REPAIR_ACTIVE) || defined(RC_MUTANT_REPAIR_NO_IDENTITY) ||            \
     defined(RC_MUTANT_PROVISION_QUALIFICATION))
#error "continuity recovery mutants are TEST-only and refused under CK_HARDWARE_STAGING"
#endif

/* What one superblock slot holds (SlotView, recovery_core.rs:17-22). */
enum { RC_SLOT_ZERO = 0, RC_SLOT_SUPERBLOCK = 1, RC_SLOT_UNDECODABLE = 2, RC_SLOT_READ_ERROR = 3 };

/* Why the Recovery Core was entered (EntryReason, recovery_core.rs:25-33).
 * RC_REASON_NONE: a normal boot may proceed.
 * RC_SEALED_REFUSAL is C only (contract K-3/K-4): the sealed mount (keyed proof,
 * anti-rollback anchor, envelope or transaction record) refused before continuity
 * could run. It admits no action (INV-15). */
enum {
    RC_REASON_NONE = 0,
    RC_STORE_UNFORMATTED,
    RC_STORE_MOUNT,      /* ST_M_* other than unformatted: record.mount_rc */
    RC_SEALED_REFUSAL,   /* SS_E_*: record.mount_rc */
    RC_UNPROVISIONED,
    RC_CONFLICT,
    RC_CONTINUITY_CORRUPT, /* record.why */
    RC_DEGRADED,         /* record.peer (ST_PEER_*) */
};

/* The read-only raw system record (SystemRecord, recovery_core.rs:61-73). */
struct rc_record {
    int slot[2];              /* RC_SLOT_* */
    uint64_t slot_generation[2]; /* valid when slot[i] == RC_SLOT_SUPERBLOCK */
    uint8_t state_digest[32]; /* SHA-256 over both raw units: binds challenges */
    int have_uuid;            /* from the first decodable slot */
    uint8_t uuid[16];
    int have_mount;           /* the sealed Store mounted */
    int mount_state;          /* ST_VALID or ST_DEGRADED_RECOVERY */
    int peer;                 /* ST_PEER_* */
    uint64_t generation;
    int reason;               /* RC_* */
    int mount_rc;             /* RC_STORE_MOUNT / RC_SEALED_REFUSAL: the error */
    const char *why;          /* RC_CONTINUITY_CORRUPT: static text */
    int have_identity;        /* continuity resolved (a view exists) */
    uint8_t agent_id[32];
    int have_catalog;
    uint32_t n_roots, n_manifests, n_other; /* verified application objects (claims) */
};

/* Caller-owned environment. The Store is opened into `store` and stays open
 * after rc_inspect (an action reuses it for provisioning). `view` receives the
 * resolved continuity. */
struct rc_env {
    const st_dev *dev;           /* Store region, 4096-byte units */
    const ts_device *anchor;     /* anchor region device */
    uint64_t anchor_lba;
    const ss_keys *keys;
    ss_workspace *ws;
    ss_store *store;
    struct cr_work *w;
    struct cr_txwork *tw;
    struct cr_view *view;
};

/* Inspect in place. Never writes (INV-13). Returns 0, or -1 for a NULL argument
 * (record untouched). */
int rc_inspect(const struct rc_env *e, struct rc_record *rec);

/* The action this state admits: CR_ACTION_REPAIR_DEGRADED_PEER, CR_ACTION_PROVISION_IDENTITY
 * or 0 (INV-15). Fails toward preservation:
 *  - repair only a Malformed peer and only with a resolved identity (MR-7);
 *  - provision only on a Valid mount that reads Unprovisioned (MR-5): a degraded
 *    mount is never treated as unprovisioned;
 *  - everything else (sealed refusals, conflicts, corrupt continuity, unformatted
 *    stores, a CRC-valid newer root whose graph is broken) admits nothing. */
int rc_applicable(const struct rc_record *rec);

/* Challenge for `action` on exactly this state (cr_challenge over the record's
 * uuid, generation, action and state digest). 1 on success, 0 when the record
 * has no uuid or no mount (recovery_core.rs:94-104). */
int rc_challenge(const struct rc_record *rec, uint8_t action, uint8_t out[32]);

/* Action outcomes (RecoveryError, recovery_core.rs:199-207). */
enum {
    RC_OK = 0,
    RC_NOT_APPLICABLE = 1,
    RC_UNAUTHORISED = 2,
    RC_IO = 3,
    RC_CONTINUITY = 4, /* provisioning refused: *cr_outcome has the CR_* outcome */
    RC_E_ARG = 5,
};
const char *rc_outcome_name(int rc);

/* Zero the INACTIVE superblock slot (1 - active, never the active one: MR-6) of
 * a degraded store after the operator's response verifies, flush, re-inspect
 * into *after (optional). Nothing is written unless authorisation passes. */
int rc_repair_degraded_peer(const struct rc_env *e, const uint8_t operator_key[32],
                            const uint8_t response[32], struct rc_record *after);

/* Provision the one identity on a Valid, unprovisioned store after the
 * operator's response verifies. Writes source Operator (INV-18, MR-9), with the
 * Store uuid taken from the inspection. Entropy comes from rng (no fallback:
 * cut 4). On RC_CONTINUITY, *cr_outcome, *why and *store_rc (all optional) say why. */
int rc_provision_identity(const struct rc_env *e, const uint8_t operator_key[32],
                          const uint8_t response[32], struct ck_rng *rng, struct cr_view *out,
                          int *cr_outcome, const char **why, int *store_rc);

/* ---- serial markers (contract section 3; the Rust Debug spellings) ----
 * Write the NUL-terminated line, without newline; return its length, 0 when cap
 * is too small. */
const char *rc_peer_name(int peer); /* "Zero", "Valid", "Malformed", "GraphBadNewer", "GraphBadOlder" */
/* "Degraded(Malformed)", "Unprovisioned", "ContinuityCorrupt(\"why\")", "StoreMount(rc)",
 * "SealedRefusal(rc)" (C only), ... */
size_t rc_reason_text(char *out, size_t cap, const struct rc_record *rec);
/* "RECOVERY_CORE: ENTERED reason=<text>" or "RECOVERY_CORE: NOT_NEEDED". */
size_t rc_marker_entry(char *out, size_t cap, const struct rc_record *rec);
/* "RECOVERY_CHALLENGE: action=<name> challenge=<64 hex>" (0 when no challenge). */
size_t rc_marker_challenge(char *out, size_t cap, const struct rc_record *rec, uint8_t action);
/* "RECOVERY_REFUSED (<NotApplicable|Unauthorised|Io|Continuity(<outcome>)>)". */
size_t rc_marker_refused(char *out, size_t cap, int rc, int cr_outcome);
/* "RECOVERY_ACTION: <name> DONE" (agent != NULL: " agent=<64 hex>"). */
size_t rc_marker_done(char *out, size_t cap, uint8_t action, const uint8_t *agent);

#endif /* CK_CONTINUITY_RECOVERY_H */
