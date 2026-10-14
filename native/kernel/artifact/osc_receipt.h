/* osc_receipt.h -- verification of Omega realization receipts (receipt v1) for OSC unit launch (aienos#383).
 *
 * Contract: aien-dev/omega spec/one-layer-receipts.md (normative; section numbers below refer to it), the
 * receipt format minted by omega's independent checker `checker2 receipt issue` (omega#448). This verifier was
 * written from that spec; no checker2 code was copied. It reuses the in-tree SHA-256 (argus/sha256.c) and
 * Ed25519 verify (sig/ed25519.c) and adds no crypto of its own.
 *
 * What a receipt says (spec section 1): checker2 judged one exact program (OSC IR) and accepted it, the
 * executable is bound to it by hash only (evidence class 1 is NOT translation validation), and a key of a
 * stated class vouches for that record. A receipt grants no capability: grants stay with the unit's
 * capability table and the kernel's authority, unchanged.
 *
 * osc_receipt_verify is a pure function of (receipt bytes, admitted unit, policy): no allocation, no global
 * state, no I/O. It runs AFTER osc_unit_admit accepted the unit and does not change admission. It returns 0
 * (the receipt is valid for this unit under this policy) or the FIRST refusal in the fixed order of spec
 * section 6, as a kernel code OSC_RCPT_BASE + the spec's stable reason number.
 *
 * Bound to the admitted unit: program = the unit's ir_sha256 (section 1 hash), executable = its code_sha256,
 * target = SHA-256("OMEGA-TARGET-V1\0" || OSC_RCPT_TARGET_NAME), firmware = none (all zero unless the policy
 * names one), dependencies = the empty list (the kernel resolves no dependency receipts, so any claimed
 * dependency is refused). Checker identity: required to be in the policy's list (an empty list refuses every
 * receipt). Producer: none (all zero unless the policy names one; the unit carries no producer identity). NOT bound by a receipt: the container
 * manifest (entry table, capability table, stack and tick budgets); those stay bound by the unit signature.
 * Requirements and input fields are NOT CHECKED. Evidence class 2 (LRAT): spec section 10 makes a class 2 receipt
 * valid only when its proofs are given and replayed; the kernel has no proofs and no LRAT checker, so it refuses
 * class 2 as RECEIPT_LRAT_PROOFS_REQUIRED (fail closed; see docs/osc-receipts.md). */
#ifndef AIENOS_CK_OSC_RECEIPT_H
#define AIENOS_CK_OSC_RECEIPT_H
#include <stddef.h>
#include <stdint.h>
#include "osc_unit.h"

#define OSC_RCPT_BYTES 416u
#define OSC_RCPT_SIGNED_BYTES 352u
/* The kernel's target name (spec section 2, offset 208). Chosen for aienos#383: an OSC unit run as an EL0 task of
 * the AIENOS C kernel on AArch64. Receipts for this kernel are issued with `--target aienos-ck-aarch64-el0`. */
#define OSC_RCPT_TARGET_NAME "aienos-ck-aarch64-el0"

/* Kernel refusal codes: OSC_RCPT_BASE + the spec section 6 reason number (stable). They share the osc_code
 * space of osc_unit.h (osc_code_name names them "RECEIPT_<spec name>") and fit osc_result.refused_code. */
#define OSC_RCPT_BASE 64u
enum osc_rcpt_code {
    OSC_RCPT_MISSING = 64,              /* kernel only: no receipt came with the unit */
    OSC_RCPT_SIZE = 65,                 /* 1: not exactly 416 bytes */
    OSC_RCPT_MAGIC = 66,                /* 2 */
    OSC_RCPT_VERSION = 67,              /* 3 */
    OSC_RCPT_SIGNATURE_ALGORITHM = 68,  /* 4 */
    OSC_RCPT_SIGNER_CLASS = 69,         /* 5 */
    OSC_RCPT_EVIDENCE_CLASS = 70,       /* 6 */
    OSC_RCPT_EPOCH_ORDER = 71,          /* 7: expiry below the policy epoch */
    OSC_RCPT_TEST_SIGNER_IN_PRODUCTION = 73, /* 9: release mode and not OWNER */
    OSC_RCPT_UNTRUSTED_SIGNER = 74,     /* 10 */
    OSC_RCPT_BAD_SIGNATURE = 75,        /* 11 */
    OSC_RCPT_REVOKED = 76,              /* 12: receipt id, then signer key fingerprint */
    OSC_RCPT_STALE_EPOCH = 77,          /* 13: policy epoch below the floor (replay of a superseded receipt) */
    OSC_RCPT_EXPIRED = 78,              /* 14 */
    OSC_RCPT_NOT_YET_VALID = 79,        /* 15 */
    OSC_RCPT_WRONG_TARGET = 80,         /* 16 */
    OSC_RCPT_WRONG_FIRMWARE = 81,       /* 17 */
    OSC_RCPT_PROGRAM_MISMATCH = 82,     /* 18 */
    OSC_RCPT_EXECUTABLE_MISMATCH = 83,  /* 19 */
    OSC_RCPT_ARGUMENT = 84,             /* 20: verifier called without a unit or a policy */
    OSC_RCPT_UNTRUSTED_CHECKER = 86,    /* 22 */
    OSC_RCPT_WRONG_PRODUCER = 87,       /* 23 */
    OSC_RCPT_DEPENDENCIES_MISMATCH = 88, /* 24 */
    /* kernel-assigned: spec section 10 names LRAT-PROOFS-REQUIRED without a number. The kernel is given no LRAT
     * proofs, so every evidence class 2 receipt that passes the section 6 steps is refused with it. */
    OSC_RCPT_LRAT_PROOFS_REQUIRED = 96
};

enum { OSC_RCPT_REVOKED_ID = 1, OSC_RCPT_REVOKED_KEY = 2 };

/* Facts about a receipt, filled as far as the verifier got (id once the length is right, the rest after the
 * structure checks). Diagnostic only: nothing here is authority. */
struct osc_receipt_info {
    uint8_t id[32];          /* SHA-256 of the 416 bytes (spec section 2) */
    uint16_t signer_class;   /* OSC_SIGNER_TEST or OSC_SIGNER_OWNER */
    uint16_t evidence_class; /* 1 IR_CHECKED, 2 IR_CHECKED_LRAT (refused: no proofs to replay) */
    uint64_t policy_epoch, expiry_epoch;
    unsigned revoked;        /* OSC_RCPT_REVOKED_ID or OSC_RCPT_REVOKED_KEY when the verdict is REVOKED */
    int have_id;
};

/* 0: valid for unit *a under *p. Else the first refusal code (OSC_RCPT_*). r == NULL or len == 0 is
 * OSC_RCPT_MISSING. info may be NULL. */
unsigned osc_receipt_verify(const uint8_t *r, size_t len, const struct osc_accept *a, const struct osc_policy *p,
                            struct osc_receipt_info *info);

/* SHA-256("OMEGA-TARGET-V1\0" || name) (spec section 2, offset 208). */
void osc_receipt_target_hash(const char *name, size_t name_len, uint8_t out[32]);

#endif
