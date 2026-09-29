/*
 * aienos_contain.h -- AEGIS containment gate (ARGUS-1 lane G).
 *
 * Spec: native/argus/docs/ARGUS1_SPEC.md sections 0 (I1-I5) and 5.
 *
 * The gate sits beside the capability authority. It takes a containment
 * request (a proposal, never authority), decides GRANT / DENY / ESCALATE, and
 * for a granted RevokeCapability performs exactly one revoke of one ordinary,
 * leaf capability of one subject, using a REVOKE-only executor capability it
 * minted once at create. It never mints, widens, delegates or promotes
 * anything else, and no request can make it.
 *
 * Every decision and every execution attempt yields a receipt (request
 * digest, generation, actor, subject, a strictly increasing gate sequence
 * number), returned to the caller and sent to the sink, so every exercise of
 * the defensive right can be audited (I5).
 *
 * Invariants as enforced here:
 *   I1  Automatic GRANT only for RevokeCapability of a LIVE, leaf, non-
 *       privileged cap at exactly the requested generation, of a subject
 *       that holds no privileged cap, with neither SYNTHETIC nor SATURATION.
 *       Re-checked right before the revoke. The authority always cascades,
 *       so the gate counts the authority's REVOKE announcements during its
 *       call: anything but exactly one -> FAILED_SCOPE and the gate goes
 *       inert (every later request ESCALATE).
 *   I2  No executor exists for any type but RevokeCapability. The type
 *       AIENOS_CONTAIN_FREEZE_PRINCIPAL is a named stand-in: execute answers
 *       UNAVAILABLE; a test executor (seam) may answer, and its receipts
 *       always carry AIENOS_CREQ_SYNTHETIC.
 *   I3  No request type expresses a whole-system action. Non-revoke types are
 *       never granted without resolve. Budget: at most AIENOS_CONTAIN_BUDGET
 *       automatic grants per AIENOS_CONTAIN_BUDGET_WINDOW decisions; beyond
 *       that ESCALATE.
 *   I4  The gate is never called by aienos_cap_validate; it acts only on a
 *       submitted request. aienos_capability.c is not modified.
 *   I5  aienos_cap_mint is called once, in aienos_contain_create, for the
 *       executor (rights REVOKE only, subject AIENOS_CONTAIN_SUBJ, no parent,
 *       no lease). A second create for the same authority is refused. If the
 *       executor stops being LIVE the gate never re-mints: it escalates.
 *
 * No malloc and no clock: the caller supplies memory, time is the authority
 * clock (aienos_cap_clock). Thread use: one bridge thread calls submit /
 * resolve / execute; lineage_observe may arrive from any thread.
 */
#ifndef AIENOS_CONTAIN_H
#define AIENOS_CONTAIN_H

#include <stddef.h>
#include <stdint.h>

#include "aienos_capability.h"

/* The gate's executor subject. Chosen by lane G: 43, next to the AEGIS
 * subjects 41 (RX_AEGIS_SUBJ) and 42 (RX_AEGIS_ROOT_SUBJ), unused by any
 * Omega or AIENOS subject. Protected like 41 and 42 (I5.b). */
#define AIENOS_CONTAIN_SUBJ 43u
#define AIENOS_CONTAIN_SUBJ_AEGIS 41u      /* == RX_AEGIS_SUBJ, ARGUS_SUBJ_AEGIS */
#define AIENOS_CONTAIN_SUBJ_AEGIS_ROOT 42u /* == RX_AEGIS_ROOT_SUBJ, ARGUS_SUBJ_AEGIS_ROOT */

/* Actor in a receipt: who made the step. */
#define AIENOS_CONTAIN_ACTOR_GATE AIENOS_CONTAIN_SUBJ
#define AIENOS_CONTAIN_ACTOR_OFFICE 0u     /* resolve with the office secret (the human) */

#define AIENOS_CONTAIN_BUDGET 8u           /* automatic grants per window (I3.b) */
#define AIENOS_CONTAIN_BUDGET_WINDOW 64u   /* decisions per window */
#define AIENOS_CONTAIN_DECISIONS 32u       /* decisions remembered for resolve / execute */
#define AIENOS_CONTAIN_REGISTRY 256u       /* authorities a process may create gates for */

#define AIENOS_CONTAIN_REQUEST_SIZE 152u   /* canonical encoding, == ARGUS_CONTAIN_REQUEST_SIZE */
#define AIENOS_CONTAIN_REQUEST_VERSION 2u  /* == ARGUS_CONTAIN_REQUEST_VERSION */
#define AIENOS_CONTAIN_DIGEST_LEN 32u
#define AIENOS_CONTAIN_MACHINE_ID_LEN 32u
#define AIENOS_CONTAIN_SECRET_LEN 32u      /* office secret presented to resolve */
#define AIENOS_CONTAIN_CAP_NONE UINT32_MAX /* == ARGUS_CAP_NONE */

/* Request types, == ARGUS_CONTAIN_* 1..10. Only RevokeCapability is LIVE. */
enum {
    AIENOS_CONTAIN_REVOKE_CAPABILITY = 1,
    AIENOS_CONTAIN_FREEZE_PRINCIPAL = 2,   /* stand-in only: no executor exists (I2) */
    AIENOS_CONTAIN_RESTRICT_PRINCIPAL = 3,
    AIENOS_CONTAIN_QUARANTINE_MACHINE = 4,
    AIENOS_CONTAIN_QUARANTINE_PROVIDER = 5,
    AIENOS_CONTAIN_REVOKE_CREDENTIAL_LEASE = 6,
    AIENOS_CONTAIN_REJECT_ARTIFACT = 7,
    AIENOS_CONTAIN_REQUIRE_REATTESTATION = 8,
    AIENOS_CONTAIN_RAISE_EFFECT_CLASS = 9,
    AIENOS_CONTAIN_PAUSE_EXTERNAL_EFFECTS = 10,
    AIENOS_CONTAIN_TYPE_MAX = 10
};

/* Request flags, == ARGUS_CREQ_*. */
#define AIENOS_CREQ_SYNTHETIC 0x0001u
#define AIENOS_CREQ_SATURATION 0x0002u
#define AIENOS_CREQ_KNOWN 0x0003u

/* Receipt status, == ARGUS_CSTATUS_*: 1-3 for a decision, 4-8 for an execution. */
enum {
    AIENOS_CONTAIN_GRANT = 1,
    AIENOS_CONTAIN_DENY = 2,
    AIENOS_CONTAIN_ESCALATE = 3,
    AIENOS_CONTAIN_DONE = 4,
    AIENOS_CONTAIN_PARTIAL = 5,
    AIENOS_CONTAIN_FAILED = 6,
    AIENOS_CONTAIN_UNAVAILABLE = 7,
    AIENOS_CONTAIN_FAILED_SCOPE = 8
};

/* Receipt kind, == ARGUS_EV_CONTAINMENT_DECIDED / _EXECUTED. */
#define AIENOS_CONTAIN_KIND_DECIDED 91u
#define AIENOS_CONTAIN_KIND_EXECUTED 92u

/* WHY codes (spec 5.2). */
enum {
    AIENOS_CONTAIN_WHY_POLICY_GRANT = 1100,
    AIENOS_CONTAIN_WHY_POLICY_DENY = 1101,
    AIENOS_CONTAIN_WHY_POLICY_ESCALATE = 1102,
    AIENOS_CONTAIN_WHY_PROTECTED_TARGET = 1103,
    AIENOS_CONTAIN_WHY_TARGET_NOT_LIVE = 1104,
    AIENOS_CONTAIN_WHY_SUBJECT_MISMATCH = 1105,
    AIENOS_CONTAIN_WHY_REPLAYED_REQUEST = 1106,
    AIENOS_CONTAIN_WHY_BUDGET = 1107,
    AIENOS_CONTAIN_WHY_BAD_REQUEST = 1108,
    AIENOS_CONTAIN_WHY_NO_EXECUTOR = 1109,
    AIENOS_CONTAIN_WHY_HUMAN_DENY = 1110,
    AIENOS_CONTAIN_WHY_HUMAN_GRANT = 1111,
    AIENOS_CONTAIN_WHY_BAD_SECRET = 1112,
    AIENOS_CONTAIN_WHY_DECISION_REPLAY = 1113,
    AIENOS_CONTAIN_WHY_NOT_LEAF = 1114,
    AIENOS_CONTAIN_WHY_LINEAGE_UNTRUSTED = 1115,
    AIENOS_CONTAIN_WHY_NOT_AUTO_ELIGIBLE = 1116
};

/* Receipt gate flags (receipt.gate_flags; not request flags). */
#define AIENOS_CONTAIN_RF_REFUSED_CALL 0x0001u /* a refused call, no state change (e.g. bad secret, second execute) */
#define AIENOS_CONTAIN_RF_HUMAN 0x0002u        /* the step came from resolve */
#define AIENOS_CONTAIN_RF_SEAM 0x0004u         /* a test seam was active */
#define AIENOS_CONTAIN_RF_INERT 0x0008u        /* the gate is inert after this step */

/* Function results. A decision (even DENY) is AIENOS_CONTAIN_OK: the verdict
 * is in the receipt. Errors mean the call itself was refused. */
#define AIENOS_CONTAIN_OK 0
#define AIENOS_CONTAIN_ERR_ARG (-1)
#define AIENOS_CONTAIN_ERR_SPACE (-2)
#define AIENOS_CONTAIN_ERR_EXISTS (-3)      /* a gate already exists for this authority */
#define AIENOS_CONTAIN_ERR_AUTHORITY (-4)   /* the executor mint failed */
#define AIENOS_CONTAIN_ERR_UNKNOWN (-5)     /* no such decision */
#define AIENOS_CONTAIN_ERR_REFUSED (-6)     /* refused and announced */
#define AIENOS_CONTAIN_ERR_FULL (-7)        /* the create registry is full */

/* Layout twin of ArgusContainmentRequest (native/argus/argus_abi.h). The
 * gate never includes argus_abi.h nor links libargus; contain_test.c asserts
 * every offsetof and the size are equal. */
typedef struct {
    uint64_t incident_id;
    uint8_t containment;       /* AIENOS_CONTAIN_* request type */
    uint8_t severity;          /* 1..5 (ARGUS_SEV_*) */
    uint16_t finding_code;
    uint32_t principal;        /* target subject; 0 = not set */
    AienosCapRef target;       /* cap and generation to act on */
    uint8_t machine_id[AIENOS_CONTAIN_MACHINE_ID_LEN];
    uint8_t finding_digest[AIENOS_CONTAIN_DIGEST_LEN];
    uint64_t request_id;       /* strictly increasing from 1 */
    uint64_t finding_sequence; /* never 0 */
    uint32_t target_object;
    uint32_t target_rights;    /* RestrictPrincipal only; 0 otherwise */
    uint8_t target_digest[AIENOS_CONTAIN_DIGEST_LEN];
    uint16_t flags;            /* AIENOS_CREQ_* */
    uint8_t version;           /* AIENOS_CONTAIN_REQUEST_VERSION */
    uint8_t reserved;          /* 0 */
} AienosContainRequest;

_Static_assert(sizeof(AienosCapRef) == 16, "AienosCapRef layout");
_Static_assert(offsetof(AienosContainRequest, incident_id) == 0, "twin layout");
_Static_assert(offsetof(AienosContainRequest, containment) == 8, "twin layout");
_Static_assert(offsetof(AienosContainRequest, severity) == 9, "twin layout");
_Static_assert(offsetof(AienosContainRequest, finding_code) == 10, "twin layout");
_Static_assert(offsetof(AienosContainRequest, principal) == 12, "twin layout");
_Static_assert(offsetof(AienosContainRequest, target) == 16, "twin layout");
_Static_assert(offsetof(AienosContainRequest, machine_id) == 32, "twin layout");
_Static_assert(offsetof(AienosContainRequest, finding_digest) == 64, "twin layout");
_Static_assert(offsetof(AienosContainRequest, request_id) == 96, "twin layout");
_Static_assert(offsetof(AienosContainRequest, finding_sequence) == 104, "twin layout");
_Static_assert(offsetof(AienosContainRequest, target_object) == 112, "twin layout");
_Static_assert(offsetof(AienosContainRequest, target_rights) == 116, "twin layout");
_Static_assert(offsetof(AienosContainRequest, target_digest) == 120, "twin layout");
_Static_assert(offsetof(AienosContainRequest, flags) == 152, "twin layout");
_Static_assert(offsetof(AienosContainRequest, version) == 154, "twin layout");
_Static_assert(offsetof(AienosContainRequest, reserved) == 155, "twin layout");
_Static_assert(sizeof(AienosContainRequest) == 160, "twin layout");

/* One receipt per decision and per execution attempt, including refused
 * calls. seq is strictly increasing over every receipt of the gate. */
typedef struct {
    uint64_t seq;               /* gate sequence, from 1 */
    uint64_t decision_id;       /* strictly increasing from 1; 0 if none was made */
    uint64_t request_id;        /* echo */
    uint64_t finding_sequence;  /* echo */
    uint64_t tick;              /* aienos_cap_clock at the step */
    uint64_t resource;          /* DECIDED: decision_id; EXECUTED: low32 slots revoked, high32 refused */
    AienosCapRef target;        /* echo; its generation is the one the gate checked */
    AienosCapRef executor;      /* the gate's executor ref */
    uint32_t principal;         /* subject (echo) */
    uint32_t actor;             /* AIENOS_CONTAIN_ACTOR_GATE or _OFFICE */
    int32_t rc;                 /* authority rc of the revoke (EXECUTED), else 0 */
    uint16_t why;               /* AIENOS_CONTAIN_WHY_*; 0 for a successful execution */
    uint16_t finding_code;      /* echo */
    uint16_t flags;             /* request flags echo, plus AIENOS_CREQ_SYNTHETIC for a test executor */
    uint16_t gate_flags;        /* AIENOS_CONTAIN_RF_* */
    uint8_t kind;               /* AIENOS_CONTAIN_KIND_DECIDED / _EXECUTED */
    uint8_t status;             /* AIENOS_CONTAIN_GRANT .. _FAILED_SCOPE */
    uint8_t type;               /* request type echo */
    uint8_t pad;
    uint8_t request_digest[AIENOS_CONTAIN_DIGEST_LEN];
} AienosContainReceipt;

typedef AienosContainReceipt AienosContainDecision;
typedef AienosContainReceipt AienosContainResult;

/* Policy. decide sets *verdict to GRANT / DENY / ESCALATE and *why. It is
 * asked only after every structural rule passed; the gate may still turn a
 * GRANT into ESCALATE (not auto-eligible, budget). Any other verdict is
 * treated as ESCALATE. */
typedef struct {
    int (*decide)(void *ctx, const AienosContainRequest *r, const AienosCapView *view,
                  uint32_t *verdict, uint32_t *why);
    void *ctx;
} AienosContainAuthorizer;

/* Table policy for ARGUS-1: one verdict per request type (index 1..10). */
typedef struct {
    uint32_t verdict[AIENOS_CONTAIN_TYPE_MAX + 1];
} AienosContainTablePolicy;
int aienos_contain_table_decide(void *ctx, const AienosContainRequest *r,
                                const AienosCapView *view, uint32_t *verdict, uint32_t *why);

/* Receipt sink (the gate observer): called after every receipt, outside the
 * gate lock, on the calling thread. */
typedef void (*AienosContainSink)(void *ctx, const AienosContainReceipt *receipt);

typedef struct AienosContain AienosContain;

size_t aienos_contain_footprint(void);

/* Mints the executor (the only mint, I5.a). *g is set before the mint, so an
 * observer that forwards to lineage_observe through *g sees the executor's
 * MINT; the lineage index is trusted only if it saw it. The index knows only
 * caps minted after create; any other target is ESCALATE (WHY 1115). */
int aienos_contain_create(AienosContain **g, void *mem, size_t bytes, AienosCapAdmin *admin,
                          const AienosCapView *view, AienosCapRef office,
                          const AienosContainAuthorizer *authz);
/* Clears the memory. Revokes nothing; the authority entry stays registered,
 * so a second create for the same authority is refused even after destroy.
 * The registry is bounded to AIENOS_CONTAIN_REGISTRY authority instances per
 * process; failed creates release their reservation. */
void aienos_contain_destroy(AienosContain *g);

int aienos_contain_set_sink(AienosContain *g, AienosContainSink fn, void *ctx);
int aienos_contain_executor(const AienosContain *g, AienosCapRef *out);
int aienos_contain_inert(const AienosContain *g);

int aienos_contain_submit(AienosContain *g, const AienosContainRequest *r,
                          const uint8_t request_digest[AIENOS_CONTAIN_DIGEST_LEN],
                          AienosContainDecision *out);
/* Canonical bytes in: len must be AIENOS_CONTAIN_REQUEST_SIZE and decode
 * clean, else DENY WHY 1108 (receipt digest = SHA-256 of the bytes given). */
int aienos_contain_submit_bytes(AienosContain *g, const uint8_t *bytes, size_t len,
                                AienosContainDecision *out);
/* ESCALATE -> GRANT / DENY, human only: office_secret is checked with
 * aienos_cap_authorize. A wrong secret is refused and announced (WHY 1112),
 * the decision stays ESCALATED. */
int aienos_contain_resolve(AienosContain *g, uint64_t decision_id, int approve,
                           const uint8_t *office_secret, AienosContainDecision *out);
/* Executes this gate's own GRANT, once. Only the last AIENOS_CONTAIN_DECISIONS
 * GRANT/ESCALATE decisions are remembered: an older one returns ERR_UNKNOWN. */
int aienos_contain_execute(AienosContain *g, uint64_t decision_id, AienosContainResult *out);
/* Fed by the bridge with every authority observer call. */
void aienos_contain_lineage_observe(AienosContain *g, uint32_t op, const AienosCapEntry *e,
                                    int result);

/* Canonical encoding (spec 2): 152 bytes, packed little-endian, field order. */
void aienos_contain_request_encode(const AienosContainRequest *r,
                                   uint8_t out[AIENOS_CONTAIN_REQUEST_SIZE]);
/* 0 if the fields are well formed (type, severity, version, reserved, flags,
 * request_id, finding_sequence), else AIENOS_CONTAIN_ERR_ARG. */
int aienos_contain_request_decode(const uint8_t in[AIENOS_CONTAIN_REQUEST_SIZE],
                                  AienosContainRequest *out);
void aienos_contain_request_digest(const AienosContainRequest *r,
                                   uint8_t out[AIENOS_CONTAIN_DIGEST_LEN]);
void aienos_contain_sha256(const uint8_t *data, size_t len, uint8_t out[AIENOS_CONTAIN_DIGEST_LEN]);

/* Test seams (spec lane G brief). Enabling them needs the admin handle the
 * gate was created with plus a LIVE office ref: a holder of both can already
 * revoke anything, so the seams add no power. Every receipt made while a seam
 * is active carries AIENOS_CONTAIN_RF_SEAM. */
#define AIENOS_CONTAIN_SEAM_NO_PROTECTED 0x1u /* disable the protected list (layer 2, G9) */
typedef struct {
    uint32_t flags;
    /* Called after the re-check, right before aienos_cap_revoke, without the
     * gate lock (G13 I1.b: force a cascade). */
    void (*pre_revoke)(void *ctx);
    void *pre_revoke_ctx;
    /* Test executor for non-LIVE types; its DONE / PARTIAL always carries
     * AIENOS_CREQ_SYNTHETIC (I2). Returns an AIENOS_CONTAIN_* execution status. */
    uint32_t (*test_executor)(void *ctx, const AienosContainRequest *r);
    void *test_executor_ctx;
} AienosContainSeams;
int aienos_contain_set_seams(AienosContain *g, const AienosContainSeams *s, AienosCapAdmin *admin,
                             AienosCapRef office);

#endif
