/* osh_op.h -- the AIENOS adapter's platform-operation layer for OSH (aien-architecture#158, contract: aien-protocols PR #16
 * OSH_PLATFORM_ABI.md sections 7 to 12, DRAFT, ABIs unfrozen).
 *
 * One real operation: `klog <words...>` writes one line to the kernel console ("osh_op_out: <words>"). It needs a
 * kernel IPC-table capability (domain 1, ipc.h) on the console-log resource with the WRITE right. The shell core (lex,
 * parse, expand) is NOT touched here: this layer only reads the request record the expander produced
 * (PIPELINE_READY, section 7), maps it to the platform operation, and reports a status. Pure logic, no hardware:
 * host-tested in tests/test_osh_op.c, driven in QEMU by core/osh_test.c (CK_OSH_OP_TEST).
 *
 * Intent and outcome records (section 10) are kept in RAM here. Omega's durable records are a separate PR; the
 * integration point is struct osh_intent and osh_op_recover(): swap the RAM array for the durable store. */
#ifndef AIENOS_CK_OSH_OP_H
#define AIENOS_CK_OSH_OP_H

#include <stddef.h>
#include <stdint.h>
#include "ipc.h"

/* section 8.6 platform error codes (numbers as in the draft) */
enum osh_err {
    OSH_E_OK = 0, OSH_E_DENIED = 1, OSH_E_REVOKED = 2, OSH_E_STALE = 3, OSH_E_NOT_FOUND = 4, OSH_E_UNAVAILABLE = 5,
    OSH_E_INVALID_ARG = 6, OSH_E_LIMIT = 7, OSH_E_INTERRUPTED = 8, OSH_E_BROKEN_PIPE = 9, OSH_E_IO = 10,
    OSH_E_OUTCOME_UNKNOWN = 11, OSH_E_CAP_DOMAIN_MISMATCH = 12, OSH_E_CAP_GEN_NARROW = 13, OSH_E_NOT_SUPPORTED = 14,
    OSH_E_WOULD_BLOCK = 15, OSH_E_PARTIAL_LAUNCH = 16
};
/* section 10 outcomes */
enum osh_outcome { OSH_O_NOT_STARTED = 0, OSH_O_COMPLETED, OSH_O_FAILED_NO_EFFECT, OSH_O_CANCELLED, OSH_O_OUTCOME_UNKNOWN };

/* The one resource and operation this layer knows. The numeric ids are this adapter's own (the draft names the
 * fields and leaves the numbering open: UNVERIFIED against a frozen contract). */
#define OSH_RES_CONSOLE_LOG 0x4f534843u /* "OSHC" */
#define OSH_RC_CONSOLE_LOG 1u           /* binding.resource_class */
#define OSH_OP_WRITE 1u                 /* binding.operation */

/* section 9 rule 2: the authority record carried by every effect */
struct osh_binding {
    uint8_t principal_id[32];
    uint8_t domain; /* 1 = kernel IPC table (32-bit generation) */
    uint32_t cap_index;
    uint64_t cap_generation;
    uint16_t resource_class;
    uint16_t operation;
};

#define OSH_INTENT_MAX 16
struct osh_intent {
    uint8_t used;      /* 1 once the intent is written */
    uint8_t closed;    /* 1 once an outcome is written */
    uint8_t outcome;   /* enum osh_outcome, valid when closed */
    uint8_t err;       /* enum osh_err, valid when closed */
    uint32_t seq;      /* 1-based pipeline number in the session */
    uint32_t status;   /* shell status when COMPLETED */
    uint8_t digest[32];
};

/* Test injection points (all zero in normal use). Each names the 1-based pipeline number of the session. */
struct osh_hooks {
    uint32_t revoke_before_perm_at;  /* the capability is revoked after the binding is built, before the effect */
    uint32_t interrupt_before_effect_at; /* an interrupt arrives after the permission check, before the effect */
    uint32_t crash_after_effect_at;  /* the adapter is lost after the effect, before the outcome is written */
    uint32_t sink_fail_at;           /* the console write reports failure */
};

struct osh_env {
    void *ctx;
    int (*out)(void *ctx, const char *line, size_t len); /* the effect: 0 = written */
    void (*log)(void *ctx, const char *line);            /* receipts and records, one line, no newline */
};

struct osh_session {
    struct ck_cap_table caps;
    struct ck_handle console_cap; /* generation 0 = none held */
    uint8_t principal[32];
    struct osh_intent intents[OSH_INTENT_MAX];
    uint32_t pipelines;
    struct osh_hooks hooks;
};

struct osh_result {
    int status;      /* shell status for $? */
    unsigned error;  /* enum osh_err */
    unsigned outcome; /* enum osh_outcome */
    int stop;        /* 1: interrupted or lost, the list must stop */
    int crashed;     /* 1: lost after the effect, outcome open */
    uint32_t seq;
    uint8_t digest[32];
};

/* A fresh session. grant_rights = rights of the console capability inserted (0 = no capability held at all). */
void osh_session_init(struct osh_session *s, unsigned grant_rights);
/* Task end: drops every capability the session holds. Returns 1 if the table is empty afterwards. */
int osh_session_close(struct osh_session *s);
/* A restart: a new session that inherits only the intent records (what a durable log would give back), holding
 * no capability. Intents without an outcome are then reported by osh_op_recover. */
void osh_session_restart(struct osh_session *fresh, const struct osh_session *old);
/* Marks every open intent OUTCOME_UNKNOWN and logs it with its request digest. Never re-runs anything.
 * Returns how many were open. */
unsigned osh_op_recover(struct osh_session *s, const struct osh_env *env);

/* Run one PIPELINE_READY request record. req = the REQUEST cells, out = the OUT cells (one byte per cell, n_out cells). */
void osh_op_exec(struct osh_session *s, const struct osh_env *env, const uint64_t *req, const uint64_t *out, size_t n_out,
                 struct osh_result *r);

/* section 9 PERM_CHECK, exposed for the tests: OSH_E_OK or the denial reason */
unsigned osh_op_perm_check(const struct osh_session *s, const struct osh_binding *b);

const char *osh_err_name(unsigned e);
const char *osh_outcome_name(unsigned o);

#endif
