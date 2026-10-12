/* lifecycle_fsm.h -- resident production lifecycle: states, verbs, transitions.
 *
 * Pure logic (no kernel calls, no libc): the host test tests/test_lifecycle.c
 * compiles this file as is. core/lifecycle.c binds it to the serial console,
 * the sealed Store and the device teardown order (CK_SERVICE=1 image only).
 *
 * States (native v1 plan P03: initialize, locked/ready, serve, quiesce, stop):
 *   INIT     before the lifecycle took over from the boot stages
 *   LOCKED   production Store not open (no production key source yet, or it
 *            refused): status/unlock/help/shutdown only; every task refused
 *   READY    Store open: a task may be submitted
 *   SERVE    one bounded task pending: approve commits it, deny or cancel drops it
 *   QUIESCE  stop order running: flush, revoke, halt
 *   STOP     nothing more is accepted
 * Verbs are the v1 operator surface and nothing else: status, unlock, task
 * <text>, approve, deny, cancel, evidence, help, shutdown, and (P06) prompt
 * <text>, recall, remember <text>, facts. */
#ifndef AIENOS_CK_LIFECYCLE_FSM_H
#define AIENOS_CK_LIFECYCLE_FSM_H

#include <stddef.h>
#include <stdint.h>

enum ck_lc_state { CK_LC_INIT = 0, CK_LC_LOCKED, CK_LC_READY, CK_LC_SERVE, CK_LC_QUIESCE, CK_LC_STOP };

enum ck_lc_verb {
    CK_LC_V_INVALID = -1, /* overlong, unprintable or malformed: refused whole */
    CK_LC_V_UNKNOWN = 0,
    CK_LC_V_EMPTY,
    CK_LC_V_HELP,
    CK_LC_V_STATUS,
    CK_LC_V_UNLOCK,
    CK_LC_V_TASK,
    CK_LC_V_APPROVE,
    CK_LC_V_DENY,
    CK_LC_V_CANCEL,
    CK_LC_V_EVIDENCE,
    CK_LC_V_SHUTDOWN,
    CK_LC_V_PROMPT, /* native v1 P06: bounded generation from the resident model */
    CK_LC_V_RECALL, /* read back the newest approved object from the Store */
    CK_LC_V_REMEMBER, /* P06 cut 4: record one owner fact in the Cortex journal (sealed Store) */
    CK_LC_V_FACTS,    /* list the remembered facts read back from the journal */
};

/* Bounds: one request line, and the task text that a line may carry. */
#define CK_LC_LINE_MAX 96 /* "unlock " + 64 hex = 71 bytes fits */
#define CK_LC_TASK_MAX 48
#define CK_LC_REPLY_MAX 256 /* generated reply bytes kept for approval (INFER_TEXT_BYTES) */
/* What is pending in SERVE: an operator note (task) or a generated reply. */
enum ck_lc_pending { CK_LC_PENDING_NONE = 0, CK_LC_PENDING_NOTE, CK_LC_PENDING_REPLY };

/* Outcome of one request against the state machine. */
enum ck_lc_result {
    CK_LC_R_OK = 0,        /* accepted, state may have changed */
    CK_LC_R_REFUSED,       /* legal verb, refused in this state (reason set) */
    CK_LC_R_INVALID,       /* the line itself was refused (bounds / syntax) */
    CK_LC_R_COMMIT,        /* approve accepted: the binding must commit the task */
    CK_LC_R_UNLOCK,        /* unlock accepted: the binding must try the key source */
    CK_LC_R_STOP,          /* shutdown accepted: the binding must run the stop order */
    CK_LC_R_GENERATE,      /* prompt accepted: the binding must generate (task holds the prompt) */
    CK_LC_R_RECALL,        /* recall accepted: the binding must read the newest approved object */
    CK_LC_R_REMEMBER,      /* remember accepted: the binding must append the fact (task holds the text) */
    CK_LC_R_FACTS,         /* facts accepted: the binding must list the journal */
};

typedef struct {
    enum ck_lc_state state;
    char task[CK_LC_TASK_MAX + 1]; /* pending note text, or the prompt of a pending reply, in SERVE; else "" */
    size_t task_len;
    char reply[CK_LC_REPLY_MAX + 1]; /* generated reply awaiting approval (pending == REPLY), else "" */
    size_t reply_len;
    enum ck_lc_pending pending;
    /* counters for the evidence verb (bounded, wrap is harmless) */
    uint32_t requests, refused, invalid, tasks, approved, denied, cancelled;
    uint32_t prompts, replies, gen_cancelled, gen_failed, recalls;
    uint32_t remembers, facts; /* P06 cut 4: accepted remember / facts requests */
    char fact[CK_LC_TASK_MAX + 1]; /* text of the remember request being served, else "" */
    size_t fact_len;
    const char *reason; /* last refusal reason, static string */
} ck_lc;

/* Decode one request line (len bytes, no terminator required). arg and arg_len
 * receive the text after "task", "prompt" or "remember" (trimmed), else an
 * empty span. */
enum ck_lc_verb ck_lc_decode(const char *line, size_t len, const char **arg, size_t *arg_len);
const char *ck_lc_verb_name(enum ck_lc_verb v);
const char *ck_lc_state_name(enum ck_lc_state s);

void ck_lc_init(ck_lc *lc);
/* Boot stages are over: Store open -> READY, else LOCKED. */
void ck_lc_start(ck_lc *lc, int store_open);
/* Apply one decoded request. Pure transition; the binding performs the side
 * effect that the result names and then calls the *_done function. */
enum ck_lc_result ck_lc_apply(ck_lc *lc, enum ck_lc_verb v, const char *arg, size_t arg_len);
/* Binding results: commit outcome (0 ok: SERVE -> READY; else stays SERVE
 * with reason), unlock outcome (1 opened: LOCKED -> READY). */
void ck_lc_commit_done(ck_lc *lc, int rc);
void ck_lc_unlock_done(ck_lc *lc, int opened);
/* Generation outcome after CK_LC_R_GENERATE: a reply of n bytes (1..CK_LC_REPLY_MAX)
 * becomes the pending proposal (READY -> SERVE, replies++); cancelled (the
 * operator typed cancel between steps) or failed/refused (n == 0) drops the
 * prompt and stays READY with the counter named by the outcome. */
enum ck_lc_gen { CK_LC_GEN_REPLY = 0, CK_LC_GEN_CANCELLED, CK_LC_GEN_FAILED };
void ck_lc_generate_done(ck_lc *lc, enum ck_lc_gen outcome, const char *reply, size_t n);
void ck_lc_stopped(ck_lc *lc);

#endif
