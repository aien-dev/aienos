/* lifecycle_fsm.c -- see lifecycle_fsm.h. No kernel calls, no libc. */
#include "lifecycle_fsm.h"

static int printable(char c) { return c >= 0x20 && c <= 0x7e; }

static int word_is(const char *w, size_t n, const char *lit)
{
    size_t i;
    for (i = 0; lit[i]; i++)
        if (i >= n || w[i] != lit[i]) return 0;
    return i == n;
}

enum ck_lc_verb ck_lc_decode(const char *line, size_t len, const char **arg, size_t *arg_len)
{
    size_t i = 0, ws, we;
    *arg = line;
    *arg_len = 0;
    if (len > CK_LC_LINE_MAX) return CK_LC_V_INVALID;
    for (i = 0; i < len; i++)
        if (!printable(line[i])) return CK_LC_V_INVALID;
    i = 0;
    while (i < len && line[i] == ' ') i++;
    if (i == len) return CK_LC_V_EMPTY;
    ws = i;
    while (i < len && line[i] != ' ') i++;
    we = i;
    while (i < len && line[i] == ' ') i++;
    /* trailing blanks are not part of the argument */
    {
        size_t end = len;
        while (end > i && line[end - 1] == ' ') end--;
        *arg = line + i;
        *arg_len = end - i;
    }
    const char *w = line + ws;
    size_t n = we - ws;
    if (word_is(w, n, "task")) {
        if (*arg_len == 0 || *arg_len > CK_LC_TASK_MAX) return CK_LC_V_INVALID;
        return CK_LC_V_TASK;
    }
    if (word_is(w, n, "prompt")) {
        if (*arg_len == 0 || *arg_len > CK_LC_TASK_MAX) return CK_LC_V_INVALID;
        return CK_LC_V_PROMPT;
    }
    /* unlock carries the optional recovery secret (the binding checks its
     * shape and never echoes it); every other verb takes no argument. */
    if (word_is(w, n, "unlock")) return CK_LC_V_UNLOCK;
    if (*arg_len != 0) return CK_LC_V_INVALID;
    if (word_is(w, n, "help")) return CK_LC_V_HELP;
    if (word_is(w, n, "status")) return CK_LC_V_STATUS;
    if (word_is(w, n, "approve")) return CK_LC_V_APPROVE;
    if (word_is(w, n, "deny")) return CK_LC_V_DENY;
    if (word_is(w, n, "cancel")) return CK_LC_V_CANCEL;
    if (word_is(w, n, "recall")) return CK_LC_V_RECALL;
    if (word_is(w, n, "evidence")) return CK_LC_V_EVIDENCE;
    if (word_is(w, n, "shutdown")) return CK_LC_V_SHUTDOWN;
    return CK_LC_V_UNKNOWN;
}

const char *ck_lc_verb_name(enum ck_lc_verb v)
{
    switch (v) {
    case CK_LC_V_INVALID: return "invalid";
    case CK_LC_V_UNKNOWN: return "unknown";
    case CK_LC_V_EMPTY: return "empty";
    case CK_LC_V_HELP: return "help";
    case CK_LC_V_STATUS: return "status";
    case CK_LC_V_UNLOCK: return "unlock";
    case CK_LC_V_TASK: return "task";
    case CK_LC_V_APPROVE: return "approve";
    case CK_LC_V_DENY: return "deny";
    case CK_LC_V_CANCEL: return "cancel";
    case CK_LC_V_EVIDENCE: return "evidence";
    case CK_LC_V_SHUTDOWN: return "shutdown";
    case CK_LC_V_PROMPT: return "prompt";
    case CK_LC_V_RECALL: return "recall";
    }
    return "?";
}

const char *ck_lc_state_name(enum ck_lc_state s)
{
    switch (s) {
    case CK_LC_INIT: return "init";
    case CK_LC_LOCKED: return "locked";
    case CK_LC_READY: return "ready";
    case CK_LC_SERVE: return "serve";
    case CK_LC_QUIESCE: return "quiesce";
    case CK_LC_STOP: return "stop";
    }
    return "?";
}

void ck_lc_init(ck_lc *lc)
{
    size_t i;
    unsigned char *p = (unsigned char *)lc;
    for (i = 0; i < sizeof *lc; i++) p[i] = 0;
    lc->state = CK_LC_INIT;
    lc->reason = "";
}

void ck_lc_start(ck_lc *lc, int store_open)
{
    lc->state = store_open ? CK_LC_READY : CK_LC_LOCKED;
}

static enum ck_lc_result refuse(ck_lc *lc, const char *why)
{
    lc->refused++;
    lc->reason = why;
    return CK_LC_R_REFUSED;
}

static void drop_task(ck_lc *lc)
{
    size_t i;
    for (i = 0; i < sizeof lc->task; i++) lc->task[i] = 0;
    for (i = 0; i < sizeof lc->reply; i++) lc->reply[i] = 0;
    lc->task_len = 0;
    lc->reply_len = 0;
    lc->pending = CK_LC_PENDING_NONE;
}

static void set_task(ck_lc *lc, const char *arg, size_t arg_len)
{
    size_t i;
    for (i = 0; i < arg_len; i++) lc->task[i] = arg[i];
    lc->task[arg_len] = 0;
    lc->task_len = arg_len;
}

enum ck_lc_result ck_lc_apply(ck_lc *lc, enum ck_lc_verb v, const char *arg, size_t arg_len)
{
    lc->requests++;
    lc->reason = "";
    if (lc->state == CK_LC_QUIESCE || lc->state == CK_LC_STOP) return refuse(lc, "stopping");
    if (lc->state == CK_LC_INIT) return refuse(lc, "not started");
    switch (v) {
    case CK_LC_V_INVALID:
        lc->invalid++;
        lc->reason = "line refused (bounds or syntax)";
        return CK_LC_R_INVALID;
    case CK_LC_V_UNKNOWN: return refuse(lc, "unknown verb");
    case CK_LC_V_EMPTY:
    case CK_LC_V_HELP:
    case CK_LC_V_STATUS:
    case CK_LC_V_EVIDENCE: return CK_LC_R_OK;
    case CK_LC_V_UNLOCK:
        if (lc->state != CK_LC_LOCKED) return refuse(lc, "already unlocked");
        return CK_LC_R_UNLOCK;
    case CK_LC_V_TASK:
        if (lc->state == CK_LC_LOCKED) return refuse(lc, "locked: no production Store");
        if (lc->state == CK_LC_SERVE) return refuse(lc, "a task is pending: approve, deny or cancel it first");
        if (arg_len == 0 || arg_len > CK_LC_TASK_MAX) return refuse(lc, "task text out of bounds");
        set_task(lc, arg, arg_len);
        lc->pending = CK_LC_PENDING_NOTE;
        lc->tasks++;
        lc->state = CK_LC_SERVE;
        return CK_LC_R_OK;
    case CK_LC_V_PROMPT:
        if (lc->state == CK_LC_LOCKED) return refuse(lc, "locked: no production Store");
        if (lc->state == CK_LC_SERVE) return refuse(lc, "a task is pending: approve, deny or cancel it first");
        if (arg_len == 0 || arg_len > CK_LC_TASK_MAX) return refuse(lc, "prompt text out of bounds");
        set_task(lc, arg, arg_len); /* the prompt; the reply arrives through ck_lc_generate_done */
        lc->prompts++;
        return CK_LC_R_GENERATE;
    case CK_LC_V_RECALL:
        if (lc->state == CK_LC_LOCKED) return refuse(lc, "locked: no production Store");
        lc->recalls++;
        return CK_LC_R_RECALL;
    case CK_LC_V_APPROVE:
        if (lc->state != CK_LC_SERVE) return refuse(lc, "nothing pending");
        return CK_LC_R_COMMIT;
    case CK_LC_V_DENY:
        if (lc->state != CK_LC_SERVE) return refuse(lc, "nothing pending");
        lc->denied++;
        drop_task(lc);
        lc->state = CK_LC_READY;
        return CK_LC_R_OK;
    case CK_LC_V_CANCEL:
        if (lc->state != CK_LC_SERVE) return refuse(lc, "nothing to cancel");
        lc->cancelled++;
        drop_task(lc);
        lc->state = CK_LC_READY;
        return CK_LC_R_OK;
    case CK_LC_V_SHUTDOWN:
        if (lc->state == CK_LC_SERVE) drop_task(lc); /* a pending, unapproved task is dropped, never committed */
        lc->state = CK_LC_QUIESCE;
        return CK_LC_R_STOP;
    }
    return refuse(lc, "unknown verb");
}

void ck_lc_commit_done(ck_lc *lc, int rc)
{
    if (lc->state != CK_LC_SERVE) return;
    if (rc == 0) {
        lc->approved++;
        drop_task(lc);
        lc->state = CK_LC_READY;
    } else {
        lc->refused++;
        lc->reason = "commit failed: task still pending (approve again or cancel)";
    }
}

void ck_lc_unlock_done(ck_lc *lc, int opened)
{
    if (lc->state != CK_LC_LOCKED) return;
    if (opened) lc->state = CK_LC_READY;
    else {
        lc->refused++;
        lc->reason = "production key source refused: still locked";
    }
}

void ck_lc_stopped(ck_lc *lc)
{
    lc->state = CK_LC_STOP;
}

void ck_lc_generate_done(ck_lc *lc, enum ck_lc_gen outcome, const char *reply, size_t n)
{
    if (lc->state != CK_LC_READY || lc->task_len == 0) return; /* only a READY prompt generates */
    if (outcome == CK_LC_GEN_REPLY && n > 0 && n <= CK_LC_REPLY_MAX) {
        size_t i;
        for (i = 0; i < n; i++) lc->reply[i] = reply[i];
        lc->reply[n] = 0;
        lc->reply_len = n;
        lc->pending = CK_LC_PENDING_REPLY;
        lc->replies++;
        lc->state = CK_LC_SERVE;
        return;
    }
    if (outcome == CK_LC_GEN_CANCELLED) lc->gen_cancelled++;
    else lc->gen_failed++;
    drop_task(lc);
}
