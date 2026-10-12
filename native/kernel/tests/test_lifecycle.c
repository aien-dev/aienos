/* test_lifecycle.c -- the resident lifecycle state machine and request
 * decoder (core/lifecycle_fsm.c) on the host: bounds, verbs, every state
 * transition, refusals in the wrong state, the stop order flag. */
#include <string.h>
#include "ck_test.h"
#include "lifecycle_fsm.h"

static enum ck_lc_verb dec(const char *s, const char **a, size_t *al) { return ck_lc_decode(s, strlen(s), a, al); }
static enum ck_lc_result req(ck_lc *lc, const char *s)
{
    const char *a; size_t al;
    enum ck_lc_verb v = dec(s, &a, &al);
    return ck_lc_apply(lc, v, a, al);
}

int main(void)
{
    const char *a; size_t al;
    /* decoder */
    CHECK(dec("status", &a, &al) == CK_LC_V_STATUS && al == 0);
    CHECK(dec("  help  ", &a, &al) == CK_LC_V_HELP);
    CHECK(dec("", &a, &al) == CK_LC_V_EMPTY && dec("   ", &a, &al) == CK_LC_V_EMPTY);
    CHECK(dec("task write the note", &a, &al) == CK_LC_V_TASK && al == 14 && memcmp(a, "write the note", 14) == 0);
    CHECK(dec("task   padded   ", &a, &al) == CK_LC_V_TASK && al == 6 && memcmp(a, "padded", 6) == 0);
    CHECK(dec("task", &a, &al) == CK_LC_V_INVALID);        /* task needs text */
    CHECK(dec("status now", &a, &al) == CK_LC_V_INVALID);  /* no argument allowed */
    CHECK(dec("unlock", &a, &al) == CK_LC_V_UNLOCK && al == 0);
    CHECK(dec("unlock deadbeef  ", &a, &al) == CK_LC_V_UNLOCK && al == 8 && memcmp(a, "deadbeef", 8) == 0);
    CHECK(CK_LC_LINE_MAX >= 7 + 64); /* "unlock " + a 64-hex recovery secret fits in one line */
    CHECK(CK_LC_LINE_MAX >= 7 + 64 + 1 + 64); /* "rotate " + current + " " + new */
    CHECK(dec("rotate aa bb", &a, &al) == CK_LC_V_ROTATE && al == 5 && memcmp(a, "aa bb", 5) == 0);
    CHECK(dec("rotate", &a, &al) == CK_LC_V_ROTATE && al == 0);
    CHECK(dec("frobnicate", &a, &al) == CK_LC_V_UNKNOWN);
    CHECK(dec("prompt hi", &a, &al) == CK_LC_V_PROMPT && al == 2 && memcmp(a, "hi", 2) == 0);
    CHECK(dec("prompt", &a, &al) == CK_LC_V_INVALID);       /* prompt needs text */
    CHECK(dec("recall", &a, &al) == CK_LC_V_RECALL && al == 0);
    CHECK(dec("recall x", &a, &al) == CK_LC_V_INVALID);     /* no argument allowed */
    CHECK(dec("remember prefer short notes", &a, &al) == CK_LC_V_REMEMBER && al == 18 && memcmp(a, "prefer short notes", 18) == 0);
    CHECK(dec("remember", &a, &al) == CK_LC_V_INVALID);     /* remember needs text */
    CHECK(dec("facts", &a, &al) == CK_LC_V_FACTS && al == 0);
    CHECK(dec("facts all", &a, &al) == CK_LC_V_INVALID);    /* no argument allowed */
    CHECK(dec("sta\x01tus", &a, &al) == CK_LC_V_INVALID);  /* unprintable */
    {
        char big[CK_LC_LINE_MAX + 2];
        memset(big, 'x', sizeof big - 1); big[sizeof big - 1] = 0;
        CHECK(dec(big, &a, &al) == CK_LC_V_INVALID);        /* CK_LC_LINE_MAX + 1 bytes refused whole */
        char t[CK_LC_LINE_MAX + 1];
        memset(t, 'y', CK_LC_LINE_MAX); t[CK_LC_LINE_MAX] = 0;
        memcpy(t, "task ", 5);
        CHECK(dec(t, &a, &al) == CK_LC_V_INVALID && al == CK_LC_LINE_MAX - 5); /* text 91 > 48 */
    }
    CHECK(strcmp(ck_lc_verb_name(CK_LC_V_SHUTDOWN), "shutdown") == 0 && strcmp(ck_lc_state_name(CK_LC_SERVE), "serve") == 0);

    /* locked: nothing but status/help/evidence/unlock/shutdown */
    ck_lc lc;
    ck_lc_init(&lc);
    CHECK(lc.state == CK_LC_INIT && req(&lc, "status") == CK_LC_R_REFUSED);
    ck_lc_start(&lc, 0);
    CHECK(lc.state == CK_LC_LOCKED);
    CHECK(req(&lc, "status") == CK_LC_R_OK && req(&lc, "help") == CK_LC_R_OK && req(&lc, "evidence") == CK_LC_R_OK);
    CHECK(req(&lc, "task hello") == CK_LC_R_REFUSED && lc.state == CK_LC_LOCKED && lc.tasks == 0);
    CHECK(req(&lc, "rotate aa bb") == CK_LC_R_REFUSED && lc.state == CK_LC_LOCKED); /* unlock first */
    CHECK(req(&lc, "approve") == CK_LC_R_REFUSED && req(&lc, "deny") == CK_LC_R_REFUSED && req(&lc, "cancel") == CK_LC_R_REFUSED);
    CHECK(req(&lc, "unlock") == CK_LC_R_UNLOCK);
    ck_lc_unlock_done(&lc, 0);
    CHECK(lc.state == CK_LC_LOCKED && strstr(lc.reason, "still locked"));
    CHECK(req(&lc, "unlock") == CK_LC_R_UNLOCK);
    ck_lc_unlock_done(&lc, 1);
    CHECK(lc.state == CK_LC_READY);
    CHECK(req(&lc, "unlock") == CK_LC_R_REFUSED); /* already unlocked */
    CHECK(req(&lc, "rotate") == CK_LC_R_REFUSED && lc.state == CK_LC_READY); /* needs both secrets */
    CHECK(req(&lc, "rotate aa bb") == CK_LC_R_ROTATE);
    ck_lc_rotate_done(&lc, 0);
    CHECK(lc.state == CK_LC_READY && strstr(lc.reason, "rotation refused"));
    CHECK(req(&lc, "rotate aa bb") == CK_LC_R_ROTATE);
    ck_lc_rotate_done(&lc, 1);
    CHECK(lc.state == CK_LC_READY);
    CHECK(req(&lc, "shutdown") == CK_LC_R_STOP && lc.state == CK_LC_QUIESCE);
    CHECK(req(&lc, "status") == CK_LC_R_REFUSED && strcmp(lc.reason, "stopping") == 0);
    ck_lc_stopped(&lc);
    CHECK(lc.state == CK_LC_STOP && req(&lc, "task x") == CK_LC_R_REFUSED);

    /* ready / serve: one pending task, approve commits, deny and cancel drop */
    ck_lc_init(&lc);
    ck_lc_start(&lc, 1);
    CHECK(lc.state == CK_LC_READY);
    CHECK(req(&lc, "approve") == CK_LC_R_REFUSED && req(&lc, "cancel") == CK_LC_R_REFUSED);
    CHECK(req(&lc, "task draft the plan") == CK_LC_R_OK && lc.state == CK_LC_SERVE && lc.tasks == 1);
    CHECK(strcmp(lc.task, "draft the plan") == 0 && lc.task_len == 14);
    CHECK(req(&lc, "task another") == CK_LC_R_REFUSED && strcmp(lc.task, "draft the plan") == 0); /* one at a time */
    CHECK(req(&lc, "approve") == CK_LC_R_COMMIT && lc.state == CK_LC_SERVE);
    ck_lc_commit_done(&lc, -5);                      /* commit failed: still pending */
    CHECK(lc.state == CK_LC_SERVE && lc.approved == 0 && strcmp(lc.task, "draft the plan") == 0);
    CHECK(req(&lc, "approve") == CK_LC_R_COMMIT);
    ck_lc_commit_done(&lc, 0);
    CHECK(lc.state == CK_LC_READY && lc.approved == 1 && lc.task_len == 0 && lc.task[0] == 0);
    CHECK(req(&lc, "task b") == CK_LC_R_OK && req(&lc, "deny") == CK_LC_R_OK && lc.state == CK_LC_READY && lc.denied == 1);
    CHECK(req(&lc, "task c") == CK_LC_R_OK && req(&lc, "cancel") == CK_LC_R_OK && lc.state == CK_LC_READY && lc.cancelled == 1);
    CHECK(req(&lc, "nonsense") == CK_LC_R_REFUSED && req(&lc, "task") == CK_LC_R_INVALID && lc.invalid == 1);
    /* a pending unapproved task is dropped by shutdown, never committed */
    CHECK(req(&lc, "task d") == CK_LC_R_OK && req(&lc, "shutdown") == CK_LC_R_STOP);
    CHECK(lc.state == CK_LC_QUIESCE && lc.task_len == 0 && lc.approved == 1);
    ck_lc_commit_done(&lc, 0); /* ignored outside SERVE */
    CHECK(lc.approved == 1);
    CHECK(lc.requests == 14);

    /* P06: prompt and recall. Locked: both refused, nothing counted. */
    ck_lc_init(&lc);
    ck_lc_start(&lc, 0);
    CHECK(req(&lc, "prompt hi") == CK_LC_R_REFUSED && lc.prompts == 0 && strstr(lc.reason, "locked"));
    CHECK(req(&lc, "recall") == CK_LC_R_REFUSED && lc.recalls == 0 && lc.refused == 2);
    /* ready: prompt asks the kernel to generate (state stays READY, the
     * prompt is the task text); the reply becomes the pending proposal */
    ck_lc_init(&lc);
    ck_lc_start(&lc, 1);
    CHECK(req(&lc, "prompt What is the capital of France?") == CK_LC_R_GENERATE && lc.state == CK_LC_READY && lc.prompts == 1);
    CHECK(strcmp(lc.task, "What is the capital of France?") == 0 && lc.task_len == 30 && lc.pending == CK_LC_PENDING_NONE);
    ck_lc_generate_done(&lc, CK_LC_GEN_REPLY, "Paris.", 6);
    CHECK(lc.state == CK_LC_SERVE && lc.pending == CK_LC_PENDING_REPLY && lc.replies == 1);
    CHECK(lc.reply_len == 6 && strcmp(lc.reply, "Paris.") == 0 && strcmp(lc.task, "What is the capital of France?") == 0);
    CHECK(req(&lc, "prompt again") == CK_LC_R_REFUSED && lc.state == CK_LC_SERVE && lc.prompts == 1); /* one proposal at a time */
    CHECK(req(&lc, "task note") == CK_LC_R_REFUSED && lc.tasks == 0);
    CHECK(req(&lc, "approve") == CK_LC_R_COMMIT && lc.pending == CK_LC_PENDING_REPLY);
    ck_lc_commit_done(&lc, 0);
    CHECK(lc.state == CK_LC_READY && lc.approved == 1 && lc.pending == CK_LC_PENDING_NONE);
    CHECK(lc.reply_len == 0 && lc.reply[0] == 0 && lc.task_len == 0 && lc.task[0] == 0);
    /* cancelled between steps: nothing pending, counted apart from `cancel` of a proposal */
    CHECK(req(&lc, "prompt Say hello.") == CK_LC_R_GENERATE);
    ck_lc_generate_done(&lc, CK_LC_GEN_CANCELLED, 0, 0);
    CHECK(lc.state == CK_LC_READY && lc.gen_cancelled == 1 && lc.cancelled == 0 && lc.task_len == 0 && lc.pending == CK_LC_PENDING_NONE);
    /* failed, empty and overlong replies: nothing pending, gen_failed counts */
    CHECK(req(&lc, "prompt Say hello.") == CK_LC_R_GENERATE);
    ck_lc_generate_done(&lc, CK_LC_GEN_FAILED, 0, 0);
    CHECK(lc.state == CK_LC_READY && lc.gen_failed == 1 && lc.task_len == 0);
    CHECK(req(&lc, "prompt x") == CK_LC_R_GENERATE);
    ck_lc_generate_done(&lc, CK_LC_GEN_REPLY, "", 0);
    CHECK(lc.state == CK_LC_READY && lc.gen_failed == 2);
    {
        char big[CK_LC_REPLY_MAX + 2];
        memset(big, 'r', sizeof big - 1); big[sizeof big - 1] = 0;
        CHECK(req(&lc, "prompt x") == CK_LC_R_GENERATE);
        ck_lc_generate_done(&lc, CK_LC_GEN_REPLY, big, CK_LC_REPLY_MAX + 1);
        CHECK(lc.state == CK_LC_READY && lc.gen_failed == 3 && lc.reply_len == 0);
        CHECK(req(&lc, "prompt x") == CK_LC_R_GENERATE);
        ck_lc_generate_done(&lc, CK_LC_GEN_REPLY, big, CK_LC_REPLY_MAX); /* exactly the bound fits */
        CHECK(lc.state == CK_LC_SERVE && lc.reply_len == CK_LC_REPLY_MAX && lc.replies == 2);
    }
    /* a reply arriving with no prompt pending is ignored (kernel-internal misuse) */
    CHECK(req(&lc, "deny") == CK_LC_R_OK && lc.state == CK_LC_READY && lc.denied == 1 && lc.reply_len == 0);
    ck_lc_generate_done(&lc, CK_LC_GEN_REPLY, "stray", 5);
    CHECK(lc.state == CK_LC_READY && lc.replies == 2 && lc.pending == CK_LC_PENDING_NONE);
    /* recall is answered in READY and in SERVE and never changes the state */
    CHECK(req(&lc, "recall") == CK_LC_R_RECALL && lc.recalls == 1 && lc.state == CK_LC_READY);
    CHECK(req(&lc, "task n") == CK_LC_R_OK && req(&lc, "recall") == CK_LC_R_RECALL && lc.recalls == 2);
    CHECK(lc.state == CK_LC_SERVE && lc.pending == CK_LC_PENDING_NOTE);
    /* shutdown drops a pending reply, never commits it; then everything is refused */
    CHECK(req(&lc, "cancel") == CK_LC_R_OK && req(&lc, "prompt z") == CK_LC_R_GENERATE);
    ck_lc_generate_done(&lc, CK_LC_GEN_REPLY, "zz", 2);
    CHECK(lc.state == CK_LC_SERVE && req(&lc, "shutdown") == CK_LC_R_STOP);
    CHECK(lc.state == CK_LC_QUIESCE && lc.reply_len == 0 && lc.task_len == 0 && lc.pending == CK_LC_PENDING_NONE);
    CHECK(req(&lc, "prompt q") == CK_LC_R_REFUSED && req(&lc, "recall") == CK_LC_R_REFUSED);
    CHECK(lc.requests == 18 && lc.prompts == 7 && lc.refused == 4 && lc.approved == 1);

    /* P06 cut 4: remember and facts. Locked: both refused, nothing counted. */
    ck_lc_init(&lc);
    ck_lc_start(&lc, 0);
    CHECK(req(&lc, "remember prefer short notes") == CK_LC_R_REFUSED && lc.remembers == 0 && strstr(lc.reason, "locked"));
    CHECK(req(&lc, "facts") == CK_LC_R_REFUSED && lc.facts == 0 && lc.refused == 2);
    /* ready: remember hands the text to the binding and never changes the
     * state or the pending task; facts likewise */
    ck_lc_init(&lc);
    ck_lc_start(&lc, 1);
    CHECK(req(&lc, "remember prefer short notes") == CK_LC_R_REMEMBER && lc.state == CK_LC_READY && lc.remembers == 1);
    CHECK(lc.fact_len == 18 && strcmp(lc.fact, "prefer short notes") == 0 && lc.task_len == 0 && lc.pending == CK_LC_PENDING_NONE);
    CHECK(req(&lc, "facts") == CK_LC_R_FACTS && lc.facts == 1 && lc.state == CK_LC_READY);
    CHECK(req(&lc, "task n") == CK_LC_R_OK && lc.state == CK_LC_SERVE);
    CHECK(req(&lc, "remember second") == CK_LC_R_REMEMBER && lc.remembers == 2 && lc.state == CK_LC_SERVE);
    CHECK(strcmp(lc.fact, "second") == 0 && lc.fact_len == 6 && strcmp(lc.task, "n") == 0 && lc.pending == CK_LC_PENDING_NOTE);
    CHECK(req(&lc, "facts") == CK_LC_R_FACTS && lc.facts == 2 && lc.state == CK_LC_SERVE);
    {
        char big[CK_LC_LINE_MAX + 1];
        memset(big, 'f', CK_LC_LINE_MAX); big[CK_LC_LINE_MAX] = 0;
        memcpy(big, "remember ", 9);
        CHECK(req(&lc, big) == CK_LC_R_INVALID && lc.invalid == 1 && lc.remembers == 2); /* text 87 > 48 refused whole */
    }
    CHECK(req(&lc, "shutdown") == CK_LC_R_STOP && req(&lc, "remember z") == CK_LC_R_REFUSED && req(&lc, "facts") == CK_LC_R_REFUSED);
    CHECK(lc.requests == 9 && lc.remembers == 2 && lc.facts == 2 && lc.refused == 2 && lc.invalid == 1);
    return ck_t_verdict("CK_LIFECYCLE");
}
