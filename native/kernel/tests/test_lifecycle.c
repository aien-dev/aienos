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
    CHECK(dec("frobnicate", &a, &al) == CK_LC_V_UNKNOWN);
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
    CHECK(req(&lc, "approve") == CK_LC_R_REFUSED && req(&lc, "deny") == CK_LC_R_REFUSED && req(&lc, "cancel") == CK_LC_R_REFUSED);
    CHECK(req(&lc, "unlock") == CK_LC_R_UNLOCK);
    ck_lc_unlock_done(&lc, 0);
    CHECK(lc.state == CK_LC_LOCKED && strstr(lc.reason, "still locked"));
    CHECK(req(&lc, "unlock") == CK_LC_R_UNLOCK);
    ck_lc_unlock_done(&lc, 1);
    CHECK(lc.state == CK_LC_READY);
    CHECK(req(&lc, "unlock") == CK_LC_R_REFUSED); /* already unlocked */
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
    return ck_t_verdict("CK_LIFECYCLE");
}
