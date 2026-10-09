/* test_osh_op.c -- host tests for core/osh_op.c: the AIENOS adapter's capability-authorized console write (`klog`).
 * Requests are built as the expander's request record (OSH_PLATFORM_ABI section 7) without calling the shell core. */
#include <string.h>
#include "ck_test.h"
#include "osh_op.h"

static char cap_buf[4096];
static int cap_calls;
static char logs[16][480];
static int nlogs;

static int sink(void *ctx, const char *line, size_t len)
{
    (void)ctx;
    cap_calls++;
    CHECK(line[len] == 0 && len > 0 && line[len - 1] == '\n'); /* a C string the kernel sink may print */
    if (strlen(cap_buf) + len < sizeof cap_buf)
    {
        size_t at = strlen(cap_buf);
        memcpy(cap_buf + at, line, len);
        cap_buf[at + len] = 0;
    }
    return 0;
}
static void logger(void *ctx, const char *line)
{
    (void)ctx;
    if (nlogs < 16)
        snprintf(logs[nlogs++], sizeof logs[0], "%s", line);
}
static const struct osh_env env = { 0, sink, logger };

static void reset_capture(void)
{
    cap_buf[0] = 0;
    cap_calls = 0;
    nlogs = 0;
}

static uint64_t req[8 + 8 * 164];
static uint64_t out[8192];

/* one command per block; args NULL-terminated; extra fields set by the caller afterwards */
static void build(unsigned ncmds, const char *const *argv, const char *const *argv2)
{
    memset(req, 0, sizeof req);
    memset(out, 0, sizeof out);
    req[0] = 0x4F524551ull;
    req[1] = ncmds;
    req[3] = 0;
    req[5] = 1;
    uint64_t used = 0;
    for (unsigned c = 0; c < ncmds; c++) {
        const char *const *a = c == 0 ? argv : argv2;
        uint64_t *b = req + 8 + c * 164;
        unsigned n = 0;
        for (; a[n]; n++) {
            size_t l = strlen(a[n]);
            for (size_t i = 0; i < l; i++)
                out[used + i] = (uint8_t)a[n][i];
            b[4 + 2 * n] = used;
            b[5 + 2 * n] = l;
            used += l;
        }
        b[0] = n;
    }
    req[4] = used;
}

static struct osh_result run(struct osh_session *s, const char *const *argv)
{
    struct osh_result r;
    build(1, argv, 0);
    osh_op_exec(s, &env, req, out, 8192, &r);
    return r;
}

int main(void)
{
    struct osh_session s, t;
    struct osh_result r;
    const char *const hello[] = { "klog", "hello", "world", 0 };

    /* allowed: the task holds WRITE on the console resource */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    r = run(&s, hello);
    CHECK(r.error == OSH_E_OK && r.outcome == OSH_O_COMPLETED && r.status == 0 && !r.stop);
    CHECK(strcmp(cap_buf, "osh_op_out: hello world\n") == 0 && cap_calls == 1);
    CHECK(s.intents[0].used && s.intents[0].closed && s.intents[0].outcome == OSH_O_COMPLETED && s.intents[0].seq == 1);
    CHECK(memcmp(s.intents[0].digest, r.digest, 32) == 0);
    uint8_t d1[32];
    memcpy(d1, r.digest, 32);
    r = run(&s, hello);
    CHECK(memcmp(d1, r.digest, 32) == 0 && r.seq == 2); /* the same request, the same digest */
    const char *const other[] = { "klog", "hello", "worlD", 0 };
    r = run(&s, other);
    CHECK(memcmp(d1, r.digest, 32) != 0);

    /* no capability at all: refused before any effect, with the named refusal */
    reset_capture();
    osh_session_init(&s, 0);
    r = run(&s, hello);
    CHECK(r.error == OSH_E_DENIED && r.outcome == OSH_O_FAILED_NO_EFFECT && r.status == 126);
    CHECK(cap_calls == 0 && cap_buf[0] == 0);
    CHECK(s.intents[0].closed && s.intents[0].outcome == OSH_O_FAILED_NO_EFFECT && s.intents[0].err == OSH_E_DENIED);
    CHECK(nlogs == 1 && strstr(logs[0], "osh_op_receipt:") && strstr(logs[0], "result=DENIED") && strstr(logs[0], "effect=none"));

    /* a capability without WRITE: denied */
    reset_capture();
    osh_session_init(&s, CK_R_READ);
    r = run(&s, hello);
    CHECK(r.error == OSH_E_DENIED && cap_calls == 0);

    /* revoked between building the request and using it */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    s.hooks.revoke_before_perm_at = 1;
    r = run(&s, hello);
    CHECK(r.error == OSH_E_REVOKED && r.outcome == OSH_O_FAILED_NO_EFFECT && cap_calls == 0);
    r = run(&s, hello); /* and it stays revoked */
    CHECK(r.error == OSH_E_REVOKED && cap_calls == 0);

    /* the binding checks, called directly */
    {
        struct osh_binding b;
        struct ck_handle h2;
        osh_session_init(&s, CK_R_WRITE);
        memset(&b, 0, sizeof b);
        memcpy(b.principal_id, s.principal, 32);
        b.domain = 1;
        b.cap_index = s.console_cap.index;
        b.cap_generation = s.console_cap.generation;
        b.resource_class = OSH_RC_CONSOLE_LOG;
        b.operation = OSH_OP_WRITE;
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_OK);
        b.domain = 2;
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_CAP_DOMAIN_MISMATCH);
        b.domain = 1;
        b.cap_generation = 0x100000001ull;
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_CAP_GEN_NARROW);
        b.cap_generation = s.console_cap.generation;
        b.resource_class = 2;
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_DENIED);
        b.resource_class = OSH_RC_CONSOLE_LOG;
        b.operation = 2;
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_DENIED);
        b.operation = OSH_OP_WRITE;
        b.principal_id[0] ^= 1;
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_DENIED);
        b.principal_id[0] ^= 1;
        b.cap_generation = s.console_cap.generation + 5; /* never issued */
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_DENIED);
        b.cap_generation = s.console_cap.generation;
        b.cap_index = 99;
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_DENIED);
        b.cap_index = s.console_cap.index;
        /* revoke, then the old handle is REVOKED; a new capability in the same slot makes the old handle STALE */
        CHECK(ck_cap_remove(&s.caps, s.console_cap) == CK_CAP_OK);
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_REVOKED);
        CHECK(ck_cap_insert(&s.caps, OSH_RES_CONSOLE_LOG, CK_R_WRITE, &h2) == CK_CAP_OK);
        CHECK(h2.index == b.cap_index && h2.generation > s.console_cap.generation);
        CHECK(osh_op_perm_check(&s, &b) == OSH_E_STALE);
        /* a capability on another resource does not authorize the console */
        osh_session_init(&s, 0);
        CHECK(ck_cap_insert(&s.caps, 0x1234u, CK_R_WRITE, &s.console_cap) == CK_CAP_OK);
        memcpy(s.cap_holder, s.principal, 32); /* the principal matches: only the resource is wrong */
        r = run(&s, hello);
        CHECK(r.error == OSH_E_DENIED && cap_calls == 0);
    }

    /* an interrupt before the effect: cancelled, no bytes, the list stops */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    s.hooks.interrupt_before_effect_at = 2;
    r = run(&s, hello);
    CHECK(r.error == OSH_E_OK && cap_calls == 1);
    r = run(&s, hello);
    CHECK(r.error == OSH_E_INTERRUPTED && r.outcome == OSH_O_CANCELLED && r.stop && r.status == 130 && cap_calls == 1);
    CHECK(s.intents[1].closed && s.intents[1].outcome == OSH_O_CANCELLED);
    CHECK(osh_session_close(&s) == 1);
    CHECK(ck_cap_lookup(&s.caps, s.console_cap, CK_R_WRITE, 0) != CK_CAP_OK); /* capability released */

    /* lost after the effect: the outcome is unknown, restart reports it and never replays it */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    s.hooks.crash_after_effect_at = 1;
    r = run(&s, hello);
    CHECK(r.crashed && r.stop && r.outcome == OSH_O_OUTCOME_UNKNOWN && cap_calls == 1);
    CHECK(s.intents[0].used && !s.intents[0].closed);
    osh_session_restart(&t, &s);
    CHECK(t.console_cap.generation == 0); /* the restarted adapter holds no capability */
    nlogs = 0;
    CHECK(osh_op_recover(&t, &env) == 1);
    CHECK(cap_calls == 1); /* not replayed */
    CHECK(t.intents[0].closed && t.intents[0].outcome == OSH_O_OUTCOME_UNKNOWN);
    CHECK(nlogs == 1 && strstr(logs[0], "outcome=OUTCOME_UNKNOWN") && strstr(logs[0], "replayed=0"));
    CHECK(osh_op_recover(&t, &env) == 0 && nlogs == 1 && cap_calls == 1); /* idempotent */

    /* a failed console write is unknown, not "no effect" */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    s.hooks.sink_fail_at = 1;
    r = run(&s, hello);
    CHECK(r.error == OSH_E_IO && r.outcome == OSH_O_OUTCOME_UNKNOWN && s.intents[0].outcome == OSH_O_OUTCOME_UNKNOWN);

    /* refused before any effect or intent: unknown name, and what this slice cannot do yet */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    const char *const ls[] = { "ls", 0 };
    r = run(&s, ls);
    CHECK(r.error == OSH_E_NOT_FOUND && r.status == 127 && r.outcome == OSH_O_NOT_STARTED && !s.intents[0].used);
    const char *const kl[] = { "klog", "a", 0 };
    build(2, kl, kl);
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_NOT_SUPPORTED && r.status == 126 && cap_calls == 0 && !s.intents[0].used); /* a pipe */
    build(1, kl, 0);
    req[8 + 2] = 1; /* nredir */
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_NOT_SUPPORTED && cap_calls == 0);
    build(1, kl, 0);
    req[8 + 1] = 1; /* nassign */
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_NOT_SUPPORTED && cap_calls == 0);
    build(1, kl, 0);
    req[8 + 3] = 3; /* builtin printf */
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_NOT_SUPPORTED && cap_calls == 0);
    CHECK(!s.intents[0].used);

    /* malformed request records are refused without using the memory */
    build(1, kl, 0);
    req[0] ^= 1;
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_INVALID_ARG && cap_calls == 0);
    build(1, kl, 0);
    req[8 + 5] = 99; /* argv[0] length past out_used */
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_INVALID_ARG && cap_calls == 0);
    build(1, kl, 0);
    out[0] = 0x14b; /* a cell that is not a byte */
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_INVALID_ARG && cap_calls == 0);
    build(1, kl, 0);
    req[1] = 9; /* ncmds over 8 */
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_INVALID_ARG && cap_calls == 0);
    build(1, kl, 0);
    req[4] = 9000; /* out_used over the OUT region */
    osh_op_exec(&s, &env, req, out, 8192, &r);
    CHECK(r.error == OSH_E_INVALID_ARG && cap_calls == 0);

    /* an argument cannot forge a record line, and an over-long line is a LIMIT before the effect */
    reset_capture();
    const char *const nl[] = { "klog", "a\nosh_op_record: forged", 0 };
    r = run(&s, nl);
    CHECK(r.error == OSH_E_OK && strcmp(cap_buf, "osh_op_out: a.osh_op_record: forged\n") == 0);
    char big[300];
    memset(big, 'x', 299);
    big[299] = 0;
    const char *const bg[] = { "klog", big, 0 };
    reset_capture();
    r = run(&s, bg);
    CHECK(r.error == OSH_E_LIMIT && cap_calls == 0);

    /* closed intents are reclaimed (their outcome is already logged): 40 sequential klogs succeed, each with a
     * "grant used" receipt; only OPEN intents count against the limit */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    int okn = 0;
    for (int i = 0; i < 40; i++)
        okn += run(&s, hello).error == OSH_E_OK;
    CHECK(okn == 40 && cap_calls == 40);
    CHECK(nlogs == 16); /* the log array keeps the first 16 lines */
    CHECK(strstr(logs[0], "osh_op_receipt: seq=1 op=console_write result=OK ") && strstr(logs[0], "effect=console_write"));
    CHECK(strstr(logs[0], "cap_domain=1 cap_index=0 cap_generation=1 resource_class=1 operation=1") && strstr(logs[0], "principal="));
    /* the receipt names the request digest */
    {
        reset_capture();
        osh_session_init(&s, CK_R_WRITE);
        r = run(&s, hello);
        char want[64 + 32];
        int w = 0;
        for (int i = 0; i < 32; i++)
            w += snprintf(want + w, sizeof want - w, "%02x", r.digest[i]);
        CHECK(nlogs == 1 && strstr(logs[0], want));
    }
    /* 16 open intents (the adapter lost after each effect) fill the log; the next pipeline is refused LIMIT with a receipt */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    for (int i = 0; i < OSH_INTENT_MAX; i++) {
        s.hooks.crash_after_effect_at = s.pipelines + 1;
        r = run(&s, hello);
        CHECK(r.crashed);
    }
    CHECK(cap_calls == OSH_INTENT_MAX);
    nlogs = 0;
    r = run(&s, hello);
    CHECK(r.error == OSH_E_LIMIT && r.outcome == OSH_O_NOT_STARTED && cap_calls == OSH_INTENT_MAX);
    CHECK(nlogs == 1 && strstr(logs[0], "osh_op_receipt:") && strstr(logs[0], "result=LIMIT") && strstr(logs[0], "effect=none"));
    /* the denial receipts carry the binding too */
    reset_capture();
    osh_session_init(&s, 0);
    r = run(&s, hello);
    CHECK(nlogs == 1 && strstr(logs[0], "result=DENIED") && strstr(logs[0], "cap_domain=1") && strstr(logs[0], "principal="));

    /* the capability belongs to the principal it was granted to: another principal presenting it is DENIED */
    reset_capture();
    osh_session_init(&s, CK_R_WRITE);
    CHECK(memcmp(s.cap_holder, s.principal, 32) == 0);
    s.principal[0] ^= 1; /* a different task now runs the shell session */
    r = run(&s, hello);
    CHECK(r.error == OSH_E_DENIED && cap_calls == 0);
    osh_session_init(&s, 0);
    {
        static const uint8_t zero32[32];
        CHECK(memcmp(s.cap_holder, zero32, 32) == 0); /* nothing granted, no holder */
    }

    /* names */
    CHECK(strcmp(osh_err_name(OSH_E_PARTIAL_LAUNCH), "PARTIAL_LAUNCH") == 0 && strcmp(osh_err_name(99), "IO") == 0);
    CHECK(strcmp(osh_outcome_name(OSH_O_CANCELLED), "CANCELLED") == 0);

    return ck_t_verdict("test_osh_op");
}
