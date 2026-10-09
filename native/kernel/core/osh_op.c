/* osh_op.c -- see osh_op.h. The adapter side of OSH on AIENOS: request record in, one capability-checked platform
 * operation out. No lexing, parsing or expansion happens here. No libc calls (host and kernel builds share it). */
#include "osh_op.h"
#include "fmt.h"
#include "sha256.h"

#if defined(CK_OSH_OP_MUTANT_SKIP_PERM) && !__STDC_HOSTED__
#error "CK_OSH_OP_MUTANT_SKIP_PERM is a host-test-only mutant"
#endif

/* section 7.1 layout */
#define REQ_MAGIC 0x4F524551ull
#define REQ_HDR 8u
#define CMD_CELLS 164u
#define MAX_CMDS 8u
#define MAX_ARGV 32u
#define MAX_ASSIGN 16u
#define MAX_REDIR 8u
#define LINE_MAX_BYTES 200u /* longest text after the prefix; over it is LIMIT before any effect */

static const char PREFIX[] = "osh_op_out: ";

static void zero(void *p, size_t n)
{
    uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        b[i] = 0;
}

__attribute__((unused)) static int same(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i])
            return 0;
    return 1;
}

const char *osh_err_name(unsigned e)
{
    static const char *const n[] = { "OK", "DENIED", "REVOKED", "STALE", "NOT_FOUND", "UNAVAILABLE", "INVALID_ARG", "LIMIT",
                                     "INTERRUPTED", "BROKEN_PIPE", "IO", "OUTCOME_UNKNOWN", "CAP_DOMAIN_MISMATCH",
                                     "CAP_GEN_NARROW", "NOT_SUPPORTED", "WOULD_BLOCK", "PARTIAL_LAUNCH" };
    return e < sizeof n / sizeof n[0] ? n[e] : "IO"; /* section 8.6: an unknown code is IO, never OK */
}

const char *osh_outcome_name(unsigned o)
{
    static const char *const n[] = { "NOT_STARTED", "COMPLETED", "FAILED_NO_EFFECT", "CANCELLED", "OUTCOME_UNKNOWN" };
    return o < sizeof n / sizeof n[0] ? n[o] : "OUTCOME_UNKNOWN";
}

static void hex32(const uint8_t d[32], char o[65])
{
    static const char x[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        o[2 * i] = x[d[i] >> 4];
        o[2 * i + 1] = x[d[i] & 15];
    }
    o[64] = 0;
}

void osh_session_init(struct osh_session *s, unsigned grant_rights)
{
    zero(s, sizeof *s);
    ck_cap_init(&s->caps, 0x4f534800u, 4);
    sha256_hash((const uint8_t *)"aienos-osh-test-session", 23, s->principal);
    if (grant_rights)
        (void)ck_cap_insert(&s->caps, OSH_RES_CONSOLE_LOG, grant_rights, &s->console_cap);
}

int osh_session_close(struct osh_session *s)
{
    if (s->console_cap.generation)
        (void)ck_cap_remove(&s->caps, s->console_cap);
    for (unsigned i = 0; i < CK_CAP_SLOTS; i++)
        if (s->caps.slots[i].live)
            return 0;
    return 1;
}

void osh_session_restart(struct osh_session *fresh, const struct osh_session *old)
{
    osh_session_init(fresh, 0);
    for (unsigned i = 0; i < OSH_INTENT_MAX; i++)
        fresh->intents[i] = old->intents[i];
    fresh->pipelines = old->pipelines;
}

static void note(const struct osh_env *env, const char *fmt, uint32_t seq, const char *what, const uint8_t dg[32])
{
    char d[65], line[200];
    hex32(dg, d);
    ck_snprintf(line, sizeof line, fmt, (unsigned)seq, what, d);
    env->log(env->ctx, line);
}

unsigned osh_op_recover(struct osh_session *s, const struct osh_env *env)
{
    unsigned n = 0;
    for (unsigned i = 0; i < OSH_INTENT_MAX; i++) {
        struct osh_intent *t = &s->intents[i];
        if (!t->used || t->closed)
            continue;
        t->closed = 1;
        t->outcome = OSH_O_OUTCOME_UNKNOWN;
        t->err = OSH_E_OUTCOME_UNKNOWN;
        note(env, "osh_op_record: seq=%u outcome=%s request_digest=%s replayed=0", t->seq, "OUTCOME_UNKNOWN", t->digest);
        n++;
    }
    return n;
}

/* section 9 rule 2 and 3: validated at the moment of the effect, against the table that holds the capability. The
 * REVOKED / STALE split is this adapter's reading of the draft: a handle whose slot is now empty (or a tombstone) and
 * whose generation was issued is REVOKED; a slot reused under a newer generation is STALE; anything never issued is DENIED. */
unsigned osh_op_perm_check(const struct osh_session *s, const struct osh_binding *b)
{
#ifdef CK_OSH_OP_MUTANT_SKIP_PERM
    (void)s;
    (void)b;
    return OSH_E_OK;
#else
    if (b->domain == 2)
        return OSH_E_CAP_DOMAIN_MISMATCH; /* the console resource lives in the kernel IPC table (domain 1) */
    if (b->domain != 1)
        return OSH_E_INVALID_ARG;
    if (b->cap_generation > 0xffffffffull)
        return OSH_E_CAP_GEN_NARROW;
    if (b->resource_class != OSH_RC_CONSOLE_LOG || b->operation != OSH_OP_WRITE)
        return OSH_E_DENIED;
    if (!same(b->principal_id, s->principal, 32))
        return OSH_E_DENIED;
    uint32_t gen = (uint32_t)b->cap_generation;
    if (gen == 0 || b->cap_index >= s->caps.n)
        return OSH_E_DENIED;
    const struct ck_cap_slot *sl = &s->caps.slots[b->cap_index];
    struct ck_handle h = { b->cap_index, gen };
    if (sl->live && !sl->tombstone && sl->generation == gen) {
        uint32_t res = 0;
        int r = ck_cap_lookup(&s->caps, h, CK_R_WRITE, &res);
        return r == CK_CAP_OK && res == OSH_RES_CONSOLE_LOG ? OSH_E_OK : OSH_E_DENIED;
    }
    if (sl->live && !sl->tombstone && sl->generation > gen)
        return OSH_E_STALE;
    if ((sl->live && sl->tombstone && sl->generation == gen) || (!sl->live && s->caps.generations[b->cap_index] == gen))
        return OSH_E_REVOKED;
    return OSH_E_DENIED;
#endif
}

static int status_for(unsigned err)
{
    if (err == OSH_E_OK)
        return 0;
    switch (err) {
    case OSH_E_NOT_FOUND: return 127;
    case OSH_E_DENIED: case OSH_E_REVOKED: case OSH_E_STALE: case OSH_E_CAP_DOMAIN_MISMATCH: case OSH_E_CAP_GEN_NARROW:
    case OSH_E_NOT_SUPPORTED: return 126; /* found but not run: the adapter's choice, UNVERIFIED against the reference shell */
    case OSH_E_INTERRUPTED: return 130;
    default: return 70; /* IO, INVALID_ARG, LIMIT, unknown: an internal-style failure */
    }
}

static void finish(struct osh_result *r, unsigned err, unsigned outcome)
{
    r->error = err;
    r->outcome = outcome;
    r->status = status_for(err);
}

static void digest_request(const uint64_t *req, unsigned ncmds, const uint64_t *out, uint64_t out_used, uint8_t d[32])
{
    sha256_ctx c;
    uint8_t b[8];
    size_t cells = REQ_HDR + (size_t)ncmds * CMD_CELLS;
    sha256_init(&c);
    for (size_t i = 0; i < cells; i++) {
        for (unsigned k = 0; k < 8; k++)
            b[k] = (uint8_t)(req[i] >> (8 * k));
        sha256_update(&c, b, 8);
    }
    for (uint64_t i = 0; i < out_used; i++) {
        b[0] = (uint8_t)out[i];
        sha256_update(&c, b, 1);
    }
    sha256_final(&c, d);
}

static struct osh_intent *close_intent(struct osh_intent *t, unsigned outcome, unsigned err, int status)
{
    t->closed = 1;
    t->outcome = (uint8_t)outcome;
    t->err = (uint8_t)err;
    t->status = (uint32_t)status;
    return t;
}

void osh_op_exec(struct osh_session *s, const struct osh_env *env, const uint64_t *req, const uint64_t *out, size_t n_out,
                 struct osh_result *r)
{
    zero(r, sizeof *r);
    r->seq = ++s->pipelines;

    /* 1. the record is the expander's output, but it sits in memory the unit could write: check it before use */
    uint64_t ncmds = req[1], out_used = req[4];
    if (req[0] != REQ_MAGIC || req[5] != 1 || (req[3] & ~1ull) || req[6] || req[7] || ncmds < 1 || ncmds > MAX_CMDS ||
        out_used > n_out) {
        finish(r, OSH_E_INVALID_ARG, OSH_O_NOT_STARTED);
        return;
    }
    digest_request(req, (unsigned)ncmds, out, out_used, r->digest);
    const uint64_t *c0 = req + REQ_HDR;
    uint64_t nargv = c0[0], nassign = c0[1], nredir = c0[2], builtin = c0[3];
    if (nargv > MAX_ARGV || nassign > MAX_ASSIGN || nredir > MAX_REDIR) {
        finish(r, OSH_E_INVALID_ARG, OSH_O_NOT_STARTED);
        return;
    }
    for (uint64_t k = 0; k < nargv; k++) {
        uint64_t off = c0[4 + 2 * k], len = c0[5 + 2 * k];
        if (off > out_used || len > out_used - off) {
            finish(r, OSH_E_INVALID_ARG, OSH_O_NOT_STARTED);
            return;
        }
        for (uint64_t i = 0; i < len; i++)
            if (out[off + i] > 255) {
                finish(r, OSH_E_INVALID_ARG, OSH_O_NOT_STARTED);
                return;
            }
    }

    /* 2. RESOLVE (section 8.3): a name is a lookup key only. Class 1, a compiled operation the adapter hosts. */
    if (nargv == 0 || c0[4 + 1] != 4 || out[c0[4]] != 'k' || out[c0[4] + 1] != 'l' || out[c0[4] + 2] != 'o' ||
        out[c0[4] + 3] != 'g') {
        finish(r, OSH_E_NOT_FOUND, OSH_O_NOT_STARTED);
        return;
    }
    /* what this layer cannot do yet is refused before any effect, never approximated */
    if (ncmds != 1 || nassign || nredir || builtin) {
        finish(r, OSH_E_NOT_SUPPORTED, OSH_O_NOT_STARTED); /* no pipes, redirections, assignments in this slice */
        return;
    }

    /* 3. the text to write: argv[1..] joined by one space; bytes outside 0x20..0x7e become '.' so an argument can
     * never forge a record line */
    char line[sizeof PREFIX + LINE_MAX_BYTES + 3];
    size_t n = 0;
    for (; PREFIX[n]; n++)
        line[n] = PREFIX[n];
    size_t body = 0;
    for (uint64_t k = 1; k < nargv; k++) {
        uint64_t off = c0[4 + 2 * k], len = c0[5 + 2 * k];
        if (body + (k > 1) + len > LINE_MAX_BYTES) {
            finish(r, OSH_E_LIMIT, OSH_O_NOT_STARTED);
            return;
        }
        if (k > 1)
            line[n + body++] = ' ';
        for (uint64_t i = 0; i < len; i++) {
            uint8_t ch = (uint8_t)out[off + i];
            line[n + body++] = ch >= 0x20 && ch <= 0x7e ? (char)ch : '.';
        }
    }
    n += body;
    line[n++] = '\n';
    line[n] = 0; /* the sink may print it as a C string */

    /* 4. the intent record, before the effect (section 10) */
    struct osh_intent *t = 0;
    for (unsigned i = 0; i < OSH_INTENT_MAX && !t; i++)
        if (!s->intents[i].used)
            t = &s->intents[i];
    if (!t) {
        finish(r, OSH_E_LIMIT, OSH_O_NOT_STARTED);
        return;
    }
    t->used = 1;
    t->closed = 0;
    t->seq = r->seq;
    for (unsigned i = 0; i < 32; i++)
        t->digest[i] = r->digest[i];

    /* 5. the binding this effect carries, built from what the task holds. Nothing here grants anything. */
    struct osh_binding b;
    zero(&b, sizeof b);
    for (unsigned i = 0; i < 32; i++)
        b.principal_id[i] = s->principal[i];
    b.domain = 1;
    b.cap_index = s->console_cap.index;
    b.cap_generation = s->console_cap.generation;
    b.resource_class = OSH_RC_CONSOLE_LOG;
    b.operation = OSH_OP_WRITE;

    if (s->hooks.revoke_before_perm_at == r->seq && s->console_cap.generation)
        (void)ck_cap_remove(&s->caps, s->console_cap); /* revoked between building the request and using it */

    /* 6. the effect boundary: validated now, not at parse time */
    unsigned pc = osh_op_perm_check(s, &b);
    if (pc != OSH_E_OK) {
        close_intent(t, OSH_O_FAILED_NO_EFFECT, pc, status_for(pc));
        finish(r, pc, OSH_O_FAILED_NO_EFFECT);
        note(env, "osh_op_receipt: seq=%u op=console_write result=%s request_digest=%s effect=none", r->seq, osh_err_name(pc),
             r->digest);
        return;
    }
    if (s->hooks.interrupt_before_effect_at == r->seq) {
        close_intent(t, OSH_O_CANCELLED, OSH_E_INTERRUPTED, 130);
        finish(r, OSH_E_INTERRUPTED, OSH_O_CANCELLED);
        r->stop = 1;
        note(env, "osh_op_record: seq=%u outcome=%s request_digest=%s effect=none", r->seq, "CANCELLED", r->digest);
        return;
    }

    /* 7. the effect */
    int w = s->hooks.sink_fail_at == r->seq ? -1 : env->out(env->ctx, line, n);
    if (w != 0) {
        /* a failed write-class effect may have partly happened: unknown, not "no effect" */
        close_intent(t, OSH_O_OUTCOME_UNKNOWN, OSH_E_IO, 70);
        finish(r, OSH_E_IO, OSH_O_OUTCOME_UNKNOWN);
        note(env, "osh_op_record: seq=%u outcome=%s request_digest=%s effect=unknown", r->seq, "OUTCOME_UNKNOWN", r->digest);
        return;
    }
    if (s->hooks.crash_after_effect_at == r->seq) {
        r->crashed = 1; /* the adapter is lost here: the effect happened, the outcome is never written */
        r->stop = 1;
        r->error = OSH_E_OUTCOME_UNKNOWN;
        r->outcome = OSH_O_OUTCOME_UNKNOWN;
        r->status = 70;
        return;
    }
    close_intent(t, OSH_O_COMPLETED, OSH_E_OK, 0);
    finish(r, OSH_E_OK, OSH_O_COMPLETED);
}
