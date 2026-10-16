/* allen_gate.c -- see allen_gate.h. No kernel calls, no libc. */
#include "allen_gate.h"

#define PFX "{\"action\":\""
#define MID "\",\"args\":{"
#define TXT "\"text\":\""

static size_t slen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

/* json[*at..) starts with lit: advance past it */
static int eat(const char *j, size_t n, size_t *at, const char *lit)
{
    size_t k = slen(lit);
    if (n - *at < k) return 0;
    for (size_t i = 0; i < k; i++)
        if (j[*at + i] != lit[i]) return 0;
    *at += k;
    return 1;
}

static int is_word(const char *s, size_t n, const char *w)
{
    size_t k = slen(w);
    if (k != n) return 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] != w[i]) return 0;
    return 1;
}

static void copy_line(struct ck_allen_gate *o, const char *v, size_t vl, const char *t, size_t tl)
{
    size_t w = 0;
    for (size_t i = 0; i < vl; i++) o->line[w++] = v[i];
    if (tl) {
        o->line[w++] = ' ';
        for (size_t i = 0; i < tl; i++) o->line[w++] = t[i];
    }
    o->line[w] = 0;
    o->line_len = (uint32_t)w;
}

static void zero(void *p, size_t n)
{
    unsigned char *b = p;
    for (size_t i = 0; i < n; i++) b[i] = 0;
}

static void copy_lc(ck_lc *dst, const ck_lc *src)
{
    const unsigned char *s = (const unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    for (size_t i = 0; i < sizeof *src; i++) d[i] = s[i];
}

static void verdict(struct ck_allen_gate *o, enum ck_allen_verdict v, const char *why)
{
    o->verdict = v;
    o->reason = why;
}

void ck_allen_gate_judge(const char *j, size_t n, const ck_lc *lc, struct ck_allen_gate *o)
{
    if (!o) return;
    zero(o, sizeof *o);
    o->verb = CK_LC_V_UNKNOWN;
    o->fsm = CK_LC_R_REFUSED;
    if (!j || !lc || n == 0 || n > CK_ALLEN_JSON_MAX) {
        verdict(o, CK_ALLEN_REJECTED, "decision size out of bounds");
        return;
    }
    /* 1. exact shape */
    size_t at = 0, vb, vl, tb = 0, tl = 0;
    if (!eat(j, n, &at, PFX)) goto shape;
    vb = at;
    while (at < n && j[at] >= 'a' && j[at] <= 'z') at++;
    vl = at - vb;
    if (vl == 0 || vl > 16 || !eat(j, n, &at, MID)) goto shape;
    if (eat(j, n, &at, TXT)) {
        tb = at;
        while (at < n && j[at] >= 0x20 && j[at] <= 0x7e && j[at] != '"' && j[at] != '\\') at++;
        tl = at - tb;
        if (tl == 0 || !eat(j, n, &at, "\"")) goto shape;
    }
    if (!eat(j, n, &at, "}}") || at != n) goto shape;

    /* 2. no command */
    if (is_word(j + vb, vl, "none") || is_word(j + vb, vl, "clarify") || is_word(j + vb, vl, "refuse")) {
        if (tl) {
            verdict(o, CK_ALLEN_REJECTED, "no-command decision carries text");
            return;
        }
        verdict(o, CK_ALLEN_NO_COMMAND, "no command");
        return;
    }

    /* 3. the card command parser: verb whitelist and text bounds */
    if (vl + 1 + tl + 1 > CK_AGENT_CMD_LINE_MAX) {
        verdict(o, CK_ALLEN_REJECTED, "command line too long");
        return;
    }
    copy_line(o, j + vb, vl, j + tb, tl);
    {
        static const char hdr[] = CK_AGENT_CMD_HEADER "\n";
        uint8_t file[sizeof hdr + CK_AGENT_CMD_LINE_MAX + 1];
        struct ck_agent_cmd cmd;
        const char *why = 0;
        size_t w = 0;
        for (size_t i = 0; i + 1 < sizeof hdr; i++) file[w++] = (uint8_t)hdr[i];
        for (size_t i = 0; i < o->line_len; i++) file[w++] = (uint8_t)o->line[i];
        file[w++] = '\n';
        if (ck_agent_cmd_parse(file, w, &cmd, &why) != 0 || cmd.nlines != 1) {
            verdict(o, CK_ALLEN_REJECTED, why ? why : "not a card command");
            return;
        }
    }
    const char *arg = 0;
    size_t arg_len = 0;
    o->verb = ck_lc_decode(o->line, o->line_len, &arg, &arg_len);
    if (o->verb <= CK_LC_V_EMPTY || !is_word(o->line, vl, ck_lc_verb_name(o->verb))) {
        verdict(o, CK_ALLEN_REJECTED, "command does not decode to its own verb");
        return;
    }

    /* 4. the lifecycle judges it on a copy */
    ck_lc copy;
    copy_lc(&copy, lc);
    o->fsm = ck_lc_apply(&copy, o->verb, arg, arg_len);
    if (o->fsm == CK_LC_R_REFUSED || o->fsm == CK_LC_R_INVALID) {
        verdict(o, CK_ALLEN_REFUSED, copy.reason && copy.reason[0] ? copy.reason : "refused by the lifecycle");
        return;
    }

    /* 5. authority stays with the operator */
    switch (o->verb) {
    case CK_LC_V_APPROVE:
    case CK_LC_V_DENY:
    case CK_LC_V_CANCEL:
#ifdef CK_ALLEN_GATE_MUTANT_TRUST_AUTHORITY
        /* TEST-ONLY mutant: ALLEN's approve/deny/cancel would be proposed like any other verb. */
        verdict(o, CK_ALLEN_PROPOSED, "mutant");
        return;
#else
        verdict(o, CK_ALLEN_NEEDS_OPERATOR, "approval authority stays with the operator");
        return;
#endif
    case CK_LC_V_REMEMBER:
    case CK_LC_V_PREFER:
        verdict(o, CK_ALLEN_NEEDS_OPERATOR, "writes the sealed Store: operator only");
        return;
    case CK_LC_V_STATUS:
    case CK_LC_V_HELP:
    case CK_LC_V_EVIDENCE:
    case CK_LC_V_RECALL:
    case CK_LC_V_FACTS:
        verdict(o, CK_ALLEN_PROPOSED, "read only");
        return;
    case CK_LC_V_TASK:
    case CK_LC_V_PROMPT:
        verdict(o, CK_ALLEN_PROPOSED, "creates a pending item that waits for the operator's approve");
        return;
    default:
        verdict(o, CK_ALLEN_REJECTED, "verb not allowed to ALLEN");
        return;
    }
shape:
    verdict(o, CK_ALLEN_REJECTED, "decision is not the exact JSON shape");
}

const char *ck_allen_verdict_name(enum ck_allen_verdict v)
{
    switch (v) {
    case CK_ALLEN_NO_COMMAND: return "NO_COMMAND";
    case CK_ALLEN_PROPOSED: return "PROPOSED";
    case CK_ALLEN_NEEDS_OPERATOR: return "NEEDS_OPERATOR";
    case CK_ALLEN_REFUSED: return "REFUSED";
    case CK_ALLEN_REJECTED: return "REJECTED";
    }
    return "?";
}
