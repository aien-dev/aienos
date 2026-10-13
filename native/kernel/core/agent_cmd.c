/* agent_cmd.c -- see agent_cmd.h. No kernel calls, no libc. */
#include "agent_cmd.h"

struct ck_agent_cmd_boot ck_agent_cmd_boot;

struct verb {
    const char *name;
    int has_text; /* 1: needs text, 0: takes none */
};

/* The only verbs a card script may carry. unlock, rotate, update and shutdown are deliberately absent. */
static const struct verb verbs[] = {
    {"status", 0}, {"help", 0},   {"evidence", 0}, {"recall", 0},  {"facts", 0},  {"approve", 0},
    {"deny", 0},   {"cancel", 0}, {"remember", 1}, {"prefer", 1}, {"prompt", 1}, {"task", 1},
};

static void zero(struct ck_agent_cmd *o)
{
    unsigned char *p = (unsigned char *)o;
    for (size_t i = 0; i < sizeof *o; i++) p[i] = 0;
}

/* verb at line[0..vl): index in verbs[], or -1 */
static int find_verb(const char *l, size_t vl)
{
#ifdef CK_AGENT_CMD_MUTANT_ANY_VERB
    /* TEST-ONLY mutant: any word is a verb (a script could carry unlock or rotate). */
    (void)l; (void)vl; (void)verbs;
    return 0;
#else
    for (size_t k = 0; k < sizeof verbs / sizeof verbs[0]; k++) {
        size_t i = 0;
        while (verbs[k].name[i] && i < vl && verbs[k].name[i] == l[i]) i++;
        if (!verbs[k].name[i] && i == vl) return (int)k;
    }
    return -1;
#endif
}

int ck_agent_cmd_parse(const uint8_t *buf, size_t n, struct ck_agent_cmd *out, const char **why)
{
    const char *w = 0;
    size_t i, hl = sizeof CK_AGENT_CMD_HEADER - 1, at;
    if (out) zero(out);
    if (!buf || !out) {
        w = "no request";
        goto out;
    }
    if (n == 0 || n > CK_AGENT_CMD_FILE_MAX) {
        w = "file size must be 1..2048 bytes";
        goto out;
    }
    for (i = 0; i < n; i++)
        if (!(buf[i] == '\n' || (buf[i] >= 0x20 && buf[i] <= 0x7e))) {
            w = "only printable ASCII and LF line ends are allowed";
            goto out;
        }
    if (buf[n - 1] != '\n') {
        w = "file does not end with a line feed";
        goto out;
    }
    if (n < hl + 1)  {
        w = "bad header line";
        goto out;
    }
    for (i = 0; i < hl; i++)
        if (buf[i] != (uint8_t)CK_AGENT_CMD_HEADER[i]) {
            w = "bad header line";
            goto out;
        }
    if (buf[hl] != '\n') {
        w = "bad header line";
        goto out;
    }
    at = hl + 1;
    while (at < n) {
        size_t e = at, vl, tl;
        int v;
        uint32_t k = out->nlines;
        while (buf[e] != '\n') e++;
        if (e == at) {
            w = "empty line";
            goto out;
        }
        if (buf[at] == ' ' || buf[e - 1] == ' ') {
            w = "line has a leading or trailing blank";
            goto out;
        }
        if (k >= CK_AGENT_CMD_LINES_MAX) {
            w = "more than 16 command lines";
            goto out;
        }
        vl = 0;
        while (at + vl < e && buf[at + vl] != ' ') vl++;
        v = find_verb((const char *)buf + at, vl);
        if (v < 0) {
            w = "verb not allowed in a card script";
            goto out;
        }
        tl = at + vl < e ? e - (at + vl + 1) : 0;
#ifndef CK_AGENT_CMD_MUTANT_ANY_VERB
        if (verbs[v].has_text) {
            if (tl == 0 || tl > CK_AGENT_CMD_TEXT_MAX || buf[at + vl + 1] == ' ') {
                w = "text must be 1..48 bytes after one blank";
                goto out;
            }
        } else if (at + vl != e) {
            w = "this verb takes no text";
            goto out;
        }
#else
        (void)tl;
        if (e - at >= CK_AGENT_CMD_LINE_MAX) {
            w = "line too long";
            goto out;
        }
#endif
        for (i = 0; i < e - at; i++) out->line[k][i] = (char)buf[at + i];
        out->line[k][e - at] = 0;
        out->len[k] = (uint32_t)(e - at);
        out->nlines++;
        at = e + 1;
    }
    if (out->nlines == 0) w = "no command line";
out:
    if (w && out) zero(out);
    if (why) *why = w;
    return w ? -1 : 0;
}
