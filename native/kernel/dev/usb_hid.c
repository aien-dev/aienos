/* usb_hid.c -- operator input pure logic (see usb_hid.h). Freestanding. */
#include "usb_hid.h"
#include "sha256.h"

#define USAGE_ENTER 0x28u
#define USAGE_ESCAPE 0x29u
#define USAGE_BACKSPACE 0x2au
#define USAGE_SPACE 0x2cu
#define USAGE_MINUS 0x2du
#define USAGE_PERIOD 0x37u
#define USAGE_SLASH 0x38u
#define MOD_ANY_SHIFT 0x22u /* left shift bit 1, right shift bit 5 */

ck_key_event ck_hid_usage(uint8_t usage, int shift)
{
    ck_key_event ev = {CK_KEY_NONE, 0};
    if (usage >= 0x04 && usage <= 0x1d) { /* a..z */
        ev.kind = CK_KEY_CHAR;
        ev.c = (char)((shift ? 'A' : 'a') + (usage - 0x04));
    } else if (usage >= 0x1e && usage <= 0x27) { /* 1..9, 0 */
        if (shift) return ev;
        ev.kind = CK_KEY_CHAR;
        ev.c = usage == 0x27 ? '0' : (char)('1' + (usage - 0x1e));
    } else if (usage == USAGE_ENTER) {
        ev.kind = CK_KEY_ENTER;
    } else if (usage == USAGE_ESCAPE) {
        ev.kind = CK_KEY_ESCAPE;
    } else if (usage == USAGE_BACKSPACE) {
        ev.kind = CK_KEY_BACKSPACE;
    } else if (!shift && (usage == USAGE_SPACE || usage == USAGE_MINUS || usage == USAGE_PERIOD || usage == USAGE_SLASH)) {
        ev.kind = CK_KEY_CHAR;
        ev.c = usage == USAGE_SPACE ? ' ' : usage == USAGE_MINUS ? '-' : usage == USAGE_PERIOD ? '.' : '/';
    }
    return ev;
}

unsigned ck_hid_decode(ck_hid_decoder *d, const uint8_t *report, size_t len, ck_key_event out[CK_HID_MAX_KEYS])
{
    if (!d || !report || len != CK_HID_REPORT_LEN) return 0;
    const uint8_t *u = report + 2;
    if (u[0] == 0x01) return 0; /* ErrorRollOver: keep the previous state */
    int shift = (report[0] & MOD_ANY_SHIFT) != 0;
    unsigned n = 0;
    for (unsigned i = 0; i < CK_HID_MAX_KEYS; i++) {
        if (u[i] == 0) continue;
        int held = 0;
        for (unsigned j = 0; j < CK_HID_MAX_KEYS; j++) held |= d->previous[j] == u[i];
        if (held) continue;
        ck_key_event ev = ck_hid_usage(u[i], shift);
        if (ev.kind != CK_KEY_NONE) out[n++] = ev;
    }
    for (unsigned i = 0; i < CK_HID_MAX_KEYS; i++) d->previous[i] = u[i];
    return n;
}

int ck_usb_find_boot_kbd(const uint8_t *b, size_t len, ck_boot_kbd *out)
{
    if (!b || !out || len < 9 || b[0] < 9 || b[1] != 2) return -1;
    size_t total = (size_t)b[2] | ((size_t)b[3] << 8);
    if (total > len) total = len;
    uint8_t configuration = b[5];
    int iface = -1;
    size_t at = 0;
    while (at + 2 <= total) {
        size_t l = b[at];
        if (l < 2 || at + l > total) return -1;
        const uint8_t *d = b + at;
        if (d[1] == 4 && l >= 9) { /* interface */
            iface = (d[5] == 3 && d[6] == 1 && d[7] == 1) ? d[2] : -1;
        } else if (d[1] == 5 && l >= 7) { /* endpoint */
            if (iface >= 0 && (d[2] & 0x80u) && (d[3] & 0x3u) == 3u) {
                out->configuration = configuration;
                out->interface = (uint8_t)iface;
                out->endpoint = d[2];
                out->max_packet = (uint16_t)(((unsigned)d[4] | ((unsigned)d[5] << 8)) & 0x7ffu);
                out->interval = d[6];
                return out->max_packet ? 0 : -1;
            }
        }
        at += l;
    }
    return -1;
}

void ck_line_reset(ck_line *l)
{
    for (unsigned i = 0; i <= CK_LINE_CAP; i++) l->buf[i] = 0;
    l->len = 0;
    l->typed = 0;
    l->overflow = 0;
}

int ck_line_feed(ck_line *l, ck_key_event ev, void (*echo)(char c))
{
    switch (ev.kind) {
    case CK_KEY_CHAR:
        l->typed++;
        if (l->len >= CK_LINE_CAP) {
            l->overflow = 1; /* fail closed: this line will be refused at Enter */
            return CK_LINE_MORE;
        }
        l->buf[l->len++] = ev.c;
        l->buf[l->len] = 0;
        if (echo) echo(ev.c);
        return CK_LINE_MORE;
    case CK_KEY_BACKSPACE:
        if (l->len > 0 && !l->overflow) {
            l->buf[--l->len] = 0;
            if (echo) echo('\b');
        }
        return CK_LINE_MORE;
    case CK_KEY_ESCAPE:
        ck_line_reset(l);
        return CK_LINE_MORE;
    case CK_KEY_ENTER:
        if (l->overflow) {
            unsigned typed = l->typed;
            ck_line_reset(l);
            l->typed = typed; /* reported by the caller, then reset again */
            l->overflow = 1;
            return CK_LINE_OVERFLOW;
        }
        l->buf[l->len] = 0;
        return CK_LINE_DONE;
    default:
        return CK_LINE_MORE;
    }
}

static int is_space(char c) { return c == ' ' || c == '\t'; }
static int word_is(const char *w, size_t n, const char *lit)
{
    size_t i = 0;
    for (; i < n; i++)
        if (lit[i] == 0 || lit[i] != w[i]) return 0;
    return lit[i] == 0;
}

/* Splits like Rust split_ascii_whitespace; first and flen give the first word. */
static int parse(const char *s, size_t len, const char **first, size_t *flen)
{
    if (len > CK_LINE_CAP) return CK_SH_INVALID;
    const char *w[3] = {0, 0, 0};
    size_t wl[3] = {0, 0, 0};
    unsigned nw = 0;
    size_t i = 0;
    while (i < len) {
        while (i < len && is_space(s[i])) i++;
        if (i >= len) break;
        size_t st = i;
        while (i < len && !is_space(s[i])) i++;
        if (nw == 2) return CK_SH_INVALID; /* a third word */
        w[nw] = s + st;
        wl[nw] = i - st;
        nw++;
    }
    if (nw == 0) return CK_SH_EMPTY;
    if (wl[0] > 16 || (nw == 2 && wl[1] > 16)) return CK_SH_INVALID;
    *first = w[0];
    *flen = wl[0];
    if (word_is(w[0], wl[0], "help")) return CK_SH_HELP;
    if (word_is(w[0], wl[0], "mem")) return CK_SH_MEM;
    if (word_is(w[0], wl[0], "el")) return CK_SH_EL;
    if (word_is(w[0], wl[0], "report")) return CK_SH_REPORT;
    if (word_is(w[0], wl[0], "uptime")) return CK_SH_UPTIME;
    if (word_is(w[0], wl[0], "exit")) return CK_SH_EXIT;
    return CK_SH_UNKNOWN;
}

int ck_shell_parse(const char *line, size_t len)
{
    const char *f = 0;
    size_t fl = 0;
    return parse(line, len, &f, &fl);
}

int ck_shell_run(const char *line, const ck_shell_ctx *ctx, void (*out)(const char *fmt, ...))
{
    size_t len = 0;
    while (line[len] && len <= CK_LINE_CAP) len++;
    const char *f = 0;
    size_t fl = 0;
    switch (parse(line, len, &f, &fl)) {
    case CK_SH_HELP: out("commands: help mem el report uptime exit\n"); return 0;
    case CK_SH_MEM: out("conventional_memory_kb: %llu\n", (unsigned long long)ctx->conventional_memory_kb); return 0;
    case CK_SH_EL: out("EL%u\n", ctx->exception_level); return 0;
    case CK_SH_REPORT:
        out("report_kind: shell\naienos_commit: %s\nkernel: C (native/kernel)\n", ctx->commit ? ctx->commit : "unknown");
        return 0;
    case CK_SH_UPTIME: out("uptime_ms: %llu\n", (unsigned long long)ctx->uptime_ms); return 0;
    case CK_SH_EXIT: return 1;
    case CK_SH_UNKNOWN: {
        char name[17];
        size_t i = 0;
        for (; i < fl && i < 16; i++) name[i] = f[i];
        name[i] = 0;
        out("unknown command: %s\n", name);
        return 0;
    }
    default: out("invalid command line\n"); return 0;
    }
}

int ck_recovery_decide(int have_key, ck_key_event ev)
{
    if (!have_key) return CK_RECOVERY_NORMAL_TIMEOUT;
    if (ev.kind == CK_KEY_CHAR && (ev.c == 'r' || ev.c == 'R')) return CK_RECOVERY_CONSOLE;
    return CK_RECOVERY_NORMAL_KEY;
}

const char *ck_recovery_name(int choice)
{
    switch (choice) {
    case CK_RECOVERY_CONSOLE: return "recovery reason=key-r";
    case CK_RECOVERY_NORMAL_KEY: return "normal reason=other-key";
    default: return "normal reason=timeout";
    }
}

void ck_recovery_identity(const char *commit, uint8_t out[32])
{
    static const char dom[] = "AIENOS-CK-RECOVERY-IDENTITY-V1"; /* hashed with its NUL */
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)dom, sizeof dom);
    size_t n = 0;
    if (commit)
        while (commit[n] && n < 64) n++;
    sha256_update(&c, (const uint8_t *)(commit ? commit : ""), n);
    sha256_final(&c, out);
}

/* ---- console session: source ownership of the shared line ---- */
void ck_src_gate_reset(ck_src_gate *g)
{
    g->owner = CK_SRC_NONE;
    g->dropped = 0;
    g->dropped_all = 0;
}

int ck_src_gate_accept(ck_src_gate *g, int src, ck_key_event ev)
{
    if (ev.kind == CK_KEY_NONE || (src != CK_SRC_SERIAL && src != CK_SRC_USB))
        return 0;
    if (g->owner == CK_SRC_NONE) {
        /* Only a printable key claims a line. Backspace, Escape and Enter on an
         * empty line pass through without owning it, so they cannot lock the
         * other source out. */
        if (ev.kind == CK_KEY_CHAR) g->owner = src;
        return 1;
    }
    if (g->owner == src)
        return 1;
    g->dropped++;
    g->dropped_all++;
    return 0;
}

unsigned ck_src_gate_release(ck_src_gate *g)
{
    unsigned d = g->dropped;
    g->owner = CK_SRC_NONE;
    g->dropped = 0;
    return d;
}

ck_key_event ck_serial_key(uint8_t byte, uint8_t *prev)
{
    ck_key_event none = {CK_KEY_NONE, 0};
    uint8_t before = *prev;
    *prev = byte;
    if (byte == '\r' || (byte == '\n' && before != '\r')) return (ck_key_event){CK_KEY_ENTER, 0};
    if (byte == 0x08 || byte == 0x7f) return (ck_key_event){CK_KEY_BACKSPACE, 0};
    if (byte == 0x1b) return (ck_key_event){CK_KEY_ESCAPE, 0};
    if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') || byte == ' ' ||
        byte == '-' || byte == '.' || byte == '/')
        return (ck_key_event){CK_KEY_CHAR, (char)byte};
    return none;
}
