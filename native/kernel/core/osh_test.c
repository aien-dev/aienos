/* osh_test.c -- OSH-AIENOS-0 kernel self-test (TEST ONLY, qualification build with CK_OSH_TEST=1).
 *
 * Runs the Omega-native shell core (three compiled OSC units: lex_run, parse_run, expand_run) as admitted EL0 tasks
 * through the launch interface, over the embedded fixture scripts, with the SAME sequencing as omega's
 * tests/osh/osh_trace.c (which mirrors src/osh/host/osh_shell.c run_src / lex_parse / run_list), and prints the
 * same trace lines on the serial console:
 *     step <n> unit=<lex|parse|expand> in_len=<n> ret=<u64> ws_sha256=<hex of WS_CELLS*8 bytes>
 *     request <n> sha256=<hex of the request record cells>
 *     event <text>   (input_window_exceeded, internal_error, request_ncmds_out_of_range, fake_status_exhausted)
 *     event exit=<status>   last line of every fixture (2 after a refusal, 70 after a unit fault status)
 * Nothing is executed: on PIPELINE_READY the driver only records the request and takes the fixture's next fake
 * status (its .status sidecar, then 0); NEED_VAR is answered from a fixed table (HOME=/home/t, X="a b", EMPTY=""),
 * $? = the last fake status, $0 = "osh_trace", $1.. from the fixture's .args sidecar. No environment, no files, no exec.
 * One caller-owned workspace of 23 pages (11456 cells) lives across every call. Input goes through the read-only
 * input window (at most 4096 bytes). A list buffer that would exceed 4096 is refused by the driver exactly as
 * osh_trace.c does (event line), documented in the gate.
 *
 * Then five negative controls (lines "osh_neg"), see qemu_ck_osh_core_test.sh.
 * QEMU (aarch64 virt), TEST signer, not physical. */
#include "ck_internal.h"
#include "fmt.h"
#include "osc_task.h"
#include "osc_admit.h"
#include "sha256.h"
#include "../tests/fixtures/osh/osh_layout.h"
#include "osh_fixtures.h"

#define LABEL "QEMU (aarch64 virt), TEST signer, not physical"
#define CKOSH_WS_CELLS 11456u
#define WS_PAGES 23u
#define INPUT_MAX 4096u
#define REQ_HDR_CELLS 8u
#define CMD_CELLS 164u

/* the constants the shell was built against (omega src/osh/osh_layout.h at the pinned commit) */
_Static_assert(OSH_WS_CELLS == CKOSH_WS_CELLS, "workspace cells differ from the pinned omega layout");
_Static_assert((uint64_t)CKOSH_WS_CELLS * 8 <= (uint64_t)WS_PAGES * 4096, "23 pages hold the workspace");
_Static_assert((uint64_t)CKOSH_WS_CELLS * 8 > (uint64_t)(WS_PAGES - 1) * 4096, "22 pages do not");
_Static_assert(OSH_LINE_CAP == INPUT_MAX, "input window equals the lexer line cap");
_Static_assert(OSH_REQ_CMD_CELLS == CMD_CELLS, "request command record size");

enum { ST_MORE = 100, ST_BUDGET = 101, ST_NEED_VAR = 102, ST_PIPE = 103, ST_COMPLETE = 104 };
enum { U_LEX = 0, U_PARSE = 1, U_EXPAND = 2, U_COUNT = 3 };
static const char *const u_file[U_COUNT] = { "osh_lex.unit", "osh_parse.unit", "osh_expand.unit" };
static const char *const u_entry[U_COUNT] = { "lex_run", "parse_run", "expand_run" };
static const char *const u_label[U_COUNT] = { "lex", "parse", "expand" };

#define UNIT_BYTES 131072u /* the packed containers (IR + code + manifest) pass 64 KiB; the code stays under CK_OSC_CODE_MAX_BYTES */
static struct {
    uint8_t bytes[UNIT_BYTES];
    size_t len;
    int have;
    struct osc_accept acc;
} unit[U_COUNT];

static int streq(const char *a, const char *b)
{
    size_t n = strlen(a);
    return n == strlen(b) && memcmp(a, b, n) == 0;
}

/* the launch gate's hand-assembled spin() unit, used only by control 4b */
static struct {
    uint8_t bytes[16384];
    size_t len;
    int have;
    struct osc_accept acc;
} spin_unit;

void ck_osh_save(const char *name, const uint8_t *b, size_t len, const struct osc_accept *acc)
{
    if (streq(name, "l01_launch_fns.unit") && len <= sizeof spin_unit.bytes) {
        memcpy(spin_unit.bytes, b, len);
        spin_unit.len = len;
        spin_unit.acc = *acc;
        spin_unit.have = 1;
        return;
    }
    for (unsigned u = 0; u < U_COUNT; u++) {
        if (!streq(name, u_file[u]))
            continue;
        if (len > UNIT_BYTES) {
            ck_printf("osh_test: %s is %u bytes, over the %u byte test buffer; not saved\n", name, (unsigned)len, UNIT_BYTES);
            return;
        }
        memcpy(unit[u].bytes, b, len);
        unit[u].len = len;
        unit[u].acc = *acc;
        unit[u].have = 1;
    }
}

static uint8_t ws_mem[WS_PAGES * 4096] __attribute__((aligned(4096)));
static uint8_t in_buf[INPUT_MAX];
static size_t blen;
static unsigned long step_no, req_no;
static const unsigned char *src_text;
static unsigned long src_len, src_pos;
static int stop; /* a launch did not RETURN: the script is abandoned and the gate fails the diff */

static uint64_t *const w = (uint64_t *)ws_mem;

static void hex(const uint8_t *p, size_t n, char *o)
{
    static const char d[] = "0123456789abcdef";
    uint8_t dg[SHA256_DIGEST_SIZE];
    sha256_hash(p, n, dg);
    for (unsigned i = 0; i < SHA256_DIGEST_SIZE; i++) {
        o[2 * i] = d[dg[i] >> 4];
        o[2 * i + 1] = d[dg[i] & 15];
    }
    o[64] = 0;
}

/* One entry call through the launch interface. 0 = RETURNED (value in *ret), else the result is printed and 1. */
static int launch(unsigned u, size_t in_len, uint64_t ws_cells, struct ck_osc_ws *wsr, uint64_t max_ticks, struct osc_result *r,
                  struct ck_osc_launch_info *info)
{
    struct ck_osc_launch_req rq;
    memset(&rq, 0, sizeof rq);
    rq.name = u_entry[u];
    rq.name_len = strlen(u_entry[u]);
    rq.nargs = 4;
    rq.args[0] = ck_osc_va_in();
    rq.args[1] = in_len;
    rq.args[2] = ck_osc_va_ws();
    rq.args[3] = ws_cells;
    rq.in = in_buf;
    rq.in_len = in_len;
    rq.ws = wsr;
    rq.max_ticks = max_ticks;
    ck_osc_launch(unit[u].bytes, unit[u].len, &unit[u].acc, &rq, r, info);
    return r->cls != OSC_RES_RETURNED;
}

static struct ck_osc_ws main_ws = { ws_mem, WS_PAGES };

static uint64_t call(unsigned u)
{
    struct osc_result r;
    struct ck_osc_launch_info info;
    char h[65];
    if (launch(u, blen, CKOSH_WS_CELLS, &main_ws, 0, &r, &info)) {
        char rs[96];
        ck_osc_result_str(&r, rs, sizeof rs);
        ck_printf("osh_fault: %s step %lu -> %s; %s\n", u_label[u], step_no + 1, rs, LABEL);
        stop = 1;
        return ~(uint64_t)0;
    }
    hex(ws_mem, (size_t)CKOSH_WS_CELLS * 8, h);
    ck_printf("step %lu unit=%s in_len=%u ret=%llu ws_sha256=%s\n", ++step_no, u_label[u], (unsigned)blen,
              (unsigned long long)r.value, h);
    return r.value;
}

static void reset_list(void)
{
    memset(ws_mem, 0, sizeof ws_mem);
    w[OSH_S_MAGIC] = OSH_ABI_MAGIC;
    w[OSH_S_VERSION] = OSH_ABI_VERSION;
    w[OSH_S_WS_CELLS] = OSH_WS_CELLS;
    blen = 0;
}

static uint64_t run_entry(unsigned u)
{
    for (int i = 0; i < 100000; i++) {
        uint64_t st = call(u);
        if (stop || st != ST_BUDGET)
            return st;
    }
    return ~(uint64_t)0;
}

static uint64_t lex_parse(void)
{
    uint64_t st = run_entry(U_LEX);
    if (st != 0 || stop)
        return st;
    return run_entry(U_PARSE);
}

static int append(const uint8_t *p, size_t n)
{
    if (blen + n > INPUT_MAX) {
        ck_printf("event input_window_exceeded have=%u add=%u max=%u\n", (unsigned)blen, (unsigned)n, INPUT_MAX);
        return -1;
    }
    memcpy(in_buf + blen, p, n);
    blen += n;
    return 0;
}

static int read_line(void)
{
    if (src_pos >= src_len)
        return 0;
    const unsigned char *s = src_text + src_pos;
    unsigned long n = 0;
    while (src_pos + n < src_len && s[n] != '\n')
        n++;
    int nl = src_pos + n < src_len;
    if (append(s, n) != 0)
        return -1;
    if (append((const uint8_t *)"\n", 1) != 0)
        return -1;
    src_pos += n + (unsigned long)nl;
    return 1;
}

static size_t dec(uint64_t v, uint8_t *o)
{
    uint8_t t[24];
    size_t n = 0;
    do {
        t[n++] = (uint8_t)('0' + v % 10);
        v /= 10;
    } while (v);
    for (size_t i = 0; i < n; i++)
        o[i] = t[n - 1 - i];
    return n;
}

static const char *var_get(const char *name)
{
    if (streq(name, "HOME"))
        return "/home/t";
    if (streq(name, "X"))
        return "a b";
    if (streq(name, "EMPTY"))
        return "";
    return NULL;
}

/* Per fixture, as omega tests/osh/osh_trace.c load_fixture(): fake pipeline statuses from the .status sidecar, the
 * positionals $1.. from the .args sidecar (one per line), $0 = "osh_trace". */
#define MAX_FAKE 256
#define MAX_POS 9
static int last_status; /* the shell's $?: fake pipeline statuses, 2 after a refusal */
static int fake[MAX_FAKE], nfake, fake_i, have_status;
static char pos_buf[4096];
static const char *pos[MAX_POS];
static int npos;
static int exhausted; /* .status ran out: omega's osh_trace exits 2 after its event line, with no exit line */
static const char ARG0[] = "osh_trace";

static int next_fake(void)
{
    if (fake_i < nfake)
        return fake[fake_i++];
    if (have_status) {
        ck_printf("event fake_status_exhausted after=%d\n", nfake);
        exhausted = 1;
    }
    return 0;
}

static int is_ws(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n';
}

/* 0, or -1 with a line printed: a malformed sidecar is a fixture error (omega's osh_trace exits 2 on it) */
static int load_fixture(unsigned i)
{
    nfake = fake_i = have_status = npos = exhausted = 0;
    last_status = 0;
    if (osh_fx[i].status) {
        const unsigned char *s = osh_fx[i].status;
        unsigned long n = osh_fx[i].status_len, q = 0;
        have_status = 1;
        for (;;) {
            while (q < n && is_ws(s[q]))
                q++;
            if (q >= n)
                break;
            unsigned long v = 0, d = 0;
            while (q < n && s[q] >= '0' && s[q] <= '9' && v <= 255) {
                v = v * 10 + (unsigned long)(s[q++] - '0');
                d++;
            }
            if (d == 0 || v > 255 || (q < n && !is_ws(s[q])) || nfake == MAX_FAKE) {
                ck_printf("osh_fixture_error: %s.status; %s\n", osh_fx[i].name, LABEL);
                return -1;
            }
            fake[nfake++] = (int)v;
        }
    }
    if (osh_fx[i].args) {
        const unsigned char *s = osh_fx[i].args;
        unsigned long n = osh_fx[i].args_len, q = 0, o = 0;
        if (n >= sizeof pos_buf) {
            ck_printf("osh_fixture_error: %s.args too long; %s\n", osh_fx[i].name, LABEL);
            return -1;
        }
        while (q < n) {
            if (npos == MAX_POS) {
                ck_printf("osh_fixture_error: %s.args has more than %d arguments; %s\n", osh_fx[i].name, MAX_POS, LABEL);
                return -1;
            }
            pos[npos++] = pos_buf + o;
            while (q < n && s[q] != '\n')
                pos_buf[o++] = (char)s[q++];
            pos_buf[o++] = 0;
            q++; /* the newline (or one past the end) */
        }
    }
    return 0;
}

static void answer(void)
{
    uint64_t kind = w[OSH_S_VR_KIND], a = w[OSH_S_VR_A], len = w[OSH_S_VR_LEN];
    const uint8_t *val = NULL;
    uint8_t num[24];
    size_t vl = 0;
    int found = 0;
    switch (kind) {
    case 1: {
        char name[256];
        if (a <= blen && len < sizeof name && len <= blen - a) {
            memcpy(name, in_buf + a, (size_t)len);
            name[len] = 0;
            const char *v = var_get(name);
            if (v) {
                found = 1;
                val = (const uint8_t *)v;
                vl = strlen(v);
            }
        }
        break;
    }
    case 2:
        found = 1;
        vl = dec((uint64_t)(unsigned)last_status, num);
        val = num;
        break;
    case 3: /* as osh_shell.c answer() */
        if (a == 0) {
            found = 1;
            val = (const uint8_t *)ARG0;
            vl = strlen(ARG0);
        } else if (a >= 1 && a <= (uint64_t)npos) {
            found = 1;
            val = (const uint8_t *)pos[a - 1];
            vl = strlen(pos[a - 1]);
        }
        break;
    case 4:
        found = 1;
        vl = dec((uint64_t)npos, num);
        val = num;
        break;
    default:
        break;
    }
    w[OSH_STAGING + 0] = (uint64_t)found;
    w[OSH_STAGING + 1] = vl;
    w[OSH_STAGING + 2] = (uint64_t)npos;
    w[OSH_STAGING + 3] = 0;
    for (size_t i = 0; i < vl && i < 1024; i++)
        w[OSH_STAGING + 4 + i] = val[i];
}

/* returns 1 when the driver must stop */
static int run_list(void)
{
    w[OSH_S_LAST_STATUS] = (uint64_t)(unsigned)last_status;
    for (int guard = 0; guard < 1000000; guard++) {
        uint64_t st = call(U_EXPAND);
        if (stop)
            return 1;
        switch (st) {
        case ST_BUDGET:
            continue;
        case ST_NEED_VAR:
            answer();
            continue;
        case ST_PIPE: {
            uint64_t nc = w[OSH_REQUEST + 1];
            if (nc > (OSH_OUT - OSH_REQUEST - REQ_HDR_CELLS) / CMD_CELLS) { /* never read past REQUEST */
                ck_printf("event request_ncmds_out_of_range ncmds=%llu\n", (unsigned long long)nc);
                last_status = 2;
                return 1;
            }
            size_t cells = (size_t)(REQ_HDR_CELLS + nc * CMD_CELLS);
            char h[65];
            hex((const uint8_t *)(w + OSH_REQUEST), cells * 8, h);
            ck_printf("request %lu sha256=%s\n", ++req_no, h);
            last_status = next_fake(); /* nothing ran: the fixture's next status */
            if (exhausted)
                return 1;
            w[OSH_S_LAST_STATUS] = (uint64_t)(unsigned)last_status;
            continue;
        }
        case ST_COMPLETE:
            return 0;
        default: /* as osh_shell.c: a refusal stops a non-interactive shell with 2, a unit fault status with 70 */
            if (st == ~(uint64_t)0 || st < 200) {
                ck_printf("event internal_error status=%llu\n", (unsigned long long)st);
                last_status = 70;
                return 1;
            }
            last_status = 2;
            return 1;
        }
    }
    return 1;
}

static int run_src(void)
{
    for (;;) {
        reset_list();
        uint64_t st;
        int eof = 0;
        for (;;) {
            int r = read_line();
            if (r < 0) {
                last_status = 2;
                return 2;
            }
            if (r == 0) {
                eof = 1;
                if (blen == 0)
                    return 0;
                w[OSH_S_EOI] = 1;
            }
            st = lex_parse();
            if (stop)
                return 3;
            if (st == 0 && w[OSH_PX_STATE] != 4)
                st = eof ? ST_COMPLETE : ST_MORE;
            if (st == ST_MORE && !eof)
                continue;
            break;
        }
        if (st == ST_COMPLETE) {
        } else if (st == 0) {
            if (run_list())
                return 1;
        } else {
            last_status = 2; /* lexer or parser refusal */
            return 2;
        }
        if (eof)
            return 0;
    }
}

static void neg_line(const char *tag, const char *what, const struct osc_result *r, const struct ck_osc_launch_info *info, const char *extra)
{
    char rs[96];
    ck_osc_result_str(r, rs, sizeof rs);
    ck_printf("osh_neg%s: %s -> %s ticks=%llu budget=%llu pages_mapped=%u page_tables_zeroed=%u slot_free=%u%s%s; %s\n", tag, what,
              rs, (unsigned long long)r->ticks, (unsigned long long)info->budget, info->pages_mapped, (unsigned)info->tables_zeroed,
              (unsigned)info->slot_free_after, extra[0] ? " " : "", extra, LABEL);
}

/* the longest fixture, used by control 4 */
static unsigned long_fx;

static void negatives(void)
{
    struct osc_result r;
    struct ck_osc_launch_info info;
    char h0[65], h1[65], x[160];

    /* 1: 22 pages, pointer range claiming 11456 cells -> refused 41 before the first instruction */
    reset_list();
    memcpy(in_buf, "echo hi\n", 8);
    struct ck_osc_ws ws22 = { ws_mem, WS_PAGES - 1 };
    launch(U_LEX, 8, CKOSH_WS_CELLS, &ws22, 0, &r, &info);
    neg_line("1", "lex_run(in+0,8,ws+0,11456) with a 22-page workspace", &r, &info, "");

    /* 2a: workspace passed with len 512 cells (23 pages mapped): emit_tok with t=127 would store at cell 572 */
    reset_list();
    w[17] = 127;
    hex(ws_mem + 512 * 8, sizeof ws_mem - 512 * 8, h0); /* every cell from 512 up */
    struct ck_osc_launch_req rq;
    memset(&rq, 0, sizeof rq);
    rq.name = "emit_tok";
    rq.name_len = 8;
    rq.nargs = 6;
    rq.args[0] = ck_osc_va_ws();
    rq.args[1] = 512; /* cells: len 512, far smaller than the unit needs */
    rq.args[2] = 0x1111;
    rq.args[3] = 0x2222;
    rq.args[4] = 0x3333;
    rq.args[5] = 0x4444;
    rq.ws = &main_ws;
    ck_osc_launch(unit[U_LEX].bytes, unit[U_LEX].len, &unit[U_LEX].acc, &rq, &r, &info);
    hex(ws_mem + 512 * 8, sizeof ws_mem - 512 * 8, h1);
    ck_snprintf(x, sizeof x, "cell17=%llu cells_512_up_unchanged=%u", (unsigned long long)w[17], (unsigned)streq(h0, h1));
    neg_line("2a", "lex emit_tok(ws+0,len 512 cells,..) with w[17]=127", &r, &info, x);

    /* 2b: the entry point with len 512: the unit's own ABI check refuses (WORKSPACE_SIZE 213), no write past 512 */
    reset_list();
    hex(ws_mem + 512 * 8, sizeof ws_mem - 512 * 8, h0);
    memcpy(in_buf, "echo hi\n", 8);
    launch(U_LEX, 8, 512, &main_ws, 0, &r, &info);
    hex(ws_mem + 512 * 8, sizeof ws_mem - 512 * 8, h1);
    ck_snprintf(x, sizeof x, "cells_512_up_unchanged=%u", (unsigned)streq(h0, h1));
    neg_line("2b", "lex_run(in+0,8,ws+0,512) with a 23-page workspace", &r, &info, x);

    /* 3: a unit with one flipped code byte is refused at admission by the Store stage; here: nothing of it can run */
    int ran = 0;
    for (unsigned u = 0; u < U_COUNT; u++)
        if (streq(u_file[u], "osh_lex_flipped.unit") && unit[u].have)
            ran = 1;
    ck_printf("osh_neg3: osh_lex_flipped.unit -> NOT_RUN (unit was not admitted)%s; %s\n", ran ? " BUG" : "", LABEL);

    /* 4: caller max_ticks 1 on the longest fixture */
    reset_list();
    src_text = osh_fx[long_fx].text;
    src_len = osh_fx[long_fx].len;
    src_pos = 0;
    blen = 0;
    {
        /* the whole fixture as one list buffer (it fits the window) */
        unsigned long n = src_len < INPUT_MAX ? src_len : INPUT_MAX - 1;
        memcpy(in_buf, src_text, n);
        in_buf[n++] = '\n';
        blen = n;
    }
    w[OSH_S_EOI] = 1;
    launch(U_LEX, blen, CKOSH_WS_CELLS, &main_ws, 1, &r, &info);
    ck_snprintf(x, sizeof x, "fixture=%s in_len=%u max_ticks=1", osh_fx[long_fx].name, (unsigned)blen);
    neg_line("4a", "lex_run over the long fixture", &r, &info, x);
    /* 4b: the shell units are loop-bounded (every loop has a bound, every entry call a step budget), so no single call of
     * theirs lasts a whole 10 ms tick under QEMU TCG: 4a returns inside the tick. The same cap through the same launch
     * path, on the launch gate's spin() unit, shows the budget bites. */
    if (spin_unit.have) {
        memset(&rq, 0, sizeof rq);
        rq.name = "spin";
        rq.name_len = 4;
        rq.max_ticks = 1;
        ck_osc_launch(spin_unit.bytes, spin_unit.len, &spin_unit.acc, &rq, &r, &info);
        neg_line("4b", "l01 spin() with the same max_ticks=1 cap", &r, &info, "");
    } else {
        ck_printf("osh_neg4b: NOT_RUN (l01_launch_fns.unit was not admitted); %s\n", LABEL);
    }
    /* and the next launch works */
    reset_list();
    memcpy(in_buf, "echo hi\n", 8);
    w[OSH_S_EOI] = 1;
    launch(U_LEX, 8, CKOSH_WS_CELLS, &main_ws, 0, &r, &info);
    neg_line("4n", "after the overrun, lex_run(in+0,8) on the same workspace", &r, &info, "");
}

void ck_osh_all(void)
{
    unsigned have = 0;
    for (unsigned u = 0; u < U_COUNT; u++)
        have += (unsigned)unit[u].have;
    ck_printf("osh_core: units=%u ws_cells=%u ws_pages=%u input_max=%u; %s\n", have, CKOSH_WS_CELLS, WS_PAGES, INPUT_MAX, LABEL);
    if (have != U_COUNT) {
        ck_printf("osh_core: NOT_RUN (a shell unit was not admitted); %s\n", LABEL);
        return;
    }
    unsigned nfx = (unsigned)(sizeof osh_fx / sizeof osh_fx[0]);
    unsigned long best = 0;
    for (unsigned i = 0; i < nfx; i++) {
        if (osh_fx[i].len > best && osh_fx[i].len <= INPUT_MAX) {
            best = osh_fx[i].len;
            long_fx = i;
        }
        stop = 0;
        step_no = 0;
        req_no = 0;
        src_text = osh_fx[i].text;
        src_len = osh_fx[i].len;
        src_pos = 0;
        ck_printf("osh_script_begin %s\n", osh_fx[i].name);
        int rc = load_fixture(i) != 0 ? 4 : run_src();
        /* omega's osh_trace ends every trace with the exit line, except after fake_status_exhausted (it exits 2 there);
         * after a launch that did not RETURN (stop) the trace is incomplete and the gate's diff fails it */
        if (rc != 4 && !stop && !exhausted)
            ck_printf("event exit=%d\n", last_status);
        ck_printf("osh_script_end %s rc=%d\n", osh_fx[i].name, rc);
    }
    negatives();
    ck_printf("osh_core_done: scripts=%u; %s\n", nfx, LABEL);
}
