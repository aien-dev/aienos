/* test_osc_launch.c -- host tests for the pure parts of OSC unit launch (artifact/osc_launch.c):
 *   - the argument rule (spec 9.2) against vectors/launch.txt, and against the spec's own C reference
 *     tools/osc-launch-check.c (built by the Makefile, path in OSC_LAUNCH_REF) on 3000 pseudo-random
 *     cases that mix interesting values (alignment, wrap, overlap, range edges);
 *   - range ownership (9.1.1 item 4), the ticks budget, and the result classification (9.3, 9.1.1):
 *     RETURNED only from the return stub, TRAPPED only from the trap stub with a code in 1..14, an SVC
 *     from anywhere else and a brk reached directly are OUTCOME_UNKNOWN(FAULT), never TRAPPED, and no
 *     exception class and no trap code 0..255 can produce RETURNED;
 *   - the launch fixture unit l01 admits and its entry table drives the same argument rule. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "osc_launch.h"
#include "osc_unit.h"
#include "osc_unit_test_anchor.h"

#ifndef OSC_FIXTURE_DIR
#define OSC_FIXTURE_DIR "native/kernel/tests/fixtures/osc_unit"
#endif
#ifndef OSC_LAUNCH_REF
#define OSC_LAUNCH_REF "osc-launch-check"
#endif

static int split(char *s, uint64_t *out, int max)
{
    int n = 0;
    for (char *t = strtok(s, ","); t; t = strtok(NULL, ",")) {
        if (n >= max) return -1;
        out[n++] = strtoull(t, NULL, 0);
    }
    return n;
}

/* ours: 1 OK, 0 refused; -1 unparsable */
static int ours(const char *kinds, const char *args)
{
    char a[512], b[512];
    uint64_t k[64], v[64];
    snprintf(a, sizeof a, "%s", kinds);
    snprintf(b, sizeof b, "%s", args);
    int nk = split(a, k, 64), na = split(b, v, 64);
    if (nk < 0 || na < 0) return -1;
    uint8_t kk[64];
    for (int i = 0; i < nk; i++) kk[i] = (uint8_t)k[i];
    return osc_launch_args_ok(kk, (unsigned)nk, v, (unsigned)na);
}

static int reference(const char *kinds, const char *args)
{
    char cmd[1200], out[128];
    snprintf(cmd, sizeof cmd, "%s '%s' '%s'", OSC_LAUNCH_REF, kinds, args);
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    if (!fgets(out, sizeof out, p)) { pclose(p); return -1; }
    pclose(p);
    return strncmp(out, "OK", 2) == 0 ? 1 : strncmp(out, "REFUSED LAUNCH_ARG_SHAPE 41", 27) == 0 ? 0 : -1;
}

static void launch_txt(void)
{
    char path[512], line[512];
    int n = 0;
    snprintf(path, sizeof path, "%s/vectors/launch.txt", OSC_FIXTURE_DIR);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char kinds[128], args[256], verdict[128];
        if (sscanf(line, "%127s %255s %127[^\n]", kinds, args, verdict) != 3) { CHECK(0); continue; }
        int want = strncmp(verdict, "OK", 2) == 0;
        if (!want) CHECK(strcmp(verdict, "REFUSED LAUNCH_ARG_SHAPE 41") == 0);
        CHECK(ours(kinds, args) == want);
        CHECK(reference(kinds, args) == want);
        n++;
    }
    fclose(f);
    CHECK(n == 16);
    printf("  launch.txt: %d lines\n", n);
}

static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
    return rs;
}

static void differential(void)
{
    static const char *const shapes[] = {
        "5,5", "11,5", "12,5", "11,5,11,5", "12,5,11,5", "11,5,12,5", "12,5,12,5", "2,5", "6,5", "1,4", "7,3",
        "8,9", "9", "5", "11,5,5", "12,5,5,5", "11,5,11,5,12,5", "12,5,12,5,12,5", "3,5,11,5", "4,6,12,5",
    };
    static const uint64_t vals[] = {
        0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffffull, 0x100000000ull,
        0xffffffffffffff80ull, 0xffffffffffff8000ull, 0xffffffff80000000ull, 0x1000, 0x1004, 0x1008, 0x1010, 0x1018,
        0x2000, 0x2000000000000000ull, 0x1fffffffffffffffull, 0x8000000000000000ull, 0xfffffffffffffff0ull,
        0xfffffffffffffff8ull, 0xffffffffffffffffull, 0xfffffffffffffff7ull,
    };
    const unsigned nv = sizeof vals / sizeof vals[0];
    int mismatch = 0, ok = 0, ref = 0;
    for (int i = 0; i < 3000; i++) {
        const char *shape = shapes[rnd() % (sizeof shapes / sizeof shapes[0])];
        int regs = 1;
        for (const char *c = shape; *c; c++) regs += *c == ',';
        char args[400];
        size_t at = 0;
        int cnt = regs;
        if (rnd() % 17 == 0) cnt = regs + (rnd() % 2 ? 1 : -1); /* wrong register count now and then */
        if (cnt < 0) cnt = 0;
        args[0] = 0;
        for (int r = 0; r < cnt; r++)
            at += (size_t)snprintf(args + at, sizeof args - at, "%s0x%llx", r ? "," : "", (unsigned long long)vals[rnd() % nv]);
        if (cnt == 0) strcpy(args, "0");
        int a = ours(shape, args), b = reference(shape, args);
        if (a != b) { mismatch++; if (mismatch < 5) printf("  MISMATCH kinds=%s args=%s ours=%d ref=%d\n", shape, args, a, b); }
        a == 1 ? ok++ : ref++;
    }
    CHECK(mismatch == 0);
    CHECK(ok > 200 && ref > 200); /* the sample exercises both verdicts */
    printf("  differential vs the spec's C reference: 3000 cases, %d OK, %d refused, %d mismatches\n", ok, ref, mismatch);
}

static void ownership(void)
{
    const uint8_t kb[2] = { 11, 5 }, kc[2] = { 12, 5 }, kbc[4] = { 11, 5, 12, 5 };
    uint64_t in = 0x200000, ws = 0x210000;
    uint64_t a1[2] = { in, 16 };
    CHECK(osc_launch_ranges_owned(kb, 2, a1, in, 16, ws, 4096));          /* exactly the input window */
    uint64_t a2[2] = { in, 17 };
    CHECK(!osc_launch_ranges_owned(kb, 2, a2, in, 16, ws, 4096));         /* one byte past */
    uint64_t a3[2] = { in + 15, 1 };
    CHECK(osc_launch_ranges_owned(kb, 2, a3, in, 16, ws, 4096));          /* last byte */
    uint64_t a4[2] = { in - 1, 1 };
    CHECK(!osc_launch_ranges_owned(kb, 2, a4, in, 16, ws, 4096));         /* one byte before */
    uint64_t a5[2] = { ws, 2 };
    CHECK(!osc_launch_ranges_owned(kb, 2, a5, in, 16, ws, 4096));         /* bytes in the workspace: not RO */
    uint64_t c1[2] = { ws, 512 };
    CHECK(osc_launch_ranges_owned(kc, 2, c1, in, 16, ws, 4096));          /* 512 cells = 4096 bytes */
    uint64_t c2[2] = { ws, 513 };
    CHECK(!osc_launch_ranges_owned(kc, 2, c2, in, 16, ws, 4096));
    uint64_t c3[2] = { in, 1 };
    CHECK(!osc_launch_ranges_owned(kc, 2, c3, in, 16, ws, 4096));         /* cells in the RO input */
    CHECK(!osc_launch_ranges_owned(kc, 2, c1, in, 16, ws, 0));            /* no workspace given */
    uint64_t c4[2] = { 0, 0 };
    CHECK(osc_launch_ranges_owned(kc, 2, c4, in, 16, ws, 0));             /* zero length, null: never dereferenced */
    uint64_t c5[2] = { ws, 0x2000000000000000ull };
    CHECK(!osc_launch_ranges_owned(kc, 2, c5, in, 16, ws, 4096));         /* n*8 would wrap */
    uint64_t m[4] = { in, 8, ws + 8, 2 };
    CHECK(osc_launch_ranges_owned(kbc, 4, m, in, 16, ws, 4096));
    uint64_t m2[4] = { in, 8, ws + 4088, 2 };
    CHECK(!osc_launch_ranges_owned(kbc, 4, m2, in, 16, ws, 4096));
}

static void budget(void)
{
    CHECK(osc_launch_budget(1000000, 0) == 1000000);   /* no cap: the declared budget */
    CHECK(osc_launch_budget(1000000, 5) == 5);         /* a cap lowers it */
    CHECK(osc_launch_budget(3, 5) == 3);               /* a cap never raises it */
    CHECK(osc_launch_budget(1, 1) == 1);
    CHECK(!osc_launch_budget_expired(0, 5));
    CHECK(!osc_launch_budget_expired(4, 5));
    CHECK(osc_launch_budget_expired(5, 5));
    CHECK(osc_launch_budget_expired(6, 5));
}

#define RT 0x7000002000ull
static uint64_t esr_svc(unsigned imm) { return (0x15ull << 26) | (1ull << 25) | imm; }
static uint64_t esr_ec(uint64_t ec) { return (ec << 26) | (1ull << 25); }

static struct osc_result cls(unsigned kind, uint64_t esr, uint64_t elr, uint64_t x0, uint64_t x1)
{
    struct osc_event e = { kind, esr, elr, x0, x1 };
    struct osc_result r;
    memset(&r, 0xaa, sizeof r);
    osc_launch_classify(&e, RT, &r);
    return r;
}

static uint64_t stub(unsigned i) { return RT + (uint64_t)i * OSC_RT_STUB_BYTES; }

static void classify(void)
{
    struct osc_result r;
    /* RETURNED: only from the return stub, value is x0 */
    r = cls(OSC_EV_SVC, esr_svc(13), stub(13) + 4, 0xfeedfaceull, 99);
    CHECK(r.cls == OSC_RES_RETURNED && r.value == 0xfeedfaceull && r.unknown_reason == 0 && r.trap_code == 0);
    r = cls(OSC_EV_SVC, esr_svc(13), stub(13) + 4, 0, 0);
    CHECK(r.cls == OSC_RES_RETURNED && r.value == 0); /* a void function reports 0 */
    /* TRAPPED: the trap stub with a code in 1..14 */
    for (unsigned c = 1; c <= 14; c++) {
        r = cls(OSC_EV_SVC, esr_svc(OSC_SVC_TRAP), stub(OSC_SVC_TRAP) + 4, 777, c);
        CHECK(r.cls == OSC_RES_TRAPPED && r.trap_code == c && r.unknown_reason == 0);
    }
    /* trap code 0, 15..255 and wide values: OUTCOME_UNKNOWN(TRAP_CODE_UNKNOWN), never TRAPPED */
    for (uint64_t c = 0; c < 256; c++) {
        if (c >= 1 && c <= 14) continue;
        r = cls(OSC_EV_SVC, esr_svc(OSC_SVC_TRAP), stub(OSC_SVC_TRAP) + 4, 0, c);
        CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_TRAP_CODE_UNKNOWN);
    }
    r = cls(OSC_EV_SVC, esr_svc(OSC_SVC_TRAP), stub(OSC_SVC_TRAP) + 4, 0, 0x100000003ull); /* low byte is 3: still not a trap */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_TRAP_CODE_UNKNOWN);
    /* runtime services this cut does not provide */
    for (unsigned i = 0; i < OSC_RT_SERVICES; i++) {
        if (i == OSC_SVC_TRAP) continue;
        r = cls(OSC_EV_SVC, esr_svc(i), stub(i) + 4, 1, 1);
        CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_OTHER);
    }
    /* an SVC from unit context (anywhere but a stub with the matching immediate) is refused as a FAULT */
    r = cls(OSC_EV_SVC, esr_svc(0), 0x7000010004ull, 0, 0);        /* in the unit's code */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT);
    r = cls(OSC_EV_SVC, esr_svc(13), stub(13) + 8, 5, 0);          /* return-stub immediate at the wrong place */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT);
    r = cls(OSC_EV_SVC, esr_svc(2), stub(13) + 4, 5, 3);           /* trap immediate at the return stub */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT);
    r = cls(OSC_EV_SVC, esr_svc(13), stub(13) + 5, 5, 0);          /* misaligned return address */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT);
    r = cls(OSC_EV_SVC, esr_svc(14), stub(14) + 4, 5, 0);          /* one stub past the table */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT);
    r = cls(OSC_EV_SVC, esr_svc(0), RT - 4, 5, 0);                 /* just below stub 0 */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT);
    r = cls(OSC_EV_SVC, esr_svc(13), 2, 5, 0);                     /* tiny elr: no wrap into a stub */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT);
    r = cls(OSC_EV_SVC, esr_ec(0x24) | 13, stub(13) + 4, 5, 0);    /* not an SVC class at all */
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT);
    /* every other synchronous class: never RETURNED, never TRAPPED; known CPU faults are FAULT */
    for (uint64_t ec = 0; ec < 64; ec++) {
        if (ec == 0x15) continue;
        r = cls(OSC_EV_SYNC, esr_ec(ec) | 3, stub(13) + 4, 1, 3);
        CHECK(r.cls == OSC_RES_UNKNOWN);
        int known = ec == 0x00 || ec == 0x07 || ec == 0x0e || ec == 0x18 || ec == 0x20 || ec == 0x22 ||
                    ec == 0x24 || ec == 0x26 || ec == 0x3c;
        CHECK(r.unknown_reason == (known ? OSC_UNK_FAULT : OSC_UNK_OTHER));
    }
    /* a brk (class 0x3c) with an immediate 1..14 reached directly is a fault, never TRAPPED (spec 8.4) */
    for (unsigned imm = 0; imm < 16; imm++) {
        r = cls(OSC_EV_SYNC, esr_ec(0x3c) | imm, 0x7000010000ull, imm, imm);
        CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_FAULT && r.trap_code == 0);
    }
    r = cls(OSC_EV_BUDGET, 0, 0x7000010000ull, 0, 0);
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_TICK_OVERRUN);
    r = cls(OSC_EV_LOST, 0, 0, 0, 0);
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_LAUNCH_LOST);
    r = cls(99, 0, 0, 0, 0);
    CHECK(r.cls == OSC_RES_UNKNOWN && r.unknown_reason == OSC_UNK_OTHER);
    /* the reason is diagnostic: values are the spec's */
    CHECK(OSC_UNK_FAULT == 1 && OSC_UNK_TICK_OVERRUN == 2 && OSC_UNK_LAUNCH_LOST == 3 &&
          OSC_UNK_TRAP_CODE_UNKNOWN == 4 && OSC_UNK_OTHER == 255);
}

static void fixture_unit(void)
{
    char path[512];
    snprintf(path, sizeof path, "%s/launch/l01_launch_fns.unit", OSC_FIXTURE_DIR);
    FILE *f = fopen(path, "rb");
    CHECK(f != NULL);
    if (!f) return;
    static uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    struct osc_policy p;
    memset(&p, 0, sizeof p);
    static const uint8_t (*const ta)[32] = &osc_unit_test1_pk;
    p.test_anchors = ta;
    p.n_test = 1;
    p.unit_formats = OSC_PROFILE_UNIT_FORMATS;
    p.abi_versions = OSC_PROFILE_ABI;
    static struct osc_accept a;
    CHECK(osc_unit_admit(buf, n, &p, &a) == OSC_OK);
    CHECK(a.function_count == 8);
    int fi = osc_unit_lookup(&a, "counter", 7);
    CHECK(fi == 7 && a.entry[fi].nregs == 2 && a.entry[fi].reg_kind[0] == 12 && a.entry[fi].reg_kind[1] == 5);
    uint64_t ok[2] = { 0x210000, 1 }, bad[2] = { 0x210004, 1 };
    CHECK(osc_launch_args_ok(a.entry[fi].reg_kind, a.entry[fi].nregs, ok, 2));
    CHECK(!osc_launch_args_ok(a.entry[fi].reg_kind, a.entry[fi].nregs, bad, 2));
    CHECK(!osc_launch_args_ok(a.entry[fi].reg_kind, a.entry[fi].nregs, ok, 1));
    CHECK(osc_unit_lookup(&a, "Counter", 7) == -1 && osc_unit_lookup(&a, "trap", 4) == 0);
    /* every word of l01 passed the section 8.4 scan inside admission; the spin loop and the bare brk are in it */
    CHECK(a.code_len == 116);
}

static void workspace_bounds(void)
{
    const uint8_t kc[2] = { 12, 5 };
    const uint64_t in = 0x200000, ws = 0x210000;
    CHECK(OSC_WS_MAX_PAGES == 32u);
    CHECK(osc_launch_ws_pages_ok(0) && osc_launch_ws_pages_ok(1) && osc_launch_ws_pages_ok(32));
    CHECK(!osc_launch_ws_pages_ok(33) && !osc_launch_ws_pages_ok(0xffffffffull) && !osc_launch_ws_pages_ok(~0ull));
    for (uint64_t pages = 0; pages <= 33; pages++) {
        uint64_t len = pages * 4096, cells = len / 8;
        uint64_t whole[2] = { ws, cells }, over[2] = { ws, cells + 1 };
        uint64_t last[2] = { ws + len - 8, 1 }, past[2] = { ws + len, 1 };
        uint64_t before[2] = { ws - 8, 1 };
        if (pages == 0) {
            CHECK(!osc_launch_ranges_owned(kc, 2, past, in, 16, ws, 0));   /* no workspace: nothing owned */
            continue;
        }
        CHECK(osc_launch_ranges_owned(kc, 2, whole, in, 16, ws, len));     /* ptr+len ends exactly at the end */
        CHECK(!osc_launch_ranges_owned(kc, 2, over, in, 16, ws, len));     /* one cell too many */
        CHECK(osc_launch_ranges_owned(kc, 2, last, in, 16, ws, len));      /* the last cell */
        CHECK(!osc_launch_ranges_owned(kc, 2, past, in, 16, ws, len));     /* first cell past the end */
        CHECK(!osc_launch_ranges_owned(kc, 2, before, in, 16, ws, len));
    }
}

int main(void)
{
    launch_txt();
    differential();
    ownership();
    workspace_bounds();
    budget();
    classify();
    fixture_unit();
    return ck_t_verdict("test_osc_launch");
}
