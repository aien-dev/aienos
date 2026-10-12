/* test_console_rx.c -- the service lifecycle's operator input on the host:
 * SPCR -> console UART selection (the DGX Spark's exact SPCR bytes), the
 * POLLED 16550 and PL011 receive decode (core/uart_rx.h) on a simulated
 * register file (byte, empty, overrun, parity, framing, break, not ready,
 * nothing answering), the line assembler (core/line_rx.c: assembly, erase,
 * overlong and damaged lines refused whole), and cancel arriving in the
 * middle of a multi-step run (ck_line_rx_cancel_poll, the function
 * core/lifecycle.c calls between generation steps). */
#include <string.h>
#include "ck_test.h"
#include "acpi.h"
#include "uart_rx.h"
#include "line_rx.h"

/* /sys/firmware/acpi/tables/SPCR read on the DGX Spark, 2026-10-12 (80
 * bytes, revision 2, ALASKA/AMI): type 0x01 at byte 36, GAS memory/32-bit/
 * dword at 0x16A00000. */
static const uint8_t spark_spcr[80] = {
    0x53, 0x50, 0x43, 0x52, 0x50, 0x00, 0x00, 0x00, 0x02, 0x53, 0x41, 0x4c, 0x41, 0x53, 0x4b, 0x41,
    0x41, 0x20, 0x4d, 0x20, 0x49, 0x20, 0x00, 0x00, 0x21, 0x02, 0x13, 0x20, 0x41, 0x4d, 0x49, 0x20,
    0x99, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x03, 0x00, 0x00, 0xa0, 0x16,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x6e, 0x03, 0x00, 0x00, 0x07, 0x00, 0x01, 0x00, 0x02, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* A 16550 with dword-spaced registers (stride 4), and one with byte registers. */
static uint32_t u4[8];
static uint8_t u1[8];
#define U4 ((volatile uint8_t *)u4)
#define U1 ((volatile uint8_t *)u1)
/* A PL011 (UARTDR 0x00, UARTFR 0x18, UARTCR 0x30). */
static uint32_t pl[0x40 / 4];
#define PL ((volatile uint8_t *)pl)

static enum ck_line_ev feed_s(struct ck_line_rx *l, const char *s)
{
    enum ck_line_ev ev = CK_LINE_NONE;
    for (; *s; s++) ev = ck_line_rx_feed(l, *s == '#' ? CK_LINE_RX_ERR : (uint8_t)*s);
    return ev;
}

/* Bytes arriving through the simulated 16550: each byte is placed in RBR
 * with its LSR flags, then taken by the real decode. */
struct wire { uint8_t lsr; uint8_t byte; };
static const struct wire *g_wire;
static size_t g_wire_n, g_wire_pos;
static struct ck_uart_rx_count g_wire_count;
static int wire_poll(void)
{
    if (g_wire_pos == g_wire_n) { u4[CK_16550_LSR] = 0x60; return ck_uart_rx_take(CK_UART_16550, U4, 4, &g_wire_count); }
    u4[CK_16550_LSR] = g_wire[g_wire_pos].lsr;
    u4[CK_16550_RBR] = g_wire[g_wire_pos].byte;
    g_wire_pos++;
    return ck_uart_rx_take(CK_UART_16550, U4, 4, &g_wire_count);
}

/* A multi-step run (stands in for ck_infer_prompt's generation loop): at
 * step i the bytes script[i] become readable ('#' = a byte the UART lost),
 * then the cancel poll runs, as lifecycle.c's cancel_poll does between steps. */
static const char *const *g_script;
static size_t g_pos;
static int g_step;
static unsigned g_polls;
static int script_poll(void)
{
    g_polls++;
    const char *s = g_script[g_step];
    if (!s || !s[g_pos]) return CK_LINE_RX_EMPTY;
    char c = s[g_pos++];
    return c == '#' ? CK_LINE_RX_ERR : (uint8_t)c;
}
static unsigned g_refused, g_refused_invalid;
static enum ck_lc_verb g_last_refused;
static void refuse(enum ck_lc_verb v, const char *reason)
{
    (void)reason;
    g_refused++;
    if (v == CK_LC_V_INVALID) g_refused_invalid++;
    g_last_refused = v;
}
/* Runs up to `steps` steps; returns the step at which cancel stopped it, or 0. */
static int run(const char *const *script, int steps, struct ck_line_rx *l)
{
    g_script = script;
    g_refused = g_refused_invalid = 0;
    g_last_refused = CK_LC_V_UNKNOWN;
    ck_line_rx_init(l);
    for (g_step = 0; g_step < steps; g_step++) {
        g_pos = 0;
        if (ck_line_rx_cancel_poll(l, script_poll, refuse)) return g_step + 1;
    }
    return 0;
}
static int g_always_a(void) { g_polls++; return 'a'; }

int main(void)
{
    int kind = -9;
    unsigned stride = 0;

    /* ---- SPCR -> console UART (the same table the transmit side uses) ---- */
    struct ck_spcr s;
    CHECK(ck_spcr_parse(spark_spcr, &s) == 0);
    CHECK(s.interface_type == 0x01 && s.space == 0 && s.bit_width == 32 && s.access_size == 3 && s.base == 0x16A00000ull);
    CHECK(ck_uart_from_spcr(s.interface_type, s.access_size, &kind, &stride) == 0 && kind == CK_UART_16550 && stride == 4);
    CHECK(ck_uart_from_spcr(0x03, 3, &kind, &stride) == 0 && kind == CK_UART_PL011 && stride == 4);
    CHECK(ck_uart_from_spcr(0x0e, 3, &kind, &stride) == 0 && kind == CK_UART_PL011);
    CHECK(ck_uart_from_spcr(0x00, 1, &kind, &stride) == 0 && kind == CK_UART_16550 && stride == 1);
    CHECK(ck_uart_from_spcr(0x12, 4, &kind, &stride) == 0 && kind == CK_UART_16550 && stride == 8);
    kind = -9;
    CHECK(ck_uart_from_spcr(0x05, 3, &kind, &stride) == -1 && kind == -9); /* NVIDIA 16550 variant: not claimed */
    CHECK(ck_uart_from_spcr(0x0f, 3, &kind, &stride) == -1);               /* Arm DCC */
    CHECK(ck_uart_from_spcr(0x02, 3, &kind, &stride) == -1);               /* MAX311x SPI */

    /* ---- 16550 readiness (stride 4: dword registers, low byte meaningful) ---- */
    uint32_t regs = 0;
    u4[CK_16550_LCR] = 0x03; /* 8N1, DLAB clear */
    u4[CK_16550_LSR] = 0x60; /* THRE + TEMT, nothing received */
    CHECK(ck_uart_rx_ready(CK_UART_16550, U4, 4, &regs) == 1 && regs == 0x0360);
    u4[CK_16550_LCR] = 0x83; /* DLAB set: offset 0 is the divisor latch */
    CHECK(ck_uart_rx_ready(CK_UART_16550, U4, 4, &regs) == 0 && regs == 0x8360);
    u4[CK_16550_LCR] = 0x03;
    u4[CK_16550_LSR] = 0xffffffffu; /* nothing answering at the address */
    CHECK(ck_uart_rx_ready(CK_UART_16550, U4, 4, &regs) == 0);
    CHECK(ck_uart_rx_ready(CK_UART_16550, 0, 4, &regs) == 0);
    CHECK(ck_uart_rx_ready(CK_UART_NONE, U4, 4, &regs) == 0);

    /* ---- 16550 receive decode ---- */
    struct ck_uart_rx_count c = {0, 0};
    u4[CK_16550_LSR] = 0x60;
    CHECK(ck_uart_rx_take(CK_UART_16550, U4, 4, &c) == CK_UART_RX_EMPTY);
    u4[CK_16550_LSR] = 0x61; u4[CK_16550_RBR] = 0xabcd0041u; /* only the low byte is data */
    CHECK(ck_uart_rx_take(CK_UART_16550, U4, 4, &c) == 'A' && c.errors == 0);
    u4[CK_16550_LSR] = 0x63; /* DR + OE: an earlier byte was lost */
    CHECK(ck_uart_rx_take(CK_UART_16550, U4, 4, &c) == CK_UART_RX_ERROR && c.errors == 1 && c.overruns == 1);
    u4[CK_16550_LSR] = 0x62; /* OE with nothing waiting */
    CHECK(ck_uart_rx_take(CK_UART_16550, U4, 4, &c) == CK_UART_RX_ERROR && c.errors == 2 && c.overruns == 2);
    u4[CK_16550_LSR] = 0x65; /* parity */
    CHECK(ck_uart_rx_take(CK_UART_16550, U4, 4, &c) == CK_UART_RX_ERROR && c.errors == 3 && c.overruns == 2);
    u4[CK_16550_LSR] = 0x69; /* framing */
    CHECK(ck_uart_rx_take(CK_UART_16550, U4, 4, &c) == CK_UART_RX_ERROR && c.errors == 4);
    u4[CK_16550_LSR] = 0x71; /* break */
    CHECK(ck_uart_rx_take(CK_UART_16550, U4, 4, &c) == CK_UART_RX_ERROR && c.errors == 5 && c.overruns == 2);
    u4[CK_16550_LSR] = 0xffffffffu; /* floating bus: never a stream of 0xff bytes */
    CHECK(ck_uart_rx_take(CK_UART_16550, U4, 4, &c) == CK_UART_RX_EMPTY && c.errors == 5);
    /* byte-spaced 16550 (stride 1) */
    u1[CK_16550_LCR] = 0x03; u1[CK_16550_LSR] = 0x61; u1[CK_16550_RBR] = 'z';
    CHECK(ck_uart_rx_ready(CK_UART_16550, U1, 1, &regs) == 1 && regs == 0x0361);
    CHECK(ck_uart_rx_take(CK_UART_16550, U1, 1, &c) == 'z');
    u1[CK_16550_LSR] = 0x60;
    CHECK(ck_uart_rx_take(CK_UART_16550, U1, 1, &c) == CK_UART_RX_EMPTY);

    /* ---- PL011 (QEMU virt) readiness and decode ---- */
    pl[CK_PL011_CR / 4] = 0x301; /* UARTEN + TXE + RXE */
    CHECK(ck_uart_rx_ready(CK_UART_PL011, PL, 4, &regs) == 1 && regs == 0x301);
    pl[CK_PL011_CR / 4] = 0x101; /* receiver off */
    CHECK(ck_uart_rx_ready(CK_UART_PL011, PL, 4, &regs) == 0);
    struct ck_uart_rx_count pc = {0, 0};
    pl[CK_PL011_FR / 4] = CK_PL011_FR_RXFE;
    CHECK(ck_uart_rx_take(CK_UART_PL011, PL, 4, &pc) == CK_UART_RX_EMPTY);
    pl[CK_PL011_FR / 4] = 0; pl[CK_PL011_DR / 4] = 0x41;
    CHECK(ck_uart_rx_take(CK_UART_PL011, PL, 4, &pc) == 'A');
    pl[CK_PL011_DR / 4] = 0x841; /* OE */
    CHECK(ck_uart_rx_take(CK_UART_PL011, PL, 4, &pc) == CK_UART_RX_ERROR && pc.errors == 1 && pc.overruns == 1);
    pl[CK_PL011_DR / 4] = 0x141; /* FE */
    CHECK(ck_uart_rx_take(CK_UART_PL011, PL, 4, &pc) == CK_UART_RX_ERROR && pc.errors == 2 && pc.overruns == 1);
    pl[CK_PL011_DR / 4] = 0x441; /* BE */
    CHECK(ck_uart_rx_take(CK_UART_PL011, PL, 4, &pc) == CK_UART_RX_ERROR && pc.errors == 3);
    CHECK(ck_uart_rx_take(CK_UART_NONE, PL, 4, &pc) == CK_UART_RX_EMPTY);

    /* ---- line assembly ---- */
    static struct ck_line_rx l;
    ck_line_rx_init(&l);
    CHECK(ck_line_rx_feed(&l, 's') == CK_LINE_ECHO && l.len == 1 && l.buf[0] == 's');
    CHECK(feed_s(&l, "tatus\r") == CK_LINE_DONE && l.len == 6 && strcmp(l.buf, "status") == 0);
    CHECK(ck_line_rx_feed(&l, '\n') == CK_LINE_DONE && l.len == 0); /* CR LF: one line, one empty line */
    CHECK(feed_s(&l, "sxy") == CK_LINE_ECHO && ck_line_rx_feed(&l, 0x7f) == CK_LINE_ERASE && ck_line_rx_feed(&l, 0x08) == CK_LINE_ERASE);
    CHECK(feed_s(&l, "tatus\n") == CK_LINE_DONE && strcmp(l.buf, "status") == 0);
    CHECK(ck_line_rx_feed(&l, 0x7f) == CK_LINE_NONE && l.len == 0); /* erase on an empty line */
    CHECK(ck_line_rx_feed(&l, 0x01) == CK_LINE_NONE && ck_line_rx_feed(&l, 0x1b) == CK_LINE_NONE && ck_line_rx_feed(&l, 0x80) == CK_LINE_NONE && l.dropped == 3 && l.len == 0);
    CHECK(feed_s(&l, "help\r") == CK_LINE_DONE && strcmp(l.buf, "help") == 0);
    {
        char line[CK_LC_LINE_MAX + 2];
        memset(line, 'a', sizeof line);
        line[CK_LC_LINE_MAX] = '\r'; line[CK_LC_LINE_MAX + 1] = 0; /* exactly the limit */
        CHECK(feed_s(&l, line) == CK_LINE_DONE && l.len == CK_LC_LINE_MAX && l.overlong == 0);
        line[CK_LC_LINE_MAX] = 'a'; line[CK_LC_LINE_MAX + 1] = 0; /* limit + 1 */
        CHECK(feed_s(&l, line) == CK_LINE_NONE && l.overflow == 1);
        CHECK(ck_line_rx_feed(&l, 0x7f) == CK_LINE_NONE);           /* erasing cannot rescue it */
        CHECK(ck_line_rx_feed(&l, '\r') == CK_LINE_OVERLONG && l.overlong == 1 && l.len == 0);
        CHECK(feed_s(&l, "status\r") == CK_LINE_DONE && strcmp(l.buf, "status") == 0); /* next line is clean */
    }
    /* damaged: a lost byte anywhere refuses the whole line */
    CHECK(feed_s(&l, "shut#down\r") == CK_LINE_DAMAGED && l.damaged_lines == 1 && l.len == 0);
    CHECK(feed_s(&l, "status\r") == CK_LINE_DONE && strcmp(l.buf, "status") == 0);
    /* the lost byte was the Enter: the next line is joined and refused with it */
    CHECK(feed_s(&l, "statu#shutdown\r") == CK_LINE_DAMAGED && l.damaged_lines == 2);
    CHECK(feed_s(&l, "#\r") == CK_LINE_DAMAGED && l.damaged_lines == 3);

    /* ---- the same through the simulated 16550: an overrun mid-line ---- */
    {
        static const struct wire w[] = {
            { 0x61, 's' }, { 0x61, 't' }, { 0x63, 'o' } /* OE: a byte lost before 'o' */, { 0x61, 'p' }, { 0x61, '\r' },
            { 0x61, 'h' }, { 0x61, 'e' }, { 0x61, 'l' }, { 0x61, 'p' }, { 0x61, '\r' },
        };
        g_wire = w; g_wire_n = sizeof w / sizeof w[0]; g_wire_pos = 0;
        g_wire_count.errors = g_wire_count.overruns = 0;
        ck_line_rx_init(&l);
        enum ck_line_ev ev[16];
        int n = 0, b;
        while ((b = wire_poll()) != CK_UART_RX_EMPTY && n < 16) ev[n++] = ck_line_rx_feed(&l, b);
        CHECK(n == 10 && ev[4] == CK_LINE_DAMAGED && ev[9] == CK_LINE_DONE && strcmp(l.buf, "help") == 0);
        CHECK(g_wire_count.errors == 1 && g_wire_count.overruns == 1 && l.damaged_lines == 1);
    }

    /* ---- cancel during a multi-step run ---- */
    static struct ck_line_rx g;
    {
        /* "cancel" split over steps 3 and 5: the run stops at step 5, not earlier, not later */
        static const char *const sc[9] = { "", "", "can", "", "cel\r", "", "", "", 0 };
        CHECK(run(sc, 8, &g) == 5 && g_refused == 0);
    }
    {
        /* another verb during the run is refused, never run, and the run goes on */
        static const char *const sc[9] = { "sta", "tus\r", "", "shutdown\r", "", "", "", "", 0 };
        CHECK(run(sc, 8, &g) == 0 && g_refused == 2 && g_last_refused == CK_LC_V_SHUTDOWN && g_refused_invalid == 0);
    }
    {
        /* a damaged "cancel" is refused (type it again); the retyped one cancels */
        static const char *const sc[9] = { "can#cel\r", "", "cancel\r", "", "", "", "", "", 0 };
        CHECK(run(sc, 8, &g) == 3 && g_refused == 1 && g_refused_invalid == 1 && g.damaged_lines == 1);
    }
    {
        /* an overlong line that starts with "cancel" is refused whole, not truncated into a cancel */
        static char longc[CK_LC_LINE_MAX + 16];
        memset(longc, 'x', sizeof longc);
        memcpy(longc, "cancel ", 7);
        longc[CK_LC_LINE_MAX + 14] = '\r'; longc[CK_LC_LINE_MAX + 15] = 0;
        static const char *sc[9] = { 0, "", "", "", "", "", "", "", 0 };
        sc[0] = longc;
        CHECK(run(sc, 8, &g) == 0 && g_refused == 1 && g_refused_invalid == 1 && g.overlong == 1);
    }
    {
        /* empty lines and a CR LF pair are ignored; "  cancel  " with spaces cancels at once */
        static const char *const sc[9] = { "\r\n\r\n", "  cancel  \r\n", "", "", "", "", "", "", 0 };
        CHECK(run(sc, 8, &g) == 2 && g_refused == 0);
    }
    {
        /* nothing typed: every step runs */
        static const char *const sc[9] = { "", "", "", "", "", "", "", "", 0 };
        CHECK(run(sc, 8, &g) == 0 && g_refused == 0);
    }
    /* bounded: a UART that never runs dry cannot hold one poll call */
    ck_line_rx_init(&g);
    g_polls = 0;
    CHECK(ck_line_rx_cancel_poll(&g, g_always_a, refuse) == 0 && g_polls == CK_LINE_RX_BURST && g.overflow == 1);

    return ck_t_verdict("CK_CONSOLE_RX");
}
