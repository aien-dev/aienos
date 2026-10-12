/* line_rx.c -- operator line assembler (see line_rx.h). Pure logic. */
#include "line_rx.h"

void ck_line_rx_init(struct ck_line_rx *l)
{
    l->len = 0;
    l->overflow = l->damaged = l->done = 0;
    l->buf[0] = 0;
    l->overlong = l->damaged_lines = l->dropped = 0;
}

static void clear(struct ck_line_rx *l)
{
    l->len = 0;
    l->overflow = l->damaged = 0;
    l->buf[0] = 0;
}

enum ck_line_ev ck_line_rx_feed(struct ck_line_rx *l, int b)
{
    if (l->done) { /* the previous call handed out a complete line */
        l->done = 0;
        clear(l);
    }
    if (b == CK_LINE_RX_ERR) {
        l->damaged = 1;
        return CK_LINE_NONE;
    }
    if (b < 0 || b > 0xff)
        return CK_LINE_NONE;
    char c = (char)b;
    if (c == '\r' || c == '\n') {
        if (l->overflow) {
            l->overlong++;
            clear(l);
            return CK_LINE_OVERLONG;
        }
        if (l->damaged) {
            l->damaged_lines++;
            clear(l);
            return CK_LINE_DAMAGED;
        }
        l->buf[l->len] = 0;
        l->done = 1;
        return CK_LINE_DONE;
    }
    if (c == 0x7f || c == 0x08) {
        if (l->len && !l->overflow) {
            l->len--;
            return CK_LINE_ERASE;
        }
        return CK_LINE_NONE;
    }
    if (b < 0x20 || b > 0x7e) {
        l->dropped++;
        return CK_LINE_NONE;
    }
    if (l->overflow)
        return CK_LINE_NONE;
    if (l->len >= CK_LC_LINE_MAX) {
        l->overflow = 1;
        return CK_LINE_NONE;
    }
    l->buf[l->len++] = c;
    return CK_LINE_ECHO;
}

int ck_line_rx_cancel_poll(struct ck_line_rx *l, int (*poll)(void), void (*refuse)(enum ck_lc_verb v, const char *reason))
{
    for (unsigned n = 0; n < CK_LINE_RX_BURST; n++) {
        int b = poll();
        if (b == CK_LINE_RX_EMPTY)
            return 0;
        switch (ck_line_rx_feed(l, b)) {
        case CK_LINE_DONE: {
            const char *arg;
            size_t arg_len;
            enum ck_lc_verb v = l->len ? ck_lc_decode(l->buf, l->len, &arg, &arg_len) : CK_LC_V_EMPTY;
            if (v == CK_LC_V_CANCEL)
                return 1;
            if (v != CK_LC_V_EMPTY)
                refuse(v, "generating: only cancel is accepted");
            break;
        }
        case CK_LINE_OVERLONG: refuse(CK_LC_V_INVALID, "line longer than the limit"); break;
        case CK_LINE_DAMAGED: refuse(CK_LC_V_INVALID, "receive error in the line (overrun, parity, framing or break): type it again"); break;
        default: break;
        }
    }
    return 0;
}
