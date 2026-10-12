/* line_rx.h -- the operator line assembler of the service lifecycle: one
 * bounded state machine fed byte by byte from the POLLED console receive
 * (core/console.c, core/uart_rx.h). Pure logic (no kernel calls, no libc):
 * the host test tests/test_console_rx.c compiles it as is; core/lifecycle.c
 * uses it for the main prompt and for the cancel poll between generation
 * steps, so both follow the same rules.
 *
 * Rules (feed one byte, or CK_LINE_RX_ERR for a byte the UART dropped):
 *   - printable ASCII 0x20..0x7e is collected, up to CK_LC_LINE_MAX bytes;
 *   - Backspace (0x08) or DEL (0x7f) removes the last byte;
 *   - CR or LF ends the line (a CR LF pair gives one line and one empty line);
 *   - any other control byte is dropped and counted;
 *   - a line past CK_LC_LINE_MAX is refused whole at its Enter (OVERLONG),
 *     the rest of it is dropped until then;
 *   - a line during which the UART reported a lost or damaged byte is
 *     refused whole at its Enter (DAMAGED): a command with a missing byte
 *     never runs. If the lost byte was the Enter itself, the next line is
 *     joined to the damaged one and refused with it (safe side). */
#ifndef AIENOS_CK_LINE_RX_H
#define AIENOS_CK_LINE_RX_H

#include <stddef.h>
#include <stdint.h>
#include "lifecycle_fsm.h"

#define CK_LINE_RX_ERR (-2)  /* same value as ck_console_rx_poll's error result */
#define CK_LINE_RX_EMPTY (-1)
/* Bytes taken per poll call at most, so a UART that never runs dry (a stuck
 * data-ready bit) cannot hold the lifecycle in one call. */
#define CK_LINE_RX_BURST 256u

enum ck_line_ev {
    CK_LINE_NONE = 0, /* nothing to show */
    CK_LINE_ECHO,     /* one byte appended: buf[len - 1] */
    CK_LINE_ERASE,    /* one byte removed */
    CK_LINE_DONE,     /* buf[0..len) is a complete line, NUL-terminated */
    CK_LINE_OVERLONG, /* the line ended and is refused: longer than CK_LC_LINE_MAX */
    CK_LINE_DAMAGED,  /* the line ended and is refused: a byte was lost or damaged */
};

struct ck_line_rx {
    char buf[CK_LC_LINE_MAX + 1];
    size_t len;
    uint8_t overflow, damaged, done;
    unsigned overlong;     /* lines refused for length */
    unsigned damaged_lines; /* lines refused for a receive error */
    unsigned dropped;      /* control bytes dropped */
};

void ck_line_rx_init(struct ck_line_rx *l);
enum ck_line_ev ck_line_rx_feed(struct ck_line_rx *l, int b);

/* The cancel check between generation steps: drains at most
 * CK_LINE_RX_BURST bytes from poll() (no echo) and returns 1 as soon as a
 * complete line decodes to `cancel`, 0 when the input ran dry or the burst
 * ended. Every other complete line (a verb other than cancel, an overlong or
 * damaged line) is refused: refuse(verb, reason) is called and the line is
 * never run. Empty lines are ignored. A partial line stays in l for the
 * next call. */
int ck_line_rx_cancel_poll(struct ck_line_rx *l, int (*poll)(void), void (*refuse)(enum ck_lc_verb v, const char *reason));

#endif
