/* console_x86.c -- ck_puts/ck_printf for AIENOS-IMAC-KERNEL-0.
 *
 * Three sinks. COM1 (I/O port 0x3f8) only when a 16550 answers there (the
 * scratch register keeps a written value): QEMU has one, the 2017 iMac has
 * none, so nothing is sent there on the iMac. The GOP framebuffer
 * (core/fbcon.c) once the kernel mapped it and called ck_x86_console_fb_on.
 * And a RAM copy of the first CK_X86_LOG_BYTES written, replayed onto the
 * screen when it comes on, so the screen also shows the lines from before
 * ExitBootServices (UEFI ConOut is not used: on a Mac it is invisible unless
 * the firmware is switched to text mode). '\n' goes to COM1 as CR LF. A fault
 * while drawing turns the screen off for good. */
#include "../core/ck_internal.h"
#include "../core/fbcon.h"
#include "x86.h"

#define COM1 0x3f8
#define CK_X86_LOG_BYTES 16384u

static int com1_on;
static struct ck_fbcon fb;
static int fb_on, fb_busy;
static char log_buf[CK_X86_LOG_BYTES];
static size_t log_len;

int ck_x86_com1_probe(void)
{
    ck_outb(COM1 + 7, 0x5a);
    if (ck_inb(COM1 + 7) != 0x5a)
        return com1_on = 0;
    ck_outb(COM1 + 7, 0xa5);
    com1_on = ck_inb(COM1 + 7) == 0xa5;
    return com1_on;
}

static void com1_putc(char c)
{
    /* LSR bit 5: transmit holding register empty. Bounded: never hangs. */
    for (unsigned i = 0; i < 100000 && !(ck_inb(COM1 + 5) & 0x20); i++)
        ck_pause();
    ck_outb(COM1, (uint8_t)c);
}

static void fb_write(const char *s, size_t n)
{
    if (!fb_on)
        return;
    if (fb_busy) {
        fb_on = 0; /* re-entered from a fault inside the drawing: screen off */
        return;
    }
    fb_busy = 1;
    ck_fbcon_write(&fb, s, n);
    fb_busy = 0;
}

static void write_n(const char *s, size_t n)
{
    if (!fb_on) {
        size_t k = n < CK_X86_LOG_BYTES - log_len ? n : CK_X86_LOG_BYTES - log_len;
        memcpy(log_buf + log_len, s, k);
        log_len += k;
    }
    fb_write(s, n);
    if (!com1_on)
        return;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\n')
            com1_putc('\r');
        com1_putc(s[i]);
    }
}

int ck_x86_console_fb_on(volatile void *base, uint32_t width, uint32_t height, uint32_t pitch,
                         uint32_t format, uint32_t *scale, uint32_t *cols, uint32_t *rows)
{
    if (ck_fbcon_setup(&fb, base, width, height, pitch, format) != 0)
        return -1;
    fb_on = 1;
    fb_write(log_buf, log_len);
    *scale = fb.scale;
    *cols = fb.cols;
    *rows = fb.rows;
    return 0;
}

void ck_puts(const char *s)
{
    write_n(s, strlen(s));
}

struct pbuf {
    char b[128];
    size_t n;
};

static void pbuf_emit(void *ctx, char c)
{
    struct pbuf *p = ctx;
    p->b[p->n++] = c;
    if (p->n == sizeof p->b) {
        write_n(p->b, p->n);
        p->n = 0;
    }
}

void ck_vprintf(const char *fmt, va_list ap)
{
    struct pbuf p;
    p.n = 0;
    ck_vformat(pbuf_emit, &p, fmt, ap);
    if (p.n)
        write_n(p.b, p.n);
}

void ck_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ck_vprintf(fmt, ap);
    va_end(ap);
}
