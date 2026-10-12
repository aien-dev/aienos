/* console.c -- ck_puts/ck_printf. Before ExitBootServices the boot stub
 * attaches UEFI ConOut; afterwards output goes to the UART the ACPI SPCR
 * names (PL011/SBSA, or 16550 in MMIO). With neither, output is dropped and
 * the panic path still resets. '\n' is sent as CR LF.
 * After ExitBootServices every byte the UART gets is also drawn on the GOP
 * framebuffer once the kernel turned it on (ck_console_set_fb, core/fbcon.c);
 * a fault while drawing turns the screen off for good, the UART goes on. */
#include "ck_internal.h"
#include "fbcon.h"
#include "arch.h"
#include "uart_rx.h"

#ifndef CK_FB_HOLD_S
#define CK_FB_HOLD_S 0
#endif

static void (*efi_write)(const char *s, size_t n);
static volatile uint8_t *uart;
static int uart_kind; /* 0 none, 1 pl011, 2 16550 */
static unsigned uart_stride;
static uint64_t uart_phys;
static struct ck_fbcon fb;
static int fb_on, fb_busy;

void ck_console_set_efi(void (*write)(const char *s, size_t n))
{
    efi_write = write;
}

int ck_console_set_uart(const struct ck_spcr *s)
{
    int kind;
    unsigned stride;
    if (!s || s->space != 0 || !s->base)
        return -1;
    if (ck_uart_from_spcr(s->interface_type, s->access_size, &kind, &stride) != 0)
        return -1;
    uart_kind = kind;
    uart_stride = stride;
    uart_phys = s->base;
    uart = (volatile uint8_t *)(uintptr_t)s->base;
    return 0;
}

const char *ck_console_uart_name(void)
{
    return uart_kind == 1 ? "pl011" : uart_kind == 2 ? "16550" : "none";
}

uint64_t ck_console_uart_base(void)
{
    return uart_phys;
}

static void uart_putc(char c)
{
    if (uart_kind == 1) {
        volatile uint32_t *fr = (volatile uint32_t *)(uart + 0x18);
        for (unsigned i = 0; i < 1000000 && (*fr & (1u << 5)); i++)
            ;
        *(volatile uint32_t *)(uart + 0x00) = (uint8_t)c;
    } else if (uart_kind == 2) {
        /* Access width from the SPCR GAS (ck_16550_width): the Spark's 16550
         * is dword-spaced and Linux drives it with 32-bit accesses only. */
        unsigned w = ck_16550_width(uart_stride);
        for (unsigned i = 0; i < 1000000 && !(ck_uart_rd(uart, CK_16550_LSR * uart_stride, w) & 0x20); i++)
            ;
        if (w == 4)
            *(volatile uint32_t *)uart = (uint8_t)c;
        else
            *uart = (uint8_t)c;
    }
}

static void write_n(const char *s, size_t n)
{
    if (efi_write) {
        efi_write(s, n);
        return;
    }
    if (fb_on) {
        if (fb_busy) {
            fb_on = 0; /* re-entered from a fault inside the drawing: screen off */
        } else {
            fb_busy = 1;
            ck_fbcon_write(&fb, s, n);
            fb_busy = 0;
        }
    }
    if (!uart_kind)
        return;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\n')
            uart_putc('\r');
        uart_putc(s[i]);
    }
}

int ck_console_set_fb(volatile void *base, uint32_t width, uint32_t height, uint32_t pitch,
                      uint32_t format)
{
    if (ck_fbcon_setup(&fb, base, width, height, pitch, format) != 0)
        return -1;
    fb_on = 1;
    return 0;
}

int ck_console_fb_info(uint32_t *scale, uint32_t *cols, uint32_t *rows)
{
    if (!fb_on)
        return -1;
    *scale = fb.scale;
    *cols = fb.cols;
    *rows = fb.rows;
    return 0;
}

/* Before a reset: keep the screen readable for CK_FB_HOLD_S seconds (0 in
 * every QEMU build; the hardware staging build sets it so an operator can
 * read or photograph the final report before the machine resets). */
void ck_console_fb_hold(void)
{
    if (!fb_on || CK_FB_HOLD_S <= 0)
        return;
    uint64_t f = ck_rd(cntfrq_el0);
    if (!f)
        return;
    ck_printf("screen: holding %u s before reset\n", (unsigned)CK_FB_HOLD_S);
    uint64_t t0 = ck_rd(cntpct_el0);
    while (ck_rd(cntpct_el0) - t0 < (uint64_t)CK_FB_HOLD_S * f)
        __asm__ volatile("yield");
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

/* ---- console receive, POLLED (operator input; see include/ck.h) ----
 * The receive side uses the UART the transmit side already chose from the
 * ACPI SPCR (ck_console_set_uart): PL011/SBSA (QEMU virt) or 16550 (the DGX
 * Spark, SPCR type 0x01 at 0x16A00000). Register decode, readiness and the
 * error rules live in core/uart_rx.h, shared with the host test. No
 * interrupt is used: the lifecycle polls between its steps. The kernel never
 * writes a UART control register (baud, FIFO, enables stay as the firmware
 * left them). */
static struct ck_uart_rx_count rx_count;

int ck_console_rx_ready(uint32_t *cr)
{
    return ck_uart_rx_ready(uart_kind, uart, uart_stride, cr);
}

int ck_console_rx_poll(void)
{
    if (uart_kind != CK_UART_PL011 && uart_kind != CK_UART_16550)
        return CK_UART_RX_EMPTY;
    return ck_uart_rx_take(uart_kind, uart, uart_stride, &rx_count);
}

unsigned ck_console_rx_errors(void)
{
    return rx_count.errors;
}

unsigned ck_console_rx_overruns(void)
{
    return rx_count.overruns;
}
