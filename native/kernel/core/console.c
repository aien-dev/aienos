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
    if (!s || s->space != 0 || !s->base)
        return -1;
    switch (s->interface_type) {
    case 0x03: /* ARM PL011 */
    case 0x0d: /* ARM SBSA generic UART, 32-bit only */
    case 0x0e: /* ARM SBSA generic UART */
        uart_kind = 1;
        uart_stride = 4;
        break;
    case 0x00: /* 16550 */
    case 0x12: /* 16550 with GAS */
        uart_kind = 2;
        uart_stride = s->access_size == 3 ? 4 : s->access_size == 4 ? 8 : 1;
        break;
    default:
        return -1;
    }
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
        volatile uint8_t *lsr = uart + 5 * uart_stride;
        for (unsigned i = 0; i < 1000000 && !(*lsr & 0x20); i++)
            ;
        if (uart_stride == 4)
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

/* ---- PL011 receive, polled (console session; see include/ck.h) ----
 * Registers (offsets and bits from Linux include/linux/amba/serial.h, the Arm
 * PL011 TRM page being unreadable here; see the docs-read record): UARTDR at
 * 0x00 (DATA bits 7:0, error flags OE/BE/PE/FE bits 11:8), UARTFR at 0x18
 * (RXFE bit 4 = receive FIFO empty), UARTCR at 0x30 (UARTEN bit 0, RXE bit 9).
 * The kernel only READS UARTCR; it never reconfigures the UART. */
static unsigned rx_errs;

int ck_console_rx_ready(uint32_t *cr)
{
    if (uart_kind != 1)
        return 0;
    uint32_t v = *(volatile uint32_t *)(uart + 0x30);
    if (cr)
        *cr = v;
    return (v & 1u) && (v & (1u << 9));
}

int ck_console_rx_poll(void)
{
    if (uart_kind != 1)
        return -1;
    if (*(volatile uint32_t *)(uart + 0x18) & (1u << 4))
        return -1;
    uint32_t d = *(volatile uint32_t *)(uart + 0x00);
    if (d & 0xf00u) {
        rx_errs++;
        return -1;
    }
    return (int)(d & 0xffu);
}

unsigned ck_console_rx_errors(void)
{
    return rx_errs;
}
