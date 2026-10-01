/* console.c -- ck_puts/ck_printf. Before ExitBootServices the boot stub
 * attaches UEFI ConOut; afterwards output goes to the UART the ACPI SPCR
 * names (PL011/SBSA, or 16550 in MMIO). With neither, output is dropped and
 * the panic path still resets. '\n' is sent as CR LF. */
#include "ck_internal.h"

static void (*efi_write)(const char *s, size_t n);
static volatile uint8_t *uart;
static int uart_kind; /* 0 none, 1 pl011, 2 16550 */
static unsigned uart_stride;
static uint64_t uart_phys;

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
    if (!uart_kind)
        return;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\n')
            uart_putc('\r');
        uart_putc(s[i]);
    }
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
