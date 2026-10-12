/* uart_rx.h -- polled console UART receive: register decode for the PL011
 * (QEMU virt, SBSA) and the 16550 (the DGX Spark console, SPCR type 0x01 at
 * 0x16A00000). Shared by core/console.c (the real MMIO base) and the host
 * test tests/test_console_rx.c (a simulated register file).
 *
 * POLLING ONLY. Nothing here enables, routes or acknowledges an interrupt,
 * and nothing writes a UART register: the firmware's line settings (baud,
 * word length, FIFO) are used as found. The caller polls between lifecycle
 * steps and between generation steps.
 *
 * Registers (no-write reads only):
 *   PL011 (Linux include/linux/amba/serial.h): UARTDR 0x00 (data bits 7:0,
 *     FE bit 8, PE bit 9, BE bit 10, OE bit 11), UARTFR 0x18 (RXFE bit 4),
 *     UARTCR 0x30 (UARTEN bit 0, RXE bit 9).
 *   16550 (Linux include/uapi/linux/serial_reg.h): RBR 0 (DLAB=0), LCR 3
 *     (DLAB bit 7), LSR 5 (DR 0x01, OE 0x02, PE 0x04, FE 0x08, BI 0x10).
 *     Register n sits at n * stride; stride 4 means 32-bit accesses (SPCR
 *     GAS access size 3, Linux UPIO_MEM32 on the Spark), stride 1 byte
 *     accesses. Reading LSR clears OE/PE/FE/BI, so it is read exactly once
 *     per byte and every flag is taken from that one read.
 *
 * Decode result: 0..255 a good byte; CK_UART_RX_EMPTY nothing waiting;
 * CK_UART_RX_ERROR a byte was lost or arrived damaged (overrun, parity,
 * framing, break): the byte is dropped and counted, and the line assembler
 * (core/line_rx.c) refuses the line it belonged to. */
#ifndef AIENOS_CK_UART_RX_H
#define AIENOS_CK_UART_RX_H

#include <stdint.h>

enum ck_uart_kind { CK_UART_NONE = 0, CK_UART_PL011 = 1, CK_UART_16550 = 2 };

#define CK_UART_RX_EMPTY (-1)
#define CK_UART_RX_ERROR (-2)

#define CK_PL011_DR 0x00u
#define CK_PL011_FR 0x18u
#define CK_PL011_CR 0x30u
#define CK_PL011_FR_RXFE (1u << 4)
#define CK_PL011_DR_FE (1u << 8)
#define CK_PL011_DR_PE (1u << 9)
#define CK_PL011_DR_BE (1u << 10)
#define CK_PL011_DR_OE (1u << 11)
#define CK_PL011_CR_UARTEN (1u << 0)
#define CK_PL011_CR_RXE (1u << 9)

#define CK_16550_RBR 0u
#define CK_16550_LCR 3u
#define CK_16550_LSR 5u
#define CK_16550_LCR_DLAB 0x80u
#define CK_16550_LSR_DR 0x01u
#define CK_16550_LSR_OE 0x02u
#define CK_16550_LSR_PE 0x04u
#define CK_16550_LSR_FE 0x08u
#define CK_16550_LSR_BI 0x10u

struct ck_uart_rx_count {
    unsigned errors;   /* every dropped byte (overrun, parity, framing, break) */
    unsigned overruns; /* of those: overruns (a byte was lost before this one) */
};

/* SPCR interface type -> UART kind and 16550 register stride. -1: no
 * console UART of a kind this kernel can drive (output dropped, no input).
 * Types from Linux include/acpi/actbl1.h (ACPI_DBG2_*). */
static inline int ck_uart_from_spcr(uint8_t interface_type, uint8_t access_size, int *kind, unsigned *stride)
{
    switch (interface_type) {
    case 0x03: /* ARM PL011 */
    case 0x0d: /* ARM SBSA generic UART, 32-bit only */
    case 0x0e: /* ARM SBSA generic UART */
        *kind = CK_UART_PL011;
        *stride = 4;
        return 0;
    case 0x00: /* 16550 fully compatible */
    case 0x01: /* 16550 subset (DBGP rev 1): the DGX Spark's SPCR */
    case 0x12: /* 16550 with parameters in the GAS */
        *kind = CK_UART_16550;
        *stride = access_size == 3 ? 4 : access_size == 4 ? 8 : 1;
        return 0;
    default:
        return -1;
    }
}

static inline uint32_t ck_uart_rd(volatile uint8_t *base, unsigned off, unsigned width)
{
    if (width == 1)
        return *(volatile uint8_t *)(base + off);
    return *(volatile uint32_t *)(base + off);
}

/* 16550 register access width: 32-bit for stride 4 and 8 (the low 32 bits
 * of a qword-spaced register), byte for stride 1. */
static inline unsigned ck_16550_width(unsigned stride)
{
    return stride == 1 ? 1 : 4;
}

/* 1 when the receiver can deliver bytes; *regs gets the register that
 * proves it (PL011 UARTCR; 16550 LCR << 8 | LSR) for the report line.
 * 16550: there is no receiver-enable bit; not ready when LSR reads all ones
 * (nothing answering at that address) or LCR.DLAB is set (offset 0 is then
 * the divisor latch, not the receive buffer). */
static inline int ck_uart_rx_ready(int kind, volatile uint8_t *base, unsigned stride, uint32_t *regs)
{
    if (!base)
        return 0;
    if (kind == CK_UART_PL011) {
        uint32_t cr = ck_uart_rd(base, CK_PL011_CR, 4);
        if (regs)
            *regs = cr;
        return (cr & CK_PL011_CR_UARTEN) && (cr & CK_PL011_CR_RXE);
    }
    if (kind == CK_UART_16550) {
        unsigned w = ck_16550_width(stride);
        uint32_t lcr = ck_uart_rd(base, CK_16550_LCR * stride, w) & 0xffu;
        uint32_t lsr = ck_uart_rd(base, CK_16550_LSR * stride, w) & 0xffu;
        if (regs)
            *regs = lcr << 8 | lsr;
        return lsr != 0xffu && !(lcr & CK_16550_LCR_DLAB);
    }
    return 0;
}

/* One polled receive: a byte, CK_UART_RX_EMPTY or CK_UART_RX_ERROR. */
static inline int ck_uart_rx_take(int kind, volatile uint8_t *base, unsigned stride, struct ck_uart_rx_count *c)
{
    if (!base)
        return CK_UART_RX_EMPTY;
    if (kind == CK_UART_PL011) {
        if (ck_uart_rd(base, CK_PL011_FR, 4) & CK_PL011_FR_RXFE)
            return CK_UART_RX_EMPTY;
        uint32_t d = ck_uart_rd(base, CK_PL011_DR, 4);
        if (d & (CK_PL011_DR_FE | CK_PL011_DR_PE | CK_PL011_DR_BE | CK_PL011_DR_OE)) {
            c->errors++;
            if (d & CK_PL011_DR_OE)
                c->overruns++;
            return CK_UART_RX_ERROR;
        }
        return (int)(d & 0xffu);
    }
    if (kind == CK_UART_16550) {
        unsigned w = ck_16550_width(stride);
        uint32_t lsr = ck_uart_rd(base, CK_16550_LSR * stride, w) & 0xffu;
        if (lsr == 0xffu)
            return CK_UART_RX_EMPTY; /* nothing answering: never a byte stream of 0xff */
        int byte = CK_UART_RX_EMPTY;
        if (lsr & CK_16550_LSR_DR)
            byte = (int)(ck_uart_rd(base, CK_16550_RBR * stride, w) & 0xffu); /* pops it either way */
        if (lsr & (CK_16550_LSR_OE | CK_16550_LSR_PE | CK_16550_LSR_FE | CK_16550_LSR_BI)) {
            c->errors++;
            if (lsr & CK_16550_LSR_OE)
                c->overruns++;
            return CK_UART_RX_ERROR; /* OE alone: an earlier byte was lost, the line is damaged */
        }
        return byte;
    }
    return CK_UART_RX_EMPTY;
}

#endif
