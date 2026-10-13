/*
 * disk_sdhci.h -- AIENOS freestanding SD card driver over an SD Host
 * Controller (SDHCI) (C, no libc, no heap). Raspberry Pi 5 microSD slot
 * (Broadcom brcm,bcm2712-sdhci, Linux bcm2712.dtsi) and QEMU sdhci-pci.
 *
 * Polled, programmed I/O only (Buffer Data Port 0x20): no DMA, so the device
 * never writes memory and no IOMMU window is needed. One command at a time.
 *
 * Register map: SD Host Controller Simplified Specification, as Linux
 * drivers/mmc/host/sdhci.h names it. Card protocol: SD Physical Layer
 * Simplified Specification (CMD0, CMD8, ACMD41, CMD2, CMD3, CMD9, CMD7, ACMD6,
 * CMD16, CMD17/18, CMD24/25, CMD12, CMD13).
 *
 * Every register access is a naturally aligned 32-bit read or write: some
 * Broadcom SDHCI blocks refuse 8/16-bit writes, so TRANSFER_MODE+COMMAND
 * (0x0C) and BLOCK_SIZE+BLOCK_COUNT (0x04) are written as one word each, and
 * the byte registers at 0x28 and 0x2C are updated read-modify-write (never
 * while a SOFTWARE_RESET bit is still set).
 *
 * The caller provides sdhci_ops: 32-bit MMIO read/write at a byte offset from
 * the controller base, and a bounded delay in microseconds.
 *
 * Bring-up (sdhci_init), each refusal its own SDHCI_E* code:
 *   - HOST_VERSION spec 2.00 or later (1.00 controllers unsupported). EVER
 *   - SOFTWARE_RESET ALL clears within 100 ms.                      ERESET
 *   - a card is present (PRESENT_STATE bit 16) within 100 ms.       ENOCARD
 *   - capabilities offer 3.3 V; bus power is 3.3 V only (no UHS 1.8 V
 *     signalling, no voltage switch).                               EVOLT
 *   - base clock from cfg.base_clock_hz, else CAPABILITIES (bits 13:8 on
 *     2.00, 15:8 on 3.00+, MHz); zero from both refuses.            ECLOCK
 *   - identification at <= 400 kHz, then default speed <= 25 MHz (no CMD6
 *     high speed), internal clock stable within 100 ms.             ECLOCK
 *   - CMD8 echo 0x1AA (physical layer 2.00+ card; v1 cards refused).  ECARD
 *   - ACMD41 ready within 1 s; CCS selects block addressing (SDHC/SDXC) or
 *     byte addressing (SDSC, CMD16 sets 512-byte blocks).          ETIMEOUT
 *   - CSD structure 1 (SDHC/SDXC: (C_SIZE + 1) * 1024 blocks) or 0 (SDSC:
 *     (C_SIZE + 1) * 2^(C_SIZE_MULT + 2) * 2^READ_BL_LEN / 512).      ECSD
 *   - 4-bit bus through ACMD6 when cfg.bus_4bit (else 1-bit).
 * Every command: CMD_INHIBIT (and DATA_INHIBIT for data or busy) clear before
 * issue; command complete, data ready and transfer complete each bounded
 * (cfg.timeout_ms, default 1000 ms); any error interrupt bit fails the command
 * (ECMD / EDATA) after CMD and DATA line resets. R1 card status error bits
 * (31:19, 13) fail the command too (ESTATUS).
 * Writes: transfer complete, then CMD13 until READY_FOR_DATA and state "tran"
 * (programming finished). sdhci_flush therefore has nothing in flight; it
 * still checks the card is in "tran" and ready. The SD cache (CMD48/49) is
 * never enabled, so an acknowledged write is on the card.
 */
#ifndef AIENOS_DISK_SDHCI_H
#define AIENOS_DISK_SDHCI_H
#include <stdint.h>
#include "disk.h"

typedef struct {
    void *ctx;
    uint32_t (*r32)(void *ctx, uint32_t off);
    void (*w32)(void *ctx, uint32_t off, uint32_t v);
    void (*delay_us)(void *ctx, uint32_t us);
} sdhci_ops;

typedef struct {
    uint32_t base_clock_hz; /* 0: from CAPABILITIES */
    uint32_t timeout_ms;    /* per command / data phase; 0: 1000 */
    int bus_4bit;           /* 1: switch to 4-bit after select */
    uint32_t max_blocks;    /* per multi-block transfer, 1..65535; 0: 128 */
} sdhci_cfg;

enum {
    SDHCI_OK = 0,
    SDHCI_EARG = -20,
    SDHCI_EVER = -21,
    SDHCI_ERESET = -22,
    SDHCI_ENOCARD = -23,
    SDHCI_EVOLT = -24,
    SDHCI_ECLOCK = -25,
    SDHCI_ECARD = -26,
    SDHCI_ETIMEOUT = -27,
    SDHCI_ECSD = -28,
    SDHCI_ECMD = -29,
    SDHCI_EDATA = -30,
    SDHCI_ESTATUS = -31,
    SDHCI_ESTATE = -32,
};

typedef struct {
    sdhci_ops ops;
    sdhci_cfg cfg;
    int ready;            /* init succeeded and no failure since */
    uint32_t spec;        /* HOST_VERSION spec field: 1 = 2.00, 2 = 3.00, ... */
    uint32_t base_hz;     /* base clock used */
    uint32_t card_hz;     /* SD clock after init */
    uint16_t rca;
    int high_capacity;    /* CCS: block addressing */
    uint64_t blocks;      /* 512-byte blocks */
    uint32_t cid[4], csd[4];
    uint32_t last_int;    /* INT_STATUS seen by the last failure (diagnostics) */
    int last_cmd;         /* command index of the last failure, -1 none */
    int last_err;         /* SDHCI_E* of the last failure, 0 none */
    disk_dev dev;
} sdhci_card;

/* Reset the controller, power and clock it, identify and select the card.
 * On success c->dev is a disk_dev (block_size 512) over the whole card. */
int sdhci_init(sdhci_card *c, const sdhci_ops *ops, const sdhci_cfg *cfg);
/* disk_dev backend entry points (c->dev uses them; ctx is the sdhci_card). */
int sdhci_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf);
int sdhci_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf);
int sdhci_flush(void *ctx);
const char *sdhci_strerror(int rc);

/* Register offsets and bits used (exported for the software model). */
#define SDHCI_R_BLOCK 0x04 /* BLOCK_SIZE (15:0) | BLOCK_COUNT (31:16) */
#define SDHCI_R_ARG 0x08
#define SDHCI_R_CMD 0x0C /* TRANSFER_MODE (15:0) | COMMAND (31:16) */
#define SDHCI_R_RESP0 0x10
#define SDHCI_R_BUF 0x20
#define SDHCI_R_PRESENT 0x24
#define SDHCI_R_HOST 0x28 /* HOST_CONTROL 7:0, POWER_CONTROL 15:8 */
#define SDHCI_R_CLOCK 0x2C /* CLOCK_CONTROL 15:0, TIMEOUT 23:16, SOFTWARE_RESET 31:24 */
#define SDHCI_R_INT 0x30
#define SDHCI_R_INT_EN 0x34
#define SDHCI_R_SIG_EN 0x38
#define SDHCI_R_CAP 0x40
#define SDHCI_R_VERSION 0xFC /* HOST_VERSION is bits 31:16 of the word at 0xFC */
#endif
