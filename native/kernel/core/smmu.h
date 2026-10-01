/* smmu.h -- Arm SMMUv3 programming for the AIENOS C kernel, ported from the
 * Rust reference crates/aienos-kernel/src/smmu.rs (linear stream table,
 * stage-1 translation only, one linear context descriptor per stream).
 *
 * Pure logic over a register-access callback and table memory, so the host
 * tests drive it against a model SMMU. The kernel glue (core/smmu_svc.c)
 * supplies MMIO accessors and Normal Non-cacheable table memory from the
 * DMA pool (ck_dma_alloc), so no cache maintenance is needed; the barrier
 * callback orders table writes before the register write that publishes
 * them. Addresses are identity mapped: a table pointer is its bus address.
 *
 * Fail-closed rules (same as the Rust reference):
 *  - GBPA.ABORT is set first and never cleared: a disabled SMMU aborts all
 *    DMA. There is no bypass STE constructor.
 *  - Every stream starts as an abort STE; only an explicit install makes a
 *    stream translate, and only through a stage-1 table.
 *  - Any error after GBPA.ABORT latched writes CR0 = 0 (SMMU off, so ABORT
 *    governs every stream). Every poll is bounded by `spins`.
 * QEMU is not hardware: nothing built on this is physically qualified. */
#ifndef AIENOS_CK_SMMU_H
#define AIENOS_CK_SMMU_H
#include <stdint.h>

#define CK_SMMU_STE_BYTES 64u
#define CK_SMMU_CD_BYTES 64u
#define CK_SMMU_CMD_BYTES 16u
#define CK_SMMU_EVT_BYTES 32u
#define CK_SMMU_MMIO_BYTES 0x20000u /* register pages 0 and 1 */

/* Register offsets (SMMUv3 architecture). */
#define CK_SMMU_IDR0 0x00u
#define CK_SMMU_IDR1 0x04u
#define CK_SMMU_CR0 0x20u
#define CK_SMMU_CR0ACK 0x24u
#define CK_SMMU_CR1 0x28u
#define CK_SMMU_CR2 0x2cu
#define CK_SMMU_GBPA 0x44u
#define CK_SMMU_STRTAB_BASE 0x80u
#define CK_SMMU_STRTAB_BASE_CFG 0x88u
#define CK_SMMU_CMDQ_BASE 0x90u
#define CK_SMMU_CMDQ_PROD 0x98u
#define CK_SMMU_CMDQ_CONS 0x9cu
#define CK_SMMU_EVENTQ_BASE 0xa0u
#define CK_SMMU_EVENTQ_PROD 0x100a8u /* page 1 */
#define CK_SMMU_EVENTQ_CONS 0x100acu /* page 1 */

#define CK_SMMU_IDR0_S1P (1u << 1)
#define CK_SMMU_GBPA_ABORT (1u << 20)
#define CK_SMMU_GBPA_UPDATE (1u << 31)
#define CK_SMMU_CR0_SMMUEN (1u << 0)
#define CK_SMMU_CR0_EVENTQEN (1u << 2)
#define CK_SMMU_CR0_CMDQEN (1u << 3)

#define CK_SMMU_CMD_CFGI_STE 0x03u
#define CK_SMMU_CMD_CFGI_ALL 0x04u
#define CK_SMMU_CMD_CFGI_CD_ALL 0x06u
#define CK_SMMU_CMD_TLBI_NSNH_ALL 0x30u
#define CK_SMMU_CMD_SYNC 0x46u

/* Event record types (word 0 bits 7:0). */
#define CK_SMMU_EVT_F_TRANSLATION 0x10u
#define CK_SMMU_EVT_F_ADDR_SIZE 0x11u
#define CK_SMMU_EVT_F_ACCESS 0x12u
#define CK_SMMU_EVT_F_PERMISSION 0x13u
#define CK_SMMU_EVT_C_BAD_STE 0x04u
#define CK_SMMU_EVT_F_STREAM_DISABLED 0x06u

#define CK_SMMU_DEFAULT_SPINS 1000000u

/* Errors (negative). */
#define CK_SMMU_ETIMEOUT (-10)  /* a bounded poll ran out */
#define CK_SMMU_ECMDQ (-11)     /* CMDQ_CONS.ERR set */
#define CK_SMMU_EUNSUP (-12)    /* IDR0/IDR1 cannot run this geometry */
#define CK_SMMU_EINVAL (-13)    /* bad stream id, geometry or alignment */
#define CK_SMMU_ENOABORT (-14)  /* GBPA.ABORT did not latch */

struct ck_smmu_regs {
    void *ctx;
    uint32_t (*rd32)(void *ctx, uint32_t off);
    void (*wr32)(void *ctx, uint32_t off, uint32_t v);
    void (*wr64)(void *ctx, uint32_t off, uint64_t v);
    void (*barrier)(void *ctx); /* table writes visible before the next register write */
};

/* Linear stream table + queues. Entry counts are powers of two; every base
 * is aligned to its own size (min 32 bytes). Pointers are bus addresses. */
struct ck_smmu_tables {
    uint64_t *strtab; /* ste_n x 8 words */
    uint32_t ste_n;
    uint64_t *cmdq;   /* cmd_n x 2 words */
    uint32_t cmd_n;
    uint64_t *evtq;   /* evt_n x 4 words */
    uint32_t evt_n;
};

struct ck_smmu_event {
    uint8_t type;
    uint32_t sid;
    uint64_t addr; /* word 2: input address for translation-class faults */
    uint64_t raw[4];
};

/* 0 if the geometry and alignment are valid, else CK_SMMU_EINVAL. */
int ck_smmu_tables_check(const struct ck_smmu_tables *t);

/* Descriptor builders. */
void ck_smmu_ste_abort(uint64_t ste[8]);
void ck_smmu_ste_stage1(uint64_t ste[8], uint64_t cd_addr);
/* CD for a stage-1 walk: 4 KiB granule, TTBR0 only (EPD1), 48-bit IPS,
 * walks Non-cacheable (the kernel's tables live in Non-cacheable memory),
 * faults recorded (R) and aborted (A). CK_SMMU_EINVAL if t0sz > 39 or ttb0
 * is not 4 KiB aligned. */
int ck_smmu_cd_stage1(uint64_t cd[8], uint64_t ttb0, uint16_t asid, uint64_t mair, uint8_t t0sz);
void ck_smmu_cmd(uint64_t w[2], uint8_t opcode, uint32_t sid, int leaf);

/* Queue index encoding: index in bits n-1:0, wrap flag in bit n. */
uint32_t ck_smmu_q_encode(uint32_t index, int wrap, uint32_t entries);

/* Append commands and wait until the SMMU consumed them all. */
int ck_smmu_submit(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, const uint64_t (*cmds)[2],
                   uint32_t n, uint32_t spins);

/* Bring-up with every stream in abort:
 *  1. GBPA.ABORT set and latched (else return without touching CR0);
 *  2. IDR0.S1P, IDR1 SIDSIZE / CMDQS / EVENTQS checked against the tables;
 *  3. all STEs abort, queues zeroed, barrier;
 *  4. CR0 = 0 (ack), queues + stream table programmed, queues enabled (ack),
 *     CFGI_ALL + TLBI_NSNH_ALL + SYNC, SMMUEN (ack).
 * Any error after step 1 writes CR0 = 0 and returns it. */
int ck_smmu_enable(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t spins);

/* Point stream `sid` at `ste`: abort + invalidate first, write words 1..7,
 * barrier, then word 0, then CFGI_STE + TLBI_NSNH_ALL + SYNC. */
int ck_smmu_install_ste(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                        const uint64_t ste[8], uint32_t spins);
/* Return `sid` to abort and invalidate it. On 0 no further DMA translates. */
int ck_smmu_abort_ste(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t, uint32_t sid,
                      uint32_t spins);

/* Consume up to n event records, oldest first; acknowledges an overflow.
 * Returns the number of records written to out. */
int ck_smmu_read_events(const struct ck_smmu_regs *r, const struct ck_smmu_tables *t,
                        struct ck_smmu_event *out, int n, int *overflowed);
#endif
