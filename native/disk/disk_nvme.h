/*
 * disk_nvme.h -- AIENOS freestanding NVMe driver (C, no libc, no heap).
 *
 * Ported from the audited Rust path (crates/aienos-kernel/src/nvme.rs,
 * nvme/driver.rs, nvme/atomicity.rs; docs/P3_NVME_*.md). Polled, one admin
 * queue pair and one I/O queue pair, no interrupts.
 *
 * The caller provides:
 *   - nvme_ops: 32-bit MMIO access to BAR0 (64-bit optional), a full memory
 *     barrier, and a bounded delay in microseconds.
 *   - nvme_dma: ONE physically contiguous, 4 KiB aligned region with its CPU
 *     pointer and its bus (physical) address. The driver carves it into fixed
 *     4 KiB pages (admin SQ, admin CQ, identify buffer, I/O SQ, I/O CQ, PRP
 *     list) followed by a bounce buffer for data. The region must be
 *     coherent with the device (or the barrier op must make it so).
 *
 * Every request goes through the bounce buffer, so caller buffers need not be
 * DMA addressable. One command is outstanding at a time; the driver waits for
 * its completion before returning.
 *
 * Checks performed by nvme_init (each refusal returns its own NVME_E* code;
 * docs/P3_NVME_UNSAFE_ASSUMPTIONS.md items marked [UA]):
 *   [UA] CAP.MPSMIN (bits 51:48) must be 0: the driver uses 4 KiB pages only
 *        (CC.MPS = 0). CAP.MPSMAX (bits 55:52) must be >= MPSMIN.  NVME_EMPS
 *   [UA] CAP.MQES (bits 15:0, 0-based): admin depth NVME_ADMIN_DEPTH and the
 *        configured I/O depth must each be <= MQES + 1.         NVME_EMQES
 *   [UA] CAP.CSS bit 37 (NVM command set) must be set; CC.CSS = 0.  NVME_ECSS
 *   [UA] CAP.AMS: documented limit, not a refusal. Round robin (CC.AMS = 0) is
 *        mandatory for every controller (NVMe base spec, CC.AMS); CAP.AMS
 *        bits 18:17 only advertise the optional WRR and vendor schemes. The
 *        audit text reading "bit 0" as round robin is wrong; the driver always
 *        programs CC.AMS = 0 (asserted by the test model).
 *   [UA] CAP.TO (bits 31:24, 500 ms units; 0 treated as 500 ms): readiness
 *        waits poll CSTS every 1 ms and give up after exactly TO*500 ms of
 *        delay (no extra delay after the final read).     NVME_ETIMEOUT
 *        CSTS.CFS seen during any wait or command poll.        NVME_ECFS
 *   [UA] VS (0x08): major version must be 1 or 2.               NVME_EVS
 *   [UA] NSID: never hard-coded. cfg.nsid == 0 picks the first active NSID
 *        from Identify CNS=02h; a caller NSID must be in 1..NN (Identify
 *        Controller NN) and identify with NSZE != 0.          NVME_ENSID
 *   [UA] LBADS: only 9 (512 B) or 12 (4096 B) accepted (disk_dev contract;
 *        10, 11 and 13..31 are valid NVMe but unsupported here).  NVME_ELBADS
 *        LBA format metadata size must be 0.                   NVME_EMETA
 *        FLBAS index must be <= NLBAF.                         NVME_EFLBAS
 *        NSZE must be non-zero.                                NVME_ENSZE
 *   [UA] Completion SQID must equal the queue the command went to (0 admin,
 *        1 I/O) and CID must match.                   NVME_ESQID / NVME_ECID
 *        Identify Controller SQES/CQES must allow 64 B / 16 B entries. NVME_EQES
 *        DMA region: non-NULL, 4 KiB aligned phys, size >= 6 pages + one data
 *        page, no address wrap.                                NVME_EARG
 *
 * Limits (documented, not checks):
 *   - Transfer size per command = min(bounce bytes, 128 KiB, 4 KiB << MDTS)
 *     (MDTS 0 = no device limit). Larger disk_dev requests are split by
 *     disk.c using max_blocks_per_io. 128 KiB needs at most 31 PRP list
 *     entries, so one PRP list page is enough; nvme_build_prps still
 *     implements list chaining (ported from Rust build_prps) and is tested.
 *   - Command poll budget: max(1000 ms, CAP.TO*500 ms) in 10 us steps.
 *   - Any timeout, CFS, CID/SQID mismatch or failed queue creation puts the
 *     controller in the failed state; every later call returns DISK_ESTATE
 *     until nvme_init runs again (fail-stop). A command that completes with a
 *     non-zero status returns DISK_EIO and the queue stays usable.
 *   - Doorbell offsets use CAP.DSTRD (4 << DSTRD stride).
 */
#ifndef AIENOS_DISK_NVME_H
#define AIENOS_DISK_NVME_H

#include <stdint.h>
#include "disk.h"

#define NVME_PAGE 4096u
#define NVME_ADMIN_DEPTH 8u
#define NVME_IO_DEPTH_DEFAULT 16u
#define NVME_IO_DEPTH_MAX 64u        /* 64 entries x 64 B = one 4 KiB page */
#define NVME_MAX_XFER (128u * 1024u) /* self-imposed cap, as in the Rust driver */
#define NVME_FIXED_PAGES 6u          /* asq, acq, identify, iosq, iocq, prp list */
#define NVME_DMA_MIN_BYTES ((NVME_FIXED_PAGES + 1u) * NVME_PAGE)

/* Register offsets (NVMe base spec). */
#define NVME_REG_CAP 0x00u
#define NVME_REG_VS 0x08u
#define NVME_REG_INTMS 0x0cu
#define NVME_REG_CC 0x14u
#define NVME_REG_CSTS 0x1cu
#define NVME_REG_AQA 0x24u
#define NVME_REG_ASQ 0x28u
#define NVME_REG_ACQ 0x30u
#define NVME_REG_DOORBELL 0x1000u

enum {
    NVME_OK = 0,
    NVME_EARG = -100,     /* bad ops / dma / config */
    NVME_EMPS = -101,     /* CAP.MPSMIN != 0 or MPSMAX < MPSMIN */
    NVME_EMQES = -102,    /* queue depth above CAP.MQES + 1 */
    NVME_ECSS = -103,     /* NVM command set not supported */
    NVME_EVS = -104,      /* unsupported major version */
    NVME_ETIMEOUT = -105, /* readiness or command poll budget exhausted */
    NVME_ECFS = -106,     /* CSTS.CFS: controller fatal status */
    NVME_ESTATUS = -107,  /* completion with non-zero status */
    NVME_ECID = -108,     /* completion CID mismatch */
    NVME_ESQID = -109,    /* completion SQID mismatch */
    NVME_ENSID = -110,    /* no usable namespace */
    NVME_ELBADS = -111,   /* LBA data size not 512 or 4096 */
    NVME_EMETA = -112,    /* LBA format carries metadata */
    NVME_EFLBAS = -113,   /* FLBAS index above NLBAF */
    NVME_ENSZE = -114,    /* namespace size zero */
    NVME_EQES = -115,     /* SQES/CQES do not allow 64/16 byte entries */
    NVME_ERANGE = -116,   /* lba/count out of range */
    NVME_ESTATE = -117,   /* not initialized or failed (fail-stop) */
};

typedef struct {
    void *ctx;
    uint32_t (*read32)(void *ctx, uint32_t off);
    void (*write32)(void *ctx, uint32_t off, uint32_t val);
    /* Optional: when NULL, 64-bit registers are accessed as two 32-bit
     * halves (low dword first), as the Rust driver does. */
    uint64_t (*read64)(void *ctx, uint32_t off);
    void (*write64)(void *ctx, uint32_t off, uint64_t val);
    void (*barrier)(void *ctx);                /* full memory + DMA barrier */
    void (*delay_us)(void *ctx, uint32_t us);  /* bounded busy wait */
} nvme_ops;

typedef struct {
    uint8_t *virt;  /* CPU pointer */
    uint64_t phys;  /* device-visible address, 4 KiB aligned */
    uint64_t bytes; /* >= NVME_DMA_MIN_BYTES */
} nvme_dma;

typedef struct {
    uint32_t nsid;     /* 0 = first active namespace */
    uint16_t io_depth; /* 0 = NVME_IO_DEPTH_DEFAULT; 2..NVME_IO_DEPTH_MAX */
} nvme_config;

typedef struct {
    uint16_t tail, head, depth, sqid;
    uint8_t phase;
    uint8_t *sq, *cq;     /* CPU pointers into the DMA region */
    uint64_t sq_phys, cq_phys;
    uint32_t sq_db, cq_db; /* doorbell register offsets */
} nvme_qpair;

typedef struct {
    nvme_ops ops;
    nvme_dma dma;
    uint64_t cap;
    uint32_t vs;
    uint32_t timeout_ms;     /* CAP.TO * 500, min 500 */
    uint32_t cmd_timeout_ms; /* max(1000, timeout_ms) */
    uint32_t dstrd_stride;
    nvme_qpair admin, io;
    uint16_t next_cid;
    int ready, failed;
    int last_err; /* last NVME_E* code, for diagnostics */
    /* Identify results */
    uint8_t mdts, vwc;
    uint32_t nn, nsid;
    uint32_t block_size;
    uint64_t block_count;
    uint32_t max_xfer_bytes;
    uint8_t *identify, *prp_list, *bounce;
    uint64_t identify_phys, prp_list_phys, bounce_phys, bounce_bytes;
    /* Power-fail atomicity fields (ported from nvme/atomicity.rs). */
    uint16_t awupf_raw, nawupf_raw, nabspf_raw, nabo_blocks;
} nvme_ctrl;

/* Reset, configure and enable the controller, identify it and the namespace,
 * create the I/O queue pair. Calling it again is a full reset ("reopen"). */
int nvme_init(nvme_ctrl *c, const nvme_ops *ops, const nvme_dma *dma, const nvme_config *cfg);

/* Clear CC.EN and wait for CSTS.RDY = 0 (bounded by CAP.TO). */
int nvme_disable(nvme_ctrl *c);

/* Block I/O in logical blocks; count <= max_xfer_bytes / block_size. */
int nvme_read(nvme_ctrl *c, uint64_t lba, uint32_t count, uint8_t *buf);
int nvme_write(nvme_ctrl *c, uint64_t lba, uint32_t count, const uint8_t *buf);
int nvme_flush(nvme_ctrl *c);

/* Fill a disk_dev backed by an initialized controller. */
int nvme_disk(nvme_ctrl *c, disk_dev *out);

/* PRP construction (port of Rust build_prps). list holds list_cap u64
 * entries that live at bus address list_addr (page aligned, contiguous).
 * On success *used is the number of list entries written. */
int nvme_build_prps(uint64_t addr, uint64_t len, uint64_t page_size, uint64_t list_addr,
                    uint64_t *list, uint32_t list_cap, uint64_t *prp1, uint64_t *prp2,
                    uint32_t *used);

/* Power-fail atomicity (port of atomicity.rs). Returns NVME_ATOMIC,
 * NVME_NOT_ATOMIC or NVME_ATOMIC_UNKNOWN for a write of lba_count blocks. */
enum { NVME_ATOMIC = 1, NVME_NOT_ATOMIC = 0, NVME_ATOMIC_UNKNOWN = -1 };
int nvme_write_is_power_fail_atomic(const nvme_ctrl *c, uint64_t start_lba, uint64_t lba_count);

#endif /* AIENOS_DISK_NVME_H */
