/* nvme_shutdown.h -- NVMe normal shutdown (CC.SHN = 01b, wait for
 * CSTS.SHST = 10b) for the C kernel's halt/reboot path. Register access goes
 * through ops so the sequence is host-testable against a model controller
 * (svc/tests/stage_test.c). native/disk is not touched: this sits in
 * native/kernel/dev next to the bind code that owns the BAR. */
#ifndef CK_NVME_SHUTDOWN_H
#define CK_NVME_SHUTDOWN_H
#include <stdint.h>

#define CK_NVME_REG_CC 0x14u
#define CK_NVME_REG_CSTS 0x1cu
#define CK_NVME_CC_EN 0x1u
#define CK_NVME_CC_SHN_MASK (3u << 14)
#define CK_NVME_CC_SHN_NORMAL (1u << 14)
#define CK_NVME_CSTS_RDY 0x1u
#define CK_NVME_CSTS_CFS (1u << 1)
#define CK_NVME_CSTS_SHST_MASK (3u << 2)
#define CK_NVME_CSTS_SHST_DONE (2u << 2)
#define CK_NVME_SHUT_POLL_US 100u
#define CK_NVME_SHUT_TIMEOUT_US 5000000u /* no RTD3E use yet: a fixed 5 s bound */
#define CK_NVME_DISABLE_TIMEOUT_US 1000000u /* fallback CC.EN = 0, bounded 1 s */

enum {
    CK_NVME_SHUT_OK = 0,           /* SHST reached 10b */
    CK_NVME_SHUT_NOT_ENABLED = 1,  /* CC.EN = 0: controller idle, nothing to shut down */
    CK_NVME_SHUT_TIMEOUT = -1,     /* SHST never reached 10b within the bound */
    CK_NVME_SHUT_GONE = -2,        /* CSTS reads all ones: device not answering */
    CK_NVME_SHUT_EARG = -3,
    CK_NVME_SHUT_FATAL = -4,       /* CSTS.CFS = 1: controller fatal, cannot shut down normally */
    CK_NVME_SHUT_NOT_READY = -5,   /* CC.EN = 1 but CSTS.RDY = 0: SHN must not be written */
    CK_NVME_SHUT_ALREADY = 2,      /* SHST already 10b: nothing written */
};

struct ck_nvme_shut_ops {
    void *ctx;
    uint32_t (*r32)(void *ctx, uint32_t off);
    void (*w32)(void *ctx, uint32_t off, uint32_t v);
    void (*barrier)(void *ctx);
    void (*delay)(void *ctx, uint32_t us);
};

struct ck_nvme_shut_result {
    uint32_t cc_before;  /* CC as found */
    uint32_t cc_after;   /* CC read back after the SHN write */
    uint32_t csts;       /* last CSTS read */
    uint32_t waited_us;  /* polling time spent */
};

/* Requests a normal shutdown and waits (bounded) for it to complete. Bus
 * mastering must still be on: the controller may DMA while it finishes. */
int ck_nvme_shutdown(const struct ck_nvme_shut_ops *o, uint32_t timeout_us, struct ck_nvme_shut_result *r);
const char *ck_nvme_shutdown_str(int rc);

/* Fallback when a normal shutdown cannot complete (TIMEOUT, FATAL,
 * NOT_READY): clear CC.EN (and SHN) and wait, bounded, for CSTS.RDY = 0 so
 * the controller stops issuing DMA before bus mastering is cut. Returns OK,
 * TIMEOUT, GONE or EARG; r->cc_after is CC read back after the write. */
int ck_nvme_disable(const struct ck_nvme_shut_ops *o, uint32_t timeout_us, struct ck_nvme_shut_result *r);
/* 1 when rc means the controller may still be live and must be disabled. */
int ck_nvme_shutdown_needs_disable(int rc);

#endif
