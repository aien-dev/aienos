/* nvme_shutdown.c -- see nvme_shutdown.h. NVMe Base 2.0 section 3.6.2
 * (normal shutdown): set CC.SHN to 01b, then wait for CSTS.SHST = 10b. */
#include "nvme_shutdown.h"

int ck_nvme_shutdown(const struct ck_nvme_shut_ops *o, uint32_t timeout_us, struct ck_nvme_shut_result *r)
{
    if (!o || !o->r32 || !o->w32 || !o->delay || !r)
        return CK_NVME_SHUT_EARG;
    r->waited_us = 0;
    r->cc_before = o->r32(o->ctx, CK_NVME_REG_CC);
    r->cc_after = r->cc_before;
    r->csts = o->r32(o->ctx, CK_NVME_REG_CSTS);
    if (r->cc_before == 0xffffffffu || r->csts == 0xffffffffu)
        return CK_NVME_SHUT_GONE;
    if (!(r->cc_before & CK_NVME_CC_EN))
        return CK_NVME_SHUT_NOT_ENABLED;
    o->w32(o->ctx, CK_NVME_REG_CC, (r->cc_before & ~CK_NVME_CC_SHN_MASK) | CK_NVME_CC_SHN_NORMAL);
    if (o->barrier)
        o->barrier(o->ctx);
    r->cc_after = o->r32(o->ctx, CK_NVME_REG_CC);
    for (;;) {
        r->csts = o->r32(o->ctx, CK_NVME_REG_CSTS);
        if (r->csts == 0xffffffffu)
            return CK_NVME_SHUT_GONE;
        if ((r->csts & CK_NVME_CSTS_SHST_MASK) == CK_NVME_CSTS_SHST_DONE)
            return CK_NVME_SHUT_OK;
        if (r->waited_us >= timeout_us)
            return CK_NVME_SHUT_TIMEOUT;
        o->delay(o->ctx, CK_NVME_SHUT_POLL_US);
        r->waited_us += CK_NVME_SHUT_POLL_US;
    }
}

const char *ck_nvme_shutdown_str(int rc)
{
    switch (rc) {
    case CK_NVME_SHUT_OK: return "complete";
    case CK_NVME_SHUT_NOT_ENABLED: return "not-enabled";
    case CK_NVME_SHUT_TIMEOUT: return "TIMEOUT";
    case CK_NVME_SHUT_GONE: return "DEVICE-GONE";
    default: return "EARG";
    }
}
