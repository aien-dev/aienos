/* unlock_req.c -- see unlock_req.h. */
#include "unlock_req.h"

struct ck_unlock_req_boot ck_unlock_req_boot;

static void wipe(void *p, size_t n)
{
    volatile uint8_t *b = p;
    while (n--)
        *b++ = 0;
}

int ck_unlock_req_check(const struct ck_unlock_req *q, const char **why)
{
    const char *w = 0;
    const uint8_t *p = (const uint8_t *)q;
    if (!q) {
        w = "no request";
        goto out;
    }
    for (unsigned i = 0; i < 8; i++)
        if (q->magic[i] != (uint8_t)CK_UNLOCK_REQ_MAGIC[i]) {
            w = "bad magic";
            goto out;
        }
    if (q->version != CK_UNLOCK_REQ_VERSION) {
        w = "bad version";
        goto out;
    }
    if (q->flags != 0) {
        w = "flags must be zero";
        goto out;
    }
    for (unsigned i = 0; i < 16; i++)
        if (q->tag[i] != (uint8_t)CK_UNLOCK_REQ_TAG[i]) {
            w = "tier tag is not QUALIF-THROWAWAY";
            goto out;
        }
    {
        unsigned zero = 1, same = 1;
        for (unsigned i = 0; i < CK_UNLOCK_REQ_SECRET_LEN; i++) {
            if (q->secret[i] != 0)
                zero = 0;
            if (q->secret[i] != q->secret[0])
                same = 0;
        }
        if (zero || same) {
            w = "secret is all zero or one repeated byte";
            goto out;
        }
    }
    for (unsigned i = 64; i < CK_UNLOCK_REQ_SIZE; i++)
        if (p[i] != 0) {
            w = "padding is not zero";
            goto out;
        }
out:
    if (why)
        *why = w;
    return w ? -1 : 0;
}

void ck_unlock_req_store(const struct ck_unlock_req *q)
{
    for (unsigned i = 0; i < CK_UNLOCK_REQ_SECRET_LEN; i++)
        ck_unlock_req_boot.secret[i] = q->secret[i];
    ck_unlock_req_boot.state = CK_UNLOCK_REQ_FOUND;
}

int ck_unlock_req_take(uint8_t out[CK_UNLOCK_REQ_SECRET_LEN])
{
    if (ck_unlock_req_boot.state != CK_UNLOCK_REQ_FOUND) {
        wipe(out, CK_UNLOCK_REQ_SECRET_LEN);
        return -1;
    }
    for (unsigned i = 0; i < CK_UNLOCK_REQ_SECRET_LEN; i++)
        out[i] = ck_unlock_req_boot.secret[i];
    wipe(ck_unlock_req_boot.secret, CK_UNLOCK_REQ_SECRET_LEN);
    ck_unlock_req_boot.state = CK_UNLOCK_REQ_NONE;
    return 0;
}
