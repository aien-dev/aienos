/* fact_req.c -- see fact_req.h. */
#include "fact_req.h"

struct ck_fact_req_boot ck_fact_req_boot;

int ck_fact_req_check(const struct ck_fact_req *q, const char **why)
{
    const char *w = 0;
    const uint8_t *p = (const uint8_t *)q;
    if (!q) {
        w = "no request";
        goto out;
    }
    for (unsigned i = 0; i < 8; i++)
        if (q->magic[i] != (uint8_t)CK_FACT_REQ_MAGIC[i]) {
            w = "bad magic";
            goto out;
        }
    if (q->version != CK_FACT_REQ_VERSION) {
        w = "bad version";
        goto out;
    }
    if (q->flags != 0) {
        w = "flags must be zero";
        goto out;
    }
    for (unsigned i = 0; i < 16; i++)
        if (q->tag[i] != (uint8_t)CK_FACT_REQ_TAG[i]) {
            w = "tier tag is not QUALIF-FACT-DATA";
            goto out;
        }
    if (q->len < 1 || q->len > CK_FACT_REQ_TEXT_MAX) {
        w = "fact length must be 1..48";
        goto out;
    }
    if (q->reserved != 0) {
        w = "reserved must be zero";
        goto out;
    }
    for (unsigned i = 0; i < CK_FACT_REQ_TEXT_MAX; i++) {
        if (i < q->len) {
            if (q->text[i] < 0x20 || q->text[i] > 0x7e) {
                w = "fact text must be printable ASCII";
                goto out;
            }
        } else if (q->text[i] != 0) {
            w = "text past the length is not zero";
            goto out;
        }
    }
    for (unsigned i = 88; i < CK_FACT_REQ_SIZE; i++)
        if (p[i] != 0) {
            w = "padding is not zero";
            goto out;
        }
out:
    if (why)
        *why = w;
    return w ? -1 : 0;
}

void ck_fact_req_store(const struct ck_fact_req *q)
{
    ck_fact_req_boot.len = q->len;
    for (unsigned i = 0; i < CK_FACT_REQ_TEXT_MAX; i++)
        ck_fact_req_boot.text[i] = q->text[i];
    ck_fact_req_boot.state = CK_FACT_REQ_FOUND;
}

void ck_fact_req_clear(void)
{
    ck_fact_req_boot.len = 0;
    for (unsigned i = 0; i < CK_FACT_REQ_TEXT_MAX; i++)
        ck_fact_req_boot.text[i] = 0;
    if (ck_fact_req_boot.state == CK_FACT_REQ_FOUND)
        ck_fact_req_boot.state = CK_FACT_REQ_NONE;
}
