/* klog_slot.c -- see klog_slot.h. Pure. */
#include "klog_slot.h"

static int same(const uint8_t *a, const char *b, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        if (a[i] != (uint8_t)b[i])
            return 0;
    return 1;
}

int ck_klog_map_check(const struct ck_klog_map *m, uint64_t last_block, const char **why)
{
    if (!same(m->magic, CK_KLOG_MAP_MAGIC, 8)) {
        *why = "bad map magic";
        return -1;
    }
    if (m->version != CK_KLOG_SLOT_VERSION) {
        *why = "unsupported map version";
        return -1;
    }
    if (m->sector_size != 512u) {
        *why = "sector size not 512";
        return -1;
    }
    if (m->count < CK_KLOG_MIN_SECTORS || m->count > CK_KLOG_MAX_SECTORS) {
        *why = "slot length out of range";
        return -1;
    }
    if (m->lba == 0) { /* sector 0 is the partition table */
        *why = "slot at sector 0";
        return -1;
    }
    if (m->lba > UINT64_MAX - m->count) {
        *why = "slot end overflows";
        return -1;
    }
    if (last_block && m->lba + m->count - 1u > last_block) {
        *why = "slot past the end of the card";
        return -1;
    }
    uint8_t any = 0;
    for (unsigned i = 0; i < 16; i++)
        any |= m->nonce[i];
    if (!any) {
        *why = "zero nonce";
        return -1;
    }
    return 0;
}

int ck_klog_hdr_match(const struct ck_klog_hdr *h, const struct ck_klog_map *m, const char **why)
{
    if (!same(h->magic, CK_KLOG_HDR_MAGIC, 8)) {
        *why = "no slot header at the mapped sector";
        return -1;
    }
    if (h->version != CK_KLOG_SLOT_VERSION) {
        *why = "unsupported slot version";
        return -1;
    }
    for (unsigned i = 0; i < 16; i++)
        if (h->nonce[i] != m->nonce[i]) {
            *why = "slot nonce differs from the map";
            return -1;
        }
    if (h->lba != m->lba || h->count != m->count) {
        *why = "slot position differs from the map";
        return -1;
    }
    return 0;
}

void ck_klog_hdr_written(struct ck_klog_hdr *h, const struct ck_klog_map *m, uint64_t log_len,
                         uint64_t log_total, uint64_t commit, const char *stage)
{
    uint8_t *p = (uint8_t *)h;
    for (unsigned i = 0; i < sizeof *h; i++)
        p[i] = 0;
    for (unsigned i = 0; i < 8; i++)
        h->magic[i] = (uint8_t)CK_KLOG_HDR_MAGIC[i];
    h->version = CK_KLOG_SLOT_VERSION;
    h->state = CK_KLOG_STATE_WRITTEN;
    for (unsigned i = 0; i < 16; i++)
        h->nonce[i] = m->nonce[i];
    h->lba = m->lba;
    h->count = m->count;
    h->log_len = log_len;
    h->log_total = log_total;
    h->commit = commit;
    for (unsigned i = 0; stage && stage[i] && i < sizeof h->stage - 1; i++)
        h->stage[i] = stage[i];
}
