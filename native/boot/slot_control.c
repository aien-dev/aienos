/* slot_control.c -- see slot_control.h. */
#include "slot_control.h"

static struct ck_slot_control g_back;

int ck_slot_control_commit(ts_region *r, const struct ck_slot_control *c, uint64_t *seq_out)
{
    uint64_t seq = 0;
    int rc = ts_commit(r, (const uint8_t *)c);
    if (rc == TS_OK)
        rc = ts_recover(r, (uint8_t *)&g_back, &seq, 0);
    if (rc == TS_OK) {
        const uint8_t *a = (const uint8_t *)&g_back, *b = (const uint8_t *)c;
        uint8_t d = 0;
        for (unsigned i = 0; i < sizeof g_back; i++)
            d |= (uint8_t)(a[i] ^ b[i]);
        if (d)
            rc = TS_CORRUPT;
    }
    if (seq_out)
        *seq_out = rc == TS_OK ? seq : 0;
    return rc;
}
