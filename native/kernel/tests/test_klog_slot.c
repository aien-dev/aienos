/* test_klog_slot.c -- core/klog_slot.c: the map check and the header match
 * refuse every way a write could land somewhere it should not. */
#include <string.h>
#include "ck_test.h"
#include "klog_slot.h"

static struct ck_klog_map good_map(void)
{
    struct ck_klog_map m;
    memset(&m, 0, sizeof m);
    memcpy(m.magic, CK_KLOG_MAP_MAGIC, 8);
    m.version = 1;
    m.sector_size = 512;
    m.lba = 123456;
    m.count = 4096;
    for (int i = 0; i < 16; i++)
        m.nonce[i] = (uint8_t)(0xa0 + i);
    return m;
}

static struct ck_klog_hdr empty_hdr(const struct ck_klog_map *m)
{
    struct ck_klog_hdr h;
    memset(&h, 0, sizeof h);
    memcpy(h.magic, CK_KLOG_HDR_MAGIC, 8);
    h.version = 1;
    memcpy(h.nonce, m->nonce, 16);
    h.lba = m->lba;
    h.count = m->count;
    return h;
}

int main(void)
{
    const char *why = 0;
    struct ck_klog_map m = good_map(), b;
    CHECK(ck_klog_map_check(&m, 0, &why) == 0);
    CHECK(ck_klog_map_check(&m, 123456 + 4095, &why) == 0); /* last sector is the card's last */
    CHECK(ck_klog_map_check(&m, 123456 + 4094, &why) == -1 && strstr(why, "past the end"));
    b = m; b.magic[0] = 'X';
    CHECK(ck_klog_map_check(&b, 0, &why) == -1 && strstr(why, "magic"));
    b = m; b.version = 2;
    CHECK(ck_klog_map_check(&b, 0, &why) == -1 && strstr(why, "version"));
    b = m; b.sector_size = 4096;
    CHECK(ck_klog_map_check(&b, 0, &why) == -1 && strstr(why, "sector size"));
    b = m; b.count = 1;
    CHECK(ck_klog_map_check(&b, 0, &why) == -1 && strstr(why, "length"));
    b = m; b.count = CK_KLOG_MAX_SECTORS + 1;
    CHECK(ck_klog_map_check(&b, 0, &why) == -1 && strstr(why, "length"));
    b = m; b.lba = 0;
    CHECK(ck_klog_map_check(&b, 0, &why) == -1 && strstr(why, "sector 0"));
    b = m; b.lba = UINT64_MAX - 10;
    CHECK(ck_klog_map_check(&b, 0, &why) == -1 && strstr(why, "overflows"));
    b = m; memset(b.nonce, 0, 16);
    CHECK(ck_klog_map_check(&b, 0, &why) == -1 && strstr(why, "nonce"));

    struct ck_klog_hdr h = empty_hdr(&m), c;
    CHECK(ck_klog_hdr_match(&h, &m, &why) == 0);
    c = h; c.magic[7] = '2';
    CHECK(ck_klog_hdr_match(&c, &m, &why) == -1 && strstr(why, "no slot header"));
    c = h; c.version = 9;
    CHECK(ck_klog_hdr_match(&c, &m, &why) == -1 && strstr(why, "version"));
    c = h; c.nonce[15] ^= 1; /* another run's slot, or another card */
    CHECK(ck_klog_hdr_match(&c, &m, &why) == -1 && strstr(why, "nonce"));
    c = h; c.lba++; /* this header was copied somewhere else */
    CHECK(ck_klog_hdr_match(&c, &m, &why) == -1 && strstr(why, "position"));
    c = h; c.count--;
    CHECK(ck_klog_hdr_match(&c, &m, &why) == -1 && strstr(why, "position"));
    struct ck_klog_hdr z;
    memset(&z, 0, sizeof z); /* blank sector: a wrong LBA on a fresh card */
    CHECK(ck_klog_hdr_match(&z, &m, &why) == -1);

    /* The WRITTEN header still matches the map (a rerun can find it). */
    struct ck_klog_hdr w;
    memset(&w, 0x5a, sizeof w);
    ck_klog_hdr_written(&w, &m, 1000, 2000, 0x1234, "final_stage_name_that_is_far_too_long_to_fit");
    CHECK(ck_klog_hdr_match(&w, &m, &why) == 0);
    CHECK(w.state == CK_KLOG_STATE_WRITTEN && w.log_len == 1000 && w.log_total == 2000 && w.commit == 0x1234);
    CHECK(w.stage[sizeof w.stage - 1] == 0 && strncmp(w.stage, "final_stage", 11) == 0);
    CHECK(w.pad[0] == 0 && w.pad[sizeof w.pad - 1] == 0);
    CHECK(ck_klog_slot_bytes(&m) == 4095u * 512u);
    return ck_t_verdict("test_klog_slot");
}
