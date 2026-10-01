/* File-backed test rig for the sealed store: one disk_file device holding a
 * 4-unit torn_slot anchor region at LBA 0 and a 64-unit Store region after
 * it. Hosted test code only. */
#ifndef STORE_RIG_H
#define STORE_RIG_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "disk_file.h"
#include "store_sealed.h"

#define RIG_ANCHOR_UNITS 4u
#define RIG_STORE_UNITS 64u
#define RIG_TOTAL_UNITS (RIG_ANCHOR_UNITS + RIG_STORE_UNITS)
#define RIG_BYTES ((size_t)RIG_TOTAL_UNITS * 4096u)

typedef struct {
    disk_file f;
    disk_dev d;
    st_disk sd;
    st_dev sdev;
    ts_device tdev;
    uint32_t bs, bpu;
} rig;

static inline int rig_open(rig *r, const char *path, uint32_t bs, int create)
{
    memset(r, 0, sizeof *r);
    r->bs = bs;
    r->bpu = 4096u / bs;
    if (create) unlink(path);
    if (disk_file_open(&r->f, &r->d, path, bs, (uint64_t)RIG_TOTAL_UNITS * r->bpu, create) != 0) return -1;
    if (st_disk_bind(&r->sd, &r->d, (uint64_t)RIG_ANCHOR_UNITS * r->bpu, RIG_STORE_UNITS, &r->sdev) != 0) {
        disk_file_close(&r->f);
        return -1;
    }
    ss_ts_device(&r->d, &r->tdev);
    return 0;
}
static inline void rig_close(rig *r) { disk_file_close(&r->f); }

static inline int file_load(const char *path, uint8_t *buf, size_t n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}
static inline int file_save(const char *path, const uint8_t *buf, size_t n)
{
    FILE *f = fopen(path, "r+b");
    if (!f) f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = fwrite(buf, 1, n, f);
    fclose(f);
    return put == n ? 0 : -1;
}

static inline void rig_keys(uint8_t cls, uint8_t seed, ss_keys *k)
{
    uint8_t kvol[32];
    memset(kvol, seed, 32);
    m5_subkeys sk;
    m5_derive_subkeys(kvol, cls, 0, &sk);
    memset(k, 0, sizeof *k);
    k->identity_class = cls;
    k->key_generation = 1;
    memcpy(k->k_root_auth, sk.k_root_auth, 32);
    memcpy(k->k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);
}

static const uint8_t RIG_UUID[16] = {0x5e, 0xa1, 0xed, 0x00, 0x11, 0x22, 0x33, 0x44,
                                     0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc};
#endif
