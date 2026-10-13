/* pi5_store_locate.c -- see pi5_store_locate.h. Hosted. */
#include <stdio.h>
#include <string.h>
#include "ck.h"
#include "disk.h"
#include "disk_file.h"
#include "disk_layout.h"
#include "store_v1.h"
#include "store_engine.h"
#include "pi5_store_locate.h"
#include "../core/pi5_marker.h"

static st_workspace g_ws;
static st_store g_st;

static int fail(char *err, size_t n, const char *msg)
{
    if (err && n) snprintf(err, n, "%s", msg);
    return -1;
}

int ck_pi5_locate_keyslot(const char *path, ck_pi5_ksm_loc *out, char *err, size_t errn)
{
    disk_file f;
    disk_dev d;
    memset(out, 0, sizeof *out);
    if (disk_file_open(&f, &d, path, 512, 0, 0)) return fail(err, errn, "cannot open the partition image");
    const uint64_t bpu = CK_LAYOUT_UNIT / DISK_SECTOR_BYTES;
    if (d.block_count < CK_PI5_MARKER_SECS + bpu) {
        disk_file_close(&f);
        return fail(err, errn, "image too small");
    }
    /* the Store view: the partition minus the marker tail, in whole units (ck_pi5_store_view) */
    uint64_t store_blocks = (d.block_count - CK_PI5_MARKER_SECS) / bpu * bpu;
    disk_dev sv = d;
    sv.block_count = store_blocks;
    uint64_t base_lba = (uint64_t)CK_LAYOUT_ANCHOR_UNITS * bpu;
    uint64_t units = store_blocks / bpu - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS;
    st_disk sd;
    st_dev sdev;
    int rc = st_disk_bind(&sd, &sv, base_lba, units, &sdev);
    if (rc) { disk_file_close(&f); return fail(err, errn, "st_disk_bind refused the geometry"); }
    rc = st_open(&g_st, &sdev, &g_ws);
    if (rc) { disk_file_close(&f); return fail(err, errn, "st_open (unkeyed) refused: not an intact Store"); }
    uint32_t n = 0;
    const sv1_entry *e = st_catalog(&g_st, &n);
    int at = -1;
    for (uint32_t i = 0; i < n; i++)
        if (e[i].kind == 21 && e[i].version == 1) {
            out->keyslot_objects++;
            at = (int)i;
        }
    if (out->keyslot_objects != 1) {
        disk_file_close(&f);
        return fail(err, errn, "need exactly one KeySlotManifest object in the catalog");
    }
    out->first_unit = e[at].first_unit;
    out->byte_length = e[at].byte_length;
    out->part_sector = base_lba + e[at].first_unit * bpu;
    out->part_byte_offset = out->part_sector * DISK_SECTOR_BYTES;
    out->wrapped_kvol_offset = out->part_byte_offset + CK_PI5_KSM_RECOVERY_SLOT_OFF + CK_PI5_KSM_WRAPPED_KVOL_OFF;
    out->wrap_tag_offset = out->part_byte_offset + CK_PI5_KSM_RECOVERY_SLOT_OFF + CK_PI5_KSM_WRAP_TAG_OFF;
    /* read the raw sector back: it must start with the manifest magic "AIENKSL1" (m5_ksm_encode) */
    uint8_t raw[512] __attribute__((aligned(64)));
    rc = disk_read(&d, out->part_sector, 1, raw);
    disk_file_close(&f);
    if (rc != DISK_OK) return fail(err, errn, "raw read of the manifest sector failed");
    if (memcmp(raw, "AIENKSL1", 8) != 0) return fail(err, errn, "raw sector at the located place is not a KeySlotManifest");
    if (out->byte_length != 640) return fail(err, errn, "manifest length is not the 640-byte raw-secret profile");
    return 0;
}
