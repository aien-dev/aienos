/*
 * store_disk.c -- ADR 0015 geometry adapter (device.rs twin): 4096-byte
 * Store units over a native/disk disk_dev with 512- or 4096-byte blocks.
 * Whole units only; never read-modify-write.
 */
#include "store_engine.h"

static int sd_read(void *ctx, uint64_t unit, uint8_t out[SV1_UNIT])
{
    st_disk *a = ctx;
    if (unit >= a->region_units)
        return -1;
    return disk_read(a->disk, a->base_lba + unit * a->blocks_per_unit, a->blocks_per_unit, out)
               ? -1
               : 0;
}

static int sd_write(void *ctx, uint64_t unit, const uint8_t in[SV1_UNIT])
{
    st_disk *a = ctx;
    if (unit >= a->region_units)
        return -1;
    return disk_write(a->disk, a->base_lba + unit * a->blocks_per_unit, a->blocks_per_unit, in)
               ? -1
               : 0;
}

static int sd_flush(void *ctx)
{
    st_disk *a = ctx;
    return disk_flush(a->disk) ? -1 : 0;
}

int st_disk_bind(st_disk *a, const disk_dev *disk, uint64_t base_lba, uint64_t region_units,
                 st_dev *out)
{
    if (!a || !disk || !out)
        return ST_E_ARG;
    if (disk_check(disk))
        return ST_E_GEOMETRY;
    uint32_t bpu;
    if (disk->block_size == 512)
        bpu = 8;
    else if (disk->block_size == 4096)
        bpu = 1;
    else
        return ST_E_GEOMETRY; /* GUARD:adapter-block-size */
    if (base_lba % bpu) return ST_E_GEOMETRY; /* GUARD:adapter-alignment */
    if (base_lba >= disk->block_count)
        return ST_E_GEOMETRY;
    uint64_t max_units = (disk->block_count - base_lba) / bpu;
    if (region_units == 0)
        region_units = max_units;
    if (region_units > max_units) return ST_E_GEOMETRY; /* GUARD:adapter-region-end */
    a->disk = disk;
    a->base_lba = base_lba;
    a->blocks_per_unit = bpu;
    a->region_units = region_units;
    out->ctx = a;
    out->region_units = region_units;
    out->read_unit = sd_read;
    out->write_unit = sd_write;
    out->flush = sd_flush;
    return 0;
}
