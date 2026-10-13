/* Native persistent-KV slab format, header-last slot state machine, and
 * bounded header-only recovery (aienos#367 cut N2).
 *
 * Red-phase stub: every entry point returns KV_E_ARG so the red test suite
 * compiles and fails before the implementation lands.
 */
#include "kv_slab.h"

int kv_disk_bind(kv_disk *out,
                 const disk_dev *disk,
                 uint64_t base_lba,
                 uint64_t units,
                 kv_lba_range store_range,
                 kv_lba_range anchor_range)
{
    (void)out;
    (void)disk;
    (void)base_lba;
    (void)units;
    (void)store_range;
    (void)anchor_range;
    return KV_E_ARG;
}

int kv_disk_read_units(const kv_disk *kd, uint64_t unit_offset, uint32_t unit_count, uint8_t *out)
{
    (void)kd;
    (void)unit_offset;
    (void)unit_count;
    (void)out;
    return KV_E_ARG;
}

int kv_disk_write_units(const kv_disk *kd, uint64_t unit_offset, uint32_t unit_count, const uint8_t *in)
{
    (void)kd;
    (void)unit_offset;
    (void)unit_count;
    (void)in;
    return KV_E_ARG;
}

int kv_disk_flush(const kv_disk *kd)
{
    (void)kd;
    return KV_E_ARG;
}

int kv_slot_payload_geometry(uint64_t payload_len, kv_slot_payload_geom *out)
{
    (void)payload_len;
    (void)out;
    return KV_E_ARG;
}

int kv_slab_init(kv_slab *slab,
                 const kv_disk *dev,
                 uint32_t slot_count,
                 uint32_t slot_units,
                 const uint8_t local_namespace[KV_HASH_LEN],
                 kv_slab_entry *entries,
                 uint8_t unit_scratch[KV_SLOT_UNIT])
{
    (void)slab;
    (void)dev;
    (void)slot_count;
    (void)slot_units;
    (void)local_namespace;
    (void)entries;
    (void)unit_scratch;
    return KV_E_ARG;
}

int kv_slab_format(kv_slab *slab)
{
    (void)slab;
    return KV_E_ARG;
}

int kv_slab_recover(kv_slab *slab)
{
    (void)slab;
    return KV_E_ARG;
}

int kv_slab_lookup(const kv_slab *slab, const uint8_t chunk_key[KV_HASH_LEN], uint32_t *slot_out)
{
    (void)slab;
    (void)chunk_key;
    (void)slot_out;
    return KV_E_ARG;
}

int kv_slot_write_begin(kv_slot_writer *w,
                        kv_slab *slab,
                        uint32_t slot_index,
                        const kv_slot_header *hdr,
                        const uint8_t *sealed_body,
                        size_t sealed_body_len)
{
    (void)w;
    (void)slab;
    (void)slot_index;
    (void)hdr;
    (void)sealed_body;
    (void)sealed_body_len;
    return KV_E_ARG;
}

int kv_slot_write_step(kv_slot_writer *w)
{
    (void)w;
    return KV_E_ARG;
}

int kv_slot_write_cancel(kv_slot_writer *w)
{
    (void)w;
    return KV_E_ARG;
}

int kv_slab_write_slot(kv_slab *slab,
                       uint32_t slot_index,
                       const kv_slot_header *hdr,
                       const uint8_t *sealed_body,
                       size_t sealed_body_len)
{
    (void)slab;
    (void)slot_index;
    (void)hdr;
    (void)sealed_body;
    (void)sealed_body_len;
    return KV_E_ARG;
}

int kv_slab_read_slot(kv_slab *slab,
                      uint32_t slot_index,
                      kv_slot_header *hdr_out,
                      uint8_t *sealed_body_out,
                      size_t body_cap,
                      size_t *sealed_len_out)
{
    (void)slab;
    (void)slot_index;
    (void)hdr_out;
    (void)sealed_body_out;
    (void)body_cap;
    (void)sealed_len_out;
    return KV_E_ARG;
}
