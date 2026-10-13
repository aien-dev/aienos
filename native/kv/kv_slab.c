/* Native persistent-KV slab format, header-last slot state machine, and
 * bounded header-only recovery (sovereign-core ADR 0003 sections 2.5, 3.3,
 * 3.4, 4.2, 9; aienos#367 cut N2).
 *
 * C11, freestanding-compatible: no heap, no clock, no libc I/O.
 */
#include "kv_slab.h"
#include <string.h>

static int range_valid(kv_lba_range r, uint64_t disk_blocks)
{
    if (r.block_count == 0u) return 0;
    if (r.base_lba >= disk_blocks) return 0;
    if (r.block_count > disk_blocks - r.base_lba) return 0;
    return 1;
}

static int ranges_overlap(kv_lba_range a, kv_lba_range b)
{
    uint64_t a_end = a.base_lba + a.block_count;
    uint64_t b_end = b.base_lba + b.block_count;
    return a.base_lba < b_end && b.base_lba < a_end;
}

int kv_disk_bind(kv_disk *out,
                 const disk_dev *disk,
                 uint64_t base_lba,
                 uint64_t units,
                 kv_lba_range store_range,
                 kv_lba_range anchor_range)
{
    if (!out || !disk) return KV_E_ARG;
    memset(out, 0, sizeof *out);
    if (disk_check(disk) != DISK_OK) return KV_E_SLAB_GEOMETRY; /* GUARD:slab-disk-check */
    uint32_t bpu = KV_SLOT_UNIT / disk->block_size;
    if (disk->max_blocks_per_io < bpu) return KV_E_SLAB_GEOMETRY; /* GUARD:slab-max-blocks-per-io */
    if (units == 0u || (base_lba % bpu) != 0u) return KV_E_SLAB_GEOMETRY; /* GUARD:slab-base-align */
    if (base_lba >= disk->block_count || units > (disk->block_count - base_lba) / bpu) return KV_E_SLAB_GEOMETRY; /* GUARD:slab-bounds-disk */
    if (!range_valid(store_range, disk->block_count)) return KV_E_SLAB_GEOMETRY; /* GUARD:slab-store-range-valid */
    if (!range_valid(anchor_range, disk->block_count)) return KV_E_SLAB_GEOMETRY; /* GUARD:slab-anchor-range-valid */

    kv_lba_range slab_range = { base_lba, units * (uint64_t)bpu };
    if (ranges_overlap(slab_range, store_range)) return KV_E_SLAB_OVERLAP; /* GUARD:slab-overlap-store */
    if (ranges_overlap(slab_range, anchor_range)) return KV_E_SLAB_OVERLAP; /* GUARD:slab-overlap-anchor */
    if (ranges_overlap(store_range, anchor_range)) return KV_E_SLAB_OVERLAP; /* GUARD:slab-overlap-peers */

    out->disk = disk;
    out->base_lba = base_lba;
    out->blocks_per_unit = bpu;
    out->region_units = units;
    return KV_OK;
}

int kv_disk_read_units(const kv_disk *kd, uint64_t unit_offset, uint32_t unit_count, uint8_t *out)
{
    if (!kd || !kd->disk || (!out && unit_count > 0u)) return KV_E_ARG;
    if (unit_offset > kd->region_units || (uint64_t)unit_count > kd->region_units - unit_offset)
        return KV_E_SLAB_BOUNDS;
    uint32_t max_u = kd->disk->max_blocks_per_io / kd->blocks_per_unit;
    if (max_u == 0u) return KV_E_SLAB_GEOMETRY;

    uint32_t done = 0u;
    while (done < unit_count) {
        uint32_t step = unit_count - done;
        if (step > max_u) step = max_u;
        uint64_t lba = kd->base_lba + (unit_offset + done) * (uint64_t)kd->blocks_per_unit;
        if (disk_read(kd->disk, lba, step * kd->blocks_per_unit, out + (size_t)done * KV_SLOT_UNIT) != DISK_OK)
            return KV_E_IO;
        done += step;
    }
    return KV_OK;
}

int kv_disk_write_units(const kv_disk *kd, uint64_t unit_offset, uint32_t unit_count, const uint8_t *in)
{
    if (!kd || !kd->disk || (!in && unit_count > 0u)) return KV_E_ARG;
    if (unit_offset > kd->region_units || (uint64_t)unit_count > kd->region_units - unit_offset)
        return KV_E_SLAB_BOUNDS;
    uint32_t max_u = kd->disk->max_blocks_per_io / kd->blocks_per_unit;
    if (max_u == 0u) return KV_E_SLAB_GEOMETRY;

    uint32_t done = 0u;
    while (done < unit_count) {
        uint32_t step = unit_count - done;
        if (step > max_u) step = max_u;
        uint64_t lba = kd->base_lba + (unit_offset + done) * (uint64_t)kd->blocks_per_unit;
        if (disk_write(kd->disk, lba, step * kd->blocks_per_unit, in + (size_t)done * KV_SLOT_UNIT) != DISK_OK)
            return KV_E_IO;
        done += step;
    }
    return KV_OK;
}

int kv_disk_flush(const kv_disk *kd)
{
    if (!kd || !kd->disk) return KV_E_ARG;
    if (disk_flush(kd->disk) != DISK_OK) return KV_E_IO;
    return KV_OK;
}

int kv_slot_payload_geometry(uint64_t payload_len, kv_slot_payload_geom *out)
{
    if (!out) return KV_E_ARG;
    memset(out, 0, sizeof *out);
    uint32_t su = 0u, env_len = 0u;
    int rc = kv_slot_geometry(payload_len, &su, &env_len);
    if (rc != KV_OK) return rc;

    uint64_t sealed_len = (uint64_t)env_len - 64u;
    uint32_t rem = (uint32_t)(sealed_len % KV_SLOT_UNIT);
    uint32_t last_bytes = (rem == 0u) ? KV_SLOT_UNIT : rem;
    out->sealed_len = sealed_len;
    out->sealed_units = su;
    out->envelope_len = env_len;
    out->last_unit_bytes = last_bytes;
    out->last_unit_pad = KV_SLOT_UNIT - last_bytes;
    return KV_OK;
}

static void slab_reset_state(kv_slab *slab)
{
    memset(slab->entries, 0, (size_t)slab->slot_count * sizeof(kv_slab_entry));
    slab->used_bytes = 0u;
    slab->payload_bytes = 0u;
    slab->next_incarnation = 1u;
    slab->valid_slots = 0u;
    slab->foreign_slots = 0u;
    slab->empty_slots = slab->slot_count;
    slab->fail_stop = 0u;
}

static void slab_evict_slot_from_index(kv_slab *slab, uint32_t slot_index)
{
    kv_slab_entry *e = &slab->entries[slot_index];
    if (!e->valid) return;
    uint64_t phys = (uint64_t)slab->slot_units * KV_SLOT_UNIT;
    if (slab->used_bytes >= phys) slab->used_bytes -= phys;
    if (slab->payload_bytes >= e->hdr.rec.chunk.payload_len)
        slab->payload_bytes -= e->hdr.rec.chunk.payload_len;
    if (slab->valid_slots > 0u) slab->valid_slots--;
    if (e->foreign_namespace && slab->foreign_slots > 0u) slab->foreign_slots--;
    slab->empty_slots = slab->slot_count - slab->valid_slots;
    memset(e, 0, sizeof *e);
}

static void slab_record_slot_in_index(kv_slab *slab, uint32_t slot_index, const kv_slot_header *hdr)
{
    slab_evict_slot_from_index(slab, slot_index);
    kv_slab_entry *e = &slab->entries[slot_index];
    e->valid = 1u;
    e->hdr = *hdr;
    e->foreign_namespace = (memcmp(hdr->rec.chunk.namespace_id, slab->local_namespace, KV_HASH_LEN) != 0) ? 1u : 0u;
    slab->valid_slots++;
    if (e->foreign_namespace) slab->foreign_slots++;
    slab->empty_slots = slab->slot_count - slab->valid_slots;
    /* ADR 4.2: used_bytes counts slot_units * 4096 physical bytes for every
     * valid slot regardless of namespace. */
    slab->used_bytes += (uint64_t)slab->slot_units * KV_SLOT_UNIT; /* GUARD:slab-used-bytes-add */
    slab->payload_bytes += hdr->rec.chunk.payload_len;
    if (hdr->slot_incarnation >= slab->next_incarnation && hdr->slot_incarnation < UINT64_MAX)
        slab->next_incarnation = hdr->slot_incarnation + 1u;
}

int kv_slab_init(kv_slab *slab,
                 const kv_disk *dev,
                 uint32_t slot_count,
                 uint32_t slot_units,
                 const uint8_t local_namespace[KV_HASH_LEN],
                 kv_slab_entry *entries,
                 uint8_t unit_scratch[KV_SLOT_UNIT])
{
    if (!slab || !dev || !dev->disk || !local_namespace || !entries || !unit_scratch) return KV_E_ARG;
    if (slot_count == 0u || slot_units < 2u || slot_units > 1u + KV_MAX_SEGMENTS) return KV_E_SLAB_GEOMETRY;
    if ((uint64_t)slot_count * (uint64_t)slot_units > dev->region_units) return KV_E_SLAB_GEOMETRY;

    memset(slab, 0, sizeof *slab);
    slab->dev = *dev;
    slab->slot_count = slot_count;
    slab->slot_units = slot_units;
    memcpy(slab->local_namespace, local_namespace, KV_HASH_LEN);
    slab->entries = entries;
    slab->unit_scratch = unit_scratch;
    slab_reset_state(slab);
    return KV_OK;
}

int kv_slab_format(kv_slab *slab)
{
    if (!slab || !slab->entries || !slab->unit_scratch) return KV_E_ARG;
    slab_reset_state(slab);
    memset(slab->unit_scratch, 0, KV_SLOT_UNIT);
    for (uint32_t s = 0u; s < slab->slot_count; s++) {
        uint64_t hdr_off = (uint64_t)s * slab->slot_units;
        if (kv_disk_write_units(&slab->dev, hdr_off, 1u, slab->unit_scratch) != KV_OK) {
            slab->fail_stop = 1u;
            return KV_E_IO;
        }
    }
    if (kv_disk_flush(&slab->dev) != KV_OK) {
        slab->fail_stop = 1u;
        return KV_E_IO;
    }
    return KV_OK;
}

int kv_slab_recover(kv_slab *slab)
{
    if (!slab || !slab->entries || !slab->unit_scratch) return KV_E_ARG;
    slab_reset_state(slab);

    for (uint32_t s = 0u; s < slab->slot_count; s++) {
        uint64_t hdr_off = (uint64_t)s * slab->slot_units;
        int rc = kv_disk_read_units(&slab->dev, hdr_off, 1u, slab->unit_scratch);
        if (rc != KV_OK) {
            slab->fail_stop = 1u;
            return rc;
        }
        kv_slot_header hdr;
        rc = kv_slot_validate(slab->unit_scratch, KV_SLOT_UNIT, s, NULL, &hdr);
        if (rc != KV_OK) continue; /* GUARD:slab-recover-validate */
        if (hdr.slot_incarnation == 0u) continue;
        if (hdr.sealed_units > slab->slot_units - 1u) continue; /* GUARD:slab-recover-sealed-fit */
        slab_record_slot_in_index(slab, s, &hdr);
    }
    return KV_OK;
}

int kv_slab_lookup(const kv_slab *slab, const uint8_t chunk_key[KV_HASH_LEN], uint32_t *slot_out)
{
    if (!slab || !slab->entries || !chunk_key || !slot_out) return KV_E_ARG;
    int found = 0;
    uint32_t best_slot = 0u;
    uint64_t best_inc = 0u;

    for (uint32_t s = 0u; s < slab->slot_count; s++) {
        const kv_slab_entry *e = &slab->entries[s];
        if (!e->valid) continue; /* GUARD:slab-lookup-valid */
        if (e->foreign_namespace) continue; /* GUARD:slab-lookup-foreign */
        if (memcmp(e->hdr.rec.chunk.chunk_key, chunk_key, KV_HASH_LEN) != 0) continue; /* GUARD:slab-lookup-key */
        if (!found || e->hdr.slot_incarnation > best_inc) {
            found = 1;
            best_slot = s;
            best_inc = e->hdr.slot_incarnation;
        }
    }
    if (!found) return KV_E_EMPTY_SLOT;
    *slot_out = best_slot;
    return KV_OK;
}

int kv_slot_write_begin(kv_slot_writer *w,
                        kv_slab *slab,
                        uint32_t slot_index,
                        const kv_slot_header *hdr,
                        const uint8_t *sealed_body,
                        size_t sealed_body_len)
{
    if (!w || !slab || !slab->entries || !slab->unit_scratch || !hdr || !sealed_body) return KV_E_ARG;
    memset(w, 0, sizeof *w);
    if (slab->fail_stop) return KV_E_IO; /* GUARD:slab-begin-failstop */
    if (slot_index >= slab->slot_count) return KV_E_SLOT_INDEX;
    if (hdr->slot_index != slot_index) return KV_E_SLOT_INDEX;
    if (hdr->slot_incarnation == 0u) return KV_E_SLOT_BOUNDS;

    int rc = kv_slot_payload_geometry(hdr->rec.chunk.payload_len, &w->geom);
    if (rc != KV_OK) return rc;
    if (hdr->sealed_units != w->geom.sealed_units || hdr->envelope_len != w->geom.envelope_len)
        return KV_E_SLOT_BOUNDS;
    if (w->geom.sealed_units > slab->slot_units - 1u) return KV_E_SLOT_BOUNDS;

    size_t full_units_bytes = (size_t)w->geom.sealed_units * KV_SLOT_UNIT;
    if (sealed_body_len != (size_t)w->geom.sealed_len && sealed_body_len != full_units_bytes)
        return KV_E_SLOT_BOUNDS;

    rc = kv_slot_encode(hdr, w->hdr_unit);
    if (rc != KV_OK) return rc;

    w->slab = slab;
    w->slot_index = slot_index;
    w->hdr = *hdr;
    w->sealed_body = sealed_body;
    w->sealed_body_len = sealed_body_len;
    w->payload_units_done = 0u;
    w->stage = KV_STAGE_SUBMITTED;
    w->phase = KV_SLOT_PHASE_ZERO_HDR;
    return KV_OK;
}

int kv_slot_write_step(kv_slot_writer *w)
{
    if (!w || !w->slab) return KV_E_ARG;
    kv_slab *slab = w->slab;
    if (slab->fail_stop) {
        w->phase = KV_SLOT_PHASE_FAILED;
        return KV_E_IO;
    }
    uint64_t slot_base = (uint64_t)w->slot_index * slab->slot_units;

    switch (w->phase) {
    case KV_SLOT_PHASE_ZERO_HDR: {
        slab_evict_slot_from_index(slab, w->slot_index);
        memset(slab->unit_scratch, 0, KV_SLOT_UNIT);
        int rc = KV_OK;
        rc = kv_disk_write_units(&slab->dev, slot_base, 1u, slab->unit_scratch); /* GUARD:slab-zero-hdr-write */
        if (rc != KV_OK) {
            w->phase = KV_SLOT_PHASE_FAILED;
            slab->fail_stop = 1u;
            return KV_E_IO;
        }
        w->phase = KV_SLOT_PHASE_FLUSH_ZERO;
        return KV_OK;
    }
    case KV_SLOT_PHASE_FLUSH_ZERO: {
        int rc = kv_disk_flush(&slab->dev);
        if (rc != KV_OK) { slab->fail_stop = 1u; w->phase = KV_SLOT_PHASE_FAILED; return KV_E_IO; } /* GUARD:slab-flush-zero */
        w->phase = KV_SLOT_PHASE_WRITE_PAYLOAD;
        return KV_OK;
    }
    case KV_SLOT_PHASE_WRITE_PAYLOAD: {
        uint32_t total_u = w->geom.sealed_units;
        uint32_t u = w->payload_units_done;
        if (u >= total_u) {
            w->phase = KV_SLOT_PHASE_FLUSH_PAYLOAD;
            return KV_OK;
        }
        uint32_t max_u = slab->dev.disk->max_blocks_per_io / slab->dev.blocks_per_unit;
        if (max_u == 0u) max_u = 1u;

        /* Full 4096-byte units before any padded tail unit can be written in one command. */
        uint32_t full_limit = (w->geom.last_unit_pad > 0u && w->sealed_body_len == (size_t)w->geom.sealed_len)
                              ? (total_u - 1u) : total_u;
        int rc = KV_OK;
        if (u < full_limit) {
            uint32_t count = full_limit - u;
            if (count > max_u) count = max_u;
            rc = kv_disk_write_units(&slab->dev, slot_base + 1u + u, count,
                                     w->sealed_body + (size_t)u * KV_SLOT_UNIT);
            if (rc == KV_OK) w->payload_units_done += count;
        } else {
            /* Final partial unit: copy last_unit_bytes and zero-pad the remainder. */
            memset(slab->unit_scratch, 0, KV_SLOT_UNIT);
            memcpy(slab->unit_scratch, w->sealed_body + (size_t)u * KV_SLOT_UNIT, w->geom.last_unit_bytes);
            rc = kv_disk_write_units(&slab->dev, slot_base + 1u + u, 1u, slab->unit_scratch);
            if (rc == KV_OK) w->payload_units_done += 1u;
        }
        if (rc != KV_OK) {
            w->phase = KV_SLOT_PHASE_FAILED;
            slab->fail_stop = 1u;
            return KV_E_IO;
        }
        if (w->payload_units_done >= total_u) {
            w->phase = KV_SLOT_PHASE_FLUSH_PAYLOAD;
        }
        return KV_OK;
    }
    case KV_SLOT_PHASE_FLUSH_PAYLOAD: {
        int rc = kv_disk_flush(&slab->dev);
        if (rc != KV_OK) { slab->fail_stop = 1u; w->phase = KV_SLOT_PHASE_FAILED; return KV_E_IO; } /* GUARD:slab-flush-payload */
        w->stage = KV_STAGE_COMPLETED; /* GUARD:slab-stage-completed */
        w->phase = KV_SLOT_PHASE_WRITE_HDR;
        return KV_OK;
    }
    case KV_SLOT_PHASE_WRITE_HDR: {
        int rc = KV_OK;
        rc = kv_disk_write_units(&slab->dev, slot_base, 1u, w->hdr_unit); /* GUARD:slab-write-hdr */
        if (rc != KV_OK) {
            w->phase = KV_SLOT_PHASE_FAILED;
            slab->fail_stop = 1u;
            return KV_E_IO;
        }
        slab_record_slot_in_index(slab, w->slot_index, &w->hdr); /* GUARD:slab-publish-index */
        w->stage = KV_STAGE_PUBLISHED; /* GUARD:slab-stage-published */
        w->phase = KV_SLOT_PHASE_FLUSH_HDR;
        return KV_OK;
    }
    case KV_SLOT_PHASE_FLUSH_HDR: {
        int rc = kv_disk_flush(&slab->dev);
        if (rc != KV_OK) { slab->fail_stop = 1u; w->phase = KV_SLOT_PHASE_FAILED; return KV_E_IO; } /* GUARD:slab-flush-hdr */
        w->stage = KV_STAGE_DURABLE; /* GUARD:slab-stage-durable */
        w->phase = KV_SLOT_PHASE_DONE;
        return KV_OK;
    }
    case KV_SLOT_PHASE_DONE:
        return KV_OK;
    case KV_SLOT_PHASE_CANCELLED:
    case KV_SLOT_PHASE_FAILED:
    default:
        return KV_E_IO;
    }
}

int kv_slot_write_cancel(kv_slot_writer *w)
{
    if (!w || !w->slab) return KV_E_ARG;
    if (w->stage >= KV_STAGE_PUBLISHED || w->phase == KV_SLOT_PHASE_DONE)
        return KV_E_LATE_CANCEL; /* GUARD:slab-late-cancel */
    if (w->phase == KV_SLOT_PHASE_CANCELLED) return KV_OK;

    if (w->phase == KV_SLOT_PHASE_FLUSH_ZERO) {
        if (kv_disk_flush(&w->slab->dev) != KV_OK) {
            w->slab->fail_stop = 1u;
            w->phase = KV_SLOT_PHASE_FAILED;
            return KV_E_IO;
        }
    }
    w->phase = KV_SLOT_PHASE_CANCELLED;
    return KV_OK;
}

int kv_slab_write_slot(kv_slab *slab,
                       uint32_t slot_index,
                       const kv_slot_header *hdr,
                       const uint8_t *sealed_body,
                       size_t sealed_body_len)
{
    kv_slot_writer w;
    int rc = kv_slot_write_begin(&w, slab, slot_index, hdr, sealed_body, sealed_body_len);
    if (rc != KV_OK) return rc;
    while (w.phase != KV_SLOT_PHASE_DONE) {
        rc = kv_slot_write_step(&w);
        if (rc != KV_OK) return rc;
    }
    return KV_OK;
}

int kv_slab_read_slot(kv_slab *slab,
                      uint32_t slot_index,
                      kv_slot_header *hdr_out,
                      uint8_t *sealed_body_out,
                      size_t body_cap,
                      size_t *sealed_len_out)
{
    if (sealed_len_out) *sealed_len_out = 0u;
    if (!slab || !slab->entries || !slab->unit_scratch || !hdr_out || !sealed_body_out)
        return KV_E_ARG;
    if (slot_index >= slab->slot_count) return KV_E_SLOT_INDEX;

    uint64_t slot_base = (uint64_t)slot_index * slab->slot_units;
    int rc = kv_disk_read_units(&slab->dev, slot_base, 1u, slab->unit_scratch);
    if (rc != KV_OK) return rc;

    kv_slot_header hdr;
    rc = kv_slot_validate(slab->unit_scratch, KV_SLOT_UNIT, slot_index, NULL, &hdr);
    if (rc != KV_OK) return rc;
    if (hdr.slot_incarnation == 0u) return KV_E_SLOT_BOUNDS;
    if (hdr.sealed_units > slab->slot_units - 1u) return KV_E_SLOT_BOUNDS;

    kv_slot_payload_geom geom;
    rc = kv_slot_payload_geometry(hdr.rec.chunk.payload_len, &geom);
    if (rc != KV_OK) return rc;
    if (body_cap < (size_t)geom.sealed_len) return KV_E_TRUNCATED;

    uint32_t full_units = (geom.last_unit_pad > 0u) ? (geom.sealed_units - 1u) : geom.sealed_units;
    if (full_units > 0u) {
        rc = kv_disk_read_units(&slab->dev, slot_base + 1u, full_units, sealed_body_out);
        if (rc != KV_OK) return rc;
    }
    if (geom.last_unit_pad > 0u) {
        rc = kv_disk_read_units(&slab->dev, slot_base + 1u + full_units, 1u, slab->unit_scratch);
        if (rc != KV_OK) return rc;
        uint8_t pad_or = 0u;
        for (uint32_t i = geom.last_unit_bytes; i < KV_SLOT_UNIT; i++) {
            pad_or |= slab->unit_scratch[i];
        }
        if (pad_or != 0u) return KV_E_SLOT_PADDING; /* GUARD:slab-read-tail-padding */
        memcpy(sealed_body_out + (size_t)full_units * KV_SLOT_UNIT,
               slab->unit_scratch, geom.last_unit_bytes);
    }

    *hdr_out = hdr;
    if (sealed_len_out) *sealed_len_out = (size_t)geom.sealed_len;
    return KV_OK;
}
