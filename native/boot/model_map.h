/* model_map.h -- MODEL.MAP: where the yardstick model's bytes live on the
 * boot disk, so the UEFI boot stub can read them through the firmware's own
 * Block I/O driver before ExitBootServices (aienos#34 lane 6, hardware model
 * ingest). Shared by the stub (native/boot/efi_model.c), the kernel's
 * handoff checks and the hosted map tool (native/kernel/tools/ck_model_map.c).
 *
 * The file is exactly 4096 bytes, little endian, at \EFI\AIENOS\MODEL.MAP on
 * the boot volume (the ESP the stub was loaded from). It names the whole disk
 * by its GPT disk GUID (header LBA 1, bytes 56..71, raw on-disk order) and
 * lists the model's extents as absolute LBAs of that disk, in FILE order
 * (extent 0 holds byte 0 of the model). The model bytes themselves stay where
 * they are (an ext4 file, or a raw range in a QEMU image); only this map is
 * staged. Integrity: the declared SHA-256 of the model is carried to the kernel
 * in the handoff and the kernel recomputes it over the bytes it received; any
 * wrong LBA, short read or stale file shows up as a hash mismatch and the
 * kernel refuses to decode (never a silent wrong model).
 *
 * The map has no checksum of its own: every field that could steer a read
 * wrong is covered by the SHA-256 check, and a malformed map is refused by
 * ck_model_map_check below (the same function in the stub and the tool). */
#ifndef AIENOS_CK_MODEL_MAP_H
#define AIENOS_CK_MODEL_MAP_H
#include <stdint.h>
#include <stddef.h>

#define CK_MODEL_MAP_MAGIC "AIENMDL1"
#define CK_MODEL_MAP_VERSION 1u
#define CK_MODEL_MAP_BYTES 4096u
#define CK_MODEL_MAP_MAX_EXTENTS 128u
#define CK_MODEL_MAP_PATH "\\EFI\\AIENOS\\MODEL.MAP"

struct ck_model_extent {
    uint64_t lba;   /* first LBA of this extent on the whole disk */
    uint64_t count; /* sectors in this extent (> 0) */
};

struct ck_model_map {
    uint8_t magic[8];         /* "AIENMDL1" */
    uint32_t version;         /* 1 */
    uint32_t sector_size;     /* 512 or 4096; must equal the disk's BlockSize */
    uint8_t disk_guid[16];    /* GPT header bytes 56..71 of LBA 1, raw */
    uint64_t model_len;       /* bytes of the model file */
    uint8_t sha256[32];       /* SHA-256 of the model file */
    uint32_t n_extents;       /* 1..CK_MODEL_MAP_MAX_EXTENTS */
    uint32_t flags;           /* 0 */
    struct ck_model_extent ext[CK_MODEL_MAP_MAX_EXTENTS];
    uint8_t pad[CK_MODEL_MAP_BYTES - 80u - 16u * CK_MODEL_MAP_MAX_EXTENTS];
};
_Static_assert(sizeof(struct ck_model_map) == CK_MODEL_MAP_BYTES, "ck_model_map size");
_Static_assert(offsetof(struct ck_model_map, ext) == 80, "ck_model_map.ext offset");

/* Structural check, no I/O. block_size 0 / last_block 0 skip the disk
 * comparisons (the host tool before it knows the disk). 0 = well formed; -1
 * with *why set otherwise. */
static inline int ck_model_map_check(const struct ck_model_map *m, uint32_t block_size,
                                     uint64_t last_block, const char **why)
{
    static const uint8_t magic[8] = CK_MODEL_MAP_MAGIC;
    for (unsigned i = 0; i < 8; i++)
        if (m->magic[i] != magic[i]) {
            *why = "bad magic";
            return -1;
        }
    if (m->version != CK_MODEL_MAP_VERSION) {
        *why = "unsupported version";
        return -1;
    }
    if (m->sector_size != 512u && m->sector_size != 4096u) {
        *why = "sector size not 512 or 4096";
        return -1;
    }
    if (block_size && m->sector_size != block_size) {
        *why = "sector size differs from the disk block size";
        return -1;
    }
    if (m->flags != 0) {
        *why = "unknown flags";
        return -1;
    }
    if (m->model_len == 0) {
        *why = "zero model length";
        return -1;
    }
    if (m->n_extents == 0 || m->n_extents > CK_MODEL_MAP_MAX_EXTENTS) {
        *why = "extent count out of range";
        return -1;
    }
    uint64_t sectors = 0;
    for (uint32_t i = 0; i < m->n_extents; i++) {
        uint64_t lba = m->ext[i].lba, n = m->ext[i].count;
        if (n == 0 || lba < 2 /* MBR + GPT header */) {
            *why = "extent empty or inside the GPT header";
            return -1;
        }
        if (lba + n < lba || (last_block && lba + n - 1 > last_block)) {
            *why = "extent past the end of the disk";
            return -1;
        }
        if (sectors + n < sectors) {
            *why = "extent total overflows";
            return -1;
        }
        sectors += n;
    }
    /* Exact coverage: the extents hold the whole model and less than one
     * extra sector (the last sector may be partial). */
    uint64_t need = (m->model_len + m->sector_size - 1) / m->sector_size;
    if (sectors != need) {
        *why = "extents do not cover exactly the model length";
        return -1;
    }
    *why = 0;
    return 0;
}

#endif
