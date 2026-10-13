/* pi5_marker.c -- see pi5_marker.h. */
#include "pi5_marker.h"
#include "../dev/disk_part.h"
#include "../dev/disk_layout.h"

#define MAGIC "AIENPI5M"
#define HDR_CRC_BYTES 40u

static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint64_t get64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = v << 8 | p[i]; return v; }
static uint32_t get32(const uint8_t *p) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = v << 8 | p[i]; return v; }

/* splitmix64 of (seed, sector, word): the payload is regenerable. */
static uint64_t word(uint64_t seed, uint32_t sec, uint32_t w)
{
    uint64_t z = seed + 0x9e3779b97f4a7c15ull * ((uint64_t)sec << 8 | w) + 0x9e3779b97f4a7c15ull;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static void fill_payload(uint8_t *buf, uint64_t seed)
{
    for (uint32_t s = 1; s < CK_PI5_MARKER_SECS; s++)
        for (uint32_t w = 0; w < DISK_SECTOR_BYTES / 8; w++)
            put64(buf + (size_t)s * DISK_SECTOR_BYTES + w * 8u, word(seed, s, w));
}

static int payload_ok(const uint8_t *buf, uint64_t seed)
{
    for (uint32_t s = 1; s < CK_PI5_MARKER_SECS; s++)
        for (uint32_t w = 0; w < DISK_SECTOR_BYTES / 8; w++)
            if (get64(buf + (size_t)s * DISK_SECTOR_BYTES + w * 8u) != word(seed, s, w))
                return 0;
    return 1;
}

static void make_header(uint8_t *h, uint64_t gen, uint32_t payload_crc)
{
    for (uint32_t i = 0; i < DISK_SECTOR_BYTES; i++) h[i] = 0;
    for (int i = 0; i < 8; i++) h[i] = (uint8_t)MAGIC[i];
    put32(h + 8, 1);
    put32(h + 12, CK_PI5_MARKER_SECS - 1u);
    put64(h + 16, gen);
    put64(h + 24, CK_PI5_MARKER_SEED);
    put32(h + 32, payload_crc);
    put32(h + 36, 0);
    put32(h + HDR_CRC_BYTES, ck_crc32(0, h, HDR_CRC_BYTES));
}

static int header_ok(const uint8_t *h)
{
    for (int i = 0; i < 8; i++)
        if (h[i] != (uint8_t)MAGIC[i]) return 0;
    return get32(h + 8) == 1 && get32(h + 12) == CK_PI5_MARKER_SECS - 1u && get64(h + 24) == CK_PI5_MARKER_SEED &&
           get32(h + HDR_CRC_BYTES) == ck_crc32(0, h, HDR_CRC_BYTES);
}

static int all_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

static uint32_t payload_crc(const uint8_t *buf)
{
    return ck_crc32(0, buf + DISK_SECTOR_BYTES, (size_t)(CK_PI5_MARKER_SECS - 1u) * DISK_SECTOR_BYTES);
}

/* Write the header sector, flush, read it back and compare. */
static int write_header(const disk_dev *d, uint64_t lba, const uint8_t *hdr, uint8_t *copy)
{
    if (disk_write(d, lba, 1, hdr) != DISK_OK || disk_flush(d) != DISK_OK) return CK_PI5_MARKER_EIO;
    if (disk_read(d, lba, 1, copy) != DISK_OK) return CK_PI5_MARKER_EIO;
    for (uint32_t i = 0; i < DISK_SECTOR_BYTES; i++)
        if (copy[i] != hdr[i]) return CK_PI5_MARKER_EVERIFY;
    return 0;
}

int ck_pi5_marker_run(const disk_dev *d, uint8_t *buf, uint64_t *generation)
{
    if (!d || !buf || d->block_size != DISK_SECTOR_BYTES || d->block_count < CK_PI5_MARKER_SECS)
        return CK_PI5_MARKER_ESIZE;
    uint64_t lba = d->block_count - CK_PI5_MARKER_SECS;
    static uint8_t hdr[DISK_SECTOR_BYTES] __attribute__((aligned(64)));
    static uint8_t copy[DISK_SECTOR_BYTES] __attribute__((aligned(64)));
    if (disk_read(d, lba, CK_PI5_MARKER_SECS, buf) != DISK_OK) return CK_PI5_MARKER_EIO;
    int rc;
    if (header_ok(buf)) {
        uint64_t seed = get64(buf + 24);
        if (!payload_ok(buf, seed) || payload_crc(buf) != get32(buf + 32)) return CK_PI5_MARKER_ECORRUPT;
        uint64_t gen = get64(buf + 16) + 1u;
        make_header(hdr, gen, get32(buf + 32));
        if ((rc = write_header(d, lba, hdr, copy)) != 0) return rc;
        *generation = gen;
        return CK_PI5_MARKER_REOPENED;
    }
    if (!all_zero(buf, CK_PI5_MARKER_BUF_BYTES)) return CK_PI5_MARKER_EREFUSED;
    fill_payload(buf, CK_PI5_MARKER_SEED);
    uint32_t pc = payload_crc(buf);
    /* payload first (63 sectors in one multi-sector write), flush, then the header, flush */
    if (disk_write(d, lba + 1u, CK_PI5_MARKER_SECS - 1u, buf + DISK_SECTOR_BYTES) != DISK_OK || disk_flush(d) != DISK_OK)
        return CK_PI5_MARKER_EIO;
    make_header(hdr, 1, pc);
    if ((rc = write_header(d, lba, hdr, copy)) != 0) return rc;
    /* whole region back, byte for byte against what was written */
    static uint8_t back[CK_PI5_MARKER_BUF_BYTES] __attribute__((aligned(64)));
    if (disk_read(d, lba + 1u, CK_PI5_MARKER_SECS - 1u, back + DISK_SECTOR_BYTES) != DISK_OK) return CK_PI5_MARKER_EIO;
    for (size_t i = DISK_SECTOR_BYTES; i < CK_PI5_MARKER_BUF_BYTES; i++)
        if (back[i] != buf[i]) return CK_PI5_MARKER_EVERIFY;
    *generation = 1;
    return CK_PI5_MARKER_FORMATTED;
}

const char *ck_pi5_marker_strerror(int rc)
{
    switch (rc) {
    case CK_PI5_MARKER_FORMATTED: return "formatted (blank region written, flushed, read back identical)";
    case CK_PI5_MARKER_REOPENED: return "reopened (payload identical to the pattern, generation bumped and read back)";
    case CK_PI5_MARKER_EIO: return "I/O error";
    case CK_PI5_MARKER_EREFUSED: return "region is neither blank nor a marker, nothing written";
    case CK_PI5_MARKER_ECORRUPT: return "marker header valid but payload differs";
    case CK_PI5_MARKER_EVERIFY: return "read back differs from what was written";
    case CK_PI5_MARKER_ESIZE: return "partition view too small or not 512-byte blocks";
    default: return "unknown";
    }
}

int ck_pi5_store_view(const ck_part *full, ck_part *out)
{
    const uint64_t bpu = CK_LAYOUT_UNIT / DISK_SECTOR_BYTES;
    if (!full || !out || !full->valid || full->dev.block_size != DISK_SECTOR_BYTES ||
        full->blocks < CK_PI5_MARKER_SECS + bpu)
        return CK_PI5_MARKER_ESIZE;
    *out = *full;
    out->blocks = (full->blocks - CK_PI5_MARKER_SECS) / bpu * bpu;
    out->dev.ctx = out;
    out->dev.block_count = out->blocks;
    return 0;
}
