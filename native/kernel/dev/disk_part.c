/* disk_part.c -- read-only GPT parser and the single bounds-checked LBA
 * translation layer of the AIENOS C kernel (see disk_part.h). Freestanding:
 * no libc, no heap; all disk reads go through disk_read on the parent. */
#include "disk_part.h"

/* 38DAAC89-5EAD-4B40-8B1E-3687A7418061 in GPT on-disk (mixed endian) order. */
const uint8_t ck_aienos_part_type[16] = {0x89, 0xac, 0xda, 0x38, 0xad, 0x5e, 0x40, 0x4b,
                                         0x8b, 0x1e, 0x36, 0x87, 0xa7, 0x41, 0x80, 0x61};

#define GPT_BUF 4096u
static uint8_t g_blk[GPT_BUF];  /* one block of the device being read */
static uint8_t g_hdr[GPT_BUF];  /* primary header copy */
static uint8_t g_bak[GPT_BUF];  /* backup header copy */
static uint64_t g_used_first[CK_GPT_MAX_USED];
static uint64_t g_used_last[CK_GPT_MAX_USED];

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t get64(const uint8_t *p)
{
    return (uint64_t)get32(p) | (uint64_t)get32(p + 4) << 32;
}
static int same(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}
static int all_zero(const uint8_t *a, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i];
    return d == 0;
}
static void copy(uint8_t *d, const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

uint32_t ck_crc32(uint32_t crc, const uint8_t *p, size_t n)
{
    crc = ~crc;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

/* Header field offsets (UEFI 2.10 table 5-5). */
enum {
    H_SIG = 0, H_REV = 8, H_SIZE = 12, H_CRC = 16, H_MY = 24, H_ALT = 32, H_FIRST = 40, H_LAST = 48,
    H_GUID = 56, H_ENT_LBA = 72, H_NUM = 80, H_ESIZE = 84, H_ECRC = 88
};
static const uint8_t gpt_sig[8] = {'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'};

/* Read block lba of d into g_blk, then check signature, revision, size and
 * CRC32; on success copy the header into out. */
static int read_header(const disk_dev *d, uint64_t lba, uint8_t *out, int bad_crc_rc, int bad_rc)
{
    if (disk_read(d, lba, 1, g_blk) != DISK_OK) return CK_GPT_EIO;
    uint32_t hsize = get32(g_blk + H_SIZE);
    if (!same(g_blk + H_SIG, gpt_sig, 8) || get32(g_blk + H_REV) != 0x00010000u || hsize < CK_GPT_HDR_MIN ||
        hsize > d->block_size)
        return bad_rc;
    uint32_t want = get32(g_blk + H_CRC);
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    uint32_t crc = ck_crc32(0, g_blk, H_CRC);
    crc = ck_crc32(crc, zero4, 4);
    crc = ck_crc32(crc, g_blk + H_CRC + 4, hsize - H_CRC - 4u);
    if (crc != want) return bad_crc_rc;
    copy(out, g_blk, d->block_size);
    return CK_GPT_OK;
}

typedef struct {
    uint32_t num, esize, blocks, bytes;
} ent_geom;

/* Stream the entry array at lba: CRC32 over num*esize bytes; when scan is
 * set, also check every used entry and find the AIENOS one. */
static int scan_entries(const disk_dev *d, uint64_t lba, const ent_geom *g, int scan, uint32_t *crc_out,
                        uint64_t first_usable, uint64_t last_usable, int *sem_rc, ck_part *p, ck_gpt_info *info)
{
    uint32_t crc = 0, left = g->bytes, idx = 0, used = 0, aienos = 0;
    for (uint32_t b = 0; b < g->blocks; b++) {
        if (disk_read(d, lba + b, 1, g_blk) != DISK_OK) return CK_GPT_EIO;
        uint32_t take = left < d->block_size ? left : d->block_size;
        crc = ck_crc32(crc, g_blk, take);
        left -= take;
        for (uint32_t off = 0; scan && off + g->esize <= take; off += g->esize, idx++) {
            const uint8_t *e = g_blk + off;
            if (all_zero(e, 16)) continue; /* unused entry */
            uint64_t f = get64(e + 32), l = get64(e + 40);
            if (*sem_rc == CK_GPT_OK && (f > l || f < first_usable || l > last_usable)) *sem_rc = CK_GPT_EOUTSIDE;
            if (used >= CK_GPT_MAX_USED) {
                if (*sem_rc == CK_GPT_OK) *sem_rc = CK_GPT_ETOOMANY;
                continue;
            }
            g_used_first[used] = f;
            g_used_last[used] = l;
            used++;
            if (same(e, ck_aienos_part_type, 16)) {
                aienos++;
                p->first_lba = f;
                p->blocks = l - f + 1u; /* f <= l checked above before it is trusted */
                info->part_index = idx;
            }
        }
    }
    *crc_out = crc;
    if (scan) {
        info->used = used;
        for (uint32_t i = 0; *sem_rc == CK_GPT_OK && i < used; i++)
            for (uint32_t j = i + 1; j < used; j++)
                if (g_used_first[i] <= g_used_last[j] && g_used_first[j] <= g_used_last[i]) {
                    *sem_rc = CK_GPT_EOVERLAP;
                    break;
                }
        if (*sem_rc == CK_GPT_OK && aienos == 0) *sem_rc = CK_GPT_ENOPART;
        if (*sem_rc == CK_GPT_OK && aienos > 1) *sem_rc = CK_GPT_EMULTI;
    }
    return CK_GPT_OK;
}

static int part_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf)
{
    const ck_part *p = ctx;
    uint64_t abs = 0;
    int rc = ck_part_xlate(p, lba, count, &abs);
    return rc ? rc : disk_read(p->parent, abs, count, buf);
}
static int part_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    const ck_part *p = ctx;
    uint64_t abs = 0;
    int rc = ck_part_xlate(p, lba, count, &abs);
    return rc ? rc : disk_write(p->parent, abs, count, buf);
}
static int part_flush(void *ctx)
{
    const ck_part *p = ctx;
    if (!p || !p->valid || !p->parent) return DISK_ESTATE;
    return disk_flush(p->parent);
}

static void part_invalid(ck_part *p, const disk_dev *d)
{
    p->parent = d;
    p->first_lba = 0;
    p->blocks = 0;
    p->valid = 0;
    p->dev.ctx = p;
    p->dev.block_size = d ? d->block_size : 0;
    p->dev.block_count = 0; /* disk_check refuses a zero-block device */
    p->dev.read = part_read;
    p->dev.write = part_write;
    p->dev.flush = part_flush;
    p->dev.max_blocks_per_io = d ? d->max_blocks_per_io : 0;
}

int ck_gpt_find_aienos(const disk_dev *d, ck_part *p, ck_gpt_info *info)
{
    if (!p || !info) return CK_GPT_EGEOM;
    part_invalid(p, d);
    for (size_t i = 0; i < sizeof *info; i++) ((uint8_t *)info)[i] = 0;
    if (disk_check(d) != DISK_OK || d->block_size > GPT_BUF || d->block_count < 8u) return CK_GPT_EGEOM;
    uint64_t last = d->block_count - 1u;
    info->last_lba = last;

    /* Protective MBR: boot signature and at least one 0xEE record. */
    if (disk_read(d, 0, 1, g_blk) != DISK_OK) return CK_GPT_EIO;
    int pmbr = g_blk[510] == 0x55 && g_blk[511] == 0xaa;
    int ee = 0;
    for (int i = 0; i < 4; i++) ee |= g_blk[446 + 16 * i + 4] == 0xee;
    if (!pmbr || !ee) return CK_GPT_ENOMBR;

    int rc = read_header(d, 1, g_hdr, CK_GPT_EHDR_CRC, CK_GPT_ESIG);
    if (rc) return rc;
    ent_geom g;
    g.num = get32(g_hdr + H_NUM);
    g.esize = get32(g_hdr + H_ESIZE);
    if (g.num == 0 || g.num > CK_GPT_MAX_ENTRIES || (g.esize != 128u && g.esize != 256u && g.esize != 512u))
        return CK_GPT_EENT;
    g.bytes = g.num * g.esize; /* <= 1024 * 512: no overflow */
    g.blocks = (g.bytes + d->block_size - 1u) / d->block_size;
    uint64_t first_u = get64(g_hdr + H_FIRST), last_u = get64(g_hdr + H_LAST), ent_lba = get64(g_hdr + H_ENT_LBA);
    if (get64(g_hdr + H_MY) != 1u || get64(g_hdr + H_ALT) != last) return CK_GPT_EHDR;
    /* Every comparison below is against values <= last, so no sum overflows. */
    if (ent_lba < 2u || ent_lba > last || g.blocks > last - ent_lba) return CK_GPT_EHDR;
    if (first_u < ent_lba + g.blocks || first_u > last_u || last_u >= last) return CK_GPT_EHDR;
    /* The backup array must fit between the usable range and the backup header. */
    if (last - 1u - last_u < g.blocks) return CK_GPT_EHDR;

    int sem = CK_GPT_OK;
    uint32_t crc = 0;
    rc = scan_entries(d, ent_lba, &g, 1, &crc, first_u, last_u, &sem, p, info);
    if (rc) return rc;
    if (crc != get32(g_hdr + H_ECRC)) return CK_GPT_EENT_CRC;

    /* Backup header and backup entry array: both copies must be valid and agree. */
    rc = read_header(d, last, g_bak, CK_GPT_EBACKUP, CK_GPT_EBACKUP);
    if (rc) return rc == CK_GPT_EIO ? rc : CK_GPT_EBACKUP;
    uint64_t bent = get64(g_bak + H_ENT_LBA);
    if (get64(g_bak + H_MY) != last || get64(g_bak + H_ALT) != 1u || get64(g_bak + H_FIRST) != first_u ||
        get64(g_bak + H_LAST) != last_u || !same(g_bak + H_GUID, g_hdr + H_GUID, 16) ||
        get32(g_bak + H_NUM) != g.num || get32(g_bak + H_ESIZE) != g.esize ||
        get32(g_bak + H_ECRC) != get32(g_hdr + H_ECRC) || bent <= last_u || bent >= last || g.blocks > last - bent)
        return CK_GPT_EBACKUP;
    uint32_t bcrc = 0;
    rc = scan_entries(d, bent, &g, 0, &bcrc, first_u, last_u, &sem, p, info);
    if (rc) return rc;
    if (bcrc != get32(g_hdr + H_ECRC)) return CK_GPT_EBACKUP;

    if (sem) {
        p->first_lba = 0;
        p->blocks = 0;
        return sem;
    }
    info->first_usable = first_u;
    info->last_usable = last_u;
    info->entries = g.num;
    info->entry_size = g.esize;
    p->valid = 1;
    p->dev.block_count = p->blocks;
    return CK_GPT_OK;
}

int ck_part_xlate(const ck_part *p, uint64_t lba, uint32_t count, uint64_t *abs)
{
    if (!p || !p->valid || !p->parent || !abs) return DISK_ESTATE;
    if (count == 0) return DISK_EARG;
    uint64_t pc = p->parent->block_count;
#if defined(CK_TEST_DISK_XLATE_BYPASS)
    /* TEST-ONLY mutation: no partition offset, parent bounds only. */
    if (lba >= pc || (uint64_t)count > pc - lba) return DISK_ERANGE;
    *abs = lba;
    return DISK_OK;
#else
    if (lba >= p->blocks || (uint64_t)count > p->blocks - lba) return DISK_ERANGE; /* GUARD:part-end */
    uint64_t a = p->first_lba + lba;
    if (a < p->first_lba || a >= pc || (uint64_t)count > pc - a) return DISK_ERANGE; /* GUARD:part-parent */
    *abs = a;
    return DISK_OK;
#endif
}

const char *ck_gpt_strerror(int rc)
{
    switch (rc) {
    case CK_GPT_OK: return "ok";
    case CK_GPT_EIO: return "read error";
    case CK_GPT_EGEOM: return "disk geometry";
    case CK_GPT_ENOMBR: return "no protective MBR";
    case CK_GPT_ESIG: return "no GPT header";
    case CK_GPT_EHDR_CRC: return "primary header CRC32 mismatch";
    case CK_GPT_EHDR: return "primary header fields invalid";
    case CK_GPT_EENT_CRC: return "entry array CRC32 mismatch";
    case CK_GPT_EENT: return "entry geometry refused";
    case CK_GPT_EBACKUP: return "backup GPT invalid";
    case CK_GPT_EOUTSIDE: return "partition outside the usable range";
    case CK_GPT_EOVERLAP: return "overlapping partitions";
    case CK_GPT_ENOPART: return "no AIENOS partition type";
    case CK_GPT_EMULTI: return "more than one AIENOS partition";
    case CK_GPT_ETOOMANY: return "too many used entries";
    default: return "error";
    }
}
