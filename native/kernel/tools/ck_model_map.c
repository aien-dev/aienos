/* ck_model_map -- host tool for MODEL.MAP (native/boot/model_map.h): where
 * the yardstick model's bytes live on the boot disk, so the UEFI boot stub
 * can read them through the firmware's Block I/O driver (aienos#34 lane 6).
 * Hosted C, Linux only (FIEMAP), test and staging tooling; never part of an
 * image. No Python.
 *
 *   ck_model_map make OUT.MAP --file GGUF --disk DEV|IMG [--sector 512]
 *        (--fiemap [--part-start LBA|auto] | --extent LBA:COUNT ...)
 *        [--corrupt-sha]
 *     Reads GGUF (length + SHA-256), the disk's GPT disk GUID (LBA 1 bytes
 *     56..71 of DEV or IMG), and the extents: --extent lists them in file
 *     order (QEMU images, from ck_gpt_image esp-model); --fiemap asks the
 *     filesystem where the file's blocks are (FS_IOC_FIEMAP) and converts
 *     partition-relative byte offsets to whole-disk LBAs with --part-start
 *     (the partition's first LBA; "auto" reads /sys/dev/block/MAJ:MIN/start
 *     of the file's own device). Every FIEMAP extent must be plain mapped
 *     data (no delalloc, unwritten, inline, encoded or unknown extents) and
 *     the extents must cover the file exactly, else refused. --corrupt-sha
 *     flips the last SHA-256 byte (the gate's negative control: the stub
 *     reads fine, the kernel must refuse to decode).
 *   ck_model_map show MAP
 *   ck_model_map check MAP --disk DEV|IMG
 *     Structural check, GUID match against the disk, then reads every extent
 *     by LBA from DEV|IMG and recomputes the SHA-256: exit 0 only when it
 *     equals the declared hash. The same bytes the firmware will read, read
 *     the same way from Linux: the pre-flight for the attended native boot. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include "model_map.h"
#include "sha256.h"

static int usage(void)
{
    fprintf(stderr,
            "usage: ck_model_map make OUT.MAP --file GGUF --disk DEV|IMG [--sector 512]\n"
            "            (--fiemap [--part-start LBA|auto] | --extent LBA:COUNT ...) [--corrupt-sha]\n"
            "       ck_model_map show MAP\n"
            "       ck_model_map check MAP --disk DEV|IMG\n");
    return 2;
}

static void hex(char *out, const uint8_t *b, unsigned n)
{
    static const char d[] = "0123456789abcdef";
    for (unsigned i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static int sha_file(FILE *f, uint64_t *len, uint8_t out[32])
{
    static uint8_t buf[1u << 20];
    sha256_ctx c;
    sha256_init(&c);
    *len = 0;
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        sha256_update(&c, buf, n);
        *len += n;
    }
    if (ferror(f)) return -1;
    sha256_final(&c, out);
    return 0;
}

/* GPT disk GUID from LBA 1 of DEV|IMG (raw 16 bytes). */
static int disk_guid(const char *disk, uint32_t sector, uint8_t out[16])
{
    int fd = open(disk, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "cannot open %s: %s\n", disk, strerror(errno)); return -1; }
    uint8_t h[4096];
    ssize_t r = pread(fd, h, sector, (off_t)sector);
    close(fd);
    if (r != (ssize_t)sector) { fprintf(stderr, "cannot read LBA 1 of %s\n", disk); return -1; }
    if (memcmp(h, "EFI PART", 8)) { fprintf(stderr, "%s: no GPT header at LBA 1 (sector %u)\n", disk, sector); return -1; }
    memcpy(out, h + 56, 16);
    return 0;
}

static int parse_extent(const char *s, struct ck_model_extent *e)
{
    char *end = 0;
    e->lba = strtoull(s, &end, 10);
    if (!end || *end != ':') return -1;
    e->count = strtoull(end + 1, &end, 10);
    return (end && *end == 0 && e->count) ? 0 : -1;
}

/* --part-start auto: the file's device's first 512-byte sector from sysfs. */
static int part_start_auto(const char *file, uint64_t *start512)
{
    struct stat st;
    if (stat(file, &st)) return -1;
    char p[128];
    snprintf(p, sizeof p, "/sys/dev/block/%u:%u/start", major(st.st_dev), minor(st.st_dev));
    FILE *f = fopen(p, "r");
    if (!f) { fprintf(stderr, "cannot read %s (is the file on a partition?)\n", p); return -1; }
    int ok = fscanf(f, "%llu", (unsigned long long *)start512) == 1;
    fclose(f);
    return ok ? 0 : -1;
}

static int fiemap_extents(const char *file, uint64_t len, uint32_t sector, uint64_t part_start_lba,
                          struct ck_model_map *m)
{
    int fd = open(file, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "cannot open %s\n", file); return -1; }
    const unsigned cap = 512;
    struct fiemap *fm = calloc(1, sizeof *fm + cap * sizeof(struct fiemap_extent));
    if (!fm) { close(fd); return -1; }
    fm->fm_start = 0;
    fm->fm_length = ~0ull;
    fm->fm_flags = FIEMAP_FLAG_SYNC;
    fm->fm_extent_count = cap;
    if (ioctl(fd, FS_IOC_FIEMAP, fm)) {
        fprintf(stderr, "FS_IOC_FIEMAP: %s\n", strerror(errno));
        free(fm);
        close(fd);
        return -1;
    }
    close(fd);
    const uint32_t bad = FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_ENCODED |
                         FIEMAP_EXTENT_DATA_ENCRYPTED | FIEMAP_EXTENT_NOT_ALIGNED |
                         FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_DATA_TAIL | FIEMAP_EXTENT_UNWRITTEN;
    uint64_t logical = 0;
    int last = 0, rc = 0;
    for (uint32_t i = 0; i < fm->fm_mapped_extents && !rc; i++) {
        const struct fiemap_extent *e = &fm->fm_extents[i];
        if (e->fe_flags & bad) { fprintf(stderr, "extent %u: flags 0x%x not plain mapped data\n", i, e->fe_flags); rc = -1; break; }
        if (e->fe_logical != logical) { fprintf(stderr, "extent %u: hole or out of order at %llu\n", i, (unsigned long long)e->fe_logical); rc = -1; break; }
        if (e->fe_physical % sector) { fprintf(stderr, "extent %u: physical offset not sector aligned\n", i); rc = -1; break; }
        if (m->n_extents >= CK_MODEL_MAP_MAX_EXTENTS) { fprintf(stderr, "more than %u extents\n", CK_MODEL_MAP_MAX_EXTENTS); rc = -1; break; }
        uint64_t take = e->fe_length;
        if (logical + take > len) take = len - logical; /* the last extent may be block padded */
        m->ext[m->n_extents].lba = part_start_lba + e->fe_physical / sector;
        m->ext[m->n_extents].count = (take + sector - 1) / sector;
        m->n_extents++;
        logical += take;
        if (e->fe_flags & FIEMAP_EXTENT_LAST) last = 1;
    }
    free(fm);
    if (rc) return rc;
    if (!last || logical != len) {
        fprintf(stderr, "FIEMAP did not cover the file (%llu of %llu bytes, last=%d)\n",
                (unsigned long long)logical, (unsigned long long)len, last);
        return -1;
    }
    return 0;
}

static int cmd_make(int argc, char **argv)
{
    const char *out = argv[2], *file = 0, *disk = 0;
    uint32_t sector = 512;
    int fiemap = 0, corrupt = 0;
    uint64_t part_start = 0;
    int part_auto = 0;
    static struct ck_model_map m;
    memset(&m, 0, sizeof m);
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--file") && i + 1 < argc) file = argv[++i];
        else if (!strcmp(argv[i], "--disk") && i + 1 < argc) disk = argv[++i];
        else if (!strcmp(argv[i], "--sector") && i + 1 < argc) sector = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--fiemap")) fiemap = 1;
        else if (!strcmp(argv[i], "--part-start") && i + 1 < argc) {
            if (!strcmp(argv[i + 1], "auto")) part_auto = 1;
            else part_start = strtoull(argv[i + 1], NULL, 10);
            i++;
        } else if (!strcmp(argv[i], "--extent") && i + 1 < argc) {
            if (m.n_extents >= CK_MODEL_MAP_MAX_EXTENTS || parse_extent(argv[++i], &m.ext[m.n_extents])) {
                fprintf(stderr, "bad --extent %s\n", argv[i]);
                return 2;
            }
            m.n_extents++;
        } else if (!strcmp(argv[i], "--corrupt-sha")) corrupt = 1;
        else return usage();
    }
    if (!file || !disk || (sector != 512 && sector != 4096) || (fiemap == (m.n_extents > 0))) return usage();
    FILE *f = fopen(file, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", file); return 1; }
    uint64_t len = 0;
    if (sha_file(f, &len, m.sha256)) { fclose(f); fprintf(stderr, "read error on %s\n", file); return 1; }
    fclose(f);
    memcpy(m.magic, CK_MODEL_MAP_MAGIC, 8);
    m.version = CK_MODEL_MAP_VERSION;
    m.sector_size = sector;
    m.model_len = len;
    if (disk_guid(disk, sector, m.disk_guid)) return 1;
    if (fiemap) {
        if (part_auto) {
            uint64_t s512 = 0;
            if (part_start_auto(file, &s512)) return 1;
            part_start = s512 * 512 / sector;
        }
        if (fiemap_extents(file, len, sector, part_start, &m)) return 1;
    }
    const char *why = 0;
    if (ck_model_map_check(&m, sector, 0, &why)) { fprintf(stderr, "map refused: %s\n", why); return 1; }
    if (corrupt) m.sha256[31] ^= 0xff;
    FILE *o = fopen(out, "wb");
    if (!o || fwrite(&m, 1, sizeof m, o) != sizeof m || fclose(o)) { fprintf(stderr, "cannot write %s\n", out); return 1; }
    char sh[65], gh[33];
    hex(sh, m.sha256, 32);
    hex(gh, m.disk_guid, 16);
    printf("model_map written=%s len=%llu extents=%u sector=%u disk=%s sha256=%s%s\n", out,
           (unsigned long long)len, m.n_extents, sector, gh, sh, corrupt ? " (CORRUPTED on purpose)" : "");
    return 0;
}

static int load_map(const char *path, struct ck_model_map *m)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return -1; }
    size_t n = fread(m, 1, sizeof *m, f);
    int extra = fgetc(f) != EOF;
    fclose(f);
    if (n != sizeof *m || extra) { fprintf(stderr, "%s: not exactly %u bytes\n", path, CK_MODEL_MAP_BYTES); return -1; }
    const char *why = 0;
    if (ck_model_map_check(m, 0, 0, &why)) { fprintf(stderr, "%s: refused: %s\n", path, why); return -1; }
    return 0;
}

static int cmd_show(int argc, char **argv)
{
    if (argc != 3) return usage();
    static struct ck_model_map m;
    if (load_map(argv[2], &m)) return 1;
    char sh[65], gh[33];
    hex(sh, m.sha256, 32);
    hex(gh, m.disk_guid, 16);
    printf("magic=%.8s version=%u sector=%u disk=%s len=%llu sha256=%s extents=%u\n", m.magic, m.version,
           m.sector_size, gh, (unsigned long long)m.model_len, sh, m.n_extents);
    for (uint32_t i = 0; i < m.n_extents; i++)
        printf("  extent %u lba=%llu count=%llu\n", i, (unsigned long long)m.ext[i].lba,
               (unsigned long long)m.ext[i].count);
    return 0;
}

static int cmd_check(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[3], "--disk")) return usage();
    static struct ck_model_map m;
    if (load_map(argv[2], &m)) return 1;
    uint8_t g[16];
    if (disk_guid(argv[4], m.sector_size, g)) return 1;
    if (memcmp(g, m.disk_guid, 16)) { fprintf(stderr, "disk GUID differs from the map\n"); return 1; }
    int fd = open(argv[4], O_RDONLY);
    if (fd < 0) { fprintf(stderr, "cannot open %s\n", argv[4]); return 1; }
    static uint8_t buf[1u << 20];
    sha256_ctx c;
    sha256_init(&c);
    uint64_t left = m.model_len;
    for (uint32_t i = 0; i < m.n_extents && left; i++) {
        uint64_t off = m.ext[i].lba * m.sector_size, bytes = m.ext[i].count * m.sector_size;
        if (bytes > left) bytes = left;
        while (bytes) {
            size_t want = bytes < sizeof buf ? (size_t)bytes : sizeof buf;
            if (pread(fd, buf, want, (off_t)off) != (ssize_t)want) { close(fd); fprintf(stderr, "read failed at byte %llu\n", (unsigned long long)off); return 1; }
            sha256_update(&c, buf, want);
            off += want;
            bytes -= want;
            left -= want;
        }
    }
    close(fd);
    uint8_t dg[32];
    sha256_final(&c, dg);
    char sh[65];
    hex(sh, dg, 32);
    if (left || memcmp(dg, m.sha256, 32)) {
        printf("model_map check: FAIL (sha256 of the mapped bytes %s, declared differs, unread=%llu)\n", sh,
               (unsigned long long)left);
        return 1;
    }
    printf("model_map check: PASS (sha256 of the mapped bytes = declared %s, %u extents, %llu bytes)\n", sh,
           m.n_extents, (unsigned long long)m.model_len);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return usage();
    if (!strcmp(argv[1], "make")) return cmd_make(argc, argv);
    if (!strcmp(argv[1], "show")) return cmd_show(argc, argv);
    if (!strcmp(argv[1], "check")) return cmd_check(argc, argv);
    return usage();
}
