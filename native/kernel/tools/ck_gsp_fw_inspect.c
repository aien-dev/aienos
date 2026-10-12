/* ck_gsp_fw_inspect -- host tool: inventory and refusal checks for the NVIDIA
 * GSP-RM firmware container that the pinned Linux driver (nvidia-open
 * 580.173.02) loads for the GB10 (aienos#286 cut C, host work: "inventory of
 * firmware and protocol sources, parsers and refusal tests for firmware
 * metadata. No loading"). docs/GB10_FIRMWARE_INVENTORY.md is the report this
 * tool backs.
 *
 * The container is an ELF64 relocatable object for RISC-V whose sections carry
 * the payload: .fwimage (the GSP-RM image), .fwversion (NUL-terminated driver
 * version string), .note.gnu.build-id, and one .fwsignature_<family> section
 * per chip family. The driver's own checks that this tool mirrors (file:line
 * in open-gpu-kernel-modules tag 580.173.02):
 *   - section lookup with bounds checks on the section header table, the
 *     section-name table and each section's offset+size
 *     (src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c:5091-5170);
 *   - .fwversion must be NUL-terminated, shorter than 64 bytes and equal to
 *     NV_VERSION_STRING (kernel_gsp.c:4731-4790);
 *   - the signature section is ".fwsignature_" + chip family name
 *     (kernel_gsp.c:4805-4840), and the GB10 (GPU_IMPLEMENTATION_GB10B) maps
 *     to family "gb10y" (src/nvidia/arch/nvalloc/common/inc/
 *     nv-firmware-chip-family-select.h:58-60).
 * This tool only reads and hashes bytes. It does not verify NVIDIA's signature
 * (the key and format belong to the chip's boot ROM and ACR) and it never
 * loads anything onto a device.
 *
 *   ck_gsp_fw_inspect inspect FILE [--family NAME] [--expect-version V]
 *     Prints one "key value" line per fact (ELF identity, every section with
 *     offset and size, version string, build id, SHA-256 of the whole file,
 *     of .fwimage and of the selected signature section) and ends with
 *     "RESULT OK" (exit 0) or "RESULT REFUSED <reason>" (exit 2). Default
 *     family is gb10y; default expected version is 580.173.02.
 *   ck_gsp_fw_inspect selftest
 *     Builds a small valid container in memory, then mutates it one field at
 *     a time and checks each mutation is refused for the named reason.
 *     Exit 0 only when every case holds.
 * Hosted C, no outside libraries (SHA-256 is the kernel's own, native/argus).
 * Never part of an image. No Python. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#define DEFAULT_FAMILY "gb10y"
#define DEFAULT_VERSION "580.173.02"
#define EM_RISCV 243u
#define ET_REL 1u
#define SHT_NOBITS 8u
#define SHDR_SIZE 64u
#define EHDR_SIZE 64u
#define MAX_SECTIONS 256u
#define MAX_REASON 160

typedef struct {
    const char *name;
    uint32_t type;
    uint64_t offset;
    uint64_t size;
} section;

typedef struct {
    char reason[MAX_REASON];
    size_t nsec;
    section sec[MAX_SECTIONS];
    const section *fwimage, *fwversion, *buildid, *fwsig;
    char version[64];
    char buildid_hex[129];
    char sig_name[64];
    uint8_t sha_file[32], sha_image[32], sha_sig[32];
} report;

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)rd16(p) | ((uint32_t)rd16(p + 2) << 16); }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v) { wr16(p, (uint16_t)v); wr16(p + 2, (uint16_t)(v >> 16)); }
static void wr64(uint8_t *p, uint64_t v) { wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }

/* offset + size <= len without overflow (the driver uses portSafeAddU64). */
static int in_bounds(uint64_t off, uint64_t size, uint64_t len)
{
    if (off > len) return 0;
    return size <= len - off;
}

static int refuse(report *r, const char *reason)
{
    snprintf(r->reason, sizeof r->reason, "%s", reason);
    return -1;
}

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 15]; }
    out[2 * n] = 0;
}

/* Parse and check the container. 0 = every check passed, -1 = refused
 * (r->reason names the first failed check). Pure: no I/O. */
static int inspect_buf(const uint8_t *buf, uint64_t len, const char *family,
                       const char *expect_version, report *r)
{
    memset(r, 0, sizeof *r);
    if (len < EHDR_SIZE) return refuse(r, "short header: file smaller than an ELF64 header");
    if (!(buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F'))
        return refuse(r, "ELF magic missing");
    if (buf[4] != 2) return refuse(r, "not ELF64 (EI_CLASS)");
    if (buf[5] != 1) return refuse(r, "not little-endian (EI_DATA)");
    if (buf[6] != 1) return refuse(r, "EI_VERSION is not 1");
    if (rd16(buf + 16) != ET_REL) return refuse(r, "e_type is not ET_REL (the pinned container is a relocatable object)");
    if (rd16(buf + 18) != EM_RISCV) return refuse(r, "e_machine is not RISC-V (243)");
    uint64_t shoff = rd64(buf + 40);
    uint16_t shentsize = rd16(buf + 58), shnum = rd16(buf + 60), shstrndx = rd16(buf + 62);
    if (shentsize != SHDR_SIZE) return refuse(r, "e_shentsize is not 64");
    if (shnum == 0) return refuse(r, "e_shnum is 0: no section header table");
    if (shnum > MAX_SECTIONS) return refuse(r, "e_shnum above this tool's limit (256)");
    if (shstrndx >= shnum) return refuse(r, "e_shstrndx out of range");
    if (!in_bounds(shoff, (uint64_t)shnum * SHDR_SIZE, len))
        return refuse(r, "section header table outside the file");
    const uint8_t *strh = buf + shoff + (uint64_t)shstrndx * SHDR_SIZE;
    uint64_t stroff = rd64(strh + 24), strsize = rd64(strh + 32);
    if (strsize == 0 || !in_bounds(stroff, strsize, len))
        return refuse(r, "section string table outside the file or empty");
    if (buf[stroff + strsize - 1] != 0) return refuse(r, "section string table not NUL-terminated");
    const char *strtab = (const char *)buf + stroff;
    for (uint16_t i = 0; i < shnum; i++) {
        const uint8_t *sh = buf + shoff + (uint64_t)i * SHDR_SIZE;
        uint32_t name = rd32(sh), type = rd32(sh + 4);
        uint64_t off = rd64(sh + 24), size = rd64(sh + 32);
        if (name >= strsize) return refuse(r, "section name index outside the string table");
        if (type != SHT_NOBITS && size > 0 && !in_bounds(off, size, len))
            return refuse(r, "section bounds: offset+size outside the file");
        section *s = &r->sec[r->nsec++];
        s->name = strtab + name; s->type = type; s->offset = off; s->size = size;
    }
    snprintf(r->sig_name, sizeof r->sig_name, ".fwsignature_%s", family);
    for (size_t i = 0; i < r->nsec; i++) {
        const section *s = &r->sec[i];
        if (!strcmp(s->name, ".fwimage")) r->fwimage = s;
        else if (!strcmp(s->name, ".fwversion")) r->fwversion = s;
        else if (!strcmp(s->name, ".note.gnu.build-id")) r->buildid = s;
        else if (!strcmp(s->name, r->sig_name)) r->fwsig = s;
    }
    if (!r->fwimage) return refuse(r, "missing section .fwimage");
    if (r->fwimage->type == SHT_NOBITS || r->fwimage->size == 0) return refuse(r, ".fwimage empty");
    if (!r->fwversion) return refuse(r, "missing section .fwversion");
    if (!r->buildid) return refuse(r, "missing section .note.gnu.build-id");
    if (!r->fwsig) return refuse(r, "missing section: no signature section for this chip family");
    if (r->fwsig->type == SHT_NOBITS || r->fwsig->size == 0) return refuse(r, "signature section empty");
    /* .fwversion: the driver's three conditions, then equality with the pin. */
    const section *v = r->fwversion;
    if (v->type == SHT_NOBITS || v->size == 0 || v->size >= 64) return refuse(r, "version section size not in 1..63");
    if (buf[v->offset + v->size - 1] != 0) return refuse(r, "version string not NUL-terminated");
    memcpy(r->version, buf + v->offset, (size_t)v->size);
    if (expect_version && (v->size != strlen(expect_version) + 1 || strcmp(r->version, expect_version) != 0))
        return refuse(r, "version mismatch against the pinned driver version");
    /* build-id note: namesz, descsz, type, "GNU\0", desc. */
    const section *n = r->buildid;
    if (n->type == SHT_NOBITS || n->size < 16) return refuse(r, "build-id note too short");
    const uint8_t *note = buf + n->offset;
    uint32_t namesz = rd32(note), descsz = rd32(note + 4), ntype = rd32(note + 8);
    if (namesz != 4 || memcmp(note + 12, "GNU", 4) != 0 || ntype != 3)
        return refuse(r, "build-id note is not an NT_GNU_BUILD_ID note");
    if (descsz == 0 || descsz > 64 || 16 + (uint64_t)descsz > n->size)
        return refuse(r, "build-id note descriptor size out of range");
    hex(note + 16, descsz, r->buildid_hex);
    sha256_hash(buf, (size_t)len, r->sha_file);
    sha256_hash(buf + r->fwimage->offset, (size_t)r->fwimage->size, r->sha_image);
    sha256_hash(buf + r->fwsig->offset, (size_t)r->fwsig->size, r->sha_sig);
    return 0;
}

static void print_report(const report *r, int ok)
{
    char h[65];
    for (size_t i = 0; i < r->nsec; i++)
        printf("section %zu %s type=%u offset=%llu size=%llu\n", i, r->sec[i].name[0] ? r->sec[i].name : "(null)",
               (unsigned)r->sec[i].type, (unsigned long long)r->sec[i].offset, (unsigned long long)r->sec[i].size);
    if (ok) {
        printf("fwversion %s\n", r->version);
        printf("build_id %s\n", r->buildid_hex);
        printf("signature_section %s size=%llu\n", r->sig_name, (unsigned long long)r->fwsig->size);
        hex(r->sha_file, 32, h); printf("sha256_file %s\n", h);
        hex(r->sha_image, 32, h); printf("sha256_fwimage %s size=%llu\n", h, (unsigned long long)r->fwimage->size);
        hex(r->sha_sig, 32, h); printf("sha256_signature %s\n", h);
        printf("RESULT OK\n");
    } else {
        printf("RESULT REFUSED %s\n", r->reason);
    }
}

static int cmd_inspect(int argc, char **argv)
{
    const char *path = NULL, *family = DEFAULT_FAMILY, *expect = DEFAULT_VERSION;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--family") && i + 1 < argc) family = argv[++i];
        else if (!strcmp(argv[i], "--expect-version") && i + 1 < argc) expect = argv[++i];
        else if (!path) path = argv[i];
        else { fprintf(stderr, "unexpected argument %s\n", argv[i]); return 1; }
    }
    if (!path) { fprintf(stderr, "usage: ck_gsp_fw_inspect inspect FILE [--family NAME] [--expect-version V]\n"); return 1; }
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return 1; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return 1; }
    rewind(f);
    uint8_t *buf = malloc(sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return 1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { fprintf(stderr, "short read\n"); free(buf); fclose(f); return 1; }
    fclose(f);
    printf("file %s bytes=%ld family=%s expect_version=%s\n", path, sz, family, expect);
    report *r = calloc(1, sizeof *r);
    if (!r) { free(buf); return 1; }
    int rc = inspect_buf(buf, (uint64_t)sz, family, expect, r);
    print_report(r, rc == 0);
    free(r); free(buf);
    return rc == 0 ? 0 : 2;
}

/* ---- self-test fixture: a minimal valid container ---------------------- */
enum { FX_NULL, FX_IMAGE, FX_NOTE, FX_VERSION, FX_SIG, FX_STRTAB, FX_NSEC };
#define FX_IMAGE_OFF 64u
#define FX_IMAGE_LEN 16u
#define FX_NOTE_OFF 80u
#define FX_NOTE_LEN 36u /* 12 + "GNU\0" + 20-byte id */
#define FX_VER_OFF 116u
#define FX_VER_LEN 11u /* "580.173.02\0" */
#define FX_SIG_OFF 128u
#define FX_SIG_LEN 32u
#define FX_STR_OFF 160u
#define FX_SHOFF 256u
#define FX_LEN (FX_SHOFF + FX_NSEC * SHDR_SIZE)

static const char fx_strtab[] = "\0.fwimage\0.note.gnu.build-id\0.fwversion\0.fwsignature_gb10y\0.shstrtab\0";
#define FX_STR_LEN (sizeof fx_strtab)

static void fx_shdr(uint8_t *b, unsigned idx, uint32_t name, uint32_t type, uint64_t off, uint64_t size)
{
    uint8_t *sh = b + FX_SHOFF + idx * SHDR_SIZE;
    memset(sh, 0, SHDR_SIZE);
    wr32(sh, name); wr32(sh + 4, type); wr64(sh + 24, off); wr64(sh + 32, size);
}

static void fx_build(uint8_t *b)
{
    memset(b, 0, FX_LEN);
    b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F'; b[4] = 2; b[5] = 1; b[6] = 1;
    wr16(b + 16, ET_REL); wr16(b + 18, EM_RISCV); wr32(b + 20, 1);
    wr64(b + 40, FX_SHOFF); wr16(b + 52, EHDR_SIZE); wr16(b + 58, SHDR_SIZE);
    wr16(b + 60, FX_NSEC); wr16(b + 62, FX_STRTAB);
    for (unsigned i = 0; i < FX_IMAGE_LEN; i++) b[FX_IMAGE_OFF + i] = (uint8_t)(0xa0 + i);
    wr32(b + FX_NOTE_OFF, 4); wr32(b + FX_NOTE_OFF + 4, 20); wr32(b + FX_NOTE_OFF + 8, 3);
    memcpy(b + FX_NOTE_OFF + 12, "GNU", 4);
    for (unsigned i = 0; i < 20; i++) b[FX_NOTE_OFF + 16 + i] = (uint8_t)i;
    memcpy(b + FX_VER_OFF, DEFAULT_VERSION, FX_VER_LEN);
    for (unsigned i = 0; i < FX_SIG_LEN; i++) b[FX_SIG_OFF + i] = (uint8_t)(0x50 + i);
    memcpy(b + FX_STR_OFF, fx_strtab, FX_STR_LEN);
    fx_shdr(b, FX_NULL, 0, 0, 0, 0);
    fx_shdr(b, FX_IMAGE, 1, 1, FX_IMAGE_OFF, FX_IMAGE_LEN);
    fx_shdr(b, FX_NOTE, 10, 7, FX_NOTE_OFF, FX_NOTE_LEN);
    fx_shdr(b, FX_VERSION, 29, 1, FX_VER_OFF, FX_VER_LEN);
    fx_shdr(b, FX_SIG, 40, 1, FX_SIG_OFF, FX_SIG_LEN);
    fx_shdr(b, FX_STRTAB, 59, 3, FX_STR_OFF, FX_STR_LEN);
}

typedef void (*mutate_fn)(uint8_t *b);
static void m_magic(uint8_t *b) { b[1] = 'X'; }
static void m_class32(uint8_t *b) { b[4] = 1; }
static void m_bigendian(uint8_t *b) { b[5] = 2; }
static void m_type(uint8_t *b) { wr16(b + 16, 2); }
static void m_machine(uint8_t *b) { wr16(b + 18, 62); }
static void m_shentsize(uint8_t *b) { wr16(b + 58, 40); }
static void m_shnum0(uint8_t *b) { wr16(b + 60, 0); }
static void m_shstrndx(uint8_t *b) { wr16(b + 62, FX_NSEC); }
static void m_shoff(uint8_t *b) { wr64(b + 40, FX_LEN - 8); }
static void m_strtab_nul(uint8_t *b) { b[FX_STR_OFF + FX_STR_LEN - 1] = 'x'; }
static void m_name_idx(uint8_t *b) { wr32(b + FX_SHOFF + FX_SIG * SHDR_SIZE, 100000); }
static void m_image_bounds(uint8_t *b) { wr64(b + FX_SHOFF + FX_IMAGE * SHDR_SIZE + 32, FX_LEN); }
static void m_overflow(uint8_t *b) { wr64(b + FX_SHOFF + FX_IMAGE * SHDR_SIZE + 24, UINT64_MAX - 1); }
static void m_image_empty(uint8_t *b) { wr64(b + FX_SHOFF + FX_IMAGE * SHDR_SIZE + 32, 0); }
static void m_version_nul(uint8_t *b) { wr64(b + FX_SHOFF + FX_VERSION * SHDR_SIZE + 32, FX_VER_LEN - 1); }
static void m_version_text(uint8_t *b) { b[FX_VER_OFF + FX_VER_LEN - 2] = '3'; }
static void m_version_long(uint8_t *b) { wr64(b + FX_SHOFF + FX_VERSION * SHDR_SIZE + 32, 64); }
static void m_sig_empty(uint8_t *b) { wr64(b + FX_SHOFF + FX_SIG * SHDR_SIZE + 32, 0); }
static void m_sig_renamed(uint8_t *b) { b[FX_STR_OFF + 40 + 17] = 'x'; } /* .fwsignature_gb10x */
static void m_note_type(uint8_t *b) { wr32(b + FX_NOTE_OFF + 8, 1); }
static void m_note_desc(uint8_t *b) { wr32(b + FX_NOTE_OFF + 4, 40); }
static void m_note_short(uint8_t *b) { wr64(b + FX_SHOFF + FX_NOTE * SHDR_SIZE + 32, 8); }

static const struct { const char *what; mutate_fn fn; const char *reason; } cases[] = {
    { "bad ELF magic", m_magic, "ELF magic" },
    { "32-bit class", m_class32, "not ELF64" },
    { "big-endian", m_bigendian, "little-endian" },
    { "e_type EXEC", m_type, "e_type" },
    { "e_machine x86-64", m_machine, "e_machine" },
    { "e_shentsize 40", m_shentsize, "e_shentsize" },
    { "e_shnum 0", m_shnum0, "e_shnum" },
    { "e_shstrndx == shnum", m_shstrndx, "e_shstrndx" },
    { "section header table past end", m_shoff, "section header table" },
    { "string table not NUL-terminated", m_strtab_nul, "string table not NUL" },
    { "section name index past string table", m_name_idx, "section name index" },
    { ".fwimage size past end of file", m_image_bounds, "section bounds" },
    { ".fwimage offset near UINT64_MAX (overflow)", m_overflow, "section bounds" },
    { ".fwimage empty", m_image_empty, ".fwimage empty" },
    { ".fwversion without NUL", m_version_nul, "NUL-terminated" },
    { ".fwversion text differs from pin", m_version_text, "version mismatch" },
    { ".fwversion 64 bytes", m_version_long, "version section size" },
    { "signature section empty", m_sig_empty, "signature section empty" },
    { "signature section for another family only", m_sig_renamed, "no signature section" },
    { "build-id note wrong type", m_note_type, "NT_GNU_BUILD_ID" },
    { "build-id descriptor past section", m_note_desc, "descriptor size" },
    { "build-id note truncated", m_note_short, "too short" },
};

static int cmd_selftest(void)
{
    uint8_t *b = malloc(FX_LEN);
    report *r = calloc(1, sizeof *r);
    if (!b || !r) return 1;
    int fail = 0;
    fx_build(b);
    if (inspect_buf(b, FX_LEN, "gb10y", DEFAULT_VERSION, r) != 0) {
        printf("FAIL valid fixture refused: %s\n", r->reason); fail = 1;
    } else if (strcmp(r->version, DEFAULT_VERSION) != 0 || strncmp(r->buildid_hex, "000102030405", 12) != 0) {
        printf("FAIL valid fixture parsed wrong (version %s build id %s)\n", r->version, r->buildid_hex); fail = 1;
    } else {
        printf("PASS valid fixture accepted (version %s, build id %s)\n", r->version, r->buildid_hex);
    }
    /* Other family missing on the valid fixture: refused, not silently accepted. */
    if (inspect_buf(b, FX_LEN, "gb10x", DEFAULT_VERSION, r) == 0 || !strstr(r->reason, "no signature section")) {
        printf("FAIL family gb10x should be refused on a gb10y-only fixture\n"); fail = 1;
    } else printf("PASS family gb10x refused: %s\n", r->reason);
    /* Truncated file: every length below FX_LEN must be refused, never crash. */
    int trunc_ok = 1;
    for (uint64_t l = 0; l < FX_LEN; l++)
        if (inspect_buf(b, l, "gb10y", DEFAULT_VERSION, r) == 0) { trunc_ok = 0; break; }
    printf("%s every truncation 0..%u refused\n", trunc_ok ? "PASS" : "FAIL", (unsigned)(FX_LEN - 1));
    if (!trunc_ok) fail = 1;
    size_t n = sizeof cases / sizeof cases[0];
    for (size_t i = 0; i < n; i++) {
        fx_build(b);
        cases[i].fn(b);
        int rc = inspect_buf(b, FX_LEN, "gb10y", DEFAULT_VERSION, r);
        if (rc == 0) { printf("FAIL %s: accepted\n", cases[i].what); fail = 1; }
        else if (!strstr(r->reason, cases[i].reason)) {
            printf("FAIL %s: refused for the wrong reason: %s\n", cases[i].what, r->reason); fail = 1;
        } else printf("PASS %s: %s\n", cases[i].what, r->reason);
    }
    printf("CK_GSP_FW_INSPECT_SELFTEST: %s (%zu mutations)\n", fail ? "FAIL" : "PASS", n);
    free(b); free(r);
    return fail;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "inspect")) return cmd_inspect(argc - 2, argv + 2);
    if (argc == 2 && !strcmp(argv[1], "selftest")) return cmd_selftest();
    fprintf(stderr, "usage: ck_gsp_fw_inspect inspect FILE [--family NAME] [--expect-version V]\n"
                    "       ck_gsp_fw_inspect selftest\n");
    return 1;
}
