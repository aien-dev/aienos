/* artifact_card.c -- see artifact_card.h. No kernel calls, no libc (host-tested by tests/test_artifact_card.c). */
#include "artifact_card.h"

struct ck_acard_boot ck_acard_boot;
uint8_t ck_acard_buf[CK_ACARD_FILE_MAX + 1u] __attribute__((aligned(64)));

static void zero(struct ck_acard *o)
{
    unsigned char *p = (unsigned char *)o;
    for (size_t i = 0; i < sizeof *o; i++) p[i] = 0;
}

static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | rd16(p + 2) << 16; }

int ck_acard_parse(const uint8_t *buf, size_t n, struct ck_acard *out, const char **why)
{
    static const char magic[8] = {'A', 'I', 'E', 'N', 'B', 'N', 'D', 0};
    const char *w = 0;
    size_t at = 12, i;
    uint32_t count = 0, c;
    if (out) zero(out);
    if (!buf || !out) {
        w = "no bundle";
        goto fail;
    }
    if (n < 12 || n > CK_ACARD_FILE_MAX) {
        w = "file size must be 12..131072 bytes";
        goto fail;
    }
    for (i = 0; i < 8; i++)
        if (buf[i] != (uint8_t)magic[i]) {
            w = "bad magic (want AIENBND)";
            goto fail;
        }
    count = rd32(buf + 8);
    if (count < 1 || count > CK_ACARD_MAX_ENTRIES) {
        w = "entry count must be 1..16";
        goto fail;
    }
    for (c = 0; c < count; c++) {
        uint32_t nl, bl;
        if (n - at < 2) {
            w = "truncated entry header";
            goto fail;
        }
        nl = rd16(buf + at);
        at += 2;
        if (nl < 1 || nl > CK_ACARD_NAME_MAX) {
            w = "name length must be 1..32";
            goto fail;
        }
        if (n - at < (size_t)nl + 4u) {
            w = "truncated entry";
            goto fail;
        }
        for (i = 0; i < nl; i++)
            if (buf[at + i] < 0x21 || buf[at + i] > 0x7e) {
                w = "name byte is not printable ASCII";
                goto fail;
            }
        for (uint32_t k = 0; k < c; k++) {
            size_t j = 0;
            while (j < nl && out->e[k].name[j] == (char)buf[at + j]) j++;
            if (j == nl && out->e[k].name[nl] == 0) {
                w = "duplicate name";
                goto fail;
            }
        }
        for (i = 0; i < nl; i++) out->e[c].name[i] = (char)buf[at + i];
        out->e[c].name[nl] = 0;
        at += nl;
        bl = rd32(buf + at);
        at += 4;
        if (bl < 1 || bl > CK_ACARD_ENTRY_MAX) {
            w = "artifact length must be 1..655360";
            goto fail;
        }
        if (n - at < bl) {
            w = "artifact bytes run past the end of the file";
            goto fail;
        }
        out->e[c].len = bl;
        out->e[c].bytes = buf + at;
        at += bl;
    }
#ifndef CK_ACARD_MUTANT_TRAILING
    if (at != n) {
        w = "bytes after the last entry";
        goto fail;
    }
#endif
    out->count = count;
    if (why) *why = 0;
    return 0;
fail:
    if (out) zero(out);
    if (why) *why = w;
    return -1;
}
