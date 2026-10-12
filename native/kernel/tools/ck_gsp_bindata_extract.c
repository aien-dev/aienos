/* ck_gsp_bindata_extract.c -- hosted extractor for the GB10 GSP firmware
 * arrays that the pinned NVIDIA open kernel driver (580.173.02) carries as
 * generated C source (aienos#286 cut C, host work only). Never loads anything.
 *
 * Input: one generated file src/nvidia/generated/g_bindata_<func>.c, e.g.
 *   g_bindata_kgspGetBinArchiveGspRmBoot_GB10B.c            (4 arrays)
 *   g_bindata_kgspGetBinArchiveGspRmFmcGfwProdSigned_GB10B.c (4 arrays)
 *
 * The file format is the driver's own bindata layout: for every array a
 * comment header (FUNCTION, FILE NAME, FILE TYPE, COMPRESSION, COMPLEX_STRUCT,
 * DATA SIZE, COMPRESSED SIZE), the `static BINDATA_CONST NvU8 <ident>_data[]`
 * hex array, a BINDATA_STORAGE_PVT record (uncompressed size, compressed
 * size, pointer, bCompressed, ...) and at the end one BINDATA_ARCHIVE with
 * entryNum and the { label, storage } list (SOURCE: the two files above;
 * bin_data_pvt.h; bin_data.c:36-45 inflates compressed storage with the
 * driver's zlib). Every one of those fields is cross-checked and any
 * disagreement is a refusal: this tool never guesses sizes.
 *
 * Compressed arrays are gzip members without the 10-byte gzip header: a raw
 * DEFLATE stream (RFC 1951) followed by the 8-byte gzip trailer CRC-32 and
 * ISIZE, both little-endian (SOURCE: the driver's own
 * extract-firmware-nouveau.py at tag 580.173.02, lines 107-108, prepends a
 * synthetic gzip header and gzip-decompresses; OBSERVED 2026-10-12 on the
 * 28-byte GB10B descriptor arrays: 20 bytes of fixed-Huffman deflate, CRC-32,
 * then 0x54 = 84). The decoder and the CRC below are our own (no zlib, no
 * outside dependency); the trailer is verified, never trusted.
 *
 * Semantic checks by label (SOURCE: rmRiscvUcode.h RM_RISCV_UCODE_DESC;
 * kernel_gsp_gh100.c:303-333 kgspPopulateWprMeta_GH100 and :718-740 the
 * RISC-V BootROM DMA programming, which shifts every offset by
 * RISCV_BR_ADDR_ALIGNMENT = 8; kernel_gsp_gb10b.c:507-527 the chain-of-trust
 * payload fields hash384 / publicKey / signature):
 *   UCODE_DESC_*  84 bytes, version 5, monitor enabled, manifest + monitor
 *                 data + monitor code inside the matching UCODE_IMAGE_* and
 *                 256-byte aligned
 *   UCODE_HASH    48 bytes and equal to SHA-384 of UCODE_IMAGE (OBSERVED
 *                 2026-10-12 on the GB10B file; enforced here)
 *   UCODE_SIG, UCODE_PKEY  384 bytes (RSA-3072)
 *
 * Usage:
 *   ck_gsp_bindata_extract extract FILE [--out DIR]
 *     Prints one `array` line per label (size, compression, SHA-256), one
 *     `desc` line per descriptor and `RESULT OK`; with --out writes
 *     DIR/<func>.<label>.bin (the uncompressed bytes). Exit 2 + `REFUSED:`.
 *   ck_gsp_bindata_extract selftest
 *     Known-answer tests for SHA-384 and the inflater (stored, fixed and
 *     dynamic Huffman blocks, the real descriptor stream), a synthetic
 *     bindata file that must extract, and every mutation that must be refused.
 *
 * Licence note: the driver files are MIT (SPDX in their header). This tool
 * reads them at run time; nothing from them is vendored into AIENOS.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#define MAX_BLOCKS 16
#define MAX_ARRAY (8u * 1024u * 1024u)
#define MAX_LINE 512
#define DESC_BYTES 84u
#define DESC_VERSION 5u
#define RISCV_BR_ALIGN 256u
#define HASH384_BYTES 48u
#define RSA3072_BYTES 384u

/* ------------------------------------------------------------------------ */
/* SHA-384 (FIPS 180-4), our own                                            */
/* ------------------------------------------------------------------------ */
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

typedef struct {
    uint64_t h[8];
    uint64_t total;
    uint8_t buf[128];
    size_t buflen;
} sha384_ctx;

static uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha384_block(sha384_ctx *c, const uint8_t *p) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | p[i * 8 + j];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        uint64_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint64_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha384_init(sha384_ctx *c) {
    static const uint64_t iv[8] = {
        0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
    };
    memcpy(c->h, iv, sizeof iv);
    c->total = 0;
    c->buflen = 0;
}

static void sha384_update(sha384_ctx *c, const uint8_t *p, size_t n) {
    c->total += n;
    while (n) {
        size_t take = 128 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; n -= take;
        if (c->buflen == 128) { sha384_block(c, c->buf); c->buflen = 0; }
    }
}

static void sha384_final(sha384_ctx *c, uint8_t out[HASH384_BYTES]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    sha384_update(c, &pad, 1);
    c->total -= 1;
    uint8_t z = 0;
    while (c->buflen != 112) { sha384_update(c, &z, 1); c->total -= 1; }
    uint8_t len[16] = {0};
    for (int i = 0; i < 8; i++) len[15 - i] = (uint8_t)(bits >> (8 * i));
    sha384_update(c, len, 16);
    for (int i = 0; i < 6; i++)
        for (int j = 0; j < 8; j++) out[i * 8 + j] = (uint8_t)(c->h[i] >> (56 - 8 * j));
}

static void sha384_hash(const uint8_t *p, size_t n, uint8_t out[HASH384_BYTES]) {
    sha384_ctx c;
    sha384_init(&c);
    sha384_update(&c, p, n);
    sha384_final(&c, out);
}

/* ------------------------------------------------------------------------ */
/* Raw DEFLATE decoder (RFC 1951), our own                                  */
/* ------------------------------------------------------------------------ */
typedef struct {
    const uint8_t *in; size_t inlen, inpos;
    uint32_t bitbuf; int bitcnt;
    uint8_t *out; size_t outlen, outpos;
    const char *err;
} inf_state;

typedef struct { uint16_t count[16]; uint16_t symbol[288]; } huff;

static int inf_bits(inf_state *s, int need, uint32_t *v) {
    while (s->bitcnt < need) {
        if (s->inpos >= s->inlen) { s->err = "inflate: input exhausted"; return -1; }
        s->bitbuf |= (uint32_t)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    *v = s->bitbuf & ((1u << need) - 1u);
    s->bitbuf >>= need;
    s->bitcnt -= need;
    return 0;
}

/* Returns the number of unused codes (0 = complete), -1 = over-subscribed. */
static int huff_construct(huff *h, const uint16_t *length, int n) {
    int offs[16];
    for (int i = 0; i < 16; i++) h->count[i] = 0;
    for (int i = 0; i < n; i++) h->count[length[i]]++;
    if (h->count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len < 16; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return -1;
    }
    offs[1] = 0;
    for (int len = 1; len < 15; len++) offs[len + 1] = offs[len] + h->count[len];
    for (int i = 0; i < n; i++)
        if (length[i] != 0) h->symbol[offs[length[i]]++] = (uint16_t)i;
    return left;
}

static int huff_decode(inf_state *s, const huff *h, int *sym) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; len++) {
        uint32_t b;
        if (inf_bits(s, 1, &b)) return -1;
        code |= (int)b;
        int count = h->count[len];
        if (code - count < first) { *sym = h->symbol[index + (code - first)]; return 0; }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    s->err = "inflate: invalid Huffman code";
    return -1;
}

static int inf_codes(inf_state *s, const huff *lencode, const huff *distcode) {
    static const uint16_t lbase[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
    static const uint16_t lext[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    static const uint16_t dbase[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
    static const uint16_t dext[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    for (;;) {
        int sym;
        if (huff_decode(s, lencode, &sym)) return -1;
        if (sym < 256) {
            if (s->outpos >= s->outlen) { s->err = "inflate: output longer than declared size"; return -1; }
            s->out[s->outpos++] = (uint8_t)sym;
            continue;
        }
        if (sym == 256) return 0;
        sym -= 257;
        if (sym >= 29) { s->err = "inflate: invalid length symbol"; return -1; }
        uint32_t e;
        if (inf_bits(s, lext[sym], &e)) return -1;
        size_t len = lbase[sym] + e;
        if (huff_decode(s, distcode, &sym)) return -1;
        if (sym >= 30) { s->err = "inflate: invalid distance symbol"; return -1; }
        if (inf_bits(s, dext[sym], &e)) return -1;
        size_t dist = dbase[sym] + e;
        if (dist > s->outpos) { s->err = "inflate: distance before start of output"; return -1; }
        if (s->outpos + len > s->outlen) { s->err = "inflate: output longer than declared size"; return -1; }
        while (len--) { s->out[s->outpos] = s->out[s->outpos - dist]; s->outpos++; }
    }
}

static int inf_stored(inf_state *s) {
    s->bitbuf = 0; s->bitcnt = 0;
    if (s->inpos + 4 > s->inlen) { s->err = "inflate: input exhausted"; return -1; }
    unsigned len = s->in[s->inpos] | (s->in[s->inpos + 1] << 8);
    unsigned nlen = s->in[s->inpos + 2] | (s->in[s->inpos + 3] << 8);
    s->inpos += 4;
    if ((len ^ 0xffffu) != nlen) { s->err = "inflate: stored block length check failed"; return -1; }
    if (s->inpos + len > s->inlen) { s->err = "inflate: input exhausted"; return -1; }
    if (s->outpos + len > s->outlen) { s->err = "inflate: output longer than declared size"; return -1; }
    memcpy(s->out + s->outpos, s->in + s->inpos, len);
    s->inpos += len; s->outpos += len;
    return 0;
}

static int inf_fixed(inf_state *s) {
    static huff lencode, distcode;
    static int built = 0;
    if (!built) {
        uint16_t lengths[288];
        int i = 0;
        for (; i < 144; i++) lengths[i] = 8;
        for (; i < 256; i++) lengths[i] = 9;
        for (; i < 280; i++) lengths[i] = 7;
        for (; i < 288; i++) lengths[i] = 8;
        huff_construct(&lencode, lengths, 288);
        for (i = 0; i < 30; i++) lengths[i] = 5;
        huff_construct(&distcode, lengths, 30);
        built = 1;
    }
    return inf_codes(s, &lencode, &distcode);
}

static int inf_dynamic(inf_state *s) {
    static const uint16_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    uint16_t lengths[320];
    huff lencode, distcode;
    uint32_t v;
    if (inf_bits(s, 5, &v)) return -1;
    int nlen = (int)v + 257;
    if (inf_bits(s, 5, &v)) return -1;
    int ndist = (int)v + 1;
    if (inf_bits(s, 4, &v)) return -1;
    int ncode = (int)v + 4;
    if (nlen > 286 || ndist > 30) { s->err = "inflate: bad code counts"; return -1; }
    int i;
    for (i = 0; i < ncode; i++) { if (inf_bits(s, 3, &v)) return -1; lengths[order[i]] = (uint16_t)v; }
    for (; i < 19; i++) lengths[order[i]] = 0;
    if (huff_construct(&lencode, lengths, 19) != 0) { s->err = "inflate: bad code-length code"; return -1; }
    i = 0;
    while (i < nlen + ndist) {
        int sym;
        if (huff_decode(s, &lencode, &sym)) return -1;
        if (sym < 16) { lengths[i++] = (uint16_t)sym; continue; }
        uint16_t rep = 0;
        int count;
        if (sym == 16) {
            if (i == 0) { s->err = "inflate: repeat with no previous length"; return -1; }
            rep = lengths[i - 1];
            if (inf_bits(s, 2, &v)) return -1;
            count = 3 + (int)v;
        } else if (sym == 17) {
            if (inf_bits(s, 3, &v)) return -1;
            count = 3 + (int)v;
        } else {
            if (inf_bits(s, 7, &v)) return -1;
            count = 11 + (int)v;
        }
        if (i + count > nlen + ndist) { s->err = "inflate: too many lengths"; return -1; }
        while (count--) lengths[i++] = rep;
    }
    if (lengths[256] == 0) { s->err = "inflate: no end-of-block code"; return -1; }
    int err = huff_construct(&lencode, lengths, nlen);
    if (err < 0 || (err > 0 && nlen - lencode.count[0] != 1)) { s->err = "inflate: bad literal/length code"; return -1; }
    err = huff_construct(&distcode, lengths + nlen, ndist);
    if (err < 0 || (err > 0 && ndist - distcode.count[0] != 1)) { s->err = "inflate: bad distance code"; return -1; }
    return inf_codes(s, &lencode, &distcode);
}

/* Inflate exactly outlen bytes from the raw stream in[0..inlen); the stream
 * must end with its final block in the last input byte. */
static int inflate_raw(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen, const char **why) {
    inf_state s = {in, inlen, 0, 0, 0, out, outlen, 0, "inflate: ok"};
    uint32_t last, type;
    do {
        if (inf_bits(&s, 1, &last)) { *why = s.err; return -1; }
        if (inf_bits(&s, 2, &type)) { *why = s.err; return -1; }
        int rc = type == 0 ? inf_stored(&s) : type == 1 ? inf_fixed(&s) : type == 2 ? inf_dynamic(&s) : -2;
        if (rc == -2) { *why = "inflate: invalid block type 3"; return -1; }
        if (rc) { *why = s.err; return -1; }
    } while (!last);
    if (s.outpos != s.outlen) { *why = "inflate: output shorter than declared size"; return -1; }
    if (s.inpos != s.inlen) { *why = "inflate: trailing bytes after the final block"; return -1; }
    return 0;
}

static uint32_t crc32_bytes(const uint8_t *p, size_t n) {
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
    }
    return ~c;
}

static uint32_t get32le(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

/* A bindata compressed array: deflate body + CRC-32 + ISIZE. */
static int unpack_gz_body(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen, const char **why) {
    if (inlen < 9) { *why = "compressed array shorter than a deflate block plus its 8-byte trailer"; return -1; }
    if (inflate_raw(in, inlen - 8, out, outlen, why)) return -1;
    if (get32le(in + inlen - 4) != outlen) { *why = "compressed trailer: ISIZE differs from DATA SIZE"; return -1; }
    if (get32le(in + inlen - 8) != crc32_bytes(out, outlen)) { *why = "compressed trailer: CRC-32 mismatch"; return -1; }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* bindata file parser                                                      */
/* ------------------------------------------------------------------------ */
typedef struct {
    char func[96];
    char label[64];
    char fname[160];
    char ident[192];
    int compressed;
    uint32_t data_size, comp_size;
    uint8_t *bytes;   /* as stored in the array */
    size_t nbytes;
    uint8_t *plain;   /* uncompressed (== bytes when not compressed) */
    size_t plain_len;
    int have_header, have_data, have_pvt;
} bd_block;

typedef struct {
    bd_block b[MAX_BLOCKS];
    int n;
    char func[96];
    int archive_seen;
    int entry_num;
    char reason[256];
} bd_file;

typedef struct { const char *p, *end; int lineno; } cursor;

static void bd_free(bd_file *f) {
    for (int i = 0; i < f->n; i++) {
        free(f->b[i].bytes);
        if (f->b[i].plain != f->b[i].bytes) free(f->b[i].plain);
        f->b[i].bytes = f->b[i].plain = NULL;
    }
}

static int refuse(bd_file *f, const cursor *c, const char *fmt, const char *a) {
    int n = snprintf(f->reason, sizeof f->reason, "line %d: ", c ? c->lineno : 0);
    if (n < 0) n = 0;
    snprintf(f->reason + n, sizeof f->reason - (size_t)n, fmt, a ? a : "");
    return -1;
}

/* Copy the next line (without its newline) into buf; 1 = got a line, 0 = EOF. */
static int next_line(cursor *c, char *buf, size_t cap, bd_file *f) {
    if (c->p >= c->end) return 0;
    const char *nl = memchr(c->p, '\n', (size_t)(c->end - c->p));
    size_t len = nl ? (size_t)(nl - c->p) : (size_t)(c->end - c->p);
    c->lineno++;
    if (len >= cap) { refuse(f, c, "line longer than %s characters", "511"); return -1; }
    memcpy(buf, c->p, len);
    buf[len] = 0;
    if (len && buf[len - 1] == '\r') buf[len - 1] = 0;
    c->p = nl ? nl + 1 : c->end;
    return 1;
}

static const char *after(const char *line, const char *prefix) {
    size_t n = strlen(prefix);
    return strncmp(line, prefix, n) == 0 ? line + n : NULL;
}

static int parse_u32(const char *s, uint32_t *v) {
    if (*s < '0' || *s > '9') return -1;
    uint64_t acc = 0;
    while (*s >= '0' && *s <= '9') { acc = acc * 10 + (uint64_t)(*s - '0'); if (acc > 0xffffffffULL) return -1; s++; }
    while (*s == ' ' || *s == ',' || *s == '\t') s++;
    if (*s && strncmp(s, "//", 2) != 0) return -1;
    *v = (uint32_t)acc;
    return 0;
}

static int copy_field(char *dst, size_t cap, const char *src, size_t len) {
    if (len == 0 || len >= cap) return -1;
    memcpy(dst, src, len);
    dst[len] = 0;
    return 0;
}

static bd_block *cur_block(bd_file *f) { return f->n ? &f->b[f->n - 1] : NULL; }

static int parse_hex_array(cursor *c, bd_file *f, bd_block *b) {
    char line[MAX_LINE];
    size_t want = b->compressed ? b->comp_size : b->data_size;
    if (want == 0 || want > MAX_ARRAY) return refuse(f, c, "array size out of range for %s", b->label);
    if (next_line(c, line, sizeof line, f) != 1 || strcmp(line, "{") != 0) return refuse(f, c, "expected '{' after the array declaration of %s", b->label);
    b->bytes = malloc(want);
    if (!b->bytes) return refuse(f, c, "out of memory for %s", b->label);
    b->nbytes = 0;
    for (;;) {
        int r = next_line(c, line, sizeof line, f);
        if (r < 0) return -1;
        if (r == 0) return refuse(f, c, "file ends inside the array of %s", b->label);
        if (strcmp(line, "};") == 0) break;
        const char *p = line;
        while (*p) {
            while (*p == ' ' || *p == '\t') p++;
            if (!*p) break;
            if (p[0] != '0' || p[1] != 'x') return refuse(f, c, "non-hex token in the array of %s", b->label);
            unsigned v = 0;
            for (int k = 2; k < 4; k++) {
                char ch = p[k];
                unsigned d = ch >= '0' && ch <= '9' ? (unsigned)(ch - '0') : ch >= 'a' && ch <= 'f' ? (unsigned)(ch - 'a' + 10) : ch >= 'A' && ch <= 'F' ? (unsigned)(ch - 'A' + 10) : 16u;
                if (d == 16u) return refuse(f, c, "non-hex token in the array of %s", b->label);
                v = v * 16 + d;
            }
            if (p[4] != ',') return refuse(f, c, "byte token without a trailing comma in %s", b->label);
            if (b->nbytes >= want) return refuse(f, c, "more bytes than the declared size in %s", b->label);
            b->bytes[b->nbytes++] = (uint8_t)v;
            p += 5;
        }
    }
    if (b->nbytes != want) return refuse(f, c, "fewer bytes than the declared size in %s", b->label);
    b->have_data = 1;
    return 0;
}

static int parse_pvt(cursor *c, bd_file *f, bd_block *b) {
    char line[MAX_LINE];
    uint32_t v;
    if (next_line(c, line, sizeof line, f) != 1 || strcmp(line, "{") != 0) return refuse(f, c, "expected '{' in the storage record of %s", b->label);
    if (next_line(c, line, sizeof line, f) != 1 || parse_u32(line + strspn(line, " "), &v)) return refuse(f, c, "storage record: bad uncompressed size for %s", b->label);
    if (v != b->data_size) return refuse(f, c, "storage record: uncompressed size differs from DATA SIZE for %s", b->label);
    if (next_line(c, line, sizeof line, f) != 1 || parse_u32(line + strspn(line, " "), &v)) return refuse(f, c, "storage record: bad compressed size for %s", b->label);
    if (v != (b->compressed ? b->comp_size : b->data_size)) return refuse(f, c, "storage record: compressed size differs from the header for %s", b->label);
    if (next_line(c, line, sizeof line, f) != 1) return refuse(f, c, "storage record: missing pointer line for %s", b->label);
    const char *p = line + strspn(line, " ");
    size_t n = strlen(b->ident);
    if (strncmp(p, b->ident, n) != 0 || p[n] != ',') return refuse(f, c, "storage record: data pointer is not the array of %s", b->label);
    if (next_line(c, line, sizeof line, f) != 1) return refuse(f, c, "storage record: missing compressed flag for %s", b->label);
    p = line + strspn(line, " ");
    int flag = after(p, "NV_TRUE,") ? 1 : after(p, "NV_FALSE,") ? 0 : -1;
    if (flag < 0) return refuse(f, c, "storage record: bad compressed flag for %s", b->label);
    if (flag != b->compressed) return refuse(f, c, "storage record: compressed flag disagrees with COMPRESSION for %s", b->label);
    b->have_pvt = 1;
    return 0;
}

static int parse_archive(cursor *c, bd_file *f, const char *decl) {
    char line[MAX_LINE];
    uint32_t v;
    if (f->archive_seen) return refuse(f, c, "second archive table%s", "");
    const char *name = after(decl, "static const BINDATA_ARCHIVE __");
    size_t n = strlen(f->func);
    if (!name || strncmp(name, f->func, n) != 0 || strcmp(name + n, " =") != 0) return refuse(f, c, "archive table name is not the file's function%s", "");
    if (next_line(c, line, sizeof line, f) != 1 || strcmp(line, "{") != 0) return refuse(f, c, "expected '{' after the archive declaration%s", "");
    if (next_line(c, line, sizeof line, f) != 1 || parse_u32(line + strspn(line, " "), &v)) return refuse(f, c, "archive: bad entryNum%s", "");
    if ((int)v != f->n) return refuse(f, c, "archive: entryNum differs from the number of arrays%s", "");
    f->entry_num = (int)v;
    if (next_line(c, line, sizeof line, f) != 1 || strcmp(line + strspn(line, " "), "{") != 0) return refuse(f, c, "archive: expected entries block%s", "");
    if (next_line(c, line, sizeof line, f) != 1 || !after(line + strspn(line, " "), "// entries[]")) return refuse(f, c, "archive: expected the entries comment%s", "");
    for (int i = 0; i < f->n; i++) {
        if (next_line(c, line, sizeof line, f) != 1) return refuse(f, c, "archive: missing entry %s", f->b[i].label);
        const char *p = line + strspn(line, " ");
        const char *lab = after(p, "{ BINDATA_LABEL_");
        if (!lab) return refuse(f, c, "archive: malformed entry for %s", f->b[i].label);
        size_t ll = strlen(f->b[i].label);
        if (strncmp(lab, f->b[i].label, ll) != 0 || (lab[ll] != ' ' && lab[ll] != ',')) return refuse(f, c, "archive: entry order or label differs from the arrays at %s", f->b[i].label);
        const char *idx = strstr(lab, "&g_bindata_pvt[__idx_");
        if (!idx) return refuse(f, c, "archive: entry without a storage index for %s", f->b[i].label);
        idx += strlen("&g_bindata_pvt[__idx_");
        size_t il = strlen(f->b[i].ident) - strlen("_data");
        if (strncmp(idx, f->b[i].ident, il) != 0 || idx[il] != ']') return refuse(f, c, "archive: storage index is not this array for %s", f->b[i].label);
    }
    if (next_line(c, line, sizeof line, f) != 1 || strcmp(line + strspn(line, " "), "}") != 0) return refuse(f, c, "archive: expected end of entries%s", "");
    if (next_line(c, line, sizeof line, f) != 1 || strcmp(line, "};") != 0) return refuse(f, c, "archive: expected end of table%s", "");
    f->archive_seen = 1;
    return 0;
}

static int parse_file(bd_file *f, const char *text, size_t len) {
    cursor c = {text, text + len, 0};
    char line[MAX_LINE];
    memset(f, 0, sizeof *f);
    for (;;) {
        int r = next_line(&c, line, sizeof line, f);
        if (r < 0) return -1;
        if (r == 0) break;
        const char *v;
        bd_block *b = cur_block(f);
        if ((v = after(line, "// FUNCTION: "))) {
            if (b && !(b->have_data && b->have_pvt)) return refuse(f, &c, "array %s has no data or no storage record", b->label);
            if (f->n >= MAX_BLOCKS) return refuse(f, &c, "more than %s arrays", "16");
            const char *lp = strchr(v, '(');
            if (!lp || strncmp(lp, "(\"BINDATA_LABEL_", 16) != 0) return refuse(f, &c, "FUNCTION line without a BINDATA_LABEL%s", "");
            const char *le = strstr(lp + 16, "\")");
            if (!le || le[2] != 0) return refuse(f, &c, "FUNCTION line not terminated%s", "");
            b = &f->b[f->n++];
            if (copy_field(b->func, sizeof b->func, v, (size_t)(lp - v))) return refuse(f, &c, "bad function name%s", "");
            if (copy_field(b->label, sizeof b->label, lp + 16, (size_t)(le - lp - 16))) return refuse(f, &c, "bad label%s", "");
            if (f->n == 1) strcpy(f->func, b->func);
            else if (strcmp(f->func, b->func) != 0) return refuse(f, &c, "array belongs to a different function: %s", b->func);
            for (int i = 0; i < f->n - 1; i++)
                if (strcmp(f->b[i].label, b->label) == 0) return refuse(f, &c, "duplicate label %s", b->label);
            b->comp_size = 0xffffffffu; b->compressed = -1; b->data_size = 0;
            const char *stem = after(b->func, "kgspGetBinArchive");
            if (!stem) return refuse(f, &c, "function is not a kgspGetBinArchive function: %s", b->func);
            char ident[sizeof b->ident];
            if (snprintf(ident, sizeof ident, "kgspBinArchive%s_BINDATA_LABEL_%s_data", stem, b->label) >= (int)sizeof ident) return refuse(f, &c, "identifier too long for %s", b->label);
            memcpy(b->ident, ident, sizeof ident);
            continue;
        }
        if (!b) {
            if (after(line, "static BINDATA_CONST") || after(line, "static const BINDATA_ARCHIVE")) return refuse(f, &c, "data before the first FUNCTION header%s", "");
            continue;
        }
        if ((v = after(line, "// FILE NAME: "))) { if (copy_field(b->fname, sizeof b->fname, v, strlen(v))) return refuse(f, &c, "bad file name for %s", b->label); continue; }
        if ((v = after(line, "// FILE TYPE: "))) { if (strcmp(v, "BINARY") != 0) return refuse(f, &c, "FILE TYPE is not BINARY for %s", b->label); continue; }
        if ((v = after(line, "// COMPRESSION: "))) {
            if (strcmp(v, "YES") == 0) b->compressed = 1;
            else if (strcmp(v, "NO") == 0) b->compressed = 0;
            else return refuse(f, &c, "COMPRESSION is neither YES nor NO for %s", b->label);
            continue;
        }
        if ((v = after(line, "// COMPLEX_STRUCT: "))) { if (strcmp(v, "NO") != 0) return refuse(f, &c, "COMPLEX_STRUCT is not NO for %s", b->label); continue; }
        if ((v = after(line, "// DATA SIZE (bytes): "))) { if (parse_u32(v, &b->data_size)) return refuse(f, &c, "bad DATA SIZE for %s", b->label); continue; }
        if ((v = after(line, "// COMPRESSED SIZE (bytes): "))) {
            if (strcmp(v, "N/A") == 0) b->comp_size = 0;
            else if (parse_u32(v, &b->comp_size)) return refuse(f, &c, "bad COMPRESSED SIZE for %s", b->label);
            continue;
        }
        if ((v = after(line, "static BINDATA_CONST NvU8 "))) {
            if (b->have_data) return refuse(f, &c, "second array for %s", b->label);
            if (b->compressed < 0 || b->data_size == 0 || b->comp_size == 0xffffffffu || !b->fname[0]) return refuse(f, &c, "array header incomplete for %s", b->label);
            if (b->compressed == 1 && b->comp_size == 0) return refuse(f, &c, "COMPRESSED SIZE missing with COMPRESSION YES for %s", b->label);
            if (b->compressed == 0 && b->comp_size != 0) return refuse(f, &c, "COMPRESSED SIZE given with COMPRESSION NO for %s", b->label);
            size_t n = strlen(b->ident);
            if (strncmp(v, b->ident, n) != 0 || strcmp(v + n, "[] = ") != 0) return refuse(f, &c, "array identifier is not the expected one for %s", b->label);
            b->have_header = 1;
            if (parse_hex_array(&c, f, b)) return -1;
            continue;
        }
        if (strcmp(line, "#if defined(BINDATA_INCLUDE_STORAGE_PVT_DEFN)") == 0) {
            if (!b->have_data) return refuse(f, &c, "storage record before the array of %s", b->label);
            if (b->have_pvt) return refuse(f, &c, "second storage record for %s", b->label);
            if (parse_pvt(&c, f, b)) return -1;
            continue;
        }
        if (after(line, "static const BINDATA_ARCHIVE __")) {
            if (!(b->have_data && b->have_pvt)) return refuse(f, &c, "array %s has no data or no storage record", b->label);
            if (parse_archive(&c, f, line)) return -1;
            continue;
        }
    }
    if (f->n == 0) return refuse(f, &c, "no arrays found%s", "");
    if (!f->archive_seen) return refuse(f, &c, "no archive table%s", "");
    for (int i = 0; i < f->n; i++) {
        bd_block *b = &f->b[i];
        if (!(b->have_data && b->have_pvt)) return refuse(f, &c, "array %s has no data or no storage record", b->label);
        if (b->compressed) {
            b->plain = malloc(b->data_size);
            if (!b->plain) return refuse(f, &c, "out of memory for %s", b->label);
            const char *why;
            if (unpack_gz_body(b->bytes, b->nbytes, b->plain, b->data_size, &why)) {
                char msg[200];
                snprintf(msg, sizeof msg, "%s (%s)", why, b->label);
                return refuse(f, NULL, "%s", msg);
            }
            b->plain_len = b->data_size;
        } else {
            b->plain = b->bytes;
            b->plain_len = b->nbytes;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Semantic checks                                                          */
/* ------------------------------------------------------------------------ */
static const bd_block *find_label(const bd_file *f, const char *label) {
    for (int i = 0; i < f->n; i++)
        if (strcmp(f->b[i].label, label) == 0) return &f->b[i];
    return NULL;
}

typedef struct {
    uint32_t version, bootloader_off, bootloader_size, bl_param_off, bl_param_size, elf_off, elf_size, app_version;
    uint32_t manifest_off, manifest_size, mdata_off, mdata_size, mcode_off, mcode_size, monitor_enabled;
    uint32_t swbrom_code_off, swbrom_code_size, swbrom_data_off, swbrom_data_size, fb_reserved, signed_as_code;
} riscv_desc;

static void decode_desc(const uint8_t *p, riscv_desc *d) {
    uint32_t *w = (uint32_t *)d;
    for (int i = 0; i < 21; i++) w[i] = get32le(p + 4 * i);
}

static int region_ok(uint32_t off, uint32_t size, size_t image) {
    return size != 0 && (off % RISCV_BR_ALIGN) == 0 && (uint64_t)off + size <= image;
}

static int check_semantics(bd_file *f, FILE *out) {
    for (int i = 0; i < f->n; i++) {
        bd_block *b = &f->b[i];
        const char *suffix = after(b->label, "UCODE_DESC");
        if (suffix) {
            if (b->plain_len != DESC_BYTES) return refuse(f, NULL, "descriptor is not 84 bytes: %s", b->label);
            riscv_desc d;
            decode_desc(b->plain, &d);
            if (d.version != DESC_VERSION) return refuse(f, NULL, "descriptor version is not 5: %s", b->label);
            if (d.monitor_enabled != 1) return refuse(f, NULL, "descriptor monitor not enabled: %s", b->label);
            char img[64];
            snprintf(img, sizeof img, "UCODE_IMAGE%s", suffix);
            const bd_block *ib = find_label(f, img);
            if (!ib) return refuse(f, NULL, "descriptor without a matching image: %s", b->label);
            if (!region_ok(d.manifest_off, d.manifest_size, ib->plain_len)) return refuse(f, NULL, "descriptor manifest region outside the image or unaligned: %s", b->label);
            if (!region_ok(d.mdata_off, d.mdata_size, ib->plain_len)) return refuse(f, NULL, "descriptor monitor-data region outside the image or unaligned: %s", b->label);
            if (!region_ok(d.mcode_off, d.mcode_size, ib->plain_len)) return refuse(f, NULL, "descriptor monitor-code region outside the image or unaligned: %s", b->label);
            if (out)
                fprintf(out, "desc %s version=%u manifest=0x%x+0x%x monitor_data=0x%x+0x%x monitor_code=0x%x+0x%x monitor_enabled=%u fb_reserved=0x%x signed_as_code=%u app_version=%u image=%s/%zu\n",
                        b->label, d.version, d.manifest_off, d.manifest_size, d.mdata_off, d.mdata_size, d.mcode_off, d.mcode_size,
                        d.monitor_enabled, d.fb_reserved, d.signed_as_code, d.app_version, img, ib->plain_len);
        } else if (strcmp(b->label, "UCODE_HASH") == 0) {
            if (b->plain_len != HASH384_BYTES) return refuse(f, NULL, "hash array is not 48 bytes%s", "");
            const bd_block *ib = find_label(f, "UCODE_IMAGE");
            if (!ib) return refuse(f, NULL, "hash array without UCODE_IMAGE%s", "");
            uint8_t h[HASH384_BYTES];
            sha384_hash(ib->plain, ib->plain_len, h);
            if (memcmp(h, b->plain, HASH384_BYTES) != 0) return refuse(f, NULL, "UCODE_HASH is not SHA-384 of UCODE_IMAGE%s", "");
            if (out) fprintf(out, "hash384 UCODE_HASH equals sha384(UCODE_IMAGE)\n");
        } else if (strcmp(b->label, "UCODE_SIG") == 0 || strcmp(b->label, "UCODE_PKEY") == 0) {
            if (b->plain_len != RSA3072_BYTES) return refuse(f, NULL, "%s is not 384 bytes", b->label);
        } else if (!after(b->label, "UCODE_IMAGE")) {
            return refuse(f, NULL, "unknown label %s", b->label);
        }
    }
    return 0;
}

static void hex(const uint8_t *p, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[p[i] >> 4]; out[2 * i + 1] = d[p[i] & 15]; }
    out[2 * n] = 0;
}

static int report(const bd_file *f, FILE *out, const char *outdir) {
    for (int i = 0; i < f->n; i++) {
        const bd_block *b = &f->b[i];
        uint8_t d[32];
        char hx[65];
        sha256_hash(b->plain, b->plain_len, d);
        hex(d, 32, hx);
        fprintf(out, "array %s %s file=%s stored=%zu compressed=%s size=%zu sha256=%s\n", b->func, b->label, b->fname, b->nbytes, b->compressed ? "yes" : "no", b->plain_len, hx);
        if (outdir) {
            char path[512];
            if (snprintf(path, sizeof path, "%s/%s.%s.bin", outdir, b->func, b->label) >= (int)sizeof path) { fprintf(out, "REFUSED: output path too long\n"); return 2; }
            FILE *w = fopen(path, "wb");
            if (!w || fwrite(b->plain, 1, b->plain_len, w) != b->plain_len || fclose(w)) { fprintf(out, "REFUSED: cannot write %s: %s\n", path, strerror(errno)); return 2; }
            fprintf(out, "wrote %s\n", path);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* CLI                                                                      */
/* ------------------------------------------------------------------------ */
static char *read_file(const char *path, size_t *len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END)) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0 || sz > 64L * 1024 * 1024) { fclose(fp); errno = EFBIG; return NULL; }
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) { free(buf); fclose(fp); errno = EIO; return NULL; }
    fclose(fp);
    buf[sz] = 0;
    *len = (size_t)sz;
    return buf;
}

static int cmd_extract(int argc, char **argv) {
    const char *path = NULL, *outdir = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) outdir = argv[++i];
        else if (!path) path = argv[i];
        else { fprintf(stderr, "usage: ck_gsp_bindata_extract extract FILE [--out DIR]\n"); return 1; }
    }
    if (!path) { fprintf(stderr, "usage: ck_gsp_bindata_extract extract FILE [--out DIR]\n"); return 1; }
    size_t len;
    char *text = read_file(path, &len);
    if (!text) { printf("REFUSED: cannot read %s: %s\n", path, strerror(errno)); return 2; }
    bd_file *f = calloc(1, sizeof *f);
    if (!f) { free(text); printf("REFUSED: out of memory\n"); return 2; }
    int rc = parse_file(f, text, len);
    free(text);
    if (rc == 0) { printf("function %s arrays=%d\n", f->func, f->n); rc = check_semantics(f, stdout); }
    if (rc) { printf("REFUSED: %s\n", f->reason); bd_free(f); free(f); return 2; }
    rc = report(f, stdout, outdir);
    if (rc == 0) printf("RESULT OK arrays=%d\n", f->n);
    bd_free(f);
    free(f);
    return rc;
}

/* ------------------------------------------------------------------------ */
/* Self-test                                                                */
/* ------------------------------------------------------------------------ */
static int failures, checks;
static void check(int ok, const char *what) {
    checks++;
    if (!ok) { failures++; printf("FAIL: %s\n", what); }
}

static size_t unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (; s[0] && s[1] && n < cap; s += 2, n++) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) return 0;
        out[n] = (uint8_t)v;
    }
    return n;
}

/* Test vectors. Deflate streams were produced once with a reference
 * compressor (raw, level 0 / 1 / 9) and are compared against the plaintext
 * (stored, fixed) or its SHA-256 (dynamic, 760 bytes). */
static const char STORED_STREAM[] = "011b00e4ff4149454e4f532073746f72656420626c6f636b2000ff7f20656e64";
static const char STORED_PLAIN[] = "4149454e4f532073746f72656420626c6f636b2000ff7f20656e64";
static const char FIXED_STREAM[] = "4b4c4a4e240e290200";
static const char FIXED_PLAIN[] = "61626361626361626361626361626361626361626361626361626361626361626361626361626361626321";
static const char DYNAMIC_STREAM[] =
    "75525b12c2200cbc0a67f04614538711689db6eaf11df280a4d22f1ed9ddec068adfe31bdc06e1e6a6e4c3f30329b9c7b6ba3907977d4cd3f2c57d21e41de6e47740889421436e9caed277f51e415ad4b613dd06d58d642faba5b6f6a28c697c84b26c0a8ab73a91a831d2b0755d56ecc363384f67e416f1af030e1864661d2a0b834e5c625ba8829eda042f8c1b361d18a1873b7e026c50d46720fef5971049e6d8c5e6b127f1c0d6fa65ed70f26b42fccdae124c6634aeb352b5fd1116aab01f";
static const char DYNAMIC_SHA256[] = "384833836853e0d0bbe4d054c4f167ce73bf9c120e749d76da574a55c1b0516a";
#define DYNAMIC_LEN 760
/* The GB10B RM_RISCV_UCODE_DESC arrays (DBG and PROD are byte-identical),
 * 28 bytes of fixed-Huffman deflate, from the pinned driver file. */
static const char GB10B_DESC_STREAM[] = "636520027041f13220de00c4be4c0c8c78f40100b72bc9c254000000";
static const uint32_t GB10B_DESC_WORDS[21] = {5, 0, 0, 0, 0, 0, 0, 0, 0, 0xa00, 0xa00, 0xa600, 0xb000, 0x24d00, 1, 0, 0, 0, 0, 0, 0};

/* Synthetic bindata file generator. */
typedef struct { const char *label, *fname; int compressed; uint32_t data_size; const uint8_t *bytes; size_t n; } fx_array;

static size_t fx_emit(char *buf, size_t cap, const char *func, const fx_array *a, int n) {
    size_t o = 0;
    const char *stem = func + strlen("kgspGetBinArchive");
#define EMIT(...) do { int w_ = snprintf(buf + o, cap - o, __VA_ARGS__); if (w_ < 0 || (size_t)w_ >= cap - o) return 0; o += (size_t)w_; } while (0)
    EMIT("/* synthetic */\n\n");
    for (int i = 0; i < n; i++) {
        EMIT("#if defined(BINDATA_INCLUDE_DATA)\n//\n// FUNCTION: %s(\"BINDATA_LABEL_%s\")\n// FILE NAME: %s\n// FILE TYPE: BINARY\n// VAR NAME: N/A\n// COMPRESSION: %s\n// COMPLEX_STRUCT: NO\n// DATA SIZE (bytes): %u\n// COMPRESSED SIZE (bytes): ",
             func, a[i].label, a[i].fname, a[i].compressed ? "YES" : "NO", a[i].data_size);
        if (a[i].compressed) EMIT("%zu\n", a[i].n); else EMIT("N/A\n");
        EMIT("//\nstatic BINDATA_CONST NvU8 kgspBinArchive%s_BINDATA_LABEL_%s_data[] = \n{\n", stem, a[i].label);
        for (size_t k = 0; k < a[i].n; k++) {
            if (k % 16 == 0) EMIT("    ");
            EMIT("0x%02x,%s", a[i].bytes[k], (k % 16 == 15 || k + 1 == a[i].n) ? "\n" : " ");
        }
        EMIT("};\n#endif // defined(BINDATA_INCLUDE_DATA)\n\n#if defined(BINDATA_INCLUDE_STORAGE_PVT_DECL)\nBINDATA_STORAGE_PVT kgspBinArchive%s_BINDATA_LABEL_%s_storage_pvt;\n#endif // defined(BINDATA_INCLUDE_STORAGE_PVT_DECL)\n\n", stem, a[i].label);
        EMIT("#if defined(BINDATA_INCLUDE_STORAGE_PVT_DEFN)\n{\n    %u,  // uncompressed data size (bytes)\n    %zu,  // compressed data size (bytes)\n    kgspBinArchive%s_BINDATA_LABEL_%s_data,  // compressed data pointer\n    %s,  // is pData compressed?\n    NV_TRUE,  // contain information for file overriding?\n    NV_FALSE,  // is the data referenced during load?\n},\n#endif // defined(BINDATA_INCLUDE_STORAGE_PVT_DEFN)\n\n",
             a[i].data_size, a[i].n, stem, a[i].label, a[i].compressed ? "NV_TRUE" : "NV_FALSE");
    }
    EMIT("#if defined(BINDATA_INCLUDE_ARCHIVE)\n//\n// Bindata Archive structure\n//\nstatic const BINDATA_ARCHIVE __%s =\n{\n    %d,  // entryNum\n    {\n        // entries[] : { label, pBinStorage }\n", func, n);
    for (int i = 0; i < n; i++)
        EMIT("        { BINDATA_LABEL_%s , (const PBINDATA_STORAGE) &g_bindata_pvt[__idx_kgspBinArchive%s_BINDATA_LABEL_%s] },\n", a[i].label, stem, a[i].label);
    EMIT("    }\n};\n\n#endif // defined(BINDATA_INCLUDE_ARCHIVE)\n");
#undef EMIT
    return o;
}

static int fx_try(const char *text, size_t len, char *reason, size_t cap) {
    bd_file *f = calloc(1, sizeof *f);
    if (!f) return -1;
    int rc = parse_file(f, text, len);
    if (rc == 0) rc = check_semantics(f, NULL);
    snprintf(reason, cap, "%s", f->reason);
    bd_free(f);
    free(f);
    return rc;
}

static void expect_refused(const char *text, size_t len, const char *want, const char *what) {
    char reason[256];
    int rc = fx_try(text, len, reason, sizeof reason);
    checks++;
    if (rc == 0 || !strstr(reason, want)) {
        failures++;
        printf("FAIL: %s: rc=%d reason='%s' (want '%s')\n", what, rc, reason, want);
    }
}

/* Replace the first occurrence of `from` in buf with `to` (same or shorter
 * length is not required; the buffer is regenerated for each mutation). */
static size_t mutate(char *buf, size_t len, size_t cap, const char *from, const char *to, int occurrence) {
    char *p = buf;
    for (int i = 0; i < occurrence; i++) {
        p = strstr(p, from);
        if (!p) return 0;
        if (i + 1 < occurrence) p += strlen(from);
    }
    size_t fl = strlen(from), tl = strlen(to);
    if (len - fl + tl >= cap) return 0;
    memmove(p + tl, p + fl, len - (size_t)(p - buf) - fl + 1);
    memcpy(p, to, tl);
    return len - fl + tl;
}

/* gzip body (no header) holding one stored block: 5 + n + 8 bytes. */
static void stored_block(const uint8_t *src, size_t n, uint8_t *dst) {
    dst[0] = 1;
    dst[1] = (uint8_t)n; dst[2] = (uint8_t)(n >> 8);
    dst[3] = (uint8_t)~dst[1]; dst[4] = (uint8_t)~dst[2];
    memcpy(dst + 5, src, n);
    uint32_t crc = crc32_bytes(src, n);
    for (int i = 0; i < 4; i++) { dst[5 + n + i] = (uint8_t)(crc >> (8 * i)); dst[9 + n + i] = (uint8_t)(n >> (8 * i)); }
}

static void put_desc(const uint32_t *w, uint8_t *desc) {
    for (int i = 0; i < 21; i++) { desc[4 * i] = (uint8_t)w[i]; desc[4 * i + 1] = (uint8_t)(w[i] >> 8); desc[4 * i + 2] = (uint8_t)(w[i] >> 16); desc[4 * i + 3] = (uint8_t)(w[i] >> 24); }
}

static int cmd_selftest(void) {
    uint8_t buf[1024], out[1024], h[48];
    char hx[97];
    const char *why;

    /* SHA-384 known answers (FIPS 180-4 examples). */
    sha384_hash((const uint8_t *)"", 0, h); hex(h, 48, hx);
    check(strcmp(hx, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b") == 0, "sha384 empty");
    sha384_hash((const uint8_t *)"abc", 3, h); hex(h, 48, hx);
    check(strcmp(hx, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7") == 0, "sha384 abc");
    {
        uint8_t *big = malloc(1000000);
        check(big != NULL, "alloc 1e6");
        if (big) {
            memset(big, 'a', 1000000);
            sha384_ctx c; sha384_init(&c);
            for (size_t o = 0; o < 1000000; o += 777) sha384_update(&c, big + o, o + 777 <= 1000000 ? 777 : 1000000 - o);
            sha384_final(&c, h); hex(h, 48, hx);
            check(strncmp(hx, "9d0e1809716474cb086e834e310a4a1c", 32) == 0, "sha384 a*1e6 streamed");
            free(big);
        }
    }

    /* Inflater known answers. */
    size_t n = unhex(STORED_STREAM, buf, sizeof buf), pn = unhex(STORED_PLAIN, out + 512, 512);
    check(inflate_raw(buf, n, out, pn, &why) == 0 && memcmp(out, out + 512, pn) == 0, "inflate stored block");
    n = unhex(FIXED_STREAM, buf, sizeof buf); pn = unhex(FIXED_PLAIN, out + 512, 512);
    check(inflate_raw(buf, n, out, pn, &why) == 0 && memcmp(out, out + 512, pn) == 0, "inflate fixed block");
    n = unhex(DYNAMIC_STREAM, buf, sizeof buf);
    {
        uint8_t d[32]; char dh[65];
        check(inflate_raw(buf, n, out, DYNAMIC_LEN, &why) == 0, "inflate dynamic block");
        sha256_hash(out, DYNAMIC_LEN, d); hex(d, 32, dh);
        check(strcmp(dh, DYNAMIC_SHA256) == 0, "inflate dynamic block content");
        check(inflate_raw(buf, n - 1, out, DYNAMIC_LEN, &why) != 0 && strstr(why, "exhausted"), "inflate truncated dynamic refused");
        check(inflate_raw(buf, n, out, DYNAMIC_LEN - 1, &why) != 0 && strstr(why, "longer than declared"), "inflate short declared size refused");
        check(inflate_raw(buf, n, out, DYNAMIC_LEN + 1, &why) != 0 && strstr(why, "shorter than declared"), "inflate long declared size refused");
        uint8_t t[sizeof buf + 1]; memcpy(t, buf, n); t[n] = 0;
        check(inflate_raw(t, n + 1, out, DYNAMIC_LEN, &why) != 0 && strstr(why, "trailing"), "inflate trailing byte refused");
    }
    check(crc32_bytes((const uint8_t *)"123456789", 9) == 0xcbf43926u, "crc32 check value");
    n = unhex(GB10B_DESC_STREAM, buf, sizeof buf);
    check(n == 28 && unpack_gz_body(buf, n, out, DESC_BYTES, &why) == 0, "unpack GB10B descriptor array (deflate + CRC-32 + ISIZE)");
    check(get32le(buf + 24) == 84 && get32le(buf + 20) == crc32_bytes(out, 84), "GB10B descriptor trailer fields");
    { uint8_t t[28]; memcpy(t, buf, 28); t[21] ^= 1; check(unpack_gz_body(t, 28, out, DESC_BYTES, &why) != 0 && strstr(why, "CRC-32"), "GB10B descriptor CRC flip refused");
      memcpy(t, buf, 28); t[24] = 83; check(unpack_gz_body(t, 28, out, DESC_BYTES, &why) != 0 && strstr(why, "ISIZE"), "GB10B descriptor ISIZE flip refused");
      check(unpack_gz_body(t, 8, out, DESC_BYTES, &why) != 0 && strstr(why, "shorter than"), "short compressed array refused"); }
    {
        riscv_desc d; decode_desc(out, &d);
        int same = 1;
        for (int i = 0; i < 21; i++) if (get32le(out + 4 * i) != GB10B_DESC_WORDS[i]) same = 0;
        check(same, "GB10B descriptor words");
        check(d.version == 5 && d.manifest_off == 0 && d.manifest_size == 0xa00 && d.mdata_off == 0xa00 && d.mdata_size == 0xa600 && d.mcode_off == 0xb000 && d.mcode_size == 0x24d00 && d.monitor_enabled == 1, "GB10B descriptor fields");
        check(d.mcode_off + d.mcode_size <= 196608u, "GB10B descriptor fits the 196608-byte image");
    }
    {
        uint8_t bad[1] = {0x07}; /* BFINAL=1, BTYPE=3 */
        check(inflate_raw(bad, 1, out, 1, &why) != 0 && strstr(why, "block type 3"), "inflate block type 3 refused");
        uint8_t st[8] = {1, 2, 0, 0xfd, 0xfe, 'a', 'b', 0}; /* NLEN wrong */
        check(inflate_raw(st, 7, out, 2, &why) != 0 && strstr(why, "length check"), "inflate stored NLEN refused");
    }

    /* Synthetic bindata files. File A mirrors the FMC archive (image, hash,
     * sig, pkey); file B mirrors the boot archive (image + compressed desc). */
    static uint8_t image[4096], sig[384], pkey[384], desc[84], desc_st[5 + 84 + 8], image2[0x3000];
    for (size_t i = 0; i < sizeof image; i++) image[i] = (uint8_t)(i * 7 + 3);
    for (size_t i = 0; i < 384; i++) { sig[i] = (uint8_t)(255 - i); pkey[i] = (uint8_t)(i ^ 0x5a); }
    sha384_hash(image, sizeof image, h);
    const uint32_t dw[21] = {5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0};
    put_desc(dw, desc);
    stored_block(desc, 84, desc_st);
    for (size_t i = 0; i < sizeof image2; i++) image2[i] = (uint8_t)(i * 13 + 1);
    const fx_array fa[4] = {
        {"UCODE_IMAGE", "kernel/inc/gspcc/bin/test_gfw_image.bin", 0, sizeof image, image, sizeof image},
        {"UCODE_HASH", "kernel/inc/gspcc/bin/test_gfw_hash.bin", 0, 48, h, 48},
        {"UCODE_SIG", "kernel/inc/gspcc/bin/test_gfw_sig.bin", 0, 384, sig, 384},
        {"UCODE_PKEY", "kernel/inc/gspcc/bin/test_gfw_pub_key.bin", 0, 384, pkey, 384},
    };
    const fx_array fb[4] = {
        {"UCODE_IMAGE_DBG", "kernel/inc/gspcc/bin/test_dbg_image.bin", 0, sizeof image2, image2, sizeof image2},
        {"UCODE_DESC_DBG", "kernel/inc/gspcc/bin/test_dbg_desc.bin", 1, 84, desc_st, sizeof desc_st},
        {"UCODE_IMAGE_PROD", "kernel/inc/gspcc/bin/test_prd_image.bin", 0, sizeof image2, image2, sizeof image2},
        {"UCODE_DESC_PROD", "kernel/inc/gspcc/bin/test_prd_desc.bin", 1, 84, desc_st, sizeof desc_st},
    };
    size_t cap = 256 * 1024;
    char *ta = malloc(cap), *tb = malloc(cap), *m = malloc(cap);
    check(ta && tb && m, "alloc fixtures");
    if (!(ta && tb && m)) return 1;
    size_t la = fx_emit(ta, cap, "kgspGetBinArchiveGspRmFmcGfwProdSigned_TEST", fa, 4);
    size_t lb = fx_emit(tb, cap, "kgspGetBinArchiveGspRmBoot_TEST", fb, 4);
    check(la > 0 && lb > 0, "emit fixtures");
    {
        char reason[256];
        check(fx_try(ta, la, reason, sizeof reason) == 0, "fixture A extracts");
        check(fx_try(tb, lb, reason, sizeof reason) == 0, "fixture B extracts");
        bd_file *f = calloc(1, sizeof *f);
        if (f && parse_file(f, tb, lb) == 0) {
            check(f->n == 4 && f->b[1].compressed == 1 && f->b[1].plain_len == 84 && memcmp(f->b[1].plain, desc, 84) == 0, "fixture B descriptor inflated");
            check(f->b[0].plain_len == sizeof image2 && memcmp(f->b[0].plain, image2, sizeof image2) == 0, "fixture B image bytes");
        } else check(0, "fixture B reparse");
        if (f) { bd_free(f); free(f); }
    }

    /* Mutations of file A (uncompressed arrays). */
    struct { const char *from, *to; int occ; const char *want; const char *what; } ma[] = {
        {"// DATA SIZE (bytes): 4096", "// DATA SIZE (bytes): 4095", 1, "more bytes than the declared size", "data size one short"},
        {"// DATA SIZE (bytes): 4096", "// DATA SIZE (bytes): 4097", 1, "fewer bytes than the declared size", "data size one long"},
        {"    4096,  // uncompressed", "    4095,  // uncompressed", 1, "uncompressed size differs from DATA SIZE", "pvt uncompressed size"},
        {"    4096,  // compressed data size", "    4000,  // compressed data size", 1, "compressed size differs from the header", "pvt compressed size"},
        {"    NV_FALSE,  // is pData compressed?", "    NV_TRUE,  // is pData compressed?", 1, "compressed flag disagrees", "pvt compressed flag"},
        {"// COMPRESSION: NO", "// COMPRESSION: YES", 1, "COMPRESSED SIZE missing", "compression yes without size"},
        {"// COMPRESSED SIZE (bytes): N/A", "// COMPRESSED SIZE (bytes): 100", 1, "COMPRESSED SIZE given with COMPRESSION NO", "compressed size with no"},
        {"// FILE TYPE: BINARY", "// FILE TYPE: TEXT", 1, "FILE TYPE is not BINARY", "file type"},
        {"// COMPLEX_STRUCT: NO", "// COMPLEX_STRUCT: YES", 1, "COMPLEX_STRUCT is not NO", "complex struct"},
        {"0x03,", "0y03,", 1, "non-hex token", "non-hex token"},
        {"0x03,", "0x03 ", 1, "without a trailing comma", "missing comma"},
        {"};\n#endif // defined(BINDATA_INCLUDE_DATA)", "\n#endif // defined(BINDATA_INCLUDE_DATA)", 1, "non-hex token", "array end removed"},
        {"(\"BINDATA_LABEL_UCODE_PKEY\")", "(\"BINDATA_LABEL_UCODE_SIG\")", 1, "duplicate label", "duplicate label"},
        {"(\"BINDATA_LABEL_UCODE_SIG\")", "(\"BINDATA_LABEL_UCODE_FOO\")", 1, "array identifier is not the expected one", "label vs identifier"},
        {"kgspBinArchiveGspRmFmcGfwProdSigned_TEST_BINDATA_LABEL_UCODE_SIG_data,  // compressed data pointer", "kgspBinArchiveGspRmFmcGfwProdSigned_TEST_BINDATA_LABEL_UCODE_PKEY_data,  // compressed data pointer", 1, "data pointer is not the array", "pvt pointer"},
        {"    4,  // entryNum", "    3,  // entryNum", 1, "entryNum differs", "archive entry count"},
        {"{ BINDATA_LABEL_UCODE_SIG ,", "{ BINDATA_LABEL_UCODE_PKEY ,", 1, "entry order or label differs", "archive label order"},
        {"&g_bindata_pvt[__idx_kgspBinArchiveGspRmFmcGfwProdSigned_TEST_BINDATA_LABEL_UCODE_SIG]", "&g_bindata_pvt[__idx_kgspBinArchiveGspRmFmcGfwProdSigned_TEST_BINDATA_LABEL_UCODE_PKEY]", 1, "storage index is not this array", "archive storage index"},
        {"static const BINDATA_ARCHIVE __kgspGetBinArchiveGspRmFmcGfwProdSigned_TEST =", "static const BINDATA_ARCHIVE __kgspGetBinArchiveOther_TEST =", 1, "archive table name is not the file's function", "archive name"},
        {"// FUNCTION: kgspGetBinArchiveGspRmFmcGfwProdSigned_TEST(\"BINDATA_LABEL_UCODE_PKEY\")", "// FUNCTION: kgspGetBinArchiveGspRmBoot_TEST(\"BINDATA_LABEL_UCODE_PKEY\")", 1, "different function", "mixed functions"},
        {"// DATA SIZE (bytes): 48", "// DATA SIZE (bytes): 47", 1, "more bytes than the declared size", "hash size via array"},
        {"// COMPRESSION: NO", "// COMPRESSION: MAYBE", 1, "neither YES nor NO", "compression keyword"},
    };
    for (size_t i = 0; i < sizeof ma / sizeof ma[0]; i++) {
        memcpy(m, ta, la + 1);
        size_t lm = mutate(m, la, cap, ma[i].from, ma[i].to, ma[i].occ);
        check(lm > 0, ma[i].what);
        if (lm) expect_refused(m, lm, ma[i].want, ma[i].what);
    }
    /* Hash that does not match the image: flip one byte of the hash array. */
    {
        memcpy(m, ta, la + 1);
        char from[8], to[8];
        snprintf(from, sizeof from, "0x%02x,", h[0]);
        snprintf(to, sizeof to, "0x%02x,", h[0] ^ 1);
        /* the hash array is the second array; its first byte follows the IMAGE array */
        char *p = strstr(m, "UCODE_HASH_data[] = \n{\n    ");
        check(p != NULL, "locate hash array");
        if (p) { p += strlen("UCODE_HASH_data[] = \n{\n    "); check(strncmp(p, from, 5) == 0, "hash first byte"); memcpy(p, to, 5); expect_refused(m, la, "not SHA-384 of UCODE_IMAGE", "hash mismatch"); }
    }
    /* Image byte flipped: also a hash mismatch. */
    {
        memcpy(m, ta, la + 1);
        char *p = strstr(m, "UCODE_IMAGE_data[] = \n{\n    0x03,");
        check(p != NULL, "locate image array");
        if (p) { p += strlen("UCODE_IMAGE_data[] = \n{\n    "); memcpy(p, "0x04,", 5); expect_refused(m, la, "not SHA-384 of UCODE_IMAGE", "image byte flipped"); }
    }
    /* Truncated file (ends inside the archive). */
    {
        memcpy(m, ta, la + 1);
        char *p = strstr(m, "        { BINDATA_LABEL_UCODE_PKEY");
        check(p != NULL, "locate last archive entry");
        if (p) { *p = 0; expect_refused(m, (size_t)(p - m), "archive: missing entry", "truncated archive"); }
        memcpy(m, ta, la + 1);
        p = strstr(m, "#if defined(BINDATA_INCLUDE_ARCHIVE)");
        if (p) { *p = 0; expect_refused(m, (size_t)(p - m), "no archive table", "no archive table"); }
    }
    /* File ends inside an array. */
    {
        memcpy(m, ta, la + 1);
        char *p = strstr(m, "};\n#endif // defined(BINDATA_INCLUDE_DATA)");
        check(p != NULL, "locate first array end");
        if (p) { *p = 0; expect_refused(m, (size_t)(p - m), "file ends inside the array", "file ends inside array"); }
    }
    /* Empty and foreign files. */
    expect_refused("", 0, "no arrays found", "empty file");
    expect_refused("int x;\nstatic BINDATA_CONST NvU8 foo[] = \n{\n};\n", 44, "data before the first FUNCTION", "array before header");

    /* Mutations of file B: regenerate the fixture with a changed descriptor
     * or a damaged compressed array, then expect the refusal. */
    struct { uint32_t words[21]; int nlen_flip, crc_flip, isize_flip, cut; uint32_t data_size; const char *want, *what; } mbs[] = {
        {{4, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 84, "descriptor version is not 5", "desc version 4"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 0, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 84, "monitor not enabled", "desc monitor disabled"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2a01, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 84, "monitor-code region outside the image", "desc code past image"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x610, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 84, "monitor-code region outside the image or unaligned", "desc code unaligned"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 84, "monitor-code region", "desc code size zero"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x3000, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 84, "monitor-data region outside the image", "desc data past image"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0x100, 0x2f80, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 84, "manifest region outside the image", "desc manifest past image"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 1, 0, 0, 0, 84, "stored block length check failed", "desc stored NLEN"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 1, 0, 0, 84, "CRC-32 mismatch", "desc CRC flipped"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 1, 0, 84, "ISIZE differs", "desc ISIZE flipped"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 83, "output longer than declared size", "desc declared 83"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 0, 85, "output shorter than declared size", "desc declared 85"},
        {{5, 0, 0, 0, 0, 0, 0, 0, 0, 0x200, 0x200, 0x400, 0x600, 0x2400, 1, 0, 0, 0, 0, 0x8000, 0}, 0, 0, 0, 5, 84, "inflate: input exhausted", "desc stream cut"},
    };
    for (size_t i = 0; i < sizeof mbs / sizeof mbs[0]; i++) {
        uint8_t d2[84], st[5 + 84 + 8];
        put_desc(mbs[i].words, d2);
        stored_block(d2, 84, st);
        if (mbs[i].nlen_flip) st[4] ^= 1;
        if (mbs[i].crc_flip) st[5 + 84] ^= 1;
        if (mbs[i].isize_flip) st[5 + 84 + 4] ^= 1;
        fx_array fm[2] = {fb[0], fb[1]};
        fm[1].bytes = st; fm[1].n = sizeof st - (size_t)mbs[i].cut; fm[1].data_size = mbs[i].data_size;
        size_t lm = fx_emit(m, cap, "kgspGetBinArchiveGspRmBoot_TEST", fm, 2);
        check(lm > 0, mbs[i].what);
        if (lm) expect_refused(m, lm, mbs[i].want, mbs[i].what);
    }
    /* Text mutations of file B. */
    struct { const char *from, *to; const char *want, *what; } mbt[] = {
        {"(\"BINDATA_LABEL_UCODE_IMAGE_PROD\")", "(\"BINDATA_LABEL_UCODE_IMAGE_PRD\")", "array identifier is not the expected one", "renamed image (identifier catches)"},
        {"(\"BINDATA_LABEL_UCODE_DESC_PROD\")", "(\"BINDATA_LABEL_UCODE_DESC_XYZ\")", "array identifier is not the expected one", "renamed desc (identifier catches)"},
        {"    97,  // compressed data size", "    98,  // compressed data size", "compressed size differs from the header", "pvt compressed size (B)"},
    };
    for (size_t i = 0; i < sizeof mbt / sizeof mbt[0]; i++) {
        memcpy(m, tb, lb + 1);
        size_t lm = mutate(m, lb, cap, mbt[i].from, mbt[i].to, 1);
        check(lm > 0, mbt[i].what);
        if (lm) expect_refused(m, lm, mbt[i].want, mbt[i].what);
    }
    /* Semantic refusals that need a consistent archive: rebuild fixtures. */
    {
        fx_array fc[2] = {fb[0], fb[1]};
        fc[1].label = "UCODE_DESC_PROD";
        size_t lc = fx_emit(m, cap, "kgspGetBinArchiveGspRmBoot_TEST", fc, 2);
        check(lc > 0, "emit fixture C");
        if (lc) expect_refused(m, lc, "descriptor without a matching image", "desc without image");
        fx_array fd[1] = {fb[0]};
        fd[0].label = "UCODE_OTHER";
        lc = fx_emit(m, cap, "kgspGetBinArchiveGspRmBoot_TEST", fd, 1);
        if (lc) expect_refused(m, lc, "unknown label", "unknown label");
        fx_array fe[2] = {fa[0], fa[2]};
        fe[1].label = "UCODE_HASH";
        lc = fx_emit(m, cap, "kgspGetBinArchiveGspRmFmcGfwProdSigned_TEST", fe, 2);
        if (lc) expect_refused(m, lc, "hash array is not 48 bytes", "hash size");
        fx_array ff[1] = {fa[2]};
        ff[0].data_size = 383; ff[0].n = 383;
        lc = fx_emit(m, cap, "kgspGetBinArchiveGspRmFmcGfwProdSigned_TEST", ff, 1);
        if (lc) expect_refused(m, lc, "UCODE_SIG is not 384 bytes", "sig size");
        fx_array fg[1] = {fa[1]};
        lc = fx_emit(m, cap, "kgspGetBinArchiveGspRmFmcGfwProdSigned_TEST", fg, 1);
        if (lc) expect_refused(m, lc, "hash array without UCODE_IMAGE", "hash without image");
        fx_array fi[2] = {fb[0], fb[1]};
        fi[1].compressed = 1; fi[1].n = 0;
        lc = fx_emit(m, cap, "kgspGetBinArchiveGspRmBoot_TEST", fi, 2);
        if (lc) expect_refused(m, lc, "COMPRESSED SIZE missing", "compressed size zero");
    }
    free(ta); free(tb); free(m);
    printf("CK_GSP_BINDATA_EXTRACT_SELFTEST: %s (%d checks, %d failures)\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "extract") == 0) return cmd_extract(argc - 2, argv + 2);
    if (argc == 2 && strcmp(argv[1], "selftest") == 0) return cmd_selftest();
    fprintf(stderr, "usage: ck_gsp_bindata_extract extract FILE [--out DIR]\n       ck_gsp_bindata_extract selftest\n");
    return 1;
}
