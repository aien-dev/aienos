/* osc_unit.c -- OSCUNIT admission. See osc_unit.h and OSC_UNIT_ARTIFACT.md
 * (aien-protocols PR #17). The check order below is section 8.2, one comment
 * per step, because the first failure decides the result. */
#include <string.h>
#include "osc_unit.h"
#include "aienos_sig.h"
#include "sha256.h"

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= p[i];
    return acc == 0;
}

static const char *const code_names[] = {
    [0] = "OK", [1] = "TRUNCATED", [2] = "BAD_MAGIC", [3] = "CONTAINER_VERSION", [4] = "HEADER_FIELD",
    [5] = "UNIT_FORMAT", [6] = "ABI_VERSION", [7] = "UNKNOWN_FLAGS", [8] = "TRAILING_BYTES",
    [9] = "TOTAL_LENGTH", [10] = "SECTION_TABLE", [11] = "SECTION_BOUNDS", [12] = "SECTION_OVERLAP",
    [13] = "SECTION_LAYOUT", [14] = "LIMIT_EXCEEDED", [15] = "IR_HASH_MISMATCH",
    [16] = "CODE_HASH_MISMATCH", [17] = "ENTRY_HASH_MISMATCH", [18] = "CAPS_HASH_MISMATCH",
    [19] = "IR_MALFORMED", [20] = "ENTRY_TABLE", [21] = "CAPS_TABLE", [22] = "SIGNER_CLASS",
    [23] = "SIGNATURE_ALGORITHM", [24] = "TEST_SIGNER_IN_RELEASE", [25] = "UNTRUSTED_SIGNER",
    [26] = "BAD_SIGNATURE", [27] = "CAP_DOMAIN_UNSUPPORTED", [28] = "CAP_GEN_NOT_REPRESENTABLE",
    [29] = "CAP_GENERATION_STALE", [30] = "RESOURCE_UNAVAILABLE", [31] = "ENTRY_NAME",
    [32] = "ENTRY_NAME_HASH", [33] = "ENTRY_NAME_DUPLICATE", [34] = "CODE_INSTRUCTION",
};

const char *osc_code_name(unsigned code)
{
    if (code < sizeof code_names / sizeof code_names[0] && code_names[code])
        return code_names[code];
    if (code == OSC_LAUNCH_BAD_ENTRY)
        return "LAUNCH_BAD_ENTRY";
    if (code == OSC_LAUNCH_ARG_SHAPE)
        return "LAUNCH_ARG_SHAPE";
    return "?";
}

/* ---------------------------------------------------------------------------
 * Section 8.4: the OSC-emitted A64 subset. A port of the operation table
 * (osc_a64.c:28-72), the variable-field masks (:76-93) and the decode
 * round trip (:245-274) of omega at d64ccb3. A word passes when for some table
 * entry (word & ~varmask(class)) == base AND the fields decoded from the word
 * re-encode to the same word. The encoder refuses only the cases tested in
 * round_trip_ok; every other field value re-encodes to itself.
 * ------------------------------------------------------------------------- */
enum { CL_RRR_SH, CL_RI, CL_R4, CL_MULH, CL_R3, CL_BFM, CL_CSINC, CL_MOV16, CL_MEM, CL_PAIR,
       CL_B26, CL_BCOND, CL_CB, CL_BREG };
enum { OP_PAIR_STP_OFF, OP_PAIR_STP_PRE, OP_PAIR_STP_POST, OP_PAIR_LDP_OFF, OP_PAIR_LDP_PRE,
       OP_PAIR_LDP_POST, OP_OTHER };

struct a64_op { uint32_t base; uint8_t cls; uint8_t pairop; };

static const struct a64_op a64_ops[] = {
    {0x8B000000u, CL_RRR_SH, OP_OTHER}, {0xCB000000u, CL_RRR_SH, OP_OTHER},
    {0xAB000000u, CL_RRR_SH, OP_OTHER}, {0xEB000000u, CL_RRR_SH, OP_OTHER},
    {0x91000000u, CL_RI, OP_OTHER}, {0xD1000000u, CL_RI, OP_OTHER},
    {0xB1000000u, CL_RI, OP_OTHER}, {0xF1000000u, CL_RI, OP_OTHER},
    {0x9B000000u, CL_R4, OP_OTHER}, {0x9B008000u, CL_R4, OP_OTHER},
    {0x9B407C00u, CL_MULH, OP_OTHER}, {0x9BC07C00u, CL_MULH, OP_OTHER},
    {0x9AC00C00u, CL_R3, OP_OTHER}, {0x9AC00800u, CL_R3, OP_OTHER},
    {0x9AC02000u, CL_R3, OP_OTHER}, {0x9AC02400u, CL_R3, OP_OTHER}, {0x9AC02800u, CL_R3, OP_OTHER},
    {0x8A000000u, CL_RRR_SH, OP_OTHER}, {0xAA000000u, CL_RRR_SH, OP_OTHER},
    {0xCA000000u, CL_RRR_SH, OP_OTHER}, {0xAA200000u, CL_RRR_SH, OP_OTHER},
    {0x93400000u, CL_BFM, OP_OTHER}, {0xD3400000u, CL_BFM, OP_OTHER},
    {0x9A800400u, CL_CSINC, OP_OTHER},
    {0xD2800000u, CL_MOV16, OP_OTHER}, {0x92800000u, CL_MOV16, OP_OTHER}, {0xF2800000u, CL_MOV16, OP_OTHER},
    {0xF9400000u, CL_MEM, OP_OTHER}, {0xF9000000u, CL_MEM, OP_OTHER},
    {0xA9000000u, CL_PAIR, OP_PAIR_STP_OFF}, {0xA9800000u, CL_PAIR, OP_PAIR_STP_PRE},
    {0xA8800000u, CL_PAIR, OP_PAIR_STP_POST}, {0xA9400000u, CL_PAIR, OP_PAIR_LDP_OFF},
    {0xA9C00000u, CL_PAIR, OP_PAIR_LDP_PRE}, {0xA8C00000u, CL_PAIR, OP_PAIR_LDP_POST},
    {0x14000000u, CL_B26, OP_OTHER}, {0x94000000u, CL_B26, OP_OTHER},
    {0x54000000u, CL_BCOND, OP_OTHER}, {0xB4000000u, CL_CB, OP_OTHER}, {0xB5000000u, CL_CB, OP_OTHER},
    {0xD63F0000u, CL_BREG, OP_OTHER}, {0xD65F0000u, CL_BREG, OP_OTHER},
    {0x38606800u, CL_R3, OP_OTHER}, /* ldrb (register) */
};

static uint32_t cls_varmask(unsigned cls)
{
    switch (cls) {
    case CL_RRR_SH: return 0x00DFFFFFu;
    case CL_RI: return 0x007FFFFFu;
    case CL_R4: return 0x001F7FFFu;
    case CL_MULH: return 0x001F03FFu;
    case CL_R3: return 0x001F03FFu;
    case CL_BFM: return 0x003FFFFFu;
    case CL_CSINC: return 0x001FF3FFu;
    case CL_MOV16: return 0x007FFFFFu;
    case CL_MEM: return 0x003FFFFFu;
    case CL_PAIR: return 0x003FFFFFu;
    case CL_B26: return 0x03FFFFFFu;
    case CL_BCOND: return 0x00FFFFEFu;
    case CL_CB: return 0x00FFFFFFu;
    case CL_BREG: return 0x000003E0u;
    default: return 0;
    }
}

/* The decoded fields re-encode to w unless the encoder refuses them. */
static int round_trip_ok(const struct a64_op *op, uint32_t w)
{
    uint32_t rd = w & 31, rn = (w >> 5) & 31, ra = (w >> 10) & 31;
    switch (op->cls) {
    case CL_RRR_SH: return ((w >> 22) & 3) <= 2;       /* LSL LSR ASR; ROR refused */
    case CL_CSINC: return ((w >> 12) & 15) <= 14;      /* cond NV refused */
    case CL_BCOND: return (w & 15) <= 13;              /* AL and NV refused */
    case CL_BREG: return rn != 31;                     /* branch register is x0..x30 only */
    case CL_PAIR: {
        int wb = op->pairop == OP_PAIR_STP_PRE || op->pairop == OP_PAIR_STP_POST ||
                 op->pairop == OP_PAIR_LDP_PRE || op->pairop == OP_PAIR_LDP_POST;
        int load = op->pairop == OP_PAIR_LDP_OFF || op->pairop == OP_PAIR_LDP_PRE ||
                   op->pairop == OP_PAIR_LDP_POST;
        /* writeback base equal to a transfer register (rn is SP when 31, never equal) */
        if (wb && rn != 31 && (rn == rd || rn == ra))
            return 0;
        if (load && rd == ra) /* Rt == Rt2, including XZR == XZR */
            return 0;
        return 1;
    }
    default: return 1;
    }
}

int osc_a64_word_allowed(uint32_t w)
{
    /* brk: the compiler emits it only as the unreachable guard after a trap call, immediate = trap code. */
    if ((w & 0xFFE0001Fu) == 0xD4200000u) {
        uint32_t imm = (w >> 5) & 0xFFFFu;
        return imm >= 1 && imm <= 14;
    }
    for (size_t i = 0; i < sizeof a64_ops / sizeof a64_ops[0]; i++) {
        const struct a64_op *op = &a64_ops[i];
        if ((w & ~cls_varmask(op->cls)) != op->base)
            continue;
        if (round_trip_ok(op, w))
            return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Admission
 * ------------------------------------------------------------------------- */
struct sec { uint32_t off, len; const uint8_t *hash; };

static int name_charset_ok(const uint8_t *n, unsigned len)
{
    for (unsigned i = 0; i < len; i++) {
        uint8_t c = n[i];
        int alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
        int digit = c >= '0' && c <= '9';
        if (!(alpha || (digit && i > 0)))
            return 0;
    }
    return len >= 1;
}

static void name_hash(const uint8_t *n, unsigned len, uint8_t out16[16])
{
    static const char tag[] = "AIENOS-OSC-FN-NAME-V1"; /* + the NUL below */
    sha256_ctx c;
    uint8_t d[32];
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)tag, sizeof tag); /* sizeof includes the NUL */
    sha256_update(&c, n, len);
    sha256_final(&c, d);
    memcpy(out16, d, 16);
}

static int key_in(const uint8_t (*set)[32], unsigned n, const uint8_t fp[32], const uint8_t **key)
{
    for (unsigned i = 0; set && i < n; i++) {
        uint8_t h[32];
        sha256_hash(set[i], 32, h);
        if (memcmp(h, fp, 32) == 0) {
            *key = set[i];
            return 1;
        }
    }
    return 0;
}

/* Ed25519 group order L, little endian. */
static const uint8_t ed_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

static int scalar_below_L(const uint8_t s[32])
{
    for (int i = 31; i >= 0; i--) {
        if (s[i] != ed_L[i])
            return s[i] < ed_L[i];
    }
    return 0; /* equal to L */
}

unsigned osc_unit_admit(const uint8_t *f, size_t len, const struct osc_policy *pol, struct osc_accept *out)
{
    struct sec sec[5]; /* 1-based */
    uint32_t total;
    unsigned ufv, cls, ncap = 0;
    uint16_t nfn;
    uint8_t digest[32];

    if (!f || !pol)
        return OSC_TRUNCATED;
    if (pol->staging_max && len > pol->staging_max)
        return OSC_RESOURCE_UNAVAILABLE;
    /* 1 */
    if (len < 128)
        return OSC_TRUNCATED;
    /* 2: magic, container version, fixed header fields and reserved bytes, unit format, ABI, flags */
    if (memcmp(f, "OSCUNIT\0", 8) != 0)
        return OSC_BAD_MAGIC;
    if (rd16(f + 8) != 1)
        return OSC_CONTAINER_VERSION;
    if (rd16(f + 10) != 128 || rd32(f + 24) != 128 || rd16(f + 28) != 4 || rd16(f + 30) != 48 ||
        !all_zero(f + 34, 2) || !all_zero(f + 50, 2) || !all_zero(f + 52, 4) || !all_zero(f + 60, 4) ||
        !all_zero(f + 96, 32))
        return OSC_HEADER_FIELD;
    ufv = rd16(f + 12);
    if (ufv >= 32 || !((pol->unit_formats >> ufv) & 1u))
        return OSC_UNIT_FORMAT;
    {
        unsigned abi = rd16(f + 14);
        if (abi >= 32 || !((pol->abi_versions >> abi) & 1u))
            return OSC_ABI_VERSION;
    }
    if (rd32(f + 16) != 0)
        return OSC_UNKNOWN_FLAGS;
    /* 3 */
    total = rd32(f + 20);
    if (total < 384 || total > OSC_UNIT_MAX_BYTES)
        return OSC_TOTAL_LENGTH;
    if (len < total)
        return OSC_TRUNCATED;
    if (len > total)
        return OSC_TRAILING_BYTES;
    /* 4: the 320 header bytes are now in the file (total >= 384). */
    for (unsigned k = 1; k <= 4; k++) {
        const uint8_t *e = f + 128 + (k - 1) * 48;
        if (rd16(e) != k || rd16(e + 2) != 0 || !all_zero(e + 12, 4))
            return OSC_SECTION_TABLE;
        sec[k].off = rd32(e + 4);
        sec[k].len = rd32(e + 8);
        sec[k].hash = e + 16;
    }
    {
        uint64_t sigoff = (uint64_t)total - 64;
        for (unsigned k = 1; k <= 4; k++)
            if (sec[k].off < 320 || (uint64_t)sec[k].off + sec[k].len > sigoff)
                return OSC_SECTION_BOUNDS;
        for (unsigned a = 1; a <= 4; a++)
            for (unsigned b = a + 1; b <= 4; b++)
                if (sec[a].len && sec[b].len && sec[a].off < (uint64_t)sec[b].off + sec[b].len &&
                    sec[b].off < (uint64_t)sec[a].off + sec[a].len)
                    return OSC_SECTION_OVERLAP;
        uint64_t pos = 320;
        for (unsigned k = 1; k <= 4; k++) {
            uint64_t want = (pos + 15) / 16 * 16;
            if (sec[k].off != want)
                return OSC_SECTION_LAYOUT;
            if (want > pos && !all_zero(f + pos, (size_t)(want - pos)))
                return OSC_SECTION_LAYOUT;
            pos = want + sec[k].len;
        }
        if (pos != sigoff)
            return OSC_SECTION_LAYOUT;
    }
    /* 5: limits (every read below lies in a bounds-checked section) */
    nfn = rd16(f + 32);
    {
        uint32_t stack = rd32(f + 36);
        uint64_t ticks = rd64(f + 40);
        uint16_t pools = rd16(f + 48);
        if (nfn < 1 || nfn > OSC_MAX_FUNCS)
            return OSC_LIMIT_EXCEEDED;
        if (stack < 4096 || stack > 1048576 || (stack % 16))
            return OSC_LIMIT_EXCEEDED;
        if (ticks < 1 || ticks > 1000000000ull)
            return OSC_LIMIT_EXCEEDED;
        if (pools > 64)
            return OSC_LIMIT_EXCEEDED;
        if (sec[1].len < 8 || sec[1].len > 1048576)
            return OSC_LIMIT_EXCEEDED;
        if (sec[2].len < 4 || sec[2].len > 262144 || (sec[2].len % 4))
            return OSC_LIMIT_EXCEEDED;
        if (sec[4].len >= 8) {
            ncap = rd16(f + sec[4].off);
            if (ncap > OSC_MAX_CAPS)
                return OSC_LIMIT_EXCEEDED;
        }
    }
    /* 6 */
    cls = rd16(f + 56);
    if (cls != OSC_SIGNER_TEST && cls != OSC_SIGNER_OWNER)
        return OSC_SIGNER_CLASS;
    if (rd16(f + 58) != 1)
        return OSC_SIGNATURE_ALGORITHM;
    /* 7: section hashes in order */
    for (unsigned k = 1; k <= 4; k++) {
        uint8_t h[32];
        sha256_hash(f + sec[k].off, sec[k].len, h);
        if (memcmp(h, sec[k].hash, 32) != 0)
            return OSC_IR_HASH_MISMATCH + (k - 1);
    }
    /* 8 */
    {
        const uint8_t *ir = f + sec[1].off;
        if (memcmp(ir, "OSC1IR\0", 7) != 0 || ir[7] != ufv)
            return OSC_IR_MALFORMED;
    }
    /* 9: code scan */
    {
        const uint8_t *code = f + sec[2].off;
        for (uint32_t o = 0; o < sec[2].len; o += 4)
            if (!osc_a64_word_allowed(rd32(code + o)))
                return OSC_CODE_INSTRUCTION;
    }
    /* 10: entry table. Locals hold the parsed records until acceptance. */
    if (sec[3].len != 96u * nfn)
        return OSC_ENTRY_TABLE;
    {
        uint64_t prev = 0;
        int have_prev = 0;
        for (unsigned i = 0; i < nfn; i++) {
            const uint8_t *e = f + sec[3].off + 96u * i;
            unsigned nregs = e[2], ret = e[3], nl;
            if (rd16(e) != i)
                return OSC_ENTRY_TABLE;
            if (nregs > 6 || ret > 9 || !all_zero(e + 10, 2))
                return OSC_ENTRY_TABLE;
            for (unsigned r = 0; r < 6; r++) {
                unsigned kind = e[4 + r];
                if (r >= nregs) {
                    if (kind != 0)
                        return OSC_ENTRY_TABLE;
                    continue;
                }
                if (kind >= 1 && kind <= 9)
                    continue;
                if (kind == 11 || kind == 12) {
                    if (ufv != 5 || r + 1 >= nregs || e[4 + r + 1] != 5)
                        return OSC_ENTRY_TABLE;
                    continue;
                }
                return OSC_ENTRY_TABLE;
            }
            uint32_t co = rd32(e + 12);
            if ((co % 4) || co >= sec[2].len || (have_prev && co <= prev))
                return OSC_ENTRY_TABLE;
            prev = co;
            have_prev = 1;
            nl = e[32];
            if (nl < 1 || nl > 63 || !all_zero(e + 33 + nl, 63 - nl) || !name_charset_ok(e + 33, nl))
                return OSC_ENTRY_NAME;
            uint8_t nh[16];
            name_hash(e + 33, nl, nh);
            if (memcmp(nh, e + 16, 16) != 0)
                return OSC_ENTRY_NAME_HASH;
            for (unsigned j = 0; j < i; j++) {
                const uint8_t *q = f + sec[3].off + 96u * j;
                if ((q[32] == nl && memcmp(q + 33, e + 33, nl) == 0) || memcmp(q + 16, e + 16, 16) == 0)
                    return OSC_ENTRY_NAME_DUPLICATE;
            }
        }
    }
    /* 11: capability table */
    if (sec[4].len != 8 + 64u * ncap)
        return OSC_CAPS_TABLE;
    if (!all_zero(f + sec[4].off + 2, 6))
        return OSC_CAPS_TABLE;
    {
        int have_prev = 0;
        uint64_t prev = 0;
        for (unsigned i = 0; i < ncap; i++) {
            const uint8_t *e = f + sec[4].off + 8 + 64u * i;
            unsigned kind = rd16(e), dom = rd16(e + 48);
            uint32_t rid = rd32(e + 4), rights = rd32(e + 8), bk = rd32(e + 12), mops = rd32(e + 16);
            uint64_t mbytes = rd64(e + 24), boff = rd64(e + 32), blen = rd64(e + 40);
            if (!all_zero(e + 20, 4) || (kind != 2 && kind != 3) || rd16(e + 2) != 0 || rid == 0)
                return OSC_CAPS_TABLE;
            if (rights == 0 || (rights & ~63u) != 0 || mops == 0 || mbytes == 0)
                return OSC_CAPS_TABLE;
            if (kind == 3) {
                if (bk != 1 || blen == 0 || mbytes > blen)
                    return OSC_CAPS_TABLE;
            } else if (bk != 2 || boff != 0 || blen != 0) {
                return OSC_CAPS_TABLE;
            }
            if ((dom != 1 && dom != 2) || rd16(e + 50) != 0 || !all_zero(e + 52, 4))
                return OSC_CAPS_TABLE;
            uint64_t key = ((uint64_t)dom << 40) | ((uint64_t)kind << 32) | rid;
            if (have_prev && key <= prev)
                return OSC_CAPS_TABLE;
            prev = key;
            have_prev = 1;
        }
    }
    /* UnitDigest = SHA256("AIENOS-OSC-UNIT-V1\0" || file[0..320)) */
    {
        static const char tag[] = "AIENOS-OSC-UNIT-V1";
        sha256_ctx c;
        sha256_init(&c);
        sha256_update(&c, (const uint8_t *)tag, sizeof tag);
        sha256_update(&c, f, 320);
        sha256_final(&c, digest);
    }
    /* 12 */
    if (cls == OSC_SIGNER_TEST && pol->release)
        return OSC_TEST_SIGNER_IN_RELEASE;
    /* 13: the key comes from the loader's anchor set of that class, never from the container */
    const uint8_t *key = 0;
    if (cls == OSC_SIGNER_TEST ? !key_in(pol->test_anchors, pol->n_test, f + 64, &key)
                               : !key_in(pol->owner_anchors, pol->n_owner, f + 64, &key))
        return OSC_UNTRUSTED_SIGNER;
    /* 14: canonical S < L, then pure Ed25519 over the domain-separated digest */
    /* scalar_below_L is defence in depth: the Ed25519 verifier also rejects a non-canonical S, so no test can separate them. */
    {
        static const char tag[] = "AIENOS-OSC-UNIT-SIGNATURE-V1";
        uint8_t msg[sizeof tag + 32];
        const uint8_t *sig = f + total - 64;
        memcpy(msg, tag, sizeof tag);
        memcpy(msg + sizeof tag, digest, 32);
        if (!scalar_below_L(sig + 32) || aienos_ed25519_verify(sig, msg, sizeof msg, key) != 0)
            return OSC_BAD_SIGNATURE;
    }
    /* 15: capability policy, three whole passes */
    for (unsigned i = 0; i < ncap; i++) {
        unsigned dom = rd16(f + sec[4].off + 8 + 64u * i + 48);
        if (dom >= 32 || !((pol->cap_domains >> dom) & 1u))
            return OSC_CAP_DOMAIN_UNSUPPORTED;
    }
    for (unsigned i = 0; i < ncap; i++) {
        const uint8_t *e = f + sec[4].off + 8 + 64u * i;
        if (rd16(e + 48) == 1 && (rd64(e + 56) >> 32) != 0)
            return OSC_CAP_GEN_NOT_REPRESENTABLE;
    }
    for (unsigned i = 0; i < ncap; i++) {
        const uint8_t *e = f + sec[4].off + 8 + 64u * i;
        uint64_t want = rd64(e + 56), cur = 0;
        if (want == 0 || !pol->gen_lookup)
            continue;
        if (pol->gen_lookup(pol->ctx, rd16(e + 48), rd16(e), rd32(e + 4), &cur) != 0 || cur != want)
            return OSC_CAP_GENERATION_STALE;
    }
    /* Build the accepted view (everything below was validated above). */
    struct osc_accept *a = out;
    struct osc_accept local;
    if (!a)
        a = &local;
    memset(a, 0, sizeof *a);
    memcpy(a->unit_digest, digest, 32);
    memcpy(a->ir_sha256, sec[1].hash, 32);
    memcpy(a->code_sha256, sec[2].hash, 32);
    memcpy(a->signer_fp, f + 64, 32);
    a->unit_format = (uint16_t)ufv;
    a->signer_class = (uint16_t)cls;
    a->function_count = nfn;
    a->pool_slots = rd16(f + 48);
    a->cap_count = (uint16_t)ncap;
    a->max_stack_bytes = rd32(f + 36);
    a->cpu_ticks = rd64(f + 40);
    a->ir_off = sec[1].off; a->ir_len = sec[1].len;
    a->code_off = sec[2].off; a->code_len = sec[2].len;
    for (unsigned i = 0; i < nfn; i++) {
        const uint8_t *e = f + sec[3].off + 96u * i;
        struct osc_entry *r = &a->entry[i];
        r->fn_index = rd16(e);
        r->nregs = e[2];
        r->ret_kind = e[3];
        memcpy(r->reg_kind, e + 4, 6);
        r->code_offset = rd32(e + 12);
        memcpy(r->name_hash, e + 16, 16);
        r->name_len = e[32];
        memcpy(r->name, e + 33, r->name_len);
        r->name[r->name_len] = 0;
    }
    for (unsigned i = 0; i < ncap; i++) {
        const uint8_t *e = f + sec[4].off + 8 + 64u * i;
        struct osc_cap *c = &a->cap[i];
        c->resource_kind = rd16(e);
        c->resource_id = rd32(e + 4);
        c->rights = rd32(e + 8);
        c->bounds_kind = rd32(e + 12);
        c->max_operations = rd32(e + 16);
        c->max_bytes = rd64(e + 24);
        c->bounds_offset = rd64(e + 32);
        c->bounds_length = rd64(e + 40);
        c->domain = rd16(e + 48);
        c->required_generation = rd64(e + 56);
    }
    /* 16 */
    if (pol->reserve && pol->reserve(pol->ctx, a) != 0)
        return OSC_RESOURCE_UNAVAILABLE;
    return OSC_OK;
}

int osc_unit_lookup(const struct osc_accept *a, const char *name, size_t name_len)
{
    if (!a || !name)
        return -1;
    for (unsigned i = 0; i < a->function_count && i < OSC_MAX_FUNCS; i++)
        if (a->entry[i].name_len == name_len && memcmp(a->entry[i].name, name, name_len) == 0)
            return a->entry[i].fn_index;
    return -1;
}
