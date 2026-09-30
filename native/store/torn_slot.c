/*
 * torn_slot.c -- see torn_slot.h for the protocol and its argument.
 * No heap, no clock, no I/O except through the ts_device callbacks.
 */
#include "torn_slot.h"
#include "../argus/sha256.h"

#include <string.h>

static const uint8_t MAGIC[8] = {'A', 'I', 'E', 'N', 'T', 'W', 'S', '1'};
static const char RECORD_DOMAIN[] = "AIENOS-TORN-SLOT-RECORD-V1"; /* + its NUL */
static const char HEADER_DOMAIN[] = "AIENOS-TORN-SLOT-HEADER-V1"; /* + its NUL */

/* Header layout, little-endian, bytes 0..87 of the commit unit:
 *   0  8  magic "AIENTWS1"
 *   8  2  version = 1
 *  10  1  slot id (0 = A, 1 = B)
 *  11  1  reserved, zero
 *  12  4  record bytes = 4096
 *  16  8  seq (>= 1)
 *  24 32  record digest = SHA256(RECORD_DOMAIN\0 || slot:u8 || seq:u64le || record[4096])
 *  56 32  header digest = SHA256(HEADER_DOMAIN\0 || bytes[0..56))
 *  88..4095 zero
 */
#define OFF_VERSION 8
#define OFF_SLOT 10
#define OFF_RESERVED 11
#define OFF_RECBYTES 12
#define OFF_SEQ 16
#define OFF_RECDIGEST 24
#define OFF_HDRDIGEST 56

static void put_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put_u32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put_u64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint16_t get_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get_u32(const uint8_t *p) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint64_t get_u64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }

static void record_digest(int slot, uint64_t seq, const uint8_t rec[TS_RECORD_BYTES],
                          uint8_t out[SHA256_DIGEST_SIZE])
{
    sha256_ctx c;
    uint8_t sb[9];
    sb[0] = (uint8_t)slot;
    put_u64(sb + 1, seq);
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)RECORD_DOMAIN, sizeof RECORD_DOMAIN); /* includes NUL */
    sha256_update(&c, sb, sizeof sb);
    sha256_update(&c, rec, TS_RECORD_BYTES);
    sha256_final(&c, out);
}

static void header_digest(const uint8_t *hdr, uint8_t out[SHA256_DIGEST_SIZE])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)HEADER_DOMAIN, sizeof HEADER_DOMAIN);
    sha256_update(&c, hdr, OFF_HDRDIGEST);
    sha256_final(&c, out);
}

/* Constant-time compare is not needed (no secret), but avoid early exit
 * anyway so timing never depends on where a tear landed. */
static int digest_eq(const uint8_t *a, const uint8_t *b)
{
    uint8_t d = 0;
    for (unsigned i = 0; i < SHA256_DIGEST_SIZE; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

void ts_encode_commit(uint8_t unit[TS_RECORD_BYTES], int slot, uint64_t seq,
                      const uint8_t rec[TS_RECORD_BYTES])
{
    memset(unit, 0, TS_RECORD_BYTES);
    memcpy(unit, MAGIC, sizeof MAGIC);
    put_u16(unit + OFF_VERSION, 1);
    unit[OFF_SLOT] = (uint8_t)slot;
    unit[OFF_RESERVED] = 0;
    put_u32(unit + OFF_RECBYTES, TS_RECORD_BYTES);
    put_u64(unit + OFF_SEQ, seq);
    record_digest(slot, seq, rec, unit + OFF_RECDIGEST);
    header_digest(unit, unit + OFF_HDRDIGEST);
}

int ts_open(ts_region *r, const ts_device *dev, uint64_t base_lba)
{
    memset(r, 0, sizeof *r);
    r->newest_slot = -1;
    if (!dev || !dev->read || !dev->write || !dev->flush) return TS_EGEOMETRY;
    if (dev->block_size != 512 && dev->block_size != 4096) return TS_EGEOMETRY;
    uint32_t bpu = TS_RECORD_BYTES / dev->block_size; /* 8 or 1: a whole multiple */
    uint64_t need = (uint64_t)TS_UNITS * bpu;
    if (base_lba > dev->block_count || dev->block_count - base_lba < need) return TS_EGEOMETRY;
    r->dev = *dev;
    r->base_lba = base_lba;
    r->blocks_per_unit = bpu;
    return TS_OK;
}

static int read_unit(ts_region *r, unsigned unit, uint8_t *buf)
{
    uint64_t lba = r->base_lba + (uint64_t)unit * r->blocks_per_unit;
    return r->dev.read(r->dev.ctx, lba, r->blocks_per_unit, buf) ? TS_EIO : TS_OK;
}

static int write_unit(ts_region *r, unsigned unit, const uint8_t *buf)
{
    uint64_t lba = r->base_lba + (uint64_t)unit * r->blocks_per_unit;
    return r->dev.write(r->dev.ctx, lba, r->blocks_per_unit, buf) ? TS_EIO : TS_OK;
}

/* Validate one slot. body receives the body bytes when valid. */
static int check_slot(ts_region *r, int slot, uint8_t body[TS_RECORD_BYTES],
                      uint64_t *seq, ts_slot_state *st)
{
    uint8_t cu[TS_RECORD_BYTES];
    uint8_t d[SHA256_DIGEST_SIZE];
    int e = read_unit(r, (unsigned)(2 * slot + 1), cu);
    if (e) return e;
    *st = TS_SLOT_INVALID;
    if (all_zero(cu, TS_RECORD_BYTES)) { *st = TS_SLOT_BLANK; return TS_OK; }
    if (memcmp(cu, MAGIC, sizeof MAGIC) != 0) return TS_OK;
    if (get_u16(cu + OFF_VERSION) != 1) return TS_OK;
    if (cu[OFF_SLOT] != (uint8_t)slot || cu[OFF_RESERVED] != 0) return TS_OK;
    if (get_u32(cu + OFF_RECBYTES) != TS_RECORD_BYTES) return TS_OK;
    if (!all_zero(cu + TS_HEADER_BYTES, TS_RECORD_BYTES - TS_HEADER_BYTES)) return TS_OK;
    header_digest(cu, d);
    if (!digest_eq(d, cu + OFF_HDRDIGEST)) return TS_OK;
    uint64_t s = get_u64(cu + OFF_SEQ);
    if (s == 0) return TS_OK;
    e = read_unit(r, (unsigned)(2 * slot), body);
    if (e) return e;
    record_digest(slot, s, body, d);
    if (!digest_eq(d, cu + OFF_RECDIGEST)) return TS_OK;
    *seq = s;
    *st = TS_SLOT_VALID;
    return TS_OK;
}

/* With no valid slot and slot B blank, slot A's commit unit must look like
 * what a crash during the very first commit can leave: every byte either
 * zero (the blank unit before) or the byte the first header writes. The
 * fixed fields of that header are known (slot 0, seq 1), so a nonzero byte
 * that differs from them, or anything past the header, is corruption and
 * not a torn write. The digest bytes cannot be checked this way; damage
 * confined to them before any second commit reads as EMPTY. */
static int unfinished_first_commit(ts_region *r, int *plausible)
{
    uint8_t cu[TS_RECORD_BYTES];
    uint8_t t[OFF_RECDIGEST];
    *plausible = 0;
    int e = read_unit(r, 1, cu);
    if (e) return e;
    memcpy(t, MAGIC, sizeof MAGIC);
    put_u16(t + OFF_VERSION, 1);
    t[OFF_SLOT] = 0;
    t[OFF_RESERVED] = 0;
    put_u32(t + OFF_RECBYTES, TS_RECORD_BYTES);
    put_u64(t + OFF_SEQ, 1);
    for (unsigned i = 0; i < OFF_RECDIGEST; i++)
        if (cu[i] != 0 && cu[i] != t[i]) return TS_OK;
    if (!all_zero(cu + TS_HEADER_BYTES, TS_RECORD_BYTES - TS_HEADER_BYTES)) return TS_OK;
    *plausible = 1;
    return TS_OK;
}

int ts_recover(ts_region *r, uint8_t out[TS_RECORD_BYTES], uint64_t *seq_out,
               ts_slot_state slot_states[2])
{
    uint8_t body[2][TS_RECORD_BYTES];
    uint64_t seq[2] = {0, 0};
    ts_slot_state st[2] = {TS_SLOT_INVALID, TS_SLOT_INVALID};

    r->known = 0;
    r->newest_slot = -1;
    r->newest_seq = 0;
    memset(out, 0, TS_RECORD_BYTES);
    if (seq_out) *seq_out = 0;
    if (r->blocks_per_unit == 0) return TS_EGEOMETRY;

    for (int s = 0; s < 2; s++) {
        int e = check_slot(r, s, body[s], &seq[s], &st[s]);
        if (e) return e;
    }
    if (slot_states) { slot_states[0] = st[0]; slot_states[1] = st[1]; }

    int pick = -1;
    if (st[0] == TS_SLOT_VALID && st[1] == TS_SLOT_VALID) {
        if (seq[0] == seq[1]) return TS_CONFLICT;
        pick = seq[0] > seq[1] ? 0 : 1;
    } else if (st[0] == TS_SLOT_VALID) {
        pick = 0;
    } else if (st[1] == TS_SLOT_VALID) {
        pick = 1;
    }

    if (pick < 0) {
        /* Slot B is only ever written after slot A held a valid record, and
         * a valid newest slot is never rewritten, so "no valid slot" is a
         * crash outcome only while B is still blank and A holds a possible
         * remnant of the first commit. Anything else fails closed. */
        if (st[1] != TS_SLOT_BLANK) return TS_CORRUPT;
        int plausible = 0;
        int e = unfinished_first_commit(r, &plausible);
        if (e) return e;
        if (!plausible) return TS_CORRUPT;
        r->known = 1;
        return TS_EMPTY;
    }
    /* A valid slot A beside a blank slot B can only be the first commit. */
    if (pick == 0 && st[1] == TS_SLOT_BLANK && seq[0] != 1) return TS_CORRUPT;
    memcpy(out, body[pick], TS_RECORD_BYTES);
    if (seq_out) *seq_out = seq[pick];
    r->newest_slot = pick;
    r->newest_seq = seq[pick];
    r->known = 1;
    return TS_OK;
}

int ts_commit(ts_region *r, const uint8_t rec[TS_RECORD_BYTES])
{
    uint8_t cu[TS_RECORD_BYTES];
    if (!r->known) return TS_ESTATE;
    if (r->newest_seq == UINT64_MAX) return TS_ESTATE;
    int target = r->newest_slot < 0 ? 0 : 1 - r->newest_slot;
    uint64_t seq = r->newest_seq + 1;

    r->known = 0; /* any failure below requires a fresh recover() */
    int e = write_unit(r, (unsigned)(2 * target), rec);
    if (e) return e;
    if (r->dev.flush(r->dev.ctx)) return TS_EIO;
    ts_encode_commit(cu, target, seq, rec);
    e = write_unit(r, (unsigned)(2 * target + 1), cu);
    if (e) return e;
    if (r->dev.flush(r->dev.ctx)) return TS_EIO;
    r->newest_slot = target;
    r->newest_seq = seq;
    r->known = 1;
    return TS_OK;
}
