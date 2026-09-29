/*
 * fuzz_argus_event.c -- deterministic decode fuzzer (xorshift64*, fixed seed).
 * Invariants: argus_event_decode returns exactly what an independent byte-level
 * oracle (below, written from argus_abi.h) says; on error (VERSION or MALFORMED)
 * the output is untouched; on success the decoded event re-encodes to exactly
 * the input bytes. Built with -fsanitize=address,undefined by lane_b.mk.
 * v1.2: kinds 90-93 in the event oracle, plus the same four modes over 152-byte
 * ContainmentRequest buffers (decode vs byte oracle, re-encode identity, digest =
 * SHA-256 of the input, output untouched on error).
 * Usage: fuzz_argus_event [iterations]   (default 1,000,000)
 */
#include "argus_abi.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static const uint16_t kinds[] = { 1, 2, 3, 4, 10, 11, 12, 20, 21, 22, 30, 31, 32, 40, 41, 42, 43,
                                  50, 51, 52, 60, 61, 62, 63, 70, 71, 72, 80, 81, 90, 91, 92, 93 };

/* Class floor per kind (argus_abi.h hostile-review rules): 1 CRITICAL, 2 SECURITY, 3 AUDIT, 0 unknown. */
static unsigned floor_of(unsigned k)
{
    switch (k) {
    case 60: case 61: case 62: case 63: case 80: case 42: case 31: case 32:
    case 71: case 72: case 4: case 12: case 21: case 52:
    case 90: case 91: case 92: case 93: return 1;
    case 1: case 3: case 10: case 20: case 22: case 30: case 40: case 41: case 50: case 51: case 70: return 2;
    case 2: case 11: case 43: case 81: return 3;
    default: return 0;
    }
}

static uint64_t le64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

/* v1.2 kinds 90-92 (ARGUS1_SPEC section 3): object_id = type | status << 8 | code << 16,
 * world_generation = request_id. Written as explicit cases, independent of argus_event.c. */
static int contain_ok(unsigned kind, uint32_t oid, unsigned out, unsigned fl, uint64_t request_id)
{
    unsigned type = oid & 0xFFu, st = (oid >> 8) & 0xFFu;
    if (type < 1 || type > 10 || request_id == 0) return 0;
    if (kind == 90) return st == 0 && out == 1;
    if (kind == 91) return (st == 1 && out == 1) || (st == 2 && out == 2) || (st == 3 && out == 3);
    if (st == 4) return out == 1 && (type == 1 || (fl & 1u));   /* DONE; I2 */
    if (st == 5) return out == 1;
    if (st == 6) return out == 2 || out == 3;
    if (st == 7 || st == 8) return out == 3;
    return 0;
}

/* Expected decode result, straight from the bytes. */
static int oracle_bytes(const uint8_t b[ARGUS_EVENT_SIZE])
{
    unsigned cls = b[1], kind = b[2] | (unsigned)b[3] << 8, eff = b[4], out = b[5], fl = b[6] | (unsigned)b[7] << 8;
    uint64_t seq = le64(b + 8);
    if (b[0] != 1) return ARGUS_ERR_VERSION;
    unsigned f = floor_of(kind);
    if (cls < 1 || cls > 4 || f == 0 || cls > f) return ARGUS_ERR_MALFORMED;
    if (eff > 3 || out < 1 || out > 3) return ARGUS_ERR_MALFORMED;   /* v1.1: flag bits 2-15 = stream id */
    if (((fl & 2u) != 0) != (kind == 80 || kind == 90)) return ARGUS_ERR_MALFORMED;   /* v1.2: 90 too */
    if (kind >= 90 && kind <= 92 && !contain_ok(kind, le32(b + 36), out, fl, le64(b + 48))) return ARGUS_ERR_MALFORMED;
    if (le32(b + 32) >= 256 && le32(b + 32) != 0xFFFFFFFFu) return ARGUS_ERR_MALFORMED;   /* CAP_NONE ok */
    if (kind == 81 && out != 1) return ARGUS_ERR_MALFORMED;                                /* summary: OK only */
    if (kind == 81 && le64(b + 48) > le64(b + 40)) return ARGUS_ERR_MALFORMED;                /* summary: min gen <= max gen */
    if (seq == 0 || seq == UINT64_MAX) return ARGUS_ERR_MALFORMED;
    if (kind >= 50 && kind <= 52 && eff != 3) return ARGUS_ERR_MALFORMED;
    return ARGUS_OK;
}

static void random_bytes(uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)rnd(); }

static void valid_event(uint8_t b[ARGUS_EVENT_SIZE])
{
    ArgusEvent e;
    random_bytes((uint8_t *)&e, sizeof e);
    e.version = 1;
    e.kind = kinds[rnd() % (sizeof kinds / sizeof kinds[0])];
    e.class_ = (uint8_t)(1 + rnd() % floor_of(e.kind));
    e.effect_class = (e.kind >= 50 && e.kind <= 52) ? ARGUS_EFFECT_EXTERNAL : (uint8_t)(rnd() % 4);
    e.outcome = e.kind == ARGUS_EV_CAPABILITY_USE_SUMMARY ? ARGUS_OUTCOME_OK : (uint8_t)(1 + rnd() % 3);
    e.flags = (uint16_t)((rnd() % 2) | ((rnd() % ARGUS_STREAM_MAX) << ARGUS_FLAG_STREAM_SHIFT) |
                         (e.kind == ARGUS_EV_TELEMETRY_DROPPED || e.kind == ARGUS_EV_CONTAINMENT_PROPOSED ? ARGUS_FLAG_CONSUMER : 0));
    if (e.kind >= ARGUS_EV_CONTAINMENT_PROPOSED && e.kind <= ARGUS_EV_CONTAINMENT_EXECUTED) {   /* v1.2 */
        static const uint8_t st90[] = { 0 }, st91[] = { 1, 2, 3 }, st92[] = { 4, 5, 6, 6, 7, 8 };
        static const uint8_t out90[] = { 1 }, out91[] = { 1, 2, 3 }, out92[] = { 1, 1, 2, 3, 3, 3 };
        unsigned type = 1 + (unsigned)(rnd() % 10), j;
        if (e.kind == 90) { j = 0; e.outcome = out90[j]; e.object_id = ARGUS_CONTAIN_PACK(type, st90[j], rnd()); }
        else if (e.kind == 91) { j = (unsigned)(rnd() % 3); e.outcome = out91[j]; e.object_id = ARGUS_CONTAIN_PACK(type, st91[j], rnd()); }
        else { j = (unsigned)(rnd() % 6); e.outcome = out92[j]; e.object_id = ARGUS_CONTAIN_PACK(type, st92[j], rnd());
               if (st92[j] == 4 && type != 1) e.flags |= ARGUS_FLAG_SYNTHETIC; }
        if (e.world_generation == 0) e.world_generation = 1;
    }
    e.cap_id = rnd() % 8 == 0 ? ARGUS_CAP_NONE : (uint32_t)(rnd() % ARGUS_CAP_MAX);
    if (e.kind == ARGUS_EV_CAPABILITY_USE_SUMMARY && e.world_generation > e.cap_generation)
        e.world_generation = e.cap_generation - (e.cap_generation ? rnd() % (e.cap_generation < 1000 ? e.cap_generation : 1000) : 0);
    if (e.sequence == 0 || e.sequence == UINT64_MAX) e.sequence = 1;
    if (argus_event_encode(&e, b) != ARGUS_OK || argus_event_validate(&e) != ARGUS_OK) {
        fprintf(stderr, "FAIL: generated valid event did not validate/encode\n");
        exit(1);
    }
}

/* ---- v1.2 ContainmentRequest decode (152 bytes) ---- */
static int oracle_request(const uint8_t b[ARGUS_CONTAIN_REQUEST_SIZE])
{
    if (b[150] != 2) return ARGUS_ERR_VERSION;
    if (b[8] < 1 || b[8] > 10) return ARGUS_ERR_MALFORMED;           /* containment type */
    if (b[9] < 1 || b[9] > 5) return ARGUS_ERR_MALFORMED;            /* severity INFO..CRITICAL */
    if (b[151] != 0) return ARGUS_ERR_MALFORMED;                     /* reserved */
    if ((b[148] & ~3u) != 0 || b[149] != 0) return ARGUS_ERR_MALFORMED;   /* flags SYNTHETIC|SATURATION */
    if (le64(b + 92) == 0 || le64(b + 100) == 0) return ARGUS_ERR_MALFORMED;   /* request_id, finding_sequence */
    return ARGUS_OK;
}

static void valid_request(uint8_t b[ARGUS_CONTAIN_REQUEST_SIZE])
{
    random_bytes(b, ARGUS_CONTAIN_REQUEST_SIZE);
    b[8] = (uint8_t)(1 + rnd() % 10);
    b[9] = (uint8_t)(1 + rnd() % 5);
    b[148] = (uint8_t)(rnd() % 4); b[149] = 0;
    b[150] = 2; b[151] = 0;
    if (le64(b + 92) == 0) b[92] = 1;
    if (le64(b + 100) == 0) b[100] = 1;
}

/* Returns the number of violations. Modes: fully random, random with version 2, valid + 1..4
 * bit flips, valid + one random byte. On success the request re-encodes to the input and
 * its digest is SHA-256 of the input; on error the output is untouched. */
static unsigned long fuzz_requests(unsigned long iters)
{
    unsigned long ok[4] = {0}, err[4] = {0}, bad = 0;
    const char *mode_name[4] = { "fully random", "random, version=2", "valid + 1..4 bit flips", "valid + random byte" };
    for (unsigned long i = 0; i < iters; i++) {
        uint8_t in[ARGUS_CONTAIN_REQUEST_SIZE], re[ARGUS_CONTAIN_REQUEST_SIZE], d1[32], d2[32];
        unsigned mode = (unsigned)(i % 4);
        switch (mode) {
        case 0: random_bytes(in, sizeof in); break;
        case 1: random_bytes(in, sizeof in); in[150] = 2; break;
        case 2: {
            valid_request(in);
            unsigned flips = 1 + (unsigned)(rnd() % 4);
            for (unsigned f = 0; f < flips; f++) {
                unsigned bit = (unsigned)(rnd() % (ARGUS_CONTAIN_REQUEST_SIZE * 8));
                in[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            }
            break;
        }
        default: valid_request(in); in[rnd() % ARGUS_CONTAIN_REQUEST_SIZE] = (uint8_t)rnd(); break;
        }
        ArgusContainmentRequest out, sentinel;
        memset(&out, 0xA5, sizeof out);
        sentinel = out;
        int rc = argus_contain_request_decode(in, &out), want = oracle_request(in);
        if (rc != want) { bad++; fprintf(stderr, "FAIL request iteration %lu: decode %d, oracle %d\n", i, rc, want); }
        if (rc == ARGUS_OK) {
            ok[mode]++;
            argus_contain_request_digest(&out, d1);
            sha256_hash(in, sizeof in, d2);
            if (argus_contain_request_encode(&out, re) != ARGUS_OK || memcmp(in, re, sizeof in) != 0 || memcmp(d1, d2, 32) != 0) {
                bad++; fprintf(stderr, "FAIL request iteration %lu: re-encode or digest differs\n", i);
            }
        } else {
            err[mode]++;
            if (memcmp(&out, &sentinel, sizeof out) != 0) { bad++; fprintf(stderr, "FAIL request iteration %lu: output written on error\n", i); }
        }
        if (bad > 10) break;
    }
    unsigned long tot_ok = 0, tot_err = 0;
    for (unsigned m = 0; m < 4; m++) {
        printf("  request %-24s accepted %8lu  rejected %8lu\n", mode_name[m], ok[m], err[m]);
        tot_ok += ok[m]; tot_err += err[m];
    }
    printf("fuzz_argus_event: %lu request buffers, %lu accepted (re-encoded byte-identical, digest = SHA-256 of input), "
           "%lu rejected, every result matched the byte oracle, %lu violations\n", tot_ok + tot_err, tot_ok, tot_err, bad);
    if (tot_ok + tot_err != iters) bad++;
    return bad;
}

int main(int argc, char **argv)
{
    unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 1000000ul;
    unsigned long ok[4] = {0}, err[4] = {0}, bad = 0;
    const char *mode_name[4] = { "fully random", "random, version=1", "valid + 1..4 bit flips", "valid + random byte" };
    for (unsigned long i = 0; i < iters; i++) {
        uint8_t in[ARGUS_EVENT_SIZE], re[ARGUS_EVENT_SIZE];
        unsigned mode = (unsigned)(i % 4);
        switch (mode) {
        case 0: random_bytes(in, sizeof in); break;
        case 1: random_bytes(in, sizeof in); in[0] = 1; break;
        case 2: {
            valid_event(in);
            unsigned flips = 1 + (unsigned)(rnd() % 4);
            for (unsigned f = 0; f < flips; f++) {
                unsigned bit = (unsigned)(rnd() % (ARGUS_EVENT_SIZE * 8));
                in[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            }
            break;
        }
        default:
            valid_event(in);
            in[rnd() % ARGUS_EVENT_SIZE] = (uint8_t)rnd();
            break;
        }
        ArgusEvent out, sentinel;
        memset(&out, 0xA5, sizeof out);
        sentinel = out;
        int rc = argus_event_decode(in, &out);
        if (rc != oracle_bytes(in)) {
            bad++;
            fprintf(stderr, "FAIL iteration %lu: decode %d, oracle %d\n", i, rc, oracle_bytes(in));
        }
        if (rc == ARGUS_OK) {
            ok[mode]++;
            if (argus_event_encode(&out, re) != ARGUS_OK || memcmp(in, re, sizeof in) != 0) {
                bad++;
                fprintf(stderr, "FAIL iteration %lu: decoded event does not re-encode to input\n", i);
            }
        } else {
            err[mode]++;
            if (rc != ARGUS_ERR_VERSION && rc != ARGUS_ERR_MALFORMED) {
                bad++;
                fprintf(stderr, "FAIL iteration %lu: unexpected error %d\n", i, rc);
            }
            if (memcmp(&out, &sentinel, sizeof out) != 0) {
                bad++;
                fprintf(stderr, "FAIL iteration %lu: decode wrote output on error\n", i);
            }
        }
        if (bad > 10) break;
    }
    unsigned long tot_ok = 0, tot_err = 0;
    for (unsigned m = 0; m < 4; m++) {
        printf("  %-24s accepted %8lu  rejected %8lu\n", mode_name[m], ok[m], err[m]);
        tot_ok += ok[m]; tot_err += err[m];
    }
    printf("fuzz_argus_event: %lu iterations, %lu accepted (all re-encoded byte-identical), %lu rejected, every result matched the byte oracle, %lu violations\n",
           tot_ok + tot_err, tot_ok, tot_err, bad);
    bad += fuzz_requests(iters);
    if (bad || tot_ok + tot_err != iters) { printf("fuzz_argus_event: FAIL\n"); return 1; }
    printf("fuzz_argus_event: PASS\n");
    return 0;
}
