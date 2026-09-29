/*
 * fuzz_argus_event.c -- deterministic decode fuzzer (xorshift64*, fixed seed).
 * Invariants: argus_event_decode returns exactly what an independent byte-level
 * oracle (below, written from argus_abi.h) says; on error (VERSION or MALFORMED)
 * the output is untouched; on success the decoded event re-encodes to exactly
 * the input bytes. Built with -fsanitize=address,undefined by lane_b.mk.
 * Usage: fuzz_argus_event [iterations]   (default 1,000,000)
 */
#include "argus_abi.h"
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
                                  50, 51, 52, 60, 61, 62, 63, 70, 71, 72, 80 };

/* Class floor per kind (argus_abi.h hostile-review rules): 1 CRITICAL, 2 SECURITY, 3 AUDIT, 0 unknown. */
static unsigned floor_of(unsigned k)
{
    switch (k) {
    case 60: case 61: case 62: case 63: case 80: case 42: case 31: case 32:
    case 71: case 72: case 4: case 12: case 21: case 52: return 1;
    case 1: case 3: case 10: case 20: case 22: case 30: case 40: case 41: case 50: case 51: case 70: return 2;
    case 2: case 11: case 43: return 3;
    default: return 0;
    }
}

static uint64_t le64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

/* Expected decode result, straight from the bytes. */
static int oracle_bytes(const uint8_t b[ARGUS_EVENT_SIZE])
{
    unsigned cls = b[1], kind = b[2] | (unsigned)b[3] << 8, eff = b[4], out = b[5], fl = b[6] | (unsigned)b[7] << 8;
    uint64_t seq = le64(b + 8);
    if (b[0] != 1) return ARGUS_ERR_VERSION;
    unsigned f = floor_of(kind);
    if (cls < 1 || cls > 4 || f == 0 || cls > f) return ARGUS_ERR_MALFORMED;
    if (eff > 3 || out < 1 || out > 3 || (fl & ~3u)) return ARGUS_ERR_MALFORMED;
    if (((fl & 2u) != 0) != (kind == 80)) return ARGUS_ERR_MALFORMED;
    if (le32(b + 32) >= 256) return ARGUS_ERR_MALFORMED;
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
    e.outcome = (uint8_t)(1 + rnd() % 3);
    e.flags = (uint16_t)((rnd() % 2) | (e.kind == ARGUS_EV_TELEMETRY_DROPPED ? ARGUS_FLAG_CONSUMER : 0));
    e.cap_id = (uint32_t)(rnd() % ARGUS_CAP_MAX);
    if (e.sequence == 0 || e.sequence == UINT64_MAX) e.sequence = 1;
    if (argus_event_encode(&e, b) != ARGUS_OK || argus_event_validate(&e) != ARGUS_OK) {
        fprintf(stderr, "FAIL: generated valid event did not validate/encode\n");
        exit(1);
    }
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
    if (bad || tot_ok + tot_err != iters) { printf("fuzz_argus_event: FAIL\n"); return 1; }
    printf("fuzz_argus_event: PASS\n");
    return 0;
}
