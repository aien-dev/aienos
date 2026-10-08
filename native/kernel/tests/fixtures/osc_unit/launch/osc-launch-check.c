/* osc-launch-check.c: reference for the launch-argument rule (spec 9.2).
 * Same logic as omega osc_ir_slice_args_ok (osc_ir.c:689-705 at d64ccb3) plus
 * the scalar-fits-kind rule. Usage: osc-launch-check KINDS ARGS
 * Prints OK | REFUSED LAUNCH_ARG_SHAPE 41. C99, libc only. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAXR 6
static int split(char *s, uint64_t *out) {
    int n = 0;
    for (char *t = strtok(s, ","); t; t = strtok(NULL, ",")) {
        if (n >= 64) return -1;
        out[n++] = strtoull(t, NULL, 0);
    }
    return n;
}
static int is_slice(uint64_t k) { return k == 11 || k == 12; }
static int fits(uint64_t k, uint64_t v) {
    switch (k) {
    case 1: return v <= 1;
    case 2: return v <= 0xff;
    case 3: return v <= 0xffff;
    case 4: return v <= 0xffffffffull;
    case 6: return (int64_t)v == (int8_t)v;
    case 7: return (int64_t)v == (int16_t)v;
    case 8: return (int64_t)v == (int32_t)v;
    default: return 1; /* 5, 9, slice registers */
    }
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    uint64_t kinds[64], args[64];
    char a[512], b[512];
    snprintf(a, sizeof a, "%s", argv[1]);
    snprintf(b, sizeof b, "%s", argv[2]);
    int nk = split(a, kinds), na = split(b, args);
    int bad = (nk < 0 || na != nk || nk > MAXR);
    for (int p = 0; !bad && p < nk; p++) {
        if (!is_slice(kinds[p]) && !fits(kinds[p], args[p])) bad = 1;
    }
    for (int p = 0; !bad && p + 1 < nk; p++) {
        if (!is_slice(kinds[p])) continue;
        uint64_t ptr = args[p], n = args[p + 1], sz = n * (kinds[p] == 12 ? 8 : 1);
        if ((kinds[p] == 12 && (n > UINT64_MAX / 8 || (n && (ptr & 7)))) || (n && !ptr) || sz > UINT64_MAX - ptr) bad = 1;
        for (int q = 0; !bad && q + 1 < nk; q++) {
            if (q == p || !is_slice(kinds[q])) continue;
            if (kinds[p] != 12 && kinds[q] != 12) continue;
            uint64_t qn = args[q + 1], qsz = qn * (kinds[q] == 12 ? 8 : 1);
            if (!sz || !qn || (kinds[q] == 12 && qn > UINT64_MAX / 8) || qsz > UINT64_MAX - args[q]) continue;
            if (ptr < args[q] + qsz && args[q] < ptr + sz) bad = 1;
        }
    }
    puts(bad ? "REFUSED LAUNCH_ARG_SHAPE 41" : "OK");
    return 0;
}
