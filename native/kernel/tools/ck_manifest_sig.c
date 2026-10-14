/* ck_manifest_sig.c -- PI5-8 Q6: detached Ed25519 signature over the exact bytes of a Pi receipts manifest
 * (scripts/pi5_receipts_manifest.sh), using the in-tree Ed25519 (native/sig, RFC 8032 pure Ed25519).
 *
 *   ck_manifest_sig verify MANIFEST SIG PUBKEYHEX   exit 0 only if SIG (64 raw bytes) is valid over MANIFEST
 *   ck_manifest_sig sign-test MANIFEST SIGOUT       signs with the PUBLIC RFC 8032 TEST 1 secret key
 *
 * There is deliberately no way to sign with any other key: no key file, no key argument. An owner or release
 * signature will be made by the owner's own signing tool; this tool only verifies those. "sign-test" exists to
 * prove the manifest bytes are signable and verifiable, and its output says TEST ONLY. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aienos_sig.h"

/* RFC 8032 section 7.1 TEST 1 (public, published in the RFC; protects nothing). */
static const char *const TEST1_SK = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
static const char *const TEST1_PK = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

static int unhex(const char *s, uint8_t *o, size_t n)
{
    if (strlen(s) != 2 * n)
        return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = s[2 * i + k];
            unsigned d = c >= '0' && c <= '9' ? (unsigned)(c - '0')
                         : c >= 'a' && c <= 'f' ? (unsigned)(c - 'a' + 10)
                         : c >= 'A' && c <= 'F' ? (unsigned)(c - 'A' + 10) : 99u;
            if (d > 15)
                return -1;
            v = v * 16 + d;
        }
        o[i] = (uint8_t)v;
    }
    return 0;
}

static uint8_t *readf(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot read %s\n", path);
        exit(2);
    }
    size_t cap = 1 << 16, len = 0;
    uint8_t *p = malloc(cap);
    size_t r;
    while (p && (r = fread(p + len, 1, cap - len, f)) > 0) {
        len += r;
        if (len == cap) {
            cap *= 2;
            p = realloc(p, cap);
        }
    }
    fclose(f);
    if (!p) {
        fprintf(stderr, "error: out of memory\n");
        exit(2);
    }
    *n = len;
    return p;
}

int main(int argc, char **argv)
{
    uint8_t sig[64], pk[32], sk[32];
    size_t mn, sn;
    if (argc == 5 && !strcmp(argv[1], "verify")) {
        uint8_t *m = readf(argv[2], &mn);
        uint8_t *s = readf(argv[3], &sn);
        if (sn != 64 || unhex(argv[4], pk, 32)) {
            fprintf(stderr, "error: SIG must be 64 raw bytes and PUBKEYHEX 64 hex digits\n");
            return 2;
        }
        memcpy(sig, s, 64);
        if (aienos_ed25519_verify(sig, m, mn, pk) != AIENOS_SIG_OK) {
            printf("MANIFEST_SIG: FAIL signature does not verify (%zu manifest bytes)\n", mn);
            return 1;
        }
        printf("MANIFEST_SIG: PASS signature verifies over %zu manifest bytes, public key %s%s\n", mn,
               argv[4], strcmp(argv[4], TEST1_PK) ? "" : " (RFC 8032 TEST 1 key: TEST ONLY, not an owner or release key)");
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "sign-test")) {
        uint8_t *m = readf(argv[2], &mn);
        uint8_t pk2[32];
        if (unhex(TEST1_SK, sk, 32) || unhex(TEST1_PK, pk, 32) || aienos_ed25519_public_key(pk2, sk) != 0 ||
            memcmp(pk, pk2, 32)) {
            fprintf(stderr, "error: RFC 8032 TEST 1 key self-check failed\n");
            return 2;
        }
        if (aienos_ed25519_sign(sig, m, mn, sk) != AIENOS_SIG_OK) {
            fprintf(stderr, "error: sign failed\n");
            return 2;
        }
        FILE *f = fopen(argv[3], "wb");
        if (!f || fwrite(sig, 1, 64, f) != 64 || fclose(f)) {
            fprintf(stderr, "error: cannot write %s\n", argv[3]);
            return 2;
        }
        printf("MANIFEST_SIGN: TEST ONLY, signed %zu manifest bytes with the public RFC 8032 TEST 1 key %s "
               "(not an owner or release key)\n", mn, TEST1_PK);
        return 0;
    }
    fprintf(stderr, "usage: ck_manifest_sig verify MANIFEST SIG PUBKEYHEX | sign-test MANIFEST SIGOUT\n");
    return 2;
}
