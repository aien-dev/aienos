/* ck_manifest_sig.c -- PI5-8: owner signature over a Pi receipts manifest (scripts/pi5_receipts_manifest.sh),
 * using the in-tree Ed25519 (native/sig, RFC 8032 pure Ed25519) and SHA-256 (native/argus).
 *
 *   ck_manifest_sig statement MANIFEST OUT          writes the fixed signed statement for MANIFEST
 *   ck_manifest_sig verify MANIFEST SIG PUBKEYHEX   exit 0 only if SIG (64 raw bytes) is a valid Ed25519
 *                                                   signature over the statement rebuilt from MANIFEST
 *   ck_manifest_sig sign-test MANIFEST SIGOUT       signs that statement with the PUBLIC RFC 8032 TEST 1 secret key
 *
 * WHAT IS SIGNED (design, docs/native/PI5-8-OWNER-CEREMONY.md): the owner key lives in a YubiKey PIV slot. The PIV
 * Ed25519 operation signs the message it is handed (pure Ed25519) but the tool and the card take only a small
 * message (yubico-piv-tool: under 3072 bytes), and a manifest can be longer. So the owner signs a fixed ASCII
 * statement of four LF-terminated lines that binds the manifest by its length and sha256:
 *
 *   AIENOS-OWNER-STATEMENT-V1
 *   purpose pi5-8-receipts-manifest
 *   manifest_bytes <decimal length>
 *   manifest_sha256 <64 lowercase hex>
 *
 * The verifier rebuilds those bytes from the manifest it is given and checks a plain Ed25519 signature over them,
 * so any change to the manifest changes the statement and the signature fails. There is deliberately no way to
 * sign with any other key: no key file, no key argument. An owner signature is made by the YubiKey; this tool only
 * verifies it. "sign-test" exists to prove the statement is signable and verifiable, and its output says TEST ONLY. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aienos_sig.h"
#include "sha256.h"

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

/* Rebuild the signed statement for a manifest. Returns its length (fixed size for a given manifest length class). */
static size_t statement_of(const uint8_t *m, size_t mn, char *out, size_t cap)
{
    uint8_t d[SHA256_DIGEST_SIZE];
    char hex[2 * SHA256_DIGEST_SIZE + 1];
    sha256_hash(m, mn, d);
    for (size_t i = 0; i < SHA256_DIGEST_SIZE; i++)
        snprintf(hex + 2 * i, 3, "%02x", d[i]);
    int n = snprintf(out, cap,
                     "AIENOS-OWNER-STATEMENT-V1\npurpose pi5-8-receipts-manifest\nmanifest_bytes %zu\nmanifest_sha256 %s\n", mn,
                     hex);
    if (n <= 0 || (size_t)n >= cap) {
        fprintf(stderr, "error: statement does not fit\n");
        exit(2);
    }
    return (size_t)n;
}

static int writef(const char *path, const void *p, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(p, 1, n, f) != n || fclose(f)) {
        fprintf(stderr, "error: cannot write %s\n", path);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t sig[64], pk[32], sk[32];
    size_t mn, sn;
    char st[256];
    if (argc == 4 && !strcmp(argv[1], "statement")) {
        uint8_t *m = readf(argv[2], &mn);
        size_t n = statement_of(m, mn, st, sizeof st);
        return writef(argv[3], st, n) ? 2 : 0;
    }
    if (argc == 5 && !strcmp(argv[1], "verify")) {
        uint8_t *m = readf(argv[2], &mn);
        uint8_t *s = readf(argv[3], &sn);
        if (sn != 64 || unhex(argv[4], pk, 32)) {
            fprintf(stderr, "error: SIG must be 64 raw bytes and PUBKEYHEX 64 hex digits\n");
            return 2;
        }
        memcpy(sig, s, 64);
        size_t n = statement_of(m, mn, st, sizeof st);
        if (aienos_ed25519_verify(sig, (const uint8_t *)st, n, pk) != AIENOS_SIG_OK) {
            printf("MANIFEST_SIG: FAIL signature does not verify over the statement for these %zu manifest bytes\n", mn);
            return 1;
        }
        printf("MANIFEST_SIG: PASS signature verifies over the statement binding %zu manifest bytes, public key %s%s\n", mn,
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
        size_t n = statement_of(m, mn, st, sizeof st);
        if (aienos_ed25519_sign(sig, (const uint8_t *)st, n, sk) != AIENOS_SIG_OK) {
            fprintf(stderr, "error: sign failed\n");
            return 2;
        }
        if (writef(argv[3], sig, 64))
            return 2;
        printf("MANIFEST_SIGN: TEST ONLY, signed the statement for %zu manifest bytes with the public RFC 8032 TEST 1 key %s "
               "(not an owner or release key)\n", mn, TEST1_PK);
        return 0;
    }
    fprintf(stderr, "usage: ck_manifest_sig statement MANIFEST OUT | verify MANIFEST SIG PUBKEYHEX | sign-test MANIFEST SIGOUT\n");
    return 2;
}
