/* Known-answer and negative tests for native/crypto.
 *
 * Vector sources (all hard-coded, none generated at build time):
 *   - RFC 8452 Appendix C.2 (all 24 AEAD_AES_256_GCM_SIV vectors) and
 *     C.3 (both counter-wrap vectors), copied verbatim from the RFC text,
 *     including record keys and POLYVAL input/result for each vector.
 *   - RFC 8452 Section 7 dot() example and Appendix A POLYVAL worked example.
 *   - FIPS 197 Appendix C.3 AES-256 block, FIPS 197 Figure 7 S-box.
 *   - crates/aienos-crypto unit tests (the same vectors, re-run separately).
 *   - FIPS 180-2 SHA-256 examples, RFC 4231 HMAC-SHA-256 cases 1 and 2.
 * Last line is exactly AIENOS_CRYPTO_NATIVE: PASS (exit 0) or ... FAIL (exit 1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../aienos_crypto.h"
#include "../crypto_internal.h"

static int g_fail, g_checks;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        g_checks++;                                            \
        if (!(cond)) {                                         \
            g_fail++;                                          \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                      \
            fprintf(stderr, "\n");                             \
        }                                                      \
    } while (0)

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex into a freshly allocated buffer (at least 1 byte). */
static uint8_t *unhex(const char *h, size_t *len)
{
    size_t n = strlen(h);
    if (n % 2 != 0) { fprintf(stderr, "odd hex\n"); exit(1); }
    uint8_t *b = malloc(n / 2 + 1);
    if (!b) exit(1);
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(h[2 * i]), lo = hexval(h[2 * i + 1]);
        if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex\n"); exit(1); }
        b[i] = (uint8_t)(hi << 4 | lo);
    }
    *len = n / 2;
    return b;
}

static void unhex_fixed(const char *h, uint8_t *out, size_t want)
{
    size_t n;
    uint8_t *b = unhex(h, &n);
    if (n != want) { fprintf(stderr, "hex length %zu != %zu\n", n, want); exit(1); }
    memcpy(out, b, n);
    free(b);
}

static int all_zero(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i]) return 0;
    return 1;
}

static int all_byte(const uint8_t *p, size_t n, uint8_t v)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != v) return 0;
    return 1;
}

/* ---------------- AES ---------------- */

static const uint8_t FIPS197_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static int n_aes, n_polyval, n_gcmsiv_rfc, n_rust, n_sha, n_neg;

static void test_aes(void)
{
    /* Every S-box entry, single byte in lane 0. */
    for (int b = 0; b < 256; b++) {
        uint8_t s[16] = {0};
        s[0] = (uint8_t)b;
        aienos_aes_sub_bytes16(s);
        CHECK(s[0] == FIPS197_SBOX[b], "sbox[%02x]", b);
    }
    /* All 16 lanes at once, each lane a different input (as aes.rs test). */
    for (int base = 0; base < 256; base += 16) {
        uint8_t s[16], in[16];
        for (int i = 0; i < 16; i++)
            in[i] = s[i] = (uint8_t)(base + i);
        aienos_aes_sub_bytes16(s);
        for (int i = 0; i < 16; i++)
            CHECK(s[i] == FIPS197_SBOX[in[i]], "sbox lanes base %d i %d", base, i);
    }
    n_rust++; /* aes.rs test_constant_time_sbox_matches_fips197_table */

    /* FIPS 197 Appendix C.3 AES-256 (aes.rs test_aes_256_fips_197_c2). */
    uint8_t key[32], blk[16], exp[16];
    aienos_aes256_key k;
    unhex_fixed("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);
    unhex_fixed("00112233445566778899aabbccddeeff", blk, 16);
    unhex_fixed("8ea2b7ca516745bfeafc49904b496089", exp, 16);
    aienos_aes256_init(&k, key);
    aienos_aes256_encrypt_block(&k, blk);
    CHECK(memcmp(blk, exp, 16) == 0, "FIPS 197 AES-256 block");
    aienos_aes256_wipe(&k);
    CHECK(all_zero((const uint8_t *)k.rk, sizeof k.rk), "aes wipe");
    n_aes += 2;
    n_rust++;
}

/* ---------------- POLYVAL ---------------- */

static void test_polyval(void)
{
    uint8_t a[16], b[16], e[16], r[16];
    /* RFC 8452 Section 7 (polyval.rs test_polyval_rfc8452_section_7_dot). */
    unhex_fixed("66e94bd4ef8a2c3b884cfa59ca342b2e", a, 16);
    unhex_fixed("ff000000000000000000000000000000", b, 16);
    unhex_fixed("ebe563401e7e91ea3ad6426b8140c394", e, 16);
    aienos_polyval_dot(r, a, b);
    CHECK(memcmp(r, e, 16) == 0, "RFC 8452 s7 dot");
    aienos_polyval_dot(a, a, b); /* aliasing out == a */
    CHECK(memcmp(a, e, 16) == 0, "dot aliasing");

    /* RFC 8452 Appendix A worked example (polyval.rs appendix_a test). */
    uint8_t h[16], x[32];
    aienos_polyval pv;
    unhex_fixed("25629347589242761d31f826ba4b757b", h, 16);
    unhex_fixed("4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362", x, 32);
    unhex_fixed("f7a3b47b846119fae5b7866cf5e5b77e", e, 16);
    aienos_polyval_init(&pv, h);
    aienos_polyval_update_block(&pv, x);
    aienos_polyval_update_block(&pv, x + 16);
    aienos_polyval_final(&pv, r);
    CHECK(memcmp(r, e, 16) == 0, "RFC 8452 App A POLYVAL blocks");
    CHECK(all_zero((const uint8_t *)&pv, sizeof pv), "polyval final wipes state");
    aienos_polyval_init(&pv, h);
    CHECK(aienos_polyval_update(&pv, x, 32) == AIENOS_CRYPTO_OK, "polyval update 32");
    aienos_polyval_final(&pv, r);
    CHECK(memcmp(r, e, 16) == 0, "RFC 8452 App A POLYVAL slice");
    aienos_polyval_init(&pv, h);
    CHECK(aienos_polyval_update(&pv, x, 17) == AIENOS_CRYPTO_ERR_LENGTH, "polyval unaligned rejected");
    CHECK(all_zero(pv.s, 16), "polyval unaligned absorbs nothing");
    aienos_polyval_wipe(&pv);
    n_polyval += 2;
    n_rust += 2;
}

/* ---------------- AES-256-GCM-SIV ---------------- */

struct siv_vec {
    size_t pt_len, aad_len; /* as declared in the RFC headings */
    const char *pt, *aad, *key, *nonce, *auth_key, *enc_key, *pv_in, *pv_out, *tag, *result;
};

static const struct siv_vec RFC_VECS[] = {
    { /* RFC 8452 C.2 */ 0, 0,
      "",
      "",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "00000000000000000000000000000000",
      "00000000000000000000000000000000",
      "07f5f4169bbf55a8400cd47ea6fd400f",
      "07f5f4169bbf55a8400cd47ea6fd400f" },
    { /* RFC 8452 C.2 */ 8, 0,
      "0100000000000000",
      "",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "0100000000000000000000000000000000000000000000004000000000000000",
      "05230f62f0eac8aa14fe4d646b59cd41",
      "843122130f7364b761e0b97427e3df28",
      "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28" },
    { /* RFC 8452 C.2 */ 12, 0,
      "010000000000000000000000",
      "",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "0100000000000000000000000000000000000000000000006000000000000000",
      "6d81a24732fd6d03ae5af544720a1c13",
      "8ca50da9ae6559e48fd10f6e5c9ca17e",
      "9aab2aeb3faa0a34aea8e2b18ca50da9ae6559e48fd10f6e5c9ca17e" },
    { /* RFC 8452 C.2 */ 16, 0,
      "01000000000000000000000000000000",
      "",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "0100000000000000000000000000000000000000000000008000000000000000",
      "74eee2bf7c9a165f8b25dea73db32a6d",
      "c9eac6fa700942702e90862383c6c366",
      "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366" },
    { /* RFC 8452 C.2 */ 32, 0,
      "0100000000000000000000000000000002000000000000000000000000000000",
      "",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "010000000000000000000000000000000200000000000000000000000000000000000000000000000001000000000000",
      "899b6381b3d46f0def7aa0517ba188f5",
      "e819e63abcd020b006a976397632eb5d",
      "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d" },
    { /* RFC 8452 C.2 */ 48, 0,
      "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000",
      "",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000000000000000000008001000000000000",
      "c1f8593d8fc29b0c290cae1992f71f51",
      "790bc96880a99ba804bd12c0e6a22cc4",
      "c00d121893a9fa603f48ccc1ca3c57ce7499245ea0046db16c53c7c66fe717e39cf6c748837b61f6ee3adcee17534ed5790bc96880a99ba804bd12c0e6a22cc4" },
    { /* RFC 8452 C.2 */ 64, 0,
      "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
      "",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "0100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000000000000000000000002000000000000",
      "6ef38b06046c7c0e225efaef8e2ec4c4",
      "112864c269fc0d9d88c61fa47e39aa08",
      "c2d5160a1f8683834910acdafc41fbb1632d4a353e8b905ec9a5499ac34f96c7e1049eb080883891a4db8caaa1f99dd004d80487540735234e3744512c6f90ce112864c269fc0d9d88c61fa47e39aa08" },
    { /* RFC 8452 C.2 */ 8, 1,
      "0200000000000000",
      "01",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "010000000000000000000000000000000200000000000000000000000000000008000000000000004000000000000000",
      "34e57bafe011b9b36fc6821b7ffb3354",
      "91213f267e3b452f02d01ae33e4ec854",
      "1de22967237a813291213f267e3b452f02d01ae33e4ec854" },
    { /* RFC 8452 C.2 */ 12, 1,
      "020000000000000000000000",
      "01",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "010000000000000000000000000000000200000000000000000000000000000008000000000000006000000000000000",
      "5c47d68a22061c1ad5623a3b66a8e206",
      "c1a4a19ae800941ccdc57cc8413c277f",
      "163d6f9cc1b346cd453a2e4cc1a4a19ae800941ccdc57cc8413c277f" },
    { /* RFC 8452 C.2 */ 16, 1,
      "02000000000000000000000000000000",
      "01",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "010000000000000000000000000000000200000000000000000000000000000008000000000000008000000000000000",
      "452896726c616746f01d11d82911d478",
      "b292d28ff61189e8e49f3875ef91aff7",
      "c91545823cc24f17dbb0e9e807d5ec17b292d28ff61189e8e49f3875ef91aff7" },
    { /* RFC 8452 C.2 */ 32, 1,
      "0200000000000000000000000000000003000000000000000000000000000000",
      "01",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000008000000000000000001000000000000",
      "4e58c1e341c9bb0ae34eda9509dfc90c",
      "aea1bad12702e1965604374aab96dbbc",
      "07dad364bfc2b9da89116d7bef6daaaf6f255510aa654f920ac81b94e8bad365aea1bad12702e1965604374aab96dbbc" },
    { /* RFC 8452 C.2 */ 48, 1,
      "020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000",
      "01",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "0100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000008000000000000008001000000000000",
      "2566a4aff9a525df9772c16d4eaf8d2a",
      "03332742b228c647173616cfd44c54eb",
      "c67a1f0f567a5198aa1fcc8e3f21314336f7f51ca8b1af61feac35a86416fa47fbca3b5f749cdf564527f2314f42fe2503332742b228c647173616cfd44c54eb" },
    { /* RFC 8452 C.2 */ 64, 1,
      "02000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000",
      "01",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000040000000000000000000000000000000500000000000000000000000000000008000000000000000002000000000000",
      "da58d2f61b0a9d343b2f37fb0c519733",
      "5bde0285037c5de81e5b570a049b62a0",
      "67fd45e126bfb9a79930c43aad2d36967d3f0e4d217c1e551f59727870beefc98cb933a8fce9de887b1e40799988db1fc3f91880ed405b2dd298318858467c895bde0285037c5de81e5b570a049b62a0" },
    { /* RFC 8452 C.2 */ 4, 12,
      "02000000",
      "010000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "010000000000000000000000000000000200000000000000000000000000000060000000000000002000000000000000",
      "6dc76ae84b88916e073a303aafde05cf",
      "1835e517741dfddccfa07fa4661b74cf",
      "22b3f4cd1835e517741dfddccfa07fa4661b74cf" },
    { /* RFC 8452 C.2 */ 20, 18,
      "0300000000000000000000000000000004000000",
      "010000000000000000000000000000000200",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "010000000000000000000000000000000200000000000000000000000000000003000000000000000000000000000000040000000000000000000000000000009000000000000000a000000000000000",
      "973ef4fd04bd31d193816ab26f8655ca",
      "b879ad976d8242acc188ab59cabfe307",
      "43dd0163cdb48f9fe3212bf61b201976067f342bb879ad976d8242acc188ab59cabfe307" },
    { /* RFC 8452 C.2 */ 18, 20,
      "030000000000000000000000000000000400",
      "0100000000000000000000000000000002000000",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      "b5d3c529dfafac43136d2d11be284d7f",
      "b914f4742be9e1d7a2f84addbf96dec3456e3c6c05ecc157cdbf0700fedad222",
      "01000000000000000000000000000000020000000000000000000000000000000300000000000000000000000000000004000000000000000000000000000000a0000000000000009000000000000000",
      "2cbb6b7ab2dbffefb797f825f826870c",
      "cfcdf5042112aa29685c912fc2056543",
      "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543" },
    { /* RFC 8452 C.2 */ 0, 0,
      "",
      "",
      "e66021d5eb8e4f4066d4adb9c33560e4f46e44bb3da0015c94f7088736864200", "e0eaf5284d884a0e77d31646",
      "e40d26f82774aa27f47b047b608b9585",
      "7c7c3d9a542cef53dde0e6de9b5800400f82e73ec5f7ee41b7ba8dcb9ba078c3",
      "00000000000000000000000000000000",
      "00000000000000000000000000000000",
      "169fbb2fbf389a995f6390af22228a62",
      "169fbb2fbf389a995f6390af22228a62" },
    { /* RFC 8452 C.2 */ 3, 5,
      "671fdd",
      "4fbdc66f14",
      "bae8e37fc83441b16034566b7a806c46bb91c3c5aedb64a6c590bc84d1a5e269", "e4b47801afc0577e34699b9e",
      "b546f5a850d0a90adfe39e95c2510fc6",
      "b9d1e239d62cbb5c49273ddac8838bdcc53bca478a770f07087caa4e0a924a55",
      "4fbdc66f140000000000000000000000671fdd0000000000000000000000000028000000000000001800000000000000",
      "b91f91f96b159a7c611c05035b839e92",
      "93da9bb81333aee0c785b240d319719d",
      "0eaccb93da9bb81333aee0c785b240d319719d" },
    { /* RFC 8452 C.2 */ 6, 10,
      "195495860f04",
      "6787f3ea22c127aaf195",
      "6545fc880c94a95198874296d5cc1fd161320b6920ce07787f86743b275d1ab3", "2f6d1f0434d8848c1177441f",
      "e156e1f9b0b07b780cbe30f259e3c8da",
      "6fc1c494519f944aae52fcd8b14e5b171b5a9429d3b76e430d49940c0021d612",
      "6787f3ea22c127aaf195000000000000195495860f040000000000000000000050000000000000003000000000000000",
      "2c480ed9d236b1df24c6eec109bd40c1",
      "6b62b84dc40c84636a5ec12020ec8c2c",
      "a254dad4f3f96b62b84dc40c84636a5ec12020ec8c2c" },
    { /* RFC 8452 C.2 */ 9, 15,
      "c9882e5386fd9f92ec",
      "489c8fde2be2cf97e74e932d4ed87d",
      "d1894728b3fed1473c528b8426a582995929a1499e9ad8780c8d63d0ab4149c0", "9f572c614b4745914474e7c7",
      "0533fd71f4119257361a3ff1469dd4e5",
      "4feba89799be8ac3684fa2bb30ade0ea51390e6d87dcf3627d2ee44493853abe",
      "489c8fde2be2cf97e74e932d4ed87d00c9882e5386fd9f92ec0000000000000078000000000000004800000000000000",
      "bf160bc9ded8c63057d2c38aae552fb4",
      "c0fd3dc6628dfe55ebb0b9fb2295c8c2",
      "0df9e308678244c44bc0fd3dc6628dfe55ebb0b9fb2295c8c2" },
    { /* RFC 8452 C.2 */ 12, 20,
      "1db2316fd568378da107b52b",
      "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f",
      "a44102952ef94b02b805249bac80e6f61455bfac8308a2d40d8c845117808235", "5c9e940fea2f582950a70d5a",
      "64779ab10ee8a280272f14cc8851b727",
      "25f40fc63f49d3b9016a8eeeb75846e0d72ca36ddbd312b6f5ef38ad14bd2651",
      "0da55210cc1c1b0abde3b2f204d1e9f8b06bc47f0000000000000000000000001db2316fd568378da107b52b00000000a0000000000000006000000000000000",
      "cc86ee22c861e1fd474c84676b42739c",
      "404099c2587f64979f21826706d497d5",
      "8dbeb9f7255bf5769dd56692404099c2587f64979f21826706d497d5" },
    { /* RFC 8452 C.2 */ 15, 25,
      "21702de0de18baa9c9596291b08466",
      "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f",
      "9745b3d1ae06556fb6aa7890bebc18fe6b3db4da3d57aa94842b9803a96e07fb", "6de71860f762ebfbd08284e4",
      "27c2959ed4daea3b1f52e849478de376",
      "307a38a5a6cf231c0a9af3b527f23a62e9a6ff09aff8ae669f760153e864fc93",
      "f37de21c7ff901cfe8a69615a93fdf7a98cad481796245709f0000000000000021702de0de18baa9c9596291b0846600c8000000000000007800000000000000",
      "c4fa5e5b713853703bcf8e6424505fa5",
      "b3080d28f6ebb5d3648ce97bd5ba67fd",
      "793576dfa5c0f88729a7ed3c2f1bffb3080d28f6ebb5d3648ce97bd5ba67fd" },
    { /* RFC 8452 C.2 */ 18, 30,
      "b202b370ef9768ec6561c4fe6b7e7296fa85",
      "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac7",
      "b18853f68d833640e42a3c02c25b64869e146d7b233987bddfc240871d7576f7", "028ec6eb5ea7e298342a94d4",
      "670b98154076ddb59b7a9137d0dcc0f0",
      "78116d78507fbe69d4a820c350f55c7cb36c3c9287df0e9614b142b76a587c3f",
      "9c2159058b1f0fe91433a5bdc20e214eab7fecef4454a10ef0657df21ac70000b202b370ef9768ec6561c4fe6b7e7296fa850000000000000000000000000000f0000000000000009000000000000000",
      "4e4108f09f41d797dc9256f8da8d58c7",
      "454fc2a154fea91f8363a39fec7d0a49",
      "857e16a64915a787637687db4a9519635cdd454fc2a154fea91f8363a39fec7d0a49" },
    { /* RFC 8452 C.2 */ 21, 35,
      "ced532ce4159b035277d4dfbb7db62968b13cd4eec",
      "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f167541",
      "3c535de192eaed3822a2fbbe2ca9dfc88255e14a661b8aa82cc54236093bbc23", "688089e55540db1872504e1c",
      "cb8c3aa3f8dbaeb4b28a3e86ff6625f8",
      "02426ce1aa3ab31313b0848469a1b5fc6c9af9602600b195b04ad407026bc06d",
      "734320ccc9d9bbbb19cb81b2af4ecbc3e72834321f7aa0f70b7282b4f33df23f16754100000000000000000000000000ced532ce4159b035277d4dfbb7db62968b13cd4eec00000000000000000000001801000000000000a800000000000000",
      "ffd503c7dd712eb3791b7114b17bb0cf",
      "9d6c7029675b89eaf4ba1ded1a286594",
      "626660c26ea6612fb17ad91e8e767639edd6c9faee9d6c7029675b89eaf4ba1ded1a286594" },
    { /* RFC 8452 C.3 */ 32, 0,
      "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e108",
      "",
      "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
      "dc95c078a24089895275f3d86b4fb868",
      "779b38d15bffb63d39d6e9ae76a9b2f375d11b0e3a68c422845c7d4690fa594f",
      "000000000000000000000000000000004db923dc793ee6497c76dcc03a98e10800000000000000000001000000000000",
      "7367cdb411b730128dd56e8edc0eff56",
      "ffffffff000000000000000000000000",
      "f3f80f2cf0cb2dd9c5984fcda908456cc537703b5ba70324a6793a7bf218d3eaffffffff000000000000000000000000" },
    { /* RFC 8452 C.3 */ 24, 0,
      "eb3640277c7ffd1303c7a542d02d3e4c0000000000000000",
      "",
      "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
      "dc95c078a24089895275f3d86b4fb868",
      "779b38d15bffb63d39d6e9ae76a9b2f375d11b0e3a68c422845c7d4690fa594f",
      "eb3640277c7ffd1303c7a542d02d3e4c000000000000000000000000000000000000000000000000c000000000000000",
      "7367cdb411b730128dd56e8edc0eff56",
      "ffffffff000000000000000000000000",
      "18ce4f0b8cb4d0cac65fea8f79257b20888e53e72299e56dffffffff000000000000000000000000" },
};
#define N_RFC_VECS (sizeof RFC_VECS / sizeof RFC_VECS[0])

/* The two GCM-SIV vectors in aes_gcm_siv.rs tests (RFC 8452 C.2 entries). */
static const struct siv_vec RUST_VECS[] = {
    { 16, 0, "01000000000000000000000000000000", "",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      NULL, NULL, NULL, NULL, NULL,
      "85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366" },
    { 8, 1, "0200000000000000", "01",
      "0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000",
      NULL, NULL, NULL, NULL, NULL,
      "1de22967237a813291213f267e3b452f02d01ae33e4ec854" },
};

/* Open must reject and leave out all zero. */
static void expect_reject(const char *what, size_t vi, const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t in_len)
{
    size_t out_len = in_len - 16;
    uint8_t *out = malloc(out_len + 1);
    if (!out) exit(1);
    memset(out, 0xa5, out_len + 1);
    int rc = aienos_gcmsiv_open(key, nonce, aad, aad_len, in, in_len, out, out_len);
    CHECK(rc == AIENOS_CRYPTO_ERR_AUTH, "vec %zu %s: open rc %d", vi, what, rc);
    CHECK(all_zero(out, out_len), "vec %zu %s: output not zeroed", vi, what);
    CHECK(out[out_len] == 0xa5, "vec %zu %s: wrote past out_len", vi, what);
    free(out);
    n_neg++;
}

static void run_vec(const struct siv_vec *v, size_t vi, int full)
{
    size_t pt_len, aad_len, key_len, nonce_len, res_len, n;
    uint8_t *pt = unhex(v->pt, &pt_len), *aad = unhex(v->aad, &aad_len);
    uint8_t *key = unhex(v->key, &key_len), *nonce = unhex(v->nonce, &nonce_len);
    uint8_t *res = unhex(v->result, &res_len);

    CHECK(pt_len == v->pt_len && aad_len == v->aad_len, "vec %zu declared lengths", vi);
    CHECK(key_len == 32 && nonce_len == 12 && res_len == pt_len + 16, "vec %zu field lengths", vi);
    if (key_len != 32 || nonce_len != 12 || res_len != pt_len + 16) {
        free(pt); free(aad); free(key); free(nonce); free(res);
        return;
    }

    if (full) {
        uint8_t ak[16], ek[32], eak[16], eek[32], tag[16], pin_out[16], r[16];
        aienos_gcmsiv_derive_keys(key, nonce, ak, ek);
        unhex_fixed(v->auth_key, eak, 16);
        unhex_fixed(v->enc_key, eek, 32);
        CHECK(memcmp(ak, eak, 16) == 0, "vec %zu auth key", vi);
        CHECK(memcmp(ek, eek, 32) == 0, "vec %zu enc key", vi);
        uint8_t *pin = unhex(v->pv_in, &n);
        aienos_polyval pv;
        aienos_polyval_init(&pv, eak);
        CHECK(aienos_polyval_update(&pv, pin, n) == AIENOS_CRYPTO_OK, "vec %zu polyval len", vi);
        aienos_polyval_final(&pv, r);
        unhex_fixed(v->pv_out, pin_out, 16);
        CHECK(memcmp(r, pin_out, 16) == 0, "vec %zu POLYVAL result", vi);
        unhex_fixed(v->tag, tag, 16);
        CHECK(memcmp(res + pt_len, tag, 16) == 0, "vec %zu tag field", vi);
        free(pin);
    }

    /* Seal. */
    uint8_t *ct = malloc(res_len + 1);
    if (!ct) exit(1);
    ct[res_len] = 0x5a;
    int rc = aienos_gcmsiv_seal(key, nonce, aad_len ? aad : NULL, aad_len, pt_len ? pt : NULL, pt_len, ct, res_len);
    CHECK(rc == AIENOS_CRYPTO_OK && memcmp(ct, res, res_len) == 0, "vec %zu seal", vi);
    CHECK(ct[res_len] == 0x5a, "vec %zu seal wrote past end", vi);

    /* Open. */
    uint8_t *pt2 = malloc(pt_len + 1);
    if (!pt2) exit(1);
    rc = aienos_gcmsiv_open(key, nonce, aad_len ? aad : NULL, aad_len, res, res_len, pt2, pt_len);
    CHECK(rc == AIENOS_CRYPTO_OK && memcmp(pt2, pt, pt_len) == 0, "vec %zu open", vi);

    /* In place: seal then open in one buffer. */
    uint8_t *buf = malloc(res_len);
    if (!buf) exit(1);
    memcpy(buf, pt, pt_len);
    rc = aienos_gcmsiv_seal(key, nonce, aad, aad_len, buf, pt_len, buf, res_len);
    CHECK(rc == AIENOS_CRYPTO_OK && memcmp(buf, res, res_len) == 0, "vec %zu in-place seal", vi);
    rc = aienos_gcmsiv_open(key, nonce, aad, aad_len, buf, res_len, buf, pt_len);
    CHECK(rc == AIENOS_CRYPTO_OK && memcmp(buf, pt, pt_len) == 0, "vec %zu in-place open", vi);

    /* Negative: flip one bit in each of tag, ciphertext, AAD, nonce. */
    uint8_t *bad = malloc(res_len);
    if (!bad) exit(1);
    for (size_t bit = 0; bit < 128; bit += 37) {
        memcpy(bad, res, res_len);
        bad[pt_len + bit / 8] ^= (uint8_t)(1u << (bit % 8));
        expect_reject("tag bit", vi, key, nonce, aad, aad_len, bad, res_len);
    }
    if (pt_len) {
        memcpy(bad, res, res_len);
        bad[pt_len - 1] ^= 0x01;
        expect_reject("ciphertext bit", vi, key, nonce, aad, aad_len, bad, res_len);
        memcpy(bad, res, res_len);
        bad[0] ^= 0x80;
        expect_reject("ciphertext bit 0", vi, key, nonce, aad, aad_len, bad, res_len);
    }
    if (aad_len) {
        aad[aad_len - 1] ^= 0x04;
        expect_reject("aad bit", vi, key, nonce, aad, aad_len, res, res_len);
        aad[aad_len - 1] ^= 0x04;
        expect_reject("aad truncated", vi, key, nonce, aad, aad_len - 1, res, res_len);
    } else {
        uint8_t one = 0;
        expect_reject("aad added", vi, key, nonce, &one, 1, res, res_len);
    }
    nonce[11] ^= 0x01;
    expect_reject("nonce bit", vi, key, nonce, aad, aad_len, res, res_len);
    nonce[11] ^= 0x01;
    key[31] ^= 0x01;
    expect_reject("key bit", vi, key, nonce, aad, aad_len, res, res_len);
    key[31] ^= 0x01;

    /* In-place failed open zeroes the whole buffer region it owns. */
    memcpy(buf, res, res_len);
    buf[pt_len] ^= 0x01;
    rc = aienos_gcmsiv_open(key, nonce, aad, aad_len, buf, res_len, buf, pt_len);
    CHECK(rc == AIENOS_CRYPTO_ERR_AUTH && all_zero(buf, pt_len), "vec %zu in-place failed open", vi);

    free(bad); free(buf); free(pt2); free(ct);
    free(pt); free(aad); free(key); free(nonce); free(res);
}

static void test_gcmsiv(void)
{
    for (size_t i = 0; i < N_RFC_VECS; i++) {
        run_vec(&RFC_VECS[i], i, 1);
        n_gcmsiv_rfc++;
    }
    for (size_t i = 0; i < sizeof RUST_VECS / sizeof RUST_VECS[0]; i++) {
        run_vec(&RUST_VECS[i], 100 + i, 0);
        n_rust++;
    }
    /* aes_gcm_siv.rs public_derived_keys test: derive is deterministic. */
    uint8_t key[32], nonce[12], a1[16], e1[32], a2[16], e2[32];
    memset(key, 0x31, 32);
    memset(nonce, 0x72, 12);
    aienos_gcmsiv_derive_keys(key, nonce, a1, e1);
    aienos_gcmsiv_derive_keys(key, nonce, a2, e2);
    CHECK(memcmp(a1, a2, 16) == 0 && memcmp(e1, e2, 32) == 0, "derive deterministic");
    n_rust++;
}

static void test_lengths(void)
{
    uint8_t key[32] = {1}, nonce[12] = {3}, small[64], in[32] = {0};
    int rc;

    /* out_len mismatch, short input, NULL with nonzero length. */
    memset(small, 0xa5, sizeof small);
    rc = aienos_gcmsiv_seal(key, nonce, NULL, 0, in, 8, small, 23);
    CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH && all_byte(small, sizeof small, 0xa5), "seal out_len short");
    rc = aienos_gcmsiv_seal(key, nonce, NULL, 0, in, 8, small, 25);
    CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH && all_byte(small, sizeof small, 0xa5), "seal out_len long");
    rc = aienos_gcmsiv_seal(key, nonce, NULL, 5, in, 8, small, 24);
    CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH, "seal NULL aad");
    rc = aienos_gcmsiv_seal(key, nonce, NULL, 0, NULL, 8, small, 24);
    CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH, "seal NULL pt");
    rc = aienos_gcmsiv_open(key, nonce, NULL, 0, in, 15, small, 0);
    CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH, "open in_len < 16");
    rc = aienos_gcmsiv_open(key, nonce, NULL, 0, in, 32, small, 15);
    CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH && all_byte(small, sizeof small, 0xa5), "open out_len mismatch");
    rc = aienos_gcmsiv_open(key, nonce, NULL, 0, in, 32, NULL, 16);
    CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH, "open NULL out");
    n_neg += 7;

    /* RFC 8452 limits: lengths are rejected before any byte is touched, so
     * a small real buffer with an oversize declared length is safe here. */
    if (sizeof(size_t) > 4) {
        size_t over_p = (size_t)(AIENOS_GCMSIV_MAX_PT_LEN + 1);
        size_t over_a = (size_t)(AIENOS_GCMSIV_MAX_AAD_LEN + 1);
        size_t over_c = (size_t)(AIENOS_GCMSIV_MAX_CT_LEN + 1);
        rc = aienos_gcmsiv_seal(key, nonce, NULL, 0, in, over_p, small, over_p + 16);
        CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH && all_byte(small, sizeof small, 0xa5), "seal pt > 2^36");
        rc = aienos_gcmsiv_seal(key, nonce, in, over_a, in, 8, small, 24);
        CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH && all_byte(small, sizeof small, 0xa5), "seal aad > 2^36");
        rc = aienos_gcmsiv_open(key, nonce, NULL, 0, in, over_c, small, over_c - 16);
        CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH && all_byte(small, sizeof small, 0xa5), "open ct > 2^36+16");
        rc = aienos_gcmsiv_open(key, nonce, in, over_a, in, 32, small, 16);
        CHECK(rc == AIENOS_CRYPTO_ERR_LENGTH && all_byte(small, sizeof small, 0xa5), "open aad > 2^36");
        n_neg += 4;
    }

    /* Constant-time compare semantics. */
    uint8_t x[16] = {0}, y[16] = {0};
    CHECK(aienos_ct_equal(x, y, 16) == 1, "ct_equal equal");
    for (int i = 0; i < 128; i++) {
        y[i / 8] ^= (uint8_t)(1u << (i % 8));
        CHECK(aienos_ct_equal(x, y, 16) == 0, "ct_equal bit %d", i);
        y[i / 8] ^= (uint8_t)(1u << (i % 8));
    }
    CHECK(aienos_ct_equal(x, y, 0) == 1, "ct_equal empty");
}

/* ---------------- SHA-256 / HMAC ---------------- */

static void test_sha_hmac(void)
{
    uint8_t d[32], e[32];
    sha256_hash((const uint8_t *)"", 0, d);
    unhex_fixed("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", e, 32);
    CHECK(memcmp(d, e, 32) == 0, "sha256 empty");
    sha256_hash((const uint8_t *)"abc", 3, d);
    unhex_fixed("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", e, 32);
    CHECK(memcmp(d, e, 32) == 0, "sha256 abc");
    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256_hash((const uint8_t *)m448, strlen(m448), d);
    unhex_fixed("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", e, 32);
    CHECK(memcmp(d, e, 32) == 0, "sha256 448-bit");
    n_sha += 3;
    n_rust += 2;

    uint8_t key[32] = {0};
    memset(key, 0x0b, 20);
    aienos_hmac_sha256(key, (const uint8_t *)"Hi There", 8, d);
    unhex_fixed("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", e, 32);
    CHECK(memcmp(d, e, 32) == 0, "hmac RFC 4231 case 1");
    aienos_hmac_sha256_ctx c;
    aienos_hmac_sha256_init(&c, key);
    aienos_hmac_sha256_update(&c, (const uint8_t *)"Hi ", 3);
    aienos_hmac_sha256_update(&c, (const uint8_t *)"There", 5);
    aienos_hmac_sha256_final(&c, d);
    CHECK(memcmp(d, e, 32) == 0, "hmac case 1 in parts (sha256.rs test)");
    CHECK(all_zero((const uint8_t *)&c, sizeof c), "hmac final wipes ctx");
    memset(key, 0, 32);
    memcpy(key, "Jefe", 4);
    const char *m2 = "what do ya want for nothing?";
    aienos_hmac_sha256(key, (const uint8_t *)m2, strlen(m2), d);
    unhex_fixed("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", e, 32);
    CHECK(memcmp(d, e, 32) == 0, "hmac RFC 4231 case 2");
    n_sha += 2;
    n_rust++;
}

int main(void)
{
    test_aes();
    test_polyval();
    test_gcmsiv();
    test_lengths();
    test_sha_hmac();

    printf("vectors: AES/FIPS-197 %d, POLYVAL RFC 8452 %d, GCM-SIV RFC 8452 C.2+C.3 %d, "
           "aienos-crypto crate tests %d, SHA-256/HMAC %d, negative cases %d\n",
           n_aes, n_polyval, n_gcmsiv_rfc, n_rust, n_sha, n_neg);
    printf("checks: %d, failures: %d\n", g_checks, g_fail);
    if (g_fail == 0 && n_gcmsiv_rfc >= 26) {
        printf("AIENOS_CRYPTO_NATIVE: PASS\n");
        return 0;
    }
    printf("AIENOS_CRYPTO_NATIVE: FAIL\n");
    return 1;
}
