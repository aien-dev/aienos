/* ck_artifact.h -- SEED-0B sealed artifact format, admission policy and
 * admission receipts in C (port of crates/aienos-artifact: format.rs,
 * capability.rs, resource.rs, verify.rs, admission.rs, receipt.rs and the
 * boot policy of aienos-kernel artifact_loader.rs). Pure code: no kernel
 * state, builds freestanding (kernel) and hosted (host tests, tool).
 * Error codes, stage codes and byte layouts are the Rust ones (ADR 0014). */
#ifndef AIENOS_CK_ARTIFACT_H
#define AIENOS_CK_ARTIFACT_H

#include <stddef.h>
#include <stdint.h>

/* ---- error codes (ArtifactError, receipt reason codes 1..20) ---- */
enum {
    CKA_OK = 0,
    CKA_BAD_MAGIC = 1,
    CKA_UNSUPPORTED_VERSION = 2,
    CKA_WRONG_TARGET = 3,
    CKA_WRONG_ABI = 4,
    CKA_LENGTH_OVERFLOW = 5,
    CKA_TRUNCATED = 6,
    CKA_WRONG_LENGTH = 7,
    CKA_RESERVED_NONZERO = 8,
    CKA_UNSUPPORTED_FLAGS = 9,
    CKA_SECTION_OVERLAP = 10,
    CKA_BAD_SECTION = 11,
    CKA_BAD_ENTRY = 12,
    CKA_MALFORMED_CAP = 13,
    CKA_RESOURCE_LIMIT = 14,
    CKA_BAD_SIG_FORMAT = 15,
    CKA_DIGEST_MISMATCH = 16,
    CKA_UNTRUSTED_SIGNER = 17,
    CKA_BAD_SIGNATURE = 18,
    CKA_RIGHTS_ESCALATION = 19,
    CKA_MALFORMED_RECEIPT = 20,
};
/* LoadError reason codes (receipt reason 0x101..0x10a). */
enum {
    CKL_NO_FRAMES = 0x101,
    CKL_STAGING_TOO_LARGE = 0x102,
    CKL_MAPPING = 0x103,
    CKL_MAPPED_DIGEST = 0x104,
    CKL_WX_AUDIT = 0x105,
    CKL_CAP_INSTALL = 0x106,
    CKL_SCHEDULER_FULL = 0x107,
    CKL_EXECUTED_DIGEST = 0x108,
    CKL_RECLAIM = 0x109,
    CKL_FIRMWARE_READ = 0x10a,
};
/* Rejection stages (receipt stage 1..9). */
enum {
    CKS_RECEIVED = 1, CKS_STAGED, CKS_VERIFIED, CKS_AUTHORIZED, CKS_RESERVED,
    CKS_MAPPED, CKS_HASHED, CKS_SEALED, CKS_CAPS,
};
const char *cka_error_name(unsigned code); /* Rust Debug name, "?" if unknown */
const char *cka_stage_name(unsigned stage);

#define CKA_HEADER_SIZE 128u
#define CKA_SECTION_SIZE 32u
#define CKA_CAP_SIZE 48u
#define CKA_ENV_SIZE 48u
#define CKA_SIG_SIZE 100u
#define CKA_MAX_CAPS 16u
#define CKA_MAX_ARTIFACT (16u << 20)
#define CKA_MAX_PAYLOAD (8u << 20)
#define CKA_CAPS_OFFSET 192u
#define CKA_TARGET_AARCH64_LE 1u
#define CKA_ABI_V1 1u
#define CKA_KIND_CHANNEL 2u
#define CKA_KIND_OBJECT 3u
#define CKA_VALID_RIGHTS 0x3fu

struct cka_cap {
    uint16_t kind;
    uint32_t id, rights, bounds, max_ops;
    uint64_t max_bytes, off, len;
};
struct cka_env {
    uint32_t code_pages, data_pages, stack_pages;
    uint16_t max_caps;
    uint32_t ipc_msgs, ipc_bytes;
    uint64_t cpu, elapsed;
    uint32_t syscalls;
};
struct cka_section {
    uint16_t kind, perms;
    uint32_t rel, flen, mlen, align;
};
struct cka_parsed {
    uint16_t target, abi, ncaps, sig_alg;
    uint32_t total, entry, res_off, payload_off, payload_len, sig_off;
    struct cka_section code, data;
    struct cka_cap caps[CKA_MAX_CAPS];
    struct cka_env env;
    uint8_t fp[32];
    uint8_t sig[64];
};
struct cka_ident {
    uint8_t id[32], payload[32], requested[32], resources[32];
};

void cka_cap_encode(const struct cka_cap *c, uint8_t out[CKA_CAP_SIZE]);
int cka_cap_decode(const uint8_t b[CKA_CAP_SIZE], struct cka_cap *c);
int cka_cap_validate(const struct cka_cap *c);
int cka_cap_is_attenuation_of(const struct cka_cap *g, const struct cka_cap *r);
void cka_env_encode(const struct cka_env *e, uint8_t out[CKA_ENV_SIZE]);
int cka_env_validate(const struct cka_env *e, unsigned ncaps);

/* format.rs parse; parse_and_identify adds the 16 MiB bound and the digests. */
int cka_parse(const uint8_t *b, size_t len, struct cka_parsed *p);
int cka_identify(const uint8_t *b, size_t len, struct cka_parsed *p, struct cka_ident *id);
/* verify.rs: anchors are TEST/public keys (32 bytes each). Fills signer_fp. */
int cka_verify(const uint8_t *b, size_t len, const uint8_t (*anchors)[32], unsigned nanchors,
               struct cka_parsed *p, struct cka_ident *id, uint8_t signer_fp[32]);
void cka_signature_message(const uint8_t id[32], uint8_t *msg, size_t *len); /* msg >= 64 */

/* ---- digests ---- */
void cka_digest_domain(const char *domain, size_t dlen, const uint8_t *b, size_t len,
                       uint8_t out[32]);
void cka_grants_digest(const struct cka_cap *g, unsigned n, uint8_t out[32]);

/* ---- admission policy (admission.rs) ---- */
#define CKA_POLICY_MAX_RULES 4u
#define CKA_POLICY_MAX_SIGNERS 4u
struct cka_limits {
    uint32_t code_pages, data_pages, stack_pages, max_caps, ipc_msgs, ipc_bytes;
    uint64_t cpu, elapsed;
    uint32_t syscalls;
};
struct cka_policy {
    struct cka_limits limits;
    unsigned nrules, nsigners;
    struct cka_cap rules[CKA_POLICY_MAX_RULES];
    uint8_t signers[CKA_POLICY_MAX_SIGNERS][32];
};
/* The boot policy; with a TEST anchor the signer list is SHA256(anchor). */
void cka_boot_policy(struct cka_policy *pol, const uint8_t (*anchors)[32], unsigned nanchors);
size_t cka_policy_canonical(const struct cka_policy *pol, uint8_t *out, size_t cap);
void cka_policy_digest(const struct cka_policy *pol, uint8_t out[32]);
struct cka_decision {
    unsigned ngrants;
    struct cka_cap grants[CKA_MAX_CAPS];
    uint8_t granted_digest[32];
};
/* evaluate(): avail = available resources of the machine. */
int cka_evaluate(const struct cka_policy *pol, const struct cka_parsed *p,
                 const uint8_t signer_fp[32], const struct cka_limits *avail,
                 struct cka_decision *d);

/* ---- admission receipt (receipt.rs) ---- */
#define CKA_RECEIPT_SIZE 512u
#define CKA_RECEIPT_SIGNED_LEN 400u
enum { CKR_ADMITTED = 1, CKR_REJECTED = 2 };
enum { CKR_TIER_SEED0B_QEMU = 1 };
enum {
    CKR_NOT_RUN = 0, CKR_EXITED, CKR_TIMEOUT, CKR_FAULT, CKR_BAD_SYSCALL, CKR_RESOURCE_OVERRUN,
};
#define CKR_F_READ_OK 0x01u
#define CKR_F_WRITE_DENIED 0x02u
#define CKR_F_RECLAIMED 0x04u
#define CKR_F_CANARY 0x08u
#define CKR_F_FORGED_DENIED 0x10u
#define CKR_F_MAPPED 0x20u
#define CKR_F_EXECUTED 0x40u
#define CKR_F_WX 0x80u
struct cka_receipt {
    uint32_t flags;
    uint16_t decision, tier;
    uint64_t seq;
    uint8_t nonce[16];
    uint64_t time;
    uint32_t status;
    int32_t exit;
    uint32_t result_flags;
    uint16_t stage, reason;
    uint32_t syscalls, reads, denials, frames;
    uint8_t id[32], payload[32], signer[32], policy[32], requested[32], granted[32],
        resources[32], verifier[32], machine[32];
    uint64_t generation, context;
    uint16_t sig_alg;
    uint8_t fp[32], sig[64];
};
const char *cka_status_name(uint32_t status);
void cka_receipt_nonce(const uint8_t verifier[32], uint64_t seq, uint8_t out[16]);
void cka_receipt_encode(const struct cka_receipt *r, uint8_t out[CKA_RECEIPT_SIZE]);
int cka_receipt_decode(const uint8_t b[CKA_RECEIPT_SIZE], struct cka_receipt *r);
int cka_receipt_validate(const struct cka_receipt *r);
void cka_receipt_digest(const uint8_t b[CKA_RECEIPT_SIZE], uint8_t out[32]);
int cka_receipt_is_signed(const uint8_t b[CKA_RECEIPT_SIZE]);
/* Signs an unsigned record in place with an Ed25519 seed (TEST key only). */
int cka_receipt_sign(uint8_t b[CKA_RECEIPT_SIZE], const uint8_t seed[32]);
int cka_receipt_verify(const uint8_t b[CKA_RECEIPT_SIZE], const uint8_t (*anchors)[32],
                       unsigned nanchors);
/* Verifier identity of a build (commit = 40 lowercase hex, else "unpinned-build"). */
void cka_verifier_identity(const char *commit, uint8_t feature, uint8_t out[32]);

/* ---- TEST-ONLY qualification keys (RFC 8032 test vectors 1 and 2) ---- */
extern const uint8_t cka_test1_pk[32];
extern const uint8_t cka_test2_pk[32];

/* little-endian field helpers */
static inline uint16_t cka_rd16(const uint8_t *b) { return (uint16_t)(b[0] | b[1] << 8); }
static inline uint32_t cka_rd32(const uint8_t *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}
static inline uint64_t cka_rd64(const uint8_t *b)
{
    return (uint64_t)cka_rd32(b) | (uint64_t)cka_rd32(b + 4) << 32;
}
static inline void cka_wr16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); }
static inline void cka_wr32(uint8_t *b, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}
static inline void cka_wr64(uint8_t *b, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}

#endif
