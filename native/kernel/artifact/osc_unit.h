/* osc_unit.h -- admission of OSC unit containers (OSCUNIT, container v1).
 *
 * Contract: aien-dev/aien-protocols PR #17, specs/osc-unit-artifact/
 * OSC_UNIT_ARTIFACT.md (section numbers below refer to it). This is a
 * different format from Binary Artifact v0 (ck_artifact.h, ADR 0014); it
 * reuses the in-tree SHA-256 (argus/sha256.c) and Ed25519 verify
 * (sig/ed25519.c) and adds no crypto of its own.
 *
 * osc_unit_admit is a pure function of (bytes, policy): no allocation, no
 * global state, no I/O, no unit code ever runs. Every offset and length is
 * checked with 64-bit arithmetic on 32-bit fields before a byte it names is
 * read. It returns 0 (accepted, *out filled) or the FIRST refusal code of the
 * fixed check order of section 8.2. Admission is not launch: nothing here
 * maps or runs code, and OWNER anchors are not provisioned until TRUST-1.
 */
#ifndef AIENOS_CK_OSC_UNIT_H
#define AIENOS_CK_OSC_UNIT_H
#include <stddef.h>
#include <stdint.h>

#define OSC_MAX_FUNCS 32u
#define OSC_MAX_CAPS 16u
#define OSC_UNIT_MAX_BYTES 2097152u

/* Section 8.3 refusal codes (v1). 0 is "accepted". */
enum osc_code {
    OSC_OK = 0,
    OSC_TRUNCATED = 1, OSC_BAD_MAGIC = 2, OSC_CONTAINER_VERSION = 3, OSC_HEADER_FIELD = 4,
    OSC_UNIT_FORMAT = 5, OSC_ABI_VERSION = 6, OSC_UNKNOWN_FLAGS = 7, OSC_TRAILING_BYTES = 8,
    OSC_TOTAL_LENGTH = 9, OSC_SECTION_TABLE = 10, OSC_SECTION_BOUNDS = 11, OSC_SECTION_OVERLAP = 12,
    OSC_SECTION_LAYOUT = 13, OSC_LIMIT_EXCEEDED = 14, OSC_IR_HASH_MISMATCH = 15,
    OSC_CODE_HASH_MISMATCH = 16, OSC_ENTRY_HASH_MISMATCH = 17, OSC_CAPS_HASH_MISMATCH = 18,
    OSC_IR_MALFORMED = 19, OSC_ENTRY_TABLE = 20, OSC_CAPS_TABLE = 21, OSC_SIGNER_CLASS = 22,
    OSC_SIGNATURE_ALGORITHM = 23, OSC_TEST_SIGNER_IN_RELEASE = 24, OSC_UNTRUSTED_SIGNER = 25,
    OSC_BAD_SIGNATURE = 26, OSC_CAP_DOMAIN_UNSUPPORTED = 27, OSC_CAP_GEN_NOT_REPRESENTABLE = 28,
    OSC_CAP_GENERATION_STALE = 29, OSC_RESOURCE_UNAVAILABLE = 30, OSC_ENTRY_NAME = 31,
    OSC_ENTRY_NAME_HASH = 32, OSC_ENTRY_NAME_DUPLICATE = 33, OSC_CODE_INSTRUCTION = 34,
    OSC_LAUNCH_BAD_ENTRY = 40, OSC_LAUNCH_ARG_SHAPE = 41
};

/* Stable spec name of a code ("?" for a number the spec does not define). */
const char *osc_code_name(unsigned code);

enum { OSC_SIGNER_TEST = 1, OSC_SIGNER_OWNER = 2 };

struct osc_entry {
    uint16_t fn_index;
    uint8_t nregs, ret_kind;
    uint8_t reg_kind[6];
    uint32_t code_offset;
    uint8_t name_hash[16];
    uint8_t name_len;
    char name[64]; /* NUL terminated copy of the name */
};

struct osc_cap {
    uint16_t resource_kind; /* 2 channel, 3 object */
    uint32_t resource_id, rights, bounds_kind, max_operations;
    uint64_t max_bytes, bounds_offset, bounds_length;
    uint16_t domain; /* 1 kernel IPC table (32-bit generation), 2 hosted authority */
    uint64_t required_generation;
};

struct osc_accept {
    uint8_t unit_digest[32]; /* UnitDigest, section 5.1: what execution and authorization bind to */
    uint8_t ir_sha256[32];   /* program identity, display only (section 5.2) */
    uint8_t code_sha256[32];
    uint8_t signer_fp[32];
    uint16_t unit_format, signer_class, function_count, pool_slots, cap_count;
    uint32_t max_stack_bytes;
    uint64_t cpu_ticks;
    uint32_t ir_off, ir_len, code_off, code_len; /* into the admitted bytes */
    struct osc_entry entry[OSC_MAX_FUNCS];
    struct osc_cap cap[OSC_MAX_CAPS];
};

/* Loader inputs (section 8.1): local, never from the container. */
struct osc_policy {
    int release;                          /* 1 release build (TEST signers refused), 0 qualification */
    const uint8_t (*test_anchors)[32];    /* raw Ed25519 public keys, class TEST */
    unsigned n_test;
    const uint8_t (*owner_anchors)[32];   /* class OWNER; empty until TRUST-1 provisions it */
    unsigned n_owner;
    uint32_t unit_formats;                /* bit v set: unit_format_version v supported */
    uint32_t abi_versions;                /* bit v set: runtime_abi_version v provided */
    uint32_t cap_domains;                 /* bit d set: capability domain d provided */
    /* Loader state for step 15(c). Returns 0 and the resource's current generation, or nonzero
     * when the loader has no such resource (then a pinned request is STALE). NULL: the loader
     * assumes pinned generations match (host conformance profile only; the kernel passes a
     * callback). */
    int (*gen_lookup)(void *ctx, unsigned domain, unsigned kind, uint32_t id, uint64_t *current);
    /* Step 16: nonzero refuses with RESOURCE_UNAVAILABLE. NULL: reservation succeeds. */
    int (*reserve)(void *ctx, const struct osc_accept *a);
    void *ctx;
};

/* 0 accepted (*out filled), else the first refusal code. out may be NULL only if the caller
 * wants the verdict alone; it is written only on acceptance. */
unsigned osc_unit_admit(const uint8_t *f, size_t len, const struct osc_policy *pol, struct osc_accept *out);

/* Section 6.1.1: exact, case-sensitive, equal-length name match; the hash is never consulted.
 * Returns the fn_index, or -1 (the caller reports LAUNCH_BAD_ENTRY, 40). */
int osc_unit_lookup(const struct osc_accept *a, const char *name, size_t name_len);

/* Section 8.4 on one word: nonzero if the word is in the OSC-emitted A64 subset (class-mask
 * match plus the decoder round trip; brk only with immediate 1..14). Exposed for tests. */
int osc_a64_word_allowed(uint32_t w);

/* Conformance profile of section 8.1 for unit format 1..5, ABI 1. */
#define OSC_PROFILE_UNIT_FORMATS 0x3Eu /* bits 1..5 */
#define OSC_PROFILE_ABI 0x2u           /* bit 1 */

#endif
