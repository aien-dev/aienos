/* slot_format.h -- AIENOS native image slots: the on-disk formats a loader
 * reads to choose which native image boots, and a kernel writes to install,
 * update and roll back WITHOUT Linux (native v1 plan P11, gate N7).
 *
 * STATUS (docs/NATIVE_IMAGE_SLOTS.md): format v1. Read by SLOTLDR.EFI
 * (native/boot/slot_loader.c, P11 cut 2a, owner decision 2026-10-12), a
 * separate chain loader in FRONT of the unchanged stub + kernel image
 * (native/boot/efi_main.c is not modified). The loader writes the control
 * record only to consume a candidate try. The service kernel
 * (native/kernel/svc/slot_service.c, cut 2b) promotes a healthy candidate and
 * abandons an exhausted or invalid one over its own NVMe path, told which slot
 * it is by the loader's boot record (below). Staging is cut 3. This header,
 * slot_select.c and the host tool native/kernel/tools/ck_slot_tool.c pin
 * the format and the decision rules (mutation-tested in make slot-test).
 *
 * Accepted design this follows: ADR 0006 (transactional A/B slots, health
 * milestones before promotion) and TRUST-1 Q19 (A = known-good, B =
 * candidate as ROLES; manifest fields; "write inactive, verify, boot once,
 * health, promote, retain rollback; bounded attempts, no boot loop, last-good
 * never erased by a candidate; dual-invalid = recovery").
 *
 * Where it lives: its own GPT partition with the type GUID below, NOT inside
 * the AIENOS Store partition (dev/disk_layout.h is untouched). In 4096-byte
 * units from the partition's first LBA:
 *
 *   unit 0..3        control record, torn-write safe (native/store/torn_slot.c
 *                    protocol: body A, commit A, body B, commit B)
 *   unit 4 ..        slot A: manifest unit, then the image bytes
 *   unit 4+CAP ..    slot B: manifest unit, then the image bytes
 *   CAP = (U - 4) / 2 units, U = whole units in the partition. The image of
 *   a slot occupies at most (CAP - 1) * 4096 bytes. Equal halves, so the
 *   loader needs no stored geometry: the partition size is the geometry.
 *
 * All integers little endian. Reserved bytes are zero and are checked.
 *
 * The MANIFEST (one unit) is signed by the Owner Root Ed25519 key (TRUST-1
 * Q13; file format tools/ck_owner_gen.c "owner_root_ed25519 <64 hex>"): the
 * first CK_SLOT_TBS_BYTES bytes are the signed message. The signature covers
 * the image through image_sha512; the loader recomputes SHA-512 over exactly
 * image_len bytes of the slot. The kernel is linked into the image
 * (payload_kind 1 = the BOOTAA64.EFI PE built by native/kernel), so
 * kernel_sha512 MUST equal image_sha512 in v1; the field exists so a future
 * split payload keeps the layout.
 *
 * The CONTROL record (one unit, inside the torn-slot region) is NOT signed:
 * it is operational state written by the kernel (stage, promote, abandon) and
 * by the loader for exactly one purpose, decrementing a candidate's remaining
 * tries before it boots that candidate, which is what bounds boot attempts
 * even if the candidate hangs. Its integrity comes from the torn-slot commit
 * digests. A missing or corrupt control record never blocks booting a valid
 * image: the loader then boots the highest valid generation.
 *
 * generation_floor is the monotonic security floor (P11: "reconcile rollback
 * policy with monotonic security floors"): a manifest whose generation is
 * below the floor is never booted, even if validly signed. Promotion raises
 * the floor to the promoted image's policy_generation; it never lowers it. */
#ifndef AIENOS_CK_SLOT_FORMAT_H
#define AIENOS_CK_SLOT_FORMAT_H
#include <stdint.h>
#include <stddef.h>

#define CK_SLOT_UNIT 4096u
#define CK_SLOT_CONTROL_UNITS 4u          /* torn-slot region (TS_UNITS) */
#define CK_SLOT_FIRST_UNIT 4u             /* slot A starts here */
#define CK_SLOT_COUNT 2u
#define CK_SLOT_NONE 0xFFu
#define CK_SLOT_MAX_TRIES 3u              /* bounded candidate boot attempts */
#define CK_SLOT_MIN_CAP_UNITS 2u          /* manifest + at least one image unit */

/* Geometry from the partition size alone (U = whole 4096-byte units in the
 * partition): CAP = (U - 4) / 2 units per slot; slot s starts at unit
 * 4 + s * CAP (its manifest), its image at the next unit, at most
 * (CAP - 1) * 4096 bytes. Shared by SLOTLDR.EFI and ck_slot_tool. */
static inline uint64_t ck_slot_cap_units(uint64_t part_units)
{
    return part_units < CK_SLOT_FIRST_UNIT ? 0 : (part_units - CK_SLOT_FIRST_UNIT) / CK_SLOT_COUNT;
}
static inline uint64_t ck_slot_manifest_unit(unsigned slot, uint64_t cap_units)
{
    return CK_SLOT_FIRST_UNIT + (uint64_t)slot * cap_units;
}

/* 8B1096CD-7928-4E08-B5E4-C19B6B532760: AIENOS image slots partition type. */
#define CK_SLOT_PART_TYPE_TEXT "8B1096CD-7928-4E08-B5E4-C19B6B532760"
#define CK_SLOT_PART_TYPE_BYTES \
    {0xcd, 0x96, 0x10, 0x8b, 0x28, 0x79, 0x08, 0x4e, 0xb5, 0xe4, 0xc1, 0x9b, 0x6b, 0x53, 0x27, 0x60}

/* ---- manifest ------------------------------------------------------------ */
#define CK_SLOT_MANIFEST_MAGIC "AIENSLT1"
#define CK_SLOT_MANIFEST_VERSION 1u
#define CK_SLOT_PAYLOAD_BOOTAA64 1u       /* stub + kernel in one PE image */
#define CK_SLOT_LOADER_ABI 1u
#define CK_SLOT_KERNEL_ABI 3u             /* CHANDOF3, BOOT_HANDOFF_CONTRACT.md */
#define CK_SLOT_TBS_BYTES 448u            /* signed message = bytes [0, 448) */
#define CK_SLOT_SIG_OFFSET 448u
#define CK_SLOT_COMMIT_CHARS 40u
#define CK_SLOT_PROVENANCE_CHARS 64u

struct ck_slot_manifest {
    uint8_t magic[8];                 /*   0 "AIENSLT1" */
    uint32_t version;                 /*   8 1 */
    uint32_t payload_kind;            /*  12 1 */
    uint32_t loader_abi;              /*  16 1 */
    uint32_t kernel_abi;              /*  20 3 */
    uint64_t generation;              /*  24 strictly increasing per release */
    uint64_t policy_generation;       /*  32 floor this image raises on promotion (<= generation) */
    uint64_t min_rollback_generation; /*  40 oldest generation this image may be rolled back to (<= generation) */
    uint64_t image_len;               /*  48 bytes of the image, > 0 */
    uint8_t image_sha512[64];         /*  56 */
    uint8_t kernel_sha512[64];        /* 120 == image_sha512 for payload_kind 1 */
    uint8_t signer_id[32];            /* 184 SHA-256 of the signer's Ed25519 public key */
    uint8_t commit[40];               /* 216 lower-case hex of the source commit, no terminator */
    uint8_t provenance[64];           /* 256 printable ASCII, zero padded */
    uint64_t timestamp;               /* 320 unix seconds, > 0 */
    uint32_t flags;                   /* 328 0 */
    uint32_t reserved0;               /* 332 0 */
    uint8_t reserved1[112];           /* 336 zero */
    uint8_t signature[64];            /* 448 Ed25519 over bytes [0, 448) */
    uint8_t pad[CK_SLOT_UNIT - 512u]; /* 512 zero */
};
_Static_assert(sizeof(struct ck_slot_manifest) == CK_SLOT_UNIT, "ck_slot_manifest size");
_Static_assert(offsetof(struct ck_slot_manifest, image_sha512) == 56, "manifest image_sha512");
_Static_assert(offsetof(struct ck_slot_manifest, signer_id) == 184, "manifest signer_id");
_Static_assert(offsetof(struct ck_slot_manifest, timestamp) == 320, "manifest timestamp");
_Static_assert(offsetof(struct ck_slot_manifest, signature) == CK_SLOT_SIG_OFFSET, "manifest signature");

/* ---- control record ------------------------------------------------------ */
#define CK_SLOT_CONTROL_MAGIC "AIENSLC1"
#define CK_SLOT_CONTROL_VERSION 1u
#define CK_SLOT_CTL_FLAG_CANDIDATE_FAILED 1u /* the last candidate was abandoned */

struct ck_slot_control {
    uint8_t magic[8];                /*  0 "AIENSLC1" */
    uint32_t version;                /*  8 1 */
    uint8_t active_slot;             /* 12 0 or 1: the known-good slot */
    uint8_t candidate_slot;          /* 13 0, 1 or CK_SLOT_NONE */
    uint8_t tries_remaining;         /* 14 0..CK_SLOT_MAX_TRIES; 0 when no candidate */
    uint8_t flags;                   /* 15 */
    uint64_t generation_floor;       /* 16 monotonic security floor */
    uint64_t last_good_generation;   /* 24 generation of the active slot when promoted (0 = unknown) */
    uint8_t reserved[CK_SLOT_UNIT - 32u]; /* 32 zero */
};
_Static_assert(sizeof(struct ck_slot_control) == CK_SLOT_UNIT, "ck_slot_control size");

/* ---- decisions ----------------------------------------------------------- */
/* What the verifier learned about one slot (slot_select.c ck_slot_verify). */
struct ck_slot_eval {
    int valid;                       /* 1 = manifest well formed, signed by a trusted key, image digest matches */
    uint64_t generation;             /* from the manifest when valid */
    uint64_t policy_generation;      /* from the manifest when valid */
    const char *why;                 /* refusal reason when !valid (static string) */
};

enum ck_slot_reason {
    CK_SLOT_R_NONE = 0,
    CK_SLOT_R_CANDIDATE_TRY,          /* booting the candidate; tries decremented (loader must persist ctl_out first) */
    CK_SLOT_R_ACTIVE,                 /* booting the active slot */
    CK_SLOT_R_CANDIDATE_EXHAUSTED,    /* candidate had no tries left: booting active */
    CK_SLOT_R_CANDIDATE_INVALID,      /* candidate failed verification: booting active */
    CK_SLOT_R_ACTIVE_INVALID_FALLBACK,/* active failed verification: booting the other valid slot */
    CK_SLOT_R_NO_CONTROL,             /* no usable control record: booting the highest valid generation */
    CK_SLOT_R_RECOVERY_REQUIRED,      /* no slot may boot */
};

struct ck_slot_decision {
    int boot_slot;                    /* 0, 1 or -1 (recovery required) */
    enum ck_slot_reason reason;
    int loader_write;                 /* 1 = ctl_out must be committed before booting boot_slot */
    struct ck_slot_control ctl_out;   /* valid when loader_write */
};

/* Structural checks, no I/O, no crypto. 0 = well formed, -1 with *why. */
int ck_slot_manifest_check(const struct ck_slot_manifest *m, const char **why);
int ck_slot_control_check(const struct ck_slot_control *c, const char **why);

/* Full verification of one slot: structure, image_len <= image_cap, SHA-512
 * of the image bytes, signer_id names one of nkeys trusted public keys and
 * the signature verifies under it. Fills *ev. Returns ev->valid. */
int ck_slot_verify(const struct ck_slot_manifest *m, const uint8_t *image, uint64_t image_cap,
                   const uint8_t (*keys)[32], unsigned nkeys, struct ck_slot_eval *ev);

/* The loader's decision. ctl may be NULL (missing or corrupt control record). */
void ck_slot_select(const struct ck_slot_control *ctl, const struct ck_slot_eval ev[CK_SLOT_COUNT],
                    struct ck_slot_decision *d);

/* Kernel-side transitions on a control record (pure; the caller commits).
 * 0 = ok, -1 refused with *why. */
void ck_slot_control_init(struct ck_slot_control *c, unsigned active_slot);
int ck_slot_stage_candidate(struct ck_slot_control *c, unsigned slot, uint64_t generation, const char **why);
int ck_slot_promote(struct ck_slot_control *c, unsigned booted_slot, uint64_t generation,
                    uint64_t policy_generation, const char **why);
int ck_slot_abandon_candidate(struct ck_slot_control *c, const char **why);


/* ---- boot record: what SLOTLDR.EFI hands the kernel (P11 cut 2b) ---------- */
/* The control record alone cannot tell a kernel which slot it is: "candidate
 * on its last try" and "candidate out of tries, active booted" both read
 * tries=0. Before StartImage the loader therefore writes this record into one
 * page it allocates with the memory type below, a UEFI OS-loader type (UEFI
 * 2.10 section 7.2 AllocatePages: 0x80000000..0xFFFFFFFF are reserved for OS
 * loaders). That page survives ExitBootServices and appears in the final
 * memory map the unchanged stub already copies into the CHANDOF3 handoff, so
 * neither the stub nor the handoff changes. The kernel's frame allocator only
 * hands out EfiConventionalMemory, so the page is never reused.
 *
 * Trust: the record is written by the loader that verified the image, before
 * ExitBootServices, i.e. inside the same firmware + loader trust boundary as
 * the handoff itself. Its digest catches a torn or stray page, not an
 * attacker inside that boundary. The kernel still cross-checks the slot's
 * manifest on disk (generation, image_sha512) before it writes anything. */
#define CK_SLOT_BOOT_MEMTYPE 0x80000A1Eu  /* OS-loader memory type of the boot record page */
#define CK_SLOT_BOOT_MAGIC "AIENSLB1"
#define CK_SLOT_BOOT_VERSION 1u
#define CK_SLOT_BOOT_BYTES 256u
#define CK_SLOT_BOOT_SIGNED 224u          /* digest = SHA-256 over bytes [0, 224) */

struct ck_slot_boot_record {
    uint8_t magic[8];                 /*   0 "AIENSLB1" */
    uint32_t version;                 /*   8 1 */
    uint8_t boot_slot;                /*  12 0 or 1: the slot whose image the loader started */
    uint8_t reason;                   /*  13 enum ck_slot_reason of the loader's decision */
    uint8_t tries;                    /*  14 tries_remaining on disk when the image started */
    uint8_t control_present;          /*  15 1 = a valid control record was read (and committed when asked) */
    uint64_t control_seq;             /*  16 torn-slot sequence of that record (0 without one) */
    uint64_t generation;              /*  24 manifest generation of the started image */
    uint64_t policy_generation;       /*  32 manifest policy_generation of the started image */
    uint8_t image_sha512[64];         /*  40 manifest image_sha512 of the started image */
    uint8_t loader_commit[40];        /* 104 loader build commit, ASCII, zero padded */
    uint8_t reserved[80];             /* 144 zero */
    uint8_t digest[32];               /* 224 SHA-256 over bytes [0, 224) */
};
_Static_assert(sizeof(struct ck_slot_boot_record) == CK_SLOT_BOOT_BYTES, "ck_slot_boot_record size");
_Static_assert(offsetof(struct ck_slot_boot_record, digest) == CK_SLOT_BOOT_SIGNED, "boot record digest");

/* Fill the digest (loader side). */
void ck_slot_boot_seal(struct ck_slot_boot_record *b);
/* Structure + digest + ranges (kernel side). 0 = ok, -1 with *why. */
int ck_slot_boot_check(const struct ck_slot_boot_record *b, const char **why);

/* ---- what the kernel does with its slot (P11 cut 2b) ---------------------- */
/* Pure decision, shared by the kernel (svc/slot_service.c) and the host
 * self-test. Inputs: the boot record (valid), the control record recovered
 * from disk (NULL when absent or corrupt), the started slot's manifest from
 * disk (structurally checked by the caller, NULL when unreadable) and whether
 * the service reached its health milestone. Rules, in order:
 *   - no control record, or the on-disk manifest of the started slot does
 *     not match the boot record (generation, image_sha512): REFUSE, write
 *     nothing (the disk changed under us or the record lies);
 *   - reason CANDIDATE_TRY and control still names that slot as candidate:
 *     healthy -> PROMOTE (ck_slot_promote with the manifest's generation and
 *     policy_generation); not healthy -> WAIT (nothing written; tries keep
 *     counting down in the loader);
 *   - reason CANDIDATE_EXHAUSTED or CANDIDATE_INVALID, control has a
 *     candidate and its active slot is the started slot -> ABANDON
 *     (ck_slot_abandon_candidate: candidate cleared, FAILED flag set; the
 *     active slot stays). This is slot_select.c rule 3's "abandoned by the
 *     kernel later". Not gated on health: the loader already decided.
 *   - anything else -> NONE.
 * *out holds the record to commit for PROMOTE and ABANDON. */
enum ck_slot_action {
    CK_SLOT_A_NONE = 0,
    CK_SLOT_A_PROMOTE,
    CK_SLOT_A_ABANDON,
    CK_SLOT_A_WAIT,
    CK_SLOT_A_REFUSE,
};
enum ck_slot_action ck_slot_kernel_action(const struct ck_slot_boot_record *b, const struct ck_slot_control *ctl,
                                          const struct ck_slot_manifest *booted, int healthy,
                                          struct ck_slot_control *out, const char **why);
const char *ck_slot_action_text(enum ck_slot_action a);

/* Text for a reason code (static string). */
const char *ck_slot_reason_text(enum ck_slot_reason r);

#endif /* AIENOS_CK_SLOT_FORMAT_H */
