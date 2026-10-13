/* store_boot.h -- the Store boot stage: mount the sealed C Store
 * (native/store store_sealed, M5 keyed, torn_slot anchor) on the boot disk,
 * read the boot record, bump boot_count, commit, flush.
 *
 * Proof separation (AGENTS.md section 1). A refusal names which proof
 * failed and never reformats a non-blank disk:
 *   structural  unkeyed Store::open (st_open) refused the region
 *   keyed       M5 identity/records/envelopes refused under the given keys
 *   rollback    the anti-rollback anchor refused the Store's generation
 *   io          the disk failed
 * Only an all-zero anchor + Store head counts as blank and is formatted.
 *
 * KEYS. Default (QEMU) build: ck_store_test_keys gives TEST identity
 * (M5_ID_TEST) keys derived from a public label. They protect nothing and
 * every line printed with them says TEST.
 * Hardware staging build (CK_HARDWARE_STAGING; built with CK_OWNER_PUBKEYS=
 * and CK_MACHINE_ID= files, see README "Owner provisioning"): the TEST keys
 * and TEST uuid are not compiled; the store uuid comes from the generated
 * owner provisioning header; keys come from ck_store_production_keys, the
 * BLOCKED_OPERATOR seam (K_vol is secret and needs the TRUST-1 key
 * ceremony), so the stage refuses before reading the disk. store_boot_run
 * refuses TEST-identity keys in that build before any disk access, so it
 * never formats a blank disk with them.
 *
 * RECOVERY KEYSLOT UNLOCK (P04 cut 1, ADR 0017 section 2.4 Slot 1).
 * ck_store_unlock_boot takes the operator's 32-byte raw recovery secret and
 * never any key material from the image: on a blank disk it draws K_vol,
 * salt and nonce from the kernel entropy service (RNDR; refused when RNDR
 * is), wraps K_vol into a Recovery_RawSecret descriptor (slot_id 1, HKDF
 * KEK) and commits the KeySlotManifest (kind 21, plaintext, bound by the
 * sealed transaction record) in the same first transaction as the boot
 * record. On a non-blank disk it reads the manifest before any key exists
 * (ss_keyslot_bootstrap), derives the KEK, unwraps K_vol and opens the Store
 * with PRODUCTION-class keys (owner hierarchy generation = active_key_epoch).
 * A wrong secret is refused by the AES-GCM-SIV tag before the Store is
 * touched. K_vol lives in a stack buffer for the unwrap only and is wiped.
 *
 * SECURITY MANIFEST (P04 cut 2a, ADR 0017 section 2.5). Every boot
 * transaction also commits one SecurityManifest (kind 22, a sealed envelope
 * whose root_mac is under k_root_auth): generation = the generation the
 * transaction creates, security_sequence = previous + 1 (1 at genesis),
 * previous_security_manifest_id = the ObjectId of the manifest it
 * supersedes (zero at genesis), key_epoch = the owner hierarchy generation
 * of the open keys, keyslot_manifest_id = the KeySlotManifest ObjectId (zero
 * for a TEST-key Store, which has none), epoch = generation (the sealed
 * Store's anti-rollback anchor counts Store generations). On every open the
 * newest manifest is read back and must verify under the open keys, name
 * this Store, bind exactly the keyslot the keyed open bound, carry the open
 * keys' epoch, the generation that committed it and a security_sequence
 * equal to the number of manifests on the Store. A Store with history but
 * no manifest, or a manifest failing any check, is refused (CK_SB_E_SECMAN)
 * before the boot record is written and the keys are wiped.
 *
 * KEY ROTATION (P04 cut 2b, ADR 0017 section 2.7 item 1, credential
 * rotation). ck_store_rotate_recovery takes the current and the new raw
 * recovery secret while the production Store is open: the current secret
 * must unwrap K_vol from the bound manifest (proof of possession, nothing is
 * written otherwise), a fresh salt and nonce come from the entropy service,
 * and one transaction commits the next KeySlotManifest of the chain
 * (manifest_sequence + 1, previous_keyslot_manifest_id = the bound manifest,
 * same K_vol and active_key_epoch, the Recovery_RawSecret descriptor
 * re-wrapped under the new KEK) together with a SecurityManifest
 * (security_sequence + 1) that binds the new manifest. The sealed store
 * admits a manifest only as the next link of the chain and binds the newest
 * one, so the next unlock accepts the new secret only: the old descriptor is
 * superseded, its ciphertext stays on the append-only Store (ADR 0017
 * section 2.7 item 2: a K_vol compromise needs migration, not rotation).
 * K_vol lives in a stack buffer for the rewrap only and is wiped.
 * Limits (cut 2b): TPM Slot 0 stays BLOCKED_HARDWARE (slot 0 Empty);
 * active_key_epoch stays 1 (K_vol never changes in place); only the boot
 * and rotation transactions write a SecurityManifest (approve, continuity
 * and journal commits do not advance security_sequence); agent_root_id,
 * continuity_manifest_id and migration_manifest_id stay zero (not yet
 * linked). */
#ifndef AIENOS_CK_STORE_BOOT_H
#define AIENOS_CK_STORE_BOOT_H
#include <stdint.h>
#include "disk.h"
#include "store_sealed.h"

#define CK_BOOT_KIND 0x0B00u   /* application kind of the boot record */
#define CK_BOOT_VERSION 1u
#define CK_BOOT_COMMIT_MAX 64u
#define CK_BOOT_RECORD_LEN 88u /* "AIENBOOT" u32 ver u32 0 u64 boot_count char commit[64] */
#define CK_SECMAN_KIND 22u     /* ADR 0017 section 2.5 SecurityManifest, M5_SECMAN_LEN bytes */

enum { CK_SB_COMMITTED = 0, CK_SB_REFUSED = 1 };

typedef struct {
    int verdict;              /* CK_SB_* */
    int formatted;            /* this run formatted a blank disk */
    int rc;                   /* first failing rc (ST_* / SS_* / disk), 0 if committed */
    const char *proof;        /* "structural" "keyed" "rollback" "io" "geometry" "record" "commit" */
    const char *step;         /* what was being done */
    int rb;                   /* SS_RB_* from the open */
    uint64_t gen_open, gen_commit;
    uint64_t boot_count_prev, boot_count_new;
    char prev_commit[CK_BOOT_COMMIT_MAX + 1];
    uint64_t store_base_lba, store_units, anchor_lba;
    uint8_t identity_class;   /* identity class of the keys given (M5_ID_*) */
    int unlocked_genesis;     /* ck_store_unlock_boot: this run created the keyslot manifest */
    const char *key_source;   /* ck_store_unlock_boot: "recovery-keyslot" */
    uint64_t secman_seq;      /* security_sequence of the SecurityManifest this boot committed */
    uint64_t keyslot_seq;     /* manifest_sequence of the KeySlotManifest bound (unlock) or committed (rotate) */
    int secman_keyslot;       /* 1: it binds the KeySlotManifest ObjectId (production Store) */
    int secman_prev;          /* 1: it links the manifest it supersedes (0 at genesis) */
} ck_store_report;

#define CK_SB_E_TEST_KEYS (-2001)        /* TEST identity keys refused (hardware staging) */
#define CK_SB_E_BLOCKED_OPERATOR (-2002) /* production key source needs the operator */
#define CK_SB_E_NO_KEYSLOT (-2003)       /* non-blank disk carries no KeySlotManifest (not a production Store) */
#define CK_SB_E_SECRET_REJECTED (-2004)  /* recovery secret did not unwrap K_vol (tag failed) */
#define CK_SB_E_ENTROPY (-2005)          /* genesis refused: kernel entropy service refused */
#define CK_SB_E_KEYSLOT_BAD (-2006)      /* manifest decoded but has no usable recovery descriptor / wrong uuid */
#define CK_SB_E_CONTINUITY (-2007)      /* service: continuity refused after the Store opened (lifecycle stays LOCKED) */
#define CK_SB_E_SECMAN (-2008)          /* SecurityManifest missing, malformed, unbound, stale or under other keys */
#define CK_SB_SECRET_LEN 32u

/* TEST keys and store uuid. Public, not secret, never production. Not
 * compiled in a CK_HARDWARE_STAGING build. */
void ck_store_test_keys(ss_keys *k);
extern const uint8_t ck_store_test_uuid[16];

/* Production Store keys. BLOCKED_OPERATOR: always zeroes k and returns
 * CK_SB_E_BLOCKED_OPERATOR until the TRUST-1 ceremony provides a K_vol source
 * (Gate 6 TPM Slot 0 unwrap or Slot 1 recovery KEK). Never falls back. */
int ck_store_production_keys(ss_keys *k);

/* 1 if keys of this identity class may open/format a Store in this build:
 * PRODUCTION always; TEST only when hardware_staging is 0. */
int ck_store_keys_admissible(const ss_keys *k, int hardware_staging);

/* One boot against disk d (the AIENOS partition view of dev/disk_part.h in the
 * kernel, a whole file in host tests; layout of dev/disk_layout.h, relative to d).
 * commit is the image commit string recorded in the new boot record.
 * Prints nothing; ck_stage_store prints. */
int store_boot_run(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                   ck_store_report *r);
/* Same with the build policy explicit (store_boot_run passes 1 in a
 * CK_HARDWARE_STAGING build, else 0); the host test drives both. */
int store_boot_run_policy(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                          int hardware_staging, ck_store_report *r);
/* Recovery keyslot unlock + boot (see the header comment). secret is the
 * operator's raw 32-byte recovery secret. expect_uuid (optional) must equal
 * the manifest's store_uuid and is the uuid of a formatted blank disk; when
 * NULL a blank disk gets a random uuid and any manifest uuid is accepted.
 * hardware_staging as store_boot_run_policy. Prints nothing. */
int ck_store_unlock_boot(const disk_dev *d, const uint8_t secret[CK_SB_SECRET_LEN], const uint8_t *expect_uuid,
                         const char *commit, int hardware_staging, ck_store_report *r);
/* Recovery secret rotation on the open production Store (see the header
 * comment): current must unwrap K_vol from the bound KeySlotManifest, next is
 * the new raw secret. One transaction (next manifest + SecurityManifest) or
 * nothing. Prints nothing. */
int ck_store_rotate_recovery(const disk_dev *d, const uint8_t current[CK_SB_SECRET_LEN],
                             const uint8_t next[CK_SB_SECRET_LEN], ck_store_report *r);
#ifdef CK_PI5_UNLOCK
/* Pi unlock image only. The board glue (core/pi5.c) supplies the recovery secret source: returns 0 and
 * fills out with the 32-byte secret, naming the source in *source (printed by the Store stage, never the
 * secret); nonzero = no secret. ck_store_pi5_unlock_run: NULL secret refuses before any disk read; else the
 * Slot 1 path with the hardware policy (TEST keys and TEST uuid do not exist in this image). Prints nothing. */
int ck_pi5_unlock_secret(uint8_t out[CK_SB_SECRET_LEN], const char **source);
int ck_store_pi5_unlock_run(const disk_dev *d, const uint8_t *secret, const char *commit, ck_store_report *r);
#endif
/* Print the report lines (also used by the host test). */
void store_boot_print(const ck_store_report *r);
/* The open Store of the last store_boot_run (valid only after it returned 0;
 * host image tool and tests write further objects through it). */
ss_store *store_boot_store(void);
#endif
