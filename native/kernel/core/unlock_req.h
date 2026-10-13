/* unlock_req.h -- the card unlock request file of the Pi qualification image
 * (PI5-4 cut 2, build flag CK_PI5_UNLOCK_CARD, only with CK_PI5_UNLOCK).
 *
 * QUALIFICATION ONLY. The Pi has no TPM and nothing reads its serial port
 * during a run, so the run tool (pi5-run.sh UNLOCK_REQ=<file>) may place
 * \EFI\AIENOS\UNLOCK.REQ on the card's EFI partition holding a THROWAWAY
 * 32-byte recovery secret. The UEFI stub (native/boot/efi_unlock.c) reads it
 * before ExitBootServices, the Store stage takes the secret exactly once and
 * runs the same Slot 1 path an operator's `unlock <64-hex>` would. The file
 * is deleted from the card after the run. A real operator secret must never
 * be put in such a file: the tier tag below says so in the bytes themselves.
 *
 * File layout, exactly 512 bytes, little endian, everything else zero:
 *   0   magic "AIENUNQ1"
 *   8   version 1
 *   12  flags 0
 *   16  tier tag "QUALIF-THROWAWAY" (16 ASCII bytes, no NUL)
 *   32  secret, 32 bytes (not all zero, not all one byte value)
 *   64  zero padding to 512
 * The secret is never printed. */
#ifndef AIENOS_CK_UNLOCK_REQ_H
#define AIENOS_CK_UNLOCK_REQ_H
#include <stddef.h>
#include <stdint.h>

#define CK_UNLOCK_REQ_MAGIC "AIENUNQ1"
#define CK_UNLOCK_REQ_TAG "QUALIF-THROWAWAY"
#define CK_UNLOCK_REQ_VERSION 1u
#define CK_UNLOCK_REQ_SIZE 512u
#define CK_UNLOCK_REQ_SECRET_LEN 32u
#define CK_UNLOCK_REQ_PATH "\\EFI\\AIENOS\\UNLOCK.REQ"
#define CK_UNLOCK_REQ_SOURCE "card request file (QUALIFICATION ONLY, throwaway secret)"

struct ck_unlock_req {
    uint8_t magic[8];
    uint32_t version;
    uint32_t flags;
    uint8_t tag[16];
    uint8_t secret[CK_UNLOCK_REQ_SECRET_LEN];
    uint8_t pad[CK_UNLOCK_REQ_SIZE - 64];
};

/* 0 = well formed; else -1 and *why names the first failed check (never the secret). */
int ck_unlock_req_check(const struct ck_unlock_req *q, const char **why);

enum { CK_UNLOCK_REQ_NONE = 0, CK_UNLOCK_REQ_ABSENT = 1, CK_UNLOCK_REQ_REFUSED = 2, CK_UNLOCK_REQ_FOUND = 3 };

/* What the UEFI stub found (shared with the kernel: the stub and the kernel are one image). */
struct ck_unlock_req_boot {
    int state;                                /* CK_UNLOCK_REQ_* */
    uint8_t secret[CK_UNLOCK_REQ_SECRET_LEN]; /* only while state is FOUND */
};
extern struct ck_unlock_req_boot ck_unlock_req_boot;

/* The stub stores a checked request (state FOUND, secret copied). */
void ck_unlock_req_store(const struct ck_unlock_req *q);
/* One-shot: copies the secret out and wipes the boot copy (state back to NONE) and returns 0;
 * returns -1 and zeroes out when there is no found request (or it was already taken). */
int ck_unlock_req_take(uint8_t out[CK_UNLOCK_REQ_SECRET_LEN]);
#endif
