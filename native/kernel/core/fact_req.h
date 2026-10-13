/* fact_req.h -- the card fact request file of the Pi Cortex qualification image
 * (PI5-5, build flag CK_PI5_FACT, only with CK_PI5_UNLOCK_CARD).
 *
 * QUALIFICATION ONLY. Nothing reads the Pi's serial port during a run, so the run tool may place
 * \EFI\AIENOS\FACT.REQ on the card's EFI partition holding ONE short fact. The UEFI stub
 * (native/boot/efi_fact.c) reads it before ExitBootServices; after the Store is open the fact stage
 * (svc/pi5_fact.c) appends it to the Cortex journal of the sealed Store, the same record
 * `remember <text>` writes in the service lifecycle. The run tool deletes the file after the run.
 * A fact is not a secret, but the file is still a labelled qualification input, not a user interface.
 *
 * File layout, exactly 512 bytes, little endian, everything else zero:
 *   0   magic "AIENFCT1"
 *   8   version 1
 *   12  flags 0
 *   16  tag "QUALIF-FACT-DATA" (16 ASCII bytes, no NUL)
 *   32  length of the fact, 1..48
 *   36  reserved 0
 *   40  fact text, printable ASCII 0x20..0x7e, `length` bytes, then zero to byte 88
 *   88  zero padding to 512 */
#ifndef AIENOS_CK_FACT_REQ_H
#define AIENOS_CK_FACT_REQ_H
#include <stddef.h>
#include <stdint.h>

#define CK_FACT_REQ_MAGIC "AIENFCT1"
#define CK_FACT_REQ_TAG "QUALIF-FACT-DATA"
#define CK_FACT_REQ_VERSION 1u
#define CK_FACT_REQ_SIZE 512u
#define CK_FACT_REQ_TEXT_MAX 48u
#define CK_FACT_REQ_PATH "\\EFI\\AIENOS\\FACT.REQ"

struct ck_fact_req {
    uint8_t magic[8];
    uint32_t version;
    uint32_t flags;
    uint8_t tag[16];
    uint32_t len;
    uint32_t reserved;
    uint8_t text[CK_FACT_REQ_TEXT_MAX];
    uint8_t pad[CK_FACT_REQ_SIZE - 88];
};

/* 0 = well formed; else -1 and *why names the first failed check. */
int ck_fact_req_check(const struct ck_fact_req *q, const char **why);

enum { CK_FACT_REQ_NONE = 0, CK_FACT_REQ_ABSENT = 1, CK_FACT_REQ_REFUSED = 2, CK_FACT_REQ_FOUND = 3 };

/* What the UEFI stub found (the stub and the kernel are one image). */
struct ck_fact_req_boot {
    int state;                          /* CK_FACT_REQ_* */
    uint32_t len;                       /* only while FOUND */
    uint8_t text[CK_FACT_REQ_TEXT_MAX]; /* only while FOUND */
};
extern struct ck_fact_req_boot ck_fact_req_boot;

void ck_fact_req_store(const struct ck_fact_req *q); /* the stub stores a checked request */
void ck_fact_req_clear(void);                        /* one-shot: the fact stage wipes it after use */
#endif
