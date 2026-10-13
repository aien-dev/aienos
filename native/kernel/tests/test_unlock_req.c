/* test_unlock_req.c -- core/unlock_req.c: the card unlock request file of the Pi qualification
 * image (CK_PI5_UNLOCK_CARD). Every malformed request is refused with a reason that never
 * contains the secret; a well-formed one is handed out exactly once and then wiped. */
#include <string.h>
#include "ck_test.h"
#include "unlock_req.h"

_Static_assert(sizeof(struct ck_unlock_req) == CK_UNLOCK_REQ_SIZE, "request is exactly one sector");

static struct ck_unlock_req good(void)
{
    struct ck_unlock_req q;
    memset(&q, 0, sizeof q);
    memcpy(q.magic, CK_UNLOCK_REQ_MAGIC, 8);
    q.version = CK_UNLOCK_REQ_VERSION;
    memcpy(q.tag, CK_UNLOCK_REQ_TAG, 16);
    for (int i = 0; i < 32; i++)
        q.secret[i] = (uint8_t)(0x30 + i * 3);
    return q;
}

static int refused(const struct ck_unlock_req *q, const char *want)
{
    const char *why = 0;
    int rc = ck_unlock_req_check(q, &why);
    return rc != 0 && why && strstr(why, want) != 0;
}

int main(void)
{
    struct ck_unlock_req q = good();
    const char *why = 0;
    CHECK(ck_unlock_req_check(&q, &why) == 0 && why == 0);
    CHECK(ck_unlock_req_check(0, &why) != 0);
    CHECK(strlen(CK_UNLOCK_REQ_TAG) == 16);
    CHECK(strstr(CK_UNLOCK_REQ_SOURCE, "QUALIFICATION ONLY, throwaway secret") != 0);

    q = good(); q.magic[0] ^= 1;
    CHECK(refused(&q, "magic"));
    q = good(); q.version = 2;
    CHECK(refused(&q, "version"));
    q = good(); q.flags = 1;
    CHECK(refused(&q, "flags"));
    q = good(); q.tag[15] = 'X';
    CHECK(refused(&q, "THROWAWAY")); /* a request that does not say throwaway is not accepted */
    q = good(); memset(q.tag, 0, 16);
    CHECK(refused(&q, "THROWAWAY"));
    q = good(); memset(q.secret, 0, 32);
    CHECK(refused(&q, "all zero"));
    q = good(); memset(q.secret, 0x41, 32);
    CHECK(refused(&q, "repeated byte"));
    q = good(); q.secret[31] ^= 0x01; /* a one-bit change is still a valid (different) secret */
    CHECK(ck_unlock_req_check(&q, &why) == 0);
    q = good(); q.pad[0] = 1;
    CHECK(refused(&q, "padding"));
    q = good(); q.pad[sizeof q.pad - 1] = 1;
    CHECK(refused(&q, "padding"));
    /* the reason text never carries secret bytes */
    q = good(); q.version = 7;
    ck_unlock_req_check(&q, &why);
    CHECK(why && !strstr(why, "0x") && strlen(why) < 64);

    /* One-shot take. */
    uint8_t out[32];
    memset(&ck_unlock_req_boot, 0, sizeof ck_unlock_req_boot);
    memset(out, 0xEE, sizeof out);
    CHECK(ck_unlock_req_take(out) == -1);          /* nothing stored: refused */
    int z = 0;
    for (int i = 0; i < 32; i++) z |= out[i];
    CHECK(z == 0);                                 /* and the caller's buffer is zeroed */
    q = good();
    ck_unlock_req_store(&q);
    CHECK(ck_unlock_req_boot.state == CK_UNLOCK_REQ_FOUND);
    CHECK(ck_unlock_req_take(out) == 0 && memcmp(out, q.secret, 32) == 0);
    int left = 0;
    for (int i = 0; i < 32; i++) left |= ck_unlock_req_boot.secret[i];
    CHECK(left == 0 && ck_unlock_req_boot.state == CK_UNLOCK_REQ_NONE); /* the boot copy is wiped */
    CHECK(ck_unlock_req_take(out) == -1);          /* a second take gets nothing */
    /* ABSENT and REFUSED states hand out nothing even if bytes were somehow left. */
    ck_unlock_req_boot.state = CK_UNLOCK_REQ_REFUSED;
    memset(ck_unlock_req_boot.secret, 0x55, 32);
    CHECK(ck_unlock_req_take(out) == -1);
    ck_unlock_req_boot.state = CK_UNLOCK_REQ_ABSENT;
    CHECK(ck_unlock_req_take(out) == -1);
    return ck_t_verdict("test_unlock_req");
}
