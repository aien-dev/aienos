/* reply_obj.h -- the v1 approved-reply Store object (kind 0x5231 'R1'), shared by the service lifecycle
 * (core/lifecycle.c, commit_task: QEMU rows 175, 205, 206 of GATES.md) and the Pi agent stage
 * (svc/pi5_agent.c, PI5-6). One builder, so the two cannot drift.
 *
 * Bytes: "aienos.reply.v1\nprompt: " + prompt + "\nreply: " + reply + "\n"
 * and, only when the caller passes a trailer (the Pi agent does, the lifecycle does not):
 * "model: " + 64 lowercase hex + "\nids: " + decimal token ids separated by single spaces + "\n".
 * With no trailer the output is byte for byte what lifecycle.c wrote before this header existed
 * (dev/tests/pi5_agent_test.c pins it against a literal). */
#ifndef AIENOS_CK_REPLY_OBJ_H
#define AIENOS_CK_REPLY_OBJ_H
#include <stddef.h>
#include <stdint.h>

#define CK_REPLY_OBJ_KIND 0x5231u /* 'R1' */
#define CK_REPLY_OBJ_HDR "aienos.reply.v1\nprompt: "
#define CK_REPLY_OBJ_SEP "\nreply: "
#define CK_REPLY_OBJ_MODEL "model: "
#define CK_REPLY_OBJ_IDS "\nids: "
#define CK_REPLY_OBJ_MAX_IDS 16u
/* Largest trailer: "model: " + 64 + "\nids: " + 16 ids of up to 10 digits and a space + "\n". */
#define CK_REPLY_OBJ_TRAILER_MAX (7 + 64 + 6 + 16 * 11 + 1)

static inline void ck_reply_put(uint8_t *buf, size_t *n, const char *s, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) buf[(*n)++] = (uint8_t)s[i];
}

/* Builds the object into buf (the caller sized it for prompt + reply + trailer + the fixed text).
 * model_hex64: NULL for no trailer. ids/nids: the token ids, only used with a trailer. Returns the
 * length. */
static inline size_t ck_reply_obj_build(uint8_t *buf, const char *prompt, size_t plen, const uint8_t *reply,
                                        size_t rlen, const char *model_hex64, const uint32_t *ids, unsigned nids)
{
    size_t n = 0, i;
    ck_reply_put(buf, &n, CK_REPLY_OBJ_HDR, sizeof CK_REPLY_OBJ_HDR - 1);
    ck_reply_put(buf, &n, prompt, plen);
    ck_reply_put(buf, &n, CK_REPLY_OBJ_SEP, sizeof CK_REPLY_OBJ_SEP - 1);
    for (i = 0; i < rlen; i++) buf[n++] = reply[i];
    buf[n++] = '\n';
    if (model_hex64) {
        unsigned k;
        ck_reply_put(buf, &n, CK_REPLY_OBJ_MODEL, sizeof CK_REPLY_OBJ_MODEL - 1);
        ck_reply_put(buf, &n, model_hex64, 64);
        ck_reply_put(buf, &n, CK_REPLY_OBJ_IDS, sizeof CK_REPLY_OBJ_IDS - 1);
        for (k = 0; k < nids && k < CK_REPLY_OBJ_MAX_IDS; k++) {
            char d[10];
            unsigned nd = 0;
            uint32_t v = ids[k];
            if (k) buf[n++] = ' ';
            do { d[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
            while (nd) buf[n++] = (uint8_t)d[--nd];
        }
        buf[n++] = '\n';
    }
    return n;
}
#endif
