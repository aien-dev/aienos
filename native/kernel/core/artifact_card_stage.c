/* artifact_card_stage.c -- offers the card artifact bundle (core/artifact_card.h) to the core loader through
 * the boot-disk hook (ck_stage_disk_artifacts, ck.h), in the images built with CK_ARTIFACT_CARD only
 * (QUALIFICATION ONLY, TEST keys). Such an image links no Store stage, so the hook has exactly one
 * definition. The bytes stay UNTRUSTED: core/artifact_loader.c verifies every candidate itself. */
#include "ck_internal.h"
#include "artifact_card.h"
#include "sha256.h"

static struct ck_disk_artifact offered[CK_ACARD_MAX_ENTRIES];

static void hex(char *o, const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        o[2 * i] = d[b[i] >> 4];
        o[2 * i + 1] = d[b[i] & 15];
    }
    o[2 * n] = 0;
}

int ck_stage_disk_artifacts(struct ck_disk_artifacts *out)
{
    static int announced;
    if (!out)
        return -1;
    memset(out, 0, sizeof *out);
    if (ck_acard_boot.state == CK_ACARD_FOUND) {
        uint8_t dg[32];
        char h[65];
        for (uint32_t i = 0; i < ck_acard_boot.set.count; i++) {
            offered[i].name = ck_acard_boot.set.e[i].name;
            offered[i].bytes = ck_acard_boot.set.e[i].bytes;
            offered[i].len = ck_acard_boot.set.e[i].len;
            offered[i].state = CK_DISK_ART_OK;
        }
        out->available = 1;
        out->why = "ok";
        out->count = ck_acard_boot.set.count;
        out->a = offered;
        if (!announced) {
            sha256_hash(ck_acard_buf, ck_acard_boot.file_len, dg);
            hex(h, dg, 32);
            ck_printf("artifact_card: %s bytes=%u entries=%u sha256=%s (QUALIFICATION ONLY, TEST keys; untrusted until verified)\n",
                      CK_ACARD_PATH, ck_acard_boot.file_len, ck_acard_boot.set.count, h);
            for (uint32_t i = 0; i < ck_acard_boot.set.count; i++) {
                sha256_hash(ck_acard_boot.set.e[i].bytes, ck_acard_boot.set.e[i].len, dg);
                hex(h, dg, 32);
                ck_printf("artifact_card: %s bytes=%u sha256=%s\n", ck_acard_boot.set.e[i].name,
                          ck_acard_boot.set.e[i].len, h);
            }
            announced = 1;
        }
        return 0;
    }
    out->why = ck_acard_boot.why ? ck_acard_boot.why : "no card artifact bundle";
    return 0;
}

void ck_stage_disk_artifacts_free(void)
{
    volatile uint8_t *b = ck_acard_buf;
    if (ck_acard_boot.state == CK_ACARD_FOUND)
        ck_printf("artifact_card: released bundle bytes=%u entries=%u\n", ck_acard_boot.file_len,
                  ck_acard_boot.set.count);
    for (size_t i = 0; i < sizeof ck_acard_buf; i++)
        b[i] = 0;
    memset(offered, 0, sizeof offered);
    memset(&ck_acard_boot, 0, sizeof ck_acard_boot);
}
