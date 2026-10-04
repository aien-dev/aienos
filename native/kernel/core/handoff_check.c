/* handoff_check.c -- refuse a malformed loader -> kernel handoff record
 * before the kernel trusts any field of it (docs/BOOT_HANDOFF_CONTRACT.md
 * section 6). Checked here: NULL record, magic (CHANDOF2 only; CHANDOF1 is
 * "bad magic"), reserved0, reserved1, the CHANDOF2 model fields, descriptor
 * stride and version, memory map size. The other PROPOSED refusals of the
 * contract (image range, overlaps, rsdp, firmware_el, CHANDOF<n> version
 * line) are not part of this cut. */
#include "handoff_check.h"
#include "fmt.h"

/* TEST-ONLY mutant (tests: make test builds it and requires it to FAIL).
 * Never in a kernel image or a hardware staging build. */
#ifdef CK_HANDOFF_MUTANT_SKIP_RESERVED
#if !__STDC_HOSTED__
#error "CK_HANDOFF_MUTANT_SKIP_RESERVED is a host test mutant only"
#endif
#ifdef CK_HARDWARE_STAGING
#error "CK_HANDOFF_MUTANT_SKIP_RESERVED cannot be combined with CK_HARDWARE_STAGING"
#endif
#endif

static char why_buf[64];

static int refuse(const char **why, const char *what, unsigned long long n)
{
    ck_snprintf(why_buf, sizeof why_buf, "%s %llu", what, n);
    *why = why_buf;
    return -1;
}

int ck_handoff_check(const struct ck_handoff *h, const char **why)
{
    if (!h) {
        *why = "null record";
        return -1;
    }
    if (h->magic != CK_HANDOFF_MAGIC) {
        *why = "bad magic";
        return -1;
    }
#ifndef CK_HANDOFF_MUTANT_SKIP_RESERVED
    if (h->reserved0 != 0) {
        *why = "reserved field nonzero";
        return -1;
    }
#endif
    if (h->reserved1 != 0) {
        *why = "reserved1 field nonzero";
        return -1;
    }
    if (h->model_flags & ~(CK_HANDOFF_MODEL_PRESENT | CK_HANDOFF_MODEL_BLOCKIO))
        return refuse(why, "bad model flags", (unsigned long long)h->model_flags);
    if (h->model_flags & CK_HANDOFF_MODEL_PRESENT) {
        if (!h->model_base || !h->model_len)
            return refuse(why, "bad model range", (unsigned long long)h->model_len);
        if (h->model_base % 4096)
            return refuse(why, "model base unaligned", (unsigned long long)h->model_base);
        if (h->model_base + h->model_len < h->model_base)
            return refuse(why, "model range overflow", (unsigned long long)h->model_len);
        if (h->model_block_size != 512 && h->model_block_size != 4096)
            return refuse(why, "bad model block size", (unsigned long long)h->model_block_size);
        if (h->model_extents == 0)
            return refuse(why, "bad model extents", 0);
    } else {
        int zero = h->model_base == 0 && h->model_len == 0 && h->model_flags == 0 &&
                   h->model_extents == 0 && h->model_read_us == 0 &&
                   h->model_disk_last_block == 0 && h->model_block_size == 0;
        for (unsigned i = 0; zero && i < 32; i++)
            zero = h->model_sha256[i] == 0;
        if (!zero) {
            *why = "model fields without model";
            return -1;
        }
    }
    if (h->desc_size < CK_HANDOFF_DESC_MIN || h->desc_size % 8 != 0)
        return refuse(why, "bad descriptor size", (unsigned long long)h->desc_size);
    if (h->desc_version != CK_HANDOFF_DESC_VERSION)
        return refuse(why, "bad descriptor version", (unsigned long long)h->desc_version);
    if (h->map_size == 0 || h->map_size > CK_HANDOFF_MAP_MAX || h->map_size % h->desc_size != 0)
        return refuse(why, "bad map size", (unsigned long long)h->map_size);
    *why = 0;
    return 0;
}
