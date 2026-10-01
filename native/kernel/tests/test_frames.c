/* test_frames.c -- frame allocator over a crafted UEFI memory map: only
 * EfiConventionalMemory is handed out, reserved ranges (image, tables,
 * handoff) never are, alignment holds, exhaustion returns -1. */
#include <stdint.h>
#include <string.h>
#include "ck_test.h"
#include "frames.h"

#define DSZ 48 /* firmware descriptor size larger than the struct, as UEFI allows */

static uint8_t map[DSZ * 16];
static int nd;

static void add(uint32_t type, uint64_t phys, uint64_t pages)
{
    struct ck_efi_desc d = { type, 0, phys, 0, pages, 0x8 };
    memcpy(map + nd * DSZ, &d, sizeof d);
    nd++;
}

static int inside_free(const struct ck_frames *f, uint64_t a)
{
    for (unsigned i = 0; i < f->n; i++)
        if (a >= f->r[i].base && a < f->r[i].end)
            return 1;
    return 0;
}

int main(void)
{
    struct ck_frames f;
    add(7, 0x40000000, 0x100);  /* conventional 1 MiB */
    add(1, 0x40100000, 0x10);   /* loader code (the image) */
    add(7, 0x40110000, 0x10);   /* conventional, adjacent after a hole */
    add(9, 0x40120000, 0x4);    /* ACPI reclaim */
    add(7, 0x40124000, 0x1000); /* conventional 16 MiB, merges with nothing */
    add(4, 0x41124000, 0x2);    /* boot services data */
    add(0, 0x50000000, 0x10);   /* reserved */
    add(7, 0x60000000, 0);      /* empty descriptor */
    ck_frames_init(&f);
    CHECK(ck_frames_from_efi(&f, map, (uint64_t)nd * DSZ, DSZ) == 3);
    CHECK(ck_frames_from_efi(&f, map, (uint64_t)nd * DSZ, 8) == -1);
    CHECK(ck_frames_free_bytes(&f) == (0x100ull + 0x10 + 0x1000) * 4096);
    CHECK(!inside_free(&f, 0x40100000) && !inside_free(&f, 0x40120000));
    CHECK(!inside_free(&f, 0x50000000) && !inside_free(&f, 0x41124000));

    /* Reserve an image-like range that straddles two free ranges, unaligned. */
    ck_frames_reserve(&f, 0x400ff800, 0x40110800);
    CHECK(!inside_free(&f, 0x400ff000) && !inside_free(&f, 0x40110000));
    CHECK(inside_free(&f, 0x400fe000) && inside_free(&f, 0x40111000));
    /* Split a range in the middle. */
    ck_frames_reserve(&f, 0x40200000, 0x40201000);
    CHECK(!inside_free(&f, 0x40200000) && inside_free(&f, 0x401ff000) && inside_free(&f, 0x40201000));

    /* Allocations never land in reserved space and respect alignment. */
    uint64_t a;
    CHECK(ck_frames_alloc(&f, 1, 4096, &a) == 0 && a == 0x40000000);
    CHECK(ck_frames_alloc(&f, 512, 2ull << 20, &a) == 0 && (a & ((2ull << 20) - 1)) == 0);
    CHECK(a >= 0x40124000 && a + 512 * 4096 <= 0x41124000);
    CHECK(ck_frames_alloc(&f, 3, 1000, &a) == -1); /* bad alignment */
    CHECK(ck_frames_alloc(&f, 0, 4096, &a) == -1);

    /* Exhaustion: drain everything one page at a time, then fail. */
    uint64_t left = ck_frames_free_bytes(&f) / 4096, got = 0;
    while (ck_frames_alloc(&f, 1, 4096, &a) == 0) {
        CHECK(a != 0x40100000 && a != 0x40120000 && !(a >= 0x400ff000 && a < 0x40111000));
        got++;
    }
    CHECK(got == left && ck_frames_free_bytes(&f) == 0);
    CHECK(ck_frames_alloc(&f, 1, 4096, &a) == -1);
    ck_frames_free(&f, 0x40000000, 2);
    CHECK(ck_frames_free_bytes(&f) == 2 * 4096);
    CHECK(ck_frames_alloc(&f, 2, 4096, &a) == 0 && a == 0x40000000);

    /* Range table overflow is counted, not silent. */
    ck_frames_init(&f);
    for (unsigned i = 0; i < CK_FRAMES_MAX + 3; i++)
        ck_frames_add(&f, 0x100000000ull + i * 0x2000ull, 0x100000000ull + i * 0x2000ull + 0x1000);
    CHECK(f.n == CK_FRAMES_MAX && f.dropped == 3);
    return ck_t_verdict("CK_FRAMES");
}
