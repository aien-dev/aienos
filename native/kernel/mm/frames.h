/* frames.h -- physical frame allocator over a sorted list of free ranges.
 * Built from the final UEFI memory map: only EfiConventionalMemory is free;
 * everything else (loader image and data, boot/runtime services, ACPI, MMIO,
 * reserved) is never handed out. Pure: no globals, host testable. */
#ifndef AIENOS_CK_FRAMES_H
#define AIENOS_CK_FRAMES_H

#include <stdint.h>

#define CK_PAGE 4096ull
#define CK_FRAMES_MAX 128

struct ck_frange {
    uint64_t base, end; /* [base, end), page aligned */
};

struct ck_frames {
    struct ck_frange r[CK_FRAMES_MAX];
    unsigned n;
    unsigned dropped; /* ranges lost because the table was full */
};

void ck_frames_init(struct ck_frames *f);
/* Adds [base, end) rounded inward to pages; merges neighbours. 0 or -1 (full). */
int ck_frames_add(struct ck_frames *f, uint64_t base, uint64_t end);
/* Removes [base, end) rounded outward to pages from the free set. */
void ck_frames_reserve(struct ck_frames *f, uint64_t base, uint64_t end);
/* Adds every EfiConventionalMemory descriptor of a UEFI memory map.
 * Returns the number of descriptors added, -1 on bad arguments. */
int ck_frames_from_efi(struct ck_frames *f, const void *map, uint64_t map_size, uint64_t desc_size);
/* npages contiguous frames aligned to `align` (power of two >= 4096).
 * 0 on success with *out set; -1 when no range fits (exhaustion). */
int ck_frames_alloc(struct ck_frames *f, uint64_t npages, uint64_t align, uint64_t *out);
void ck_frames_free(struct ck_frames *f, uint64_t base, uint64_t npages);
uint64_t ck_frames_free_bytes(const struct ck_frames *f);

/* UEFI descriptor fields used by the allocator and the mapper. */
struct ck_efi_desc {
    uint32_t type;
    uint32_t pad;
    uint64_t phys;
    uint64_t virt;
    uint64_t pages;
    uint64_t attr;
};
#define CK_EFI_CONVENTIONAL 7u

#endif
