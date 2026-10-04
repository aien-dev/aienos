/* handoff.h -- what the AIENOS UEFI boot stub passes to the C kernel core
 * after ExitBootServices. Everything referenced here lives in memory the
 * frame allocator never hands out (the loaded image, LoaderData, ACPI).
 *
 * CHANDOF2 (2026-10-04, aienos#34 lane 6): CHANDOF1 plus the yardstick
 * model's bytes, read by the stub from the boot disk before ExitBootServices
 * (native/boot/efi_model.c, map format native/boot/model_map.h).
 * CHANDOF3 (2026-10-04, L6-C): CHANDOF2 plus the UEFI Graphics Output
 * Protocol linear framebuffer the stub found before ExitBootServices
 * (native/boot/efi_gop.c), so the kernel can show its report on a screen
 * (core/fbcon.c). Per the contract (docs/BOOT_HANDOFF_CONTRACT.md section 8)
 * a new layout gets a new magic; a kernel built for CHANDOF3 refuses
 * CHANDOF1 and CHANDOF2 as "unsupported version <n>". */
#ifndef AIENOS_CK_HANDOFF_H
#define AIENOS_CK_HANDOFF_H
#include <stdint.h>
#include <stddef.h>

#define CK_HANDOFF_MAGIC 0x33464f444e414843ull    /* "CHANDOF3" */
#define CK_HANDOFF_MAGIC_V1 0x31464f444e414843ull /* "CHANDOF1": refused */
#define CK_HANDOFF_MAGIC_V2 0x32464f444e414843ull /* "CHANDOF2": refused */
/* The seven bytes "CHANDOF" (little endian, low 56 bits); the top byte is
 * the ASCII version digit. */
#define CK_HANDOFF_MAGIC_STEM 0x00464f444e414843ull

/* model_flags */
#define CK_HANDOFF_MODEL_PRESENT 1u /* model_base/model_len hold the model */
#define CK_HANDOFF_MODEL_BLOCKIO 2u /* read through UEFI Block I/O from MODEL.MAP */

/* fb_status (CHANDOF3) */
#define CK_HANDOFF_FB_NONE 0u      /* no Graphics Output Protocol: every fb_* field zero */
#define CK_HANDOFF_FB_PRESENT 1u   /* linear 32-bit framebuffer, fb_format 0 (RGBX) or 1 (BGRX) */
#define CK_HANDOFF_FB_NO_LINEAR 2u /* GOP found, but PixelBitMask/PixelBltOnly: fb_base/fb_size zero */
/* fb_format: EFI_GRAPHICS_PIXEL_FORMAT (UEFI 2.10 section 12.9.2) */
#define CK_HANDOFF_FB_RGBX 0u /* PixelRedGreenBlueReserved8BitPerColor: byte 0 red */
#define CK_HANDOFF_FB_BGRX 1u /* PixelBlueGreenRedReserved8BitPerColor: byte 0 blue */
#define CK_HANDOFF_FB_MAX_DIM 16384u /* refused above this width/height/pitch */

struct ck_handoff {
    uint64_t magic;
    uint32_t firmware_el;      /* CurrentEL at UEFI entry (2 on QEMU virtualization=on) */
    uint32_t desc_version;
    uint64_t firmware_ttbr0;   /* TTBR0_EL2 (or EL1) firmware translated with */
    uint64_t firmware_sctlr;   /* SCTLR_EL2 (or EL1) of the firmware regime */
    uint64_t rsdp;             /* ACPI 2.0 RSDP physical address, 0 if absent */
    uint64_t memory_map;       /* copy of the final UEFI memory map */
    uint64_t map_size;
    uint64_t desc_size;
    uint64_t image_base;       /* loaded PE image, [base, end) */
    uint64_t image_end;
    uint64_t counter_freq_hz;
    uint64_t uefi_entry_ticks;
    uint32_t exit_attempts;    /* ExitBootServices calls until success */
    uint32_t reserved0;
    const char *commit;
    /* CHANDOF2: the model (EfiLoaderData pages, 4 KiB aligned), or all zero. */
    uint64_t model_base;
    uint64_t model_len;        /* bytes */
    uint8_t model_sha256[32];  /* declared by MODEL.MAP; the kernel recomputes */
    uint32_t model_flags;      /* CK_HANDOFF_MODEL_* */
    uint32_t model_extents;    /* extents read */
    uint64_t model_read_us;    /* firmware Block I/O time for the whole model */
    uint64_t model_disk_last_block; /* EFI_BLOCK_IO_MEDIA.LastBlock of the disk */
    uint32_t model_block_size; /* EFI_BLOCK_IO_MEDIA.BlockSize of the disk */
    uint32_t reserved1;        /* zero */
    /* CHANDOF3: the GOP framebuffer (EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE and its
     * Info, UEFI 2.10 section 12.9.2), or all zero without a GOP. */
    uint64_t fb_base;          /* FrameBufferBase: physical, pixel (0,0) */
    uint64_t fb_size;          /* FrameBufferSize, bytes */
    uint32_t fb_width;         /* HorizontalResolution, pixels */
    uint32_t fb_height;        /* VerticalResolution, pixels */
    uint32_t fb_pitch;         /* PixelsPerScanLine (pixels, not bytes) */
    uint32_t fb_format;        /* CK_HANDOFF_FB_RGBX / _BGRX (EFI enum value) */
    uint32_t fb_status;        /* CK_HANDOFF_FB_* */
    uint32_t fb_gop_handles;   /* GOP handles the stub saw (report only) */
};
/* Layout pins for the frozen CHANDOF3 record (docs/BOOT_HANDOFF_CONTRACT.md
 * section 3, LP64): a reorder, resize or new field fails the build. */
_Static_assert(sizeof(struct ck_handoff) == 232, "ck_handoff size");
_Static_assert(offsetof(struct ck_handoff, magic) == 0, "ck_handoff.magic offset");
_Static_assert(offsetof(struct ck_handoff, firmware_el) == 8, "ck_handoff.firmware_el offset");
_Static_assert(offsetof(struct ck_handoff, desc_version) == 12, "ck_handoff.desc_version offset");
_Static_assert(offsetof(struct ck_handoff, firmware_ttbr0) == 16, "ck_handoff.firmware_ttbr0 offset");
_Static_assert(offsetof(struct ck_handoff, firmware_sctlr) == 24, "ck_handoff.firmware_sctlr offset");
_Static_assert(offsetof(struct ck_handoff, rsdp) == 32, "ck_handoff.rsdp offset");
_Static_assert(offsetof(struct ck_handoff, memory_map) == 40, "ck_handoff.memory_map offset");
_Static_assert(offsetof(struct ck_handoff, map_size) == 48, "ck_handoff.map_size offset");
_Static_assert(offsetof(struct ck_handoff, desc_size) == 56, "ck_handoff.desc_size offset");
_Static_assert(offsetof(struct ck_handoff, image_base) == 64, "ck_handoff.image_base offset");
_Static_assert(offsetof(struct ck_handoff, image_end) == 72, "ck_handoff.image_end offset");
_Static_assert(offsetof(struct ck_handoff, counter_freq_hz) == 80, "ck_handoff.counter_freq_hz offset");
_Static_assert(offsetof(struct ck_handoff, uefi_entry_ticks) == 88, "ck_handoff.uefi_entry_ticks offset");
_Static_assert(offsetof(struct ck_handoff, exit_attempts) == 96, "ck_handoff.exit_attempts offset");
_Static_assert(offsetof(struct ck_handoff, reserved0) == 100, "ck_handoff.reserved0 offset");
_Static_assert(offsetof(struct ck_handoff, commit) == 104, "ck_handoff.commit offset");
_Static_assert(offsetof(struct ck_handoff, model_base) == 112, "ck_handoff.model_base offset");
_Static_assert(offsetof(struct ck_handoff, model_len) == 120, "ck_handoff.model_len offset");
_Static_assert(offsetof(struct ck_handoff, model_sha256) == 128, "ck_handoff.model_sha256 offset");
_Static_assert(offsetof(struct ck_handoff, model_flags) == 160, "ck_handoff.model_flags offset");
_Static_assert(offsetof(struct ck_handoff, model_extents) == 164, "ck_handoff.model_extents offset");
_Static_assert(offsetof(struct ck_handoff, model_read_us) == 168, "ck_handoff.model_read_us offset");
_Static_assert(offsetof(struct ck_handoff, model_disk_last_block) == 176, "ck_handoff.model_disk_last_block offset");
_Static_assert(offsetof(struct ck_handoff, model_block_size) == 184, "ck_handoff.model_block_size offset");
_Static_assert(offsetof(struct ck_handoff, reserved1) == 188, "ck_handoff.reserved1 offset");
_Static_assert(offsetof(struct ck_handoff, fb_base) == 192, "ck_handoff.fb_base offset");
_Static_assert(offsetof(struct ck_handoff, fb_size) == 200, "ck_handoff.fb_size offset");
_Static_assert(offsetof(struct ck_handoff, fb_width) == 208, "ck_handoff.fb_width offset");
_Static_assert(offsetof(struct ck_handoff, fb_height) == 212, "ck_handoff.fb_height offset");
_Static_assert(offsetof(struct ck_handoff, fb_pitch) == 216, "ck_handoff.fb_pitch offset");
_Static_assert(offsetof(struct ck_handoff, fb_format) == 220, "ck_handoff.fb_format offset");
_Static_assert(offsetof(struct ck_handoff, fb_status) == 224, "ck_handoff.fb_status offset");
_Static_assert(offsetof(struct ck_handoff, fb_gop_handles) == 228, "ck_handoff.fb_gop_handles offset");

/* Kernel core entry, still at the firmware EL with firmware translation. */
__attribute__((noreturn)) void ck_kernel_entry(struct ck_handoff *h);

#endif
