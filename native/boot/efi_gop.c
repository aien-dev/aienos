/* efi_gop.c -- find the UEFI Graphics Output Protocol framebuffer before
 * ExitBootServices and record it in the CHANDOF3 handoff (fb_* fields), so
 * the kernel can draw its report on the screen (native/kernel/core/fbcon.c).
 *
 * UEFI 2.10 section 12.9: "The EFI_GRAPHICS_OUTPUT_PROTOCOL also exports
 * enough information about the current mode for operating system startup
 * software to access the linear frame buffer directly." The stub reads the
 * current mode only; it never calls SetMode (the screen keeps the mode the
 * firmware chose) and never calls Blt.
 *
 * Choice: the GOP on ConOut's handle when it has a linear framebuffer;
 * otherwise the first handle (LocateHandleBuffer order) whose mode is
 * PixelRedGreenBlueReserved8BitPerColor or PixelBlueGreenRedReserved8BitPerColor
 * with a nonzero FrameBufferBase. (edk2's console splitter may put a
 * Blt-only GOP on the ConOut handle; that one is skipped.) PixelBitMask and
 * PixelBltOnly modes are not used: fb_status NO_LINEAR. No GOP at all:
 * fb_status NONE, every fb_* field zero, and the kernel boots on the UART. */
#include "efi.h"
#include "../kernel/core/ck_internal.h"

static int linear(const EFI_GRAPHICS_OUTPUT_PROTOCOL *g)
{
    const EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *m = g ? g->Mode : 0;
    if (!m || !m->Info || !m->FrameBufferBase)
        return 0;
    return m->Info->PixelFormat == PixelRedGreenBlueReserved8BitPerColor ||
           m->Info->PixelFormat == PixelBlueGreenRedReserved8BitPerColor;
}

static void record(struct ck_handoff *h, const EFI_GRAPHICS_OUTPUT_PROTOCOL *g, const char *from)
{
    const EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *m = g->Mode;
    const EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *i = m->Info;
    h->fb_status = CK_HANDOFF_FB_PRESENT;
    h->fb_base = m->FrameBufferBase;
    h->fb_size = m->FrameBufferSize;
    h->fb_width = i->HorizontalResolution;
    h->fb_height = i->VerticalResolution;
    h->fb_pitch = i->PixelsPerScanLine;
    h->fb_format = i->PixelFormat;
    ck_printf("gop: ok from=%s handles=%u mode=%u/%u %ux%u pitch=%u format=%u base=0x%llx size=0x%llx\n",
              from, h->fb_gop_handles, m->Mode, m->MaxMode, i->HorizontalResolution,
              i->VerticalResolution, i->PixelsPerScanLine, i->PixelFormat,
              (unsigned long long)m->FrameBufferBase, (unsigned long long)m->FrameBufferSize);
}

void ck_boot_gop_find(EFI_SYSTEM_TABLE *st, struct ck_handoff *h)
{
    static const EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID_INIT;
    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_HANDLE *handles = 0;
    uint64_t n = 0;
    EFI_STATUS s = bs->LocateHandleBuffer(ByProtocol, &gop_guid, 0, &n, &handles);
    if (s != EFI_SUCCESS || !n || !handles) {
        ck_printf("gop: none (LocateHandleBuffer status=0x%llx handles=%llu)\n", (unsigned long long)s,
                  (unsigned long long)n);
        return; /* fb_status NONE, every fb_* field still zero (BSS) */
    }
    h->fb_gop_handles = n > 0xffffffffull ? 0xffffffffu : (uint32_t)n;

    EFI_GRAPHICS_OUTPUT_PROTOCOL *g = 0;
    if (st->ConsoleOutHandle &&
        bs->HandleProtocol(st->ConsoleOutHandle, &gop_guid, (void **)&g) == EFI_SUCCESS && linear(g)) {
        bs->FreePool(handles);
        record(h, g, "conout");
        return;
    }
    uint32_t first_format = PixelFormatMax;
    for (uint64_t k = 0; k < n; k++) {
        g = 0;
        if (bs->HandleProtocol(handles[k], &gop_guid, (void **)&g) != EFI_SUCCESS || !g)
            continue;
        if (linear(g)) {
            bs->FreePool(handles);
            record(h, g, "handle");
            return;
        }
        if (first_format == PixelFormatMax && g->Mode && g->Mode->Info)
            first_format = g->Mode->Info->PixelFormat;
    }
    bs->FreePool(handles);
    h->fb_status = CK_HANDOFF_FB_NO_LINEAR;
    ck_printf("gop: no linear framebuffer (handles=%u first_format=%u)\n", h->fb_gop_handles, first_format);
}
