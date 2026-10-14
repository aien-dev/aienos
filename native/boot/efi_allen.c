/* efi_allen.c -- read \EFI\AIENOS\ALLEN.EXM from the boot volume before ExitBootServices (pi5-allen image,
 * CK_ALLEN, PI5-8 cut K). Nothing is written. The bytes are kept as read; the kernel stage (core/allen.c) has the
 * Rust unit check the whole file before any case runs. Result in ck_allen_boot: ABSENT (no file: the stage says so
 * and runs nothing), REFUSED (unreadable or over the size bound), FOUND. */
#include "efi.h"
#include "../kernel/core/allen.h"
#include "../kernel/arch/arch.h"
#include "../kernel/core/ck_internal.h"

struct ck_allen_boot ck_allen_boot __attribute__((aligned(64)));

void ck_boot_allen_find(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    static CHAR16 path[] = {'\\', 'E', 'F', 'I', '\\', 'A', 'I', 'E', 'N', 'O', 'S', '\\',
                            'A', 'L', 'L', 'E', 'N', '.', 'E', 'X', 'M', 0};
    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *f = 0;
    ck_allen_boot.state = CK_ALLEN_EXM_ABSENT;
    ck_allen_boot.len = 0;
    if (bs->HandleProtocol(image, &li_guid, (void **)&li) != EFI_SUCCESS || !li || !li->DeviceHandle ||
        bs->HandleProtocol(li->DeviceHandle, &fs_guid, (void **)&fs) != EFI_SUCCESS || !fs ||
        fs->OpenVolume(fs, &root) != EFI_SUCCESS || !root) {
        ck_puts("allen_exam: absent (boot volume not readable)\n");
        return;
    }
    if (root->Open(root, &f, path, EFI_FILE_MODE_READ, 0) != EFI_SUCCESS || !f) {
        root->Close(root);
        ck_puts("allen_exam: absent (no " CK_ALLEN_EXM_PATH ")\n");
        return;
    }
    uint64_t n = sizeof ck_allen_boot.buf; /* one byte more than the format allows: a longer file is refused */
    EFI_STATUS s = f->Read(f, &n, ck_allen_boot.buf);
    f->Close(f);
    root->Close(root);
    if (s != EFI_SUCCESS || n < 1 || n > CK_ALLEN_FILE_MAX) {
        ck_allen_boot.state = CK_ALLEN_EXM_REFUSED;
        ck_printf("allen_exam: refused (read status=0x%llx bytes=%llu, want 1..%u)\n", (unsigned long long)s,
                  (unsigned long long)n, (unsigned)CK_ALLEN_FILE_MAX);
        return;
    }
    ck_allen_boot.len = (uint32_t)n;
    ck_allen_boot.state = CK_ALLEN_EXM_FOUND;
    ck_printf("allen_exam: read %llu bytes from " CK_ALLEN_EXM_PATH " (QUALIFICATION ONLY)\n", (unsigned long long)n);
}
