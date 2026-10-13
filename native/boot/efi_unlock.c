/* efi_unlock.c -- read \EFI\AIENOS\UNLOCK.REQ from the boot volume before
 * ExitBootServices (Raspberry Pi 5 qualification image, CK_PI5_UNLOCK_CARD).
 * Nothing is written. The file holds a THROWAWAY recovery secret placed by the
 * run tool (see native/kernel/core/unlock_req.h); the secret is never printed.
 * Result in ck_unlock_req_boot (stub and kernel are one image): ABSENT (no
 * file: not an error, the Store stays closed), REFUSED (printed why), FOUND. */
#include "efi.h"
#include "../kernel/core/unlock_req.h"
#include "../kernel/arch/arch.h"
#include "../kernel/core/ck_internal.h"

static uint8_t buf[CK_UNLOCK_REQ_SIZE + 1u] __attribute__((aligned(64)));

static void wipe_buf(void)
{
    volatile uint8_t *b = buf;
    for (unsigned i = 0; i < sizeof buf; i++)
        b[i] = 0;
}

void ck_boot_unlock_req_find(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    static CHAR16 path[] = {'\\', 'E', 'F', 'I', '\\', 'A', 'I', 'E', 'N', 'O', 'S', '\\',
                            'U', 'N', 'L', 'O', 'C', 'K', '.', 'R', 'E', 'Q', 0};
    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *f = 0;
    ck_unlock_req_boot.state = CK_UNLOCK_REQ_ABSENT;
    if (bs->HandleProtocol(image, &li_guid, (void **)&li) != EFI_SUCCESS || !li || !li->DeviceHandle ||
        bs->HandleProtocol(li->DeviceHandle, &fs_guid, (void **)&fs) != EFI_SUCCESS || !fs ||
        fs->OpenVolume(fs, &root) != EFI_SUCCESS || !root) {
        ck_puts("unlock_req: absent (boot volume not readable); the Store stays closed\n");
        return;
    }
    if (root->Open(root, &f, path, EFI_FILE_MODE_READ, 0) != EFI_SUCCESS || !f) {
        root->Close(root);
        ck_puts("unlock_req: absent (no " CK_UNLOCK_REQ_PATH "); the Store stays closed\n");
        return;
    }
    wipe_buf();
    uint64_t n = sizeof buf; /* one byte more than the format: a longer file is refused */
    EFI_STATUS s = f->Read(f, &n, buf);
    f->Close(f);
    root->Close(root);
    ck_unlock_req_boot.state = CK_UNLOCK_REQ_REFUSED;
    if (s != EFI_SUCCESS || n != CK_UNLOCK_REQ_SIZE) {
        ck_printf("unlock_req: refused (read status=0x%llx bytes=%llu, want exactly %u)\n", (unsigned long long)s,
                  (unsigned long long)n, (unsigned)CK_UNLOCK_REQ_SIZE);
        wipe_buf();
        return;
    }
    const char *why = 0;
    if (ck_unlock_req_check((const struct ck_unlock_req *)buf, &why)) {
        ck_printf("unlock_req: refused (%s)\n", why ? why : "malformed");
        wipe_buf();
        return;
    }
    ck_unlock_req_store((const struct ck_unlock_req *)buf);
    wipe_buf();
    ck_puts("unlock_req: found a well-formed request file (QUALIFICATION ONLY, throwaway secret); secret not printed\n");
}
