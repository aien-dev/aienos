/* efi_artifact.c -- read \EFI\AIENOS\ARTIFACT.BND from the boot volume before ExitBootServices
 * (EL0 artifact qualification image, CK_ARTIFACT_CARD: the Raspberry Pi 5 image and its QEMU twin).
 * Nothing is written. The file is a bundle of signed artifacts placed by the run tool
 * (native/kernel/core/artifact_card.h); it is untrusted input, parsed strictly here and verified by the
 * core loader later. Result in ck_acard_boot (stub and kernel are one image): ABSENT (no file: the loader
 * reports no source), REFUSED (printed why), FOUND. Same pattern as efi_agentcmd.c. */
#include "efi.h"
#include "../kernel/core/artifact_card.h"
#include "../kernel/arch/arch.h"
#include "../kernel/core/ck_internal.h"

static void wipe_buf(void)
{
    volatile uint8_t *b = ck_acard_buf;
    for (unsigned i = 0; i < sizeof ck_acard_buf; i++)
        b[i] = 0;
}

void ck_boot_artifact_card_find(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    static CHAR16 path[] = {'\\', 'E', 'F', 'I', '\\', 'A', 'I', 'E', 'N', 'O', 'S', '\\',
                            'A', 'R', 'T', 'I', 'F', 'A', 'C', 'T', '.', 'B', 'N', 'D', 0};
    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *f = 0;
    ck_acard_boot.state = CK_ACARD_ABSENT;
    ck_acard_boot.why = "no card artifact bundle (boot volume not readable)";
    if (bs->HandleProtocol(image, &li_guid, (void **)&li) != EFI_SUCCESS || !li || !li->DeviceHandle ||
        bs->HandleProtocol(li->DeviceHandle, &fs_guid, (void **)&fs) != EFI_SUCCESS || !fs ||
        fs->OpenVolume(fs, &root) != EFI_SUCCESS || !root) {
        ck_puts("artifact_card: absent (boot volume not readable); no artifact candidates this boot\n");
        return;
    }
    if (root->Open(root, &f, path, EFI_FILE_MODE_READ, 0) != EFI_SUCCESS || !f) {
        root->Close(root);
        ck_acard_boot.why = "no card artifact bundle (file absent)";
        ck_puts("artifact_card: absent (no " CK_ACARD_PATH "); no artifact candidates this boot\n");
        return;
    }
    wipe_buf();
    uint64_t n = sizeof ck_acard_buf; /* one byte more than the format allows: a longer file is refused */
    EFI_STATUS s = f->Read(f, &n, ck_acard_buf);
    f->Close(f);
    root->Close(root);
    ck_acard_boot.state = CK_ACARD_REFUSED;
    ck_acard_boot.why = "card artifact bundle refused (read failed or size out of range)";
    if (s != EFI_SUCCESS || n < 1 || n > CK_ACARD_FILE_MAX) {
        ck_printf("artifact_card: refused (read status=0x%llx bytes=%llu, want 12..%u)\n", (unsigned long long)s,
                  (unsigned long long)n, (unsigned)CK_ACARD_FILE_MAX);
        wipe_buf();
        return;
    }
    const char *why = 0;
    if (ck_acard_parse(ck_acard_buf, (size_t)n, &ck_acard_boot.set, &why)) {
        ck_acard_boot.why = "card artifact bundle refused (malformed)";
        ck_printf("artifact_card: refused (%s)\n", why ? why : "malformed");
        wipe_buf();
        return;
    }
    ck_acard_boot.state = CK_ACARD_FOUND;
    ck_acard_boot.why = 0;
    ck_acard_boot.file_len = (uint32_t)n;
    ck_printf("artifact_card: found a well-formed bundle (QUALIFICATION ONLY, TEST keys, %u entries, %u bytes)\n",
              (unsigned)ck_acard_boot.set.count, (unsigned)n);
}
