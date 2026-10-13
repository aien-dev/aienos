/* efi_klog.c -- read \EFI\AIENOS\KLOG.MAP from the boot volume before
 * ExitBootServices and find the card that carries the matching log slot,
 * through the firmware's own Block I/O (Raspberry Pi 5 build, CK_KLOG).
 * The kernel later writes its console log into that slot with its own SD
 * driver (native/kernel/core/klog_flush.c), after checking the slot header
 * again itself. Here nothing is written: this file only reads.
 *
 * Result in ck_klog_boot (shared with the kernel: the stub and the kernel
 * are one image). state CK_KLOG_BOOT_ABSENT (no map: not an error),
 * _REFUSED (printed why), _FOUND (map checked and the slot header read back
 * from exactly one whole disk). */
#include "efi.h"
#include "../kernel/core/klog_slot.h"
#include "../kernel/core/klog_boot.h"
#include "../kernel/arch/arch.h"
#include "../kernel/core/ck_internal.h"

struct ck_klog_boot ck_klog_boot;
static struct ck_klog_hdr sector __attribute__((aligned(4096)));

static int read_map(EFI_HANDLE image, EFI_BOOT_SERVICES *bs, struct ck_klog_map *m)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    static CHAR16 path[] = {'\\', 'E', 'F', 'I', '\\', 'A', 'I', 'E', 'N', 'O', 'S', '\\',
                            'K', 'L', 'O', 'G', '.', 'M', 'A', 'P', 0};
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *f = 0;
    if (bs->HandleProtocol(image, &li_guid, (void **)&li) != EFI_SUCCESS || !li || !li->DeviceHandle)
        return 1;
    if (bs->HandleProtocol(li->DeviceHandle, &fs_guid, (void **)&fs) != EFI_SUCCESS || !fs)
        return 1;
    if (fs->OpenVolume(fs, &root) != EFI_SUCCESS || !root)
        return 1;
    if (root->Open(root, &f, path, EFI_FILE_MODE_READ, 0) != EFI_SUCCESS || !f) {
        root->Close(root);
        return 1;
    }
    uint64_t n = sizeof *m;
    memset(m, 0, sizeof *m);
    EFI_STATUS s = f->Read(f, &n, m);
    f->Close(f);
    root->Close(root);
    if (s != EFI_SUCCESS || n != sizeof *m) {
        ck_printf("klog_map: refused (read status=0x%llx bytes=%llu, want %u)\n", (unsigned long long)s,
                  (unsigned long long)n, (unsigned)sizeof *m);
        return -1;
    }
    return 0;
}

void ck_boot_klog_find(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID bio_guid = EFI_BLOCK_IO_PROTOCOL_GUID_INIT;
    EFI_BOOT_SERVICES *bs = st->BootServices;
    struct ck_klog_boot *kb = &ck_klog_boot;
    const char *why = 0;
    memset(kb, 0, sizeof *kb);
    int rc = read_map(image, bs, &kb->map);
    if (rc > 0) {
        kb->state = CK_KLOG_BOOT_ABSENT;
        ck_puts("klog_map: absent (no " CK_KLOG_MAP_PATH "); the log stays on the console only\n");
        return;
    }
    kb->state = CK_KLOG_BOOT_REFUSED;
    if (rc < 0)
        return;
    if (ck_klog_map_check(&kb->map, 0, &why)) {
        ck_printf("klog_map: refused (%s)\n", why);
        return;
    }
    EFI_HANDLE *handles = 0;
    uint64_t n = 0;
    if (bs->LocateHandleBuffer(ByProtocol, &bio_guid, 0, &n, &handles) != EFI_SUCCESS || !handles) {
        ck_puts("klog_map: refused (no Block I/O handles)\n");
        return;
    }
    unsigned matches = 0;
    uint64_t last = 0;
    for (uint64_t i = 0; i < n; i++) {
        EFI_BLOCK_IO_PROTOCOL *bio = 0;
        if (bs->HandleProtocol(handles[i], &bio_guid, (void **)&bio) != EFI_SUCCESS || !bio || !bio->Media)
            continue;
        const EFI_BLOCK_IO_MEDIA *md = bio->Media;
        if (!md->MediaPresent || md->LogicalPartition || md->BlockSize != 512u ||
            md->LastBlock < kb->map.lba + kb->map.count - 1u)
            continue;
        if (bio->ReadBlocks(bio, md->MediaId, kb->map.lba, 512u, &sector) != EFI_SUCCESS)
            continue;
        if (ck_klog_hdr_match(&sector, &kb->map, &why) == 0) {
            matches++;
            last = md->LastBlock;
        }
    }
    bs->FreePool(handles);
    if (matches != 1) {
        ck_printf("klog_map: refused (%u disks carry the slot header, want exactly 1; %llu Block I/O handles)\n",
                  matches, (unsigned long long)n);
        return;
    }
    kb->state = CK_KLOG_BOOT_FOUND;
    kb->disk_last_block = last;
    ck_printf("klog_map: slot lba=%llu sectors=%llu on a disk of %llu sectors (firmware read back the header)\n",
              (unsigned long long)kb->map.lba, (unsigned long long)kb->map.count,
              (unsigned long long)(last + 1u));
}
