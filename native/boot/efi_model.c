/* efi_model.c -- read the yardstick model from the boot disk before
 * ExitBootServices, through the firmware's own Block I/O driver (the one that
 * just loaded BOOTAA64.EFI), and hand it to the kernel in CHANDOF2
 * (aienos#34 lane 6: the first model ingest path that exists on hardware).
 *
 * Why the firmware and not our NVMe driver: our C NVMe driver and its SMMU
 * confinement have never run on the DGX Spark (GB10_NATIVE_STATUS: NVMe
 * unconfirmed), the inference image is the core-only image without the NVMe
 * stage, and one attended boot must not gamble. UEFI Block I/O is the path
 * the firmware already proved by loading this image.
 *
 * Flow (UEFI 2.10; edk2 LoadedImage.h, SimpleFileSystem.h, BlockIo.h):
 *   1. HandleProtocol(image, LoadedImage) -> DeviceHandle = the boot volume;
 *      HandleProtocol(DeviceHandle, SimpleFileSystem) -> OpenVolume -> Open
 *      \EFI\AIENOS\MODEL.MAP read-only. Absent map: "model_map: absent",
 *      nothing recorded, boot continues (the kernel then has no disk model).
 *   2. ck_model_map_check (native/boot/model_map.h): magic, version, sector
 *      size, extents, exact coverage. Refused -> "model_map: refused (...)".
 *   3. LocateHandleBuffer(ByProtocol, BlockIo): among whole disks
 *      (LogicalPartition == 0, MediaPresent, BlockSize == map sector size)
 *      read LBA 1 and match "EFI PART" + disk GUID bytes 56..71 with the map.
 *   4. AllocatePages(AllocateAnyPages, EfiLoaderData): the kernel never hands
 *      LoaderData out (mm/mmu.c) and reserves this range explicitly.
 *   5. ReadBlocks per extent in <= 8 MiB pieces, BufferSize a multiple of
 *      BlockSize, buffers page aligned (>= IoAlign for every driver seen).
 *   6. Record base, length, declared SHA-256, flags, timing in the handoff.
 * The stub does NOT hash: the kernel recomputes SHA-256 over the bytes it
 * received (core/infer.c) and refuses to decode on a mismatch, so a wrong LBA,
 * a short read or a stale file can never pass as the model. */
#include "efi.h"
#include "model_map.h"
#include "handoff.h"
#include "../kernel/arch/arch.h"
#include "../kernel/core/ck_internal.h"

#define READ_CHUNK (8ull << 20)
#define PAGE 4096ull

static struct ck_model_map map __attribute__((aligned(4096)));
static uint8_t lba1[4096] __attribute__((aligned(4096)));


static void hex(char *out, const uint8_t *b, unsigned n)
{
    static const char d[] = "0123456789abcdef";
    for (unsigned i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static uint64_t ticks_to_us(uint64_t ticks, uint64_t hz)
{
    return hz ? (ticks / hz) * 1000000ull + ((ticks % hz) * 1000000ull) / hz : 0;
}

static void clear_model(struct ck_handoff *h)
{
    h->model_base = h->model_len = 0;
    memset(h->model_sha256, 0, sizeof h->model_sha256);
    h->model_flags = h->model_extents = 0;
    h->model_read_us = h->model_disk_last_block = 0;
    h->model_block_size = 0;
}

/* Read MODEL.MAP from the volume this image was loaded from. 1 = absent,
 * -1 = present but unreadable/malformed (printed), 0 = in `map`. */
static int read_map(EFI_HANDLE image, EFI_BOOT_SERVICES *bs)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    static CHAR16 path[] = {'\\', 'E', 'F', 'I', '\\', 'A', 'I', 'E', 'N', 'O', 'S', '\\',
                            'M', 'O', 'D', 'E', 'L', '.', 'M', 'A', 'P', 0};
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *f = 0;
    EFI_STATUS s = bs->HandleProtocol(image, &li_guid, (void **)&li);
    if (s != EFI_SUCCESS || !li || !li->DeviceHandle) {
        ck_printf("model_map: absent (no LoadedImage device, status=0x%llx)\n", (unsigned long long)s);
        return 1;
    }
    s = bs->HandleProtocol(li->DeviceHandle, &fs_guid, (void **)&fs);
    if (s != EFI_SUCCESS || !fs) {
        ck_printf("model_map: absent (boot volume has no file system, status=0x%llx)\n",
                  (unsigned long long)s);
        return 1;
    }
    s = fs->OpenVolume(fs, &root);
    if (s != EFI_SUCCESS || !root) {
        ck_printf("model_map: absent (OpenVolume status=0x%llx)\n", (unsigned long long)s);
        return 1;
    }
    s = root->Open(root, &f, path, EFI_FILE_MODE_READ, 0);
    if (s != EFI_SUCCESS || !f) {
        ck_puts("model_map: absent (no " CK_MODEL_MAP_PATH " on the boot volume)\n");
        root->Close(root);
        return 1;
    }
    uint64_t n = sizeof map;
    memset(&map, 0, sizeof map);
    s = f->Read(f, &n, &map);
    f->Close(f);
    root->Close(root);
    if (s != EFI_SUCCESS || n != sizeof map) {
        ck_printf("model_map: refused (read status=0x%llx bytes=%llu, want %u)\n",
                  (unsigned long long)s, (unsigned long long)n, (unsigned)sizeof map);
        return -1;
    }
    return 0;
}

/* The whole disk whose GPT disk GUID matches the map; 0 if none. */
static EFI_BLOCK_IO_PROTOCOL *find_disk(EFI_BOOT_SERVICES *bs, uint64_t *seen)
{
    static const EFI_GUID bio_guid = EFI_BLOCK_IO_PROTOCOL_GUID_INIT;
    EFI_HANDLE *handles = 0;
    uint64_t n = 0;
    EFI_BLOCK_IO_PROTOCOL *found = 0;
    *seen = 0;
    EFI_STATUS s = bs->LocateHandleBuffer(ByProtocol, &bio_guid, 0, &n, &handles);
    if (s != EFI_SUCCESS || !handles)
        return 0;
    *seen = n;
    for (uint64_t i = 0; i < n && !found; i++) {
        EFI_BLOCK_IO_PROTOCOL *bio = 0;
        if (bs->HandleProtocol(handles[i], &bio_guid, (void **)&bio) != EFI_SUCCESS || !bio || !bio->Media)
            continue;
        const EFI_BLOCK_IO_MEDIA *m = bio->Media;
        if (!m->MediaPresent || m->LogicalPartition || m->BlockSize != map.sector_size ||
            m->BlockSize > sizeof lba1 || m->LastBlock < 2)
            continue;
        if (bio->ReadBlocks(bio, m->MediaId, 1, m->BlockSize, lba1) != EFI_SUCCESS)
            continue;
        if (memcmp(lba1, "EFI PART", 8) == 0 && memcmp(lba1 + 56, map.disk_guid, 16) == 0)
            found = bio;
    }
    bs->FreePool(handles);
    return found;
}

/* 0: model loaded and recorded in h; 1: no MODEL.MAP (not an error);
 * -1: map present but refused or the read failed (printed, nothing recorded). */
int ck_boot_model_load(EFI_HANDLE image, EFI_SYSTEM_TABLE *st, struct ck_handoff *h)
{
    EFI_BOOT_SERVICES *bs = st->BootServices;
    char gh[33], sh[65];
    clear_model(h);
    int rc = read_map(image, bs);
    if (rc)
        return rc;
    const char *why = 0;
    if (ck_model_map_check(&map, 0, 0, &why)) {
        ck_printf("model_map: refused (%s)\n", why);
        return -1;
    }
    hex(gh, map.disk_guid, 16);
    hex(sh, map.sha256, 32);
    ck_printf("model_map: ok len=%llu extents=%u sector=%u disk=%s\n", (unsigned long long)map.model_len,
              map.n_extents, map.sector_size, gh);

    uint64_t seen = 0;
    EFI_BLOCK_IO_PROTOCOL *bio = find_disk(bs, &seen);
    if (!bio) {
        ck_printf("model_map: refused (disk %s not found among %llu block devices)\n", gh,
                  (unsigned long long)seen);
        return -1;
    }
    const EFI_BLOCK_IO_MEDIA *m = bio->Media;
    if (ck_model_map_check(&map, m->BlockSize, m->LastBlock, &why)) {
        ck_printf("model_map: refused (%s)\n", why);
        return -1;
    }
    if (m->IoAlign > PAGE) {
        ck_printf("model_map: refused (IoAlign %u > page)\n", m->IoAlign);
        return -1;
    }

    uint64_t bs_bytes = m->BlockSize;
    uint64_t sectors = (map.model_len + bs_bytes - 1) / bs_bytes;
    uint64_t pages = (sectors * bs_bytes + PAGE - 1) / PAGE;
    uint64_t base = 0;
    EFI_STATUS s = bs->AllocatePages(AllocateAnyPages, EfiLoaderData, pages, &base);
    if (s != EFI_SUCCESS || !base) {
        ck_printf("model_map: refused (AllocatePages %llu pages status=0x%llx)\n",
                  (unsigned long long)pages, (unsigned long long)s);
        return -1;
    }
    ck_printf("model: reading %llu bytes in %u extents, block_size=%u last_block=%llu -> 0x%llx\n",
              (unsigned long long)map.model_len, map.n_extents, m->BlockSize,
              (unsigned long long)m->LastBlock, (unsigned long long)base);

    uint64_t t0 = ck_rd(cntpct_el0), off = 0;
    for (uint32_t i = 0; i < map.n_extents; i++) {
        uint64_t lba = map.ext[i].lba, left = map.ext[i].count;
        while (left) {
            uint64_t n = left * bs_bytes > READ_CHUNK ? READ_CHUNK / bs_bytes : left;
            s = bio->ReadBlocks(bio, m->MediaId, lba, n * bs_bytes, (void *)(uintptr_t)(base + off));
            if (s != EFI_SUCCESS) {
                ck_printf("model: ReadBlocks status=0x%llx at lba=%llu count=%llu (extent %u)\n",
                          (unsigned long long)s, (unsigned long long)lba, (unsigned long long)n, i);
                bs->FreePages(base, pages);
                return -1;
            }
            lba += n;
            left -= n;
            off += n * bs_bytes;
        }
    }
    uint64_t us = ticks_to_us(ck_rd(cntpct_el0) - t0, h->counter_freq_hz);

    h->model_base = base;
    h->model_len = map.model_len;
    memcpy(h->model_sha256, map.sha256, 32);
    h->model_flags = CK_HANDOFF_MODEL_PRESENT | CK_HANDOFF_MODEL_BLOCKIO;
    h->model_extents = map.n_extents;
    h->model_read_us = us;
    h->model_disk_last_block = m->LastBlock;
    h->model_block_size = m->BlockSize;
    ck_printf("model: base=0x%llx len=%llu extents=%u read_us=%llu declared_sha256=%s\n",
              (unsigned long long)base, (unsigned long long)map.model_len, map.n_extents,
              (unsigned long long)us, sh);
    return 0;
}
