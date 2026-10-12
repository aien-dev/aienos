/* slot_loader.c -- SLOTLDR.EFI: the AIENOS signed A/B image slot loader
 * (native v1 plan P11 cut 2a, gate N7; docs/NATIVE_IMAGE_SLOTS.md).
 *
 * A separate UEFI application that runs IN FRONT of the unchanged native
 * image (stub native/boot/efi_main.c + kernel, one PE). The owner approved a
 * narrowly scoped slot loader on 2026-10-12: signed A/B image selection,
 * boot-success tracking (bounded candidate tries) and rollback, nothing else.
 * Putting it in its own PE keeps the qualified stub + kernel byte-identical
 * (BOOT_HANDOFF_CONTRACT.md section 7) and avoids recursion: a stub that
 * chain-loaded itself would select slots again inside the chained copy.
 *
 * Flow (UEFI 2.10 boot services only; edk2 BlockIo.h, LoadedImage.h):
 *   1. LocateHandleBuffer(ByProtocol, BlockIo): on every whole disk
 *      (LogicalPartition == 0, block size 512 or 4096) read the primary GPT
 *      (header CRC32, entry array CRC32, usable range) and find entries with
 *      the slots partition type CK_SLOT_PART_TYPE_BYTES. Exactly one across
 *      all disks, or recovery is required (no fallback guess).
 *   2. Control record: torn-slot recover over partition units 0..3
 *      (native/store/torn_slot.c, the same object the host tool links).
 *   3. Each slot: read the manifest unit, read image_len bytes of the image
 *      (bounded by the slot capacity, <= 8 MiB ReadBlocks pieces), then
 *      ck_slot_verify against the owner keys baked in at build time
 *      (CK_SLOT_KEYS, or the TEST 1 key with CK_TEST_SLOT_KEY=1, which the
 *      Makefile refuses with CK_HARDWARE_STAGING).
 *   4. ck_slot_select (slot_select.c, mutation-tested in make slot-test).
 *      CK_SLOT_R_CANDIDATE_TRY: commit ctl_out (tries - 1) with ts_commit,
 *      FlushBlocks, read it back, and only then boot the candidate. That is
 *      what bounds attempts when a candidate hangs or never promotes. If the
 *      commit fails the candidate is treated as invalid and selection reruns.
 *   4b. (cut 2b) Hand the kernel one boot record (slot_format.h struct
 *      ck_slot_boot_record: slot, reason, tries, control sequence, the
 *      manifest's generation and digest) in one page of OS-loader memory type
 *      CK_SLOT_BOOT_MEMTYPE. The page survives ExitBootServices and appears in
 *      the memory map the unchanged stub hands over; the service kernel
 *      (svc/slot_service.c) promotes or abandons from it. No page: the kernel
 *      writes nothing. The control record is committed through
 *      ck_slot_control_commit (slot_control.c), the routine the kernel uses.
 *   5. One decision line, then LoadImage(SourceBuffer = the verified bytes,
 *      DevicePath = this loader's own LoadedImageDevicePath, so the chained
 *      stub's LoadedImage->DeviceHandle is still the boot volume and its
 *      MODEL.MAP still loads) and StartImage.
 *   Recovery required: print why for both slots and return EFI_LOAD_ERROR to
 *   the firmware, which goes on to its next boot option.
 *
 * Never: UEFI variables, runtime services, ExitBootServices (the chained
 * stub leaves boot services itself), any disk write other than the control
 * region, any write when the control record is missing or corrupt.
 * Freestanding C with the kernel's flags; no kernel objects are linked. */
#include <stdarg.h>
#include "efi.h"
#include "slot_format.h"
#include "slot_control.h"
#include "../kernel/core/fmt.h"

#ifndef AIENOS_COMMIT
#define AIENOS_COMMIT "unknown"
#endif

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

/* Generated at build time (native/kernel/Makefile, ck_slot_tool keys-c). */
extern const uint8_t ck_slot_loader_keys[][32];
extern const unsigned ck_slot_loader_nkeys;
extern const char ck_slot_loader_key_note[];

#define EFI_LOAD_ERROR EFI_ERR(1)
#define READ_CHUNK (8ull << 20)
#define PAGE 4096ull
#define GPT_ENT_MAX (128u * 1024u)

/* Boot-services members efi.h keeps as placeholders (UEFI 2.10 sections 7.4
 * and 13.9; r-efi system.rs BootLoadImage/BootStartImage, block_io.rs). The
 * shared efi.h is left untouched so the stub's sources do not change. */
typedef EFI_STATUS (*load_image_fn)(uint8_t boot_policy, EFI_HANDLE parent, void *device_path,
                                    void *source, uint64_t source_size, EFI_HANDLE *out);
typedef EFI_STATUS (*start_image_fn)(EFI_HANDLE image, uint64_t *exit_data_size, CHAR16 **exit_data);
typedef EFI_STATUS (*write_blocks_fn)(EFI_BLOCK_IO_PROTOCOL *bio, uint32_t media_id, uint64_t lba,
                                      uint64_t size, void *buf);
typedef EFI_STATUS (*flush_blocks_fn)(EFI_BLOCK_IO_PROTOCOL *bio);

/* EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID (UEFI 2.10 section 9.2;
 * vendor/uefi/src/proto/device_path/mod.rs LoadedImageDevicePath). */
#define LOADED_IMAGE_DEVICE_PATH_GUID_INIT \
    { 0xbc62157e, 0x3e33, 0x4fec, { 0x99, 0x20, 0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf } }

static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout;
static EFI_BOOT_SERVICES *bs;

static uint8_t blk[4096] __attribute__((aligned(4096)));
static uint8_t hdr[4096];
static uint8_t ents[GPT_ENT_MAX + 4096] __attribute__((aligned(4096)));
static uint8_t bounce[CK_SLOT_UNIT] __attribute__((aligned(4096)));
static struct ck_slot_manifest man[CK_SLOT_COUNT] __attribute__((aligned(4096)));
static struct ck_slot_control ctl_rec;

/* ---- console -------------------------------------------------------------- */
struct line {
    char b[256];
    size_t n;
};

static void line_emit(void *ctx, char c)
{
    struct line *l = ctx;
    if (l->n < sizeof l->b - 1)
        l->b[l->n++] = c;
}

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    struct line l;
    CHAR16 w[2 * sizeof l.b + 1];
    size_t k = 0;
    va_list ap;
    l.n = 0;
    va_start(ap, fmt);
    ck_vformat(line_emit, &l, fmt, ap);
    va_end(ap);
    for (size_t i = 0; i < l.n; i++) {
        if (l.b[i] == '\n')
            w[k++] = '\r';
        w[k++] = (uint8_t)l.b[i];
    }
    w[k] = 0;
    if (conout)
        conout->OutputString(conout, w);
}

/* ---- primary GPT ------------------------------------------------------------ */
static uint32_t crc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
    return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}

struct slots_part {
    EFI_BLOCK_IO_PROTOCOL *bio;
    uint32_t bs;
    uint64_t first, last;
};

/* Number of slots-type entries in this disk's primary GPT (0: no GPT or none),
 * the first one in *out; -1 with *why when the GPT is present but refused. */
static int gpt_scan(EFI_BLOCK_IO_PROTOCOL *bio, struct slots_part *out, const char **why)
{
    static const uint8_t type[16] = CK_SLOT_PART_TYPE_BYTES;
    const EFI_BLOCK_IO_MEDIA *m = bio->Media;
    uint32_t bsz = m->BlockSize;
    int count = 0;
    if (bio->ReadBlocks(bio, m->MediaId, 1, bsz, blk) != EFI_SUCCESS) {
        *why = "LBA 1 read failed";
        return -1;
    }
    if (memcmp(blk, "EFI PART", 8) != 0)
        return 0;
    uint32_t hsz = le32(blk + 12);
    if (le32(blk + 8) != 0x00010000u || hsz < 92 || hsz > bsz) {
        *why = "GPT header revision or size";
        return -1;
    }
    memcpy(hdr, blk, hsz);
    memset(hdr + 16, 0, 4);
    if (crc32(hdr, hsz) != le32(blk + 16)) {
        *why = "GPT header CRC32 mismatch";
        return -1;
    }
    uint64_t fu = le64(blk + 40), lu = le64(blk + 48), elba = le64(blk + 72);
    uint32_t nent = le32(blk + 80), esz = le32(blk + 84), ecrc = le32(blk + 88);
    if (le64(blk + 24) != 1 || fu > lu || lu > m->LastBlock) {
        *why = "GPT header LBAs";
        return -1;
    }
    if (esz < 128 || esz % 8 || nent == 0 || nent > 1024 || (uint64_t)nent * esz > GPT_ENT_MAX) {
        *why = "GPT entry geometry";
        return -1;
    }
    uint64_t ebytes = (uint64_t)nent * esz, eblocks = (ebytes + bsz - 1) / bsz;
    if (elba < 2 || elba + eblocks - 1 > m->LastBlock) {
        *why = "GPT entry array LBA";
        return -1;
    }
    if (bio->ReadBlocks(bio, m->MediaId, elba, eblocks * bsz, ents) != EFI_SUCCESS) {
        *why = "GPT entry array read failed";
        return -1;
    }
    if (crc32(ents, (size_t)ebytes) != ecrc) {
        *why = "GPT entry array CRC32 mismatch";
        return -1;
    }
    for (uint32_t i = 0; i < nent; i++) {
        const uint8_t *e = ents + (uint64_t)i * esz;
        if (memcmp(e, type, 16) != 0)
            continue;
        uint64_t f = le64(e + 32), l = le64(e + 40);
        if (f > l || f < fu || l > lu) {
            *why = "slots partition outside the GPT usable range";
            return -1;
        }
        if (count++ == 0) {
            out->bio = bio;
            out->bs = bsz;
            out->first = f;
            out->last = l;
        }
    }
    return count;
}

/* Exactly one slots partition across every whole disk, or -1 with *why. */
static int find_slots(struct slots_part *sp, const char **why)
{
    static const EFI_GUID bio_guid = EFI_BLOCK_IO_PROTOCOL_GUID_INIT;
    EFI_HANDLE *handles = 0;
    uint64_t n = 0;
    int total = 0;
    if (bs->LocateHandleBuffer(ByProtocol, &bio_guid, 0, &n, &handles) != EFI_SUCCESS || !handles) {
        *why = "no block devices";
        return -1;
    }
    for (uint64_t i = 0; i < n; i++) {
        EFI_BLOCK_IO_PROTOCOL *bio = 0;
        struct slots_part c;
        const char *w = 0;
        if (bs->HandleProtocol(handles[i], &bio_guid, (void **)&bio) != EFI_SUCCESS || !bio || !bio->Media)
            continue;
        const EFI_BLOCK_IO_MEDIA *m = bio->Media;
        if (!m->MediaPresent || m->LogicalPartition || (m->BlockSize != 512 && m->BlockSize != 4096) ||
            m->LastBlock < 34 || m->IoAlign > PAGE)
            continue;
        int rc = gpt_scan(bio, &c, &w);
        if (rc < 0) {
            say("slot_loader: disk %llu: GPT refused (%s)\n", (unsigned long long)i, w);
            continue;
        }
        if (rc > 0 && total == 0)
            *sp = c;
        total += rc;
    }
    bs->FreePool(handles);
    if (total == 0) {
        *why = "no slots partition (type " CK_SLOT_PART_TYPE_TEXT ")";
        return -1;
    }
    if (total > 1) {
        *why = "more than one slots partition";
        return -1;
    }
    return 0;
}

/* ---- torn-slot device over the whole disk (absolute LBAs) ----------------- */
static int dev_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf)
{
    struct slots_part *sp = ctx;
    uint64_t n = (uint64_t)count * sp->bs;
    if (n == 0 || n > sizeof bounce)
        return -1;
    if (sp->bio->ReadBlocks(sp->bio, sp->bio->Media->MediaId, lba, n, bounce) != EFI_SUCCESS)
        return -1;
    memcpy(buf, bounce, (size_t)n);
    return 0;
}

static int dev_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    struct slots_part *sp = ctx;
    uint64_t n = (uint64_t)count * sp->bs;
    write_blocks_fn wr = (write_blocks_fn)sp->bio->WriteBlocks;
    if (n == 0 || n > sizeof bounce || !wr || sp->bio->Media->ReadOnly)
        return -1;
    /* Only the control region (units 0..3) is ever written. */
    if (lba < sp->first || lba + count > sp->first + CK_SLOT_CONTROL_UNITS * (CK_SLOT_UNIT / sp->bs))
        return -1;
    memcpy(bounce, buf, (size_t)n);
    return wr(sp->bio, sp->bio->Media->MediaId, lba, n, bounce) == EFI_SUCCESS ? 0 : -1;
}

static int dev_flush(void *ctx)
{
    struct slots_part *sp = ctx;
    flush_blocks_fn fl = (flush_blocks_fn)sp->bio->FlushBlocks;
    return fl && fl(sp->bio) == EFI_SUCCESS ? 0 : -1;
}

/* ---- slots -------------------------------------------------------------------- */
/* Read image_len bytes of slot s into fresh pages; 0 when the manifest is not
 * structurally readable or the image does not fit (ck_slot_verify says why). */
static uint8_t *read_image(const struct slots_part *sp, uint64_t lba, const struct ck_slot_manifest *m,
                           uint64_t cap, uint64_t *pages_out, const char **why)
{
    const EFI_BLOCK_IO_MEDIA *md = sp->bio->Media;
    uint64_t bytes = (m->image_len + sp->bs - 1) / sp->bs * sp->bs;
    uint64_t pages = (bytes + PAGE - 1) / PAGE, base = 0, off = 0;
    *pages_out = 0;
    if (ck_slot_manifest_check(m, why) != 0 || m->image_len > cap)
        return 0;
    if (bs->AllocatePages(AllocateAnyPages, EfiLoaderData, pages, &base) != EFI_SUCCESS || !base) {
        *why = "AllocatePages failed";
        return 0;
    }
    while (off < bytes) {
        uint64_t n = bytes - off > READ_CHUNK ? READ_CHUNK : bytes - off;
        if (sp->bio->ReadBlocks(sp->bio, md->MediaId, lba + off / sp->bs, n, (void *)(uintptr_t)(base + off)) !=
            EFI_SUCCESS) {
            bs->FreePages(base, pages);
            *why = "image read failed";
            return 0;
        }
        off += n;
    }
    *pages_out = pages;
    return (uint8_t *)(uintptr_t)base;
}

static const char *unusable_why(const struct ck_slot_eval *e, const struct ck_slot_control *ctl, unsigned s)
{
    if (!e->valid)
        return e->why ? e->why : "invalid";
    if (ctl && e->generation < ctl->generation_floor)
        return "below the generation floor";
    if (ctl && ctl->candidate_slot == s && ctl->tries_remaining == 0)
        return "candidate out of tries";
    if (ctl && ctl->candidate_slot == s)
        return "candidate, active unusable: never boots on its own authority";
    return "not selectable";
}

/* ---- boot record for the kernel (P11 cut 2b, slot_format.h) ------------------ */
/* One page of the OS-loader memory type CK_SLOT_BOOT_MEMTYPE: it survives
 * ExitBootServices and shows up in the final memory map the unchanged stub
 * copies into the handoff. If the allocation fails the image still boots;
 * its kernel then finds no record and writes nothing (no promotion, no
 * abandon): fail closed, the tries counter still bounds a candidate. */
static void hand_over(unsigned b, const struct ck_slot_decision *d, const struct ck_slot_control *ctl,
                      uint64_t seq, const struct ck_slot_manifest *m)
{
    uint64_t pa = 0;
    struct ck_slot_boot_record *br;
    const char *c = AIENOS_COMMIT;
    EFI_STATUS s = bs->AllocatePages(AllocateAnyPages, CK_SLOT_BOOT_MEMTYPE, 1, &pa);
    if (s != EFI_SUCCESS || !pa) {
        say("slot_loader: boot record NOT handed over (AllocatePages status=0x%llx): the kernel will write nothing\n",
            (unsigned long long)s);
        return;
    }
    br = (struct ck_slot_boot_record *)(uintptr_t)pa;
    memset(br, 0, PAGE);
    memcpy(br->magic, CK_SLOT_BOOT_MAGIC, 8);
    br->version = CK_SLOT_BOOT_VERSION;
    br->boot_slot = (uint8_t)b;
    br->reason = (uint8_t)d->reason;
    br->tries = d->loader_write ? d->ctl_out.tries_remaining : (ctl ? ctl->tries_remaining : 0);
    br->control_present = ctl ? 1 : 0;
    br->control_seq = ctl ? seq : 0;
    br->generation = m->generation;
    br->policy_generation = m->policy_generation;
    memcpy(br->image_sha512, m->image_sha512, 64);
    for (unsigned i = 0; i < sizeof br->loader_commit && c[i]; i++)
        br->loader_commit[i] = (uint8_t)c[i];
    ck_slot_boot_seal(br);
    say("slot_loader: boot record handed over type=0x%x slot=%c reason=%s seq=%llu\n", CK_SLOT_BOOT_MEMTYPE, 'A' + b,
        ck_slot_reason_text(d->reason), (unsigned long long)br->control_seq);
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID lidp_guid = LOADED_IMAGE_DEVICE_PATH_GUID_INIT;
    struct slots_part sp;
    struct ck_slot_eval ev[CK_SLOT_COUNT];
    struct ck_slot_decision d;
    const struct ck_slot_control *ctl = 0;
    uint8_t *img[CK_SLOT_COUNT] = {0, 0};
    uint64_t pages[CK_SLOT_COUNT] = {0, 0};
    const char *why = 0;
    ts_device dev;
    ts_region r;
    ts_slot_state tss[2];
    uint64_t seq = 0;
    int trc;

    conout = st->ConOut;
    bs = st->BootServices;
    say("slot_loader: AIENOS SLOTLDR v1 commit=%s keys=%u\n", AIENOS_COMMIT, ck_slot_loader_nkeys);
    say("slot_loader: %s\n", ck_slot_loader_key_note);
    if (ck_slot_loader_nkeys == 0) {
        say("slot_loader: recovery_required (no trusted keys built in)\n");
        return EFI_LOAD_ERROR;
    }
    if (find_slots(&sp, &why) != 0) {
        say("slot_loader: recovery_required (%s)\n", why);
        return EFI_LOAD_ERROR;
    }
    uint64_t units = (sp.last - sp.first + 1) * sp.bs / CK_SLOT_UNIT;
    uint64_t cap_units = ck_slot_cap_units(units), bpu = CK_SLOT_UNIT / sp.bs;
    uint64_t image_cap = cap_units >= CK_SLOT_MIN_CAP_UNITS ? (cap_units - 1) * CK_SLOT_UNIT : 0;
    say("slot_loader: slots partition first_lba=%llu last_lba=%llu block=%u units=%llu cap_units=%llu\n",
        (unsigned long long)sp.first, (unsigned long long)sp.last, sp.bs, (unsigned long long)units,
        (unsigned long long)cap_units);
    if (cap_units < CK_SLOT_MIN_CAP_UNITS) {
        say("slot_loader: recovery_required (slots partition too small)\n");
        return EFI_LOAD_ERROR;
    }

    /* Control record (torn-slot region, units 0..3). */
    dev.ctx = &sp;
    dev.block_size = sp.bs;
    dev.block_count = sp.bio->Media->LastBlock + 1;
    dev.read = dev_read;
    dev.write = dev_write;
    dev.flush = dev_flush;
    trc = ts_open(&r, &dev, sp.first);
    if (trc == TS_OK)
        trc = ts_recover(&r, (uint8_t *)&ctl_rec, &seq, tss);
    if (trc == TS_OK) {
        if (ck_slot_control_check(&ctl_rec, &why) == 0) {
            ctl = &ctl_rec;
            say("slot_loader: control seq=%llu active=%c candidate=%c tries=%u flags=0x%x floor=%llu last_good=%llu\n",
                (unsigned long long)seq, 'A' + ctl->active_slot,
                ctl->candidate_slot == CK_SLOT_NONE ? '-' : 'A' + ctl->candidate_slot, ctl->tries_remaining,
                ctl->flags, (unsigned long long)ctl->generation_floor,
                (unsigned long long)ctl->last_good_generation);
        } else {
            say("slot_loader: control record refused (%s): no control, nothing will be written\n", why);
        }
    } else if (trc == TS_EMPTY) {
        say("slot_loader: control none committed: no control, nothing will be written\n");
    } else {
        say("slot_loader: control region unreadable or corrupt (rc=%d): no control, nothing will be written\n", trc);
    }

    /* Both slots: manifest, image, verification. */
    for (unsigned s = 0; s < CK_SLOT_COUNT; s++) {
        uint64_t lba = sp.first + ck_slot_manifest_unit(s, cap_units) * bpu;
        const char *rw = 0;
        ev[s].valid = 0;
        ev[s].generation = ev[s].policy_generation = 0;
        ev[s].why = 0;
        if (sp.bio->ReadBlocks(sp.bio, sp.bio->Media->MediaId, lba, CK_SLOT_UNIT, &man[s]) != EFI_SUCCESS) {
            ev[s].why = "manifest read failed";
        } else {
            img[s] = read_image(&sp, lba + bpu, &man[s], image_cap, &pages[s], &rw);
            if (!img[s] && rw && ck_slot_manifest_check(&man[s], &why) == 0 && man[s].image_len <= image_cap)
                ev[s].why = rw; /* allocation or read failure */
            else
                ck_slot_verify(&man[s], img[s], image_cap, ck_slot_loader_keys, ck_slot_loader_nkeys, &ev[s]);
        }
        if (ev[s].valid)
            say("slot_loader: slot %c valid gen=%llu policy=%llu len=%llu%s\n", 'A' + s,
                (unsigned long long)ev[s].generation, (unsigned long long)ev[s].policy_generation,
                (unsigned long long)man[s].image_len,
                ctl && ev[s].generation < ctl->generation_floor ? " (below the generation floor)" : "");
        else
            say("slot_loader: slot %c refused (%s)\n", 'A' + s, ev[s].why ? ev[s].why : "invalid");
    }

    ck_slot_select(ctl, ev, &d);
    if (d.loader_write) {
        uint64_t bseq = 0;
        int crc = ck_slot_control_commit(&r, &d.ctl_out, &bseq);
        if (crc == TS_OK)
            seq = bseq;
        if (crc != TS_OK) {
            unsigned c = (unsigned)d.boot_slot;
            say("slot_loader: control commit failed (rc=%d): the candidate is not booted\n", crc);
            ev[c].valid = 0;
            ev[c].why = "control commit failed";
            ck_slot_select(ctl, ev, &d);
        } else {
            say("slot_loader: control committed seq=%llu tries=%u\n", (unsigned long long)bseq,
                d.ctl_out.tries_remaining);
        }
    }
    if (d.boot_slot < 0) {
        say("slot_loader: recovery_required (A: %s; B: %s)\n", unusable_why(&ev[0], ctl, 0),
            unusable_why(&ev[1], ctl, 1));
        for (unsigned s = 0; s < CK_SLOT_COUNT; s++)
            if (img[s])
                bs->FreePages((uint64_t)(uintptr_t)img[s], pages[s]);
        return EFI_LOAD_ERROR;
    }

    unsigned b = (unsigned)d.boot_slot;
    unsigned tries = d.loader_write ? d.ctl_out.tries_remaining : (ctl ? ctl->tries_remaining : 0);
    say("slot_loader: boot=%c reason=%s gen=%llu tries=%u floor=%llu\n", 'A' + b, ck_slot_reason_text(d.reason),
        (unsigned long long)ev[b].generation, tries, (unsigned long long)(ctl ? ctl->generation_floor : 0));
    if (img[b ^ 1u])
        bs->FreePages((uint64_t)(uintptr_t)img[b ^ 1u], pages[b ^ 1u]);

    hand_over(b, &d, ctl, seq, &man[b]);
    void *dp = 0;
    if (bs->HandleProtocol(image, &lidp_guid, &dp) != EFI_SUCCESS)
        dp = 0;
    EFI_HANDLE child = 0;
    EFI_STATUS s = ((load_image_fn)bs->LoadImage)(0, image, dp, img[b], man[b].image_len, &child);
    bs->FreePages((uint64_t)(uintptr_t)img[b], pages[b]);
    if (s != EFI_SUCCESS || !child) {
        say("slot_loader: LoadImage of slot %c status=0x%llx: not booted\n", 'A' + b, (unsigned long long)s);
        return EFI_LOAD_ERROR;
    }
    say("slot_loader: starting slot %c\n", 'A' + b);
    s = ((start_image_fn)bs->StartImage)(child, 0, 0);
    say("slot_loader: slot %c returned status=0x%llx\n", 'A' + b, (unsigned long long)s);
    return s;
}
