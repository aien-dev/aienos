/* ck_gsp_boot_args_encode -- host tool: byte-exact encoder, decoder and
 * refusal tests for the system-memory argument blocks the pinned Linux
 * driver (nvidia-open 580.173.02) prepares before it boots GSP-RM on the
 * GB10B (aienos#286 cut C host work: "parsers and refusal tests for firmware
 * metadata. No loading"). docs/GB10_FIRMWARE_INVENTORY.md section 12 is the
 * report this tool backs. Nothing here touches a device.
 *
 * Five blocks, every line from open-gpu-kernel-modules tag 580.173.02:
 *
 *  1. GspFwWprMeta, 256 bytes, natural layout (gsp_fw_wpr_meta.h:60-208,
 *     ct_assert(sizeof == 256) in kernel_gsp_gh100.c:305). Allocated as one
 *     4 KiB page, 4 KiB aligned, cached, unprotected sysmem, zeroed
 *     (kernel_gsp_tu102.c:120-142). Filled by kgspPopulateWprMeta_GH100
 *     (kernel_gsp_gh100.c:295-388) then overridden by
 *     kgspPopulateWprMeta_GB10B (kernel_gsp_gb10b.c:62-86):
 *       magic 0xdc3aae21371a60b3, revision 1                [gh100.c:375-376]
 *       sizeOfBootloader = GspRmBoot image size (196,608)    [:321]
 *       sysmemAddrOfBootloader = its 4 KiB-aligned PA        [:322-323]
 *       sizeOfRadix3Elf = GSP-RM .fwimage size               [:326]
 *       sysmemAddrOfRadix3Elf = PA of the radix-3 root page  [:327-328]
 *       bootloaderCodeOffset/DataOffset/ManifestOffset =
 *         desc monitorCodeOffset/monitorDataOffset/manifestOffset
 *         (GB10B: 0xb000 / 0xa00 / 0x0)                      [:331-333]
 *       sysmemAddrOfSignature (256-aligned PA), sizeOfSignature =
 *         NV_ALIGN_UP(signatureSize, 256)      [:335-339; kernel_gsp.c:4697-4701]
 *       nonWprHeapSize = 0 (GB10B override)                  [gb10b.c:82]
 *       gspFwHeapSize = kgspGetFwHeapSize(.., 0, 0)          [:355]
 *       frtsSize = 0 (kgspGetFrtsSize_4a4dee for GB10B)      [:358; g_kernel_gsp_nvoc.c:1254-1256, .h:1781-1783]
 *       gspFwHeapVfPartitionCount = 0 (no vGPU offload)      [:361-362]
 *       sysmemAddrOfCrashReportQueue/size: crash-cat queue if allocated [:364-372]
 *       vgaWorkspaceSize = 0, pmuReservedSize = 0 (GB10B)    [gb10b.c:78-79]
 *       flags: PPCIE cleared; SCAN_RECOVERY_MARGIN only on a retry with
 *         ECC disabled                                       [:378-385; kernel_gsp.c:3935-3943]
 *       everything else 0: the FMC/ACR patch the FB layout   [gb10b.c:33-35]
 *     Heap size on GB10B (kernel_gsp.c:5538-5593, 5617-5668): ZERO_FB is
 *     true for "GB10B | GB20B | GB20C" (g_gpu_nvoc.c) so memSizeGB = 1;
 *     heap = OS carveout 22 MiB (kgspGetFwHeapParamOsCarveoutSize_4b5307,
 *     non-vGPU) + base 14 MiB (fwHeapParamBaseSize, Hopper+ list) +
 *     align1M(96 KiB * 1) + align1M(48 KiB * 2048) = 22+14+1+96 = 133 MiB,
 *     clamped to [88 MiB, U32_MAX] (min kgspGetMinWprHeapSizeMB_647ce6 = 88
 *     non-vGPU; the override path is off by default,
 *     NV_REG_STR_GSP_FIRMWARE_HEAP_SIZE_MB_DEFAULT = 0). Registry overrides
 *     would be clamped to [88, 280] MiB (gsp_fw_heap.h:109-110).
 *
 *  2. Libos init arguments: an array of LibosMemoryRegionInitArgument
 *     (libos_init_args.h: id8 u64, pa u64, size u64, kind u8, loc u8;
 *     natural size 32) in one 4 KiB uncached, 4 KiB-aligned, zeroed page
 *     (LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX = 4096; kernel_gsp_tu102.c:
 *     147-171). kgspSetupLibosInitArgs_IMPL (kernel_gsp.c:5179-5222): one
 *     CONTIGUOUS/SYSMEM entry per log buffer in registration order, id8 =
 *     the memory id packed big-endian (_kgspGenerateInitArgId, :2657-2675),
 *     pa = the buffer's first page PA, size = buffer size; then "RMARGS" ->
 *     the GSP_ARGUMENTS_CACHED page (size 4096). Remaining entries stay
 *     zero (kind NONE). GB10B log set (libos 3: kgspGetLibosVersion_61db9f;
 *     release build; kernel logging true for GB10B, .fwlogging_kernel_gb10y
 *     exists) in order (kernel_gsp.c:3150-3240, nv-firmware-chip-family-
 *     select.h:105-115,151-152): LOGINIT 64 KiB, LOGINTR 64 KiB, LOGRM
 *     64 KiB, LOGMNOC 64 KiB, LOGDBG 64 KiB, LOGROOT 4 KiB, LOGKRNL 64 KiB
 *     (= kgspGetLogCount LOG_IDX_LIBOS3_SIZE = 7), then RMARGS: 8 entries.
 *
 *  3. Each log buffer: contiguous cached sysmem, 4 KiB aligned, zeroed; the
 *     host writes its own PTE table into it after an 8-byte put pointer
 *     (kernel_gsp.c:3070-3104 "Pass the PTE table for the log buffer in the
 *     log buffer, after the put pointer"): u64 put = 0, then one u64 PA per
 *     4 KiB page of the buffer. The init-argument pa is PTE[0] = the base.
 *
 *  4. GSP_ARGUMENTS_CACHED (gsp_init_args.h), natural layout 88 bytes, in
 *     one 4 KiB cached, 4 KiB-aligned, zeroed page (kernel_gsp_tu102.c:
 *     174-198). kgspPopulateGspRmInitArgs_IMPL (kernel_gsp.c:4505-4573):
 *     messageQueue: sharedMemPhysAddr = PA of page 0 of the RPC shared
 *     buffer (the page-table page), pageTableEntryCount, cmdQueueOffset =
 *     pageTableSize, statQueueOffset = cmdQueueOffset + commandQueueSize;
 *     sr: all 0 on a normal boot; gpuInstance; bDmemStack = true (stack
 *     placement default 0); profilerArgs 0; sysmemHeapArgs = PA/size of the
 *     ZERO_FB sysmem heap (512 MiB default, contiguous uncached;
 *     kernel_gsp_tu102.c:200-223, nvrm_registry.h:2355-2356).
 *     RPC shared buffer (message_queue_cpu.c:60-125, 220-310): command
 *     queue 256 KiB on silicon, status queue 256 KiB; numPtes = 128 +
 *     ceil(128*8/4096) = 129; pageTableSize = align4K(129*8) = 4096; the
 *     table page holds the PAs of all 129 pages (itself first); command
 *     queue at 4096, status queue at 266240; sharedMemPA = PTE[0].
 *
 *  5. Radix-3 page table for the GSP-RM ELF (kgspCreateRadix3, kernel_gsp.c:
 *     4915-5050): 4 KiB pages, 512 entries per page; level 3 = data pages,
 *     level i-1 pages = ceil(level i pages / 512); level 0 must be 1 page;
 *     levels 0..2 are laid out back to back, then the data; each level
 *     page holds the PAs of the next level's pages. sizeOfRadix3Elf is the
 *     ELF size and sysmemAddrOfRadix3Elf the PA of the level-0 page.
 *
 * Refusals this tool enforces (reason strings are the test oracle): bad
 * magic/revision, bootloader size/offsets not the GB10B pair, unaligned or
 * zero addresses (4 KiB for pages, 256 for the signature), signature size
 * not a 256 multiple, zero ELF size, heap size outside [88 MiB, 280 MiB],
 * GB10B-must-be-zero fields non-zero (nonWprHeapSize, frtsSize,
 * vgaWorkspaceSize, pmuReservedSize, VF count), FMC-owned fields non-zero
 * on the host side (FB layout, bootCount, verified), unknown flag bits,
 * libos entries out of order or of the wrong kind/loc/size, RMARGS not last,
 * message-queue arguments inconsistent, log buffer size not a page multiple.
 *
 * INFERRED (medium), not a driver check: the GSP-FMC accepts the 133 MiB
 * heap request on GB10B exactly as the driver computes it; a different value
 * within the clamp is a change of behaviour that only the chip can judge.
 *
 * No device access, no firmware, no loading. Hosted build only.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/* ---------- the driver's structures, natural layout (LP64, little endian) ---------- */

#define GSP_FW_WPR_META_MAGIC     0xdc3aae21371a60b3ULL
#define GSP_FW_WPR_META_REVISION  1ULL
#define GSP_FW_WPR_META_VERIFIED  0xa0a0a0a0a0a0a0a0ULL
#define GSP_FW_FLAGS_CLOCK_BOOST              (1u << 0)
#define GSP_FW_FLAGS_RECOVERY_MARGIN_PRESENT  (1u << 1)
#define GSP_FW_FLAGS_PPCIE_ENABLED            (1u << 2)
#define GSP_FW_FLAGS_MULTI_GPU_NVLE_ENABLED   (1u << 3)
#define GSP_FW_FLAGS_SCAN_RECOVERY_MARGIN     (1u << 4)

typedef struct {
    uint64_t magic;
    uint64_t revision;
    uint64_t sysmemAddrOfRadix3Elf;
    uint64_t sizeOfRadix3Elf;
    uint64_t sysmemAddrOfBootloader;
    uint64_t sizeOfBootloader;
    uint64_t bootloaderCodeOffset;
    uint64_t bootloaderDataOffset;
    uint64_t bootloaderManifestOffset;
    union {
        struct { uint64_t sysmemAddrOfSignature; uint64_t sizeOfSignature; };
        struct { uint32_t gspFwHeapFreeListWprOffset; uint32_t unused0; uint64_t unused1; };
    };
    uint64_t gspFwRsvdStart;
    uint64_t nonWprHeapOffset;
    uint64_t nonWprHeapSize;
    uint64_t gspFwWprStart;
    uint64_t gspFwHeapOffset;
    uint64_t gspFwHeapSize;
    uint64_t gspFwOffset;
    uint64_t bootBinOffset;
    uint64_t frtsOffset;
    uint64_t frtsSize;
    uint64_t gspFwWprEnd;
    uint64_t fbSize;
    uint64_t vgaWorkspaceOffset;
    uint64_t vgaWorkspaceSize;
    uint64_t bootCount;
    union {
        struct {
            uint64_t partitionRpcAddr;
            uint16_t partitionRpcRequestOffset;
            uint16_t partitionRpcReplyOffset;
            uint32_t elfCodeOffset;
            uint32_t elfDataOffset;
            uint32_t elfCodeSize;
            uint32_t elfDataSize;
            uint32_t lsUcodeVersion;
        };
        struct {
            uint32_t partitionRpcPadding[4];
            uint64_t sysmemAddrOfCrashReportQueue;
            uint32_t sizeOfCrashReportQueue;
            uint32_t lsUcodeVersionPadding[1];
        };
    };
    uint8_t  gspFwHeapVfPartitionCount;
    uint8_t  flags;
    uint8_t  padding[2];
    uint32_t pmuReservedSize;
    uint64_t verified;
} GspFwWprMeta;

#define LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX 4096
enum { LIBOS_MEMORY_REGION_NONE = 0, LIBOS_MEMORY_REGION_CONTIGUOUS = 1, LIBOS_MEMORY_REGION_RADIX3 = 2 };
enum { LIBOS_MEMORY_REGION_LOC_NONE = 0, LIBOS_MEMORY_REGION_LOC_SYSMEM = 1, LIBOS_MEMORY_REGION_LOC_FB = 2 };
typedef struct {
    uint64_t id8;
    uint64_t pa;
    uint64_t size;
    uint8_t  kind;
    uint8_t  loc;
} LibosMemoryRegionInitArgument;

typedef struct {
    uint64_t sharedMemPhysAddr;
    uint32_t pageTableEntryCount;
    uint64_t cmdQueueOffset;   /* NvLength = NvU64 on LP64 (nvtypes.h:309) */
    uint64_t statQueueOffset;
} MESSAGE_QUEUE_INIT_ARGUMENTS;
typedef struct {
    uint32_t oldLevel;
    uint32_t flags;
    uint8_t  bInPMTransition;  /* NvBool */
} GSP_SR_INIT_ARGUMENTS;
typedef struct {
    MESSAGE_QUEUE_INIT_ARGUMENTS messageQueueInitArguments;
    GSP_SR_INIT_ARGUMENTS        srInitArguments;
    uint32_t                     gpuInstance;
    uint8_t                      bDmemStack;
    struct { uint64_t pa; uint64_t size; } profilerArgs;
    struct { uint64_t pa; uint64_t size; } sysmemHeapArgs;
} GSP_ARGUMENTS_CACHED;

/* ---------- GB10B constants traced from the driver ---------- */

#define PAGE_SZ               4096ULL
#define GB10B_BOOTLOADER_SIZE 196608ULL   /* GspRmBoot_GB10B UCODE_IMAGE_PROD */
#define GB10B_BL_CODE_OFF     0xb000ULL   /* desc monitorCodeOffset */
#define GB10B_BL_DATA_OFF     0xa00ULL    /* desc monitorDataOffset */
#define GB10B_BL_MANIFEST_OFF 0x0ULL      /* desc manifestOffset */
#define GB10B_FW_HEAP_SIZE    (133ULL << 20)
#define GB10B_FW_HEAP_MIN     (88ULL << 20)
#define GB10B_FW_HEAP_MAX     (280ULL << 20)
#define GB10B_SYSMEM_HEAP     (512ULL << 20)
#define MQ_CMD_QUEUE_SIZE     0x40000ULL
#define MQ_STAT_QUEUE_SIZE    0x40000ULL
#define MQ_NUM_PTES           129u
#define MQ_PAGE_TABLE_SIZE    4096ULL
#define GSP_FW_FLAGS_KNOWN    (GSP_FW_FLAGS_CLOCK_BOOST | GSP_FW_FLAGS_RECOVERY_MARGIN_PRESENT | \
                               GSP_FW_FLAGS_PPCIE_ENABLED | GSP_FW_FLAGS_MULTI_GPU_NVLE_ENABLED | \
                               GSP_FW_FLAGS_SCAN_RECOVERY_MARGIN)

static const struct { const char *id; uint64_t size; } gb10b_logs[] = {
    {"LOGINIT", 0x10000}, {"LOGINTR", 0x10000}, {"LOGRM", 0x10000}, {"LOGMNOC", 0x10000},
    {"LOGDBG",  0x10000}, {"LOGROOT", 0x1000},  {"LOGKRNL", 0x10000},
};
#define GB10B_LOG_COUNT 7u
#define GB10B_LIBOS_ENTRIES (GB10B_LOG_COUNT + 1u)

/* _kgspGenerateInitArgId: at most 8 ASCII bytes, first byte most significant. */
static uint64_t init_arg_id(const char *name) {
    uint64_t id = 0;
    for (int i = 0; i < 8; i++) {
        unsigned char c = (unsigned char)*name++;
        if (c == '\0') break;
        id = (id << 8) | c;
    }
    return id;
}

/* ---------- little-endian helpers over raw bytes ---------- */
static uint64_t rd64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) { p[i] = (uint8_t)v; v >>= 8; } }
static void wr32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) { p[i] = (uint8_t)v; v >>= 8; } }

/* ---------- 1. GspFwWprMeta ---------- */

typedef struct {
    uint64_t bootloader_pa, radix3_root_pa, elf_size, signature_pa, signature_size;
    uint64_t heap_size;            /* 0 = GB10B default 133 MiB */
    uint64_t crash_queue_pa; uint32_t crash_queue_size;
    int scan_recovery_margin;      /* retry with ECC disabled only */
} wpr_in;

static const char *wpr_encode(const wpr_in *in, uint8_t out[256]) {
    GspFwWprMeta m;
    memset(&m, 0, sizeof m);
    if (in->bootloader_pa == 0 || (in->bootloader_pa & (PAGE_SZ - 1))) return "bootloader address zero or not 4 KiB aligned";
    if (in->radix3_root_pa == 0 || (in->radix3_root_pa & (PAGE_SZ - 1))) return "radix3 root address zero or not 4 KiB aligned";
    if (in->elf_size == 0) return "ELF size zero";
    if (in->signature_pa == 0 || (in->signature_pa & 255)) return "signature address zero or not 256 aligned";
    if (in->signature_size == 0 || (in->signature_size & 255)) return "signature size zero or not a 256 multiple";
    uint64_t heap = in->heap_size ? in->heap_size : GB10B_FW_HEAP_SIZE;
    if (heap < GB10B_FW_HEAP_MIN || heap > GB10B_FW_HEAP_MAX || (heap & ((1ULL << 20) - 1))) return "heap size outside [88 MiB, 280 MiB] or not a MiB multiple";
    if ((in->crash_queue_pa == 0) != (in->crash_queue_size == 0)) return "crash report queue address and size must both be zero or both set";
    if (in->crash_queue_pa & (PAGE_SZ - 1)) return "crash report queue address not 4 KiB aligned";
    m.magic = GSP_FW_WPR_META_MAGIC;
    m.revision = GSP_FW_WPR_META_REVISION;
    m.sizeOfBootloader = GB10B_BOOTLOADER_SIZE;
    m.sysmemAddrOfBootloader = in->bootloader_pa;
    m.sizeOfRadix3Elf = in->elf_size;
    m.sysmemAddrOfRadix3Elf = in->radix3_root_pa;
    m.bootloaderCodeOffset = GB10B_BL_CODE_OFF;
    m.bootloaderDataOffset = GB10B_BL_DATA_OFF;
    m.bootloaderManifestOffset = GB10B_BL_MANIFEST_OFF;
    m.sysmemAddrOfSignature = in->signature_pa;
    m.sizeOfSignature = in->signature_size;
    m.nonWprHeapSize = 0;
    m.gspFwHeapSize = heap;
    m.frtsSize = 0;
    m.gspFwHeapVfPartitionCount = 0;
    m.sysmemAddrOfCrashReportQueue = in->crash_queue_pa;
    m.sizeOfCrashReportQueue = in->crash_queue_size;
    m.vgaWorkspaceSize = 0;
    m.pmuReservedSize = 0;
    m.flags = in->scan_recovery_margin ? GSP_FW_FLAGS_SCAN_RECOVERY_MARGIN : 0;
    memcpy(out, &m, 256);
    return NULL;
}

/* Decode + refuse: the host-side shape of a fresh-boot GB10B WprMeta. */
static const char *wpr_check(const uint8_t *b, size_t n, wpr_in *out) {
    if (n != 256) return "WprMeta size not 256";
    if (rd64(b + 0) != GSP_FW_WPR_META_MAGIC) return "magic wrong";
    if (rd64(b + 8) != GSP_FW_WPR_META_REVISION) return "revision not 1";
    uint64_t r3 = rd64(b + 16), elf = rd64(b + 24), bl = rd64(b + 32), bls = rd64(b + 40);
    if (r3 == 0 || (r3 & (PAGE_SZ - 1))) return "radix3 root address zero or not 4 KiB aligned";
    if (elf == 0) return "ELF size zero";
    if (bl == 0 || (bl & (PAGE_SZ - 1))) return "bootloader address zero or not 4 KiB aligned";
    if (bls != GB10B_BOOTLOADER_SIZE) return "bootloader size not the GB10B GspRmBoot image size";
    if (rd64(b + 48) != GB10B_BL_CODE_OFF || rd64(b + 56) != GB10B_BL_DATA_OFF || rd64(b + 64) != GB10B_BL_MANIFEST_OFF) return "bootloader offsets not the GB10B descriptor values";
    uint64_t sig = rd64(b + 72), sigs = rd64(b + 80);
    if (sig == 0 || (sig & 255)) return "signature address zero or not 256 aligned";
    if (sigs == 0 || (sigs & 255)) return "signature size zero or not a 256 multiple";
    /* FB layout fields are the FMC's: gspFwRsvdStart 88, nonWprHeapOffset 96, gspFwWprStart 112,
       gspFwHeapOffset 120, gspFwOffset 136, bootBinOffset 144, frtsOffset 152, gspFwWprEnd 168,
       fbSize 176, vgaWorkspaceOffset 184 */
    static const int fmc_owned[] = {88, 96, 112, 120, 136, 144, 152, 168, 176, 184};
    for (size_t i = 0; i < sizeof fmc_owned / sizeof fmc_owned[0]; i++)
        if (rd64(b + fmc_owned[i]) != 0) return "FMC-owned FB layout field non-zero on the host side";
    if (rd64(b + 104) != 0) return "nonWprHeapSize must be 0 on GB10B";
    uint64_t heap = rd64(b + 128);
    if (heap < GB10B_FW_HEAP_MIN || heap > GB10B_FW_HEAP_MAX || (heap & ((1ULL << 20) - 1))) return "heap size outside [88 MiB, 280 MiB] or not a MiB multiple";
    if (rd64(b + 160) != 0) return "frtsSize must be 0 on GB10B";
    if (rd64(b + 192) != 0) return "vgaWorkspaceSize must be 0 on GB10B";
    if (rd64(b + 200) != 0) return "bootCount must be 0 on the host side";
    /* union at 208: partitionRpc* zero (bootstrapper-owned) = padding[0..3] zero */
    for (int i = 0; i < 16; i++) if (b[208 + i] != 0) return "partition RPC fields must be 0";
    uint64_t cq = rd64(b + 224); uint32_t cqs = rd32(b + 232);
    if ((cq == 0) != (cqs == 0)) return "crash report queue address and size must both be zero or both set";
    if (cq & (PAGE_SZ - 1)) return "crash report queue address not 4 KiB aligned";
    if (rd32(b + 236) != 0) return "lsUcodeVersion padding must be 0";
    if (b[240] != 0) return "gspFwHeapVfPartitionCount must be 0";
    if (b[241] & ~GSP_FW_FLAGS_KNOWN) return "unknown flag bits";
    if (b[241] & (GSP_FW_FLAGS_PPCIE_ENABLED | GSP_FW_FLAGS_MULTI_GPU_NVLE_ENABLED | GSP_FW_FLAGS_CLOCK_BOOST | GSP_FW_FLAGS_RECOVERY_MARGIN_PRESENT)) return "flag bit the host never sets on GB10B";
    if (b[242] != 0 || b[243] != 0) return "padding must be 0";
    if (rd32(b + 244) != 0) return "pmuReservedSize must be 0 on GB10B";
    if (rd64(b + 248) != 0) return "verified must be 0 on the host side";
    if (out) {
        memset(out, 0, sizeof *out);
        out->bootloader_pa = bl; out->radix3_root_pa = r3; out->elf_size = elf;
        out->signature_pa = sig; out->signature_size = sigs; out->heap_size = heap;
        out->crash_queue_pa = cq; out->crash_queue_size = cqs;
        out->scan_recovery_margin = (b[241] & GSP_FW_FLAGS_SCAN_RECOVERY_MARGIN) != 0;
    }
    return NULL;
}

/* ---------- 2. libos init arguments ---------- */

typedef struct { uint64_t log_pa[GB10B_LOG_COUNT]; uint64_t rmargs_pa; } libos_in;

static const char *libos_encode(const libos_in *in, uint8_t out[LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX]) {
    memset(out, 0, LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX);
    for (unsigned i = 0; i < GB10B_LOG_COUNT; i++)
        if (in->log_pa[i] == 0 || (in->log_pa[i] & (PAGE_SZ - 1))) return "log buffer address zero or not 4 KiB aligned";
    if (in->rmargs_pa == 0 || (in->rmargs_pa & (PAGE_SZ - 1))) return "RMARGS address zero or not 4 KiB aligned";
    LibosMemoryRegionInitArgument e;
    for (unsigned i = 0; i < GB10B_LIBOS_ENTRIES; i++) {
        memset(&e, 0, sizeof e);
        e.kind = LIBOS_MEMORY_REGION_CONTIGUOUS;
        e.loc = LIBOS_MEMORY_REGION_LOC_SYSMEM;
        if (i < GB10B_LOG_COUNT) { e.id8 = init_arg_id(gb10b_logs[i].id); e.pa = in->log_pa[i]; e.size = gb10b_logs[i].size; }
        else { e.id8 = init_arg_id("RMARGS"); e.pa = in->rmargs_pa; e.size = PAGE_SZ; }
        memcpy(out + i * sizeof e, &e, sizeof e);
    }
    return NULL;
}

static const char *libos_check(const uint8_t *b, size_t n, libos_in *out) {
    if (n != LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX) return "libos init arguments size not 4096";
    const size_t es = sizeof(LibosMemoryRegionInitArgument);
    for (unsigned i = 0; i < GB10B_LIBOS_ENTRIES; i++) {
        const uint8_t *p = b + i * es;
        uint64_t id = rd64(p), pa = rd64(p + 8), sz = rd64(p + 16);
        uint8_t kind = p[24], loc = p[25];
        for (int k = 26; k < 32; k++) if (p[k] != 0) return "entry padding must be 0";
        if (kind != LIBOS_MEMORY_REGION_CONTIGUOUS) return "entry kind not CONTIGUOUS";
        if (loc != LIBOS_MEMORY_REGION_LOC_SYSMEM) return "entry loc not SYSMEM";
        if (pa == 0 || (pa & (PAGE_SZ - 1))) return "entry address zero or not 4 KiB aligned";
        if (i < GB10B_LOG_COUNT) {
            if (id != init_arg_id(gb10b_logs[i].id)) return "log entry id or order wrong for GB10B";
            if (sz != gb10b_logs[i].size) return "log entry size wrong for GB10B";
        } else {
            if (id != init_arg_id("RMARGS")) return "entry after the logs is not RMARGS";
            if (sz != PAGE_SZ) return "RMARGS size not 4096";
        }
    }
    for (size_t k = GB10B_LIBOS_ENTRIES * es; k < n; k++) if (b[k] != 0) return "bytes after the last entry must be 0";
    if (out) { for (unsigned i = 0; i < GB10B_LOG_COUNT; i++) out->log_pa[i] = rd64(b + i * es + 8); out->rmargs_pa = rd64(b + GB10B_LOG_COUNT * es + 8); }
    return NULL;
}

/* ---------- 3. log buffer prefix: put pointer + own PTE table ---------- */

static const char *logbuf_prefix(uint64_t base_pa, uint64_t size, uint8_t *out, size_t cap, size_t *len) {
    if (base_pa == 0 || (base_pa & (PAGE_SZ - 1))) return "log buffer address zero or not 4 KiB aligned";
    if (size == 0 || (size & (PAGE_SZ - 1))) return "log buffer size zero or not a page multiple";
    uint64_t pages = size / PAGE_SZ;
    size_t need = 8 + (size_t)pages * 8;
    if (need > size) return "PTE table does not fit in the buffer";
    if (need > cap) return "output buffer too small";
    wr64(out, 0);
    for (uint64_t i = 0; i < pages; i++) wr64(out + 8 + i * 8, base_pa + i * PAGE_SZ);
    *len = need;
    return NULL;
}

/* ---------- 4. GSP_ARGUMENTS_CACHED + RPC shared-buffer page table ---------- */

typedef struct { uint64_t mq_base_pa; uint32_t gpu_instance; uint64_t sysmem_heap_pa, sysmem_heap_size; } rmargs_in;

static const char *rmargs_encode(const rmargs_in *in, uint8_t out[PAGE_SZ]) {
    GSP_ARGUMENTS_CACHED a;
    memset(&a, 0, sizeof a);
    memset(out, 0, PAGE_SZ);
    if (in->mq_base_pa == 0 || (in->mq_base_pa & (PAGE_SZ - 1))) return "message queue address zero or not 4 KiB aligned";
    if (in->sysmem_heap_pa == 0 || (in->sysmem_heap_pa & (PAGE_SZ - 1))) return "sysmem heap address zero or not 4 KiB aligned";
    if (in->sysmem_heap_size == 0 || (in->sysmem_heap_size & ((1ULL << 20) - 1))) return "sysmem heap size zero or not a MiB multiple";
    a.messageQueueInitArguments.sharedMemPhysAddr = in->mq_base_pa;
    a.messageQueueInitArguments.pageTableEntryCount = MQ_NUM_PTES;
    a.messageQueueInitArguments.cmdQueueOffset = MQ_PAGE_TABLE_SIZE;
    a.messageQueueInitArguments.statQueueOffset = MQ_PAGE_TABLE_SIZE + MQ_CMD_QUEUE_SIZE;
    a.gpuInstance = in->gpu_instance;
    a.bDmemStack = 1;
    a.sysmemHeapArgs.pa = in->sysmem_heap_pa;
    a.sysmemHeapArgs.size = in->sysmem_heap_size;
    memcpy(out, &a, sizeof a);
    return NULL;
}

static const char *rmargs_check(const uint8_t *b, size_t n, rmargs_in *out) {
    if (n != PAGE_SZ) return "RMARGS page size not 4096";
    uint64_t mq = rd64(b + 0); uint32_t ptes = rd32(b + 8);
    if (rd32(b + 12) != 0) return "padding after pageTableEntryCount must be 0";
    uint64_t cmd = rd64(b + 16), stat = rd64(b + 24);
    if (mq == 0 || (mq & (PAGE_SZ - 1))) return "message queue address zero or not 4 KiB aligned";
    if (ptes != MQ_NUM_PTES) return "pageTableEntryCount not 129";
    if (cmd != MQ_PAGE_TABLE_SIZE) return "cmdQueueOffset not 4096";
    if (stat != MQ_PAGE_TABLE_SIZE + MQ_CMD_QUEUE_SIZE) return "statQueueOffset not 266240";
    if (rd32(b + 32) != 0 || rd32(b + 36) != 0 || b[40] != 0) return "suspend/resume arguments must be 0 on a normal boot";
    for (int i = 41; i < 44; i++) if (b[i] != 0) return "padding after srInitArguments must be 0";
    uint32_t gi = rd32(b + 44);
    if (b[48] != 1) return "bDmemStack not 1";
    for (int i = 49; i < 56; i++) if (b[i] != 0) return "padding after bDmemStack must be 0";
    if (rd64(b + 56) != 0 || rd64(b + 64) != 0) return "profilerArgs must be 0";
    uint64_t hp = rd64(b + 72), hs = rd64(b + 80);
    if (hp == 0 || (hp & (PAGE_SZ - 1))) return "sysmem heap address zero or not 4 KiB aligned";
    if (hs == 0 || (hs & ((1ULL << 20) - 1))) return "sysmem heap size zero or not a MiB multiple";
    for (size_t k = 88; k < n; k++) if (b[k] != 0) return "bytes after GSP_ARGUMENTS_CACHED must be 0";
    if (out) { out->mq_base_pa = mq; out->gpu_instance = gi; out->sysmem_heap_pa = hp; out->sysmem_heap_size = hs; }
    return NULL;
}

/* The RPC shared buffer's page-table page: PAs of all 129 pages, itself first (contiguous case). */
static const char *mqtable_encode(uint64_t base_pa, uint8_t out[PAGE_SZ]) {
    memset(out, 0, PAGE_SZ);
    if (base_pa == 0 || (base_pa & (PAGE_SZ - 1))) return "message queue address zero or not 4 KiB aligned";
    for (unsigned i = 0; i < MQ_NUM_PTES; i++) wr64(out + i * 8, base_pa + (uint64_t)i * PAGE_SZ);
    return NULL;
}

/* ---------- 5. radix-3 layout ---------- */

typedef struct { uint64_t npages[4]; uint64_t offset[4]; uint64_t pt_size, alloc_size; } radix3_layout;

static const char *radix3_plan(uint64_t size, radix3_layout *l) {
    if (size == 0) return "ELF size zero";
    memset(l, 0, sizeof *l);
    l->npages[3] = (size + PAGE_SZ - 1) / PAGE_SZ;
    for (int i = 3; i > 0; i--) l->npages[i - 1] = ((l->npages[i] - 1) >> 9) + 1;
    uint64_t n = 0;
    for (int i = 1; i < 4; i++) { n += l->npages[i - 1]; l->offset[i] = n * PAGE_SZ; }
    if (l->npages[0] != 1) return "ELF too large for a 3-level radix table";
    l->pt_size = n * PAGE_SZ;
    l->alloc_size = l->pt_size + l->npages[3] * PAGE_SZ;
    return NULL;
}

/* Fill the three table levels for a contiguous allocation at base_pa (data follows the tables). */
static const char *radix3_tables(uint64_t size, uint64_t base_pa, uint8_t *out, size_t cap, size_t *len) {
    radix3_layout l; const char *e = radix3_plan(size, &l);
    if (e) return e;
    if (base_pa == 0 || (base_pa & (PAGE_SZ - 1))) return "radix3 base address zero or not 4 KiB aligned";
    if (l.pt_size > cap) return "output buffer too small";
    memset(out, 0, l.pt_size);
    for (int i = 0; i < 3; i++)
        for (uint64_t k = 0; k < l.npages[i + 1]; k++)
            wr64(out + l.offset[i] + k * 8, base_pa + l.offset[i + 1] + k * PAGE_SZ);
    *len = l.pt_size;
    return NULL;
}

/* ---------- self-test ---------- */

static int checks, failures;
static void check(int ok, const char *what) { checks++; if (!ok) { failures++; printf("FAIL: %s\n", what); } }
static void expect_refusal(const char *got, const char *want, const char *what) {
    char buf[256]; snprintf(buf, sizeof buf, "%s: expected \"%s\", got \"%s\"", what, want, got ? got : "(accepted)");
    check(got != NULL && strcmp(got, want) == 0, buf);
}

static void sample_wpr(wpr_in *w) {
    memset(w, 0, sizeof *w);
    w->bootloader_pa = 0x100000000ULL; w->radix3_root_pa = 0x100100000ULL; w->elf_size = 0x4000000ULL;
    w->signature_pa = 0x100200100ULL; w->signature_size = 0x400;
}

static int selftest(void) {
    /* layouts against the compiler */
    check(sizeof(GspFwWprMeta) == 256, "sizeof GspFwWprMeta == 256");
    check(offsetof(GspFwWprMeta, sysmemAddrOfSignature) == 72, "sysmemAddrOfSignature at 72");
    check(offsetof(GspFwWprMeta, gspFwHeapSize) == 128, "gspFwHeapSize at 128");
    check(offsetof(GspFwWprMeta, bootCount) == 200, "bootCount at 200");
    check(offsetof(GspFwWprMeta, sysmemAddrOfCrashReportQueue) == 224, "sysmemAddrOfCrashReportQueue at 224");
    check(offsetof(GspFwWprMeta, gspFwHeapVfPartitionCount) == 240, "gspFwHeapVfPartitionCount at 240");
    check(offsetof(GspFwWprMeta, flags) == 241, "flags at 241");
    check(offsetof(GspFwWprMeta, pmuReservedSize) == 244, "pmuReservedSize at 244");
    check(offsetof(GspFwWprMeta, verified) == 248, "verified at 248");
    check(sizeof(LibosMemoryRegionInitArgument) == 32, "sizeof LibosMemoryRegionInitArgument == 32");
    check(offsetof(LibosMemoryRegionInitArgument, kind) == 24 && offsetof(LibosMemoryRegionInitArgument, loc) == 25, "kind/loc at 24/25");
    check(sizeof(GSP_ARGUMENTS_CACHED) == 88, "sizeof GSP_ARGUMENTS_CACHED == 88");
    check(offsetof(GSP_ARGUMENTS_CACHED, srInitArguments) == 32, "srInitArguments at 32");
    check(offsetof(GSP_ARGUMENTS_CACHED, gpuInstance) == 44, "gpuInstance at 44");
    check(offsetof(GSP_ARGUMENTS_CACHED, bDmemStack) == 48, "bDmemStack at 48");
    check(offsetof(GSP_ARGUMENTS_CACHED, profilerArgs) == 56, "profilerArgs at 56");
    check(offsetof(GSP_ARGUMENTS_CACHED, sysmemHeapArgs) == 72, "sysmemHeapArgs at 72");
    check(sizeof(MESSAGE_QUEUE_INIT_ARGUMENTS) == 32, "sizeof MESSAGE_QUEUE_INIT_ARGUMENTS == 32");
    check(sizeof(GSP_SR_INIT_ARGUMENTS) == 12, "sizeof GSP_SR_INIT_ARGUMENTS == 12");

    /* golden constants */
    check(init_arg_id("RMARGS") == 0x524D41524753ULL, "RMARGS id8");
    check(init_arg_id("LOGINIT") == 0x4C4F47494E4954ULL, "LOGINIT id8");
    check(init_arg_id("LOGKRNL") == 0x4C4F474B524E4CULL, "LOGKRNL id8");
    check(init_arg_id("ABCDEFGHIJ") == 0x4142434445464748ULL, "id8 truncates to 8 bytes");
    check(GB10B_FW_HEAP_SIZE == 0x8500000ULL, "GB10B heap 133 MiB");
    {   /* recompute the heap exactly as _kgspCalculateFwHeapSize does with ZERO_FB */
        uint64_t memSizeGB = 1, a1m = (1ULL << 20) - 1;
        uint64_t heap = (22ULL << 20) + (14ULL << 20) + (((96ULL << 10) * memSizeGB + a1m) & ~a1m) + (((48ULL << 10) * 2048 + a1m) & ~a1m);
        if (heap < (88ULL << 20)) heap = 88ULL << 20;
        check(heap == GB10B_FW_HEAP_SIZE, "heap formula reproduces 133 MiB");
    }
    check(MQ_NUM_PTES == (MQ_CMD_QUEUE_SIZE + MQ_STAT_QUEUE_SIZE) / PAGE_SZ + ((MQ_CMD_QUEUE_SIZE + MQ_STAT_QUEUE_SIZE) / PAGE_SZ * 8 + PAGE_SZ - 1) / PAGE_SZ, "numPtes formula gives 129");
    check(((MQ_NUM_PTES * 8 + PAGE_SZ - 1) & ~(PAGE_SZ - 1)) == MQ_PAGE_TABLE_SIZE, "pageTableSize 4096");

    /* 1. WprMeta round trip + golden bytes */
    wpr_in w, w2; uint8_t m[256];
    sample_wpr(&w);
    check(wpr_encode(&w, m) == NULL, "WprMeta encode accepted");
    check(rd64(m) == GSP_FW_WPR_META_MAGIC && rd64(m + 8) == 1, "magic + revision bytes");
    check(rd64(m + 40) == GB10B_BOOTLOADER_SIZE && rd64(m + 48) == 0xb000 && rd64(m + 56) == 0xa00 && rd64(m + 64) == 0, "bootloader size/offsets bytes");
    check(rd64(m + 128) == GB10B_FW_HEAP_SIZE && rd64(m + 104) == 0 && rd64(m + 160) == 0 && rd64(m + 192) == 0 && rd32(m + 244) == 0, "GB10B zeroed fields + heap");
    check(wpr_check(m, 256, &w2) == NULL, "WprMeta decode accepted");
    check(memcmp(&w, &w2, sizeof w) == 0 || (w2.heap_size == GB10B_FW_HEAP_SIZE && w2.bootloader_pa == w.bootloader_pa && w2.radix3_root_pa == w.radix3_root_pa && w2.elf_size == w.elf_size && w2.signature_pa == w.signature_pa && w2.signature_size == w.signature_size), "WprMeta round trip");
    w.heap_size = 200ULL << 20; w.scan_recovery_margin = 1; w.crash_queue_pa = 0x100300000ULL; w.crash_queue_size = 0x2000;
    check(wpr_encode(&w, m) == NULL && wpr_check(m, 256, &w2) == NULL && w2.heap_size == (200ULL << 20) && w2.scan_recovery_margin == 1 && w2.crash_queue_pa == w.crash_queue_pa && w2.crash_queue_size == 0x2000, "WprMeta optional fields round trip");
    check(m[241] == GSP_FW_FLAGS_SCAN_RECOVERY_MARGIN, "flags byte");
    /* encode refusals */
    { wpr_in b = w; b.bootloader_pa = 0x100000800ULL; expect_refusal(wpr_encode(&b, m), "bootloader address zero or not 4 KiB aligned", "unaligned bootloader"); }
    { wpr_in b = w; b.bootloader_pa = 0; expect_refusal(wpr_encode(&b, m), "bootloader address zero or not 4 KiB aligned", "zero bootloader"); }
    { wpr_in b = w; b.radix3_root_pa = 0x1000ULL + 8; expect_refusal(wpr_encode(&b, m), "radix3 root address zero or not 4 KiB aligned", "unaligned radix3"); }
    { wpr_in b = w; b.elf_size = 0; expect_refusal(wpr_encode(&b, m), "ELF size zero", "zero elf"); }
    { wpr_in b = w; b.signature_pa = 0x100200080ULL; expect_refusal(wpr_encode(&b, m), "signature address zero or not 256 aligned", "unaligned signature"); }
    { wpr_in b = w; b.signature_size = 0x3f0; expect_refusal(wpr_encode(&b, m), "signature size zero or not a 256 multiple", "odd signature size"); }
    { wpr_in b = w; b.heap_size = 87ULL << 20; expect_refusal(wpr_encode(&b, m), "heap size outside [88 MiB, 280 MiB] or not a MiB multiple", "heap too small"); }
    { wpr_in b = w; b.heap_size = 281ULL << 20; expect_refusal(wpr_encode(&b, m), "heap size outside [88 MiB, 280 MiB] or not a MiB multiple", "heap too large"); }
    { wpr_in b = w; b.heap_size = (133ULL << 20) + 1; expect_refusal(wpr_encode(&b, m), "heap size outside [88 MiB, 280 MiB] or not a MiB multiple", "heap not MiB"); }
    { wpr_in b = w; b.crash_queue_size = 0; expect_refusal(wpr_encode(&b, m), "crash report queue address and size must both be zero or both set", "crash queue half set"); }
    { wpr_in b = w; b.crash_queue_pa = 0x100300010ULL; expect_refusal(wpr_encode(&b, m), "crash report queue address not 4 KiB aligned", "crash queue unaligned"); }
    /* decode refusals, one field at a time from a good block */
    sample_wpr(&w); check(wpr_encode(&w, m) == NULL, "good block");
    expect_refusal(wpr_check(m, 255, NULL), "WprMeta size not 256", "short block");
    {
        struct { int off; int width; uint64_t val; const char *want; } muts[] = {
            {0, 8, 0xdc3aae21371a60b2ULL, "magic wrong"},
            {8, 8, 2, "revision not 1"},
            {16, 8, 0x100100800ULL, "radix3 root address zero or not 4 KiB aligned"},
            {24, 8, 0, "ELF size zero"},
            {32, 8, 0, "bootloader address zero or not 4 KiB aligned"},
            {40, 8, 196607, "bootloader size not the GB10B GspRmBoot image size"},
            {48, 8, 0xb100, "bootloader offsets not the GB10B descriptor values"},
            {56, 8, 0xa00 + 0x100, "bootloader offsets not the GB10B descriptor values"},
            {64, 8, 0x100, "bootloader offsets not the GB10B descriptor values"},
            {72, 8, 0x100200180ULL, "signature address zero or not 256 aligned"},
            {80, 8, 0x3ff, "signature size zero or not a 256 multiple"},
            {88, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {96, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {104, 8, 1, "nonWprHeapSize must be 0 on GB10B"},
            {112, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {120, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {128, 8, 1ULL << 20, "heap size outside [88 MiB, 280 MiB] or not a MiB multiple"},
            {136, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {144, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {152, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {160, 8, 1, "frtsSize must be 0 on GB10B"},
            {168, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {176, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {184, 8, 1, "FMC-owned FB layout field non-zero on the host side"},
            {192, 8, 1, "vgaWorkspaceSize must be 0 on GB10B"},
            {200, 8, 1, "bootCount must be 0 on the host side"},
            {208, 8, 1, "partition RPC fields must be 0"},
            {220, 4, 1, "partition RPC fields must be 0"},
            {224, 8, 0x100300000ULL, "crash report queue address and size must both be zero or both set"},
            {232, 4, 0x2000, "crash report queue address and size must both be zero or both set"},
            {236, 4, 1, "lsUcodeVersion padding must be 0"},
            {240, 1, 1, "gspFwHeapVfPartitionCount must be 0"},
            {241, 1, 0x20, "unknown flag bits"},
            {241, 1, GSP_FW_FLAGS_PPCIE_ENABLED, "flag bit the host never sets on GB10B"},
            {241, 1, GSP_FW_FLAGS_CLOCK_BOOST, "flag bit the host never sets on GB10B"},
            {242, 1, 1, "padding must be 0"},
            {244, 4, 1, "pmuReservedSize must be 0 on GB10B"},
            {248, 8, GSP_FW_WPR_META_VERIFIED, "verified must be 0 on the host side"},
        };
        for (size_t i = 0; i < sizeof muts / sizeof muts[0]; i++) {
            uint8_t t[256]; memcpy(t, m, 256);
            if (muts[i].width == 8) wr64(t + muts[i].off, muts[i].val);
            else if (muts[i].width == 4) wr32(t + muts[i].off, (uint32_t)muts[i].val);
            else t[muts[i].off] = (uint8_t)muts[i].val;
            char what[64]; snprintf(what, sizeof what, "WprMeta mutation at %d", muts[i].off);
            expect_refusal(wpr_check(t, 256, NULL), muts[i].want, what);
        }
        { uint8_t t[256]; memcpy(t, m, 256); wr64(t + 224, 0x100300010ULL); wr32(t + 232, 0x1000);
          expect_refusal(wpr_check(t, 256, NULL), "crash report queue address not 4 KiB aligned", "crash queue unaligned (decode)"); }
    }

    /* 2. libos init arguments */
    libos_in li, li2; uint8_t la[LIBOS_MEMORY_REGION_INIT_ARGUMENTS_MAX];
    for (unsigned i = 0; i < GB10B_LOG_COUNT; i++) li.log_pa[i] = 0x200000000ULL + (uint64_t)i * 0x10000;
    li.rmargs_pa = 0x200100000ULL;
    check(libos_encode(&li, la) == NULL, "libos encode accepted");
    check(rd64(la) == init_arg_id("LOGINIT") && rd64(la + 16) == 0x10000 && la[24] == 1 && la[25] == 1, "entry 0 bytes");
    check(rd64(la + 5 * 32) == init_arg_id("LOGROOT") && rd64(la + 5 * 32 + 16) == 0x1000, "LOGROOT entry 4 KiB");
    check(rd64(la + 6 * 32) == init_arg_id("LOGKRNL"), "LOGKRNL entry seventh");
    check(rd64(la + 7 * 32) == init_arg_id("RMARGS") && rd64(la + 7 * 32 + 16) == 4096 && rd64(la + 7 * 32 + 8) == li.rmargs_pa, "RMARGS entry eighth");
    check(la[8 * 32] == 0 && la[8 * 32 + 24] == LIBOS_MEMORY_REGION_NONE, "ninth entry is NONE");
    check(libos_check(la, sizeof la, &li2) == NULL && memcmp(&li, &li2, sizeof li) == 0, "libos round trip");
    { libos_in b = li; b.log_pa[2] = 0x200020800ULL; expect_refusal(libos_encode(&b, la), "log buffer address zero or not 4 KiB aligned", "libos unaligned log"); }
    { libos_in b = li; b.rmargs_pa = 0; expect_refusal(libos_encode(&b, la), "RMARGS address zero or not 4 KiB aligned", "libos zero rmargs"); }
    check(libos_encode(&li, la) == NULL, "libos good block");
    expect_refusal(libos_check(la, 4095, NULL), "libos init arguments size not 4096", "libos short");
    { uint8_t t[4096]; memcpy(t, la, 4096); t[24] = LIBOS_MEMORY_REGION_RADIX3; expect_refusal(libos_check(t, 4096, NULL), "entry kind not CONTIGUOUS", "libos kind"); }
    { uint8_t t[4096]; memcpy(t, la, 4096); t[25] = LIBOS_MEMORY_REGION_LOC_FB; expect_refusal(libos_check(t, 4096, NULL), "entry loc not SYSMEM", "libos loc"); }
    { uint8_t t[4096]; memcpy(t, la, 4096); t[30] = 1; expect_refusal(libos_check(t, 4096, NULL), "entry padding must be 0", "libos pad"); }
    { uint8_t t[4096]; memcpy(t, la, 4096); wr64(t + 32, init_arg_id("LOGRM")); expect_refusal(libos_check(t, 4096, NULL), "log entry id or order wrong for GB10B", "libos order"); }
    { uint8_t t[4096]; memcpy(t, la, 4096); wr64(t + 5 * 32 + 16, 0x10000); expect_refusal(libos_check(t, 4096, NULL), "log entry size wrong for GB10B", "libos size"); }
    { uint8_t t[4096]; memcpy(t, la, 4096); wr64(t + 7 * 32, init_arg_id("RMCOV")); expect_refusal(libos_check(t, 4096, NULL), "entry after the logs is not RMARGS", "libos rmargs id"); }
    { uint8_t t[4096]; memcpy(t, la, 4096); wr64(t + 7 * 32 + 16, 88); expect_refusal(libos_check(t, 4096, NULL), "RMARGS size not 4096", "libos rmargs size"); }
    { uint8_t t[4096]; memcpy(t, la, 4096); wr64(t + 3 * 32 + 8, 0); expect_refusal(libos_check(t, 4096, NULL), "entry address zero or not 4 KiB aligned", "libos zero pa"); }
    { uint8_t t[4096]; memcpy(t, la, 4096); t[9 * 32 + 24] = 1; expect_refusal(libos_check(t, 4096, NULL), "bytes after the last entry must be 0", "libos trailing"); }

    /* 3. log buffer prefix */
    uint8_t lb[8 + 16 * 8]; size_t ln = 0;
    check(logbuf_prefix(0x200000000ULL, 0x10000, lb, sizeof lb, &ln) == NULL && ln == 8 + 16 * 8, "logbuf 64 KiB prefix length");
    check(rd64(lb) == 0 && rd64(lb + 8) == 0x200000000ULL && rd64(lb + 8 + 15 * 8) == 0x20000F000ULL, "logbuf put + PTEs");
    check(logbuf_prefix(0x200000000ULL, 0x1000, lb, sizeof lb, &ln) == NULL && ln == 16, "logbuf 4 KiB prefix");
    expect_refusal(logbuf_prefix(0x200000000ULL, 0x1800, lb, sizeof lb, &ln), "log buffer size zero or not a page multiple", "logbuf odd size");
    expect_refusal(logbuf_prefix(0x200000100ULL, 0x1000, lb, sizeof lb, &ln), "log buffer address zero or not 4 KiB aligned", "logbuf unaligned");
    expect_refusal(logbuf_prefix(0x200000000ULL, 0x10000, lb, 16, &ln), "output buffer too small", "logbuf small out");

    /* 4. RMARGS + message queue table */
    rmargs_in ri = { 0x300000000ULL, 0, 0x400000000ULL, GB10B_SYSMEM_HEAP }, ri2; uint8_t ra[PAGE_SZ];
    check(rmargs_encode(&ri, ra) == NULL, "rmargs encode accepted");
    check(rd64(ra) == 0x300000000ULL && rd32(ra + 8) == 129 && rd64(ra + 16) == 4096 && rd64(ra + 24) == 266240 && ra[48] == 1 && rd64(ra + 72) == 0x400000000ULL && rd64(ra + 80) == (512ULL << 20), "rmargs bytes");
    check(rmargs_check(ra, PAGE_SZ, &ri2) == NULL && memcmp(&ri, &ri2, sizeof ri) == 0, "rmargs round trip");
    { rmargs_in b = ri; b.mq_base_pa = 0x300000010ULL; expect_refusal(rmargs_encode(&b, ra), "message queue address zero or not 4 KiB aligned", "rmargs mq unaligned"); }
    { rmargs_in b = ri; b.sysmem_heap_size = 0x80000; expect_refusal(rmargs_encode(&b, ra), "sysmem heap size zero or not a MiB multiple", "rmargs heap size"); }
    { rmargs_in b = ri; b.sysmem_heap_pa = 0; expect_refusal(rmargs_encode(&b, ra), "sysmem heap address zero or not 4 KiB aligned", "rmargs heap pa"); }
    check(rmargs_encode(&ri, ra) == NULL, "rmargs good block");
    expect_refusal(rmargs_check(ra, 88, NULL), "RMARGS page size not 4096", "rmargs short");
    { uint8_t t[PAGE_SZ]; memcpy(t, ra, PAGE_SZ); wr32(t + 8, 128); expect_refusal(rmargs_check(t, PAGE_SZ, NULL), "pageTableEntryCount not 129", "rmargs ptes"); }
    { uint8_t t[PAGE_SZ]; memcpy(t, ra, PAGE_SZ); wr32(t + 12, 1); expect_refusal(rmargs_check(t, PAGE_SZ, NULL), "padding after pageTableEntryCount must be 0", "rmargs pad"); }
    { uint8_t t[PAGE_SZ]; memcpy(t, ra, PAGE_SZ); wr64(t + 16, 8192); expect_refusal(rmargs_check(t, PAGE_SZ, NULL), "cmdQueueOffset not 4096", "rmargs cmd"); }
    { uint8_t t[PAGE_SZ]; memcpy(t, ra, PAGE_SZ); wr64(t + 24, 4096); expect_refusal(rmargs_check(t, PAGE_SZ, NULL), "statQueueOffset not 266240", "rmargs stat"); }
    { uint8_t t[PAGE_SZ]; memcpy(t, ra, PAGE_SZ); t[40] = 1; expect_refusal(rmargs_check(t, PAGE_SZ, NULL), "suspend/resume arguments must be 0 on a normal boot", "rmargs sr"); }
    { uint8_t t[PAGE_SZ]; memcpy(t, ra, PAGE_SZ); t[48] = 0; expect_refusal(rmargs_check(t, PAGE_SZ, NULL), "bDmemStack not 1", "rmargs dmem"); }
    { uint8_t t[PAGE_SZ]; memcpy(t, ra, PAGE_SZ); wr64(t + 56, 1); expect_refusal(rmargs_check(t, PAGE_SZ, NULL), "profilerArgs must be 0", "rmargs profiler"); }
    { uint8_t t[PAGE_SZ]; memcpy(t, ra, PAGE_SZ); t[100] = 1; expect_refusal(rmargs_check(t, PAGE_SZ, NULL), "bytes after GSP_ARGUMENTS_CACHED must be 0", "rmargs trailing"); }
    uint8_t mt[PAGE_SZ];
    check(mqtable_encode(0x300000000ULL, mt) == NULL && rd64(mt) == 0x300000000ULL && rd64(mt + 128 * 8) == 0x300080000ULL && rd64(mt + 129 * 8) == 0, "mq table 129 PTEs, itself first");
    expect_refusal(mqtable_encode(0x300000008ULL, mt), "message queue address zero or not 4 KiB aligned", "mq table unaligned");

    /* 5. radix3 */
    radix3_layout rl;
    check(radix3_plan(1, &rl) == NULL && rl.npages[3] == 1 && rl.npages[2] == 1 && rl.npages[1] == 1 && rl.npages[0] == 1 && rl.pt_size == 3 * PAGE_SZ && rl.alloc_size == 4 * PAGE_SZ, "radix3 one byte");
    check(radix3_plan(512 * PAGE_SZ, &rl) == NULL && rl.npages[3] == 512 && rl.npages[2] == 1 && rl.pt_size == 3 * PAGE_SZ, "radix3 exactly 512 pages");
    check(radix3_plan(512 * PAGE_SZ + 1, &rl) == NULL && rl.npages[3] == 513 && rl.npages[2] == 2 && rl.npages[1] == 1 && rl.pt_size == 4 * PAGE_SZ && rl.offset[1] == PAGE_SZ && rl.offset[2] == 2 * PAGE_SZ && rl.offset[3] == 4 * PAGE_SZ, "radix3 513 pages");
    check(radix3_plan(75012080ULL, &rl) == NULL && rl.npages[3] == 18314 && rl.npages[2] == 36 && rl.npages[1] == 1 && rl.pt_size == 38 * PAGE_SZ, "radix3 for the pinned gsp_ga10x.bin size");
    expect_refusal(radix3_plan(0, &rl), "ELF size zero", "radix3 zero");
    expect_refusal(radix3_plan(((uint64_t)512 * 512 * 512 + 1) * PAGE_SZ, &rl), "ELF too large for a 3-level radix table", "radix3 too large");
    static uint8_t rt[4 * 4096]; size_t rn = 0;
    check(radix3_tables(512 * PAGE_SZ + 1, 0x500000000ULL, rt, sizeof rt, &rn) == NULL && rn == 4 * PAGE_SZ, "radix3 tables length");
    check(rd64(rt) == 0x500001000ULL && rd64(rt + 8) == 0, "level 0 -> level 1 page");
    check(rd64(rt + PAGE_SZ) == 0x500002000ULL && rd64(rt + PAGE_SZ + 8) == 0x500003000ULL && rd64(rt + PAGE_SZ + 16) == 0, "level 1 -> two level 2 pages");
    check(rd64(rt + 2 * PAGE_SZ) == 0x500004000ULL && rd64(rt + 2 * PAGE_SZ + 511 * 8) == 0x500004000ULL + 511 * PAGE_SZ && rd64(rt + 3 * PAGE_SZ) == 0x500004000ULL + 512 * PAGE_SZ && rd64(rt + 3 * PAGE_SZ + 8) == 0, "level 2 -> 513 data pages");
    expect_refusal(radix3_tables(PAGE_SZ, 0x500000100ULL, rt, sizeof rt, &rn), "radix3 base address zero or not 4 KiB aligned", "radix3 base unaligned");

    printf("CK_GSP_BOOT_ARGS_ENCODE_SELFTEST: %s (%d checks, %d failures)\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}

/* ---------- CLI ---------- */

static uint64_t parse_u64(const char *s, int *ok) { char *e; unsigned long long v = strtoull(s, &e, 0); if (*s == 0 || *e != 0) { *ok = 0; return 0; } return v; }
static int write_file(const char *path, const uint8_t *b, size_t n) { FILE *f = fopen(path, "wb"); if (!f) return -1; size_t w = fwrite(b, 1, n, f); fclose(f); return w == n ? 0 : -1; }
static int read_file(const char *path, uint8_t **b, size_t *n) {
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    fseek(f, 0, SEEK_END); long len = ftell(f); fseek(f, 0, SEEK_SET);
    if (len < 0 || len > (1 << 20)) { fclose(f); return -1; }
    *b = malloc((size_t)len + 1); if (!*b) { fclose(f); return -1; }
    *n = fread(*b, 1, (size_t)len, f); fclose(f); return *n == (size_t)len ? 0 : -1;
}
static int usage(void) {
    fprintf(stderr, "usage: ck_gsp_boot_args_encode selftest | layout\n"
        "  wprmeta --bootloader HEX --radix3 HEX --elf-size N --sig HEX --sig-size N [--heap N] [--crashq HEX --crashq-size N] [--scan-margin] [--out F]\n"
        "  check-wprmeta F | check-libos F | check-rmargs F\n"
        "  libos --log HEX x7 (LOGINIT LOGINTR LOGRM LOGMNOC LOGDBG LOGROOT LOGKRNL) --rmargs HEX [--out F]\n"
        "  logbuf --pa HEX --size N [--out F]\n"
        "  rmargs --mq HEX [--gpu N] --heap HEX --heap-size N [--out F]\n"
        "  mqtable --mq HEX [--out F]\n"
        "  radix3 --elf-size N [--base HEX --out F]\n");
    return 2;
}
static int refused(const char *why) { printf("REFUSED: %s\n", why); return 2; }
/* Write the block to --out when given; 0 on success, 2 (refused) on a write failure. */
static int emit(const char *out, const uint8_t *b, size_t n) {
    if (!out) return 0;
    if (write_file(out, b, n)) return refused("cannot write output");
    printf("wrote %s (%zu bytes)\n", out, n);
    return 0;
}
static void dump(const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x%s", b[i], (i % 32 == 31 || i + 1 == n) ? "\n" : ""); }

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    const char *mode = argv[1];
    if (!strcmp(mode, "selftest")) return selftest();
    if (!strcmp(mode, "layout")) {
        printf("GspFwWprMeta 256 bytes: magic 0 revision 8 sysmemAddrOfRadix3Elf 16 sizeOfRadix3Elf 24 sysmemAddrOfBootloader 32 sizeOfBootloader 40 bootloaderCodeOffset 48 bootloaderDataOffset 56 bootloaderManifestOffset 64 sysmemAddrOfSignature 72 sizeOfSignature 80 gspFwRsvdStart 88 nonWprHeapOffset 96 nonWprHeapSize 104 gspFwWprStart 112 gspFwHeapOffset 120 gspFwHeapSize 128 gspFwOffset 136 bootBinOffset 144 frtsOffset 152 frtsSize 160 gspFwWprEnd 168 fbSize 176 vgaWorkspaceOffset 184 vgaWorkspaceSize 192 bootCount 200 partitionRpc/crashQueue 208..239 gspFwHeapVfPartitionCount 240 flags 241 padding 242 pmuReservedSize 244 verified 248\n");
        printf("LibosMemoryRegionInitArgument 32 bytes: id8 0 pa 8 size 16 kind 24 loc 25; page holds 128 entries, GB10B uses 8\n");
        printf("GSP_ARGUMENTS_CACHED 88 bytes: sharedMemPhysAddr 0 pageTableEntryCount 8 cmdQueueOffset 16 statQueueOffset 24 sr.oldLevel 32 sr.flags 36 sr.bInPMTransition 40 gpuInstance 44 bDmemStack 48 profilerArgs 56 sysmemHeapArgs 72\n");
        printf("GB10B constants: bootloader 196608 code 0xb000 data 0xa00 manifest 0x0; heap 0x%llx (133 MiB) in [88,280] MiB; frts 0; nonWprHeap 0; sysmem heap default 512 MiB; mq cmd 0x40000 stat 0x40000 ptes 129 table 4096; logs LOGINIT LOGINTR LOGRM LOGMNOC LOGDBG(64K each) LOGROOT(4K) LOGKRNL(64K) then RMARGS(4K)\n", (unsigned long long)GB10B_FW_HEAP_SIZE);
        return 0;
    }
    const char *out = NULL; int ok = 1;
    uint64_t v[16] = {0}; int nlog = 0; uint64_t logs[GB10B_LOG_COUNT] = {0}; int scan = 0; unsigned gpu = 0;
    enum { A_BL, A_R3, A_ELF, A_SIG, A_SIGS, A_HEAP, A_CQ, A_CQS, A_RM, A_PA, A_SZ, A_MQ, A_HEAPPA, A_HEAPSZ, A_BASE };
    static const char *names[] = {"--bootloader", "--radix3", "--elf-size", "--sig", "--sig-size", "--heap", "--crashq", "--crashq-size", "--rmargs", "--pa", "--size", "--mq", "--heap", "--heap-size", "--base"};
    int is_rmargs = !strcmp(mode, "rmargs");
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--out") && i + 1 < argc) { out = argv[++i]; continue; }
        if (!strcmp(argv[i], "--scan-margin")) { scan = 1; continue; }
        if (!strcmp(argv[i], "--gpu") && i + 1 < argc) { gpu = (unsigned)parse_u64(argv[++i], &ok); continue; }
        if (!strcmp(argv[i], "--log") && i + 1 < argc) { if (nlog < (int)GB10B_LOG_COUNT) logs[nlog++] = parse_u64(argv[++i], &ok); else return refused("more than 7 --log values"); continue; }
        int hit = 0;
        for (int k = 0; k < 15 && i + 1 < argc; k++) {
            if (!strcmp(argv[i], names[k])) {
                if (k == A_HEAP && is_rmargs) k = A_HEAPPA;   /* rmargs: --heap is the sysmem heap address */
                v[k] = parse_u64(argv[++i], &ok); hit = 1; break;
            }
        }
        if (!hit) { if (argv[i][0] == '-') return usage(); }
        if (!ok) return refused("bad number");
    }
    if (!strcmp(mode, "wprmeta")) {
        wpr_in w = { v[A_BL], v[A_R3], v[A_ELF], v[A_SIG], v[A_SIGS], v[A_HEAP], v[A_CQ], (uint32_t)v[A_CQS], scan };
        uint8_t m[256]; const char *e = wpr_encode(&w, m); if (e) return refused(e);
        printf("wprmeta ok heap=0x%llx\n", (unsigned long long)rd64(m + 128)); dump(m, 256);
        return emit(out, m, 256);
    }
    if (!strcmp(mode, "libos")) {
        if (nlog != (int)GB10B_LOG_COUNT) return refused("need exactly 7 --log values");
        libos_in li; memcpy(li.log_pa, logs, sizeof logs); li.rmargs_pa = v[A_RM];
        uint8_t la[4096]; const char *e = libos_encode(&li, la); if (e) return refused(e);
        printf("libos ok entries=%u\n", GB10B_LIBOS_ENTRIES); dump(la, GB10B_LIBOS_ENTRIES * 32);
        return emit(out, la, 4096);
    }
    if (!strcmp(mode, "logbuf")) {
        static uint8_t lb[8 + 4096]; size_t ln = 0; const char *e = logbuf_prefix(v[A_PA], v[A_SZ], lb, sizeof lb, &ln); if (e) return refused(e);
        printf("logbuf ok prefix=%zu bytes pages=%llu\n", ln, (unsigned long long)(v[A_SZ] / PAGE_SZ)); dump(lb, ln > 64 ? 64 : ln);
        return emit(out, lb, ln);
    }
    if (is_rmargs) {
        rmargs_in ri = { v[A_MQ], gpu, v[A_HEAPPA], v[A_HEAPSZ] ? v[A_HEAPSZ] : GB10B_SYSMEM_HEAP };
        uint8_t ra[PAGE_SZ]; const char *e = rmargs_encode(&ri, ra); if (e) return refused(e);
        printf("rmargs ok\n"); dump(ra, 88);
        return emit(out, ra, PAGE_SZ);
    }
    if (!strcmp(mode, "mqtable")) {
        uint8_t mt[PAGE_SZ]; const char *e = mqtable_encode(v[A_MQ], mt); if (e) return refused(e);
        printf("mqtable ok ptes=%u cmd=0x%llx stat=0x%llx\n", MQ_NUM_PTES, (unsigned long long)(v[A_MQ] + MQ_PAGE_TABLE_SIZE), (unsigned long long)(v[A_MQ] + MQ_PAGE_TABLE_SIZE + MQ_CMD_QUEUE_SIZE)); dump(mt, 64);
        return emit(out, mt, PAGE_SZ);
    }
    if (!strcmp(mode, "radix3")) {
        radix3_layout l; const char *e = radix3_plan(v[A_ELF], &l); if (e) return refused(e);
        printf("radix3 ok data_pages=%llu l2_pages=%llu l1_pages=%llu l0_pages=1 table_bytes=%llu alloc_bytes=%llu data_offset=0x%llx\n",
               (unsigned long long)l.npages[3], (unsigned long long)l.npages[2], (unsigned long long)l.npages[1], (unsigned long long)l.pt_size, (unsigned long long)l.alloc_size, (unsigned long long)l.offset[3]);
        if (v[A_BASE]) {
            uint8_t *rt = malloc(l.pt_size); size_t rn = 0; if (!rt) return refused("out of memory");
            e = radix3_tables(v[A_ELF], v[A_BASE], rt, l.pt_size, &rn); if (e) { free(rt); return refused(e); }
            int rc = emit(out, rt, rn);
            free(rt);
            if (rc) return rc;
        }
        return 0;
    }
    if (!strncmp(mode, "check-", 6)) {
        if (argc < 3) return usage();
        uint8_t *b; size_t n; if (read_file(argv[2], &b, &n)) return refused("cannot read file");
        const char *e = !strcmp(mode, "check-wprmeta") ? wpr_check(b, n, NULL) : !strcmp(mode, "check-libos") ? libos_check(b, n, NULL) : !strcmp(mode, "check-rmargs") ? rmargs_check(b, n, NULL) : "unknown check";
        free(b);
        if (e) return refused(e);
        printf("%s: OK\n", mode); return 0;
    }
    return usage();
}
