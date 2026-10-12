/* ck_gsp_cot_encode -- host tool: byte-exact encoder, decoder and refusal
 * tests for the message the pinned Linux driver (nvidia-open 580.173.02)
 * sends to SEC2 to boot the GSP first-stage image (GSP-FMC) on the GB10
 * (aienos#286 cut C/D host work: "parsers and refusal tests for firmware
 * metadata. No loading"). docs/GB10_FIRMWARE_INVENTORY.md section 10 is the
 * report this tool backs. Nothing here touches a device.
 *
 * Wire format, every line from open-gpu-kernel-modules tag 580.173.02:
 *   - Transport: NVDM (NVIDIA Data Model) over MCTP over the SEC2 EMEM
 *     channel 0, 1024 bytes (src/nvidia/arch/nvalloc/common/inc/fsp/
 *     fsp_emem_channels.h:9-11; kernel_sec2_gb10b.c:36-41, :322-333).
 *   - A packet is two header dwords then the payload (kernel_sec2.c:50-52,
 *     :305-325). Dword 0 is the MCTP transport header (fsp_mctp_format.h:
 *     8-16: SOM bit 31, EOM bit 30, SEQ 29:28, TO 27, TAG 26:24, SEID 23:16,
 *     DEID 15:8, RSVD 7:4, VERSION 3:0); the driver sets only SOM, EOM,
 *     SEID and SEQ (kernel_sec2.c:319-321; kern_fsp_gh100.c:319-322).
 *     Dword 1 is the NVDM message header (fsp_mctp_format.h:17-22:
 *     TYPE 6:0 = 0x7e vendor-PCI, IC bit 7 = 0, VENDOR_ID 23:8 = 0x10de,
 *     NVDM_TYPE 31:24; kernel_sec2_gb10b.c:391-402).
 *   - The boot message is NVDM_TYPE_COT = 0x14 (fsp_nvdm_format.h:14) and
 *     the GB10B SEID is 0 for every type (g_kernel_sec2_nvoc.c:879-888,
 *     g_kernel_sec2_nvoc.h:907-909). The driver sends it as one packet
 *     (payload <= 1016 bytes; kernel_sec2.c:305-308) and never sends a
 *     second command on this channel (kernel_sec2_gb10b.c:719-722).
 *   - Payload: NVDM_PAYLOAD_COT, packed, 860 bytes (src/nvidia/inc/kernel/
 *     gpu/fsp/kern_fsp_cot_payload.h:12-29): version u16, size u16,
 *     gspFmcSysmemOffset u64, frtsSysmemOffset u64, frtsSysmemSize u32,
 *     frtsVidmemOffset u64, frtsVidmemSize u32, hash384 48 B, publicKey
 *     384 B, signature 384 B, gspBootArgsSysmemOffset u64. GB10B uses
 *     version 1 (g_kernel_sec2_nvoc.c:478-482), size = 860
 *     (kernel_sec2_gb10b.c:580-581), signature and key sizes 384
 *     (g_kernel_sec2_nvoc.c:472-476). The driver zero-fills the payload and
 *     sets only gspFmcSysmemOffset, frtsSysmemSize (= the GSP-FMC image
 *     size, sic), hash384, signature, publicKey and gspBootArgsSysmemOffset
 *     (kernel_sec2_gb10b.c:507-532, :578); frtsSysmemOffset and the two
 *     frtsVidmem fields stay 0.
 *   - After the packet is written at EMEM offset 0 with auto-increment,
 *     QUEUE_HEAD = 0 and QUEUE_TAIL = padded size - 4 (kernel_sec2_gb10b.c:
 *     700-732); SEC2 sets HEAD = TAIL when it has taken the packet
 *     (:344-356) and MAILBOX0 leaves 0xc001cafe when the command is handled
 *     (:285-297).
 *   - Boot arguments the payload points at: GSP_FMC_BOOT_PARAMS
 *     (src/nvidia/arch/nvalloc/common/inc/gsp/gspifpub.h), natural C layout
 *     (not packed), 88 bytes on the AArch64 LP64 ABI the driver and this
 *     host share; filled by kgspSetupGspFmcArgs_GH100
 *     (kernel_gsp_gh100.c:415-470): descriptor = GspFwWprMeta (256 bytes,
 *     gsp_fw_wpr_meta.h) on a fresh boot, bIsGspRmBoot = true, bootArgs =
 *     the libos init arguments, SPDM and flush fields only with CC.
 *
 * Refusals this tool enforces when encoding or decoding (reason strings are
 * the test oracle): zero or unaligned image address, address beyond the DMA
 * window, zero image size, hash/key/signature length not 48/384/384, zero
 * boot-args address, payload version or size field wrong, non-zero
 * reserved FRTS fields, payload that does not fit one packet, header dwords
 * that are not the single-packet COT shape, packet length not a dword
 * multiple, DMA target out of range, descriptor size not 256, boot flag
 * not set.
 *
 * INFERRED (not a driver check): the image address must be 4 KiB aligned
 * (the driver maps NV_ALIGN_UP(size, 0x1000) bytes of page-granular system
 * memory, kernel_sec2_gb10b.c:489-495) and every system address must fit
 * the 41-bit DMA window /proc/driver/nvidia/gpus reports for this GPU
 * (--dma-bits overrides).
 *
 *   ck_gsp_cot_encode selftest     layout, golden headers, round trips,
 *                                  every mutation and truncation refused
 *   ck_gsp_cot_encode layout       print the two layouts as "field offset size"
 *   ck_gsp_cot_encode encode --fmc-addr HEX --fmc-size N --hash FILE
 *        --key FILE --sig FILE --bootargs-addr HEX [--dma-bits N] [--out FILE]
 *                                  build the packet; prints header words,
 *                                  sizes, tail offset and SHA-256
 * Hosted C, no outside libraries (SHA-256 is the kernel's own, native/argus).
 * Never part of an image. No Python. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

/* ---- constants from the driver (SOURCE lines in the header comment) ---- */
#define EMEM_CHANNEL_BYTES 1024u
#define PACKET_HEADER_BYTES 8u
#define PACKET_PAYLOAD_CAP (EMEM_CHANNEL_BYTES - PACKET_HEADER_BYTES)
#define NVDM_TYPE_COT 0x14u
#define MCTP_MSG_TYPE_VENDOR_PCI 0x7eu
#define MCTP_VENDOR_ID_NV 0x10deu
#define COT_VERSION_GB10B 1u
#define COT_HASH_BYTES 48u
#define COT_KEY_BYTES 384u
#define COT_SIG_BYTES 384u
#define COT_PAYLOAD_BYTES 860u
#define COT_PACKET_BYTES (PACKET_HEADER_BYTES + COT_PAYLOAD_BYTES) /* 868 */
#define FMC_PARAMS_BYTES 88u
#define WPR_META_BYTES 256u
#define DMA_BITS_DEFAULT 41u
#define GSP_DMA_TARGET_COUNT 3u

/* NVDM_PAYLOAD_COT offsets (packed). */
#define COT_OFF_VERSION 0u
#define COT_OFF_SIZE 2u
#define COT_OFF_FMC_ADDR 4u
#define COT_OFF_FRTS_SYSMEM_OFF 12u
#define COT_OFF_FRTS_SYSMEM_SIZE 20u
#define COT_OFF_FRTS_VIDMEM_OFF 24u
#define COT_OFF_FRTS_VIDMEM_SIZE 32u
#define COT_OFF_HASH 36u
#define COT_OFF_KEY 84u
#define COT_OFF_SIG 468u
#define COT_OFF_BOOTARGS_ADDR 852u

/* GSP_FMC_BOOT_PARAMS offsets (natural layout, LP64). */
#define FMC_OFF_REGKEYS 0u
#define FMC_OFF_BOOT_TARGET 8u
#define FMC_OFF_BOOT_DESC_SIZE 12u
#define FMC_OFF_BOOT_DESC_OFFSET 16u
#define FMC_OFF_BOOT_WPR_OFFSET 24u
#define FMC_OFF_BOOT_WPR_SIZE 32u
#define FMC_OFF_BOOT_IS_GSP_RM 36u
#define FMC_OFF_RM_TARGET 40u
#define FMC_OFF_RM_BOOTARGS 48u
#define FMC_OFF_SPDM_TARGET 56u
#define FMC_OFF_SPDM_PAYLOAD_OFF 64u
#define FMC_OFF_SPDM_PAYLOAD_SIZE 72u
#define FMC_OFF_FLUSH_LO 80u
#define FMC_OFF_FLUSH_HI 84u

/* Mirrors of the driver's declarations, used only to check the offsets
 * above against the compiler's own layout at self-test time. */
#pragma pack(1)
typedef struct {
    uint16_t version;
    uint16_t size;
    uint64_t gspFmcSysmemOffset;
    uint64_t frtsSysmemOffset;
    uint32_t frtsSysmemSize;
    uint64_t frtsVidmemOffset;
    uint32_t frtsVidmemSize;
    uint32_t hash384[12];
    uint32_t publicKey[96];
    uint32_t signature[96];
    uint64_t gspBootArgsSysmemOffset;
} mirror_cot_payload;
#pragma pack()
typedef enum { M_TARGET_A, M_TARGET_B, M_TARGET_C, M_TARGET_COUNT } mirror_dma_target;
typedef struct { uint32_t regkeys; } mirror_init_params;
typedef struct {
    mirror_dma_target target;
    uint32_t gspRmDescSize;
    uint64_t gspRmDescOffset;
    uint64_t wprCarveoutOffset;
    uint32_t wprCarveoutSize;
    uint8_t bIsGspRmBoot;
} mirror_acr_params;
typedef struct { mirror_dma_target target; uint64_t bootArgsOffset; } mirror_rm_params;
typedef struct { mirror_dma_target target; uint64_t payloadBufferOffset; uint32_t payloadBufferSize; } mirror_spdm_params;
typedef struct { uint32_t flushSysmemAddrValLo; uint32_t flushSysmemAddrValHi; } mirror_mem_params;
typedef struct {
    mirror_init_params initParams;
    mirror_acr_params bootGspRmParams;
    mirror_rm_params gspRmParams;
    mirror_spdm_params gspSpdmParams;
    mirror_mem_params gspRmMemParams;
} mirror_fmc_boot_params;

/* ---- inputs and results ---- */
typedef struct {
    uint64_t fmc_sysmem_addr;
    uint32_t fmc_size;
    const uint8_t *hash; size_t hash_len;
    const uint8_t *key; size_t key_len;
    const uint8_t *sig; size_t sig_len;
    uint64_t bootargs_sysmem_addr;
    unsigned dma_bits; /* 0 = DMA_BITS_DEFAULT */
} cot_inputs;

typedef struct {
    uint32_t regkeys;
    uint32_t desc_target;
    uint32_t desc_size;
    uint64_t desc_offset;
    uint64_t wpr_carveout_offset;
    uint32_t wpr_carveout_size;
    uint8_t is_gsp_rm_boot;
    uint32_t bootargs_target;
    uint64_t bootargs_offset;
    uint32_t spdm_target;
    uint64_t spdm_payload_offset;
    uint32_t spdm_payload_size;
    uint32_t flush_lo, flush_hi;
    unsigned dma_bits;
} fmc_inputs;

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get32(const uint8_t *p) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint64_t get64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }

static int addr_ok(uint64_t a, unsigned dma_bits, int need_page_align, const char **why, const char *what) {
    if (dma_bits == 0) dma_bits = DMA_BITS_DEFAULT;
    if (a == 0) { *why = "zero address"; return 0; }
    if (dma_bits < 64 && (a >> dma_bits) != 0) { *why = "address beyond the DMA window"; return 0; }
    if (need_page_align && (a & 0xfffu) != 0) { *why = "image address not 4 KiB aligned"; return 0; }
    (void)what;
    return 1;
}

/* ---- headers ---- */
int cot_mctp_header(unsigned som, unsigned eom, unsigned seid, unsigned seq, uint32_t *out, const char **why) {
    if (som > 1 || eom > 1) { *why = "som/eom not a bit"; return -1; }
    if (seid > 0xff) { *why = "seid out of range"; return -1; }
    if (seq > 3) { *why = "seq out of range"; return -1; }
    *out = ((uint32_t)som << 31) | ((uint32_t)eom << 30) | ((uint32_t)seq << 28) | ((uint32_t)seid << 16);
    return 0;
}
int cot_nvdm_header(unsigned nvdm_type, uint32_t *out, const char **why) {
    if (nvdm_type > 0xff) { *why = "nvdm type out of range"; return -1; }
    *out = MCTP_MSG_TYPE_VENDOR_PCI | (MCTP_VENDOR_ID_NV << 8) | ((uint32_t)nvdm_type << 24);
    return 0;
}

/* ---- NVDM_PAYLOAD_COT version 1 ---- */
int cot_payload_encode(const cot_inputs *in, uint8_t out[COT_PAYLOAD_BYTES], const char **why) {
    if (!in || !out) { *why = "null argument"; return -1; }
    if (!addr_ok(in->fmc_sysmem_addr, in->dma_bits, 1, why, "fmc")) return -1;
    if (in->fmc_size == 0) { *why = "zero image size"; return -1; }
    if (!in->hash || in->hash_len != COT_HASH_BYTES) { *why = "hash length not 48"; return -1; }
    if (!in->key || in->key_len != COT_KEY_BYTES) { *why = "public key length not 384"; return -1; }
    if (!in->sig || in->sig_len != COT_SIG_BYTES) { *why = "signature length not 384"; return -1; }
    if (!addr_ok(in->bootargs_sysmem_addr, in->dma_bits, 0, why, "bootargs")) return -1;
    memset(out, 0, COT_PAYLOAD_BYTES);
    put16(out + COT_OFF_VERSION, COT_VERSION_GB10B);
    put16(out + COT_OFF_SIZE, COT_PAYLOAD_BYTES);
    put64(out + COT_OFF_FMC_ADDR, in->fmc_sysmem_addr);
    put32(out + COT_OFF_FRTS_SYSMEM_SIZE, in->fmc_size);
    memcpy(out + COT_OFF_HASH, in->hash, COT_HASH_BYTES);
    memcpy(out + COT_OFF_KEY, in->key, COT_KEY_BYTES);
    memcpy(out + COT_OFF_SIG, in->sig, COT_SIG_BYTES);
    put64(out + COT_OFF_BOOTARGS_ADDR, in->bootargs_sysmem_addr);
    return 0;
}
/* Decode and re-check. On success the hash/key/sig pointers point into buf. */
int cot_payload_decode(const uint8_t *buf, size_t len, cot_inputs *out, unsigned dma_bits, const char **why) {
    if (!buf || !out) { *why = "null argument"; return -1; }
    if (len != COT_PAYLOAD_BYTES) { *why = "payload length not 860"; return -1; }
    if (get16(buf + COT_OFF_VERSION) != COT_VERSION_GB10B) { *why = "payload version not 1"; return -1; }
    if (get16(buf + COT_OFF_SIZE) != COT_PAYLOAD_BYTES) { *why = "payload size field not 860"; return -1; }
    if (get64(buf + COT_OFF_FRTS_SYSMEM_OFF) != 0) { *why = "frtsSysmemOffset not zero"; return -1; }
    if (get64(buf + COT_OFF_FRTS_VIDMEM_OFF) != 0) { *why = "frtsVidmemOffset not zero"; return -1; }
    if (get32(buf + COT_OFF_FRTS_VIDMEM_SIZE) != 0) { *why = "frtsVidmemSize not zero"; return -1; }
    memset(out, 0, sizeof *out);
    out->fmc_sysmem_addr = get64(buf + COT_OFF_FMC_ADDR);
    out->fmc_size = get32(buf + COT_OFF_FRTS_SYSMEM_SIZE);
    out->hash = buf + COT_OFF_HASH; out->hash_len = COT_HASH_BYTES;
    out->key = buf + COT_OFF_KEY; out->key_len = COT_KEY_BYTES;
    out->sig = buf + COT_OFF_SIG; out->sig_len = COT_SIG_BYTES;
    out->bootargs_sysmem_addr = get64(buf + COT_OFF_BOOTARGS_ADDR);
    out->dma_bits = dma_bits;
    if (!addr_ok(out->fmc_sysmem_addr, dma_bits, 1, why, "fmc")) return -1;
    if (out->fmc_size == 0) { *why = "zero image size"; return -1; }
    if (!addr_ok(out->bootargs_sysmem_addr, dma_bits, 0, why, "bootargs")) return -1;
    return 0;
}

/* ---- one EMEM packet ---- */
int cot_packet_encode(const uint8_t *payload, size_t len, unsigned nvdm_type, uint8_t out[EMEM_CHANNEL_BYTES],
                      size_t *out_len, uint32_t *tail_offset, const char **why) {
    uint32_t h0, h1;
    if (!payload || !out || !out_len || !tail_offset) { *why = "null argument"; return -1; }
    if (len == 0) { *why = "empty payload"; return -1; }
    if (len > PACKET_PAYLOAD_CAP) { *why = "payload does not fit one packet"; return -1; }
    if (cot_mctp_header(1, 1, 0, 0, &h0, why) != 0) return -1;
    if (cot_nvdm_header(nvdm_type, &h1, why) != 0) return -1;
    memset(out, 0, EMEM_CHANNEL_BYTES);
    put32(out, h0);
    put32(out + 4, h1);
    memcpy(out + PACKET_HEADER_BYTES, payload, len);
    *out_len = (PACKET_HEADER_BYTES + len + 3u) & ~3u; /* NV_ALIGN_UP(size, 4) */
    *tail_offset = (uint32_t)(*out_len - 4u);           /* TAIL = last dword written */
    return 0;
}
/* Accepts exactly the single-packet COT shape. payload_out points into buf. */
int cot_packet_decode(const uint8_t *buf, size_t len, const uint8_t **payload_out, size_t *payload_len, const char **why) {
    uint32_t h0, h1, want;
    if (!buf || !payload_out || !payload_len) { *why = "null argument"; return -1; }
    if (len < PACKET_HEADER_BYTES + 1) { *why = "packet shorter than the headers"; return -1; }
    if (len > EMEM_CHANNEL_BYTES) { *why = "packet larger than the channel"; return -1; }
    if ((len & 3u) != 0) { *why = "packet length not a dword multiple"; return -1; }
    h0 = get32(buf); h1 = get32(buf + 4);
    if ((h0 >> 31) != 1) { *why = "SOM not set"; return -1; }
    if (((h0 >> 30) & 1u) != 1) { *why = "EOM not set"; return -1; }
    if (((h0 >> 28) & 3u) != 0) { *why = "seq not zero"; return -1; }
    if (((h0 >> 16) & 0xffu) != 0) { *why = "seid not zero"; return -1; }
    if ((h0 & 0x0fffffffu) != 0) { *why = "mctp reserved bits set"; return -1; }
    cot_nvdm_header(NVDM_TYPE_COT, &want, why);
    if (h1 != want) {
        if ((h1 & 0x7fu) != MCTP_MSG_TYPE_VENDOR_PCI) { *why = "nvdm msg type not vendor-pci"; return -1; }
        if (((h1 >> 8) & 0xffffu) != MCTP_VENDOR_ID_NV) { *why = "nvdm vendor id not nvidia"; return -1; }
        if ((h1 >> 24) != NVDM_TYPE_COT) { *why = "nvdm type not COT"; return -1; }
        *why = "nvdm IC bit set"; return -1;
    }
    *payload_out = buf + PACKET_HEADER_BYTES;
    *payload_len = len - PACKET_HEADER_BYTES;
    return 0;
}

/* ---- GSP_FMC_BOOT_PARAMS ---- */
int fmc_params_encode(const fmc_inputs *in, uint8_t out[FMC_PARAMS_BYTES], const char **why) {
    if (!in || !out) { *why = "null argument"; return -1; }
    if (in->desc_target >= GSP_DMA_TARGET_COUNT) { *why = "descriptor DMA target out of range"; return -1; }
    if (in->desc_size != WPR_META_BYTES) { *why = "descriptor size not 256"; return -1; }
    if (!addr_ok(in->desc_offset, in->dma_bits, 0, why, "desc")) return -1;
    if (in->is_gsp_rm_boot != 1) { *why = "bIsGspRmBoot not set"; return -1; }
    if (in->bootargs_target >= GSP_DMA_TARGET_COUNT) { *why = "boot-args DMA target out of range"; return -1; }
    if (!addr_ok(in->bootargs_offset, in->dma_bits, 0, why, "bootargs")) return -1;
    if (in->spdm_target >= GSP_DMA_TARGET_COUNT) { *why = "SPDM DMA target out of range"; return -1; }
    memset(out, 0, FMC_PARAMS_BYTES);
    put32(out + FMC_OFF_REGKEYS, in->regkeys);
    put32(out + FMC_OFF_BOOT_TARGET, in->desc_target);
    put32(out + FMC_OFF_BOOT_DESC_SIZE, in->desc_size);
    put64(out + FMC_OFF_BOOT_DESC_OFFSET, in->desc_offset);
    put64(out + FMC_OFF_BOOT_WPR_OFFSET, in->wpr_carveout_offset);
    put32(out + FMC_OFF_BOOT_WPR_SIZE, in->wpr_carveout_size);
    out[FMC_OFF_BOOT_IS_GSP_RM] = in->is_gsp_rm_boot;
    put32(out + FMC_OFF_RM_TARGET, in->bootargs_target);
    put64(out + FMC_OFF_RM_BOOTARGS, in->bootargs_offset);
    put32(out + FMC_OFF_SPDM_TARGET, in->spdm_target);
    put64(out + FMC_OFF_SPDM_PAYLOAD_OFF, in->spdm_payload_offset);
    put32(out + FMC_OFF_SPDM_PAYLOAD_SIZE, in->spdm_payload_size);
    put32(out + FMC_OFF_FLUSH_LO, in->flush_lo);
    put32(out + FMC_OFF_FLUSH_HI, in->flush_hi);
    return 0;
}
int fmc_params_decode(const uint8_t *buf, size_t len, fmc_inputs *out, unsigned dma_bits, const char **why) {
    if (!buf || !out) { *why = "null argument"; return -1; }
    if (len != FMC_PARAMS_BYTES) { *why = "params length not 88"; return -1; }
    memset(out, 0, sizeof *out);
    out->regkeys = get32(buf + FMC_OFF_REGKEYS);
    out->desc_target = get32(buf + FMC_OFF_BOOT_TARGET);
    out->desc_size = get32(buf + FMC_OFF_BOOT_DESC_SIZE);
    out->desc_offset = get64(buf + FMC_OFF_BOOT_DESC_OFFSET);
    out->wpr_carveout_offset = get64(buf + FMC_OFF_BOOT_WPR_OFFSET);
    out->wpr_carveout_size = get32(buf + FMC_OFF_BOOT_WPR_SIZE);
    out->is_gsp_rm_boot = buf[FMC_OFF_BOOT_IS_GSP_RM];
    out->bootargs_target = get32(buf + FMC_OFF_RM_TARGET);
    out->bootargs_offset = get64(buf + FMC_OFF_RM_BOOTARGS);
    out->spdm_target = get32(buf + FMC_OFF_SPDM_TARGET);
    out->spdm_payload_offset = get64(buf + FMC_OFF_SPDM_PAYLOAD_OFF);
    out->spdm_payload_size = get32(buf + FMC_OFF_SPDM_PAYLOAD_SIZE);
    out->flush_lo = get32(buf + FMC_OFF_FLUSH_LO);
    out->flush_hi = get32(buf + FMC_OFF_FLUSH_HI);
    out->dma_bits = dma_bits;
    /* padding bytes must be zero: 4..7, 37..39, 44..47, 60..63, 76..79 */
    for (size_t i = 0; i < len; i++) {
        int pad = (i >= 4 && i < 8) || (i >= 37 && i < 40) || (i >= 44 && i < 48) || (i >= 60 && i < 64) || (i >= 76 && i < 80);
        if (pad && buf[i] != 0) { *why = "padding byte not zero"; return -1; }
    }
    uint8_t re[FMC_PARAMS_BYTES];
    if (fmc_params_encode(out, re, why) != 0) return -1;
    if (memcmp(re, buf, FMC_PARAMS_BYTES) != 0) { *why = "re-encode differs"; return -1; }
    return 0;
}

/* ---- self-test ---- */
static int fails;
static void check(int ok, const char *what) {
    printf("  %s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}
static void expect_refused(int rc, const char *why, const char *want, const char *what) {
    int ok = rc != 0 && why && strcmp(why, want) == 0;
    printf("  %s refused: %s", ok ? "ok  " : "FAIL", what);
    if (!ok) printf(" (rc=%d why=%s want=%s)", rc, why ? why : "(null)", want);
    printf("\n");
    if (!ok) fails++;
}

static int selftest(void) {
    const char *why = "";
    printf("CK_GSP_COT_ENCODE_SELFTEST: begin\n");

    /* 1. layouts against the compiler's own view of the mirrored structs */
    check(sizeof(mirror_cot_payload) == COT_PAYLOAD_BYTES, "NVDM_PAYLOAD_COT is 860 bytes");
    check(offsetof(mirror_cot_payload, version) == COT_OFF_VERSION &&
          offsetof(mirror_cot_payload, size) == COT_OFF_SIZE &&
          offsetof(mirror_cot_payload, gspFmcSysmemOffset) == COT_OFF_FMC_ADDR &&
          offsetof(mirror_cot_payload, frtsSysmemOffset) == COT_OFF_FRTS_SYSMEM_OFF &&
          offsetof(mirror_cot_payload, frtsSysmemSize) == COT_OFF_FRTS_SYSMEM_SIZE &&
          offsetof(mirror_cot_payload, frtsVidmemOffset) == COT_OFF_FRTS_VIDMEM_OFF &&
          offsetof(mirror_cot_payload, frtsVidmemSize) == COT_OFF_FRTS_VIDMEM_SIZE &&
          offsetof(mirror_cot_payload, hash384) == COT_OFF_HASH &&
          offsetof(mirror_cot_payload, publicKey) == COT_OFF_KEY &&
          offsetof(mirror_cot_payload, signature) == COT_OFF_SIG &&
          offsetof(mirror_cot_payload, gspBootArgsSysmemOffset) == COT_OFF_BOOTARGS_ADDR,
          "NVDM_PAYLOAD_COT field offsets");
    check(sizeof(mirror_fmc_boot_params) == FMC_PARAMS_BYTES && sizeof(mirror_dma_target) == 4, "GSP_FMC_BOOT_PARAMS is 88 bytes");
    check(offsetof(mirror_fmc_boot_params, initParams) == FMC_OFF_REGKEYS &&
          offsetof(mirror_fmc_boot_params, bootGspRmParams) == FMC_OFF_BOOT_TARGET &&
          offsetof(mirror_fmc_boot_params, bootGspRmParams.gspRmDescSize) == FMC_OFF_BOOT_DESC_SIZE &&
          offsetof(mirror_fmc_boot_params, bootGspRmParams.gspRmDescOffset) == FMC_OFF_BOOT_DESC_OFFSET &&
          offsetof(mirror_fmc_boot_params, bootGspRmParams.wprCarveoutOffset) == FMC_OFF_BOOT_WPR_OFFSET &&
          offsetof(mirror_fmc_boot_params, bootGspRmParams.wprCarveoutSize) == FMC_OFF_BOOT_WPR_SIZE &&
          offsetof(mirror_fmc_boot_params, bootGspRmParams.bIsGspRmBoot) == FMC_OFF_BOOT_IS_GSP_RM &&
          offsetof(mirror_fmc_boot_params, gspRmParams) == FMC_OFF_RM_TARGET &&
          offsetof(mirror_fmc_boot_params, gspRmParams.bootArgsOffset) == FMC_OFF_RM_BOOTARGS &&
          offsetof(mirror_fmc_boot_params, gspSpdmParams) == FMC_OFF_SPDM_TARGET &&
          offsetof(mirror_fmc_boot_params, gspSpdmParams.payloadBufferOffset) == FMC_OFF_SPDM_PAYLOAD_OFF &&
          offsetof(mirror_fmc_boot_params, gspSpdmParams.payloadBufferSize) == FMC_OFF_SPDM_PAYLOAD_SIZE &&
          offsetof(mirror_fmc_boot_params, gspRmMemParams) == FMC_OFF_FLUSH_LO &&
          offsetof(mirror_fmc_boot_params, gspRmMemParams.flushSysmemAddrValHi) == FMC_OFF_FLUSH_HI,
          "GSP_FMC_BOOT_PARAMS field offsets");

    /* 2. golden header words */
    uint32_t h;
    check(cot_mctp_header(1, 1, 0, 0, &h, &why) == 0 && h == 0xC0000000u, "MCTP first+last packet, seid 0, seq 0 = 0xC0000000");
    check(cot_mctp_header(0, 1, 0, 3, &h, &why) == 0 && h == 0x70000000u, "MCTP last continuation seq 3 = 0x70000000");
    check(cot_mctp_header(0, 0, 0, 1, &h, &why) == 0 && h == 0x10000000u, "MCTP middle packet seq 1 = 0x10000000");
    check(cot_mctp_header(1, 1, 0x2a, 0, &h, &why) == 0 && h == 0xC02A0000u, "MCTP seid lands in bits 23:16");
    check(cot_nvdm_header(NVDM_TYPE_COT, &h, &why) == 0 && h == 0x1410DE7Eu, "NVDM header for COT = 0x1410DE7E");
    expect_refused(cot_mctp_header(1, 1, 0, 4, &h, &why), why, "seq out of range", "mctp seq 4");
    expect_refused(cot_mctp_header(2, 1, 0, 0, &h, &why), why, "som/eom not a bit", "mctp som 2");
    expect_refused(cot_mctp_header(1, 1, 256, 0, &h, &why), why, "seid out of range", "mctp seid 256");
    expect_refused(cot_nvdm_header(256, &h, &why), why, "nvdm type out of range", "nvdm type 256");

    /* 3. payload round trip */
    static uint8_t hash[COT_HASH_BYTES], key[COT_KEY_BYTES], sig[COT_SIG_BYTES];
    for (unsigned i = 0; i < COT_HASH_BYTES; i++) hash[i] = (uint8_t)(0x10 + i);
    for (unsigned i = 0; i < COT_KEY_BYTES; i++) key[i] = (uint8_t)(0x20 + i);
    for (unsigned i = 0; i < COT_SIG_BYTES; i++) sig[i] = (uint8_t)(0x30 + i);
    cot_inputs in = { 0x0000012345670000ull, 195912u, hash, COT_HASH_BYTES, key, COT_KEY_BYTES, sig, COT_SIG_BYTES, 0x00000123456a0000ull, 0 };
    uint8_t pl[COT_PAYLOAD_BYTES], pkt[EMEM_CHANNEL_BYTES];
    size_t pkt_len = 0; uint32_t tail = 0;
    check(cot_payload_encode(&in, pl, &why) == 0, "payload encodes");
    check(get16(pl) == 1 && get16(pl + 2) == 860, "payload version 1 size 860");
    check(get64(pl + COT_OFF_FMC_ADDR) == in.fmc_sysmem_addr && get32(pl + COT_OFF_FRTS_SYSMEM_SIZE) == in.fmc_size, "image address and size in place");
    check(memcmp(pl + COT_OFF_HASH, hash, 48) == 0 && memcmp(pl + COT_OFF_KEY, key, 384) == 0 && memcmp(pl + COT_OFF_SIG, sig, 384) == 0, "hash, key, signature in place");
    check(get64(pl + COT_OFF_BOOTARGS_ADDR) == in.bootargs_sysmem_addr, "boot-args address in place");
    { int zero = 1; for (unsigned i = COT_OFF_FRTS_SYSMEM_OFF; i < COT_OFF_HASH; i++) if (i < COT_OFF_FRTS_SYSMEM_SIZE || i >= COT_OFF_FRTS_VIDMEM_OFF) zero &= pl[i] == 0; check(zero, "reserved FRTS fields zero"); }
    cot_inputs back;
    check(cot_payload_decode(pl, sizeof pl, &back, 0, &why) == 0 && back.fmc_sysmem_addr == in.fmc_sysmem_addr && back.fmc_size == in.fmc_size &&
          back.bootargs_sysmem_addr == in.bootargs_sysmem_addr && memcmp(back.hash, hash, 48) == 0 && memcmp(back.key, key, 384) == 0 && memcmp(back.sig, sig, 384) == 0,
          "payload decodes to the same fields");
    check(cot_packet_encode(pl, sizeof pl, NVDM_TYPE_COT, pkt, &pkt_len, &tail, &why) == 0 && pkt_len == COT_PACKET_BYTES && tail == COT_PACKET_BYTES - 4u,
          "packet is 868 bytes, tail dword offset 864");
    check(get32(pkt) == 0xC0000000u && get32(pkt + 4) == 0x1410DE7Eu && memcmp(pkt + 8, pl, sizeof pl) == 0, "packet = headers + payload");
    { const uint8_t *p; size_t n; check(cot_packet_decode(pkt, pkt_len, &p, &n, &why) == 0 && n == COT_PAYLOAD_BYTES && memcmp(p, pl, n) == 0, "packet decodes"); }
    { uint8_t one[3] = {1, 2, 3}; size_t n; uint32_t t; check(cot_packet_encode(one, 3, NVDM_TYPE_COT, pkt, &n, &t, &why) == 0 && n == 12 && t == 8, "3-byte payload pads to 12, tail 8"); }

    /* 4. payload encode refusals, one field at a time */
    cot_inputs m;
    m = in; m.fmc_sysmem_addr = 0; expect_refused(cot_payload_encode(&m, pl, &why), why, "zero address", "image address 0");
    m = in; m.fmc_sysmem_addr = 0x12345670800ull; expect_refused(cot_payload_encode(&m, pl, &why), why, "image address not 4 KiB aligned", "image address unaligned");
    m = in; m.fmc_sysmem_addr = 1ull << 41; expect_refused(cot_payload_encode(&m, pl, &why), why, "address beyond the DMA window", "image address at 2^41");
    m = in; m.fmc_sysmem_addr = 1ull << 41; m.dma_bits = 42; check(cot_payload_encode(&m, pl, &why) == 0, "2^41 accepted with --dma-bits 42");
    m = in; m.fmc_size = 0; expect_refused(cot_payload_encode(&m, pl, &why), why, "zero image size", "image size 0");
    m = in; m.hash_len = 47; expect_refused(cot_payload_encode(&m, pl, &why), why, "hash length not 48", "hash 47 bytes");
    m = in; m.hash = NULL; expect_refused(cot_payload_encode(&m, pl, &why), why, "hash length not 48", "hash null");
    m = in; m.key_len = 385; expect_refused(cot_payload_encode(&m, pl, &why), why, "public key length not 384", "key 385 bytes");
    m = in; m.sig_len = 0; expect_refused(cot_payload_encode(&m, pl, &why), why, "signature length not 384", "signature empty");
    m = in; m.bootargs_sysmem_addr = 0; expect_refused(cot_payload_encode(&m, pl, &why), why, "zero address", "boot-args address 0");
    m = in; m.bootargs_sysmem_addr = 1ull << 41; expect_refused(cot_payload_encode(&m, pl, &why), why, "address beyond the DMA window", "boot-args at 2^41");
    expect_refused(cot_payload_encode(NULL, pl, &why), why, "null argument", "null inputs");

    /* 5. payload decode refusals */
    uint8_t d[COT_PAYLOAD_BYTES];
    cot_payload_encode(&in, pl, &why);
#define MUT(setup, want, what) do { memcpy(d, pl, sizeof d); setup; expect_refused(cot_payload_decode(d, sizeof d, &back, 0, &why), why, want, what); } while (0)
    expect_refused(cot_payload_decode(pl, 859, &back, 0, &why), why, "payload length not 860", "payload 859 bytes");
    expect_refused(cot_payload_decode(pl, 861, &back, 0, &why), why, "payload length not 860", "payload 861 bytes");
    MUT(put16(d, 2), "payload version not 1", "version 2");
    MUT(put16(d, 0), "payload version not 1", "version 0");
    MUT(put16(d + 2, 859), "payload size field not 860", "size field 859");
    MUT(put64(d + COT_OFF_FRTS_SYSMEM_OFF, 0x1000), "frtsSysmemOffset not zero", "frtsSysmemOffset set");
    MUT(put64(d + COT_OFF_FRTS_VIDMEM_OFF, 1), "frtsVidmemOffset not zero", "frtsVidmemOffset set");
    MUT(put32(d + COT_OFF_FRTS_VIDMEM_SIZE, 1), "frtsVidmemSize not zero", "frtsVidmemSize set");
    MUT(put64(d + COT_OFF_FMC_ADDR, 0), "zero address", "decoded image address 0");
    MUT(put64(d + COT_OFF_FMC_ADDR, 0x1010), "image address not 4 KiB aligned", "decoded image address unaligned");
    MUT(put64(d + COT_OFF_FMC_ADDR, 1ull << 41), "address beyond the DMA window", "decoded image address at 2^41");
    MUT(put32(d + COT_OFF_FRTS_SYSMEM_SIZE, 0), "zero image size", "decoded image size 0");
    MUT(put64(d + COT_OFF_BOOTARGS_ADDR, 0), "zero address", "decoded boot-args 0");
#undef MUT

    /* 6. packet refusals */
    cot_packet_encode(pl, sizeof pl, NVDM_TYPE_COT, pkt, &pkt_len, &tail, &why);
    { uint8_t big[PACKET_PAYLOAD_CAP + 1]; size_t n; uint32_t t; memset(big, 0, sizeof big);
      expect_refused(cot_packet_encode(big, sizeof big, NVDM_TYPE_COT, pkt, &n, &t, &why), why, "payload does not fit one packet", "payload 1017 bytes");
      check(cot_packet_encode(big, PACKET_PAYLOAD_CAP, NVDM_TYPE_COT, pkt, &n, &t, &why) == 0 && n == 1024 && t == 1020, "payload 1016 bytes fills the channel exactly");
      expect_refused(cot_packet_encode(big, 0, NVDM_TYPE_COT, pkt, &n, &t, &why), why, "empty payload", "payload 0 bytes");
      cot_packet_encode(pl, sizeof pl, NVDM_TYPE_COT, pkt, &pkt_len, &tail, &why); }
    uint8_t q[EMEM_CHANNEL_BYTES]; const uint8_t *p; size_t n;
#define PMUT(setup, want, what) do { memcpy(q, pkt, sizeof q); setup; expect_refused(cot_packet_decode(q, pkt_len, &p, &n, &why), why, want, what); } while (0)
    PMUT(put32(q, 0x40000000u), "SOM not set", "SOM cleared");
    PMUT(put32(q, 0x80000000u), "EOM not set", "EOM cleared");
    PMUT(put32(q, 0xD0000000u), "seq not zero", "seq 1");
    PMUT(put32(q, 0xC0050000u), "seid not zero", "seid 5");
    PMUT(put32(q, 0xC8000000u), "mctp reserved bits set", "TO bit set");
    PMUT(put32(q, 0xC0000001u), "mctp reserved bits set", "version nibble set");
    PMUT(put32(q + 4, 0x1510DE7Eu), "nvdm type not COT", "nvdm type 0x15 (FSP_RESPONSE)");
    PMUT(put32(q + 4, 0x1410DF7Eu), "nvdm vendor id not nvidia", "vendor id off by one");
    PMUT(put32(q + 4, 0x1410DE7Fu), "nvdm msg type not vendor-pci", "msg type 0x7f");
    PMUT(put32(q + 4, 0x1410DEFEu), "nvdm IC bit set", "IC bit set");
#undef PMUT
    expect_refused(cot_packet_decode(pkt, pkt_len - 1, &p, &n, &why), why, "packet length not a dword multiple", "packet 867 bytes");
    expect_refused(cot_packet_decode(pkt, 1028, &p, &n, &why), why, "packet larger than the channel", "packet 1028 bytes");
    { int all = 1; for (size_t t = 0; t < PACKET_HEADER_BYTES + 1; t++) { if (cot_packet_decode(pkt, t, &p, &n, &why) == 0) all = 0; }
      check(all, "every truncation 0..8 refused"); }
    { const uint8_t *pp; size_t nn; cot_packet_decode(pkt, pkt_len, &pp, &nn, &why);
      expect_refused(cot_payload_decode(pp, nn - 4, &back, 0, &why), why, "payload length not 860", "packet with a short payload"); }

    /* 7. FMC boot params round trip and refusals */
    fmc_inputs f = { 0, 1, WPR_META_BYTES, 0x0000012345680000ull, 0, 0, 1, 1, 0x00000123456c0000ull, 0, 0, 0, 0, 0, 0 };
    uint8_t fb[FMC_PARAMS_BYTES]; fmc_inputs fback;
    check(fmc_params_encode(&f, fb, &why) == 0, "FMC params encode");
    check(get32(fb + FMC_OFF_BOOT_TARGET) == 1 && get32(fb + FMC_OFF_BOOT_DESC_SIZE) == 256 && get64(fb + FMC_OFF_BOOT_DESC_OFFSET) == f.desc_offset &&
          fb[FMC_OFF_BOOT_IS_GSP_RM] == 1 && get64(fb + FMC_OFF_RM_BOOTARGS) == f.bootargs_offset, "FMC params fields in place");
    check(fmc_params_decode(fb, sizeof fb, &fback, 0, &why) == 0 && fback.desc_offset == f.desc_offset && fback.bootargs_offset == f.bootargs_offset && fback.desc_target == 1, "FMC params decode");
    fmc_inputs g;
    g = f; g.desc_target = 3; expect_refused(fmc_params_encode(&g, fb, &why), why, "descriptor DMA target out of range", "desc target 3");
    g = f; g.desc_size = 255; expect_refused(fmc_params_encode(&g, fb, &why), why, "descriptor size not 256", "desc size 255");
    g = f; g.desc_offset = 0; expect_refused(fmc_params_encode(&g, fb, &why), why, "zero address", "desc offset 0");
    g = f; g.is_gsp_rm_boot = 0; expect_refused(fmc_params_encode(&g, fb, &why), why, "bIsGspRmBoot not set", "boot flag clear");
    g = f; g.bootargs_target = 3; expect_refused(fmc_params_encode(&g, fb, &why), why, "boot-args DMA target out of range", "boot-args target 3");
    g = f; g.bootargs_offset = 1ull << 41; expect_refused(fmc_params_encode(&g, fb, &why), why, "address beyond the DMA window", "boot-args at 2^41");
    g = f; g.spdm_target = 7; expect_refused(fmc_params_encode(&g, fb, &why), why, "SPDM DMA target out of range", "SPDM target 7");
    fmc_params_encode(&f, fb, &why);
    { uint8_t e[FMC_PARAMS_BYTES]; memcpy(e, fb, sizeof e); e[5] = 1; expect_refused(fmc_params_decode(e, sizeof e, &fback, 0, &why), why, "padding byte not zero", "padding byte 5 set");
      memcpy(e, fb, sizeof e); e[FMC_OFF_BOOT_IS_GSP_RM] = 0; expect_refused(fmc_params_decode(e, sizeof e, &fback, 0, &why), why, "bIsGspRmBoot not set", "decoded boot flag clear");
      memcpy(e, fb, sizeof e); put32(e + FMC_OFF_BOOT_DESC_SIZE, 512); expect_refused(fmc_params_decode(e, sizeof e, &fback, 0, &why), why, "descriptor size not 256", "decoded desc size 512");
      expect_refused(fmc_params_decode(fb, 87, &fback, 0, &why), why, "params length not 88", "params 87 bytes"); }

    printf("CK_GSP_COT_ENCODE_SELFTEST: %s (%d failures)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}

static void layout(void) {
    printf("NVDM_PAYLOAD_COT version 1, packed, %u bytes (kern_fsp_cot_payload.h:13-28)\n", COT_PAYLOAD_BYTES);
    printf("version %u 2\nsize %u 2\ngspFmcSysmemOffset %u 8\nfrtsSysmemOffset %u 8\nfrtsSysmemSize %u 4\nfrtsVidmemOffset %u 8\nfrtsVidmemSize %u 4\nhash384 %u 48\npublicKey %u 384\nsignature %u 384\ngspBootArgsSysmemOffset %u 8\n",
           COT_OFF_VERSION, COT_OFF_SIZE, COT_OFF_FMC_ADDR, COT_OFF_FRTS_SYSMEM_OFF, COT_OFF_FRTS_SYSMEM_SIZE, COT_OFF_FRTS_VIDMEM_OFF, COT_OFF_FRTS_VIDMEM_SIZE, COT_OFF_HASH, COT_OFF_KEY, COT_OFF_SIG, COT_OFF_BOOTARGS_ADDR);
    printf("packet: mctp 0xC0000000 at 0, nvdm 0x1410DE7E at 4, payload at 8, length %u, QUEUE_TAIL %u, QUEUE_HEAD 0\n", COT_PACKET_BYTES, COT_PACKET_BYTES - 4u);
    printf("GSP_FMC_BOOT_PARAMS natural layout, %u bytes (gspifpub.h)\n", FMC_PARAMS_BYTES);
    printf("initParams.regkeys %u 4\nbootGspRmParams.target %u 4\nbootGspRmParams.gspRmDescSize %u 4\nbootGspRmParams.gspRmDescOffset %u 8\nbootGspRmParams.wprCarveoutOffset %u 8\nbootGspRmParams.wprCarveoutSize %u 4\nbootGspRmParams.bIsGspRmBoot %u 1\ngspRmParams.target %u 4\ngspRmParams.bootArgsOffset %u 8\ngspSpdmParams.target %u 4\ngspSpdmParams.payloadBufferOffset %u 8\ngspSpdmParams.payloadBufferSize %u 4\ngspRmMemParams.flushSysmemAddrValLo %u 4\ngspRmMemParams.flushSysmemAddrValHi %u 4\n",
           FMC_OFF_REGKEYS, FMC_OFF_BOOT_TARGET, FMC_OFF_BOOT_DESC_SIZE, FMC_OFF_BOOT_DESC_OFFSET, FMC_OFF_BOOT_WPR_OFFSET, FMC_OFF_BOOT_WPR_SIZE, FMC_OFF_BOOT_IS_GSP_RM, FMC_OFF_RM_TARGET, FMC_OFF_RM_BOOTARGS, FMC_OFF_SPDM_TARGET, FMC_OFF_SPDM_PAYLOAD_OFF, FMC_OFF_SPDM_PAYLOAD_SIZE, FMC_OFF_FLUSH_LO, FMC_OFF_FLUSH_HI);
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    uint8_t *buf = malloc(4096);
    size_t cap = 4096, n = 0;
    if (!buf) { fclose(f); return NULL; }
    for (;;) {
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (n < cap) break;
        uint8_t *nb = realloc(buf, cap * 2);
        if (!nb) { free(buf); fclose(f); return NULL; }
        buf = nb; cap *= 2;
    }
    fclose(f);
    *len = n;
    return buf;
}

static int encode_cli(int argc, char **argv) {
    const char *hash_p = NULL, *key_p = NULL, *sig_p = NULL, *out_p = NULL, *why = "";
    cot_inputs in; memset(&in, 0, sizeof in);
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i], *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!v) { fprintf(stderr, "missing value for %s\n", a); return 2; }
        if (!strcmp(a, "--fmc-addr")) in.fmc_sysmem_addr = strtoull(v, NULL, 16);
        else if (!strcmp(a, "--fmc-size")) in.fmc_size = (uint32_t)strtoul(v, NULL, 0);
        else if (!strcmp(a, "--hash")) hash_p = v;
        else if (!strcmp(a, "--key")) key_p = v;
        else if (!strcmp(a, "--sig")) sig_p = v;
        else if (!strcmp(a, "--bootargs-addr")) in.bootargs_sysmem_addr = strtoull(v, NULL, 16);
        else if (!strcmp(a, "--dma-bits")) in.dma_bits = (unsigned)strtoul(v, NULL, 0);
        else if (!strcmp(a, "--out")) out_p = v;
        else { fprintf(stderr, "unknown option %s\n", a); return 2; }
        i++;
    }
    if (!hash_p || !key_p || !sig_p) { fprintf(stderr, "need --hash --key --sig\n"); return 2; }
    size_t hl = 0, kl = 0, sl = 0;
    uint8_t *hb = read_file(hash_p, &hl), *kb = read_file(key_p, &kl), *sb = read_file(sig_p, &sl);
    if (!hb || !kb || !sb) { fprintf(stderr, "cannot read an input file\n"); return 2; }
    in.hash = hb; in.hash_len = hl; in.key = kb; in.key_len = kl; in.sig = sb; in.sig_len = sl;
    uint8_t pl[COT_PAYLOAD_BYTES], pkt[EMEM_CHANNEL_BYTES];
    size_t n = 0; uint32_t tail = 0;
    if (cot_payload_encode(&in, pl, &why) != 0 || cot_packet_encode(pl, sizeof pl, NVDM_TYPE_COT, pkt, &n, &tail, &why) != 0) {
        printf("RESULT REFUSED %s\n", why);
        return 2;
    }
    uint8_t dg[32];
    sha256_hash(pkt, n, dg);
    printf("mctp_header 0x%08x\nnvdm_header 0x%08x\npayload_version %u\npayload_size %u\npacket_len %zu\nqueue_head 0\nqueue_tail %u\nfmc_addr 0x%llx\nfmc_size %u\nbootargs_addr 0x%llx\nsha256_packet ",
           get32(pkt), get32(pkt + 4), get16(pl), get16(pl + 2), n, tail, (unsigned long long)in.fmc_sysmem_addr, in.fmc_size, (unsigned long long)in.bootargs_sysmem_addr);
    for (int i = 0; i < 32; i++) printf("%02x", dg[i]);
    printf("\n");
    if (out_p) {
        FILE *f = fopen(out_p, "wb");
        if (!f || fwrite(pkt, 1, n, f) != n) { printf("RESULT REFUSED cannot write output\n"); if (f) fclose(f); return 2; }
        fclose(f);
    }
    printf("RESULT OK\n");
    free(hb); free(kb); free(sb);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "selftest")) return selftest();
    if (argc >= 2 && !strcmp(argv[1], "layout")) { layout(); return 0; }
    if (argc >= 2 && !strcmp(argv[1], "encode")) return encode_cli(argc, argv);
    fprintf(stderr, "usage: ck_gsp_cot_encode selftest | layout | encode --fmc-addr HEX --fmc-size N --hash F --key F --sig F --bootargs-addr HEX [--dma-bits N] [--out F]\n");
    return 2;
}
