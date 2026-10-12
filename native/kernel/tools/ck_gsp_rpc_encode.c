/* ck_gsp_rpc_encode -- host tool: byte-exact encoder, decoder and refusal
 * tests for the GSP-RM message queue (command queue, status queue, queue
 * element, RPC header, continuation records and the packed registry table)
 * exactly as the pinned Linux driver (nvidia-open 580.173.02) builds them
 * (aienos#286 cut C host work: "parsers and refusal tests for firmware
 * metadata. No loading"). docs/GB10_FIRMWARE_INVENTORY.md section 13 is the
 * report this tool backs. Nothing here touches a device.
 *
 * Every line below is from open-gpu-kernel-modules tag 580.173.02:
 *
 *  1. Shared queue library (src/nvidia/src/libraries/.../msgq.c, msgq_priv.h):
 *     msgqTxHeader 32 bytes {version, size, msgSize, msgCount, writePtr,
 *     flags, rxHdrOff, entryOff} written by the producer; msgqRxHeader
 *     4 bytes {readPtr} written by the consumer. MSGQ_VERSION 0.
 *     msgqTxCreate(size, msgSize, hdrAlign, entryAlign, flags):
 *       rxHdrOff = ALIGN_UP(32, 1<<hdrAlign)
 *       entryOff = ALIGN_UP(rxHdrOff + 4, 1<<entryAlign)
 *       refuse: msgSize < 16, msgSize > size, size < entryOff + msgSize
 *       msgCount = (size - entryOff) / msgSize, writePtr 0, txFree = msgCount-1
 *     msgqRxLink(size, msgSize) on the peer's header refuses (return codes):
 *       -2 msgSize < 16; -3 msgSize > size; -6 size < entryOff + msgSize;
 *       -7 size mismatch; -8 msgSize mismatch; -9 version != 0;
 *       -10 rxHdrOff < 32 or entryOff < our rxHdrOff + 4 or
 *           msgCount != (size - entryOff) / msgSize.
 *     SWAP_RX (flag 1) on both sides: each side's readPtr for incoming
 *     messages lives in its OWN backing store at its rxHdrOff.
 *     Ring arithmetic (msgqTxGetFreeSpace / msgqRxGetReadAvailable):
 *       free  = (readPtr + msgCount - writePtr - 1) mod msgCount
 *       avail = (writePtr + msgCount - readPtr) mod msgCount
 *     a pointer >= msgCount is corrupt: 0 free / 0 available.
 *
 *  2. The driver's queues (message_queue_cpu.c GspMsgQueuesInit, kernel_gsp
 *     tu102 queue setup): command queue 0x40000 bytes, status queue 0x40000
 *     bytes, both msgSize 4096 (GSP_MSG_QUEUE_ELEMENT_SIZE_MIN), hdrAlign 4
 *     (16 bytes), entryAlign 12 (4096), flags MSGQ_FLAGS_SWAP_RX. Hence
 *     rxHdrOff 32, entryOff 4096, msgCount 63, 62 usable slots.
 *
 *  3. GSP_MSG_QUEUE_ELEMENT (message_queue_priv.h:36-51): authTagBuffer[16],
 *     aadBuffer[16], u32 checkSum, u32 seqNum, u32 elemCount, then the RPC
 *     header aligned 8 at offset 48 (GSP_MSG_QUEUE_ELEMENT_HDR_SIZE 48);
 *     sizeof = 80. ELEMENT_SIZE_MIN 4096, MAX 16*4096 = 65536,
 *     BYTES_TO_ELEMENTS = ceil(bytes / 4096). RPC_SIZE_MAX = 65536-48 =
 *     65488 (pRpc->maxRpcSize, kernel_gsp.c).
 *
 *  4. rpc_message_header_v03_00 (g_rpc-message-header.h), 32 bytes:
 *     u32 header_version, signature, length, function, rpc_result,
 *     rpc_result_private, sequence, cpuRmGfid. rpcWriteCommonHeader
 *     (rpc_common.c): zero the buffer, header_version = MAJOR 3 << 24 |
 *     MINOR 0 << 16 (rpc_headers.h:56-59), signature 0x43505256
 *     ("VRPC" little-endian, rpc_headers.h:61), rpc_result and
 *     rpc_result_private = RPC_PENDING 0xFFFFFFFF, function, length = 32 +
 *     payload. sequence: synchronous RPCs get pRpc->sequence++, asynchronous
 *     (_issueRpcAsync, pSequence NULL) get 0 (kernel_gsp.c:395-406).
 *
 *  5. GspMsgQueueSendCommand (message_queue_cpu.c:440-600), no CC:
 *     msgLen = 48 + rpc.length; refuse msgLen < 80 or > 65536
 *     (NV_ERR_INVALID_PARAM_STRUCT); zero-pad to a multiple of 8;
 *     seqNum = txSeqNum (0 at init, ++ per accepted message); elemCount =
 *     ceil(msgLen/4096); checkSum = 0 then checkSum = _checkSum32(msgLen):
 *     XOR of every u64 word, then HI32 ^ LO32, so the finished element
 *     checksums to zero (message_queue_priv.h:112-124). Elements are copied
 *     4096 bytes at a time into successive ring slots, then submitted
 *     (msgqTxSubmitBuffers) and the doorbell NV_PGSP_QUEUE_HEAD(0) =
 *     0x110c00 is written 0 (dev_gsp_tu102.h:38, kernel_gsp_tu102.c
 *     kgspSetCmdQueueHead).
 *
 *  6. GspMsgQueueReceiveStatus (:600-720): read element 0 of the status
 *     ring, nElements = elemCount, copy all; checksum over 48 + rpc.length
 *     must be 0 (NV_ERR_INVALID_DATA); seqNum must equal rxSeqNum ("Bad
 *     sequence number": an older seqNum is consumed and the read retried,
 *     up to 3 times), then rxSeqNum++. kgspWaitForRmInitDone polls for
 *     NV_VGPU_MSG_EVENT_GSP_INIT_DONE (0x1001) with sequence 0 and requires
 *     rpc_result == NV_OK.
 *
 *  7. Large RPCs (_issueRpcLarge, rpc.c:2038-2130): first message carries
 *     the real function with length = min(total, 65488); each further chunk
 *     is a fresh header with function CONTINUATION_RECORD (71), length =
 *     32 + chunk, chunk <= 65488 - 32 = 65456 payload bytes.
 *
 *  8. SET_REGISTRY (function 73, rpcSetRegistry_v17_00, rpc.c ~10700 and
 *     RmPackageRegistry, arch/nvalloc/unix/src/registry.c:628-711) payload
 *     PACKED_REGISTRY_TABLE (g_os_nvoc.h:226-248): u32 size, u32
 *     numEntries, entries[] of {u32 nameOffset; u8 type; u32 data; u32
 *     length} (natural layout 16 bytes, entries at offset 8), then the
 *     string area: for each entry the NUL-terminated name, then for STRING
 *     (3) / BINARY (2) the value bytes with data = their offset; DWORD (1)
 *     keeps the value in data with length 4 and no bytes in the area. size =
 *     8 + 16*n + sum(namelen+1) + sum(value bytes); numEntries == n;
 *     a zero-length string/binary is skipped by the driver with a warning
 *     and this encoder refuses it. An empty registry is NV_WARN_NOTHING_TO_DO
 *     and the RPC is not sent.
 *
 *  9. GSP_SET_SYSTEM_INFO (function 72, rpcGspSetSystemInfo_v17_00,
 *     rpc.c:10493) payload GspSystemInfo (gsp_static_config.h:172-229):
 *     PCI/BAR physical addresses, PCI ids, chipset, ACPI method data,
 *     hypervisor/VF state, host page size. Its contents come from the real
 *     device and the native kernel's bus layer; this tool records the
 *     function number, the header rule and the size: 936 bytes under the
 *     natural LP64 layout (no pack pragma in gsp_static_config.h; nested
 *     BUSINFO 10 bytes (g_chipset_nvoc.h:220-227), ACPI_METHOD_DATA 676
 *     bytes = bValid + DOD 72 + JT 12 + MUX 580 + CAPS 8 with
 *     NV0073_CTRL_SYSTEM_ACPI_ID_MAP_MAX_DISPLAYS 16 (gpu_acpi_data.h:72-115,
 *     ctrl0073system.h:747), GSP_VF_INFO 40, GSP_PCIE_CONFIG_REG 4), so the
 *     RPC length is 32 + 936 = 968 and it fits one 4 KiB slot. The size was
 *     reproduced by compiling the struct text copied from those headers.
 *
 * Claim tags: every number above is DOCUMENTED (source lines). That the
 * GSP-RM firmware on GB10B accepts exactly these bytes without Linux present
 * is INFERRED (medium) until the first attended run.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MSGQ_VERSION            0u
#define MSGQ_FLAGS_SWAP_RX      1u
#define MSGQ_MSG_SIZE_MIN       16u
#define MSGQ_TX_HDR_SIZE        32u
#define MSGQ_RX_HDR_SIZE        4u
#define GSP_MQ_SIZE             0x40000u
#define GSP_MQ_MSG_SIZE         4096u
#define GSP_MQ_HDR_ALIGN        4u      /* 2^4 */
#define GSP_MQ_ENTRY_ALIGN      12u     /* 2^12 */
#define GSP_MQ_RXHDR_OFF        32u
#define GSP_MQ_ENTRY_OFF        4096u
#define GSP_MQ_MSG_COUNT        63u
#define ELEM_HDR_SIZE           48u
#define ELEM_STRUCT_SIZE        80u
#define ELEM_SIZE_MIN           4096u
#define ELEM_SIZE_MAX           65536u
#define RPC_HDR_SIZE            32u
#define RPC_SIZE_MAX            (ELEM_SIZE_MAX - ELEM_HDR_SIZE)      /* 65488 */
#define RPC_CONT_PAYLOAD_MAX    (RPC_SIZE_MAX - RPC_HDR_SIZE)        /* 65456 */
#define RPC_HEADER_VERSION      0x03000000u
#define RPC_SIGNATURE_VALID     0x43505256u
#define RPC_PENDING             0xFFFFFFFFu
#define RPC_RESULT_UNKNOWN_FN   0xFF100001u
#define RPC_RESULT_BAD_FORMAT   0xFF100002u
#define FN_NOP                  0u
#define FN_CONTINUATION_RECORD  71u
#define FN_GSP_SET_SYSTEM_INFO  72u
#define FN_SET_REGISTRY         73u
#define EV_GSP_INIT_DONE        0x1001u
#define EV_GSP_RUN_CPU_SEQUENCER 0x1002u
#define EV_RC_TRIGGERED         0x1004u
#define EV_GSP_LOCKDOWN_NOTICE  0x101cu
#define EV_GSP_POST_NOCAT_RECORD 0x1020u
#define NV_PGSP_QUEUE_HEAD_0    0x110c00u
#define GSP_SYSTEM_INFO_SIZE    936u
#define GSP_SYSTEM_INFO_RPC_LEN (RPC_HDR_SIZE + GSP_SYSTEM_INFO_SIZE)   /* 968 */
#define REG_TYPE_UNKNOWN 0u
#define REG_TYPE_DWORD   1u
#define REG_TYPE_BINARY  2u
#define REG_TYPE_STRING  3u
#define REG_TABLE_HDR    8u
#define REG_ENTRY_SIZE   16u

/* Compiler-checked layouts (natural alignment, LP64; same on aarch64 and the
 * x86-64 CI host). */
typedef struct { uint32_t version, size, msgSize, msgCount, writePtr, flags, rxHdrOff, entryOff; } msgq_tx_header;
typedef struct { uint32_t readPtr; } msgq_rx_header;
typedef struct { uint32_t header_version, signature, length, function, rpc_result, rpc_result_private, sequence, cpuRmGfid; } rpc_header;
typedef struct { uint8_t authTag[16], aad[16]; uint32_t checkSum, seqNum, elemCount; _Alignas(8) rpc_header rpc; } mq_element;
typedef struct { uint32_t nameOffset; uint8_t type; uint32_t data; uint32_t length; } packed_reg_entry;
typedef struct { uint32_t size, numEntries; } packed_reg_table_hdr;
_Static_assert(sizeof(msgq_tx_header) == MSGQ_TX_HDR_SIZE, "msgqTxHeader is 32 bytes");
_Static_assert(sizeof(msgq_rx_header) == MSGQ_RX_HDR_SIZE, "msgqRxHeader is 4 bytes");
_Static_assert(sizeof(rpc_header) == RPC_HDR_SIZE, "rpc_message_header_v is 32 bytes");
_Static_assert(offsetof(mq_element, rpc) == ELEM_HDR_SIZE, "rpc header at 48");
_Static_assert(sizeof(mq_element) == ELEM_STRUCT_SIZE, "GSP_MSG_QUEUE_ELEMENT is 80 bytes");
_Static_assert(sizeof(packed_reg_entry) == REG_ENTRY_SIZE, "PACKED_REGISTRY_ENTRY is 16 bytes");
_Static_assert(offsetof(packed_reg_entry, type) == 4 && offsetof(packed_reg_entry, data) == 8 && offsetof(packed_reg_entry, length) == 12, "entry field offsets");
_Static_assert(sizeof(packed_reg_table_hdr) == REG_TABLE_HDR, "PACKED_REGISTRY_TABLE entries at 8");

static uint64_t rd64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) { p[i] = (uint8_t)v; v >>= 8; } }
static uint32_t align_up(uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); }

/* ---- 1. queue headers ---- */
typedef struct { uint32_t size, msgSize, hdrAlign, entryAlign, flags; } mq_create_in;

/* msgqTxCreate rules; writes the 32-byte producer header. */
static const char *mq_tx_create(const mq_create_in *in, uint8_t out[MSGQ_TX_HDR_SIZE]) {
    if (in->msgSize < MSGQ_MSG_SIZE_MIN || in->msgSize > in->size) return "msgSize out of range";
    if (in->hdrAlign < 2 || in->hdrAlign > 31 || in->entryAlign < 2 || in->entryAlign > 31) return "alignment out of range";
    uint32_t rxHdrOff = align_up(MSGQ_TX_HDR_SIZE, 1u << in->hdrAlign);
    uint32_t entryOff = align_up(rxHdrOff + MSGQ_RX_HDR_SIZE, 1u << in->entryAlign);
    if (in->size < entryOff + in->msgSize) return "size too small for one entry";
    msgq_tx_header h = { MSGQ_VERSION, in->size, in->msgSize, (in->size - entryOff) / in->msgSize, 0, in->flags, rxHdrOff, entryOff };
    memcpy(out, &h, sizeof h);
    return NULL;
}

/* msgqRxLink checks on a peer header we read from shared memory. Returns the
 * driver's negative code as text so a log line can be matched. our_rxHdrOff
 * is our own header's rxHdrOff (the -10 rule compares against it). */
static const char *mq_rx_link_check(const uint8_t *b, size_t n, uint32_t size, uint32_t msgSize, uint32_t our_rxHdrOff, msgq_tx_header *out) {
    if (n < MSGQ_TX_HDR_SIZE) return "short header";
    if (msgSize < MSGQ_MSG_SIZE_MIN) return "-2 msgSize below 16";
    if (msgSize > size) return "-3 msgSize above size";
    msgq_tx_header h; memcpy(&h, b, sizeof h);
    if (size < h.entryOff + msgSize) return "-6 size below entryOff + msgSize";
    if (h.size != size) return "-7 size mismatch";
    if (h.msgSize != msgSize) return "-8 msgSize mismatch";
    if (h.version != MSGQ_VERSION) return "-9 version not 0";
    if (h.rxHdrOff < MSGQ_TX_HDR_SIZE || h.entryOff < our_rxHdrOff + MSGQ_RX_HDR_SIZE || h.msgCount != (size - h.entryOff) / msgSize) return "-10 offsets or msgCount inconsistent";
    if (h.writePtr >= h.msgCount) return "writePtr beyond msgCount";
    if (out) *out = h;
    return NULL;
}

static uint32_t ring_free(uint32_t readPtr, uint32_t writePtr, uint32_t msgCount) {
    if (readPtr >= msgCount || writePtr >= msgCount || msgCount == 0) return 0;
    return (readPtr + msgCount - writePtr - 1) % msgCount;
}
static uint32_t ring_avail(uint32_t readPtr, uint32_t writePtr, uint32_t msgCount) {
    if (readPtr >= msgCount || writePtr >= msgCount || msgCount == 0) return 0;
    return (writePtr + msgCount - readPtr) % msgCount;
}

/* ---- 2. RPC header + queue element ---- */
static uint32_t checksum32(const uint8_t *p, size_t len) {
    uint64_t x = 0;
    for (size_t i = 0; i < len; i += 8) x ^= rd64(p + i);
    return (uint32_t)(x >> 32) ^ (uint32_t)x;
}

typedef struct { uint32_t function, sequence, payload_len; const uint8_t *payload; uint32_t seqNum; } elem_in;

/* Build one message as the driver would place it in the ring: element header +
 * RPC header + payload, zero padded to elemCount*4096. out must hold 65536.
 * *msg_len gets the padded-to-8 message length used for the checksum. */
static const char *elem_encode(const elem_in *in, uint8_t *out, size_t cap, uint32_t *msg_len, uint32_t *elem_count) {
    if (in->payload_len > RPC_SIZE_MAX - RPC_HDR_SIZE) return "payload exceeds RPC_SIZE_MAX";
    uint32_t rpc_len = RPC_HDR_SIZE + in->payload_len;
    uint32_t msgLen = ELEM_HDR_SIZE + rpc_len;
    if (msgLen < ELEM_STRUCT_SIZE || msgLen > ELEM_SIZE_MAX) return "message length outside [80, 65536]";
    uint32_t nelem = (msgLen + ELEM_SIZE_MIN - 1) / ELEM_SIZE_MIN;
    if (cap < (size_t)nelem * ELEM_SIZE_MIN) return "output too small";
    memset(out, 0, (size_t)nelem * ELEM_SIZE_MIN);
    rpc_header h = { RPC_HEADER_VERSION, RPC_SIGNATURE_VALID, rpc_len, in->function, RPC_PENDING, RPC_PENDING, in->sequence, 0 };
    memcpy(out + ELEM_HDR_SIZE, &h, sizeof h);
    if (in->payload_len) memcpy(out + ELEM_HDR_SIZE + RPC_HDR_SIZE, in->payload, in->payload_len);
    wr32(out + 36, in->seqNum);
    wr32(out + 40, nelem);
    wr32(out + 32, 0);
    uint32_t padded = align_up(msgLen, 8);
    wr32(out + 32, checksum32(out, padded));
    if (msg_len) *msg_len = padded;
    if (elem_count) *elem_count = nelem;
    return NULL;
}

typedef struct { uint32_t checkSum, seqNum, elemCount; rpc_header rpc; uint32_t msgLen; } elem_view;

/* Receive-side validation (GspMsgQueueReceiveStatus + rpcRecvPoll checks). */
static const char *elem_check(const uint8_t *b, size_t n, uint32_t expect_seq, elem_view *out) {
    if (n < ELEM_STRUCT_SIZE) return "short element";
    elem_view v; v.checkSum = rd32(b + 32); v.seqNum = rd32(b + 36); v.elemCount = rd32(b + 40);
    memcpy(&v.rpc, b + ELEM_HDR_SIZE, sizeof v.rpc);
    if (v.rpc.signature != RPC_SIGNATURE_VALID) return "bad RPC signature";
    if (v.rpc.header_version != RPC_HEADER_VERSION) return "bad RPC header version";
    if (v.rpc.length < RPC_HDR_SIZE || v.rpc.length > RPC_SIZE_MAX) return "RPC length outside [32, 65488]";
    v.msgLen = ELEM_HDR_SIZE + v.rpc.length;
    if (v.elemCount == 0 || v.elemCount > ELEM_SIZE_MAX / ELEM_SIZE_MIN) return "elemCount outside [1, 16]";
    if (v.elemCount != (v.msgLen + ELEM_SIZE_MIN - 1) / ELEM_SIZE_MIN) return "elemCount does not match length";
    if (n < (size_t)align_up(v.msgLen, 8)) return "element shorter than its RPC length";
    if (checksum32(b, align_up(v.msgLen, 8)) != 0) return "checksum not zero";
    if (v.seqNum != expect_seq) return v.seqNum < expect_seq ? "old seqNum (driver consumes and retries)" : "seqNum ahead of expected";
    if (out) *out = v;
    return NULL;
}

/* ---- 3. continuation plan for a large RPC ---- */
typedef struct { uint32_t chunks; uint32_t first_len; uint32_t last_payload; } cont_plan;
static const char *cont_plan_for(uint32_t total_rpc_len, cont_plan *p) {
    if (total_rpc_len < RPC_HDR_SIZE) return "total below header";
    p->first_len = total_rpc_len < RPC_SIZE_MAX ? total_rpc_len : RPC_SIZE_MAX;
    uint32_t rem = total_rpc_len - p->first_len; p->chunks = 1; p->last_payload = 0;
    while (rem) { uint32_t c = rem < RPC_CONT_PAYLOAD_MAX ? rem : RPC_CONT_PAYLOAD_MAX; rem -= c; p->chunks++; p->last_payload = c; }
    return NULL;
}

/* ---- 4. packed registry table ---- */
typedef struct { const char *name; uint8_t type; uint32_t dword; const uint8_t *bytes; uint32_t len; } reg_in;

static const char *reg_encode(const reg_in *e, uint32_t n, uint8_t *out, size_t cap, uint32_t *size_out) {
    if (n == 0) return "empty registry (driver: NV_WARN_NOTHING_TO_DO, RPC not sent)";
    uint32_t size = REG_TABLE_HDR + REG_ENTRY_SIZE * n;
    for (uint32_t i = 0; i < n; i++) {
        if (!e[i].name || !e[i].name[0]) return "entry without a name";
        if (e[i].type == REG_TYPE_DWORD) { if (e[i].len) return "DWORD entry carries bytes"; }
        else if (e[i].type == REG_TYPE_STRING || e[i].type == REG_TYPE_BINARY) { if (e[i].len == 0) return "zero-length string/binary (driver would drop it)"; }
        else return "unknown entry type";
        size += (uint32_t)strlen(e[i].name) + 1 + e[i].len;
    }
    if (size > RPC_SIZE_MAX - RPC_HDR_SIZE) return "registry exceeds one RPC (driver would use continuation records)";
    if (cap < size) return "output too small";
    memset(out, 0, size);
    wr32(out, size); wr32(out + 4, n);
    uint32_t off = REG_TABLE_HDR + REG_ENTRY_SIZE * n;
    for (uint32_t i = 0; i < n; i++) {
        uint8_t *ent = out + REG_TABLE_HDR + REG_ENTRY_SIZE * i;
        uint32_t slen = (uint32_t)strlen(e[i].name) + 1;
        wr32(ent, off); memcpy(out + off, e[i].name, slen); off += slen;
        ent[4] = e[i].type;
        if (e[i].type == REG_TYPE_DWORD) { wr32(ent + 8, e[i].dword); wr32(ent + 12, 4); }
        else { wr32(ent + 8, off); wr32(ent + 12, e[i].len); memcpy(out + off, e[i].bytes, e[i].len); off += e[i].len; }
    }
    if (off != size) return "first/second pass mismatch";
    if (size_out) *size_out = size;
    return NULL;
}

static const char *reg_check(const uint8_t *b, size_t n, uint32_t *entries_out) {
    if (n < REG_TABLE_HDR) return "short table";
    uint32_t size = rd32(b), cnt = rd32(b + 4);
    if (size != n) return "size field does not match buffer";
    if (cnt == 0) return "no entries";
    if ((uint64_t)REG_TABLE_HDR + (uint64_t)REG_ENTRY_SIZE * cnt > size) return "entry table overruns size";
    uint32_t expect_off = REG_TABLE_HDR + REG_ENTRY_SIZE * cnt;
    for (uint32_t i = 0; i < cnt; i++) {
        const uint8_t *ent = b + REG_TABLE_HDR + REG_ENTRY_SIZE * i;
        uint32_t nameOff = rd32(ent), type = ent[4], data = rd32(ent + 8), len = rd32(ent + 12);
        if (ent[5] || ent[6] || ent[7]) return "entry padding not zero";
        if (nameOff != expect_off) return "name not packed in order";
        uint32_t k = nameOff; while (k < size && b[k]) k++;
        if (k >= size || k == nameOff) return "name not terminated or empty";
        expect_off = k + 1;
        if (type == REG_TYPE_DWORD) { if (len != 4) return "DWORD length not 4"; }
        else if (type == REG_TYPE_STRING || type == REG_TYPE_BINARY) {
            if (len == 0 || data != expect_off) return "string/binary data offset or length wrong";
            if ((uint64_t)data + len > size) return "value overruns size";
            expect_off += len;
        } else return "unknown entry type";
    }
    if (expect_off != size) return "trailing bytes or size short";
    if (entries_out) *entries_out = cnt;
    return NULL;
}

/* ---- self-test ---- */
static int checks, failures;
static void check(int ok, const char *what) { checks++; if (!ok) { failures++; printf("FAIL: %s\n", what); } }
static void expect_refusal(const char *got, const char *want, const char *what) {
    checks++; if (!got || strncmp(got, want, strlen(want))) { failures++; printf("FAIL: %s: got '%s' want '%s'\n", what, got ? got : "(accepted)", want); }
}

static int selftest(void) {
    /* 1. the driver's own queue geometry */
    mq_create_in q = { GSP_MQ_SIZE, GSP_MQ_MSG_SIZE, GSP_MQ_HDR_ALIGN, GSP_MQ_ENTRY_ALIGN, MSGQ_FLAGS_SWAP_RX };
    uint8_t th[MSGQ_TX_HDR_SIZE];
    check(mq_tx_create(&q, th) == NULL, "command queue header encodes");
    static const uint8_t golden_tx[32] = { 0,0,0,0, 0,0,4,0, 0,16,0,0, 63,0,0,0, 0,0,0,0, 1,0,0,0, 32,0,0,0, 0,16,0,0 };
    check(memcmp(th, golden_tx, 32) == 0, "golden msgqTxHeader for 256 KiB / 4096 / swap-rx");
    check(rd32(th + 12) == GSP_MQ_MSG_COUNT && rd32(th + 24) == GSP_MQ_RXHDR_OFF && rd32(th + 28) == GSP_MQ_ENTRY_OFF, "msgCount 63, rxHdrOff 32, entryOff 4096");
    mq_create_in bad = q; bad.msgSize = 8; expect_refusal(mq_tx_create(&bad, th), "msgSize out of range", "msgSize below 16 refused");
    bad = q; bad.msgSize = GSP_MQ_SIZE + 1; expect_refusal(mq_tx_create(&bad, th), "msgSize out of range", "msgSize above size refused");
    bad = q; bad.size = 4096; expect_refusal(mq_tx_create(&bad, th), "size too small", "size without room for an entry refused");
    bad = q; bad.hdrAlign = 1; expect_refusal(mq_tx_create(&bad, th), "alignment out of range", "hdrAlign below 2 refused");
    /* peer link checks against the same header (GSP builds its status queue identically) */
    msgq_tx_header peer;
    check(mq_rx_link_check(golden_tx, 32, GSP_MQ_SIZE, GSP_MQ_MSG_SIZE, GSP_MQ_RXHDR_OFF, &peer) == NULL && peer.msgCount == 63, "rxLink accepts the driver's header");
    expect_refusal(mq_rx_link_check(golden_tx, 32, GSP_MQ_SIZE, 8, 32, NULL), "-2", "rxLink msgSize < 16");
    expect_refusal(mq_rx_link_check(golden_tx, 32, 4096, 8192, 32, NULL), "-3", "rxLink msgSize > size");
    expect_refusal(mq_rx_link_check(golden_tx, 32, 4096, 4096, 32, NULL), "-6", "rxLink size < entryOff + msgSize");
    expect_refusal(mq_rx_link_check(golden_tx, 32, 0x80000, 4096, 32, NULL), "-7", "rxLink size mismatch");
    expect_refusal(mq_rx_link_check(golden_tx, 32, GSP_MQ_SIZE, 8192, 32, NULL), "-8", "rxLink msgSize mismatch");
    uint8_t mut[32]; memcpy(mut, golden_tx, 32); wr32(mut, 1); expect_refusal(mq_rx_link_check(mut, 32, GSP_MQ_SIZE, 4096, 32, NULL), "-9", "rxLink version != 0");
    memcpy(mut, golden_tx, 32); wr32(mut + 24, 16); expect_refusal(mq_rx_link_check(mut, 32, GSP_MQ_SIZE, 4096, 32, NULL), "-10", "rxLink rxHdrOff < 32");
    memcpy(mut, golden_tx, 32); wr32(mut + 12, 62); expect_refusal(mq_rx_link_check(mut, 32, GSP_MQ_SIZE, 4096, 32, NULL), "-10", "rxLink msgCount wrong");
    memcpy(mut, golden_tx, 32); wr32(mut + 16, 63); expect_refusal(mq_rx_link_check(mut, 32, GSP_MQ_SIZE, 4096, 32, NULL), "writePtr beyond", "writePtr >= msgCount refused");
    expect_refusal(mq_rx_link_check(golden_tx, 16, GSP_MQ_SIZE, 4096, 32, NULL), "short header", "short header refused");
    /* ring arithmetic */
    check(ring_free(0, 0, 63) == 62 && ring_avail(0, 0, 63) == 0, "empty ring: 62 free, 0 available");
    check(ring_free(0, 62, 63) == 0 && ring_avail(0, 62, 63) == 62, "full ring: 0 free, 62 available");
    check(ring_free(5, 3, 63) == 1 && ring_avail(5, 3, 63) == 61, "wrapped write behind read");
    check(ring_free(10, 20, 63) == 52 && ring_avail(10, 20, 63) == 10, "read behind write");
    check(ring_free(63, 0, 63) == 0 && ring_avail(0, 63, 63) == 0, "pointer at msgCount reads as corrupt: 0");
    check(ring_free(0, 0, 0) == 0, "msgCount 0 never divides");
    /* 2. one small RPC (NOP, sync sequence 7, queue seqNum 3) */
    static uint8_t el[ELEM_SIZE_MAX]; uint32_t ml = 0, ec = 0;
    elem_in e = { FN_NOP, 7, 0, NULL, 3 };
    check(elem_encode(&e, el, sizeof el, &ml, &ec) == NULL && ml == 80 && ec == 1, "NOP element: 80 bytes, 1 slot");
    check(rd32(el + 48) == RPC_HEADER_VERSION && rd32(el + 52) == RPC_SIGNATURE_VALID && rd32(el + 56) == 32 && rd32(el + 60) == FN_NOP, "RPC header words");
    check(rd32(el + 64) == RPC_PENDING && rd32(el + 68) == RPC_PENDING && rd32(el + 72) == 7 && rd32(el + 76) == 0, "pending results, sequence, gfid 0");
    check(rd32(el + 36) == 3 && rd32(el + 40) == 1, "element seqNum and elemCount");
    check(checksum32(el, 80) == 0, "finished element checksums to zero");
    for (int i = 0; i < 32; i++) check(el[i] == 0, "auth/aad bytes zero without CC");
    elem_view v;
    check(elem_check(el, 4096, 3, &v) == NULL && v.rpc.function == FN_NOP && v.msgLen == 80, "receive-side validation accepts it");
    expect_refusal(elem_check(el, 4096, 4, NULL), "old seqNum", "older seqNum flagged for consume-and-retry");
    expect_refusal(elem_check(el, 4096, 2, NULL), "seqNum ahead", "future seqNum refused");
    memcpy(mut, el, 32); uint8_t tmp[4096]; memcpy(tmp, el, 4096);
    tmp[70] ^= 1; expect_refusal(elem_check(tmp, 4096, 3, NULL), "checksum not zero", "flipped header bit breaks the checksum");
    memcpy(tmp, el, 4096); wr32(tmp + 52, 0x43505257); expect_refusal(elem_check(tmp, 4096, 3, NULL), "bad RPC signature", "signature mutation refused");
    memcpy(tmp, el, 4096); wr32(tmp + 48, 0x02000000); expect_refusal(elem_check(tmp, 4096, 3, NULL), "bad RPC header version", "version 2 refused");
    memcpy(tmp, el, 4096); wr32(tmp + 40, 2); expect_refusal(elem_check(tmp, 4096, 3, NULL), "elemCount does not match", "elemCount 2 for an 80-byte message refused");
    memcpy(tmp, el, 4096); wr32(tmp + 56, 16); expect_refusal(elem_check(tmp, 4096, 3, NULL), "RPC length outside", "length below header refused");
    expect_refusal(elem_check(el, 64, 3, NULL), "short element", "short buffer refused");
    /* 3. a payload that needs several ring slots, odd length to exercise the pad */
    static uint8_t pay[9000]; for (size_t i = 0; i < sizeof pay; i++) pay[i] = (uint8_t)(i * 7 + 1);
    e.function = FN_SET_REGISTRY; e.sequence = 0; e.payload_len = 9001 - 32; e.payload = pay; e.seqNum = 0;
    check(elem_encode(&e, el, sizeof el, &ml, &ec) == NULL && ec == 3 && ml == align_up(48 + 9001, 8), "9001-byte RPC: 3 slots, padded to 8");
    check(checksum32(el, ml) == 0 && el[48 + 9001] == 0 && el[48 + 9001 + 6] == 0, "zero padding after the message");
    check(elem_check(el, 3 * 4096, 0, &v) == NULL && v.elemCount == 3 && v.rpc.length == 9001, "multi-slot element validates");
    check(elem_check(el, 9056, 0, NULL) == NULL, "exactly the padded length suffices");
    expect_refusal(elem_check(el, 9048, 0, NULL), "element shorter", "buffer one word short refused");
    /* bounds */
    static uint8_t big[70000];
    e.payload = big; e.payload_len = RPC_SIZE_MAX - RPC_HDR_SIZE; check(elem_encode(&e, el, sizeof el, &ml, &ec) == NULL && ec == 16 && ml == ELEM_SIZE_MAX, "largest RPC: 65488 bytes in 16 slots");
    e.payload_len = RPC_SIZE_MAX - RPC_HDR_SIZE + 1; expect_refusal(elem_encode(&e, el, sizeof el, &ml, &ec), "payload exceeds", "65489 refused");
    e.payload_len = 0; expect_refusal(elem_encode(&e, el, 64, &ml, &ec), "output too small", "small output refused");
    /* 4. continuation plan */
    cont_plan cp;
    check(cont_plan_for(32, &cp) == NULL && cp.chunks == 1 && cp.first_len == 32, "header-only RPC: one message");
    check(cont_plan_for(RPC_SIZE_MAX, &cp) == NULL && cp.chunks == 1, "65488 fits in one message");
    check(cont_plan_for(RPC_SIZE_MAX + 1, &cp) == NULL && cp.chunks == 2 && cp.last_payload == 1, "65489: one continuation record of 1 byte");
    check(cont_plan_for(RPC_SIZE_MAX + RPC_CONT_PAYLOAD_MAX, &cp) == NULL && cp.chunks == 2 && cp.last_payload == RPC_CONT_PAYLOAD_MAX, "exactly one full continuation");
    check(cont_plan_for(RPC_SIZE_MAX + RPC_CONT_PAYLOAD_MAX + 1, &cp) == NULL && cp.chunks == 3 && cp.last_payload == 1, "third chunk starts at 65489+65456+1");
    expect_refusal(cont_plan_for(8, &cp), "total below header", "sub-header total refused");
    /* 5. registry table */
    static const uint8_t bin[3] = { 0xaa, 0xbb, 0xcc };
    reg_in regs[3] = { { "RmMsg", REG_TYPE_STRING, 0, (const uint8_t *)"abc", 3 }, { "EnableGpuFirmwareLogs", REG_TYPE_DWORD, 1, NULL, 0 }, { "Blob", REG_TYPE_BINARY, 0, bin, 3 } };
    static uint8_t rt[4096]; uint32_t rs = 0;
    check(reg_encode(regs, 3, rt, sizeof rt, &rs) == NULL, "three-entry registry encodes");
    /* 8 + 48 + ("RmMsg"6 + 3) + ("EnableGpuFirmwareLogs"22) + ("Blob"5 + 3) = 95 */
    check(rs == 95 && rd32(rt) == 95 && rd32(rt + 4) == 3, "size 95, numEntries 3");
    check(rd32(rt + 8) == 56 && rt[12] == REG_TYPE_STRING && rd32(rt + 16) == 62 && rd32(rt + 20) == 3 && memcmp(rt + 56, "RmMsg", 6) == 0 && memcmp(rt + 62, "abc", 3) == 0, "string entry: name at 56, value at 62");
    check(rd32(rt + 24) == 65 && rt[28] == REG_TYPE_DWORD && rd32(rt + 32) == 1 && rd32(rt + 36) == 4, "dword entry: name at 65, data 1, length 4");
    check(rd32(rt + 40) == 87 && rt[44] == REG_TYPE_BINARY && rd32(rt + 48) == 92 && rd32(rt + 52) == 3 && memcmp(rt + 92, bin, 3) == 0, "binary entry: name at 87, value at 92");
    check(rt[13] == 0 && rt[14] == 0 && rt[15] == 0, "entry padding bytes zero");
    uint32_t cnt = 0; check(reg_check(rt, rs, &cnt) == NULL && cnt == 3, "registry check accepts its own output");
    uint8_t rm[4096]; memcpy(rm, rt, rs); wr32(rm, 96); expect_refusal(reg_check(rm, rs, NULL), "size field", "size field mismatch refused");
    memcpy(rm, rt, rs); wr32(rm + 4, 0); expect_refusal(reg_check(rm, rs, NULL), "no entries", "zero entries refused");
    memcpy(rm, rt, rs); wr32(rm + 4, 7); expect_refusal(reg_check(rm, rs, NULL), "entry table overruns", "numEntries beyond size refused");
    memcpy(rm, rt, rs); rm[13] = 1; expect_refusal(reg_check(rm, rs, NULL), "entry padding", "dirty padding refused");
    memcpy(rm, rt, rs); wr32(rm + 8, 57); expect_refusal(reg_check(rm, rs, NULL), "name not packed", "out-of-order name refused");
    memcpy(rm, rt, rs); rm[61] = 'x'; expect_refusal(reg_check(rm, rs, NULL), "string/binary data offset", "unterminated name is caught by the value offset");
    memcpy(rm, rt, rs); wr32(rm + 36, 8); expect_refusal(reg_check(rm, rs, NULL), "DWORD length", "dword with length 8 refused");
    memcpy(rm, rt, rs); wr32(rm + 52, 4); expect_refusal(reg_check(rm, rs, NULL), "value overruns", "binary length past the end refused");
    memcpy(rm, rt, rs); rm[44] = 9; expect_refusal(reg_check(rm, rs, NULL), "unknown entry type", "type 9 refused");
    memcpy(rm, rt, rs); rm[rs] = 0; expect_refusal(reg_check(rm, rs + 1, NULL), "size field", "trailing byte refused");
    expect_refusal(reg_encode(regs, 0, rt, sizeof rt, &rs), "empty registry", "empty registry refused");
    reg_in z = { "Zero", REG_TYPE_STRING, 0, (const uint8_t *)"", 0 }; expect_refusal(reg_encode(&z, 1, rt, sizeof rt, &rs), "zero-length", "zero-length string refused");
    reg_in d = { "D", REG_TYPE_DWORD, 5, bin, 3 }; expect_refusal(reg_encode(&d, 1, rt, sizeof rt, &rs), "DWORD entry carries", "dword with bytes refused");
    reg_in u = { "U", 7, 0, NULL, 0 }; expect_refusal(reg_encode(&u, 1, rt, sizeof rt, &rs), "unknown entry type", "unknown type refused");
    reg_in nn = { "", REG_TYPE_DWORD, 1, NULL, 0 }; expect_refusal(reg_encode(&nn, 1, rt, sizeof rt, &rs), "entry without a name", "empty name refused");
    reg_in bg = { "Big", REG_TYPE_BINARY, 0, big, 66000 }; expect_refusal(reg_encode(&bg, 1, rt, sizeof rt, &rs), "registry exceeds one RPC", "oversize registry refused");
    expect_refusal(reg_encode(regs, 3, rt, 16, &rs), "output too small", "small registry output refused");
    /* 6. a complete SET_REGISTRY message, as the driver would ring it */
    e.function = FN_SET_REGISTRY; e.sequence = 0; e.payload_len = rs; e.payload = rt; e.seqNum = 1;
    check(elem_encode(&e, el, sizeof el, &ml, &ec) == NULL && ec == 1 && rd32(el + 56) == 32 + 95 && rd32(el + 60) == FN_SET_REGISTRY, "SET_REGISTRY element: length 127, function 73");
    check(elem_check(el, 4096, 1, &v) == NULL && reg_check(el + 80, v.rpc.length - 32, &cnt) == NULL && cnt == 3, "registry survives the element round trip");
    /* 7. constants a native kernel must match */
    check(FN_CONTINUATION_RECORD == 71 && FN_GSP_SET_SYSTEM_INFO == 72 && FN_SET_REGISTRY == 73, "function numbers 71/72/73");
    check(EV_GSP_INIT_DONE == 0x1001 && EV_GSP_RUN_CPU_SEQUENCER == 0x1002 && EV_RC_TRIGGERED == 0x1004 && EV_GSP_LOCKDOWN_NOTICE == 0x101c && EV_GSP_POST_NOCAT_RECORD == 0x1020, "event numbers");
    check(RPC_RESULT_UNKNOWN_FN == 0xFF100001 && RPC_RESULT_BAD_FORMAT == 0xFF100002 && NV_PGSP_QUEUE_HEAD_0 == 0x110c00, "result codes and doorbell register");
    check(RPC_SIZE_MAX == 65488 && RPC_CONT_PAYLOAD_MAX == 65456, "RPC_SIZE_MAX 65488, continuation payload 65456");
    /* 8. the system-info message: 936-byte payload, one slot */
    e.function = FN_GSP_SET_SYSTEM_INFO; e.sequence = 0; e.payload_len = GSP_SYSTEM_INFO_SIZE; e.payload = big; e.seqNum = 0;
    check(elem_encode(&e, el, sizeof el, &ml, &ec) == NULL && ec == 1 && rd32(el + 56) == GSP_SYSTEM_INFO_RPC_LEN && ml == 1016, "GSP_SET_SYSTEM_INFO: length 968, 1 slot, padded 1016");
    check(elem_check(el, 4096, 0, &v) == NULL && v.rpc.function == FN_GSP_SET_SYSTEM_INFO, "system-info element validates with seqNum 0");
    printf("CK_GSP_RPC_ENCODE_SELFTEST: %s (%d checks, %d failures)\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}

/* ---- CLI ---- */
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
    fprintf(stderr, "usage: ck_gsp_rpc_encode selftest | layout\n"
        "  txheader [--size N --msg-size N --hdr-align N --entry-align N --flags N] [--out F]   (defaults: the driver's command queue)\n"
        "  check-txheader F [--size N --msg-size N --our-rxhdr N]                               (msgqRxLink rules on a peer header)\n"
        "  ring --read N --write N [--count N]                                                  (free / available slots)\n"
        "  element --function N [--sequence N] [--seqnum N] [--payload F] [--out F]            (one ring message, padded to whole slots)\n"
        "  check-element F [--seqnum N]                                                         (receive-side validation)\n"
        "  contplan --rpc-len N                                                                 (continuation records needed)\n"
        "  registry --dword NAME=N | --string NAME=TEXT ... [--out F]                           (PACKED_REGISTRY_TABLE)\n"
        "  check-registry F\n");
    return 2;
}
static int refused(const char *why) { printf("REFUSED: %s\n", why); return 2; }
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
        printf("msgqTxHeader 32 bytes: version 0 size 4 msgSize 8 msgCount 12 writePtr 16 flags 20 rxHdrOff 24 entryOff 28; msgqRxHeader: readPtr 0\n");
        printf("driver queues: size 0x40000 msgSize 4096 hdrAlign 16 entryAlign 4096 flags SWAP_RX -> rxHdrOff 32 entryOff 4096 msgCount 63 (62 usable)\n");
        printf("GSP_MSG_QUEUE_ELEMENT: authTag 0 aad 16 checkSum 32 seqNum 36 elemCount 40 rpc 48 (sizeof 80); slot 4096, max 16 slots, RPC_SIZE_MAX 65488\n");
        printf("rpc_message_header_v03_00 32 bytes: header_version 0 (0x03000000) signature 4 (0x43505256) length 8 function 12 rpc_result 16 rpc_result_private 20 sequence 24 cpuRmGfid 28\n");
        printf("functions: NOP 0 CONTINUATION_RECORD 71 GSP_SET_SYSTEM_INFO 72 SET_REGISTRY 73; events: GSP_INIT_DONE 0x1001 RUN_CPU_SEQUENCER 0x1002 RC_TRIGGERED 0x1004 LOCKDOWN_NOTICE 0x101c POST_NOCAT_RECORD 0x1020\n");
        printf("results: RPC_PENDING 0xffffffff UNKNOWN_FUNCTION 0xff100001 INVALID_MESSAGE_FORMAT 0xff100002; doorbell NV_PGSP_QUEUE_HEAD(0) 0x110c00 <- 0\n");
        printf("GspSystemInfo payload 936 bytes (gpuPhysAddr 0 ... FHBBusInfo 138 chipsetIDInfo 148 acpiMethodData 160 hypervisorType 836 gspVFInfo 856 hostPageSize 920 bWindowChannelAlwaysMapped 931); GSP_SET_SYSTEM_INFO RPC length 968\n");
        printf("PACKED_REGISTRY_TABLE: size 0 numEntries 4 entries 8 x {nameOffset 0 type 4 data 8 length 12} (16 each), then names and values; types DWORD 1 BINARY 2 STRING 3\n");
        return 0;
    }
    const char *out = NULL, *payload_path = NULL; int ok = 1;
    uint64_t size = GSP_MQ_SIZE, msg_size = GSP_MQ_MSG_SIZE, hdr_align = GSP_MQ_HDR_ALIGN, entry_align = GSP_MQ_ENTRY_ALIGN, flags = MSGQ_FLAGS_SWAP_RX;
    uint64_t our_rxhdr = GSP_MQ_RXHDR_OFF, rptr = 0, wptr = 0, count = GSP_MQ_MSG_COUNT, function = 0, sequence = 0, seqnum = 0, rpc_len = 0;
    int have_function = 0;
    reg_in regs[64]; uint32_t nregs = 0; static char regbuf[64][512];
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--out") && i + 1 < argc) { out = argv[++i]; continue; }
        if (!strcmp(a, "--payload") && i + 1 < argc) { payload_path = argv[++i]; continue; }
        if ((!strcmp(a, "--dword") || !strcmp(a, "--string")) && i + 1 < argc) {
            if (nregs >= 64) return refused("more than 64 registry entries");
            const char *kv = argv[++i]; const char *eq = strchr(kv, '=');
            if (!eq || eq == kv || strlen(kv) >= sizeof regbuf[0]) return refused("registry entry must be NAME=VALUE");
            strcpy(regbuf[nregs], kv); regbuf[nregs][eq - kv] = 0;
            reg_in *r = &regs[nregs]; r->name = regbuf[nregs]; r->bytes = NULL; r->len = 0; r->dword = 0;
            if (!strcmp(a, "--dword")) { r->type = REG_TYPE_DWORD; r->dword = (uint32_t)parse_u64(eq + 1, &ok); if (!ok) return refused("bad dword value"); }
            else { r->type = REG_TYPE_STRING; r->bytes = (const uint8_t *)regbuf[nregs] + (eq - kv) + 1; r->len = (uint32_t)strlen(eq + 1); }
            nregs++; continue;
        }
        struct { const char *n; uint64_t *v; } opts[] = { {"--size", &size}, {"--msg-size", &msg_size}, {"--hdr-align", &hdr_align}, {"--entry-align", &entry_align}, {"--flags", &flags},
            {"--our-rxhdr", &our_rxhdr}, {"--read", &rptr}, {"--write", &wptr}, {"--count", &count}, {"--function", &function}, {"--sequence", &sequence}, {"--seqnum", &seqnum}, {"--rpc-len", &rpc_len} };
        int hit = 0;
        for (size_t k = 0; k < sizeof opts / sizeof opts[0] && i + 1 < argc; k++)
            if (!strcmp(a, opts[k].n)) { *opts[k].v = parse_u64(argv[++i], &ok); if (opts[k].v == &function) have_function = 1; hit = 1; break; }
        if (!hit && a[0] == '-') return usage();
        if (!ok) return refused("bad number");
    }
    if (size > 0xffffffffu || msg_size > 0xffffffffu || hdr_align > 31 || entry_align > 31 || flags > 0xffffffffu) return refused("value out of 32-bit range");
    if (!strcmp(mode, "txheader")) {
        mq_create_in q = { (uint32_t)size, (uint32_t)msg_size, (uint32_t)hdr_align, (uint32_t)entry_align, (uint32_t)flags };
        uint8_t h[MSGQ_TX_HDR_SIZE]; const char *e = mq_tx_create(&q, h); if (e) return refused(e);
        printf("txheader ok msgCount=%u rxHdrOff=%u entryOff=%u\n", rd32(h + 12), rd32(h + 24), rd32(h + 28)); dump(h, 32);
        return emit(out, h, 32);
    }
    if (!strcmp(mode, "ring")) {
        if (rptr > 0xffffffffu || wptr > 0xffffffffu || count > 0xffffffffu) return refused("value out of 32-bit range");
        printf("ring count=%llu read=%llu write=%llu free=%u available=%u\n", (unsigned long long)count, (unsigned long long)rptr, (unsigned long long)wptr,
               ring_free((uint32_t)rptr, (uint32_t)wptr, (uint32_t)count), ring_avail((uint32_t)rptr, (uint32_t)wptr, (uint32_t)count));
        return 0;
    }
    if (!strcmp(mode, "element")) {
        if (!have_function) return refused("need --function");
        if (function > 0xffffffffu || sequence > 0xffffffffu || seqnum > 0xffffffffu) return refused("value out of 32-bit range");
        uint8_t *p = NULL; size_t pn = 0;
        if (payload_path && read_file(payload_path, &p, &pn)) return refused("cannot read payload");
        static uint8_t el[ELEM_SIZE_MAX]; uint32_t ml = 0, ec = 0;
        elem_in in = { (uint32_t)function, (uint32_t)sequence, (uint32_t)pn, p, (uint32_t)seqnum };
        const char *e = elem_encode(&in, el, sizeof el, &ml, &ec); free(p); if (e) return refused(e);
        printf("element ok function=%u sequence=%u seqNum=%u rpc_length=%u msg_len=%u slots=%u checksum=0x%08x\n", in.function, in.sequence, in.seqNum, rd32(el + 56), ml, ec, rd32(el + 32));
        dump(el, 80);
        return emit(out, el, (size_t)ec * ELEM_SIZE_MIN);
    }
    if (!strcmp(mode, "contplan")) {
        if (rpc_len > 0xffffffffu) return refused("value out of 32-bit range");
        cont_plan cp; const char *e = cont_plan_for((uint32_t)rpc_len, &cp); if (e) return refused(e);
        printf("contplan rpc_len=%u messages=%u first_len=%u last_continuation_payload=%u\n", (uint32_t)rpc_len, cp.chunks, cp.first_len, cp.last_payload);
        return 0;
    }
    if (!strcmp(mode, "registry")) {
        static uint8_t rt[RPC_SIZE_MAX]; uint32_t rs = 0;
        const char *e = reg_encode(regs, nregs, rt, sizeof rt, &rs); if (e) return refused(e);
        printf("registry ok size=%u entries=%u\n", rs, nregs); dump(rt, rs > 96 ? 96 : rs);
        return emit(out, rt, rs);
    }
    if (!strncmp(mode, "check-", 6)) {
        if (argc < 3 || argv[2][0] == '-') return usage();
        uint8_t *b; size_t n; if (read_file(argv[2], &b, &n)) return refused("cannot read file");
        const char *e; char extra[96] = "";
        if (!strcmp(mode, "check-txheader")) { msgq_tx_header h; e = mq_rx_link_check(b, n, (uint32_t)size, (uint32_t)msg_size, (uint32_t)our_rxhdr, &h); if (!e) snprintf(extra, sizeof extra, " msgCount=%u writePtr=%u", h.msgCount, h.writePtr); }
        else if (!strcmp(mode, "check-element")) { elem_view v; e = elem_check(b, n, (uint32_t)seqnum, &v); if (!e) snprintf(extra, sizeof extra, " function=0x%x sequence=%u result=0x%08x length=%u slots=%u", v.rpc.function, v.rpc.sequence, v.rpc.rpc_result, v.rpc.length, v.elemCount); }
        else if (!strcmp(mode, "check-registry")) { uint32_t c = 0; e = reg_check(b, n, &c); if (!e) snprintf(extra, sizeof extra, " entries=%u", c); }
        else e = "unknown check";
        free(b);
        if (e) return refused(e);
        printf("%s: OK%s\n", mode, extra); return 0;
    }
    return usage();
}
