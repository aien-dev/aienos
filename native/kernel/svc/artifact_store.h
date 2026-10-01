/* artifact_store.h -- signed P2 artifacts on the boot disk, kept as ordinary
 * application objects inside the sealed C Store (store_sealed.h). No second
 * disk format: an artifact is one or more Store objects of kind
 * CK_ART_CHUNK_KIND plus one index object of kind CK_ART_INDEX_KIND, all
 * sealed, catalogued and anchored exactly like the boot record.
 *
 * Lookup: the index with the highest Store generation names the candidates
 * (name, byte length, chunk count) in boot order. Each chunk object carries
 * its artifact's name, total length, chunk number and chunk count; a chunk
 * is used only if it matches an index entry exactly and is not newer than
 * that index. Index entries and chunks both carry the SHA-256 of the whole
 * artifact; a chunk is used only for the entry with the same digest, and the
 * assembled bytes must hash to it, so chunks of different writes are never
 * spliced. An entry with any chunk absent is MISSING, one whose assembly does
 * not hash to its digest is MISMATCH (the loader refuses both at stage
 * "received", reason FirmwareRead), never partly loaded.
 *
 * Trust: the Store keys are TEST keys from a public label (store_boot.h), so
 * the Store's MACs prove nothing about who wrote an artifact. Bytes read here
 * are untrusted input: the kernel loader (core/artifact_loader.c) still runs
 * the full format, signature, digest and admission checks on them.
 *
 *   index  "AIENAIX1" u32 version(1) u32 count, then count entries of 80:
 *          u8 name_len(1..32) u8[3] 0, char name[32] (zero padded),
 *          u32 byte_len(1..CK_ART_MAX_BYTES), u16 chunks, u16 0, u32 0,
 *          u8 sha256[32] of the whole artifact
 *   chunk  "AIENACH1" u32 version(1) u32 total_len u16 chunk u16 chunks
 *          u8 name_len u8[3] 0, char name[32], u8 sha256[32] of the whole
 *          artifact, then the chunk's bytes
 *          (CK_ART_CHUNK_DATA per chunk, the last one the remainder)
 * All integers little endian. */
#ifndef AIENOS_CK_ARTIFACT_STORE_H
#define AIENOS_CK_ARTIFACT_STORE_H
#include <stddef.h>
#include <stdint.h>
#include "store_sealed.h"

#define CK_ART_INDEX_KIND 0x0A01u
#define CK_ART_CHUNK_KIND 0x0A02u
#define CK_ART_VERSION 1u
#define CK_ART_NAME_MAX 32u
#define CK_ART_MAX_ENTRIES 48u                 /* = loader MAX_CANDIDATES */
#define CK_ART_MAX_BYTES (160u * 4096u)        /* = loader MAX_BATCH pages */
#define CK_ART_INDEX_HDR 16u
#define CK_ART_INDEX_ENTRY 80u
#define CK_ART_CHUNK_HDR 88u
#define CK_ART_CHUNK_DATA (SS_MAX_PLAINTEXT - CK_ART_CHUNK_HDR)
#define CK_ART_MAX_CHUNKS ((CK_ART_MAX_BYTES + CK_ART_CHUNK_DATA - 1u) / CK_ART_CHUNK_DATA)

enum { CK_ART_OK = 0, CK_ART_MISSING = 1, CK_ART_TOO_LARGE = 2, CK_ART_MISMATCH = 3 };

typedef struct {
    char name[CK_ART_NAME_MAX + 1];
    uint32_t len;       /* byte length from the index */
    uint16_t chunks;    /* chunk count from the index */
    uint16_t present;   /* chunks found */
    int state;          /* CK_ART_* */
    uint8_t *bytes;     /* len bytes, CK_ART_OK only (ck_alloc) */
    uint8_t want[32];   /* artifact SHA-256 named by the index */
    uint8_t sha256[32]; /* of bytes exactly as read, CK_ART_OK only */
} ck_art_entry;

typedef struct {
    int found;                  /* an index object was read */
    uint64_t index_generation;  /* Store generation of that index */
    uint8_t index_sha256[32];   /* of the index object's plaintext */
    uint32_t count;
    uint32_t chunks_used, chunks_ignored;
    ck_art_entry e[CK_ART_MAX_ENTRIES];
} ck_art_set;

/* Read the newest index and every chunk it names from an open sealed store.
 * 0 with set->found == 0: no index (no artifacts on this disk). 0 with
 * set->found == 1: entries filled (each OK, MISSING, MISMATCH or TOO_LARGE). < 0: a
 * malformed index or a Store read error; *why names it; nothing usable. */
int ck_art_collect(ss_store *s, ck_art_set *set, const char **why);
void ck_art_set_free(ck_art_set *set);
void ck_stage_disk_artifacts_free(void);

/* Store stage hook (svc/store_boot.c): s is the open Store after this boot's
 * commit, or NULL when the Store was refused (refusal names why). Reads and
 * prints the "artifact_disk:" lines; the core loader picks the result up
 * through ck_stage_disk_artifacts (ck.h). Must run before the NVMe release. */
void ck_art_stage_load(ss_store *s, const char *refusal);

#ifdef CK_ART_STORE_WRITER
/* Host-side writer (image build tool and host tests only; never compiled
 * into the kernel). Writes every chunk (at most SS_MAX_OBJECTS per Store
 * transaction), then the index in a final transaction, so an index is only
 * ever committed after all of its chunks. missing != 0 puts the entry in the
 * index (byte_len = len, which must still be >= 1) without writing chunks:
 * a deliberately absent artifact for the hostile disk case. */
typedef struct {
    const char *name;
    const uint8_t *bytes;
    size_t len;
    int missing;
} ck_art_input;
int ck_art_write(ss_store *s, const ck_art_input *in, size_t n);
#endif
#endif
