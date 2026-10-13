/* kv_record.c -- RED STUB for cut N1 (aienos#367): every entry point refuses.
 * The next commit replaces this file with the codec. */
#include "kv_record.h"

int kv_compute_config_digest(const kv_compute_config *c, uint8_t out[32]) { (void)c; (void)out; return KV_E_ARG; }
int kv_namespace_id(const kv_namespace_fields *f, uint8_t out[32]) { (void)f; (void)out; return KV_E_ARG; }
int kv_expected_payload_len(const kv_namespace_fields *f, uint32_t t, uint64_t *o) { (void)f; (void)t; (void)o; return KV_E_ARG; }
int kv_segment_bytes(const kv_namespace_fields *f, uint32_t t, uint64_t *o) { (void)f; (void)t; (void)o; return KV_E_ARG; }
int kv_ns_segment_count(const kv_namespace_fields *f, uint32_t t, uint32_t *o) { (void)f; (void)t; (void)o; return KV_E_ARG; }
int kv_segment_count(uint64_t p, uint64_t s, uint32_t *o) { (void)p; (void)s; (void)o; return KV_E_ARG; }
int kv_chunk_key(const uint8_t ns[32], const uint8_t parent[32], uint32_t fp, const uint32_t *t, size_t n, uint8_t out[32])
{ (void)ns; (void)parent; (void)fp; (void)t; (void)n; (void)out; return KV_E_ARG; }
int kv_chunk_chain(const uint8_t ns[32], uint32_t ct, const uint32_t *t, size_t n, uint8_t (*k)[32], size_t cap, size_t *nk)
{ (void)ns; (void)ct; (void)t; (void)n; (void)k; (void)cap; (void)nk; return KV_E_ARG; }
int kv_chunk_header_build(const kv_namespace_fields *f, const uint8_t ns[32], const uint8_t ck[32], const uint8_t parent[32],
                          uint32_t fp, uint32_t tc, uint64_t w, kv_chunk_header *out)
{ (void)f; (void)ns; (void)ck; (void)parent; (void)fp; (void)tc; (void)w; (void)out; return KV_E_ARG; }
void kv_header_encode(const kv_record_header *h, uint8_t out[KV_HEADER_LEN]) { (void)h; (void)out; }
int kv_header_decode_struct(const uint8_t *b, size_t l, kv_record_header *o) { (void)b; (void)l; (void)o; return KV_E_ARG; }
int kv_header_decode(const uint8_t *b, size_t l, kv_record_header *o) { (void)b; (void)l; (void)o; return KV_E_ARG; }
void kv_payload_root(const uint8_t (*s)[32], size_t n, uint8_t out[32]) { (void)s; (void)n; (void)out; }
int kv_region_encode(const kv_record_header *h, const uint8_t (*s)[32], size_t n, uint8_t out[KV_HEADER_REGION_LEN])
{ (void)h; (void)s; (void)n; (void)out; return KV_E_ARG; }
int kv_validate_record(const uint8_t *b, size_t l, uint64_t fs, const kv_chunk_header *e, uint64_t sb, kv_record_header *o)
{ (void)b; (void)l; (void)fs; (void)e; (void)sb; (void)o; return KV_E_ARG; }
int kv_slot_geometry(uint64_t p, uint32_t *su, uint32_t *el) { (void)p; (void)su; (void)el; return KV_E_ARG; }
int kv_slot_encode(const kv_slot_header *s, uint8_t out[KV_SLOT_UNIT]) { (void)s; (void)out; return KV_E_ARG; }
int kv_slot_decode(const uint8_t *u, size_t l, uint32_t si, kv_slot_header *o) { (void)u; (void)l; (void)si; (void)o; return KV_E_ARG; }
int kv_slot_validate(const uint8_t *u, size_t l, uint32_t si, const kv_chunk_header *e, kv_slot_header *o)
{ (void)u; (void)l; (void)si; (void)e; (void)o; return KV_E_ARG; }
int kv_slot_keys(const uint8_t k[32], uint8_t a[32], uint8_t b[32]) { (void)k; (void)a; (void)b; return KV_E_ARG; }
int kv_envelope_ids(const uint8_t k[32], const uint8_t u[16], const uint8_t n[32], const uint8_t c[32], uint32_t si, uint64_t inc,
                    uint64_t kg, uint8_t cl, uint64_t pl, const uint8_t ps[32], uint8_t id[16], uint8_t np[8])
{ (void)k; (void)u; (void)n; (void)c; (void)si; (void)inc; (void)kg; (void)cl; (void)pl; (void)ps; (void)id; (void)np; return KV_E_ARG; }
void kv_slot_binding(const uint8_t u[16], const uint8_t id[16], uint64_t kg, uint8_t cl, m5_object_binding *o)
{ (void)u; (void)id; (void)kg; (void)cl; (void)o; }
