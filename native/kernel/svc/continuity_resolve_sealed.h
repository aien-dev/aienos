/* continuity_resolve_sealed.h -- binds cr_source (continuity_resolve.h) to the
 * real sealed Store (native/store/store_sealed.h). Reads only. */
#ifndef CK_CONTINUITY_RESOLVE_SEALED_H
#define CK_CONTINUITY_RESOLVE_SEALED_H

#include "continuity_commit.h"
#include "store_sealed.h"

/* Source over the verified claims of an opened ss_store (P-3: kind and version
 * come from the claim, no decryption to list). The store must stay open. */
void cr_bind_sealed(struct cr_source *out, ss_store *s);

/* Write side (cut 4): a cr_sink over ss_transact. hook/hook_arg are passed to
 * every ss_transact (crash checkpoints ST_CP_*, SS_CP_*); NULL for none. */
struct cr_sealed_sink {
    ss_store *s;
    st_hook hook;
    void *hook_arg;
};
void cr_bind_sealed_sink(struct cr_sink *out, struct cr_sealed_sink *ctx);

/* Raw-unit state digest of the Store region (units 0 and 1 of dev), as
 * recovery_core.rs:109-133: an unreadable unit leaves its buffer zero. */
void cr_state_digest_dev(const st_dev *dev, uint8_t out[32]);

#endif
