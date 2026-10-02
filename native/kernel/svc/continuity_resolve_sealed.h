/* continuity_resolve_sealed.h -- binds cr_source (continuity_resolve.h) to the
 * real sealed Store (native/store/store_sealed.h). Reads only. */
#ifndef CK_CONTINUITY_RESOLVE_SEALED_H
#define CK_CONTINUITY_RESOLVE_SEALED_H

#include "continuity_resolve.h"
#include "store_sealed.h"

/* Source over the verified claims of an opened ss_store (P-3: kind and version
 * come from the claim, no decryption to list). The store must stay open. */
void cr_bind_sealed(struct cr_source *out, ss_store *s);

/* Raw-unit state digest of the Store region (units 0 and 1 of dev), as
 * recovery_core.rs:109-133: an unreadable unit leaves its buffer zero. */
void cr_state_digest_dev(const st_dev *dev, uint8_t out[32]);

#endif
