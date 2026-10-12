/* cortex_store.c -- the canonical Omega Cortex store (CxStore) built
 * freestanding inside AIENOS: no POSIX journal, no libc allocation. The
 * source is vendored byte for byte from the omega.lock commit
 * (third_party/omega/rx_cortex.c, checked by scripts/omega_lock_check.sh);
 * this wrapper only sets the build switches so the vendored file stays
 * identical to Omega's. The journal backend is svc/cortex_journal.c. */
#define CX_NO_POSIX 1
#define CX_CONFIG_H "cortex_config.h"
#include "../third_party/omega/rx_cortex.c"
