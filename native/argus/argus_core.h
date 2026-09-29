/*
 * argus_core.h -- capacity constants of the ARGUS-0 resident state engine.
 *
 * Public entry points live in argus_abi.h. This header only exposes the fixed
 * table sizes so tests and the integrator can reason about them. The layout of
 * struct ArgusStateView / struct ArgusCore stays private to argus_core.c.
 */
#ifndef ARGUS_CORE_H
#define ARGUS_CORE_H
#include "argus_abi.h"

#define ARGUS_CORE_CAPS          256u  /* == AIENOS_CAP_MAX; indexed directly by cap_id */
#define ARGUS_CORE_MACHINES      16u
#define ARGUS_CORE_ARTIFACTS     64u
#define ARGUS_CORE_LEASES        64u
#define ARGUS_CORE_PROVIDERS     32u
#define ARGUS_CORE_PRODUCERS     32u   /* (machine_id, consumer bit) sequence streams */
#define ARGUS_CORE_INCIDENTS     64u   /* distinct (principal, finding code) with severity >= HIGH */
#define ARGUS_CORE_MAX_FINDINGS  32u   /* internal scratch per ingest; more are counted then truncated */

#endif /* ARGUS_CORE_H */
