#ifndef ARGUS_CONTAIN_H
#define ARGUS_CONTAIN_H

#include "argus_abi.h"

/* Bounded, caller-owned containment state. No allocation, clocks, authority, or I/O. */
typedef struct ArgusContain ArgusContain;

size_t argus_contain_footprint(void);
int argus_contain_init(ArgusContain **state, void *memory, size_t bytes);

/* Observe a validated event after core ingestion. Findings are codes 17-21. */
int argus_contain_observe(ArgusContain *state, const ArgusCore *core,
                          const ArgusEvent *event, ArgusFinding *findings,
                          size_t finding_cap, size_t *finding_count);

/* Convert eligible detector findings to requests and kind-90 events. The caller
 * ingests returned events directly into the core, then hands requests to AEGIS. */
int argus_contain_propose(ArgusContain *state, const ArgusCore *core,
                          const ArgusFinding *findings, size_t finding_count,
                          const ArgusEvent *trigger_event,
                          ArgusContainmentRequest *requests, size_t request_cap,
                          ArgusEvent *proposed_events, size_t event_cap,
                          size_t *proposal_count);

void argus_contain_health(const ArgusContain *state, ArgusContainHealth *out);
void argus_contain_state_digest(const ArgusContain *state,
                                uint8_t out[ARGUS_DIGEST_LEN]);

#endif
