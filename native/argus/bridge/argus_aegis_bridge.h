#ifndef ARGUS_AEGIS_BRIDGE_H
#define ARGUS_AEGIS_BRIDGE_H

#include "../argus_contain.h"
#include "../argus_core.h"
#include "../../capability/aienos_contain.h"

typedef struct ArgusAegisBridge ArgusAegisBridge;

size_t argus_aegis_bridge_footprint(void);
int argus_aegis_bridge_init(ArgusAegisBridge **out, void *memory, size_t bytes,
                            ArgusCore *core, ArgusContain *contain,
                            AienosContain **gate_ref, const AienosCapView *view,
                            const uint8_t machine_id[ARGUS_MACHINE_ID_LEN]);
void argus_aegis_bridge_destroy(ArgusAegisBridge *bridge);

/* Register these directly with the capability observer and containment gate. */
void argus_aegis_bridge_observer(void *ctx, uint32_t op, const AienosCapEntry *entry,
                                 int result);
int argus_aegis_bridge_attach_gate(ArgusAegisBridge *bridge);

/* Core-ingest entry used by the consumer for ordinary events and kind 90. */
int argus_aegis_bridge_ingest(ArgusAegisBridge *bridge, const ArgusEvent *event);
/* Submit one proposal. A GRANT is executed synchronously on this caller thread. */
int argus_aegis_bridge_submit(ArgusAegisBridge *bridge,
                             const ArgusContainmentRequest *request,
                             AienosContainDecision *decision,
                             AienosContainResult *result);

size_t argus_aegis_bridge_take_findings(ArgusAegisBridge *bridge,
                                        ArgusFinding *out, size_t capacity);
int argus_aegis_bridge_error(const ArgusAegisBridge *bridge);

#endif
