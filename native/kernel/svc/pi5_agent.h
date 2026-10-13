/* pi5_agent.h -- the Pi 5 agent stage (PI5-6 final cut, CK_PI5_AGENT, QUALIFICATION ONLY while the recovery
 * secret comes from the card request file).
 *
 * One fixed prompt, one bounded reply (at most CK_AGENT_MAX_NEW tokens), persisted in the sealed Store and
 * recovered by a later boot. Runs right after the Store stage opened the Store through the Slot 1 recovery
 * secret (PI5-4), BEFORE the model is touched:
 *   - Store not open (wrong secret): "NOTHING RECOVERED", no hashing, no session, nothing written.
 *   - Store holds an agent reply for the fixed prompt: RECOVER. The model is not used, even if MODEL.MAP is on
 *     the card. The object is read back through the sealed Store, parsed and checked against the golden
 *     tokens, the golden text and the golden model digest, and printed with the Store generation it was
 *     committed at. Writes nothing.
 *   - No reply yet: GENERATE. The resident model is ingested and hashed (core/infer.c ck_infer_run, the same
 *     path as the QEMU service image), one bounded prompt runs (ck_infer_prompt), the session is closed, and
 *     only a reply that passes every golden check is committed as one sealed Store object of the lifecycle's
 *     reply kind 'R1' (core/reply_obj.h, shared with core/lifecycle.c) plus a model/ids trailer.
 * Both ways end with the same line:
 *   agent: reply store_gen=G object_sha256=H model_sha256=M tokens=N ids=... text="..."
 * so a boot-2 log can be compared with the boot-1 log line for line. */
#ifndef AIENOS_CK_PI5_AGENT_H
#define AIENOS_CK_PI5_AGENT_H
#include <stdint.h>
#include "store_sealed.h"

#define CK_AGENT_PROMPT "What is the capital of France?"
#define CK_AGENT_MAX_NEW 16u /* the reply cap N (also the session's max_new in core/infer.c SESS_MAX_NEW) */
/* Golden values: llama.cpp's greedy reply for CK_AGENT_PROMPT on Llama-3.2-1B-Instruct-Q4_K_M
 * (crates/aienos-infer/tests/fixtures/ref_fr.txt, PROVENANCE.md) and its chat-template head. */
#define CK_AGENT_GOLDEN_NIDS 8u
#define CK_AGENT_GOLDEN_TEXT "The capital of France is Paris."
#define CK_AGENT_GOLDEN_MODEL_SHA256 "3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1"

enum {
    CK_AGENT_MODE_NOSTORE = 1,  /* Store not open: nothing recovered, nothing generated */
    CK_AGENT_MODE_RECOVER = 2,
    CK_AGENT_MODE_GENERATE = 3,
    CK_AGENT_MODE_NOMODEL = 4,  /* no reply yet and no resident model: nothing written */
};

struct ck_agent_result {
    int mode;           /* CK_AGENT_MODE_* */
    int ok;             /* 1: the reply was recovered/committed and passed every check */
    uint64_t store_gen; /* Store generation the reply object was committed at */
    char object_sha256[65];
};

/* The inference unit entry points the stage uses (core/infer.c in the image; a stub in the host test). */
void ck_infer_run(void);

/* s: the open writable Store, or NULL when it is not open. Returns 0 when the stage did what its mode says
 * and every check passed (NOSTORE counts: it is a refusal, not a failure of this stage); <0 otherwise
 * (printed). */
int ck_pi5_agent_run(ss_store *s, struct ck_agent_result *out);
#endif
