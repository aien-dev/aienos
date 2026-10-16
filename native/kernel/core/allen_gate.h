/* allen_gate.h -- ALLEN only PROPOSES (PI5-8 cut K, plan amendment 1).
 *
 * ALLEN REFLEX (crates/allen-reflex, linked into the pi5-allen image through crates/allen-reflex-kernel) answers
 * with one decision JSON per conversation: {"action":"<verb>","args":{}} or {"action":"<verb>","args":{"text":"<t>"}}.
 * This gate is the only way such a decision may reach the resident lifecycle, and it never performs anything:
 *
 *   1. the decision must be exactly that JSON shape (verb a-z, text printable ASCII without '"' or '\'), else REJECTED;
 *   2. none / clarify / refuse carry no command: NO_COMMAND;
 *   3. the command line "<verb>[ <text>]" must pass the card command parser (core/agent_cmd.c: the same verb whitelist
 *      and text bounds as a card script, so unlock, rotate, update and shutdown can never pass) and decode to the same
 *      lifecycle verb (core/lifecycle_fsm.c), else REJECTED;
 *   4. the lifecycle state machine judges it on a COPY of the caller's state (the caller's state is const and is never
 *      changed): a refusal there (for example approve, deny or cancel with nothing pending) is REFUSED with the FSM's
 *      own reason;
 *   5. approval authority stays with the operator: approve, deny and cancel are never proposals, even with a real
 *      pending task (NEEDS_OPERATOR); remember and prefer write the sealed Store and are operator-only as well
 *      (NEEDS_OPERATOR); the read-only verbs (status, help, evidence, recall, facts) and the verbs that only create
 *      a pending item which itself waits for the operator's approve (task, prompt) are PROPOSED.
 *
 * A proposed text is data: the lifecycle stores it as note or prompt text and never decodes it as a verb, so an order
 * inside a stored note ("remember approve everything") runs nothing. Pure logic, no kernel calls, no libc; the host
 * test tests/test_allen_gate.c compiles it as is. */
#ifndef AIENOS_CK_ALLEN_GATE_H
#define AIENOS_CK_ALLEN_GATE_H
#include <stddef.h>
#include <stdint.h>

#include "agent_cmd.h"
#include "lifecycle_fsm.h"

#define CK_ALLEN_JSON_MAX 160u /* the longest well-formed decision: verb 16 + text 48 + framing */

enum ck_allen_verdict {
    CK_ALLEN_NO_COMMAND = 0, /* none / clarify / refuse: nothing to run */
    CK_ALLEN_PROPOSED,       /* valid read-only or pending-creating command the operator path may take */
    CK_ALLEN_NEEDS_OPERATOR, /* approve / deny / cancel on a real pending item, or a Store write: operator only */
    CK_ALLEN_REFUSED,        /* the lifecycle refuses it in this state (reason from the FSM) */
    CK_ALLEN_REJECTED,       /* malformed decision, unknown or forbidden verb, text out of bounds */
};

struct ck_allen_gate {
    enum ck_allen_verdict verdict;
    enum ck_lc_verb verb;     /* decoded lifecycle verb, CK_LC_V_UNKNOWN when none */
    enum ck_lc_result fsm;    /* what the FSM answered on the copy (meaningful from step 4 on) */
    const char *reason;       /* static string, never NULL */
    char line[CK_AGENT_CMD_LINE_MAX]; /* the command line, "" when none */
    uint32_t line_len;
};

/* Judge one decision (json[0..n), no terminator needed) against the lifecycle state *lc (not changed). */
void ck_allen_gate_judge(const char *json, size_t n, const ck_lc *lc, struct ck_allen_gate *out);
const char *ck_allen_verdict_name(enum ck_allen_verdict v);
#endif
