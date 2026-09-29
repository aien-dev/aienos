#include "../argus_abi.h"
#include "../argus_contain.h"
#include "../bridge/argus_aegis_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); } } while(0)

typedef struct {
    AienosCapAdmin *admin;
    AienosCapView *view;
    AienosCapRef office;
    AienosContain *gate;
    AienosContainTablePolicy policy;
    ArgusCore *core;
    ArgusContain *contain;
    ArgusAegisBridge *bridge;
    void *core_mem, *contain_mem, *gate_mem, *bridge_mem;
    uint8_t machine[ARGUS_MACHINE_ID_LEN];
} Rig;

static void setup(Rig *r) {
    memset(r,0,sizeof(*r));
    CHECK(aienos_cap_start(&r->admin,&r->view)==AIENOS_CAP_OK);
    CHECK(aienos_cap_office(r->admin,&r->office)==AIENOS_CAP_OK);
    r->core_mem=calloc(1,argus_core_footprint());
    r->contain_mem=calloc(1,argus_contain_footprint());
    r->gate_mem=calloc(1,aienos_contain_footprint());
    r->bridge_mem=calloc(1,argus_aegis_bridge_footprint());
    CHECK(r->core_mem&&r->contain_mem&&r->gate_mem&&r->bridge_mem);
    CHECK(argus_core_init(&r->core,r->core_mem,argus_core_footprint())==ARGUS_OK);
    CHECK(argus_contain_init(&r->contain,r->contain_mem,argus_contain_footprint())==ARGUS_OK);
    r->machine[0]=0xA1;
    CHECK(argus_aegis_bridge_init(&r->bridge,r->bridge_mem,argus_aegis_bridge_footprint(),
          r->core,r->contain,&r->gate,r->view,r->machine)==ARGUS_OK);
    ArgusEvent joined={0}; joined.version=ARGUS_ABI_VERSION; joined.class_=ARGUS_CLASS_SECURITY;
    joined.kind=ARGUS_EV_MACHINE_JOINED; joined.outcome=ARGUS_OUTCOME_OK;
    joined.flags=(uint16_t)((1u<<ARGUS_FLAG_STREAM_SHIFT)|ARGUS_FLAG_SYNTHETIC);
    joined.sequence=1; joined.object_id=ARGUS_TRUST_OBSERVED; joined.cap_id=ARGUS_CAP_NONE;
    memcpy(joined.machine_id,r->machine,sizeof joined.machine_id);
    CHECK(argus_aegis_bridge_ingest(r->bridge,&joined)==ARGUS_OK);
    r->policy.verdict[AIENOS_CONTAIN_REVOKE_CAPABILITY]=AIENOS_CONTAIN_GRANT;
    AienosContainAuthorizer az={aienos_contain_table_decide,&r->policy};
    CHECK(aienos_cap_set_observer(r->admin,argus_aegis_bridge_observer,r->bridge)==AIENOS_CAP_OK);
    CHECK(aienos_contain_create(&r->gate,r->gate_mem,aienos_contain_footprint(),r->admin,r->view,r->office,&az)==AIENOS_CONTAIN_OK);
    CHECK(argus_aegis_bridge_attach_gate(r->bridge)==ARGUS_OK);
}

static void teardown(Rig *r) {
    aienos_cap_set_observer(r->admin,NULL,NULL);
    aienos_contain_destroy(r->gate);
    argus_aegis_bridge_destroy(r->bridge);
    aienos_cap_stop(r->admin,r->view);
    free(r->bridge_mem); free(r->gate_mem); free(r->contain_mem); free(r->core_mem);
}

static AienosCapRef mint(Rig *r,uint32_t subject,uint32_t rights) {
    AienosCapMint m={0,subject,0x9000u+subject,rights,0,{AIENOS_CAP_PARENT_NONE,0},r->office};
    AienosCapRef out={AIENOS_CAP_PARENT_NONE,0};
    CHECK(aienos_cap_mint(r->admin,&m,&out)==AIENOS_CAP_OK);
    return out;
}

static AienosContainRequest request(uint64_t id,uint32_t subject,AienosCapRef target) {
    AienosContainRequest q={0};
    q.containment=AIENOS_CONTAIN_REVOKE_CAPABILITY; q.severity=ARGUS_SEV_HIGH;
    q.finding_code=ARGUS_F_STALE_GENERATION; q.principal=subject; q.target=target;
    q.request_id=id; q.finding_sequence=id; q.version=AIENOS_CONTAIN_REQUEST_VERSION;
    q.incident_id=id;
    q.finding_digest[0]=(uint8_t)id;
    return q;
}

static int live(Rig *r,AienosCapRef c) {
    AienosCapEntry e;
    return aienos_cap_inspect(r->view,c,&e)==AIENOS_CAP_OK && e.state==AIENOS_CAP_STATE_LIVE;
}

static ArgusEvent receipt_event(Rig *r,uint16_t kind,uint64_t seq,
                                const ArgusContainmentRequest *q,uint8_t status) {
    ArgusEvent e={0}; e.version=ARGUS_ABI_VERSION; e.class_=ARGUS_CLASS_CRITICAL;
    e.kind=kind; e.outcome=ARGUS_OUTCOME_OK; e.flags=(uint16_t)(2u<<ARGUS_FLAG_STREAM_SHIFT);
    e.sequence=seq; e.cap_id=q?q->target.cap_id:ARGUS_CAP_NONE;
    e.cap_generation=q?q->target.generation:0; e.principal=q?q->principal:0;
    e.world_generation=q?q->request_id:999;
    e.object_id=ARGUS_CONTAIN_PACK(q?q->containment:ARGUS_CONTAIN_REVOKE_CAPABILITY,
                                    status,q?q->finding_code:ARGUS_F_STALE_GENERATION);
    e.resource=kind==ARGUS_EV_CONTAINMENT_DECIDED?77:1;
    memcpy(e.machine_id,r->machine,sizeof e.machine_id);
    if(q) argus_contain_request_digest(q,e.evidence_digest);
    return e;
}

static int take_code(Rig *r,uint16_t kind,uint64_t seq,
                     const ArgusContainmentRequest *q,uint8_t status,uint16_t wanted) {
    ArgusEvent e=receipt_event(r,kind,seq,q,status);
    CHECK(argus_aegis_bridge_ingest(r->bridge,&e)==ARGUS_OK);
    ArgusFinding f[16]; size_t n=argus_aegis_bridge_take_findings(r->bridge,f,16);
    for(size_t i=0;i<n;i++) if(f[i].code==wanted) return 1;
    return 0;
}

static ArgusContainmentRequest make_proposal(Rig *r,AienosCapRef target) {
    ArgusFinding f={0}; f.code=ARGUS_F_STALE_GENERATION; f.severity=ARGUS_SEV_CRITICAL;
    f.confidence=ARGUS_CONF_DETERMINISTIC; f.containment=ARGUS_CONTAIN_REVOKE_CAPABILITY;
    f.sequence=2; f.principal=7; f.cap_id=target.cap_id; f.cap_generation=target.generation-1;
    memcpy(f.machine_id,r->machine,sizeof f.machine_id);
    ArgusEvent trigger={0}; trigger.sequence=2; trigger.kind=ARGUS_EV_STALE_GENERATION;
    trigger.cap_id=target.cap_id; trigger.cap_generation=target.generation-1;
    memcpy(trigger.machine_id,r->machine,sizeof trigger.machine_id);
    ArgusContainmentRequest q={0}; ArgusEvent prop={0}; size_t n=0;
    CHECK(argus_contain_propose(r->contain,r->core,&f,1,&trigger,&q,1,&prop,1,&n)==ARGUS_OK && n==1);
    CHECK(argus_aegis_bridge_ingest(r->bridge,&prop)==ARGUS_OK);
    return q;
}

static void hostile_receipt_transitions(void) {
    Rig r; setup(&r); AienosCapRef c=mint(&r,7,AIENOS_CAP_RIGHT_READ);
    CHECK(take_code(&r,ARGUS_EV_CONTAINMENT_DECIDED,1,NULL,ARGUS_CSTATUS_GRANT,
                    ARGUS_F_CONTAINMENT_DECISION_UNMATCHED));
    teardown(&r);

    setup(&r); c=mint(&r,7,AIENOS_CAP_RIGHT_READ);
    ArgusContainmentRequest q=make_proposal(&r,c);
    CHECK(take_code(&r,ARGUS_EV_CONTAINMENT_EXECUTED,1,&q,ARGUS_CSTATUS_DONE,
                    ARGUS_F_CONTAINMENT_EXECUTION_UNAUTHORIZED));
    teardown(&r);

    setup(&r); c=mint(&r,7,AIENOS_CAP_RIGHT_READ);
    q=make_proposal(&r,c);
    ArgusEvent grant=receipt_event(&r,ARGUS_EV_CONTAINMENT_DECIDED,1,&q,ARGUS_CSTATUS_GRANT);
    CHECK(argus_aegis_bridge_ingest(r.bridge,&grant)==ARGUS_OK);
    ArgusFinding scratch[8]; size_t nf=argus_aegis_bridge_take_findings(r.bridge,scratch,8);
    CHECK(nf==0);
    CHECK(take_code(&r,ARGUS_EV_CONTAINMENT_EXECUTED,2,&q,ARGUS_CSTATUS_DONE,
                    ARGUS_F_CONTAINMENT_EXECUTION_UNCONFIRMED));
    CHECK(live(&r,c));
    teardown(&r);
}

static void hostile_digest_and_scope(void) {
    Rig r; setup(&r);
    AienosCapRef c=mint(&r,7,AIENOS_CAP_RIGHT_READ);
    AienosContainRequest q=request(1,7,c); uint8_t d[AIENOS_CONTAIN_DIGEST_LEN];
    AienosContainDecision dec={0}; aienos_contain_request_digest(&q,d); d[0]^=0x80;
    CHECK(aienos_contain_submit(r.gate,&q,d,&dec)==AIENOS_CONTAIN_OK);
    CHECK(dec.status==AIENOS_CONTAIN_DENY && live(&r,c));

    /* Mint while the observer is detached: the gate cannot trust this target's lineage. */
    CHECK(aienos_cap_set_observer(r.admin,NULL,NULL)==AIENOS_CAP_OK);
    AienosCapRef pre=mint(&r,8,AIENOS_CAP_RIGHT_READ);
    CHECK(aienos_cap_set_observer(r.admin,argus_aegis_bridge_observer,r.bridge)==AIENOS_CAP_OK);
    q=request(2,8,pre); aienos_contain_request_digest(&q,d);
    CHECK(aienos_contain_submit(r.gate,&q,d,&dec)==AIENOS_CONTAIN_OK);
    CHECK(dec.status==AIENOS_CONTAIN_ESCALATE && !aienos_contain_inert(r.gate));
    AienosContainResult result={0};
    CHECK(aienos_contain_execute(r.gate,dec.decision_id,&result)!=AIENOS_CONTAIN_OK);
    CHECK(live(&r,pre));
    printf("HOSTILE bad_digest_denied %s\n",live(&r,c)?"PASS":"FAIL");
    printf("HOSTILE unobserved_target_cannot_auto_revoke %s\n",live(&r,pre)?"PASS":"FAIL");
    teardown(&r);
}

static void hostile_single_execution_and_replay(void) {
    Rig r; setup(&r);
    AienosCapRef c=mint(&r,11,AIENOS_CAP_RIGHT_READ);
    AienosContainRequest q=request(10,11,c); uint8_t d[AIENOS_CONTAIN_DIGEST_LEN];
    AienosContainDecision dec={0}; AienosContainResult result={0};
    aienos_contain_request_digest(&q,d);
    CHECK(aienos_contain_submit(r.gate,&q,d,&dec)==AIENOS_CONTAIN_OK);
    CHECK(dec.status==AIENOS_CONTAIN_GRANT);
    CHECK(aienos_contain_execute(r.gate,dec.decision_id,&result)==AIENOS_CONTAIN_OK);
    CHECK(result.status==AIENOS_CONTAIN_DONE && !live(&r,c));
    CHECK(aienos_contain_execute(r.gate,dec.decision_id,&result)!=AIENOS_CONTAIN_OK);
    CHECK(result.status==AIENOS_CONTAIN_FAILED);

    AienosCapRef next=mint(&r,12,AIENOS_CAP_RIGHT_READ);
    q=request(11,12,next); aienos_contain_request_digest(&q,d);
    CHECK(aienos_contain_submit(r.gate,&q,d,&dec)==AIENOS_CONTAIN_OK && dec.status==AIENOS_CONTAIN_GRANT);
    CHECK(aienos_contain_submit(r.gate,&q,d,&result)==AIENOS_CONTAIN_OK);
    CHECK(result.status==AIENOS_CONTAIN_DENY && live(&r,next));
    printf("HOSTILE execute_once_and_replay_denied %s\n",live(&r,next)?"PASS":"FAIL");
    teardown(&r);
}

static void hostile_protected_and_synthetic(void) {
    Rig r; setup(&r);
    AienosCapRef office=r.office;
    AienosContainRequest q=request(20,0,office); uint8_t d[AIENOS_CONTAIN_DIGEST_LEN];
    AienosContainDecision dec={0}; aienos_contain_request_digest(&q,d);
    CHECK(aienos_contain_submit(r.gate,&q,d,&dec)==AIENOS_CONTAIN_OK);
    CHECK(dec.status==AIENOS_CONTAIN_DENY && live(&r,office));

    q=request(21,31,(AienosCapRef){AIENOS_CONTAIN_CAP_NONE,0});
    q.containment=AIENOS_CONTAIN_QUARANTINE_MACHINE; q.flags=AIENOS_CREQ_SYNTHETIC;
    aienos_contain_request_digest(&q,d);
    CHECK(aienos_contain_submit(r.gate,&q,d,&dec)==AIENOS_CONTAIN_OK);
    CHECK(dec.status==AIENOS_CONTAIN_ESCALATE);
    AienosContainResult result={0};
    CHECK(aienos_contain_execute(r.gate,dec.decision_id,&result)!=AIENOS_CONTAIN_OK);
    CHECK(result.status==AIENOS_CONTAIN_FAILED);
    printf("HOSTILE protected_office_and_synthetic_scope %s\n",dec.status==AIENOS_CONTAIN_ESCALATE && result.status==AIENOS_CONTAIN_FAILED?"PASS":"FAIL");
    teardown(&r);
}

int main(void) {
    hostile_digest_and_scope();
    hostile_single_execution_and_replay();
    hostile_protected_and_synthetic();
    hostile_receipt_transitions();
    printf("ARGUS-1 hostile containment: %d checks, %d failures\n",checks,failures);
    return failures?1:0;
}
