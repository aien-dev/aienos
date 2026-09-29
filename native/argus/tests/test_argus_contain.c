#include "../argus_abi.h"
#include "../argus_core.h"
#include "../argus_contain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(x) do { checks++; if(!(x)) { failures++; fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); } } while(0)

static ArgusEvent event(uint16_t kind, uint64_t seq)
{
    ArgusEvent e={0}; e.version=ARGUS_ABI_VERSION; e.kind=kind; e.sequence=seq;
    e.class_=argus_event_min_class(kind); e.outcome=ARGUS_OUTCOME_OK;
    e.cap_id=ARGUS_CAP_NONE; e.principal=7; e.machine_id[0]=0xA5; return e;
}

int main(void)
{
    void *cmem=calloc(1,argus_core_footprint());
    void *smem=calloc(1,argus_contain_footprint());
    ArgusCore *core=NULL; ArgusContain *state=NULL;
    CHECK(cmem && smem);
    CHECK(argus_core_init(&core,cmem,argus_core_footprint())==ARGUS_OK);
    CHECK(argus_contain_init(&state,smem,argus_contain_footprint())==ARGUS_OK);

    /* Seed one ordinary LIVE cap in the actual core shadow. */
    ArgusEvent grant=event(ARGUS_EV_CAPABILITY_GRANTED,1);
    grant.class_=ARGUS_CLASS_SECURITY; grant.cap_id=5; grant.cap_generation=9;
    grant.object_id=1u; grant.resource=0x100;
    ArgusFinding scratch[ARGUS_CORE_MAX_FINDINGS]; size_t nf=0;
    CHECK(argus_core_ingest(core,&grant,scratch,ARGUS_CORE_MAX_FINDINGS,&nf)==ARGUS_OK);

    ArgusFinding f={0}; f.code=ARGUS_F_STALE_GENERATION; f.severity=ARGUS_SEV_CRITICAL;
    f.confidence=ARGUS_CONF_DETERMINISTIC; f.containment=ARGUS_CONTAIN_REVOKE_CAPABILITY;
    f.sequence=2; f.principal=7; f.cap_id=5; f.cap_generation=8; f.machine_id[0]=0xA5;
    ArgusContainmentRequest req[4]; ArgusEvent prop[4]; size_t np=0;
    CHECK(argus_contain_propose(state,core,&f,1,req,4,prop,4,&np)==ARGUS_OK && np==1);
    CHECK(req[0].target.cap_id==5 && req[0].target.generation==9 && req[0].request_id==1);
    CHECK(prop[0].kind==ARGUS_EV_CONTAINMENT_PROPOSED && prop[0].world_generation==1);
    CHECK(argus_event_validate(&prop[0])==ARGUS_OK);
    uint8_t dig1[ARGUS_DIGEST_LEN],dig2[ARGUS_DIGEST_LEN];
    argus_contain_state_digest(state,dig1); argus_contain_state_digest(state,dig2);
    CHECK(memcmp(dig1,dig2,sizeof dig1)==0);

    /* An identical outstanding key is suppressed. */
    np=0; CHECK(argus_contain_propose(state,core,&f,1,req,4,prop,4,&np)==ARGUS_OK && np==0);
    ArgusContainHealth h; argus_contain_health(state,&h); CHECK(h.suppressed_dedup==1);

    /* 90 -> 91 GRANT -> observer kind 4 -> 92 DONE confirms only the observed action. */
    size_t nfind=0;
    CHECK(argus_contain_observe(state,core,&prop[0],scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
    ArgusEvent decision=event(ARGUS_EV_CONTAINMENT_DECIDED,3);
    decision.class_=ARGUS_CLASS_CRITICAL; decision.world_generation=req[0].request_id;
    decision.object_id=ARGUS_CONTAIN_PACK(req[0].containment,ARGUS_CSTATUS_GRANT,req[0].finding_code);
    decision.cap_id=req[0].target.cap_id; decision.cap_generation=req[0].target.generation;
    memcpy(decision.machine_id,req[0].machine_id,ARGUS_MACHINE_ID_LEN);
    argus_contain_request_digest(&req[0],decision.evidence_digest);
    CHECK(argus_contain_observe(state,core,&decision,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK && nfind==0);
    ArgusEvent revoke=event(ARGUS_EV_CAPABILITY_REVOKED,4); revoke.class_=ARGUS_CLASS_CRITICAL;
    revoke.cap_id=req[0].target.cap_id; revoke.cap_generation=req[0].target.generation;
    CHECK(argus_contain_observe(state,core,&revoke,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
    ArgusEvent done=event(ARGUS_EV_CONTAINMENT_EXECUTED,5); done.class_=ARGUS_CLASS_CRITICAL;
    done.world_generation=req[0].request_id; done.object_id=ARGUS_CONTAIN_PACK(req[0].containment,ARGUS_CSTATUS_DONE,req[0].finding_code);
    done.resource=1; done.cap_id=req[0].target.cap_id; done.cap_generation=req[0].target.generation;
    memcpy(done.machine_id,req[0].machine_id,ARGUS_MACHINE_ID_LEN); argus_contain_request_digest(&req[0],done.evidence_digest);
    CHECK(argus_contain_observe(state,core,&done,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK && nfind==0);
    argus_contain_health(state,&h); CHECK(h.requested==1 && h.granted==1 && h.confirmed==1 && h.failed==0);

    /* A stale protected target is suppressed, even when the finding asks for revoke. */
    f.cap_id=0; f.sequence=8; np=99;
    CHECK(argus_contain_propose(state,core,&f,1,req,4,prop,4,&np)==ARGUS_OK && np==0);
    argus_contain_health(state,&h); CHECK(h.suppressed_protected==1);

    /* Timeout origin is the last transition; no code 20 at exactly the limit,
     * then one code 20 after the limit. A separate request exercises expiry. */
    f.cap_id=5; f.sequence=10; f.code=ARGUS_F_FORGED_CAPABILITY;
    f.containment=ARGUS_CONTAIN_REVOKE_CAPABILITY; f.severity=ARGUS_SEV_CRITICAL;
    np=0; CHECK(argus_contain_propose(state,core,&f,1,req,4,prop,4,&np)==ARGUS_OK && np==1);
    CHECK(argus_contain_observe(state,core,&prop[0],scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
    decision=event(ARGUS_EV_CONTAINMENT_DECIDED,11); decision.class_=ARGUS_CLASS_CRITICAL;
    decision.world_generation=req[0].request_id; decision.object_id=ARGUS_CONTAIN_PACK(req[0].containment,ARGUS_CSTATUS_ESCALATE,req[0].finding_code);
    decision.cap_id=req[0].target.cap_id; decision.cap_generation=req[0].target.generation;
    memcpy(decision.machine_id,req[0].machine_id,ARGUS_MACHINE_ID_LEN); argus_contain_request_digest(&req[0],decision.evidence_digest);
    CHECK(argus_contain_observe(state,core,&decision,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
    for(uint64_t i=0;i<ARGUS_CONTAIN_TIMEOUT_EVENTS;i++) {
        ArgusEvent tick=event(ARGUS_EV_TELEMETRY_DROPPED,12+i);
        CHECK(argus_contain_observe(state,core,&tick,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
        if(i==ARGUS_CONTAIN_TIMEOUT_EVENTS-1) CHECK(nfind==0);
    }
    ArgusEvent tick=event(ARGUS_EV_TELEMETRY_DROPPED,20000);
    CHECK(argus_contain_observe(state,core,&tick,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
    CHECK(nfind==1 && scratch[0].code==ARGUS_F_CONTAINMENT_UNANSWERED);
    argus_contain_health(state,&h); CHECK(h.expired==1);
    argus_contain_state_digest(state,dig1);
    argus_contain_state_digest(state,dig2);
    CHECK(memcmp(dig1,dig2,sizeof dig1)==0);

    printf("ARGUS-1 containment: %d checks, %d failures; state bytes=%zu\n",checks,failures,argus_contain_footprint());
    free(smem); free(cmem); return failures?1:0;
}
