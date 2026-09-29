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
    ArgusEvent trigger=event(ARGUS_EV_STALE_GENERATION,2); trigger.cap_id=5; trigger.cap_generation=8;
    ArgusContainmentRequest req[4]; ArgusEvent prop[4]; size_t np=0;
    CHECK(argus_contain_propose(state,core,&f,1,&trigger,req,4,prop,4,&np)==ARGUS_OK && np==1);
    CHECK(req[0].target.cap_id==5 && req[0].target.generation==9 && req[0].request_id==1);
    CHECK(prop[0].kind==ARGUS_EV_CONTAINMENT_PROPOSED && prop[0].world_generation==1);
    CHECK(argus_event_validate(&prop[0])==ARGUS_OK);
    uint8_t dig1[ARGUS_DIGEST_LEN],dig2[ARGUS_DIGEST_LEN];
    argus_contain_state_digest(state,dig1); argus_contain_state_digest(state,dig2);
    CHECK(memcmp(dig1,dig2,sizeof dig1)==0);

    /* An identical outstanding key is suppressed. */
    np=0; CHECK(argus_contain_propose(state,core,&f,1,&trigger,req,4,prop,4,&np)==ARGUS_OK && np==0);
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

    /* A closed confirmed key cannot be replayed; an unknown decision raises code 17. */
    np=0; CHECK(argus_contain_propose(state,core,&f,1,&trigger,req,4,prop,4,&np)==ARGUS_OK && np==0);
    argus_contain_health(state,&h); CHECK(h.suppressed_cooldown==1);
    ArgusEvent foreign=event(ARGUS_EV_CONTAINMENT_DECIDED,6); foreign.class_=ARGUS_CLASS_CRITICAL;
    foreign.world_generation=999; foreign.object_id=ARGUS_CONTAIN_PACK(ARGUS_CONTAIN_REVOKE_CAPABILITY,ARGUS_CSTATUS_GRANT,ARGUS_F_STALE_GENERATION);
    CHECK(argus_contain_observe(state,core,&foreign,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
    CHECK(nfind==1 && scratch[0].code==ARGUS_F_CONTAINMENT_DECISION_UNMATCHED);
    argus_contain_health(state,&h); CHECK(h.decisions_unmatched==1);

    /* A stale protected target is suppressed, even when the finding asks for revoke. */
    f.cap_id=0; f.sequence=8; np=99;
    CHECK(argus_contain_propose(state,core,&f,1,&trigger,req,4,prop,4,&np)==ARGUS_OK && np==0);
    argus_contain_health(state,&h); CHECK(h.suppressed_protected==1);

    /* Timeout origin is the last transition; no code 20 at exactly the limit,
     * then one code 20 after the limit. A separate request exercises expiry. */
    f.cap_id=5; f.sequence=10; f.code=ARGUS_F_FORGED_CAPABILITY;
    f.containment=ARGUS_CONTAIN_REVOKE_CAPABILITY; f.severity=ARGUS_SEV_CRITICAL;
    trigger.sequence=10; np=0; CHECK(argus_contain_propose(state,core,&f,1,&trigger,req,4,prop,4,&np)==ARGUS_OK && np==1);
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

    /* Non-live containment types remain explicitly synthetic and carry their target. */
    f.containment=ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE; f.code=ARGUS_F_CREDENTIAL_SCOPE_VIOLATION;
    f.sequence=20001; np=0;
    trigger.object_id=44; trigger.sequence=f.sequence;
    CHECK(argus_contain_propose(state,core,&f,1,&trigger,req,4,prop,4,&np)==ARGUS_OK && np==1);
    CHECK(req[0].flags==ARGUS_CREQ_SYNTHETIC && req[0].target.cap_id==ARGUS_CAP_NONE && req[0].target_object==44);

    /* A storm of distinct principals can only spend the fixed 16-per-window budget. */
    void *budget_mem=calloc(1,argus_contain_footprint()); ArgusContain *budget_state=NULL;
    CHECK(budget_mem && argus_contain_init(&budget_state,budget_mem,argus_contain_footprint())==ARGUS_OK);
    ArgusFinding storm[ARGUS_CONTAIN_WINDOW_MAX+1];
    for(size_t i=0;i<ARGUS_CONTAIN_WINDOW_MAX+1;i++) {
        memset(&storm[i],0,sizeof storm[i]); storm[i].code=ARGUS_F_CREDENTIAL_SCOPE_VIOLATION;
        storm[i].severity=ARGUS_SEV_HIGH; storm[i].confidence=ARGUS_CONF_DETERMINISTIC;
        storm[i].containment=ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE;
        storm[i].sequence=300+i; storm[i].principal=(uint32_t)(100+i); storm[i].machine_id[0]=0xA5;
    }
    ArgusContainmentRequest storm_req[ARGUS_CONTAIN_WINDOW_MAX+1];
    ArgusEvent storm_events[ARGUS_CONTAIN_WINDOW_MAX+1]; size_t storm_n=0;
    trigger.object_id=90;
    CHECK(argus_contain_propose(budget_state,core,storm,ARGUS_CONTAIN_WINDOW_MAX+1,&trigger,
          storm_req,ARGUS_CONTAIN_WINDOW_MAX+1,storm_events,ARGUS_CONTAIN_WINDOW_MAX+1,&storm_n)==ARGUS_OK);
    CHECK(storm_n==ARGUS_CONTAIN_WINDOW_MAX);
    for(size_t i=0;i<storm_n;i++) CHECK(argus_event_validate(&storm_events[i])==ARGUS_OK);
    ArgusContainHealth budget_health; argus_contain_health(budget_state,&budget_health);
    CHECK(budget_health.requested==ARGUS_CONTAIN_WINDOW_MAX && budget_health.suppressed_budget==1);
    free(budget_mem);

    /* Pending-table overflow reports one explicit CRITICAL telemetry event. */
    void *full_mem=calloc(1,argus_contain_footprint()); ArgusContain *full_state=NULL;
    CHECK(full_mem && argus_contain_init(&full_state,full_mem,argus_contain_footprint())==ARGUS_OK);
    ArgusFinding batch[ARGUS_CONTAIN_WINDOW_MAX]; ArgusContainmentRequest batch_req[ARGUS_CONTAIN_WINDOW_MAX];
    ArgusEvent batch_events[ARGUS_CONTAIN_WINDOW_MAX];
    for(unsigned window=0;window<2;window++) {
        for(size_t i=0;i<ARGUS_CONTAIN_WINDOW_MAX;i++) {
            memset(&batch[i],0,sizeof batch[i]); batch[i].code=ARGUS_F_CREDENTIAL_SCOPE_VIOLATION;
            batch[i].severity=ARGUS_SEV_HIGH; batch[i].confidence=ARGUS_CONF_DETERMINISTIC;
            batch[i].containment=ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE;
            batch[i].sequence=500+window*100+i; batch[i].principal=500+(uint32_t)(window*100+i);
            batch[i].machine_id[0]=0xA5;
        }
        size_t batch_n=0;
        CHECK(argus_contain_propose(full_state,core,batch,ARGUS_CONTAIN_WINDOW_MAX,&trigger,
              batch_req,ARGUS_CONTAIN_WINDOW_MAX,batch_events,ARGUS_CONTAIN_WINDOW_MAX,&batch_n)==ARGUS_OK);
        CHECK(batch_n==ARGUS_CONTAIN_WINDOW_MAX);
        for(size_t i=0;i<batch_n;i++) CHECK(argus_contain_observe(full_state,core,&batch_events[i],scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
        if(window==0) for(uint64_t i=0;i<4090;i++) {
            ArgusEvent tick=event(ARGUS_EV_TELEMETRY_DROPPED,1000+i);
            if(argus_contain_observe(full_state,core,&tick,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)!=ARGUS_OK) failures++;
        }
    }
    for(uint64_t i=0;i<4080;i++) {
        ArgusEvent tick=event(ARGUS_EV_TELEMETRY_DROPPED,6000+i);
        if(argus_contain_observe(full_state,core,&tick,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)!=ARGUS_OK) failures++;
    }
    ArgusFinding overflow_f=batch[0]; overflow_f.principal=900; overflow_f.sequence=9000;
    size_t overflow_n=0;
    CHECK(argus_contain_propose(full_state,core,&overflow_f,1,&trigger,batch_req,ARGUS_CONTAIN_WINDOW_MAX,
          batch_events,ARGUS_CONTAIN_WINDOW_MAX,&overflow_n)==ARGUS_OK && overflow_n==0);
    ArgusEvent loss={0}; CHECK(argus_contain_take_overflow_event(full_state,&loss)==ARGUS_OK);
    CHECK(loss.kind==ARGUS_EV_TELEMETRY_DROPPED && loss.class_==ARGUS_CLASS_CRITICAL && loss.resource==1);
    CHECK(argus_event_validate(&loss)==ARGUS_OK);
    CHECK(argus_contain_take_overflow_event(full_state,&loss)==ARGUS_ERR_STATE);
    free(full_mem);

    /* ESCALATE permits one follow-up decision; DENY closes and cools down the key. */
    void *deny_mem=calloc(1,argus_contain_footprint()); ArgusContain *deny_state=NULL;
    CHECK(deny_mem && argus_contain_init(&deny_state,deny_mem,argus_contain_footprint())==ARGUS_OK);
    f.code=ARGUS_F_STALE_GENERATION; f.containment=ARGUS_CONTAIN_REVOKE_CAPABILITY;
    f.cap_id=5; f.sequence=10000; f.severity=ARGUS_SEV_HIGH; f.confidence=ARGUS_CONF_DETERMINISTIC;
    trigger.sequence=f.sequence;
    np=0; CHECK(argus_contain_propose(deny_state,core,&f,1,&trigger,req,4,prop,4,&np)==ARGUS_OK && np==1);
    CHECK(argus_contain_observe(deny_state,core,&prop[0],scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK);
    decision=event(ARGUS_EV_CONTAINMENT_DECIDED,10001); decision.class_=ARGUS_CLASS_CRITICAL;
    decision.world_generation=req[0].request_id; decision.object_id=ARGUS_CONTAIN_PACK(req[0].containment,ARGUS_CSTATUS_ESCALATE,req[0].finding_code);
    decision.cap_id=req[0].target.cap_id; decision.cap_generation=req[0].target.generation;
    memcpy(decision.machine_id,req[0].machine_id,ARGUS_MACHINE_ID_LEN); argus_contain_request_digest(&req[0],decision.evidence_digest);
    CHECK(argus_contain_observe(deny_state,core,&decision,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK && nfind==0);
    decision.sequence++; decision.object_id=ARGUS_CONTAIN_PACK(req[0].containment,ARGUS_CSTATUS_DENY,req[0].finding_code);
    decision.outcome=ARGUS_OUTCOME_DENIED;
    CHECK(argus_contain_observe(deny_state,core,&decision,scratch,ARGUS_CORE_MAX_FINDINGS,&nfind)==ARGUS_OK && nfind==0);
    argus_contain_health(deny_state,&h); CHECK(h.escalated==1 && h.denied==1);
    np=0; CHECK(argus_contain_propose(deny_state,core,&f,1,&trigger,req,4,prop,4,&np)==ARGUS_OK && np==0);
    argus_contain_health(deny_state,&h); CHECK(h.suppressed_cooldown==1);
    free(deny_mem);

    printf("ARGUS-1 containment: %d checks, %d failures; state bytes=%zu\n",checks,failures,argus_contain_footprint());
    free(smem); free(cmem); return failures?1:0;
}
