#include "../argus_abi.h"
#include "../argus_core.h"
#include "../argus_contain.h"
#include "../bridge/argus_aegis_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(x) do { checks++; if(!(x)) { failures++; fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); } } while(0)

int main(void)
{
    AienosCapAdmin *admin=NULL; AienosCapView *view=NULL; AienosCapRef office={0};
    CHECK(aienos_cap_start(&admin,&view)==AIENOS_CAP_OK);
    CHECK(aienos_cap_office(admin,&office)==AIENOS_CAP_OK);

    void *core_mem=calloc(1,argus_core_footprint());
    void *contain_mem=calloc(1,argus_contain_footprint());
    void *gate_mem=calloc(1,aienos_contain_footprint());
    void *bridge_mem=calloc(1,argus_aegis_bridge_footprint());
    CHECK(core_mem&&contain_mem&&gate_mem&&bridge_mem);
    ArgusCore *core=NULL; ArgusContain *contain=NULL; AienosContain *gate=NULL;
    CHECK(argus_core_init(&core,core_mem,argus_core_footprint())==ARGUS_OK);
    CHECK(argus_contain_init(&contain,contain_mem,argus_contain_footprint())==ARGUS_OK);
    uint8_t machine[ARGUS_MACHINE_ID_LEN]={0}; machine[0]=0xA1;
    ArgusAegisBridge *bridge=NULL;
    CHECK(argus_aegis_bridge_init(&bridge,bridge_mem,argus_aegis_bridge_footprint(),core,contain,
          &gate,view,machine)==ARGUS_OK);

    ArgusEvent joined={0}; joined.version=ARGUS_ABI_VERSION; joined.class_=ARGUS_CLASS_SECURITY;
    joined.kind=ARGUS_EV_MACHINE_JOINED; joined.outcome=ARGUS_OUTCOME_OK;
    joined.flags=(uint16_t)(1u<<ARGUS_FLAG_STREAM_SHIFT)|ARGUS_FLAG_SYNTHETIC;
    joined.sequence=1; joined.object_id=ARGUS_TRUST_OBSERVED; joined.cap_id=ARGUS_CAP_NONE;
    memcpy(joined.machine_id,machine,sizeof machine);
    CHECK(argus_aegis_bridge_ingest(bridge,&joined)==ARGUS_OK);

    /* Observer registration precedes create so the executor mint seeds both shadows. */
    CHECK(aienos_cap_set_observer(admin,argus_aegis_bridge_observer,bridge)==AIENOS_CAP_OK);
    AienosContainTablePolicy policy={0}; policy.verdict[AIENOS_CONTAIN_REVOKE_CAPABILITY]=AIENOS_CONTAIN_GRANT;
    AienosContainAuthorizer authorizer={aienos_contain_table_decide,&policy};
    CHECK(aienos_contain_create(&gate,gate_mem,aienos_contain_footprint(),admin,view,office,&authorizer)==AIENOS_CONTAIN_OK);
    CHECK(argus_aegis_bridge_attach_gate(bridge)==ARGUS_OK);

    /* A normal leaf capability is minted after gate creation and observed. */
    AienosCapMint mint={0,7,0x1234,AIENOS_CAP_RIGHT_READ,0,{AIENOS_CAP_PARENT_NONE,0},office};
    AienosCapRef target={0}; CHECK(aienos_cap_mint(admin,&mint,&target)==AIENOS_CAP_OK);

    /* A stale successful use creates one deterministic revoke proposal. */
    ArgusEvent use={0}; use.version=ARGUS_ABI_VERSION; use.class_=ARGUS_CLASS_AUDIT;
    use.kind=ARGUS_EV_CAPABILITY_USED; use.effect_class=ARGUS_EFFECT_NONE; use.outcome=ARGUS_OUTCOME_OK;
    use.flags=(uint16_t)(1u<<ARGUS_FLAG_STREAM_SHIFT); use.sequence=2; use.code=AIENOS_CAP_ERR_STALE_GEN;
    use.cap_id=target.cap_id; use.cap_generation=target.generation; use.principal=7;
    memcpy(use.machine_id,machine,sizeof machine);
    CHECK(argus_aegis_bridge_ingest(bridge,&use)==ARGUS_OK);
    ArgusFinding found[16]; size_t nf=argus_aegis_bridge_take_findings(bridge,found,16);
    CHECK(nf==1 && found[0].code==ARGUS_F_STALE_GENERATION && found[0].containment==ARGUS_CONTAIN_REVOKE_CAPABILITY);

    ArgusContainmentRequest request[1]; ArgusEvent proposed[1]; size_t np=0;
    CHECK(argus_contain_propose(contain,core,found,nf,&use,request,1,proposed,1,&np)==ARGUS_OK && np==1);
    CHECK(argus_aegis_bridge_ingest(bridge,&proposed[0])==ARGUS_OK);
    AienosContainDecision decision={0}; AienosContainResult result={0};
    CHECK(argus_aegis_bridge_submit(bridge,&request[0],&decision,&result)==ARGUS_OK);
    CHECK(decision.status==AIENOS_CONTAIN_GRANT && result.status==AIENOS_CONTAIN_DONE);
    AienosCapEntry after={0}; CHECK(aienos_cap_inspect(view,target,&after)==AIENOS_CAP_OK);
    CHECK(after.state==AIENOS_CAP_STATE_REVOKED);
    ArgusContainHealth health; argus_contain_health(contain,&health);
    CHECK(health.requested==1 && health.granted==1 && health.confirmed==1 && health.failed_scope==0);
    CHECK(argus_aegis_bridge_error(bridge)==ARGUS_OK);

    ArgusCoreHealth core_health; argus_core_health(core,&core_health);
    CHECK(core_health.events_received>=6 && core_health.events_rejected==0);

    /* Stop callbacks before destroying the gate; this is part of its lifetime contract. */
    CHECK(aienos_cap_set_observer(admin,NULL,NULL)==AIENOS_CAP_OK);
    aienos_contain_destroy(gate); argus_aegis_bridge_destroy(bridge);
    aienos_cap_stop(admin,view);
    free(bridge_mem); free(gate_mem); free(contain_mem); free(core_mem);
    printf("ARGUS-1 bridge end-to-end: %d checks, %d failures\n",checks,failures);
    return failures?1:0;
}
