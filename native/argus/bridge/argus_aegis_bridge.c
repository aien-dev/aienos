#include "argus_aegis_bridge.h"

#include <pthread.h>
#include <string.h>

#define BRIDGE_REQUESTS 32u
#define BRIDGE_FINDINGS 128u

typedef struct {
    uint64_t request_id;
    uint8_t machine_id[ARGUS_MACHINE_ID_LEN];
    uint8_t digest[ARGUS_DIGEST_LEN];
} BridgeRequest;

struct ArgusAegisBridge {
    pthread_mutex_t lock;
    ArgusCore *core;
    ArgusContain *contain;
    AienosContain **gate_ref;
    const AienosCapView *view;
    uint8_t machine_id[ARGUS_MACHINE_ID_LEN];
    uint64_t sequence;
    int error;
    BridgeRequest requests[BRIDGE_REQUESTS];
    ArgusFinding findings[BRIDGE_FINDINGS];
    size_t finding_count;
};

static int zero_digest(const uint8_t d[ARGUS_DIGEST_LEN])
{
    uint8_t v=0; for(size_t i=0;i<ARGUS_DIGEST_LEN;i++) v|=d[i]; return v==0;
}

size_t argus_aegis_bridge_footprint(void) { return sizeof(ArgusAegisBridge); }

int argus_aegis_bridge_init(ArgusAegisBridge **out, void *memory, size_t bytes,
                            ArgusCore *core, ArgusContain *contain,
                            AienosContain **gate_ref, const AienosCapView *view,
                            const uint8_t machine_id[ARGUS_MACHINE_ID_LEN])
{
    if(!out || !memory || bytes<sizeof(ArgusAegisBridge) || !core || !contain || !gate_ref || !machine_id)
        return ARGUS_ERR_ARG;
    memset(memory,0,sizeof(ArgusAegisBridge));
    ArgusAegisBridge *b=(ArgusAegisBridge *)memory;
    if(pthread_mutex_init(&b->lock,NULL)!=0) return ARGUS_ERR_STATE;
    b->core=core; b->contain=contain; b->gate_ref=gate_ref; b->view=view;
    memcpy(b->machine_id,machine_id,ARGUS_MACHINE_ID_LEN); b->sequence=1;
    *out=b; return ARGUS_OK;
}
void argus_aegis_bridge_destroy(ArgusAegisBridge *b)
{ if(b) (void)pthread_mutex_destroy(&b->lock); }

static const BridgeRequest *request_by_id(const ArgusAegisBridge *b, uint64_t id)
{
    for(size_t i=0;i<BRIDGE_REQUESTS;i++) if(b->requests[i].request_id==id) return &b->requests[i];
    return NULL;
}

static int append_findings(ArgusAegisBridge *b, const ArgusFinding *a, size_t na,
                           const ArgusFinding *c, size_t nc)
{
    if(na+nc>BRIDGE_FINDINGS-b->finding_count) return ARGUS_ERR_OVERFLOW;
    if(na) { memcpy(b->findings+b->finding_count,a,na*sizeof *a); b->finding_count+=na; }
    if(nc) { memcpy(b->findings+b->finding_count,c,nc*sizeof *c); b->finding_count+=nc; }
    return ARGUS_OK;
}

static int ingest_locked(ArgusAegisBridge *b, const ArgusEvent *ev)
{
    ArgusFinding core_findings[ARGUS_CORE_MAX_FINDINGS];
    ArgusFinding contain_findings[ARGUS_CORE_MAX_FINDINGS];
    size_t ncore=0,ncontain=0;
    int rc=argus_core_ingest(b->core,ev,core_findings,ARGUS_CORE_MAX_FINDINGS,&ncore);
    if(rc!=ARGUS_OK && rc!=ARGUS_ERR_FULL) return rc;
    int core_rc=rc;
    rc=argus_contain_observe(b->contain,b->core,ev,contain_findings,ARGUS_CORE_MAX_FINDINGS,&ncontain);
    if(rc!=ARGUS_OK) return rc;
    rc=append_findings(b,core_findings,ncore,contain_findings,ncontain);
    return rc==ARGUS_OK?core_rc:rc;
}

int argus_aegis_bridge_ingest(ArgusAegisBridge *b, const ArgusEvent *ev)
{
    if(!b || !ev) return ARGUS_ERR_ARG;
    pthread_mutex_lock(&b->lock); int rc=ingest_locked(b,ev);
    if(rc!=ARGUS_OK && rc!=ARGUS_ERR_FULL) b->error=rc;
    pthread_mutex_unlock(&b->lock); return rc;
}

static void receipt_sink(void *ctx, const AienosContainReceipt *r)
{
    ArgusAegisBridge *b=(ArgusAegisBridge *)ctx;
    if(!b || !r) return;
    pthread_mutex_lock(&b->lock);
    if(b->sequence==0 || b->sequence==UINT64_MAX) {
        b->error=ARGUS_ERR_FULL; pthread_mutex_unlock(&b->lock); return;
    }
    const BridgeRequest *q=request_by_id(b,r->request_id);
    if(!q) { b->error=ARGUS_ERR_STATE; pthread_mutex_unlock(&b->lock); return; }
    ArgusEvent e={0}; e.version=ARGUS_ABI_VERSION; e.class_=ARGUS_CLASS_CRITICAL;
    e.kind=(uint16_t)r->kind; e.effect_class=ARGUS_EFFECT_NONE;
    e.sequence=b->sequence++; e.tick=r->tick; e.principal=r->principal; e.cap_id=r->target.cap_id;
    e.cap_generation=r->target.generation; e.world_generation=r->request_id;
    e.object_id=ARGUS_CONTAIN_PACK(r->type,r->status,r->finding_code); e.resource=r->resource;
    e.code=(e.kind==ARGUS_EV_CONTAINMENT_DECIDED)?(int32_t)r->why:r->rc;
    e.outcome=(r->status==ARGUS_CSTATUS_GRANT || r->status==ARGUS_CSTATUS_DONE || r->status==ARGUS_CSTATUS_PARTIAL)?ARGUS_OUTCOME_OK:
        (r->status==ARGUS_CSTATUS_DENY || (r->status==ARGUS_CSTATUS_FAILED && r->rc<0))?ARGUS_OUTCOME_DENIED:ARGUS_OUTCOME_ERROR;
    e.flags=(uint16_t)(ARGUS_STREAM_BRIDGE<<ARGUS_FLAG_STREAM_SHIFT);
    if(r->flags&AIENOS_CREQ_SYNTHETIC) e.flags|=ARGUS_FLAG_SYNTHETIC;
    memcpy(e.machine_id,q->machine_id,ARGUS_MACHINE_ID_LEN);
    memcpy(e.evidence_digest,r->request_digest,ARGUS_DIGEST_LEN);
    int rc=ingest_locked(b,&e); if(rc!=ARGUS_OK && rc!=ARGUS_ERR_FULL) b->error=rc;
    pthread_mutex_unlock(&b->lock);
}

int argus_aegis_bridge_attach_gate(ArgusAegisBridge *b)
{
    if(!b || !b->gate_ref || !*b->gate_ref) return ARGUS_ERR_ARG;
    return aienos_contain_set_sink(*b->gate_ref,receipt_sink,b)==AIENOS_CONTAIN_OK?ARGUS_OK:ARGUS_ERR_STATE;
}

void argus_aegis_bridge_observer(void *ctx, uint32_t op, const AienosCapEntry *entry, int result)
{
    ArgusAegisBridge *b=(ArgusAegisBridge *)ctx;
    if(!b) return;
    if(b->gate_ref && *b->gate_ref) aienos_contain_lineage_observe(*b->gate_ref,op,entry,result);
    if(result!=AIENOS_CAP_OK || !entry || (op!=AIENOS_CAP_OBS_MINT && op!=AIENOS_CAP_OBS_REVOKE)) return;
    ArgusEvent e={0}; e.version=ARGUS_ABI_VERSION; e.class_=(op==AIENOS_CAP_OBS_MINT)?ARGUS_CLASS_SECURITY:ARGUS_CLASS_CRITICAL;
    e.kind=(op==AIENOS_CAP_OBS_MINT)?ARGUS_EV_CAPABILITY_GRANTED:ARGUS_EV_CAPABILITY_REVOKED;
    e.effect_class=ARGUS_EFFECT_NONE; e.outcome=ARGUS_OUTCOME_OK; e.cap_id=entry->cap_id;
    e.object_id=entry->rights; e.cap_generation=entry->generation; e.principal=entry->subject;
    e.resource=entry->resource; e.flags=(uint16_t)(ARGUS_STREAM_BRIDGE<<ARGUS_FLAG_STREAM_SHIFT);
    if(b->view) e.tick=aienos_cap_clock(b->view);
    memcpy(e.machine_id,b->machine_id,ARGUS_MACHINE_ID_LEN);
    pthread_mutex_lock(&b->lock);
    if(b->sequence==0 || b->sequence==UINT64_MAX) b->error=ARGUS_ERR_FULL;
    else { e.sequence=b->sequence++; int rc=ingest_locked(b,&e); if(rc!=ARGUS_OK && rc!=ARGUS_ERR_FULL) b->error=rc; }
    pthread_mutex_unlock(&b->lock);
}

int argus_aegis_bridge_submit(ArgusAegisBridge *b, const ArgusContainmentRequest *r,
                             AienosContainDecision *decision, AienosContainResult *result)
{
    if(!b || !r || !decision || !result || !b->gate_ref || !*b->gate_ref) return ARGUS_ERR_ARG;
    BridgeRequest saved={0}; saved.request_id=r->request_id; argus_contain_request_digest(r,saved.digest);
    if(zero_digest(r->machine_id)) memcpy(saved.machine_id,r->target_digest,ARGUS_MACHINE_ID_LEN);
    else memcpy(saved.machine_id,r->machine_id,ARGUS_MACHINE_ID_LEN);
    pthread_mutex_lock(&b->lock); b->requests[r->request_id%BRIDGE_REQUESTS]=saved; pthread_mutex_unlock(&b->lock);

    AienosContainRequest ar={0};
    ar.incident_id=r->incident_id; ar.containment=r->containment; ar.severity=r->severity;
    ar.finding_code=r->finding_code; ar.principal=r->principal; ar.target.cap_id=r->target.cap_id;
    ar.target.generation=r->target.generation; memcpy(ar.machine_id,r->machine_id,ARGUS_MACHINE_ID_LEN);
    memcpy(ar.finding_digest,r->finding_digest,ARGUS_DIGEST_LEN); ar.request_id=r->request_id;
    ar.finding_sequence=r->finding_sequence; ar.target_object=r->target_object; ar.target_rights=r->target_rights;
    memcpy(ar.target_digest,r->target_digest,ARGUS_DIGEST_LEN); ar.flags=r->flags; ar.version=r->version; ar.reserved=r->reserved;
    int rc=aienos_contain_submit(*b->gate_ref,&ar,saved.digest,decision);
    if(rc!=AIENOS_CONTAIN_OK) return ARGUS_ERR_STATE;
    if(decision->status==AIENOS_CONTAIN_GRANT) {
        rc=aienos_contain_execute(*b->gate_ref,decision->decision_id,result);
        if(rc!=AIENOS_CONTAIN_OK) return ARGUS_ERR_STATE;
    } else memset(result,0,sizeof *result);
    return argus_aegis_bridge_error(b);
}

size_t argus_aegis_bridge_take_findings(ArgusAegisBridge *b, ArgusFinding *out, size_t cap)
{
    if(!b || !out || cap==0) return 0;
    pthread_mutex_lock(&b->lock); size_t n=b->finding_count<cap?b->finding_count:cap;
    if(n) { memcpy(out,b->findings,n*sizeof *out); memmove(b->findings,b->findings+n,(b->finding_count-n)*sizeof *out); b->finding_count-=n; }
    pthread_mutex_unlock(&b->lock); return n;
}

int argus_aegis_bridge_error(const ArgusAegisBridge *b)
{
    if(!b) return ARGUS_ERR_ARG;
    ArgusAegisBridge *m=(ArgusAegisBridge *)b; pthread_mutex_lock(&m->lock); int rc=m->error; pthread_mutex_unlock(&m->lock); return rc;
}
