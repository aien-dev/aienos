#include "argus_contain.h"
#include "argus_core.h"
#include "sha256.h"

#include <string.h>

enum { ST_FREE=0, ST_PROPOSED, ST_GRANTED, ST_ESCALATED, ST_CONFIRMED,
       ST_DENIED, ST_FAILED, ST_FAILED_SCOPE, ST_EXPIRED };

typedef struct {
    ArgusContainmentRequest req;
    uint8_t digest[ARGUS_DIGEST_LEN];
    uint8_t state, kind4_count, retries;
    uint64_t entered, decision_id, closed_at;
} Pending;

typedef struct {
    uint8_t used, type, severity, state, retries;
    uint32_t principal, cap_id, target_object;
    uint64_t generation, last_event, request_id;
    uint16_t finding_code;
    uint8_t digest[ARGUS_DIGEST_LEN];
} Recent;

struct ArgusContain {
    uint64_t events, next_request_id, next_proposal_sequence, window_start;
    uint32_t window_count;
    uint32_t executor_cap_id;
    uint8_t overflow_reported;
    Pending pending[ARGUS_CONTAIN_PENDING];
    Recent recent[ARGUS_CONTAIN_RECENT];
    ArgusContainHealth health;
};

static void wr32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void wr16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void wr64(uint8_t *p, uint64_t v)
{ wr32(p,(uint32_t)v); wr32(p+4,(uint32_t)(v>>32)); }

size_t argus_contain_footprint(void) { return sizeof(ArgusContain); }
int argus_contain_init(ArgusContain **state, void *memory, size_t bytes)
{
    if (!state || !memory || bytes < sizeof(ArgusContain)) return ARGUS_ERR_ARG;
    memset(memory,0,sizeof(ArgusContain));
    *state=(ArgusContain *)memory;
    (*state)->next_request_id=1;
    (*state)->next_proposal_sequence=1;
    return ARGUS_OK;
}

static int is_open(uint8_t s)
{ return s==ST_PROPOSED || s==ST_GRANTED || s==ST_ESCALATED; }

static int same_key_req(const ArgusContainmentRequest *a, const ArgusContainmentRequest *b)
{
    return a->containment==b->containment && a->principal==b->principal &&
        a->target.cap_id==b->target.cap_id && a->target.generation==b->target.generation &&
        a->target_object==b->target_object && a->finding_code==b->finding_code;
}
static int same_key_recent(const Recent *a, const ArgusContainmentRequest *b)
{
    return a->used && a->type==b->containment && a->principal==b->principal &&
        a->cap_id==b->target.cap_id && a->generation==b->target.generation &&
        a->target_object==b->target_object && a->finding_code==b->finding_code;
}
static int same_key_recent_recent(const Recent *a, const Recent *b)
{
    return a->used && a->type==b->type && a->principal==b->principal &&
        a->cap_id==b->cap_id && a->generation==b->generation &&
        a->target_object==b->target_object && a->finding_code==b->finding_code;
}
static int find_pending(const ArgusContain *s, uint64_t id)
{
    for (size_t i=0;i<ARGUS_CONTAIN_PENDING;i++)
        if (s->pending[i].state!=ST_FREE && s->pending[i].req.request_id==id) return (int)i;
    return -1;
}
static const Recent *find_recent_request(const ArgusContain *s, uint64_t id)
{
    for(size_t i=0;i<ARGUS_CONTAIN_RECENT;i++)
        if(s->recent[i].used && s->recent[i].request_id==id) return &s->recent[i];
    return NULL;
}
static int pending_slot(ArgusContain *s)
{
    for (size_t i=0;i<ARGUS_CONTAIN_PENDING;i++) if (s->pending[i].state==ST_FREE) return (int)i;
    return -1;
}
static void remember(ArgusContain *s, Pending *p)
{
    Recent r={0}; const ArgusContainmentRequest *q=&p->req;
    r.used=1; r.type=q->containment; r.severity=q->severity; r.state=p->state;
    r.retries=p->retries; r.principal=q->principal; r.cap_id=q->target.cap_id;
    r.generation=q->target.generation; r.target_object=q->target_object; r.request_id=q->request_id;
    r.finding_code=q->finding_code; r.last_event=s->events;
    memcpy(r.digest,p->digest,ARGUS_DIGEST_LEN);
    size_t slot=0;
    for (size_t i=0;i<ARGUS_CONTAIN_RECENT;i++) {
        if (!s->recent[i].used) { slot=i; goto chosen; }
        if (same_key_recent_recent(&s->recent[i],&r)) { slot=i; goto chosen; }
        if (s->recent[i].last_event<s->recent[slot].last_event) slot=i;
    }
chosen:
    s->recent[slot]=r;
    p->closed_at=s->events;
}
static void close_pending(ArgusContain *s, Pending *p, uint8_t state)
{
    p->state=state; remember(s,p); memset(p,0,sizeof *p);
}

static void emit_contain_finding(ArgusFinding *f, uint16_t code, uint8_t severity,
                                 const ArgusEvent *ev, uint32_t principal,
                                 uint32_t cap_id, uint64_t generation)
{
    memset(f,0,sizeof *f); f->code=code; f->severity=severity;
    f->confidence=ARGUS_CONF_DETERMINISTIC; f->detector=code;
    f->sequence=ev->sequence; f->principal=principal; f->cap_id=cap_id;
    f->cap_generation=generation; memcpy(f->machine_id,ev->machine_id,ARGUS_MACHINE_ID_LEN);
    argus_event_digest(ev,f->event_digest);
}
static int push_finding(ArgusContain *s, ArgusFinding *out, size_t cap, size_t *n,
                        uint16_t code, uint8_t severity, const ArgusEvent *ev,
                        uint32_t principal, uint32_t cap_id, uint64_t generation)
{
    if (*n>=cap) return ARGUS_ERR_OVERFLOW;
    emit_contain_finding(&out[(*n)++],code,severity,ev,principal,cap_id,generation);
    if (code==ARGUS_F_CONTAINMENT_DECISION_UNMATCHED) s->health.decisions_unmatched++;
    else if (code==ARGUS_F_CONTAINMENT_EXECUTION_UNAUTHORIZED) s->health.executions_unauthorized++;
    else if (code==ARGUS_F_CONTAINMENT_EXECUTION_UNCONFIRMED) s->health.executions_unconfirmed++;
    return ARGUS_OK;
}

static int echo_matches(const Pending *p, const ArgusEvent *ev)
{
    const ArgusContainmentRequest *q=&p->req;
    return ARGUS_CONTAIN_TYPE_OF(ev->object_id)==q->containment &&
        ARGUS_CONTAIN_CODE_OF(ev->object_id)==q->finding_code && ev->principal==q->principal &&
        ev->cap_id==q->target.cap_id && ev->cap_generation==q->target.generation &&
        ev->world_generation==q->request_id && memcmp(ev->machine_id,q->machine_id,ARGUS_MACHINE_ID_LEN)==0 &&
        memcmp(ev->evidence_digest,p->digest,ARGUS_DIGEST_LEN)==0;
}

static void apply_decision(ArgusContain *s, Pending *p, const ArgusEvent *ev)
{
    uint8_t status=ARGUS_CONTAIN_STATUS_OF(ev->object_id);
    p->decision_id=ev->resource; p->entered=s->events;
    if (status==ARGUS_CSTATUS_GRANT) { p->state=ST_GRANTED; s->health.granted++; }
    else if (status==ARGUS_CSTATUS_DENY) { close_pending(s,p,ST_DENIED); s->health.denied++; }
    else if (status==ARGUS_CSTATUS_ESCALATE) { p->state=ST_ESCALATED; s->health.escalated++; }
}

int argus_contain_observe(ArgusContain *s, const ArgusCore *core, const ArgusEvent *ev,
                          ArgusFinding *out, size_t cap, size_t *n_out)
{
    (void)core;
    if (!s || !ev || !n_out || !out || cap==0) return ARGUS_ERR_ARG;
    size_t n=0; s->events++;
    if (s->events>s->window_start+ARGUS_CONTAIN_WINDOW_EVENTS) {
        s->window_start=((s->events-1)/ARGUS_CONTAIN_WINDOW_EVENTS)*ARGUS_CONTAIN_WINDOW_EVENTS;
        s->window_count=0;
    }
    if (ev->kind==ARGUS_EV_CONTAINMENT_DECIDED || ev->kind==ARGUS_EV_CONTAINMENT_EXECUTED) {
        uint64_t id=ev->world_generation; int ix=find_pending(s,id);
        if (ix<0) {
            const Recent *r=find_recent_request(s,id);
            int scope_close=ev->kind==ARGUS_EV_CONTAINMENT_EXECUTED && r && r->state==ST_FAILED_SCOPE &&
                ARGUS_CONTAIN_STATUS_OF(ev->object_id)==ARGUS_CSTATUS_FAILED_SCOPE &&
                ARGUS_CONTAIN_TYPE_OF(ev->object_id)==r->type && ARGUS_CONTAIN_CODE_OF(ev->object_id)==r->finding_code &&
                ev->principal==r->principal && ev->cap_id==r->cap_id && ev->cap_generation==r->generation &&
                ev->world_generation==r->request_id && memcmp(ev->evidence_digest,r->digest,ARGUS_DIGEST_LEN)==0;
            if (!scope_close && cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_DECISION_UNMATCHED,ARGUS_SEV_HIGH,ev,ev->principal,ev->cap_id,ev->cap_generation); if(rc)return rc; }
        } else if (!is_open(s->pending[ix].state) || !echo_matches(&s->pending[ix],ev)) {
            if (cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_DECISION_UNMATCHED,ARGUS_SEV_HIGH,ev,ev->principal,ev->cap_id,ev->cap_generation); if(rc) return rc; }
        } else {
            Pending *p=&s->pending[ix]; uint8_t status=ARGUS_CONTAIN_STATUS_OF(ev->object_id);
            if (ev->kind==ARGUS_EV_CONTAINMENT_DECIDED) {
                if ((p->state==ST_PROPOSED && (status==ARGUS_CSTATUS_GRANT || status==ARGUS_CSTATUS_DENY || status==ARGUS_CSTATUS_ESCALATE)) ||
                    (p->state==ST_ESCALATED && (status==ARGUS_CSTATUS_GRANT || status==ARGUS_CSTATUS_DENY))) apply_decision(s,p,ev);
                else { if (cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_DECISION_UNMATCHED,ARGUS_SEV_HIGH,ev,ev->principal,ev->cap_id,ev->cap_generation); if(rc) return rc; } }
            } else {
                if (p->state!=ST_GRANTED) {
                    if (status==ARGUS_CSTATUS_DONE || status==ARGUS_CSTATUS_PARTIAL) {
                        if (cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_EXECUTION_UNAUTHORIZED,ARGUS_SEV_CRITICAL,ev,ev->principal,ev->cap_id,ev->cap_generation); if(rc) return rc; }
                    } else { if(cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_DECISION_UNMATCHED,ARGUS_SEV_HIGH,ev,ev->principal,ev->cap_id,ev->cap_generation); if(rc)return rc; } }
                } else if (status==ARGUS_CSTATUS_FAILED_SCOPE ||
                           (status==ARGUS_CSTATUS_DONE && (uint32_t)ev->resource!=1u) ||
                           (status==ARGUS_CSTATUS_PARTIAL && (uint32_t)ev->resource>1u)) {
                    close_pending(s,p,ST_FAILED_SCOPE); s->health.failed_scope++;
                    if (cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_SCOPE_EXCEEDED,ARGUS_SEV_CRITICAL,ev,ev->principal,ev->cap_id,ev->cap_generation); if(rc) return rc; }
                } else if (status==ARGUS_CSTATUS_DONE) {
                    if (p->kind4_count==1) { close_pending(s,p,ST_CONFIRMED); s->health.confirmed++; }
                    else { if(cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_EXECUTION_UNCONFIRMED,ARGUS_SEV_HIGH,ev,ev->principal,ev->cap_id,ev->cap_generation); if(rc)return rc; } close_pending(s,p,ST_FAILED); s->health.failed++; }
                } else if (status==ARGUS_CSTATUS_FAILED || status==ARGUS_CSTATUS_UNAVAILABLE) {
                    close_pending(s,p,ST_FAILED); if(status==ARGUS_CSTATUS_FAILED) s->health.failed++; else s->health.unavailable++;
                } else {
                    if(cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_DECISION_UNMATCHED,ARGUS_SEV_HIGH,ev,ev->principal,ev->cap_id,ev->cap_generation); if(rc)return rc; }
                }
            }
        }
    } else if (ev->kind==ARGUS_EV_CONTAINMENT_PROPOSED) {
        int ix=find_pending(s,ev->world_generation);
        if (ix>=0 && s->pending[ix].state==ST_PROPOSED && echo_matches(&s->pending[ix],ev))
            s->pending[ix].entered=s->events;
    } else if (ev->kind==ARGUS_EV_CAPABILITY_GRANTED && ev->principal==43u) {
        s->executor_cap_id=ev->cap_id;
    } else if (ev->kind==ARGUS_EV_CAPABILITY_REVOKED) {
        int matched=0;
        for (size_t i=0;i<ARGUS_CONTAIN_PENDING;i++) {
            Pending *p=&s->pending[i];
            if (p->state!=ST_FREE && p->req.target.cap_id==ev->cap_id && p->req.target.generation==ev->cap_generation) {
                matched=1;
                if (p->state!=ST_GRANTED) {
                    if(cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_EXECUTION_UNAUTHORIZED,ARGUS_SEV_CRITICAL,ev,p->req.principal,p->req.target.cap_id,p->req.target.generation); if(rc)return rc; }
                    continue;
                }
                p->kind4_count++; p->entered=s->events;
                if (p->kind4_count>1) {
                    close_pending(s,p,ST_FAILED_SCOPE); s->health.failed_scope++;
                    if(cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_SCOPE_EXCEEDED,ARGUS_SEV_CRITICAL,ev,p->req.principal,p->req.target.cap_id,p->req.target.generation); if(rc)return rc; }
                }
            }
        }
        if (!matched) for (size_t i=0;i<ARGUS_CONTAIN_RECENT;i++) {
            const Recent *r=&s->recent[i];
            if(r->used && r->cap_id==ev->cap_id && r->generation==ev->cap_generation) {
                if(cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_EXECUTION_UNAUTHORIZED,ARGUS_SEV_CRITICAL,ev,r->principal,r->cap_id,r->generation); if(rc)return rc; }
                matched=1; break;
            }
        }
    }
    /* Timeout is measured from the latest valid state transition, including 90 -> 91
     * and GRANT -> observer revoke. Expire only after the full interval has elapsed. */
    for (size_t i=0;i<ARGUS_CONTAIN_PENDING;i++) {
        Pending *p=&s->pending[i];
        if (is_open(p->state) && s->events-p->entered>ARGUS_CONTAIN_TIMEOUT_EVENTS) {
            close_pending(s,p,ST_EXPIRED); s->health.expired++;
            if (cap) { int rc=push_finding(s,out,cap,&n,ARGUS_F_CONTAINMENT_UNANSWERED,ARGUS_SEV_MEDIUM,ev,p->req.principal,p->req.target.cap_id,p->req.target.generation); if(rc)return rc; }
        }
    }
    *n_out=n; return ARGUS_OK;
}

static int protected_target(const ArgusContain *s, const ArgusStateOps *ops, const ArgusStateView *view,
                            const ArgusFinding *f, const ArgusCapShadow *c, int have_cap)
{
    if (f->cap_id==0 || f->cap_id==ARGUS_CAP_NONE || f->cap_id==s->executor_cap_id) return 1;
    if (!have_cap) return 0;
    if (c->subject==ARGUS_SUBJ_AEGIS || c->subject==ARGUS_SUBJ_AEGIS_ROOT || c->subject==43u ||
        (c->rights&ARGUS_CAP_RIGHT_PRIVILEGED)!=0) return 1;
    for (uint32_t id=0;id<ARGUS_CAP_MAX;id++) {
        ArgusCapShadow other={0};
        if (ops->cap(view,id,&other)==ARGUS_OK && other.state==ARGUS_SHADOW_LIVE &&
            other.subject==c->subject && (other.rights&ARGUS_CAP_RIGHT_PRIVILEGED)!=0) return 1;
    }
    return 0;
}
static int never_propose(uint16_t code)
{ return code==11 || code==12 || code==13 || code==16 || (code>=17 && code<=21); }

int argus_contain_propose(ArgusContain *s, const ArgusCore *core,
                          const ArgusFinding *findings, size_t nf,
                          ArgusContainmentRequest *requests, size_t rcap,
                          ArgusEvent *events, size_t ecap, size_t *n_out)
{
    if(!s || !core || (nf && !findings) || !n_out || (rcap && !requests) || (ecap && !events)) return ARGUS_ERR_ARG;
    size_t n=0; const ArgusStateOps *ops=argus_core_ops(); const ArgusStateView *view=argus_core_view(core);
    for(size_t j=0;j<nf;j++) {
        const ArgusFinding *f=&findings[j];
        if(f->confidence!=ARGUS_CONF_DETERMINISTIC || f->severity<ARGUS_SEV_HIGH ||
           f->containment==ARGUS_CONTAIN_NONE || f->containment>ARGUS_CONTAIN_MAX || never_propose(f->code)) continue;
        if(s->next_request_id==0 || s->next_request_id==UINT64_MAX ||
           s->next_proposal_sequence==0 || s->next_proposal_sequence==UINT64_MAX) return ARGUS_ERR_FULL;
        ArgusCapShadow c={0}; int has=ops->cap(view,f->cap_id,&c)==ARGUS_OK && c.state==ARGUS_SHADOW_LIVE;
        if(f->containment==ARGUS_CONTAIN_REVOKE_CAPABILITY && protected_target(s,ops,view,f,&c,has)) { s->health.suppressed_protected++; continue; }
        if(f->containment==ARGUS_CONTAIN_REVOKE_CAPABILITY && (!has || c.generation==0)) continue;
        ArgusContainmentRequest q={0};
        uint64_t incident=0; (void)argus_core_incident(core,f->principal,f->code,&incident);
        q.incident_id=incident; q.containment=f->containment; q.severity=f->severity; q.finding_code=f->code;
        q.principal=(f->containment==ARGUS_CONTAIN_REVOKE_CAPABILITY)?c.subject:f->principal;
        q.target.cap_id=(f->containment==ARGUS_CONTAIN_REVOKE_CAPABILITY)?f->cap_id:ARGUS_CAP_NONE;
        q.target.generation=(f->containment==ARGUS_CONTAIN_REVOKE_CAPABILITY)?c.generation:0;
        memcpy(q.machine_id,f->machine_id,ARGUS_MACHINE_ID_LEN); argus_finding_digest(f,q.finding_digest);
        q.request_id=s->next_request_id; q.finding_sequence=f->sequence; q.version=ARGUS_CONTAIN_REQUEST_VERSION;
        int duplicate=0;
        for(size_t i=0;i<ARGUS_CONTAIN_PENDING;i++) if(is_open(s->pending[i].state)&&same_key_req(&s->pending[i].req,&q)) {duplicate=1;break;}
        if(duplicate) {s->health.suppressed_dedup++;continue;}
        uint8_t retries=0;
        for(size_t i=0;i<ARGUS_CONTAIN_RECENT;i++) if(same_key_recent(&s->recent[i],&q)) {
            Recent *r=&s->recent[i];
            if(r->state==ST_CONFIRMED || r->retries>=ARGUS_CONTAIN_RETRIES ||
               (f->severity<=r->severity && s->events-r->last_event<ARGUS_CONTAIN_COOLDOWN_EVENTS)) {s->health.suppressed_cooldown++;duplicate=1;break;}
            retries=(uint8_t)(r->retries+1u); r->retries=retries;
        }
        if(duplicate) continue;
        if(s->window_count>=ARGUS_CONTAIN_WINDOW_MAX) {s->health.suppressed_budget++;continue;}
        int ix=pending_slot(s);
        if(ix<0) {
            s->health.pending_full++;
            if(!s->overflow_reported) { s->overflow_reported=1; /* visible via health; caller reports telemetry loss */ }
            continue;
        }
        if(n>=rcap || n>=ecap) return ARGUS_ERR_OVERFLOW;
        Pending *p=&s->pending[ix]; memset(p,0,sizeof *p); p->req=q; p->state=ST_PROPOSED; p->entered=s->events; p->retries=retries;
        argus_contain_request_digest(&q,p->digest); requests[n]=q;
        ArgusEvent *e=&events[n]; memset(e,0,sizeof *e); e->version=ARGUS_ABI_VERSION; e->class_=ARGUS_CLASS_CRITICAL;
        e->kind=ARGUS_EV_CONTAINMENT_PROPOSED; e->outcome=ARGUS_OUTCOME_OK; e->flags=ARGUS_FLAG_CONSUMER;
        e->sequence=s->next_proposal_sequence++; e->principal=q.principal; e->cap_id=q.target.cap_id; e->cap_generation=q.target.generation;
        e->world_generation=q.request_id; e->object_id=ARGUS_CONTAIN_PACK(q.containment,ARGUS_CSTATUS_PROPOSED,q.finding_code);
        e->resource=q.finding_sequence; memcpy(e->machine_id,q.machine_id,ARGUS_MACHINE_ID_LEN); memcpy(e->evidence_digest,p->digest,ARGUS_DIGEST_LEN);
        n++; s->next_request_id++; s->window_count++; s->health.requested++;
    }
    *n_out=n; return ARGUS_OK;
}

void argus_contain_health(const ArgusContain *s, ArgusContainHealth *out)
{ if(s&&out) *out=s->health; }

void argus_contain_state_digest(const ArgusContain *s, uint8_t out[ARGUS_DIGEST_LEN])
{
    if(!out) return;
    if(!s) {memset(out,0,ARGUS_DIGEST_LEN);return;}
    uint8_t b[ARGUS_CONTAIN_PENDING*(ARGUS_CONTAIN_REQUEST_SIZE+56)+ARGUS_CONTAIN_RECENT*80+256]; size_t n=0;
    static const uint8_t domain[]="AIENOS-ARGUS-CONTAIN-STATE-V1\0"; memcpy(b+n,domain,sizeof domain);n+=sizeof domain;
    wr64(b+n,s->events);n+=8; wr64(b+n,s->next_request_id);n+=8; wr64(b+n,s->next_proposal_sequence);n+=8; wr64(b+n,s->window_start);n+=8; wr32(b+n,s->window_count);n+=4; wr32(b+n,s->executor_cap_id);n+=4; b[n++]=s->overflow_reported;
    for(size_t i=0;i<ARGUS_CONTAIN_PENDING;i++) { const Pending *p=&s->pending[i]; b[n++]=p->state; if(p->state==ST_FREE) continue;
        uint8_t enc[ARGUS_CONTAIN_REQUEST_SIZE]; (void)argus_contain_request_encode(&p->req,enc); memcpy(b+n,enc,sizeof enc);n+=sizeof enc;
        memcpy(b+n,p->digest,ARGUS_DIGEST_LEN);n+=ARGUS_DIGEST_LEN; b[n++]=p->kind4_count; wr64(b+n,p->entered);n+=8;wr64(b+n,p->decision_id);n+=8; }
    for(size_t i=0;i<ARGUS_CONTAIN_RECENT;i++) { const Recent *r=&s->recent[i]; b[n++]=r->used; if(!r->used)continue;
        b[n++]=r->type;b[n++]=r->severity;b[n++]=r->state;b[n++]=r->retries;wr32(b+n,r->principal);n+=4;wr32(b+n,r->cap_id);n+=4;wr64(b+n,r->generation);n+=8;wr32(b+n,r->target_object);n+=4;wr16(b+n,r->finding_code);n+=2;wr64(b+n,r->last_event);n+=8;wr64(b+n,r->request_id);n+=8;memcpy(b+n,r->digest,ARGUS_DIGEST_LEN);n+=ARGUS_DIGEST_LEN; }
    const uint64_t health[]={s->health.requested,s->health.granted,s->health.denied,s->health.escalated,
        s->health.confirmed,s->health.failed,s->health.failed_scope,s->health.unavailable,s->health.expired,
        s->health.suppressed_dedup,s->health.suppressed_cooldown,s->health.suppressed_budget,
        s->health.suppressed_protected,s->health.pending_full,s->health.decisions_unmatched,
        s->health.executions_unauthorized,s->health.executions_unconfirmed};
    for(size_t i=0;i<sizeof health/sizeof health[0];i++) { wr64(b+n,health[i]); n+=8; }
    sha256_hash(b,n,out);
}
