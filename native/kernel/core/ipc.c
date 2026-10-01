/* ipc.c -- see ipc.h. caps.rs and ipc.rs logic, step for step. */
#include "ipc.h"

void ck_cap_init(struct ck_cap_table *t, uint32_t id, unsigned n)
{
    t->id = id;
    t->n = n == 0 ? 1 : (n > CK_CAP_SLOTS ? CK_CAP_SLOTS : n);
    for (unsigned i = 0; i < CK_CAP_SLOTS; i++) {
        t->slots[i] = (struct ck_cap_slot){ 0 };
        t->generations[i] = 0;
    }
}

static int allocate(struct ck_cap_table *t, uint32_t resource, unsigned rights, int has_parent,
                    uint32_t parent_table, struct ck_handle parent, struct ck_handle *out)
{
    for (unsigned i = 0; i < t->n; i++) {
        /* A slot whose generation reached the maximum is retired for good, so
         * no old handle can ever match again. */
        if (t->slots[i].live || t->generations[i] == 0xffffffffu)
            continue;
        uint32_t gen = t->generations[i] + 1;
        t->generations[i] = gen;
        t->slots[i] = (struct ck_cap_slot){ .live = 1, .rights = (uint8_t)rights,
                                            .has_parent = (uint8_t)has_parent,
                                            .generation = gen, .resource = resource,
                                            .parent_table = parent_table, .parent = parent };
        out->index = i;
        out->generation = gen;
        return CK_CAP_OK;
    }
    return CK_CAP_FULL;
}

int ck_cap_insert(struct ck_cap_table *t, uint32_t resource, unsigned rights, struct ck_handle *out)
{
    if (rights & ~CK_R_ALL)
        return CK_CAP_ESCALATION;
    return allocate(t, resource, rights, 0, 0, (struct ck_handle){ 0, 0 }, out);
}

/* Live slot for the handle, tombstones included (revocation walks them). */
static const struct ck_cap_slot *slot_any(const struct ck_cap_table *t, struct ck_handle h)
{
    if (h.index >= t->n)
        return 0;
    const struct ck_cap_slot *s = &t->slots[h.index];
    return s->live && s->generation == h.generation ? s : 0;
}

static const struct ck_cap_slot *slot_ok(const struct ck_cap_table *t, struct ck_handle h)
{
    const struct ck_cap_slot *s = slot_any(t, h);
    return s && !s->tombstone ? s : 0;
}

int ck_cap_lookup(const struct ck_cap_table *t, struct ck_handle h, unsigned required,
                  uint32_t *resource)
{
    const struct ck_cap_slot *s = slot_ok(t, h);
    if (!s)
        return CK_CAP_INVALID;
    if ((s->rights & required) != required)
        return CK_CAP_MISSING_RIGHTS;
    if (resource)
        *resource = s->resource;
    return CK_CAP_OK;
}

int ck_cap_rights(const struct ck_cap_table *t, struct ck_handle h, unsigned *rights)
{
    const struct ck_cap_slot *s = slot_ok(t, h);
    if (!s)
        return CK_CAP_INVALID;
    *rights = s->rights;
    return CK_CAP_OK;
}

int ck_cap_remove(struct ck_cap_table *t, struct ck_handle h)
{
    const struct ck_cap_slot *s = slot_ok(t, h);
    if (!s)
        return CK_CAP_INVALID;
    if (s->derived)
        t->slots[h.index].tombstone = 1;
    else
        t->slots[h.index] = (struct ck_cap_slot){ 0 };
    return CK_CAP_OK;
}

int ck_cap_derive_into(struct ck_cap_table *from, struct ck_handle h, struct ck_cap_table *to,
                       unsigned rights, struct ck_handle *out)
{
    const struct ck_cap_slot *s = slot_ok(from, h);
    if (!s)
        return CK_CAP_INVALID;
    if (!(s->rights & CK_R_DERIVE))
        return CK_CAP_MISSING_RIGHTS;
    if (rights & ~(unsigned)s->rights)
        return CK_CAP_ESCALATION;
    int r = allocate(to, s->resource, rights, 1, from->id, h, out);
    if (r)
        return r;
    from->slots[h.index].derived = 1;
    return CK_CAP_OK;
}

int ck_cap_derive(struct ck_cap_table *t, struct ck_handle h, unsigned rights, struct ck_handle *out)
{
    return ck_cap_derive_into(t, h, t, rights, out);
}

int ck_cap_transfer(struct ck_cap_table *from, struct ck_handle h, struct ck_cap_table *to,
                    struct ck_handle *out)
{
    const struct ck_cap_slot *s = slot_ok(from, h);
    if (!s)
        return CK_CAP_INVALID;
    if (!(s->rights & CK_R_GRANT))
        return CK_CAP_MISSING_RIGHTS;
    return allocate(to, s->resource, s->rights, 0, 0, (struct ck_handle){ 0, 0 }, out);
}

static struct ck_cap_table *table_by_id(struct ck_cap_table *const *tables, unsigned n, uint32_t id)
{
    for (unsigned i = 0; i < n; i++)
        if (tables[i]->id == id)
            return tables[i];
    return 0;
}

/* Depth of (table, h) below the root along parent links: >= 0, -1 if not a
 * descendant, DEPTH_CYCLE if the chain is longer than every slot (a cycle). */
#define DEPTH_CYCLE (-1000)
static int revocation_depth(uint32_t table, struct ck_handle h, uint32_t root_table,
                            struct ck_handle root, struct ck_cap_table *const *tables, unsigned n,
                            unsigned capacity)
{
    for (unsigned depth = 0; depth <= capacity; depth++) {
        if (table == root_table && h.index == root.index && h.generation == root.generation)
            return (int)depth;
        const struct ck_cap_table *t = table_by_id(tables, n, table);
        if (!t)
            return -1;
        const struct ck_cap_slot *s = slot_any(t, h);
        if (!s || !s->has_parent)
            return -1;
        table = s->parent_table;
        h = s->parent;
    }
    return DEPTH_CYCLE;
}

int ck_cap_revoke(uint32_t table_id, struct ck_handle h, struct ck_cap_table *const *tables,
                  unsigned ntables)
{
    unsigned matches = 0;
    for (unsigned i = 0; i < ntables; i++)
        matches += tables[i]->id == table_id;
    if (matches != 1)
        return CK_CAP_DUPLICATE_TABLE;
    const struct ck_cap_slot *rs = slot_ok(table_by_id(tables, ntables, table_id), h);
    if (!rs)
        return CK_CAP_INVALID;
    if (!(rs->rights & CK_R_REVOKE))
        return CK_CAP_MISSING_RIGHTS;
    unsigned capacity = 0;
    for (unsigned i = 0; i < ntables; i++)
        capacity += tables[i]->n;
    /* Validate every chain first: a cycle fails before anything is removed. */
    for (unsigned i = 0; i < ntables; i++)
        for (unsigned s = 0; s < tables[i]->n; s++)
            if (tables[i]->slots[s].live &&
                revocation_depth(tables[i]->id,
                                 (struct ck_handle){ s, tables[i]->slots[s].generation }, table_id,
                                 h, tables, ntables, capacity) == DEPTH_CYCLE)
                return CK_CAP_FULL;
    for (unsigned round = 0; round < capacity; round++) {
        int best = -1;
        struct ck_cap_table *bt = 0;
        unsigned bs = 0;
        for (unsigned i = 0; i < ntables; i++)
            for (unsigned s = 0; s < tables[i]->n; s++) {
                if (!tables[i]->slots[s].live)
                    continue;
                int d = revocation_depth(tables[i]->id,
                                         (struct ck_handle){ s, tables[i]->slots[s].generation },
                                         table_id, h, tables, ntables, capacity);
                if (d > best) {
                    best = d;
                    bt = tables[i];
                    bs = s;
                }
            }
        if (best < 0)
            break;
        bt->slots[bs] = (struct ck_cap_slot){ 0 };
    }
    return CK_CAP_OK;
}

/* ---- channel ---- */
void ck_chan_init(struct ck_channel *c, unsigned cap)
{
    c->head = c->len = 0;
    c->cap = cap == 0 ? 1 : (cap > CK_CHAN_CAP ? CK_CHAN_CAP : cap);
}

int ck_chan_send(struct ck_channel *c, const struct ck_msg *m)
{
    if (c->len == c->cap)
        return -1;
    c->ring[(c->head + c->len) % c->cap] = *m;
    c->len++;
    return 0;
}

int ck_chan_recv(struct ck_channel *c, struct ck_msg *m)
{
    if (c->len == 0)
        return -1;
    *m = c->ring[c->head];
    c->head = (c->head + 1) % c->cap;
    c->len--;
    return 0;
}

/* ---- ipc ---- */
void ck_ipc_reset(struct ck_ipc *ipc, struct ck_handle *a_send, struct ck_handle *a_object,
                  struct ck_handle *b_recv)
{
    ck_chan_init(&ipc->chan, CK_CHAN_CAP);
    ipc->object[0] = 0xc0ffee01;
    ipc->object[1] = 0x0badc0de;
    ipc->object[2] = 0x12345678;
    ipc->object[3] = 0x9abcdef0;
    ck_cap_init(&ipc->tables[0], CK_IPC_PRINCIPAL_A, CK_CAP_SLOTS);
    ck_cap_init(&ipc->tables[1], CK_IPC_PRINCIPAL_B, CK_CAP_SLOTS);
    ipc->active = 0;
    ck_cap_insert(&ipc->tables[0], CK_IPC_CHANNEL_RESOURCE, CK_R_WRITE, a_send);
    ck_cap_insert(&ipc->tables[0], CK_IPC_OBJECT_RESOURCE,
                  CK_R_READ | CK_R_WRITE | CK_R_DERIVE | CK_R_REVOKE, a_object);
    ck_cap_insert(&ipc->tables[1], CK_IPC_CHANNEL_RESOURCE, CK_R_READ, b_recv);
}

static int gated(const struct ck_cap_table *t, struct ck_handle h, unsigned right, uint32_t resource)
{
    uint32_t found;
    int r = ck_cap_lookup(t, h, right, &found);
    if (r == CK_CAP_OK)
        return found == resource ? CK_IPC_OK : CK_IPC_WRONG_RESOURCE;
    return r == CK_CAP_MISSING_RIGHTS ? CK_IPC_MISSING_RIGHTS : CK_IPC_INVALID_HANDLE;
}

int ck_ipc_send(struct ck_ipc *ipc, unsigned p, struct ck_handle h, const struct ck_msg *m)
{
    if (p > 1)
        return CK_IPC_INVALID_HANDLE;
    int r = gated(&ipc->tables[p], h, CK_R_WRITE, CK_IPC_CHANNEL_RESOURCE);
    if (r)
        return r;
    return ck_chan_send(&ipc->chan, m) ? CK_IPC_CHANNEL_FULL : CK_IPC_OK;
}

int ck_ipc_recv(struct ck_ipc *ipc, unsigned p, struct ck_handle h, struct ck_msg *m)
{
    if (p > 1)
        return CK_IPC_INVALID_HANDLE;
    int r = gated(&ipc->tables[p], h, CK_R_READ, CK_IPC_CHANNEL_RESOURCE);
    if (r)
        return r;
    return ck_chan_recv(&ipc->chan, m) ? CK_IPC_CHANNEL_EMPTY : CK_IPC_OK;
}

int ck_ipc_delegate(struct ck_ipc *ipc, unsigned from, struct ck_handle h, unsigned to,
                    unsigned rights, struct ck_handle *child)
{
    if (from > 1 || to > 1 || from == to)
        return CK_IPC_INVALID_HANDLE;
    int r = gated(&ipc->tables[from], h, CK_R_READ, CK_IPC_OBJECT_RESOURCE);
    if (r)
        return r;
    if (rights & ~(CK_R_READ | CK_R_WRITE))
        return CK_IPC_MISSING_RIGHTS;
    r = ck_cap_derive_into(&ipc->tables[from], h, &ipc->tables[to], rights, child);
    switch (r) {
    case CK_CAP_OK: return CK_IPC_OK;
    case CK_CAP_FULL: return CK_IPC_DELEGATION_FAILED;
    case CK_CAP_MISSING_RIGHTS:
    case CK_CAP_ESCALATION: return CK_IPC_MISSING_RIGHTS;
    default: return CK_IPC_INVALID_HANDLE;
    }
}

int ck_ipc_object_read(struct ck_ipc *ipc, unsigned p, struct ck_handle h, uint64_t offset,
                       uint64_t *value)
{
    if (p > 1)
        return CK_IPC_INVALID_HANDLE;
    int r = gated(&ipc->tables[p], h, CK_R_READ, CK_IPC_OBJECT_RESOURCE);
    if (r)
        return r;
    if (offset >= CK_IPC_OBJECT_SLOTS)
        return CK_IPC_WRONG_RESOURCE;
    *value = ipc->object[offset];
    return CK_IPC_OK;
}

int ck_ipc_object_write(struct ck_ipc *ipc, unsigned p, struct ck_handle h, uint64_t offset,
                        uint64_t value)
{
    if (p > 1)
        return CK_IPC_INVALID_HANDLE;
    int r = gated(&ipc->tables[p], h, CK_R_WRITE, CK_IPC_OBJECT_RESOURCE);
    if (r)
        return r;
    if (offset >= CK_IPC_OBJECT_SLOTS)
        return CK_IPC_WRONG_RESOURCE;
    ipc->object[offset] = value;
    return CK_IPC_OK;
}

int ck_ipc_revoke(struct ck_ipc *ipc, unsigned owner, struct ck_handle h)
{
    if (owner > 1)
        return CK_IPC_INVALID_HANDLE;
    struct ck_cap_table *const tables[2] = { &ipc->tables[0], &ipc->tables[1] };
    int r = ck_cap_revoke(ipc->tables[owner].id, h, tables, 2);
    switch (r) {
    case CK_CAP_OK: return CK_IPC_OK;
    case CK_CAP_FULL: return CK_IPC_DELEGATION_FAILED;
    case CK_CAP_MISSING_RIGHTS:
    case CK_CAP_ESCALATION: return CK_IPC_MISSING_RIGHTS;
    default: return CK_IPC_INVALID_HANDLE;
    }
}
