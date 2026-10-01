/* test_ipc.c -- host tests for core/ipc.c: the caps.rs and ipc.rs test lists
 * (generation checks, attenuation, cross-table revoke, tombstones, bounded
 * FIFO channel, gated IPC calls) plus the exact sequence the EL0 IPC demo runs. */
#include "ck_test.h"
#include "ipc.h"

#define H(i, g) ((struct ck_handle){ (i), (g) })

static struct ck_msg msg(uint32_t kind)
{
    struct ck_msg m = { 0 };
    m.kind = kind;
    m.payload[0] = kind * 3u;
    m.object = kind;
    return m;
}

static int msg_eq(const struct ck_msg *a, const struct ck_msg *b)
{
    return a->kind == b->kind && a->payload[0] == b->payload[0] &&
           a->payload[1] == b->payload[1] && a->payload[2] == b->payload[2] &&
           a->region_base == b->region_base && a->region_pages == b->region_pages &&
           a->object == b->object;
}

int main(void)
{
    struct ck_cap_table t, u, v;
    struct ck_handle h, h2, c, gc;
    uint32_t res = 0;

    /* raw handles: round trip, generation 0 is forged */
    struct ck_handle r;
    CHECK(ck_handle_raw(H(3, 7)) == ((7ull << 32) | 3));
    CHECK(ck_handle_from_raw((7ull << 32) | 3, &r) == 0 && r.index == 3 && r.generation == 7);
    CHECK(ck_handle_from_raw(5, &r) == -1);

    /* stale handle after slot reuse */
    ck_cap_init(&t, 1, 2);
    CHECK(ck_cap_insert(&t, 10, CK_R_READ, &h) == 0);
    CHECK(ck_cap_remove(&t, h) == 0);
    CHECK(ck_cap_insert(&t, 11, CK_R_READ, &h2) == 0);
    CHECK(h2.index == h.index && h2.generation != h.generation);
    CHECK(ck_cap_lookup(&t, h, CK_R_READ, &res) == CK_CAP_INVALID);
    CHECK(ck_cap_lookup(&t, h2, CK_R_READ, &res) == 0 && res == 11);
    CHECK(ck_cap_lookup(&t, h2, CK_R_WRITE, &res) == CK_CAP_MISSING_RIGHTS);
    CHECK(ck_cap_lookup(&t, H(9, 1), CK_R_READ, &res) == CK_CAP_INVALID);

    /* generation exhaustion retires the slot */
    ck_cap_init(&t, 1, 1);
    t.generations[0] = 0xfffffffeu;
    CHECK(ck_cap_insert(&t, 1, CK_R_READ, &h) == 0 && h.generation == 0xffffffffu);
    CHECK(ck_cap_remove(&t, h) == 0);
    CHECK(ck_cap_insert(&t, 1, CK_R_READ, &h2) == CK_CAP_FULL);

    /* derive cannot add rights; needs DERIVE */
    ck_cap_init(&t, 1, 8);
    ck_cap_insert(&t, 5, CK_R_READ | CK_R_DERIVE, &h);
    CHECK(ck_cap_derive(&t, h, CK_R_READ | CK_R_WRITE, &c) == CK_CAP_ESCALATION);
    CHECK(ck_cap_derive(&t, h, CK_R_READ, &c) == 0);
    CHECK(ck_cap_derive(&t, c, CK_R_READ, &gc) == CK_CAP_MISSING_RIGHTS);
    CHECK(ck_cap_insert(&t, 5, 0x40, &h2) == CK_CAP_ESCALATION);

    /* revoke cascades two levels across tables */
    ck_cap_init(&t, 1, 8);
    ck_cap_init(&u, 2, 8);
    ck_cap_init(&v, 3, 8);
    ck_cap_insert(&t, 5, CK_R_ALL, &h);
    CHECK(ck_cap_derive_into(&t, h, &u, CK_R_READ | CK_R_DERIVE, &c) == 0);
    CHECK(ck_cap_derive_into(&u, c, &v, CK_R_READ, &gc) == 0);
    ck_cap_insert(&u, 6, CK_R_READ, &h2); /* unrelated survivor */
    struct ck_cap_table *const three[3] = { &t, &u, &v };
    CHECK(ck_cap_revoke(2, c, three, 3) == CK_CAP_MISSING_RIGHTS);
    CHECK(ck_cap_revoke(1, h, three, 3) == 0);
    CHECK(ck_cap_lookup(&t, h, 0, 0) == CK_CAP_INVALID);
    CHECK(ck_cap_lookup(&u, c, 0, 0) == CK_CAP_INVALID);
    CHECK(ck_cap_lookup(&v, gc, 0, 0) == CK_CAP_INVALID);
    CHECK(ck_cap_lookup(&u, h2, CK_R_READ, &res) == 0 && res == 6);
    struct ck_cap_table *const dup[2] = { &t, &t };
    CHECK(ck_cap_revoke(1, h, dup, 2) == CK_CAP_DUPLICATE_TABLE);

    /* revoke with single-slot tables */
    ck_cap_init(&t, 1, 1);
    ck_cap_init(&u, 2, 1);
    ck_cap_insert(&t, 5, CK_R_ALL, &h);
    CHECK(ck_cap_derive_into(&t, h, &u, CK_R_READ, &c) == 0);
    struct ck_cap_table *const two[2] = { &t, &u };
    CHECK(ck_cap_revoke(1, h, two, 2) == 0);
    CHECK(ck_cap_insert(&t, 5, CK_R_READ, &h2) == 0 && ck_cap_insert(&u, 5, CK_R_READ, &h2) == 0);

    /* cyclic parent metadata fails closed before removing anything */
    ck_cap_init(&t, 1, 2);
    ck_cap_init(&u, 2, 2);
    ck_cap_insert(&t, 5, CK_R_ALL, &h);
    ck_cap_insert(&u, 5, CK_R_ALL, &c);
    ck_cap_insert(&u, 5, CK_R_ALL, &gc);
    u.slots[c.index].has_parent = 1;
    u.slots[c.index].parent_table = 2;
    u.slots[c.index].parent = gc;
    u.slots[gc.index].has_parent = 1;
    u.slots[gc.index].parent_table = 2;
    u.slots[gc.index].parent = c;
    CHECK(ck_cap_revoke(1, h, two, 2) == CK_CAP_FULL);
    CHECK(ck_cap_lookup(&t, h, 0, 0) == 0);

    /* transfer needs GRANT; full table reported */
    ck_cap_init(&t, 1, 8);
    ck_cap_init(&u, 2, 1);
    ck_cap_insert(&t, 5, CK_R_READ, &h);
    CHECK(ck_cap_transfer(&t, h, &u, &c) == CK_CAP_MISSING_RIGHTS);
    ck_cap_insert(&t, 5, CK_R_READ | CK_R_GRANT, &h2);
    CHECK(ck_cap_transfer(&t, h2, &u, &c) == 0);
    CHECK(ck_cap_transfer(&t, h2, &u, &gc) == CK_CAP_FULL);

    /* removing a derived parent tombstones it; subtree stays revocable */
    ck_cap_init(&t, 1, 8);
    ck_cap_init(&u, 2, 8);
    ck_cap_insert(&t, 5, CK_R_ALL, &h);
    ck_cap_derive_into(&t, h, &u, CK_R_READ | CK_R_DERIVE | CK_R_REVOKE, &c);
    ck_cap_derive_into(&u, c, &t, CK_R_READ, &gc);
    CHECK(ck_cap_remove(&u, c) == 0);
    CHECK(ck_cap_lookup(&u, c, 0, 0) == CK_CAP_INVALID);
    CHECK(u.slots[c.index].tombstone == 1);
    CHECK(ck_cap_lookup(&t, gc, CK_R_READ, 0) == 0);
    CHECK(ck_cap_revoke(1, h, two, 2) == 0);
    CHECK(ck_cap_lookup(&t, gc, 0, 0) == CK_CAP_INVALID);
    CHECK(u.slots[c.index].live == 0);
    /* removing a never-derived capability frees its slot */
    ck_cap_init(&t, 1, 1);
    ck_cap_insert(&t, 5, CK_R_READ, &h);
    CHECK(ck_cap_remove(&t, h) == 0 && t.slots[0].live == 0);
    CHECK(ck_cap_remove(&t, h) == CK_CAP_INVALID);

    /* channel is FIFO and bounded */
    struct ck_channel ch;
    struct ck_msg m1 = msg(1), m2 = msg(2), out;
    ck_chan_init(&ch, 2);
    CHECK(ck_chan_send(&ch, &m1) == 0 && ck_chan_send(&ch, &m2) == 0);
    struct ck_msg m3 = msg(3);
    CHECK(ck_chan_send(&ch, &m3) == -1);
    CHECK(ck_chan_recv(&ch, &out) == 0 && msg_eq(&out, &m1));
    CHECK(ck_chan_send(&ch, &m3) == 0);
    CHECK(ck_chan_recv(&ch, &out) == 0 && msg_eq(&out, &m2));
    CHECK(ck_chan_recv(&ch, &out) == 0 && msg_eq(&out, &m3));
    CHECK(ck_chan_recv(&ch, &out) == -1);

    /* gated IPC */
    static struct ck_ipc ipc;
    struct ck_handle a_send, a_obj, b_recv, child;
    uint64_t val = 0;
    ck_ipc_reset(&ipc, &a_send, &a_obj, &b_recv);
    struct ck_msg m7 = msg(7);
    CHECK(ck_ipc_recv(&ipc, 0, a_send, &out) == CK_IPC_MISSING_RIGHTS);
    CHECK(ck_ipc_send(&ipc, 1, b_recv, &m7) == CK_IPC_MISSING_RIGHTS);
    CHECK(ck_ipc_send(&ipc, 0, a_obj, &m7) == CK_IPC_WRONG_RESOURCE);
    CHECK(ck_ipc_send(&ipc, 0, H(a_send.index, a_send.generation + 1), &m7) ==
          CK_IPC_INVALID_HANDLE);
    CHECK(ck_ipc_recv(&ipc, 1, b_recv, &out) == CK_IPC_CHANNEL_EMPTY);
    /* delegation without DERIVE, and escalation, are MissingRights */
    struct ck_handle plain;
    ck_cap_insert(&ipc.tables[0], CK_IPC_OBJECT_RESOURCE, CK_R_READ, &plain);
    CHECK(ck_ipc_delegate(&ipc, 0, plain, 1, CK_R_READ, &child) == CK_IPC_MISSING_RIGHTS);
    CHECK(ck_ipc_delegate(&ipc, 0, a_obj, 1, CK_R_READ | CK_R_MAP, &child) ==
          CK_IPC_MISSING_RIGHTS);
    CHECK(ck_ipc_delegate(&ipc, 0, a_obj, 1, CK_R_READ | CK_R_WRITE, &child) == 0);
    CHECK(ck_ipc_object_write(&ipc, 1, child, 3, 77) == 0 && ipc.object[3] == 77);
    CHECK(ck_ipc_object_read(&ipc, 1, child, 4, &val) == CK_IPC_WRONG_RESOURCE);

    /* end to end: the exact EL0 demo sequence */
    ck_ipc_reset(&ipc, &a_send, &a_obj, &b_recv);
    struct ck_msg sent = { .kind = 7, .payload = { 0x1111, 0x2222, 0x3333 },
                           .region_base = 0xa000, .region_pages = 2, .object = 0 };
    CHECK(ck_ipc_send(&ipc, 0, a_send, &sent) == 0);
    CHECK(ck_ipc_delegate(&ipc, 0, a_obj, 1, CK_R_READ, &child) == 0);
    CHECK(ck_ipc_recv(&ipc, 1, b_recv, &out) == 0 && msg_eq(&out, &sent));
    CHECK(ck_ipc_object_read(&ipc, 1, child, 0, &val) == 0 && val == 0xc0ffee01);
    CHECK(ck_ipc_object_write(&ipc, 1, child, 0, 0xbad) == CK_IPC_MISSING_RIGHTS);
    struct ck_handle forged;
    CHECK(ck_handle_from_raw(ck_handle_raw(child) ^ (1ull << 32), &forged) == -1);
    forged = H(child.index, child.generation + 1);
    CHECK(ck_ipc_object_read(&ipc, 1, forged, 0, &val) == CK_IPC_INVALID_HANDLE);
    CHECK(ck_ipc_revoke(&ipc, 1, child) == CK_IPC_MISSING_RIGHTS);
    CHECK(ck_ipc_revoke(&ipc, 0, a_obj) == 0);
    CHECK(ck_ipc_object_read(&ipc, 1, child, 1, &val) == CK_IPC_INVALID_HANDLE);
    CHECK(ck_ipc_object_read(&ipc, 0, a_obj, 1, &val) == CK_IPC_INVALID_HANDLE);
    CHECK(ck_ipc_send(&ipc, 0, a_send, &sent) == 0); /* unrelated caps survive */

    /* receiver table full: source untouched */
    ck_ipc_reset(&ipc, &a_send, &a_obj, &b_recv);
    for (int i = 0; i < CK_CAP_SLOTS - 1; i++)
        ck_cap_insert(&ipc.tables[1], 1, CK_R_READ, &h);
    CHECK(ck_ipc_delegate(&ipc, 0, a_obj, 1, CK_R_READ, &child) == CK_IPC_DELEGATION_FAILED);
    CHECK(ipc.tables[0].slots[a_obj.index].derived == 0);
    return ck_t_verdict("test_ipc");
}
