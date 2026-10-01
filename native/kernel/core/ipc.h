/* ipc.h -- capability tables and typed bounded IPC for the C kernel core.
 * Port of crates/aienos-kernel/src/caps.rs (CapTable: generation-checked
 * handles, attenuating derive, cross-table derive, tombstones, cascading
 * revoke) and crates/aienos-kernel/src/ipc.rs (bounded FIFO channel of fixed
 * 56-byte messages, two principals, a four-word object reachable only through
 * capabilities). Pure logic, no hardware: host-tested in tests/test_ipc.c;
 * the EL0 IPC demo (core/m3.c) drives it from SVC calls. */
#ifndef AIENOS_CK_IPC_H
#define AIENOS_CK_IPC_H

#include <stdint.h>

/* Rights (caps.rs Rights; the same bits are the syscall wire form). */
#define CK_R_READ 0x01u
#define CK_R_WRITE 0x02u
#define CK_R_MAP 0x04u
#define CK_R_GRANT 0x08u
#define CK_R_DERIVE 0x10u
#define CK_R_REVOKE 0x20u
#define CK_R_ALL 0x3fu

enum {
    CK_CAP_OK = 0,
    CK_CAP_FULL = -1,
    CK_CAP_INVALID = -2,
    CK_CAP_MISSING_RIGHTS = -3,
    CK_CAP_ESCALATION = -4,
    CK_CAP_DUPLICATE_TABLE = -5,
};

struct ck_handle {
    uint32_t index, generation;
};
/* Register form: generation << 32 | index (abi.rs Handle::to_raw). */
static inline uint64_t ck_handle_raw(struct ck_handle h)
{
    return ((uint64_t)h.generation << 32) | h.index;
}
/* Fails closed (-1) on generation 0. */
static inline int ck_handle_from_raw(uint64_t raw, struct ck_handle *h)
{
    if ((raw >> 32) == 0)
        return -1;
    h->index = (uint32_t)raw;
    h->generation = (uint32_t)(raw >> 32);
    return 0;
}

#define CK_CAP_SLOTS 8
struct ck_cap_slot {
    uint8_t live, rights, derived, tombstone, has_parent;
    uint32_t generation, resource;
    uint32_t parent_table;
    struct ck_handle parent;
};
struct ck_cap_table {
    uint32_t id;
    unsigned n; /* usable slots, 1..CK_CAP_SLOTS */
    struct ck_cap_slot slots[CK_CAP_SLOTS];
    uint32_t generations[CK_CAP_SLOTS];
};

void ck_cap_init(struct ck_cap_table *t, uint32_t id, unsigned n);
int ck_cap_insert(struct ck_cap_table *t, uint32_t resource, unsigned rights, struct ck_handle *out);
/* 0 and *resource if the handle is live and holds every required right. */
int ck_cap_lookup(const struct ck_cap_table *t, struct ck_handle h, unsigned required,
                  uint32_t *resource);
int ck_cap_rights(const struct ck_cap_table *t, struct ck_handle h, unsigned *rights);
/* A derived-from capability becomes a tombstone so revoke still reaches its
 * children; others free their slot. */
int ck_cap_remove(struct ck_cap_table *t, struct ck_handle h);
int ck_cap_derive(struct ck_cap_table *t, struct ck_handle h, unsigned rights, struct ck_handle *out);
int ck_cap_derive_into(struct ck_cap_table *from, struct ck_handle h, struct ck_cap_table *to,
                       unsigned rights, struct ck_handle *out);
int ck_cap_transfer(struct ck_cap_table *from, struct ck_handle h, struct ck_cap_table *to,
                    struct ck_handle *out);
/* Needs REVOKE on (table_id, h); removes it and every descendant in tables,
 * deepest first. Table ids must be unique among tables. */
int ck_cap_revoke(uint32_t table_id, struct ck_handle h, struct ck_cap_table *const *tables,
                  unsigned ntables);

/* ---- typed messages and the bounded channel (ipc.rs) ---- */
struct ck_msg {
    uint32_t kind;
    uint32_t reserved;
    uint64_t payload[3];
    uint64_t region_base;
    uint32_t region_pages;
    uint32_t reserved2;
    uint64_t object;
};
_Static_assert(sizeof(struct ck_msg) == 56, "message is 56 bytes like abi.rs Message");

#define CK_CHAN_CAP 8
struct ck_channel {
    struct ck_msg ring[CK_CHAN_CAP];
    unsigned head, len, cap; /* cap: 1..CK_CHAN_CAP */
};
void ck_chan_init(struct ck_channel *c, unsigned cap);
int ck_chan_send(struct ck_channel *c, const struct ck_msg *m); /* -1 full */
int ck_chan_recv(struct ck_channel *c, struct ck_msg *m);       /* -1 empty */

enum {
    CK_IPC_OK = 0,
    CK_IPC_CHANNEL_FULL = -1,
    CK_IPC_CHANNEL_EMPTY = -2,
    CK_IPC_MISSING_RIGHTS = -3,
    CK_IPC_INVALID_HANDLE = -4,
    CK_IPC_WRONG_RESOURCE = -5,
    CK_IPC_DELEGATION_FAILED = -6,
};

#define CK_IPC_CHANNEL_RESOURCE 0x49504348u /* "IPCH" */
#define CK_IPC_OBJECT_RESOURCE 0x49504f42u  /* "IPOB" */
#define CK_IPC_PRINCIPAL_A 0x45000041u
#define CK_IPC_PRINCIPAL_B 0x45000042u
#define CK_IPC_OBJECT_SLOTS 4

struct ck_ipc {
    struct ck_channel chan;
    uint64_t object[CK_IPC_OBJECT_SLOTS];
    struct ck_cap_table tables[2]; /* principal A, principal B */
    unsigned active;               /* index of the running principal */
};

/* Fresh state: A holds send (WRITE on the channel) and the object (READ,
 * WRITE, DERIVE, REVOKE); B holds receive (READ on the channel). A active. */
void ck_ipc_reset(struct ck_ipc *ipc, struct ck_handle *a_send, struct ck_handle *a_object,
                  struct ck_handle *b_recv);
int ck_ipc_send(struct ck_ipc *ipc, unsigned principal, struct ck_handle h, const struct ck_msg *m);
int ck_ipc_recv(struct ck_ipc *ipc, unsigned principal, struct ck_handle h, struct ck_msg *m);
/* Delegates the object from principal `from` to `to` with rights that must
 * be a subset of READ|WRITE (and of the source rights). */
int ck_ipc_delegate(struct ck_ipc *ipc, unsigned from, struct ck_handle h, unsigned to,
                    unsigned rights, struct ck_handle *child);
int ck_ipc_object_read(struct ck_ipc *ipc, unsigned principal, struct ck_handle h,
                       uint64_t offset, uint64_t *value);
int ck_ipc_object_write(struct ck_ipc *ipc, unsigned principal, struct ck_handle h,
                        uint64_t offset, uint64_t value);
/* Revokes (owner principal index, h) across both tables. */
int ck_ipc_revoke(struct ck_ipc *ipc, unsigned owner, struct ck_handle h);

#endif
