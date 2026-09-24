//! Typed kernel-owned message channels, gated by capability handles.
//!
//! The channel ring, the object bytes and every principal's capability table
//! are kernel-owned. A task can only touch a channel or object through a
//! handle in its own table with the required right, so there is no global
//! lookup that bypasses caller authority. Delegation uses
//! [`crate::caps::CapTable::derive_into`], which links the child to its parent
//! for tree revocation: attenuating a capability and later revoking the
//! ancestor invalidates every derived copy.

use crate::caps::{CapError, CapTable, Handle, Rights};
use core::sync::atomic::{AtomicU32, Ordering};

pub use crate::abi::{ChannelId, MemoryRegion, Message, ObjectId, TaskId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    Full,
    Empty,
}

/// Bounded FIFO ring of fixed-size messages. Deterministic: send appends at
/// `tail`, receive pops from `head`, no allocation, no dropping.
pub struct Channel<const N: usize> {
    ring: [Message; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Channel<N> {
    pub const fn new() -> Self {
        Self {
            ring: [Message::NEW; N],
            head: 0,
            len: 0,
        }
    }

    pub fn send(&mut self, message: Message) -> Result<(), ChannelError> {
        if self.len == N {
            return Err(ChannelError::Full);
        }
        let tail = (self.head + self.len) % N;
        self.ring[tail] = message;
        self.len += 1;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Message, ChannelError> {
        if self.len == 0 {
            return Err(ChannelError::Empty);
        }
        let message = self.ring[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Ok(message)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> Default for Channel<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcError {
    ChannelFull,
    ChannelEmpty,
    MissingRights,
    InvalidHandle,
    WrongResource,
    DelegationFailed,
}

impl From<CapError> for IpcError {
    fn from(error: CapError) -> Self {
        match error {
            CapError::Full => IpcError::DelegationFailed,
            CapError::InvalidHandle => IpcError::InvalidHandle,
            CapError::MissingRights => IpcError::MissingRights,
            CapError::RightsEscalation => IpcError::MissingRights,
            CapError::DuplicateTable => IpcError::InvalidHandle,
        }
    }
}

/// Capability resource IDs. A channel capability carries the channel ID as its
/// resource; an object capability carries [`OBJECT_RESOURCE`].
pub const CHANNEL_RESOURCE: u32 = 0x4950_4348;
pub const OBJECT_RESOURCE: u32 = 0x4950_4F42;

pub const PRINCIPAL_A: u32 = 0x4500_0041;
pub const PRINCIPAL_B: u32 = 0x4500_0042;

pub const CHANNEL: ChannelId = ChannelId(0);
pub const CHANNEL_CAPACITY: usize = 8;
pub const TABLE_CAPACITY: usize = 8;

/// Kernel-owned object bytes reachable only through object capabilities.
pub const OBJECT_SLOTS: usize = 4;

// Kernel-owned IPC state. Touched only from EL1 dispatchers.
static mut CHANNELS: [Channel<CHANNEL_CAPACITY>; 2] = [Channel::new(), Channel::new()];
static mut OBJECT: [u64; OBJECT_SLOTS] = [0; OBJECT_SLOTS];
static mut PRINCIPAL_TABLES: [CapTable<TABLE_CAPACITY>; 2] =
    [CapTable::new(PRINCIPAL_A), CapTable::new(PRINCIPAL_B)];
static ACTIVE_PRINCIPAL: AtomicU32 = AtomicU32::new(0);

fn principal_index(id: u32) -> Option<usize> {
    match id {
        PRINCIPAL_A => Some(0),
        PRINCIPAL_B => Some(1),
        _ => None,
    }
}

/// Reset every kernel-owned IPC structure and provision the two principals:
/// A holds the channel send right plus a full-rights object capability;
/// B holds only the channel receive right. Returns A's channel and object
/// handles and B's channel handle.
///
/// # Safety
/// Caller must have exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn reset() -> (Handle, Handle, Handle) {
    unsafe { CHANNELS[CHANNEL.0 as usize] = Channel::new() };
    unsafe {
        OBJECT = [0xc0ff_ee01, 0x0bad_c0de, 0x1234_5678, 0x9abc_def0];
        PRINCIPAL_TABLES = [CapTable::new(PRINCIPAL_A), CapTable::new(PRINCIPAL_B)];
    }
    ACTIVE_PRINCIPAL.store(PRINCIPAL_A, Ordering::Release);
    let send = unsafe { principal_table_at(0) }
        .insert(CHANNEL_RESOURCE, Rights::WRITE)
        .expect("principal A send capability");
    let object = unsafe { principal_table_at(0) }
        .insert(
            OBJECT_RESOURCE,
            Rights::READ | Rights::WRITE | Rights::DERIVE | Rights::REVOKE,
        )
        .expect("principal A object capability");
    let recv = unsafe { principal_table_at(1) }
        .insert(CHANNEL_RESOURCE, Rights::READ)
        .expect("principal B receive capability");
    (send, object, recv)
}

/// Record the principal about to run at EL0; syscall dispatch resolves
/// handles against that principal's table.
pub fn set_active_principal(id: TaskId) {
    ACTIVE_PRINCIPAL.store(id.0, Ordering::Release);
}

/// # Safety
/// The active principal's table must not be aliased elsewhere.
pub unsafe fn with_active_table<R>(
    f: impl FnOnce(&mut CapTable<TABLE_CAPACITY>) -> Result<R, IpcError>,
) -> Result<R, IpcError> {
    let index =
        principal_index(ACTIVE_PRINCIPAL.load(Ordering::Acquire)).ok_or(IpcError::InvalidHandle)?;
    let table = unsafe { (&raw mut PRINCIPAL_TABLES[index]).as_mut().unwrap() };
    f(table)
}

fn channel_table() -> &'static mut Channel<CHANNEL_CAPACITY> {
    // SAFETY: EL1-only, single CPU, bounded channel set.
    unsafe { (&raw mut CHANNELS[CHANNEL.0 as usize]).as_mut().unwrap() }
}

fn gated(
    table: &CapTable<TABLE_CAPACITY>,
    handle: Handle,
    right: Rights,
    resource: u32,
) -> Result<(), IpcError> {
    match table.lookup(handle, right) {
        Ok(found) if found == resource => Ok(()),
        Ok(_) => Err(IpcError::WrongResource),
        Err(CapError::MissingRights) => Err(IpcError::MissingRights),
        Err(_) => Err(IpcError::InvalidHandle),
    }
}

/// Send a typed message on a channel the caller holds with WRITE right.
pub fn channel_send(
    table: &mut CapTable<TABLE_CAPACITY>,
    handle: Handle,
    message: Message,
) -> Result<(), IpcError> {
    gated(table, handle, Rights::WRITE, CHANNEL_RESOURCE)?;
    channel_table()
        .send(message)
        .map_err(|_| IpcError::ChannelFull)
}

/// Receive a typed message from a channel the caller holds with READ right.
pub fn channel_receive(
    table: &mut CapTable<TABLE_CAPACITY>,
    handle: Handle,
) -> Result<Message, IpcError> {
    gated(table, handle, Rights::READ, CHANNEL_RESOURCE)?;
    channel_table()
        .receive()
        .map_err(|_| IpcError::ChannelEmpty)
}

/// Delegate an object capability into another principal's table with
/// attenuated rights. Requires DERIVE on the source; escalation is rejected by
/// the capability table. The child keeps a parent link for tree revocation.
pub fn delegate_object(
    from: &mut CapTable<TABLE_CAPACITY>,
    handle: Handle,
    to: &mut CapTable<TABLE_CAPACITY>,
    rights: Rights,
) -> Result<Handle, IpcError> {
    gated(from, handle, Rights::READ, OBJECT_RESOURCE)?;
    if !rights.is_subset_of(Rights::READ | Rights::WRITE) {
        return Err(IpcError::MissingRights);
    }
    CapTable::derive_into(from, handle, to, rights).map_err(IpcError::from)
}

/// Read one word of a kernel object through a READ capability.
pub fn object_read(
    table: &CapTable<TABLE_CAPACITY>,
    handle: Handle,
    offset: usize,
) -> Result<u64, IpcError> {
    gated(table, handle, Rights::READ, OBJECT_RESOURCE)?;
    if offset >= OBJECT_SLOTS {
        return Err(IpcError::WrongResource);
    }
    // SAFETY: EL1-only state; bounds checked above.
    Ok(unsafe { OBJECT[offset] })
}

/// Write one word of a kernel object through a WRITE capability.
pub fn object_write(
    table: &mut CapTable<TABLE_CAPACITY>,
    handle: Handle,
    offset: usize,
    value: u64,
) -> Result<(), IpcError> {
    gated(table, handle, Rights::WRITE, OBJECT_RESOURCE)?;
    if offset >= OBJECT_SLOTS {
        return Err(IpcError::WrongResource);
    }
    // SAFETY: EL1-only state; bounds checked above.
    unsafe { OBJECT[offset] = value };
    Ok(())
}

/// Revoke an ancestor object capability; every derived child in the supplied
/// table set becomes invalid.
///
/// # Safety
/// Exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn revoke_object_ancestor(owner: u32, handle: Handle) -> Result<(), IpcError> {
    let mut tables = [
        unsafe { (&raw mut PRINCIPAL_TABLES[0]).as_mut().unwrap() },
        unsafe { (&raw mut PRINCIPAL_TABLES[1]).as_mut().unwrap() },
    ];
    CapTable::<TABLE_CAPACITY>::revoke(owner, handle, &mut tables).map_err(IpcError::from)
}

/// Look a raw handle up in the active principal's table for `right`, bounded
/// to `resource`. The EL0 entry point for every object/channel operation.
///
/// # Safety
/// Exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn active_lookup(handle: Handle, right: Rights, resource: u32) -> Result<(), IpcError> {
    let index =
        principal_index(ACTIVE_PRINCIPAL.load(Ordering::Acquire)).ok_or(IpcError::InvalidHandle)?;
    let table = unsafe { (&raw mut PRINCIPAL_TABLES[index]).as_mut().unwrap() };
    gated(table, handle, right, resource)
}

/// Resolve the table for a principal index without an active-principal check;
/// callers gate authority themselves.
///
/// # Safety
/// Exclusive access to the kernel IPC state; indices must be distinct when
/// two tables are held at once.
unsafe fn principal_table_at(index: usize) -> &'static mut CapTable<TABLE_CAPACITY> {
    unsafe { (&raw mut PRINCIPAL_TABLES[index]).as_mut().unwrap() }
}

fn active_index() -> Result<usize, IpcError> {
    principal_index(ACTIVE_PRINCIPAL.load(Ordering::Acquire)).ok_or(IpcError::InvalidHandle)
}

/// Send on a channel from the active principal's table.
///
/// # Safety
/// Exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn channel_send_active(handle: Handle, message: Message) -> Result<(), IpcError> {
    let index = active_index()?;
    let table = unsafe { principal_table_at(index) };
    channel_send(table, handle, message)
}

/// Receive from a channel on the active principal's table.
///
/// # Safety
/// Exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn channel_receive_active(handle: Handle) -> Result<Message, IpcError> {
    let index = active_index()?;
    let table = unsafe { principal_table_at(index) };
    channel_receive(table, handle)
}

/// Delegate from the active principal's table into another principal's table.
/// The source is always the active principal, so a task can never delegate a
/// capability it does not itself hold.
///
/// # Safety
/// Exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn delegate_from_active(
    handle: Handle,
    to_index: u32,
    rights: Rights,
) -> Result<Handle, IpcError> {
    let from_index = active_index()?;
    let to_index = principal_index(match to_index {
        0 => PRINCIPAL_A,
        1 => PRINCIPAL_B,
        _ => return Err(IpcError::InvalidHandle),
    })
    .ok_or(IpcError::InvalidHandle)?;
    if from_index == to_index {
        return Err(IpcError::InvalidHandle);
    }
    let from = unsafe { principal_table_at(from_index) };
    let to = unsafe { principal_table_at(to_index) };
    delegate_object(from, handle, to, rights)
}

/// Read a kernel object word from the active principal's table.
///
/// # Safety
/// Exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn object_read_active(handle: Handle, offset: usize) -> Result<u64, IpcError> {
    let index = active_index()?;
    let table = unsafe { principal_table_at(index) };
    object_read(table, handle, offset)
}

/// Write a kernel object word from the active principal's table.
///
/// # Safety
/// Exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn object_write_active(
    handle: Handle,
    offset: usize,
    value: u64,
) -> Result<(), IpcError> {
    let index = active_index()?;
    let table = unsafe { principal_table_at(index) };
    object_write(table, handle, offset, value)
}

/// Access the active principal's table mutably.
///
/// # Safety
/// Exclusive access to the kernel IPC state (EL1, single CPU).
pub unsafe fn active_table() -> &'static mut CapTable<TABLE_CAPACITY> {
    let index =
        principal_index(ACTIVE_PRINCIPAL.load(Ordering::Acquire)).expect("active principal");
    unsafe { (&raw mut PRINCIPAL_TABLES[index]).as_mut().unwrap() }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SERIAL: AtomicU32 = AtomicU32::new(0);

    /// Tests share the kernel-owned IPC statics; serialize them. The guard
    /// releases on drop so a panicking test cannot wedge the rest.
    struct Serial;
    impl Drop for Serial {
        fn drop(&mut self) {
            TEST_SERIAL.store(0, Ordering::Release);
        }
    }
    fn serial() -> Serial {
        while TEST_SERIAL
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Serial
    }

    fn message(kind: u32) -> Message {
        Message::new(
            kind,
            [kind as u64, 0x22, 0x33],
            MemoryRegion::new(0x1000, 2),
            ObjectId(0x0a),
        )
    }

    #[test]
    fn message_abi_is_fixed_size_and_unaligned_free() {
        let _serial = serial();
        assert_eq!(core::mem::size_of::<Message>(), 56);
        assert_eq!(core::mem::align_of::<Message>(), 8);
        assert_eq!(core::mem::size_of::<MemoryRegion>(), 16);
        assert_eq!(core::mem::size_of::<TaskId>(), 4);
        assert_eq!(core::mem::size_of::<ChannelId>(), 4);
        assert_eq!(core::mem::size_of::<ObjectId>(), 8);
    }

    #[test]
    fn channel_is_fifo_and_bounded() {
        let _serial = serial();
        let mut channel: Channel<2> = Channel::new();
        assert!(channel.is_empty());
        channel.send(message(1)).unwrap();
        channel.send(message(2)).unwrap();
        assert_eq!(channel.send(message(3)), Err(ChannelError::Full));
        assert_eq!(channel.receive().unwrap(), message(1));
        assert_eq!(channel.receive().unwrap(), message(2));
        assert_eq!(channel.receive(), Err(ChannelError::Empty));
        // Wrap deterministically after drain.
        channel.send(message(4)).unwrap();
        assert_eq!(channel.receive().unwrap(), message(4));
    }

    #[test]
    fn send_requires_write_and_receive_requires_read() {
        let _serial = serial();
        let (a_send, _a_object, b_recv) = unsafe { reset() };
        let a = unsafe { active_table() };
        // A's send handle lacks READ, so receive must be denied even for A.
        assert_eq!(channel_receive(a, a_send), Err(IpcError::MissingRights));
        // B's receive handle lacks WRITE, so send must be denied.
        set_active_principal(TaskId(PRINCIPAL_B));
        let b = unsafe { active_table() };
        assert_eq!(
            channel_send(b, b_recv, message(9)),
            Err(IpcError::MissingRights)
        );
        assert!(channel_table().is_empty());
    }

    #[test]
    fn stale_and_forged_handles_are_invalid() {
        let _serial = serial();
        let (a_send, _a_object, _b_recv) = unsafe { reset() };
        let mut forged = a_send;
        forged.generation = forged.generation.wrapping_add(1);
        let a = unsafe { active_table() };
        assert_eq!(
            channel_send(a, forged, message(1)),
            Err(IpcError::InvalidHandle)
        );
        // Tombstoned index with an old generation is equally invalid.
        let mut stale = a_send;
        stale.index = TABLE_CAPACITY as u32 + 1;
        assert_eq!(
            channel_send(a, stale, message(1)),
            Err(IpcError::InvalidHandle)
        );
    }

    #[test]
    fn delegation_without_derive_right_is_denied() {
        let _serial = serial();
        let (_a_send, _a_object, _b_recv) = unsafe { reset() };
        let mut b = CapTable::<TABLE_CAPACITY>::new(PRINCIPAL_B);
        // Strip DERIVE from A's object capability first: derive a READ-only
        // child into a scratch table, revoke the original... simpler: build a
        // source without DERIVE directly.
        let a = unsafe { active_table() };
        let plain = a.insert(OBJECT_RESOURCE, Rights::READ).unwrap();
        assert_eq!(
            delegate_object(a, plain, &mut b, Rights::READ),
            Err(IpcError::MissingRights)
        );
    }

    #[test]
    fn rights_escalation_is_rejected() {
        let _serial = serial();
        let (_a_send, a_object, _b_recv) = unsafe { reset() };
        let a = unsafe { active_table() };
        let mut b = CapTable::<TABLE_CAPACITY>::new(PRINCIPAL_B);
        assert_eq!(
            delegate_object(a, a_object, &mut b, Rights::READ | Rights::MAP),
            Err(IpcError::MissingRights),
            "delegating a right the source does not hold is escalation"
        );
        // READ|WRITE is a legal subset of the source and must succeed.
        assert!(delegate_object(a, a_object, &mut b, Rights::READ | Rights::WRITE).is_ok());
    }

    #[test]
    fn receiver_table_full_rolls_back_cleanly() {
        let _serial = serial();
        let (_a_send, a_object, _b_recv) = unsafe { reset() };
        let a = unsafe { active_table() };
        let mut tiny = CapTable::<1>::new(PRINCIPAL_B);
        tiny.insert(CHANNEL_RESOURCE, Rights::READ).unwrap();
        assert_eq!(
            CapTable::derive_into(a, a_object, &mut tiny, Rights::READ),
            Err(CapError::Full)
        );
        // The source must be untouched by the failed derivation: it can still
        // derive into a table with room.
        let mut fresh = CapTable::<TABLE_CAPACITY>::new(0x515);
        assert!(CapTable::derive_into(a, a_object, &mut fresh, Rights::READ).is_ok());
    }

    #[test]
    fn attenuated_child_cannot_write_or_escalate() {
        let _serial = serial();
        let (_a_send, a_object, _b_recv) = unsafe { reset() };
        let a = unsafe { active_table() };
        let mut b = CapTable::<TABLE_CAPACITY>::new(PRINCIPAL_B);
        let child = CapTable::derive_into(a, a_object, &mut b, Rights::READ).unwrap();
        assert_eq!(object_read(&b, child, 0), Ok(OBJECT_INITIALIZER[0]));
        assert_eq!(
            object_write(&mut b, child, 0, 0xdead),
            Err(IpcError::MissingRights)
        );
        // The child cannot re-delegate either: it lacks DERIVE.
        let mut c = CapTable::<TABLE_CAPACITY>::new(0x515);
        assert_eq!(
            CapTable::derive_into(&mut b, child, &mut c, Rights::READ),
            Err(CapError::MissingRights)
        );
    }

    #[test]
    fn ancestor_revocation_reaches_the_derived_child() {
        let _serial = serial();
        let (_a_send, a_object, _b_recv) = unsafe { reset() };
        let a = unsafe { active_table() };
        set_active_principal(TaskId(PRINCIPAL_B));
        let b = unsafe { active_table() };
        let child = CapTable::derive_into(a, a_object, b, Rights::READ).unwrap();
        assert!(object_read(b, child, 1).is_ok());
        unsafe { revoke_object_ancestor(PRINCIPAL_A, a_object).unwrap() };
        assert_eq!(
            object_read(b, child, 1),
            Err(IpcError::InvalidHandle),
            "revoking the ancestor invalidates the derived handle"
        );
        // And the owner's own capability is gone too.
        assert_eq!(object_read(a, a_object, 1), Err(IpcError::InvalidHandle));
    }

    #[test]
    fn end_to_end_send_delegate_receive_read() {
        let _serial = serial();
        let (a_send, a_object, b_recv) = unsafe { reset() };
        let a = unsafe { active_table() };
        channel_send(a, a_send, message(7)).unwrap();
        set_active_principal(TaskId(PRINCIPAL_B));
        let b = unsafe { active_table() };
        let child = CapTable::derive_into(a, a_object, b, Rights::READ).unwrap();
        let received = channel_receive(b, b_recv).unwrap();
        assert_eq!(received, message(7));
        assert_eq!(object_read(b, child, 0), Ok(OBJECT_INITIALIZER[0]));
        assert_eq!(object_write(b, child, 0, 1), Err(IpcError::MissingRights));
    }

    const OBJECT_INITIALIZER: [u64; OBJECT_SLOTS] =
        [0xc0ff_ee01, 0x0bad_c0de, 0x1234_5678, 0x9abc_def0];
}
