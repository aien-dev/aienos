//! Deterministic Recovery Core entry, inspection and operator-authorised
//! actions over System Store v1 and continuity (ADR 0006, ADR 0007, ADR 0016).
//!
//! No model, no network. Inspection never writes. Every write is an explicit
//! operator action whose challenge is bound to the exact on-disk state it
//! acts on, so an authorisation cannot be replayed onto a different state or
//! used for a different action. No action here can create an identity on a
//! store that already holds data it cannot account for.

use crate::continuity::{self, Continuity, ContinuityError, ProvisionSource};
use crate::crypto::sha256::Sha256;
use crate::recovery::OperatorAuth;
use crate::store::engine::{MountError, MountState, PeerCondition, Store, StoreDevice};
use crate::store::v1::{FormatError, Superblock, STORE_UNIT_BYTES};

/// What one superblock slot holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotView {
    Zero,
    Superblock { generation: u64 },
    Undecodable(FormatError),
    ReadError,
}

/// Why the Recovery Core was entered (or `None` when a normal boot may proceed).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryReason {
    StoreUnformatted,
    StoreMount(MountError),
    Unprovisioned,
    Conflict,
    ContinuityCorrupt(&'static str),
    Degraded(PeerCondition),
}

/// Operator actions the Recovery Core can perform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Zero the inactive superblock slot of a `DegradedRecovery` store so it
    /// mounts writable again on its valid root.
    RepairDegradedPeer = 1,
    /// Create the one identity on a formatted store with no agent root.
    ProvisionIdentity = 2,
}

impl Action {
    pub const fn name(self) -> &'static str {
        match self {
            Action::RepairDegradedPeer => "repair-degraded-peer",
            Action::ProvisionIdentity => "provision-identity",
        }
    }
}

/// The read-only raw system record printed on entry.
#[derive(Clone, Debug)]
pub struct SystemRecord {
    pub slots: [SlotView; 2],
    /// SHA-256 over both raw superblock units: binds challenges to this state.
    pub state_digest: [u8; 32],
    pub store_uuid: Option<[u8; 16]>,
    pub mount: Option<(MountState, PeerCondition, u64)>,
    pub reason: Option<EntryReason>,
    pub continuity: Option<Continuity>,
    /// Catalog entry counts: agent roots, manifests, other.
    pub catalog: Option<(usize, usize, usize)>,
}

impl SystemRecord {
    /// The action this state admits, if any.
    pub fn applicable(&self) -> Option<Action> {
        match self.reason? {
            EntryReason::Degraded(PeerCondition::Malformed | PeerCondition::GraphBadNewer) => {
                Some(Action::RepairDegradedPeer)
            }
            EntryReason::Unprovisioned => Some(Action::ProvisionIdentity),
            _ => None,
        }
    }

    /// Challenge for `action` on exactly this state:
    /// SHA-256(domain || store uuid || generation || action || state digest).
    pub fn challenge(&self, action: Action) -> Option<[u8; 32]> {
        let uuid = self.store_uuid?;
        let (_, _, generation) = self.mount?;
        let mut h = Sha256::new();
        h.update(b"AIENOS-RECOVERY-CHALLENGE-v1\0");
        h.update(&uuid);
        h.update(&generation.to_le_bytes());
        h.update(&[action as u8]);
        h.update(&self.state_digest);
        Some(h.finalize())
    }
}

/// Inspects `device` in place. Never writes.
pub fn inspect<D: StoreDevice>(device: &mut D) -> SystemRecord {
    let mut raw = [[0u8; STORE_UNIT_BYTES]; 2];
    let mut slots = [SlotView::ReadError; 2];
    let mut uuid = None;
    for slot in 0..2 {
        if device.read_unit(slot as u64, &mut raw[slot]).is_err() {
            continue;
        }
        slots[slot] = if raw[slot].iter().all(|b| *b == 0) {
            SlotView::Zero
        } else {
            match Superblock::decode(&raw[slot], slot as u32) {
                Ok(sb) => {
                    uuid.get_or_insert(sb.store_uuid);
                    SlotView::Superblock {
                        generation: sb.generation,
                    }
                }
                Err(e) => SlotView::Undecodable(e),
            }
        };
    }
    let mut h = Sha256::new();
    h.update(&raw[0]);
    h.update(&raw[1]);
    let state_digest = h.finalize();

    let mut record = SystemRecord {
        slots,
        state_digest,
        store_uuid: uuid,
        mount: None,
        reason: None,
        continuity: None,
        catalog: None,
    };

    let mut store = match Store::open(Borrowed(device)) {
        Ok(store) => store,
        Err(e) => {
            record.reason = Some(match e {
                MountError::Unformatted => EntryReason::StoreUnformatted,
                other => EntryReason::StoreMount(other),
            });
            return record;
        }
    };
    record.mount = Some((
        store.mount_state(),
        store.peer_condition(),
        store.generation(),
    ));
    let entries = &store.catalog().entries;
    let roots = entries
        .iter()
        .filter(|e| e.kind == continuity::KIND_AGENT_ROOT)
        .count();
    let manifests = entries
        .iter()
        .filter(|e| e.kind == continuity::KIND_MANIFEST)
        .count();
    record.catalog = Some((roots, manifests, entries.len() - roots - manifests));

    match continuity::resolve(&mut store) {
        Ok(c) => record.continuity = Some(c),
        Err(ContinuityError::Unprovisioned) => record.reason = Some(EntryReason::Unprovisioned),
        Err(ContinuityError::Conflict) => record.reason = Some(EntryReason::Conflict),
        Err(ContinuityError::Corrupt(why)) => {
            record.reason = Some(EntryReason::ContinuityCorrupt(why))
        }
        Err(_) => record.reason = Some(EntryReason::ContinuityCorrupt("continuity unreadable")),
    }
    if store.mount_state() == MountState::DegradedRecovery && record.reason.is_none() {
        record.reason = Some(EntryReason::Degraded(store.peer_condition()));
    }
    record
}

/// Borrowing adapter: `Store::open` takes its device by value, and a failed
/// mount must not lose the caller's device.
struct Borrowed<'a, D: StoreDevice>(&'a mut D);

impl<D: StoreDevice> StoreDevice for Borrowed<'_, D> {
    type Error = D::Error;
    fn region_units(&self) -> u64 {
        self.0.region_units()
    }
    fn read_unit(&mut self, unit: u64, out: &mut [u8; STORE_UNIT_BYTES]) -> Result<(), D::Error> {
        self.0.read_unit(unit, out)
    }
    fn write_unit(&mut self, unit: u64, bytes: &[u8; STORE_UNIT_BYTES]) -> Result<(), D::Error> {
        self.0.write_unit(unit, bytes)
    }
    fn flush(&mut self) -> Result<(), D::Error> {
        self.0.flush()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    /// The state does not admit this action.
    NotApplicable,
    /// The operator response did not verify for this state and action.
    Unauthorised,
    Io,
    Continuity(ContinuityError),
}

fn authorise(
    record: &SystemRecord,
    action: Action,
    operator_key: &[u8; 32],
    response: &[u8; 32],
) -> Result<(), RecoveryError> {
    if record.applicable() != Some(action) {
        return Err(RecoveryError::NotApplicable);
    }
    let challenge = record
        .challenge(action)
        .ok_or(RecoveryError::NotApplicable)?;
    if !OperatorAuth::verify_offline_credentials(operator_key, &challenge, response) {
        return Err(RecoveryError::Unauthorised);
    }
    Ok(())
}

/// Zeroes the inactive superblock slot of a degraded store after verifying
/// the operator's response. Nothing is written unless authorisation passes.
pub fn repair_degraded_peer<D: StoreDevice>(
    device: &mut D,
    operator_key: &[u8; 32],
    response: &[u8; 32],
) -> Result<SystemRecord, RecoveryError> {
    let record = inspect(device);
    authorise(&record, Action::RepairDegradedPeer, operator_key, response)?;
    // The valid root is the decodable slot the engine mounted; the other goes.
    let active = {
        let store = Store::open(Borrowed(device)).map_err(|_| RecoveryError::Io)?;
        store.active_slot() as u64
    };
    let peer = 1 - active;
    device
        .write_unit(peer, &[0u8; STORE_UNIT_BYTES])
        .map_err(|_| RecoveryError::Io)?;
    device.flush().map_err(|_| RecoveryError::Io)?;
    Ok(inspect(device))
}

/// Provisions the one identity on an unprovisioned store after verifying the
/// operator's response. Refused on any other state.
pub fn provision_identity<D: StoreDevice>(
    device: &mut D,
    operator_key: &[u8; 32],
    response: &[u8; 32],
    agent_id: [u8; 32],
) -> Result<Continuity, RecoveryError> {
    let record = inspect(device);
    authorise(&record, Action::ProvisionIdentity, operator_key, response)?;
    let uuid = record.store_uuid.ok_or(RecoveryError::NotApplicable)?;
    let mut store = Store::open(Borrowed(device)).map_err(|_| RecoveryError::Io)?;
    continuity::provision(&mut store, agent_id, uuid, ProvisionSource::Operator)
        .map_err(RecoveryError::Continuity)
}

#[cfg(test)]
#[path = "recovery_core_tests.rs"]
mod tests;
