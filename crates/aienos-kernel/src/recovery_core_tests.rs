use super::*;
use crate::continuity::{self, CortexRecord, Epistemic, ProvisionSource, Update};
use crate::store::genesis::genesis_units;
use alloc::vec;
use alloc::vec::Vec;

const UUID: [u8; 16] = [0x5a; 16];
const AGENT: [u8; 32] = [0x11; 32];
const OPERATOR: [u8; 32] = [0x0f; 32];

#[derive(Clone, PartialEq, Eq)]
struct Mem {
    units: Vec<[u8; STORE_UNIT_BYTES]>,
}

impl StoreDevice for Mem {
    type Error = ();
    fn region_units(&self) -> u64 {
        self.units.len() as u64
    }
    fn read_unit(
        &mut self,
        unit: u64,
        out: &mut [u8; STORE_UNIT_BYTES],
    ) -> core::result::Result<(), ()> {
        *out = *self.units.get(unit as usize).ok_or(())?;
        Ok(())
    }
    fn write_unit(
        &mut self,
        unit: u64,
        bytes: &[u8; STORE_UNIT_BYTES],
    ) -> core::result::Result<(), ()> {
        *self.units.get_mut(unit as usize).ok_or(())? = *bytes;
        Ok(())
    }
    fn flush(&mut self) -> core::result::Result<(), ()> {
        Ok(())
    }
}

fn blank() -> Mem {
    Mem {
        units: vec![[0u8; STORE_UNIT_BYTES]; 256],
    }
}

fn formatted() -> Mem {
    let mut dev = blank();
    for (i, u) in genesis_units(UUID, 256).iter().enumerate() {
        dev.units[i] = *u;
    }
    dev
}

/// Provisioned, with one remembered fact committed.
fn remembered() -> Mem {
    let mut store = Store::open(formatted()).unwrap();
    let c = continuity::provision(&mut store, AGENT, UUID, ProvisionSource::Qualification).unwrap();
    continuity::commit(
        &mut store,
        &c,
        Update {
            state: None,
            cortex: vec![CortexRecord {
                status: Epistemic::OperatorDecision,
                evidence_hash: [0; 32],
                statement: b"keep this".to_vec(),
            }],
        },
        false,
    )
    .unwrap();
    store.into_device()
}

fn degraded() -> Mem {
    let mut dev = remembered();
    let active = Store::open(dev.clone()).unwrap().active_slot() as usize;
    dev.units[1 - active] = [0xa5; STORE_UNIT_BYTES];
    dev
}

fn respond(record: &SystemRecord, action: Action, key: &[u8; 32]) -> [u8; 32] {
    OperatorAuth::expected_response(key, &record.challenge(action).unwrap())
}

#[test]
fn inspection_never_writes_and_names_the_reason() {
    let cases: [(Mem, Option<EntryReason>); 4] = [
        (blank(), Some(EntryReason::StoreUnformatted)),
        (formatted(), Some(EntryReason::Unprovisioned)),
        (remembered(), None),
        (
            degraded(),
            Some(EntryReason::Degraded(PeerCondition::Malformed)),
        ),
    ];
    for (dev, want) in cases {
        let mut probe = dev.clone();
        let record = inspect(&mut probe);
        assert!(probe == dev, "inspection wrote to the device");
        assert_eq!(record.reason, want);
    }
    let r = inspect(&mut remembered());
    assert_eq!(r.continuity.unwrap().root.agent_id, AGENT);
    assert_eq!(r.catalog.unwrap().0, 1, "one agent root");
}

#[test]
fn degraded_repair_needs_the_operator_and_restores_a_writable_store() {
    let mut dev = degraded();
    let record = inspect(&mut dev);
    assert_eq!(record.applicable(), Some(Action::RepairDegradedPeer));
    let good = respond(&record, Action::RepairDegradedPeer, &OPERATOR);

    // Wrong key, wrong action, zero response: refused, nothing written.
    let before = dev.clone();
    let wrong_key = respond(&record, Action::RepairDegradedPeer, &[0x0e; 32]);
    let wrong_action = respond(&record, Action::ProvisionIdentity, &OPERATOR);
    for bad in [wrong_key, wrong_action, [0; 32]] {
        assert_eq!(
            repair_degraded_peer(&mut dev, &OPERATOR, &bad).map(|_| ()),
            Err(RecoveryError::Unauthorised)
        );
        assert!(dev == before, "a refused repair wrote to the device");
    }
    // Provisioning is not the applicable action here.
    assert_eq!(
        provision_identity(&mut dev, &OPERATOR, &wrong_action, [0x22; 32]).map(|_| ()),
        Err(RecoveryError::NotApplicable)
    );

    let after = repair_degraded_peer(&mut dev, &OPERATOR, &good).unwrap();
    assert_eq!(after.reason, None, "store is healthy after repair");
    let (mount, peer, _) = after.mount.unwrap();
    assert_eq!((mount, peer), (MountState::Valid, PeerCondition::Zero));

    // Same identity and memory, and it is writable again.
    let mut store = Store::open(dev.clone()).unwrap();
    let (c, committed) = continuity::resume(&mut store).unwrap();
    assert!(committed);
    assert_eq!(c.root.agent_id, AGENT);
    assert_eq!(c.cortex[0].statement, b"keep this".to_vec());

    // Replaying the old authorisation on the new state does nothing.
    let mut dev = store.into_device();
    let snapshot = dev.clone();
    assert!(repair_degraded_peer(&mut dev, &OPERATOR, &good).is_err());
    assert!(dev == snapshot);
}

#[test]
fn provisioning_is_operator_only_and_only_on_an_unprovisioned_store() {
    let mut dev = formatted();
    let record = inspect(&mut dev);
    assert_eq!(record.applicable(), Some(Action::ProvisionIdentity));
    let before = dev.clone();
    assert_eq!(
        provision_identity(&mut dev, &OPERATOR, &[7; 32], AGENT).map(|_| ()),
        Err(RecoveryError::Unauthorised)
    );
    assert!(dev == before);

    let good = respond(&record, Action::ProvisionIdentity, &OPERATOR);
    let c = provision_identity(&mut dev, &OPERATOR, &good, AGENT).unwrap();
    assert_eq!(c.root.agent_id, AGENT);
    assert_eq!(c.root.source, ProvisionSource::Operator);

    // The same authorisation cannot provision again.
    assert_eq!(
        provision_identity(&mut dev, &OPERATOR, &good, [0x33; 32]).map(|_| ()),
        Err(RecoveryError::NotApplicable)
    );
}

#[test]
fn identity_lost_in_the_newest_root_never_looks_unprovisioned() {
    // Found by the QEMU campaign: provision (generation 2) then corrupt the
    // agent root. The graph-broken generation-2 root makes the Store mount
    // degraded on generation 1 (genesis, no identity). That must not read as
    // "unprovisioned", even to an operator holding a valid key.
    let mut store = Store::open(formatted()).unwrap();
    continuity::provision(&mut store, AGENT, UUID, ProvisionSource::Qualification).unwrap();
    let mut dev = store.into_device();
    let root_unit = Store::open(dev.clone())
        .unwrap()
        .catalog()
        .entries
        .iter()
        .find(|e| e.kind == continuity::KIND_AGENT_ROOT)
        .unwrap()
        .first_unit;
    dev.units[root_unit as usize][20] ^= 0xff;

    let record = inspect(&mut dev);
    assert_eq!(
        record.reason,
        Some(EntryReason::Degraded(PeerCondition::GraphBadNewer))
    );
    assert_eq!(record.applicable(), None);

    // A response that is genuinely valid for this exact state still cannot
    // provision or repair: the refusal is the preservation rule, not the key.
    let before = dev.clone();
    for action in [Action::ProvisionIdentity, Action::RepairDegradedPeer] {
        let valid = respond(&record, action, &OPERATOR);
        let result = match action {
            Action::ProvisionIdentity => {
                provision_identity(&mut dev, &OPERATOR, &valid, [0x22; 32]).map(|_| ())
            }
            Action::RepairDegradedPeer => {
                repair_degraded_peer(&mut dev, &OPERATOR, &valid).map(|_| ())
            }
        };
        assert_eq!(result, Err(RecoveryError::NotApplicable), "{action:?}");
    }
    assert!(dev == before, "nothing was written");
}

#[test]
fn malformed_peer_without_a_resolvable_identity_is_not_repaired() {
    // Garbage in slot B of a formatted store that never had an identity: the
    // valid root resolves no identity, so repair is not offered either.
    let mut dev = formatted();
    dev.units[1] = [0xa5; STORE_UNIT_BYTES];
    let record = inspect(&mut dev);
    assert_eq!(
        record.reason,
        Some(EntryReason::Degraded(PeerCondition::Malformed))
    );
    assert_eq!(record.applicable(), None);
}

#[test]
fn orphaned_continuity_objects_are_corrupt_not_unprovisioned() {
    // A manifest without its agent root means the identity was lost.
    let mut store = Store::open(formatted()).unwrap();
    let orphan = continuity::Manifest {
        root: crate::store::v1::ObjectId([0x77; 32]),
        previous: None,
        sequence: 1,
        incarnation: 1,
        agent_state: None,
        cortex_wal: Vec::new(),
    }
    .encode()
    .unwrap();
    store
        .transact(&[crate::store::engine::ObjectInput {
            kind: continuity::KIND_MANIFEST,
            version: continuity::STORE_OBJECT_VERSION,
            bytes: &orphan,
        }])
        .unwrap();
    let mut dev = store.into_device();
    let record = inspect(&mut dev);
    assert!(
        matches!(record.reason, Some(EntryReason::ContinuityCorrupt(_))),
        "{:?}",
        record.reason
    );
    assert_eq!(record.applicable(), None);
}

#[test]
fn identity_loss_through_corruption_offers_no_action_that_mints() {
    // Corrupt the agent root object's bytes: the Store graph no longer
    // validates, so the Recovery Core must stop, not provision.
    let mut dev = remembered();
    let root_unit = {
        let store = Store::open(dev.clone()).unwrap();
        store
            .catalog()
            .entries
            .iter()
            .find(|e| e.kind == continuity::KIND_AGENT_ROOT)
            .unwrap()
            .first_unit
    };
    dev.units[root_unit as usize][20] ^= 0xff;
    let record = inspect(&mut dev);
    assert!(
        matches!(
            record.reason,
            Some(EntryReason::StoreMount(_) | EntryReason::ContinuityCorrupt(_))
        ),
        "{:?}",
        record.reason
    );
    assert_eq!(record.applicable(), None);
    let before = dev.clone();
    let forged = [0x55; 32];
    assert!(provision_identity(&mut dev, &OPERATOR, &forged, [0x22; 32]).is_err());
    assert!(repair_degraded_peer(&mut dev, &OPERATOR, &forged).is_err());
    assert!(dev == before, "no action wrote after identity loss");
}

#[test]
fn challenges_bind_state_and_action() {
    let r1 = inspect(&mut degraded());
    let mut other = degraded();
    let active = Store::open(other.clone()).unwrap().active_slot() as usize;
    other.units[1 - active] = [0x5a; STORE_UNIT_BYTES];
    let r2 = inspect(&mut other);
    assert_ne!(
        r1.challenge(Action::RepairDegradedPeer),
        r2.challenge(Action::RepairDegradedPeer),
        "different on-disk state, different challenge"
    );
    assert_ne!(
        r1.challenge(Action::RepairDegradedPeer),
        r1.challenge(Action::ProvisionIdentity)
    );
}
