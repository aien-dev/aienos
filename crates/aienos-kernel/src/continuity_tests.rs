use super::*;
use crate::store::engine::{MountState, ObjectInput, Store, StoreDevice};
use crate::store::genesis::genesis_units;
use crate::store::v1::STORE_UNIT_BYTES;
use alloc::vec;

const UUID: [u8; 16] = [0x5a; 16];
const AGENT: [u8; 32] = [0x11; 32];

#[derive(Clone)]
struct Mem {
    units: Vec<[u8; STORE_UNIT_BYTES]>,
    /// Writes accepted before the device "loses power" (None = unlimited).
    writes_left: Option<usize>,
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
        if let Some(left) = self.writes_left.as_mut() {
            if *left == 0 {
                return Err(());
            }
            *left -= 1;
        }
        *self.units.get_mut(unit as usize).ok_or(())? = *bytes;
        Ok(())
    }
    fn flush(&mut self) -> core::result::Result<(), ()> {
        Ok(())
    }
}

fn formatted() -> Mem {
    let mut units = vec![[0u8; STORE_UNIT_BYTES]; 256];
    for (i, u) in genesis_units(UUID, 256).iter().enumerate() {
        units[i] = *u;
    }
    Mem {
        units,
        writes_left: None,
    }
}

fn open(dev: Mem) -> Store<Mem> {
    Store::open(dev).expect("store opens")
}

fn fact(text: &str) -> CortexRecord {
    CortexRecord {
        status: Epistemic::OperatorDecision,
        evidence_hash: [0x42; 32],
        statement: text.as_bytes().to_vec(),
    }
}

fn provisioned() -> Store<Mem> {
    let mut store = open(formatted());
    provision(&mut store, AGENT, UUID, ProvisionSource::Qualification).unwrap();
    store
}

/// Simulates a cold restart: drop everything in memory, reopen the medium.
fn restart(store: Store<Mem>) -> Store<Mem> {
    open(store.into_device())
}

#[test]
fn unprovisioned_store_never_mints_an_identity() {
    let mut store = open(formatted());
    let generation = store.generation();
    assert_eq!(resolve(&mut store), Err(ContinuityError::Unprovisioned));
    assert_eq!(
        resume(&mut store).map(|_| ()),
        Err(ContinuityError::Unprovisioned)
    );
    assert_eq!(store.generation(), generation, "nothing was written");
    assert!(store.catalog().entries.is_empty());
}

#[test]
fn provision_then_cold_restart_returns_the_same_identity_and_memory() {
    let mut store = provisioned();
    let c1 = resolve(&mut store).unwrap();
    assert_eq!(c1.root.agent_id, AGENT);
    assert_eq!(c1.manifest.sequence, 1);
    assert_eq!(c1.manifest.incarnation, 1);

    // Commit memory and a branch fork.
    let mut state = c1.state.clone();
    let child = state.fork(&c1.root.root_branch).unwrap();
    let c2 = commit(
        &mut store,
        &c1,
        Update {
            state: Some(state),
            cortex: vec![fact("the operator's name is Drake"), fact("M4 is next")],
        },
        false,
    )
    .unwrap();
    assert_eq!(c2.cortex.len(), 2);

    // Cold restart: same identity, same memory, same lineage, incarnation + 1.
    let mut store = restart(store);
    let (c3, committed) = resume(&mut store).unwrap();
    assert!(committed);
    assert_eq!(c3.root_id, c1.root_id);
    assert_eq!(c3.root.agent_id, AGENT);
    assert_eq!(c3.manifest.incarnation, 2);
    assert_eq!(c3.manifest.sequence, 3);
    assert_eq!(c3.cortex, c2.cortex);
    let branch = c3.state.branch(&child).expect("forked branch survived");
    assert_eq!(branch.parent, Some(c1.root.root_branch));
    assert_eq!(branch.depth, 1);

    // A second restart advances only the incarnation.
    let mut store = restart(store);
    let (c4, _) = resume(&mut store).unwrap();
    assert_eq!(c4.manifest.incarnation, 3);
    assert_eq!(c4.root, c3.root);
    assert_eq!(c4.state, c3.state);
    assert_eq!(c4.cortex, c3.cortex);
}

#[test]
fn provisioning_twice_is_refused() {
    let mut store = provisioned();
    assert_eq!(
        provision(&mut store, [0x22; 32], UUID, ProvisionSource::Operator).map(|_| ()),
        Err(ContinuityError::AlreadyProvisioned)
    );
    assert_eq!(resolve(&mut store).unwrap().root.agent_id, AGENT);
}

#[test]
fn two_roots_stop_with_conflict() {
    let mut store = provisioned();
    // Bypass `provision` to plant a second root, as corruption or a bad merge could.
    let other = AgentRoot {
        agent_id: [0x22; 32],
        store_uuid: UUID,
        root_branch: root_branch_id(&[0x22; 32]),
        provisioned_generation: 9,
        source: ProvisionSource::Operator,
    }
    .encode();
    store
        .transact(&[ObjectInput {
            kind: KIND_AGENT_ROOT,
            version: STORE_OBJECT_VERSION,
            bytes: &other,
        }])
        .unwrap();
    assert_eq!(resolve(&mut store), Err(ContinuityError::Conflict));
    assert_eq!(
        resume(&mut store).map(|_| ()),
        Err(ContinuityError::Conflict)
    );
}

#[test]
fn forked_or_gapped_manifest_chains_are_corrupt() {
    // Fork: two manifests both claiming sequence 2.
    let mut store = provisioned();
    let c1 = resolve(&mut store).unwrap();
    let mut bad = c1.manifest.clone();
    bad.previous = Some(c1.manifest_id);
    bad.sequence = 2;
    bad.incarnation = 7;
    let bytes = bad.encode().unwrap();
    commit(&mut store, &c1, Update::default(), true).unwrap();
    store
        .transact(&[ObjectInput {
            kind: KIND_MANIFEST,
            version: STORE_OBJECT_VERSION,
            bytes: &bytes,
        }])
        .unwrap();
    assert!(matches!(
        resolve(&mut store),
        Err(ContinuityError::Corrupt(_))
    ));

    // Gap: a manifest at sequence 5 with nothing between.
    let mut store = provisioned();
    let c1 = resolve(&mut store).unwrap();
    let mut gap = c1.manifest.clone();
    gap.previous = Some(c1.manifest_id);
    gap.sequence = 5;
    let bytes = gap.encode().unwrap();
    store
        .transact(&[ObjectInput {
            kind: KIND_MANIFEST,
            version: STORE_OBJECT_VERSION,
            bytes: &bytes,
        }])
        .unwrap();
    assert!(matches!(
        resolve(&mut store),
        Err(ContinuityError::Corrupt(_))
    ));
}

#[test]
fn degraded_mount_resumes_read_only() {
    let store = provisioned();
    let mut dev = store.into_device();
    // Plant a malformed peer superblock: the engine mounts DegradedRecovery.
    let active = Store::open(dev.clone()).unwrap().active_slot() as usize;
    dev.units[1 - active] = [0xa5; STORE_UNIT_BYTES];
    dev.units[1 - active][..8].copy_from_slice(b"AIENSTR1");
    let mut store = open(dev);
    assert_eq!(store.mount_state(), MountState::DegradedRecovery);
    let generation = store.generation();
    let (c, committed) = resume(&mut store).unwrap();
    assert!(!committed);
    assert_eq!(c.root.agent_id, AGENT);
    assert_eq!(store.generation(), generation, "nothing was committed");
    assert_eq!(
        commit(&mut store, &c, Update::default(), true).map(|_| ()),
        Err(ContinuityError::ReadOnly)
    );
}

#[test]
fn a_crash_at_every_write_of_a_commit_leaves_old_or_new_never_a_third_state() {
    let mut base = provisioned();
    let c1 = resolve(&mut base).unwrap();
    let before = base.into_device();

    let update = || Update {
        state: None,
        cortex: vec![fact("remember across the crash")],
    };
    // Count the unit writes one continuity commit performs.
    let mut counting = before.clone();
    counting.writes_left = Some(usize::MAX);
    let mut counted = open(counting);
    commit(&mut counted, &c1, update(), true).unwrap();
    let total = usize::MAX - counted.into_device().writes_left.unwrap();
    assert!(total >= 4, "payload, catalog, commit record and superblock");

    // Cut power before each write in turn (0..total) and after the last one.
    for allowed in 0..=total {
        let mut dev = before.clone();
        dev.writes_left = Some(allowed);
        let mut store = open(dev);
        let _ = commit(&mut store, &c1, update(), true);
        // Power returns: reopen the medium as written so far.
        let mut dev = store.into_device();
        dev.writes_left = None;
        let mut store = open(dev);
        let c = resolve(&mut store).unwrap();
        assert_eq!(
            c.root.agent_id, AGENT,
            "identity survives a crash at write {allowed}"
        );
        match c.manifest.sequence {
            1 => assert!(c.cortex.is_empty()),
            2 => assert_eq!(c.cortex, vec![fact("remember across the crash")]),
            s => panic!("third state: sequence {s} after crash at write {allowed}"),
        }
        if allowed == total {
            assert_eq!(c.manifest.sequence, 2, "all writes landed: the new state");
        }
    }
}

#[test]
fn encodings_round_trip_and_reject_tampering() {
    let root = AgentRoot {
        agent_id: AGENT,
        store_uuid: UUID,
        root_branch: root_branch_id(&AGENT),
        provisioned_generation: 2,
        source: ProvisionSource::Operator,
    };
    let bytes = root.encode();
    assert_eq!(AgentRoot::decode(&bytes).unwrap(), root);

    // Every single-byte flip is rejected or changes the decoded value.
    for i in 0..bytes.len() {
        let mut t = bytes.clone();
        t[i] ^= 0x01;
        if let Ok(decoded) = AgentRoot::decode(&t) {
            assert_ne!(decoded, root, "flip at byte {i} went unnoticed");
        }
    }
    // Truncation and trailing bytes are rejected.
    assert!(AgentRoot::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut long = bytes.clone();
    long.push(0);
    assert!(AgentRoot::decode(&long).is_err());
    // A root branch that does not derive from the agent is rejected.
    let mut wrong = root;
    wrong.root_branch = [0x99; 32];
    assert!(AgentRoot::decode(&wrong.encode()).is_err());

    let seg = WalSegment {
        sequence: 3,
        records: vec![fact("a"), fact("bb")],
    };
    assert_eq!(WalSegment::decode(&seg.encode().unwrap()).unwrap(), seg);

    let mut state = AgentState::genesis(AGENT, 1);
    let child = state.fork(&root_branch_id(&AGENT)).unwrap();
    state.fork(&child).unwrap();
    assert_eq!(AgentState::decode(&state.encode().unwrap()).unwrap(), state);
}

#[test]
fn branch_table_validation_rejects_broken_lineage() {
    let mut state = AgentState::genesis(AGENT, 1);
    let root = root_branch_id(&AGENT);
    let child = state.fork(&root).unwrap();
    assert!(state.validate().is_ok());

    let mut t = state.clone();
    t.branches.iter_mut().find(|b| b.id == child).unwrap().depth = 5;
    assert!(t.validate().is_err(), "wrong depth");

    let mut t = state.clone();
    t.branches.iter_mut().find(|b| b.id == root).unwrap().forks = 2;
    assert!(t.validate().is_err(), "missing fork index 1");

    let mut t = state.clone();
    t.branches.retain(|b| b.id != root);
    assert!(t.validate().is_err(), "no root");
}
