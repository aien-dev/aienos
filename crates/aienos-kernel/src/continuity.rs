//! M4 continuity objects over System Store v1 (ADR 0016, Proposed).
//!
//! AIEN is provisioned once (ADR 0007). Every later start must locate, verify
//! and resume the one durable `LogicalAgentId`, or stop. This module holds the
//! canonical encodings of the continuity objects and the deterministic boot
//! resolution over a mounted [`Store`]. No model, no network, `no_std`.
//!
//! The encodings carry `format_version = 0` while ADR 0016 is Proposed: they
//! are qualification formats on disposable media, not a frozen on-disk format.
//! Store v1 object `version` is 1 for all of them (Store v1 rejects 0).

use alloc::vec::Vec;

use crate::crypto::sha256::Sha256;
use crate::store::checkpoint::CheckpointHook;
use crate::store::engine::{MountState, ObjectInput, Store, StoreDevice, StoreError};
use crate::store::v1::ObjectId;

pub const KIND_AGENT_ROOT: u16 = 16;
pub const KIND_MANIFEST: u16 = 17;
pub const KIND_AGENT_STATE: u16 = 18;
pub const KIND_CORTEX_WAL: u16 = 20;
/// Store v1 object version used for every continuity object.
pub const STORE_OBJECT_VERSION: u16 = 1;
/// Continuity encoding version while ADR 0016 is Proposed.
pub const FORMAT_VERSION: u16 = 0;

pub const MAX_WAL_SEGMENTS: usize = 64;
pub const MAX_BRANCHES: usize = 256;
pub const MAX_WAL_RECORDS: usize = 64;
pub const MAX_STATEMENT_BYTES: usize = 1024;

const HEADER_BYTES: usize = 16;
const MAGIC_ROOT: &[u8; 8] = b"AIENROOT";
const MAGIC_MANIFEST: &[u8; 8] = b"AIENMANI";
const MAGIC_BRANCHES: &[u8; 8] = b"AIENBRAN";
const MAGIC_WAL: &[u8; 8] = b"AIENCWAL";
const ZERO_ID: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuityError {
    Store(StoreError),
    /// No agent root and provisioning was not requested: stop, never mint.
    Unprovisioned,
    /// More than one agent root: stop.
    Conflict,
    /// A root already exists; provisioning refused.
    AlreadyProvisioned,
    /// The mount is read-only (`DegradedRecovery`); nothing may be committed.
    ReadOnly,
    /// The continuity graph is inconsistent: stop in the Recovery Core.
    Corrupt(&'static str),
    /// An update exceeds a format bound.
    Limit(&'static str),
}

impl From<StoreError> for ContinuityError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

type Result<T> = core::result::Result<T, ContinuityError>;

// ---------------------------------------------------------------------------
// Identity derivations (shared with the host `aienos-agent-state` crate)
// ---------------------------------------------------------------------------

/// Root branch id of an agent: SHA-256("AIENOS_ROOT_BRANCH_v1:" || agent).
pub fn root_branch_id(agent: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"AIENOS_ROOT_BRANCH_v1:");
    h.update(agent);
    h.finalize()
}

/// Child branch id: SHA-256("AIENOS_CHILD_BRANCH_v1:" || parent || index BE).
pub fn child_branch_id(parent: &[u8; 32], index: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"AIENOS_CHILD_BRANCH_v1:");
    h.update(parent);
    h.update(&index.to_be_bytes());
    h.finalize()
}

// ---------------------------------------------------------------------------
// Canonical byte helpers
// ---------------------------------------------------------------------------

fn header(out: &mut Vec<u8>, magic: &[u8; 8], body_len: usize) {
    out.extend_from_slice(magic);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(body_len as u32).to_le_bytes());
}

/// Strict reader: every read is bounds-checked and the whole input must be
/// consumed.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn open(bytes: &'a [u8], magic: &[u8; 8]) -> Result<Self> {
        let mut r = Self { bytes, at: 0 };
        if r.take(8)? != magic {
            return Err(ContinuityError::Corrupt("bad magic"));
        }
        if r.u16()? != FORMAT_VERSION {
            return Err(ContinuityError::Corrupt(
                "unsupported continuity format version",
            ));
        }
        if r.u16()? != 0 {
            return Err(ContinuityError::Corrupt("nonzero header reserved"));
        }
        if r.u32()? as usize != bytes.len() - HEADER_BYTES {
            return Err(ContinuityError::Corrupt("body length mismatch"));
        }
        Ok(r)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ContinuityError::Corrupt("truncated object"))?;
        let s = &self.bytes[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn id(&mut self) -> Result<[u8; 32]> {
        let mut out = [0; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let mut a = [0; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
    fn zeros(&mut self, n: usize) -> Result<()> {
        if self.take(n)?.iter().any(|b| *b != 0) {
            return Err(ContinuityError::Corrupt("nonzero reserved"));
        }
        Ok(())
    }
    fn finish(self) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(ContinuityError::Corrupt("trailing bytes"));
        }
        Ok(())
    }
}

fn object_id(kind: u16, bytes: &[u8]) -> Result<ObjectId> {
    ObjectId::calculate(kind, STORE_OBJECT_VERSION, bytes)
        .map_err(|e| ContinuityError::Store(StoreError::Format(e)))
}

fn opt_id(id: [u8; 32]) -> Option<ObjectId> {
    (id != ZERO_ID).then_some(ObjectId(id))
}

fn raw(id: Option<ObjectId>) -> [u8; 32] {
    id.map_or(ZERO_ID, |i| i.0)
}

// ---------------------------------------------------------------------------
// AgentRoot (kind 16): written once, at provisioning
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionSource {
    /// An operator-authorised provisioning action (Recovery Core, ADR 0006).
    Operator = 1,
    /// A qualification harness on disposable media.
    Qualification = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentRoot {
    pub agent_id: [u8; 32],
    pub store_uuid: [u8; 16],
    pub root_branch: [u8; 32],
    pub provisioned_generation: u64,
    pub source: ProvisionSource,
}

const ROOT_BODY: usize = 32 + 16 + 32 + 8 + 1 + 7;

impl AgentRoot {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_BYTES + ROOT_BODY);
        header(&mut out, MAGIC_ROOT, ROOT_BODY);
        out.extend_from_slice(&self.agent_id);
        out.extend_from_slice(&self.store_uuid);
        out.extend_from_slice(&self.root_branch);
        out.extend_from_slice(&self.provisioned_generation.to_le_bytes());
        out.push(self.source as u8);
        out.extend_from_slice(&[0; 7]);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::open(bytes, MAGIC_ROOT)?;
        let agent_id = r.id()?;
        let mut store_uuid = [0; 16];
        store_uuid.copy_from_slice(r.take(16)?);
        let root_branch = r.id()?;
        let provisioned_generation = r.u64()?;
        let source = match r.u8()? {
            1 => ProvisionSource::Operator,
            2 => ProvisionSource::Qualification,
            _ => return Err(ContinuityError::Corrupt("unknown provisioning source")),
        };
        r.zeros(7)?;
        r.finish()?;
        if agent_id == ZERO_ID {
            return Err(ContinuityError::Corrupt("zero agent id"));
        }
        if root_branch != root_branch_id(&agent_id) {
            return Err(ContinuityError::Corrupt(
                "root branch does not derive from agent",
            ));
        }
        Ok(Self {
            agent_id,
            store_uuid,
            root_branch,
            provisioned_generation,
            source,
        })
    }
}

// ---------------------------------------------------------------------------
// ContinuityManifest (kind 17): one per Class A commit
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub root: ObjectId,
    pub previous: Option<ObjectId>,
    pub sequence: u64,
    pub incarnation: u64,
    pub agent_state: Option<ObjectId>,
    pub cortex_wal: Vec<ObjectId>,
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.cortex_wal.len() > MAX_WAL_SEGMENTS {
            return Err(ContinuityError::Limit("too many cortex WAL segments"));
        }
        let body = 32 + 32 + 8 + 8 + 32 + 2 + 6 + 32 * self.cortex_wal.len();
        let mut out = Vec::with_capacity(HEADER_BYTES + body);
        header(&mut out, MAGIC_MANIFEST, body);
        out.extend_from_slice(&self.root.0);
        out.extend_from_slice(&raw(self.previous));
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.incarnation.to_le_bytes());
        out.extend_from_slice(&raw(self.agent_state));
        out.extend_from_slice(&(self.cortex_wal.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 6]);
        for id in &self.cortex_wal {
            out.extend_from_slice(&id.0);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::open(bytes, MAGIC_MANIFEST)?;
        let root = ObjectId(r.id()?);
        let previous = opt_id(r.id()?);
        let sequence = r.u64()?;
        let incarnation = r.u64()?;
        let agent_state = opt_id(r.id()?);
        let wal_count = r.u16()? as usize;
        r.zeros(6)?;
        if wal_count > MAX_WAL_SEGMENTS {
            return Err(ContinuityError::Corrupt("too many cortex WAL segments"));
        }
        let mut cortex_wal = Vec::with_capacity(wal_count);
        for _ in 0..wal_count {
            cortex_wal.push(ObjectId(r.id()?));
        }
        r.finish()?;
        if sequence == 0 || (sequence == 1) != previous.is_none() {
            return Err(ContinuityError::Corrupt(
                "manifest sequence/previous mismatch",
            ));
        }
        Ok(Self {
            root,
            previous,
            sequence,
            incarnation,
            agent_state,
            cortex_wal,
        })
    }
}

// ---------------------------------------------------------------------------
// AgentStateCheckpoint (kind 18): the branch table
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Branch {
    pub id: [u8; 32],
    /// `None` only for the root branch.
    pub parent: Option<[u8; 32]>,
    pub depth: u32,
    /// Number of children forked from this branch so far.
    pub forks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentState {
    pub agent_id: [u8; 32],
    /// Manifest sequence this checkpoint was written at (keeps ids unique).
    pub written_at: u64,
    /// Sorted by branch id.
    pub branches: Vec<Branch>,
}

const BRANCH_BYTES: usize = 32 + 32 + 4 + 4 + 8;

impl AgentState {
    /// A fresh agent: only the root branch.
    pub fn genesis(agent_id: [u8; 32], written_at: u64) -> Self {
        Self {
            agent_id,
            written_at,
            branches: alloc::vec![Branch {
                id: root_branch_id(&agent_id),
                parent: None,
                depth: 0,
                forks: 0,
            }],
        }
    }

    pub fn branch(&self, id: &[u8; 32]) -> Option<&Branch> {
        self.branches
            .binary_search_by(|b| b.id.cmp(id))
            .ok()
            .map(|i| &self.branches[i])
    }

    /// Forks a child of `parent` with the next deterministic index.
    pub fn fork(&mut self, parent: &[u8; 32]) -> Result<[u8; 32]> {
        if self.branches.len() >= MAX_BRANCHES {
            return Err(ContinuityError::Limit("too many branches"));
        }
        let i = self
            .branches
            .binary_search_by(|b| b.id.cmp(parent))
            .map_err(|_| ContinuityError::Corrupt("fork parent is absent"))?;
        let (index, depth) = (self.branches[i].forks, self.branches[i].depth);
        let child = Branch {
            id: child_branch_id(parent, index),
            parent: Some(*parent),
            depth: depth
                .checked_add(1)
                .ok_or(ContinuityError::Limit("branch depth"))?,
            forks: 0,
        };
        self.branches[i].forks = index + 1;
        let at = self
            .branches
            .binary_search_by(|b| b.id.cmp(&child.id))
            .err()
            .ok_or(ContinuityError::Corrupt("child branch id collision"))?;
        self.branches.insert(at, child);
        Ok(child.id)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let body = 32 + 8 + 4 + 4 + BRANCH_BYTES * self.branches.len();
        let mut out = Vec::with_capacity(HEADER_BYTES + body);
        header(&mut out, MAGIC_BRANCHES, body);
        out.extend_from_slice(&self.agent_id);
        out.extend_from_slice(&self.written_at.to_le_bytes());
        out.extend_from_slice(&(self.branches.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        for b in &self.branches {
            out.extend_from_slice(&b.id);
            out.extend_from_slice(&b.parent.unwrap_or(ZERO_ID));
            out.extend_from_slice(&b.depth.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&b.forks.to_le_bytes());
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::open(bytes, MAGIC_BRANCHES)?;
        let agent_id = r.id()?;
        let written_at = r.u64()?;
        let count = r.u32()? as usize;
        r.zeros(4)?;
        if count == 0 || count > MAX_BRANCHES {
            return Err(ContinuityError::Corrupt("branch count out of range"));
        }
        let mut branches = Vec::with_capacity(count);
        for _ in 0..count {
            let id = r.id()?;
            let parent = r.id()?;
            let depth = r.u32()?;
            r.zeros(4)?;
            let forks = r.u64()?;
            branches.push(Branch {
                id,
                parent: (parent != ZERO_ID).then_some(parent),
                depth,
                forks,
            });
        }
        r.finish()?;
        let state = Self {
            agent_id,
            written_at,
            branches,
        };
        state.validate()?;
        Ok(state)
    }

    /// Exactly one root derived from the agent; every child derives from its
    /// parent with depth + 1; each parent's children are exactly indexes
    /// `0..forks`; ids strictly sorted.
    pub fn validate(&self) -> Result<()> {
        let bad = ContinuityError::Corrupt;
        if self.branches.is_empty() || self.branches.len() > MAX_BRANCHES {
            return Err(bad("branch count out of range"));
        }
        if self.branches.windows(2).any(|w| w[0].id >= w[1].id) {
            return Err(bad("branches not strictly sorted"));
        }
        let root = root_branch_id(&self.agent_id);
        let mut roots = 0;
        let mut children = 0u64;
        for b in &self.branches {
            match b.parent {
                None => {
                    if b.id != root || b.depth != 0 {
                        return Err(bad("unexpected root branch"));
                    }
                    roots += 1;
                }
                Some(p) => {
                    let parent = self.branch(&p).ok_or(bad("parent branch is absent"))?;
                    let index_ok = (0..parent.forks).any(|i| child_branch_id(&p, i) == b.id);
                    if !index_ok || Some(b.depth) != parent.depth.checked_add(1) {
                        return Err(bad("branch lineage is inconsistent"));
                    }
                    children += 1;
                }
            }
        }
        let forks: u64 = self.branches.iter().map(|b| b.forks).sum();
        if roots != 1 || forks != children {
            return Err(bad("fork indexes are not contiguous"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CortexWalSegment (kind 20): committed Cortex records
// ---------------------------------------------------------------------------

/// Mirrors `aienos-cortex` `EpistemicStatus` discriminants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Epistemic {
    DirectObservation = 1,
    VerifiedFact = 2,
    Inference = 3,
    Hypothesis = 4,
    Contradiction = 5,
    OperatorDecision = 6,
}

impl Epistemic {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::DirectObservation,
            2 => Self::VerifiedFact,
            3 => Self::Inference,
            4 => Self::Hypothesis,
            5 => Self::Contradiction,
            6 => Self::OperatorDecision,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CortexRecord {
    pub status: Epistemic,
    pub evidence_hash: [u8; 32],
    pub statement: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalSegment {
    /// Manifest sequence this segment was committed in.
    pub sequence: u64,
    pub records: Vec<CortexRecord>,
}

impl WalSegment {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.records.is_empty() || self.records.len() > MAX_WAL_RECORDS {
            return Err(ContinuityError::Limit("WAL segment record count"));
        }
        let mut body = 8 + 4 + 4;
        for rec in &self.records {
            if rec.statement.is_empty() || rec.statement.len() > MAX_STATEMENT_BYTES {
                return Err(ContinuityError::Limit("statement length"));
            }
            body += 4 + 32 + rec.statement.len();
        }
        let mut out = Vec::with_capacity(HEADER_BYTES + body);
        header(&mut out, MAGIC_WAL, body);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        for rec in &self.records {
            out.push(rec.status as u8);
            out.push(0);
            out.extend_from_slice(&(rec.statement.len() as u16).to_le_bytes());
            out.extend_from_slice(&rec.evidence_hash);
            out.extend_from_slice(&rec.statement);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::open(bytes, MAGIC_WAL)?;
        let sequence = r.u64()?;
        let count = r.u32()? as usize;
        r.zeros(4)?;
        if count == 0 || count > MAX_WAL_RECORDS {
            return Err(ContinuityError::Corrupt("WAL segment record count"));
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let status = Epistemic::from_u8(r.u8()?)
                .ok_or(ContinuityError::Corrupt("unknown epistemic status"))?;
            r.zeros(1)?;
            let len = r.u16()? as usize;
            if len == 0 || len > MAX_STATEMENT_BYTES {
                return Err(ContinuityError::Corrupt("statement length"));
            }
            let evidence_hash = r.id()?;
            let statement = r.take(len)?.to_vec();
            records.push(CortexRecord {
                status,
                evidence_hash,
                statement,
            });
        }
        r.finish()?;
        Ok(Self { sequence, records })
    }
}

// ---------------------------------------------------------------------------
// Boot resolution
// ---------------------------------------------------------------------------

/// The verified continuity view of one Store generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Continuity {
    pub root_id: ObjectId,
    pub root: AgentRoot,
    pub manifest_id: ObjectId,
    pub manifest: Manifest,
    pub state: AgentState,
    /// Every committed Cortex record, in commit order.
    pub cortex: Vec<CortexRecord>,
}

/// Class A changes to commit with the next manifest.
#[derive(Clone, Debug, Default)]
pub struct Update {
    /// Replace the branch table (e.g. after a fork).
    pub state: Option<AgentState>,
    /// Append these Cortex records as one WAL segment.
    pub cortex: Vec<CortexRecord>,
}

fn ids_of_kind(store: &Store<impl StoreDevice>, kind: u16) -> Vec<ObjectId> {
    store
        .catalog()
        .entries
        .iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.object_id)
        .collect()
}

fn read_kind<D: StoreDevice>(store: &mut Store<D>, id: ObjectId, kind: u16) -> Result<Vec<u8>> {
    let entry = store
        .catalog()
        .entries
        .iter()
        .find(|e| e.object_id == id)
        .copied()
        .ok_or(ContinuityError::Corrupt("referenced object is absent"))?;
    if entry.kind != kind || entry.version != STORE_OBJECT_VERSION {
        return Err(ContinuityError::Corrupt(
            "referenced object has the wrong kind",
        ));
    }
    Ok(store.read_object(id)?)
}

/// Locates and verifies the continuity view without writing anything.
/// Never creates an identity.
pub fn resolve<D: StoreDevice>(store: &mut Store<D>) -> Result<Continuity> {
    let roots = ids_of_kind(store, KIND_AGENT_ROOT);
    let root_id = match roots.as_slice() {
        // Continuity objects without their root mean the identity was lost,
        // not that the store was never provisioned: fail toward preservation.
        [] if [KIND_MANIFEST, KIND_AGENT_STATE, KIND_CORTEX_WAL]
            .iter()
            .any(|kind| !ids_of_kind(store, *kind).is_empty()) =>
        {
            return Err(ContinuityError::Corrupt(
                "continuity objects without an agent root",
            ))
        }
        [] => return Err(ContinuityError::Unprovisioned),
        [one] => *one,
        _ => return Err(ContinuityError::Conflict),
    };
    let root = AgentRoot::decode(&read_kind(store, root_id, KIND_AGENT_ROOT)?)?;

    // Every manifest must belong to one unbroken chain 1..=n for this root.
    let mut manifests = Vec::new();
    for id in ids_of_kind(store, KIND_MANIFEST) {
        let m = Manifest::decode(&read_kind(store, id, KIND_MANIFEST)?)?;
        if m.root != root_id {
            return Err(ContinuityError::Corrupt("manifest names a foreign root"));
        }
        manifests.push((id, m));
    }
    if manifests.is_empty() {
        return Err(ContinuityError::Corrupt("agent root has no manifest"));
    }
    manifests.sort_by_key(|(_, m)| m.sequence);
    for (i, (id, m)) in manifests.iter().enumerate() {
        if m.sequence != i as u64 + 1 {
            return Err(ContinuityError::Corrupt("manifest sequence gap or fork"));
        }
        let expected_previous = i.checked_sub(1).map(|p| manifests[p].0);
        if m.previous != expected_previous {
            return Err(ContinuityError::Corrupt("manifest chain is broken"));
        }
        let _ = id;
    }
    let (manifest_id, manifest) = manifests.pop().expect("non-empty");

    let state_id = manifest
        .agent_state
        .ok_or(ContinuityError::Corrupt("manifest has no agent state"))?;
    let state = AgentState::decode(&read_kind(store, state_id, KIND_AGENT_STATE)?)?;
    if state.agent_id != root.agent_id {
        return Err(ContinuityError::Corrupt(
            "agent state belongs to another agent",
        ));
    }

    let mut cortex = Vec::new();
    let mut last_sequence = 0;
    for id in &manifest.cortex_wal {
        let seg = WalSegment::decode(&read_kind(store, *id, KIND_CORTEX_WAL)?)?;
        if seg.sequence <= last_sequence || seg.sequence > manifest.sequence {
            return Err(ContinuityError::Corrupt("WAL segments out of order"));
        }
        last_sequence = seg.sequence;
        cortex.extend(seg.records);
    }

    Ok(Continuity {
        root_id,
        root,
        manifest_id,
        manifest,
        state,
        cortex,
    })
}

fn writable<D: StoreDevice>(store: &Store<D>) -> Result<()> {
    if store.mount_state() != MountState::Valid {
        return Err(ContinuityError::ReadOnly);
    }
    Ok(())
}

/// Creates the one durable identity. Only reachable from an explicit,
/// authorised provisioning request; refuses if any root exists.
pub fn provision<D: StoreDevice>(
    store: &mut Store<D>,
    agent_id: [u8; 32],
    store_uuid: [u8; 16],
    source: ProvisionSource,
) -> Result<Continuity> {
    writable(store)?;
    if !ids_of_kind(store, KIND_AGENT_ROOT).is_empty() {
        return Err(ContinuityError::AlreadyProvisioned);
    }
    if agent_id == ZERO_ID {
        return Err(ContinuityError::Corrupt("zero agent id"));
    }
    let root = AgentRoot {
        agent_id,
        store_uuid,
        root_branch: root_branch_id(&agent_id),
        provisioned_generation: store.generation() + 1,
        source,
    };
    let root_bytes = root.encode();
    let root_id = object_id(KIND_AGENT_ROOT, &root_bytes)?;
    let state_bytes = AgentState::genesis(agent_id, 1).encode()?;
    let state_id = object_id(KIND_AGENT_STATE, &state_bytes)?;
    let manifest = Manifest {
        root: root_id,
        previous: None,
        sequence: 1,
        incarnation: 1,
        agent_state: Some(state_id),
        cortex_wal: Vec::new(),
    };
    let manifest_bytes = manifest.encode()?;
    store.transact(&[
        ObjectInput {
            kind: KIND_AGENT_ROOT,
            version: STORE_OBJECT_VERSION,
            bytes: &root_bytes,
        },
        ObjectInput {
            kind: KIND_AGENT_STATE,
            version: STORE_OBJECT_VERSION,
            bytes: &state_bytes,
        },
        ObjectInput {
            kind: KIND_MANIFEST,
            version: STORE_OBJECT_VERSION,
            bytes: &manifest_bytes,
        },
    ])?;
    resolve(store)
}

/// Commits `update` and a new manifest in one Store transaction. With
/// `new_incarnation` the incarnation advances (a resume); otherwise it is kept.
pub fn commit<D: StoreDevice>(
    store: &mut Store<D>,
    current: &Continuity,
    update: Update,
    new_incarnation: bool,
) -> Result<Continuity> {
    commit_with_hook(store, current, update, new_incarnation, |_| {})
}

/// [`commit`] with a Store checkpoint hook (qualification crash campaigns).
pub fn commit_with_hook<D: StoreDevice, H: CheckpointHook>(
    store: &mut Store<D>,
    current: &Continuity,
    update: Update,
    new_incarnation: bool,
    hook: H,
) -> Result<Continuity> {
    writable(store)?;
    let sequence = current
        .manifest
        .sequence
        .checked_add(1)
        .ok_or(ContinuityError::Limit("manifest sequence"))?;
    let mut objects: Vec<(u16, Vec<u8>)> = Vec::new();

    let mut agent_state = current.manifest.agent_state;
    if let Some(mut state) = update.state {
        if state.agent_id != current.root.agent_id {
            return Err(ContinuityError::Corrupt(
                "agent state belongs to another agent",
            ));
        }
        state.written_at = sequence;
        let bytes = state.encode()?;
        agent_state = Some(object_id(KIND_AGENT_STATE, &bytes)?);
        objects.push((KIND_AGENT_STATE, bytes));
    }

    let mut cortex_wal = current.manifest.cortex_wal.clone();
    if !update.cortex.is_empty() {
        if cortex_wal.len() >= MAX_WAL_SEGMENTS {
            return Err(ContinuityError::Limit("cortex WAL needs compaction"));
        }
        let bytes = WalSegment {
            sequence,
            records: update.cortex,
        }
        .encode()?;
        cortex_wal.push(object_id(KIND_CORTEX_WAL, &bytes)?);
        objects.push((KIND_CORTEX_WAL, bytes));
    }

    let incarnation = if new_incarnation {
        current
            .manifest
            .incarnation
            .checked_add(1)
            .ok_or(ContinuityError::Limit("incarnation"))?
    } else {
        current.manifest.incarnation
    };
    let manifest = Manifest {
        root: current.root_id,
        previous: Some(current.manifest_id),
        sequence,
        incarnation,
        agent_state,
        cortex_wal,
    };
    objects.push((KIND_MANIFEST, manifest.encode()?));

    let inputs: Vec<ObjectInput<'_>> = objects
        .iter()
        .map(|(kind, bytes)| ObjectInput {
            kind: *kind,
            version: STORE_OBJECT_VERSION,
            bytes,
        })
        .collect();
    store.transact_with_hook(&inputs, hook)?;
    resolve(store)
}

/// A normal boot: resolve the existing identity and durably advance the
/// incarnation before anything acts on it (commit-before-observation).
/// On a read-only mount the verified view is returned without committing.
pub fn resume<D: StoreDevice>(store: &mut Store<D>) -> Result<(Continuity, bool)> {
    let current = resolve(store)?;
    if store.mount_state() != MountState::Valid {
        return Ok((current, false));
    }
    Ok((commit(store, &current, Update::default(), true)?, true))
}

#[cfg(test)]
#[path = "continuity_tests.rs"]
mod tests;
