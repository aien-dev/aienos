//! Mount and transaction semantics for the canonical System Store v1 format.
//!
//! This layer only sees bounded 4096-byte Store units. Device geometry,
//! provisioning, partitioning, and controller protocols belong below it.

use alloc::vec;
use alloc::vec::Vec;

pub use super::checkpoint::Checkpoint;
use super::checkpoint::CheckpointHook;
use super::v1::{
    object_unit_count, Catalog, CatalogEntry, CommitRecord, FormatError, ObjectId, Superblock,
    MAX_CATALOG_ENTRIES, MAX_REGION_UNITS, MAX_TRANSACTION_OBJECTS, MAX_TRANSACTION_UNITS,
    OBJECT_KIND_CATALOG, OBJECT_KIND_COMMIT_RECORD, OBJECT_VERSION_V1, STORE_UNIT_BYTES,
};

/// Narrow bounded Store-unit I/O consumed by the Store engine.
pub trait StoreDevice {
    type Error;

    fn region_units(&self) -> u64;
    fn read_unit(&mut self, unit: u64, out: &mut [u8; STORE_UNIT_BYTES])
        -> Result<(), Self::Error>;
    fn write_unit(&mut self, unit: u64, bytes: &[u8; STORE_UNIT_BYTES]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountState {
    Valid,
    DegradedRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountError {
    Io,
    Unformatted,
    ForeignOrUnknown,
    UnsupportedVersion,
    CorruptRecoveryRequired,
    ConflictingRoots,
    InconsistentHistory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    Io,
    Corrupt,
    ReadOnlyDegraded,
    DuplicateObjectConflict,
    NoSpace,
    CatalogFull,
    GenerationExhausted,
    TransactionLimit,
    InvalidObject,
    NeedsReopen,
    Format(FormatError),
}

#[derive(Clone, Copy, Debug)]
pub struct ObjectInput<'a> {
    pub kind: u16,
    pub version: u16,
    pub bytes: &'a [u8],
}

#[derive(Clone, Debug)]
struct ValidatedRoot {
    superblock: Superblock,
    commit: CommitRecord,
    commit_id: ObjectId,
    catalog: Catalog,
}

#[derive(Debug)]
pub struct Store<D> {
    device: D,
    root: ValidatedRoot,
    state: MountState,
    poisoned: bool,
}

impl<D: StoreDevice> Store<D> {
    /// Reads and validates both roots and their complete object graphs.
    /// No write or flush is issued by this method.
    pub fn open(mut device: D) -> Result<Self, MountError> {
        let units = device.region_units();
        if !(4..=MAX_REGION_UNITS).contains(&units) {
            return Err(MountError::CorruptRecoveryRequired);
        }
        let mut raw = [[0u8; STORE_UNIT_BYTES]; 2];
        device
            .read_unit(0, &mut raw[0])
            .map_err(|_| MountError::Io)?;
        device
            .read_unit(1, &mut raw[1])
            .map_err(|_| MountError::Io)?;
        let zero = [
            raw[0].iter().all(|b| *b == 0),
            raw[1].iter().all(|b| *b == 0),
        ];
        if zero == [true, true] {
            return Err(MountError::Unformatted);
        }
        let magic = [has_superblock_magic(&raw[0]), has_superblock_magic(&raw[1])];
        if !magic[0] && !magic[1] {
            return Err(MountError::ForeignOrUnknown);
        }
        // The CRC is checked before version/features are inspected. A supported
        // peer never hides a CRC-valid but unsupported root.
        if (0..2).any(|i| crc_valid(&raw[i]) && unsupported_superblock(&raw[i])) {
            return Err(MountError::UnsupportedVersion);
        }

        let mut roots: [Option<ValidatedRoot>; 2] = [None, None];
        let mut graph_bad = [false; 2];
        let mut malformed = [false; 2];
        let mut crc_supported = [false; 2];
        for slot in 0..2 {
            if zero[slot] {
                continue;
            }
            if !magic[slot] || !crc_valid(&raw[slot]) || unsupported_superblock(&raw[slot]) {
                malformed[slot] = true;
                continue;
            }
            crc_supported[slot] = true;
            let sb = match Superblock::decode(&raw[slot], slot as u32) {
                Ok(sb) if sb.region_units == units => sb,
                _ => {
                    malformed[slot] = true;
                    continue;
                }
            };
            match validate_root(&mut device, sb) {
                Ok(root) => roots[slot] = Some(root),
                Err(RootError::Io(_)) => return Err(MountError::Io),
                Err(RootError::Graph) => graph_bad[slot] = true,
            }
        }

        match (roots[0].take(), roots[1].take()) {
            (Some(a), Some(b)) => {
                let chosen = select_two(a, b)?;
                Ok(Self {
                    device,
                    root: chosen,
                    state: MountState::Valid,
                    poisoned: false,
                })
            }
            (Some(root), None) | (None, Some(root)) => {
                let good_slot = if root.superblock.slot_id == 0 { 0 } else { 1 };
                let other = 1 - good_slot;
                if zero[other] {
                    Ok(Self {
                        device,
                        root,
                        state: MountState::Valid,
                        poisoned: false,
                    })
                } else if malformed[other] {
                    Err(
                        if unsupported_superblock(&raw[other]) && crc_valid(&raw[other]) {
                            MountError::UnsupportedVersion
                        } else {
                            MountError::CorruptRecoveryRequired
                        },
                    )
                } else if graph_bad[other] && crc_supported[other] {
                    if generation_of(&raw[other]) > root.superblock.generation {
                        Ok(Self {
                            device,
                            root,
                            state: MountState::DegradedRecovery,
                            poisoned: false,
                        })
                    } else if generation_of(&raw[other]) < root.superblock.generation {
                        Ok(Self {
                            device,
                            root,
                            state: MountState::Valid,
                            poisoned: false,
                        })
                    } else {
                        Err(MountError::CorruptRecoveryRequired)
                    }
                } else {
                    Err(MountError::CorruptRecoveryRequired)
                }
            }
            (None, None) => Err(MountError::CorruptRecoveryRequired),
        }
    }

    pub fn mount_state(&self) -> MountState {
        self.state
    }
    pub fn generation(&self) -> u64 {
        self.root.commit.generation
    }
    pub fn committed_high_water(&self) -> u64 {
        self.root.commit.committed_high_water
    }
    pub fn active_slot(&self) -> u32 {
        self.root.superblock.slot_id
    }
    pub fn catalog(&self) -> &Catalog {
        &self.root.catalog
    }
    pub fn into_device(self) -> D {
        self.device
    }

    /// Reads one catalog object and independently verifies its descriptor,
    /// semantic bytes, and physical zero padding.
    pub fn read_object(&mut self, id: ObjectId) -> Result<Vec<u8>, StoreError> {
        let entry = self
            .root
            .catalog
            .entries
            .binary_search_by_key(&id, |e| e.object_id)
            .ok()
            .map(|i| self.root.catalog.entries[i])
            .ok_or(StoreError::InvalidObject)?;
        read_application_object(&mut self.device, entry).map_err(map_root_error)
    }

    pub fn transact(&mut self, objects: &[ObjectInput<'_>]) -> Result<(), StoreError> {
        self.transact_with_hook(objects, |_| {})
    }

    /// The hook observes logical crash boundaries and does not alter bytes or
    /// ordering. Production callers should use `transact`.
    pub fn transact_with_hook<F: CheckpointHook>(
        &mut self,
        objects: &[ObjectInput<'_>],
        mut hook: F,
    ) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::NeedsReopen);
        }
        if self.state == MountState::DegradedRecovery {
            return Err(StoreError::ReadOnlyDegraded);
        }
        let plan = self.preflight(objects)?;
        hook.on_checkpoint(Checkpoint::BeforeFirstWrite);
        for (entry, bytes) in &plan.append {
            if let Err(error) =
                write_object(&mut self.device, entry.first_unit, entry.unit_count, bytes)
            {
                self.poisoned = true;
                return Err(error);
            }
        }
        hook.on_checkpoint(Checkpoint::AfterPayloadObjects);
        if let Err(error) = write_object(
            &mut self.device,
            plan.catalog_first,
            plan.catalog_units,
            &plan.catalog_bytes,
        ) {
            self.poisoned = true;
            return Err(error);
        }
        hook.on_checkpoint(Checkpoint::AfterCatalog);
        if let Err(error) = write_one(&mut self.device, plan.commit_unit, &plan.commit_unit_bytes) {
            self.poisoned = true;
            return Err(error);
        }
        hook.on_checkpoint(Checkpoint::AfterCommitRecord);
        self.device.flush().map_err(|_| {
            self.poisoned = true;
            StoreError::Io
        })?;
        hook.on_checkpoint(Checkpoint::AfterFirstFlush);
        if let Err(error) = write_one(
            &mut self.device,
            u64::from(plan.superblock.slot_id),
            &plan.superblock_bytes,
        ) {
            self.poisoned = true;
            return Err(error);
        }
        hook.on_checkpoint(Checkpoint::AfterInactiveSuperblock);
        self.device.flush().map_err(|_| {
            self.poisoned = true;
            StoreError::Io
        })?;
        hook.on_checkpoint(Checkpoint::AfterFinalFlush);
        self.root = plan.root;
        Ok(())
    }

    fn preflight(&mut self, objects: &[ObjectInput<'_>]) -> Result<CommitPlan, StoreError> {
        if objects.len() > MAX_TRANSACTION_OBJECTS {
            return Err(StoreError::TransactionLimit);
        }
        let mut requested: Vec<(ObjectId, u16, u16, Vec<u8>, u32)> = Vec::new();
        let mut app_units = 0u64;
        for object in objects {
            let id = ObjectId::calculate(object.kind, object.version, object.bytes)
                .map_err(StoreError::Format)?;
            let units = object_unit_count(object.bytes.len() as u64).map_err(StoreError::Format)?;
            if let Some(existing) = requested.iter().find(|v| v.0 == id) {
                if existing.1 != object.kind
                    || existing.2 != object.version
                    || existing.3.as_slice() != object.bytes
                {
                    return Err(StoreError::DuplicateObjectConflict);
                }
                continue;
            }
            requested.push((
                id,
                object.kind,
                object.version,
                object.bytes.to_vec(),
                units,
            ));
        }

        let mut entries = self.root.catalog.entries.clone();
        let mut append = Vec::new();
        let mut next = self.root.commit.committed_high_water;
        for (id, kind, version, bytes, units) in requested {
            if let Ok(index) = entries.binary_search_by_key(&id, |e| e.object_id) {
                let old = entries[index];
                if old.kind != kind
                    || old.version != version
                    || old.byte_length != bytes.len() as u64
                    || old.unit_count != units
                {
                    return Err(StoreError::DuplicateObjectConflict);
                }
                let verified =
                    read_application_object(&mut self.device, old).map_err(map_root_error)?;
                if verified != bytes {
                    return Err(StoreError::DuplicateObjectConflict);
                }
                continue;
            }
            app_units = app_units
                .checked_add(u64::from(units))
                .ok_or(StoreError::NoSpace)?;
            let entry = CatalogEntry {
                object_id: id,
                kind,
                version,
                first_unit: next,
                byte_length: bytes.len() as u64,
                unit_count: units,
                flags: 0,
            };
            next = next
                .checked_add(u64::from(units))
                .ok_or(StoreError::NoSpace)?;
            entries.push(entry);
            append.push((entry, bytes));
        }
        entries.sort_by_key(|e| e.object_id);
        if entries.len() > MAX_CATALOG_ENTRIES {
            return Err(StoreError::CatalogFull);
        }
        // MAX_TRANSACTION_UNITS bounds appended application payload units.
        if app_units > MAX_TRANSACTION_UNITS {
            return Err(StoreError::TransactionLimit);
        }
        let catalog = Catalog { entries };
        let catalog_bytes = catalog.encode().map_err(StoreError::Format)?;
        let catalog_units =
            object_unit_count(catalog_bytes.len() as u64).map_err(StoreError::Format)?;
        let catalog_first = next;
        let commit_unit = catalog_first
            .checked_add(u64::from(catalog_units))
            .ok_or(StoreError::NoSpace)?;
        let high_water = commit_unit.checked_add(1).ok_or(StoreError::NoSpace)?;
        if high_water > self.device.region_units() || high_water > MAX_REGION_UNITS {
            return Err(StoreError::NoSpace);
        }
        let generation = self
            .root
            .commit
            .generation
            .checked_add(1)
            .ok_or(StoreError::GenerationExhausted)?;
        let catalog_id =
            ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &catalog_bytes)
                .map_err(StoreError::Format)?;
        let commit = CommitRecord {
            store_uuid: self.root.commit.store_uuid,
            region_units: self.root.commit.region_units,
            generation,
            previous_generation: self.root.commit.generation,
            previous_commit_id: self.root.commit_id,
            previous_catalog_id: self.root.commit.catalog_id,
            catalog_id,
            catalog_first_unit: catalog_first,
            catalog_byte_length: catalog_bytes.len() as u64,
            catalog_unit_count: catalog_units,
            catalog_entry_count: catalog.entries.len() as u32,
            committed_high_water: high_water,
        };
        let commit_bytes = commit.encode().map_err(StoreError::Format)?;
        let commit_id = commit.object_id().map_err(StoreError::Format)?;
        let mut commit_unit_bytes = [0; STORE_UNIT_BYTES];
        commit_unit_bytes[..commit_bytes.len()].copy_from_slice(&commit_bytes);
        let slot = 1 - self.root.superblock.slot_id;
        let superblock = Superblock {
            store_uuid: commit.store_uuid,
            slot_id: slot,
            region_units: commit.region_units,
            generation,
            commit_record_id: commit_id,
            commit_record_unit: commit_unit,
            catalog_id,
            catalog_first_unit: catalog_first,
            catalog_byte_length: commit.catalog_byte_length,
            catalog_unit_count: catalog_units,
            catalog_entry_count: commit.catalog_entry_count,
            committed_high_water: high_water,
        };
        let superblock_bytes = superblock.encode().map_err(StoreError::Format)?;
        let root = ValidatedRoot {
            superblock: superblock.clone(),
            commit,
            commit_id,
            catalog,
        };
        Ok(CommitPlan {
            append,
            catalog_first,
            catalog_units,
            catalog_bytes,
            commit_unit,
            commit_unit_bytes,
            superblock,
            superblock_bytes,
            root,
        })
    }
}

#[derive(Debug)]
struct CommitPlan {
    append: Vec<(CatalogEntry, Vec<u8>)>,
    catalog_first: u64,
    catalog_units: u32,
    catalog_bytes: Vec<u8>,
    commit_unit: u64,
    commit_unit_bytes: [u8; STORE_UNIT_BYTES],
    superblock: Superblock,
    superblock_bytes: [u8; STORE_UNIT_BYTES],
    root: ValidatedRoot,
}

enum RootError<E> {
    Io(E),
    Graph,
}

fn validate_root<D: StoreDevice>(
    device: &mut D,
    sb: Superblock,
) -> Result<ValidatedRoot, RootError<D::Error>> {
    if sb.region_units != device.region_units() {
        return Err(RootError::Graph);
    }
    let mut commit_unit = [0; STORE_UNIT_BYTES];
    device
        .read_unit(sb.commit_record_unit, &mut commit_unit)
        .map_err(RootError::Io)?;
    let commit_bytes = &commit_unit[..super::v1::COMMIT_RECORD_BYTES];
    if commit_unit[super::v1::COMMIT_RECORD_BYTES..]
        .iter()
        .any(|b| *b != 0)
    {
        return Err(RootError::Graph);
    }
    let commit_id = ObjectId::calculate(OBJECT_KIND_COMMIT_RECORD, OBJECT_VERSION_V1, commit_bytes)
        .map_err(|_| RootError::Graph)?;
    if commit_id != sb.commit_record_id {
        return Err(RootError::Graph);
    }
    let commit = CommitRecord::decode(commit_bytes).map_err(|_| RootError::Graph)?;
    sb.validate_commit(commit_id, &commit)
        .map_err(|_| RootError::Graph)?;
    let catalog_len = usize::try_from(commit.catalog_byte_length).map_err(|_| RootError::Graph)?;
    let catalog_total =
        usize::try_from(u64::from(commit.catalog_unit_count) * STORE_UNIT_BYTES as u64)
            .map_err(|_| RootError::Graph)?;
    let mut catalog_extent = vec![0; catalog_total];
    for i in 0..commit.catalog_unit_count {
        let start = i as usize * STORE_UNIT_BYTES;
        let slice: &mut [u8; STORE_UNIT_BYTES] = (&mut catalog_extent
            [start..start + STORE_UNIT_BYTES])
            .try_into()
            .map_err(|_| RootError::Graph)?;
        device
            .read_unit(commit.catalog_first_unit + u64::from(i), slice)
            .map_err(RootError::Io)?;
    }
    let catalog_id = commit.catalog_id;
    catalog_id
        .validate_extent(
            OBJECT_KIND_CATALOG,
            OBJECT_VERSION_V1,
            commit.catalog_byte_length,
            &catalog_extent,
        )
        .map_err(|_| RootError::Graph)?;
    let catalog = Catalog::decode(&catalog_extent[..catalog_len]).map_err(|_| RootError::Graph)?;
    commit
        .validates_catalog(catalog_id, &catalog)
        .map_err(|_| RootError::Graph)?;
    catalog
        .validate_extents(
            commit.region_units,
            commit.catalog_first_unit,
            commit.committed_high_water,
        )
        .map_err(|_| RootError::Graph)?;
    for entry in catalog.entries.iter().copied() {
        read_application_object(device, entry)?;
    }
    Ok(ValidatedRoot {
        superblock: sb,
        commit,
        commit_id,
        catalog,
    })
}

fn read_application_object<D: StoreDevice>(
    device: &mut D,
    entry: CatalogEntry,
) -> Result<Vec<u8>, RootError<D::Error>> {
    let bytes_len = usize::try_from(u64::from(entry.unit_count) * STORE_UNIT_BYTES as u64)
        .map_err(|_| RootError::Graph)?;
    let mut extent = vec![0; bytes_len];
    for i in 0..entry.unit_count {
        let start = i as usize * STORE_UNIT_BYTES;
        let slice: &mut [u8; STORE_UNIT_BYTES] = (&mut extent[start..start + STORE_UNIT_BYTES])
            .try_into()
            .map_err(|_| RootError::Graph)?;
        device
            .read_unit(entry.first_unit + u64::from(i), slice)
            .map_err(RootError::Io)?;
    }
    entry
        .object_id
        .validate_extent(entry.kind, entry.version, entry.byte_length, &extent)
        .map_err(|_| RootError::Graph)?;
    let semantic = usize::try_from(entry.byte_length).map_err(|_| RootError::Graph)?;
    Ok(extent[..semantic].to_vec())
}

fn select_two(a: ValidatedRoot, b: ValidatedRoot) -> Result<ValidatedRoot, MountError> {
    if a.commit.generation == b.commit.generation {
        if a.superblock.equivalent_root(&b.superblock) {
            return Ok(a);
        }
        return Err(MountError::ConflictingRoots);
    }
    let (older, newer) = if a.commit.generation < b.commit.generation {
        (a, b)
    } else {
        (b, a)
    };
    if older.commit.generation.checked_add(1) != Some(newer.commit.generation) {
        return Err(MountError::InconsistentHistory);
    }
    if !newer
        .commit
        .identifies_predecessor(&older.commit, older.commit_id)
    {
        return Err(MountError::InconsistentHistory);
    }
    verify_append_transition(&older, &newer)?;
    Ok(newer)
}

fn verify_append_transition(
    older: &ValidatedRoot,
    newer: &ValidatedRoot,
) -> Result<(), MountError> {
    for entry in &older.catalog.entries {
        let index = newer
            .catalog
            .entries
            .binary_search_by_key(&entry.object_id, |candidate| candidate.object_id)
            .map_err(|_| MountError::InconsistentHistory)?;
        if newer.catalog.entries[index] != *entry {
            return Err(MountError::InconsistentHistory);
        }
    }
    let mut added: Vec<CatalogEntry> = Vec::new();
    for entry in &newer.catalog.entries {
        match older
            .catalog
            .entries
            .binary_search_by_key(&entry.object_id, |e| e.object_id)
        {
            Ok(i) if older.catalog.entries[i] != *entry => {
                return Err(MountError::InconsistentHistory)
            }
            Ok(_) => {}
            Err(_) => added.push(*entry),
        }
    }
    added.sort_by_key(|e| e.first_unit);
    let mut next = older.commit.committed_high_water;
    for entry in added {
        if entry.first_unit != next {
            return Err(MountError::InconsistentHistory);
        }
        next = next
            .checked_add(u64::from(entry.unit_count))
            .ok_or(MountError::InconsistentHistory)?;
    }
    if next != newer.commit.catalog_first_unit {
        return Err(MountError::InconsistentHistory);
    }
    Ok(())
}

fn write_object<D: StoreDevice>(
    device: &mut D,
    first: u64,
    units: u32,
    bytes: &[u8],
) -> Result<(), StoreError> {
    for i in 0..units {
        let mut unit = [0; STORE_UNIT_BYTES];
        let start = i as usize * STORE_UNIT_BYTES;
        let end = core::cmp::min(start + STORE_UNIT_BYTES, bytes.len());
        unit[..end - start].copy_from_slice(&bytes[start..end]);
        write_one(device, first + u64::from(i), &unit)?;
    }
    Ok(())
}

fn write_one<D: StoreDevice>(
    device: &mut D,
    unit: u64,
    bytes: &[u8; STORE_UNIT_BYTES],
) -> Result<(), StoreError> {
    device.write_unit(unit, bytes).map_err(|_| StoreError::Io)
}

fn has_superblock_magic(bytes: &[u8; STORE_UNIT_BYTES]) -> bool {
    &bytes[..8] == b"AIENSTR1"
}
fn crc_valid(bytes: &[u8; STORE_UNIT_BYTES]) -> bool {
    let expected = u32::from_le_bytes(bytes[168..172].try_into().unwrap_or([0; 4]));
    let mut copy = *bytes;
    copy[168..172].fill(0);
    super::v1::crc32c(&copy) == expected
}
fn unsupported_superblock(bytes: &[u8; STORE_UNIT_BYTES]) -> bool {
    has_superblock_magic(bytes)
        && crc_valid(bytes)
        && (u16::from_le_bytes([bytes[8], bytes[9]]) != 1
            || u16::from_le_bytes([bytes[10], bytes[11]]) != 0
            || bytes[12..28].iter().any(|b| *b != 0))
}
fn generation_of(bytes: &[u8; STORE_UNIT_BYTES]) -> u64 {
    u64::from_le_bytes(bytes[56..64].try_into().unwrap_or([0; 8]))
}
fn map_root_error<E>(err: RootError<E>) -> StoreError {
    match err {
        RootError::Io(_) => StoreError::Io,
        RootError::Graph => StoreError::Corrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[derive(Clone, Debug)]
    struct MemoryDevice {
        units: Vec<[u8; STORE_UNIT_BYTES]>,
        reads: Vec<u64>,
        writes: Vec<u64>,
        flushes: usize,
        fail_read: Option<u64>,
        fail_write: Option<u64>,
        fail_flush: bool,
    }

    impl StoreDevice for MemoryDevice {
        type Error = ();
        fn region_units(&self) -> u64 {
            self.units.len() as u64
        }
        fn read_unit(&mut self, unit: u64, out: &mut [u8; STORE_UNIT_BYTES]) -> Result<(), ()> {
            self.reads.push(unit);
            if self.fail_read == Some(unit) {
                return Err(());
            }
            *out = *self.units.get(unit as usize).ok_or(())?;
            Ok(())
        }
        fn write_unit(&mut self, unit: u64, bytes: &[u8; STORE_UNIT_BYTES]) -> Result<(), ()> {
            self.writes.push(unit);
            if self.fail_write == Some(unit) {
                return Err(());
            }
            *self.units.get_mut(unit as usize).ok_or(())? = *bytes;
            Ok(())
        }
        fn flush(&mut self) -> Result<(), ()> {
            self.flushes += 1;
            if self.fail_flush {
                return Err(());
            }
            Ok(())
        }
    }

    fn blank(units: usize) -> MemoryDevice {
        MemoryDevice {
            units: vec![[0; STORE_UNIT_BYTES]; units],
            reads: Vec::new(),
            writes: Vec::new(),
            flushes: 0,
            fail_read: None,
            fail_write: None,
            fail_flush: false,
        }
    }

    fn seed_genesis(mut dev: MemoryDevice) -> MemoryDevice {
        let catalog = Catalog {
            entries: Vec::new(),
        };
        let catalog_bytes = catalog.encode().unwrap();
        let catalog_id =
            ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &catalog_bytes).unwrap();
        let commit = CommitRecord {
            store_uuid: [0x5a; 16],
            region_units: dev.region_units(),
            generation: 1,
            previous_generation: 0,
            previous_commit_id: ObjectId([0; 32]),
            previous_catalog_id: ObjectId([0; 32]),
            catalog_id,
            catalog_first_unit: 2,
            catalog_byte_length: catalog_bytes.len() as u64,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 4,
        };
        let mut cat_unit = [0; STORE_UNIT_BYTES];
        cat_unit[..catalog_bytes.len()].copy_from_slice(&catalog_bytes);
        dev.units[2] = cat_unit;
        let mut commit_unit = [0; STORE_UNIT_BYTES];
        commit_unit[..super::super::v1::COMMIT_RECORD_BYTES]
            .copy_from_slice(&commit.encode().unwrap());
        dev.units[3] = commit_unit;
        dev.units[0] = Superblock {
            store_uuid: commit.store_uuid,
            slot_id: 0,
            region_units: commit.region_units,
            generation: 1,
            commit_record_id: commit.object_id().unwrap(),
            commit_record_unit: 3,
            catalog_id,
            catalog_first_unit: 2,
            catalog_byte_length: commit.catalog_byte_length,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 4,
        }
        .encode()
        .unwrap();
        dev
    }

    fn seed_full_catalog() -> MemoryDevice {
        let region_units = 4_168usize;
        let mut dev = blank(region_units);
        let mut entries = Vec::with_capacity(MAX_CATALOG_ENTRIES);
        for index in 0..MAX_CATALOG_ENTRIES {
            let kind = 3 + index as u16;
            let semantic = [kind as u8];
            let id = ObjectId::calculate(kind, 1, &semantic).unwrap();
            entries.push(CatalogEntry {
                object_id: id,
                kind,
                version: 1,
                first_unit: 2 + index as u64,
                byte_length: 1,
                unit_count: 1,
                flags: 0,
            });
            dev.units[2 + index][0] = semantic[0];
        }
        entries.sort_by_key(|entry| entry.object_id);
        let catalog = Catalog { entries };
        let catalog_bytes = catalog.encode().unwrap();
        let catalog_id = ObjectId::calculate(OBJECT_KIND_CATALOG, 1, &catalog_bytes).unwrap();
        let catalog_first = 2 + MAX_CATALOG_ENTRIES as u64;
        let catalog_units = object_unit_count(catalog_bytes.len() as u64).unwrap();
        assert_eq!(catalog_units, 65);
        for i in 0..catalog_units as usize {
            let start = i * STORE_UNIT_BYTES;
            let end = core::cmp::min(start + STORE_UNIT_BYTES, catalog_bytes.len());
            dev.units[catalog_first as usize + i][..end - start]
                .copy_from_slice(&catalog_bytes[start..end]);
        }
        let commit_unit = catalog_first + u64::from(catalog_units);
        let high_water = commit_unit + 1;
        let commit = CommitRecord {
            store_uuid: [0x5a; 16],
            region_units: region_units as u64,
            generation: 1,
            previous_generation: 0,
            previous_commit_id: ObjectId([0; 32]),
            previous_catalog_id: ObjectId([0; 32]),
            catalog_id,
            catalog_first_unit: catalog_first,
            catalog_byte_length: catalog_bytes.len() as u64,
            catalog_unit_count: catalog_units,
            catalog_entry_count: MAX_CATALOG_ENTRIES as u32,
            committed_high_water: high_water,
        };
        dev.units[commit_unit as usize][..super::super::v1::COMMIT_RECORD_BYTES]
            .copy_from_slice(&commit.encode().unwrap());
        dev.units[0] = Superblock {
            store_uuid: commit.store_uuid,
            slot_id: 0,
            region_units: commit.region_units,
            generation: 1,
            commit_record_id: commit.object_id().unwrap(),
            commit_record_unit: commit_unit,
            catalog_id,
            catalog_first_unit: catalog_first,
            catalog_byte_length: commit.catalog_byte_length,
            catalog_unit_count: catalog_units,
            catalog_entry_count: commit.catalog_entry_count,
            committed_high_water: high_water,
        }
        .encode()
        .unwrap();
        dev
    }

    fn seed_generation_two() -> MemoryDevice {
        let mut store = Store::open(seed_genesis(blank(32))).unwrap();
        store.transact(&one(b"next generation")).unwrap();
        store.into_device()
    }

    fn rewrite_commit(dev: &mut MemoryDevice, slot: u32, unit: u64, commit: CommitRecord) {
        let mut commit_unit = [0; STORE_UNIT_BYTES];
        commit_unit[..super::super::v1::COMMIT_RECORD_BYTES]
            .copy_from_slice(&commit.encode().unwrap());
        dev.units[unit as usize] = commit_unit;
        let mut sb = Superblock::decode(&dev.units[slot as usize], slot).unwrap();
        sb.generation = commit.generation;
        sb.commit_record_id = commit.object_id().unwrap();
        dev.units[slot as usize] = sb.encode().unwrap();
    }

    fn seed_conflicting_same_generation_roots() -> MemoryDevice {
        let mut dev = seed_genesis(blank(32));
        let catalog = Catalog {
            entries: Vec::new(),
        };
        let bytes = catalog.encode().unwrap();
        let id = ObjectId::calculate(OBJECT_KIND_CATALOG, 1, &bytes).unwrap();
        let mut catalog_unit = [0; STORE_UNIT_BYTES];
        catalog_unit[..bytes.len()].copy_from_slice(&bytes);
        dev.units[4] = catalog_unit;
        let commit = CommitRecord {
            store_uuid: [0x6b; 16],
            region_units: dev.region_units(),
            generation: 1,
            previous_generation: 0,
            previous_commit_id: ObjectId([0; 32]),
            previous_catalog_id: ObjectId([0; 32]),
            catalog_id: id,
            catalog_first_unit: 4,
            catalog_byte_length: bytes.len() as u64,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 6,
        };
        dev.units[5][..super::super::v1::COMMIT_RECORD_BYTES]
            .copy_from_slice(&commit.encode().unwrap());
        dev.units[1] = Superblock {
            store_uuid: commit.store_uuid,
            slot_id: 1,
            region_units: commit.region_units,
            generation: 1,
            commit_record_id: commit.object_id().unwrap(),
            commit_record_unit: 5,
            catalog_id: id,
            catalog_first_unit: 4,
            catalog_byte_length: commit.catalog_byte_length,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 6,
        }
        .encode()
        .unwrap();
        dev
    }

    fn one<'a>(bytes: &'a [u8]) -> [ObjectInput<'a>; 1] {
        [ObjectInput {
            kind: 3,
            version: 1,
            bytes,
        }]
    }

    #[test]
    fn store_open_side_effect_free() {
        let dev = seed_genesis(blank(32));
        let store = Store::open(dev).unwrap();
        let dev = store.into_device();
        assert_eq!(dev.writes, []);
        assert_eq!(dev.flushes, 0);
        assert!(dev.reads.contains(&0) && dev.reads.contains(&1));
    }

    #[test]
    fn store_full_graph_validation_rejects_damaged_payload_and_keeps_io_distinct() {
        let mut dev = seed_genesis(blank(32));
        let value = b"payload";
        let id = ObjectId::calculate(3, 1, value).unwrap();
        let entry = CatalogEntry {
            object_id: id,
            kind: 3,
            version: 1,
            first_unit: 2,
            byte_length: value.len() as u64,
            unit_count: 1,
            flags: 0,
        };
        let catalog = Catalog {
            entries: vec![entry],
        };
        let cat_bytes = catalog.encode().unwrap();
        let cat_id =
            ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &cat_bytes).unwrap();
        let commit = CommitRecord {
            store_uuid: [0x5a; 16],
            region_units: dev.region_units(),
            generation: 1,
            previous_generation: 0,
            previous_commit_id: ObjectId([0; 32]),
            previous_catalog_id: ObjectId([0; 32]),
            catalog_id: cat_id,
            catalog_first_unit: 3,
            catalog_byte_length: cat_bytes.len() as u64,
            catalog_unit_count: 1,
            catalog_entry_count: 1,
            committed_high_water: 5,
        };
        let mut payload = [0; STORE_UNIT_BYTES];
        payload[..value.len()].copy_from_slice(value);
        dev.units[2] = payload;
        let mut cat_unit = [0; STORE_UNIT_BYTES];
        cat_unit[..cat_bytes.len()].copy_from_slice(&cat_bytes);
        dev.units[3] = cat_unit;
        let mut cr = [0; STORE_UNIT_BYTES];
        cr[..super::super::v1::COMMIT_RECORD_BYTES].copy_from_slice(&commit.encode().unwrap());
        dev.units[4] = cr;
        dev.units[0] = Superblock {
            store_uuid: commit.store_uuid,
            slot_id: 0,
            region_units: commit.region_units,
            generation: 1,
            commit_record_id: commit.object_id().unwrap(),
            commit_record_unit: 4,
            catalog_id: cat_id,
            catalog_first_unit: 3,
            catalog_byte_length: commit.catalog_byte_length,
            catalog_unit_count: 1,
            catalog_entry_count: 1,
            committed_high_water: 5,
        }
        .encode()
        .unwrap();
        dev.units[2][STORE_UNIT_BYTES - 1] = 1;
        assert_eq!(
            Store::open(dev.clone()).err().unwrap(),
            MountError::CorruptRecoveryRequired
        );
        let mut io_dev = dev;
        io_dev.fail_read = Some(4);
        assert_eq!(Store::open(io_dev).err().unwrap(), MountError::Io);
    }

    #[test]
    fn store_history_matrix_equivalent_and_adjacent_roots() {
        assert_eq!(
            Store::open(seed_conflicting_same_generation_roots())
                .err()
                .unwrap(),
            MountError::ConflictingRoots
        );
        let store = Store::open(seed_genesis(blank(32))).unwrap();
        let mut dev = store.into_device();
        // Slot is part of the CRC'd bytes; re-encode the equivalent root.
        let root = Superblock::decode(&dev.units[0], 0).unwrap();
        let mut peer = root;
        peer.slot_id = 1;
        dev.units[1] = peer.encode().unwrap();
        let store = Store::open(dev).unwrap();
        assert_eq!(store.generation(), 1);
        let value = b"next";
        let mut store = store;
        store.transact(&one(value)).unwrap();
        let dev = store.into_device();
        assert_eq!(Store::open(dev).unwrap().generation(), 2);

        let mut wrong_previous = seed_generation_two();
        let mut record =
            CommitRecord::decode(&wrong_previous.units[6][..super::super::v1::COMMIT_RECORD_BYTES])
                .unwrap();
        record.previous_commit_id = ObjectId([0x33; 32]);
        rewrite_commit(&mut wrong_previous, 1, 6, record);
        assert_eq!(
            Store::open(wrong_previous).err().unwrap(),
            MountError::InconsistentHistory
        );

        let mut non_adjacent = seed_generation_two();
        let mut record =
            CommitRecord::decode(&non_adjacent.units[6][..super::super::v1::COMMIT_RECORD_BYTES])
                .unwrap();
        record.generation = 3;
        record.previous_generation = 2;
        rewrite_commit(&mut non_adjacent, 1, 6, record);
        assert_eq!(
            Store::open(non_adjacent).err().unwrap(),
            MountError::InconsistentHistory
        );

        let mut damaged_new = seed_generation_two();
        damaged_new.units[4][0] ^= 1;
        let mut recovered = Store::open(damaged_new).unwrap();
        assert_eq!(recovered.mount_state(), MountState::DegradedRecovery);
        assert_eq!(
            recovered.transact(&one(b"read only")),
            Err(StoreError::ReadOnlyDegraded)
        );

        let mut damaged_old = seed_generation_two();
        damaged_old.units[2][0] ^= 1;
        let recovered = Store::open(damaged_old).unwrap();
        assert_eq!(recovered.mount_state(), MountState::Valid);
        assert_eq!(recovered.generation(), 2);
    }

    #[test]
    fn store_history_rejects_deleting_an_old_catalog_entry() {
        let mut dev = seed_generation_two();
        let previous =
            CommitRecord::decode(&dev.units[6][..super::super::v1::COMMIT_RECORD_BYTES]).unwrap();
        let catalog = Catalog {
            entries: Vec::new(),
        };
        let catalog_bytes = catalog.encode().unwrap();
        let catalog_id = ObjectId::calculate(OBJECT_KIND_CATALOG, 1, &catalog_bytes).unwrap();
        let mut catalog_unit = [0; STORE_UNIT_BYTES];
        catalog_unit[..catalog_bytes.len()].copy_from_slice(&catalog_bytes);
        dev.units[7] = catalog_unit;
        let commit = CommitRecord {
            store_uuid: previous.store_uuid,
            region_units: previous.region_units,
            generation: 3,
            previous_generation: 2,
            previous_commit_id: previous.object_id().unwrap(),
            previous_catalog_id: previous.catalog_id,
            catalog_id,
            catalog_first_unit: 7,
            catalog_byte_length: catalog_bytes.len() as u64,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 9,
        };
        dev.units[8][..super::super::v1::COMMIT_RECORD_BYTES]
            .copy_from_slice(&commit.encode().unwrap());
        dev.units[0] = Superblock {
            store_uuid: commit.store_uuid,
            slot_id: 0,
            region_units: commit.region_units,
            generation: 3,
            commit_record_id: commit.object_id().unwrap(),
            commit_record_unit: 8,
            catalog_id,
            catalog_first_unit: 7,
            catalog_byte_length: catalog_bytes.len() as u64,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 9,
        }
        .encode()
        .unwrap();
        assert_eq!(
            Store::open(dev).err().unwrap(),
            MountError::InconsistentHistory
        );
    }

    #[test]
    fn store_mount_classification_is_deterministic() {
        assert_eq!(
            Store::open(blank(8)).err().unwrap(),
            MountError::Unformatted
        );
        let mut foreign = blank(8);
        foreign.units[0][0] = 0x77;
        assert_eq!(
            Store::open(foreign).err().unwrap(),
            MountError::ForeignOrUnknown
        );

        let mut unsupported = seed_genesis(blank(8));
        unsupported.units[0][8..10].copy_from_slice(&2u16.to_le_bytes());
        unsupported.units[0][168..172].fill(0);
        let crc = super::super::v1::crc32c(&unsupported.units[0]);
        unsupported.units[0][168..172].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            Store::open(unsupported).err().unwrap(),
            MountError::UnsupportedVersion
        );

        let mut bad_crc = seed_genesis(blank(8));
        bad_crc.units[0][168] ^= 1;
        assert_eq!(
            Store::open(bad_crc).err().unwrap(),
            MountError::CorruptRecoveryRequired
        );
    }

    #[test]
    fn store_nospace_zero_writes() {
        let mut store = Store::open(seed_genesis(blank(6))).unwrap();
        assert_eq!(
            store.transact(&one(b"cannot fit")),
            Err(StoreError::NoSpace)
        );
        let dev = store.into_device();
        assert!(dev.writes.is_empty());
        assert_eq!(dev.flushes, 0);
    }

    #[test]
    fn store_catalogfull_zero_writes() {
        let mut store = Store::open(seed_full_catalog()).unwrap();
        assert_eq!(
            store.transact(&one(b"new object")),
            Err(StoreError::CatalogFull)
        );
        let dev = store.into_device();
        assert!(dev.writes.is_empty());
        assert_eq!(dev.flushes, 0);
    }

    #[test]
    fn store_generation_overflow_zero_writes() {
        let mut store = Store::open(seed_genesis(blank(32))).unwrap();
        store.root.commit.generation = u64::MAX;
        store.root.superblock.generation = u64::MAX;
        assert_eq!(
            store.transact(&one(b"overflow")),
            Err(StoreError::GenerationExhausted)
        );
        let dev = store.into_device();
        assert!(dev.writes.is_empty());
        assert_eq!(dev.flushes, 0);
    }

    #[test]
    fn store_transaction_commit_dedup_and_tail_reuse() {
        let mut dev = seed_genesis(blank(32));
        dev.units[4].fill(0xa5); // uncommitted tail is reusable
        let mut store = Store::open(dev).unwrap();
        let value = b"committed payload";
        store.transact(&one(value)).unwrap();
        assert_eq!(store.generation(), 2);
        let dev = store.into_device();
        assert!(dev.writes.contains(&4));
        assert_eq!(dev.flushes, 2);
        let mut store = Store::open(dev).unwrap();
        let payload_id = ObjectId::calculate(3, 1, value).unwrap();
        let before = store.device.writes.len();
        store.transact(&one(value)).unwrap();
        let writes = &store.device.writes[before..];
        assert_eq!(writes, &[7, 8, 0]); // catalog, commit record, inactive root only
        assert_eq!(store.read_object(payload_id).unwrap(), value);
    }

    #[test]
    fn store_checkpoint_order_does_not_change_persistent_bytes() {
        let initial = seed_genesis(blank(32));
        let mut plain = Store::open(initial.clone()).unwrap();
        plain.transact(&one(b"checkpointed")).unwrap();
        let plain = plain.into_device();

        let mut observed = Store::open(initial).unwrap();
        let mut checkpoints = Vec::new();
        observed
            .transact_with_hook(&one(b"checkpointed"), |checkpoint| {
                checkpoints.push(checkpoint)
            })
            .unwrap();
        let observed = observed.into_device();
        assert_eq!(checkpoints, Checkpoint::ORDERED);
        assert_eq!(observed.units, plain.units);
        assert_eq!(observed.writes, plain.writes);
        assert_eq!(observed.flushes, plain.flushes);
    }

    #[test]
    fn store_dedup_corruption_and_descriptor_conflict_fail_before_writes() {
        let mut store = Store::open(seed_genesis(blank(32))).unwrap();
        let value = b"dedup target";
        store.transact(&one(value)).unwrap();
        let mut store = Store::open(store.into_device()).unwrap();
        store.device.writes.clear();
        store.device.flushes = 0;
        store.device.units[4][0] ^= 1;
        assert_eq!(store.transact(&one(value)), Err(StoreError::Corrupt));
        assert!(store.device.writes.is_empty());
        assert_eq!(store.device.flushes, 0);

        let mut store = Store::open(seed_generation_two()).unwrap();
        let id = store.root.catalog.entries[0].object_id;
        store.root.catalog.entries[0].kind += 1;
        store.device.writes.clear();
        store.device.flushes = 0;
        let conflicting = [ObjectInput {
            kind: 3,
            version: 1,
            bytes: b"next generation",
        }];
        assert_eq!(
            store.transact(&conflicting),
            Err(StoreError::DuplicateObjectConflict)
        );
        assert_eq!(store.root.catalog.entries[0].object_id, id);
        assert!(store.device.writes.is_empty());
        assert_eq!(store.device.flushes, 0);
    }

    #[test]
    fn store_io_fail_closed() {
        let mut dev = seed_genesis(blank(32));
        dev.fail_read = Some(3);
        assert_eq!(Store::open(dev).err().unwrap(), MountError::Io);
        let mut store = Store::open(seed_genesis(blank(32))).unwrap();
        store.device.fail_write = Some(4);
        assert_eq!(store.transact(&one(b"fault")), Err(StoreError::Io));
        assert_eq!(store.transact(&one(b"again")), Err(StoreError::NeedsReopen));
    }
}
