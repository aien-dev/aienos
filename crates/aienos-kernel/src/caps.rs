//! Fixed-capacity capability handles with generation checks and revocation.

pub use crate::abi::Handle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u8);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const MAP: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);
    pub const DERIVE: Self = Self(1 << 4);
    pub const REVOKE: Self = Self(1 << 5);
    const ALL: u8 = (1 << 6) - 1;

    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn is_subset_of(self, other: Self) -> bool {
        other.contains(self)
    }
}

impl core::ops::BitOr for Rights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapError {
    Full,
    InvalidHandle,
    MissingRights,
    RightsEscalation,
    DuplicateTable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Location {
    table: u32,
    handle: Handle,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    resource: u32,
    rights: Rights,
    parent: Option<Location>,
    /// Something was derived from this capability (possibly into another table).
    derived: bool,
    /// Removed by its holder but kept so descendants' parent chains stay
    /// intact for revocation. Invisible to every operation except revocation.
    tombstone: bool,
}

/// A task's capability table. `id` must be unique among tables passed to
/// cross-table operations; resource IDs are opaque to this data structure.
pub struct CapTable<const N: usize> {
    id: u32,
    slots: [Option<Slot>; N],
    generations: [u32; N],
}

impl<const N: usize> CapTable<N> {
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            slots: [None; N],
            generations: [0; N],
        }
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn insert(&mut self, resource: u32, rights: Rights) -> Result<Handle, CapError> {
        self.allocate(resource, rights, None)
    }

    fn allocate(
        &mut self,
        resource: u32,
        rights: Rights,
        parent: Option<Location>,
    ) -> Result<Handle, CapError> {
        let index = self
            .slots
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                (slot.is_none() && self.generations[index] != u32::MAX).then_some(index)
            })
            .ok_or(CapError::Full)?;
        let generation = self.generations[index] + 1;
        self.generations[index] = generation;
        self.slots[index] = Some(Slot {
            generation,
            resource,
            rights,
            parent,
            derived: false,
            tombstone: false,
        });
        Ok(Handle {
            index: index as u32,
            generation,
        })
    }

    /// A live capability (tombstones are invisible).
    fn slot(&self, handle: Handle) -> Result<&Slot, CapError> {
        self.slot_any(handle)
            .filter(|slot| !slot.tombstone)
            .ok_or(CapError::InvalidHandle)
    }

    /// Any occupied slot, including tombstones (for ancestry walks only).
    fn slot_any(&self, handle: Handle) -> Option<&Slot> {
        self.slots
            .get(handle.index as usize)
            .and_then(Option::as_ref)
            .filter(|slot| slot.generation == handle.generation)
    }

    pub fn lookup(&self, handle: Handle, required_rights: Rights) -> Result<u32, CapError> {
        let slot = self.slot(handle)?;
        if !slot.rights.contains(required_rights) {
            return Err(CapError::MissingRights);
        }
        Ok(slot.resource)
    }

    pub fn rights(&self, handle: Handle) -> Result<Rights, CapError> {
        Ok(self.slot(handle)?.rights)
    }

    /// Drop this handle. Descendants are not revoked (use `revoke` for that),
    /// but a capability that has been derived from becomes a tombstone rather
    /// than a free slot, so its descendants stay reachable from any ancestor's
    /// `revoke`. Freeing it would break their parent chains and leave the
    /// subtree unrevocable from above.
    pub fn remove(&mut self, handle: Handle) -> Result<(), CapError> {
        let derived = self.slot(handle)?.derived;
        let index = handle.index as usize;
        if derived {
            if let Some(slot) = self.slots[index].as_mut() {
                slot.tombstone = true;
            }
        } else {
            self.slots[index] = None;
        }
        Ok(())
    }

    pub fn derive(&mut self, handle: Handle, rights: Rights) -> Result<Handle, CapError> {
        let source = *self.slot(handle)?;
        if !source.rights.contains(Rights::DERIVE) {
            return Err(CapError::MissingRights);
        }
        if !rights.is_subset_of(source.rights) {
            return Err(CapError::RightsEscalation);
        }
        let child = self.allocate(
            source.resource,
            rights,
            Some(Location {
                table: self.id,
                handle,
            }),
        )?;
        if let Some(slot) = self.slots[handle.index as usize].as_mut() {
            slot.derived = true;
        }
        Ok(child)
    }

    /// Derive into another table, retaining a parent link for tree revocation.
    pub fn derive_into<const M: usize>(
        from: &mut Self,
        handle: Handle,
        to: &mut CapTable<M>,
        rights: Rights,
    ) -> Result<Handle, CapError> {
        let source = *from.slot(handle)?;
        if !source.rights.contains(Rights::DERIVE) {
            return Err(CapError::MissingRights);
        }
        if !rights.is_subset_of(source.rights) {
            return Err(CapError::RightsEscalation);
        }
        let parent = Location {
            table: from.id,
            handle,
        };
        let child = to.allocate(source.resource, rights, Some(parent))?;
        if let Some(slot) = from.slots[handle.index as usize].as_mut() {
            slot.derived = true;
        }
        Ok(child)
    }

    pub fn transfer<const M: usize>(
        from: &mut Self,
        handle: Handle,
        to: &mut CapTable<M>,
    ) -> Result<Handle, CapError> {
        let source = *from.slot(handle)?;
        if !source.rights.contains(Rights::GRANT) {
            return Err(CapError::MissingRights);
        }
        to.allocate(source.resource, source.rights, None)
    }

    /// Remove a capability and all descendants found in the supplied table set.
    /// The caller supplies every table that may contain descendants.
    pub fn revoke<const M: usize>(
        table_id: u32,
        handle: Handle,
        tables: &mut [&mut CapTable<M>],
    ) -> Result<(), CapError> {
        if tables.iter().filter(|table| table.id == table_id).count() != 1 {
            return Err(CapError::DuplicateTable);
        }
        let root_index = tables
            .iter()
            .position(|table| table.id == table_id)
            .unwrap();
        if !tables[root_index]
            .slot(handle)?
            .rights
            .contains(Rights::REVOKE)
        {
            return Err(CapError::MissingRights);
        }
        let root = Location {
            table: table_id,
            handle,
        };
        let capacity = M.saturating_mul(tables.len());

        // Validate every parent chain before changing any slot. The table set
        // bounds each walk, including malformed cyclic derivation metadata.
        for table in tables.iter() {
            for (index, slot) in table.slots.iter().enumerate() {
                if slot.is_some() {
                    let start = Location {
                        table: table.id,
                        handle: Handle {
                            index: index as u32,
                            generation: slot.unwrap().generation,
                        },
                    };
                    let _ = Self::revocation_depth(start, root, tables, capacity)?;
                }
            }
        }

        // Remove deepest descendants first so their parent chains remain
        // available while calculating the shallower depths.
        for _ in 0..capacity {
            let mut deepest: Option<(Location, usize)> = None;
            for table in tables.iter() {
                for (index, slot) in table.slots.iter().enumerate() {
                    if let Some(slot) = slot {
                        let loc = Location {
                            table: table.id,
                            handle: Handle {
                                index: index as u32,
                                generation: slot.generation,
                            },
                        };
                        if let Some(depth) = Self::revocation_depth(loc, root, tables, capacity)? {
                            if deepest.is_none_or(|(_, deepest_depth)| depth > deepest_depth) {
                                deepest = Some((loc, depth));
                            }
                        }
                    }
                }
            }
            let Some((loc, _)) = deepest else { break };
            let table = tables
                .iter_mut()
                .find(|table| table.id == loc.table)
                .unwrap();
            table.slots[loc.handle.index as usize] = None;
        }
        Ok(())
    }

    fn revocation_depth<const M: usize>(
        mut current: Location,
        root: Location,
        tables: &[&mut CapTable<M>],
        capacity: usize,
    ) -> Result<Option<usize>, CapError> {
        for depth in 0..=capacity {
            if current == root {
                return Ok(Some(depth));
            }
            let Some(table) = tables.iter().find(|table| table.id == current.table) else {
                return Ok(None);
            };
            // Walk through tombstones: they keep removed ancestors' links.
            let Some(slot) = table.slot_any(current.handle) else {
                return Ok(None);
            };
            let Some(parent) = slot.parent else {
                return Ok(None);
            };
            current = parent;
        }
        Err(CapError::Full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_handle_rejected_after_slot_reuse() {
        let mut table = CapTable::<1>::new(1);
        let old = table.insert(7, Rights::READ).unwrap();
        table.remove(old).unwrap();
        let new = table.insert(8, Rights::READ).unwrap();
        assert_ne!(old.generation, new.generation);
        assert_eq!(
            table.lookup(old, Rights::READ),
            Err(CapError::InvalidHandle)
        );
    }

    #[test]
    fn generation_exhaustion_retires_slot_without_reviving_old_handle() {
        let mut table = CapTable::<2>::new(1);
        let old = table.insert(7, Rights::READ).unwrap();
        table.generations[old.index as usize] = u32::MAX - 1;
        table.remove(old).unwrap();

        let final_handle = table.insert(8, Rights::READ).unwrap();
        assert_eq!(final_handle.index, old.index);
        assert_eq!(final_handle.generation, u32::MAX);
        table.remove(final_handle).unwrap();

        let replacement = table.insert(9, Rights::READ).unwrap();
        assert_ne!(replacement.index, old.index);
        assert_eq!(
            table.lookup(old, Rights::READ),
            Err(CapError::InvalidHandle)
        );
        assert_eq!(
            table.lookup(final_handle, Rights::READ),
            Err(CapError::InvalidHandle)
        );
    }

    #[test]
    fn derive_cannot_add_rights() {
        let mut table = CapTable::<3>::new(1);
        let parent = table.insert(7, Rights::READ | Rights::DERIVE).unwrap();
        assert_eq!(
            table.derive(parent, Rights::READ | Rights::WRITE),
            Err(CapError::RightsEscalation)
        );
        let child = table.derive(parent, Rights::READ).unwrap();
        assert_eq!(table.rights(child), Ok(Rights::READ));
    }

    #[test]
    fn revoke_cascades_two_levels_across_tables() {
        let mut a = CapTable::<4>::new(1);
        let mut b = CapTable::<4>::new(2);
        let root = a
            .insert(7, Rights::READ | Rights::DERIVE | Rights::REVOKE)
            .unwrap();
        let child =
            CapTable::derive_into(&mut a, root, &mut b, Rights::READ | Rights::DERIVE).unwrap();
        let grandchild = b.derive(child, Rights::READ).unwrap();
        CapTable::<4>::revoke(1, root, &mut [&mut a, &mut b]).unwrap();
        assert_eq!(a.lookup(root, Rights::READ), Err(CapError::InvalidHandle));
        assert_eq!(b.lookup(child, Rights::READ), Err(CapError::InvalidHandle));
        assert_eq!(
            b.lookup(grandchild, Rights::READ),
            Err(CapError::InvalidHandle)
        );
    }

    #[test]
    fn revoke_with_single_slot_tables_removes_cross_table_child() {
        let mut a = CapTable::<1>::new(1);
        let mut b = CapTable::<1>::new(2);
        let root = a
            .insert(7, Rights::READ | Rights::DERIVE | Rights::REVOKE)
            .unwrap();
        let child = CapTable::derive_into(&mut a, root, &mut b, Rights::READ).unwrap();

        CapTable::<1>::revoke(1, root, &mut [&mut a, &mut b]).unwrap();

        assert_eq!(a.lookup(root, Rights::READ), Err(CapError::InvalidHandle));
        assert_eq!(b.lookup(child, Rights::READ), Err(CapError::InvalidHandle));
    }

    #[test]
    fn transfer_needs_grant_and_table_full_is_reported() {
        let mut source = CapTable::<2>::new(1);
        let mut target = CapTable::<1>::new(2);
        let denied = source.insert(1, Rights::READ).unwrap();
        assert_eq!(
            CapTable::transfer(&mut source, denied, &mut target),
            Err(CapError::MissingRights)
        );
        let granted = source.insert(2, Rights::READ | Rights::GRANT).unwrap();
        let received = CapTable::transfer(&mut source, granted, &mut target).unwrap();
        assert_eq!(target.lookup(received, Rights::READ), Ok(2));
        assert_eq!(target.insert(3, Rights::READ), Err(CapError::Full));
    }
    #[test]
    fn removing_a_derived_parent_keeps_the_subtree_revocable() {
        // Review regression: removing an intermediate capability used to free
        // its slot, breaking the child's parent chain so revoking the
        // grandparent no longer reached the child.
        let mut a = CapTable::<4>::new(1);
        let mut b = CapTable::<4>::new(2);
        let all = Rights::READ | Rights::DERIVE | Rights::REVOKE;
        let root = a.insert(9, all).unwrap();
        let mid = a.derive(root, all).unwrap();
        let leaf = CapTable::derive_into(&mut a, mid, &mut b, Rights::READ).unwrap();
        a.remove(mid).unwrap();
        // The removed handle is dead; the leaf is still usable (remove != revoke).
        assert_eq!(a.lookup(mid, Rights::READ), Err(CapError::InvalidHandle));
        assert_eq!(b.lookup(leaf, Rights::READ), Ok(9));
        // Revoking the grandparent still reaches the leaf through the tombstone.
        CapTable::<4>::revoke(1, root, &mut [&mut a, &mut b]).unwrap();
        assert_eq!(b.lookup(leaf, Rights::READ), Err(CapError::InvalidHandle));
        assert_eq!(a.lookup(root, Rights::READ), Err(CapError::InvalidHandle));
    }

    #[test]
    fn removing_a_never_derived_capability_frees_its_slot() {
        let mut t = CapTable::<1>::new(1);
        let h = t.insert(3, Rights::READ).unwrap();
        t.remove(h).unwrap();
        assert!(t.insert(4, Rights::READ).is_ok(), "slot reusable");
    }
}
