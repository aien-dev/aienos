//! Fixed-capacity capability handles with generation checks and revocation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    pub index: u32,
    pub generation: u32,
}

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
            .position(Option::is_none)
            .ok_or(CapError::Full)?;
        let generation = self.generations[index].wrapping_add(1).max(1);
        self.generations[index] = generation;
        self.slots[index] = Some(Slot {
            generation,
            resource,
            rights,
            parent,
        });
        Ok(Handle {
            index: index as u32,
            generation,
        })
    }

    fn slot(&self, handle: Handle) -> Result<&Slot, CapError> {
        self.slots
            .get(handle.index as usize)
            .and_then(Option::as_ref)
            .filter(|slot| slot.generation == handle.generation)
            .ok_or(CapError::InvalidHandle)
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

    pub fn remove(&mut self, handle: Handle) -> Result<(), CapError> {
        self.slot(handle)?;
        self.slots[handle.index as usize] = None;
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
        self.allocate(
            source.resource,
            rights,
            Some(Location {
                table: self.id,
                handle,
            }),
        )
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
        to.allocate(source.resource, rights, Some(parent))
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
        let mut revoked = [None; M];
        revoked[0] = Some(Location {
            table: table_id,
            handle,
        });
        let mut count = 1;
        let mut cursor = 0;
        while cursor < count {
            let parent = revoked[cursor].unwrap();
            for table in tables.iter_mut() {
                for (index, slot) in table.slots.iter().enumerate() {
                    if slot.and_then(|s| s.parent) == Some(parent) {
                        let loc = Location {
                            table: table.id,
                            handle: Handle {
                                index: index as u32,
                                generation: slot.unwrap().generation,
                            },
                        };
                        if count == M {
                            return Err(CapError::Full);
                        }
                        revoked[count] = Some(loc);
                        count += 1;
                    }
                }
            }
            cursor += 1;
        }
        for loc in revoked[..count].iter().flatten() {
            if let Some(table) = tables.iter_mut().find(|table| table.id == loc.table) {
                if table.slot(loc.handle).is_ok() {
                    table.slots[loc.handle.index as usize] = None;
                }
            }
        }
        Ok(())
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
}
