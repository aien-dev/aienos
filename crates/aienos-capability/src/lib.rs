//! Native capability authority.
//!
//! This is the AIENOS side of the host reference root. The slot rules match
//! that root: a reference is an index plus a generation, a reused slot does
//! not honor the old reference, generation never wraps, delegation can only
//! narrow rights, and revoking an ancestor revokes the descendants.
//!
//! What the older capability table does not carry lives here: the subject the
//! capability was issued to, the epoch, the lease, a full 64-bit resource
//! identity, and office rights that cannot be delegated.
//!
//! [`AuthorityView`] can check a reference. It cannot mint, revoke, reclaim,
//! move the clock, or change the epoch. Those operations live on
//! [`AuthorityAdmin`], and they refuse to run unless the caller still holds
//! the office token that was never written into the table.

#![no_std]

use core::sync::atomic::{AtomicU32, Ordering};

pub const CAP_MAX: usize = 256;
pub const MAX_DEPTH: u32 = 8;
pub const TOKEN_LEN: usize = 32;
pub const RES_AUTHORITY: u64 = 0;

pub const OK: i32 = 0;
pub const ERR_BOUNDS: i32 = -1;
pub const ERR_STALE_GEN: i32 = -2;
pub const ERR_REVOKED: i32 = -3;
pub const ERR_EPOCH: i32 = -4;
pub const ERR_SUBJECT: i32 = -5;
pub const ERR_RESOURCE: i32 = -6;
pub const ERR_RIGHTS: i32 = -7;
pub const ERR_EXPIRED: i32 = -8;
pub const ERR_CHAIN: i32 = -9;
pub const ERR_AMPLIFY: i32 = -10;
pub const ERR_NOT_DELEGABLE: i32 = -11;
pub const ERR_FULL: i32 = -12;
pub const ERR_IO: i32 = -13;
pub const ERR_STATE: i32 = -14;
pub const ERR_UNAUTHORIZED: i32 = -15;
pub const ERR_OVERFLOW: i32 = -16;
pub const ERR_EXHAUSTED: i32 = -17;

pub const RIGHT_READ: u32 = 0x1;
pub const RIGHT_WRITE: u32 = 0x2;
pub const RIGHT_EFFECT: u32 = 0x4;
pub const RIGHT_DELEGATE: u32 = 0x8;
pub const RIGHT_MINT: u32 = 0x10;
pub const RIGHT_REVOKE: u32 = 0x20;
pub const RIGHT_RECLAIM: u32 = 0x40;
pub const RIGHT_EPOCH: u32 = 0x80;
pub const RIGHT_CLOCK: u32 = 0x100;
/// Authorizes a lineage transition. Intelligence may propose the next
/// generation. Only a holder of this right may promote it, and the right
/// cannot be handed on.
pub const RIGHT_PROMOTE: u32 = 0x200;
pub const RIGHT_PRIVILEGED: u32 =
    RIGHT_MINT | RIGHT_REVOKE | RIGHT_RECLAIM | RIGHT_EPOCH | RIGHT_CLOCK | RIGHT_PROMOTE;
pub const RIGHT_KNOWN: u32 =
    RIGHT_READ | RIGHT_WRITE | RIGHT_EFFECT | RIGHT_DELEGATE | RIGHT_PRIVILEGED;

pub const STATE_FREE: u32 = 0;
pub const STATE_LIVE: u32 = 1;
pub const STATE_REVOKED: u32 = 2;

pub const PARENT_NONE: u32 = u32::MAX;

static NEXT_BOOT_GEN: AtomicU32 = AtomicU32::new(1);

/// A 32-bit resource widened without dropping any bits.
pub const fn widen_resource(id: u32) -> u64 {
    id as u64
}

/// Narrow a resource only when the top half is zero. Anything else is refused
/// rather than silently truncated.
pub const fn narrow_resource(id: u64) -> Result<u32, i32> {
    if id > u32::MAX as u64 {
        Err(ERR_RESOURCE)
    } else {
        Ok(id as u32)
    }
}

pub const fn generation_advance(generation: u32) -> Result<u32, i32> {
    if generation == u32::MAX {
        Err(ERR_EXHAUSTED)
    } else {
        Ok(generation + 1)
    }
}

pub const fn add_u64(a: u64, b: u64) -> Result<u64, i32> {
    if b > u64::MAX - a {
        Err(ERR_OVERFLOW)
    } else {
        Ok(a + b)
    }
}

/// Take the next boot generation. A later authority starts higher, so a
/// reference from a stopped authority cannot validate against the new one.
pub fn take_boot_gen() -> Result<u32, i32> {
    let mut cur = NEXT_BOOT_GEN.load(Ordering::Relaxed);
    loop {
        if cur == 0 || cur == u32::MAX {
            return Err(ERR_EXHAUSTED);
        }
        match NEXT_BOOT_GEN.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
        {
            Ok(_) => return Ok(cur),
            Err(observed) => cur = observed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapRef {
    pub cap_id: u32,
    pub generation: u32,
}

impl CapRef {
    pub const NONE: Self = Self {
        cap_id: PARENT_NONE,
        generation: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub cap_id: u32,
    pub generation: u32,
    pub state: u32,
    pub issuer: u32,
    pub subject: u32,
    pub rights: u32,
    pub resource: u64,
    pub epoch: u64,
    pub lease_expiry: u64,
    pub parent_id: u32,
    pub parent_generation: u32,
    pub minted_by_id: u32,
    pub minted_by_generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mint {
    pub issuer: u32,
    pub subject: u32,
    pub resource: u64,
    pub rights: u32,
    pub lease_ticks: u64,
    pub parent: CapRef,
    pub authority: CapRef,
}

/// The table itself. Checking it does not confer the right to change it.
#[derive(Clone, Debug)]
pub struct AuthorityState {
    boot_gen: u32,
    epoch: u64,
    clock: u64,
    entries: [Entry; CAP_MAX],
    delivered: [bool; CAP_MAX],
    writer_alive: bool,
}

impl AuthorityState {
    pub fn bootstrap(boot_gen: u32) -> Result<Self, i32> {
        if boot_gen == 0 || boot_gen == u32::MAX {
            return Err(ERR_EXHAUSTED);
        }
        let mut entries = [Entry {
            cap_id: 0,
            generation: boot_gen,
            state: STATE_FREE,
            issuer: 0,
            subject: 0,
            rights: 0,
            resource: 0,
            epoch: 0,
            lease_expiry: 0,
            parent_id: PARENT_NONE,
            parent_generation: 0,
            minted_by_id: 0,
            minted_by_generation: 0,
        }; CAP_MAX];
        let mut i = 0;
        while i < CAP_MAX {
            entries[i].cap_id = i as u32;
            i += 1;
        }
        let mut state = Self {
            boot_gen,
            epoch: 1,
            clock: 0,
            entries,
            delivered: [false; CAP_MAX],
            writer_alive: true,
        };
        let office = &mut state.entries[0];
        office.state = STATE_LIVE;
        office.issuer = 0;
        office.subject = 0;
        office.resource = RES_AUTHORITY;
        office.rights = RIGHT_PRIVILEGED;
        office.epoch = 1;
        office.parent_id = PARENT_NONE;
        state.delivered[0] = true;
        Ok(state)
    }

    pub fn boot_gen(&self) -> u32 {
        self.boot_gen
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn clock(&self) -> u64 {
        self.clock
    }

    pub fn office(&self) -> CapRef {
        CapRef {
            cap_id: 0,
            generation: self.entries[0].generation,
        }
    }

    pub fn writer_alive(&self) -> bool {
        self.writer_alive
    }

    pub fn kill_writer(&mut self) {
        self.writer_alive = false;
    }

    pub fn inspect(&self, cap: CapRef) -> Result<Entry, i32> {
        if cap.cap_id as usize >= CAP_MAX {
            return Err(ERR_BOUNDS);
        }
        let entry = self.entries[cap.cap_id as usize];
        if entry.generation != cap.generation {
            return Err(ERR_STALE_GEN);
        }
        if entry.state == STATE_FREE {
            return Err(ERR_STATE);
        }
        Ok(entry)
    }

    pub fn validate(
        &self,
        cap: CapRef,
        subject: u32,
        resource: u64,
        rights: u32,
    ) -> Result<Entry, i32> {
        if cap.cap_id as usize >= CAP_MAX {
            return Err(ERR_BOUNDS);
        }
        let mut chain = [Entry {
            cap_id: 0,
            generation: 0,
            state: 0,
            issuer: 0,
            subject: 0,
            rights: 0,
            resource: 0,
            epoch: 0,
            lease_expiry: 0,
            parent_id: 0,
            parent_generation: 0,
            minted_by_id: 0,
            minted_by_generation: 0,
        }; (MAX_DEPTH as usize) + 1];
        let mut n = 0u32;
        let mut id = cap.cap_id;
        while id != PARENT_NONE {
            if n > MAX_DEPTH || id as usize >= CAP_MAX {
                return Err(ERR_CHAIN);
            }
            chain[n as usize] = self.entries[id as usize];
            id = chain[n as usize].parent_id;
            n += 1;
        }
        let entry = chain[0];
        if entry.generation != cap.generation {
            return Err(ERR_STALE_GEN);
        }
        if entry.state != STATE_LIVE {
            return Err(ERR_REVOKED);
        }
        if entry.epoch != self.epoch {
            return Err(ERR_EPOCH);
        }
        if entry.lease_expiry != 0 && self.clock >= entry.lease_expiry {
            return Err(ERR_EXPIRED);
        }
        let mut i = 1u32;
        while i < n {
            let parent = chain[i as usize];
            let child = chain[(i - 1) as usize];
            if parent.generation != child.parent_generation {
                return Err(ERR_CHAIN);
            }
            if parent.state != STATE_LIVE {
                return Err(ERR_CHAIN);
            }
            if parent.epoch != self.epoch {
                return Err(ERR_CHAIN);
            }
            if parent.lease_expiry != 0 && self.clock >= parent.lease_expiry {
                return Err(ERR_CHAIN);
            }
            i += 1;
        }
        if entry.subject != subject {
            return Err(ERR_SUBJECT);
        }
        if entry.resource != resource {
            return Err(ERR_RESOURCE);
        }
        if entry.rights & rights != rights {
            return Err(ERR_RIGHTS);
        }
        Ok(entry)
    }

    fn chain_ok(&self, mut entry_id: u32) -> Result<(), i32> {
        let mut depth = 0u32;
        loop {
            let entry = self.entries[entry_id as usize];
            if entry.parent_id == PARENT_NONE {
                return Ok(());
            }
            depth += 1;
            if depth > MAX_DEPTH {
                return Err(ERR_CHAIN);
            }
            if entry.parent_id as usize >= CAP_MAX {
                return Err(ERR_CHAIN);
            }
            let parent = self.entries[entry.parent_id as usize];
            if parent.generation != entry.parent_generation || parent.state != STATE_LIVE {
                return Err(ERR_CHAIN);
            }
            entry_id = entry.parent_id;
        }
    }

    fn ancestor_hops(&self, mut entry_id: u32) -> u32 {
        let mut hops = 0u32;
        loop {
            let entry = self.entries[entry_id as usize];
            if entry.parent_id == PARENT_NONE || hops > MAX_DEPTH {
                return hops;
            }
            if entry.parent_id as usize >= CAP_MAX {
                return MAX_DEPTH + 1;
            }
            hops += 1;
            entry_id = entry.parent_id;
        }
    }

    fn auth_use(&self, authority: CapRef, need: u32) -> Result<usize, i32> {
        if authority.cap_id as usize >= CAP_MAX {
            return Err(ERR_UNAUTHORIZED);
        }
        let index = authority.cap_id as usize;
        if !self.delivered[index] {
            return Err(ERR_UNAUTHORIZED);
        }
        let entry = self.entries[index];
        if entry.generation != authority.generation {
            return Err(ERR_STALE_GEN);
        }
        if entry.state != STATE_LIVE {
            return Err(ERR_REVOKED);
        }
        if entry.epoch != self.epoch {
            return Err(ERR_EPOCH);
        }
        if entry.lease_expiry != 0 && self.clock >= entry.lease_expiry {
            return Err(ERR_EXPIRED);
        }
        self.chain_ok(authority.cap_id)?;
        if entry.rights & need != need {
            return Err(ERR_UNAUTHORIZED);
        }
        Ok(index)
    }

    fn lease_expiry(&self, ticks: u64) -> Result<u64, i32> {
        if ticks == 0 {
            Ok(0)
        } else {
            add_u64(self.clock, ticks)
        }
    }

    pub fn mint(&mut self, request: Mint) -> Result<CapRef, i32> {
        if !self.writer_alive {
            return Err(ERR_IO);
        }
        if request.rights == 0 || request.rights & !RIGHT_KNOWN != 0 {
            return Err(ERR_RIGHTS);
        }
        if request.rights & RIGHT_PRIVILEGED != 0 && request.rights & RIGHT_DELEGATE != 0 {
            return Err(ERR_NOT_DELEGABLE);
        }
        let auth_index = if request.parent.cap_id == PARENT_NONE {
            let index = self.auth_use(request.authority, RIGHT_MINT)?;
            let auth = self.entries[index];
            if (request.rights & RIGHT_PRIVILEGED) & !auth.rights != 0 {
                return Err(ERR_UNAUTHORIZED);
            }
            index
        } else {
            if request.authority.cap_id != request.parent.cap_id
                || request.authority.generation != request.parent.generation
            {
                return Err(ERR_UNAUTHORIZED);
            }
            let index = self.auth_use(request.authority, 0)?;
            let auth = self.entries[index];
            if auth.rights & RIGHT_DELEGATE == 0 {
                return Err(ERR_NOT_DELEGABLE);
            }
            if request.parent.cap_id as usize >= CAP_MAX {
                return Err(ERR_BOUNDS);
            }
            if auth.resource != request.resource {
                return Err(ERR_RESOURCE);
            }
            if request.rights & !auth.rights != 0 {
                return Err(ERR_AMPLIFY);
            }
            if request.rights & RIGHT_PRIVILEGED != 0 {
                return Err(ERR_NOT_DELEGABLE);
            }
            if self.ancestor_hops(request.parent.cap_id) >= MAX_DEPTH {
                return Err(ERR_CHAIN);
            }
            if auth.lease_expiry != 0 {
                let child = self.lease_expiry(request.lease_ticks)?;
                if child == 0 || child > auth.lease_expiry {
                    return Err(ERR_AMPLIFY);
                }
            }
            index
        };
        let expiry = self.lease_expiry(request.lease_ticks)?;
        let auth = self.entries[auth_index];
        let mut saw_exhausted = false;
        let mut i = 0usize;
        while i < CAP_MAX {
            if self.entries[i].state == STATE_FREE {
                if self.entries[i].generation == u32::MAX {
                    saw_exhausted = true;
                } else {
                    let entry = &mut self.entries[i];
                    entry.state = STATE_LIVE;
                    entry.issuer = request.issuer;
                    entry.subject = request.subject;
                    entry.resource = request.resource;
                    entry.rights = request.rights;
                    entry.epoch = self.epoch;
                    entry.lease_expiry = expiry;
                    entry.parent_id = request.parent.cap_id;
                    entry.parent_generation = if request.parent.cap_id == PARENT_NONE {
                        0
                    } else {
                        request.parent.generation
                    };
                    entry.minted_by_id = auth.cap_id;
                    entry.minted_by_generation = auth.generation;
                    self.delivered[i] = true;
                    return Ok(CapRef {
                        cap_id: entry.cap_id,
                        generation: entry.generation,
                    });
                }
            }
            i += 1;
        }
        Err(if saw_exhausted {
            ERR_EXHAUSTED
        } else {
            ERR_FULL
        })
    }

    fn cascade_revoke(&mut self) {
        let mut guard = 0;
        loop {
            if guard >= CAP_MAX {
                break;
            }
            guard += 1;
            let mut changed = false;
            let mut i = 0usize;
            while i < CAP_MAX {
                let parent_id = self.entries[i].parent_id;
                let live = self.entries[i].state == STATE_LIVE && parent_id != PARENT_NONE;
                if live && (parent_id as usize) < CAP_MAX {
                    let parent = self.entries[parent_id as usize];
                    if parent.generation == self.entries[i].parent_generation
                        && parent.state == STATE_REVOKED
                    {
                        self.entries[i].state = STATE_REVOKED;
                        changed = true;
                    }
                }
                i += 1;
            }
            if !changed {
                break;
            }
        }
    }

    pub fn revoke(&mut self, authority: CapRef, target: CapRef) -> Result<(), i32> {
        if !self.writer_alive {
            return Err(ERR_IO);
        }
        let auth_index = self.auth_use(authority, RIGHT_REVOKE)?;
        if target.cap_id as usize >= CAP_MAX {
            return Err(ERR_BOUNDS);
        }
        let auth_rights = self.entries[auth_index].rights;
        let entry = &mut self.entries[target.cap_id as usize];
        if entry.generation != target.generation {
            return Err(ERR_STALE_GEN);
        }
        if entry.state != STATE_LIVE {
            return Err(ERR_STATE);
        }
        if (entry.rights & RIGHT_PRIVILEGED) & !auth_rights != 0 {
            return Err(ERR_UNAUTHORIZED);
        }
        entry.state = STATE_REVOKED;
        self.cascade_revoke();
        Ok(())
    }

    pub fn reclaim(&mut self, authority: CapRef, cap_id: u32) -> Result<(), i32> {
        if !self.writer_alive {
            return Err(ERR_IO);
        }
        self.auth_use(authority, RIGHT_RECLAIM)?;
        if cap_id as usize >= CAP_MAX {
            return Err(ERR_BOUNDS);
        }
        let entry = &mut self.entries[cap_id as usize];
        if entry.state != STATE_REVOKED {
            return Err(ERR_STATE);
        }
        let next = generation_advance(entry.generation)?;
        entry.generation = next;
        entry.state = STATE_FREE;
        entry.rights = 0;
        entry.lease_expiry = 0;
        entry.parent_id = PARENT_NONE;
        entry.parent_generation = 0;
        self.delivered[cap_id as usize] = false;
        Ok(())
    }

    pub fn advance_clock(&mut self, authority: CapRef, ticks: u64) -> Result<(), i32> {
        if !self.writer_alive {
            return Err(ERR_IO);
        }
        self.auth_use(authority, RIGHT_CLOCK)?;
        self.clock = add_u64(self.clock, ticks)?;
        Ok(())
    }

    pub fn bump_epoch(&mut self, authority: CapRef) -> Result<(), i32> {
        if !self.writer_alive {
            return Err(ERR_IO);
        }
        self.auth_use(authority, RIGHT_EPOCH)?;
        self.epoch = add_u64(self.epoch, 1)?;
        Ok(())
    }

    /// Test seam. Puts a free or revoked slot on a chosen generation so the
    /// exhaustion rule can be shown without four billion reclamations.
    /// Refuses a live slot, so it cannot mint a forged generation.
    pub fn set_generation_for_test(&mut self, cap_id: u32, generation: u32) -> Result<(), i32> {
        if cap_id as usize >= CAP_MAX {
            return Err(ERR_BOUNDS);
        }
        let entry = &mut self.entries[cap_id as usize];
        if entry.state == STATE_LIVE {
            return Err(ERR_STATE);
        }
        if generation == 0 {
            return Err(ERR_EXHAUSTED);
        }
        entry.generation = generation;
        Ok(())
    }
}

/// Read-only handle. Cognition and the reaction world may hold this.
/// It has no office token and no operation that changes the table.
#[derive(Clone, Copy)]
pub struct AuthorityView<'a> {
    state: &'a AuthorityState,
}

impl<'a> AuthorityView<'a> {
    pub fn new(state: &'a AuthorityState) -> Self {
        Self { state }
    }

    pub fn inspect(self, cap: CapRef) -> Result<Entry, i32> {
        self.state.inspect(cap)
    }

    pub fn validate(
        self,
        cap: CapRef,
        subject: u32,
        resource: u64,
        rights: u32,
    ) -> Result<Entry, i32> {
        self.state.validate(cap, subject, resource, rights)
    }

    /// The only mint-shaped call cognition is allowed to make. It does not
    /// look at the table and it does not change it.
    pub fn cognition_attempt_mint(self, _request: Mint) -> i32 {
        ERR_UNAUTHORIZED
    }

    pub fn cognition_attempt_revoke(self, _authority: CapRef, _target: CapRef) -> i32 {
        ERR_UNAUTHORIZED
    }

    pub fn cognition_attempt_reclaim(self, _authority: CapRef, _cap_id: u32) -> i32 {
        ERR_UNAUTHORIZED
    }

    pub fn cognition_attempt_clock(self, _authority: CapRef, _ticks: u64) -> i32 {
        ERR_UNAUTHORIZED
    }

    pub fn cognition_attempt_epoch(self, _authority: CapRef) -> i32 {
        ERR_UNAUTHORIZED
    }
}

/// Office holder. The token never enters [`AuthorityState`].
pub struct AuthorityAdmin {
    token: [u8; TOKEN_LEN],
}

impl AuthorityAdmin {
    pub fn new(token: [u8; TOKEN_LEN]) -> Self {
        Self { token }
    }

    pub fn token_matches(&self, presented: &[u8; TOKEN_LEN]) -> bool {
        let mut diff = 0u8;
        let mut i = 0;
        while i < TOKEN_LEN {
            diff |= self.token[i] ^ presented[i];
            i += 1;
        }
        diff == 0
    }

    pub fn authorize(&self, presented: &[u8; TOKEN_LEN]) -> Result<(), i32> {
        if self.token_matches(presented) {
            Ok(())
        } else {
            Err(ERR_UNAUTHORIZED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot() -> AuthorityState {
        AuthorityState::bootstrap(1).unwrap()
    }

    fn office(state: &AuthorityState) -> CapRef {
        state.office()
    }

    fn root_mint(
        state: &mut AuthorityState,
        subject: u32,
        resource: u64,
        rights: u32,
    ) -> Result<CapRef, i32> {
        state.mint(Mint {
            issuer: 3,
            subject,
            resource,
            rights,
            lease_ticks: 0,
            parent: CapRef::NONE,
            authority: office(state),
        })
    }

    #[test]
    fn high_half_resource_is_kept() {
        let wide = (1u64 << 32) | 0x51;
        assert_eq!(narrow_resource(wide), Err(ERR_RESOURCE));
        assert_eq!(widen_resource(0x51), 0x51);
        let mut state = boot();
        let cap = root_mint(&mut state, 1, wide, RIGHT_READ).unwrap();
        assert!(state.validate(cap, 1, wide, RIGHT_READ).is_ok());
        assert_eq!(
            state.validate(cap, 1, 0x51, RIGHT_READ).unwrap_err(),
            ERR_RESOURCE
        );
    }

    #[test]
    fn forged_stale_subject_resource_and_rights_fail_closed() {
        let mut state = boot();
        let cap = root_mint(&mut state, 1, 0x20, RIGHT_WRITE).unwrap();
        assert_eq!(
            state
                .validate(
                    CapRef {
                        cap_id: 200,
                        generation: 7
                    },
                    1,
                    0x20,
                    RIGHT_WRITE
                )
                .unwrap_err(),
            ERR_STALE_GEN
        );
        assert_eq!(
            state
                .validate(
                    CapRef {
                        cap_id: 300,
                        generation: 1
                    },
                    1,
                    0x20,
                    RIGHT_WRITE
                )
                .unwrap_err(),
            ERR_BOUNDS
        );
        state.revoke(office(&state), cap).unwrap();
        state.reclaim(office(&state), cap.cap_id).unwrap();
        let reused = root_mint(&mut state, 7, 0x20, RIGHT_WRITE).unwrap();
        assert_eq!(reused.cap_id, cap.cap_id);
        assert_eq!(reused.generation, cap.generation + 1);
        assert_eq!(
            state.validate(cap, 1, 0x20, RIGHT_WRITE).unwrap_err(),
            ERR_STALE_GEN
        );
        let live = root_mint(&mut state, 1, 0x20, RIGHT_READ).unwrap();
        assert_eq!(
            state.validate(live, 9, 0x20, RIGHT_READ).unwrap_err(),
            ERR_SUBJECT
        );
        assert_eq!(
            state.validate(live, 1, 0x30, RIGHT_READ).unwrap_err(),
            ERR_RESOURCE
        );
        assert_eq!(
            state.validate(live, 1, 0x20, RIGHT_WRITE).unwrap_err(),
            ERR_RIGHTS
        );
    }

    #[test]
    fn amplification_lease_epoch_and_revoked_ancestor_fail() {
        let mut state = boot();
        let parent = root_mint(&mut state, 1, 0x20, RIGHT_READ | RIGHT_DELEGATE).unwrap();
        let amplify = state.mint(Mint {
            issuer: 1,
            subject: 2,
            resource: 0x20,
            rights: RIGHT_READ | RIGHT_WRITE,
            lease_ticks: 0,
            parent,
            authority: parent,
        });
        assert_eq!(amplify.unwrap_err(), ERR_AMPLIFY);
        let child = state
            .mint(Mint {
                issuer: 1,
                subject: 2,
                resource: 0x20,
                rights: RIGHT_READ,
                lease_ticks: 0,
                parent,
                authority: parent,
            })
            .unwrap();
        state.revoke(office(&state), parent).unwrap();
        assert_eq!(state.inspect(child).unwrap().state, STATE_REVOKED);
        assert_eq!(
            state.validate(child, 2, 0x20, RIGHT_READ).unwrap_err(),
            ERR_REVOKED
        );

        let mut state = boot();
        let leased = state
            .mint(Mint {
                issuer: 3,
                subject: 1,
                resource: 0x10,
                rights: RIGHT_READ,
                lease_ticks: 5,
                parent: CapRef::NONE,
                authority: office(&state),
            })
            .unwrap();
        state.advance_clock(office(&state), 10).unwrap();
        assert_eq!(
            state.validate(leased, 1, 0x10, RIGHT_READ).unwrap_err(),
            ERR_EXPIRED
        );

        let fresh = root_mint(&mut state, 1, 0x10, RIGHT_READ).unwrap();
        state.bump_epoch(office(&state)).unwrap();
        assert_eq!(
            state.validate(fresh, 1, 0x10, RIGHT_READ).unwrap_err(),
            ERR_EPOCH
        );
        assert_eq!(state.bump_epoch(office(&state)).unwrap_err(), ERR_EPOCH);
    }

    #[test]
    fn privileged_rights_cannot_be_delegated_and_office_stays() {
        let mut state = boot();
        let both = root_mint(&mut state, 1, RES_AUTHORITY, RIGHT_REVOKE | RIGHT_DELEGATE);
        assert_eq!(both.unwrap_err(), ERR_NOT_DELEGABLE);
        let revoker = root_mint(&mut state, 1, RES_AUTHORITY, RIGHT_REVOKE).unwrap();
        let passed = state.mint(Mint {
            issuer: 3,
            subject: 2,
            resource: RES_AUTHORITY,
            rights: RIGHT_REVOKE,
            lease_ticks: 0,
            parent: revoker,
            authority: revoker,
        });
        assert_eq!(passed.unwrap_err(), ERR_NOT_DELEGABLE);
        assert_eq!(
            state.revoke(revoker, office(&state)).unwrap_err(),
            ERR_UNAUTHORIZED
        );
        assert!(state
            .validate(office(&state), 0, RES_AUTHORITY, RIGHT_MINT)
            .is_ok());
    }

    #[test]
    fn promote_right_cannot_be_delegated() {
        let mut state = boot();
        let combined = root_mint(&mut state, 4, 0x905, RIGHT_PROMOTE | RIGHT_DELEGATE);
        assert_eq!(combined.unwrap_err(), ERR_NOT_DELEGABLE);
        let promoter = root_mint(&mut state, 4, 0x905, RIGHT_PROMOTE).unwrap();
        let handed_on = state.mint(Mint {
            issuer: 4,
            subject: 5,
            resource: 0x905,
            rights: RIGHT_PROMOTE,
            lease_ticks: 0,
            parent: promoter,
            authority: promoter,
        });
        assert_eq!(handed_on.unwrap_err(), ERR_NOT_DELEGABLE);
        assert!(state.validate(promoter, 4, 0x905, RIGHT_PROMOTE).is_ok());
        assert_eq!(
            state
                .validate(promoter, 9, 0x905, RIGHT_PROMOTE)
                .unwrap_err(),
            ERR_SUBJECT
        );
    }

    #[test]
    fn generation_wrap_restarts_and_cognition_cannot_mint() {
        assert_eq!(generation_advance(u32::MAX).unwrap_err(), ERR_EXHAUSTED);
        let mut state = boot();
        let cap = root_mint(&mut state, 1, 0x10, RIGHT_READ).unwrap();
        state.revoke(office(&state), cap).unwrap();
        state.set_generation_for_test(cap.cap_id, u32::MAX).unwrap();
        assert_eq!(
            state.reclaim(office(&state), cap.cap_id).unwrap_err(),
            ERR_EXHAUSTED
        );
        assert_eq!(
            state.validate(cap, 1, 0x10, RIGHT_READ).unwrap_err(),
            ERR_STALE_GEN
        );
        let replacement = root_mint(&mut state, 1, 0x11, RIGHT_READ).unwrap();
        assert_ne!(replacement.cap_id, cap.cap_id);

        let old = root_mint(&mut state, 1, 0x12, RIGHT_READ).unwrap();
        state.kill_writer();
        assert_eq!(
            root_mint(&mut state, 1, 0x13, RIGHT_READ).unwrap_err(),
            ERR_IO
        );
        let recovered = AuthorityState::bootstrap(state.boot_gen() + 1).unwrap();
        assert_eq!(
            recovered.validate(old, 1, 0x12, RIGHT_READ).unwrap_err(),
            ERR_STALE_GEN
        );
        assert_ne!(
            recovered
                .validate(state.office(), 0, RES_AUTHORITY, RIGHT_MINT)
                .unwrap_err(),
            OK
        );

        let view = AuthorityView::new(&recovered);
        let before = recovered.clock();
        assert_eq!(
            view.cognition_attempt_mint(Mint {
                issuer: 1,
                subject: 1,
                resource: 1,
                rights: RIGHT_READ,
                lease_ticks: 0,
                parent: CapRef::NONE,
                authority: recovered.office(),
            }),
            ERR_UNAUTHORIZED
        );
        assert_eq!(
            view.cognition_attempt_revoke(recovered.office(), old),
            ERR_UNAUTHORIZED
        );
        assert_eq!(
            view.cognition_attempt_epoch(recovered.office()),
            ERR_UNAUTHORIZED
        );
        assert_eq!(recovered.clock(), before);
        let admin = AuthorityAdmin::new([9; TOKEN_LEN]);
        assert_eq!(
            admin.authorize(&[0; TOKEN_LEN]).unwrap_err(),
            ERR_UNAUTHORIZED
        );
        assert!(admin.authorize(&[9; TOKEN_LEN]).is_ok());
    }

    #[test]
    fn ordinary_capability_cannot_administer_and_depth_stops() {
        let mut state = boot();
        let world = root_mint(&mut state, 1, 0x10, RIGHT_READ).unwrap();
        assert_eq!(state.revoke(world, world).unwrap_err(), ERR_UNAUTHORIZED);
        assert_eq!(state.advance_clock(world, 1).unwrap_err(), ERR_UNAUTHORIZED);
        assert_eq!(state.bump_epoch(world).unwrap_err(), ERR_UNAUTHORIZED);
        assert_eq!(
            state.reclaim(world, world.cap_id).unwrap_err(),
            ERR_UNAUTHORIZED
        );
        let mut cur = root_mint(&mut state, 1, 0x20, RIGHT_READ | RIGHT_DELEGATE).unwrap();
        for _ in 0..8 {
            cur = state
                .mint(Mint {
                    issuer: 3,
                    subject: 2,
                    resource: 0x20,
                    rights: RIGHT_READ | RIGHT_DELEGATE,
                    lease_ticks: 0,
                    parent: cur,
                    authority: cur,
                })
                .unwrap();
        }
        let too_deep = state.mint(Mint {
            issuer: 3,
            subject: 2,
            resource: 0x20,
            rights: RIGHT_READ | RIGHT_DELEGATE,
            lease_ticks: 0,
            parent: cur,
            authority: cur,
        });
        assert_eq!(too_deep.unwrap_err(), ERR_CHAIN);
    }
}
