//! Fixed-capacity resource accounting and watchdog policy for isolated Worlds.
//!
//! This module has no hardware dependencies. A caller supplies counter ticks
//! and performs the actual revocation and restoration around these decisions.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceEnvelope {
    pub cpu_ticks_per_period: u64,
    pub memory_frames_limit: u64,
    pub dma_window_bytes_limit: u64,
    /// Maximum counter ticks from admission until the World deadline.
    pub max_runtime_ticks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceLimit {
    CpuTicks,
    MemoryFrames,
    DmaBytes,
    RuntimeDeadline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    Full,
    DuplicateWorld,
    UnknownWorld,
    Exceeded(ResourceLimit),
    Quarantined,
    InvalidRelease,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorldState {
    Active,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetMode {
    Active,
    Idle,
    Urgent,
}

/// Owner-priority scaling for Forge CPU budgets. Urgent is a temporary
/// elevated allowance and may exceed the admitted base CPU allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetPolicy {
    mode: BudgetMode,
}

impl BudgetPolicy {
    pub const fn new() -> Self {
        Self {
            mode: BudgetMode::Active,
        }
    }

    pub const fn mode(self) -> BudgetMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: BudgetMode) {
        self.mode = mode;
    }

    const fn allowance(self, base: u64) -> u64 {
        let (whole, remainder, divisor) = match self.mode {
            BudgetMode::Active => (0, 100, 1000),
            BudgetMode::Idle => (0, 800, 1000),
            BudgetMode::Urgent => (1, 500, 1000),
        };
        base.saturating_mul(whole)
            .saturating_add((base / divisor) * remainder)
            .saturating_add(((base % divisor) * remainder) / divisor)
    }
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorldBudget {
    id: u32,
    envelope: ResourceEnvelope,
    forge: bool,
    cpu_used: u64,
    frames_used: u64,
    dma_used: u64,
    /// Counter value when the watchdog was last armed (admit, pet, restore).
    armed_at: u64,
    state: WorldState,
}

/// Resource budgets and per-World watchdogs with caller-chosen fixed capacity.
pub struct BudgetManager<const WORLDS: usize> {
    worlds: [Option<WorldBudget>; WORLDS],
    policy: BudgetPolicy,
}

impl<const WORLDS: usize> BudgetManager<WORLDS> {
    pub const fn new() -> Self {
        Self {
            worlds: [None; WORLDS],
            policy: BudgetPolicy::new(),
        }
    }

    /// Admit a World. Deadline addition saturates to avoid wrapping a counter.
    pub fn admit(
        &mut self,
        id: u32,
        envelope: ResourceEnvelope,
        forge: bool,
        now: u64,
    ) -> Result<(), BudgetError> {
        if self.worlds.iter().flatten().any(|w| w.id == id) {
            return Err(BudgetError::DuplicateWorld);
        }
        let slot = self
            .worlds
            .iter()
            .position(Option::is_none)
            .ok_or(BudgetError::Full)?;
        self.worlds[slot] = Some(WorldBudget {
            id,
            envelope,
            forge,
            cpu_used: 0,
            frames_used: 0,
            dma_used: 0,
            armed_at: now,
            state: WorldState::Active,
        });
        Ok(())
    }

    /// Remove an explicitly stopped World and free its fixed slot.
    pub fn remove(&mut self, id: u32) -> Result<(), BudgetError> {
        let slot = self.slot(id)?;
        self.worlds[slot] = None;
        Ok(())
    }

    /// Start a new CPU accounting period for every active World.
    pub fn begin_period(&mut self) {
        for world in self.worlds.iter_mut().flatten() {
            if world.state == WorldState::Active {
                world.cpu_used = 0;
            }
        }
    }

    pub fn set_mode(&mut self, mode: BudgetMode) {
        self.policy.set_mode(mode);
    }
    pub const fn mode(&self) -> BudgetMode {
        self.policy.mode()
    }

    pub fn cpu_allowance(&self, id: u32) -> Result<u64, BudgetError> {
        let world = self.world(id)?;
        Ok(if world.forge {
            self.policy.allowance(world.envelope.cpu_ticks_per_period)
        } else {
            world.envelope.cpu_ticks_per_period
        })
    }

    pub fn state(&self, id: u32) -> Result<WorldState, BudgetError> {
        Ok(self.world(id)?.state)
    }

    pub fn charge_cpu(&mut self, id: u32, ticks: u64) -> Result<(), BudgetError> {
        let allowance = self.cpu_allowance(id)?;
        let world = self.world_mut(id)?;
        let next = world
            .cpu_used
            .checked_add(ticks)
            .ok_or(BudgetError::Exceeded(ResourceLimit::CpuTicks))?;
        if next > allowance {
            return Err(BudgetError::Exceeded(ResourceLimit::CpuTicks));
        }
        world.cpu_used = next;
        Ok(())
    }

    pub fn charge_frames(&mut self, id: u32, frames: u64) -> Result<(), BudgetError> {
        let world = self.world_mut(id)?;
        let next = world
            .frames_used
            .checked_add(frames)
            .ok_or(BudgetError::Exceeded(ResourceLimit::MemoryFrames))?;
        if next > world.envelope.memory_frames_limit {
            return Err(BudgetError::Exceeded(ResourceLimit::MemoryFrames));
        }
        world.frames_used = next;
        Ok(())
    }

    pub fn release_frames(&mut self, id: u32, frames: u64) -> Result<(), BudgetError> {
        let world = self.world_mut(id)?;
        if frames > world.frames_used {
            return Err(BudgetError::InvalidRelease);
        }
        world.frames_used -= frames;
        Ok(())
    }

    pub fn charge_dma(&mut self, id: u32, bytes: u64) -> Result<(), BudgetError> {
        let world = self.world_mut(id)?;
        let next = world
            .dma_used
            .checked_add(bytes)
            .ok_or(BudgetError::Exceeded(ResourceLimit::DmaBytes))?;
        if next > world.envelope.dma_window_bytes_limit {
            return Err(BudgetError::Exceeded(ResourceLimit::DmaBytes));
        }
        world.dma_used = next;
        Ok(())
    }

    /// Pet an active World, extending its watchdog deadline from `now`.
    pub fn pet(&mut self, id: u32, now: u64) -> Result<(), BudgetError> {
        let world = self.world_mut(id)?;
        world.armed_at = now;
        Ok(())
    }

    /// Quarantine overdue Worlds and return their IDs. Quarantine is sticky.
    pub fn check(&mut self, now: u64) -> [Option<u32>; WORLDS] {
        let mut expired = [None; WORLDS];
        for (index, entry) in self.worlds.iter_mut().enumerate() {
            if let Some(world) = entry {
                // Elapsed time with wrapping arithmetic stays correct across a
                // counter wrap (a saturating deadline expired early near u64::MAX).
                if world.state == WorldState::Active
                    && now.wrapping_sub(world.armed_at) >= world.envelope.max_runtime_ticks
                {
                    world.state = WorldState::Quarantined;
                    expired[index] = Some(world.id);
                }
            }
        }
        expired
    }

    /// Explicitly restore a quarantined World from its admitted envelope.
    /// Call only after the owner/caller restored its last known-good state.
    pub fn restore(&mut self, id: u32, now: u64) -> Result<(), BudgetError> {
        let world = self.world_mut_allow_quarantined(id)?;
        world.cpu_used = 0;
        world.frames_used = 0;
        world.dma_used = 0;
        world.armed_at = now;
        world.state = WorldState::Active;
        Ok(())
    }

    fn slot(&self, id: u32) -> Result<usize, BudgetError> {
        self.worlds
            .iter()
            .position(|w| w.is_some_and(|w| w.id == id))
            .ok_or(BudgetError::UnknownWorld)
    }
    fn world(&self, id: u32) -> Result<&WorldBudget, BudgetError> {
        self.worlds[self.slot(id)?]
            .as_ref()
            .ok_or(BudgetError::UnknownWorld)
    }
    fn world_mut_allow_quarantined(&mut self, id: u32) -> Result<&mut WorldBudget, BudgetError> {
        let slot = self.slot(id)?;
        self.worlds[slot].as_mut().ok_or(BudgetError::UnknownWorld)
    }
    fn world_mut(&mut self, id: u32) -> Result<&mut WorldBudget, BudgetError> {
        let world = self.world_mut_allow_quarantined(id)?;
        if world.state == WorldState::Quarantined {
            return Err(BudgetError::Quarantined);
        }
        Ok(world)
    }
}

impl<const WORLDS: usize> Default for BudgetManager<WORLDS> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> ResourceEnvelope {
        ResourceEnvelope {
            cpu_ticks_per_period: 100,
            memory_frames_limit: 4,
            dma_window_bytes_limit: 32,
            max_runtime_ticks: 10,
        }
    }
    fn manager() -> BudgetManager<2> {
        let mut manager = BudgetManager::new();
        manager.admit(7, envelope(), false, 0).unwrap();
        manager
    }

    #[test]
    fn each_resource_limit_is_enforced_independently() {
        let mut m = manager();
        assert_eq!(
            m.charge_cpu(7, 101),
            Err(BudgetError::Exceeded(ResourceLimit::CpuTicks))
        );
        assert_eq!(
            m.charge_frames(7, 5),
            Err(BudgetError::Exceeded(ResourceLimit::MemoryFrames))
        );
        assert_eq!(
            m.charge_dma(7, 33),
            Err(BudgetError::Exceeded(ResourceLimit::DmaBytes))
        );
    }

    #[test]
    fn releasing_frames_restores_headroom() {
        let mut m = manager();
        m.charge_frames(7, 4).unwrap();
        m.release_frames(7, 2).unwrap();
        m.charge_frames(7, 2).unwrap();
        assert_eq!(m.release_frames(7, 5), Err(BudgetError::InvalidRelease));
    }

    #[test]
    fn watchdog_pet_expiry_and_sticky_quarantine() {
        let mut m = manager();
        assert_eq!(m.check(9), [None, None]);
        m.pet(7, 8).unwrap();
        assert_eq!(m.check(17), [None, None]);
        assert_eq!(m.check(18), [Some(7), None]);
        assert_eq!(m.charge_cpu(7, 1), Err(BudgetError::Quarantined));
        assert_eq!(m.pet(7, 20), Err(BudgetError::Quarantined));
        assert_eq!(m.state(7), Ok(WorldState::Quarantined));
        m.restore(7, 20).unwrap();
        assert_eq!(m.state(7), Ok(WorldState::Active));
    }

    #[test]
    fn explicit_policy_switch_changes_forge_allowance() {
        let mut m = BudgetManager::<1>::new();
        m.admit(1, envelope(), true, 0).unwrap();
        assert_eq!(m.cpu_allowance(1), Ok(10));
        m.set_mode(BudgetMode::Idle);
        assert_eq!(m.cpu_allowance(1), Ok(80));
        m.set_mode(BudgetMode::Urgent);
        assert_eq!(m.cpu_allowance(1), Ok(150));
    }

    #[test]
    fn arithmetic_is_overflow_safe_at_u64_limits() {
        let mut m = BudgetManager::<1>::new();
        let max = ResourceEnvelope {
            cpu_ticks_per_period: u64::MAX,
            memory_frames_limit: u64::MAX,
            dma_window_bytes_limit: u64::MAX,
            max_runtime_ticks: u64::MAX,
        };
        m.admit(1, max, false, u64::MAX - 1).unwrap();
        assert_eq!(m.charge_cpu(1, u64::MAX), Ok(()));
        assert_eq!(
            m.charge_cpu(1, 1),
            Err(BudgetError::Exceeded(ResourceLimit::CpuTicks))
        );
        assert_eq!(m.charge_frames(1, u64::MAX), Ok(()));
        assert_eq!(
            m.charge_frames(1, 1),
            Err(BudgetError::Exceeded(ResourceLimit::MemoryFrames))
        );
        assert_eq!(m.charge_dma(1, u64::MAX), Ok(()));
        assert_eq!(
            m.charge_dma(1, 1),
            Err(BudgetError::Exceeded(ResourceLimit::DmaBytes))
        );
        // One tick of a u64::MAX runtime budget has elapsed: not expired. (The
        // saturating-deadline draft reported expiry here; that was the wrap bug.)
        assert_eq!(m.check(u64::MAX), [None]);
        assert_eq!(m.cpu_allowance(1), Ok(u64::MAX));
    }
    #[test]
    fn watchdog_is_correct_across_counter_wrap() {
        // Review regression: admitted at u64::MAX - 4 with a 10-tick runtime must
        // survive until 10 ticks have elapsed, even though the counter wraps.
        let start = u64::MAX - 4;
        let mut manager = BudgetManager::<4>::new();
        let envelope = ResourceEnvelope {
            max_runtime_ticks: 10,
            ..envelope()
        };
        manager.admit(1, envelope, false, start).unwrap();
        let expired = |r: [Option<u32>; 4]| r.iter().flatten().count();
        assert_eq!(expired(manager.check(u64::MAX)), 0, "4 ticks elapsed");
        assert_eq!(
            expired(manager.check(start.wrapping_add(9))),
            0,
            "9 ticks elapsed"
        );
        assert_eq!(
            expired(manager.check(start.wrapping_add(10))),
            1,
            "10 ticks: expired"
        );
    }
}
