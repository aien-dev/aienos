//! Device authority: a device may only move memory (DMA) while a capability
//! says it may.
//!
//! # The security invariant
//!
//! Device authority and capability authority are the same boundary. A device
//! can reach memory only through two gates that the kernel controls:
//!
//! 1. The IOMMU (SMMU) stream table entry for the device's stream. Until the
//!    kernel installs a translation window there, every DMA the device issues
//!    is aborted by the IOMMU.
//! 2. The PCI bus master enable (BME) bit. While it is clear, the device
//!    cannot start DMA at all.
//!
//! This module is the only code that opens those gates, and it opens them only
//! when a capability that names the device and carries the `MAP` right is
//! presented. It opens the IOMMU gate first and the BME gate second, so there
//! is never a moment where the device can issue DMA that the IOMMU would not
//! confine.
//!
//! Revocation closes the gates in the reverse order: stop handing the device
//! new work, clear BME, quiesce or reset the device, set the stream to ABORT,
//! invalidate any cached translations, and only then remove the capability
//! and everything derived from it. Taking authority away never depends on the
//! device cooperating: if a hardware step fails, the remaining steps still
//! run, so BME ends clear and the stream ends aborted wherever the hardware
//! allows, and the error is reported.
//!
//! Every authority check happens before any hardware effect. A missing,
//! stale, or under-privileged capability causes no hardware effect at all.
//!
//! An active device remembers which capability activated it. If that
//! capability disappears by any route other than [`revoke_device`] (the
//! holder removes it, an ancestor is revoked with plain [`CapTable::revoke`],
//! or the holder's table is destroyed), the kernel calls
//! [`DeviceTable::sweep`], which tears down every device whose activating
//! capability no longer resolves with `MAP`. So a device never keeps DMA
//! access that no live capability grants.
//!
//! Every teardown also forgets the device's DMA window, so the next
//! activation only reaches memory the kernel hands out afresh, never the
//! previous holder's buffers.
//!
//! Hardware is reached through the small traits [`DmaTranslation`],
//! [`PciCommand`], and [`Quiesce`], so this logic is host-tested with a fake
//! recorder and does not depend on a particular SMMU or PCI driver.
//!
//! Two notes on scope:
//!
//! - `REVOKE` on a device capability is the power to stop that device for
//!   every holder, because there is only one device. Derive `REVOKE` only to
//!   a task trusted with that power.
//! - Revocation removes the presented capability and its descendants. A
//!   capability to the same device that was never derived from it (for
//!   example an independent root, or a copy made by `transfer`) is a separate
//!   grant of authority and survives, although the device is left quiesced
//!   and must be activated again, with a fresh window, by whoever holds `MAP`.

use crate::caps::{CapError, CapTable, Handle, Rights};
use crate::mem::frame_allocator::PAGE_SIZE;

/// Kernel-assigned identity of a device, stable for the life of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceId(pub u32);

/// Where a device stands with respect to DMA.
///
/// The discriminants are fixed so the state can be reported or stored in a
/// stable form.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaState {
    /// BME clear and the stream aborted (or never opened). No DMA possible.
    /// This is the only state from which a device may be activated.
    Quiesced = 0,
    /// The IOMMU translation is installed but BME is still clear. Transient:
    /// it exists only between the two activation steps, and is kept as a
    /// named state so a later split of activation (for example waiting on a
    /// driver between the steps) has a correct place to stop.
    TranslationInstalled = 1,
    /// BME set and the translation installed: the device may DMA inside its
    /// window.
    Active = 2,
    /// Teardown started but did not complete cleanly. The device is not
    /// trusted again until a teardown succeeds (see
    /// [`DeviceTable::force_quiesce`]).
    Revoking = 3,
}

/// The IOVA range a device may reach once its translation is installed:
/// `pages` pages of `PAGE_SIZE` bytes starting at `iova`. How the range maps
/// to physical memory is the `DmaTranslation` implementation's business.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaWindow {
    pub iova: u64,
    pub pages: u32,
}

impl DmaWindow {
    /// Non-empty, page aligned, and not wrapping past the top of the address
    /// space.
    pub const fn is_valid(self) -> bool {
        let page = PAGE_SIZE as u64;
        self.pages != 0
            && self.iova.is_multiple_of(page)
            && self.iova.checked_add(self.pages as u64 * page).is_some()
    }
}

/// Names one capability slot: the table it lives in and its handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapRef {
    pub table: u32,
    pub handle: Handle,
}

/// One DMA-capable device known to the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    pub id: DeviceId,
    /// PCI requester ID (bus, device, function).
    pub requester_id: u16,
    /// IOMMU stream ID for this device's DMA.
    pub stream_id: u32,
    pub state: DmaState,
    /// The window to install on activation. `None` means the kernel has not
    /// given the device any memory yet, so it cannot be activated. Cleared by
    /// every teardown.
    pub window: Option<DmaWindow>,
    /// The capability that activated the device, while it is active.
    pub authority: Option<CapRef>,
}

impl Device {
    /// A new device in the safe starting state: quiesced, no window.
    pub const fn new(id: DeviceId, requester_id: u16, stream_id: u32) -> Self {
        Self {
            id,
            requester_id,
            stream_id,
            state: DmaState::Quiesced,
            window: None,
            authority: None,
        }
    }
}

/// A hardware operation failed. The code is driver specific and opaque here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwFault(pub u32);

/// Which hardware step an error came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwStep {
    InstallTranslation,
    EnableBusMaster,
    DisableBusMaster,
    Quiesce,
    AbortStream,
    Invalidate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceError {
    /// The capability was missing, stale, or lacked the needed right.
    Cap(CapError),
    /// The capability is valid but does not name a registered device.
    NotADevice,
    /// The device is not in a state that allows the operation.
    WrongState(DmaState),
    /// Activation was requested before the kernel set a DMA window.
    NoWindow,
    /// The window is empty, unaligned, or wraps the address space.
    BadWindow,
    /// The device table has no free slot.
    Full,
    /// Registration clashes with an existing resource, device ID, requester
    /// ID, or stream ID.
    Duplicate,
    /// A hardware step failed. For activation the device was torn down again;
    /// for revocation the capability was still revoked. If the device state
    /// is [`DmaState::Revoking`] afterwards, the teardown itself also failed
    /// and [`DeviceTable::force_quiesce`] should be retried.
    Hardware { step: HwStep, fault: HwFault },
    /// Hardware teardown succeeded but `CapTable::revoke` then refused (for
    /// example malformed derivation data). DMA is stopped and the window is
    /// forgotten, but no capability was removed.
    Revoke(CapError),
}

impl From<CapError> for DeviceError {
    fn from(error: CapError) -> Self {
        Self::Cap(error)
    }
}

/// IOMMU control for one stream. Implemented over the SMMU driver.
pub trait DmaTranslation {
    /// Make `window` the only memory the stream may reach. Must be visible to
    /// the IOMMU (synchronized) before returning `Ok`.
    fn install_translation(&mut self, stream_id: u32, window: DmaWindow) -> Result<(), HwFault>;
    /// Point the stream at an ABORT entry so every DMA from it faults.
    fn abort_stream(&mut self, stream_id: u32) -> Result<(), HwFault>;
    /// Drop any translations the IOMMU may have cached for the stream.
    fn invalidate(&mut self, stream_id: u32) -> Result<(), HwFault>;
}

/// PCI command register control. Implemented over the PCI config space.
pub trait PciCommand {
    /// Set or clear the bus master enable bit for `requester_id`.
    fn set_bus_master(&mut self, requester_id: u16, enabled: bool) -> Result<(), HwFault>;
}

/// The device driver's part of teardown.
pub trait Quiesce {
    /// Stop handing the device new work (close submission queues).
    fn stop_work(&mut self, device: &Device);
    /// Wait for in-flight work to finish, or reset the device.
    fn quiesce(&mut self, device: &Device) -> Result<(), HwFault>;
}

#[derive(Clone, Copy)]
struct Entry {
    resource: u32,
    device: Device,
}

/// Fixed-capacity map from a capability resource ID to a device. No
/// allocation. The resource IDs share the opaque space used by `CapTable`, so
/// the kernel must pick device resource IDs that do not collide with other
/// resources.
pub struct DeviceTable<const N: usize> {
    entries: [Option<Entry>; N],
}

impl<const N: usize> Default for DeviceTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DeviceTable<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Add a device reachable through capabilities naming `resource`. The
    /// device must start quiesced with no authority. Resource, device ID,
    /// requester ID, and stream ID must all be unique: two devices sharing a
    /// stream or a bus master bit could not be revoked apart.
    pub fn register(&mut self, resource: u32, device: Device) -> Result<(), DeviceError> {
        if device.state != DmaState::Quiesced || device.authority.is_some() {
            return Err(DeviceError::WrongState(device.state));
        }
        if let Some(window) = device.window {
            if !window.is_valid() {
                return Err(DeviceError::BadWindow);
            }
        }
        let clash = self.entries.iter().flatten().any(|entry| {
            entry.resource == resource
                || entry.device.id == device.id
                || entry.device.requester_id == device.requester_id
                || entry.device.stream_id == device.stream_id
        });
        if clash {
            return Err(DeviceError::Duplicate);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(DeviceError::Full)?;
        *slot = Some(Entry { resource, device });
        Ok(())
    }

    pub fn get(&self, resource: u32) -> Option<&Device> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.resource == resource)
            .map(|entry| &entry.device)
    }

    fn get_mut(&mut self, resource: u32) -> Option<&mut Device> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.resource == resource)
            .map(|entry| &mut entry.device)
    }

    /// Set the window a later activation will install. Only allowed while the
    /// device is quiesced, so a live device's reach never changes underneath
    /// it. This is a kernel decision, not a capability holder's.
    pub fn set_window(&mut self, resource: u32, window: DmaWindow) -> Result<(), DeviceError> {
        let device = self.get_mut(resource).ok_or(DeviceError::NotADevice)?;
        if device.state != DmaState::Quiesced {
            return Err(DeviceError::WrongState(device.state));
        }
        if !window.is_valid() {
            return Err(DeviceError::BadWindow);
        }
        device.window = Some(window);
        Ok(())
    }

    /// Tear down every device that is not quiesced and whose activating
    /// capability no longer resolves, with `MAP`, to that device. A table
    /// missing from `tables` counts as gone, so the caller must pass every
    /// live table. Call this after any capability removal that did not go
    /// through [`revoke_device`]. Devices left in [`DmaState::Revoking`] by
    /// an earlier failed teardown are retried too. Every device is processed;
    /// the first hardware error is returned.
    pub fn sweep<const M: usize, H>(
        &mut self,
        tables: &[&CapTable<M>],
        hw: &mut H,
    ) -> Result<(), DeviceError>
    where
        H: DmaTranslation + PciCommand + Quiesce,
    {
        let mut first = Ok(());
        for entry in self.entries.iter_mut().flatten() {
            if entry.device.state == DmaState::Quiesced {
                continue;
            }
            let live = entry.device.authority.is_some_and(|auth| {
                let mut owners = tables.iter().filter(|table| table.id() == auth.table);
                match (owners.next(), owners.next()) {
                    (Some(table), None) => {
                        table.lookup(auth.handle, Rights::MAP) == Ok(entry.resource)
                    }
                    _ => false,
                }
            });
            if !live {
                let result = teardown(&mut entry.device, hw);
                if first.is_ok() {
                    first = result;
                }
            }
        }
        first
    }

    /// Run the teardown sequence on a device without a capability. Removing
    /// authority never needs authority, so the kernel may call this at any
    /// time (for example to retry after a failed teardown left the device in
    /// [`DmaState::Revoking`]). Returns the first hardware error, if any.
    pub fn force_quiesce<H>(&mut self, resource: u32, hw: &mut H) -> Result<(), DeviceError>
    where
        H: DmaTranslation + PciCommand + Quiesce,
    {
        let device = self.get_mut(resource).ok_or(DeviceError::NotADevice)?;
        teardown(device, hw)
    }
}

/// Resolve `handle` in `caps` with `rights` to a registered device.
fn resolve<'d, const N: usize, const M: usize>(
    caps: &CapTable<M>,
    handle: Handle,
    rights: Rights,
    devices: &'d mut DeviceTable<N>,
) -> Result<&'d mut Device, DeviceError> {
    let resource = caps.lookup(handle, rights)?;
    devices.get_mut(resource).ok_or(DeviceError::NotADevice)
}

/// Give the device named by `handle` DMA access to its window.
///
/// Requires a capability with `MAP` that names a registered, quiesced device
/// with a window. Every check runs before any hardware effect, so a refused
/// request touches no hardware. On success the order is: install the IOMMU
/// translation, then set BME; the device ends [`DmaState::Active`] and
/// records `handle` in `caps` as its authority.
///
/// If a hardware step fails, the full teardown runs so BME ends clear and the
/// stream ends aborted, and the failing step is reported. The teardown also
/// forgets the window, so the kernel must set one again before a retry.
pub fn activate<const N: usize, const M: usize, H>(
    caps: &CapTable<M>,
    handle: Handle,
    devices: &mut DeviceTable<N>,
    hw: &mut H,
) -> Result<(), DeviceError>
where
    H: DmaTranslation + PciCommand + Quiesce,
{
    let device = resolve(caps, handle, Rights::MAP, devices)?;
    if device.state != DmaState::Quiesced {
        return Err(DeviceError::WrongState(device.state));
    }
    let window = device.window.ok_or(DeviceError::NoWindow)?;

    if let Err(fault) = hw.install_translation(device.stream_id, window) {
        // The activation error is the one returned. A failed teardown is
        // still visible to the caller: the state stays Revoking.
        let _ = teardown(device, hw);
        return Err(DeviceError::Hardware {
            step: HwStep::InstallTranslation,
            fault,
        });
    }
    device.state = DmaState::TranslationInstalled;

    if let Err(fault) = hw.set_bus_master(device.requester_id, true) {
        let _ = teardown(device, hw);
        return Err(DeviceError::Hardware {
            step: HwStep::EnableBusMaster,
            fault,
        });
    }
    device.state = DmaState::Active;
    device.authority = Some(CapRef {
        table: caps.id(),
        handle,
    });
    Ok(())
}

/// Take DMA access away from the device named by `handle` and revoke the
/// capability and everything derived from it.
///
/// `table_id` names the table in `tables` that holds `handle`, which must
/// carry `REVOKE` and name a registered device. `tables` must include every
/// table that may hold descendants, exactly as for [`CapTable::revoke`].
/// These checks run before any hardware effect.
///
/// Order: stop new work, clear BME, quiesce or reset, abort the stream,
/// invalidate translations, then revoke the capability tree. The device ends
/// [`DmaState::Quiesced`] with no window and no authority. If a hardware step
/// fails, the remaining steps still run, the capability is still revoked, the
/// device is left in [`DmaState::Revoking`] so it cannot be activated, and
/// the first hardware error is returned.
///
/// `CapTable::revoke` checks the derivation tree itself and can still refuse
/// after the hardware is down (only on malformed derivation data). Then DMA
/// stays stopped and [`DeviceError::Revoke`] is returned. Stopping DMA first
/// is the safe direction to fail in.
pub fn revoke_device<const N: usize, const M: usize, H>(
    table_id: u32,
    handle: Handle,
    tables: &mut [&mut CapTable<M>],
    devices: &mut DeviceTable<N>,
    hw: &mut H,
) -> Result<(), DeviceError>
where
    H: DmaTranslation + PciCommand + Quiesce,
{
    let mut matching = tables.iter().filter(|table| table.id() == table_id);
    let caps = match (matching.next(), matching.next()) {
        (Some(table), None) => table,
        _ => return Err(DeviceError::Cap(CapError::DuplicateTable)),
    };
    let device = resolve(caps, handle, Rights::REVOKE, devices)?;

    let hardware = teardown(device, hw);
    // Authority is removed even if the hardware misbehaved: a faulty device
    // must not be able to keep its capability alive.
    let revoked = CapTable::<M>::revoke(table_id, handle, tables);
    hardware?;
    revoked.map_err(DeviceError::Revoke)
}

/// Close both DMA gates. Runs every step even after a failure and returns the
/// first failure. The device is `Quiesced` only if every step succeeded. The
/// window and authority are forgotten either way.
fn teardown<H>(device: &mut Device, hw: &mut H) -> Result<(), DeviceError>
where
    H: DmaTranslation + PciCommand + Quiesce,
{
    device.state = DmaState::Revoking;
    device.window = None;
    device.authority = None;
    let mut first: Option<DeviceError> = None;
    let mut note = |step: HwStep, result: Result<(), HwFault>| {
        if let (Err(fault), None) = (result, first) {
            first = Some(DeviceError::Hardware { step, fault });
        }
    };

    hw.stop_work(device);
    note(
        HwStep::DisableBusMaster,
        hw.set_bus_master(device.requester_id, false),
    );
    note(HwStep::Quiesce, hw.quiesce(device));
    note(HwStep::AbortStream, hw.abort_stream(device.stream_id));
    note(HwStep::Invalidate, hw.invalidate(device.stream_id));

    match first {
        None => {
            device.state = DmaState::Quiesced;
            Ok(())
        }
        Some(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Effect {
        Install(u32, DmaWindow),
        Bme(u16, bool),
        StopWork(DeviceId),
        Quiesce(DeviceId),
        Abort(u32),
        Invalidate(u32),
    }

    /// Records every hardware effect and can fail one chosen step.
    #[derive(Default)]
    struct Recorder {
        effects: Vec<Effect>,
        fail: Option<HwStep>,
        /// Hardware view of BME and the stream, to check the final state.
        bme: bool,
        aborted: bool,
    }

    impl Recorder {
        fn failing(step: HwStep) -> Self {
            Self {
                fail: Some(step),
                ..Self::default()
            }
        }
        fn result(&self, step: HwStep) -> Result<(), HwFault> {
            if self.fail == Some(step) {
                Err(HwFault(0xdead))
            } else {
                Ok(())
            }
        }
    }

    impl DmaTranslation for Recorder {
        fn install_translation(
            &mut self,
            stream_id: u32,
            window: DmaWindow,
        ) -> Result<(), HwFault> {
            self.effects.push(Effect::Install(stream_id, window));
            self.result(HwStep::InstallTranslation)?;
            self.aborted = false;
            Ok(())
        }
        fn abort_stream(&mut self, stream_id: u32) -> Result<(), HwFault> {
            self.effects.push(Effect::Abort(stream_id));
            self.result(HwStep::AbortStream)?;
            self.aborted = true;
            Ok(())
        }
        fn invalidate(&mut self, stream_id: u32) -> Result<(), HwFault> {
            self.effects.push(Effect::Invalidate(stream_id));
            self.result(HwStep::Invalidate)
        }
    }

    impl PciCommand for Recorder {
        fn set_bus_master(&mut self, requester_id: u16, enabled: bool) -> Result<(), HwFault> {
            self.effects.push(Effect::Bme(requester_id, enabled));
            let step = if enabled {
                HwStep::EnableBusMaster
            } else {
                HwStep::DisableBusMaster
            };
            self.result(step)?;
            self.bme = enabled;
            Ok(())
        }
    }

    impl Quiesce for Recorder {
        fn stop_work(&mut self, device: &Device) {
            self.effects.push(Effect::StopWork(device.id));
        }
        fn quiesce(&mut self, device: &Device) -> Result<(), HwFault> {
            self.effects.push(Effect::Quiesce(device.id));
            self.result(HwStep::Quiesce)
        }
    }

    const RES: u32 = 0x100;
    const DEV: DeviceId = DeviceId(3);
    const RID: u16 = 0x0010;
    const SID: u32 = 0x10;
    const WINDOW: DmaWindow = DmaWindow {
        iova: 0x4000_0000,
        pages: 4,
    };
    const ALL: Rights = Rights::from_bits(0x3f).unwrap();

    fn devices() -> DeviceTable<4> {
        let mut table = DeviceTable::new();
        table.register(RES, Device::new(DEV, RID, SID)).unwrap();
        table.set_window(RES, WINDOW).unwrap();
        table
    }

    fn teardown_effects() -> [Effect; 5] {
        [
            Effect::StopWork(DEV),
            Effect::Bme(RID, false),
            Effect::Quiesce(DEV),
            Effect::Abort(SID),
            Effect::Invalidate(SID),
        ]
    }

    fn state(devices: &DeviceTable<4>) -> DmaState {
        devices.get(RES).unwrap().state
    }

    #[test]
    fn activate_installs_translation_before_bus_master() {
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, Rights::MAP).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();

        activate(&caps, handle, &mut devices, &mut hw).unwrap();

        assert_eq!(
            hw.effects,
            [Effect::Install(SID, WINDOW), Effect::Bme(RID, true)]
        );
        assert_eq!(state(&devices), DmaState::Active);
    }

    #[test]
    fn revoke_runs_exact_teardown_then_removes_capability_tree() {
        let mut owner = CapTable::<4>::new(1);
        let mut user = CapTable::<4>::new(2);
        let root = owner.insert(RES, ALL).unwrap();
        let child = CapTable::derive_into(&mut owner, root, &mut user, Rights::MAP).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        activate(&user, child, &mut devices, &mut hw).unwrap();
        hw.effects.clear();

        revoke_device(1, root, &mut [&mut owner, &mut user], &mut devices, &mut hw).unwrap();

        assert_eq!(hw.effects, teardown_effects());
        assert_eq!(state(&devices), DmaState::Quiesced);
        assert_eq!(
            owner.lookup(root, Rights::NONE),
            Err(CapError::InvalidHandle)
        );
        assert_eq!(
            user.lookup(child, Rights::NONE),
            Err(CapError::InvalidHandle)
        );
    }

    #[test]
    fn activate_with_revoked_handle_fails_without_effects() {
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, ALL).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        activate(&caps, handle, &mut devices, &mut hw).unwrap();
        revoke_device(1, handle, &mut [&mut caps], &mut devices, &mut hw).unwrap();
        hw.effects.clear();

        assert_eq!(
            activate(&caps, handle, &mut devices, &mut hw),
            Err(DeviceError::Cap(CapError::InvalidHandle))
        );
        assert!(hw.effects.is_empty());
    }

    #[test]
    fn missing_capability_causes_no_effects() {
        let caps = CapTable::<4>::new(1);
        let mut devices = devices();
        let mut hw = Recorder::default();
        let bogus = Handle {
            index: 0,
            generation: 1,
        };
        assert_eq!(
            activate(&caps, bogus, &mut devices, &mut hw),
            Err(DeviceError::Cap(CapError::InvalidHandle))
        );
        let mut caps = caps;
        assert_eq!(
            revoke_device(1, bogus, &mut [&mut caps], &mut devices, &mut hw),
            Err(DeviceError::Cap(CapError::InvalidHandle))
        );
        assert!(hw.effects.is_empty());
        assert_eq!(state(&devices), DmaState::Quiesced);
    }

    #[test]
    fn read_only_capability_causes_no_effects() {
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, Rights::READ).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        assert_eq!(
            activate(&caps, handle, &mut devices, &mut hw),
            Err(DeviceError::Cap(CapError::MissingRights))
        );
        assert_eq!(
            revoke_device(1, handle, &mut [&mut caps], &mut devices, &mut hw),
            Err(DeviceError::Cap(CapError::MissingRights))
        );
        assert!(hw.effects.is_empty());
        assert_eq!(caps.lookup(handle, Rights::READ), Ok(RES));
    }

    #[test]
    fn map_without_revoke_cannot_tear_down_an_active_device() {
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, Rights::MAP).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        activate(&caps, handle, &mut devices, &mut hw).unwrap();
        hw.effects.clear();
        assert_eq!(
            revoke_device(1, handle, &mut [&mut caps], &mut devices, &mut hw),
            Err(DeviceError::Cap(CapError::MissingRights))
        );
        assert!(hw.effects.is_empty());
        assert_eq!(state(&devices), DmaState::Active);
    }

    #[test]
    fn attenuated_capability_without_map_cannot_activate() {
        let mut caps = CapTable::<4>::new(1);
        let root = caps.insert(RES, ALL).unwrap();
        let weak = caps
            .derive(root, Rights::READ | Rights::WRITE | Rights::REVOKE)
            .unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        assert_eq!(
            activate(&caps, weak, &mut devices, &mut hw),
            Err(DeviceError::Cap(CapError::MissingRights))
        );
        assert!(hw.effects.is_empty());
        assert_eq!(state(&devices), DmaState::Quiesced);
    }

    #[test]
    fn capability_for_other_resource_is_not_a_device() {
        let mut caps = CapTable::<4>::new(1);
        let console = caps.insert(1, ALL).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        assert_eq!(
            activate(&caps, console, &mut devices, &mut hw),
            Err(DeviceError::NotADevice)
        );
        assert_eq!(
            revoke_device(1, console, &mut [&mut caps], &mut devices, &mut hw),
            Err(DeviceError::NotADevice)
        );
        assert!(hw.effects.is_empty());
        assert_eq!(caps.lookup(console, Rights::READ), Ok(1));
    }

    #[test]
    fn activation_refused_without_window_or_when_already_active() {
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, Rights::MAP).unwrap();
        let mut devices = DeviceTable::<4>::new();
        devices.register(RES, Device::new(DEV, RID, SID)).unwrap();
        let mut hw = Recorder::default();
        assert_eq!(
            activate(&caps, handle, &mut devices, &mut hw),
            Err(DeviceError::NoWindow)
        );
        assert!(hw.effects.is_empty());

        devices.set_window(RES, WINDOW).unwrap();
        activate(&caps, handle, &mut devices, &mut hw).unwrap();
        hw.effects.clear();
        assert_eq!(
            activate(&caps, handle, &mut devices, &mut hw),
            Err(DeviceError::WrongState(DmaState::Active))
        );
        assert_eq!(
            devices.set_window(RES, WINDOW),
            Err(DeviceError::WrongState(DmaState::Active))
        );
        assert!(hw.effects.is_empty());
    }

    #[test]
    fn activation_failure_at_each_step_leaves_bus_master_clear_and_stream_aborted() {
        for step in [HwStep::InstallTranslation, HwStep::EnableBusMaster] {
            let mut caps = CapTable::<4>::new(1);
            let handle = caps.insert(RES, Rights::MAP).unwrap();
            let mut devices = devices();
            let mut hw = Recorder::failing(step);

            let result = activate(&caps, handle, &mut devices, &mut hw);

            assert_eq!(
                result,
                Err(DeviceError::Hardware {
                    step,
                    fault: HwFault(0xdead)
                })
            );
            let mut expected = Vec::from([Effect::Install(SID, WINDOW)]);
            if step == HwStep::EnableBusMaster {
                expected.push(Effect::Bme(RID, true));
            }
            expected.extend(teardown_effects());
            assert_eq!(hw.effects, expected, "{step:?}");
            assert!(!hw.bme, "{step:?}");
            assert!(hw.aborted, "{step:?}");
            assert_eq!(state(&devices), DmaState::Quiesced, "{step:?}");
        }
    }

    #[test]
    fn failed_teardown_blocks_activation_until_a_clean_retry() {
        // Quiescing fails during revocation, so teardown is incomplete.
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, ALL).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::failing(HwStep::Quiesce);
        activate(&caps, handle, &mut devices, &mut hw).unwrap();

        assert!(revoke_device(1, handle, &mut [&mut caps], &mut devices, &mut hw).is_err());
        assert_eq!(state(&devices), DmaState::Revoking);

        // A fresh capability to the same device still cannot activate it.
        let again = caps.insert(RES, Rights::MAP).unwrap();
        hw.effects.clear();
        assert_eq!(
            activate(&caps, again, &mut devices, &mut hw),
            Err(DeviceError::WrongState(DmaState::Revoking))
        );
        assert!(hw.effects.is_empty());

        // A clean retry without a capability returns it to Quiesced.
        hw.fail = None;
        devices.force_quiesce(RES, &mut hw).unwrap();
        assert_eq!(hw.effects, teardown_effects());
        assert_eq!(state(&devices), DmaState::Quiesced);
    }

    #[test]
    fn revoke_failure_at_each_step_still_closes_gates_and_revokes() {
        for step in [
            HwStep::DisableBusMaster,
            HwStep::Quiesce,
            HwStep::AbortStream,
            HwStep::Invalidate,
        ] {
            let mut owner = CapTable::<4>::new(1);
            let mut user = CapTable::<4>::new(2);
            let root = owner.insert(RES, ALL).unwrap();
            let child = CapTable::derive_into(&mut owner, root, &mut user, Rights::MAP).unwrap();
            let mut devices = devices();
            let mut hw = Recorder::default();
            activate(&user, child, &mut devices, &mut hw).unwrap();
            hw.effects.clear();
            hw.fail = Some(step);

            let result =
                revoke_device(1, root, &mut [&mut owner, &mut user], &mut devices, &mut hw);

            assert_eq!(
                result,
                Err(DeviceError::Hardware {
                    step,
                    fault: HwFault(0xdead)
                }),
                "{step:?}"
            );
            // Every step still ran, in order.
            assert_eq!(hw.effects, teardown_effects(), "{step:?}");
            // BME is clear unless clearing it is the step that failed, and
            // the stream is aborted unless aborting is the step that failed.
            assert_eq!(hw.bme, step == HwStep::DisableBusMaster, "{step:?}");
            assert_eq!(hw.aborted, step != HwStep::AbortStream, "{step:?}");
            assert_eq!(state(&devices), DmaState::Revoking, "{step:?}");
            // Authority is gone regardless.
            assert_eq!(
                owner.lookup(root, Rights::NONE),
                Err(CapError::InvalidHandle)
            );
            assert_eq!(
                user.lookup(child, Rights::NONE),
                Err(CapError::InvalidHandle)
            );
        }
    }

    #[test]
    fn duplicate_or_missing_table_in_revoke_set_causes_no_effects() {
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, ALL).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        let mut other = CapTable::<4>::new(2);
        assert_eq!(
            revoke_device(1, handle, &mut [&mut other], &mut devices, &mut hw),
            Err(DeviceError::Cap(CapError::DuplicateTable))
        );
        let mut twin = CapTable::<4>::new(1);
        assert_eq!(
            revoke_device(
                1,
                handle,
                &mut [&mut caps, &mut twin],
                &mut devices,
                &mut hw
            ),
            Err(DeviceError::Cap(CapError::DuplicateTable))
        );
        assert!(hw.effects.is_empty());
        assert_eq!(caps.lookup(handle, Rights::MAP), Ok(RES));
    }

    #[test]
    fn register_rejects_clashes_and_live_devices() {
        let mut devices = DeviceTable::<2>::new();
        devices.register(RES, Device::new(DEV, RID, SID)).unwrap();
        for (resource, id, rid, sid) in [
            (RES, DeviceId(9), 1, 99),
            (7, DEV, 1, 99),
            (7, DeviceId(9), RID, 99),
            (7, DeviceId(9), 1, SID),
        ] {
            assert_eq!(
                devices.register(resource, Device::new(id, rid, sid)),
                Err(DeviceError::Duplicate)
            );
        }
        let mut bad = Device::new(DeviceId(9), 1, 99);
        bad.window = Some(DmaWindow { iova: 1, pages: 1 });
        assert_eq!(devices.register(7, bad), Err(DeviceError::BadWindow));
        let mut live = Device::new(DeviceId(9), 1, 99);
        live.state = DmaState::Active;
        assert_eq!(
            devices.register(7, live),
            Err(DeviceError::WrongState(DmaState::Active))
        );
        devices
            .register(7, Device::new(DeviceId(9), 1, 99))
            .unwrap();
        assert_eq!(
            devices.register(8, Device::new(DeviceId(10), 2, 100)),
            Err(DeviceError::Full)
        );
    }

    #[test]
    fn window_validation() {
        let mut devices = devices();
        for window in [
            DmaWindow {
                iova: 0x1000,
                pages: 0,
            },
            DmaWindow {
                iova: 0x1001,
                pages: 1,
            },
            DmaWindow {
                iova: !0xfff,
                pages: 2,
            },
        ] {
            assert_eq!(devices.set_window(RES, window), Err(DeviceError::BadWindow));
        }
        assert_eq!(devices.get(RES).unwrap().window, Some(WINDOW));
        assert_eq!(
            devices.set_window(0x999, WINDOW),
            Err(DeviceError::NotADevice)
        );
    }

    #[test]
    fn revoke_forgets_window_so_next_holder_cannot_reuse_it() {
        let mut caps = CapTable::<4>::new(1);
        let first = caps.insert(RES, ALL).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        activate(&caps, first, &mut devices, &mut hw).unwrap();
        revoke_device(1, first, &mut [&mut caps], &mut devices, &mut hw).unwrap();
        assert_eq!(devices.get(RES).unwrap().window, None);
        assert_eq!(devices.get(RES).unwrap().authority, None);

        let next = caps.insert(RES, Rights::MAP).unwrap();
        hw.effects.clear();
        assert_eq!(
            activate(&caps, next, &mut devices, &mut hw),
            Err(DeviceError::NoWindow)
        );
        assert!(hw.effects.is_empty());
    }

    #[test]
    fn activation_records_its_authority() {
        let mut caps = CapTable::<4>::new(7);
        let handle = caps.insert(RES, Rights::MAP).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        activate(&caps, handle, &mut devices, &mut hw).unwrap();
        assert_eq!(
            devices.get(RES).unwrap().authority,
            Some(CapRef { table: 7, handle })
        );
    }

    #[test]
    fn sweep_leaves_devices_with_live_authority_alone() {
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, Rights::MAP).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        activate(&caps, handle, &mut devices, &mut hw).unwrap();
        hw.effects.clear();

        devices.sweep(&[&caps], &mut hw).unwrap();

        assert!(hw.effects.is_empty());
        assert_eq!(state(&devices), DmaState::Active);
    }

    #[test]
    fn sweep_tears_down_when_ancestor_revoked_through_plain_cap_path() {
        let mut owner = CapTable::<4>::new(1);
        let mut user = CapTable::<4>::new(2);
        let root = owner.insert(RES, ALL).unwrap();
        let child = CapTable::derive_into(&mut owner, root, &mut user, Rights::MAP).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        activate(&user, child, &mut devices, &mut hw).unwrap();
        hw.effects.clear();

        CapTable::<4>::revoke(1, root, &mut [&mut owner, &mut user]).unwrap();
        devices.sweep(&[&owner, &user], &mut hw).unwrap();

        assert_eq!(hw.effects, teardown_effects());
        assert_eq!(state(&devices), DmaState::Quiesced);
        assert!(!hw.bme && hw.aborted);
    }

    #[test]
    fn sweep_tears_down_after_holder_removes_or_table_is_gone() {
        // The holder drops its handle, and the slot is reused by an unrelated
        // capability: the generation check keeps it from counting.
        let mut caps = CapTable::<1>::new(1);
        let handle = caps.insert(RES, Rights::MAP).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::default();
        activate(&caps, handle, &mut devices, &mut hw).unwrap();
        caps.remove(handle).unwrap();
        let reused = caps.insert(RES, Rights::MAP).unwrap();
        assert_eq!(reused.index, handle.index);
        hw.effects.clear();
        devices.sweep(&[&caps], &mut hw).unwrap();
        assert_eq!(hw.effects, teardown_effects());
        assert_eq!(state(&devices), DmaState::Quiesced);

        // The holder's whole table is gone.
        devices.set_window(RES, WINDOW).unwrap();
        activate(&caps, reused, &mut devices, &mut hw).unwrap();
        hw.effects.clear();
        devices.sweep::<1, _>(&[], &mut hw).unwrap();
        assert_eq!(hw.effects, teardown_effects());
        assert_eq!(state(&devices), DmaState::Quiesced);
    }

    #[test]
    fn sweep_retries_a_failed_teardown() {
        let mut caps = CapTable::<4>::new(1);
        let handle = caps.insert(RES, ALL).unwrap();
        let mut devices = devices();
        let mut hw = Recorder::failing(HwStep::AbortStream);
        activate(&caps, handle, &mut devices, &mut hw).unwrap();
        assert!(revoke_device(1, handle, &mut [&mut caps], &mut devices, &mut hw).is_err());
        assert_eq!(state(&devices), DmaState::Revoking);
        assert!(!hw.aborted);

        hw.fail = None;
        hw.effects.clear();
        devices.sweep(&[&caps], &mut hw).unwrap();
        assert_eq!(hw.effects, teardown_effects());
        assert!(hw.aborted);
        assert_eq!(state(&devices), DmaState::Quiesced);
    }

    #[test]
    fn state_discriminants_are_stable() {
        assert_eq!(DmaState::Quiesced as u8, 0);
        assert_eq!(DmaState::TranslationInstalled as u8, 1);
        assert_eq!(DmaState::Active as u8, 2);
        assert_eq!(DmaState::Revoking as u8, 3);
    }
}
