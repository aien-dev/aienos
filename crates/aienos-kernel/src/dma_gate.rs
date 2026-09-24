//! PCI bus mastering (DMA) gate. Governing rule for M3: no SMMU confinement
//! means no DMA.
//!
//! A PCI function can only start DMA while bit 2 of its Command register
//! (Bus Master Enable, BME) is set. This module holds the pure decisions
//! around that bit so they can be host tested:
//!
//! - [`sweep_bus_master`] walks an ECAM bus range after firmware exit and
//!   clears BME on every endpoint firmware left with it set, so each device
//!   starts with DMA off.
//! - [`dma_grant`] decides whether a driver may set BME again: only when an
//!   SMMU translation domain for the device is installed, or when the
//!   explicit, unsafe, QEMU-only debug bypass is compiled in AND the platform
//!   describes no SMMU at all. A present SMMU that failed to initialise never
//!   falls back to the bypass.
//!
//! No MMIO happens here: config space is reached through [`PciConfig`].

/// Offset of the 16-bit PCI Command register.
pub const PCI_COMMAND: u16 = 0x04;
/// Command register bit: memory space decode.
pub const PCI_COMMAND_MEMORY: u16 = 1 << 1;
/// Command register bit: Bus Master Enable (the device may issue DMA).
pub const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Whether `command` lets the device issue DMA.
pub const fn bus_master_enabled(command: u16) -> bool {
    command & PCI_COMMAND_BUS_MASTER != 0
}

/// `command` with Bus Master Enable cleared and every other bit kept.
pub const fn without_bus_master(command: u16) -> u16 {
    command & !PCI_COMMAND_BUS_MASTER
}

/// `command` with memory decode and Bus Master Enable set.
pub const fn with_bus_master(command: u16) -> u16 {
    command | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER
}

/// Why a device got DMA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaGrant {
    /// An SMMU domain translates this device's stream: confined DMA.
    Confined,
    /// UNSAFE: no SMMU on the platform and the debug bypass is compiled in.
    /// The device reaches physical memory directly. QEMU debugging only.
    UnsafeBypass,
}

/// Why a device stays without DMA (Bus Master Enable left clear).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaDenied {
    /// The platform describes no SMMU (no IORT SMMUv3 node).
    NoSmmu,
    /// An SMMU exists but no domain for this device is installed.
    SmmuNotReady,
}

/// Decide whether a device may have Bus Master Enable set.
///
/// - `smmu_ready`: a translation domain for this device's stream is live.
/// - `smmu_present`: firmware described an SMMU for this platform.
/// - `unsafe_bypass`: the `unsafe-debug-dma-without-smmu` build feature.
///
/// The bypass only applies when there is no SMMU at all. If an SMMU exists
/// and its setup failed, the answer is always [`DmaDenied::SmmuNotReady`].
pub const fn dma_grant(
    smmu_ready: bool,
    smmu_present: bool,
    unsafe_bypass: bool,
) -> Result<DmaGrant, DmaDenied> {
    if smmu_ready {
        Ok(DmaGrant::Confined)
    } else if smmu_present {
        Err(DmaDenied::SmmuNotReady)
    } else if unsafe_bypass {
        Ok(DmaGrant::UnsafeBypass)
    } else {
        Err(DmaDenied::NoSmmu)
    }
}

/// Config space access for one PCI segment (an ECAM window).
pub trait PciConfig {
    /// Read the 32-bit register at `offset`, `None` when outside the window.
    fn read32(&mut self, bus: u8, device: u8, function: u8, offset: u16) -> Option<u32>;
    /// Write the 16-bit register at `offset`. A 16-bit write keeps the
    /// write-one-to-clear Status bits next to the Command register intact.
    fn write16(&mut self, bus: u8, device: u8, function: u8, offset: u16, value: u16);
}

/// A PCI function address on one segment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Bdf {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

/// One endpoint whose Bus Master Enable the sweep found set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BusMasterFinding {
    pub at: Bdf,
    /// Command register as firmware left it.
    pub command_before: u16,
    /// Command register read back after the clear.
    pub command_after: u16,
}

impl BusMasterFinding {
    /// Whether the clear took effect.
    pub const fn cleared(&self) -> bool {
        !bus_master_enabled(self.command_after)
    }
}

/// Findings kept in full; later ones are only counted.
pub const SWEEP_FINDINGS: usize = 8;

/// Result of [`sweep_bus_master`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BusMasterSweep {
    /// Functions that answered a config read.
    pub functions: u16,
    /// PCI-to-PCI bridges among them (left untouched, see below).
    pub bridges: u16,
    /// Bridges with Bus Master Enable set.
    pub bridges_bus_master: u16,
    /// Endpoints firmware left with Bus Master Enable set.
    pub endpoints_bus_master: u16,
    /// Endpoints whose Bus Master Enable is still set after the clear.
    pub still_enabled: u16,
    /// The first [`SWEEP_FINDINGS`] endpoints found with BME set.
    pub findings: [BusMasterFinding; SWEEP_FINDINGS],
}

impl BusMasterSweep {
    /// The recorded findings.
    pub fn findings(&self) -> &[BusMasterFinding] {
        let n = usize::from(self.endpoints_bus_master).min(SWEEP_FINDINGS);
        &self.findings[..n]
    }
}

/// Walk buses `start_bus..=end_bus` and clear Bus Master Enable on every
/// endpoint (header type 0) that has it set. Bridges (header type 1) are
/// counted but not changed: a bridge's BME only forwards DMA from devices
/// below it, and those devices are cleared individually.
pub fn sweep_bus_master<C: PciConfig>(
    config: &mut C,
    start_bus: u8,
    end_bus: u8,
) -> BusMasterSweep {
    let mut sweep = BusMasterSweep::default();
    for bus in start_bus..=end_bus {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let present = config
                    .read32(bus, device, function, 0)
                    .filter(|id| id & 0xffff != 0xffff);
                if present.is_none() {
                    if function == 0 {
                        break;
                    }
                    continue;
                }
                sweep.functions = sweep.functions.saturating_add(1);
                let header = config
                    .read32(bus, device, function, 0x0c)
                    .map_or(0, |v| ((v >> 16) & 0xff) as u8);
                let command = config
                    .read32(bus, device, function, PCI_COMMAND)
                    .map_or(0, |v| v as u16);
                if header & 0x7f == 0x01 {
                    sweep.bridges = sweep.bridges.saturating_add(1);
                    if bus_master_enabled(command) {
                        sweep.bridges_bus_master = sweep.bridges_bus_master.saturating_add(1);
                    }
                } else if bus_master_enabled(command) {
                    config.write16(
                        bus,
                        device,
                        function,
                        PCI_COMMAND,
                        without_bus_master(command),
                    );
                    let after = config
                        .read32(bus, device, function, PCI_COMMAND)
                        .map_or(command, |v| v as u16);
                    let finding = BusMasterFinding {
                        at: Bdf {
                            bus,
                            device,
                            function,
                        },
                        command_before: command,
                        command_after: after,
                    };
                    if let Some(slot) = sweep
                        .findings
                        .get_mut(usize::from(sweep.endpoints_bus_master))
                    {
                        *slot = finding;
                    }
                    sweep.endpoints_bus_master = sweep.endpoints_bus_master.saturating_add(1);
                    if !finding.cleared() {
                        sweep.still_enabled = sweep.still_enabled.saturating_add(1);
                    }
                }
                if function == 0 && header & 0x80 == 0 {
                    break;
                }
            }
        }
    }
    sweep
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    /// Config space image keyed by (bus, device, function); each entry holds
    /// the vendor/device id, header type and Command register.
    #[derive(Default)]
    struct FakeConfig {
        functions: BTreeMap<(u8, u8, u8), (u32, u8, u16)>,
        /// Functions whose Command register ignores writes.
        stuck: Vec<(u8, u8, u8)>,
        writes: Vec<((u8, u8, u8), u16, u16)>,
    }

    impl PciConfig for FakeConfig {
        fn read32(&mut self, bus: u8, device: u8, function: u8, offset: u16) -> Option<u32> {
            let Some(&(id, header, command)) = self.functions.get(&(bus, device, function)) else {
                return Some(u32::MAX);
            };
            Some(match offset {
                0 => id,
                0x0c => u32::from(header) << 16,
                // Status bits in the upper half must survive a Command write.
                PCI_COMMAND => 0x0010_0000 | u32::from(command),
                _ => 0,
            })
        }
        fn write16(&mut self, bus: u8, device: u8, function: u8, offset: u16, value: u16) {
            self.writes.push(((bus, device, function), offset, value));
            if self.stuck.contains(&(bus, device, function)) {
                return;
            }
            if let Some(entry) = self.functions.get_mut(&(bus, device, function)) {
                if offset == PCI_COMMAND {
                    entry.2 = value;
                }
            }
        }
    }

    #[test]
    fn command_bits() {
        assert!(bus_master_enabled(0x0007));
        assert!(!bus_master_enabled(0x0003));
        assert_eq!(without_bus_master(0x0407), 0x0403);
        assert_eq!(with_bus_master(0x0400), 0x0406);
    }

    #[test]
    fn grant_requires_smmu_or_explicit_bypass_without_smmu() {
        assert_eq!(dma_grant(true, true, false), Ok(DmaGrant::Confined));
        assert_eq!(dma_grant(true, true, true), Ok(DmaGrant::Confined));
        assert_eq!(dma_grant(false, false, false), Err(DmaDenied::NoSmmu));
        assert_eq!(dma_grant(false, false, true), Ok(DmaGrant::UnsafeBypass));
    }

    #[test]
    fn failed_smmu_never_falls_back_to_bypass() {
        assert_eq!(dma_grant(false, true, false), Err(DmaDenied::SmmuNotReady));
        assert_eq!(dma_grant(false, true, true), Err(DmaDenied::SmmuNotReady));
    }

    #[test]
    fn sweep_clears_endpoints_and_leaves_bridges() {
        let mut config = FakeConfig::default();
        // Host bridge, BME off.
        config.functions.insert((0, 0, 0), (0x0008_1b36, 0, 0x0000));
        // Endpoint with BME on (virtio-blk left running by firmware).
        config.functions.insert((0, 1, 0), (0x1042_1af4, 0, 0x0007));
        // xHCI with memory decode only.
        config.functions.insert((0, 2, 0), (0x000d_1b36, 0, 0x0002));
        // Root port with BME on.
        config.functions.insert((0, 3, 0), (0x000c_1b36, 1, 0x0007));
        // Endpoint behind the root port with BME on.
        config.functions.insert((1, 0, 0), (0x1234_abcd, 0, 0x0006));
        let sweep = sweep_bus_master(&mut config, 0, 1);
        assert_eq!(sweep.functions, 5);
        assert_eq!(sweep.bridges, 1);
        assert_eq!(sweep.bridges_bus_master, 1);
        assert_eq!(sweep.endpoints_bus_master, 2);
        assert_eq!(sweep.still_enabled, 0);
        let found: Vec<_> = sweep.findings().iter().map(|f| f.at).collect();
        assert_eq!(
            found,
            [
                Bdf {
                    bus: 0,
                    device: 1,
                    function: 0
                },
                Bdf {
                    bus: 1,
                    device: 0,
                    function: 0
                }
            ]
        );
        assert_eq!(sweep.findings()[0].command_before, 0x0007);
        assert_eq!(sweep.findings()[0].command_after, 0x0003);
        assert_eq!(config.functions[&(0, 1, 0)].2, 0x0003);
        assert_eq!(config.functions[&(0, 3, 0)].2, 0x0007, "bridge untouched");
        assert_eq!(config.functions[&(0, 2, 0)].2, 0x0002, "no write when off");
        assert_eq!(config.writes.len(), 2);
        assert!(config.writes.iter().all(|w| w.1 == PCI_COMMAND));
    }

    #[test]
    fn sweep_reports_a_bus_master_bit_that_will_not_clear() {
        let mut config = FakeConfig::default();
        config.functions.insert((0, 4, 0), (0x5678_abcd, 0, 0x0006));
        config.stuck.push((0, 4, 0));
        let sweep = sweep_bus_master(&mut config, 0, 0);
        assert_eq!(sweep.endpoints_bus_master, 1);
        assert_eq!(sweep.still_enabled, 1);
        assert!(!sweep.findings()[0].cleared());
    }

    #[test]
    fn sweep_walks_multifunction_devices_only_when_marked() {
        let mut config = FakeConfig::default();
        // Single-function device: function 1 must not be probed.
        config
            .functions
            .insert((0, 5, 0), (0x1111_abcd, 0x00, 0x0004));
        config
            .functions
            .insert((0, 5, 1), (0x2222_abcd, 0x00, 0x0004));
        // Multi-function device: both functions are visited.
        config
            .functions
            .insert((0, 6, 0), (0x3333_abcd, 0x80, 0x0004));
        config
            .functions
            .insert((0, 6, 1), (0x4444_abcd, 0x00, 0x0004));
        let sweep = sweep_bus_master(&mut config, 0, 0);
        assert_eq!(sweep.functions, 3);
        assert_eq!(sweep.endpoints_bus_master, 3);
        assert_eq!(config.functions[&(0, 5, 1)].2, 0x0004, "never visited");
    }

    #[test]
    fn sweep_keeps_counting_past_the_recorded_findings() {
        let mut config = FakeConfig::default();
        for device in 0..12u8 {
            config
                .functions
                .insert((0, device, 0), (0x9999_abcd, 0, 0x0004));
        }
        let sweep = sweep_bus_master(&mut config, 0, 0);
        assert_eq!(sweep.endpoints_bus_master, 12);
        assert_eq!(sweep.findings().len(), SWEEP_FINDINGS);
        assert!(config.functions.values().all(|f| f.2 == 0));
    }
}
