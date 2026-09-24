//! Minimal ACPI table parsing for early CPU topology.
//!
//! Pure functions over byte slices so they are testable on the host; the boot
//! image copies no memory and only hands the firmware's tables in as slices.
//!
//! The MADT lists one GIC CPU interface (GICC) entry per core. Since ACPI 6.0
//! each entry carries a Processor Power Efficiency Class; lower numbers are more
//! power-efficient. On heterogeneous parts such as the GB10 (Cortex-A725 and
//! Cortex-X925) this is how firmware tells the OS which cores are which,
//! without starting the secondary cores.

pub const SDT_HEADER_LEN: usize = 36;
const MADT_ENTRIES_OFFSET: usize = 44;
const GICC_TYPE: u8 = 0x0B;
const GICD_TYPE: u8 = 0x0C;
const GICR_TYPE: u8 = 0x0E;
const GICC_FLAGS: usize = 12;
const GICC_MPIDR: usize = 68;
const GICC_EFFICIENCY_CLASS: usize = 76;
/// GICC entries shorter than this predate the efficiency class field.
const GICC_LEN_WITH_CLASS: usize = 77;
const GICC_ENABLED: u32 = 1;
const GICC_ONLINE_CAPABLE: u32 = 1 << 3;

/// Distinct efficiency classes tracked; real parts have two or three.
pub const MAX_CLASSES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    Truncated,
    BadSignature,
    BadChecksum,
    BadEntry,
}

/// GICv3 physical register regions advertised by the MADT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GicBases {
    pub distributor: Option<u64>,
    pub redistributor: Option<(u64, u32)>,
}

/// Reads the first GIC distributor and redistributor regions from a MADT.
pub fn madt_gic_bases(madt: &[u8]) -> Result<GicBases, AcpiError> {
    let madt = checked_table(madt, b"APIC")?;
    let mut bases = GicBases::default();
    let mut at = MADT_ENTRIES_OFFSET;
    while at < madt.len() {
        let kind = madt[at];
        let len = *madt.get(at + 1).ok_or(AcpiError::Truncated)? as usize;
        if len < 2 || at + len > madt.len() {
            return Err(AcpiError::BadEntry);
        }
        let entry = &madt[at..at + len];
        if kind == GICD_TYPE {
            if len < 24 {
                return Err(AcpiError::BadEntry);
            }
            if bases.distributor.is_none() {
                bases.distributor = u64_at(entry, 8);
            }
        } else if kind == GICR_TYPE {
            if len < 16 {
                return Err(AcpiError::BadEntry);
            }
            if bases.redistributor.is_none() {
                bases.redistributor = Some((
                    u64_at(entry, 4).ok_or(AcpiError::BadEntry)?,
                    u32_at(entry, 12).ok_or(AcpiError::BadEntry)?,
                ));
            }
        }
        at += len;
    }
    Ok(bases)
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Length field of a system description table header.
pub fn sdt_length(header: &[u8]) -> Option<usize> {
    u32_at(header, 4).map(|l| l as usize)
}

/// Validates signature, declared length and checksum; returns the table.
pub fn checked_table<'a>(bytes: &'a [u8], signature: &[u8; 4]) -> Result<&'a [u8], AcpiError> {
    let len = sdt_length(bytes).ok_or(AcpiError::Truncated)?;
    if len < SDT_HEADER_LEN || len > bytes.len() {
        return Err(AcpiError::Truncated);
    }
    let table = &bytes[..len];
    if &table[..4] != signature {
        return Err(AcpiError::BadSignature);
    }
    if table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
        return Err(AcpiError::BadChecksum);
    }
    Ok(table)
}

/// Physical addresses listed in an XSDT.
pub fn xsdt_entries(xsdt: &[u8]) -> impl Iterator<Item = u64> + '_ {
    xsdt.get(SDT_HEADER_LEN..)
        .unwrap_or(&[])
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuTopology {
    /// Enabled or online-capable cores listed in the MADT.
    pub cores: u32,
    /// `(efficiency_class, core_count)`, sorted by class; unused slots are zero.
    pub classes: [(u8, u32); MAX_CLASSES],
    pub distinct_classes: usize,
    /// Cores whose GICC entry is too old to carry an efficiency class.
    pub unknown_class: u32,
    /// Affinity (MPIDR) of the first listed core, for cross-checking the boot core.
    pub first_mpidr: Option<u64>,
    /// The boot core (matched by MPIDR affinity) appears in the MADT.
    pub boot_core_listed: bool,
    /// Efficiency class of the boot core, if its entry carries one.
    pub boot_class: Option<u8>,
}

impl CpuTopology {
    fn add(&mut self, class: u8) {
        if let Some(slot) = self.classes[..self.distinct_classes]
            .iter_mut()
            .find(|(c, _)| *c == class)
        {
            slot.1 += 1;
        } else if self.distinct_classes < MAX_CLASSES {
            self.classes[self.distinct_classes] = (class, 1);
            self.distinct_classes += 1;
            self.classes[..self.distinct_classes].sort_unstable_by_key(|(c, _)| *c);
        } else {
            self.unknown_class += 1;
        }
    }

    pub fn classes(&self) -> &[(u8, u32)] {
        &self.classes[..self.distinct_classes]
    }
}

/// Serial console described by the ACPI SPCR table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpcrConsole {
    /// SPCR interface type (0x00 16550, 0x03 PL011, 0x0e SBSA, 0x12 16550 with GAS).
    pub interface_type: u8,
    /// Generic Address Structure: 0 = system memory.
    pub address_space: u8,
    pub register_bit_width: u8,
    /// GAS access size: 1 byte, 2 word, 3 dword, 4 qword.
    pub access_size: u8,
    pub base: u64,
}

/// Which early UART driver fits an SPCR console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UartKind {
    /// 16550-compatible with 32-bit registers (4-byte stride), as on the DGX Spark.
    Ns16550Mmio32(u64),
    /// ARM PL011 or SBSA generic UART (PL011 register subset).
    Pl011(u64),
    /// Present but not drivable by the early console.
    Unsupported,
}

impl SpcrConsole {
    pub fn kind(&self) -> UartKind {
        if self.address_space != 0 || self.base == 0 {
            return UartKind::Unsupported;
        }
        match self.interface_type {
            0x00 | 0x12 if self.access_size == 3 || self.register_bit_width == 32 => {
                UartKind::Ns16550Mmio32(self.base)
            }
            0x03 | 0x0d | 0x0e => UartKind::Pl011(self.base),
            _ => UartKind::Unsupported,
        }
    }
}

const SPCR_INTERFACE_TYPE: usize = 36;
const SPCR_BASE_GAS: usize = 40;

/// Reads the console from a validated SPCR table.
pub fn spcr_console(spcr: &[u8]) -> Result<SpcrConsole, AcpiError> {
    let spcr = checked_table(spcr, b"SPCR")?;
    let gas = spcr
        .get(SPCR_BASE_GAS..SPCR_BASE_GAS + 12)
        .ok_or(AcpiError::Truncated)?;
    Ok(SpcrConsole {
        interface_type: spcr[SPCR_INTERFACE_TYPE],
        address_space: gas[0],
        register_bit_width: gas[1],
        access_size: gas[3],
        base: u64_at(gas, 4).ok_or(AcpiError::Truncated)?,
    })
}

/// MPIDR affinity fields (Aff3, Aff2, Aff1, Aff0); other bits are flags.
pub const MPIDR_AFFINITY_MASK: u64 = 0xff_00ff_ffff;

/// Summarises the cores in a validated MADT ("APIC") table.
pub fn madt_cpu_topology(madt: &[u8]) -> Result<CpuTopology, AcpiError> {
    madt_cpu_topology_for(madt, None)
}

/// Like `madt_cpu_topology`, also locating the core whose MPIDR is `boot_mpidr`.
pub fn madt_cpu_topology_for(
    madt: &[u8],
    boot_mpidr: Option<u64>,
) -> Result<CpuTopology, AcpiError> {
    let madt = checked_table(madt, b"APIC")?;
    let mut topo = CpuTopology::default();
    let mut at = MADT_ENTRIES_OFFSET;
    while at < madt.len() {
        let kind = madt[at];
        let len = *madt.get(at + 1).ok_or(AcpiError::Truncated)? as usize;
        if len < 2 || at + len > madt.len() {
            return Err(AcpiError::BadEntry);
        }
        let entry = &madt[at..at + len];
        if kind == GICC_TYPE {
            let flags = u32_at(entry, GICC_FLAGS).ok_or(AcpiError::BadEntry)?;
            if flags & (GICC_ENABLED | GICC_ONLINE_CAPABLE) != 0 {
                topo.cores += 1;
                if topo.first_mpidr.is_none() {
                    topo.first_mpidr = u64_at(entry, GICC_MPIDR);
                }
                let mpidr = u64_at(entry, GICC_MPIDR).unwrap_or(u64::MAX);
                if boot_mpidr
                    .is_some_and(|b| b & MPIDR_AFFINITY_MASK == mpidr & MPIDR_AFFINITY_MASK)
                {
                    topo.boot_core_listed = true;
                    topo.boot_class =
                        (len >= GICC_LEN_WITH_CLASS).then(|| entry[GICC_EFFICIENCY_CLASS]);
                }
                if len >= GICC_LEN_WITH_CLASS {
                    topo.add(entry[GICC_EFFICIENCY_CLASS]);
                } else {
                    topo.unknown_class += 1;
                }
            }
        }
        at += len;
    }
    Ok(topo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn gicc(mpidr: u64, flags: u32, class: u8, len: usize) -> Vec<u8> {
        let mut e = std::vec![0u8; len];
        e[0] = GICC_TYPE;
        e[1] = len as u8;
        e[GICC_FLAGS..GICC_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        e[GICC_MPIDR..GICC_MPIDR + 8].copy_from_slice(&mpidr.to_le_bytes());
        if len > GICC_EFFICIENCY_CLASS {
            e[GICC_EFFICIENCY_CLASS] = class;
        }
        e
    }

    fn madt(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut t = std::vec![0u8; MADT_ENTRIES_OFFSET];
        t[..4].copy_from_slice(b"APIC");
        for e in entries {
            t.extend_from_slice(e);
        }
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        let sum = t.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        t[9] = 0u8.wrapping_sub(sum);
        t
    }

    #[test]
    fn extracts_gicd_and_gicr_bases() {
        let mut dist = std::vec![0u8; 24];
        dist[0] = GICD_TYPE;
        dist[1] = 24;
        dist[8..16].copy_from_slice(&0x0800_0000u64.to_le_bytes());
        let mut redist = std::vec![0u8; 16];
        redist[0] = GICR_TYPE;
        redist[1] = 16;
        redist[4..12].copy_from_slice(&0x080a_0000u64.to_le_bytes());
        redist[12..16].copy_from_slice(&0x20_0000u32.to_le_bytes());
        let table = madt(&[dist, redist]);
        assert_eq!(
            madt_gic_bases(&table).unwrap(),
            GicBases {
                distributor: Some(0x0800_0000),
                redistributor: Some((0x080a_0000, 0x20_0000)),
            }
        );
    }

    #[test]
    fn counts_gb10_style_heterogeneous_cores_by_efficiency_class() {
        // Ten efficient cores (class 0) then ten performance cores (class 1).
        let entries: Vec<Vec<u8>> = (0..20u64)
            .map(|i| gicc(0x8100_0000 + (i << 8), GICC_ENABLED, u8::from(i >= 10), 82))
            .collect();
        let topo = madt_cpu_topology(&madt(&entries)).unwrap();
        assert_eq!(topo.cores, 20);
        assert_eq!(topo.classes(), &[(0, 10), (1, 10)]);
        assert_eq!(topo.unknown_class, 0);
        assert_eq!(topo.first_mpidr, Some(0x8100_0000));
    }

    #[test]
    fn finds_the_boot_core_class_ignoring_mpidr_flag_bits() {
        let entries: Vec<Vec<u8>> = (0..20u64)
            .map(|i| gicc(0x8100_0000 + (i << 8), GICC_ENABLED, u8::from(i >= 10), 82))
            .collect();
        let table = madt(&entries);
        // MPIDR_EL1 bit 31 is RES1 and absent from the MADT copy.
        let boot = (1 << 31) | 0x8100_0000 | (15 << 8);
        let topo = madt_cpu_topology_for(&table, Some(boot)).unwrap();
        assert!(topo.boot_core_listed);
        assert_eq!(topo.boot_class, Some(1));

        let missing = madt_cpu_topology_for(&table, Some(0x42)).unwrap();
        assert!(!missing.boot_core_listed);
        assert_eq!(missing.boot_class, None);
    }

    #[test]
    fn skips_disabled_cores_and_counts_old_entries_as_unknown() {
        let entries = [
            gicc(0, GICC_ENABLED, 0, 80),
            gicc(1, 0, 1, 80),                   // disabled, not online capable
            gicc(2, GICC_ONLINE_CAPABLE, 1, 80), // hot-pluggable, counted
            gicc(3, GICC_ENABLED, 0, 76),        // ACPI 5.x entry, no class byte
        ];
        let topo = madt_cpu_topology(&madt(&entries)).unwrap();
        assert_eq!(topo.cores, 3);
        assert_eq!(topo.classes(), &[(0, 1), (1, 1)]);
        assert_eq!(topo.unknown_class, 1);
    }

    #[test]
    fn rejects_bad_checksum_signature_and_lengths() {
        let good = madt(&[gicc(0, GICC_ENABLED, 0, 80)]);
        let mut bad_sum = good.clone();
        bad_sum[MADT_ENTRIES_OFFSET + 30] ^= 1;
        assert_eq!(madt_cpu_topology(&bad_sum), Err(AcpiError::BadChecksum));

        let mut wrong_sig = good.clone();
        wrong_sig[0] = b'X';
        wrong_sig[9] = wrong_sig[9].wrapping_sub(b'X' - b'A');
        assert_eq!(madt_cpu_topology(&wrong_sig), Err(AcpiError::BadSignature));

        assert_eq!(
            madt_cpu_topology(&good[..good.len() - 1]),
            Err(AcpiError::Truncated)
        );

        let mut zero_len = madt(&[]);
        zero_len.extend_from_slice(&[GICC_TYPE, 0]);
        let len = zero_len.len() as u32;
        zero_len[4..8].copy_from_slice(&len.to_le_bytes());
        zero_len[9] = 0;
        let sum = zero_len.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        zero_len[9] = 0u8.wrapping_sub(sum);
        assert_eq!(madt_cpu_topology(&zero_len), Err(AcpiError::BadEntry));
    }

    fn spcr(interface_type: u8, space: u8, bit_width: u8, access: u8, base: u64) -> Vec<u8> {
        let mut t = std::vec![0u8; 80];
        t[..4].copy_from_slice(b"SPCR");
        t[4..8].copy_from_slice(&80u32.to_le_bytes());
        t[SPCR_INTERFACE_TYPE] = interface_type;
        t[SPCR_BASE_GAS] = space;
        t[SPCR_BASE_GAS + 1] = bit_width;
        t[SPCR_BASE_GAS + 3] = access;
        t[SPCR_BASE_GAS + 4..SPCR_BASE_GAS + 12].copy_from_slice(&base.to_le_bytes());
        let sum = t.iter().fold(0u8, |s, b| s.wrapping_add(*b));
        t[9] = 0u8.wrapping_sub(sum);
        t
    }

    #[test]
    fn spcr_selects_the_early_uart_driver() {
        // DGX Spark style: 16550-compatible, 32-bit registers at 0x16A00000.
        let spark = spcr_console(&spcr(0x12, 0, 32, 3, 0x16A0_0000)).unwrap();
        assert_eq!(spark.kind(), UartKind::Ns16550Mmio32(0x16A0_0000));
        // QEMU virt: ARM PL011 at 0x09000000.
        let qemu = spcr_console(&spcr(0x03, 0, 32, 3, 0x0900_0000)).unwrap();
        assert_eq!(qemu.kind(), UartKind::Pl011(0x0900_0000));
        // Byte-wide 16550, I/O port space and unknown types are not drivable.
        assert_eq!(
            spcr_console(&spcr(0x00, 0, 8, 1, 0x3f8)).unwrap().kind(),
            UartKind::Unsupported
        );
        assert_eq!(
            spcr_console(&spcr(0x12, 1, 32, 3, 0x3f8)).unwrap().kind(),
            UartKind::Unsupported
        );
        assert_eq!(
            spcr_console(&spcr(0x20, 0, 32, 3, 0x1000)).unwrap().kind(),
            UartKind::Unsupported
        );
        // A corrupted table is rejected.
        let mut bad = spcr(0x03, 0, 32, 3, 0x0900_0000);
        bad[50] ^= 1;
        assert_eq!(spcr_console(&bad), Err(AcpiError::BadChecksum));
    }

    #[test]
    fn reads_xsdt_entry_addresses() {
        let mut xsdt = std::vec![0u8; SDT_HEADER_LEN];
        xsdt.extend_from_slice(&0x1234_5678u64.to_le_bytes());
        xsdt.extend_from_slice(&0x9abc_def0u64.to_le_bytes());
        let addrs: Vec<u64> = xsdt_entries(&xsdt).collect();
        assert_eq!(addrs, [0x1234_5678, 0x9abc_def0]);
    }
}
