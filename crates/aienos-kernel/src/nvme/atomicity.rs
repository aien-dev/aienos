//! NVMe power-fail atomic-write qualification for the System Store root write.
//!
//! NVMe reports power-fail atomic write units as **0-based** logical-block
//! counts (decoded size = raw + 1). The effective guarantee for a namespace is
//! the namespace value (`NAWUPF`) when the namespace advertises one, otherwise
//! the controller value (`AWUPF`). A write is power-fail atomic only if it fits
//! entirely inside that unit AND does not cross an atomic boundary
//! (`NABSPF`/`NABO`). If the guarantee cannot be established, qualification
//! fails closed.
//!
//! Field byte offsets follow NVMe 1.4 Identify Controller (Figure 249) and
//! Identify Namespace (Figure 247).

/// Identify Controller AWUPF byte offset (u16 LE, 0-based).
pub const ID_CTRL_AWUPF_OFFSET: usize = 528;
/// Identify Namespace NAWUPF byte offset (u16 LE, 0-based).
pub const ID_NS_NAWUPF_OFFSET: usize = 36;
/// Identify Namespace NABO byte offset (u16 LE, blocks).
pub const ID_NS_NABO_OFFSET: usize = 42;
/// Identify Namespace NABSPF byte offset (u16 LE, 0-based blocks).
pub const ID_NS_NABSPF_OFFSET: usize = 44;
/// Permanent System Store unit size the root activation write must cover.
pub const STORE_UNIT_BYTES: u64 = 4096;

/// Read a little-endian u16 at `offset`, or `None` if the page is too short.
pub fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let slice = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Decoded atomicity fields for one namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicityFields {
    pub lba_bytes: u32,
    /// Controller AWUPF raw value (0-based); `None` if not observed.
    pub awupf_raw: Option<u16>,
    /// Namespace NAWUPF raw value (0-based); `Some(0)`/`None` means the
    /// namespace does not advertise its own power-fail unit.
    pub nawupf_raw: Option<u16>,
    /// Namespace atomic boundary size raw value (0-based blocks); 0 = none.
    pub nabspf_raw: Option<u16>,
    /// Namespace atomic boundary offset in logical blocks.
    pub nabo_blocks: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicityRefusal {
    EmptyWrite,
    ExceedsAtomicUnit {
        required_blocks: u64,
        guaranteed_blocks: u64,
    },
    CrossesAtomicBoundary {
        boundary_blocks: u64,
        start_lba: u64,
        lba_count: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicityUnknown {
    NoPowerFailGuaranteeReported,
    UnsupportedGeometry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicityDecision {
    Atomic { effective_blocks: u64 },
    NotAtomic(AtomicityRefusal),
    Unknown(AtomicityUnknown),
}

impl AtomicityFields {
    /// Effective guaranteed power-fail atomic size in logical blocks.
    pub fn effective_power_fail_blocks(&self) -> Option<u64> {
        match self.nawupf_raw {
            Some(raw) if raw > 0 => Some(u64::from(raw) + 1),
            _ => self.awupf_raw.map(|raw| u64::from(raw) + 1),
        }
    }

    /// Atomic boundary size in logical blocks, if the namespace reports one.
    pub fn boundary_blocks(&self) -> Option<u64> {
        self.nabspf_raw
            .filter(|raw| *raw > 0)
            .map(|raw| u64::from(raw) + 1)
    }

    fn region(&self, block: u64, size: u64) -> i128 {
        let offset = i128::from(self.nabo_blocks % size as u16);
        (i128::from(block) - offset).div_euclid(i128::from(size))
    }

    /// Deterministic power-fail atomicity predicate.
    pub fn write_is_power_fail_atomic(&self, start_lba: u64, lba_count: u64) -> AtomicityDecision {
        if lba_count == 0 {
            return AtomicityDecision::NotAtomic(AtomicityRefusal::EmptyWrite);
        }
        let Some(guaranteed) = self.effective_power_fail_blocks() else {
            return AtomicityDecision::Unknown(AtomicityUnknown::NoPowerFailGuaranteeReported);
        };
        if lba_count > guaranteed {
            return AtomicityDecision::NotAtomic(AtomicityRefusal::ExceedsAtomicUnit {
                required_blocks: lba_count,
                guaranteed_blocks: guaranteed,
            });
        }
        if let Some(size) = self.boundary_blocks() {
            if self.region(start_lba, size) != self.region(start_lba + lba_count - 1, size) {
                return AtomicityDecision::NotAtomic(AtomicityRefusal::CrossesAtomicBoundary {
                    boundary_blocks: size,
                    start_lba,
                    lba_count,
                });
            }
        }
        AtomicityDecision::Atomic {
            effective_blocks: guaranteed,
        }
    }

    /// (start LBA, LBA count) of a 4096-byte Store superblock unit.
    pub fn store_unit_lba(&self, slot: u32) -> Option<(u64, u64)> {
        let block_size = u64::from(self.lba_bytes);
        if block_size == 0 || !STORE_UNIT_BYTES.is_multiple_of(block_size) {
            return None;
        }
        let blocks = STORE_UNIT_BYTES / block_size;
        Some((u64::from(slot).checked_mul(blocks)?, blocks))
    }

    /// Qualification decision for one Store superblock slot (0 = A, 1 = B).
    pub fn store_root_decision(&self, slot: u32) -> AtomicityDecision {
        match self.store_unit_lba(slot) {
            Some((start, count)) => self.write_is_power_fail_atomic(start, count),
            None => AtomicityDecision::Unknown(AtomicityUnknown::UnsupportedGeometry),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(
        lba_bytes: u32,
        awupf_raw: Option<u16>,
        nawupf_raw: Option<u16>,
        nabspf_raw: Option<u16>,
        nabo_blocks: u16,
    ) -> AtomicityFields {
        AtomicityFields {
            lba_bytes,
            awupf_raw,
            nawupf_raw,
            nabspf_raw,
            nabo_blocks,
        }
    }

    #[test]
    fn insufficient_controller_awupf_rejects() {
        let f = fields(512, Some(6), None, None, 0); // decoded 7 blocks < 8
        assert_eq!(
            f.write_is_power_fail_atomic(0, 8),
            AtomicityDecision::NotAtomic(AtomicityRefusal::ExceedsAtomicUnit {
                required_blocks: 8,
                guaranteed_blocks: 7,
            })
        );
    }

    #[test]
    fn sufficient_decoded_awupf_accepts() {
        let f = fields(512, Some(7), None, None, 0); // decoded 8 blocks
        assert_eq!(
            f.write_is_power_fail_atomic(0, 8),
            AtomicityDecision::Atomic {
                effective_blocks: 8
            }
        );
    }

    #[test]
    fn namespace_override_wins_over_controller() {
        // NAWUPF 3h -> 4 blocks; controller AWUPF 15h -> 16 blocks. The
        // namespace value governs, so an 8-block write is not atomic.
        let f = fields(512, Some(15), Some(3), None, 0);
        assert_eq!(f.effective_power_fail_blocks(), Some(4));
        assert_eq!(
            f.write_is_power_fail_atomic(0, 8),
            AtomicityDecision::NotAtomic(AtomicityRefusal::ExceedsAtomicUnit {
                required_blocks: 8,
                guaranteed_blocks: 4,
            })
        );
    }

    #[test]
    fn namespace_zero_falls_back_to_controller() {
        // NVMe 1.4: NAWUPF 0h means the controller AWUPF applies.
        let f = fields(512, Some(7), Some(0), None, 0);
        assert_eq!(f.effective_power_fail_blocks(), Some(8));
        assert!(matches!(
            f.write_is_power_fail_atomic(0, 8),
            AtomicityDecision::Atomic { .. }
        ));
    }

    #[test]
    fn controller_fallback_when_namespace_absent() {
        let f = fields(512, Some(7), None, None, 0);
        assert!(matches!(
            f.write_is_power_fail_atomic(0, 8),
            AtomicityDecision::Atomic { .. }
        ));
    }

    #[test]
    fn sufficient_unit_but_crosses_boundary_rejects() {
        let f = fields(512, Some(15), None, Some(3), 0); // boundary size 4
        assert_eq!(
            f.write_is_power_fail_atomic(0, 8),
            AtomicityDecision::NotAtomic(AtomicityRefusal::CrossesAtomicBoundary {
                boundary_blocks: 4,
                start_lba: 0,
                lba_count: 8,
            })
        );
        // A write inside one boundary region is fine.
        assert!(matches!(
            f.write_is_power_fail_atomic(0, 4),
            AtomicityDecision::Atomic { .. }
        ));
    }

    #[test]
    fn boundary_safe_write_accepts() {
        let f = fields(512, Some(7), None, None, 0);
        assert!(matches!(
            f.write_is_power_fail_atomic(8, 8),
            AtomicityDecision::Atomic { .. }
        ));
    }

    #[test]
    fn boundary_offset_is_respected() {
        // size 8, offset 4: [0,8) spans regions -1 and 0 -> crosses.
        let f = fields(512, Some(15), None, Some(7), 4);
        assert!(matches!(
            f.write_is_power_fail_atomic(0, 8),
            AtomicityDecision::NotAtomic(AtomicityRefusal::CrossesAtomicBoundary { .. })
        ));
        // [4,12) lies wholly in region 0 -> atomic.
        assert!(matches!(
            f.write_is_power_fail_atomic(4, 8),
            AtomicityDecision::Atomic { .. }
        ));
    }

    #[test]
    fn store_root_512_geometry() {
        let f = fields(512, Some(7), None, None, 0);
        assert_eq!(f.store_unit_lba(0), Some((0, 8)));
        assert_eq!(f.store_unit_lba(1), Some((8, 8)));
        assert!(matches!(
            f.store_root_decision(0),
            AtomicityDecision::Atomic { .. }
        ));
        assert!(matches!(
            f.store_root_decision(1),
            AtomicityDecision::Atomic { .. }
        ));
    }

    #[test]
    fn store_root_4096_geometry() {
        let f = fields(4096, Some(0), None, None, 0); // 1 block
        assert_eq!(f.store_unit_lba(0), Some((0, 1)));
        assert_eq!(f.store_unit_lba(1), Some((1, 1)));
        assert!(matches!(
            f.store_root_decision(1),
            AtomicityDecision::Atomic { .. }
        ));
    }

    #[test]
    fn encoding_edge_zero_and_max() {
        assert_eq!(
            fields(512, Some(0), None, None, 0).effective_power_fail_blocks(),
            Some(1)
        );
        assert_eq!(
            fields(512, Some(u16::MAX), None, None, 0).effective_power_fail_blocks(),
            Some(65536)
        );
    }

    #[test]
    fn unknown_state_fails_closed() {
        let f = fields(512, None, None, None, 0);
        assert_eq!(
            f.write_is_power_fail_atomic(0, 8),
            AtomicityDecision::Unknown(AtomicityUnknown::NoPowerFailGuaranteeReported)
        );
    }

    #[test]
    fn unsupported_geometry_fails_closed() {
        let f = fields(600, Some(15), None, None, 0);
        assert_eq!(
            f.store_root_decision(0),
            AtomicityDecision::Unknown(AtomicityUnknown::UnsupportedGeometry)
        );
    }

    #[test]
    fn empty_write_rejects() {
        let f = fields(512, Some(15), None, None, 0);
        assert_eq!(
            f.write_is_power_fail_atomic(0, 0),
            AtomicityDecision::NotAtomic(AtomicityRefusal::EmptyWrite)
        );
    }

    #[test]
    fn read_u16_le_bounds() {
        let bytes = [0x07u8, 0x00, 0xff];
        assert_eq!(read_u16_le(&bytes, 0), Some(7));
        assert_eq!(read_u16_le(&bytes, 2), None);
        assert_eq!(read_u16_le(&bytes, 99), None);
    }
}
