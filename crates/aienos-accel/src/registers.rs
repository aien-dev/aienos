//! Source-backed GB10 register inventory.
//!
//! This is a knowledge ledger, not a driver. It records only registers the
//! repository can point at a source for. At present that is exactly two: the
//! PMC registers `BOOT_0` and `BOOT_42`, whose offsets the existing UEFI
//! handoff already reads. Their semantic meaning is not established here, and
//! an absent entry is not an inferred register: unknown registers stay
//! unknown.
//!
//! Nothing in this module reads or writes a register. It carries metadata.

use core::fmt::Write;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegisterAccess {
    ReadOnly,
    ReadWrite,
    Unknown,
}

/// Whether reading the register is inside the established safe set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegisterSafety {
    /// The repository already reads it through an established path.
    EstablishedRead,
    /// A read would need explicit, separate approval before it is attempted.
    RequiresApproval,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegisterSpec {
    pub block: &'static str,
    pub name: &'static str,
    pub offset: u64,
    pub width_bits: u8,
    pub access: RegisterAccess,
    /// Where the offset is recorded. A repository or public source, never a
    /// guess from the register name.
    pub evidence: &'static str,
    /// A value observed by any AIENOS path, if one exists.
    pub observed_value: Option<u32>,
    /// The path that observed `observed_value`, if any.
    pub observed_by: Option<&'static str>,
    pub safe_to_read: RegisterSafety,
    /// Native AIENOS has decoded this register on hardware.
    pub native_observed: bool,
    /// The register's meaning is established.
    pub semantics_known: bool,
}

pub const PMC_BLOCK: &str = "GB10 PMC";
const PMC_EVIDENCE: &str =
    "crates/aienos-accel PMC_BOOT_0/PMC_BOOT_42 offsets used by the UEFI handoff; meaning not established";

/// The complete known-register set. It has two entries by design.
pub const GB10_REGISTERS: [RegisterSpec; 2] = [
    RegisterSpec {
        block: PMC_BLOCK,
        name: "BOOT_0",
        offset: 0x0000,
        width_bits: 32,
        access: RegisterAccess::ReadOnly,
        evidence: PMC_EVIDENCE,
        observed_value: None,
        observed_by: None,
        safe_to_read: RegisterSafety::EstablishedRead,
        native_observed: false,
        semantics_known: false,
    },
    RegisterSpec {
        block: PMC_BLOCK,
        name: "BOOT_42",
        offset: 0x0a00,
        width_bits: 32,
        access: RegisterAccess::ReadOnly,
        evidence: PMC_EVIDENCE,
        observed_value: None,
        observed_by: None,
        safe_to_read: RegisterSafety::EstablishedRead,
        native_observed: false,
        semantics_known: false,
    },
];

pub fn find(name: &str) -> Option<&'static RegisterSpec> {
    GB10_REGISTERS.iter().find(|spec| spec.name == name)
}

/// Write the ledger deterministically. One line per register.
pub fn write_ledger(out: &mut impl Write) {
    for spec in &GB10_REGISTERS {
        let _ = write!(
            out,
            "gb10.register {}.{}: offset {:#06x} width {} access {:?} safety {:?} native_observed {} semantics_known {}",
            spec.block,
            spec.name,
            spec.offset,
            spec.width_bits,
            spec.access,
            spec.safe_to_read,
            spec.native_observed,
            spec.semantics_known,
        );
        match spec.observed_value {
            Some(value) => {
                let _ = write!(out, " observed_value {value:#010x}");
            }
            None => {
                let _ = write!(out, " observed_value unknown");
            }
        }
        match spec.observed_by {
            Some(path) => {
                let _ = writeln!(out, " observed_by {path:?} evidence {:?}", spec.evidence);
            }
            None => {
                let _ = writeln!(out, " observed_by none evidence {:?}", spec.evidence);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_is_exactly_the_two_established_offsets() {
        assert_eq!(GB10_REGISTERS.len(), 2);
        assert_eq!(find("BOOT_0").unwrap().offset, crate::PMC_BOOT_0);
        assert_eq!(find("BOOT_42").unwrap().offset, crate::PMC_BOOT_42);
        assert!(find("BOOT_1").is_none());
        for spec in &GB10_REGISTERS {
            assert_eq!(spec.safe_to_read, RegisterSafety::EstablishedRead);
            assert!(!spec.native_observed);
            assert!(!spec.semantics_known);
            assert!(spec.observed_value.is_none());
        }
    }

    #[test]
    fn ledger_renders_without_claiming_semantics() {
        extern crate std;
        use std::string::String;
        let mut text = String::new();
        write_ledger(&mut text);
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("GB10 PMC.BOOT_0: offset 0x0000"));
        assert!(text.contains("semantics_known false"));
        assert!(text.contains("native_observed false"));
    }
}
