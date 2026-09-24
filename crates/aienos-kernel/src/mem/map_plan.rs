//! Pure planning for the identity map used by the EL2 to EL1h handoff.
use super::pagetable::{MapFlags, MemoryAttribute};
use alloc::vec::Vec;

pub const EFI_MEMORY_RUNTIME: u64 = 1 << 63;
pub const EFI_MEMORY_RO: u64 = 1 << 17;
pub const EFI_MEMORY_XP: u64 = 1 << 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    pub start: u64,
    pub length: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EfiMemoryDescriptor {
    pub memory_type: u32,
    pub phys_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeSection {
    pub va: u64,
    pub size: u64,
    pub characteristics: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeAttributes {
    pub range: AddressRange,
    pub read_only: bool,
    pub execute_protect: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedMapping {
    pub range: AddressRange,
    pub flags: MapFlags,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeDecision {
    AttributesTableUnavailableCallBeforeTransition,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    EmptyRange,
    Overflow,
    RuntimeCodeAttributesMissing,
    RuntimeCodeCannotSplit,
    Overlap,
    ImageSectionOutsideAllocation,
}

const EFI_LOADER_CODE: u32 = 1;
const EFI_RUNTIME_CODE: u32 = 5;
const EFI_RUNTIME_DATA: u32 = 6;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

fn flags(write: bool, execute: bool, attribute: MemoryAttribute) -> MapFlags {
    MapFlags {
        attribute,
        writable: write,
        executable: execute,
        user: false,
        shareable: true,
        global: true,
    }
}
fn end(r: AddressRange) -> Result<u64, PlanError> {
    r.start.checked_add(r.length).ok_or(PlanError::Overflow)
}
fn overlap(a: AddressRange, b: AddressRange) -> Result<bool, PlanError> {
    Ok(a.start < end(b)? && b.start < end(a)?)
}

/// Produces page-aligned identity mappings. If runtime code attributes are unavailable,
/// the explicit decision is to finish runtime calls before entering EL1h.
pub fn build_map_plan(
    memory: &[EfiMemoryDescriptor],
    _image_base: u64,
    image_allocation: AddressRange,
    sections: &[PeSection],
    runtime_attributes: Option<&[RuntimeAttributes]>,
    mmio: &[AddressRange],
) -> Result<(Vec<PlannedMapping>, Option<RuntimeDecision>), PlanError> {
    let mut out = Vec::new();
    for d in memory {
        let length = d.page_count.checked_mul(4096).ok_or(PlanError::Overflow)?;
        if length == 0 {
            continue;
        }
        let region = AddressRange {
            start: d.phys_start,
            length,
        };
        if d.memory_type == EFI_LOADER_CODE {
            let mut covered = 0;
            for section in sections {
                let size = section.size;
                if size == 0 {
                    continue;
                }
                let start = section.va;
                let aligned_start = start & !4095;
                let aligned_end = start
                    .checked_add(size)
                    .and_then(|value| value.checked_add(4095))
                    .ok_or(PlanError::Overflow)?
                    & !4095;
                let r = AddressRange {
                    start: aligned_start,
                    length: aligned_end
                        .checked_sub(aligned_start)
                        .ok_or(PlanError::Overflow)?,
                };
                if !overlap(r, image_allocation)? {
                    return Err(PlanError::ImageSectionOutsideAllocation);
                }
                if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    && section.characteristics & IMAGE_SCN_MEM_WRITE != 0
                {
                    return Err(PlanError::Overlap);
                }
                let f = flags(
                    section.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                    MemoryAttribute::NormalWriteBack,
                );
                out.push(PlannedMapping { range: r, flags: f });
                covered += r.length;
            }
            if covered == 0 {
                out.push(PlannedMapping {
                    range: region,
                    flags: MapFlags::KERNEL_DATA,
                });
            }
        } else if d.memory_type == EFI_RUNTIME_CODE
            || (d.attribute & EFI_MEMORY_RUNTIME != 0 && d.memory_type != EFI_RUNTIME_DATA)
        {
            let Some(attrs) = runtime_attributes else {
                return Ok((
                    out,
                    Some(RuntimeDecision::AttributesTableUnavailableCallBeforeTransition),
                ));
            };
            let mut cursor = region.start;
            while cursor < end(region)? {
                let attr = attrs
                    .iter()
                    .find(|a| a.range.start <= cursor && end(a.range).is_ok_and(|e| e > cursor))
                    .ok_or(PlanError::RuntimeCodeAttributesMissing)?;
                let stop = end(attr.range)?.min(end(region)?);
                let executable = !attr.execute_protect;
                if executable && !attr.read_only {
                    return Err(PlanError::RuntimeCodeCannotSplit);
                }
                out.push(PlannedMapping {
                    range: AddressRange {
                        start: cursor,
                        length: stop - cursor,
                    },
                    flags: flags(
                        !attr.read_only && attr.execute_protect,
                        executable,
                        MemoryAttribute::NormalWriteBack,
                    ),
                });
                cursor = stop;
            }
        } else if d.memory_type == EFI_RUNTIME_DATA {
            out.push(PlannedMapping {
                range: region,
                flags: MapFlags::KERNEL_DATA,
            });
        }
    }
    for r in mmio {
        out.push(PlannedMapping {
            range: *r,
            flags: flags(true, false, MemoryAttribute::DeviceNgnre),
        });
    }
    for i in 0..out.len() {
        for j in i + 1..out.len() {
            if overlap(out[i].range, out[j].range)? {
                return Err(PlanError::Overlap);
            }
        }
    }
    Ok((out, None))
}

pub const fn mair_el1() -> u64 {
    0x04ff
}
/// PARange is ID_AA64MMFR0_EL1[3:0], encoded as the IPS field.
/// TTBR0: T0SZ=16 (48-bit), WB-WA walks, inner shareable, 4 KiB granule.
/// TTBR1 walks are disabled (EPD1) but T1SZ/TG1 still get valid values, since
/// TG1 = 0b00 is a reserved encoding.
pub const fn tcr_el1(parange: u8) -> u64 {
    16 | (1 << 8)
        | (1 << 10)
        | (3 << 12)
        | (16 << 16)
        | (1 << 23)
        | (0b10 << 30)
        | (((parange as u64) & 7) << 32)
}
/// Architectural RES1 bits plus M, C and I. Alignment and access checks stay disabled.
pub const fn sctlr_el1() -> u64 {
    0x30d0_0800 | 1 | (1 << 2) | (1 << 12)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn d(t: u32, p: u64, pages: u64, a: u64) -> EfiMemoryDescriptor {
        EfiMemoryDescriptor {
            memory_type: t,
            phys_start: p,
            page_count: pages,
            attribute: a,
        }
    }
    const RX: u32 = 0x4000_0000 | IMAGE_SCN_MEM_EXECUTE;
    const RW: u32 = 0x4000_0000 | IMAGE_SCN_MEM_WRITE;
    #[test]
    fn translation_register_values_match_the_architecture() {
        assert_eq!(mair_el1() & 0xff, 0xff, "idx0 Normal WB RA/WA");
        assert_eq!((mair_el1() >> 8) & 0xff, 0x04, "idx1 Device-nGnRE");
        let tcr = tcr_el1(0b0101); // 48-bit PA
        assert_eq!(tcr & 0x3f, 16, "T0SZ");
        assert_eq!((tcr >> 8) & 0b11, 0b01, "IRGN0 WB-WA");
        assert_eq!((tcr >> 10) & 0b11, 0b01, "ORGN0 WB-WA");
        assert_eq!((tcr >> 12) & 0b11, 0b11, "SH0 inner");
        assert_eq!((tcr >> 14) & 0b11, 0b00, "TG0 4 KiB");
        assert_eq!((tcr >> 16) & 0x3f, 16, "T1SZ");
        assert_ne!(tcr & (1 << 23), 0, "EPD1");
        assert_eq!((tcr >> 30) & 0b11, 0b10, "TG1 4 KiB, not reserved 0b00");
        assert_eq!((tcr >> 32) & 0b111, 0b101, "IPS from PARange");
        let sctlr = sctlr_el1();
        assert_eq!(sctlr & 0x30d0_0800, 0x30d0_0800, "RES1 bits");
        assert_eq!(
            sctlr & ((1 << 0) | (1 << 2) | (1 << 12)),
            0b1_0000_0000_0101,
            "M, C, I"
        );
        assert_eq!(
            sctlr & ((1 << 1) | (1 << 19) | (1 << 25)),
            0,
            "A, WXN, EE clear"
        );
    }

    #[test]
    fn section_permissions_are_wx_safe() {
        let mem = [d(EFI_LOADER_CODE, 0x100000, 4, 0)];
        let sec = [
            PeSection {
                va: 0x100000,
                size: 4096,
                characteristics: RX,
            },
            PeSection {
                va: 0x101000,
                size: 4096,
                characteristics: RW,
            },
        ];
        let (p, decision) = build_map_plan(
            &mem,
            0x100000,
            AddressRange {
                start: 0x100000,
                length: 16384,
            },
            &sec,
            None,
            &[],
        )
        .unwrap();
        assert_eq!(decision, None);
        assert_eq!(p.len(), 2);
        assert!(p.iter().all(|m| !(m.flags.writable && m.flags.executable)));
        assert!(p[0].flags.executable && !p[0].flags.writable);
        assert!(p[1].flags.writable && !p[1].flags.executable);
    }
    #[test]
    fn missing_mat_has_explicit_runtime_call_decision() {
        let (p, d) = build_map_plan(
            &[d(EFI_RUNTIME_CODE, 0x400000, 1, EFI_MEMORY_RUNTIME)],
            0,
            AddressRange {
                start: 0,
                length: 1,
            },
            &[],
            None,
            &[],
        )
        .unwrap();
        assert!(p.is_empty());
        assert_eq!(
            d,
            Some(RuntimeDecision::AttributesTableUnavailableCallBeforeTransition)
        );
    }
    #[test]
    fn runtime_code_needs_ro_xp_split() {
        let mem = [d(EFI_RUNTIME_CODE, 0x400000, 2, EFI_MEMORY_RUNTIME)];
        let attrs = [
            RuntimeAttributes {
                range: AddressRange {
                    start: 0x400000,
                    length: 4096,
                },
                read_only: true,
                execute_protect: false,
            },
            RuntimeAttributes {
                range: AddressRange {
                    start: 0x401000,
                    length: 4096,
                },
                read_only: false,
                execute_protect: true,
            },
        ];
        let (p, _) = build_map_plan(
            &mem,
            0,
            AddressRange {
                start: 0,
                length: 1,
            },
            &[],
            Some(&attrs),
            &[],
        )
        .unwrap();
        assert_eq!(p.len(), 2);
        assert!(p[0].flags.executable && !p[0].flags.writable);
        assert!(p[1].flags.writable && !p[1].flags.executable);
    }
    #[test]
    fn unsplittable_runtime_code_is_rejected() {
        let m = [d(EFI_RUNTIME_CODE, 0x400000, 1, EFI_MEMORY_RUNTIME)];
        let a = [RuntimeAttributes {
            range: AddressRange {
                start: 0x400000,
                length: 4096,
            },
            read_only: false,
            execute_protect: false,
        }];
        assert_eq!(
            build_map_plan(
                &m,
                0,
                AddressRange {
                    start: 0,
                    length: 1
                },
                &[],
                Some(&a),
                &[]
            ),
            Err(PlanError::RuntimeCodeCannotSplit)
        );
    }
    #[test]
    fn mmio_is_device_nx_and_overlap_rejected() {
        let (p, _) = build_map_plan(
            &[],
            0,
            AddressRange {
                start: 0,
                length: 1,
            },
            &[],
            None,
            &[AddressRange {
                start: 0x90000000,
                length: 4096,
            }],
        )
        .unwrap();
        assert_eq!(p[0].flags.attribute, MemoryAttribute::DeviceNgnre);
        assert!(!p[0].flags.executable);
        assert_eq!(
            build_map_plan(
                &[],
                0,
                AddressRange {
                    start: 0,
                    length: 1
                },
                &[],
                None,
                &[
                    AddressRange {
                        start: 4096,
                        length: 8192
                    },
                    AddressRange {
                        start: 8192,
                        length: 4096
                    }
                ]
            ),
            Err(PlanError::Overlap)
        );
    }
    #[test]
    fn register_values_encode_required_fields() {
        assert_eq!(mair_el1(), 0x04ff);
        assert_eq!(tcr_el1(5) & 7 << 32, 5 << 32);
        assert_eq!(sctlr_el1() & (1 | 4 | 1 << 12), 1 | 4 | 1 << 12);
    }
}
