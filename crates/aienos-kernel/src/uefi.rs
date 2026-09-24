//! UEFI memory attributes table (MAT) parser.
use crate::mem::map_plan::{AddressRange, RuntimeAttributes, EFI_MEMORY_RO, EFI_MEMORY_XP};
use alloc::vec::Vec;

/// EFI_MEMORY_ATTRIBUTES_TABLE configuration table GUID in UEFI byte order.
pub const EFI_MEMORY_ATTRIBUTES_TABLE_GUID: [u8; 16] = [
    0x1d, 0x91, 0xfa, 0xdc, 0xeb, 0x26, 0x9f, 0x46, 0xa2, 0x20, 0x38, 0xb7, 0xdc, 0x46, 0x12, 0x20,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatError {
    Truncated,
    InvalidDescriptorSize,
    Overflow,
}
fn u32at(b: &[u8], n: usize) -> Result<u32, MatError> {
    let s = b
        .get(n..n.checked_add(4).ok_or(MatError::Overflow)?)
        .ok_or(MatError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64at(b: &[u8], n: usize) -> Result<u64, MatError> {
    let s = b
        .get(n..n.checked_add(8).ok_or(MatError::Overflow)?)
        .ok_or(MatError::Truncated)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Parse the MAT table body. Descriptor extensions are skipped according to
/// DescriptorSize; each result describes one physical descriptor range.
pub fn parse_memory_attributes_table(table: &[u8]) -> Result<Vec<RuntimeAttributes>, MatError> {
    if table.len() < 16 {
        return Err(MatError::Truncated);
    }
    let count = usize::try_from(u32at(table, 4)?).map_err(|_| MatError::Overflow)?;
    let stride = usize::try_from(u32at(table, 8)?).map_err(|_| MatError::Overflow)?;
    if stride < 40 {
        return Err(MatError::InvalidDescriptorSize);
    }
    let bytes = count.checked_mul(stride).ok_or(MatError::Overflow)?;
    let end = 16usize.checked_add(bytes).ok_or(MatError::Overflow)?;
    table.get(16..end).ok_or(MatError::Truncated)?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let d = 16 + i * stride;
        let start = u64at(table, d + 8)?;
        let pages = u64at(table, d + 24)?;
        let attribute = u64at(table, d + 32)?;
        let length = pages.checked_mul(4096).ok_or(MatError::Overflow)?;
        start.checked_add(length).ok_or(MatError::Overflow)?;
        out.push(RuntimeAttributes {
            range: AddressRange { start, length },
            read_only: attribute & EFI_MEMORY_RO != 0,
            execute_protect: attribute & EFI_MEMORY_XP != 0,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn table(stride: usize) -> Vec<u8> {
        let mut b = vec![0; 16 + stride * 2];
        b[0..4].copy_from_slice(&1u32.to_le_bytes());
        b[4..8].copy_from_slice(&2u32.to_le_bytes());
        b[8..12].copy_from_slice(&(stride as u32).to_le_bytes());
        for i in 0..2 {
            let d = 16 + i * stride;
            b[d + 8..d + 16].copy_from_slice(&(0x8000u64 + i as u64 * 0x2000).to_le_bytes());
            b[d + 24..d + 32].copy_from_slice(&2u64.to_le_bytes());
            b[d + 32..d + 40].copy_from_slice(
                &(if i == 0 { EFI_MEMORY_RO } else { EFI_MEMORY_XP }).to_le_bytes(),
            );
        }
        b
    }
    #[test]
    fn honors_48_and_56_byte_descriptor_strides() {
        for stride in [48, 56] {
            let a = parse_memory_attributes_table(&table(stride)).unwrap();
            assert_eq!(a.len(), 2);
            assert_eq!(
                a[0].range,
                AddressRange {
                    start: 0x8000,
                    length: 8192
                }
            );
            assert!(a[0].read_only && !a[0].execute_protect);
            assert!(!a[1].read_only && a[1].execute_protect);
        }
    }
    #[test]
    fn rejects_truncated_and_short_descriptors() {
        assert_eq!(
            parse_memory_attributes_table(&[0; 15]),
            Err(MatError::Truncated)
        );
        let mut b = table(48);
        b.truncate(b.len() - 1);
        assert_eq!(parse_memory_attributes_table(&b), Err(MatError::Truncated));
        let mut b = table(48);
        b[8..12].copy_from_slice(&39u32.to_le_bytes());
        assert_eq!(
            parse_memory_attributes_table(&b),
            Err(MatError::InvalidDescriptorSize)
        );
    }
}
