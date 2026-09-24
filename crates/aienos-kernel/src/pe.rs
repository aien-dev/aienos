//! Bounds-checked parser for loaded PE32+ AArch64 section tables.
use crate::mem::map_plan::PeSection;
use alloc::vec::Vec;

const PAGE: u64 = 4096;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const PE32_PLUS: u16 = 0x20b;
const EXECUTE: u32 = 0x2000_0000;
const WRITE: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeError {
    Truncated,
    BadDosMagic,
    BadPeSignature,
    WrongMachine,
    WrongOptionalMagic,
    Overflow,
    Overlap,
    WritableExecutable,
}

fn u16at(b: &[u8], n: usize) -> Result<u16, PeError> {
    let s = b
        .get(n..n.checked_add(2).ok_or(PeError::Overflow)?)
        .ok_or(PeError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn u32at(b: &[u8], n: usize) -> Result<u32, PeError> {
    let s = b
        .get(n..n.checked_add(4).ok_or(PeError::Overflow)?)
        .ok_or(PeError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse loaded image sections. Returned virtual addresses are absolute and sizes
/// cover both virtual and raw contents, rounded to 4 KiB.
pub fn parse_pe_sections(image: &[u8], image_base: u64) -> Result<Vec<PeSection>, PeError> {
    if u16at(image, 0)? != 0x5a4d {
        return Err(PeError::BadDosMagic);
    }
    let pe = usize::try_from(u32at(image, 0x3c)?).map_err(|_| PeError::Overflow)?;
    if image
        .get(pe..pe.checked_add(4).ok_or(PeError::Overflow)?)
        .ok_or(PeError::Truncated)?
        != b"PE\0\0"
    {
        return Err(PeError::BadPeSignature);
    }
    let coff = pe.checked_add(4).ok_or(PeError::Overflow)?;
    if u16at(image, coff)? != IMAGE_FILE_MACHINE_ARM64 {
        return Err(PeError::WrongMachine);
    }
    let count = usize::from(u16at(image, coff + 2)?);
    let optional_size = usize::from(u16at(image, coff + 16)?);
    let optional = coff.checked_add(20).ok_or(PeError::Overflow)?;
    let optional_end = optional
        .checked_add(optional_size)
        .ok_or(PeError::Overflow)?;
    if image
        .get(optional..optional_end)
        .ok_or(PeError::Truncated)?
        .len()
        < 2
    {
        return Err(PeError::Truncated);
    }
    if u16at(image, optional)? != PE32_PLUS {
        return Err(PeError::WrongOptionalMagic);
    }
    let table = optional_end;
    let table_len = count.checked_mul(40).ok_or(PeError::Overflow)?;
    image
        .get(table..table.checked_add(table_len).ok_or(PeError::Overflow)?)
        .ok_or(PeError::Truncated)?;
    let mut sections = Vec::with_capacity(count);
    for i in 0..count {
        let h = table + i * 40;
        let virtual_size = u64::from(u32at(image, h + 8)?);
        let rva = u64::from(u32at(image, h + 12)?);
        let raw_size = u64::from(u32at(image, h + 16)?);
        let size = virtual_size.max(raw_size);
        let size = size.checked_add(PAGE - 1).ok_or(PeError::Overflow)? & !(PAGE - 1);
        let va = image_base.checked_add(rva).ok_or(PeError::Overflow)?;
        let characteristics = u32at(image, h + 36)?;
        if characteristics & WRITE != 0 && characteristics & EXECUTE != 0 {
            return Err(PeError::WritableExecutable);
        }
        let end = va.checked_add(size).ok_or(PeError::Overflow)?;
        for prior in &sections {
            let prior: &PeSection = prior;
            let prior_end = prior.va.checked_add(prior.size).ok_or(PeError::Overflow)?;
            if size != 0 && prior.size != 0 && va < prior_end && prior.va < end {
                return Err(PeError::Overlap);
            }
        }
        sections.push(PeSection {
            va,
            size,
            characteristics,
        });
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image(n: usize) -> Vec<u8> {
        let mut b = vec![0; n.max(0x100 + 24 + 240 + 80)];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        b[0x98..0x9a].copy_from_slice(&PE32_PLUS.to_le_bytes());
        let t = 0x80 + 24 + 240;
        for (i, (rva, vs, raw, c)) in [
            (0x1000u32, 0x1000u32, 0x800u32, 0x6000_0020u32),
            (0x2000, 0x800, 0x1000, 0xc000_0040),
        ]
        .iter()
        .enumerate()
        {
            let h = t + i * 40;
            b[h + 8..h + 12].copy_from_slice(&vs.to_le_bytes());
            b[h + 12..h + 16].copy_from_slice(&rva.to_le_bytes());
            b[h + 16..h + 20].copy_from_slice(&raw.to_le_bytes());
            b[h + 36..h + 40].copy_from_slice(&c.to_le_bytes());
        }
        b
    }
    #[test]
    fn valid_sections_use_base_and_page_rounded_max_size() {
        let s = parse_pe_sections(&image(0), 0x400000).unwrap();
        assert_eq!(
            s[0],
            PeSection {
                va: 0x401000,
                size: 4096,
                characteristics: 0x6000_0020
            }
        );
        assert_eq!(s[1].size, 4096);
    }
    #[test]
    fn rejects_truncation_and_invalid_headers() {
        let mut b = image(0);
        assert_eq!(parse_pe_sections(&b[..10], 0), Err(PeError::Truncated));
        assert_eq!(parse_pe_sections(&b[..0x90], 0), Err(PeError::Truncated));
        let table_end = 0x80 + 24 + 240 + 40;
        assert_eq!(
            parse_pe_sections(&b[..table_end], 0),
            Err(PeError::Truncated)
        );
        b[0] = 0;
        assert_eq!(parse_pe_sections(&b, 0), Err(PeError::BadDosMagic));
        let mut b = image(0);
        b[0x80] = 0;
        assert_eq!(parse_pe_sections(&b, 0), Err(PeError::BadPeSignature));
        let mut b = image(0);
        b[0x84] = 0;
        assert_eq!(parse_pe_sections(&b, 0), Err(PeError::WrongMachine));
        let mut b = image(0);
        b[0x98] = 0;
        assert_eq!(parse_pe_sections(&b, 0), Err(PeError::WrongOptionalMagic));
    }
    #[test]
    fn rejects_wx_and_overlapping_ranges() {
        let mut b = image(0);
        let t = 0x80 + 24 + 240;
        b[t + 36..t + 40].copy_from_slice(&0xa000_0000u32.to_le_bytes());
        assert_eq!(parse_pe_sections(&b, 0), Err(PeError::WritableExecutable));
        let mut b = image(0);
        b[t + 40 + 12..t + 40 + 16].copy_from_slice(&0x1800u32.to_le_bytes());
        assert_eq!(parse_pe_sections(&b, 0), Err(PeError::Overlap));
    }
}
