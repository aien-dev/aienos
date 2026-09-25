//! Host tooling for System Store v1 QEMU qualification images.
//!
//! Test-only. Every byte this tool writes is derived from the kernel's own
//! `store::v1` encoder and CRC, so the qualification scripts carry no second
//! implementation of the format.
//!
//! Commands:
//!   cfg IMAGE BYTE_OFFSET MODE SETTLE
//!       Write the 4096-byte qualification control block.
//!   tear-closure OLD NEW STORE_BYTE_OFFSET SECTOR_BYTES
//!       Prove that every sector-granular tear of the one superblock write that
//!       separates OLD from NEW leaves either the old or the new slot bytes.
//!   inject IMAGE STORE_BYTE_OFFSET SLOT|inactive CASE [SOURCE]
//!       Overwrite superblock SLOT with one deterministic defect (see `CASES`).

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::ExitCode;

use aienos_kernel::store::v1::{
    crc32c, FormatError, Superblock, STORE_UNIT_BYTES, SUPERBLOCK_CRC_OFFSET,
};

type Unit = [u8; STORE_UNIT_BYTES];

/// Injection cases. Every case except `bad_crc` and `seeded_garbage` keeps a
/// valid CRC, so each one reaches exactly the check it names.
const CASES: &[&str] = &[
    "bad_crc",
    "wrong_magic",
    "nonzero_reserved",
    "wrong_slot_id",
    "region_mismatch",
    "unsupported_version",
    "seeded_garbage",
    "new_root",
];

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("cfg") => cfg(&args[1..]),
        Some("tear-closure") => tear_closure(&args[1..]),
        Some("inject") => inject(&args[1..]),
        _ => Err(format!(
            "usage: aienos-store-tool cfg|tear-closure|inject ... (cases: {})",
            CASES.join(",")
        )),
    };
    match result {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("aienos-store-tool: {e}");
            ExitCode::FAILURE
        }
    }
}

fn num(s: &str, what: &str) -> Result<u64, String> {
    s.parse().map_err(|_| format!("bad {what}: {s}"))
}

fn arity(args: &[String], min: usize, max: usize) -> Result<(), String> {
    if args.len() < min || args.len() > max {
        return Err(format!(
            "expected {min}..={max} arguments, got {}",
            args.len()
        ));
    }
    Ok(())
}

fn read_unit_at(path: &str, offset: u64) -> Result<Unit, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    let mut unit = [0u8; STORE_UNIT_BYTES];
    f.read_exact(&mut unit)
        .map_err(|e| format!("{path}: {e}"))?;
    Ok(unit)
}

fn write_at(path: &str, offset: u64, bytes: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("{path}: {e}"))?;
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    f.write_all(bytes).map_err(|e| format!("{path}: {e}"))?;
    f.sync_all().map_err(|e| format!("{path}: {e}"))
}

fn rechecksum(unit: &mut Unit) {
    unit[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
    let crc = crc32c(unit);
    unit[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
}

fn cfg(args: &[String]) -> Result<String, String> {
    arity(args, 4, 4)?;
    let offset = num(&args[1], "byte offset")?;
    let mode = u8::try_from(num(&args[2], "mode")?).map_err(|_| "mode > 255")?;
    let settle = u8::try_from(num(&args[3], "settle")?).map_err(|_| "settle > 255")?;
    let mut block = [0u8; STORE_UNIT_BYTES];
    block[0] = mode;
    block[1] = settle;
    write_at(&args[0], offset, &block)?;
    Ok(format!("cfg mode={mode} settle={settle}"))
}

/// Describes a superblock slot's bytes for reports.
fn describe(unit: &Unit, slot: u32) -> String {
    if unit.iter().all(|b| *b == 0) {
        return "zero".into();
    }
    match Superblock::decode(unit, slot) {
        Ok(sb) => format!("gen{}", sb.generation),
        Err(e) => format!("undecodable({e:?})"),
    }
}

fn tear_closure(args: &[String]) -> Result<String, String> {
    arity(args, 4, 4)?;
    let old = fs::read(&args[0]).map_err(|e| format!("{}: {e}", args[0]))?;
    let new = fs::read(&args[1]).map_err(|e| format!("{}: {e}", args[1]))?;
    let store_offset =
        usize::try_from(num(&args[2], "store offset")?).map_err(|e| e.to_string())?;
    let sector = usize::try_from(num(&args[3], "sector bytes")?).map_err(|e| e.to_string())?;
    if old.len() != new.len() {
        return Err("images differ in length".into());
    }
    if sector == 0 || !STORE_UNIT_BYTES.is_multiple_of(sector) {
        return Err(format!(
            "sector size {sector} does not divide the store unit"
        ));
    }
    if !store_offset.is_multiple_of(sector) {
        return Err("store offset is not sector aligned".into());
    }

    // Every differing byte must lie inside one superblock slot of the store.
    let mut slot_hit: Option<usize> = None;
    for (i, (a, b)) in old.iter().zip(&new).enumerate() {
        if a == b {
            continue;
        }
        let rel = i
            .checked_sub(store_offset)
            .ok_or_else(|| format!("images differ outside the store at byte {i}"))?;
        let slot = rel / STORE_UNIT_BYTES;
        if slot > 1 {
            return Err(format!(
                "images differ outside the superblock slots (store unit {slot}); \
                 the two runs did not persist identical payloads"
            ));
        }
        match slot_hit {
            None => slot_hit = Some(slot),
            Some(s) if s == slot => {}
            Some(_) => return Err("both superblock slots differ".into()),
        }
    }
    let slot = slot_hit.ok_or("images are identical: nothing separates old from new")?;
    let base = store_offset + slot * STORE_UNIT_BYTES;
    let mut old_unit = [0u8; STORE_UNIT_BYTES];
    let mut new_unit = [0u8; STORE_UNIT_BYTES];
    old_unit.copy_from_slice(&old[base..base + STORE_UNIT_BYTES]);
    new_unit.copy_from_slice(&new[base..base + STORE_UNIT_BYTES]);

    let new_sb = Superblock::decode(&new_unit, slot as u32)
        .map_err(|e| format!("new slot {slot} is not a valid superblock: {e:?}"))?;
    let old_desc = describe(&old_unit, slot as u32);
    if old_desc.starts_with("undecodable") {
        return Err(format!(
            "old slot {slot} is {old_desc}; the engine never overwrites such a slot"
        ));
    }

    let sectors = STORE_UNIT_BYTES / sector;
    let differing: Vec<usize> = (0..sectors)
        .filter(|s| {
            old_unit[s * sector..(s + 1) * sector] != new_unit[s * sector..(s + 1) * sector]
        })
        .collect();
    let (as_old, as_new) = tear_outcomes(&old_unit, &new_unit, sector).map_err(|mask| {
        format!(
            "STORE_ROOT_TEAR_CLOSURE: FAIL (slot={slot} mask={mask:#x} yields a third state; \
             differing sectors {differing:?})"
        )
    })?;
    Ok(format!(
        "STORE_ROOT_TEAR_CLOSURE: PASS (slot={slot} old={old_desc} new=gen{} sector_bytes={sector} \
         differing_sectors={differing:?} combinations={} as_old={as_old} as_new={as_new})",
        new_sb.generation,
        1u32 << sectors
    ))
}

/// Applies every subset of `sector`-sized blocks of `new` over `old` (each
/// sector either reached the medium or did not). Returns how many subsets
/// reproduce `old` and `new`, or the first subset mask that yields neither.
fn tear_outcomes(old: &Unit, new: &Unit, sector: usize) -> Result<(u32, u32), u32> {
    let sectors = STORE_UNIT_BYTES / sector;
    assert!(sectors <= 16, "too many sectors per unit to enumerate");
    let (mut as_old, mut as_new) = (0u32, 0u32);
    for mask in 0u32..(1 << sectors) {
        let mut torn = *old;
        for s in 0..sectors {
            if mask & (1 << s) != 0 {
                torn[s * sector..(s + 1) * sector]
                    .copy_from_slice(&new[s * sector..(s + 1) * sector]);
            }
        }
        if torn == *old {
            as_old += 1;
        } else if torn == *new {
            as_new += 1;
        } else {
            return Err(mask);
        }
    }
    Ok((as_old, as_new))
}

/// The slot the engine would overwrite next: the zero slot, else the valid
/// superblock with the lower generation. Refuses anything ambiguous.
fn inactive_slot(image: &str, store_offset: u64) -> Result<u32, String> {
    let mut generation = [None; 2];
    for slot in 0..2u32 {
        let unit = read_unit_at(
            image,
            store_offset + u64::from(slot) * STORE_UNIT_BYTES as u64,
        )?;
        if unit.iter().all(|b| *b == 0) {
            return Ok(slot);
        }
        generation[slot as usize] = Superblock::decode(&unit, slot).ok().map(|sb| sb.generation);
    }
    match generation {
        [Some(a), Some(b)] if a < b => Ok(0),
        [Some(a), Some(b)] if b < a => Ok(1),
        _ => Err("cannot determine the inactive slot (both slots valid at one generation, or one undecodable)".into()),
    }
}

/// xorshift64 stream with a fixed seed: the same 4096 bytes on every run.
fn seeded_garbage() -> Unit {
    let mut state: u64 = 0x4149_454E_4F53_0136;
    let mut unit = [0u8; STORE_UNIT_BYTES];
    for chunk in unit.as_chunks_mut::<8>().0 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    unit
}

fn inject(args: &[String]) -> Result<String, String> {
    arity(args, 4, 5)?;
    let image = &args[0];
    let store_offset = num(&args[1], "store offset")?;
    let slot = if args[2] == "inactive" {
        inactive_slot(image, store_offset)?
    } else {
        u32::try_from(num(&args[2], "slot")?).map_err(|e| e.to_string())?
    };
    if slot > 1 {
        return Err("slot must be 0, 1 or inactive".into());
    }
    let case = args[3].as_str();
    let slot_offset = store_offset + u64::from(slot) * STORE_UNIT_BYTES as u64;

    let source = || -> Result<Unit, String> {
        let path = args.get(4).ok_or("this case needs a SOURCE image")?;
        let unit = read_unit_at(path, slot_offset)?;
        Superblock::decode(&unit, slot)
            .map_err(|e| format!("source slot {slot} is not a valid superblock: {e:?}"))?;
        Ok(unit)
    };

    // (bytes, the decode error this case must produce, or None for a valid root)
    let (unit, expect): (Unit, Option<FormatError>) = match case {
        "bad_crc" => {
            let mut u = source()?;
            u[SUPERBLOCK_CRC_OFFSET] ^= 0x01;
            (u, Some(FormatError::BadSuperblockCrc))
        }
        "wrong_magic" => {
            let mut u = source()?;
            u[..8].copy_from_slice(b"AIENBAD1");
            rechecksum(&mut u);
            (u, Some(FormatError::BadSuperblockMagic))
        }
        "nonzero_reserved" => {
            let mut u = source()?;
            u[200] = 0x42;
            rechecksum(&mut u);
            (u, Some(FormatError::NonzeroReserved))
        }
        "wrong_slot_id" => {
            let mut u = source()?;
            u[44..48].copy_from_slice(&(1 - slot).to_le_bytes());
            rechecksum(&mut u);
            (u, Some(FormatError::WrongSuperblockSlot))
        }
        "region_mismatch" => {
            // Decodes cleanly; the engine rejects it because region_units does
            // not match the device.
            let mut u = source()?;
            let region = u64::from_le_bytes(u[48..56].try_into().unwrap_or([0; 8]));
            u[48..56].copy_from_slice(&(region + 1).to_le_bytes());
            rechecksum(&mut u);
            (u, None)
        }
        "unsupported_version" => {
            let mut u = source()?;
            u[8..10].copy_from_slice(&2u16.to_le_bytes());
            rechecksum(&mut u);
            (u, Some(FormatError::UnsupportedVersion))
        }
        "seeded_garbage" => (seeded_garbage(), Some(FormatError::BadSuperblockMagic)),
        "new_root" => (source()?, None),
        other => return Err(format!("unknown case {other}; cases: {}", CASES.join(","))),
    };

    // Prove the case isolates the defect it names before touching the image.
    let got = Superblock::decode(&unit, slot).err();
    if got != expect {
        return Err(format!(
            "case {case}: decode gave {got:?}, expected {expect:?}"
        ));
    }
    write_at(image, slot_offset, &unit)?;
    Ok(format!(
        "inject case={case} slot={slot} decode={}",
        expect.map_or("Ok".to_string(), |e| format!("{e:?}"))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tear_outcomes_detects_a_third_state() {
        let old = [0u8; STORE_UNIT_BYTES];
        let mut one_sector = old;
        one_sector[7] = 1;
        assert_eq!(tear_outcomes(&old, &one_sector, 512), Ok((128, 128)));

        let mut two_sectors = one_sector;
        two_sectors[512 * 3] = 1;
        // Sector 0 alone reaching the medium is neither old nor new.
        assert_eq!(tear_outcomes(&old, &two_sectors, 512), Err(0x1));
    }

    #[test]
    fn garbage_is_stable_and_not_a_superblock() {
        let a = seeded_garbage();
        assert_eq!(a, seeded_garbage());
        assert_ne!(&a[..8], b"AIENSTR1");
        assert_eq!(
            Superblock::decode(&a, 1).err(),
            Some(FormatError::BadSuperblockMagic)
        );
    }
}
