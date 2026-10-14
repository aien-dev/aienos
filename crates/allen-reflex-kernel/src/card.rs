//! The exam card file `\EFI\AIENOS\ALLEN.EXM` (QUALIFICATION ONLY input of the pi5-allen image).
//!
//! Layout: plain text, at most [`FILE_MAX`] bytes, LF line ends.
//! - line 1: exactly [`HEADER`]
//! - lines 2..: 1..[`CASES_MAX`] case lines `<id>|<turns>`
//!   - `id`: 1..[`ID_MAX`] bytes of `A-Z a-z 0-9 _ -`, unique in the file
//!   - `turns`: 1..[`TURNS_MAX`] bytes, the exam's turns field (`user ~~ assistant ~~ user ...`)
//! - every byte is printable ASCII 0x20..0x7e or the LF that ends a line; the file ends with an LF;
//!   no empty line, no CR, no tab, no NUL.
//!
//! The file carries no expected answers: labels stay on the host, which joins the decision lines
//! with them (`scripts/allen_pi_results.sh`). Only the turns reach the core.

use alloc::vec::Vec;

/// First line of the file.
pub const HEADER: &[u8] = b"AIENALX1 QUALIF-ALLEN-EXAM";
/// Largest file accepted.
pub const FILE_MAX: usize = 131_072;
/// Most cases in one file.
pub const CASES_MAX: usize = 512;
/// Longest case id.
pub const ID_MAX: usize = 16;
/// Longest turns field.
pub const TURNS_MAX: usize = 4096;

/// One case: byte ranges into the file buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseRef {
    /// id bytes `[id.0, id.1)`
    pub id: (usize, usize),
    /// turns bytes `[turns.0, turns.1)`
    pub turns: (usize, usize),
}

/// Parse and check the whole file. `Err` names the first failed check; nothing is kept then.
pub fn parse(buf: &[u8]) -> Result<Vec<CaseRef>, &'static str> {
    let n = buf.len();
    if n == 0 || n > FILE_MAX {
        return Err("file size must be 1..131072 bytes");
    }
    if !buf
        .iter()
        .all(|&b| b == b'\n' || (0x20..=0x7e).contains(&b))
    {
        return Err("only printable ASCII and LF line ends are allowed");
    }
    if buf[n - 1] != b'\n' {
        return Err("file does not end with a line feed");
    }
    let hl = HEADER.len();
    if n < hl + 1 || &buf[..hl] != HEADER || buf[hl] != b'\n' {
        return Err("bad header line");
    }
    let mut out: Vec<CaseRef> = Vec::new();
    let mut at = hl + 1;
    while at < n {
        let mut e = at;
        while buf[e] != b'\n' {
            e += 1;
        }
        if e == at {
            return Err("empty line");
        }
        if out.len() >= CASES_MAX {
            return Err("more than 512 cases");
        }
        let bar = match buf[at..e].iter().position(|&b| b == b'|') {
            Some(p) => at + p,
            None => return Err("case line has no '|' after the id"),
        };
        let id = &buf[at..bar];
        if id.is_empty() || id.len() > ID_MAX {
            return Err("id must be 1..16 bytes");
        }
        if !id
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("id may hold only A-Z a-z 0-9 _ -");
        }
        let tl = e - (bar + 1);
        if tl == 0 || tl > TURNS_MAX {
            return Err("turns must be 1..4096 bytes");
        }
        if out.iter().any(|c| &buf[c.id.0..c.id.1] == id) {
            return Err("duplicate case id");
        }
        out.push(CaseRef {
            id: (at, bar),
            turns: (bar + 1, e),
        });
        at = e + 1;
    }
    if out.is_empty() {
        return Err("no case line");
    }
    Ok(out)
}
