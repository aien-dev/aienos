//! Ordered request handling. A message is cut into requests at explicit sequence markers
//! ("and then", ", then", "after that", ";", "and approve ..."). The exam contract says
//! "if the message asks for several steps, give only the first step", so the core decides on
//! the first request that is not a pure acknowledgement, and copies its argument only from it.
//! Sentence breaks alone do not cut ("I do not know what to ask. Show me the options." is
//! one request), except that a leading sentence of fillers ("Ok.") is dropped.

use crate::lexicon::{is_in, AND_VERBS, FILLER, FILLER_COMMA};
use crate::text::{gap, Token};
use alloc::vec::Vec;

/// A request: token range `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clause {
    /// first token
    pub start: usize,
    /// one past the last token
    pub end: usize,
}

const TRAILING_MARKERS: &[&str] = &["afterwards", "afterward", "later", "next"];

/// Cut `toks` into requests in order.
pub fn clauses(toks: &[Token]) -> Vec<Clause> {
    let mut out = Vec::new();
    let n = toks.len();
    let mut s = 0;
    let mut i = 0;
    while i < n {
        let w = toks[i].word.as_str();
        let g = toks[i].gap;
        // ";" always separates
        if i > s && g & gap::SEMI != 0 {
            out.push(Clause { start: s, end: i });
            s = i;
            i += 1;
            continue;
        }
        // "and then", ", then", ". Then"
        if w == "then" && i > s {
            let prev_and = toks[i - 1].word == "and" && i - 1 > s;
            if prev_and || g & (gap::COMMA | gap::STOP) != 0 {
                let e = if prev_and { i - 1 } else { i };
                out.push(Clause { start: s, end: e });
                s = i + 1;
                i += 1;
                continue;
            }
        }
        // "after that" (", after that", "and after that")
        if w == "after" && i + 1 < n && toks[i + 1].word == "that" && i > s {
            let prev_and = toks[i - 1].word == "and" && i - 1 > s;
            if prev_and || g & (gap::COMMA | gap::STOP) != 0 {
                let e = if prev_and { i - 1 } else { i };
                out.push(Clause { start: s, end: e });
                s = i + 2;
                i += 2;
                continue;
            }
        }
        // "X and approve it": a second agent verb starts a new request
        if w == "and" && i > s && i + 1 < n && is_in(AND_VERBS, toks[i + 1].word.as_str()) {
            out.push(Clause { start: s, end: i });
            s = i + 1;
            i += 1;
            continue;
        }
        i += 1;
    }
    if s < n {
        out.push(Clause { start: s, end: n });
    }
    // trailing sequence markers ("... and approve it afterwards") are not content
    for c in out.iter_mut() {
        while c.end > c.start && is_in(TRAILING_MARKERS, toks[c.end - 1].word.as_str()) {
            c.end -= 1;
        }
    }
    out.retain(|c| c.end > c.start);
    out
}

fn all_filler(toks: &[Token], s: usize, e: usize) -> bool {
    e > s
        && toks[s..e]
            .iter()
            .all(|t| !t.alnum || is_in(FILLER, &t.word))
}

/// The request the decision is about: the first clause that is not only fillers, with any
/// leading filler sentence or filler-comma word removed. Falls back to the first clause.
pub fn primary(toks: &[Token], cl: &[Clause]) -> Option<Clause> {
    let first = *cl.first()?;
    let pick = cl
        .iter()
        .copied()
        .find(|c| !all_filler(toks, c.start, c.end))
        .unwrap_or(first);
    let mut c = pick;
    // drop leading filler sentences ("Ok. Remember ...")
    loop {
        let mut j = c.start + 1;
        while j < c.end && toks[j].gap & gap::STOP == 0 {
            j += 1;
        }
        if j < c.end && all_filler(toks, c.start, j) {
            c.start = j;
        } else {
            break;
        }
    }
    // drop "Ok," / "Well," before more words
    while c.end - c.start > 1
        && is_in(FILLER_COMMA, &toks[c.start].word)
        && toks[c.start + 1].gap & gap::COMMA != 0
    {
        c.start += 1;
    }
    Some(c)
}
