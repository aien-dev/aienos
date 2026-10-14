//! Argument copy. The text of remember, prefer, task and prompt is copied byte for byte
//! from the operator's request (case and inner punctuation kept). Only its two boundaries
//! are decided: where the command words end and where trailing words ("from now on") begin.
//!
//! Boundaries are learned from training spans (the words before and after the expected
//! text, per action). For an unseen phrasing:
//! 1. the longest learned leading cue at the start, or the last 2+ words of a learned cue
//!    one or two words in ("Create a task to" matches the tail of "add a task to");
//! 2. a colon or free dash within the first 8 words, at or after that cue, when the words
//!    before it are cue words or unknown ("Remember this note: ...");
//! 3. with no cue so far, a store/to-do/preference frame is skipped; then, in every case,
//!    words seen more often as cue than as content for that action ("to" after "add a task").
//!
//! Defined outcomes when no valid text exists (the caller answers `clarify`):
//! [`SpanError::Empty`] (nothing but pointer words: "Save this."), [`SpanError::TooLong`]
//! (more than 48 bytes; never truncated silently), [`SpanError::Unrepresentable`]
//! (a double quote, a backslash or a byte outside printable ASCII, which the card-script
//! format cannot carry). Curly apostrophes are the one substitution: they become `'`.

use crate::action::Action;
use crate::lexicon::{is_in, longest, skip_polite, TEXT_FRAMES, VACUOUS, WRITE_VERBS};
use crate::segment::Clause;
use crate::text::{fnv, gap, Token};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Bound on learned cues (prefix + suffix).
pub const MAX_CUES: usize = 512;
/// Bound on words in one cue.
pub const MAX_CUE_WORDS: usize = 8;
/// Bound on per-word statistics entries.
pub const MAX_STATS: usize = 4096;
/// Longest text the agent accepts (agent_cmd.c).
pub const MAX_TEXT: usize = 48;

/// Why no text could be produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpanError {
    /// only pointer or command words
    Empty,
    /// longer than 48 bytes
    TooLong,
    /// a byte the card-script format cannot carry
    Unrepresentable,
}

/// Learned cue phrases and per-word cue/content counts.
#[derive(Clone, Default)]
pub struct CueMemory {
    prefix: Vec<(u8, Vec<u64>)>,
    suffix: Vec<(u8, Vec<u64>)>,
    stats: BTreeMap<(u8, u64), (u16, u16)>,
}

const TRAIL_POLITE: &[&str] = &["please", "thanks"];

fn h(t: &Token) -> u64 {
    fnv(t.word.as_bytes())
}

impl CueMemory {
    /// Bytes held (approximate).
    pub fn bytes(&self) -> usize {
        (self.prefix.iter().chain(self.suffix.iter()))
            .map(|c| 32 + c.1.capacity() * 8)
            .sum::<usize>()
            + self.stats.len() * 48
    }

    /// Number of learned cues.
    pub fn cues(&self) -> usize {
        self.prefix.len() + self.suffix.len()
    }

    fn add_cue(list: &mut Vec<(u8, Vec<u64>)>, a: u8, c: Vec<u64>, total: usize) {
        if c.len() > MAX_CUE_WORDS || total >= MAX_CUES {
            return;
        }
        if !list.iter().any(|x| x.0 == a && x.1 == c) {
            list.push((a, c));
        }
    }

    fn bump(&mut self, a: u8, t: &Token, cue: bool) {
        let k = (a, h(t));
        if !self.stats.contains_key(&k) && self.stats.len() >= MAX_STATS {
            return;
        }
        let e = self.stats.entry(k).or_insert((0, 0));
        if cue {
            e.0 = e.0.saturating_add(1);
        } else {
            e.1 = e.1.saturating_add(1);
        }
    }

    /// Learn from one example whose text occupies bytes `[bs, be)` of the message.
    /// Returns false when the span does not fall on token boundaries inside the clause.
    pub fn learn(&mut self, toks: &[Token], c: Clause, a: Action, bs: usize, be: usize) -> bool {
        let lead = skip_polite(toks, c.start, c.end);
        let s0 = (c.start..c.end).find(|&i| toks[i].start >= bs);
        let e0 = (c.start..c.end).rev().find(|&i| toks[i].end <= be);
        let (s0, e0) = match (s0, e0) {
            (Some(s), Some(e)) if s <= e && s >= lead => (s, e + 1),
            _ => return false,
        };
        let ai = a.idx() as u8;
        let total = self.cues();
        let pre: Vec<u64> = toks[lead..s0].iter().map(h).collect();
        Self::add_cue(&mut self.prefix, ai, pre, total);
        if e0 < c.end {
            let total = self.cues();
            let suf: Vec<u64> = toks[e0..c.end].iter().map(h).collect();
            Self::add_cue(&mut self.suffix, ai, suf, total);
        }
        for i in lead..s0 {
            self.bump(ai, &toks[i], true);
        }
        for i in s0..e0 {
            self.bump(ai, &toks[i], false);
        }
        true
    }

    fn cue_like(&self, a: u8, t: &Token) -> Option<bool> {
        self.stats.get(&(a, h(t))).map(|(c, p)| c > p)
    }

    /// Token range `[s, e)` of the text for action `a` in clause `c`.
    pub fn bounds(&self, toks: &[Token], c: Clause, a: Action) -> (usize, usize) {
        let ai = a.idx() as u8;
        let lead = skip_polite(toks, c.start, c.end);
        let end = c.end;
        let mut s = None;
        // 1. longest learned non-empty leading cue at the head, or the tail (2+ words) of a
        //    learned cue starting one or two words later ("Create a task to" via "add a task to")
        let mut best = 0;
        for p in lead..core::cmp::min(lead + 3, end) {
            for (la, cue) in &self.prefix {
                if *la != ai || cue.is_empty() {
                    continue;
                }
                for j in 0..cue.len() {
                    let m = cue.len() - j;
                    let full = p == lead && j == 0;
                    if (!full && (m < 2 || p == lead)) || m <= best || p + m >= end {
                        continue;
                    }
                    if cue[j..]
                        .iter()
                        .enumerate()
                        .all(|(k, w)| h(&toks[p + k]) == *w)
                    {
                        best = m;
                        s = Some(p + m);
                    }
                }
            }
        }
        // 2. colon or free dash within the first 8 words, at or after the cue
        {
            let from = s.unwrap_or(lead + 1);
            let hi = core::cmp::min(end, lead + 8);
            if let Some(j) = (from..hi).find(|&j| toks[j].gap & (gap::COLON | gap::DASH) != 0) {
                let ok = toks[s.unwrap_or(lead)..j]
                    .iter()
                    .all(|t| self.cue_like(ai, t).unwrap_or(true));
                if ok {
                    s = Some(j);
                }
            }
        }
        // 3. without a cue: skip a store/to-do/preference frame; then, in every case, skip
        //    words seen more often as cue than as content for this action ("to" after
        //    "add a task")
        let mut v = match s {
            Some(v) => v,
            None => {
                let mut v = lead;
                if a != Action::Prompt {
                    let f = longest(toks, v, TEXT_FRAMES);
                    if v + f < end {
                        v += f;
                    }
                }
                v
            }
        };
        while v + 1 < end && v < lead + 6 && self.cue_like(ai, &toks[v]) == Some(true) {
            v += 1;
        }
        let mut s = v;
        if s >= end {
            s = end;
        }
        // trailing cue (longest learned suffix), then trailing courtesy words
        let mut e = end;
        let mut bests = 0;
        for (la, cue) in &self.suffix {
            if *la != ai || cue.len() <= bests || s + cue.len() >= e {
                continue;
            }
            let at = e - cue.len();
            if cue.iter().enumerate().all(|(k, w)| h(&toks[at + k]) == *w) {
                bests = cue.len();
            }
        }
        e -= bests;
        while e > s + 1 && is_in(TRAIL_POLITE, &toks[e - 1].word) {
            e -= 1;
        }
        if e > s + 2 && toks[e - 2].word == "thank" && toks[e - 1].word == "you" {
            e -= 2;
        }
        (s, e)
    }

    /// Copy the text for action `a` out of `msg`.
    pub fn extract(
        &self,
        msg: &str,
        toks: &[Token],
        c: Clause,
        a: Action,
    ) -> Result<(String, usize, usize), SpanError> {
        let (s, e) = self.bounds(toks, c, a);
        if s >= e {
            return Err(SpanError::Empty);
        }
        let content = toks[s..e].iter().any(|t| {
            t.alnum
                && !is_in(VACUOUS, &t.word)
                && !(a == Action::Prompt && is_in(WRITE_VERBS, &t.word))
        });
        if !content {
            return Err(SpanError::Empty);
        }
        let bs = toks[s].start;
        let mut be = toks[e - 1].end;
        let b = msg.as_bytes();
        let opens = b[bs..be].iter().filter(|&&x| x == b'(').count();
        let closes = b[bs..be].iter().filter(|&&x| x == b')').count();
        if opens > closes && be < b.len() && b[be] == b')' {
            be += 1;
        }
        let mut out = String::with_capacity(be - bs);
        for ch in msg[bs..be].chars() {
            match ch {
                '\u{2019}' | '\u{2018}' => out.push('\''),
                c => out.push(c),
            }
        }
        if out.len() > MAX_TEXT {
            return Err(SpanError::TooLong);
        }
        if out
            .bytes()
            .any(|x| !(0x20..=0x7e).contains(&x) || x == b'"' || x == b'\\')
        {
            return Err(SpanError::Unrepresentable);
        }
        Ok((out, bs, be))
    }
}
