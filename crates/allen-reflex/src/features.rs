//! Observable features of one request. All three scorers (hypervector, nearest exemplar,
//! perceptron) read exactly this list, so a comparison between them compares only the scorer.

use crate::action::Action;
use crate::dialog::{DialogState, Pending};
use crate::lexicon::{
    is_in, longest, skip_polite, Concept, CONCEPTS, FILLER, N_CONCEPTS, TEXT_FRAMES, VACUOUS,
};
use crate::segment::Clause;
use crate::text::{fnv, gap, Token};
use alloc::vec::Vec;

/// A symbol: the atom a feature is built from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sym {
    /// word stem (hash)
    Word(u64),
    /// one character of a character n-gram
    Char(u8),
    /// concept class
    Concept(u8),
    /// dialog context value
    Ctx(u8),
    /// shape value (length bucket, question, argument content)
    Shape(u8),
    /// the head word of the request (hash)
    Lead(u64),
}

impl Sym {
    /// (family tag, value) used to seed the item vector.
    pub fn family(self) -> (u64, u64) {
        match self {
            Sym::Word(h) => (1, h),
            Sym::Char(c) => (2, c as u64),
            Sym::Concept(c) => (3, c as u64),
            Sym::Ctx(c) => (4, c as u64),
            Sym::Shape(c) => (5, c as u64),
            Sym::Lead(h) => (6, h),
        }
    }
}

/// Feature channels, each with its own weight.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Channel {
    /// word unigram
    Word = 0,
    /// word bigram (ordered)
    Bigram,
    /// character 3- and 4-grams inside a word
    Chars,
    /// concept class
    Concept,
    /// head word and head bigram
    Lead,
    /// dialog context (pending state, previous decision)
    Ctx,
    /// context bound to concept or head word
    CtxConj,
    /// shape
    Shape,
}

/// Number of channels.
pub const N_CHANNELS: usize = 8;

/// One feature: an ordered tuple of up to 4 symbols, bound together, with a weight.
#[derive(Clone, Copy, Debug)]
pub struct Feat {
    /// symbols, `len` of them used
    pub syms: [Sym; 4],
    /// used symbols
    pub len: u8,
    /// channel
    pub ch: Channel,
    /// weight (from the config)
    pub w: u16,
}

impl Feat {
    /// Stable 64-bit key (sparse scorers).
    pub fn key(&self) -> u64 {
        let mut b = [0u8; 4 * 9 + 1];
        b[0] = self.ch as u8;
        for k in 0..self.len as usize {
            let (f, v) = self.syms[k].family();
            b[1 + k * 9] = f as u8;
            b[2 + k * 9..10 + k * 9].copy_from_slice(&v.to_le_bytes());
        }
        fnv(&b[..1 + self.len as usize * 9])
    }
}

/// Bound on features per request (input is bounded, so this is never reached in practice).
pub const MAX_FEATS: usize = 768;

/// Context symbol values.
fn pend_sym(p: Pending) -> u8 {
    match p {
        Pending::Unknown => 0,
        Pending::Yes => 1,
        Pending::No => 2,
    }
}

/// Count of content words after the head frame ("Add a task." has 0, "Add a task: X" has 1+).
pub fn rest_content(toks: &[Token], c: Clause) -> usize {
    let lead = skip_polite(toks, c.start, c.end);
    let f = longest(toks, lead, TEXT_FRAMES);
    toks[core::cmp::min(lead + f, c.end)..c.end]
        .iter()
        .filter(|t| t.alnum && !is_in(VACUOUS, &t.word) && !is_in(FILLER, &t.word))
        .count()
}

/// Concepts present in `toks[s..e]` (dedup, as a bitmask).
pub fn concepts(toks: &[Token], s: usize, e: usize) -> u32 {
    let mut m = 0u32;
    for i in s..e {
        for (c, phrases) in CONCEPTS {
            if longest(&toks[..e], i, phrases) > 0 {
                m |= 1 << (*c as u32);
            }
        }
    }
    m
}

fn push(v: &mut Vec<Feat>, ch: Channel, w: &[u16; N_CHANNELS], syms: &[Sym]) {
    let wt = w[ch as usize];
    if wt == 0 || v.len() >= MAX_FEATS {
        return;
    }
    let mut s = [Sym::Shape(0); 4];
    s[..syms.len()].copy_from_slice(syms);
    v.push(Feat {
        syms: s,
        len: syms.len() as u8,
        ch,
        w: wt,
    });
}

/// Extract the features of request `c` with dialog state `d`.
pub fn extract(
    toks: &[Token],
    c: Clause,
    d: &DialogState,
    w: &[u16; N_CHANNELS],
    ends_q: bool,
) -> Vec<Feat> {
    let mut v = Vec::new();
    let words: Vec<&Token> = toks[c.start..c.end].iter().filter(|t| t.alnum).collect();
    let mut seen: Vec<u64> = Vec::new();
    for t in &words {
        let h = fnv(t.stem.as_bytes());
        if !seen.contains(&h) {
            seen.push(h);
            push(&mut v, Channel::Word, w, &[Sym::Word(h)]);
        }
    }
    for p in words.windows(2) {
        let a = fnv(p[0].stem.as_bytes());
        let b = fnv(p[1].stem.as_bytes());
        push(&mut v, Channel::Bigram, w, &[Sym::Word(a), Sym::Word(b)]);
    }
    for t in &words {
        let mut buf = [0u8; 34];
        let wb = t.word.as_bytes();
        let n = core::cmp::min(wb.len(), 32);
        buf[0] = b'^';
        buf[1..1 + n].copy_from_slice(&wb[..n]);
        buf[1 + n] = b'$';
        let s = &buf[..n + 2];
        for g in [3usize, 4] {
            if s.len() < g {
                continue;
            }
            for win in s.windows(g) {
                let mut syms = [Sym::Char(0); 4];
                for (k, &ch) in win.iter().enumerate() {
                    syms[k] = Sym::Char(ch);
                }
                push(&mut v, Channel::Chars, w, &syms[..g]);
            }
        }
    }
    let cm = concepts(toks, c.start, c.end);
    for k in 0..N_CONCEPTS as u8 {
        if cm & (1 << k) != 0 {
            push(&mut v, Channel::Concept, w, &[Sym::Concept(k)]);
            push(
                &mut v,
                Channel::CtxConj,
                w,
                &[Sym::Ctx(pend_sym(d.pending)), Sym::Concept(k)],
            );
        }
    }
    let lead = skip_polite(toks, c.start, c.end);
    if lead < c.end {
        let h = fnv(toks[lead].stem.as_bytes());
        push(&mut v, Channel::Lead, w, &[Sym::Lead(h)]);
        push(
            &mut v,
            Channel::CtxConj,
            w,
            &[Sym::Ctx(pend_sym(d.pending)), Sym::Lead(h)],
        );
        if lead + 1 < c.end {
            let h2 = fnv(toks[lead + 1].stem.as_bytes());
            push(&mut v, Channel::Lead, w, &[Sym::Lead(h), Sym::Word(h2)]);
        }
    }
    push(&mut v, Channel::Ctx, w, &[Sym::Ctx(pend_sym(d.pending))]);
    let prev = d.prev.map(|a: Action| a.idx() as u8 + 1).unwrap_or(0);
    push(&mut v, Channel::Ctx, w, &[Sym::Ctx(16 + prev)]);
    let n = words.len();
    let lb = match n {
        0..=1 => 0,
        2 => 1,
        3..=4 => 2,
        5..=8 => 3,
        _ => 4,
    };
    push(&mut v, Channel::Shape, w, &[Sym::Shape(lb)]);
    let q = ends_q
        || toks[c.start + 1..c.end]
            .iter()
            .any(|t| t.gap & gap::QUESTION != 0);
    if q {
        push(&mut v, Channel::Shape, w, &[Sym::Shape(10)]);
    }
    let r = match rest_content(toks, c) {
        0 => 20,
        1..=2 => 21,
        _ => 22,
    };
    push(&mut v, Channel::Shape, w, &[Sym::Shape(r)]);
    v
}

/// Index of a concept for tests and explanations.
pub fn concept_bit(c: Concept) -> u32 {
    1 << (c as u32)
}
