//! Tokenizer that keeps the original bytes: every token records its byte range in the
//! message, so an argument is always copied from the operator's own text (case and
//! inner punctuation preserved), never rebuilt from normalized words.

use alloc::string::String;
use alloc::vec::Vec;

/// Punctuation seen in the gap before a token.
pub mod gap {
    /// `.`, `!` or `?` (end of a sentence).
    pub const STOP: u8 = 1;
    /// `,`
    pub const COMMA: u8 = 2;
    /// `:`
    pub const COLON: u8 = 4;
    /// `;`
    pub const SEMI: u8 = 8;
    /// a free-standing dash (`-`, `--`).
    pub const DASH: u8 = 16;
    /// `?` specifically.
    pub const QUESTION: u8 = 32;
}

/// One word of the message.
#[derive(Clone, Debug)]
pub struct Token {
    /// Byte offset of the first byte in the original message.
    pub start: usize,
    /// Byte offset one past the last byte.
    pub end: usize,
    /// Lower-case form (contractions expanded; curly apostrophe made ASCII).
    pub word: String,
    /// Crude stem used for features.
    pub stem: String,
    /// Punctuation in the gap before this token (see [`gap`]).
    pub gap: u8,
    /// True if the token has at least one ASCII letter or digit.
    pub alnum: bool,
}

/// Bytes that end or start a token when they sit at its edge.
fn edge_punct(b: u8) -> bool {
    matches!(
        b,
        b'.' | b','
            | b';'
            | b':'
            | b'!'
            | b'?'
            | b'"'
            | b'\''
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'-'
            | b'`'
            | b'*'
    )
}

fn gap_flags(s: &[u8]) -> u8 {
    let mut f = 0;
    for (i, &b) in s.iter().enumerate() {
        f |= match b {
            b'.' | b'!' => gap::STOP,
            b'?' => gap::STOP | gap::QUESTION,
            b',' => gap::COMMA,
            b':' => gap::COLON,
            b';' => gap::SEMI,
            b'-' => {
                // a dash counts only when free-standing (spaces around it)
                let l = i == 0 || s[i - 1] == b' ' || s[i - 1] == b'-';
                let r = i + 1 == s.len() || s[i + 1] == b' ' || s[i + 1] == b'-';
                if l && r {
                    gap::DASH
                } else {
                    0
                }
            }
            _ => 0,
        };
    }
    f
}

/// Lower-case ASCII; curly apostrophes (U+2019, U+2018) become `'`.
fn lower(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\u{2019}' | '\u{2018}' => o.push('\''),
            _ => o.push(c.to_ascii_lowercase()),
        }
    }
    o
}

/// Contraction expansion: returns up to two words.
fn expand(w: &str) -> (String, Option<&'static str>) {
    const SUF: [(&str, &str, &str); 9] = [
        ("can't", "can", "not"),
        ("won't", "will", "not"),
        ("n't", "", "not"),
        ("'m", "", "am"),
        ("'re", "", "are"),
        ("'ll", "", "will"),
        ("'ve", "", "have"),
        ("'d", "", "would"),
        ("'s", "", ""),
    ];
    for (suf, head, tail) in SUF {
        if w.len() > suf.len() && w.ends_with(suf) {
            let base = if head.is_empty() {
                String::from(&w[..w.len() - suf.len()])
            } else {
                String::from(head)
            };
            if base.is_empty() {
                break;
            }
            return (base, if tail.is_empty() { None } else { Some(tail) });
        }
    }
    (String::from(w), None)
}

/// Very small suffix stripper (features only; never used for copying text).
pub fn stem(w: &str) -> String {
    let n = w.len();
    let b = w.as_bytes();
    if !b.iter().all(|c| c.is_ascii_alphabetic()) || n <= 3 {
        return String::from(w);
    }
    if n > 5 && w.ends_with("ing") {
        return String::from(&w[..n - 3]);
    }
    if n > 4 && w.ends_with("ies") {
        let mut s = String::from(&w[..n - 3]);
        s.push('y');
        return s;
    }
    if n > 4 && w.ends_with("ed") && !w.ends_with("eed") {
        return String::from(&w[..n - 2]);
    }
    if w.ends_with('s') && !w.ends_with("ss") && !w.ends_with("us") && !w.ends_with("is") {
        return String::from(&w[..n - 1]);
    }
    String::from(w)
}

/// Split a message into tokens. Bounded by `max_tokens`.
pub fn tokenize(msg: &str, max_tokens: usize) -> Vec<Token> {
    let b = msg.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut gap_start = 0;
    while i < b.len() && out.len() < max_tokens {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // a whitespace-delimited chunk
        let cs = i;
        while i < b.len() && !b[i].is_ascii_whitespace() {
            i += 1;
        }
        let ce = i;
        let mut s = cs;
        let mut e = ce;
        while s < e && edge_punct(b[s]) {
            s += 1;
        }
        while e > s && edge_punct(b[e - 1]) {
            e -= 1;
        }
        if s == e {
            continue; // pure punctuation: stays in the gap
        }
        // keep the slice on char boundaries (edge_punct bytes are ASCII, so this holds)
        let raw = &msg[s..e];
        let g = gap_flags(&b[gap_start..s]);
        gap_start = e;
        let lw = lower(raw);
        let alnum = lw.bytes().any(|c| c.is_ascii_alphanumeric());
        let (w1, w2) = expand(&lw);
        let st = stem(&w1);
        out.push(Token {
            start: s,
            end: e,
            word: w1,
            stem: st,
            gap: g,
            alnum,
        });
        if let Some(t) = w2 {
            if out.len() < max_tokens {
                out.push(Token {
                    start: s,
                    end: e,
                    word: String::from(t),
                    stem: String::from(t),
                    gap: 0,
                    alnum: true,
                });
            }
        }
    }
    out
}

/// Punctuation flags after the last token (end of message).
pub fn tail_gap(msg: &str, toks: &[Token]) -> u8 {
    let from = toks.last().map(|t| t.end).unwrap_or(0);
    gap_flags(&msg.as_bytes()[from..])
}

/// FNV-1a 64-bit hash.
pub fn fnv(s: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &c in s {
        h ^= c as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
