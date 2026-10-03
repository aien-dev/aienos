//! Llama-3 byte-level BPE tokenizer built from the GGUF `tokenizer.ggml.*`
//! arrays (pre-tokenizer `llama-bpe`).
//!
//! Adapted in structure from `crates/aienos-kernel/src/infer/tokenizer.rs`
//! (that one reads a custom text vocabulary; this one reads GGUF tokens and
//! merges and adds the llama-bpe pre-tokenizer split and the GPT-2 byte map).
//! No regex engine: the llama-bpe split is a hand-written matcher with the
//! same alternatives and backtracking as llama.cpp's regex
//! (`llama-vocab.cpp`, `LLAMA_VOCAB_PRE_TYPE_LLAMA3`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::gguf::TokenizerData;

/// Why a tokenizer could not be built or a text could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenizerError {
    /// `tokenizer.ggml.tokens` is empty or too large for u32 ids.
    BadVocab,
    /// A byte-level symbol is missing from the vocabulary.
    MissingSymbol,
    /// A token id is outside the vocabulary.
    BadId(u32),
}

/// Longest pre-token fed to the BPE merge loop (keeps it bounded).
const MAX_WORD_BYTES: usize = 1024;
/// Longest `<|...|>` special token string recognised in text.
const MAX_SPECIAL_BYTES: usize = 64;

const TYPE_CONTROL: i32 = 3;
const TYPE_USER_DEFINED: i32 = 4;

/// GPT-2 `bytes_to_unicode`: printable bytes map to themselves, the rest to
/// U+0100 upward in byte order.
fn byte_to_char(b: u8) -> char {
    let keep = (33..=126).contains(&b) || (161..=172).contains(&b) || (174..=255).contains(&b);
    if keep {
        return b as char;
    }
    // Rank of this byte among the non-kept bytes.
    let mut n = 0u32;
    for x in 0..b {
        let k = (33..=126).contains(&x) || (161..=172).contains(&x) || (174..=255).contains(&x);
        if !k {
            n += 1;
        }
    }
    char::from_u32(256 + n).expect("valid scalar")
}

fn char_to_byte(c: char) -> Option<u8> {
    let cp = c as u32;
    if cp < 256 {
        let b = cp as u8;
        let keep = (33..=126).contains(&b) || (161..=172).contains(&b) || (174..=255).contains(&b);
        return if keep { Some(b) } else { None };
    }
    if cp >= 256 {
        let n = cp - 256;
        let mut seen = 0u32;
        for b in 0..=255u8 {
            let keep =
                (33..=126).contains(&b) || (161..=172).contains(&b) || (174..=255).contains(&b);
            if !keep {
                if seen == n {
                    return Some(b);
                }
                seen += 1;
            }
        }
    }
    None
}

/// Byte-level BPE tokenizer borrowing the GGUF strings.
pub struct Tokenizer<'a> {
    tokens: Vec<&'a str>,
    types: Vec<i32>,
    /// `(token text, id)` sorted by text.
    by_text: Vec<(&'a str, u32)>,
    /// `(merge "left right", rank)` sorted by text.
    merges: Vec<(&'a str, u32)>,
    pub bos_id: Option<u32>,
    pub eos_id: Option<u32>,
    /// `<|eot_id|>` if present.
    pub eot_id: Option<u32>,
    /// Dense table: GPT-2 mapped char of every byte.
    byte_chars: [char; 256],
}

impl<'a> Tokenizer<'a> {
    pub fn new(data: &TokenizerData<'a>) -> Result<Self, TokenizerError> {
        let tokens: Vec<&'a str> = data.tokens.strings().collect();
        if tokens.is_empty()
            || tokens.len() != data.tokens.len()
            || tokens.len() > u32::MAX as usize
        {
            return Err(TokenizerError::BadVocab);
        }
        let types: Vec<i32> = match data.token_type {
            Some(a) => a.i32s().collect(),
            None => Vec::new(),
        };
        let mut by_text: Vec<(&'a str, u32)> = tokens
            .iter()
            .enumerate()
            .map(|(i, t)| (*t, i as u32))
            .collect();
        // Duplicate texts: keep the lowest id (stable sort + dedup below).
        by_text.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));
        by_text.dedup_by(|b, a| a.0 == b.0);
        let mut merges: Vec<(&'a str, u32)> = match data.merges {
            Some(m) => m
                .strings()
                .enumerate()
                .map(|(i, s)| (s, i as u32))
                .collect(),
            None => Vec::new(),
        };
        merges.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));
        merges.dedup_by(|b, a| a.0 == b.0);
        let mut byte_chars = ['\0'; 256];
        for b in 0..=255u8 {
            byte_chars[b as usize] = byte_to_char(b);
        }
        let mut t = Tokenizer {
            tokens,
            types,
            by_text,
            merges,
            bos_id: data.bos_id,
            eos_id: data.eos_id,
            eot_id: None,
            byte_chars,
        };
        t.eot_id = t.lookup("<|eot_id|>");
        Ok(t)
    }

    pub fn vocab_size(&self) -> usize {
        self.tokens.len()
    }

    /// Token text as stored (GPT-2 mapped).
    pub fn token_text(&self, id: u32) -> Option<&'a str> {
        self.tokens.get(id as usize).copied()
    }

    /// Id of an exact token text.
    pub fn lookup(&self, text: &str) -> Option<u32> {
        self.by_text
            .binary_search_by(|p| p.0.cmp(text))
            .ok()
            .map(|i| self.by_text[i].1)
    }

    fn merge_rank(&self, buf: &mut String, left: &str, right: &str) -> Option<u32> {
        buf.clear();
        buf.push_str(left);
        buf.push(' ');
        buf.push_str(right);
        self.merges
            .binary_search_by(|p| p.0.cmp(buf.as_str()))
            .ok()
            .map(|i| self.merges[i].1)
    }

    fn is_special(&self, id: u32) -> bool {
        matches!(
            self.types.get(id as usize),
            Some(&TYPE_CONTROL) | Some(&TYPE_USER_DEFINED)
        )
    }

    /// True for control tokens (printed as nothing).
    pub fn is_control(&self, id: u32) -> bool {
        self.types.get(id as usize) == Some(&TYPE_CONTROL)
    }

    /// Encode `text`. With `parse_special`, `<|name|>` strings that are
    /// control or user-defined tokens become their single id. No BOS is
    /// added (the chat template carries it).
    pub fn encode(&self, text: &str, parse_special: bool) -> Result<Vec<u32>, TokenizerError> {
        let mut out = Vec::new();
        let mut rest = text;
        loop {
            let hit = if parse_special {
                self.find_special(rest)
            } else {
                None
            };
            match hit {
                Some((at, len, id)) => {
                    self.encode_plain(&rest[..at], &mut out)?;
                    out.push(id);
                    rest = &rest[at + len..];
                }
                None => {
                    self.encode_plain(rest, &mut out)?;
                    return Ok(out);
                }
            }
        }
    }

    /// First special token string in `s`: (byte offset, byte length, id).
    fn find_special(&self, s: &str) -> Option<(usize, usize, u32)> {
        let b = s.as_bytes();
        let mut i = 0;
        while i + 1 < b.len() {
            if b[i] == b'<' && b[i + 1] == b'|' {
                let end = (i + MAX_SPECIAL_BYTES).min(b.len());
                let mut j = i + 2;
                while j + 1 < end + 1 && j + 1 < b.len() {
                    if b[j] == b'|' && b[j + 1] == b'>' {
                        let cand = &s[i..j + 2];
                        if let Some(id) = self.lookup(cand) {
                            if self.is_special(id) {
                                return Some((i, cand.len(), id));
                            }
                        }
                        break;
                    }
                    j += 1;
                }
            }
            i += 1;
        }
        None
    }

    fn encode_plain(&self, text: &str, out: &mut Vec<u32>) -> Result<(), TokenizerError> {
        let mut mapped = String::new();
        let mut buf = String::new();
        for word in pretokenize(text) {
            for chunk in word.as_bytes().chunks(MAX_WORD_BYTES) {
                mapped.clear();
                for &b in chunk {
                    mapped.push(self.byte_chars[b as usize]);
                }
                self.bpe_word(&mapped, &mut buf, out)?;
            }
        }
        Ok(())
    }

    fn bpe_word(
        &self,
        word: &str,
        buf: &mut String,
        out: &mut Vec<u32>,
    ) -> Result<(), TokenizerError> {
        // llama-bpe sets ignore_merges: a whole pre-token in the vocab wins.
        if let Some(id) = self.lookup(word) {
            out.push(id);
            return Ok(());
        }
        // Symbols as (start, end) byte ranges of `word`.
        let mut syms: Vec<(usize, usize)> = word
            .char_indices()
            .map(|(i, c)| (i, i + c.len_utf8()))
            .collect();
        loop {
            let mut best: Option<(u32, usize)> = None;
            for i in 0..syms.len().saturating_sub(1) {
                let l = &word[syms[i].0..syms[i].1];
                let r = &word[syms[i + 1].0..syms[i + 1].1];
                if let Some(rank) = self.merge_rank(buf, l, r) {
                    if best.is_none_or(|(br, _)| rank < br) {
                        best = Some((rank, i));
                    }
                }
            }
            match best {
                Some((_, i)) => {
                    syms[i].1 = syms[i + 1].1;
                    syms.remove(i + 1);
                }
                None => break,
            }
        }
        for (s, e) in syms {
            out.push(
                self.lookup(&word[s..e])
                    .ok_or(TokenizerError::MissingSymbol)?,
            );
        }
        Ok(())
    }

    /// Append the raw bytes of token `id` (control tokens add nothing).
    pub fn decode_token(&self, id: u32, out: &mut Vec<u8>) -> Result<(), TokenizerError> {
        let t = self.token_text(id).ok_or(TokenizerError::BadId(id))?;
        if self.is_control(id) {
            return Ok(());
        }
        for c in t.chars() {
            match char_to_byte(c) {
                Some(b) => out.push(b),
                None => {
                    let mut tmp = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
                }
            }
        }
        Ok(())
    }

    /// Bytes for a whole id sequence.
    pub fn decode(&self, ids: &[u32]) -> Result<Vec<u8>, TokenizerError> {
        let mut out = Vec::new();
        for &id in ids {
            self.decode_token(id, &mut out)?;
        }
        Ok(out)
    }

    /// Llama-3 instruct chat template for one user turn, ending at the
    /// assistant header so generation starts the reply.
    pub fn encode_chat(&self, user: &str) -> Result<Vec<u32>, TokenizerError> {
        let mut s = String::from("<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n");
        s.push_str(user);
        s.push_str("<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n");
        self.encode(&s, true)
    }
}

fn is_letter(c: char) -> bool {
    c.is_alphabetic()
}
fn is_number(c: char) -> bool {
    c.is_numeric()
}
fn is_nl(c: char) -> bool {
    c == '\r' || c == '\n'
}

/// Split `text` like the llama-bpe regex:
/// `(?:'[sS]|'[tT]|'[rR][eE]|'[vV][eE]|'[mM]|'[lL][lL]|'[dD])
///  |[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*
///  |\s*[\r\n]+|\s+(?!\S)|\s+`
/// `\p{L}` is approximated by `char::is_alphabetic` (a superset: also
/// letter-numbers and a few combining marks), `\p{N}` by `char::is_numeric`.
pub fn pretokenize(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let end = i + match_one(&text[i..]);
        parts.push(&text[i..end]);
        i = end;
    }
    parts
}

/// Length in bytes of the first match at the start of `s` (always >= 1).
fn match_one(s: &str) -> usize {
    let mut it = s.chars();
    let c0 = it.next().expect("non-empty");
    // 1: contractions
    if c0 == '\'' {
        let rest = &s[1..];
        let low = |n: usize| -> Option<[u8; 2]> {
            let b = rest.as_bytes();
            if b.len() < n {
                return None;
            }
            Some([
                b[0].to_ascii_lowercase(),
                if n > 1 { b[1].to_ascii_lowercase() } else { 0 },
            ])
        };
        if let Some([a, b]) = low(2) {
            if (a == b'r' && b == b'e') || (a == b'v' && b == b'e') || (a == b'l' && b == b'l') {
                return 3;
            }
        }
        if let Some([a, _]) = low(1) {
            if matches!(a, b's' | b't' | b'm' | b'd') {
                return 2;
            }
        }
    }
    // 2: optional one char, then letters
    if is_letter(c0) {
        return c0.len_utf8() + run(&s[c0.len_utf8()..], is_letter);
    }
    if !is_nl(c0) && !is_number(c0) {
        let l0 = c0.len_utf8();
        if s[l0..].chars().next().is_some_and(is_letter) {
            return l0 + run(&s[l0..], is_letter);
        }
    }
    // 3: 1..=3 digits
    if is_number(c0) {
        let mut n = 0;
        let mut len = 0;
        for c in s.chars() {
            if n == 3 || !is_number(c) {
                break;
            }
            len += c.len_utf8();
            n += 1;
        }
        return len;
    }
    // 4: optional space, symbols, trailing newlines
    let sym = |c: char| !c.is_whitespace() && !is_letter(c) && !is_number(c);
    {
        let skip = if c0 == ' ' { 1 } else { 0 };
        let body = run(&s[skip..], sym);
        if body > 0 {
            let tail = run(&s[skip + body..], is_nl);
            return skip + body + tail;
        }
    }
    // 5-7: whitespace handling (c0 is whitespace here)
    let ws = run(s, char::is_whitespace);
    let w = &s[..ws];
    // 5: \s*[\r\n]+  -> through the last newline of the run
    if let Some(p) = w.rfind(is_nl) {
        return p + 1; // \r and \n are one byte
    }
    // 6: \s+(?!\S)
    if ws == s.len() {
        return ws;
    }
    let n_chars = w.chars().count();
    if n_chars > 1 {
        let last = w.chars().next_back().expect("non-empty").len_utf8();
        return ws - last;
    }
    // 7: \s+
    ws
}

/// Byte length of the longest prefix whose chars all satisfy `f`.
fn run(s: &str, f: impl Fn(char) -> bool) -> usize {
    let mut len = 0;
    for c in s.chars() {
        if !f(c) {
            break;
        }
        len += c.len_utf8();
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_map_is_gpt2() {
        assert_eq!(byte_to_char(b'A'), 'A');
        assert_eq!(byte_to_char(b' '), 'Ġ');
        assert_eq!(byte_to_char(b'\n'), 'Ċ');
        assert_eq!(byte_to_char(0), 'Ā');
        assert_eq!(byte_to_char(127), 'ġ');
        assert_eq!(byte_to_char(173), 'ĭ');
        for b in 0..=255u8 {
            assert_eq!(char_to_byte(byte_to_char(b)), Some(b));
        }
    }

    fn split(s: &str) -> Vec<&str> {
        pretokenize(s)
    }

    #[test]
    fn pretokenize_cases() {
        assert_eq!(split("Hello world"), ["Hello", " world"]);
        assert_eq!(
            split("it's I'M we'LL"),
            ["it", "'s", " I", "'M", " we", "'LL"]
        );
        assert_eq!(split("a1234b"), ["a", "123", "4", "b"]);
        assert_eq!(split("x  y"), ["x", " ", " y"]);
        assert_eq!(split("end.\n\nnext"), ["end", ".\n\n", "next"]);
        assert_eq!(split("a \n b"), ["a", " \n", " b"]);
        assert_eq!(split("a   "), ["a", "   "]);
        assert_eq!(split(" ,x"), [" ,", "x"]);
        assert_eq!(split("(abc"), ["(abc"]);
        assert_eq!(split("\n\n"), ["\n\n"]);
        assert_eq!(split("é à"), ["é", " à"]);
        assert_eq!(split("don't"), ["don", "'t"]);
        assert_eq!(split("'x"), ["'x"]);
        assert_eq!(split("1 2"), ["1", " ", "2"]);
    }

    #[test]
    fn pretokenize_covers_input() {
        let s = "Mixed: 12345, \t tabs\r\n\r\n  and ünïcode… ok'd 99 \u{3000} end ";
        assert_eq!(split(s).concat(), s);
    }
}
