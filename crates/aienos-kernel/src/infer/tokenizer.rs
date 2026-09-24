//! Byte-level BPE tokenizer.
//!
//! Vocabulary text is UTF-8 with one record per line. `T id hexbytes` adds a
//! regular token, `M left_id right_id` adds a merge (records are in increasing
//! rank order), and `S id hexbytes` adds a special token. Hex is case
//! insensitive, must contain complete byte pairs, and may be empty. Blank
//! lines and lines whose first non-space character is `#` are ignored. Token
//! IDs are unique across `T` and `S`; merge pairs are unique. The merged token
//! is found by concatenating the two vocabulary byte strings, so it must have
//! a `T` record. Every byte value used by input must have a one-byte `T`
//! record, allowing explicit byte fallback without lossy unknown handling.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Reverse;

/// Failure while loading vocabulary data or encoding/decoding tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenizerError {
    InvalidRecord,
    InvalidId,
    InvalidHex,
    DuplicateId(u32),
    DuplicateMerge(u32, u32),
    MissingToken(u32),
    MissingByte(u8),
}

/// A byte-level BPE vocabulary with ranked merges and special tokens.
#[derive(Clone, Debug)]
pub struct BpeTokenizer {
    tokens: BTreeMap<u32, Vec<u8>>,
    ids_by_bytes: BTreeMap<Vec<u8>, u32>,
    merges: Vec<(u32, u32)>,
    specials: Vec<(u32, Vec<u8>)>,
}

impl BpeTokenizer {
    /// Load `T`, `M`, and `S` records from the documented text format.
    pub fn from_text(input: &str) -> Result<Self, TokenizerError> {
        let mut tokenizer = Self {
            tokens: BTreeMap::new(),
            ids_by_bytes: BTreeMap::new(),
            merges: Vec::new(),
            specials: Vec::new(),
        };
        for line in input.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["T", id, bytes] | ["S", id, bytes] => {
                    let id = id.parse().map_err(|_| TokenizerError::InvalidId)?;
                    let bytes = decode_hex(bytes)?;
                    if fields[0] == "S" && bytes.is_empty() {
                        return Err(TokenizerError::InvalidRecord);
                    }
                    if tokenizer.tokens.contains_key(&id) {
                        return Err(TokenizerError::DuplicateId(id));
                    }
                    if fields[0] == "T" {
                        if tokenizer.ids_by_bytes.contains_key(&bytes) {
                            return Err(TokenizerError::InvalidRecord);
                        }
                        tokenizer.ids_by_bytes.insert(bytes.clone(), id);
                    } else {
                        tokenizer.specials.push((id, bytes.clone()));
                    }
                    tokenizer.tokens.insert(id, bytes);
                }
                ["M", left, right] => {
                    let left = left.parse().map_err(|_| TokenizerError::InvalidId)?;
                    let right = right.parse().map_err(|_| TokenizerError::InvalidId)?;
                    if tokenizer.merges.contains(&(left, right)) {
                        return Err(TokenizerError::DuplicateMerge(left, right));
                    }
                    tokenizer.merges.push((left, right));
                }
                _ => return Err(TokenizerError::InvalidRecord),
            }
        }
        for (left, right) in &tokenizer.merges {
            if !tokenizer.tokens.contains_key(left) {
                return Err(TokenizerError::MissingToken(*left));
            }
            if !tokenizer.tokens.contains_key(right) {
                return Err(TokenizerError::MissingToken(*right));
            }
            let mut bytes = tokenizer.tokens[left].clone();
            bytes.extend_from_slice(&tokenizer.tokens[right]);
            if !tokenizer.ids_by_bytes.contains_key(&bytes) {
                return Err(TokenizerError::InvalidRecord);
            }
        }
        tokenizer
            .specials
            .sort_by_key(|special| Reverse(special.1.len()));
        Ok(tokenizer)
    }

    /// Encode UTF-8 text, matching special tokens before applying BPE.
    pub fn encode(&self, text: &str) -> Result<Vec<u32>, TokenizerError> {
        let input = text.as_bytes();
        let mut output = Vec::new();
        let mut ordinary = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            if let Some((id, bytes)) = self
                .specials
                .iter()
                .find(|(_, bytes)| input[offset..].starts_with(bytes))
            {
                self.encode_bytes(&ordinary, &mut output)?;
                ordinary.clear();
                output.push(*id);
                offset += bytes.len();
            } else {
                ordinary.push(input[offset]);
                offset += 1;
            }
        }
        self.encode_bytes(&ordinary, &mut output)?;
        Ok(output)
    }

    /// Decode token IDs to their original bytes.
    pub fn decode(&self, ids: &[u32]) -> Result<Vec<u8>, TokenizerError> {
        let mut output = Vec::new();
        for id in ids {
            let bytes = self
                .tokens
                .get(id)
                .ok_or(TokenizerError::MissingToken(*id))?;
            output.extend_from_slice(bytes);
        }
        Ok(output)
    }

    fn encode_bytes(&self, bytes: &[u8], output: &mut Vec<u32>) -> Result<(), TokenizerError> {
        let mut pieces = Vec::with_capacity(bytes.len());
        for byte in bytes {
            pieces.push(
                *self
                    .ids_by_bytes
                    .get(&[*byte][..])
                    .ok_or(TokenizerError::MissingByte(*byte))?,
            );
        }
        loop {
            let best = self.merges.iter().enumerate().find_map(|(rank, pair)| {
                pieces
                    .windows(2)
                    .position(|window| window == [pair.0, pair.1])
                    .map(|at| (rank, at))
            });
            let Some((_, at)) = best else { break };
            let left = self.tokens[&pieces[at]].as_slice();
            let right = self.tokens[&pieces[at + 1]].as_slice();
            let mut merged = Vec::with_capacity(left.len() + right.len());
            merged.extend_from_slice(left);
            merged.extend_from_slice(right);
            pieces[at] = self.ids_by_bytes[&merged];
            pieces.remove(at + 1);
        }
        output.extend(pieces);
        Ok(())
    }
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, TokenizerError> {
    if hex.len() & 1 != 0 {
        return Err(TokenizerError::InvalidHex);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let encoded = hex.as_bytes();
    for index in (0..encoded.len()).step_by(2) {
        let high = hex_digit(encoded[index]).ok_or(TokenizerError::InvalidHex)?;
        let low = hex_digit(encoded[index + 1]).ok_or(TokenizerError::InvalidHex)?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn tiny() -> BpeTokenizer {
        let mut vocab = String::new();
        for byte in 0u8..=255 {
            vocab.push_str(&format!("T {} {:02x}\n", byte, byte));
        }
        vocab.push_str("T 300 6869\nT 301 686920\nT 302 6869207468657265\n");
        vocab.push_str("T 303 7468\nT 304 746865\nT 305 74686572\nT 306 7468657265\n");
        vocab.push_str("S 400 3c7c626f737c3e\nS 401 3c7c656f737c3e\n");
        vocab.push_str("M 104 105\nM 116 104\nM 303 101\nM 304 114\nM 305 101\n");
        vocab.push_str("M 300 32\nM 301 306\n");
        BpeTokenizer::from_text(&vocab).unwrap()
    }

    #[test]
    fn applies_lowest_ranked_merge_first() {
        let tokenizer = tiny();
        assert_eq!(tokenizer.encode("hi").unwrap(), vec![300]);
        assert_eq!(tokenizer.encode("hi there").unwrap(), vec![302]);
    }

    #[test]
    fn round_trips_ascii_utf8_empty_and_fallback() {
        let tokenizer = tiny();
        for text in ["hello", "AIENOS", "héllo 世界", "", "🦀"] {
            let ids = tokenizer.encode(text).unwrap();
            assert_eq!(tokenizer.decode(&ids).unwrap(), text.as_bytes());
        }
        assert_eq!(tokenizer.encode("?").unwrap(), vec![b'?' as u32]);
    }

    #[test]
    fn matches_special_tokens_before_bpe() {
        let tokenizer = tiny();
        let ids = tokenizer.encode("<|bos|>hi<|eos|>").unwrap();
        assert_eq!(ids, vec![400, 300, 401]);
        assert_eq!(tokenizer.decode(&ids).unwrap(), b"<|bos|>hi<|eos|>");
    }

    #[test]
    fn reports_missing_byte_and_bad_format() {
        assert_eq!(
            BpeTokenizer::from_text("T 1 0").unwrap_err(),
            TokenizerError::InvalidHex
        );
        let tokenizer = BpeTokenizer::from_text("T 1 61").unwrap();
        assert_eq!(
            tokenizer.encode("b"),
            Err(TokenizerError::MissingByte(b'b'))
        );
    }
}
