//! Append-only TokenHistory log with cryptographic rolling hash chains.

use aienos_kernel::crypto::sha256;
use serde::{Deserialize, Serialize};

/// Record of an individual token and its cryptographic chain state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    pub sequence_idx: u64,
    pub token_id: u32,
    pub token_hash: [u8; 32],
}

/// Append-only log of token sequence IDs & hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenHistory {
    records: Vec<TokenRecord>,
    rolling_hash: [u8; 32],
}

impl Default for TokenHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenHistory {
    /// Initialize an empty token history with genesis rolling hash.
    pub fn new() -> Self {
        let genesis_hash = sha256::hash(b"AIENOS_TOKEN_GENESIS_v1");
        Self {
            records: Vec::new(),
            rolling_hash: genesis_hash,
        }
    }

    /// Number of tokens in history.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if history is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Current cumulative rolling hash.
    pub fn rolling_hash(&self) -> [u8; 32] {
        self.rolling_hash
    }

    /// Slice of all token records.
    pub fn records(&self) -> &[TokenRecord] {
        &self.records
    }

    /// Extract raw token IDs.
    pub fn tokens(&self) -> Vec<u32> {
        self.records.iter().map(|r| r.token_id).collect()
    }

    /// Append a single token to the history log, updating rolling cryptographic hash.
    pub fn append(&mut self, token_id: u32) {
        let seq = self.records.len() as u64;
        let mut hasher = sha256::Sha256::new();
        hasher.update(&self.rolling_hash);
        hasher.update(&seq.to_be_bytes());
        hasher.update(&token_id.to_be_bytes());
        let next_hash = hasher.finalize();

        self.records.push(TokenRecord {
            sequence_idx: seq,
            token_id,
            token_hash: next_hash,
        });
        self.rolling_hash = next_hash;
    }

    /// Append a batch of tokens sequentially.
    pub fn append_tokens(&mut self, tokens: &[u32]) {
        for &t in tokens {
            self.append(t);
        }
    }

    /// Fork this token history into a new independent branch starting from this state.
    pub fn fork(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_history_rolling_hash() {
        let mut h1 = TokenHistory::new();
        h1.append_tokens(&[101, 202, 303]);

        let mut h2 = TokenHistory::new();
        h2.append_tokens(&[101, 202, 303]);

        assert_eq!(h1.len(), 3);
        assert_eq!(h1.rolling_hash(), h2.rolling_hash());
        assert_eq!(h1.tokens(), vec![101, 202, 303]);

        // Appending different tokens must diverge hashes
        let mut h3 = h1.fork();
        h3.append(404);
        assert_ne!(h1.rolling_hash(), h3.rolling_hash());
    }
}
