//! Epistemic records capturing knowledge with immutable provenance and evidence hashes.

use crate::status::EpistemicStatus;
use aienos_kernel::crypto::sha256;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Epistemic Record preserving knowledge with verifiable provenance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EpistemicRecord {
    pub id: [u8; 16],
    pub status: EpistemicStatus,
    pub statement: String,
    pub provenance_source: String,
    pub evidence_hash: [u8; 32],
    pub created_at_utc: u64,
    pub confidence: f32,
    pub verified_by: Option<String>,
    pub causal_parents: Vec<[u8; 16]>,
}

impl EpistemicRecord {
    /// Create a new record with calculated deterministic evidence hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: EpistemicStatus,
        statement: impl Into<String>,
        provenance_source: impl Into<String>,
        evidence_payload: &[u8],
        created_at_utc: u64,
        confidence: f32,
        verified_by: Option<String>,
        causal_parents: Vec<[u8; 16]>,
    ) -> Self {
        let stmt = statement.into();
        let prov = provenance_source.into();

        // Calculate cryptographic evidence hash: SHA-256(status || statement || provenance || payload)
        let mut hasher = sha256::Sha256::new();
        hasher.update(&[status as u8]);
        hasher.update(stmt.as_bytes());
        hasher.update(prov.as_bytes());
        hasher.update(evidence_payload);
        for parent in &causal_parents {
            hasher.update(parent);
        }
        let evidence_hash = hasher.finalize();

        // Deterministic ID derived from evidence hash + timestamp
        let mut id_hasher = sha256::Sha256::new();
        id_hasher.update(&evidence_hash);
        id_hasher.update(&created_at_utc.to_be_bytes());
        let full_id = id_hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&full_id[..16]);

        Self {
            id,
            status,
            statement: stmt,
            provenance_source: prov,
            evidence_hash,
            created_at_utc,
            confidence: confidence.clamp(0.0, 1.0),
            verified_by,
            causal_parents,
        }
    }

    /// Hex-formatted string of record ID.
    pub fn id_hex(&self) -> String {
        self.id.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Hex-formatted string of evidence hash.
    pub fn hash_hex(&self) -> String {
        self.evidence_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

impl fmt::Display for EpistemicRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}] ({}) \"{}\" (conf: {:.2}, prov: {})",
            self.status,
            &self.id_hex()[..8],
            self.statement,
            self.confidence,
            self.provenance_source
        )
    }
}
