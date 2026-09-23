//! Cortex Epistemic Store engine managing the verifiable knowledge graph.

use crate::record::EpistemicRecord;
use crate::status::EpistemicStatus;
use crate::verification::{verify_grounding, CortexError};
use aienos_kernel::crypto::sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Epistemic Journal Envelope with cryptographic SHA-256 seal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalEnvelope {
    pub records: Vec<EpistemicRecord>,
    pub seal: [u8; 32],
}

/// Persistent Epistemic Knowledge Store.
#[derive(Default)]
pub struct CortexStore {
    records: HashMap<[u8; 16], EpistemicRecord>,
    status_index: HashMap<EpistemicStatus, Vec<[u8; 16]>>,
}

impl CortexStore {
    /// Initialize a new empty Cortex store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a Direct Observation (hardware sensor, file read, physical input).
    pub fn record_observation(
        &mut self,
        statement: impl Into<String>,
        provenance_source: impl Into<String>,
        raw_evidence: &[u8],
        created_at_utc: u64,
    ) -> EpistemicRecord {
        let record = EpistemicRecord::new(
            EpistemicStatus::DirectObservation,
            statement,
            provenance_source,
            raw_evidence,
            created_at_utc,
            1.0,
            None,
            Vec::new(),
        );
        self.insert_record(record.clone());
        record
    }

    /// Record a Mathematically or Cryptographically Verified Fact.
    pub fn record_verified_fact(
        &mut self,
        statement: impl Into<String>,
        provenance_source: impl Into<String>,
        verifier_tool: &str,
        proof_payload: &[u8],
        causal_parents: Vec<[u8; 16]>,
        created_at_utc: u64,
    ) -> Result<EpistemicRecord, CortexError> {
        let record = EpistemicRecord::new(
            EpistemicStatus::VerifiedFact,
            statement,
            provenance_source,
            proof_payload,
            created_at_utc,
            1.0,
            Some(verifier_tool.to_string()),
            causal_parents,
        );
        self.insert_record(record.clone());
        Ok(record)
    }

    /// Record an Operator Decision (canonical directive from human operator).
    pub fn record_operator_decision(
        &mut self,
        statement: impl Into<String>,
        operator_signature: &str,
        created_at_utc: u64,
    ) -> EpistemicRecord {
        let record = EpistemicRecord::new(
            EpistemicStatus::OperatorDecision,
            statement,
            format!("operator:{}", operator_signature),
            operator_signature.as_bytes(),
            created_at_utc,
            1.0,
            Some(operator_signature.to_string()),
            Vec::new(),
        );
        self.insert_record(record.clone());
        record
    }

    /// Record an Inference deduced by a model.
    ///
    /// Invariant: Must strictly ground in DirectObservation, VerifiedFact, or OperatorDecision.
    /// Rejects ungrounded model hallucinations.
    pub fn record_inference(
        &mut self,
        statement: impl Into<String>,
        model_name: impl Into<String>,
        causal_parents: Vec<[u8; 16]>,
        confidence: f32,
        created_at_utc: u64,
    ) -> Result<EpistemicRecord, CortexError> {
        let record = EpistemicRecord::new(
            EpistemicStatus::Inference,
            statement,
            model_name,
            &[],
            created_at_utc,
            confidence,
            None,
            causal_parents,
        );

        // Strictly verify grounding in verified facts or observations
        verify_grounding(&record, &|id| self.records.get(id))?;

        self.insert_record(record.clone());
        Ok(record)
    }

    /// Record a tentative Hypothesis.
    pub fn record_hypothesis(
        &mut self,
        statement: impl Into<String>,
        agent_source: impl Into<String>,
        causal_parents: Vec<[u8; 16]>,
        created_at_utc: u64,
    ) -> Result<EpistemicRecord, CortexError> {
        let record = EpistemicRecord::new(
            EpistemicStatus::Hypothesis,
            statement,
            agent_source,
            &[],
            created_at_utc,
            0.5,
            None,
            causal_parents,
        );

        // Verify grounding in valid parent records
        verify_grounding(&record, &|id| self.records.get(id))?;

        self.insert_record(record.clone());
        Ok(record)
    }

    /// Flag a detected Contradiction between two existing epistemic records.
    pub fn flag_contradiction(
        &mut self,
        record_a_id: [u8; 16],
        record_b_id: [u8; 16],
        reason: &str,
        created_at_utc: u64,
    ) -> Result<EpistemicRecord, CortexError> {
        if !self.records.contains_key(&record_a_id) {
            return Err(CortexError::RecordNotFound(record_a_id));
        }
        if !self.records.contains_key(&record_b_id) {
            return Err(CortexError::RecordNotFound(record_b_id));
        }

        let record = EpistemicRecord::new(
            EpistemicStatus::Contradiction,
            format!("Contradiction detected: {}", reason),
            "cortex_sentinel",
            reason.as_bytes(),
            created_at_utc,
            1.0,
            None,
            vec![record_a_id, record_b_id],
        );

        self.insert_record(record.clone());
        Ok(record)
    }

    /// Retrieve an individual record by ID.
    pub fn get(&self, id: &[u8; 16]) -> Option<&EpistemicRecord> {
        self.records.get(id)
    }

    /// Retrieve all records of a specific epistemic status.
    pub fn find_by_status(&self, status: EpistemicStatus) -> Vec<&EpistemicRecord> {
        self.status_index
            .get(&status)
            .map(|ids| ids.iter().filter_map(|id| self.records.get(id)).collect())
            .unwrap_or_default()
    }

    /// Total records in store.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if store is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn insert_record(&mut self, record: EpistemicRecord) {
        let id = record.id;
        let status = record.status;
        self.status_index.entry(status).or_default().push(id);
        self.records.insert(id, record);
    }

    /// Export durable journal with SHA-256 integrity seal.
    pub fn export_journal(&self) -> Result<Vec<u8>, CortexError> {
        let mut list: Vec<EpistemicRecord> = self.records.values().cloned().collect();
        // Deterministic sort by timestamp, then id
        list.sort_by(|a, b| {
            a.created_at_utc
                .cmp(&b.created_at_utc)
                .then_with(|| a.id.cmp(&b.id))
        });

        let serialized =
            serde_json::to_vec(&list).map_err(|e| CortexError::CorruptedJournal(e.to_string()))?;
        let seal = sha256::hash(&serialized);

        let envelope = JournalEnvelope {
            records: list,
            seal,
        };

        serde_json::to_vec(&envelope).map_err(|e| CortexError::CorruptedJournal(e.to_string()))
    }

    /// Import journal across reboot, verifying cryptographic seal and rebuilding indexes.
    pub fn import_journal(&mut self, journal_data: &[u8]) -> Result<usize, CortexError> {
        let envelope: JournalEnvelope = serde_json::from_slice(journal_data)
            .map_err(|e| CortexError::CorruptedJournal(e.to_string()))?;

        let serialized = serde_json::to_vec(&envelope.records)
            .map_err(|e| CortexError::CorruptedJournal(e.to_string()))?;
        let computed_seal = sha256::hash(&serialized);

        if envelope.seal != computed_seal {
            return Err(CortexError::IntegrityChecksumMismatch);
        }

        let count = envelope.records.len();
        for record in envelope.records {
            self.insert_record(record);
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epistemic_grounding_and_hallucination_rejection() {
        let mut cortex = CortexStore::new();

        // 1. Record raw hardware observation
        let obs = cortex.record_observation(
            "UART0 base physical address is 0x09000000",
            "device_tree",
            b"phys_uart0_reg",
            100,
        );

        // 2. Valid inference derived from observation
        let inf = cortex
            .record_inference(
                "Driver can safely bind to UART0 MMIO",
                "llama3-spark",
                vec![obs.id],
                0.95,
                101,
            )
            .expect("Valid grounded inference");
        assert_eq!(inf.status, EpistemicStatus::Inference);

        // Deep grounded inference: inf2 -> inf -> obs
        let inf2 = cortex
            .record_inference(
                "Early console can initialize without Linux driver",
                "llama3-spark",
                vec![inf.id],
                0.90,
                102,
            )
            .expect("Valid deep grounded inference");
        assert_eq!(inf2.status, EpistemicStatus::Inference);

        // 3. Hallucination test: attempt ungrounded inference (no parents)
        let hallucination_empty = cortex.record_inference(
            "The system has 1024 GB10 GPUs connected",
            "speculative_model",
            vec![],
            0.99,
            103,
        );
        assert!(matches!(
            hallucination_empty,
            Err(CortexError::UngroundedAssertion(_))
        ));

        // 4. Hallucination test: circular inference with no ground truth
        let mut circular_rec_a = EpistemicRecord::new(
            EpistemicStatus::Inference,
            "Claim A is true because Claim B is true",
            "model_hallucination",
            &[],
            104,
            0.8,
            None,
            vec![], // filled below
        );
        let circular_rec_b = EpistemicRecord::new(
            EpistemicStatus::Inference,
            "Claim B is true because Claim A is true",
            "model_hallucination",
            &[],
            104,
            0.8,
            None,
            vec![circular_rec_a.id],
        );
        circular_rec_a.causal_parents = vec![circular_rec_b.id];

        // If we inject circular records manually into store, verify_grounding must detect cycle
        cortex.insert_record(circular_rec_a.clone());
        cortex.insert_record(circular_rec_b.clone());

        let res_a = verify_grounding(&circular_rec_a, &|id| cortex.get(id));
        assert!(matches!(
            res_a,
            Err(CortexError::CircularDependencyDetected(_))
        ));

        // 5. Hallucination test: references non-existent parent
        let forged_id = [0xAAu8; 16];
        let hallucination_forged = cortex.record_inference(
            "Secret backdoors exist in kernel",
            "adversarial_prompt",
            vec![forged_id],
            0.8,
            105,
        );
        assert!(matches!(
            hallucination_forged,
            Err(CortexError::RecordNotFound(_))
        ));

        // 6. Mixed parent grounding rejection: one grounded observation + one ungrounded hallucination
        // Must NOT allow the observation to mask the hallucinated parent!
        let ungrounded_parent = EpistemicRecord::new(
            EpistemicStatus::Inference,
            "Fabricated premise with zero grounding",
            "malicious_model",
            &[],
            106,
            0.9,
            None,
            vec![], // No causal parents!
        );
        cortex.insert_record(ungrounded_parent.clone());

        let mixed_inference = cortex.record_inference(
            "Hybrid inference based on observation AND fabrication",
            "hybrid_model",
            vec![obs.id, ungrounded_parent.id],
            0.85,
            107,
        );
        assert!(
            matches!(mixed_inference, Err(CortexError::UngroundedAssertion(_))),
            "Inference containing even one ungrounded parent must be rejected"
        );

        // 7. Transitive grounding: Observation -> Hypothesis -> Inference
        let hypo = cortex
            .record_hypothesis(
                "Hypothesis derived from valid observation",
                "explorer_agent",
                vec![obs.id],
                108,
            )
            .expect("Hypothesis grounded in observation must succeed");

        let transitive_inf = cortex
            .record_inference(
                "Inference deduced from verified hypothesis",
                "reasoning_model",
                vec![hypo.id],
                0.95,
                109,
            )
            .expect("Transitively grounded inference must succeed");
        assert_eq!(transitive_inf.causal_parents, vec![hypo.id]);

        // 8. Flag contradiction between opposing assertions
        let contradiction = cortex
            .flag_contradiction(
                obs.id,
                ungrounded_parent.id,
                "Hardware sensor disagrees with fabricated premise",
                110,
            )
            .expect("Flag contradiction");
        assert_eq!(contradiction.status, EpistemicStatus::Contradiction);
    }

    #[test]
    fn test_cortex_persistence_and_status_queries() {
        let mut cortex = CortexStore::new();
        let obs = cortex.record_observation("Boot completed at tick 42", "kernel_log", b"", 100);
        let fact = cortex
            .record_verified_fact(
                "SHA256 test vector passes FIPS 180-4",
                "test_suite",
                "cargo_test",
                b"proof",
                vec![obs.id],
                101,
            )
            .unwrap();

        let op = cortex.record_operator_decision(
            "Promote Phase 3 to canonical state",
            "operator_ed25519_key",
            102,
        );

        assert_eq!(
            cortex
                .find_by_status(EpistemicStatus::DirectObservation)
                .len(),
            1
        );
        assert_eq!(
            cortex.find_by_status(EpistemicStatus::VerifiedFact).len(),
            1
        );
        assert_eq!(
            cortex
                .find_by_status(EpistemicStatus::OperatorDecision)
                .len(),
            1
        );

        // Export and restore across simulated reboot
        let journal = cortex.export_journal().expect("Export journal");
        let mut restored = CortexStore::new();
        let imported_count = restored.import_journal(&journal).expect("Import journal");
        assert_eq!(imported_count, 3);
        assert_eq!(restored.get(&obs.id).unwrap().statement, obs.statement);
        assert_eq!(restored.get(&fact.id).unwrap().statement, fact.statement);
        assert_eq!(restored.get(&op.id).unwrap().statement, op.statement);
    }
}
