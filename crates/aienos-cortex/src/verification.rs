//! Grounding verification and hallucination detection for Cortex Epistemic Store.

use crate::record::EpistemicRecord;
use core::fmt;
use std::collections::HashSet;

/// Errors arising during Cortex epistemic storage or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CortexError {
    UngroundedAssertion(String),
    CircularDependencyDetected(Vec<[u8; 16]>),
    RecordNotFound([u8; 16]),
    ContradictionDetected {
        record_a: [u8; 16],
        record_b: [u8; 16],
        reason: String,
    },
    CorruptedJournal(String),
    IntegrityChecksumMismatch,
}

impl fmt::Display for CortexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UngroundedAssertion(msg) => write!(f, "Ungrounded epistemic assertion: {}", msg),
            Self::CircularDependencyDetected(cycle) => {
                write!(
                    f,
                    "Circular epistemic dependency detected across {} records",
                    cycle.len()
                )
            }
            Self::RecordNotFound(id) => write!(f, "Epistemic record not found: {:02x?}", id),
            Self::ContradictionDetected {
                record_a,
                record_b,
                reason,
            } => write!(
                f,
                "Contradiction between {:02x?} and {:02x?}: {}",
                record_a, record_b, reason
            ),
            Self::CorruptedJournal(msg) => write!(f, "Corrupted epistemic journal: {}", msg),
            Self::IntegrityChecksumMismatch => write!(f, "Journal cryptographic checksum mismatch"),
        }
    }
}

/// Recursively verify that a record is strictly grounded in DirectObservation, VerifiedFact, or OperatorDecision.
///
/// Invariant: Every causal ancestry branch MUST terminate in an immutable ground truth.
/// Rejects any assertion that relies even partially on ungrounded hypotheses or missing/circular evidence.
pub fn verify_grounding<'a, F>(record: &EpistemicRecord, lookup: &F) -> Result<(), CortexError>
where
    F: Fn(&[u8; 16]) -> Option<&'a EpistemicRecord>,
{
    if record.status.is_ground_truth() {
        return Ok(());
    }

    if record.causal_parents.is_empty() {
        return Err(CortexError::UngroundedAssertion(format!(
            "Assertion \"{}\" ({:?}) has no causal parent references",
            record.statement, record.status
        )));
    }

    let mut grounded_cache = HashSet::new();
    let mut path = vec![record.id];

    fn check_node<'a, F>(
        current_id: &[u8; 16],
        lookup: &F,
        grounded_cache: &mut HashSet<[u8; 16]>,
        path: &mut Vec<[u8; 16]>,
    ) -> Result<(), CortexError>
    where
        F: Fn(&[u8; 16]) -> Option<&'a EpistemicRecord>,
    {
        if path.contains(current_id) {
            path.push(*current_id);
            return Err(CortexError::CircularDependencyDetected(path.clone()));
        }

        if grounded_cache.contains(current_id) {
            return Ok(());
        }

        let current_rec = lookup(current_id).ok_or(CortexError::RecordNotFound(*current_id))?;

        if current_rec.status.is_ground_truth() {
            grounded_cache.insert(*current_id);
            return Ok(());
        }

        if current_rec.causal_parents.is_empty() {
            return Err(CortexError::UngroundedAssertion(format!(
                "Assertion \"{}\" ({:?}) has no causal parent references",
                current_rec.statement, current_rec.status
            )));
        }

        path.push(*current_id);
        for parent_id in &current_rec.causal_parents {
            check_node(parent_id, lookup, grounded_cache, path)?;
        }
        path.pop();

        grounded_cache.insert(*current_id);
        Ok(())
    }

    for parent_id in &record.causal_parents {
        check_node(parent_id, lookup, &mut grounded_cache, &mut path)?;
    }

    Ok(())
}
