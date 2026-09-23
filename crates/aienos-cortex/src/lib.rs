//! AIENOS Cortex Epistemic Store (§11).
//!
//! Preserves durable epistemic memory with verifiable provenance:
//! DirectObservation, VerifiedFact, Inference, Hypothesis, Contradiction, OperatorDecision.
//! Rejects ungrounded model hallucinations and circular assertions.

pub mod record;
pub mod status;
pub mod store;
pub mod verification;

pub use record::EpistemicRecord;
pub use status::EpistemicStatus;
pub use store::{CortexStore, JournalEnvelope};
pub use verification::{verify_grounding, CortexError};
