//! AIENOS AEGIS: Capability Graph, Effect Intent Pipeline, and J-Space Worlds (§13, §5, §12).
//!
//! Enforces unforgeable capability tokens, copy-on-write transactional worlds,
//! and strict boundary policies: intelligence proposes; deterministic authority disposes.

pub mod broker;
pub mod capability;
pub mod effect;
pub mod evaluator;
pub mod world;

pub use broker::{EffectAuditRecord, EffectBroker};
pub use capability::{AegisError, CapabilityGraph, CapabilityScope, CapabilityToken};
pub use effect::{EffectIntent, OperatorGrant};
pub use evaluator::{AegisDecision, AegisEvaluator};
pub use world::{JSpaceWorld, WorldStatus};
