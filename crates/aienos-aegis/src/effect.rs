//! Effect Intents and Operator Grants conforming to AEGIS (§5).

use aienos_agent_state::LogicalAgentId;
use aienos_kernel::crypto::sha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Effect Intent proposed by an agent reasoning loop.
///
/// Intelligence proposes; deterministic authority disposes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectIntent {
    pub id: [u8; 16],
    pub agent_id: LogicalAgentId,
    pub action: String,
    pub parameters: BTreeMap<String, String>,
    pub claimed_capability_id: [u8; 16],
    pub is_reversible: bool,
    pub world_id: Option<[u8; 16]>,
}

impl EffectIntent {
    /// Create a new effect intent.
    pub fn new(
        agent_id: LogicalAgentId,
        action: impl Into<String>,
        parameters: BTreeMap<String, String>,
        claimed_capability_id: [u8; 16],
        is_reversible: bool,
        world_id: Option<[u8; 16]>,
    ) -> Self {
        let action_str = action.into();
        let mut hasher = sha256::Sha256::new();
        hasher.update(agent_id.as_bytes());
        hasher.update(action_str.as_bytes());
        hasher.update(&claimed_capability_id);
        hasher.update(&[is_reversible as u8]);
        if let Some(wid) = &world_id {
            hasher.update(wid);
        }
        for (k, v) in &parameters {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }
        let digest = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);

        Self {
            id,
            agent_id,
            action: action_str,
            parameters,
            claimed_capability_id,
            is_reversible,
            world_id,
        }
    }
}

/// Explicit Operator Grant required for any irreversible action crossing boundaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorGrant {
    pub intent_id: [u8; 16],
    pub operator_id: String,
    pub granted_at_utc: u64,
    pub signature: [u8; 32],
}

impl OperatorGrant {
    /// Issue an operator grant.
    pub fn issue(
        intent_id: [u8; 16],
        operator_id: &str,
        operator_secret: &[u8; 32],
        granted_at_utc: u64,
    ) -> Self {
        let mut hasher = sha256::Sha256::new();
        hasher.update(operator_secret);
        hasher.update(&intent_id);
        hasher.update(operator_id.as_bytes());
        hasher.update(&granted_at_utc.to_be_bytes());
        let signature = hasher.finalize();

        Self {
            intent_id,
            operator_id: operator_id.to_string(),
            granted_at_utc,
            signature,
        }
    }

    /// Verify operator grant signature.
    pub fn verify(&self, operator_secret: &[u8; 32]) -> bool {
        let mut hasher = sha256::Sha256::new();
        hasher.update(operator_secret);
        hasher.update(&self.intent_id);
        hasher.update(self.operator_id.as_bytes());
        hasher.update(&self.granted_at_utc.to_be_bytes());
        hasher.finalize() == self.signature
    }
}
