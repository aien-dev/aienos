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
    fn hash_field(hasher: &mut sha256::Sha256, field: &[u8]) {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }

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
        hasher.update(b"AIENOS_INTENT_V1");
        hasher.update(agent_id.as_bytes());
        Self::hash_field(&mut hasher, action_str.as_bytes());
        hasher.update(&claimed_capability_id);
        hasher.update(&[is_reversible as u8]);
        if let Some(wid) = &world_id {
            hasher.update(&[1]);
            hasher.update(wid);
        } else {
            hasher.update(&[0]);
        }
        hasher.update(&(parameters.len() as u64).to_be_bytes());
        for (k, v) in &parameters {
            Self::hash_field(&mut hasher, k.as_bytes());
            Self::hash_field(&mut hasher, v.as_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_id_distinguishes_parameter_boundaries() {
        let agent = LogicalAgentId::from_seed("intent-boundaries");
        let mut first = BTreeMap::new();
        first.insert("ab".into(), "c".into());
        let mut second = BTreeMap::new();
        second.insert("a".into(), "bc".into());
        let first = EffectIntent::new(agent, "fs.write", first, [1; 16], false, None);
        let second = EffectIntent::new(agent, "fs.write", second, [1; 16], false, None);
        assert_ne!(first.id, second.id);
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
        let signature =
            Self::signature_for(&intent_id, operator_id, granted_at_utc, operator_secret);

        Self {
            intent_id,
            operator_id: operator_id.to_string(),
            granted_at_utc,
            signature,
        }
    }

    /// Verify operator grant signature.
    pub fn verify(&self, operator_secret: &[u8; 32]) -> bool {
        Self::signature_for(
            &self.intent_id,
            &self.operator_id,
            self.granted_at_utc,
            operator_secret,
        ) == self.signature
    }

    fn signature_for(
        intent_id: &[u8; 16],
        operator_id: &str,
        granted_at_utc: u64,
        operator_secret: &[u8; 32],
    ) -> [u8; 32] {
        let operator_len = (operator_id.len() as u64).to_be_bytes();
        sha256::hmac_sha256(
            operator_secret,
            &[
                b"AIENOS_GRANT_V1",
                intent_id,
                &operator_len,
                operator_id.as_bytes(),
                &granted_at_utc.to_be_bytes(),
            ],
        )
    }
}
