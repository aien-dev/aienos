//! AEGIS Effect Broker: Dispatching approved intents to hardware and drivers (§5).

use crate::capability::{AegisError, CapabilityGraph};
use crate::effect::{EffectIntent, OperatorGrant};
use crate::evaluator::{AegisDecision, AegisEvaluator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Immutable audit record of an effect evaluation and execution attempt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectAuditRecord {
    pub intent_id: [u8; 16],
    pub action: String,
    pub timestamp_utc: u64,
    pub decision: AegisDecision,
    pub executed: bool,
    pub error: Option<String>,
}

pub type EffectHandlerFn = Box<dyn Fn(&EffectIntent) -> Result<String, String> + Send + Sync>;

/// Sovereign Effect Broker enforcing authorization before hardware execution.
pub struct EffectBroker {
    evaluator: AegisEvaluator,
    handlers: HashMap<String, EffectHandlerFn>,
    audit_ledger: Vec<EffectAuditRecord>,
}

impl EffectBroker {
    /// Initialize Effect Broker with an evaluator.
    pub fn new(evaluator: AegisEvaluator) -> Self {
        Self {
            evaluator,
            handlers: HashMap::new(),
            audit_ledger: Vec::new(),
        }
    }

    /// Register a native driver/subsystem effect handler.
    pub fn register_handler<F>(&mut self, action_prefix: &str, handler: F)
    where
        F: Fn(&EffectIntent) -> Result<String, String> + Send + Sync + 'static,
    {
        self.handlers
            .insert(action_prefix.to_string(), Box::new(handler));
    }

    /// Dispatch an effect intent through AEGIS authorization.
    ///
    /// Rejects any irreversible effect originating from an unapproved intent.
    pub fn dispatch(
        &mut self,
        intent: &EffectIntent,
        graph: &CapabilityGraph,
        grant: Option<&OperatorGrant>,
        now_utc: u64,
    ) -> Result<String, AegisError> {
        let decision = self.evaluator.evaluate(intent, graph, grant, now_utc);

        match &decision {
            AegisDecision::Approved { .. } => {
                // Prefer the most specific matching action prefix.
                let handler = self
                    .handlers
                    .iter()
                    .filter(|(prefix, _)| intent.action.starts_with(prefix.as_str()))
                    .max_by_key(|(prefix, _)| prefix.len())
                    .map(|(_, h)| h);

                let result = if let Some(h) = handler {
                    h(intent).map_err(AegisError::ExecutionFailed)
                } else {
                    Err(AegisError::ExecutionFailed(format!(
                        "no handler registered for {}",
                        intent.action
                    )))
                };

                let is_ok = result.is_ok();
                let err_msg = result.as_ref().err().map(|e| e.to_string());

                self.audit_ledger.push(EffectAuditRecord {
                    intent_id: intent.id,
                    action: intent.action.clone(),
                    timestamp_utc: now_utc,
                    decision: decision.clone(),
                    executed: is_ok,
                    error: err_msg,
                });

                result
            }
            AegisDecision::RequiresOperatorApproval { reason, .. } => {
                let err_reason = reason.clone();
                self.audit_ledger.push(EffectAuditRecord {
                    intent_id: intent.id,
                    action: intent.action.clone(),
                    timestamp_utc: now_utc,
                    decision,
                    executed: false,
                    error: Some(err_reason),
                });
                Err(AegisError::MissingOperatorGrant)
            }
            AegisDecision::Rejected { reason } => {
                let err_reason = reason.clone();
                self.audit_ledger.push(EffectAuditRecord {
                    intent_id: intent.id,
                    action: intent.action.clone(),
                    timestamp_utc: now_utc,
                    decision,
                    executed: false,
                    error: Some(err_reason.clone()),
                });
                Err(AegisError::IrreversibleEffectDenied(err_reason))
            }
        }
    }

    /// Audit ledger of all effect attempts.
    pub fn audit_ledger(&self) -> &[EffectAuditRecord] {
        &self.audit_ledger
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityScope;
    use aienos_agent_state::LogicalAgentId;
    use std::collections::BTreeMap;

    #[test]
    fn test_aegis_reversible_vs_irreversible_enforcement() {
        let master_secret = [0x42u8; 32];
        let operator_secret = [0x99u8; 32];

        let mut graph = CapabilityGraph::new(master_secret);
        let agent = LogicalAgentId::from_seed("aegis-test-agent");

        let fs_cap_id = [1u8; 16];
        graph.issue_root_token(
            fs_cap_id,
            agent,
            CapabilityScope::Filesystem {
                path_prefix: "/workspace".to_string(),
                read_only: false,
            },
            3,
            2000,
        );

        let evaluator = AegisEvaluator::new(operator_secret);
        let mut broker = EffectBroker::new(evaluator);

        // 1. REVERSIBLE: inside J-Space World -> Auto-Approved
        let mut params = BTreeMap::new();
        params.insert("path".to_string(), "/workspace/test.txt".to_string());
        let world_id = Some([0xAAu8; 16]);

        let reversible_intent = EffectIntent::new(
            agent,
            "fs.write",
            params.clone(),
            fs_cap_id,
            true, // is_reversible
            world_id,
        );

        let missing_handler = broker.dispatch(&reversible_intent, &graph, None, 99);
        assert!(matches!(
            missing_handler,
            Err(AegisError::ExecutionFailed(_))
        ));
        assert!(!broker.audit_ledger()[0].executed);
        broker.register_handler("fs.write", |_| Ok("mock file write".to_string()));
        broker.register_handler("net.fetch", |_| Ok("mock network fetch".to_string()));

        let rev_result = broker.dispatch(&reversible_intent, &graph, None, 100);
        assert!(
            rev_result.is_ok(),
            "Reversible intent inside world must succeed"
        );

        // 2. IRREVERSIBLE: outside world without Operator Grant -> REJECTED
        let irreversible_intent = EffectIntent::new(
            agent,
            "fs.write",
            params.clone(),
            fs_cap_id,
            false, // is_reversible == false
            None,
        );

        let unapproved_res = broker.dispatch(&irreversible_intent, &graph, None, 101);
        assert!(
            matches!(unapproved_res, Err(AegisError::MissingOperatorGrant)),
            "Irreversible intent without operator grant must be rejected"
        );

        // 3. IRREVERSIBLE with valid Operator Grant -> APPROVED
        let grant = OperatorGrant::issue(
            irreversible_intent.id,
            "human_operator_1",
            &operator_secret,
            102,
        );

        let approved_res = broker.dispatch(&irreversible_intent, &graph, Some(&grant), 102);
        assert!(
            approved_res.is_ok(),
            "Irreversible intent with operator grant must succeed"
        );

        // 4. Verification that forged operator grant fails
        let bad_secret = [0x00u8; 32];
        let forged_grant =
            OperatorGrant::issue(irreversible_intent.id, "forged_operator", &bad_secret, 103);
        let forged_res = broker.dispatch(&irreversible_intent, &graph, Some(&forged_grant), 103);
        assert!(
            forged_res.is_err(),
            "Forged operator grant must be strictly rejected"
        );

        // 5. ADR 0004: Autonomous external outbound fetch via Standing Capability
        let standing_cap_id = [2u8; 16];
        graph.issue_root_token(
            standing_cap_id,
            agent,
            CapabilityScope::StandingFetch {
                host: "api.sovereign.local".to_string(),
            },
            2,
            2000,
        );

        let mut fetch_params = BTreeMap::new();
        fetch_params.insert("host".to_string(), "api.sovereign.local".to_string());
        let fetch_intent = EffectIntent::new(
            agent,
            "net.fetch",
            fetch_params,
            standing_cap_id,
            false, // external effect crossing boundary
            None,
        );

        // Dispatches autonomously without requiring interactive human prompt
        let fetch_res = broker.dispatch(&fetch_intent, &graph, None, 104);
        assert!(
            fetch_res.is_ok(),
            "Standing capability autonomous fetch must be authorized"
        );
    }
}
