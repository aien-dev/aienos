//! AEGIS Effect Broker: Dispatching approved intents to hardware and drivers (§5).

use crate::capability::{AegisError, CapabilityGraph};
use crate::effect::{EffectIntent, OperatorGrant};
use crate::evaluator::{AegisDecision, AegisEvaluator};
use crate::world::{JSpaceWorld, WorldStatus};
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
    worlds: HashMap<[u8; 16], JSpaceWorld>,
    audit_ledger: Vec<EffectAuditRecord>,
}

impl EffectBroker {
    /// Initialize Effect Broker with an evaluator.
    pub fn new(evaluator: AegisEvaluator) -> Self {
        Self {
            evaluator,
            handlers: HashMap::new(),
            worlds: HashMap::new(),
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

    /// Give the broker ownership of a transactional World delta.
    pub fn register_world(&mut self, world: JSpaceWorld) -> Result<(), AegisError> {
        if world.status != WorldStatus::Active || self.worlds.contains_key(&world.world_id) {
            return Err(AegisError::ExecutionFailed(
                "World must be active with a unique ID".to_string(),
            ));
        }
        self.worlds.insert(world.world_id, world);
        Ok(())
    }

    /// Inspect a broker-owned World without mutating its delta.
    pub fn world(&self, id: &[u8; 16]) -> Option<&JSpaceWorld> {
        self.worlds.get(id)
    }

    /// Discard every pending change in a broker-owned World.
    pub fn rollback_world(&mut self, id: &[u8; 16]) -> Result<(), AegisError> {
        let world = self
            .worlds
            .get_mut(id)
            .ok_or_else(|| AegisError::ExecutionFailed("World is not registered".to_string()))?;
        world.rollback();
        Ok(())
    }

    fn apply_world_effect(&mut self, intent: &EffectIntent) -> Result<String, AegisError> {
        let world_id = intent
            .world_id
            .ok_or_else(|| AegisError::ExecutionFailed("World ID is required".to_string()))?;
        let world = self
            .worlds
            .get_mut(&world_id)
            .ok_or_else(|| AegisError::ExecutionFailed("World is not registered".to_string()))?;
        if world.status != WorldStatus::Active {
            return Err(AegisError::ExecutionFailed(
                "World is not active".to_string(),
            ));
        }
        let path = intent.parameters.get("path").ok_or_else(|| {
            AegisError::ExecutionFailed("Filesystem path is required".to_string())
        })?;
        match intent.action.as_str() {
            "fs.write" => {
                let content = intent.parameters.get("content").ok_or_else(|| {
                    AegisError::ExecutionFailed("World write content is required".to_string())
                })?;
                world.write_file(path, content.as_bytes().to_vec());
                Ok("World delta write committed".to_string())
            }
            "fs.delete" => {
                world.delete_file(path);
                Ok("World delta deletion committed".to_string())
            }
            _ => Err(AegisError::ExecutionFailed(
                "Action has no World delta handler".to_string(),
            )),
        }
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
        let world_fs_effect =
            intent.world_id.is_some() && matches!(intent.action.as_str(), "fs.write" | "fs.delete");
        let world_bound = world_fs_effect
            && intent.world_id.is_some_and(|id| {
                self.worlds
                    .get(&id)
                    .is_some_and(|world| world.status == WorldStatus::Active)
            });
        let decision =
            self.evaluator
                .evaluate_with_world_binding(intent, graph, grant, now_utc, world_bound);

        match &decision {
            AegisDecision::Approved { .. } => {
                // Prefer the most specific matching action prefix.
                let handler = self
                    .handlers
                    .iter()
                    .filter(|(prefix, _)| intent.action.starts_with(prefix.as_str()))
                    .max_by_key(|(prefix, _)| prefix.len())
                    .map(|(_, h)| h);

                let result = if world_fs_effect {
                    self.apply_world_effect(intent)
                } else if let Some(h) = handler {
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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

        // 1. A claimed World does not prove the handler is isolated.
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
            Err(AegisError::MissingOperatorGrant)
        ));
        assert!(!broker.audit_ledger()[0].executed);
        broker.register_handler("fs.write", |_| Ok("mock file write".to_string()));
        broker.register_handler("net.fetch", |_| Ok("mock network fetch".to_string()));

        let rev_result = broker.dispatch(&reversible_intent, &graph, None, 100);
        assert!(matches!(rev_result, Err(AegisError::MissingOperatorGrant)));

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

    #[test]
    fn claimed_world_cannot_authorize_network_or_escaped_filesystem_effects() {
        let mut graph = CapabilityGraph::new([0x42; 32]);
        let agent = LogicalAgentId::from_seed("boundary-test-agent");
        let evaluator = AegisEvaluator::new([0x99; 32]);

        let net_id = [1; 16];
        graph.issue_root_token(
            net_id,
            agent,
            CapabilityScope::Network {
                host: "example.org".into(),
                port: 443,
            },
            0,
            2000,
        );
        let mut net_params = BTreeMap::new();
        net_params.insert("host".into(), "example.org".into());
        net_params.insert("port".into(), "443".into());
        let net_intent = EffectIntent::new(
            agent,
            "net.connect",
            net_params,
            net_id,
            true,
            Some([9; 16]),
        );
        assert!(matches!(
            evaluator.evaluate(&net_intent, &graph, None, 100),
            AegisDecision::RequiresOperatorApproval { .. }
        ));

        let fs_id = [2; 16];
        graph.issue_root_token(
            fs_id,
            agent,
            CapabilityScope::Filesystem {
                path_prefix: "/workspace".into(),
                read_only: false,
            },
            0,
            2000,
        );
        for path in ["/workspace-extra/file", "/workspace/../etc/passwd"] {
            let mut params = BTreeMap::new();
            params.insert("path".into(), path.into());
            let intent = EffectIntent::new(agent, "fs.write", params, fs_id, true, Some([9; 16]));
            assert!(matches!(
                evaluator.evaluate(&intent, &graph, None, 100),
                AegisDecision::Rejected { .. }
            ));
        }
    }

    #[test]
    fn world_bound_write_uses_delta_and_rollback_discards_it() {
        let mut graph = CapabilityGraph::new([0x42; 32]);
        let agent = LogicalAgentId::from_seed("world-bound-agent");
        let fs_id = [1; 16];
        let world_id = [9; 16];
        graph.issue_root_token(
            fs_id,
            agent,
            CapabilityScope::Filesystem {
                path_prefix: "/workspace".into(),
                read_only: false,
            },
            0,
            2000,
        );
        let mut broker = EffectBroker::new(AegisEvaluator::new([0x99; 32]));
        broker
            .register_world(JSpaceWorld::new(world_id, None))
            .unwrap();
        let host_handler_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&host_handler_called);
        broker.register_handler("fs.write", move |_| {
            called.store(true, Ordering::SeqCst);
            Ok("host write".into())
        });

        let mut params = BTreeMap::new();
        params.insert("path".into(), "/workspace/note.txt".into());
        params.insert("content".into(), "draft".into());
        let intent = EffectIntent::new(agent, "fs.write", params, fs_id, true, Some(world_id));
        assert!(broker.dispatch(&intent, &graph, None, 100).is_ok());
        assert!(!host_handler_called.load(Ordering::SeqCst));
        assert_eq!(
            broker
                .world(&world_id)
                .unwrap()
                .read_file("/workspace/note.txt", |_| None),
            Some(b"draft".to_vec())
        );
        let mut delete_params = BTreeMap::new();
        delete_params.insert("path".into(), "/workspace/note.txt".into());
        let delete = EffectIntent::new(
            agent,
            "fs.delete",
            delete_params,
            fs_id,
            true,
            Some(world_id),
        );
        assert!(broker.dispatch(&delete, &graph, None, 100).is_ok());
        assert_eq!(
            broker
                .world(&world_id)
                .unwrap()
                .read_file("/workspace/note.txt", |_| Some(b"base".to_vec())),
            None
        );
        broker.rollback_world(&world_id).unwrap();
        assert_eq!(
            broker
                .world(&world_id)
                .unwrap()
                .read_file("/workspace/note.txt", |_| None),
            None
        );
        assert!(matches!(
            broker.dispatch(&intent, &graph, None, 101),
            Err(AegisError::MissingOperatorGrant)
        ));
    }
}
