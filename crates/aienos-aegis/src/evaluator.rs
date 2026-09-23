//! AEGIS Policy Evaluator: Enforcing cryptographic capabilities and reversibility invariants (§5).

use crate::capability::{CapabilityGraph, CapabilityScope};
use crate::effect::{EffectIntent, OperatorGrant};
use serde::{Deserialize, Serialize};

/// Policy evaluation outcome emitted by AEGIS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AegisDecision {
    Approved { reason: String },
    RequiresOperatorApproval { intent_id: [u8; 16], reason: String },
    Rejected { reason: String },
}

/// Deterministic AEGIS Evaluator.
///
/// Intelligence proposes; deterministic authority disposes. The model cannot authorize itself.
pub struct AegisEvaluator {
    operator_secret: [u8; 32],
}

impl AegisEvaluator {
    /// Create new AEGIS Evaluator bound to the operator's sovereign root secret.
    pub fn new(operator_secret: [u8; 32]) -> Self {
        Self { operator_secret }
    }

    /// Evaluate an effect intent against the capability graph and reversibility policy.
    pub fn evaluate(
        &self,
        intent: &EffectIntent,
        graph: &CapabilityGraph,
        grant: Option<&OperatorGrant>,
        now_utc: u64,
    ) -> AegisDecision {
        // 1. Retrieve and cryptographically validate the claimed capability token
        let token = match graph.get_token(&intent.claimed_capability_id) {
            Ok(t) => t,
            Err(e) => {
                return AegisDecision::Rejected {
                    reason: e.to_string(),
                }
            }
        };

        if let Err(e) = graph.validate_token(&token, now_utc) {
            return AegisDecision::Rejected {
                reason: e.to_string(),
            };
        }

        // 2. Validate token holder matches proposing agent
        if token.holder != intent.agent_id {
            return AegisDecision::Rejected {
                reason: format!(
                    "Agent {} is not authorized holder of token {}",
                    intent.agent_id, token.holder
                ),
            };
        }

        // 3. Match capability scope against requested action
        if !Self::scope_authorizes_action(&token.scope, &intent.action, &intent.parameters) {
            return AegisDecision::Rejected {
                reason: format!(
                    "Capability scope {:?} does not authorize action \"{}\"",
                    token.scope, intent.action
                ),
            };
        }

        // 4. Evaluate Reversibility & Standing Authority Policy (ADR 0004)
        // Decouple Reversible from Authorized:
        // - Free inside reversible state (J-Space World) -> Auto-Approved
        // - Non-destructive autonomous reads/fetches authorized via Standing Capabilities -> Auto-Approved
        // - Irreversible, destructive, or boundary operations -> Strictly require OperatorGrant
        if intent.is_reversible && intent.world_id.is_some() {
            return AegisDecision::Approved {
                reason: "Reversible effect inside J-Space World auto-approved".to_string(),
            };
        }

        let is_standing_fetch = matches!(token.scope, CapabilityScope::StandingFetch { .. })
            || (intent.action == "fs.read" || intent.action == "hardware.inspect");

        if is_standing_fetch && !Self::is_high_impact_boundary(&intent.action) {
            return AegisDecision::Approved {
                reason: format!(
                    "Autonomous effect authorized via Standing Capability {:?}",
                    token.scope
                ),
            };
        }

        // Irreversible or high-impact effect: strictly requires valid OperatorGrant
        if let Some(og) = grant {
            if og.intent_id != intent.id {
                return AegisDecision::Rejected {
                    reason: "Operator grant intent ID does not match proposed intent".to_string(),
                };
            }
            if !og.verify(&self.operator_secret) {
                return AegisDecision::Rejected {
                    reason: "Cryptographic signature on operator grant is invalid".to_string(),
                };
            }
            AegisDecision::Approved {
                reason: format!(
                    "Irreversible action approved by operator grant from {}",
                    og.operator_id
                ),
            }
        } else {
            AegisDecision::RequiresOperatorApproval {
                intent_id: intent.id,
                reason: format!(
                    "Irreversible action \"{}\" crosses boundary and requires explicit operator authorization",
                    intent.action
                ),
            }
        }
    }

    /// Check if action is high impact boundary requiring human operator grant.
    pub fn is_high_impact_boundary(action: &str) -> bool {
        matches!(
            action,
            "disk.format"
                | "fs.delete"
                | "fs.write"
                | "git.publish"
                | "code.publish"
                | "kernel.replace"
                | "system.install"
                | "credential.modify"
                | "finance.spend"
        )
    }

    fn scope_authorizes_action(
        scope: &CapabilityScope,
        action: &str,
        params: &std::collections::BTreeMap<String, String>,
    ) -> bool {
        match scope {
            CapabilityScope::SystemAdmin => true,
            CapabilityScope::Filesystem {
                path_prefix,
                read_only,
            } => {
                if action == "fs.read" {
                    if let Some(path) = params.get("path") {
                        path.starts_with(path_prefix)
                    } else {
                        false
                    }
                } else if action == "fs.write" || action == "fs.delete" {
                    if *read_only {
                        false
                    } else if let Some(path) = params.get("path") {
                        path.starts_with(path_prefix)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CapabilityScope::StandingFetch { host } => {
                if action == "net.fetch" || action == "net.read" {
                    let req_host = params.get("host").map(|s| s.as_str()).unwrap_or("");
                    host == "*" || host == req_host
                } else {
                    false
                }
            }
            CapabilityScope::Network { host, port } => {
                if action == "net.connect" || action == "net.send" {
                    let req_host = params.get("host").map(|s| s.as_str()).unwrap_or("");
                    let req_port: u16 =
                        params.get("port").and_then(|p| p.parse().ok()).unwrap_or(0);

                    (host == "*" || host == req_host) && (*port == 0 || *port == req_port)
                } else {
                    false
                }
            }
            CapabilityScope::Device {
                device_name,
                read_only,
            } => {
                if action.starts_with("device.") {
                    let req_dev = params.get("device").map(|s| s.as_str()).unwrap_or("");
                    let is_write = action == "device.write";
                    req_dev == device_name && (!is_write || !*read_only)
                } else {
                    false
                }
            }
            CapabilityScope::World { .. } => action.starts_with("world."),
            CapabilityScope::Custom {
                namespace,
                action: act,
            } => {
                if let Some(suffix) = action.strip_prefix(&format!("{}.", namespace)) {
                    act == "*" || act == suffix
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}
