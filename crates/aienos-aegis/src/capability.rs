//! Unforgeable capability tokens and the AEGIS Directed Acyclic Capability Graph (§13).

use aienos_agent_state::LogicalAgentId;
use aienos_kernel::crypto::sha256;
use core::fmt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path};

/// Check a lexical absolute path boundary. Handlers must still resolve symlinks safely.
pub(crate) fn path_within(path: &str, prefix: &str) -> bool {
    let path = Path::new(path);
    let prefix = Path::new(prefix);
    path.is_absolute()
        && prefix.is_absolute()
        && !path.components().any(|part| part == Component::ParentDir)
        && !prefix.components().any(|part| part == Component::ParentDir)
        && path.starts_with(prefix)
}

/// Errors occurring in capability evaluation and graph operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AegisError {
    InvalidSignature,
    TokenExpired,
    TokenRevoked,
    TokenNotFound([u8; 16]),
    UnauthorizedAgent,
    ScopeExceeded(String),
    DelegationDepthExceeded,
    IrreversibleEffectDenied(String),
    MissingOperatorGrant,
    ExecutionFailed(String),
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Invalid capability cryptographic signature"),
            Self::TokenExpired => write!(f, "Capability token has expired"),
            Self::TokenRevoked => write!(f, "Capability token has been revoked"),
            Self::TokenNotFound(id) => write!(f, "Capability token not found: {:02x?}", id),
            Self::UnauthorizedAgent => {
                write!(f, "Agent is not the authorized holder of capability")
            }
            Self::ScopeExceeded(msg) => {
                write!(f, "Requested action exceeds capability scope: {}", msg)
            }
            Self::DelegationDepthExceeded => write!(f, "Maximum delegation depth exceeded"),
            Self::IrreversibleEffectDenied(msg) => {
                write!(f, "Irreversible effect denied by policy: {}", msg)
            }
            Self::MissingOperatorGrant => {
                write!(
                    f,
                    "Irreversible effect requires explicit operator cryptographic grant"
                )
            }
            Self::ExecutionFailed(msg) => write!(f, "Effect execution failed: {}", msg),
        }
    }
}

/// Scope definition for granular capability permissions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityScope {
    Filesystem {
        path_prefix: String,
        read_only: bool,
    },
    Network {
        host: String,
        port: u16,
    },
    Model {
        model_name: String,
        max_tokens: u32,
    },
    Device {
        device_name: String,
        read_only: bool,
    },
    World {
        max_depth: u32,
    },
    /// Standing capability for autonomous external network fetches (ADR 0004).
    StandingFetch {
        host: String,
    },
    SystemAdmin,
    Custom {
        namespace: String,
        action: String,
    },
}

impl CapabilityScope {
    /// Check if child scope is an attenuation (equal or stricter subset) of self.
    pub fn contains(&self, child: &CapabilityScope) -> bool {
        match (self, child) {
            (CapabilityScope::SystemAdmin, _) => true,
            (
                CapabilityScope::StandingFetch { host: h_parent },
                CapabilityScope::StandingFetch { host: h_child },
            ) => h_parent == "*" || h_parent == h_child,
            (
                CapabilityScope::Filesystem {
                    path_prefix: p_parent,
                    read_only: ro_parent,
                },
                CapabilityScope::Filesystem {
                    path_prefix: p_child,
                    read_only: ro_child,
                },
            ) => path_within(p_child, p_parent) && (*ro_parent == *ro_child || *ro_child),
            (
                CapabilityScope::Network {
                    host: h_parent,
                    port: p_parent,
                },
                CapabilityScope::Network {
                    host: h_child,
                    port: p_child,
                },
            ) => {
                (h_parent == "*" || h_parent == h_child) && (*p_parent == 0 || p_parent == p_child)
            }
            (
                CapabilityScope::Model {
                    model_name: m_parent,
                    max_tokens: tok_parent,
                },
                CapabilityScope::Model {
                    model_name: m_child,
                    max_tokens: tok_child,
                },
            ) => (m_parent == "*" || m_parent == m_child) && tok_child <= tok_parent,
            (
                CapabilityScope::World {
                    max_depth: d_parent,
                },
                CapabilityScope::World { max_depth: d_child },
            ) => d_child <= d_parent,
            (
                CapabilityScope::Custom {
                    namespace: ns_p,
                    action: act_p,
                },
                CapabilityScope::Custom {
                    namespace: ns_c,
                    action: act_c,
                },
            ) => ns_p == ns_c && (act_p == "*" || act_p == act_c),
            _ => false,
        }
    }
}

/// Unforgeable cryptographic capability token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub id: [u8; 16],
    pub parent_id: Option<[u8; 16]>,
    pub issuer: String,
    pub holder: LogicalAgentId,
    pub scope: CapabilityScope,
    pub delegation_depth: u32,
    pub valid_until_utc: u64,
    pub signature: [u8; 32],
}

impl CapabilityToken {
    /// Compute HMAC-SHA256 signature over token payload.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_signature(
        secret: &[u8; 32],
        id: &[u8; 16],
        parent_id: Option<&[u8; 16]>,
        issuer: &str,
        holder: &LogicalAgentId,
        scope: &CapabilityScope,
        delegation_depth: u32,
        valid_until_utc: u64,
    ) -> [u8; 32] {
        let parent_marker = [u8::from(parent_id.is_some())];
        let absent_parent = [0u8; 16];
        let parent = parent_id.unwrap_or(&absent_parent);
        let issuer_len = (issuer.len() as u64).to_be_bytes();
        let scope_bytes = serde_json::to_vec(scope).unwrap_or_default();
        let scope_len = (scope_bytes.len() as u64).to_be_bytes();
        sha256::hmac_sha256(
            secret,
            &[
                b"AIENOS_CAP_V1",
                id,
                &parent_marker,
                parent,
                &issuer_len,
                issuer.as_bytes(),
                holder.as_bytes(),
                &scope_len,
                &scope_bytes,
                &delegation_depth.to_be_bytes(),
                &valid_until_utc.to_be_bytes(),
            ],
        )
    }
}

/// Directed Acyclic Capability Graph managing root authorities, delegations, and revocations.
pub struct CapabilityGraph {
    master_secret: [u8; 32],
    tokens: HashMap<[u8; 16], CapabilityToken>,
    child_map: HashMap<[u8; 16], Vec<[u8; 16]>>,
    revoked_tokens: HashSet<[u8; 16]>,
}

impl CapabilityGraph {
    /// Initialize capability graph with master kernel authority secret.
    pub fn new(master_secret: [u8; 32]) -> Self {
        Self {
            master_secret,
            tokens: HashMap::new(),
            child_map: HashMap::new(),
            revoked_tokens: HashSet::new(),
        }
    }

    /// Issue a root capability granted directly by the operator.
    pub fn issue_root_token(
        &mut self,
        id: [u8; 16],
        holder: LogicalAgentId,
        scope: CapabilityScope,
        delegation_depth: u32,
        valid_until_utc: u64,
    ) -> CapabilityToken {
        let signature = CapabilityToken::compute_signature(
            &self.master_secret,
            &id,
            None,
            "root.authority",
            &holder,
            &scope,
            delegation_depth,
            valid_until_utc,
        );

        let token = CapabilityToken {
            id,
            parent_id: None,
            issuer: "root.authority".to_string(),
            holder,
            scope,
            delegation_depth,
            valid_until_utc,
            signature,
        };

        self.tokens.insert(id, token.clone());
        token
    }

    /// Derive an attenuated child capability token.
    pub fn derive_child_token(
        &mut self,
        parent_id: [u8; 16],
        child_id: [u8; 16],
        new_holder: LogicalAgentId,
        child_scope: CapabilityScope,
        now_utc: u64,
    ) -> Result<CapabilityToken, AegisError> {
        let parent = self.get_token(&parent_id)?;
        self.validate_token(&parent, now_utc)?;

        if parent.delegation_depth == 0 {
            return Err(AegisError::DelegationDepthExceeded);
        }

        if !parent.scope.contains(&child_scope) {
            return Err(AegisError::ScopeExceeded(format!(
                "Child scope {:?} not contained in parent scope {:?}",
                child_scope, parent.scope
            )));
        }

        let delegation_depth = parent.delegation_depth - 1;
        let valid_until_utc = parent.valid_until_utc;

        let signature = CapabilityToken::compute_signature(
            &self.master_secret,
            &child_id,
            Some(&parent_id),
            &format!("cap:{:02x?}", parent_id),
            &new_holder,
            &child_scope,
            delegation_depth,
            valid_until_utc,
        );

        let child = CapabilityToken {
            id: child_id,
            parent_id: Some(parent_id),
            issuer: format!("cap:{:02x?}", parent_id),
            holder: new_holder,
            scope: child_scope,
            delegation_depth,
            valid_until_utc,
            signature,
        };

        self.tokens.insert(child_id, child.clone());
        self.child_map.entry(parent_id).or_default().push(child_id);

        Ok(child)
    }

    /// Revoke a capability token and all downstream delegated descendants.
    pub fn revoke(&mut self, token_id: [u8; 16]) {
        let mut queue = vec![token_id];
        while let Some(current) = queue.pop() {
            self.revoked_tokens.insert(current);
            if let Some(children) = self.child_map.get(&current) {
                for &child in children {
                    queue.push(child);
                }
            }
        }
    }

    /// Get token by ID.
    pub fn get_token(&self, id: &[u8; 16]) -> Result<CapabilityToken, AegisError> {
        self.tokens
            .get(id)
            .cloned()
            .ok_or(AegisError::TokenNotFound(*id))
    }

    /// Cryptographically validate token authenticity, expiry, and revocation.
    pub fn validate_token(&self, token: &CapabilityToken, now_utc: u64) -> Result<(), AegisError> {
        if self.revoked_tokens.contains(&token.id) {
            return Err(AegisError::TokenRevoked);
        }

        // Cascading ancestor revocation check
        let mut curr_parent = token.parent_id;
        while let Some(pid) = curr_parent {
            if self.revoked_tokens.contains(&pid) {
                return Err(AegisError::TokenRevoked);
            }
            curr_parent = self.tokens.get(&pid).and_then(|p| p.parent_id);
        }

        if now_utc > token.valid_until_utc {
            return Err(AegisError::TokenExpired);
        }

        let expected_sig = CapabilityToken::compute_signature(
            &self.master_secret,
            &token.id,
            token.parent_id.as_ref(),
            &token.issuer,
            &token.holder,
            &token.scope,
            token.delegation_depth,
            token.valid_until_utc,
        );

        if token.signature != expected_sig {
            return Err(AegisError::InvalidSignature);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_scope_rejects_sibling_and_traversal_paths() {
        assert!(path_within("/workspace/src/main.rs", "/workspace"));
        assert!(path_within("/workspace", "/workspace"));
        assert!(!path_within("/workspace-extra/file", "/workspace"));
        assert!(!path_within("/workspace/../etc/passwd", "/workspace"));
        assert!(!path_within("workspace/file", "/workspace"));

        let parent = CapabilityScope::Filesystem {
            path_prefix: "/workspace".into(),
            read_only: false,
        };
        for escaped in ["/workspace-extra", "/workspace/../etc"] {
            assert!(!parent.contains(&CapabilityScope::Filesystem {
                path_prefix: escaped.into(),
                read_only: true,
            }));
        }
    }

    #[test]
    fn test_capability_attenuation_and_cascading_revocation() {
        let master_secret = [0x5Au8; 32];
        let mut graph = CapabilityGraph::new(master_secret);
        let root_agent = LogicalAgentId::from_seed("root_agent");
        let sub_agent = LogicalAgentId::from_seed("sub_agent");

        let root_id = [1u8; 16];
        let root_token = graph.issue_root_token(
            root_id,
            root_agent,
            CapabilityScope::Filesystem {
                path_prefix: "/workspace".to_string(),
                read_only: false,
            },
            3,
            2000,
        );
        assert!(graph.validate_token(&root_token, 100).is_ok());

        // 1. Derive attenuated child token (read-only subset)
        let child_id = [2u8; 16];
        let child_token = graph
            .derive_child_token(
                root_id,
                child_id,
                sub_agent,
                CapabilityScope::Filesystem {
                    path_prefix: "/workspace/src".to_string(),
                    read_only: true,
                },
                101,
            )
            .expect("Attenuated derivation must succeed");
        assert!(graph.validate_token(&child_token, 101).is_ok());

        // 2. Scope expansion attempt must fail (trying to claim root path or rw)
        let invalid_child_id = [3u8; 16];
        let expanded_res = graph.derive_child_token(
            root_id,
            invalid_child_id,
            sub_agent,
            CapabilityScope::Filesystem {
                path_prefix: "/etc".to_string(),
                read_only: false,
            },
            102,
        );
        assert!(matches!(expanded_res, Err(AegisError::ScopeExceeded(_))));

        // 3. Expiration check
        assert!(matches!(
            graph.validate_token(&child_token, 2001),
            Err(AegisError::TokenExpired)
        ));

        // 4. Cascading revocation: revoking root must invalidate child
        graph.revoke(root_id);
        assert!(matches!(
            graph.validate_token(&root_token, 105),
            Err(AegisError::TokenRevoked)
        ));
        assert!(matches!(
            graph.validate_token(&child_token, 105),
            Err(AegisError::TokenRevoked)
        ));
    }
}
