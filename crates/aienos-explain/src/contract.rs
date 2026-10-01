//! Evidence graph contract `aien.explain.evidence-graph` version 1.
//!
//! This is the language-neutral boundary of the explanation bridge. Any producer
//! (the aienos Cortex adapter, spark-rsi, a future omega `rx_cortex` exporter written
//! in C or Omega) emits this plain JSON document; the builder consumes it. The
//! canonical form is the JSON described in `docs/EXPLAIN_EVIDENCE_GRAPH_V1.md`:
//! string ids, small unsigned integer codes, per-mille integer confidence, and
//! producer-formatted decimal strings for measurements. No Rust enum layout and no
//! floating point value is part of the canonical format.

use serde::{Deserialize, Serialize};

/// Format tag every v1 document carries.
pub const FORMAT: &str = "aien.explain.evidence-graph";
/// Contract version understood by this crate.
pub const VERSION: u16 = 1;
/// Hard cap on nodes in one input document (adversarial input bound).
pub const MAX_GRAPH_NODES: usize = 65_536;
/// Hard cap on parent edges of one node.
pub const MAX_PARENTS_PER_NODE: usize = 1_024;

/// Explicit error codes. The numeric code is part of the contract (stable across
/// languages); the message is for humans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExplainError {
    /// 1: document is not valid JSON or misses required fields.
    BadFormat(String),
    /// 2: `format` or `version` is not one this crate understands.
    UnsupportedVersion(String),
    /// 3: an integer code (status, kind, relation) is outside the contract.
    UnknownCode { field: &'static str, value: u32 },
    /// 4: two nodes share an id.
    DuplicateNodeId(String),
    /// 5: the artifact to explain is not in the graph.
    TargetNotFound(String),
    /// 6: the document exceeds a hard size cap.
    GraphTooLarge(String),
    /// 7: a clarification asked for a step that does not exist.
    StepOutOfRange(u32),
    /// 8: the record is not part of the evidence the branch depends on.
    NotInBranchScope(String),
    /// 9: the Cortex journal could not be read or failed its seal.
    Journal(String),
    /// 10: limits are zero or above the hard caps.
    InvalidLimits(String),
}

impl ExplainError {
    /// Stable numeric error code.
    pub fn code(&self) -> u16 {
        match self {
            Self::BadFormat(_) => 1,
            Self::UnsupportedVersion(_) => 2,
            Self::UnknownCode { .. } => 3,
            Self::DuplicateNodeId(_) => 4,
            Self::TargetNotFound(_) => 5,
            Self::GraphTooLarge(_) => 6,
            Self::StepOutOfRange(_) => 7,
            Self::NotInBranchScope(_) => 8,
            Self::Journal(_) => 9,
            Self::InvalidLimits(_) => 10,
        }
    }
}

impl core::fmt::Display for ExplainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = self.code();
        match self {
            Self::BadFormat(m) => write!(f, "E{code} bad format: {m}"),
            Self::UnsupportedVersion(m) => write!(f, "E{code} unsupported version: {m}"),
            Self::UnknownCode { field, value } => {
                write!(f, "E{code} unknown code {value} in field {field}")
            }
            Self::DuplicateNodeId(id) => write!(f, "E{code} duplicate node id {id}"),
            Self::TargetNotFound(id) => write!(f, "E{code} artifact not found: {id}"),
            Self::GraphTooLarge(m) => write!(f, "E{code} graph too large: {m}"),
            Self::StepOutOfRange(n) => write!(f, "E{code} no step {n} in this explanation"),
            Self::NotInBranchScope(m) => write!(f, "E{code} not in branch scope: {m}"),
            Self::Journal(m) => write!(f, "E{code} Cortex journal: {m}"),
            Self::InvalidLimits(m) => write!(f, "E{code} invalid limits: {m}"),
        }
    }
}

impl std::error::Error for ExplainError {}

/// Epistemic status code. 1..=6 are exactly the aienos Cortex `EpistemicStatus`
/// numbering; 0 means the producer could not classify the artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    Unclassified,
    DirectObservation,
    VerifiedFact,
    Inference,
    Hypothesis,
    Contradiction,
    OperatorDecision,
}

impl Status {
    pub fn from_code(code: u8) -> Result<Self, ExplainError> {
        Ok(match code {
            0 => Self::Unclassified,
            1 => Self::DirectObservation,
            2 => Self::VerifiedFact,
            3 => Self::Inference,
            4 => Self::Hypothesis,
            5 => Self::Contradiction,
            6 => Self::OperatorDecision,
            v => {
                return Err(ExplainError::UnknownCode {
                    field: "status",
                    value: v as u32,
                })
            }
        })
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Unclassified => 0,
            Self::DirectObservation => 1,
            Self::VerifiedFact => 2,
            Self::Inference => 3,
            Self::Hypothesis => 4,
            Self::Contradiction => 5,
            Self::OperatorDecision => 6,
        }
    }

    /// Grounding statuses end a backward walk (same set as Cortex `is_ground_truth`).
    pub fn is_grounding(self) -> bool {
        matches!(
            self,
            Self::DirectObservation | Self::VerifiedFact | Self::OperatorDecision
        )
    }

    /// Technical name (matches the Cortex enum variant names).
    pub fn name(self) -> &'static str {
        match self {
            Self::Unclassified => "Unclassified",
            Self::DirectObservation => "DirectObservation",
            Self::VerifiedFact => "VerifiedFact",
            Self::Inference => "Inference",
            Self::Hypothesis => "Hypothesis",
            Self::Contradiction => "Contradiction",
            Self::OperatorDecision => "OperatorDecision",
        }
    }
}

/// What kind of artifact a node is. Codes are part of the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    CortexRecord,
    CapabilityMetric,
    CapabilityAnalysis,
    Diagnostic,
    Hypothesis,
    Prediction,
    Falsification,
    EvaluationReceipt,
    PromotionState,
    OperatorDecision,
    AgentBranch,
    Conclusion,
    Alternative,
}

impl NodeKind {
    pub fn from_code(code: u16) -> Result<Self, ExplainError> {
        Ok(match code {
            1 => Self::CortexRecord,
            2 => Self::CapabilityMetric,
            3 => Self::CapabilityAnalysis,
            4 => Self::Diagnostic,
            5 => Self::Hypothesis,
            6 => Self::Prediction,
            7 => Self::Falsification,
            8 => Self::EvaluationReceipt,
            9 => Self::PromotionState,
            10 => Self::OperatorDecision,
            11 => Self::AgentBranch,
            12 => Self::Conclusion,
            13 => Self::Alternative,
            v => {
                return Err(ExplainError::UnknownCode {
                    field: "kind",
                    value: v as u32,
                })
            }
        })
    }

    pub fn code(self) -> u16 {
        match self {
            Self::CortexRecord => 1,
            Self::CapabilityMetric => 2,
            Self::CapabilityAnalysis => 3,
            Self::Diagnostic => 4,
            Self::Hypothesis => 5,
            Self::Prediction => 6,
            Self::Falsification => 7,
            Self::EvaluationReceipt => 8,
            Self::PromotionState => 9,
            Self::OperatorDecision => 10,
            Self::AgentBranch => 11,
            Self::Conclusion => 12,
            Self::Alternative => 13,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::CortexRecord => "CortexRecord",
            Self::CapabilityMetric => "CapabilityMetric",
            Self::CapabilityAnalysis => "CapabilityAnalysis",
            Self::Diagnostic => "Diagnostic",
            Self::Hypothesis => "Hypothesis",
            Self::Prediction => "Prediction",
            Self::Falsification => "Falsification",
            Self::EvaluationReceipt => "EvaluationReceipt",
            Self::PromotionState => "PromotionState",
            Self::OperatorDecision => "OperatorDecision",
            Self::AgentBranch => "AgentBranch",
            Self::Conclusion => "Conclusion",
            Self::Alternative => "Alternative",
        }
    }
}

/// How a node relates to one of its listed parents. Codes are part of the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relation {
    /// The node rests on the parent (causal parent, derived from, input to).
    SupportedBy,
    /// The node is an evaluation or test result of the parent.
    Evaluates,
    /// The node is a component of the parent (prediction of a hypothesis).
    PartOf,
    /// The node records a conflict involving the parent (not support).
    Contradicts,
    /// The node is an explicitly recorded alternative to the parent (not support).
    AlternativeTo,
    /// A branch references the parent as evidence it depends on.
    References,
}

impl Relation {
    pub fn from_code(code: u16) -> Result<Self, ExplainError> {
        Ok(match code {
            1 => Self::SupportedBy,
            2 => Self::Evaluates,
            3 => Self::PartOf,
            4 => Self::Contradicts,
            5 => Self::AlternativeTo,
            6 => Self::References,
            v => {
                return Err(ExplainError::UnknownCode {
                    field: "relation",
                    value: v as u32,
                })
            }
        })
    }

    pub fn code(self) -> u16 {
        match self {
            Self::SupportedBy => 1,
            Self::Evaluates => 2,
            Self::PartOf => 3,
            Self::Contradicts => 4,
            Self::AlternativeTo => 5,
            Self::References => 6,
        }
    }

    /// Only these relations are followed backward as support. Contradiction and
    /// alternative links are disclosed separately and never count as support.
    pub fn is_support(self) -> bool {
        matches!(
            self,
            Self::SupportedBy | Self::Evaluates | Self::PartOf | Self::References
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::SupportedBy => "SupportedBy",
            Self::Evaluates => "Evaluates",
            Self::PartOf => "PartOf",
            Self::Contradicts => "Contradicts",
            Self::AlternativeTo => "AlternativeTo",
            Self::References => "References",
        }
    }
}

/// Where a node came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// Producing system, e.g. `aienos-cortex`, `aienos-agent-state`, `spark-rsi`.
    pub system: String,
    /// Artifact type in that system, e.g. `EpistemicRecord`, `HypothesisContract`.
    pub artifact: String,
    /// Identifier or provenance string inside that system.
    pub reference: String,
    /// Content digest or receipt digest as lowercase hex, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// One named measurement. The value is a decimal string formatted by the producer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub unit: String,
}

/// A parent edge as written in the document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeDoc {
    pub to: String,
    pub relation: u16,
}

/// A link the producer knows should exist but has no artifact for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingDoc {
    pub expected: String,
    pub reason: String,
}

/// One evidence node as written in the document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDoc {
    pub id: String,
    pub kind: u16,
    pub status: u8,
    pub statement: String,
    pub source: SourceRef,
    /// Confidence in thousandths, only where the source system has the concept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_permille: Option<u16>,
    /// Where the confidence number came from (declared, computed, recorded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_basis: Option<String>,
    /// Recording time from the source, informational only. Never used for ordering:
    /// time order is not causal order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at_utc: Option<u64>,
    #[serde(default)]
    pub parents: Vec<EdgeDoc>,
    #[serde(default)]
    pub measurements: Vec<Measurement>,
    #[serde(default)]
    pub missing: Vec<MissingDoc>,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Optional branch scope: which records a reasoning branch actually referenced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDoc {
    pub branch: String,
    pub referenced: Vec<String>,
}

/// The whole document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub format: String,
    pub version: u16,
    pub producer: String,
    pub nodes: Vec<NodeDoc>,
    /// Nodes whose parents the producer did not expand because of its own limits.
    #[serde(default)]
    pub truncated_at: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeDoc>,
}

impl EvidenceGraph {
    /// Empty v1 document for a producer.
    pub fn new(producer: impl Into<String>) -> Self {
        Self {
            format: FORMAT.to_string(),
            version: VERSION,
            producer: producer.into(),
            nodes: Vec::new(),
            truncated_at: Vec::new(),
            scope: None,
        }
    }

    /// Parse and validate a JSON document.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ExplainError> {
        let g: Self =
            serde_json::from_slice(bytes).map_err(|e| ExplainError::BadFormat(e.to_string()))?;
        g.validate()?;
        Ok(g)
    }

    /// Canonical JSON bytes (field order fixed by the struct, node order as given).
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("evidence graph serializes")
    }

    /// Check format tag, version, size caps, codes and id uniqueness.
    pub fn validate(&self) -> Result<(), ExplainError> {
        if self.format != FORMAT {
            return Err(ExplainError::UnsupportedVersion(format!(
                "format {:?}, expected {:?}",
                self.format, FORMAT
            )));
        }
        if self.version != VERSION {
            return Err(ExplainError::UnsupportedVersion(format!(
                "version {}, expected {}",
                self.version, VERSION
            )));
        }
        if self.nodes.len() > MAX_GRAPH_NODES {
            return Err(ExplainError::GraphTooLarge(format!(
                "{} nodes, cap {}",
                self.nodes.len(),
                MAX_GRAPH_NODES
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for n in &self.nodes {
            if !seen.insert(n.id.as_str()) {
                return Err(ExplainError::DuplicateNodeId(n.id.clone()));
            }
            NodeKind::from_code(n.kind)?;
            Status::from_code(n.status)?;
            if n.parents.len() > MAX_PARENTS_PER_NODE {
                return Err(ExplainError::GraphTooLarge(format!(
                    "node {} has {} parents, cap {}",
                    n.id,
                    n.parents.len(),
                    MAX_PARENTS_PER_NODE
                )));
            }
            for e in &n.parents {
                Relation::from_code(e.relation)?;
            }
            if let Some(c) = n.confidence_permille {
                if c > 1000 {
                    return Err(ExplainError::UnknownCode {
                        field: "confidence_permille",
                        value: c as u32,
                    });
                }
            }
        }
        Ok(())
    }
}
