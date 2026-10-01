//! The grounded explanation bundle: the authoritative, deterministic output of the
//! builder. Renderers only read it. It has no field for analogies or prose, and it
//! grants no authority (explanation is observational).

use crate::contract::{Measurement, NodeKind, Relation, SourceRef, Status};
use serde::{Serialize, Serializer};

fn ser_status<S: Serializer>(s: &Status, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(s.name())
}
fn ser_kind<S: Serializer>(k: &NodeKind, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(k.name())
}
fn ser_relation<S: Serializer>(r: &Relation, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(r.name())
}

/// Narrative role of a step in the path. Derived only from kind and status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Role {
    Observed,
    Analysis,
    Hypothesis,
    Prediction,
    Falsification,
    Evaluation,
    Decision,
    Conclusion,
}

impl Role {
    pub fn of(kind: NodeKind, status: Status) -> Self {
        match kind {
            NodeKind::CapabilityMetric => Self::Observed,
            NodeKind::CapabilityAnalysis | NodeKind::Diagnostic => Self::Analysis,
            NodeKind::Hypothesis => Self::Hypothesis,
            NodeKind::Prediction => Self::Prediction,
            NodeKind::Falsification => Self::Falsification,
            NodeKind::EvaluationReceipt => Self::Evaluation,
            NodeKind::PromotionState | NodeKind::OperatorDecision => Self::Decision,
            NodeKind::Conclusion | NodeKind::AgentBranch => Self::Conclusion,
            NodeKind::Alternative => Self::Analysis,
            NodeKind::CortexRecord => match status {
                Status::DirectObservation | Status::VerifiedFact => Self::Observed,
                Status::OperatorDecision => Self::Decision,
                Status::Hypothesis => Self::Hypothesis,
                Status::Inference | Status::Contradiction | Status::Unclassified => Self::Analysis,
            },
        }
    }

    pub fn heading(self) -> &'static str {
        match self {
            Self::Observed => "Observed",
            Self::Analysis => "System analysis",
            Self::Hypothesis => "Hypothesis",
            Self::Prediction => "Prediction",
            Self::Falsification => "Falsification",
            Self::Evaluation => "Evaluation",
            Self::Decision => "Decision",
            Self::Conclusion => "Conclusion",
        }
    }
}

/// A support link from a step to an earlier step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SupportLink {
    /// 1-based index of the supporting step.
    pub step: u32,
    #[serde(serialize_with = "ser_relation")]
    pub relation: Relation,
}

/// One step of the linear path, in causal (parents first) order.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CausalStep {
    /// 1-based position in the path.
    pub index: u32,
    pub node_id: String,
    #[serde(serialize_with = "ser_kind")]
    pub kind: NodeKind,
    #[serde(serialize_with = "ser_status")]
    pub status: Status,
    pub role: Role,
    pub statement: String,
    pub source: SourceRef,
    pub confidence_permille: Option<u16>,
    pub confidence_basis: Option<String>,
    pub recorded_at_utc: Option<u64>,
    pub measurements: Vec<Measurement>,
    pub notes: Vec<String>,
    /// Earlier steps this step rests on.
    pub supported_by: Vec<SupportLink>,
    /// Shortest number of support edges from the conclusion.
    pub depth: u32,
    /// True when the status is a grounding status (observation, verified fact,
    /// operator decision).
    pub grounding: bool,
    /// True when the branch in scope referenced this record directly.
    pub branch_referenced: bool,
}

/// Kinds of uncertainty kept visible in the explanation. Codes are stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum UncertaintyKind {
    /// A support edge points into itself through a loop; the loop edge was cut.
    Cycle,
    /// A contradiction record involves a step of this path.
    ConflictingEvidence,
    /// A parent id is listed but no such artifact exists.
    MissingParent,
    /// The producer declared a link it expected but has no artifact for.
    MissingLink,
    /// A derived claim (inference, hypothesis) has no recorded support at all.
    Unsupported,
    /// A hypothesis on the path has no evaluation step attached to it.
    HypothesisNotFalsified,
    /// The path is inferred (contains an inference that is not grounded only).
    Inferred,
    /// The artifact's epistemic status is unknown.
    Unknown,
    /// Traversal stopped at the depth or node limit.
    Truncated,
    /// Free-form caveat recorded by the producer (e.g. declared, not measured).
    ProducerNote,
}

impl UncertaintyKind {
    pub fn code(self) -> u16 {
        match self {
            Self::Cycle => 1,
            Self::ConflictingEvidence => 2,
            Self::MissingParent => 3,
            Self::MissingLink => 4,
            Self::Unsupported => 5,
            Self::HypothesisNotFalsified => 6,
            Self::Inferred => 7,
            Self::Unknown => 8,
            Self::Truncated => 9,
            Self::ProducerNote => 10,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Cycle => "circular support",
            Self::ConflictingEvidence => "conflicting evidence",
            Self::MissingParent => "missing evidence",
            Self::MissingLink => "missing link",
            Self::Unsupported => "unsupported claim",
            Self::HypothesisNotFalsified => "hypothesis not yet tested",
            Self::Inferred => "inferred step",
            Self::Unknown => "unknown status",
            Self::Truncated => "explanation cut short",
            Self::ProducerNote => "caveat",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Uncertainty {
    pub kind: UncertaintyKind,
    /// Node the uncertainty is attached to.
    pub node_id: String,
    /// Other id involved (missing parent, loop target, expected link).
    pub related: Option<String>,
    pub detail: String,
}

/// A contradiction record that involves the path. Always shown.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ContradictionRef {
    pub node_id: String,
    pub statement: String,
    pub source: SourceRef,
    /// Path node ids the contradiction involves.
    pub involves: Vec<String>,
}

/// An alternative explanation that the evidence explicitly records.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Alternative {
    pub node_id: String,
    pub statement: String,
    pub source: SourceRef,
    pub alternative_to: String,
    pub measurements: Vec<Measurement>,
}

/// An evidence pointer (digest, receipt, measurements) attached to a step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceRef {
    pub step: u32,
    pub node_id: String,
    pub source: SourceRef,
    pub measurements: Vec<Measurement>,
}

/// Limits used for the traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Limits {
    pub max_depth: u32,
    pub max_nodes: u32,
}

impl Limits {
    pub const HARD_MAX_DEPTH: u32 = 256;
    pub const HARD_MAX_NODES: u32 = 4096;
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_nodes: 256,
        }
    }
}

/// How the bundle was built.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExplanationProvenance {
    pub builder: String,
    pub contract_format: String,
    pub contract_version: u16,
    pub producer: String,
    /// sha256 of the canonical input graph JSON, lowercase hex.
    pub input_digest: String,
    pub target: String,
    pub limits: Limits,
    pub branch_scope: Option<String>,
    /// Number of nodes visited out of the number in the input graph.
    pub visited_nodes: u32,
    pub graph_nodes: u32,
}

/// The authoritative explanation. Deterministic for identical input and limits.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExplanationBundle {
    /// The conclusion is always the last step.
    pub conclusion_step: u32,
    pub steps: Vec<CausalStep>,
    pub evidence: Vec<EvidenceRef>,
    pub uncertainties: Vec<Uncertainty>,
    pub contradictions: Vec<ContradictionRef>,
    pub alternatives: Vec<Alternative>,
    pub provenance: ExplanationProvenance,
    /// sha256 of the canonical JSON of every field above, lowercase hex.
    pub bundle_digest: String,
}

impl ExplanationBundle {
    pub fn conclusion(&self) -> &CausalStep {
        &self.steps[(self.conclusion_step - 1) as usize]
    }

    pub fn step(&self, index: u32) -> Option<&CausalStep> {
        if index == 0 {
            return None;
        }
        self.steps.get((index - 1) as usize)
    }

    /// Canonical JSON of the bundle.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("bundle serializes")
    }

    /// Recompute the digest over the content (excluding the digest field).
    pub fn compute_digest(&self) -> String {
        #[derive(Serialize)]
        struct Content<'a> {
            conclusion_step: u32,
            steps: &'a [CausalStep],
            evidence: &'a [EvidenceRef],
            uncertainties: &'a [Uncertainty],
            contradictions: &'a [ContradictionRef],
            alternatives: &'a [Alternative],
            provenance: &'a ExplanationProvenance,
        }
        let c = Content {
            conclusion_step: self.conclusion_step,
            steps: &self.steps,
            evidence: &self.evidence,
            uncertainties: &self.uncertainties,
            contradictions: &self.contradictions,
            alternatives: &self.alternatives,
            provenance: &self.provenance,
        };
        hex(&aienos_crypto::sha256::hash(
            &serde_json::to_vec(&c).expect("bundle serializes"),
        ))
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}
