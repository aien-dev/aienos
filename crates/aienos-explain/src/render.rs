//! Deterministic presentation of an [`ExplanationBundle`].
//!
//! Every function here takes the bundle by shared reference and returns text. The
//! renderer can drop detail, but it can never change a step's status, add a step, or
//! add evidence. Analogies come from a fixed catalog in this module, are always
//! labelled as illustrations, and are always followed by the evidence itself.

use crate::bundle::{CausalStep, ExplanationBundle, Role, Uncertainty, UncertaintyKind};
use crate::contract::{NodeKind, Relation, Status};
use std::fmt::Write;

/// Presentation mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Conclusion, strongest reason, strongest evidence, material uncertainty.
    Summary,
    /// The path, step by step, grouped under role headings.
    StepByStep,
    /// Identifiers, statuses, digests, measurements, uncertainty codes.
    Technical,
    /// A familiar picture first (labelled), then the evidence path.
    Analogy,
}

/// Who is reading. Explicit only; nothing is inferred about the reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    General,
    Operator,
    Developer,
    SystemsEngineer,
    Researcher,
}

impl Audience {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "general" => Self::General,
            "operator" => Self::Operator,
            "developer" => Self::Developer,
            "systems-engineer" => Self::SystemsEngineer,
            "researcher" => Self::Researcher,
            _ => return None,
        })
    }

    fn shows_ids(self) -> bool {
        !matches!(self, Self::General)
    }
}

/// Progressive disclosure: 0 conclusion, 1 principal reasons, 2 causal path,
/// 3 evidence and measurements, 4 raw provenance references.
pub const MAX_LEVEL: u8 = 4;

/// What to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExplanationRequest {
    pub mode: Mode,
    /// Disclosure level 0..=4; `None` uses the mode's default.
    pub level: Option<u8>,
    pub audience: Audience,
}

impl ExplanationRequest {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            level: None,
            audience: Audience::Operator,
        }
    }

    pub fn effective_level(&self) -> u8 {
        let d = match self.mode {
            Mode::Summary => 1,
            Mode::StepByStep | Mode::Analogy => 2,
            Mode::Technical => 4,
        };
        self.level.unwrap_or(d).min(MAX_LEVEL)
    }
}

/// Plain words for a status. A hypothesis is never described as verified or proven.
pub fn status_words(s: Status) -> &'static str {
    match s {
        Status::DirectObservation => "observed",
        Status::VerifiedFact => "checked fact",
        Status::Inference => "inferred, not checked",
        Status::Hypothesis => "hypothesis, not yet established",
        Status::Contradiction => "conflict between records",
        Status::OperatorDecision => "operator decision",
        Status::Unclassified => "status unknown",
    }
}

fn short(id: &str) -> String {
    match id.split_once(':') {
        Some((ns, rest)) if rest.chars().count() > 12 => {
            format!("{ns}:{}", rest.chars().take(12).collect::<String>())
        }
        _ => id.to_string(),
    }
}

fn step_line(s: &CausalStep, level: u8, aud: Audience) -> String {
    let mut out = format!("{}. [{}] {}", s.index, status_words(s.status), s.statement);
    if level >= 2 {
        let strong: Vec<String> = s
            .supported_by
            .iter()
            .filter(|l| l.relation != Relation::References)
            .map(|l| l.step.to_string())
            .collect();
        let weak: Vec<String> = s
            .supported_by
            .iter()
            .filter(|l| l.relation == Relation::References)
            .map(|l| l.step.to_string())
            .collect();
        if !strong.is_empty() {
            let _ = write!(out, " (rests on step {})", strong.join(", "));
        }
        if !weak.is_empty() {
            let _ = write!(
                out,
                " (refers to step {}; a weak link, not a recorded one)",
                weak.join(", ")
            );
        }
    }
    if aud.shows_ids() {
        let _ = write!(out, " [{} {}]", s.source.system, short(&s.node_id));
    } else {
        let _ = write!(out, " [from {}]", s.source.system);
    }
    if s.branch_referenced {
        out.push_str(" (referenced by the branch)");
    }
    out
}

fn measurements_line(s: &CausalStep) -> Option<String> {
    if s.measurements.is_empty() {
        return None;
    }
    let ms: Vec<String> = s
        .measurements
        .iter()
        .map(|m| {
            if m.unit.is_empty() {
                format!("{}={}", m.name, m.value)
            } else {
                format!("{}={} {}", m.name, m.value, m.unit)
            }
        })
        .collect();
    Some(format!("   measurements: {}", ms.join(", ")))
}

fn severity(k: UncertaintyKind) -> u8 {
    match k {
        UncertaintyKind::Cycle => 0,
        UncertaintyKind::ConflictingEvidence => 1,
        UncertaintyKind::MissingParent => 2,
        UncertaintyKind::MissingLink => 3,
        UncertaintyKind::Unsupported => 4,
        UncertaintyKind::HypothesisNotFalsified => 5,
        UncertaintyKind::Unknown => 6,
        UncertaintyKind::Truncated => 7,
        UncertaintyKind::ProducerNote => 8,
        UncertaintyKind::Inferred => 9,
    }
}

fn material(b: &ExplanationBundle) -> Option<&Uncertainty> {
    b.uncertainties
        .iter()
        .min_by_key(|u| (severity(u.kind), u.node_id.clone(), u.detail.clone()))
}

fn uncertainty_line(u: &Uncertainty) -> String {
    format!("- {}: {}", u.kind.label(), u.detail)
}

/// The direct support of the conclusion with the best grounding.
fn strongest_reason(b: &ExplanationBundle) -> Option<&CausalStep> {
    let c = b.conclusion();
    c.supported_by
        .iter()
        .filter(|l| l.relation != Relation::References)
        .filter_map(|l| b.step(l.step))
        .max_by_key(|s| {
            (
                s.grounding,
                s.status != Status::Hypothesis,
                s.confidence_permille.unwrap_or(0),
                s.index,
            )
        })
}

/// The grounding step with evidence (digest or measurement) closest to the conclusion.
fn strongest_evidence(b: &ExplanationBundle) -> Option<&CausalStep> {
    b.evidence
        .iter()
        .filter_map(|e| b.step(e.step))
        .filter(|s| s.grounding)
        .min_by_key(|s| (s.depth, s.index))
}

fn header(b: &ExplanationBundle, aud: Audience) -> String {
    let c = b.conclusion();
    let mut s = format!("Conclusion: {} [{}]", c.statement, status_words(c.status));
    if aud.shows_ids() {
        let _ = write!(s, " ({})", short(&c.node_id));
    }
    s.push('\n');
    s
}

fn render_summary(b: &ExplanationBundle, level: u8, aud: Audience) -> String {
    let mut out = header(b, aud);
    if level == 0 {
        return out;
    }
    match strongest_reason(b) {
        Some(r) => {
            let _ = writeln!(
                out,
                "Main reason: {} [{}]",
                r.statement,
                status_words(r.status)
            );
        }
        None => out.push_str(
            "Main reason: none recorded. The system has no evidence supporting this conclusion.\n",
        ),
    }
    match strongest_evidence(b) {
        Some(e) => {
            let _ = writeln!(
                out,
                "Strongest evidence: {} [{}]",
                e.statement,
                status_words(e.status)
            );
            if let Some(m) = measurements_line(e) {
                let _ = writeln!(out, "{}", m.trim_start());
            }
        }
        None => out.push_str("Strongest evidence: no observed or checked evidence on this path.\n"),
    }
    match material(b) {
        Some(u) => {
            let _ = writeln!(out, "Main uncertainty: {}", u.detail);
        }
        None => out.push_str("Main uncertainty: none recorded on this path.\n"),
    }
    if level >= 2 {
        out.push('\n');
        out.push_str(&render_steps(b, level, aud));
    }
    out
}

fn render_steps(b: &ExplanationBundle, level: u8, aud: Audience) -> String {
    let mut out = String::new();
    if level == 0 {
        return header(b, aud);
    }
    let shown: Vec<&CausalStep> = if level == 1 {
        let c = b.conclusion();
        let mut v: Vec<&CausalStep> = c
            .supported_by
            .iter()
            .filter_map(|l| b.step(l.step))
            .collect();
        v.push(c);
        v
    } else {
        b.steps.iter().collect()
    };
    let mut last: Option<Role> = None;
    for s in shown {
        if last != Some(s.role) {
            let _ = writeln!(out, "{}:", s.role.heading());
            last = Some(s.role);
        }
        if s.index == b.conclusion_step {
            let _ = writeln!(
                out,
                "{}. Therefore: {} [{}]",
                s.index,
                s.statement,
                status_words(s.status)
            );
        } else {
            let _ = writeln!(out, "{}", step_line(s, level, aud));
        }
        if level >= 3 {
            if let Some(m) = measurements_line(s) {
                let _ = writeln!(out, "{m}");
            }
        }
        if level >= 4 {
            let _ = writeln!(
                out,
                "   source: {} {} {}{}",
                s.source.system,
                s.source.artifact,
                s.source.reference,
                s.source
                    .digest
                    .as_ref()
                    .map(|d| format!(" digest {d}"))
                    .unwrap_or_default()
            );
        }
    }
    out.push_str("Uncertainty:\n");
    let visible: Vec<&Uncertainty> = b
        .uncertainties
        .iter()
        .filter(|u| level >= 3 || u.kind != UncertaintyKind::Inferred)
        .collect();
    if visible.is_empty() {
        out.push_str("- no gaps recorded on this path (inferred steps are marked as such)\n");
    }
    for u in visible {
        let _ = writeln!(out, "{}", uncertainty_line(u));
    }
    if !b.contradictions.is_empty() {
        out.push_str("Conflicts:\n");
        for c in &b.contradictions {
            let _ = writeln!(
                out,
                "- {} (involves {} step(s))",
                c.statement,
                c.involves.len()
            );
        }
    }
    if level >= 2 && !b.alternatives.is_empty() {
        out.push_str("Other explanations the system recorded:\n");
        for a in &b.alternatives {
            let _ = writeln!(out, "- {}", a.statement);
        }
    }
    out
}

fn render_technical(b: &ExplanationBundle, level: u8) -> String {
    let mut out = String::new();
    let c = b.conclusion();
    let _ = writeln!(
        out,
        "explanation target={} producer={} builder={} contract={} v{}",
        b.provenance.target,
        b.provenance.producer,
        b.provenance.builder,
        b.provenance.contract_format,
        b.provenance.contract_version
    );
    let _ = writeln!(
        out,
        "conclusion step={} id={} status={} kind={}",
        c.index,
        c.node_id,
        c.status.name(),
        c.kind.name()
    );
    if level == 0 {
        return out;
    }
    for s in &b.steps {
        let sup: Vec<String> = s
            .supported_by
            .iter()
            .map(|l| format!("{}:{}", l.relation.name(), l.step))
            .collect();
        let _ = writeln!(
            out,
            "step {} id={} kind={} status={} role={:?} depth={} grounding={} supported_by=[{}]",
            s.index,
            s.node_id,
            s.kind.name(),
            s.status.name(),
            s.role,
            s.depth,
            s.grounding,
            sup.join(",")
        );
        let _ = writeln!(out, "  statement: {}", s.statement);
        if let Some(p) = s.confidence_permille {
            let _ = writeln!(
                out,
                "  confidence_permille={} basis={}",
                p,
                s.confidence_basis.as_deref().unwrap_or("unspecified")
            );
        }
        if level >= 3 {
            if let Some(m) = measurements_line(s) {
                let _ = writeln!(out, " {}", m.trim_start());
            }
        }
        if level >= 4 {
            let _ = writeln!(
                out,
                "  source system={} artifact={} reference={} digest={}",
                s.source.system,
                s.source.artifact,
                s.source.reference,
                s.source.digest.as_deref().unwrap_or("-")
            );
            if let Some(t) = s.recorded_at_utc {
                let _ = writeln!(
                    out,
                    "  recorded_at_utc={t} (informational, not used for order)"
                );
            }
        }
        for n in &s.notes {
            let _ = writeln!(out, "  note: {n}");
        }
    }
    for u in &b.uncertainties {
        let _ = writeln!(
            out,
            "uncertainty code={} kind={:?} node={} related={} detail={}",
            u.kind.code(),
            u.kind,
            u.node_id,
            u.related.as_deref().unwrap_or("-"),
            u.detail
        );
    }
    for c in &b.contradictions {
        let _ = writeln!(
            out,
            "contradiction id={} involves=[{}] statement={}",
            c.node_id,
            c.involves.join(","),
            c.statement
        );
    }
    for a in &b.alternatives {
        let _ = writeln!(
            out,
            "alternative id={} to={} statement={}",
            a.node_id, a.alternative_to, a.statement
        );
    }
    if level >= 4 {
        let _ = writeln!(
            out,
            "input_digest={} bundle_digest={} visited={}/{} limits=depth:{},nodes:{}",
            b.provenance.input_digest,
            b.bundle_digest,
            b.provenance.visited_nodes,
            b.provenance.graph_nodes,
            b.provenance.limits.max_depth,
            b.provenance.limits.max_nodes
        );
    }
    out
}

/// Fixed, presentation-only analogy catalog keyed by artifact kind and status.
/// These sentences are illustrations. They are not stored anywhere, not part of the
/// bundle, and not evidence for anything.
pub fn analogy_for(kind: NodeKind, status: Status) -> Option<&'static str> {
    Some(match (kind, status) {
        (NodeKind::CapabilityAnalysis, _) => {
            "The flagged part acts like a toll booth on a busy road: every request has to pass through it, so when it slows down, everything behind it queues up."
        }
        (NodeKind::Hypothesis, _) | (NodeKind::CortexRecord, Status::Hypothesis) => {
            "A hypothesis is like a mechanic's first guess about a noise in the engine: useful for deciding what to check, but not a finding until the check is done."
        }
        (NodeKind::Falsification, _) => {
            "A falsification test is like agreeing in advance which gauge reading would prove the repair did not work."
        }
        (NodeKind::EvaluationReceipt, _) => {
            "The evaluation receipt is like an inspection sheet signed after a test drive: it records what was measured, not what was hoped."
        }
        (NodeKind::AgentBranch, _) => {
            "A branch is like one line of investigation in a case file: it lists the documents it actually relied on, not every document in the archive."
        }
        (_, Status::Contradiction) => {
            "A contradiction is like two witnesses whose accounts do not match: the system keeps both and flags the conflict instead of picking one quietly."
        }
        _ => return None,
    })
}

fn render_analogy(b: &ExplanationBundle, level: u8, aud: Audience) -> String {
    let mut out = String::new();
    let pick = b
        .steps
        .iter()
        .rev()
        .find_map(|s| analogy_for(s.kind, s.status).map(|a| (s.index, a)));
    match pick {
        Some((i, a)) => {
            let _ = writeln!(
                out,
                "Analogy (illustration only, not evidence; about step {i}):"
            );
            let _ = writeln!(out, "  {a}");
        }
        None => out.push_str("Analogy: none available for this explanation.\n"),
    }
    out.push_str("\nThe evidence itself:\n");
    out.push_str(&render_steps(b, level.max(1), aud));
    out
}

/// Render the bundle. Pure function of (bundle, request).
pub fn render(b: &ExplanationBundle, req: &ExplanationRequest) -> String {
    let level = req.effective_level();
    match req.mode {
        Mode::Summary => render_summary(b, level, req.audience),
        Mode::StepByStep => {
            let mut s = header(b, req.audience);
            if level > 0 {
                s.push('\n');
                s.push_str(&render_steps(b, level, req.audience));
            }
            s
        }
        Mode::Technical => render_technical(b, level),
        Mode::Analogy => render_analogy(b, level, req.audience),
    }
}
