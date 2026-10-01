//! Clarification and rewind over one bundle, without recomputing anything.
//!
//! "Explain that", "explain step 4", "go one level deeper", "where did that come
//! from?", "show the evidence", "explain it technically / simply", "give me an
//! analogy", "what are you uncertain about?", "what else was considered?" all read
//! the same immutable bundle.

use crate::bundle::ExplanationBundle;
use crate::contract::{ExplainError, Relation};
use crate::render::{render, status_words, Audience, ExplanationRequest, Mode, MAX_LEVEL};
use std::fmt::Write;

/// A conversation about one explanation.
pub struct ExplanationSession {
    bundle: ExplanationBundle,
    level: u8,
    audience: Audience,
}

impl ExplanationSession {
    pub fn new(bundle: ExplanationBundle, audience: Audience) -> Self {
        Self {
            bundle,
            level: 0,
            audience,
        }
    }

    pub fn bundle(&self) -> &ExplanationBundle {
        &self.bundle
    }

    pub fn level(&self) -> u8 {
        self.level
    }

    fn req(&self, mode: Mode, level: u8) -> ExplanationRequest {
        ExplanationRequest {
            mode,
            level: Some(level),
            audience: self.audience,
        }
    }

    /// "Explain that": the conclusion only (level 0).
    pub fn explain(&mut self) -> String {
        self.level = 0;
        render(&self.bundle, &self.req(Mode::StepByStep, 0))
    }

    /// "Go one level deeper."
    pub fn deeper(&mut self) -> String {
        self.level = (self.level + 1).min(MAX_LEVEL);
        render(&self.bundle, &self.req(Mode::StepByStep, self.level))
    }

    /// "Back up one level."
    pub fn shallower(&mut self) -> String {
        self.level = self.level.saturating_sub(1);
        render(&self.bundle, &self.req(Mode::StepByStep, self.level))
    }

    /// "Explain step n": the step, what it rests on, and what rests on it.
    pub fn step(&self, n: u32) -> Result<String, ExplainError> {
        let s = self.bundle.step(n).ok_or(ExplainError::StepOutOfRange(n))?;
        let mut out = format!(
            "Step {}: {} [{}]\n",
            s.index,
            s.statement,
            status_words(s.status)
        );
        if s.supported_by.is_empty() {
            if s.grounding {
                out.push_str("It is a starting point: recorded directly, not derived.\n");
            } else {
                out.push_str("Nothing earlier on the path supports it.\n");
            }
        } else {
            for l in &s.supported_by {
                let p = self.bundle.step(l.step).expect("support index valid");
                let verb = if l.relation == Relation::References {
                    "It refers to (weak link, not a recorded one)"
                } else {
                    "It rests on"
                };
                let _ = writeln!(
                    out,
                    "{verb} step {} ({}): {}",
                    p.index,
                    l.relation.name(),
                    p.statement
                );
            }
        }
        for later in &self.bundle.steps {
            if later.supported_by.iter().any(|l| l.step == s.index) {
                let _ = writeln!(out, "Step {} rests on it.", later.index);
            }
        }
        for u in self
            .bundle
            .uncertainties
            .iter()
            .filter(|u| u.node_id == s.node_id)
        {
            let _ = writeln!(out, "Caveat: {}", u.detail);
        }
        Ok(out)
    }

    /// "Where did that claim come from?"
    pub fn source(&self, n: u32) -> Result<String, ExplainError> {
        let s = self.bundle.step(n).ok_or(ExplainError::StepOutOfRange(n))?;
        Ok(format!(
            "Step {} comes from {} ({}), reference {}{}; node {}; status {}.\n",
            s.index,
            s.source.system,
            s.source.artifact,
            s.source.reference,
            s.source
                .digest
                .as_ref()
                .map(|d| format!(", digest {d}"))
                .unwrap_or_default(),
            s.node_id,
            s.status.name()
        ))
    }

    /// "Show the evidence."
    pub fn evidence(&self) -> String {
        let mut out = String::new();
        if self.bundle.evidence.is_empty() {
            out.push_str("No digests, receipts or measurements are attached to this path.\n");
        }
        for e in &self.bundle.evidence {
            let _ = write!(
                out,
                "Step {}: {} {} {}",
                e.step, e.source.system, e.source.artifact, e.source.reference
            );
            if let Some(d) = &e.source.digest {
                let _ = write!(out, " digest {d}");
            }
            out.push('\n');
            for m in &e.measurements {
                let _ = writeln!(out, "  {} = {} {}", m.name, m.value, m.unit);
            }
        }
        out
    }

    pub fn technical(&self) -> String {
        render(&self.bundle, &self.req(Mode::Technical, MAX_LEVEL))
    }

    pub fn simple(&self) -> String {
        render(
            &self.bundle,
            &ExplanationRequest {
                mode: Mode::Summary,
                level: Some(1),
                audience: Audience::General,
            },
        )
    }

    pub fn analogy(&self) -> String {
        render(&self.bundle, &self.req(Mode::Analogy, 2))
    }

    /// "What are you uncertain about?"
    pub fn uncertainties(&self) -> String {
        if self.bundle.uncertainties.is_empty() && self.bundle.contradictions.is_empty() {
            return "No uncertainty is recorded on this path.\n".into();
        }
        let mut out = String::new();
        for u in &self.bundle.uncertainties {
            let _ = writeln!(out, "- {}: {}", u.kind.label(), u.detail);
        }
        for c in &self.bundle.contradictions {
            let _ = writeln!(out, "- conflict: {}", c.statement);
        }
        out
    }

    /// "What other explanations were considered?" Only explicitly recorded ones.
    pub fn alternatives(&self) -> String {
        if self.bundle.alternatives.is_empty() {
            return "No alternative explanations are recorded in the evidence.\n".into();
        }
        let mut out = String::new();
        for a in &self.bundle.alternatives {
            let _ = writeln!(out, "- {}", a.statement);
        }
        out
    }
}
