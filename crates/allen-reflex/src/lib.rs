#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::needless_range_loop)]

//! ALLEN REFLEX v0: ALLEN's own decision core for the Pi.
//!
//! It reads an operator message (with earlier turns) and answers with exactly one
//! machine-checkable decision `{"action":"<name>","args":{...}}` from the 15 decisions of
//! the orchestration exam. No language model and no prompt: a small learned memory plus
//! explicit rules taken from the agent's own source (`agent_cmd.c`, `lifecycle_fsm.c`).
//!
//! Pipeline for one decision:
//! 1. [`dialog`]: roles and turn order; pending-task state from earlier decisions.
//! 2. [`text`]: tokens with byte offsets into the original message.
//! 3. [`segment`]: ordered requests; the decision is about the first real request.
//! 4. [`policy`]: refuse by intent (rule breaking, verbs the agent lacks, obeying data).
//! 5. [`features`] then a scorer from [`model`]: hypervector memory (REFLEX), or the
//!    nearest-exemplar and perceptron baselines over the same features.
//! 6. Abstention: low similarity, low margin or low neighbour agreement -> `clarify`/`none`.
//! 7. [`span`]: copy the argument text (1..48 printable ASCII bytes) or answer `clarify`.
//!
//! The crate is `no_std` + `alloc`; its only dependency is the in-repo `aienos-crypto`
//! (SHA-256 for [`tower`] cache keys). A kernel that links it must provide a global
//! allocator and a panic handler. Every input is bounded (see [`Config`]).

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod action;
pub mod dialog;
pub mod features;
pub mod hv;
pub mod lexicon;
pub mod model;
pub mod policy;
pub mod route;
pub mod segment;
pub mod span;
pub mod text;
pub mod tower;

pub use action::{Action, N_LABELS};
pub use dialog::{Pending, Role, Turn};
pub use model::{Conflict, HvConfig, MemoryFull, SleepReport};

use alloc::string::String;
use alloc::vec::Vec;
use features::{Feat, N_CHANNELS};
use model::{argmax, HvModel, NearestModel, PerceptronModel, Scores};
use policy::RefuseRule;
use segment::Clause;
use span::{CueMemory, SpanError};
use text::Token;

/// Which label scorer runs behind the shared front end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// hypervector exemplars + ternary prototypes
    Reflex,
    /// nearest exemplar over sparse feature sets (no hypervectors)
    Nearest,
    /// averaged perceptron over sparse features
    Perceptron,
}

impl Mode {
    /// Mode name used in result file names.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Reflex => "reflex",
            Mode::Nearest => "nearest",
            Mode::Perceptron => "perceptron",
        }
    }
}

/// All knobs. [`Config::frozen`] holds the values the exam was scored with.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// scorer
    pub mode: Mode,
    /// weight per feature channel (Word, Bigram, Chars, Concept, Lead, Ctx, CtxConj, Shape)
    pub weights: [u16; N_CHANNELS],
    /// hypervector settings (k is also used by the nearest baseline)
    pub hv: HvConfig,
    /// below this score margin between the top two labels: abstain (`clarify`)
    pub t_margin: f32,
    /// below this similarity to the nearest exemplar: answer `abs_label`
    pub t_abs: f32,
    /// what an unfamiliar message gets
    pub abs_label: Action,
    /// below this share of top-k neighbours agreeing with the top label: abstain
    pub t_agree: f32,
    /// at or above this similarity the nearest exemplar's label is taken as is
    /// (one-shot corrections win for the same message)
    pub exact: f32,
    /// perceptron passes
    pub perceptron_epochs: u32,
    /// sleep: same-label exemplars this similar are merged
    pub sleep_dup: f32,
    /// sleep: different-label exemplars this similar are reported as conflicts
    pub sleep_conflict: f32,
    /// input bound: bytes of the scored message (agent_cmd.c's file limit)
    pub max_msg_bytes: usize,
    /// input bound: tokens read
    pub max_tokens: usize,
    /// input bound: turns read
    pub max_turns: usize,
}

impl Config {
    /// The frozen configuration (chosen on dev; see docs/native/PI5-8-ALLEN-REFLEX.md).
    pub fn frozen(mode: Mode) -> Config {
        let base = Config {
            mode,
            weights: [3, 2, 1, 4, 4, 3, 3, 2],
            hv: HvConfig {
                words: 128,
                k: 3,
                alpha: 0.5,
                zero_band: 0.42,
                epochs: 40,
                eta: 0.5,
                max_exemplars: 1024,
            },
            t_margin: 0.0,
            t_abs: -1.0,
            abs_label: Action::None,
            t_agree: 0.0,
            exact: 0.97,
            perceptron_epochs: 20,
            sleep_dup: 0.95,
            sleep_conflict: 0.80,
            max_msg_bytes: 2048,
            max_tokens: 256,
            max_turns: 16,
        };
        match mode {
            Mode::Reflex => Config {
                weights: [3, 0, 1, 6, 4, 3, 3, 2],
                ..base
            },
            Mode::Nearest => Config {
                weights: [0, 2, 0, 6, 4, 0, 3, 2],
                hv: HvConfig { k: 5, ..base.hv },
                ..base
            },
            Mode::Perceptron => Config {
                weights: [0, 2, 1, 4, 4, 3, 3, 2],
                perceptron_epochs: 10,
                ..base
            },
        }
    }
}

/// One decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// the action
    pub action: Action,
    /// text for remember, prefer, task, prompt (1..48 printable ASCII, no `"` or `\`)
    pub text: Option<String>,
}

impl Decision {
    fn bare(a: Action) -> Decision {
        Decision {
            action: a,
            text: None,
        }
    }

    /// The decision as one JSON line, always valid for the exam schema.
    pub fn json(&self) -> String {
        let mut s = String::from("{\"action\":\"");
        s.push_str(self.action.name());
        s.push_str("\",\"args\":{");
        if let Some(t) = &self.text {
            s.push_str("\"text\":\"");
            s.push_str(t);
            s.push('"');
        }
        s.push_str("}}");
        s
    }
}

/// Why the decision came out as it did.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Why {
    /// no user turn
    NoUserTurn,
    /// message longer than the bound
    InputTooLong,
    /// no words
    NoWords,
    /// policy layer refused
    Policy(RefuseRule),
    /// nearest exemplar is (almost) the same message
    ExactRecall,
    /// top label of the scorer
    Scored,
    /// nearest exemplar too far: unfamiliar message
    LowSimilarity,
    /// top two labels too close
    LowMargin,
    /// neighbours disagree
    LowAgreement,
    /// a text action without usable text
    Span(SpanError),
}

/// Explanation of a decision. Kept outside the decision JSON.
#[derive(Clone, Debug)]
pub struct Explanation {
    /// reason
    pub why: Why,
    /// scorer's top label (before abstention)
    pub top: Action,
    /// runner-up
    pub second: Action,
    /// score margin between them
    pub margin: f32,
    /// nearest exemplar similarity
    pub best_sim: f32,
    /// neighbour agreement
    pub agree: f32,
    /// nearest exemplar: label and its message
    pub nearest: Option<(Action, String)>,
    /// word where a policy rule fired
    pub rule_word: Option<String>,
    /// byte range of the copied text in the message
    pub span: Option<(usize, usize)>,
}

impl Explanation {
    fn new(why: Why) -> Explanation {
        Explanation {
            why,
            top: Action::Clarify,
            second: Action::Clarify,
            margin: 0.0,
            best_sim: 0.0,
            agree: 0.0,
            nearest: None,
            rule_word: None,
            span: None,
        }
    }
}

/// Why learning was not done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LearnError {
    /// learning is switched off (evaluation)
    Off,
    /// exemplar memory is full; run `sleep()`
    Full,
    /// the turns have no user message
    NoUserTurn,
}

enum Model {
    Hv(HvModel),
    Nearest(NearestModel),
    Perceptron(PerceptronModel),
}

struct Analysis<'a> {
    msg: &'a str,
    toks: Vec<Token>,
    clauses: Vec<Clause>,
    primary: Clause,
    state: dialog::DialogState,
}

/// The decision core.
pub struct Reflex {
    cfg: Config,
    model: Model,
    cues: CueMemory,
    learning: bool,
}

fn find_ci(hay: &str, needle: &str) -> Option<usize> {
    let h = hay.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

impl Reflex {
    /// Empty core with configuration `cfg`. Learning is on.
    pub fn new(cfg: Config) -> Reflex {
        let model = match cfg.mode {
            Mode::Reflex => Model::Hv(HvModel::new(cfg.hv)),
            Mode::Nearest => Model::Nearest(NearestModel::new(cfg.hv.k, cfg.hv.max_exemplars)),
            Mode::Perceptron => {
                Model::Perceptron(PerceptronModel::new(cfg.perceptron_epochs, 65536))
            }
        };
        Reflex {
            cfg,
            model,
            cues: CueMemory::default(),
            learning: true,
        }
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Switch learning on or off. With learning off, `learn_*` return [`LearnError::Off`].
    pub fn set_learning(&mut self, on: bool) {
        self.learning = on;
    }

    /// Stored exemplars (0 for the perceptron, which keeps weights).
    pub fn exemplars(&self) -> usize {
        match &self.model {
            Model::Hv(m) => m.len(),
            Model::Nearest(m) => m.len(),
            Model::Perceptron(_) => 0,
        }
    }

    /// Label and message of exemplar `i`.
    pub fn exemplar(&self, i: usize) -> Option<(Action, &str)> {
        match &self.model {
            Model::Hv(m) if i < m.len() => Some(m.exemplar(i)),
            Model::Nearest(m) if i < m.len() => Some(m.exemplar(i)),
            _ => None,
        }
    }

    /// Bytes of learned state (exemplars, prototypes, cues), capacity based.
    pub fn memory_bytes(&self) -> usize {
        let m = match &self.model {
            Model::Hv(m) => m.bytes(),
            Model::Nearest(m) => m.bytes(),
            Model::Perceptron(m) => m.bytes(),
        };
        m + self.cues.bytes()
    }

    fn analyse<'a>(&self, turns: &[Turn<'a>]) -> Result<Analysis<'a>, Why> {
        let turns = if turns.len() > self.cfg.max_turns {
            &turns[turns.len() - self.cfg.max_turns..]
        } else {
            turns
        };
        let state = dialog::state(turns);
        let lu = state.last_user.ok_or(Why::NoUserTurn)?;
        let msg = turns[lu].text;
        if msg.len() > self.cfg.max_msg_bytes {
            return Err(Why::InputTooLong);
        }
        let toks = text::tokenize(msg, self.cfg.max_tokens);
        if !toks.iter().any(|t| t.alnum) {
            return Err(Why::NoWords);
        }
        let clauses = segment::clauses(&toks);
        let primary = segment::primary(&toks, &clauses).ok_or(Why::NoWords)?;
        Ok(Analysis {
            msg,
            toks,
            clauses,
            primary,
            state,
        })
    }

    fn feats(&self, a: &Analysis) -> Vec<Feat> {
        let p = a.primary;
        let from = a.toks[p.end - 1].end;
        let to = if p.end < a.toks.len() {
            a.toks[p.end].start
        } else {
            a.msg.len()
        };
        let ends_q = a.msg.as_bytes()[from..to].contains(&b'?');
        features::extract(&a.toks, p, &a.state, &self.cfg.weights, ends_q)
    }

    fn score(&self, f: &[Feat]) -> Scores {
        match &self.model {
            Model::Hv(m) => m.score_hv(&m.encode(f)),
            Model::Nearest(m) => m.score(f),
            Model::Perceptron(m) => m.score(f),
        }
    }

    /// Decide. Never fails: every outcome is one schema-valid decision.
    pub fn decide(&self, turns: &[Turn]) -> (Decision, Explanation) {
        let a = match self.analyse(turns) {
            Ok(a) => a,
            Err(w) => return (Decision::bare(Action::Clarify), Explanation::new(w)),
        };
        if let Some((r, i)) = policy::check(&a.toks, &a.clauses) {
            let mut e = Explanation::new(Why::Policy(r));
            e.rule_word = Some(a.toks[i].word.clone());
            return (Decision::bare(Action::Refuse), e);
        }
        let f = self.feats(&a);
        let mut sc = self.score(&f);
        if a.state.pending == Pending::No {
            for l in [Action::Approve, Action::Deny, Action::Cancel] {
                sc.s[l.idx()] = -9.0;
            }
        }
        let top = argmax(&sc.s);
        let mut s2 = sc.s;
        s2[top] = f32::MIN;
        let second = argmax(&s2);
        let mut e = Explanation::new(Why::Scored);
        e.top = Action::from_idx(top);
        e.second = Action::from_idx(second);
        e.margin = sc.s[top] - sc.s[second];
        e.best_sim = sc.best_sim;
        e.agree = sc.agree;
        e.nearest = sc
            .nearest
            .and_then(|i| self.exemplar(i))
            .map(|(l, n)| (l, String::from(n)));
        let mut act = Action::from_idx(top);
        let near_label = e.nearest.as_ref().map(|n| n.0);
        if sc.best_sim >= self.cfg.exact
            && near_label.is_some_and(|l| !(a.state.pending == Pending::No && l.needs_pending()))
        {
            act = near_label.unwrap_or(act);
            e.why = Why::ExactRecall;
        } else if sc.best_sim < self.cfg.t_abs {
            act = self.cfg.abs_label;
            e.why = Why::LowSimilarity;
        } else if e.margin < self.cfg.t_margin && act != Action::Clarify {
            act = Action::Clarify;
            e.why = Why::LowMargin;
        } else if sc.agree < self.cfg.t_agree && act != Action::Clarify {
            act = Action::Clarify;
            e.why = Why::LowAgreement;
        }
        if act.has_text() {
            match self.cues.extract(a.msg, &a.toks, a.primary, act) {
                Ok((t, bs, be)) => {
                    e.span = Some((bs, be));
                    return (
                        Decision {
                            action: act,
                            text: Some(t),
                        },
                        e,
                    );
                }
                Err(se) => {
                    e.why = Why::Span(se);
                    return (Decision::bare(Action::Clarify), e);
                }
            }
        }
        (Decision::bare(act), e)
    }

    fn store(
        &mut self,
        turns: &[Turn],
        label: Action,
        text: Option<&str>,
        wrong: Option<Action>,
        online: bool,
    ) -> Result<(), LearnError> {
        let a = self.analyse(turns).map_err(|_| LearnError::NoUserTurn)?;
        let f = self.feats(&a);
        let note = String::from(a.msg);
        match &mut self.model {
            Model::Hv(m) => {
                let q = m.encode(&f);
                let i = m.push(&q, label, &note).map_err(|_| LearnError::Full)?;
                if online {
                    m.online(i, wrong);
                }
            }
            Model::Nearest(m) => {
                m.push(&f, label, &note).map_err(|_| LearnError::Full)?;
            }
            Model::Perceptron(m) => {
                if online {
                    m.online(&f, label);
                } else {
                    m.push(&f, label);
                }
            }
        }
        if let (true, Some(t)) = (label.has_text(), text) {
            if let Some(bs) = find_ci(a.msg, t) {
                self.cues.learn(&a.toks, a.primary, label, bs, bs + t.len());
            }
        }
        Ok(())
    }

    /// Bulk training: store one labelled example. Call [`Reflex::finish_training`] after the last.
    pub fn train(
        &mut self,
        turns: &[Turn],
        label: Action,
        text: Option<&str>,
    ) -> Result<(), LearnError> {
        self.store(turns, label, text, None, false)
    }

    /// Build prototypes (REFLEX: bundling + retraining) or fit weights (perceptron).
    pub fn finish_training(&mut self) {
        match &mut self.model {
            Model::Hv(m) => {
                m.rebuild();
            }
            Model::Nearest(_) => {}
            Model::Perceptron(m) => m.fit(),
        }
    }

    /// The operator confirmed a decision: keep it as an exemplar (one-shot).
    pub fn learn_confirm(&mut self, turns: &[Turn], d: &Decision) -> Result<(), LearnError> {
        if !self.learning {
            return Err(LearnError::Off);
        }
        self.store(turns, d.action, d.text.as_deref(), None, true)
    }

    /// The operator corrected a decision: store the right label and text (one-shot).
    /// The same message is answered with the corrected label from then on.
    pub fn learn_correct(
        &mut self,
        turns: &[Turn],
        label: Action,
        text: Option<&str>,
    ) -> Result<(), LearnError> {
        if !self.learning {
            return Err(LearnError::Off);
        }
        let wrong = Some(self.decide(turns).0.action).filter(|w| *w != label);
        self.store(turns, label, text, wrong, true)
    }

    /// Consolidation ("sleep"): merge near duplicates, rebuild prototypes, and list
    /// exemplar pairs with different labels that look alike (questions for the operator).
    pub fn sleep(&mut self) -> SleepReport {
        let (dup, con) = (self.cfg.sleep_dup, self.cfg.sleep_conflict);
        match &mut self.model {
            Model::Hv(m) => m.sleep(dup, con),
            Model::Nearest(m) => SleepReport {
                kept: m.len(),
                ..SleepReport::default()
            },
            Model::Perceptron(m) => {
                m.fit();
                SleepReport::default()
            }
        }
    }
}

/// Build turns from the exam's `turns` field ("user ~~ assistant ~~ user ...").
pub fn exam_turns(s: &str) -> Vec<Turn<'_>> {
    s.split(" ~~ ")
        .enumerate()
        .map(|(i, t)| Turn {
            role: if i % 2 == 0 {
                Role::User
            } else {
                Role::Assistant
            },
            text: t,
        })
        .collect()
}
