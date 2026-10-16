//! One trained core and one decision line per case. Shared by the kernel entry points and the
//! host harness (`examples/host_exam.rs`), so both print the same bytes for the same case.
//!
//! The core gets the turns only. Learning is switched off before the first decision (scoring
//! rule of `docs/native/PI5-8-ALLEN-REFLEX.md`), and `decide` takes the core by shared
//! reference, so no decision can change the next one.

use allen_reflex::{exam_turns, Config, Mode, Reflex};
use alloc::string::String;

/// Line prefix of a decision.
pub const LINE_TAG: &str = "ALLEN_D";

/// Mode for a number on the C side (0 reflex, 1 nearest, 2 perceptron).
pub fn mode_of(n: u32) -> Option<Mode> {
    match n {
        0 => Some(Mode::Reflex),
        1 => Some(Mode::Nearest),
        2 => Some(Mode::Perceptron),
        _ => None,
    }
}

/// A trained core for one mode.
pub struct Session {
    core: Reflex,
    examples: usize,
}

impl Session {
    /// Train a fresh core with the frozen configuration of `mode` on the compiled-in pool,
    /// then switch learning off.
    pub fn train(mode: Mode) -> Result<Session, &'static str> {
        let mut core = Reflex::new(Config::frozen(mode));
        let mut err = None;
        let examples = crate::pool::for_each(|ex| {
            if err.is_some() {
                return;
            }
            let t = exam_turns(ex.turns);
            let text = if ex.text.is_empty() {
                None
            } else {
                Some(ex.text)
            };
            if core.train(&t, ex.action, text).is_err() {
                err = Some("training refused an example");
            }
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        core.finish_training();
        core.set_learning(false);
        Ok(Session { core, examples })
    }

    /// Mode name.
    pub fn mode(&self) -> Mode {
        self.core.config().mode
    }

    /// Training examples stored.
    pub fn examples(&self) -> usize {
        self.examples
    }

    /// Learned-state bytes reported by the core (capacity based).
    pub fn memory_bytes(&self) -> usize {
        self.core.memory_bytes()
    }

    /// Exemplars kept by the core.
    pub fn exemplars(&self) -> usize {
        self.core.exemplars()
    }

    /// The decision JSON for `turns`. Nothing else of the core's output leaves this function.
    pub fn decide_json(&self, turns: &str) -> String {
        let t = exam_turns(turns);
        self.core.decide(&t).0.json()
    }
}

/// `ALLEN_D <mode> <id> <json>` into `out` (cleared first); returns the byte offset of the JSON.
pub fn line(out: &mut String, mode: Mode, id: &str, json: &str) -> usize {
    out.clear();
    out.push_str(LINE_TAG);
    out.push(' ');
    out.push_str(mode.name());
    out.push(' ');
    out.push_str(id);
    out.push(' ');
    let off = out.len();
    out.push_str(json);
    off
}

/// Line prefix of an interactive route proposal (aienos#399).
pub const ROUTE_TAG: &str = "ALLEN_P";

/// What the C side checks about one proposal (route, label, speaker, readiness).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalFacts {
    /// `Route` index
    pub route: u32,
    /// the core's `Action` index
    pub label: u32,
    /// 1 owner, 0 guest
    pub owner: u32,
    /// 1 ready, 0 not ready
    pub ready: u32,
}

impl Session {
    /// The proposal JSON for one route card request in this image's context. `caps` are the
    /// image's real capabilities (bits of [`allen_reflex::route::Caps::from_bits`]); the card
    /// can only say who speaks, the consent and the pending state, never what the image has.
    pub fn propose_json(
        &self,
        r: &crate::card::RouteRef,
        turns_escaped: &str,
        request_id: u64,
        caps: u32,
    ) -> (String, ProposalFacts) {
        use allen_reflex::route::{self, Calibration, Caps, RouteCtx, RouteRequest, Speaker};
        let decoded = route::pct_decode(turns_escaped);
        let text = decoded.as_deref().unwrap_or("");
        let t = exam_turns(text);
        let ctx = RouteCtx {
            speaker: if r.owner {
                Speaker::Owner
            } else {
                Speaker::Guest
            },
            memory_consent: r.consent,
            pending: r.pending,
            caps: Caps::from_bits(caps),
            installed_model: None,
            subject_id: [0u8; 32],
            cal: Calibration::frozen(self.mode()),
        };
        let req = RouteRequest {
            request_id,
            session_id: r.session,
            turns: if decoded.is_some() { &t } else { &[] },
        };
        let p = route::propose(&self.core, &req, &ctx);
        let facts = ProposalFacts {
            route: p.route as u32,
            label: p.label.idx() as u32,
            owner: r.owner as u32,
            ready: p.not_ready.is_none() as u32,
        };
        (p.json(), facts)
    }
}

/// `ALLEN_P <mode> <id> <json>` into `out` (cleared first); returns the byte offset of the JSON.
pub fn route_line(out: &mut String, mode: Mode, id: &str, json: &str) -> usize {
    out.clear();
    out.push_str(ROUTE_TAG);
    out.push(' ');
    out.push_str(mode.name());
    out.push(' ');
    out.push_str(id);
    out.push(' ');
    let off = out.len();
    out.push_str(json);
    off
}
