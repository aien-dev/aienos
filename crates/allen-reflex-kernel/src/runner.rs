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
