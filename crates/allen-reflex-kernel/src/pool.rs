//! The training pool compiled into the image: the exam train split plus ALLEN's own contract cases,
//! the same pool `crates/allen-reflex/examples/common::pool()` builds (train first, then extra, file
//! order). Dev and held-out cases are never part of it.

use allen_reflex::Action;

/// `docs/native/pi5-8/orchestrator-exam/cases-train.psv` (id|category|action|text|turns).
pub const TRAIN_PSV: &str =
    include_str!("../../../docs/native/pi5-8/orchestrator-exam/cases-train.psv");
/// `docs/native/pi5-8/orchestrator-exam/cases-reflex-extra.psv` (id|family|category|action|text|turns|source).
pub const EXTRA_PSV: &str =
    include_str!("../../../docs/native/pi5-8/orchestrator-exam/cases-reflex-extra.psv");

/// One labelled training example (borrowed from the compiled-in text).
#[derive(Clone, Copy, Debug)]
pub struct Example {
    /// label
    pub action: Action,
    /// expected argument text, empty when none
    pub text: &'static str,
    /// the exam's turns field
    pub turns: &'static str,
}

/// Call `f` on every pool example in training order. `Err` names a malformed line.
pub fn for_each(mut f: impl FnMut(Example)) -> Result<usize, &'static str> {
    let mut n = 0;
    for (src, fields) in [(TRAIN_PSV, 5usize), (EXTRA_PSV, 7usize)] {
        for line in src.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let mut it = line.splitn(fields, '|');
            let mut col = [""; 7];
            let mut k = 0;
            for c in it.by_ref() {
                col[k] = c;
                k += 1;
            }
            if k != fields {
                return Err("pool line has the wrong number of fields");
            }
            // train: id cat act text turns; extra: id fam cat act text turns src
            let (act, text, turns) = if fields == 5 {
                (col[2], col[3], col[4])
            } else {
                (col[3], col[4], col[5])
            };
            let action = Action::from_name(act).ok_or("pool line has an unknown action")?;
            f(Example {
                action,
                text,
                turns,
            });
            n += 1;
        }
    }
    Ok(n)
}
