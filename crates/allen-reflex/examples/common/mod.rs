//! Host-side helpers shared by the examples (std allowed here; the core stays no_std).
#![allow(dead_code)]

use allen_reflex::{exam_turns, Action, Config, Reflex};
use std::path::PathBuf;

/// One exam case. `id`, `cat`, `action` and `text` are labels: the harness keeps them,
/// the core only ever sees `turns`.
#[derive(Clone, Debug)]
pub struct Case {
    pub id: String,
    pub family: String,
    pub cat: String,
    pub action: Action,
    pub text: String,
    pub turns: String,
    /// "contract", "train:Dxxx" (extra file) or the split name
    pub source: String,
}

pub fn exam_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/native/pi5-8/orchestrator-exam")
}

/// Read cases-<split>.psv (id|cat|action|text|turns) or the extra file
/// (id|family|cat|action|text|turns|source).
pub fn load(split: &str) -> Vec<Case> {
    if split == "heldout" && std::env::var("ALLEN_REFLEX_HELDOUT_ONCE").ok().as_deref() != Some("1")
    {
        panic!(
            "held-out is sealed: set ALLEN_REFLEX_HELDOUT_ONCE=1 only for the single final scoring"
        );
    }
    let name = if split == "extra" {
        "cases-reflex-extra.psv".to_string()
    } else {
        format!("cases-{split}.psv")
    };
    let p = exam_dir().join(name);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    let mut out = Vec::new();
    for line in s.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line
            .splitn(if split == "extra" { 7 } else { 5 }, '|')
            .collect();
        let (id, fam, cat, act, text, turns, src) = if split == "extra" {
            assert!(f.len() == 7, "bad extra line: {line}");
            (f[0], f[1], f[2], f[3], f[4], f[5], f[6])
        } else {
            assert!(f.len() == 5, "bad line: {line}");
            (f[0], f[0], f[1], f[2], f[3], f[4], split)
        };
        out.push(Case {
            id: id.into(),
            family: fam.into(),
            cat: cat.into(),
            action: Action::from_name(act).unwrap_or_else(|| panic!("bad action {act}")),
            text: text.into(),
            turns: turns.into(),
            source: src.into(),
        });
    }
    out
}

/// Train a fresh core on `cases`.
pub fn build(cfg: Config, cases: &[&Case]) -> Reflex {
    let mut r = Reflex::new(cfg);
    for c in cases {
        let t = exam_turns(&c.turns);
        let txt = if c.text.is_empty() {
            None
        } else {
            Some(c.text.as_str())
        };
        r.train(&t, c.action, txt).expect("train");
    }
    r.finish_training();
    r
}

/// The training pool: train split + our own extra cases.
pub fn pool() -> Vec<Case> {
    let mut v = load("train");
    v.extend(load("extra"));
    v
}

/// Score as score.sh does: (action ok, exact ok).
pub fn judge(c: &Case, d: &allen_reflex::Decision) -> (bool, bool) {
    let a = d.action == c.action;
    if !a {
        return (false, false);
    }
    if c.text.is_empty() {
        return (true, true);
    }
    let n = |s: &str| -> String {
        let l = s.to_ascii_lowercase();
        let l = l.split_whitespace().collect::<Vec<_>>().join(" ");
        l.trim_end_matches(|ch: char| ".!?;,".contains(ch) || ch.is_whitespace())
            .trim()
            .to_string()
    };
    (true, d.text.as_deref().map(n) == Some(n(&c.text)))
}

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}
