//! Tuning on dev and on family-grouped cross-validation of the training pool.
//! usage: cargo run --release -p allen-reflex --example tune
//! Never reads held-out. Every knob is moved one at a time from Config::frozen, and each
//! setting is scored on (a) dev, trained on the whole pool, and (b) 10-fold cross-validation
//! of the pool where a train case and all its paraphrases (one family) sit in the same fold.
//! Then a risk-coverage table for the abstain thresholds (margin, neighbour agreement).
#[path = "common/mod.rs"]
mod common;
use allen_reflex::{exam_turns, Action, Config, Mode};
use common::*;

/// Fold of a case: train case Dxxx shares the fold of its paraphrase family F-Dxxx.
fn fold(c: &Case) -> usize {
    let key = if c.family.starts_with('D') {
        format!("F-{}", c.family)
    } else {
        c.family.clone()
    };
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    (h % 10) as usize
}

/// (action ok, exact ok, n) on `test` for a core trained on `train`.
fn run(cfg: Config, train: &[&Case], test: &[&Case]) -> (usize, usize, usize) {
    let mut core = build(cfg, train);
    core.set_learning(false);
    let (mut a, mut e) = (0, 0);
    for c in test {
        let (d, _) = core.decide(&exam_turns(&c.turns));
        let (x, y) = judge(c, &d);
        a += x as usize;
        e += y as usize;
    }
    (a, e, test.len())
}

fn cv(cfg: Config, pool: &[Case]) -> (usize, usize, usize) {
    let mut t = (0, 0, 0);
    for k in 0..10 {
        let tr: Vec<&Case> = pool.iter().filter(|c| fold(c) != k).collect();
        let te: Vec<&Case> = pool.iter().filter(|c| fold(c) == k).collect();
        let r = run(cfg, &tr, &te);
        t = (t.0 + r.0, t.1 + r.1, t.2 + r.2);
    }
    t
}

fn line(name: &str, cfg: Config, pool: &[Case], dev: &[Case]) {
    let all: Vec<&Case> = pool.iter().collect();
    let dv: Vec<&Case> = dev.iter().collect();
    let d = run(cfg, &all, &dv);
    let c = cv(cfg, pool);
    println!(
        "{:<10} {:<28} dev action {:>2}/{} exact {:>2}/{}   cv action {:>3}/{} exact {:>3}/{}",
        cfg.mode.name(),
        name,
        d.0,
        d.2,
        d.1,
        d.2,
        c.0,
        c.2,
        c.1,
        c.2
    );
}

fn main() {
    let pool = pool();
    let dev = load("dev");
    let only = std::env::args().nth(1).unwrap_or_default();
    if only.is_empty() || only == "grid" {
        for mode in [Mode::Reflex, Mode::Nearest, Mode::Perceptron] {
            let f = Config::frozen(mode);
            line("frozen", f, &pool, &dev);
            if mode == Mode::Perceptron {
                for ep in [5, 10, 40] {
                    let mut c = f;
                    c.perceptron_epochs = ep;
                    line(&format!("epochs={ep}"), c, &pool, &dev);
                }
            }
            for k in [1, 5] {
                if mode == Mode::Perceptron {
                    break;
                }
                let mut c = f;
                c.hv.k = k;
                line(&format!("k={k}"), c, &pool, &dev);
            }
            for ch in 0..8 {
                for w in [0u16, 6] {
                    let mut c = f;
                    c.weights[ch] = w;
                    line(&format!("weight[{ch}]={w}"), c, &pool, &dev);
                }
            }
            if mode != Mode::Reflex {
                continue;
            }
            for words in [64, 256] {
                let mut c = f;
                c.hv.words = words;
                line(&format!("D={}", words * 64), c, &pool, &dev);
            }
            for alpha in [0.0, 0.25, 0.75, 1.0] {
                let mut c = f;
                c.hv.alpha = alpha;
                line(&format!("alpha={alpha}"), c, &pool, &dev);
            }
            for zb in [0.0, 0.8] {
                let mut c = f;
                c.hv.zero_band = zb;
                line(&format!("zero_band={zb}"), c, &pool, &dev);
            }
            for (ep, eta) in [(0, 0.5), (10, 0.5), (40, 0.05), (40, 1.0)] {
                let mut c = f;
                c.hv.epochs = ep;
                c.hv.eta = eta;
                line(&format!("epochs={ep} eta={eta}"), c, &pool, &dev);
            }
        }
    }
    if only.is_empty() || only == "risk" {
        // risk-coverage: pooled over cross-validation folds and dev
        for mode in [Mode::Reflex, Mode::Nearest, Mode::Perceptron] {
            let f = Config::frozen(mode);
            let mut rows: Vec<(f32, f32, bool, bool, bool)> = Vec::new(); // margin, agree, correct, exp clarify, src dev
            let mut collect = |train: Vec<&Case>, test: Vec<&Case>, is_dev: bool| {
                let mut core = build(f, &train);
                core.set_learning(false);
                for c in test {
                    let (d, e) = core.decide(&exam_turns(&c.turns));
                    if !matches!(e.why, allen_reflex::Why::Scored) {
                        continue;
                    }
                    let ok = judge(c, &d).1;
                    rows.push((e.margin, e.agree, ok, c.action == Action::Clarify, is_dev));
                }
            };
            for k in 0..10 {
                collect(
                    pool.iter().filter(|c| fold(c) != k).collect(),
                    pool.iter().filter(|c| fold(c) == k).collect(),
                    false,
                );
            }
            collect(pool.iter().collect(), dev.iter().collect(), true);
            println!(
                "{} risk-coverage over {} scored decisions (cv + dev)",
                f.mode.name(),
                rows.len()
            );
            println!("  t_margin  t_agree  answered  wrong_answered  exact_if_abstain_is_clarify");
            for tm in [0.0f32, 0.005, 0.01, 0.02, 0.05, 0.1] {
                for ta in [0.0f32, 0.5, 0.7] {
                    let (mut ans, mut wrong, mut exact) = (0, 0, 0);
                    for r in &rows {
                        let abstain = r.0 < tm || r.1 < ta;
                        if abstain {
                            exact += r.3 as usize;
                        } else {
                            ans += 1;
                            wrong += !r.2 as usize;
                            exact += r.2 as usize;
                        }
                    }
                    println!(
                        "  {tm:<8}  {ta:<7}  {ans:>8}  {wrong:>14}  {exact:>5}/{}",
                        rows.len()
                    );
                }
            }
        }
    }
}
