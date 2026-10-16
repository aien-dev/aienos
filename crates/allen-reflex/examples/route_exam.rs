//! Score the interactive router (aienos#399) on one route family file.
//!
//!   cargo run --release -p allen-reflex --example route_exam -- <family.psv> [--sweep]
//!
//! Each core trains on the exam train split + extra cases only (as the Pi image), learning off.
//! Context per row: speaker and flags from the row (C consent, P pending); caps all present,
//! installed model "tinyllama" (the scoring context written in the family header).
//! Prints one `ROUTE <mode> <id> ok|MISS expected=<route>/<then> got=<route>/<then> why=<why>`
//! line per case and one `ROUTE_SUM` line per mode. `--sweep` (dev only) also prints the
//! accuracy for a grid of similarity thresholds, so the frozen calibration can be chosen.
#[path = "common/mod.rs"]
mod common;
use allen_reflex::route::{pct_decode, propose, Calibration, Caps, Route, RouteCtx, RouteRequest, Speaker};
use allen_reflex::{exam_turns, Config, Mode};
use common::*;

struct Row {
    id: String,
    family: String,
    speaker: Speaker,
    consent: bool,
    pending: bool,
    route: Route,
    then: String,
    turns: String,
}

fn load(path: &str) -> Vec<Row> {
    let src = std::fs::read_to_string(path).expect("read family");
    let mut out = Vec::new();
    for l in src.lines() {
        if l.starts_with('#') || l.is_empty() {
            continue;
        }
        let c: Vec<&str> = l.splitn(7, '|').collect();
        assert_eq!(c.len(), 7, "bad row {l}");
        out.push(Row {
            id: c[0].into(),
            family: c[1].into(),
            speaker: match c[2] {
                "owner" => Speaker::Owner,
                "guest" => Speaker::Guest,
                s => panic!("bad speaker {s}"),
            },
            consent: c[3].contains('C'),
            pending: c[3].contains('P'),
            route: Route::from_name(c[4]).unwrap_or_else(|| panic!("bad route {}", c[4])),
            then: c[5].into(),
            turns: pct_decode(c[6]).expect("bad escape"),
        });
    }
    out
}

fn score(rows: &[Row], r: &allen_reflex::Reflex, mode: Mode, cal: Calibration, print: bool) -> (usize, usize) {
    let mut ok = 0;
    let (mut abst_true, mut abst_pred, mut abst_hit) = (0, 0, 0);
    for (i, row) in rows.iter().enumerate() {
        let t = exam_turns(&row.turns);
        let ctx = RouteCtx {
            speaker: row.speaker,
            memory_consent: row.consent,
            pending: row.pending,
            caps: Caps::from_bits(15),
            installed_model: Some("tinyllama"),
            subject_id: [0; 32],
            cal,
        };
        let p = propose(
            r,
            &RouteRequest {
                request_id: i as u64 + 1,
                session_id: 1,
                turns: &t,
            },
            &ctx,
        );
        let then = p.then.map(|t| t.name()).unwrap_or("-");
        let hit = p.route == row.route && then == row.then;
        ok += hit as usize;
        abst_true += (row.route == Route::Clarify) as usize;
        abst_pred += (p.route == Route::Clarify) as usize;
        abst_hit += (row.route == Route::Clarify && p.route == Route::Clarify) as usize;
        if print {
            println!(
                "ROUTE {} {} {} family={} expected={}/{} got={}/{} why={} label={}",
                mode.name(),
                row.id,
                if hit { "ok" } else { "MISS" },
                row.family,
                row.route.name(),
                row.then,
                p.route.name(),
                then,
                p.why.name(),
                p.label.name()
            );
        }
    }
    if print {
        let n = rows.len();
        let answered = n - abst_pred;
        println!(
            "ROUTE_SUM mode={} cases={} correct={} coverage={}/{} clarify_expected={} clarify_given={} clarify_both={} min_sim={} min_margin={}",
            mode.name(),
            n,
            ok,
            answered,
            n,
            abst_true,
            abst_pred,
            abst_hit,
            cal.min_sim,
            cal.min_margin
        );
    }
    (ok, rows.len())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rows = load(args.get(1).expect("family file"));
    let sweep = args.iter().any(|a| a == "--sweep");
    let pool = pool();
    let all: Vec<&Case> = pool.iter().collect();
    for mode in [Mode::Reflex, Mode::Nearest, Mode::Perceptron] {
        let mut r = build(Config::frozen(mode), &all);
        r.set_learning(false);
        score(&rows, &r, mode, Calibration::frozen(mode), true);
        if sweep {
            for k in 0..=12 {
                let s = k as f32 * 0.05;
                let (ok, n) = score(&rows, &r, mode, Calibration { min_sim: s, min_margin: f32::MIN }, false);
                println!("ROUTE_SWEEP mode={} min_sim={:.2} correct={}/{}", mode.name(), s, ok, n);
            }
            for m in [0.0f32, 0.05, 0.1, 0.2, 0.3, 0.5, 1.0] {
                let (ok, n) = score(&rows, &r, mode, Calibration { min_sim: -1.0, min_margin: m }, false);
                println!("ROUTE_SWEEP mode={} min_margin={:.2} correct={}/{}", mode.name(), m, ok, n);
            }
        }
    }
}
