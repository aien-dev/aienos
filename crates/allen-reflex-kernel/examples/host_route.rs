//! Host harness of the pi5-allen route stage (aienos#399): the same route card, the same
//! compiled-in pool, the same runner code and the same capabilities as the image (none: no Store,
//! no owner desk, no local model, no Spark link), so its `ALLEN_P` lines must equal the Pi's byte
//! for byte.
//! usage: cargo run --release --example host_route -- <route card> [caps, default 0]
//! stdout: the proposal lines (reflex, nearest, perceptron; card order). stderr: timings on this machine.
use allen_reflex::Mode;
use allen_reflex_kernel::{card, runner};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args.first().expect("usage: host_route <route card> [caps]");
    let caps: u32 = args.get(1).map(|c| c.parse().expect("caps")).unwrap_or(0);
    let buf = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let reqs = card::parse_route(&buf).unwrap_or_else(|e| panic!("{path}: refused ({e})"));
    let mut line = String::new();
    for mode in [Mode::Reflex, Mode::Nearest, Mode::Perceptron] {
        let sess = runner::Session::train(mode).expect("train");
        let mut ns = Vec::with_capacity(reqs.len());
        for (i, r) in reqs.iter().enumerate() {
            let id = std::str::from_utf8(&buf[r.id.0..r.id.1]).unwrap();
            let turns = std::str::from_utf8(&buf[r.turns.0..r.turns.1]).unwrap();
            let t = Instant::now();
            let (json, _) = sess.propose_json(r, turns, i as u64 + 1, caps);
            ns.push(t.elapsed().as_nanos());
            runner::route_line(&mut line, mode, id, &json);
            println!("{line}");
        }
        ns.sort_unstable();
        eprintln!(
            "host {}: n={} p50_ns={} max_ns={} (this machine, not the Pi)",
            mode.name(),
            ns.len(),
            ns[(ns.len() - 1) / 2],
            ns[ns.len() - 1]
        );
    }
}
