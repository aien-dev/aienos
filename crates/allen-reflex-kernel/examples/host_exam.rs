//! Host harness of the pi5-allen image: the same card file, the same compiled-in pool, the same
//! runner code, so its `ALLEN_D` lines must equal the Pi's byte for byte.
//! usage: cargo run --release --example host_exam -- <ALLEN.EXM> [modes: reflex nearest perceptron]
//! stdout: the decision lines (mode by mode, card order). stderr: timings on this machine.
use allen_reflex::Mode;
use allen_reflex_kernel::{card, runner};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args.first().expect("usage: host_exam <ALLEN.EXM> [modes]");
    let buf = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let cases = card::parse(&buf).unwrap_or_else(|e| panic!("{path}: refused ({e})"));
    let modes: Vec<Mode> = if args.len() > 1 {
        args[1..]
            .iter()
            .map(|m| match m.as_str() {
                "reflex" => Mode::Reflex,
                "nearest" => Mode::Nearest,
                "perceptron" => Mode::Perceptron,
                _ => panic!("mode {m}"),
            })
            .collect()
    } else {
        vec![Mode::Reflex, Mode::Nearest, Mode::Perceptron]
    };
    let mut line = String::new();
    for mode in modes {
        let t0 = Instant::now();
        let sess = runner::Session::train(mode).expect("train");
        let init_us = t0.elapsed().as_micros();
        let mut ns = Vec::with_capacity(cases.len());
        for c in &cases {
            let id = std::str::from_utf8(&buf[c.id.0..c.id.1]).unwrap();
            let turns = std::str::from_utf8(&buf[c.turns.0..c.turns.1]).unwrap();
            let t = Instant::now();
            let json = sess.decide_json(turns);
            ns.push(t.elapsed().as_nanos());
            runner::line(&mut line, mode, id, &json);
            println!("{line}");
        }
        ns.sort_unstable();
        eprintln!(
            "host {}: init_us={} examples={} n={} median_ns={} max_ns={} memory_bytes={}",
            mode.name(),
            init_us,
            sess.examples(),
            ns.len(),
            ns[(ns.len() - 1) / 2],
            ns[ns.len() - 1],
            sess.memory_bytes()
        );
    }
}
