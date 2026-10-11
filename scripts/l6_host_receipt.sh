#!/usr/bin/env bash
# L6-A/L6-B: host-side tokens-per-second receipt (aienos#34 lane 6).
# Builds the l6_host example with the GB10 dot-product features (RUSTFLAGS; override to compare), runs it on
# both dot paths (AIENOS_DOT=f32 and int8) pinned to cores 0 and 19 (core types are read from /proc/cpuinfo,
# not assumed; on this machine they interleave: cpu0=0xd87 A725, cpu19=0xd85 X925),
# runs llama.cpp single-thread on the same model, runs the int8-vs-f32 parity test (token identity is the pass rule),
# writes evidence/l6_host_<sha12>_l6b.json. `--parity-only` runs only the parity test and writes evidence/l6_host_<sha12>_l6b_parity.json.
# Reproduce: scripts/l6_host_receipt.sh   (env: AIENOS_MODEL, AIENOS_N, LLAMA_BENCH, RUSTFLAGS)
set -euo pipefail
cd "$(dirname "$0")/.."
MODEL="${AIENOS_MODEL:-$HOME/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf}"
N="${AIENOS_N:-64}"
LB="${LLAMA_BENCH:-$HOME/llama.cpp-build/bin/llama-bench}"
[ -x "$LB" ] || LB="$HOME/llama.cpp-build/build/bin/llama-bench"
COMMIT="$(git rev-parse HEAD)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export AIENOS_MODEL="$MODEL" AIENOS_N="$N" AIENOS_COMMIT="$COMMIT"
export RUSTFLAGS="${RUSTFLAGS:--C target-feature=+dotprod,+i8mm}"
LOAD1="$(cut -d' ' -f1 /proc/loadavg)"

GOV="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
NPROC="$(nproc)"
PARTS="$(grep -E '^CPU part' /proc/cpuinfo | awk '{print $4}' | sort | uniq -c | awk '{print $2 "x" $1}' | paste -sd, -)"
HOST="$(hostname)"; KERNEL="$(uname -r)"
echo "commit=$COMMIT governor=$GOV nproc=$NPROC cpu_part=$PARTS host=$HOST kernel=$KERNEL rustflags=$RUSTFLAGS load1=$LOAD1"

# --- int8 vs f32 parity (docs/l6b-int8-qualification.md, condition 2) -------------------------------------------
# PASS RULE (gated): the int8 path produces the identical 64 token ids as the f32 path. The per-position max
# absolute logit difference is reported, not gated. Runs the ignored model-backed test on one core (X925, cpu19),
# never killed. Writes a JSON object to $1.
PARITY_CORE=19
run_parity() {
  local out="$1" rc=0 sha12 rec
  sha12="$(sha256sum "$MODEL" | cut -c1-12)"
  rec="evidence/l6_host_${sha12}_l6b.json"
  local pcmd="cargo test --release -p aienos-infer --test forward int8_parity -- --ignored --nocapture --test-threads=1"
  cargo test --release -p aienos-infer --test forward --no-run
  echo "RUN: AIENOS_MODEL=$MODEL taskset -c $PARITY_CORE $pcmd"
  taskset -c "$PARITY_CORE" $pcmd >"$TMP/parity.txt" 2>"$TMP/parity.err" || rc=$?
  # libtest prints "test name ... " without a newline, so the first PARITY line is not at line start.
  grep -oE "PARITY_[A-Z0-9_]+: .*" "$TMP/parity.txt" >"$TMP/parity.lines" || true
  echo "exit=$rc"; cut -c1-200 "$TMP/parity.lines"
  grep -q "^PARITY_TOKENS_IDENTICAL:" "$TMP/parity.lines" || { echo "parity test produced no PARITY lines (see build/test error)"; tail -20 "$TMP/parity.err"; exit 3; }
  local pv; pv() { sed -n "s/^$1: //p" "$TMP/parity.lines"; }
  local recorded="[]"; [ -f "$rec" ] && recorded="$(jq -c '.legs.f32_core19.tokens' "$rec")"
  jq -n --arg ident "$(pv PARITY_TOKENS_IDENTICAL)" --arg div "$(pv PARITY_FIRST_DIVERGENCE)" \
    --argjson cmp "$(pv PARITY_COMPARED_POSITIONS)" --argjson mx "$(pv PARITY_MAX_LOGIT_ABS_DIFF)" \
    --argjson mxp "$(pv PARITY_MAX_LOGIT_ABS_DIFF_POSITION)" --arg per "$(pv PARITY_PER_POSITION_MAX)" \
    --arg ft "$(pv PARITY_F32_TOKENS)" --arg it "$(pv PARITY_INT8_TOKENS)" --argjson recorded "$recorded" \
    --argjson rc "$rc" --arg cmd "AIENOS_MODEL=<model> taskset -c $PARITY_CORE $pcmd" --arg recfile "$rec" --argjson core "$PARITY_CORE" \
    '($ft|split(" ")|map(tonumber)) as $f | ($it|split(" ")|map(tonumber)) as $i |
     {rule:"PASS iff the int8 path produces the identical 64 token ids as the f32 path (gated). Max abs logit difference is reported, not gated, this round.",
      tokens_identical:($ident=="yes"), first_divergence_index:(if $div=="none" then null else ($div|tonumber) end),
      compared_positions:$cmp, max_logit_abs_diff:$mx, max_logit_abs_diff_position:$mxp,
      per_position_max_logit_abs_diff:($per|split(" ")|map(tonumber)),
      f32_matches_recorded:($f==$recorded), recorded_file:$recfile,
      f32_tokens:$f, int8_tokens:$i, test_exit_code:$rc, core_pinned:$core, command:$cmd,
      verdict:(if $ident=="yes" and $rc==0 then "PASS" else "FAIL" end)}' >"$out"
}

if [ "${1:-}" = "--parity-only" ]; then
  # Writes only the parity record; the speed receipt is not touched.
  run_parity "$TMP/parity.json"
  SHA="$(sha256sum "$MODEL" | cut -d' ' -f1)"
  OUT="evidence/l6_host_${SHA:0:12}_l6b_parity.json"
  jq -n --arg commit "$COMMIT" --arg path "$MODEL" --arg sha "$SHA" --arg host "$HOST" --arg kernel "$KERNEL" \
    --arg cpu_part "$PARTS" --arg gov "$GOV" --arg rustflags "$RUSTFLAGS" --argjson load1 "$LOAD1" \
    --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --slurpfile p "$TMP/parity.json" \
    '{commit:$commit, model:{path:$path, sha256:$sha}, host:$host, kernel:$kernel, cpu_part:$cpu_part, governor:$gov,
      rustflags:$rustflags, load1_at_start:$load1, parity_int8_vs_f32:$p[0], generated_at_utc:$now}' | jq -S . >"$OUT"
  echo "wrote $OUT"; exit 0
fi

CMD="cargo run --release -p aienos-infer --example l6_host"
cargo build --release -p aienos-infer --example l6_host
for dot in f32 int8; do
  for core in 0 19; do
    echo "RUN: AIENOS_MODEL=$MODEL AIENOS_N=$N AIENOS_DOT=$dot taskset -c $core $CMD"
    rc=0; AIENOS_DOT="$dot" taskset -c "$core" $CMD >"$TMP/run_${dot}_${core}.txt" || rc=$?
    echo "exit=$rc"; echo "$rc" >"$TMP/rc_${dot}_${core}"
    grep -E '^(prefill_us|decode_tokens|mean_tok_us|tok_per_s|PARITY):' "$TMP/run_${dot}_${core}.txt"
  done
done

LLAMA_BUILD="NOT_RUN"; LLAMA_TPS="null"; LLAMA_TPS19="null"
LLCMD="taskset -c 0 $LB -m $MODEL -ngl 0 -t 1 -p 0 -n 64 -r 3 -o json"
if [ -x "$LB" ]; then
  echo "RUN: $LLCMD"
  taskset -c 0 "$LB" -m "$MODEL" -ngl 0 -t 1 -p 0 -n 64 -r 3 -o json >"$TMP/ll0.json" 2>"$TMP/ll0.err" || true
  LLAMA_TPS="$(jq '[.[]|select(.n_gen==64)|.avg_ts][0] // null' "$TMP/ll0.json")"
  LLAMA_BUILD="$(jq -r '.[0]|"\(.build_commit) \(.build_number)"' "$TMP/ll0.json")"
  echo "RUN: ${LLCMD/taskset -c 0/taskset -c 19}"
  taskset -c 19 "$LB" -m "$MODEL" -ngl 0 -t 1 -p 0 -n 64 -r 3 -o json >"$TMP/ll19.json" 2>/dev/null || true
  LLAMA_TPS19="$(jq '[.[]|select(.n_gen==64)|.avg_ts][0] // null' "$TMP/ll19.json")"
else
  echo "llama-bench not found: NOT_RUN"
fi

cpart() { awk -v c="$1" '/^processor/{p=$3} /^CPU part/{if(p==c)print $4}' /proc/cpuinfo; }  # 0xd85=Cortex-X925, 0xd87=Cortex-A725
val() { sed -n "s/^$3: //p" "$TMP/run_$1_$2.txt"; }
leg() { # <dot> <core> -> JSON object
  jq -n --arg core "$2" --arg dot "$1" --arg parity "$(val "$1" "$2" PARITY)" --arg ids "$(val "$1" "$2" tokens)" \
    --arg us "$(val "$1" "$2" tok_us)" --arg text "$(val "$1" "$2" text)" \
    --argjson prefill "$(val "$1" "$2" prefill_us)" --argjson dt "$(val "$1" "$2" decode_tokens)" \
    --argjson mean "$(val "$1" "$2" mean_tok_us)" --argjson tps "$(val "$1" "$2" tok_per_s)" \
    --argjson rc "$(cat "$TMP/rc_$1_$2")" --arg part "$(cpart "$2")" \
    '{core_pinned:($core|tonumber), dot:$dot, cpu_part:$part, exit_code:$rc, parity:$parity, prefill_us:$prefill,
      decode_tokens:$dt, tokens:($ids|split(" ")|map(tonumber)), tok_us:($us|split(" ")|map(tonumber)),
      mean_tok_us:$mean, tok_per_s:$tps, text:$text}'
}
run_parity "$TMP/parity.json"
SHA="$(val int8 0 model_sha256)"
OUT="evidence/l6_host_${SHA:0:12}_l6b.json"
jq -n --arg commit "$COMMIT" --arg path "$MODEL" --arg sha "$SHA" --argjson size "$(val int8 0 model_size_bytes)" \
  --arg prompt "$(val int8 0 prompt)" --arg golden "$(val int8 0 golden_ids)" \
  --slurpfile par "$TMP/parity.json" --argjson c0 "$(leg int8 0)" --argjson c19 "$(leg int8 19)" --argjson f0 "$(leg f32 0)" --argjson f19 "$(leg f32 19)" \
  --arg rustflags "$RUSTFLAGS" --argjson load1 "$LOAD1" \
  --arg cpu_part "$PARTS" --arg gov "$GOV" --arg host "$HOST" --arg kernel "$KERNEL" --argjson nproc "$NPROC" \
  --arg lb "$LLAMA_BUILD" --arg llcmd "$LLCMD" --argjson lt0 "$LLAMA_TPS" --argjson lt19 "$LLAMA_TPS19" \
  --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg cmd "AIENOS_N=$N AIENOS_DOT=<f32|int8> taskset -c <core> $CMD" \
  '{commit:$commit, model:{path:$path, sha256:$sha, size_bytes:$size}, prompt:$prompt,
    golden_ids:($golden|split(" ")|map(tonumber)), parity:($c0.parity), parity_int8_vs_f32:$par[0], dot:"int8",
    prefill_us:$c0.prefill_us, decode_tokens:$c0.decode_tokens, tok_us:$c0.tok_us,
    mean_tok_us:$c0.mean_tok_us, tok_per_s:$c0.tok_per_s, core_pinned:0,
    cpu_part:$cpu_part, nproc:$nproc, governor:$gov, host:$host, kernel:$kernel,
    legs:{core0:$c0, core19:$c19, f32_core0:$f0, f32_core19:$f19},
    summary_tok_per_s:{int8_core0:$c0.tok_per_s, int8_core19:$c19.tok_per_s, f32_core0:$f0.tok_per_s, f32_core19:$f19.tok_per_s,
      llama_cpp_1thread_core0:$lt0, llama_cpp_1thread_core19:$lt19},
    rustflags:$rustflags, load1_at_start:$load1,
    harness_command:$cmd, threads:1,
    llama_cpp:{build:$lb, threads:1, tok_per_s:$lt0, tok_per_s_core19:$lt19, command:$llcmd},
    reference:{file:"evidence/config_a_reference_bundle.json", tok_per_s:54.2, note:"20 threads, server; not like for like"},
    generated_at_utc:$now}' | jq -S . >"$OUT"
echo "wrote $OUT"
