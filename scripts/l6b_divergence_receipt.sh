#!/usr/bin/env bash
# L6-B int8 parity diagnosis receipt (aienos#34). Diagnosis only: it changes no pass rule and no default.
# 1. Rebuilds tests/ref/llama_ref_hist.c against the local llama.cpp, replays the recorded common history
#    (prompt + the 12 tokens f32 and int8 agree on) and checks the logits against the committed fixture
#    crates/aienos-infer/tests/fixtures/ref_fr_idx12_logits.f32.
# 2. Runs the ignored model-backed tests int8_divergence_diagnosis_index_12 and int8_vs_q8k_emulation_drift
#    and the model-backed int8_matvec_equals_rounded_f32_on_real_activation, pinned to one X925 core, never killed.
# 3. Writes evidence/l6b_int8_divergence_<model sha12>.json.
# Reproduce: scripts/l6b_divergence_receipt.sh   (env: AIENOS_MODEL, LLAMA_DIR, RUSTFLAGS, DIAG_CORE)
set -euo pipefail
cd "$(dirname "$0")/.."
MODEL="${AIENOS_MODEL:-$HOME/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf}"
LLAMA_DIR="${LLAMA_DIR:-$HOME/llama.cpp-build}"
CORE="${DIAG_CORE:-19}"
COMMIT="$(git rev-parse HEAD)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export AIENOS_MODEL="$MODEL"
export RUSTFLAGS="${RUSTFLAGS:--C target-feature=+dotprod,+i8mm}"
LOAD1="$(cut -d' ' -f1 /proc/loadavg)"
HOST="$(hostname)"; KERNEL="$(uname -r)"
CPU_PART="$(awk -v c="$CORE" '/^processor/{p=$3} /^CPU part/{if (p==c) print $4}' /proc/cpuinfo)"
SHA="$(sha256sum "$MODEL" | cut -d' ' -f1)"
FIX=crates/aienos-infer/tests/fixtures/ref_fr_idx12_logits.f32
HIST="128000 128006 882 128007 271 3923 374 279 6864 315 9822 30 128009 128006 78191 128007 271 791 6864 315 9822 374 12366 13 128009 128006 78191 128007 271"
echo "commit=$COMMIT host=$HOST core=$CORE cpu_part=$CPU_PART rustflags=$RUSTFLAGS load1=$LOAD1"

# --- 1. llama.cpp reference for the same history -------------------------------------------------------------------
LL_COMMIT="NOT_RUN"; LL_REPRO="null"; LL_LINES=""
if [ -f "$LLAMA_DIR/include/llama.h" ]; then
  LL_COMMIT="$(git -C "$LLAMA_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  cc -O2 -Wall crates/aienos-infer/tests/ref/llama_ref_hist.c -o "$TMP/llama_ref_hist" \
    -I"$LLAMA_DIR/include" -I"$LLAMA_DIR/ggml/include" -L"$LLAMA_DIR/build/bin" \
    -lllama -lggml -lggml-base -Wl,-rpath,"$LLAMA_DIR/build/bin"
  # shellcheck disable=SC2086
  LL_LINES="$(taskset -c "$CORE" "$TMP/llama_ref_hist" "$MODEL" "$TMP/ll.f32" 17 4897,53692 $HIST 2>/dev/null)"
  echo "$LL_LINES"
  if cmp -s "$TMP/ll.f32" "$FIX"; then LL_REPRO=true; else LL_REPRO=false; fi
fi
LL_ARGMAX="$(awk '/^argmax/{print $2}' <<<"$LL_LINES")"; LL_GAP="$(awk '/^argmax/{print $4}' <<<"$LL_LINES")"

# --- 2. model-backed tests ----------------------------------------------------------------------------------------
cargo test --release -p aienos-infer --test forward --no-run
run() { # name extra-args -> $TMP/<name>.txt, exit code on stdout
  local rc=0
  taskset -c "$CORE" cargo test --release -p aienos-infer --test forward "$1" -- $2 --nocapture --test-threads=1 \
    >"$TMP/$1.txt" 2>"$TMP/$1.err" || rc=$?
  echo "$rc"
}
RC_DIAG="$(run int8_divergence_diagnosis_index_12 --ignored)"
RC_DRIFT="$(run int8_vs_q8k_emulation_drift --ignored)"
RC_REAL="$(run int8_matvec_equals_rounded_f32_on_real_activation "")"
echo "exit codes: diagnosis=$RC_DIAG drift=$RC_DRIFT real_activation=$RC_REAL"

# libtest prints "test name ... " without a newline, so take each tag from where it starts.
grep -o 'DIAG_POS.*' "$TMP/int8_divergence_diagnosis_index_12.txt" | tr -d '|' | awk '{
  printf "{\"index\":%d,\"f32_argmax\":%s,\"f32_gap\":%s,\"int8_argmax\":%s,\"int8_gap\":%s,\"max_logit_abs_diff\":%s,\"emulation_vs_int8\":%s}\n",
    $2, $5, $7, $10, $12, $14, $16 }' | jq -s . >"$TMP/pos.json"
grep -o 'DIAG_MODE.*' "$TMP/int8_divergence_diagnosis_index_12.txt" | awk '{
  sub(":", "", $2);
  printf "{\"mode\":\"%s\",\"argmax\":%s,\"top1_top2_gap\":%s,\"logit_4897\":%s,\"logit_53692\":%s,\"f32tok_minus_int8tok\":%s,\"maxdiff_vs_f32\":%s,\"maxdiff_vs_llama\":%s}\n",
    $2, $4, $6, $8, $10, $12, $14, $16 }' | jq -s . >"$TMP/modes.json"
REPEAT="$(grep -o 'DIAG_F32_REPEAT_MAXDIFF: [^ ]*' "$TMP/int8_divergence_diagnosis_index_12.txt" | awk '{print $2}')"
grep -o 'DRIFT.*' "$TMP/int8_vs_q8k_emulation_drift.txt" | awk '{
  printf "{\"tokens\":%d,\"class\":\"%s\",\"int8_vs_emulation\":%s,\"int8_vs_f32\":%s,\"emulation_vs_f32\":%s}\n", $3, $5, $7, $9, $11 }' \
  | jq -s . >"$TMP/drift.json"
grep -o 'REAL_ACT.*' "$TMP/int8_matvec_equals_rounded_f32_on_real_activation.txt" | awk '{
  sub(":", "", $2); printf "{\"weight\":\"layer0.%s\",\"f32_vs_f64_ref\":%s,\"int8_vs_f64_ref\":%s,\"max_abs_ref\":%s}\n", $2, $4, $6, $8 }' \
  | jq -s . >"$TMP/real.json"

OUT="evidence/l6b_int8_divergence_${SHA:0:12}.json"
jq -n --arg commit "$COMMIT" --arg path "$MODEL" --arg sha "$SHA" --arg host "$HOST" --arg kernel "$KERNEL" \
  --arg cpu_part "$CPU_PART" --argjson core "$CORE" --arg rustflags "$RUSTFLAGS" --argjson load1 "$LOAD1" \
  --arg ll_commit "$LL_COMMIT" --argjson ll_repro "$LL_REPRO" --arg ll_argmax "$LL_ARGMAX" --arg ll_gap "$LL_GAP" \
  --argjson rc_diag "$RC_DIAG" --argjson rc_drift "$RC_DRIFT" --argjson rc_real "$RC_REAL" --arg repeat "$REPEAT" \
  --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile pos "$TMP/pos.json" --slurpfile modes "$TMP/modes.json" --slurpfile drift "$TMP/drift.json" \
  --slurpfile real "$TMP/real.json" \
  '{commit:$commit, model:{path:$path, sha256:$sha}, host:$host, kernel:$kernel, core_pinned:$core, cpu_part:$cpu_part,
    rustflags:$rustflags, load1_at_start:$load1, generated_at_utc:$now,
    scope:"diagnosis only; parity rule, default path and INT8_PROMOTION_DEFAULT unchanged",
    history:"prompt (17 ids) + recorded common tokens 0..11; decision at index 12",
    llama_cpp:{commit:$ll_commit, argmax:($ll_argmax|tonumber? // null), top1_top2_gap:($ll_gap|tonumber? // null),
      fixture_reproduced:$ll_repro},
    exit_codes:{diagnosis:$rc_diag, drift:$rc_drift, real_activation:$rc_real},
    f32_repeat_max_logit_diff:($repeat|tonumber? // null),
    positions:$pos[0], modes_at_index_12:$modes[0], drift_int8_vs_emulation:$drift[0],
    real_activation_matvec:$real[0]}' | jq -S . >"$OUT"
echo "wrote $OUT"
