#!/bin/bash
# Run the orchestration exam on one GGUF with llama.cpp (greedy, the model's own chat template).
# usage: run_exam.sh <gguf> <name> [splits: "train dev heldout"] [modes: "free constrained"]
# env:   LLAMA_BIN (llama-server dir, default ~/llama.cpp-build/build/bin)   THREADS (default 8)
#        TEMPLATE (a llama.cpp built-in template name; only for GGUFs that embed none, e.g. zephyr for TinyLlama)
#        CPU=1 (default) hides the GPU so a busy shared GPU is never touched   PORT (default derived from name)
# writes results/<name>.<split>.<mode>.jsonl : one record per case with the raw model text.
set -u
gguf=$1; name=$2; splits=${3:-"train dev heldout"}; modes=${4:-"free constrained"}
here=$(cd "$(dirname "$0")" && pwd)
bin=${LLAMA_BIN:-$HOME/llama.cpp-build/build/bin}
threads=${THREADS:-8}
port=${PORT:-$((20000 + $(printf '%s' "$name" | cksum | cut -d' ' -f1) % 20000))}
out="$here/results"; mkdir -p "$out"
[ "${CPU:-1}" = 1 ] && export CUDA_VISIBLE_DEVICES=""
export LD_LIBRARY_PATH="$bin:${LD_LIBRARY_PATH:-}"
tmpl=(); [ -n "${TEMPLATE:-}" ] && tmpl=(--chat-template "$TEMPLATE")
"$bin/llama-server" -m "$gguf" --port "$port" --host 127.0.0.1 -t "$threads" -c 4096 -ngl 0 --jinja "${tmpl[@]}" \
  --no-webui --log-disable >"$out/$name.server.log" 2>&1 &
srv=$!
trap 'kill $srv 2>/dev/null; wait $srv 2>/dev/null' EXIT
until curl -sf "http://127.0.0.1:$port/health" >/dev/null; do
  kill -0 $srv 2>/dev/null || { echo "server died, see $out/$name.server.log" >&2; exit 1; }
  sleep 1
done
sys=$(cat "$here/system_prompt.txt")
gram=$(cat "$here/grammar.gbnf")
for split in $splits; do
  for mode in $modes; do
    f="$out/$name.$split.$mode.jsonl"; : >"$f"
    grep -v '^#' "$here/cases-$split.psv" | while IFS='|' read -r id cat act text turns; do
      msgs=$(jq -cn --arg sys "$sys" --arg t "$turns" '[{role:"system",content:$sys}] + ($t|split(" ~~ ")|to_entries|map({role:(if .key%2==0 then "user" else "assistant" end),content:.value}))')
      body=$(jq -cn --argjson m "$msgs" --arg g "$gram" --arg mode "$mode" \
        '{messages:$m,temperature:0,top_k:1,seed:1,max_tokens:96,cache_prompt:true,chat_template_kwargs:{enable_thinking:false}} + (if $mode=="constrained" then {grammar:$g} else {} end)')
      t0=$(date +%s%N)
      resp=$(curl -s "http://127.0.0.1:$port/v1/chat/completions" -H 'Content-Type: application/json' -d "$body")
      ms=$(( ($(date +%s%N) - t0) / 1000000 ))
      jq -cn --arg id "$id" --arg split "$split" --arg cat "$cat" --arg ea "$act" --arg et "$text" --argjson ms "$ms" --arg resp "$resp" \
        '($resp|fromjson? // {}) as $r | {id:$id,split:$split,cat:$cat,exp_action:$ea,exp_text:$et,ms:$ms,finish:($r.choices[0].finish_reason // "error"),raw:($r.choices[0].message.content // ""),ptok:($r.usage.prompt_tokens // 0),ctok:($r.usage.completion_tokens // 0)}' >>"$f"
    done
    echo "$name $split $mode: $(wc -l <"$f") cases" >&2
  done
done
