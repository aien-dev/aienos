#!/usr/bin/env bash
# PI5-8 host golden check: the engine's forward pass vs llama.cpp, greedy tokens, one model, three prompts.
#   host_golden.sh MODEL.gguf TEMPLATE EOS_ID [N=16] [sdot]
#   TEMPLATE: llama3 | zephyr | danube | chatml     sdot: use the dotprod int8 path (default: f32 scalar)
# llama.cpp is the build in $LLAMA (default ~/llama.cpp-build, commit 4a89937, the one PI5-6 used).
# Prompt ids come from llama.cpp's own tokenizer and are fed to the engine, so the engine's tokenizer
# is not judged here (see docs/native/PI5-8-MODEL-CHOICE.md, "Limits").
# Files for the Pi image land in $OUT (default /tmp/pi58-golden/<model name>): <p>.ref holds the ids line
# and the llama.cpp steps, <p>.probe the engine's output, <p>.exp / <p>.got the compared "index id" lists.
set -euo pipefail
model="${1:?model}"; tpl="${2:?template}"; eos="${3:?eos id}"; n="${4:-16}"; dot="${5:-}"
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/../.." && pwd)"
L="${LLAMA:-$HOME/llama.cpp-build}"
name="$(basename "$model" .gguf)"; out="${OUT:-/tmp/pi58-golden/$name${dot:+-$dot}}"; mkdir -p "$out"
ref="${out}/llama_ref"
[[ -x "$ref" ]] || gcc -O1 -o "$ref" "$repo/crates/aienos-infer/tests/ref/llama_ref.c" -I"$L/include" -I"$L/ggml/include" \
    -L"$L/build/bin" -lllama -lggml -lggml-base -Wl,-rpath,"$L/build/bin"
probe="$repo/target/release/examples/model_probe"
[[ -x "$probe" ]] || cargo build --release -p aienos-infer --example model_probe --manifest-path "$repo/Cargo.toml"
wrap() {
    case "$tpl" in
        llama3) printf '<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n%s<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n' "$1" ;;
        zephyr) printf '<s><|user|>\n%s</s>\n<|assistant|>\n' "$1" ;;
        danube) printf '<s><|prompt|>%s</s><|answer|>' "$1" ;;
        chatml) printf '<|im_start|>user\n%s<|im_end|>\n<|im_start|>assistant\n' "$1" ;;
        *) echo "unknown template $tpl" >&2; exit 2 ;;
    esac
}
# Exact token match = PASS. If the lists differ, look at the FIRST divergence: when llama.cpp's own top-1 minus top-2
# logit gap there is below 1.0 (the largest single-logit difference seen between the engine and llama.cpp on the Llama
# control, 0.9), the two implementations may legitimately disagree (floats are summed in a different order, a near-tie
# flips): NOISE. A larger gap is FAIL. The 1.0 threshold is this script's own choice, not a published standard.
fail=0
for p in short long1 long2; do
    wrap "$(cat "$here/prompt-$p.txt")" > "$out/$p.prompt"
    # read back with a sentinel so the template's trailing newlines survive command substitution
    text="$(cat "$out/$p.prompt"; printf x)"; text="${text%x}"
    # CPU only, as llama_ref.c intends (n_gpu_layers=0); hiding the GPU also stops a busy GPU from aborting the run
    CUDA_VISIBLE_DEVICES="" "$ref" "$model" "$text" "$n" "$out/$p.logits" > "$out/$p.ref" 2>"$out/$p.ref.err"
    AIENOS_DOT="$dot" AIENOS_LOGITS="$out/$p.logits" "$probe" "$model" "$out/$p.ref" "$n" "$eos" > "$out/$p.probe"
    awk '$1=="step"{print $2,$3} $1=="eog"{print "eog"}' "$out/$p.ref" > "$out/$p.exp"
    awk '$1=="step"{print $2,$3} $1=="eog"{print "eog"}' "$out/$p.probe" > "$out/$p.got"
    ids_n=$(( $(head -1 "$out/$p.ref" | wc -w) - 1 ))
    if cmp -s "$out/$p.exp" "$out/$p.got"; then
        r=PASS
    else
        div=$(paste -d' ' "$out/$p.exp" "$out/$p.got" | awk 'NF==4 && $2!=$4 {print $1; exit}')
        gap=$(awk -v s="$div" '$1=="step" && $2==s {print $4}' "$out/$p.ref")
        if awk -v g="$gap" 'BEGIN{exit !(g<1.0)}'; then r="NOISE(first divergence step $div, llama.cpp gap $gap)"
        else r="FAIL(first divergence step $div, llama.cpp gap $gap)"; fail=1; fi
    fi
    echo "golden $name prompt=$p ids=$ids_n tokens=$(grep -c '^step' "$out/$p.ref") dot=${dot:-f32} $r"
    echo "  $(grep logits_vs_llama "$out/$p.probe" || true)"
    echo "  llama.cpp: $(awk '$1=="step"{printf "%s ", $3}' "$out/$p.ref")"
    [[ $r == PASS ]] || echo "  engine:    $(awk '$1=="step"{printf "%s ", $3}' "$out/$p.probe")"
done
exit $fail
