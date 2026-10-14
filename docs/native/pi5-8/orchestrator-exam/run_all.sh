#!/bin/bash
# Run the exam on every model in models.tsv (downloaded by download_models.sh), JOBS models at a time.
# usage: run_all.sh   env: JOBS (default 3) THREADS (default 6) MODELS_DIR
here=$(cd "$(dirname "$0")" && pwd)
root=${MODELS_DIR:-$HOME/models/pi5-8-orchestrator}
export THREADS=${THREADS:-6}
grep -v '^#' "$here/models.tsv" | while IFS=$'\t' read -r name role repo url file; do
  t=""; [ "$name" = tinyllama-1.1b ] && t=zephyr   # this GGUF embeds no template; the model card's Zephyr format
  echo "$name|$root/$name/$file|$t"
done | xargs -P "${JOBS:-3}" -I{} bash -c 'IFS="|" read -r n f t <<<"{}"; TEMPLATE=$t '"$here"'/run_exam.sh "$f" "$n" >/dev/null 2>>'"$here"'/results/run_all.err; echo done $n'
