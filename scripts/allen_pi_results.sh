#!/usr/bin/env bash
# allen_pi_results.sh -- turn the decision lines of a pi5-allen run (kernel.log from the card, or a QEMU serial log) into
# exam result files for docs/native/pi5-8/orchestrator-exam/score.sh, and compare them with the committed host results.
#
#   allen_pi_results.sh <kernel.log> [result name, default allen-reflex-pi]
#
# Writes results/<name>.<split>.<mode>.jsonl for split train, dev and mode reflex, nearest, perceptron, in the record
# format of run_exam.sh (id split cat exp_action exp_text ms finish raw ptok ctok us; us = the kernel's own timing of the
# decision, from its ALLEN_G line). The expected answers come from the host .psv files, joined by case id: the card file
# never carried them. Then prints score.sh rows for the Pi and for the committed host results (allen-reflex) and checks
# that every decision ("raw") is identical, case by case. Train and dev only: held-out files are never read.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exam="${here}/docs/native/pi5-8/orchestrator-exam"
log="${1:?kernel.log}"
name="${2:-allen-reflex-pi}"
[[ -r "${log}" ]] || { echo "no log ${log}" >&2; exit 2; }
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
tr -d '\r' <"${log}" >"${tmp}/log"
bad=0
for split in train dev; do
    psv="${exam}/cases-${split}.psv"
    for mode in reflex nearest perceptron; do
        out="${exam}/results/${name}.${split}.${mode}.jsonl"
        # ALLEN_D <mode> <id> <json>   ALLEN_G <mode> <id> <verdict> <verb> ns=<n>
        awk -v mode="${mode}" -v psv="${psv}" -v sp="${split}" '
            BEGIN { FS = "|"; while ((getline l < psv) > 0) { if (l ~ /^#/ || l == "") continue; n = split(l, f, "|");
                    cat[f[1]] = f[2]; act[f[1]] = f[3]; txt[f[1]] = f[4]; order[++k] = f[1] } FS = " " }
            $1 == "ALLEN_D" && $2 == mode && ($3 in cat) { j = $0; sub(/^ALLEN_D [^ ]+ [^ ]+ /, "", j); raw[$3] = j }
            $1 == "ALLEN_G" && $2 == mode && ($3 in cat) { v = $6; sub(/^ns=/, "", v); ns[$3] = v }
            END { for (i = 1; i <= k; i++) { id = order[i]; if (!(id in raw) || !(id in ns)) { print "MISSING " id > "/dev/stderr"; continue }
                  printf "%s\t%s\t%s\t%s\t%s\t%s\t%d\n", id, sp, cat[id], act[id], txt[id], raw[id], int(ns[id] / 1000 + 0.5) } }
        ' "${tmp}/log" >"${tmp}/rows" 2>"${tmp}/missing"
        if [[ -s "${tmp}/missing" ]]; then
            echo "FAIL ${split}.${mode}: $(wc -l <"${tmp}/missing") cases have no decision line in the log"; bad=1
        fi
        jq -cR 'split("\t") | {id: .[0], split: .[1], cat: .[2], exp_action: .[3], exp_text: .[4], ms: 0, finish: "stop",
                raw: .[5], ptok: 0, ctok: 0, us: (.[6] | tonumber)}' "${tmp}/rows" >"${out}"
        host="${exam}/results/allen-reflex.${split}.${mode}.jsonl"
        if cmp -s <(jq -r '[.id, .raw] | @tsv' "${host}") <(jq -r '[.id, .raw] | @tsv' "${out}"); then
            echo "identical ${split}.${mode}: $(wc -l <"${out}") decisions equal the committed host results"
        else
            echo "DIFFERENT ${split}.${mode}: decisions differ from the committed host results"; bad=1
        fi
    done
done
"${exam}/score.sh" --header 2>/dev/null || true
for split in train dev; do
    for mode in reflex nearest perceptron; do
        "${exam}/score.sh" "${name}" "${split}" "${mode}"
        "${exam}/score.sh" allen-reflex "${split}" "${mode}"
    done
done
[[ "${bad}" == 0 ]] && echo "ALLEN_PI_RESULTS: IDENTICAL" || { echo "ALLEN_PI_RESULTS: DIFFERENT"; exit 1; }
