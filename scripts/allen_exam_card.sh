#!/usr/bin/env bash
# allen_exam_card.sh -- build the pi5-allen exam card file (\EFI\AIENOS\ALLEN.EXM, crates/allen-reflex-kernel/src/card.rs)
# from exam case files. Only the case id and the turns go into the card file; expected answers stay on the host
# (scripts/allen_pi_results.sh joins them back by id).
#
#   allen_exam_card.sh <out file> <case file>...
#
# A case file is an exam .psv (id|category|action|text|turns) or, for the bounds cases, a .cases file (id|turns).
# Refuses the held-out file and any path under ~/sealed: this tool is for train/dev rehearsal and bounds tests;
# a sealed set is staged only by the declared final scoring procedure.
set -euo pipefail
out="${1:?out file}"; shift
[[ $# -ge 1 ]] || { echo "usage: $0 <out file> <case file>..." >&2; exit 2; }
for f in "$@"; do
    case "$(readlink -f "$f")" in
        */sealed/*|*heldout*) echo "REFUSE: ${f} is a held-out or sealed case file (rehearsal uses train/dev only)" >&2; exit 2 ;;
    esac
    [[ -r "$f" ]] || { echo "no case file ${f}" >&2; exit 2; }
done
tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
printf 'AIENALX1 QUALIF-ALLEN-EXAM\n' > "${tmp}"
for f in "$@"; do
    if [[ "$f" == *.psv ]]; then
        # id|category|action|text|turns -> id|turns (turns may itself hold '|': keep everything after the 4th bar)
        awk '!/^#/ && NF { i = index($0, "|"); id = substr($0, 1, i - 1); r = $0;
             for (k = 0; k < 4; k++) { j = index(r, "|"); r = substr(r, j + 1) } print id "|" r }' "$f" >> "${tmp}"
    else
        grep -v '^#' "$f" | grep -v '^$' >> "${tmp}"
    fi
done
n=$(( $(wc -l < "${tmp}") - 1 ))
bytes=$(stat -c %s "${tmp}")
[[ ${bytes} -le 131072 ]] || { echo "card file ${bytes} bytes > 131072" >&2; exit 1; }
[[ ${n} -ge 1 && ${n} -le 512 ]] || { echo "card file has ${n} cases (1..512)" >&2; exit 1; }
dups=$(tail -n +2 "${tmp}" | cut -d'|' -f1 | sort | uniq -d | head -3 | tr '\n' ' ')
[[ -z "${dups}" ]] || { echo "duplicate case ids: ${dups}" >&2; exit 1; }
mv "${tmp}" "${out}"
trap - EXIT
echo "card file ${out}: ${n} cases, ${bytes} bytes, sha256 $(sha256sum "${out}" | cut -d' ' -f1)"
