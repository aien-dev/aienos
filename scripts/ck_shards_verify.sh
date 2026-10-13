#!/usr/bin/env bash
# ck_shards_verify.sh: the CK CI final check. Reads the stdout of every sharded
# `ck_gates.sh --only ...` run and proves the shards together are one complete
# gate run:
#   - exactly EXPECT shard outputs were found;
#   - every gate in the ck_gates.sh table has exactly one real verdict
#     (PASS, FAIL or NOT_RUN) across all shards, and NOT_SELECTED in every
#     other shard (so nothing was dropped or run twice);
#   - no verdict line names a gate that is not in the table;
#   - every gate with a C implementation (source not "missing", except FPU and
#     INFER, which need the Rust bare-metal target and the model file) is PASS.
# Usage: bash scripts/ck_shards_verify.sh EXPECT DIR   (DIR holds *.txt, searched recursively)
#        bash scripts/ck_shards_verify.sh --self-test
# Exit: 0 all good, 1 a check failed, 2 usage.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
table="$(sed -n "/^CK_GATE_TABLE='/,/^'/p" "${here}/ck_gates.sh" | awk -F'|' 'NF==3 {print $1 "|" $2}')"
[[ -n "${table}" ]] || { echo "could not read the gate table"; exit 2; }

verify() { # EXPECT DIR
    local expect="$1" dir="$2" files=() f g src n real notsel bad=0 line
    mapfile -t files < <(find "${dir}" -type f -name '*.txt' | sort)
    if [[ ${#files[@]} != "${expect}" ]]; then
        echo "FAIL  expected ${expect} shard outputs, found ${#files[@]}"; bad=1
    fi
    while IFS='|' read -r g src; do
        [[ -n "${g}" ]] || continue
        real=0; notsel=0
        for f in "${files[@]}"; do
            line="$(grep -E "^AIENOS_CK_${g}: (PASS|FAIL|NOT_RUN|NOT_SELECTED)( |\$)" "${f}" | head -5)"
            [[ -n "${line}" ]] || { echo "FAIL  ${g}: no verdict line at all in ${f}"; bad=1; continue; }
            n=$(grep -c . <<<"${line}")
            [[ ${n} == 1 ]] || { echo "FAIL  ${g}: ${n} verdict lines in ${f}"; bad=1; continue; }
            if [[ "${line}" == *": NOT_SELECTED"* ]]; then notsel=$((notsel + 1))
            else
                real=$((real + 1))
                case "${g}:${src}" in
                    FPU:*|INFER:*|*:missing) [[ "${line}" == *": FAIL"* ]] && { echo "FAIL  ${g}: ${line}"; bad=1; } ;;
                    *) [[ "${line}" == "AIENOS_CK_${g}: PASS"* ]] || { echo "FAIL  ${g}: ${line}"; bad=1; } ;;
                esac
            fi
        done
        if [[ ${real} != 1 ]]; then echo "FAIL  ${g}: reported ${real} times across shards (want exactly 1)"; bad=1
        else echo "ok    ${g}: reported once, NOT_SELECTED in ${notsel} other shard(s)"; fi
    done <<<"${table}"
    # No stray gate names.
    for f in "${files[@]}"; do
        while read -r g; do
            grep -q "^${g}|" <<<"${table}" || { echo "FAIL  ${f}: verdict line for unknown gate ${g}"; bad=1; }
        done < <(sed -nE 's/^AIENOS_CK_([A-Z0-9_]+): (PASS|FAIL|NOT_RUN|NOT_SELECTED)( .*)?$/\1/p' "${f}" | grep -vE '^(GATES|B7B_PROBE|SERVICE_DISK_BUILD)' )
    done
    if [[ ${bad} == 0 ]]; then echo "AIENOS_CK_SHARDS: PASS (every gate reported exactly once across ${#files[@]} shards)"; return 0; fi
    echo "AIENOS_CK_SHARDS: FAIL"; return 1
}

self_test() {
    local t rc fails=0 g src
    t="$(mktemp -d)"; mkdir -p "${t}/good"
    # Two shards: A runs M1, B runs everything else, all PASS (FPU and INFER NOT_RUN).
    : >"${t}/good/a.txt"; : >"${t}/good/b.txt"
    while IFS='|' read -r g src; do
        [[ -n "${g}" ]] || continue
        v=PASS; [[ ${g} == FPU || ${g} == INFER ]] && v=NOT_RUN
        if [[ ${g} == M1 ]]; then echo "AIENOS_CK_${g}: ${v}" >>"${t}/good/a.txt"; echo "AIENOS_CK_${g}: NOT_SELECTED (x)" >>"${t}/good/b.txt"
        else echo "AIENOS_CK_${g}: NOT_SELECTED (x)" >>"${t}/good/a.txt"; echo "AIENOS_CK_${g}: ${v}" >>"${t}/good/b.txt"; fi
    done <<<"${table}"
    chk() { # NAME WANT_RC DIR EXPECT
        verify "$4" "$3" >/dev/null 2>&1; rc=$?
        [[ ${rc} == "$2" ]] && echo "PASS  $1" || { echo "FAIL  $1 (rc ${rc})"; fails=1; }
    }
    chk "complete shards pass" 0 "${t}/good" 2
    chk "wrong shard count fails" 1 "${t}/good" 3
    cp -r "${t}/good" "${t}/dup"; sed -i 's/^AIENOS_CK_SMP: NOT_SELECTED.*/AIENOS_CK_SMP: PASS/' "${t}/dup/a.txt"
    chk "a gate reported twice fails" 1 "${t}/dup" 2
    cp -r "${t}/good" "${t}/drop"; sed -i 's/^AIENOS_CK_SMP: PASS/AIENOS_CK_SMP: NOT_SELECTED (x)/' "${t}/drop/b.txt"
    chk "a gate reported by no shard fails" 1 "${t}/drop" 2
    cp -r "${t}/good" "${t}/fail"; sed -i 's/^AIENOS_CK_SMP: PASS/AIENOS_CK_SMP: FAIL (x)/' "${t}/fail/b.txt"
    chk "a failing gate fails" 1 "${t}/fail" 2
    cp -r "${t}/good" "${t}/nr"; sed -i 's/^AIENOS_CK_NET: PASS.*/AIENOS_CK_NET: NOT_RUN (tool missing)/' "${t}/nr/b.txt"
    chk "a required gate that is NOT_RUN fails" 1 "${t}/nr" 2
    cp -r "${t}/good" "${t}/gone"; sed -i '/^AIENOS_CK_SMP:/d' "${t}/gone/a.txt"
    chk "a missing verdict line fails" 1 "${t}/gone" 2
    rm -rf "${t}"
    [[ ${fails} == 0 ]] && { echo "AIENOS_CK_SHARDS_VERIFY_SELF_TEST: PASS"; exit 0; }
    echo "AIENOS_CK_SHARDS_VERIFY_SELF_TEST: FAIL"; exit 1
}

case "${1:-}" in
    --self-test) self_test ;;
    '') echo "usage: ck_shards_verify.sh EXPECT DIR | --self-test" >&2; exit 2 ;;
    *) [[ $# == 2 && "$1" =~ ^[0-9]+$ && -d "$2" ]] || { echo "usage: ck_shards_verify.sh EXPECT DIR | --self-test" >&2; exit 2; }
       verify "$1" "$2" ;;
esac
