#!/usr/bin/env bash
# check_receipt_labels.sh: lint for evidence receipts that carry hardcoded
# invariant labels (a literal `true` inside an "invariants" block).
#
# A receipt with such a block is only acceptable if an addendum in the same
# folder amends it: the addendum names the receipt's path and carries the
# receipt's current sha256. Without that, the literal true reads as a PASS that
# nothing checked.
#
# Usage: scripts/check_receipt_labels.sh [EVIDENCE_DIR]   (default: ../evidence)
#        scripts/check_receipt_labels.sh --self-test
# Exit: 0 = every such receipt is amended, 1 = at least one is not.
set -uo pipefail

lint_dir() { # DIR -> prints PASS/FAIL lines, returns 1 on any FAIL
    local dir="$1" rc=0 f base h found
    shopt -s nullglob
    for f in "${dir}"/*.json; do
        base="$(basename "${f}")"
        case "${base}" in *addendum*) continue ;; esac
        # a literal true inside an "invariants" object (up to the closing brace)
        if sed -n '/"invariants"[[:space:]]*:[[:space:]]*{/,/}/p' "${f}" | grep -Eq ':[[:space:]]*true[[:space:]]*,?[[:space:]]*$'; then
            h="$(sha256sum "${f}" | cut -d' ' -f1)"
            found=0
            for a in "${dir}"/*addendum*.json; do
                if grep -Eq "\"path\"[[:space:]]*:[[:space:]]*\"evidence/${base}\"" "${a}" && grep -Eq "\"sha256\"[[:space:]]*:[[:space:]]*\"${h}\"" "${a}"; then found=1; break; fi
            done
            if [[ ${found} == 1 ]]; then echo "PASS  ${base}: hardcoded invariants are amended by an addendum bound to sha256 ${h:0:8}"
            else echo "FAIL  ${base}: literal true invariants with no addendum bound to its current sha256 ${h:0:8}"; rc=1; fi
        fi
    done
    return ${rc}
}

if [[ "${1:-}" == --self-test ]]; then
    st=0; t="$(mktemp -d)"; trap 'rm -rf "${t}"' EXIT
    expect() { # name want dir
        local rc=0; lint_dir "$3" >"${t}/out.txt" 2>&1 || rc=$?
        if [[ "${rc}" == "$2" ]]; then echo "PASS  ${1} -> exit ${rc}"; else echo "FAIL  ${1}: wanted ${2}, got ${rc}"; cat "${t}/out.txt"; st=1; fi
    }
    mk() { mkdir -p "${t}/$1"; printf '{\n  "invariants": {\n    "a_check": true,\n    "policy": "x"\n  }\n}\n' >"${t}/$1/r.json"; }
    mk bare;   expect "mutant: literal true, no addendum -> FAIL" 1 "${t}/bare"
    mk good;   h="$(sha256sum "${t}/good/r.json" | cut -d' ' -f1)"
    printf '{"amends_receipt":{"path":"evidence/r.json","sha256":"%s"}}\n' "${h}" >"${t}/good/r_addendum.json"
    expect "amended by an addendum bound to the hash -> PASS" 0 "${t}/good"
    mk stale;  printf '{"amends_receipt":{"path":"evidence/r.json","sha256":"%064d"}}\n' 0 >"${t}/stale/r_addendum.json"
    expect "mutant: addendum bound to a different hash -> FAIL" 1 "${t}/stale"
    mkdir -p "${t}/nr"; printf '{\n  "invariants": {\n    "a_check": "NOT_RUN"\n  }\n}\n' >"${t}/nr/r.json"
    expect "NOT_RUN labels need no addendum -> PASS" 0 "${t}/nr"
    mkdir -p "${t}/other"; printf '{\n  "ok": true\n}\n' >"${t}/other/r.json"
    expect "receipt with no invariants block -> PASS" 0 "${t}/other"
    if [[ ${st} == 0 ]]; then echo "CHECK_RECEIPT_LABELS_SELF_TEST: PASS"; exit 0; fi
    echo "CHECK_RECEIPT_LABELS_SELF_TEST: FAIL"; exit 1
fi

dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/evidence}"
if lint_dir "${dir}"; then echo "RECEIPT_LABELS: PASS"; exit 0; fi
echo "RECEIPT_LABELS: FAIL"; exit 1
