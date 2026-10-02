#!/usr/bin/env bash
# lib_verify_summary.sh: the skipped-step bookkeeping and the closing verdict
# of scripts/verify_all.sh, kept here so the verdict can be tested without
# cargo or QEMU. Source it; or run `bash scripts/lib_verify_summary.sh
# --self-test` for negative controls.
#
# Rule: the last line of verify_all.sh says what actually ran. A skipped step
# makes the verdict NOT_RUN for that step (never "PASS"), and AIENOS_STRICT=1
# turns any skipped step into a failure. QEMU steps are emulator evidence only;
# hardware is never checked by verify_all.sh.

SKIPPED_STEPS=()

skipped() {
    echo "SKIPPED: $*"
    SKIPPED_STEPS+=("$*")
    if [[ "${AIENOS_STRICT:-0}" == "1" ]]; then
        echo "STRICT FAIL: a step was skipped under AIENOS_STRICT=1 ($*)" >&2
        exit 1
    fi
}

# run_or_skip DESCRIPTION COMMAND...: a script that exits 3 reports NOT_RUN (it
# skipped a check class); that is a skipped step here, never a pass. Any other
# nonzero exit stops the harness, as before.
run_or_skip() {
    local desc="$1" rc=0; shift
    "$@" || rc=$?
    if [[ "${rc}" == 3 ]]; then skipped "${desc}: the script reported NOT_RUN (exit 3)"
    elif [[ "${rc}" != 0 ]]; then exit "${rc}"; fi
    return 0
}

final_verdict() {
    echo ""
    echo "============================================================"
    if [[ ${#SKIPPED_STEPS[@]} -eq 0 ]]; then
        echo "VERIFY_ALL: PASS (every step ran; QEMU steps are emulator evidence only, hardware NOT_RUN)"
    else
        printf 'NOT_RUN  skipped step: %s\n' "${SKIPPED_STEPS[@]}"
        echo "VERIFY_ALL: NOT_RUN (${#SKIPPED_STEPS[@]} step(s) skipped; every step that ran passed; not a full pass)"
    fi
    echo "============================================================"
}

if [[ "${BASH_SOURCE[0]}" == "$0" && "${1:-}" == --self-test ]]; then
    lib="${BASH_SOURCE[0]}"; st=0
    ok() { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; st=1; }
    # Each case runs in its own shell so exit paths are observable.
    case_out() { AIENOS_STRICT="${STRICT:-0}" bash -c 'source "$1"; shift; eval "$@"' _ "${lib}" "$1" 2>&1; }

    out="$(case_out 'final_verdict')"
    grep -qF 'VERIFY_ALL: PASS' <<<"${out}" && ok "no skipped step -> VERIFY_ALL: PASS" || bad "clean run did not print PASS"

    out="$(case_out 'skipped "demo step" >/dev/null; final_verdict')"
    if grep -qF 'VERIFY_ALL: NOT_RUN (1 step(s) skipped' <<<"${out}" && ! grep -qF 'VERIFY_ALL: PASS' <<<"${out}"; then
        ok "one skipped step -> VERIFY_ALL: NOT_RUN, never PASS (the old banner said PASSED regardless)"
    else bad "skipped step verdict wrong: ${out}"; fi
    grep -qF 'skipped step: demo step' <<<"${out}" && ok "the skipped step is named in the verdict" || bad "skipped step not named"

    rc=0; STRICT=1 case_out 'skipped "demo step"' >/dev/null || rc=$?
    [[ "${rc}" == 1 ]] && ok "AIENOS_STRICT=1: a skipped step exits 1" || bad "strict skip exited ${rc}"

    rc=0; out="$(case_out 'run_or_skip demo bash -c "exit 3"; final_verdict')" || rc=$?
    if [[ "${rc}" == 0 ]] && grep -qF 'VERIFY_ALL: NOT_RUN' <<<"${out}"; then ok "a child exiting 3 (NOT_RUN) is a skipped step"; else bad "exit-3 child: rc=${rc}"; fi

    rc=0; case_out 'run_or_skip demo bash -c "exit 1"; echo reached' >/dev/null || rc=$?
    [[ "${rc}" == 1 ]] && ok "a child exiting 1 stops the harness" || bad "exit-1 child: rc=${rc}"

    rc=0; out="$(case_out 'run_or_skip demo true; final_verdict')" || rc=$?
    [[ "${rc}" == 0 ]] && grep -qF 'VERIFY_ALL: PASS' <<<"${out}" && ok "a child exiting 0 is not a skip" || bad "exit-0 child: rc=${rc}"

    if [[ ${st} == 0 ]]; then echo "VERIFY_ALL_SUMMARY_SELF_TEST: PASS"; exit 0; fi
    echo "VERIFY_ALL_SUMMARY_SELF_TEST: FAIL"; exit 1
fi
