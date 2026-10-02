#!/usr/bin/env bash
# CK gate M4_RECOVERY: C kernel Recovery Core (inspect / repair-degraded-peer /
# provision-identity, operator-authorised) under QEMU, one cold boot each.
# Oracle: scripts/qemu_recovery_test.sh (Rust). Contract section 6.2.
# Mode selection: contract K-7. The operator key is TEST-ONLY (0x0f x32).
# QEMU is not hardware. Run only through the heavy forge. Usage: [--mutant NAME]
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo_root="$(pwd)"
gate_name=M4_RECOVERY
script_tag=qemu_ck_recovery
# shellcheck source=scripts/lib_ck_cont_qemu.sh
source scripts/lib_ck_cont_qemu.sh
cq_init "$@"
cq_build
[[ "${cq_mode}" == mutant ]] || cq_default_image_checks
cq_quiet_and_trap
[[ "${cq_mode}" == mutant || "${hw_ok}" == 1 ]] || fail=1
new_disk

test_key=$(printf '0f%.0s' $(seq 32))
wrong_key=$(printf '0e%.0s' $(seq 32))
zero=$(printf '00%.0s' $(seq 32))
respond() { "${cont_tool}" respond "$1" "$2"; }
challenge_for() { sed -nE "s/^RECOVERY_CHALLENGE: action=$1 challenge=([0-9a-f]{64})\$/\1/p" "${work}/serial.txt" | tail -1; }
refused_unauth() { [[ -n "$(out '^RECOVERY_REFUSED \(Unauthorised\)$')" ]] && unchanged; }
b() { plan "$@"; boot; } # plan + boot

# Setup: provisioned store with memory, then a malformed inactive peer.
fresh_image; b 5
l=$(out '^CONTINUITY: PROVISIONED '); agent=$(agent_of "${l}")
[[ -n "${agent}" ]] || bad "setup: provision failed"
b 7
lm=$(out '^CONTINUITY: REMEMBERED '); memory=$(field memory "${lm}")
[[ -n "${memory}" ]] || bad "setup: remember failed"
good_image="${top}/good.img"; cp "${image}" "${good_image}"
"${cont_tool}" inject-peer "${image}" 4096 >/dev/null || bad "setup: inject-peer failed"

echo "=== 1. Degraded store ==="
b 9
if [[ -n "$(out '^RECOVERY_OPERATOR_KEY: TEST-ONLY$')" && \
      -n "$(out '^RECOVERY_CORE: ENTERED reason=Degraded\(Malformed\)$')" && \
      "$(agent_of "$(out '^RECOVERY_RECORD:')")" == "${agent}" ]] && unchanged; then
    pass "88 inspection enters the Recovery Core (Degraded(Malformed)), same agent, writes nothing"
else bad "88 inspection: $(grep -E '^RECOVERY_' "${work}/serial.txt" | tr '\n' '|')"; fi
c_repair=$(challenge_for repair-degraded-peer)
[[ ${#c_repair} == 64 ]] || bad "88 no repair challenge offered"
good=$(respond "${test_key}" "${c_repair}")
flip="${good:0:63}$([[ "${good:63:1}" == 0 ]] && echo 1 || echo 0)"
i=0
for c in zero wrong_key wrong_challenge flipped_last_byte; do
    case "${c}" in
        zero) r="${zero}" ;;
        wrong_key) r=$(respond "${wrong_key}" "${c_repair}") ;;
        wrong_challenge) r=$(respond "${test_key}" "$(printf 'ff%.0s' $(seq 32))") ;;
        flipped_last_byte) r="${flip}" ;;
    esac
    plan 10 "response=${r}"; boot
    i=$(( i + 1 ))
    if refused_unauth; then pass "88.${i} repair with ${c} response refused (Unauthorised), image unchanged"
    else bad "88.${i} repair with ${c}: $(out '^RECOVERY_(ACTION|REFUSED)')"; fi
done
plan 10 "response=${good}"; boot
if [[ -n "$(out '^RECOVERY_ACTION: repair-degraded-peer DONE$')" ]] && ! unchanged; then pass "89 authorised repair done, image changed"
else bad "89 authorised repair: $(out '^RECOVERY_(ACTION|REFUSED)')"; fi
b 6; r=$(out '^CONTINUITY: RESUMED ')
if [[ "$(agent_of "${r}")" == "${agent}" && "$(field memory "${r}")" == "${memory}" ]]; then pass "89a after repair a cold boot resumes writable, same agent and memory"
else bad "89a resume after repair: '${r:-$(out '^CONTINUITY:')}'"; fi
plan 10 "response=${good}"; boot
if [[ -n "$(out '^RECOVERY_REFUSED \(NotApplicable\)$')" ]] && unchanged; then pass "89b replaying the repair authorisation on the healthy store: NotApplicable, image unchanged"
else bad "89b replay: $(out '^RECOVERY_(ACTION|REFUSED)')"; fi

echo "=== 2. Unprovisioned store ==="
fresh_image; b 1; b 9
if [[ -n "$(out '^RECOVERY_CORE: ENTERED reason=Unprovisioned$')" ]] && unchanged; then pass "90 unprovisioned store enters the Recovery Core"
else bad "90 inspection: $(grep -E '^RECOVERY_' "${work}/serial.txt" | tr '\n' '|')"; fi
c_prov=$(challenge_for provision-identity)
[[ ${#c_prov} == 64 ]] || bad "90 no provision challenge offered"
plan 11 "response=$(respond "${wrong_key}" "${c_prov}")"; boot
if refused_unauth; then pass "90a provisioning with the wrong key refused, image unchanged"
else bad "90a wrong key: $(out '^RECOVERY_(ACTION|REFUSED)')"; fi
plan 11 "response=$(respond "${test_key}" "${c_prov}")"; boot
da=$(out '^RECOVERY_ACTION: provision-identity DONE agent=[0-9a-f]{64}$'); pa=$(agent_of "${da}")
b 6; r=$(out '^CONTINUITY: RESUMED ')
if [[ -n "${pa}" && "$(agent_of "${r}")" == "${pa}" ]]; then pass "90b authorised provisioning done; a cold resume returns that agent"
else bad "90b provisioning: '${da}' resume '${r}'"; fi

echo "=== 3. Corrupted agent root (identity lost) ==="
cp "${good_image}" "${image}"
"${cont_tool}" corrupt-root "${image}" 4096 >/dev/null || bad "91 corrupt-root failed"
b 9
if [[ -n "$(out '^RECOVERY_CORE: ENTERED ')" && -z "$(out '^RECOVERY_CHALLENGE')" ]] && unchanged; then pass "91 corrupted root: Recovery Core entered, no challenge, image unchanged"
else bad "91 corrupt root: $(grep -E '^RECOVERY_' "${work}/serial.txt" | tr '\n' '|')"; fi
for m in 10 11; do
    plan "${m}" "response=${zero}"; boot
    if [[ -n "$(out '^RECOVERY_REFUSED ')" && -z "$(out '^RECOVERY_ACTION')" ]] && unchanged; then pass "91.m${m} mode ${m} with a forged response refused, nothing done, image unchanged"
    else bad "91.m${m} forged response: $(out '^RECOVERY_(ACTION|REFUSED)')"; fi
done
b 6
if [[ -z "$(out '^CONTINUITY: (RESUMED|PROVISIONED)')" && -n "$(out '^CONTINUITY: ')" ]] && unchanged; then pass "91c normal boot after identity loss: no RESUMED/PROVISIONED ($(out '^CONTINUITY: ')), image unchanged"
else bad "91c identity loss resume: '$(out '^CONTINUITY: ')'"; fi

echo "rows ${rows_ok}/${rows}; M1 failures: ${m1_fail}"
if [[ "${cq_mode}" == mutant ]]; then
    release_flag
    if [[ "${fail}" == 0 ]]; then verdict SURVIVED; else verdict "KILLED (gate failed)"; fi
    exit 0
fi
[[ "${hw_ok:-1}" == 1 && "${fail}" == 0 ]] && verdict PASS || verdict FAIL
[[ "${fail}" == 0 ]]
