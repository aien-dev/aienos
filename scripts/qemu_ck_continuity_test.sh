#!/usr/bin/env bash
# CK gate M4_CONTINUITY: C kernel continuity (resolve/provision/resume/commit)
# on a 4096-byte-LBA NVMe image under QEMU, one cold QEMU process per boot.
# Oracle: scripts/qemu_continuity_test.sh (Rust). Contract section 6.1.
# Mode selection: contract K-7 (see scripts/lib_ck_cont_qemu.sh). QEMU is not
# hardware. Run only through the heavy forge. Usage: [--mutant NAME]
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo_root="$(pwd)"
gate_name=M4_CONTINUITY
script_tag=qemu_ck_continuity
# shellcheck source=scripts/lib_ck_cont_qemu.sh
source scripts/lib_ck_cont_qemu.sh
cq_init "$@"
cq_build
[[ "${cq_mode}" == mutant ]] || cq_default_image_checks
cq_quiet_and_trap
[[ "${cq_mode}" == mutant || "${hw_ok}" == 1 ]] || fail=1
new_disk

view_ok() { # line word inc seq cortex branches
    [[ "$1" =~ ^CONTINUITY:\ $2\ agent=[0-9a-f]{64}\ incarnation=$3\ sequence=$4\ cortex=$5\ branches=$6\ memory=[0-9a-f]{16}$ ]]
}

# 81 blank media, resume
fresh_image; plan 6
boot; l=$(out '^CONTINUITY: ')
if [[ "${l}" == "CONTINUITY: STOP (store Unformatted)" ]] && unchanged; then pass "81 blank media resume: ${l}, image unchanged"; else bad "81 blank resume: '${l}' unchanged=$(unchanged && echo y || echo n)"; fi

# 82 formatted store, no root (mode 1 = ordinary Store boot formats it)
fresh_image; plan 1; boot; plan 6
boot; l=$(out '^CONTINUITY: ')
if [[ "${l}" == "CONTINUITY: UNPROVISIONED" ]] && unchanged; then pass "82 formatted store, no root: UNPROVISIONED, image unchanged"; else bad "82 unprovisioned: '${l}'"; fi

# 83 provision on a fresh disk
fresh_image; plan 5
boot; l=$(out '^CONTINUITY: ')
if view_ok "${l}" PROVISIONED 1 1 0 1; then agent=$(agent_of "${l}"); pass "83 provision: PROVISIONED agent=${agent:0:16}.. incarnation=1 sequence=1"; else bad "83 provision: '${l}'"; agent=""; fi
prov_image="${top}/prov.img"; cp "${image}" "${prov_image}"

# 83a provision again
plan 5
boot; l=$(out '^CONTINUITY: ')
if [[ "${l}" == "CONTINUITY: STOP (AlreadyProvisioned)" ]] && unchanged; then pass "83a second provision refused, image unchanged"; else bad "83a second provision: '${l}'"; fi

# 83b independent provisioning gives a different agent
fresh_image; plan 5
boot; l2=$(out '^CONTINUITY: ')
a2=$(agent_of "${l2}")
if [[ -n "${agent}" && -n "${a2}" && "${a2}" != "${agent}" ]]; then pass "83b second fresh disk gets a different agent"; else bad "83b agents equal or missing"; fi

# 84 resume (commits incarnation 2) then remember
image="${prov_image}"; plan 7
boot; l=$(out '^CONTINUITY: RESUMED ')
view_ok "${l}" RESUMED 2 2 0 1 && [[ "$(agent_of "${l}")" == "${agent}" ]] && r_ok=1 || r_ok=0
l_rem=$(out '^CONTINUITY: REMEMBERED ')
if [[ "${r_ok}" == 1 ]] && view_ok "${l_rem}" REMEMBERED 2 3 1 2; then pass "84 resume + remember: incarnation=2 sequence=2 then sequence=3 cortex=1 branches=2"; else bad "84: '${l}' / '${l_rem}'"; fi
mem=$(field memory "${l_rem}")
rem_image="${top}/rem.img"; cp "${image}" "${rem_image}"

# 85, 85a cold restarts
plan 6
boot; l=$(out '^CONTINUITY: RESUMED ')
if view_ok "${l}" RESUMED 3 4 1 2 && [[ "$(agent_of "${l}")" == "${agent}" && "$(field memory "${l}")" == "${mem}" ]]; then pass "85 cold restart 1: same agent and memory, incarnation=3 sequence=4"; else bad "85: '${l}' want mem ${mem}"; fi
boot; l=$(out '^CONTINUITY: RESUMED ')
if view_ok "${l}" RESUMED 4 5 1 2 && [[ "$(agent_of "${l}")" == "${agent}" && "$(field memory "${l}")" == "${mem}" ]]; then pass "85a cold restart 2: incarnation=4 sequence=5"; else bad "85a: '${l}'"; fi

# 86 reference: the new memory after one uninterrupted mode 8 commit
work_image="${top}/work.img"; cp "${rem_image}" "${work_image}"; image="${work_image}"; plan 8
boot; l=$(out '^CONTINUITY: COMMITTED ')
new_mem=$(field memory "${l}")
if [[ -n "${new_mem}" && "${new_mem}" != "${mem}" ]]; then pass "86 reference: uninterrupted commit gives new memory ${new_mem}"; else bad "86 reference commit: '${l}'"; fi

# 86a-86i kill at each checkpoint, then cold resume
i=0
for cp in before_first_write after_payload_objects after_catalog after_commit_record after_first_flush \
          after_inactive_superblock after_final_flush before_anchor after_anchor; do
    case "${cp}" in
        after_inactive_superblock) want=either ;;
        after_final_flush|before_anchor|after_anchor) want=new ;;
        *) want=old ;;
    esac
    cp "${rem_image}" "${work_image}"; image="${work_image}"
    plan 8 "cp=${cp}"
    boot_kill "${cp}"
    seen=$(grep -c "^CHECKPOINT: ${cp}\$" "${work}/serial.txt" || true)
    plan 6
    boot; l=$(out '^CONTINUITY: ')
    got=$(field memory "${l}")
    case "${want}" in
        old) okm=$([[ "${got}" == "${mem}" ]] && echo 1 || echo 0) ;;
        new) okm=$([[ "${got}" == "${new_mem}" ]] && echo 1 || echo 0) ;;
        either) okm=$([[ "${got}" == "${mem}" || "${got}" == "${new_mem}" ]] && echo 1 || echo 0) ;;
    esac
    i=$(( i + 1 ))
    if [[ "${seen}" -ge 1 && "${l}" =~ ^CONTINUITY:\ RESUMED\  && "$(agent_of "${l}")" == "${agent}" && "${okm}" == 1 ]]; then
        pass "86.${i} kill at ${cp}: marker seen, same agent, ${want} memory"
    else
        bad "86.${i} kill at ${cp}: seen=${seen} want=${want} got='${l}'"
    fi
done

# 87 malformed peer: read-only resume
cp "${rem_image}" "${work_image}"; image="${work_image}"
"${cont_tool}" inject-peer "${image}" 4096 >/dev/null || bad "87 inject-peer tool failed"
plan 6
boot; l=$(out '^CONTINUITY: ')
if view_ok "${l}" RESUMED_READONLY 2 3 1 2 && [[ "$(agent_of "${l}")" == "${agent}" && "$(field memory "${l}")" == "${mem}" ]] && unchanged; then
    pass "87 malformed peer: RESUMED_READONLY, same agent and memory, image unchanged"
else bad "87 malformed peer: '${l}'"; fi

echo "rows ${rows_ok}/${rows}; M1 failures: ${m1_fail}"
if [[ "${cq_mode}" == mutant ]]; then
    release_flag
    if [[ "${fail}" == 0 ]]; then verdict SURVIVED; else verdict "KILLED (gate failed)"; fi
    exit 0
fi
[[ "${hw_ok:-1}" == 1 && "${fail}" == 0 ]] && verdict PASS || verdict FAIL
[[ "${fail}" == 0 ]]
