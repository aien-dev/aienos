#!/usr/bin/env bash
# CK gate M4_ALLEN: the ALLEN subject (ARCH-0035 / OS-0018, both PROPOSED) in
# the AIENOS lifecycle, on a 4096-byte-LBA emulated NVMe image under QEMU, one
# cold QEMU process per boot (scripts/lib_ck_cont_qemu.sh: every boot is a new
# qemu-system-aarch64 process; the ESP folder and the UEFI vars are rebuilt for
# every boot; only the NVMe image file carries state from one boot to the next).
#
# The kernel is the TEST continuity image (make full CK_TEST_CONTINUITY=1),
# the same image and the same provisioning boundary as M4_CONTINUITY: plan
# mode 5 with lineage= provisions the identity AND the genesis subject in one
# Store transaction (svc/continuity_subject_provision.c); intent= adds one
# standing intent as subject sequence 2; plan mode 6 resumes and restores the
# subject read-only before anything is written (svc/continuity_boot.c).
#
#   G7  native genesis       the kernel creates the subject during provisioning
#   G8  exactly once         provisioning a provisioned image is refused; restores never mint
#   G9  cold restart         same subject, intent and lineage after QEMU process death, twice
#   G10 native path          an independent host reader finds the subject ON the image; the
#                            restore plan carries no subject; another image restores another subject
#   G11 corruption           forked chain, flipped envelope, missing subject: refused, nothing minted
#   G12 foreign identity     another installation's subject chain: refused, never adopted
#   FI  power loss           SIGKILL at every Store checkpoint of the genesis transaction, then a
#                            cold boot: unprovisioned or identity WITH subject, never one alone
#
# QEMU is not hardware: a PASS qualifies nothing physical (no DGX Spark reboot,
# no physical NVMe, no machine migration). Usage: [--mutant NAME] (the
# subject_restore_mints and subject_accept_foreign mutants must be KILLED).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo_root="$(pwd)"
gate_name=M4_ALLEN
script_tag=qemu_ck_allen
# shellcheck source=scripts/lib_ck_cont_qemu.sh
source scripts/lib_ck_cont_qemu.sh
cq_init "$@"
cq_build
[[ "${cq_mode}" == mutant ]] || cq_default_image_checks
cq_quiet_and_trap
[[ "${cq_mode}" == mutant || "${hw_ok}" == 1 ]] || fail=1
new_disk

# Qualification inputs. The lineage is the digest of record 1 of the omega
# Cortex journal the ALLEN v0 host gates seed (omega tests/allen/run.sh j1);
# the intent is the v0 qualification goal (regime 7, 1000 ns per call).
LINEAGE=e3f241da5ea18408653a70e3691653db216b5dcc51169b799827cf4f2699731b
REGIME=7
TARGET=1000
prov_plan() { plan 5 "lineage=${LINEAGE}" "intent=${REGIME},${TARGET}" "$@"; }

if [[ "${cq_mode}" != mutant ]]; then
    if grep -aqF "ALLEN: GENESIS" "${plain_efi}"; then bad "default image carries the ALLEN TEST markers"; else pass "default image carries no ALLEN TEST markers"; fi
fi

dump() { # IMG -> the host reader's lines, on a COPY (the reader never touches the image under test)
    local c="${top}/dump.img"; cp "$1" "${c}"
    "${cont_tool}" subject-dump "${c}" 4096 "${2:-}" 2>&1; rm -f "${c}"
}
kv() { sed -nE "s/.* $1=([^ ]+).*/\1/p" <<<"$2" | head -1; }
allen() { grep -E "^ALLEN: $1( |$)" "${work}/serial.txt" | tail -1; }
n_allen() { grep -cE "^ALLEN: $1( |$)" "${work}/serial.txt" || true; }
plan_text() { dd if="${image}" bs="${unit}" skip="${plan_unit}" count=1 status=none | tr -d '\0' | head -1; }

# ---------------------------------------------------------------- G7 genesis
fresh_image
d0=$(dump "${image}")
prov_plan
boot
l_prov=$(out '^CONTINUITY: ')
l_gen=$(allen GENESIS); l_int=$(allen INTENDED); l_i=$(allen INTENT)
agent=$(agent_of "${l_prov}")
S1=$(kv subject "${l_gen}"); S2=$(kv subject "${l_int}"); I=$(kv id "${l_i}")
d1=$(dump "${image}" "${top}/allen_head.bin")
if [[ "${d0}" =~ subject-dump:\ store=Refused$ || "${d0}" =~ identity=Unprovisioned ]] \
   && [[ "${l_prov}" =~ ^CONTINUITY:\ PROVISIONED\ agent=[0-9a-f]{64}\ incarnation=1\ sequence=1\ cortex=0\ branches=1 ]] \
   && [[ "${l_gen}" == "ALLEN: GENESIS subject=${S1} sequence=1 agent=${agent} lineage=${LINEAGE} intents=0 active=0" ]] \
   && [[ ${#S1} == 64 ]]; then
    pass "G7 native genesis: blank image (${d0##*subject-dump: }) -> kernel provisioning created subject ${S1:0:16}.. sequence 1 for agent ${agent:0:16}.., lineage bound"
else bad "G7 genesis: before='${d0}' prov='${l_prov}' gen='${l_gen}'"; fi
if [[ "${l_int}" == "ALLEN: INTENDED subject=${S2} sequence=2 agent=${agent} lineage=${LINEAGE} intents=1 active=1" ]] \
   && [[ "${l_i}" == "ALLEN: INTENT id=${I} kind=1 regime=${REGIME} target_ns=${TARGET} since=2" && ${#I} == 64 && "${S2}" != "${S1}" ]]; then
    pass "G7 standing intent: sequence 2 ${S2:0:16}.. holds intent ${I:0:16}.. (regime ${REGIME}, ${TARGET} ns)"
else bad "G7 intent: '${l_int}' / '${l_i}'"; fi
if [[ "$(kv genesis_objects "${d1}")" == 1 && "$(kv subject_objects "${d1}")" == 2 && "$(kv subject "${d1}")" == "${S2}" \
      && "$(kv agent "${d1}")" == "${agent}" && "$(kv lineage "${d1}")" == "${LINEAGE}" ]]; then
    pass "G7 host reader: the image holds one genesis and one successor, head ${S2:0:16}.. (no host tool created them)"
else bad "G7 host reader: '${d1}'"; fi
prov_image="${top}/prov.img"; cp "${image}" "${prov_image}"
prov_sha=$(sha "${prov_image}")

# ------------------------------------------------------- G8 exactly once
image="${top}/g8.img"; cp "${prov_image}" "${image}"
prov_plan
boot
if [[ "$(out '^CONTINUITY: ')" == "CONTINUITY: STOP (AlreadyProvisioned)" && "$(n_allen GENESIS)" == 0 ]] && unchanged; then
    pass "G8 second provisioning refused: no genesis, image unchanged"
else bad "G8 second provisioning: '$(out '^CONTINUITY: ')' genesis=$(n_allen GENESIS)"; fi

# --------------------------------------------- G9 cold restart (two restores)
image="${top}/g9.img"; cp "${prov_image}" "${image}"
plan 6
rplan=$(plan_text)
g9_ok=1
for k in 1 2; do
    boot; q=${qemu_status}
    l_r=$(allen RESTORED); l_ri=$(allen INTENT); l_c=$(out '^CONTINUITY: RESUMED ')
    inc=$(( k + 1 ))
    if [[ "${q}" == 0 && "${l_r}" == "ALLEN: RESTORED subject=${S2} sequence=2 agent=${agent} lineage=${LINEAGE} intents=1 active=1" \
          && "${l_ri}" == "ALLEN: INTENT id=${I} kind=1 regime=${REGIME} target_ns=${TARGET} since=2" \
          && "$(n_allen GENESIS)" == 0 && "${l_c}" =~ incarnation=${inc}\  && "$(agent_of "${l_c}")" == "${agent}" ]]; then
        pass "G9 cold restart ${k}: new QEMU process (previous exited ${q}), same subject ${S2:0:16}.., same intent, same lineage, incarnation ${inc}"
    else g9_ok=0; bad "G9 cold restart ${k}: q=${q} '${l_r}' / '${l_ri}' / '${l_c}'"; fi
done
d9=$(dump "${image}" "${top}/allen_head_after.bin")
if [[ "$(kv genesis_objects "${d9}")" == 1 && "$(kv subject_objects "${d9}")" == 2 && "$(kv subject "${d9}")" == "${S2}" ]] \
   && cmp -s "${top}/allen_head.bin" "${top}/allen_head_after.bin"; then
    pass "G9 after two restores: still one genesis, two subject objects, head object byte-identical"
else bad "G9 after restores: '${d9}'"; fi

# --------------------------------------------------------- G10 native path
# The restore plan names only the mode; the ESP and UEFI vars are rebuilt for
# every boot (prep); an image provisioned separately restores ITS subject.
if [[ "${rplan}" == "AIENCONT v1 mode=6" ]]; then pass "G10 restore plan carries no subject, lineage or intent ('${rplan}')"; else bad "G10 restore plan: '${rplan}'"; fi
fresh_image
prov_plan; boot
b_agent=$(agent_of "$(out '^CONTINUITY: PROVISIONED ')"); B2=$(kv subject "$(allen INTENDED)")
b_image="${top}/b.img"; cp "${image}" "${b_image}"
plan 6; boot
l_b=$(allen RESTORED)
if [[ -n "${B2}" && "${B2}" != "${S2}" && "${b_agent}" != "${agent}" && "$(kv subject "${l_b}")" == "${B2}" && "$(kv agent "${l_b}")" == "${b_agent}" ]]; then
    pass "G10 a second image restores its own subject ${B2:0:16}.. (agent ${b_agent:0:16}..), not ${S2:0:16}..: the subject comes from the disk"
else bad "G10 second image: B2=${B2} restored='${l_b}'"; fi
if [[ -s "${top}/allen_head.bin" && "$(sha256sum "${top}/allen_head.bin" | cut -c1-64)" != "" ]]; then
    pass "G10 host reader decoded the head object from the sealed Store on the image (${S2:0:16}..)"
else bad "G10 host reader produced no head object"; fi

# ------------------------------------------------------------ G11 corruption
# a) a forked chain (a second genesis subject for the same agent)
image="${top}/g11a.img"; cp "${prov_image}" "${image}"
"${cont_tool}" subject-plant "${image}" 4096 fork >/dev/null || bad "G11a plant fork tool failed"
plan 6
for k in 1 2; do
    boot
    if [[ "$(allen CORRUPT)" == "ALLEN: CORRUPT (subject chain fork)" && -z "$(allen RESTORED)" && "$(n_allen GENESIS)" == 0 \
          && -z "$(out '^CONTINUITY: RESUMED')" ]] && unchanged; then
        pass "G11a forked chain, boot ${k}: CORRUPT, nothing restored, nothing minted, image unchanged"
    else bad "G11a fork boot ${k}: '$(allen CORRUPT)' restored='$(allen RESTORED)' cont='$(out '^CONTINUITY: ')'"; fi
done
d11=$(dump "${image}")
[[ "$(kv subject_objects "${d11}")" == 3 ]] && pass "G11a image still holds exactly the planted objects (3), no replacement" || bad "G11a objects: '${d11}'"
# b) a flipped byte in a subject envelope
image="${top}/g11b.img"; cp "${prov_image}" "${image}"
"${cont_tool}" corrupt-subject "${image}" 4096 >/dev/null || bad "G11b corrupt tool failed"
plan 6; boot
l11b="$(out '^(ALLEN|CONTINUITY): ')"
if [[ -z "$(allen RESTORED)" && "$(n_allen GENESIS)" == 0 && -z "$(out '^CONTINUITY: RESUMED')" ]] && unchanged \
   && [[ "${l11b}" =~ ^(ALLEN:\ STOP|ALLEN:\ CORRUPT|CONTINUITY:\ STOP\ \(store\ Refused) ]]; then
    pass "G11b corrupted subject envelope: refused ('${l11b}'), nothing restored or minted, image unchanged"
else bad "G11b envelope: '${l11b}' restored='$(allen RESTORED)'"; fi
# c) a provisioned identity without a subject (identity-only provisioning)
fresh_image; plan 5; boot
c_agent=$(agent_of "$(out '^CONTINUITY: PROVISIONED ')")
plan 6
for k in 1 2; do
    boot
    if [[ "$(allen ABSENT)" == "ALLEN: ABSENT (provisioned without a subject; restore never mints one)" && "$(n_allen GENESIS)" == 0 \
          && -z "$(allen RESTORED)" && "$(agent_of "$(out '^CONTINUITY: RESUMED ')")" == "${c_agent}" ]]; then
        pass "G11c missing subject, boot ${k}: ABSENT reported, none minted"
    else bad "G11c missing subject boot ${k}: '$(allen 'ABSENT|RESTORED|CORRUPT|STOP')'"; fi
done
d11c=$(dump "${image}")
[[ "$(kv subject_objects "${d11c}")" == 0 ]] && pass "G11c host reader: still no subject object on the image" || bad "G11c objects: '${d11c}'"
c_image="${top}/c.img"; cp "${image}" "${c_image}"

# ------------------------------------------------------ G12 foreign identity
# a) another installation's whole subject chain beside this one's
image="${top}/g12a.img"; cp "${prov_image}" "${image}"
"${cont_tool}" subject-plant "${image}" 4096 foreign "${b_image}" >/dev/null || bad "G12a plant tool failed"
plan 6; boot
if [[ "$(allen CORRUPT)" == "ALLEN: CORRUPT (subject object belongs to another agent)" && -z "$(allen RESTORED)" \
      && "$(n_allen GENESIS)" == 0 ]] && unchanged; then
    pass "G12a foreign chain beside our own: CORRUPT (another agent), nothing restored or minted, image unchanged"
else bad "G12a: '$(allen 'CORRUPT|STOP|RESTORED')'"; fi
# b) another installation's chain on an identity that has none of its own
image="${top}/g12b.img"; cp "${c_image}" "${image}"
"${cont_tool}" subject-plant "${image}" 4096 foreign "${b_image}" >/dev/null || bad "G12b plant tool failed"
plan 6; boot
if [[ "$(allen CORRUPT)" == "ALLEN: CORRUPT (subject object belongs to another agent)" && -z "$(allen RESTORED)" \
      && "$(n_allen GENESIS)" == 0 ]] && unchanged; then
    pass "G12b foreign chain on a subjectless identity: refused, never adopted, nothing minted, image unchanged"
else bad "G12b: '$(allen 'CORRUPT|STOP|RESTORED')'"; fi

# ------------------------------------- FI power loss during the genesis write
i=0
for cp in before_first_write after_payload_objects after_catalog after_commit_record after_first_flush \
          after_inactive_superblock after_final_flush before_anchor after_anchor; do
    case "${cp}" in
        after_inactive_superblock) want=either ;;
        after_final_flush|before_anchor|after_anchor) want=new ;;
        *) want=old ;;
    esac
    fresh_image
    prov_plan "cp=${cp}"
    boot_kill "${cp}"
    seen=$(grep -c "^continuity: HALT at ${cp} " "${work}/serial.txt" || true)
    plan 6; boot
    l=$(out '^CONTINUITY: '); la=$(out '^ALLEN: ')
    if [[ "${l}" == "CONTINUITY: UNPROVISIONED" && -z "${la}" ]]; then got=old
    elif [[ "${l}" =~ ^CONTINUITY:\ RESUMED\  && "${la}" =~ ^ALLEN:\ RESTORED\ subject=[0-9a-f]{64}\ sequence=1\ agent=$(agent_of "${l}")\ lineage=${LINEAGE}\ intents=0\ active=0$ ]]; then got=new
    else got=bad; fi
    i=$(( i + 1 ))
    if [[ "${seen}" -ge 1 && "${got}" != bad && ( "${want}" == either || "${want}" == "${got}" ) ]]; then
        pass "FI.${i} SIGKILL at ${cp}: cold boot finds the ${got} state ($([[ ${got} == old ]] && echo unprovisioned, no subject || echo identity with its genesis subject))"
    else bad "FI.${i} SIGKILL at ${cp}: seen=${seen} want=${want} got=${got} '${l}' / '${la}'"; fi
    if [[ "${got}" == old && "${cp}" == before_first_write ]]; then
        prov_plan; boot
        [[ -n "$(allen GENESIS)" ]] && pass "FI.${i}b interrupted provisioning that committed nothing can be provisioned again" \
            || bad "FI.${i}b re-provision: '$(out '^(ALLEN|CONTINUITY): ')'"
    fi
done

[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${top}/allen_head.bin" "${AIENOS_LOG_DIR}/allen_head.bin"
# Facts for the evidence receipt (one line, parsed by the receipt writer).
echo "ALLEN_FACTS agent=${agent} genesis=${S1} subject=${S2} intent=${I} lineage=${LINEAGE} regime=${REGIME} target_ns=${TARGET} prov_image_sha256=${prov_sha} head_object_sha256=$(sha "${top}/allen_head.bin")"
echo "rows ${rows_ok}/${rows}; M1 failures: ${m1_fail}"
if [[ "${cq_mode}" == mutant ]]; then
    release_flag
    if [[ "${fail}" == 0 ]]; then verdict SURVIVED; else verdict "KILLED (gate failed)"; fi
    exit 0
fi
[[ "${hw_ok:-1}" == 1 && "${fail}" == 0 ]] && verdict PASS || verdict FAIL
[[ "${fail}" == 0 ]]
