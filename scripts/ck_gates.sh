#!/usr/bin/env bash
# ck_gates.sh: one entrypoint for the AIENOS C kernel ("CK", Lane 18) QEMU
# gates, with a content-addressed receipt.
#
# It refuses a dirty tree, runs the C kernel QEMU scripts that exist
# (scripts/qemu_ck_boot_test.sh, scripts/qemu_ck_store_test.sh,
# scripts/qemu_ck_net_test.sh, scripts/qemu_ck_artifact_test.sh,
# scripts/qemu_ck_smp_test.sh, scripts/qemu_ck_store_crash_test.sh,
# scripts/qemu_ck_disk_layout_test.sh, scripts/qemu_ck_continuity_test.sh,
# scripts/qemu_ck_recovery_test.sh), and prints
# one line per gate:
#     AIENOS_CK_<gate>: PASS|FAIL|NOT_RUN [(reason)]
# for M1 M3 SMMU NVME_SHUTDOWN P2_ARTIFACT M0_ROLLBACK M4_NVME M4_STORE M4_STORE_CRASH
# M4_CONTINUITY M4_RECOVERY ARGUS1_REVOKE KEYBOARD NET SMP DISK_LAYOUT. Gates with no C
# implementation print NOT_RUN (MISSING_IMPLEMENTATION: <reason>) and never
# run anything. A missing child script, a child that reports NOT_RUN, a child
# that prints no verdict line, or a PASS line contradicted by the child's exit
# status is never PASS. The parity of each gate with the Rust QEMU gates is
# in native/kernel/GATES.md.
#
# QEMU is an emulator: a PASS here qualifies nothing physical (the receipt
# says "physical": "NOT_RUN"). The child scripts take the machine quiet flag
# (~/workspace/.spark-quiet) themselves and report NOT_RUN while another run
# holds it; this script does not take it.
#
# Usage: bash scripts/ck_gates.sh [--out DIR]
#        bash scripts/ck_gates.sh --self-test
#   --out DIR    where the receipt goes (default: evidence/). The receipt
#                evidence/ck_gates_<sha256 of its content>.json is the only
#                file a run adds to the tree; an existing receipt is never
#                overwritten. Child logs stay in a temp folder outside the tree.
#   --self-test  checks the verdict parsing with canned child outputs (PASS,
#                FAIL, NOT_RUN, missing marker, missing script), the receipt
#                naming and the dirty-tree refusal. Runs no QEMU.
#
# Exit: 0 no gate FAILed (NOT_RUN allowed), 1 a gate FAILed or the run
#       changed the tree, 2 usage error, dirty tree at start, or receipt clash.
set -uo pipefail

# ===========================================================================
# GATE TABLE: gate | source | reason when there is no C implementation
# source: boot  -> verdict line from scripts/qemu_ck_boot_test.sh
#         store -> verdict line from scripts/qemu_ck_store_test.sh
#         net   -> verdict line from scripts/qemu_ck_net_test.sh
#         artifact -> verdict line from scripts/qemu_ck_artifact_test.sh
#         smp   -> verdict line from scripts/qemu_ck_smp_test.sh
#         crash -> verdict line from scripts/qemu_ck_store_crash_test.sh
#         disk  -> verdict line from scripts/qemu_ck_disk_layout_test.sh
#         cont  -> verdict line from scripts/qemu_ck_continuity_test.sh
#         recov -> verdict line from scripts/qemu_ck_recovery_test.sh
#         missing -> NOT_RUN (MISSING_IMPLEMENTATION), never run, never PASS
# ===========================================================================
CK_GATE_TABLE='
M1|boot|-
M3|boot|-
SMMU|store|-
NVME_SHUTDOWN|store|-
P2_ARTIFACT|artifact|-
M0_ROLLBACK|missing|C loader signatures, A/B, BootNext and rollback are parked (native/boot/README.md)
M4_NVME|store|-
M4_STORE|store|-
M4_STORE_CRASH|crash|-
M4_CONTINUITY|cont|-
M4_RECOVERY|recov|-
ARGUS1_REVOKE|store|-
KEYBOARD|missing|no xHCI/USB HID keyboard driver in the C kernel
NET|net|-
SMP|smp|-
DISK_LAYOUT|disk|-
'
CHILDREN=(boot store net artifact smp crash disk cont recov)
# ===========================================================================

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Receipts always boot QEMU -cpu max (FEAT_RNG present): the manual negative
# override AIENOS_QEMU_CPU of the child scripts never reaches a receipt run.
unset AIENOS_QEMU_CPU
QUIET_FLAG="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
AAVMF_CODE_FD="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
AAVMF_VARS_FD="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
PHYSICAL_STATEMENT="QEMU emulator runs only. Nothing here was run on Machine 1 or any GB10; no physical qualification is claimed."
M4_NVME_PASS_NOTE="SMMU-confined NVMe DMA in QEMU (iommu=smmuv3, default build); TEST-ONLY bypass build boot-checked separately"
NET_PASS_NOTE="QEMU user networking (slirp), virtio-net with ACCESS_PLATFORM required behind the smmuv3 vIOMMU; this PASS covers: attach, UDP TX seen by the host helper, UDP reply RX parsed by M6-A, an out-of-window device DMA refused (F_TRANSLATION, page intact) and recovery by reset, as checked by this run only; QEMU, not hardware"

die() { echo "ck_gates: $*" >&2; exit 2; }
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/}"; s="${s//$'\n'/\\n}"
    printf '"%s"' "$(printf '%s' "${s}" | tr -d '\000-\010\013\014\016-\037')"
}
sha_of() { sha256sum | cut -d' ' -f1; }
file_sha() { [[ -r "$1" ]] && sha_of <"$1" || echo "not readable"; }

tree_state() { git -C "$1" status --porcelain --untracked-files=normal; }
refuse_if_dirty() {
    local st; st="$(tree_state "$1")" || die "git status failed in $1"
    if [[ -n "${st}" ]]; then
        echo "ck_gates: refusing to run on a dirty tree. Commit, stash or remove these first:" >&2
        printf '%s\n' "${st}" >&2
        exit 2
    fi
}

# ------------------------------------------------------------ child scripts
# set_default_children: the real child scripts (only main calls this; the
# self-test points the same variables at canned scripts in a temp folder).
set_default_children() {
    declare -gA child_script=(
        [boot]="${repo_root}/scripts/qemu_ck_boot_test.sh"
        [store]="${repo_root}/scripts/qemu_ck_store_test.sh"
        [net]="${repo_root}/scripts/qemu_ck_net_test.sh"
        [artifact]="${repo_root}/scripts/qemu_ck_artifact_test.sh"
        [smp]="${repo_root}/scripts/qemu_ck_smp_test.sh"
        [crash]="${repo_root}/scripts/qemu_ck_store_crash_test.sh"
        [disk]="${repo_root}/scripts/qemu_ck_disk_layout_test.sh"
        [cont]="${repo_root}/scripts/qemu_ck_continuity_test.sh"
        [recov]="${repo_root}/scripts/qemu_ck_recovery_test.sh"
    )
}

# run_children: runs each child script that exists, logs outside the tree.
run_children() {
    local c script t0 log
    declare -gA child_present=() child_rc=() child_secs=() child_log=() child_log_sha=() child_lines=() child_script_sha=()
    for c in "${CHILDREN[@]}"; do
        script="${child_script[${c}]}"
        log="${work_dir}/logs/${c}.log"
        child_log[${c}]="${log}"
        if [[ ! -f "${script}" ]]; then
            child_present[${c}]=0; child_rc[${c}]=-; child_secs[${c}]=0
            child_log_sha[${c}]=-; child_lines[${c}]=0; child_script_sha[${c}]=-
            echo "--- [${c}] ${script#"${repo_root}"/} not present: its gates are NOT_RUN" >&2
            continue
        fi
        child_present[${c}]=1
        child_script_sha[${c}]="$(file_sha "${script}")"
        echo "--- [${c}] running ${script#"${repo_root}"/} ..." >&2
        t0="$(date +%s)"
        bash "${script}" >"${log}" 2>&1 </dev/null
        child_rc[${c}]=$?
        child_secs[${c}]=$(( $(date +%s) - t0 ))
        child_log_sha[${c}]="$(sha_of <"${log}")"
        child_lines[${c}]="$(wc -l <"${log}")"
        echo "--- [${c}] exit ${child_rc[${c}]} after ${child_secs[${c}]} s" >&2
    done
}

# classify_gate GATE SOURCE REASON -> "VERDICT|reason"
# A verdict line must be a whole line: ^AIENOS_CK_<gate>: VERDICT( ...)?$
classify_gate() {
    local gate="$1" src="$2" why="$3" log rc markers n
    if [[ "${src}" == missing ]]; then
        echo "NOT_RUN|MISSING_IMPLEMENTATION: ${why}"; return
    fi
    if [[ -z "${child_script[${src}]+x}" ]]; then
        echo "FAIL|gate table names unknown source ${src}"; return
    fi
    if [[ "${child_present[${src}]:-0}" != 1 ]]; then
        echo "NOT_RUN|child script $(basename "${child_script[${src}]}") not present at this commit"; return
    fi
    log="${child_log[${src}]}"; rc="${child_rc[${src}]}"
    markers="$(sed -nE "s/^AIENOS_CK_${gate}: (PASS|FAIL|NOT_RUN)( .*)?\$/\\1/p" "${log}" | sort -u)"
    n="$(grep -c . <<<"${markers}")"
    if [[ -z "${markers}" ]]; then
        echo "FAIL|child exited ${rc} without an AIENOS_CK_${gate} verdict line"; return
    fi
    if [[ "${n}" -gt 1 ]]; then
        echo "FAIL|contradictory AIENOS_CK_${gate} verdict lines ($(paste -sd, - <<<"${markers}"))"; return
    fi
    case "${markers}" in
        NOT_RUN) echo "NOT_RUN|child reported NOT_RUN (exit ${rc})" ;;
        FAIL)    echo "FAIL|child reported FAIL (exit ${rc})" ;;
        PASS)
            if [[ "${rc}" == 0 ]]; then
                echo "PASS|child reported PASS, exit 0"
            elif [[ "${rc}" == 1 ]] && grep -qE '^AIENOS_CK_[A-Z0-9_]+: FAIL( .*)?$' "${log}"; then
                echo "PASS|child reported PASS; its exit 1 comes from another gate's FAIL line"
            else
                echo "FAIL|child printed PASS but exited ${rc} with no FAIL line to explain it"
            fi ;;
    esac
}

# nvme_dma_mode: what DMA mode the store child's C NVMe path reported.
nvme_dma_mode() {
    local log="${child_log[store]:-}"
    if [[ "${child_present[store]:-0}" != 1 || ! -f "${log}" ]]; then echo "not run"; return; fi
    # The store script prints check descriptions, not serial lines; accept
    # its PASS lines as well as the raw serial lines. Confined is reported
    # only from the confined PASS line and the negative-test PASS line.
    if grep -qE '^PASS  NVMe DMA granted confined$' "${log}" \
        && grep -qE '^PASS  DMA outside the window faulted, page intact, controller still usable \(differs\)$' "${log}"; then
        local m="Confined (QEMU SMMUv3 stage 1, out-of-window DMA faulted)"
        grep -qE '^PASS  NVMe DMA denied without an SMMU$' "${log}" && m+="; no-SMMU boot denied (NoSmmu)"
        grep -qE '^PASS  NVMe DMA granted through the TEST-ONLY bypass$' "${log}" && m+="; TEST-ONLY bypass image checked separately"
        echo "${m}"
    elif grep -qE '^PASS  NVMe DMA granted through the unsafe bypass$|dma_gate: nvme granted \(UnsafeBypass\)' "${log}"; then
        if grep -qE '^PASS  NVMe DMA denied without an SMMU$' "${log}"; then
            echo "UnsafeBypass (QEMU-only build, no SMMU confinement); default image denied (NoSmmu)"
        else
            echo "UnsafeBypass (QEMU-only build, no SMMU confinement)"
        fi
    elif grep -q 'dma_gate: nvme granted (Confined)' "${log}"; then echo "Confined"
    elif grep -q 'dma_gate: nvme denied (NoSmmu)' "${log}"; then echo "denied (NoSmmu)"
    else echo "not reported"; fi
}

# evaluate_table: fills gate_rows ("gate|source|verdict|reason") and prints
# one verdict line per gate.
evaluate_table() {
    local gate src why out v r
    gate_rows=()
    while IFS='|' read -r gate src why; do
        [[ -n "${gate}" ]] || continue
        out="$(classify_gate "${gate}" "${src}" "${why}")"
        v="${out%%|*}"; r="${out#*|}"
        # M4_NVME PASS means the SMMU-confined mode: say so.
        [[ "${v}" == PASS && "${gate}" == M4_NVME ]] && r="${M4_NVME_PASS_NOTE}"
        [[ "${v}" == PASS && "${gate}" == NET ]] && r="${NET_PASS_NOTE}"
        gate_rows+=("${gate}|${src}|${v}|${r}")
        if [[ "${v}" == PASS && ( "${gate}" == M4_NVME || "${gate}" == NET ) ]]; then
            echo "AIENOS_CK_${gate}: PASS (${r})"
        elif [[ "${v}" == PASS ]]; then
            echo "AIENOS_CK_${gate}: PASS"
        else
            echo "AIENOS_CK_${gate}: ${v} (${r})"
        fi
    done <<<"${CK_GATE_TABLE}"
}

count_rows() {
    n_pass=0; n_fail=0; n_notrun=0; n_total=0
    local row v
    for row in "${gate_rows[@]}"; do
        IFS='|' read -r _ _ v _ <<<"${row}"
        n_total=$((n_total + 1))
        case "${v}" in
            PASS) n_pass=$((n_pass + 1)) ;;
            NOT_RUN) n_notrun=$((n_notrun + 1)) ;;
            *) n_fail=$((n_fail + 1)) ;;
        esac
    done
    if [[ ${n_total} -gt 0 && ${n_pass} == "${n_total}" ]]; then overall=ALL_GATES_PASS_QEMU_ONLY; else overall=NOT_ALL_GATES_PASS; fi
}

# --------------------------------------------------------------- receipt
collect_host() {
    h_host="$(uname -n)"; h_arch="$(uname -m)"; h_kernel="$(uname -r)"
    h_cpu="$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | sort -u | paste -sd';' -)"
    [[ -n "${h_cpu}" ]] || h_cpu="not readable"
    if command -v qemu-system-aarch64 >/dev/null; then
        q_path="$(command -v qemu-system-aarch64)"
        q_version="$(qemu-system-aarch64 --version 2>/dev/null | head -1)"
    else
        q_path="not installed"; q_version="not installed"
    fi
    fw_code_sha="$(file_sha "${AAVMF_CODE_FD}")"; fw_vars_sha="$(file_sha "${AAVMF_VARS_FD}")"
}

# write_receipt: builds the JSON in work_dir, names it by its sha256 and
# installs it in out_dir without ever replacing an existing file.
write_receipt() {
    local tmp="${work_dir}/receipt.tmp" i c g s v r first
    {
        echo "{"
        echo "  \"schema\": \"aienos.ck_gates.v1\","
        echo "  \"started_utc\": $(json_str "${started_utc}"),"
        echo "  \"finished_utc\": $(json_str "$(date -u +%FT%TZ)"),"
        echo "  \"commit\": $(json_str "${head_sha}"),"
        echo "  \"commit_subject\": $(json_str "${head_subject}"),"
        echo "  \"tree_clean_before\": ${tree_clean_before},"
        echo "  \"tree_clean_after\": ${tree_clean_after},"
        echo "  \"quiet_flag\": $(json_str "${QUIET_FLAG}"),"
        echo "  \"quiet_flag_present_at_start\": ${quiet_at_start},"
        echo "  \"host\": {\"hostname\": $(json_str "${h_host}"), \"arch\": $(json_str "${h_arch}"), \"kernel\": $(json_str "${h_kernel}"), \"cpu_model\": $(json_str "${h_cpu}")},"
        echo "  \"qemu\": {\"binary\": $(json_str "${q_path}"), \"version\": $(json_str "${q_version}")},"
        echo "  \"firmware\": {\"aavmf_code\": $(json_str "${AAVMF_CODE_FD}"), \"aavmf_code_sha256\": $(json_str "${fw_code_sha}"), \"aavmf_vars\": $(json_str "${AAVMF_VARS_FD}"), \"aavmf_vars_sha256\": $(json_str "${fw_vars_sha}")},"
        echo "  \"nvme_dma_mode\": $(json_str "${dma_mode}"),"
        echo "  \"children\": ["
        first=1
        for c in "${CHILDREN[@]}"; do
            [[ ${first} == 1 ]] || echo ","
            first=0
            printf '    {"name": %s, "script": %s, "present": %s, "script_sha256": %s, "exit": %s, "seconds": %s, "log_sha256": %s, "log_lines": %s}' \
                "$(json_str "${c}")" "$(json_str "${child_script[${c}]#"${repo_root}"/}")" \
                "$([[ ${child_present[${c}]} == 1 ]] && echo true || echo false)" \
                "$(json_str "${child_script_sha[${c}]}")" "$(json_str "${child_rc[${c}]}")" \
                "${child_secs[${c}]:-0}" "$(json_str "${child_log_sha[${c}]}")" "${child_lines[${c}]:-0}"
        done
        echo ""
        echo "  ],"
        echo "  \"gates\": ["
        for i in "${!gate_rows[@]}"; do
            IFS='|' read -r g s v r <<<"${gate_rows[$i]}"
            printf '    {"id": %s, "marker": %s, "source": %s, "verdict": %s, "reason": %s}' \
                "$(json_str "${g}")" "$(json_str "AIENOS_CK_${g}")" "$(json_str "${s}")" "$(json_str "${v}")" "$(json_str "${r}")"
            [[ $i -lt $((${#gate_rows[@]} - 1)) ]] && echo "," || echo ""
        done
        echo "  ],"
        echo "  \"counts\": {\"total\": ${n_total}, \"pass\": ${n_pass}, \"fail\": ${n_fail}, \"not_run\": ${n_notrun}},"
        echo "  \"verdict\": $(json_str "${overall}"),"
        echo "  \"parity\": \"native/kernel/GATES.md\","
        echo "  \"physical\": \"NOT_RUN\","
        echo "  \"physical_statement\": $(json_str "${PHYSICAL_STATEMENT}")"
        echo "}"
    } >"${tmp}"
    receipt_sha="$(sha_of <"${tmp}")"
    receipt_path="${out_dir}/ck_gates_${receipt_sha}.json"
    install_receipt "${tmp}" "${receipt_path}"
}

# install_receipt SRC DEST: noclobber copy; refuses an existing DEST.
install_receipt() {
    if [[ -e "$2" ]]; then
        echo "ck_gates: receipt $2 already exists; never overwritten" >&2
        return 2
    fi
    ( set -C; cat "$1" >"$2" ) 2>/dev/null || { echo "ck_gates: could not create $2 (exists or unwritable)" >&2; return 2; }
}

# ----------------------------------------------------------------- self-test
self_test() {
    local st_fail=0 tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/ck-gates-selftest.XXXXXX")" || exit 2
    work_dir="${tmp}/work"; mkdir -p "${work_dir}/logs" "${tmp}/kids"
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; st_fail=1; }
    # fake NAME RC LINES...: a canned child script.
    fake() {
        local f="${tmp}/kids/$1.sh" rc="$2"; shift 2
        { echo '#!/usr/bin/env bash'; printf 'printf "%%s\\n"'; printf ' %q' "$@"; echo; echo "exit ${rc}"; } >"${f}"
        echo "${f}"
    }
    expect() { # GATE VERDICT
        local row g v
        for row in "${gate_rows[@]}"; do
            IFS='|' read -r g _ v _ <<<"${row}"
            if [[ "${g}" == "$1" ]]; then
                [[ "${v}" == "$2" ]] && ok "${scen}: $1 -> $2" || bad "${scen}: $1 -> ${v}, expected $2"
                return
            fi
        done
        bad "${scen}: $1 has no row"
    }
    expect_missing_all() {
        local g
        for g in P2_ARTIFACT M0_ROLLBACK M4_STORE_CRASH M4_CONTINUITY M4_RECOVERY KEYBOARD DISK_LAYOUT; do expect "${g}" NOT_RUN; done  # P2_ARTIFACT: no artifact child in A..G; M4_STORE_CRASH: no crash child in A..J and R; DISK_LAYOUT: no disk child in A..S
    }
    scenario() { # NAME BOOT_SCRIPT STORE_SCRIPT [NET_SCRIPT] [ARTIFACT_SCRIPT] [SMP_SCRIPT] [CRASH_SCRIPT] [DISK_SCRIPT] (absent: missing)
        scen="$1"
        declare -gA child_script=([boot]="$2" [store]="$3" [net]="${4:-${tmp}/kids/net_not_present.sh}" [artifact]="${5:-${tmp}/kids/no_artifact_child.sh}" [smp]="${6:-${tmp}/kids/no_smp_child.sh}" [crash]="${7:-${tmp}/kids/no_crash_child.sh}" [disk]="${8:-${tmp}/kids/no_disk_child.sh}" [cont]="${tmp}/kids/no_cont_child.sh" [recov]="${tmp}/kids/no_recov_child.sh")
        run_children 2>/dev/null
        evaluate_table >"${tmp}/${scen}.out"
    }

    # A: all present gates PASS; the store child also claims PASS for gates
    # with no C implementation, which must stay NOT_RUN.
    scenario A "$(fake bootA 0 'PASS  x' 'AIENOS_CK_M3: PASS' 'AIENOS_CK_M1: PASS')" \
        "$(fake storeA 0 'AIENOS_CK_M4_NVME: PASS' 'AIENOS_CK_M4_STORE: PASS' 'AIENOS_CK_M4_STORE_CRASH: PASS' 'AIENOS_CK_ARGUS1_REVOKE: PASS (narrow)' \
            'AIENOS_CK_SMMU: PASS' 'AIENOS_CK_NVME_SHUTDOWN: PASS' 'AIENOS_CK_KEYBOARD: PASS' 'PASS  NVMe DMA granted confined' \
            'PASS  DMA outside the window faulted, page intact, controller still usable (differs)' 'PASS  NVMe DMA denied without an SMMU' \
            'PASS  NVMe DMA granted through the TEST-ONLY bypass')" \
        "$(fake netA 0 'PASS  UDP reply received' 'AIENOS_CK_NET: PASS')" "" \
        "$(fake smpA 0 'PASS  3 secondary cores checked in' 'AIENOS_CK_SMP_MUTATION: FAIL' 'AIENOS_CK_SMP: PASS')"
    expect M1 PASS; expect M3 PASS; expect M4_NVME PASS; expect M4_STORE PASS; expect ARGUS1_REVOKE PASS; expect SMMU PASS; expect NVME_SHUTDOWN PASS; expect NET PASS; expect SMP PASS; expect_missing_all
    count_rows
    [[ "${n_pass}/${n_fail}/${n_notrun}/${n_total}" == "9/0/7/16" && ${overall} == NOT_ALL_GATES_PASS ]] \
        && ok "A: counts 9/0/7 of 16, verdict NOT_ALL_GATES_PASS" || bad "A: counts ${n_pass}/${n_fail}/${n_notrun}/${n_total} ${overall}"
    [[ "$(nvme_dma_mode)" == "Confined (QEMU SMMUv3 stage 1, out-of-window DMA faulted); no-SMMU boot denied (NoSmmu); TEST-ONLY bypass image checked separately" ]] && ok "A: confined DMA mode recorded from the store PASS lines" || bad "A: dma mode '$(nvme_dma_mode)'"
    grep -qxF "AIENOS_CK_M4_NVME: PASS (${M4_NVME_PASS_NOTE})" "${tmp}/A.out" \
        && ok "A: M4_NVME PASS line carries the confined-mode note" || bad "A: M4_NVME PASS line lacks the note"
    grep -qxF "AIENOS_CK_NET: PASS (${NET_PASS_NOTE})" "${tmp}/A.out" \
        && ok "A: NET PASS line carries the QEMU slirp / SMMU fence note" || bad "A: NET PASS line lacks the note"
    grep -qx 'AIENOS_CK_KEYBOARD: NOT_RUN (MISSING_IMPLEMENTATION: no xHCI/USB HID keyboard driver in the C kernel)' "${tmp}/A.out" \
        && ok "A: missing gate prints NOT_RUN (MISSING_IMPLEMENTATION: reason)" || bad "A: KEYBOARD line wrong"
    [[ "$(grep -c '^AIENOS_CK_[A-Z0-9_]*: ' "${tmp}/A.out")" == 16 ]] && ok "A: exactly 16 verdict lines" || bad "A: verdict line count"

    # B: boot FAIL; store script missing -> its three gates NOT_RUN, never PASS.
    scenario B "$(fake bootB 1 'FAIL  kernel: alive' 'AIENOS_CK_M3: FAIL' 'AIENOS_CK_M1: FAIL')" "${tmp}/kids/does_not_exist.sh"
    expect M1 FAIL; expect M3 FAIL; expect M4_NVME NOT_RUN; expect M4_STORE NOT_RUN; expect ARGUS1_REVOKE NOT_RUN; expect SMMU NOT_RUN; expect NVME_SHUTDOWN NOT_RUN; expect NET NOT_RUN; expect SMP NOT_RUN; expect_missing_all
    [[ "$(nvme_dma_mode)" == "not run" ]] && ok "B: dma mode 'not run' when the store script is missing" || bad "B: dma mode"

    # C: boot NOT_RUN (quiet flag held, exit 3); store mixed with exit 1.
    scenario C "$(fake bootC 3 'NOT_RUN  quiet flag held' 'AIENOS_CK_M3: NOT_RUN' 'AIENOS_CK_M1: NOT_RUN')" \
        "$(fake storeC 1 'AIENOS_CK_M4_NVME: PASS' 'AIENOS_CK_M4_STORE: FAIL' 'AIENOS_CK_ARGUS1_REVOKE: PASS')"
    expect M1 NOT_RUN; expect M3 NOT_RUN; expect M4_NVME PASS; expect M4_STORE FAIL; expect ARGUS1_REVOKE PASS

    # D: no marker at all (exit 0); PASS lines with an unexplained exit 2.
    scenario D "$(fake bootD 0 'all good, honest')" \
        "$(fake storeD 2 'AIENOS_CK_M4_NVME: PASS' 'AIENOS_CK_M4_STORE: PASS' 'AIENOS_CK_ARGUS1_REVOKE: PASS')"
    expect M1 FAIL; expect M3 FAIL; expect M4_NVME FAIL; expect M4_STORE FAIL; expect ARGUS1_REVOKE FAIL

    # E: contradictory lines; a marker inside a line (echoed serial) does not
    # count; NOT_RUN with exit 3.
    scenario E "$(fake bootE 0 'AIENOS_CK_M1: PASS' 'AIENOS_CK_M1: FAIL')" \
        "$(fake storeE 3 'serial: AIENOS_CK_M4_NVME: PASS' 'AIENOS_CK_M4_STORE: NOT_RUN' 'AIENOS_CK_ARGUS1_REVOKE: NOT_RUN')"
    expect M1 FAIL; expect M4_NVME FAIL; expect M4_STORE NOT_RUN; expect ARGUS1_REVOKE NOT_RUN

    # F: PASS line but exit 3 (e.g. killed after printing) -> FAIL.
    scenario F "$(fake bootF 3 'AIENOS_CK_M1: PASS')" "$(fake storeF 0 'AIENOS_CK_M4_NVME: PASSED' 'AIENOS_CK_M4_STORE: PASS')"
    expect M1 FAIL; expect M4_NVME FAIL; expect M4_STORE PASS; expect ARGUS1_REVOKE FAIL

    # G: M3 FAIL with M1 PASS in one boot (exit 1 explained by the M3 FAIL
    # line); an M3 PASS claimed by the store child is ignored (M3 is a boot gate).
    scenario G "$(fake bootG 1 'FAIL  typed IPC' 'AIENOS_CK_M3: FAIL' 'AIENOS_CK_M1: PASS')" \
        "$(fake storeG 0 'AIENOS_CK_M3: PASS' 'AIENOS_CK_M4_NVME: PASS')"
    expect M1 PASS; expect M3 FAIL; expect M4_NVME PASS

    # H: artifact child PASS -> P2_ARTIFACT PASS; its claim for M0_ROLLBACK
    # (no C implementation) stays NOT_RUN. I: artifact child NOT_RUN (quiet
    # flag held, exit 3) -> NOT_RUN; J: FAIL -> FAIL.
    scenario H "$(fake bootH 0 'AIENOS_CK_M1: PASS')" "$(fake storeH 0 'AIENOS_CK_M4_NVME: PASS')" "" \
        "$(fake artH 0 'PASS  x' 'AIENOS_CK_M0_ROLLBACK: PASS' 'AIENOS_CK_P2_ARTIFACT: PASS')"
    expect P2_ARTIFACT PASS; expect M0_ROLLBACK NOT_RUN; expect M1 PASS
    scenario I "$(fake bootI 0 'AIENOS_CK_M1: PASS')" "$(fake storeI 0 'AIENOS_CK_M4_NVME: PASS')" "" \
        "$(fake artI 3 'NOT_RUN  quiet flag held' 'AIENOS_CK_P2_ARTIFACT: NOT_RUN')"
    expect P2_ARTIFACT NOT_RUN
    scenario J "$(fake bootJ 0 'AIENOS_CK_M1: PASS')" "$(fake storeJ 0 'AIENOS_CK_M4_NVME: PASS')" "" \
        "$(fake artJ 1 'FAIL  P25WX' 'AIENOS_CK_P2_ARTIFACT: FAIL')"
    expect P2_ARTIFACT FAIL
    # O: the crash child (scripts/qemu_ck_store_crash_test.sh) PASS -> M4_STORE_CRASH PASS,
    # and only that child's line counts (the store child's claim in A was ignored).
    # P: crash child FAIL -> FAIL. Q: crash child prints PASS but exits 1 with no
    # FAIL line -> FAIL. S: crash child quiet flag held (exit 3) -> NOT_RUN.
    scenario O "$(fake bootO 0 'AIENOS_CK_M1: PASS')" "$(fake storeO 0 'AIENOS_CK_M4_NVME: PASS')" "" "" "" \
        "$(fake crashO 0 'CK_STORE_CRASH_512B_QEMU: PASS' 'AIENOS_CK_M4_STORE_CRASH: PASS')"
    expect M4_STORE_CRASH PASS; expect M4_CONTINUITY NOT_RUN; expect M4_RECOVERY NOT_RUN
    scenario P "$(fake bootP 0 'AIENOS_CK_M1: PASS')" "$(fake storeP 0 'AIENOS_CK_M4_STORE_CRASH: PASS')" "" "" "" \
        "$(fake crashP 1 'bs=4096 settle=3 cp=after_final_flush -> BAD' 'AIENOS_CK_M4_STORE_CRASH: FAIL')"
    expect M4_STORE_CRASH FAIL
    scenario Q "$(fake bootQ 0 'AIENOS_CK_M1: PASS')" "$(fake storeQ 0 'AIENOS_CK_M4_NVME: PASS')" "" "" "" \
        "$(fake crashQ 1 'AIENOS_CK_M4_STORE_CRASH: PASS')"
    expect M4_STORE_CRASH FAIL
    scenario S "$(fake bootS 0 'AIENOS_CK_M1: PASS')" "$(fake storeS 0 'AIENOS_CK_M4_NVME: PASS')" "" "" "" \
        "$(fake crashS 3 'NOT_RUN  quiet flag held' 'AIENOS_CK_M4_STORE_CRASH: NOT_RUN')"
    expect M4_STORE_CRASH NOT_RUN

    # K: SMP child FAIL (a core never checked in) -> FAIL; L: quiet flag held
    # (exit 3) -> NOT_RUN; M: PASS line with an unexplained exit 2 -> FAIL;
    # N: only the mutation verdict line (AIENOS_CK_SMP_MUTATION) -> no SMP
    # verdict -> FAIL, never PASS.
    scenario K "$(fake bootK 0 'AIENOS_CK_M1: PASS')" "$(fake storeK 0 'AIENOS_CK_M4_NVME: PASS')" "" "" \
        "$(fake smpK 1 'FAIL  core never checked in: smp_cpu: target=0x3 checked_in=no' 'AIENOS_CK_SMP: FAIL')"
    expect SMP FAIL; expect M1 PASS
    scenario L "$(fake bootL 0 'AIENOS_CK_M1: PASS')" "$(fake storeL 0 'AIENOS_CK_M4_NVME: PASS')" "" "" \
        "$(fake smpL 3 'NOT_RUN  quiet flag held' 'AIENOS_CK_SMP: NOT_RUN')"
    expect SMP NOT_RUN
    scenario M "$(fake bootM 0 'AIENOS_CK_M1: PASS')" "$(fake storeM 0 'AIENOS_CK_M4_NVME: PASS')" "" "" \
        "$(fake smpM 2 'AIENOS_CK_SMP: PASS')"
    expect SMP FAIL
    scenario N "$(fake bootN 0 'AIENOS_CK_M1: PASS')" "$(fake storeN 0 'AIENOS_CK_M4_NVME: PASS')" "" "" \
        "$(fake smpN 0 'AIENOS_CK_SMP_MUTATION: PASS (gate checks FAIL on the CPU_ON-skip image; mutation killed)')"
    expect SMP FAIL

    # T: disk child (scripts/qemu_ck_disk_layout_test.sh) PASS -> DISK_LAYOUT PASS;
    # a store gate it claims is ignored. U: disk child FAIL (mutant survived)
    # -> FAIL; V: PASS line, exit 1 -> FAIL.
    scenario T "$(fake bootT 0 'AIENOS_CK_M1: PASS')" "$(fake storeT 3 'AIENOS_CK_M4_STORE: NOT_RUN')" "" "" "" "" \
        "$(fake diskT 0 'PASS  translation bypass makes DISK_LAYOUT fail (mutant killed)' 'AIENOS_CK_M4_STORE: PASS' 'AIENOS_CK_DISK_LAYOUT: PASS')"
    expect DISK_LAYOUT PASS; expect M4_STORE NOT_RUN
    scenario U "$(fake bootU 0 'AIENOS_CK_M1: PASS')" "$(fake storeU 0 'AIENOS_CK_M4_NVME: PASS')" "" "" "" "" \
        "$(fake diskU 1 'FAIL  translation bypass mutant survived' 'AIENOS_CK_DISK_LAYOUT: FAIL')"
    expect DISK_LAYOUT FAIL
    scenario V "$(fake bootV 0 'AIENOS_CK_M1: PASS')" "$(fake storeV 0 'AIENOS_CK_M4_NVME: PASS')" "" "" "" "" \
        "$(fake diskV 1 'AIENOS_CK_DISK_LAYOUT: PASS')"
    expect DISK_LAYOUT FAIL

    # Receipt: named by its content hash, valid JSON, physical NOT_RUN, never overwritten.
    scenario R "$(fake bootR 0 'AIENOS_CK_M1: PASS')" "$(fake storeR 0 'AIENOS_CK_M4_NVME: PASS')"
    count_rows
    out_dir="${tmp}/out"; mkdir -p "${out_dir}"
    started_utc=x; head_sha=x; head_subject='quote " backslash \ tab	end'; tree_clean_before=true; tree_clean_after=true; quiet_at_start=false
    h_host=h; h_arch=a; h_kernel=k; h_cpu=c; q_path=q; q_version=v; fw_code_sha=x; fw_vars_sha=y; dma_mode="$(nvme_dma_mode)"
    write_receipt
    if [[ -f "${receipt_path}" && "$(sha_of <"${receipt_path}")" == "${receipt_sha}" && "${receipt_path}" == *"/ck_gates_${receipt_sha}.json" ]]; then
        ok "receipt name is the sha256 of its content"
    else
        bad "receipt name does not match its content hash"
    fi
    # tree_clean_before comes from the pre-run tree state, never a literal.
    grep -q '"tree_clean_before": true,' "${receipt_path}" && ok "receipt records tree_clean_before true when the tree was clean" || bad "tree_clean_before not true in a clean-tree receipt"
    tree_clean_before=false; out_dir="${tmp}/out_dirty"; mkdir -p "${out_dir}"
    write_receipt
    grep -q '"tree_clean_before": false,' "${receipt_path}" && ok "mutant: dirty tree before the run -> receipt says tree_clean_before false" || bad "mutant survived: tree_clean_before stayed true"
    tree_clean_before=true; out_dir="${tmp}/out"
    # Restore the clean-tree receipt as the one the checks below look at.
    write_receipt
    if command -v jq >/dev/null; then
        jq -e '.physical == "NOT_RUN" and (.gates | length) == 16 and .verdict == "NOT_ALL_GATES_PASS"
               and ([.gates[] | select(.id == "M1")][0].verdict == "PASS")
               and ([.gates[] | select(.id == "ARGUS1_REVOKE")][0].verdict == "FAIL")
               and (.children | length) == 9 and .commit_subject == "quote \" backslash \\ tab\tend"' "${receipt_path}" >/dev/null \
            && ok "receipt is valid JSON (jq) with expected fields" || bad "receipt JSON invalid or fields wrong"
    else
        echo "NOT_RUN  jq not installed; JSON validity not machine-checked"; jq_skipped=1
    fi
    local before_sha; before_sha="$(sha_of <"${receipt_path}")"
    echo junk >"${work_dir}/other.tmp"
    if ! install_receipt "${work_dir}/other.tmp" "${receipt_path}" 2>/dev/null && [[ "$(sha_of <"${receipt_path}")" == "${before_sha}" ]]; then
        ok "an existing receipt is never overwritten"
    else
        bad "an existing receipt was overwritten or the clash was not refused"
    fi

    # The gate table parses: 16 rows, known sources, reasons only on missing rows.
    local g s w rows=0 tbad=0
    while IFS='|' read -r g s w; do
        [[ -n "${g}" ]] || continue
        rows=$((rows + 1))
        case "${s}" in
            boot|store|net|artifact|smp|crash|disk|cont|recov) [[ "${w}" == - ]] || tbad=1 ;;
            missing) [[ -n "${w}" && "${w}" != - ]] || tbad=1 ;;
            *) tbad=1 ;;
        esac
    done <<<"${CK_GATE_TABLE}"
    [[ ${tbad} == 0 && ${rows} == 16 ]] && ok "gate table: 16 rows well-formed" || bad "gate table malformed (${rows} rows)"

    # Dirty-tree refusal, end to end, on a private clone (never this tree).
    # Both runs stop before any child script (no QEMU).
    local clone="${tmp}/clone" rc
    if git clone -q --shared "${repo_root}" "${clone}" 2>/dev/null; then
        cp "${BASH_SOURCE[0]}" "${clone}/scripts/ck_gates.sh"
        git -C "${clone}" add scripts/ck_gates.sh
        git -C "${clone}" -c user.name=t -c user.email=t@t commit -qm selftest --allow-empty
        : >"${clone}/untracked_junk"
        bash "${clone}/scripts/ck_gates.sh" --out "${tmp}/o1" >/dev/null 2>&1; rc=$?
        [[ ${rc} == 2 && ! -e "${tmp}/o1" ]] && ok "dirty tree (untracked file) refused, exit 2, no receipt" || bad "untracked junk gave exit ${rc}"
        rm -f "${clone}/untracked_junk"
        echo x >>"${clone}/README.md" 2>/dev/null || echo x >"${clone}/README.md"
        bash "${clone}/scripts/ck_gates.sh" --out "${tmp}/o2" >/dev/null 2>&1; rc=$?
        [[ ${rc} == 2 && ! -e "${tmp}/o2" ]] && ok "dirty tree (modified tracked file) refused, exit 2, no receipt" || bad "modified tree gave exit ${rc}"
    else
        bad "could not make a private clone for the dirty-tree test"
    fi
    bash "${BASH_SOURCE[0]}" --bogus >/dev/null 2>&1; rc=$?
    [[ ${rc} == 2 ]] && ok "unknown argument -> exit 2" || bad "unknown argument gave exit ${rc}"

    rm -rf --one-file-system "${tmp}"
    if [[ ${st_fail} == 0 ]]; then echo "AIENOS_CK_GATES_SELF_TEST: PASS${jq_skipped:+ (jq NOT_RUN: JSON validity of the receipt not machine-checked)}"; exit 0; fi
    echo "AIENOS_CK_GATES_SELF_TEST: FAIL"; exit 1
}

# ---------------------------------------------------------------------- main
main() {
    local out_arg="" mode=full
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --out) [[ $# -ge 2 ]] || die "--out needs a directory"; out_arg="$2"; shift ;;
            --self-test) mode=self ;;
            -h|--help) sed -n '2,36p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
            *) die "unknown argument: $1" ;;
        esac
        shift
    done
    if [[ ${mode} == self ]]; then self_test; fi

    refuse_if_dirty "${repo_root}"
    local before; before="$(tree_state "${repo_root}")"
    tree_clean_before=true
    [[ -z "${before}" ]] || tree_clean_before=false
    head_sha="$(git -C "${repo_root}" rev-parse HEAD)"
    head_subject="$(git -C "${repo_root}" log -1 --format=%s HEAD)"
    started_utc="$(date -u +%FT%TZ)"
    quiet_at_start="$([[ -e ${QUIET_FLAG} ]] && echo true || echo false)"
    # Resolved now, created only after the tree re-check, so an in-tree DIR
    # gets the receipt and nothing else.
    out_dir="$(realpath -m -- "${out_arg:-${repo_root}/evidence}")"
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ck-gates-work.XXXXXX")" || die "mktemp failed"
    mkdir -p "${work_dir}/logs"

    echo "AIENOS C kernel gates at ${head_sha} (${head_subject}); QEMU only, qualifies nothing physical"
    collect_host
    set_default_children
    run_children
    dma_mode="$(nvme_dma_mode)"
    evaluate_table
    count_rows

    local after; after="$(tree_state "${repo_root}")"
    tree_clean_after=true
    if [[ "${after}" != "${before}" ]]; then
        tree_clean_after=false
        echo "ck_gates: the run changed the tree:" >&2
        printf '%s\n' "${after}" >&2
    fi

    mkdir -p "${out_dir}" || die "cannot create ${out_dir}"
    write_receipt || exit 2
    echo "NVMe DMA mode: ${dma_mode}"
    echo "Child logs: ${work_dir}/logs"
    echo "Receipt: ${receipt_path}"
    echo "AIENOS_CK_GATES: ${overall} (pass=${n_pass} fail=${n_fail} not_run=${n_notrun} of ${n_total}; physical NOT_RUN)"
    [[ ${n_fail} == 0 && ${tree_clean_after} == true ]] && exit 0 || exit 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
