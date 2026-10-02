# Shared machinery of the C kernel continuity and Recovery Core QEMU gates
# (scripts/qemu_ck_continuity_test.sh = CK gate M4_CONTINUITY,
# scripts/qemu_ck_recovery_test.sh = CK gate M4_RECOVERY). Sourced, not run.
#
# Mode selection is contract K-7 (native/kernel/CONTINUITY_RECOVERY_CONTRACT.md,
# native/kernel/svc/continuity_boot.h): the host writes one ASCII plan line
#     AIENCONT v1 mode=<N>[ cp=<checkpoint>][ response=<64 hex>]
# into the last 4096-byte unit of the AIENOS partition of a 4096-byte-LBA GPT
# image; the TEST image "make full CK_TEST_CONTINUITY=1" (refused with
# CK_HARDWARE_STAGING / CK_QEMU_UNSAFE_DMA / CK_TEST_STORE_CRASH) runs the
# continuity or Recovery Core wiring instead of the boot-record commit. Every
# boot is a fresh QEMU process (cold restart); only the NVMe image persists.
#
# The caller defines before sourcing: gate_name (e.g. M4_CONTINUITY), script_tag,
# and calls cq_init "$@" (parses --mutant NAME), then uses the helpers below.
# QEMU is not hardware: a PASS qualifies nothing physical.

cq_mutant=""
cq_mode=gate
cq_init() {
    case "${1:-}" in
        "") ;;
        --mutant)
            cq_mode=mutant; cq_mutant="${2:-}"
            case "${cq_mutant}" in
                resume_no_commit|resume_provisions|degraded_is_unprovisioned|compare_16|bare_sha256) ;;
                *) echo "usage: $0 [--mutant resume_no_commit|resume_provisions|degraded_is_unprovisioned|compare_16|bare_sha256]" >&2; exit 2 ;;
            esac ;;
        *) echo "usage: $0 [--mutant NAME]" >&2; exit 2 ;;
    esac
}
verdict() {
    if [[ "${cq_mode}" == mutant ]]; then
        echo "AIENOS_CK_${gate_name}_MUTANT_${cq_mutant^^}: $1"
    else
        echo "AIENOS_CK_${gate_name}: $1"
    fi
}

img_bytes=67108864
unit=4096
plan_unit=0
set_part() { plan_unit=$(( ($2 + 1) * $1 / unit - 1 )); }

cq_build() {
    code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
    vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
    command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; verdict NOT_RUN; exit 2; }
    [[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; verdict NOT_RUN; exit 2; }
    commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    cross=""
    if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
    out="${repo_root}/target/native-kernel"
    mk_full() { make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" full "$@" >/dev/null; }
    if [[ "${cq_mode}" == mutant ]]; then
        mk_full CK_TEST_CONTINUITY=1 CK_TEST_CONTINUITY_MUTANT="${cq_mutant}" || { echo "mutant build failed"; verdict NOT_RUN; exit 2; }
        test_efi="${out}/full-test-continuity-mutant-${cq_mutant}/BOOTAA64.EFI"
        plain_efi="${test_efi}"
    else
        mk_full || { echo "build failed"; verdict NOT_RUN; exit 2; }
        mk_full CK_TEST_CONTINUITY=1 || { echo "TEST continuity build failed"; verdict NOT_RUN; exit 2; }
        test_efi="${out}/full-test-continuity/BOOTAA64.EFI"
        plain_efi="${out}/full/BOOTAA64.EFI"
    fi
    make -s -C native/kernel CROSS="${cross}" OUT="${out}" gpt-image cont-tool >/dev/null || { echo "host tools build failed"; verdict NOT_RUN; exit 2; }
    gpt_tool="${out}/host/ck_gpt_image"
    cont_tool="${out}/host/ck_cont_tool"
}

# make_refusals: parse only (make -n); nothing is built.
make_refusals() {
    local out f=0 tmpo
    mk() { make -n -s -C native/kernel OUT="${1}" full "${@:2}" 2>&1; }
    tmpo="$(mktemp -d)"
    out="$(mk "${tmpo}" CK_TEST_CONTINUITY=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=/dev/null CK_MACHINE_ID=/dev/null)"
    grep -q "CK_TEST_CONTINUITY (TEST-ONLY continuity mode selection) cannot be combined with CK_HARDWARE_STAGING" <<<"${out}" \
        && echo "PASS  make refuses the continuity test mode with CK_HARDWARE_STAGING" || { echo "FAIL  hardware staging accepted the continuity test mode"; f=1; }
    out="$(mk "${tmpo}" CK_TEST_CONTINUITY=1 CK_QEMU_UNSAFE_DMA=1)"
    grep -q "cannot be combined with CK_QEMU_UNSAFE_DMA" <<<"${out}" \
        && echo "PASS  make refuses the continuity test mode with CK_QEMU_UNSAFE_DMA" || { echo "FAIL  unsafe DMA build accepted the continuity test mode"; f=1; }
    out="$(mk "${tmpo}" CK_TEST_CONTINUITY=1 CK_TEST_STORE_CRASH=1)"
    grep -q "cannot be combined with CK_TEST_STORE_CRASH" <<<"${out}" \
        && echo "PASS  make refuses the continuity test mode with the Store crash hook" || { echo "FAIL  crash hook build accepted the continuity test mode"; f=1; }
    out="$(mk "${tmpo}" CK_TEST_CONTINUITY_MUTANT=resume_no_commit)"
    grep -q "CK_TEST_CONTINUITY_MUTANT needs CK_TEST_CONTINUITY=1" <<<"${out}" \
        && echo "PASS  make refuses a continuity mutant without the TEST mode" || { echo "FAIL  mutant built without the TEST mode"; f=1; }
    out="$(mk "${tmpo}" CK_TEST_CONTINUITY=1 CK_TEST_CONTINUITY_MUTANT=bogus)"
    grep -q "CK_TEST_CONTINUITY_MUTANT must be" <<<"${out}" \
        && echo "PASS  make refuses an unknown continuity mutant" || { echo "FAIL  unknown continuity mutant accepted"; f=1; }
    rm -rf "${tmpo}"
    return "${f}"
}

# cq_default_image_checks: the default image carries no TEST wiring; the TEST
# image announces itself. Sets hw_ok.
cq_default_image_checks() {
    hw_ok=1
    make_refusals || hw_ok=0
    if grep -aqE "AIENCONT|RECOVERY_OPERATOR_KEY|TEST-ONLY continuity" "${plain_efi}"; then
        echo "FAIL  default image carries continuity test strings"; hw_ok=0
    else
        echo "PASS  default image carries no continuity test strings"
    fi
    if grep -aqF "TEST-ONLY continuity mode selection image" "${test_efi}"; then
        echo "PASS  TEST continuity image announces itself"
    else
        echo "FAIL  TEST continuity image lacks its announcement"; hw_ok=0
    fi
}

cq_quiet_and_trap() {
    quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
    quiet_tag="${AIENOS_QUIET_TAG:-${script_tag} $$}"
    if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
        echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
        verdict NOT_RUN
        exit 3
    fi
    own_flag=1
    release_flag() {
        if [[ "${own_flag}" == 1 ]]; then
            own_flag=0
            if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
        fi
    }
    top="$(mktemp -d)"
    qemu_pid=""
    cleanup() { [[ -n "${qemu_pid}" ]] && kill -9 "${qemu_pid}" 2>/dev/null; rm -rf "${top}"; release_flag; }
    trap cleanup EXIT
    # shellcheck source=scripts/lib_ck_m1_checks.sh
    source "${repo_root}/scripts/lib_ck_m1_checks.sh"
    fail=0; m1_fail=0; rows=0; rows_ok=0
    work="${top}/boot"
}

pass() { echo "PASS  $1"; rows=$(( rows + 1 )); rows_ok=$(( rows_ok + 1 )); }
bad() {
    echo "FAIL  $1"; fail=1; rows=$(( rows + 1 ))
    if [[ "${cq_mode}" == mutant ]]; then
        release_flag
        verdict "KILLED (the gate's check failed on the mutant: $1)"
        exit 0
    fi
}
sha() { sha256sum "$1" | cut -d' ' -f1; }
digest() { sha "${image}"; }

new_disk() { # -> ${gpt_tmpl}; sets plan_unit from the range the tool WROTE
    local l re='^gpt_image bs=[0-9]+ blocks=[0-9]+ aienos_first_lba=([0-9]+) aienos_last_lba=([0-9]+)$'
    gpt_tmpl="${top}/gpt-4096.img"
    l=$("${gpt_tool}" create "${gpt_tmpl}" 4096 $(( img_bytes / 1048576 )) aienos-middle) || l=""
    if [[ "${l}" =~ ${re} ]]; then set_part 4096 "${BASH_REMATCH[2]}"; return 0; fi
    echo "FAIL  GPT boot disk image not created (${l})"; verdict NOT_RUN; exit 2
}
fresh_image() { image="${top}/disk.img"; cp "${gpt_tmpl}" "${image}"; }

# plan MODE [cp=NAME] [response=HEX]: write the K-7 plan line into the scratch unit.
plan() {
    local line="AIENCONT v1 mode=$1"; shift
    local w; for w in "$@"; do line+=" ${w}"; done
    { printf '%s\n' "${line}"; head -c "${unit}" /dev/zero; } | head -c "${unit}" \
        | dd of="${image}" bs="${unit}" seek="${plan_unit}" conv=notrunc status=none
}
clear_plan() { head -c "${unit}" /dev/zero | dd of="${image}" bs="${unit}" seek="${plan_unit}" conv=notrunc status=none; }

qemu_args() {
    qargs=(-M "virt,virtualization=on,gic-version=3,iommu=smmuv3" -accel tcg,thread=single -cpu max -smp 4 -m 2048
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}"
        -drive if=pflash,format=raw,file="${work}/vars.fd"
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp"
        -device virtio-blk-pci,drive=esp
        -drive if=none,id=nvme0,format=raw,file="${image}"
        -device "nvme,drive=nvme0,serial=aienos-continuity,logical_block_size=4096,physical_block_size=4096"
        -device ramfb -display none -nic none
        -serial file:"${work}/serial.log" -no-reboot)
}
prep() { # efi
    rm -rf "${work}"; mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$1" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
}
# boot: one cold boot that runs to its end (the guest resets); M1 checks.
# Sets before/after (image digests bracketing only the guest's writes).
boot() {
    prep "${test_efi}"; qemu_args
    before=$(digest)
    timeout "${AIENOS_QEMU_TIMEOUT:-240}" qemu-system-aarch64 "${qargs[@]}"
    qemu_status=$?
    after=$(digest)
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/${script_tag}_${boot_n:-0}.log"
    boot_n=$(( ${boot_n:-0} + 1 ))
    failed=0
    ck_m1_checks >"${work}/m1.txt"
    if [[ "${failed}" != 0 || "${qemu_status}" != 0 ]]; then
        echo "FAIL  boot ${boot_n}: M1 checks or QEMU exit ${qemu_status}"; grep '^FAIL' "${work}/m1.txt" | sed 's/^/      /'
        m1_fail=1
        if [[ "${cq_mode}" == mutant ]]; then :; else fail=1; fi
        return 1
    fi
    return 0
}
# boot_kill CP: run until "continuity: HALT at CP", then SIGKILL.
boot_kill() {
    prep "${test_efi}"; qemu_args
    : >"${work}/serial.log"
    qemu-system-aarch64 "${qargs[@]}" &
    qemu_pid=$!
    local deadline=$(( $(date +%s) + ${AIENOS_QEMU_TIMEOUT:-240} ))
    while (( $(date +%s) < deadline )); do
        grep -qE '^(continuity: HALT at |CONTINUITY: )' "${work}/serial.log" 2>/dev/null && break
        kill -0 "${qemu_pid}" 2>/dev/null || break
        sleep 0.1
    done
    sleep 0.2
    kill -9 "${qemu_pid}" 2>/dev/null
    wait "${qemu_pid}" 2>/dev/null
    qemu_pid=""
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/${script_tag}_kill_${1}.log"
}
# line: the last serial line of this boot that starts with the pattern (ERE).
out() { grep -E "$1" "${work}/serial.txt" | tail -1; }
cont() { grep -oE "^CONTINUITY: $1( .*)?$" "${work}/serial.txt" | tail -1; }
field() { sed -nE "s/.* $1=([0-9a-f]+).*/\1/p" <<<"$2"; }
agent_of() { sed -nE 's/.*agent=([0-9a-f]{64}).*/\1/p' <<<"$1"; }
unchanged() { [[ "${before}" == "${after}" ]]; }
serial_cont() { grep -E '^(CONTINUITY|RECOVERY)' "${work}/serial.txt" | head -4 | tr '\n' '|'; }
