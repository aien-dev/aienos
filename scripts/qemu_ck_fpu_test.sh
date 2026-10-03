#!/usr/bin/env bash
# Boot the AIENOS C kernel with the FP/SIMD Rust probe linked in (QEMU AArch64,
# UEFI/AAVMF, EL2 like Machine 1) and check that the kernel, built
# -mgeneral-regs-only, ran ONE floating-point/SIMD-enabled Rust unit
# (crates/aienos-fpu-probe: f32 dot product, exp approximation, NEON 4-lane
# add) and printed its results (aienos#34 lane 0).
# Last line: AIENOS_CK_FPU: PASS|FAIL|NOT_RUN (read by scripts/ck_gates.sh).
# NOT_RUN (never a silent pass) when cargo, the aarch64-unknown-none Rust
# target, qemu or AAVMF is missing, or the machine quiet flag is held.
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# FAIL when the script re-checks the serial lines itself and finds: no
# "fpu:" line, rc != 0, any of the five result words different from the known
# bit patterns (dot=68.0, NEON 11/22/33/44), exp(1) outside 1e-4 of e, a
# kernel-printed PASS the script does not reproduce, a panic/fault report, a
# missing "kernel: alive", or a non-zero QEMU exit.
#
# Usage: bash scripts/qemu_ck_fpu_test.sh               the gate
#        bash scripts/qemu_ck_fpu_test.sh --self-test   canned logs, no QEMU/build
# Environment: AIENOS_QEMU_TIMEOUT (180 s), AIENOS_QUIET_FLAG / AIENOS_QUIET_TAG,
# AIENOS_LOG_DIR, AIENOS_QEMU_VERBOSE.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict_name=AIENOS_CK_FPU

# fpu_check_log FILE: PASS/FAIL line per check; sets fpu_failed=1 on failure.
fpu_check_log() {
    local f="$1" line re bits dot e rc
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; fpu_failed=1; }
    re='^fpu: el1_cpacr=0x([0-9a-f]+) rc=(-?[0-9]+) dot_bits=0x([0-9a-f]+) exp1_bits=0x([0-9a-f]+) neon_bits=0x([0-9a-f]+),0x([0-9a-f]+),0x([0-9a-f]+),0x([0-9a-f]+)$'
    if [[ "$(grep -cE "${re}" "${f}" || true)" != 1 ]]; then
        bad "exactly one well-formed fpu: result line"
    else
        line="$(grep -E "${re}" "${f}")"
        rc="$(sed -E "s/${re}/\\2/" <<<"${line}")"
        dot="$(sed -E "s/${re}/\\3/" <<<"${line}")"
        e="$(sed -E "s/${re}/\\4/" <<<"${line}")"
        bits="$(sed -E "s/${re}/\\5,\\6,\\7,\\8/" <<<"${line}")"
        [[ "${rc}" == 0 ]] && ok "probe returned 0" || bad "probe returned ${rc}"
        [[ "${dot}" == 42880000 ]] && ok "f32 dot product = 68.0 exactly (0x42880000)" || bad "dot product bits 0x${dot}, expected 0x42880000"
        [[ "${bits}" == 41300000,41b00000,42040000,42300000 ]] && ok "NEON vaddq_f32 lanes = 11,22,33,44" || bad "NEON lanes ${bits}"
        # exp(1) within 1e-4 of e: e = 0x402df854; ulp near e is 2^-22, so 1e-4 is about 420 ulps.
        local d=$(( 0x${e} - 0x402df854 )); (( d < 0 )) && d=$(( -d ))
        if (( d <= 420 )); then ok "exp(1) bits 0x${e} within 1e-4 of e"; else bad "exp(1) bits 0x${e} too far from e"; fi
        local cp="$(sed -E "s/${re}/\\1/" <<<"${line}")"
        [[ $(( 0x${cp} >> 20 & 3 )) == 3 ]] && ok "CPACR_EL1.FPEN = 0b11 at EL1" || bad "CPACR_EL1.FPEN is not 0b11 (0x${cp})"
    fi
    grep -qx 'AIENOS_CK_FPU: PASS' "${f}" && ok "kernel reported AIENOS_CK_FPU: PASS" || bad "kernel did not report AIENOS_CK_FPU: PASS"
    grep -q "kernel: alive" "${f}" && ok "kernel alive" || bad "kernel never reached kernel: alive"
    if grep -qE 'report_kind: (panic|fault)' "${f}"; then bad "panic or fault report"; else ok "no panic or fault"; fi
}

if [[ "${1:-}" == --self-test ]]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
    good() { printf 'kernel: alive\nfpu: el1_cpacr=0x300000 rc=0 dot_bits=0x42880000 exp1_bits=0x402df84e neon_bits=0x41300000,0x41b00000,0x42040000,0x42300000\nAIENOS_CK_FPU: PASS\nreport_kind: final\n'; }
    st=0
    chk() { fpu_failed=0; out="$(fpu_check_log "$3")"; grep -q '^FAIL' <<<"${out}" && fpu_failed=1
        if [[ "$2" == pass && ${fpu_failed} == 0 ]] || [[ "$2" == fail && ${fpu_failed} == 1 ]]; then echo "PASS  self-test $1"; else echo "FAIL  self-test $1"; st=1; fi; }
    good >"${tmp}/g"; chk good pass "${tmp}/g"
    sed 's/dot_bits=0x42880000/dot_bits=0x42880001/' "${tmp}/g" >"${tmp}/a"; chk wrong-dot fail "${tmp}/a"
    sed 's/exp1_bits=0x402df84e/exp1_bits=0x40300000/' "${tmp}/g" >"${tmp}/b"; chk wrong-exp fail "${tmp}/b"
    sed 's/0x42040000,0x42300000/0x42040000,0x42300001/' "${tmp}/g" >"${tmp}/c"; chk wrong-neon fail "${tmp}/c"
    sed 's/rc=0/rc=2/' "${tmp}/g" >"${tmp}/d"; chk rc-nonzero fail "${tmp}/d"
    sed 's/el1_cpacr=0x300000/el1_cpacr=0x100000/' "${tmp}/g" >"${tmp}/e"; chk fpen-not-3 fail "${tmp}/e"
    grep -v '^AIENOS_CK_FPU' "${tmp}/g" >"${tmp}/f"; chk no-kernel-verdict fail "${tmp}/f"
    grep -v '^fpu:' "${tmp}/g" >"${tmp}/h"; chk no-result-line fail "${tmp}/h"
    { cat "${tmp}/g"; echo "report_kind: fault"; } >"${tmp}/i"; chk fault fail "${tmp}/i"
    [[ ${st} == 0 ]] && { echo "AIENOS_CK_FPU_SELF_TEST: PASS"; exit 0; }
    echo "AIENOS_CK_FPU_SELF_TEST: FAIL"; exit 1
fi

notrun() { echo "NOT_RUN  $*"; echo "${verdict_name}: NOT_RUN ($*)"; exit 2; }
command -v qemu-system-aarch64 >/dev/null || notrun "qemu-system-aarch64 not installed"
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || notrun "AAVMF firmware not found"
command -v cargo >/dev/null || notrun "cargo not installed"
if ! rustc --print target-list 2>/dev/null | grep -qx aarch64-unknown-none \
   || ! [[ -d "$(rustc --print sysroot)/lib/rustlib/aarch64-unknown-none/lib" ]]; then
    notrun "Rust target aarch64-unknown-none not installed (rustup target add aarch64-unknown-none)"
fi

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel-fpu"
lib="${repo_root}/target/fpu-probe/aarch64-unknown-none/release/libaienos_fpu_probe.a"
CARGO_TARGET_DIR="${repo_root}/target/fpu-probe" cargo build -q --release --target aarch64-unknown-none \
    --manifest-path crates/aienos-fpu-probe/Cargo.toml
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" CK_RUST_LIBS="${lib}" >/dev/null

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_fpu_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${verdict_name}: NOT_RUN"
    exit 3
fi
own_flag=1
release_flag() {
    if [[ "${own_flag}" == 1 ]]; then
        own_flag=0
        if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
    fi
}
work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; release_flag; }
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${out}/BOOTAA64.EFI" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${vars_fd}" "${work}/vars.fd"
log="${work}/serial.log"

started=$(date +%s)
set +e
timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 2 -m 2048 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
    -device virtio-blk-pci,drive=esp \
    -device ramfb -display none -nic none \
    -serial file:"${log}" -no-reboot
qemu_status=$?
set -e
elapsed=$(( $(date +%s) - started ))
release_flag

tr -d '\r' <"${log}" >"${work}/serial.txt"
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_fpu_serial.log"
echo "qemu exit ${qemu_status} after ${elapsed} s (commit ${commit:0:12})"

fpu_failed=0
results="$(fpu_check_log "${work}/serial.txt")" || true
grep -q '^FAIL' <<<"${results}" && fpu_failed=1
printf '%s\n' "${results}"
if [[ "${qemu_status}" == 0 ]]; then echo "PASS  QEMU exit 0 (PSCI reset)"; else echo "FAIL  QEMU exit ${qemu_status}"; fpu_failed=1; fi
grep -E '^fpu: ' "${work}/serial.txt" || true
if [[ "${fpu_failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"; cat "${work}/serial.txt"
fi
if [[ "${fpu_failed}" == 0 ]]; then echo "AIENOS_CK_FPU: PASS"; exit 0; fi
echo "AIENOS_CK_FPU: FAIL"; exit 1
