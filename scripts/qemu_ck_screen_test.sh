#!/usr/bin/env bash
# Boot the AIENOS C kernel core in QEMU AArch64 (UEFI/AAVMF, EL2 like
# Machine 1) with a ramfb display and check that the kernel drew its console
# on the UEFI Graphics Output Protocol framebuffer the boot stub handed over
# in the CHANDOF3 record (native/boot/efi_gop.c, native/kernel/core/fbcon.c).
# Last line: AIENOS_CK_SCREEN: PASS|FAIL|NOT_RUN (read by scripts/ck_gates.sh).
#
# Two boots, both with "-device ramfb" and a QMP socket; QEMU runs with
# "-action reboot=shutdown,shutdown=pause", so the kernel's final PSCI reset
# pauses the guest with the last screen still in place, and the script takes a
# QMP "screendump" (binary PPM) before quitting QEMU.
#   1. default image (core only, as built by make): the serial log must show
#      the stub's "gop: ok" line, exactly one "screen: gop" line, "kernel:
#      alive", no panic/fault, a reset (QEMU status "shutdown"), and the host
#      checker (native/kernel/tools/ck_fb_check.c) must find the screendump
#      pixel-identical to the screen the kernel's own console code renders
#      from the serial bytes, decode every cell against the kernel's font,
#      and find the rows "report_kind: final" and "note: QEMU qualifies
#      nothing physical" on screen.
#   2. negative control, TEST-only image (make CK_TEST_STALE_HANDOFF=2): the
#      stub hands over a CHANDOF2 record; the kernel must refuse it with
#      "panic: handoff: unsupported version 2 (kernel reads CHANDOF3 only)",
#      never draw ("screen: gop" absent, "kernel: alive" absent), and the
#      host checker must FAIL on that boot's serial log and screendump.
# QEMU is not hardware: a PASS here qualifies nothing physical. It says
# nothing about the Spark's own GOP (UNVERIFIED until an attended boot).
#
# NOT_RUN (never a silent pass) when qemu, AAVMF, socat or the host compiler
# is missing, the QEMU gate lock (~/workspace/.qemu-gate-lock, exclusive
# create, same rule as the FPU and INFER gates) is held, or the machine quiet
# flag (~/workspace/.spark-quiet) exists; this script never writes the quiet
# flag.
#
# Usage: bash scripts/qemu_ck_screen_test.sh               the gate
#        bash scripts/qemu_ck_screen_test.sh --self-test   canned logs and
#                                rendered screens, no QEMU
# Environment: AIENOS_QEMU_TIMEOUT (300 s per boot), AIENOS_GATE_LOCK /
# AIENOS_GATE_TAG, AIENOS_QUIET_FLAG (read only), AIENOS_LOG_DIR (serial logs,
# screendumps, decoded rows and PNGs when ffmpeg exists), AIENOS_QEMU_VERBOSE,
# AIENOS_FB_CHECK_TOOL (prebuilt checker, for a red run on an older commit).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict_name=AIENOS_CK_SCREEN
stale_line='panic: handoff: unsupported version 2 (kernel reads CHANDOF3 only)'
expect_rows=("report_kind: final" "note: QEMU qualifies nothing physical")

# positive_checks SERIAL PPM TOOL STATUS OUTPREFIX: PASS/FAIL line per check.
positive_checks() {
    local serial="$1" ppm="$2" tool="$3" status="$4" pre="$5" n args=() e
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; }
    grep -qE '^gop: ok ' "${serial}" && ok "boot stub found a GOP linear framebuffer" || bad "no 'gop: ok' line from the boot stub"
    n="$(grep -cE '^screen: gop ' "${serial}" || true)"
    [[ "${n}" == 1 ]] && ok "kernel put its console on the framebuffer (one 'screen: gop' line)" || bad "${n} 'screen: gop' lines (want 1)"
    grep -qx 'kernel: alive' "${serial}" && ok "kernel alive" || bad "kernel never reached kernel: alive"
    if grep -qE 'report_kind: (panic|fault)' "${serial}"; then bad "panic or fault report"; else ok "no panic or fault"; fi
    [[ "${status}" == shutdown ]] && ok "guest reset reached (QEMU paused at shutdown)" || bad "QEMU status '${status}' (want shutdown)"
    for e in "${expect_rows[@]}"; do args+=(--expect "${e}"); done
    if "${tool}" --serial "${serial}" --ppm "${ppm}" --render "${pre}.expected.ppm" "${args[@]}" >"${pre}.fbcheck.txt" 2>&1; then
        ok "screendump matches the rendered console: $(tail -1 "${pre}.fbcheck.txt")"
    else
        bad "screen check: $(grep -E '^fb_check: (FAIL|expect .*MISSING|pixel)' "${pre}.fbcheck.txt" | head -3 | paste -sd';' -)"
    fi
}

# negative_checks SERIAL PPM TOOL STATUS OUTPREFIX
negative_checks() {
    local serial="$1" ppm="$2" tool="$3" status="$4" pre="$5"
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; }
    grep -qF 'TEST-ONLY stale handoff image' "${serial}" && ok "negative image announced itself (TEST-ONLY)" || bad "negative image did not announce itself"
    grep -qxF "${stale_line}" "${serial}" && ok "kernel refused the CHANDOF2 record: ${stale_line}" || bad "no '${stale_line}' line"
    if grep -qE '^screen: gop ' "${serial}"; then bad "kernel drew on the screen after a stale record"; else ok "no screen console after the refusal"; fi
    if grep -qx 'kernel: alive' "${serial}"; then bad "kernel went on after a stale record"; else ok "kernel stopped before kernel: alive"; fi
    [[ "${status}" == shutdown ]] && ok "refusal ended in a reset (QEMU paused at shutdown)" || bad "QEMU status '${status}' (want shutdown)"
    if "${tool}" --serial "${serial}" --ppm "${ppm}" --expect "${stale_line}" >"${pre}.fbcheck.txt" 2>&1; then
        bad "screen check PASSED on the refused boot (checker does not discriminate)"
    else
        ok "screen check FAILS on the refused boot as required ($(tail -1 "${pre}.fbcheck.txt"))"
    fi
}

build_tool() { # OUT -> path of ck_fb_check (AIENOS_FB_CHECK_TOOL: a prebuilt
    # checker, only for the red run on a commit that predates the tool)
    if [[ -n "${AIENOS_FB_CHECK_TOOL:-}" ]]; then echo "${AIENOS_FB_CHECK_TOOL}"; return; fi
    make -s -C native/kernel OUT="$1" fb-check >/dev/null
    echo "$1/host/ck_fb_check"
}

if [[ "${1:-}" == --self-test ]]; then
    command -v "${HOSTCC:-cc}" >/dev/null || command -v gcc >/dev/null || { echo "${verdict_name}_SELF_TEST: NOT_RUN (no host compiler)"; exit 2; }
    tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
    tool="$(build_tool "${tmp}/out")"
    st=0
    expect_result() { # NAME pass|fail OUTPUT-FILE
        local f=0; grep -q '^FAIL' "$3" && f=1
        if [[ "$2" == pass && ${f} == 0 ]] || [[ "$2" == fail && ${f} == 1 ]]; then echo "PASS  self-test $1"; else echo "FAIL  self-test $1"; sed 's/^/      /' "$3"; st=1; fi
    }
    # A canned positive boot: firmware noise, the marker, 80 numbered lines
    # (forces one half-scroll on the 60-row 800x600 grid), the final report.
    {
        printf 'BdsDxe: loading Boot0001\r\ngop: ok from=conout handles=2 mode=1/3 800x600 pitch=800 format=1 base=0xbc7a0000 size=0x300000\r\n'
        printf 'screen: gop 800x600 pitch=800 format=bgrx base=0xbc7a0000 bytes=0x1d4c00 scale=1 grid=100x60 font=8x8 mode=half-scroll\r\n'
        printf '\r\nkernel: alive\r\n'
        for i in $(seq 1 80); do printf 'line %02d: the quick brown fox jumps over the lazy dog ~!@#$%%^&*()_+{}|:"<>?\r\n' "${i}"; done
        printf 'report_kind: final\r\nnote: QEMU qualifies nothing physical\r\n'
    } >"${tmp}/good.raw"
    tr -d '\r' <"${tmp}/good.raw" >"${tmp}/good.log"
    "${tool}" --serial "${tmp}/good.raw" --render "${tmp}/good.ppm" >/dev/null
    positive_checks "${tmp}/good.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/p1" >"${tmp}/r1"; expect_result positive-good pass "${tmp}/r1"
    # one flipped pixel byte in the last row of the image
    cp "${tmp}/good.ppm" "${tmp}/flip.ppm"; sz=$(stat -c %s "${tmp}/flip.ppm")
    printf '\x80' | dd of="${tmp}/flip.ppm" bs=1 seek=$((sz - 7)) conv=notrunc status=none
    positive_checks "${tmp}/good.log" "${tmp}/flip.ppm" "${tool}" shutdown "${tmp}/p2" >"${tmp}/r2"; expect_result one-pixel-off fail "${tmp}/r2"
    # the screen of a different text (one character changed in the log)
    sed 's/line 79: the quick/line 79: the quack/' "${tmp}/good.log" >"${tmp}/other.log"
    positive_checks "${tmp}/other.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/p3" >"${tmp}/r3"; expect_result one-char-off fail "${tmp}/r3"
    # no marker line; marker twice; expected row missing; not reset; panic
    grep -v '^screen: gop' "${tmp}/good.log" >"${tmp}/nomark.log"
    positive_checks "${tmp}/nomark.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/p4" >"${tmp}/r4"; expect_result no-marker fail "${tmp}/r4"
    { cat "${tmp}/good.log"; grep '^screen: gop' "${tmp}/good.log"; } >"${tmp}/twomark.log"
    positive_checks "${tmp}/twomark.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/p5" >"${tmp}/r5"; expect_result two-markers fail "${tmp}/r5"
    grep -v '^note: QEMU' "${tmp}/good.raw" >"${tmp}/nonote.raw"; tr -d '\r' <"${tmp}/nonote.raw" >"${tmp}/nonote.log"
    "${tool}" --serial "${tmp}/nonote.raw" --render "${tmp}/nonote.ppm" >/dev/null
    positive_checks "${tmp}/nonote.log" "${tmp}/nonote.ppm" "${tool}" shutdown "${tmp}/p6" >"${tmp}/r6"; expect_result expected-row-missing fail "${tmp}/r6"
    positive_checks "${tmp}/good.log" "${tmp}/good.ppm" "${tool}" running "${tmp}/p7" >"${tmp}/r7"; expect_result no-reset fail "${tmp}/r7"
    { cat "${tmp}/good.log"; echo "report_kind: panic"; } >"${tmp}/panic.log"
    positive_checks "${tmp}/panic.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/p8" >"${tmp}/r8"; expect_result panic fail "${tmp}/r8"
    # negative control: a refused boot, and a "refused" boot that drew anyway
    printf 'handoff: TEST-ONLY stale handoff image: the kernel gets a CHANDOF2 record; never counts toward a PASS\nreport_kind: panic\n%s\n' "${stale_line}" >"${tmp}/neg.log"
    positive_checks "${tmp}/neg.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/p9" >"${tmp}/r9"; expect_result stale-boot-is-not-a-positive fail "${tmp}/r9"
    negative_checks "${tmp}/neg.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/n1" >"${tmp}/r10"; expect_result negative-good pass "${tmp}/r10"
    { cat "${tmp}/neg.log"; cat "${tmp}/good.log"; } >"${tmp}/negdrew.log"
    negative_checks "${tmp}/negdrew.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/n2" >"${tmp}/r11"; expect_result negative-that-drew fail "${tmp}/r11"
    grep -v "^panic: handoff" "${tmp}/neg.log" >"${tmp}/negnoline.log"
    negative_checks "${tmp}/negnoline.log" "${tmp}/good.ppm" "${tool}" shutdown "${tmp}/n3" >"${tmp}/r12"; expect_result negative-without-refusal-line fail "${tmp}/r12"
    [[ ${st} == 0 ]] && { echo "${verdict_name}_SELF_TEST: PASS"; exit 0; }
    echo "${verdict_name}_SELF_TEST: FAIL"; exit 1
fi

notrun() { echo "NOT_RUN  $*"; echo "${verdict_name}: NOT_RUN ($*)"; exit 2; }
command -v qemu-system-aarch64 >/dev/null || notrun "qemu-system-aarch64 not installed"
command -v socat >/dev/null || notrun "socat not installed (QMP screendump)"
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || notrun "AAVMF firmware not found"

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel-screen"
out_neg="${repo_root}/target/native-kernel-test-stale-handoff"
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" >/dev/null
make -s -C native/kernel CROSS="${cross}" OUT="${out_neg}" AIENOS_COMMIT="${commit}" CK_TEST_STALE_HANDOFF=2 >/dev/null
tool="$(build_tool "${out}")"

# Machine-wide quiet flag: read only, never written here.
quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
if [[ -e "${quiet_flag}" ]]; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${verdict_name}: NOT_RUN"
    exit 3
fi
# One QEMU gate at a time: exclusive create (set -C) of the gate lock.
gate_lock="${AIENOS_GATE_LOCK:-${HOME}/workspace/.qemu-gate-lock}"
gate_tag="${AIENOS_GATE_TAG:-qemu_ck_screen_test $$}"
if ! ( set -C; echo "${gate_tag}" > "${gate_lock}" ) 2>/dev/null; then
    echo "NOT_RUN  QEMU gate lock ${gate_lock} is held: $(head -c 200 "${gate_lock}" 2>/dev/null || true)"
    echo "${verdict_name}: NOT_RUN"
    exit 3
fi
own_lock=1
release_lock() {
    if [[ "${own_lock}" == 1 ]]; then
        own_lock=0
        if [[ -f "${gate_lock}" ]] && grep -qxF -- "${gate_tag}" "${gate_lock}"; then rm -f "${gate_lock}"; fi
    fi
}
work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; release_lock; }
trap cleanup EXIT

qmp() { # SOCKET JSON-COMMAND -> QEMU's replies
    printf '{"execute":"qmp_capabilities"}\n%s\n' "$2" | socat -t3 - "UNIX-CONNECT:$1" 2>/dev/null || true
}

# boot NAME EFI: one QEMU run; sets boot_status, boot_rc, boot_secs.
boot() {
    local name="$1" efi="$2" d="${work}/$1" t0 deadline st qpid
    mkdir -p "${d}/esp/EFI/BOOT" "${d}/esp/EFI/AIENOS"
    touch "${d}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "${efi}" "${d}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${d}/vars.fd"
    t0=$(date +%s); deadline=$(( t0 + ${AIENOS_QEMU_TIMEOUT:-300} ))
    qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${d}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${d}/esp" \
        -device virtio-blk-pci,drive=esp \
        -device ramfb -display none -nic none \
        -serial file:"${d}/serial.raw" \
        -qmp unix:"${d}/qmp.sock",server=on,wait=off \
        -action reboot=shutdown,shutdown=pause &
    qpid=$!
    boot_status=timeout
    while (( $(date +%s) < deadline )) && kill -0 "${qpid}" 2>/dev/null; do
        sleep 2
        st="$(qmp "${d}/qmp.sock" '{"execute":"query-status"}' | sed -n 's/.*"status": *"\([a-z-]*\)".*/\1/p' | tail -1)"
        if [[ -n "${st}" && "${st}" != running && "${st}" != prelaunch ]]; then boot_status="${st}"; break; fi
    done
    qmp "${d}/qmp.sock" "{\"execute\":\"screendump\",\"arguments\":{\"filename\":\"${d}/screen.ppm\"}}" >"${d}/qmp_screendump.txt"
    qmp "${d}/qmp.sock" '{"execute":"quit"}' >/dev/null
    set +e; wait "${qpid}"; boot_rc=$?; set -e
    boot_secs=$(( $(date +%s) - t0 ))
    tr -d '\r' <"${d}/serial.raw" >"${d}/serial.txt" 2>/dev/null || : >"${d}/serial.txt"
    echo "qemu ${name}: status ${boot_status}, exit ${boot_rc} after ${boot_secs} s"
}

started=$(date +%s)
boot positive "${out}/BOOTAA64.EFI"; pos_status="${boot_status}"
boot negative "${out_neg}/BOOTAA64.EFI"; neg_status="${boot_status}"
release_lock
echo "commit ${commit:0:12}, both boots in $(( $(date +%s) - started )) s"

failed=0
pos="$(positive_checks "${work}/positive/serial.txt" "${work}/positive/screen.ppm" "${tool}" "${pos_status}" "${work}/positive/out")" || true
neg="$(negative_checks "${work}/negative/serial.txt" "${work}/negative/screen.ppm" "${tool}" "${neg_status}" "${work}/negative/out")" || true
echo "-- default image (GOP console)"; printf '%s\n' "${pos}"
echo "-- negative control (TEST-only CHANDOF2 record)"; printf '%s\n' "${neg}"
grep -q '^FAIL' <<<"${pos}${neg}" && failed=1
grep -E '^(gop|screen): ' "${work}/positive/serial.txt" || true
grep -E '^screen_row ' "${work}/positive/out.fbcheck.txt" 2>/dev/null | grep -v '||$' | tail -8 || true

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then
    for b in positive negative; do
        cp "${work}/${b}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_screen_${b}_serial.log" 2>/dev/null || true
        cp "${work}/${b}/screen.ppm" "${AIENOS_LOG_DIR}/qemu_ck_screen_${b}_screendump.ppm" 2>/dev/null || true
        cp "${work}/${b}/out.fbcheck.txt" "${AIENOS_LOG_DIR}/qemu_ck_screen_${b}_fbcheck.txt" 2>/dev/null || true
        if command -v ffmpeg >/dev/null && [[ -f "${work}/${b}/screen.ppm" ]]; then
            ffmpeg -loglevel error -y -i "${work}/${b}/screen.ppm" "${AIENOS_LOG_DIR}/qemu_ck_screen_${b}_screendump.png" || true
        fi
    done
    cp "${work}/positive/out.expected.ppm" "${AIENOS_LOG_DIR}/qemu_ck_screen_positive_expected.ppm" 2>/dev/null || true
fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for b in positive negative; do echo "---- ${b} serial console (last 40 lines) ----"; tail -40 "${work}/${b}/serial.txt"; done
fi
if [[ "${failed}" == 0 ]]; then echo "${verdict_name}: PASS"; exit 0; fi
echo "${verdict_name}: FAIL"; exit 1
