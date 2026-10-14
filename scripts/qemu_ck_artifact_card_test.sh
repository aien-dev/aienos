#!/usr/bin/env bash
# QEMU twin of the Raspberry Pi 5 EL0 artifact qualification image (PI5-7 cut 3, native/kernel/core/artifact_card.h).
# Builds the SAME code the Pi image runs (make CK_ARTIFACT_CARD=1 CK_SEED0B_TEST_ANCHOR=1, the core image with the card
# bundle source; the Pi image adds only CK_PI5) and boots it in QEMU AArch64 + UEFI (AAVMF) with the signed artifacts in ONE
# file on the ESP, \EFI\AIENOS\ARTIFACT.BND. QEMU is not hardware: a PASS here qualifies nothing physical; it is the red-
# before-green run that must pass before a Pi run is spent.
#
# TEST keys only: every artifact is signed by the in-tree C tool with the public RFC 8032 TEST 1 key (SEED-0B, TEST ONLY).
# Boots (all with the card image):
#   1. layout: the bundle holds P25EXEC only, to read the kernel's own layout lines; the two kernel-address probes are then
#      assembled for exactly those addresses (fixtures/p2_7/assemble.sh);
#   2. qualification: P25EXEC (good, exits 0 through SYS_EXIT after a capability read), P27KREAD (EL0 load from kernel memory),
#      P27KWRITE (EL0 store to kernel memory), P27PRIV (EL0 read of a kernel control register), P26SEED (good, runs AFTER the
#      three faults: the kernel kept running), P25TAMP (one payload byte flipped after signing): every verdict, the fault
#      class/ESR/FAR, the receipts (host-verified), frame accounting, TEST-ONLY labels;
#   3. negative controls: no ARTIFACT.BND on the card (no candidates), and a bundle with one trailing byte (refused whole).
# Last line: AIENOS_CK_ARTIFACT_CARD: PASS|FAIL|NOT_RUN.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict=AIENOS_CK_ARTIFACT_CARD

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict}: NOT_RUN"; exit 2; }

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take "qemu_ck_artifact_card" "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "${verdict}: NOT_RUN"
    exit 3
fi
work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; gh_lock_release; }
trap cleanup EXIT
failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel-artifact-card"
make -s -C native/kernel CROSS="${cross}" AIENOS_COMMIT="${commit}" OUT="${out}" CK_ARTIFACT_CARD=1 CK_SEED0B_TEST_ANCHOR=1 >/dev/null
make -s -C native/kernel CROSS="${cross}" OUT="${out}" tool >/dev/null
tool="${out}/host/ck_artifact_tool"
efi="${out}/BOOTAA64.EFI"
fx="crates/aienos-artifact-tool/fixtures"

# ---- static: the image is TEST-ONLY labelled and carries no fw_cfg artifact code ----
if grep -aqF "artifact_trust: seed0b-test qualification build" "${efi}"; then pass "card image carries the TEST ONLY trust label"; else fail "card image lacks the TEST ONLY trust label"; fi
if grep -aqE "opt/aienos/artifacts|fw_cfg|QEMU0002" "${efi}"; then fail "card image carries fw_cfg artifact code"; else pass "card image has no fw_cfg artifact code"; fi
for bad in "CK_ARTIFACT_CARD=1" "CK_ARTIFACT_CARD=1 CK_SEED0B_TEST_ANCHOR=1 CK_HARDWARE_STAGING=1" "CK_PI5_ARTIFACT=1 CK_PI5_STORE=1" "CK_ARTIFACT_CARD=1 CK_SEED0B_TEST_ANCHOR=1 full"; do
    # shellcheck disable=SC2086
    if make -n -C native/kernel ${bad} >/dev/null 2>&1; then fail "Makefile accepts ${bad}"; else pass "Makefile refuses ${bad}"; fi
done

boot() { # bundle-or-empty, serial text output
    local esp="${work}/esp" log="${work}/serial.log" status
    rm -rf "${esp}"
    mkdir -p "${esp}/EFI/BOOT" "${esp}/EFI/AIENOS"
    cp "${efi}" "${esp}/EFI/BOOT/BOOTAA64.EFI"
    if [[ -n "$1" ]]; then cp "$1" "${esp}/EFI/AIENOS/ARTIFACT.BND"; fi
    cp "${vars_fd}" "${work}/vars.fd"
    set +e
    nice -n 10 timeout "${AIENOS_QEMU_TIMEOUT:-300}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${esp}" \
        -device virtio-blk-pci,drive=esp \
        -device ramfb -display none -nic none \
        -serial file:"${log}" -no-reboot 2>/dev/null
    status=$?
    set -e
    tr -d '\r' <"${log}" >"$2"
    [[ "${status}" == 0 ]] || fail "QEMU exit status ${status} (124 = timeout)"
}
has() { grep -qE -- "$2" "$1"; }
check() { if has "$1" "$3"; then pass "$2"; else fail "$2"; fi; }

# ---- inputs: signed artifacts (TEST key) ----
art="${work}/art"
mkdir -p "${art}"
"${fx}/p2_5/pack.sh" "${tool}" "${art}" >/dev/null
"${fx}/p2_6/pack.sh" "${tool}" "${art}" >/dev/null

# ---- boot 1: layout ----
"${tool}" bundle "${work}/layout.bnd" "${art}/P25EXEC.AIEN" >/dev/null
boot "${work}/layout.bnd" "${work}/layout.txt"
root=$(sed -nE 's/^mmu_switch: .* aienos_root=(0x[0-9a-f]+) .*/\1/p' "${work}/layout.txt" | head -1)
heap_lo=$(sed -nE 's/^memory: .* heap=(0x[0-9a-f]+)-(0x[0-9a-f]+) .*/\1/p' "${work}/layout.txt" | head -1)
heap_hi=$(sed -nE 's/^memory: .* heap=(0x[0-9a-f]+)-(0x[0-9a-f]+) .*/\2/p' "${work}/layout.txt" | head -1)
if [[ -n "${root}" && -n "${heap_lo}" && -n "${heap_hi}" ]]; then
    kw=$(printf '0x%x' $(( (heap_lo + heap_hi) / 2 & ~0xfff )))
    pass "kernel layout read: translation root ${root}, heap ${heap_lo}-${heap_hi}; probes target ${root} (read) and ${kw} (write)"
else
    fail "kernel layout lines (root='${root}' heap='${heap_lo}-${heap_hi}')"; root=0x40000000; kw=0x4a000000
fi
KREAD_ADDR="${root}" KWRITE_ADDR="${kw}" "${fx}/p2_7/assemble.sh" "${work}/p27" >/dev/null
"${fx}/p2_7/pack.sh" "${tool}" "${art}" "${work}/p27" >/dev/null
# the committed Pi variant must still be exactly what probe.S assembles to (default addresses)
"${fx}/p2_7/assemble.sh" "${work}/p27pi" >/dev/null
pi_ok=1
for p in p27kread p27kwrite p27priv; do cmp -s "${work}/p27pi/${p}/code.bin" "${fx}/p2_7/${p}/code.bin" || pi_ok=0; done
if [[ "${pi_ok}" == 1 ]]; then pass "committed Pi probe code.bin files equal probe.S assembled"; else fail "committed Pi probe code.bin differs from probe.S"; fi

# ---- boot 2: qualification ----
order=(P25EXEC P27KREAD P27KWRITE P27PRIV P26SEED P25TAMP)
files=()
for n in "${order[@]}"; do files+=("${art}/${n}.AIEN"); done
"${tool}" bundle "${work}/qual.bnd" "${files[@]}" >/dev/null
qual="${work}/qual.txt"
boot "${work}/qual.bnd" "${qual}"
check "${qual}" "kernel alive, M3 EL0 isolation proof unchanged" "el0: ok write=granted forged=denied fault=contained exit=0"
check "${qual}" "stub found a well-formed bundle on the card" "^artifact_card: found a well-formed bundle \(QUALIFICATION ONLY, TEST keys, 6 entries, $(stat -c %s "${work}/qual.bnd") bytes\)$"
check "${qual}" "TEST ONLY trust label" "^artifact_trust: seed0b-test qualification build — TEST ONLY$"
check "${qual}" "card_file source with six candidates" "^artifact_source: card_file candidates=6 "
if has "${qual}" "artifact_source: nvme_store|fw_cfg"; then fail "wrong artifact source label"; fi
check "${qual}" "bundle SHA-256 as the kernel read it equals the host file" "^artifact_card: .* sha256=$(sha256sum "${work}/qual.bnd" | cut -d' ' -f1) "
ok=1
for n in "${order[@]}"; do
    has "${qual}" "^artifact_card: ${n}\.AIEN bytes=$(stat -c %s "${art}/${n}.AIEN") sha256=$(sha256sum "${art}/${n}.AIEN" | cut -d' ' -f1)$" || { ok=0; echo "  kernel-side SHA-256 differs: ${n}"; }
done
if [[ "${ok}" == 1 ]]; then pass "kernel-side SHA-256 of all six artifacts equals the host files"; else fail "kernel-side artifact SHA-256"; fi
adm() { echo "^artifact: $1\.AIEN admitted id=[0-9a-f]{16} tier=seed0b-test exec=$2 bytes=identified=verified=admitted=mapped=executed wx=enforced caps=$3 revoked=yes reclaimed=yes frames=[0-9]+ "; }
check "${qual}" "(a) P25EXEC ran at EL0 and returned exit 0 through SYS_EXIT, capability read granted, forged handle denied" "$(adm P25EXEC exited:0x0 1)syscalls=3 reads=1 denials=1$"
check "${qual}" "(a) P26SEED ran after the faults, exit 0, 3 granted reads, 5 denials" "$(adm P26SEED exited:0x0 1)syscalls=9 reads=3 denials=5$"
check "${qual}" "(b) P25TAMP (one payload byte flipped) refused before running" "^artifact: P25TAMP\.AIEN rejected stage=verified reason=BadSignature reclaimed=yes$"
check "${qual}" "(c) P27KREAD: EL0 load from kernel memory faults" "$(adm P27KREAD fault:outside-read 0)syscalls=0 reads=0 denials=0$"
check "${qual}" "(c) P27KWRITE: EL0 store to kernel memory faults" "$(adm P27KWRITE fault:outside-write 0)syscalls=0 reads=0 denials=0$"
check "${qual}" "(c) P27PRIV: EL0 read of a kernel control register faults" "$(adm P27PRIV fault:privileged-insn 0)syscalls=0 reads=0 denials=0$"
check "${qual}" "(c) P27KREAD fault: data abort from EL0 (EC 0x24), read, FAR = the kernel root" "^artifact_fault: P27KREAD\.AIEN class=outside-read esr=0x[0-9a-f]+ ec=0x24 far=${root} elr=0x[0-9a-f]+ contained=yes$"
check "${qual}" "(c) P27KWRITE fault: data abort from EL0 (EC 0x24), write, FAR = the kernel heap address" "^artifact_fault: P27KWRITE\.AIEN class=outside-write esr=0x[0-9a-f]+ ec=0x24 far=${kw} elr=0x[0-9a-f]+ contained=yes$"
check "${qual}" "(c) P27PRIV fault: unknown-reason/trapped system instruction (EC 0x00 or 0x18), FAR not claimed" "^artifact_fault: P27PRIV\.AIEN class=privileged-insn esr=0x[0-9a-f]+ ec=0x(0|18) far=n/a elr=0x[0-9a-f]+ contained=yes$"
if has "${qual}" "exec=exited:0x57"; then fail "a probe reached its violation exit 0x57 (isolation broken)"; else pass "no probe reached its violation exit"; fi
check "${qual}" "kernel kept running: final report after all candidates" "^artifacts: candidates=6 admitted=5 rejected=1$"
if has "${qual}" "report_kind: (panic|fault)"; then fail "panic or fault reported"; else pass "no kernel panic or fault report"; fi
before=$(grep -oE "artifact_frames_free_before: [0-9]+" "${qual}" | awk '{print $2}' | tail -1)
after=$(grep -oE "artifact_frames_free_after: [0-9]+" "${qual}" | awk '{print $2}' | tail -1)
if [[ -n "${before}" && "${before}" == "${after}" ]]; then pass "every frame returned after all candidates (${before} free before and after)"; else fail "frame accounting (before=${before:-?} after=${after:-?})"; fi
check "${qual}" "bundle buffer released after the loader" "^artifact_card: released bundle bytes=$(stat -c %s "${work}/qual.bnd") entries=6$"
# receipts: decoded, bound to the supplied artifact, digest recomputed on the host, TEST ONLY signature verifies
receipt_check() { # name pattern
    local line record kdigest o file="${work}/$1.receipt"
    line=$(grep -E "^receipt: $1\.AIEN seq=[0-9]+ digest=[0-9a-f]{64} record=[0-9a-f]{1024}$" "${qual}" | tail -1 || true)
    if [[ -z "${line}" ]]; then fail "$1 receipt emitted"; return; fi
    record=${line##*record=}
    kdigest=$(sed -E 's/.* digest=([0-9a-f]{64}) .*/\1/' <<<"${line}")
    "${tool}" receipt from-hex "${record}" "${file}" >/dev/null 2>&1 || { fail "$1 receipt decodes"; return; }
    o=$("${tool}" receipt check "${file}" "${art}/$1.AIEN" 2>&1) || { fail "$1 receipt binds the artifact (${o})"; return; }
    [[ "${o}" == *"digest=${kdigest} "* ]] || { fail "$1 receipt digest recomputed by the host"; return; }
    grep -qE -- "$2" <<<"${o}" || { fail "$1 receipt records the observed outcome (${o})"; return; }
    "${tool}" receipt sign-test "${file}" "${file}.signed" >/dev/null 2>&1 || { fail "$1 receipt TEST ONLY signing"; return; }
    if "${tool}" receipt verify "${file}.signed" | grep -q "RECEIPT_VERIFY: PASS digest=${kdigest} "; then pass "$1 receipt: bound, host digest match, outcome recorded, TEST ONLY signature verifies"; else fail "$1 signed receipt verifies"; fi
}
receipt_check P25EXEC "decision=Admitted .* status=Exited exit=0 "
receipt_check P26SEED "decision=Admitted .* status=Exited exit=0 "
receipt_check P25TAMP "decision=Rejected .* stage=3 reason=0x12 status=NotRun "
for n in P27KREAD P27KWRITE P27PRIV; do receipt_check "${n}" "decision=Admitted .* status=Fault exit=0 syscalls=0 "; done

# ---- boot 3: no bundle on the card ----
none="${work}/none.txt"
boot "" "${none}"
check "${none}" "no bundle: loader reports no source" "^artifact_source: none \(no card artifact bundle \(file absent\)\)$"
check "${none}" "no bundle: zero candidates" "^artifacts: candidates=0 admitted=0 rejected=0$"

# ---- boot 4: a bundle with one trailing byte is refused whole ----
cp "${work}/qual.bnd" "${work}/trail.bnd"
printf '\000' >>"${work}/trail.bnd"
trail="${work}/trail.txt"
boot "${work}/trail.bnd" "${trail}"
check "${trail}" "trailing byte: bundle refused by the stub" "^artifact_card: refused \(bytes after the last entry\)$"
check "${trail}" "trailing byte: no artifact reaches the loader" "^artifacts: candidates=0 admitted=0 rejected=0$"
if has "${trail}" "^artifact: [A-Z0-9-]+\.AIEN "; then fail "an artifact of a refused bundle was named"; else pass "no artifact of the refused bundle was named or run"; fi

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then
    cp "${qual}" "${AIENOS_LOG_DIR}/qemu_ck_artifact_card_serial.log"
fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- qualification serial (artifact lines) ----"
    grep -E "^(artifact|grant|kernel|report_kind|panic|fault|exception|esr|far)" "${qual}" | head -80 || true
fi
if [[ "${failed}" == 0 ]]; then echo "${verdict}: PASS"; else echo "${verdict}: FAIL"; exit 1; fi
