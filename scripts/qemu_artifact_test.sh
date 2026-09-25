#!/usr/bin/env bash
# P2-5 Binary Artifact loader qualification in QEMU AArch64 (UEFI, EL2 start).
#
# Firmware reads signed .AIEN files from \EFI\AIENOS\ARTIFACTS on the ESP and
# hands their bytes to the kernel, which stages, verifies, admits, loads and
# runs each one as an isolated EL0 task, then reclaims it. Two boots:
#
#   1. seed0b-qualification build (TEST ONLY qualification trust anchor):
#      P25EXEC  admitted, runs from the exact authenticated bytes, exits 0
#      P25WX    admitted, killed by a W^X permission fault on its code page
#      P25SPIN  admitted, killed when its admitted time budget runs out
#      P25TAMP  one payload byte flipped after signing: rejected BadSignature
#   2. ordinary build (empty production trust set): every candidate rejected
#      UntrustedSigner. Production trust fails closed.
#
# Every candidate must end with reclaimed=yes (all frames returned, no live
# capabilities). No physical hardware is touched.
#
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

fixtures="crates/aienos-artifact-tool/fixtures/p2_5"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

# The committed probe bytes are the qualification inputs. When an assembler
# is available, prove they are exactly what probe.S assembles to.
as_bin=as
[[ "$(uname -m)" == "aarch64" ]] || as_bin=aarch64-linux-gnu-as
if command -v "${as_bin}" >/dev/null; then
    "${fixtures}/assemble.sh" "${work}/asm"
    for probe in p25exec p25wx p25spin; do
        if cmp -s "${work}/asm/${probe}/code.bin" "${fixtures}/${probe}/code.bin"; then
            pass "${probe} code.bin is exactly what probe.S assembles to"
        else
            fail "${probe} code.bin differs from probe.S"
        fi
    done
else
    echo "NOTE  no AArch64 assembler; using committed probe bytes unchecked"
fi

# Test-only signing: debug build by design (release refuses the feature).
cargo build --quiet -p aienos-artifact-tool --features seed0b-test-signing
tool="target/debug/aienos-artifact-tool"
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS/ARTIFACTS"
"${fixtures}/pack.sh" "${tool}" "${work}/esp/EFI/AIENOS/ARTIFACTS"
mv "${work}/esp/EFI/AIENOS/ARTIFACTS/ids.txt" "${work}/ids.txt"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
id_prefix() { # name -> first 16 hex digits of its ArtifactId
    awk -v n="$1" '$1 == n { print substr($2, 1, 16) }' "${work}/ids.txt"
}

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
build_image() { # features, output
    AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
        -p aienos-boot --target aarch64-unknown-uefi --features "$1" --bin aienos-handoff
    cp target/aarch64-unknown-uefi/release/aienos-handoff.efi "$2"
}
build_image seed0b-qualification "${work}/qualification.efi"
build_image handoff "${work}/production.efi"

boot() { # image, serial text output
    cp "$1" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    local log="${work}/serial.log" started status
    started=$(date +%s)
    set +e
    # Issue #61: single-threaded TCG; MTTCG hung in 1/40 soak boots.
    timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -device ramfb -display none -nic none \
        -serial file:"${log}" -no-reboot
    status=$?
    set -e
    tr -d '\r' <"${log}" >"$2"
    echo "qemu exit ${status} after $(( $(date +%s) - started )) s (commit ${commit:0:12})"
    [[ "${status}" != 124 ]] || fail "QEMU timed out (no reset)"
}

has() { grep -qE -- "$2" "$1"; }
check() { # serial, description, extended regex
    if has "$1" "$3"; then pass "$2"; else fail "$2"; fi
}
common_checks() { # serial
    check "$1" "left firmware and entered the kernel" "kernel: alive"
    check "$1" "M3 cooperative threads unchanged" "threads: ok"
    check "$1" "M3 EL0 isolation proof unchanged" "el0: ok write=granted forged=denied fault=contained exit=0"
    check "$1" "M3 typed IPC proof unchanged" "ipc: ok message=delivered cap=delegated rights=attenuated forged=denied revoked=denied"
    check "$1" "firmware read four artifact candidates" "artifact_candidates: 4$"
    check "$1" "final report reached the console" "report_kind: final"
    if has "$1" "report_kind: (panic|fault)"; then fail "panic or fault reported"; fi
}

# ---- boot 1: qualification build --------------------------------------------
qual="${work}/qualification.txt"
boot "${work}/qualification.efi" "${qual}"
common_checks "${qual}"
check "${qual}" "qualification build is labelled TEST ONLY" \
    "artifact_trust: seed0b-test qualification build — TEST ONLY"
exec_id="$(id_prefix P25EXEC.AIEN)"
check "${qual}" "P25EXEC admitted and executed its exact authenticated bytes, exit 0, caps revoked, reclaimed" \
    "artifact: P25EXEC\.AIEN admitted id=${exec_id} tier=seed0b-test exec=exited:0x0 bytes=identified=verified=admitted=mapped=executed wx=enforced caps=1 revoked=yes reclaimed=yes"
check "${qual}" "P25WX admitted then killed by W^X fault on its code page, reclaimed" \
    "artifact: P25WX\.AIEN admitted id=$(id_prefix P25WX.AIEN) tier=seed0b-test exec=fault:code-write .*wx=enforced .*reclaimed=yes"
check "${qual}" "P25SPIN admitted then killed at its time budget, reclaimed" \
    "artifact: P25SPIN\.AIEN admitted id=$(id_prefix P25SPIN.AIEN) tier=seed0b-test exec=timeout .*reclaimed=yes"
check "${qual}" "P25TAMP (payload byte flipped after signing) rejected BadSignature, reclaimed" \
    "artifact: P25TAMP\.AIEN rejected stage=(received|staged|verified) reason=BadSignature reclaimed=yes"
check "${qual}" "final report summarises three admitted, one rejected" \
    "artifacts: candidates=4 admitted=3 rejected=1"

# ---- boot 2: ordinary build, empty production trust -------------------------
prod="${work}/production.txt"
boot "${work}/production.efi" "${prod}"
common_checks "${prod}"
if has "${prod}" "seed0b-test qualification build"; then
    fail "ordinary build must not carry the qualification label"
fi
for name in P25EXEC P25WX P25SPIN P25TAMP; do
    reason=UntrustedSigner
    # The tampered file may fail its signature check before or after signer
    # lookup; either way it must be rejected, never run.
    [[ "${name}" != P25TAMP ]] || reason="(UntrustedSigner|BadSignature)"
    check "${prod}" "ordinary build rejects ${name} (${reason}), reclaimed" \
        "artifact: ${name}\.AIEN rejected stage=[a-z]+ reason=${reason} reclaimed=yes"
done
if has "${prod}" "artifact: [A-Z0-9]+\.AIEN admitted"; then
    fail "ordinary build admitted an artifact"
fi
check "${prod}" "final report summarises zero admitted" \
    "artifacts: candidates=4 admitted=0 rejected=4"

if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then
    cp "${qual}" "${AIENOS_LOG_DIR}/qemu_artifact_qualification_serial.log"
    cp "${prod}" "${AIENOS_LOG_DIR}/qemu_artifact_production_serial.log"
fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console: qualification build ----"
    cat "${qual}"
    echo "---- serial console: ordinary build ----"
    cat "${prod}"
fi
[[ "${failed}" == 0 ]] && echo "QEMU_ARTIFACT: PASS" || { echo "QEMU_ARTIFACT: FAIL"; exit 1; }
