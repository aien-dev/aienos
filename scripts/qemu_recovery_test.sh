#!/usr/bin/env bash
# Recovery Core qualification in QEMU (ADR 0006): deterministic entry and
# read-only inspection, operator-authorised repair and provisioning bound to
# the exact on-disk state, and no action that mints an identity after
# identity loss. No model, no network.
#
# The operator key is TEST ONLY (public in this tree); the real credential
# scheme is not decided (ADR 0006 / M5). 4096-byte LBA, native NVMe driver.
# Emits RECOVERY_CORE_QEMU: PASS only when every step passes.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; exit 2; }

boot_timeout="${AIENOS_QEMU_TIMEOUT:-180}"
img_bytes=67108864
lba_bytes=4096
cfg_offset=$(( 32 * lba_bytes ))
store_offset=$(( 64 * lba_bytes ))
region_units=256
machine="virt,virtualization=on,gic-version=3,iommu=smmuv3"
target_dir="target/qemu-recovery"
# TEST ONLY operator key (crates/aienos-boot/src/store_qual.rs).
test_key=$(printf '0f%.0s' $(seq 32))
wrong_key=$(printf '0e%.0s' $(seq 32))
zero=$(printf '00%.0s' $(seq 32))

echo "=== Building aienos-handoff (recovery-qual) and aienos-store-tool ==="
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
git diff --quiet HEAD 2>/dev/null || commit="${commit}-dirty"
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features recovery-qual --bin aienos-handoff \
    --target-dir "${target_dir}" || { echo "build failed"; exit 2; }
cargo build --quiet --release -p aienos-store-tool || { echo "store tool build failed"; exit 2; }
tool="target/release/aienos-store-tool"

work="$(mktemp -d)"
qemu_pid=""
cleanup() { [[ -n "${qemu_pid}" ]] && kill -9 "${qemu_pid}" 2>/dev/null || true; rm -rf "${work}"; }
trap cleanup EXIT
mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${target_dir}/aarch64-unknown-uefi/release/aienos-handoff.efi" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"

image="${work}/nvme.img"
serial="${work}/serial.log"
fail=0

fresh_image() { rm -f "${image}"; truncate -s "${img_bytes}" "${image}"; }
digest() { sha256sum "${image}" | cut -d' ' -f1; }
pass() { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

run_qemu() {
    cp -f "${vars_fd}" "${work}/vars.fd"
    rm -f "${serial}"
    timeout "${boot_timeout}" qemu-system-aarch64 \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${image}" \
        -device nvme,drive=nvme0,serial=aienos-recovery,logical_block_size=${lba_bytes},physical_block_size=${lba_bytes} \
        -display none -nic none -serial file:"${serial}" -no-reboot || true
}

# boot MODE [RESPONSE_HEX]: write the control block, then one cold boot.
# before/after digests bracket only the guest's writes.
boot() {
    "${tool}" cfg "${image}" "${cfg_offset}" "$1" 0 ${2:+"$2"} >/dev/null || { echo "cfg write failed"; exit 2; }
    before=$(digest)
    run_qemu
    after=$(digest)
}
out() { tr -d '\r' <"${serial}" | grep -E "$1" | tail -1; }
challenge_for() { out "^RECOVERY_CHALLENGE: action=$1 " | sed -nE 's/.*challenge=([0-9a-f]{64}).*/\1/p'; }
respond() { "${tool}" operator-respond "$1" "$2"; }
agent_of() { sed -nE 's/.*agent=([0-9a-f]{64}).*/\1/p' <<<"$1"; }
unchanged() { [[ "${before}" == "${after}" ]]; }

echo "=== 1. Degraded store: operator-authorised repair ==="
fresh_image
boot 5; agent=$(agent_of "$(out '^CONTINUITY: PROVISIONED')")
boot 7; memory=$(out '^CONTINUITY: REMEMBERED' | sed -nE 's/.*memory=([0-9a-f]+).*/\1/p')
[[ ${#agent} == 64 && -n "${memory}" ]] || bad "could not build a provisioned store with memory"
"${tool}" inject "${image}" "${store_offset}" inactive seeded_garbage >/dev/null || bad "inject failed"

boot 9
if [[ -n "$(out '^RECOVERY_OPERATOR_KEY: TEST-ONLY$')" && \
      -n "$(out '^RECOVERY_CORE: ENTERED reason=Degraded\(Malformed\)$')" && \
      "$(agent_of "$(out '^RECOVERY_RECORD:')")" == "${agent}" ]] && unchanged; then
    pass "inspection enters the Recovery Core (Degraded(Malformed)), shows the same agent, writes nothing"
else
    bad "inspection: $(tr -d '\r' <"${serial}" | grep -E '^RECOVERY_' | tr '\n' '|')"
fi
c_repair=$(challenge_for repair-degraded-peer)
[[ ${#c_repair} == 64 ]] || bad "no repair challenge offered"

for case in zero wrong_key wrong_action; do
    case "${case}" in
        zero)         r="${zero}" ;;
        wrong_key)    r=$(respond "${wrong_key}" "${c_repair}") ;;
        wrong_action) r=$(respond "${test_key}" "$(printf 'ff%.0s' $(seq 32))") ;;
    esac
    boot 10 "${r}"
    if [[ -n "$(out '^RECOVERY_REFUSED \(Unauthorised\)$')" ]] && unchanged; then
        pass "repair with ${case} response refused, nothing written"
    else
        bad "repair with ${case}: $(out '^RECOVERY_(ACTION|REFUSED)')"
    fi
done

good=$(respond "${test_key}" "${c_repair}")
boot 10 "${good}"
if [[ -n "$(out '^RECOVERY_ACTION: repair-degraded-peer DONE$')" ]] && ! unchanged; then
    pass "authorised repair done"
else
    bad "authorised repair: $(out '^RECOVERY_(ACTION|REFUSED)')"
fi
boot 6
r=$(out '^CONTINUITY: RESUMED ')
if [[ "$(agent_of "${r}")" == "${agent}" && "${r}" == *"memory=${memory}"* ]]; then
    pass "after repair a cold boot resumes writable with the same agent and memory"
else
    bad "resume after repair: '${r:-$(out '^CONTINUITY:')}'"
fi
boot 10 "${good}"
if [[ -n "$(out '^RECOVERY_REFUSED \(NotApplicable\)$')" ]] && unchanged; then
    pass "replaying the repair authorisation on the healthy store does nothing"
else
    bad "replay: $(out '^RECOVERY_(ACTION|REFUSED)')"
fi

echo "=== 2. Unprovisioned store: operator-authorised provisioning ==="
fresh_image
"${tool}" cfg "${image}" "${cfg_offset}" 1 0 >/dev/null; run_qemu   # formatted store with data, no identity
boot 9
c_prov=$(challenge_for provision-identity)
if [[ -n "$(out '^RECOVERY_CORE: ENTERED reason=Unprovisioned$')" && ${#c_prov} == 64 ]] && unchanged; then
    pass "unprovisioned store enters the Recovery Core and offers only provisioning"
else
    bad "unprovisioned inspection: $(tr -d '\r' <"${serial}" | grep -E '^RECOVERY_' | tr '\n' '|')"
fi
boot 11 "$(respond "${wrong_key}" "${c_prov}")"
if [[ -n "$(out '^RECOVERY_REFUSED \(Unauthorised\)$')" ]] && unchanged; then
    pass "provisioning with a wrong key refused, nothing written"
else
    bad "wrong-key provisioning: $(out '^RECOVERY_(ACTION|REFUSED)')"
fi
boot 11 "$(respond "${test_key}" "${c_prov}")"
new_agent=$(agent_of "$(out '^RECOVERY_ACTION: provision-identity DONE')")
boot 6
if [[ ${#new_agent} == 64 && "$(agent_of "$(out '^CONTINUITY: RESUMED ')")" == "${new_agent}" ]]; then
    pass "operator provisioning created one identity and a cold boot resumes it"
else
    bad "operator provisioning: agent='${new_agent}' resume='$(out '^CONTINUITY:')'"
fi

echo "=== 3. Identity loss: nothing may mint ==="
fresh_image
boot 5; lost=$(agent_of "$(out '^CONTINUITY: PROVISIONED')")
"${tool}" corrupt-kind "${image}" "${store_offset}" "${region_units}" 16 >/dev/null || bad "corrupt-kind failed"
boot 9
if [[ -n "$(out '^RECOVERY_CORE: ENTERED reason=')" && -z "$(out '^RECOVERY_CHALLENGE:')" ]] && unchanged; then
    pass "corrupted agent root: Recovery Core entered, no action offered, nothing written ($(out '^RECOVERY_CORE:' | sed 's/.*reason=//'))"
else
    bad "identity loss inspection: $(tr -d '\r' <"${serial}" | grep -E '^RECOVERY_' | tr '\n' '|')"
fi
forged=$(respond "${test_key}" "$(printf 'aa%.0s' $(seq 32))")
for m in 10 11; do
    boot "${m}" "${forged}"
    if [[ -n "$(out '^RECOVERY_REFUSED \(')" && -z "$(out '^RECOVERY_ACTION:')" ]] && unchanged; then
        pass "mode ${m} after identity loss refused, nothing written"
    else
        bad "mode ${m} after identity loss: $(out '^RECOVERY_(ACTION|REFUSED)')"
    fi
done
boot 6
if [[ -z "$(out '^CONTINUITY: (RESUMED|PROVISIONED)')" ]] && unchanged; then
    pass "a normal boot after identity loss does not resume or mint (${lost:0:16}... is not replaced)"
else
    bad "normal boot after identity loss: $(out '^CONTINUITY:')"
fi

echo
echo "=== Summary (commit ${commit}) ==="
if [[ "${fail}" == 0 ]]; then
    echo "RECOVERY_CORE_QEMU: PASS"
else
    echo "RECOVERY_CORE_QEMU: FAIL"
    exit 1
fi
echo "RECOVERY_CORE_OPERATOR_CREDENTIAL: TEST-ONLY (real scheme undecided, ADR 0006 / M5)"
