#!/usr/bin/env bash
# qemu_secureboot_signing_test.sh: TRUST-1 Gate 4, Secure Boot enforcement in QEMU.
#
# Boots the AIENOS handoff loader under AArch64 UEFI firmware with Secure
# Boot ON, using the Debian "snakeoil" test key set (AAVMF_CODE.snakeoil.fd +
# AAVMF_VARS.snakeoil.fd). The snakeoil key is a published TEST key shipped
# with qemu-efi-aarch64 (password "snakeoil"); it is never an owner key and
# nothing here touches real firmware, real keys or the TPM.
#
# Cases (each a fresh copy of the firmware variables):
#   1. signed with the snakeoil key (the enrolled db key)  -> must boot to "kernel: alive"
#   2. unsigned                                            -> must be refused
#   3. signed, then one byte flipped in the signed region  -> must be refused
#   4. signed with a throwaway key that is not in db       -> must be refused
# Case 1 is the control: it proves the firmware boots our loader at all, so
# the refusals in 2-4 come from signature checking, not from a broken image.
#
# Exit 0 = all four as expected; 1 = a case failed; 2 = missing tools.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_SB_CODE:-/usr/share/AAVMF/AAVMF_CODE.snakeoil.fd}"
vars_fd="${AAVMF_SB_VARS:-/usr/share/AAVMF/AAVMF_VARS.snakeoil.fd}"
sk_key="${SNAKEOIL_KEY:-/usr/share/qemu-efi-aarch64/PkKek-1-snakeoil.key}"
sk_crt="${SNAKEOIL_CERT:-/usr/share/qemu-efi-aarch64/PkKek-1-snakeoil.pem}"
boot_timeout="${AIENOS_QEMU_TIMEOUT:-120}"
reject_timeout="${AIENOS_SB_REJECT_TIMEOUT:-45}"

for t in qemu-system-aarch64 sbsign sbverify openssl cargo; do
    command -v "${t}" >/dev/null || { echo "Error: ${t} not installed" >&2; exit 2; }
done
for f in "${code_fd}" "${vars_fd}" "${sk_key}" "${sk_crt}"; do
    [[ -r "${f}" ]] || { echo "Error: ${f} not found (package qemu-efi-aarch64)" >&2; exit 2; }
done

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo "Building aienos-handoff binary for the Secure Boot test..."
AIENOS_COMMIT="${commit}" AIENOS_RESTART_SECS=1 cargo build --quiet --release \
    -p aienos-boot --target aarch64-unknown-uefi --features handoff --bin aienos-handoff
efi="target/aarch64-unknown-uefi/release/aienos-handoff.efi"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
chmod 700 "${work}"

# sbsign cannot read an encrypted key; decrypt the public test key into the
# private temp folder only.
openssl pkey -in "${sk_key}" -passin pass:snakeoil -out "${work}/snakeoil.key" 2>/dev/null
openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=AIENOS throwaway not-in-db/" \
    -keyout "${work}/wrong.key" -out "${work}/wrong.crt" 2>/dev/null

mkimg() { # name source
    mkdir -p "${work}/$1/esp/EFI/BOOT" "${work}/$1/esp/EFI/AIENOS"
    touch "${work}/$1/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/$1/esp/EFI/BOOT/BOOTAA64.EFI"
}

sbsign --key "${work}/snakeoil.key" --cert "${sk_crt}" --output "${work}/signed.efi" "${efi}" 2>/dev/null
sbverify --cert "${sk_crt}" "${work}/signed.efi" >/dev/null 2>&1 \
    || { echo "FAIL  sbverify does not accept our own snakeoil signature"; exit 1; }
sbsign --key "${work}/wrong.key" --cert "${work}/wrong.crt" --output "${work}/wrongkey.efi" "${efi}" 2>/dev/null

# Flip one byte in the middle of the image (inside the code, which the
# Authenticode hash covers; the appended signature is at the end).
cp "${work}/signed.efi" "${work}/tampered.efi"
size="$(stat -c %s "${efi}")"
off=$((size / 2))
orig="$(od -An -tu1 -j "${off}" -N1 "${work}/tampered.efi" | tr -d ' ')"
printf "$(printf '\\%03o' $(((orig ^ 0xff) & 0xff)))" \
    | dd of="${work}/tampered.efi" bs=1 seek="${off}" conv=notrunc status=none
sbverify --cert "${sk_crt}" "${work}/tampered.efi" >/dev/null 2>&1 \
    && { echo "FAIL  tampered image still verifies (byte flip missed the hashed region)"; exit 1; }

mkimg signed "${work}/signed.efi"
mkimg unsigned "${efi}"
mkimg tampered "${work}/tampered.efi"
mkimg wrongkey "${work}/wrongkey.efi"

boot() { # name timeout
    local d="${work}/$1"
    cp "${vars_fd}" "${d}/vars.fd"
    set +e
    timeout "$2" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${d}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${d}/esp" \
        -device virtio-blk-pci,drive=esp \
        -device ramfb -display none -nic none \
        -serial file:"${d}/serial.log" -no-reboot >/dev/null 2>&1
    set -e
    tr -d '\r' <"${d}/serial.log" >"${d}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${d}/serial.txt" "${AIENOS_LOG_DIR}/gate4_secureboot_$1.log"
}

status=0
boot signed "${boot_timeout}"
if grep -q "kernel: alive" "${work}/signed/serial.txt"; then
    echo "PASS  signed with enrolled test key: booted to kernel alive (Secure Boot on)"
else
    echo "FAIL  signed image did not boot; refusals below would prove nothing"
    tail -n 20 "${work}/signed/serial.txt"
    exit 1
fi

for c in unsigned tampered wrongkey; do
    boot "${c}" "${reject_timeout}"
    if grep -q "kernel: alive" "${work}/${c}/serial.txt"; then
        echo "FAIL  ${c} image booted with Secure Boot on"
        status=1
    elif grep -q "Access Denied" "${work}/${c}/serial.txt"; then
        # EFI_ACCESS_DENIED from LoadImage is the firmware signature verdict.
        echo "PASS  ${c} image refused by firmware signature check (Access Denied)"
    else
        echo "FAIL  ${c} image did not boot, but no Access Denied verdict was logged"
        status=1
    fi
done

if [[ ${status} -eq 0 ]]; then
    echo "TRUST-1 Gate 4 Secure Boot signing test: ALL PASS"
fi
exit "${status}"
