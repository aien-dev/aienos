#!/usr/bin/env bash
# test_trust1_key_ceremony.sh: self-test for trust1_key_ceremony.sh with
# THROWAWAY keys in a private temp folder (deleted on exit). Never an owner
# key. Checks: generate + verify; private keys are stored encrypted; two
# backups each decrypt from their own copy; the record holds no private
# material; a changed manifest, a swapped public key, and a wrong
# passphrase are each refused; the Boot Signer cert can sign and verify an
# EFI image (when sbsign/sbverify and a built loader are present).

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tool="${repo_root}/scripts/trust1_key_ceremony.sh"
OPENSSL="${AIENOS_OPENSSL:-openssl}"

work="$(mktemp -d)"
trap 'rm -rf --one-file-system "${work}"' EXIT
chmod 700 "${work}"

fail() { echo "FAIL  $*"; exit 1; }
pass() { echo "PASS  $*"; }

printf 'throwaway-test-passphrase\n' >"${work}/pass"
export AIENOS_CEREMONY_PASS_FILE="${work}/pass"
out="${work}/ceremony"

bash "${tool}" generate "${out}" --allow-online >/dev/null || fail "generate"
bash "${tool}" verify "${out}/public" >/dev/null || fail "verify after generate"
pass "generate: four keys and a root-signed manifest that verifies"

for k in "${out}"/private/*.key.pem; do
    grep -q "BEGIN ENCRYPTED PRIVATE KEY" "${k}" || fail "$(basename "${k}") not encrypted"
done
[[ "$(find "${out}/private" -type f | wc -l)" -eq 4 ]] || fail "unexpected files in private/"
pass "every private key is stored encrypted"

bash "${tool}" generate "${out}" --allow-online >/dev/null 2>&1 && fail "generate overwrote a ceremony"
pass "generate refuses to overwrite"

mkdir -p "${work}/mediaA" "${work}/mediaB"
bash "${tool}" backup "${out}" "${work}/mediaA" backup-A >/dev/null || fail "backup A"
bash "${tool}" backup "${out}" "${work}/mediaB" backup-B >/dev/null || fail "backup B"
bash "${tool}" record "${out}" >/dev/null || fail "record"
grep -q '^backup_count=2$' "${out}/public/ceremony_record.txt" || fail "record backup count"
grep -rq "PRIVATE KEY" "${out}/public" && fail "private material in public/"
pass "two backups decrypt from their own copies; record has no private material"

printf 'wrong-passphrase-123\n' >"${work}/wrongpass"
mkdir -p "${work}/mediaC"
AIENOS_CEREMONY_PASS_FILE="${work}/wrongpass" bash "${tool}" backup "${out}" "${work}/mediaC" backup-C \
    >/dev/null 2>&1 && fail "backup accepted a wrong passphrase"
pass "a wrong passphrase cannot open the backup copy"

cp -r "${out}/public" "${work}/tampered"
sed -i.bak 's/^generation=1$/generation=2/' "${work}/tampered/authority_manifest.txt"
rm -f "${work}/tampered/authority_manifest.txt.bak"
bash "${tool}" verify "${work}/tampered" >/dev/null 2>&1 && fail "changed manifest verified"
pass "a changed manifest is refused"

cp -r "${out}/public" "${work}/swapped"
"${OPENSSL}" genpkey -algorithm ed25519 -out "${work}/other.pem" 2>/dev/null
"${OPENSSL}" pkey -in "${work}/other.pem" -pubout -out "${work}/swapped/release_signer.pub.pem"
bash "${tool}" verify "${work}/swapped" >/dev/null 2>&1 && fail "swapped release key verified"
pass "a swapped public key is refused"

# Rotation: add -> verify (old and new both trusted) -> revoke (only new).
cp -r "${out}/public" "${work}/gen1snap"
printf 'release payload\n' >"${work}/payload"
"${OPENSSL}" pkeyutl -sign -rawin -inkey "${out}/private/release_signer.key.pem" -passin file:"${work}/pass" \
    -in "${work}/payload" -out "${work}/payload.oldsig"
bash "${tool}" rotate "${out}" release_signer add >/dev/null || fail "rotate add"
grep -q '^generation=2$' "${out}/public/authority_manifest.txt" || fail "add did not make generation 2"
grep -q '^role\.release_signer\.next\.pub_sha256=' "${out}/public/authority_manifest.txt" || fail "next key not in manifest"
"${OPENSSL}" pkeyutl -verify -rawin -pubin -inkey "${out}/public/release_signer.pub.pem" \
    -in "${work}/payload" -sigfile "${work}/payload.oldsig" >/dev/null 2>&1 || fail "old key stopped verifying during transition"
pass "rotation add: generation 2 trusts old and new release keys; old signatures still verify"
bash "${tool}" rotate "${out}" release_signer revoke >/dev/null || fail "rotate revoke"
grep -q '^generation=3$' "${out}/public/authority_manifest.txt" || fail "revoke did not make generation 3"
grep -q '^role\.release_signer\.revoked_pub_sha256=' "${out}/public/authority_manifest.txt" || fail "old key not listed revoked"
"${OPENSSL}" pkeyutl -verify -rawin -pubin -inkey "${out}/public/release_signer.pub.pem" \
    -in "${work}/payload" -sigfile "${work}/payload.oldsig" >/dev/null 2>&1 && fail "revoked key still current"
ls "${out}"/private/release_signer.gen2.revoked.key.pem >/dev/null || fail "old key not quarantined"
pass "rotation revoke: generation 3 trusts only the new key; old key quarantined, not deleted"
bash "${tool}" rotate "${out}" owner_root add >/dev/null 2>&1 && fail "rotate allowed owner_root"
pass "owner_root cannot be rotated by the routine tool (special recovery ceremony only)"
bash "${tool}" verify "${work}/gen1snap" 1 >/dev/null || fail "intact generation 1 snapshot refused at minimum 1"
bash "${tool}" verify "${work}/gen1snap" 3 >/dev/null 2>&1 && fail "rollback to generation 1 accepted"
bash "${tool}" verify "${out}/public" 3 >/dev/null || fail "current generation 3 refused"
pass "a validly signed older generation is refused when generation 3 is the minimum"

efi="${repo_root}/target/aarch64-unknown-uefi/release/aienos-handoff.efi"
if command -v sbsign >/dev/null && command -v sbverify >/dev/null && [[ -f "${efi}" ]]; then
    "${OPENSSL}" pkey -in "${out}/private/boot_signer.key.pem" -passin file:"${work}/pass" \
        -out "${work}/bs.key" 2>/dev/null
    sbsign --key "${work}/bs.key" --cert "${out}/public/boot_signer.crt.pem" \
        --output "${work}/signed.efi" "${efi}" 2>/dev/null
    sbverify --cert "${out}/public/boot_signer.crt.pem" "${work}/signed.efi" >/dev/null 2>&1 \
        || fail "Boot Signer signature does not verify"
    pass "Boot Signer cert signs and verifies the EFI loader (sbsign/sbverify)"
else
    echo "SKIP  Boot Signer EFI signing (sbsign, sbverify or built loader missing)"
fi

echo "TRUST-1 key ceremony self-test (throwaway keys): ALL PASS"
