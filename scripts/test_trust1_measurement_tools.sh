#!/usr/bin/env bash
# test_trust1_measurement_tools.sh: host self-test for the TRUST-1 Gate 0/2
# read-only tools, run against a software TPM (swtpm). No hardware access:
# PCRs come from swtpm, Secure Boot variables from a fake efivars folder,
# and the firmware event log is absent.
#
# Checks: capture works and is self-consistent; compare finds no change
# between identical states and names the PCR that changed; the Gate 2
# receipt records a restored rollback and stops on an unrestored one; a
# tampered capture is refused; the credential header decoder reads a
# synthetic credential and its --live check follows PCR 7.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
campaign="${repo_root}/scripts/tpm_measurement_campaign.sh"
credpol="${repo_root}/scripts/trust1_credential_policy.sh"

# FLAG(sovereignty): tpm2-tools (outside dep) required on Linux host; replace with in-house C TPM tool.
for t in swtpm tpm2_pcrread tpm2_pcrextend tpm2_eventlog xxd; do
    command -v "${t}" >/dev/null || { echo "Error: ${t} not installed" >&2; exit 2; }
done

work="$(mktemp -d)"
cleanup() {
    [[ -z "${SWTPM_PID:-}" ]] || kill "${SWTPM_PID}" 2>/dev/null || true
    rm -rf "${work}"
}
trap cleanup EXIT

port=$((20000 + RANDOM % 20000))
mkdir -p "${work}/tpm"
swtpm socket --tpm2 --tpmstate dir="${work}/tpm" \
    --server type=tcp,port="${port}",bindaddr=127.0.0.1 \
    --ctrl type=tcp,port=$((port + 1)),bindaddr=127.0.0.1 \
    --flags not-need-init,startup-clear &
SWTPM_PID=$!
export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=${port}"
for _ in $(seq 1 50); do tpm2_pcrread sha256:0 >/dev/null 2>&1 && break; sleep 0.1; done
tpm2_pcrread sha256:0 >/dev/null

# Fake efivarfs: 4 attribute bytes + payload.
efi="${work}/efivars"
mkdir -p "${efi}"
g=8be4df61-93ca-11d2-aa0d-00e098032b8c
s=d719b2cb-3d3a-4596-a3bc-dad00e67656f
printf '\x06\x00\x00\x00\x01' >"${efi}/SecureBoot-${g}"
printf '\x06\x00\x00\x00\x00' >"${efi}/SetupMode-${g}"
for v in PK KEK; do printf '\x27\x00\x00\x00test-%s' "${v}" >"${efi}/${v}-${g}"; done
for v in db dbx; do printf '\x27\x00\x00\x00test-%s' "${v}" >"${efi}/${v}-${s}"; done
export AIENOS_EFIVARS_DIR="${efi}" AIENOS_EVENTLOG="${work}/no-eventlog"

fail() { echo "FAIL  $*"; exit 1; }
pass() { echo "PASS  $*"; }

bash "${campaign}" capture "${work}/a" state-a >/dev/null
bash "${campaign}" capture "${work}/b" state-b >/dev/null
grep -q '^secure_boot=1$' "${work}/a/capture.env" || fail "secure_boot byte not read"
grep -q '^eventlog_replay=no_eventlog$' "${work}/a/capture.env" || fail "absent event log not recorded"
bash "${campaign}" compare "${work}/a" "${work}/b" >/dev/null || fail "identical states reported as changed"
pass "capture + compare: identical states compare equal"

bash "${campaign}" capture "${work}/a" again >/dev/null 2>&1 && fail "capture overwrote an existing directory"
pass "capture refuses to overwrite"

tpm2_pcrextend 7:sha256=$(printf '%064d' 1) >/dev/null
bash "${campaign}" capture "${work}/c" state-c >/dev/null
set +e
out="$(bash "${campaign}" compare "${work}/a" "${work}/c")"; rc=$?
set -e
[[ ${rc} -eq 3 ]] || fail "compare exit ${rc}, expected 3 after PCR 7 extend"
grep -q '^CHANGED pcr_sha256_7 ' <<<"${out}" || fail "compare did not name PCR 7"
[[ "$(grep -c '^CHANGED' <<<"${out}")" -eq 1 ]] || fail "compare reported more than PCR 7"
pass "compare names exactly PCR 7 after one extend"

bash "${campaign}" receipt --variable test-extend --before "${work}/a" --after "${work}/c" \
    --post-rollback "${work}/b" --explain "self-test" --out "${work}/r1.json" >/dev/null \
    || fail "restored rollback not recorded"
grep -q '"rollback_restored": true' "${work}/r1.json" || fail "r1 rollback_restored not true"
grep -q 'pcr_sha256_7' "${work}/r1.json" || fail "r1 does not list PCR 7 as changed"
set +e
bash "${campaign}" receipt --variable test-unrestored --before "${work}/a" --after "${work}/c" \
    --post-rollback "${work}/c" --prev "${work}/r1.json" --out "${work}/r2.json" >/dev/null; rc=$?
set -e
[[ ${rc} -eq 4 ]] || fail "unrestored rollback exit ${rc}, expected 4"
grep -q '"result": "STOP_UNEXPECTED_STATE"' "${work}/r2.json" || fail "r2 not STOP"
grep -q "\"previous_receipt_sha256\": \"$(sha256sum "${work}/r1.json" | cut -d' ' -f1)\"" "${work}/r2.json" \
    || fail "r2 not chained to r1"
pass "receipt: restored rollback RECORDED, unrestored STOP, chained"

echo extra >"${work}/b/extra.txt"
bash "${campaign}" compare "${work}/a" "${work}/b" >/dev/null 2>&1 && fail "added file not detected"
echo x >>"${work}/c/capture.env"
bash "${campaign}" compare "${work}/a" "${work}/c" >/dev/null 2>&1 && fail "edited capture not detected"
pass "tampered captures refused"

# Synthetic host+tpm2 credential header bound to PolicyPCR(sha256, PCR 7).
pcr7="$(tpm2_pcrread sha256:7 | awk '$1 == 7 { sub(/^0x/, "", $3); print tolower($3) }')"
pd="$(printf '%s' "${pcr7}" | xxd -r -p | sha256sum | cut -d' ' -f1)"
policy="$(printf '%064d%s%s%s' 0 0000017f 00000001000b03800000 "${pd}" | xxd -r -p | sha256sum | cut -d' ' -f1)"
{
    printf '93a8940948744490' ; printf '90caf2fc93cab553'          # type id host+tpm2
    printf '20000000010000000c00000010000000'                        # key, block, iv, tag sizes
    printf '%032d' 0                                                  # iv (12) padded to 16
    printf '8000000000000000' ; printf '0b00' ; printf '2300'        # mask, bank, primary
    printf '08000000' ; printf '20000000'                            # blob 8 bytes, policy 32
    printf '%016d' 0                                                  # blob
    printf '%s' "${policy}"
    printf '%064d' 0                                                  # trailing ciphertext stand-in
} | xxd -r -p | base64 >"${work}/test.cred"
dec="$(bash "${credpol}" --live "${work}/test.cred")" || fail "decoder rejected matching credential"
grep -q 'type=host+tpm2' <<<"${dec}" || fail "type not decoded"
grep -q 'pcrs=7$' <<<"${dec}" || fail "PCR mask not decoded"
grep -q 'pcr_bank=sha256' <<<"${dec}" || fail "bank not decoded"
grep -q "policy_hash=${policy}" <<<"${dec}" || fail "policy hash not decoded"
grep -q 'policy_matches_live_pcrs=yes' <<<"${dec}" || fail "live policy should match"
tpm2_pcrextend 7:sha256=$(printf '%064d' 2) >/dev/null
bash "${credpol}" --live "${work}/test.cred" >"${work}/dec2.txt" && fail "decoder accepted after PCR 7 changed"
grep -q 'policy_matches_live_pcrs=no' "${work}/dec2.txt" || fail "live mismatch not reported"
pass "credential decoder: header decoded, --live follows PCR 7"

echo "TRUST-1 measurement tools self-test: ALL PASS"
