#!/usr/bin/env bash
# test_trust1_attended_evidence_check.sh: HOST VALIDATION ONLY fixture tests
# for scripts/trust1_attended_evidence_check.sh. Every fixture is synthetic or
# made with throwaway keys in a temp folder; nothing touches Machine 1, a TPM,
# firmware, boot media or a real key.
#
# For every gate the checker must ACCEPT one good record and REJECT each of:
# missing, mismatched (wrong digest or candidate), partial and failing records.
# Negative control: the whole suite is first run against a stub checker that
# accepts everything; that run must be RED (catch nothing). Then the real
# checker must be GREEN. Marker on success:
#   TRUST1_ATTENDED_EVIDENCE_CHECK self-test (HOST VALIDATION ONLY): ALL PASS
# Env: AIENOS_QUIET_FLAG is not used; no chip or QEMU is started.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
real="${repo_root}/scripts/trust1_attended_evidence_check.sh"
campaign="${repo_root}/scripts/tpm_measurement_campaign.sh"
ceremony="${repo_root}/scripts/trust1_key_ceremony.sh"
for t in jq sha256sum openssl; do command -v "${t}" >/dev/null || { echo "Error: ${t} not installed" >&2; exit 2; }; done

work="$(mktemp -d)"
trap 'rm -rf --one-file-system "${work}"' EXIT
chmod 700 "${work}"
echo "HOST VALIDATION ONLY: fixture tests, no hardware, throwaway keys"

# ------------------------------------------------------------------ fixtures
hex() { printf '%064x' "$1"; }
make_capture() { # dir label boot_id secure_boot pcr7_seed [pcr1_seed]
    local d="$1" i
    mkdir -p "${d}/efivars"
    for i in 0 1 2 3 4 5 6 7 10; do
        local seed="${i}"
        [[ "${i}" == 7 ]] && seed="${5}"
        [[ "${i}" == 1 && -n "${6:-}" ]] && seed="${6}"
        echo "${i} 0x$(hex "$((seed + 100))")"
    done >"${d}/pcr_sha256.norm"
    echo "fake pcrs" >"${d}/pcr_sha256.txt"
    echo "fake efivar" >"${d}/efivars/PK.efivar"
    {
        echo "capture_label=$2"; echo "capture_utc=2026-10-05T00:00:00Z"; echo "host=fixture"
        echo "boot_id=$3"; echo "firmware_version=5.36_0ACUM018"
        echo "secure_boot=$4"; echo "setup_mode=0"
        echo "PK_efivar_sha256=$(hex 1)"; echo "KEK_efivar_sha256=$(hex 2)"
        echo "db_efivar_sha256=$(hex 3)"; echo "dbx_efivar_sha256=$(hex 4)"
        echo "eventlog_replay=match"
    } >"${d}/capture.env"
    (cd "${d}" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
}
resum() { (cd "$1" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS); }

TEST_SHA="$(hex 4242)"
LOADER_SHA="$(hex 7777)"
make_log() { # out
    cat >"$1" <<LOG
== recovery environment identity
captured_utc: 2026-10-05T00:00:00Z
PASS  booted_from_removable_media: root is /dev/ram0 (not the internal NVMe)
secure_boot_byte: 1
PASS  secure_boot_state_recorded: byte=1 (1=enabled)
PASS  nvme_root_mounted: findmnt /mnt/root
PASS  pcrs_read: tpm2_pcrread sha256
PASS  event_log_recorded: /sys/kernel/security/tpm0/binary_bios_measurements
efi_image: /EFI/ubuntu/shimaa64.efi sha256=$(hex 5555)
efi_image: /EFI/AIENOS/loader.efi sha256=${LOADER_SHA}
PASS  esp_loaders_hashed: 2 EFI image(s) hashed
PASS  recovery_unlock_readonly: store opened read-only with the offline spare
test_artifact: trust1-roundtrip-test.txt sha256=${TEST_SHA}
PASS  test_artifact_round_trip: expected ${TEST_SHA}
== verdict
RECOVERY_BOOT_GATE: PASS
LOG
}

# --------------------------------------------------------------------- suite
FAILS=0
CHECKER="${real}"
expect() { # want(accept|reject) name needle -- args...
    local want="$1" name="$2" needle="$3"; shift 4
    local out rc
    out="$(bash "${CHECKER}" "$@" 2>&1)"; rc=$?
    if [[ "${want}" == accept ]]; then
        if [[ "${rc}" -eq 0 && "${out}" == *"ACCEPT"* ]]; then echo "ok    accept: ${name}"; return; fi
    else
        if [[ "${rc}" -eq 1 && "${out}" == *"REJECT"* && "${out}" == *"${needle}"* ]]; then echo "ok    reject: ${name}"; return; fi
    fi
    echo "MISS  ${want} expected: ${name} (exit ${rc}; needle '${needle}')"
    FAILS=$((FAILS + 1))
}

run_suite() {
    FAILS=0
    local w="${work}/s$RANDOM"; mkdir -p "${w}"
    # ---- gate 1
    make_log "${w}/g1.log"
    expect accept "gate1 good log" "" -- gate1 "${w}/g1.log" --expect-test-sha "${TEST_SHA}" --expect-loader-sha "${LOADER_SHA}"
    expect reject "gate1 missing log" "missing or empty" -- gate1 "${w}/nope.log" --expect-test-sha "${TEST_SHA}"
    : >"${w}/empty.log"
    expect reject "gate1 empty log" "missing or empty" -- gate1 "${w}/empty.log" --expect-test-sha "${TEST_SHA}"
    expect reject "gate1 wrong test digest" "digest mismatch" -- gate1 "${w}/g1.log" --expect-test-sha "$(hex 9)"
    expect reject "gate1 wrong candidate loader" "wrong candidate loader" -- gate1 "${w}/g1.log" --expect-test-sha "${TEST_SHA}" --expect-loader-sha "$(hex 8)"
    sed '/^RECOVERY_BOOT_GATE/d;/^== verdict/d' "${w}/g1.log" >"${w}/g1-cut.log"
    expect reject "gate1 cut-off log (no verdict)" "cut-off log" -- gate1 "${w}/g1-cut.log" --expect-test-sha "${TEST_SHA}"
    sed 's/^PASS  test_artifact_round_trip:.*/FAIL  test_artifact_round_trip: expected x/;s/^RECOVERY_BOOT_GATE: PASS/RECOVERY_BOOT_GATE: FAIL/' "${w}/g1.log" >"${w}/g1-fail.log"
    expect reject "gate1 failing record" "failing checks" -- gate1 "${w}/g1-fail.log" --expect-test-sha "${TEST_SHA}"
    { cat "${w}/g1.log"; echo "RECOVERY_BOOT_GATE: FAIL"; } >"${w}/g1-both.log"
    expect reject "gate1 log with both PASS and FAIL verdicts" "contains RECOVERY_BOOT_GATE: FAIL" -- gate1 "${w}/g1-both.log" --expect-test-sha "${TEST_SHA}"
    sed '/recovery_unlock_readonly/d;/test_artifact/d;/^PASS  test_artifact/d' "${w}/g1.log" >"${w}/g1-part.log"
    echo 'recovery_unlock: not authorized for this run (set AIENOS_UNLOCK_CIPHER, AIENOS_UNLOCK_SPARE, AIENOS_UNLOCK_IDENTITY)' >>"${w}/g1-part.log"
    expect reject "gate1 partial (unlock not run)" "partial record" -- gate1 "${w}/g1-part.log" --expect-test-sha "${TEST_SHA}"
    sed 's/^secure_boot_byte: 1/secure_boot_byte: 0/' "${w}/g1.log" >"${w}/g1-sb0.log"
    expect reject "gate1 Secure Boot OFF" "Secure Boot was not recorded ON" -- gate1 "${w}/g1-sb0.log" --expect-test-sha "${TEST_SHA}"

    # ---- gate 0 stability
    make_capture "${w}/c1" b1 id-1 1 7; make_capture "${w}/c2" b2 id-2 1 7; make_capture "${w}/c3" b3 id-3 1 7
    expect accept "gate0 three identical cold captures" "" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/c3" --expect-pcr7 "$(hex 107)"
    expect reject "gate0 only two captures" "needs at least 3" -- gate0-stability "${w}/c1" "${w}/c2"
    expect reject "gate0 missing folder" "partial capture" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/none"
    make_capture "${w}/d3" b3 id-3 1 8
    expect reject "gate0 PCR7 moved" "PCR7 changed" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/d3"
    expect reject "gate0 wrong expected PCR7 (wrong candidate)" "wrong candidate state" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/c3" --expect-pcr7 "$(hex 999)"
    make_capture "${w}/e3" b3 id-3 1 7 50
    expect reject "gate0 PCR1 moved (warm-style)" "PCR1 changed" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/e3"
    cp -r "${w}/c3" "${w}/t3"; echo "0 0x$(hex 1)" >>"${w}/t3/pcr_sha256.norm"
    expect reject "gate0 tampered capture" "SHA256SUMS" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/t3"
    cp -r "${w}/c3" "${w}/p3"; rm "${w}/p3/capture.env"
    expect reject "gate0 partial capture (no capture.env)" "partial capture" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/p3"
    make_capture "${w}/s3" b3 id-3 0 7
    expect reject "gate0 Secure Boot OFF capture" "secure_boot=0" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/s3"
    make_capture "${w}/s1" b1 id-1 0 7; make_capture "${w}/s2" b2 id-2 0 7
    expect accept "gate0 OFF captures with --expect-secure-boot 0" "" -- gate0-stability "${w}/s1" "${w}/s2" "${w}/s3" --expect-secure-boot 0
    make_capture "${w}/r3" b3 id-1 1 7
    expect reject "gate0 same boot counted twice" "repeats an earlier folder" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/r3"
    cp -r "${w}/c3" "${w}/m3"; sed -i 's/^eventlog_replay=match/eventlog_replay=mismatch/' "${w}/m3/capture.env"; resum "${w}/m3"
    expect reject "gate0 event log replay mismatch" "not 'match'" -- gate0-stability "${w}/c1" "${w}/c2" "${w}/m3"

    # ---- gate 2 receipt (written by the real campaign tool from fixtures)
    make_capture "${w}/before" before id-b 1 7; make_capture "${w}/after" after id-a 1 8; make_capture "${w}/post" post id-p 1 7
    : >"${w}/baseline.json"; echo '{"baseline":1}' >"${w}/baseline.json"
    bash "${campaign}" receipt --variable timer --before "${w}/before" --after "${w}/after" --post-rollback "${w}/post" \
        --baseline "${w}/baseline.json" --out "${w}/r.json" >/dev/null 2>&1 || { echo "MISS  could not build gate2 fixture receipt"; FAILS=$((FAILS + 1)); }
    local bs; bs="$(sha256sum "${w}/baseline.json" | cut -d' ' -f1)"
    expect accept "gate2 good receipt with folders" "" -- gate2-receipt "${w}/r.json" --expect-baseline-sha "${bs}" --expect-variable timer \
        --before "${w}/before" --after "${w}/after" --post-rollback "${w}/post"
    expect reject "gate2 good receipt without capture folders" "capture folder not given" -- gate2-receipt "${w}/r.json" --expect-baseline-sha "${bs}" --expect-variable timer
    expect reject "gate2 good receipt missing post-rollback folder" "post_rollback: capture folder not given" -- gate2-receipt "${w}/r.json" --expect-baseline-sha "${bs}" --expect-variable timer --before "${w}/before" --after "${w}/after"
    expect reject "gate2 missing receipt" "missing or empty" -- gate2-receipt "${w}/none.json"
    echo '{ not json' >"${w}/bad.json"
    expect reject "gate2 garbage receipt" "not valid JSON" -- gate2-receipt "${w}/bad.json"
    jq 'del(.rollback_restored)' "${w}/r.json" >"${w}/r-part.json"
    expect reject "gate2 partial receipt (field removed)" "lacks field 'rollback_restored'" -- gate2-receipt "${w}/r-part.json"
    jq '.result="STOP_UNEXPECTED_STATE" | .rollback_restored=false' "${w}/r.json" >"${w}/r-fail.json"
    expect reject "gate2 failing receipt" "not RECORDED" -- gate2-receipt "${w}/r-fail.json"
    expect reject "gate2 wrong baseline digest" "wrong chain" -- gate2-receipt "${w}/r.json" --expect-baseline-sha "$(hex 5)"
    expect reject "gate2 wrong variable" "expected 'boot_order'" -- gate2-receipt "${w}/r.json" --expect-variable boot_order
    expect reject "gate2 folder does not match receipt digest" "does not match folder digest" -- gate2-receipt "${w}/r.json" --before "${w}/after"
    jq '.receipt_type="other"' "${w}/r.json" >"${w}/r-type.json"
    expect reject "gate2 wrong receipt type" "receipt_type" -- gate2-receipt "${w}/r-type.json"

    # ---- gate 3 (real ceremony tool, throwaway keys)
    local c="${w}/cer"
    printf 'throwaway-test-passphrase\n' >"${w}/pass"
    export AIENOS_CEREMONY_PASS_FILE="${w}/pass"
    mkdir -p "${w}/mA" "${w}/mB"
    if bash "${ceremony}" generate "${c}" --allow-online >/dev/null 2>&1 \
        && bash "${ceremony}" backup "${c}" "${w}/mA" backup-A >/dev/null 2>&1 \
        && bash "${ceremony}" backup "${c}" "${w}/mB" backup-B >/dev/null 2>&1 \
        && bash "${ceremony}" record "${c}" >/dev/null 2>&1; then
        local pub="${c}/public" ms
        ms="$(sha256sum "${pub}/authority_manifest.txt" | cut -d' ' -f1)"
        # a record the operator has not signed yet is a partial record
        expect reject "gate3 unsigned record (placeholder)" "placeholder" -- gate3 "${pub}" --expect-manifest-sha "${ms}"
        cp -r "${pub}" "${w}/signed"
        sed -i 's/^operator_signature=.*/operator_signature=fixture-operator-signature/' "${w}/signed/ceremony_record.txt"
        expect accept "gate3 good signed record" "" -- gate3 "${w}/signed" --expect-manifest-sha "${ms}"
        expect reject "gate3 wrong manifest digest (wrong candidate)" "wrong candidate" -- gate3 "${w}/signed" --expect-manifest-sha "$(hex 3)"
        expect reject "gate3 missing folder" "missing" -- gate3 "${w}/nope" --expect-manifest-sha "${ms}"
        cp -r "${w}/signed" "${w}/g3a"; sed -i 's/^backup_count=2/backup_count=1/;0,/^backup label=/{//d}' "${w}/g3a/ceremony_record.txt"
        expect reject "gate3 only one backup" "below 2" -- gate3 "${w}/g3a" --expect-manifest-sha "${ms}"
        cp -r "${w}/signed" "${w}/g3b"; sed -i '/^role\.release_signer\.pub_sha256=/d' "${w}/g3b/ceremony_record.txt"
        expect reject "gate3 partial record (role fingerprint missing)" "role release_signer" -- gate3 "${w}/g3b" --expect-manifest-sha "${ms}"
        cp -r "${w}/signed" "${w}/g3c"; sed -i 's/^generation=1$/generation=2/' "${w}/g3c/authority_manifest.txt"
        expect reject "gate3 manifest altered after record" "does not match the manifest file" -- gate3 "${w}/g3c" --expect-manifest-sha "${ms}"
        cp -r "${w}/signed" "${w}/g3d"; echo "-----BEGIN PRIVATE KEY-----" >>"${w}/g3d/ceremony_record.txt"
        expect reject "gate3 private material in record" "private key material" -- gate3 "${w}/g3d" --expect-manifest-sha "${ms}"
        cp -r "${w}/signed" "${w}/g3e"; sed -i 's/^firmware_changed=no/firmware_changed=yes/' "${w}/g3e/ceremony_record.txt"
        expect reject "gate3 firmware changed" "firmware_changed=no" -- gate3 "${w}/g3e" --expect-manifest-sha "${ms}"
        cp -r "${w}/signed" "${w}/g3f"; cp "${w}/g3c/authority_manifest.txt" "${w}/g3f/authority_manifest.txt"
        sed -i "s/^manifest_sha256=.*/manifest_sha256=$(sha256sum "${w}/g3f/authority_manifest.txt" | cut -d' ' -f1)/" "${w}/g3f/ceremony_record.txt"
        expect reject "gate3 re-pointed record, manifest signature fails" "verify failed" -- gate3 "${w}/g3f" --expect-manifest-sha "$(sha256sum "${w}/g3f/authority_manifest.txt" | cut -d' ' -f1)"
    else
        echo "MISS  could not build gate3 throwaway ceremony"; FAILS=$((FAILS + 1))
    fi
    unset AIENOS_CEREMONY_PASS_FILE
    # ---- usage
    local rc; bash "${CHECKER}" bogus >/dev/null 2>&1; rc=$?
    if [[ "${rc}" -eq 2 ]]; then echo "ok    usage: unknown subcommand exits 2"; else echo "MISS  usage exit ${rc}"; FAILS=$((FAILS + 1)); fi
    return 0
}

# Negative control: a stub that accepts everything must be caught.
stub="${work}/accept-all.sh"
printf '#!/usr/bin/env bash\necho "TRUST1_ATTENDED_EVIDENCE stub: ACCEPT"\nexit 0\n' >"${stub}"
echo "== RED run: stub checker that accepts everything"
CHECKER="${stub}"; run_suite >"${work}/red.log"; red_fails="${FAILS}"
grep -c '^MISS' "${work}/red.log" | sed 's/^/stub misses caught by the suite: /'
if [[ "${red_fails}" -lt 10 ]]; then echo "FAIL  the suite did not go red against an accept-all stub (${red_fails} misses)"; exit 1; fi
echo "== GREEN run: real checker"
CHECKER="${real}"; run_suite >"${work}/green.log"; grep -v "^ok" "${work}/green.log"
if [[ "${FAILS}" -ne 0 ]]; then echo "TRUST1_ATTENDED_EVIDENCE_CHECK self-test (HOST VALIDATION ONLY): FAIL (${FAILS})"; exit 1; fi
echo "checks passed: $(grep -c '^ok' "${work}/green.log")"
echo "TRUST1_ATTENDED_EVIDENCE_CHECK self-test (HOST VALIDATION ONLY): ALL PASS"
