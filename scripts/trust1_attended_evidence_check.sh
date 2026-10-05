#!/usr/bin/env bash
# trust1_attended_evidence_check.sh: HOST VALIDATION ONLY.
#
# Reads evidence that an attended TRUST-1 sitting left behind and says whether
# the evidence is well formed and bound to what the operator expects. It
# REJECTS missing, mismatched (wrong digest or candidate), partial and failing
# records. It does not and cannot prove the physical event happened: a file
# can be forged. ACCEPT means "this record is internally consistent and
# matches the digests you named", never "the boot or ceremony was done".
# Gate rows in scripts/trust1_m5_qualify.sh stay NOT_RUN (BLOCKED_OPERATOR /
# BLOCKED_HARDWARE) until the physical event is recorded by the operator; this
# tool is not wired into those rows.
#
# Read-only: no sudo, no TPM, no efivar or disk writes. Works on files only.
#
# Subcommands (each prints REJECT lines with the reason, then one verdict):
#   gate1 COLLECTOR_LOG --expect-test-sha SHA [--expect-loader-sha SHA]
#       Gate 1 attended recovery-stick boot: output of
#       scripts/collect_recovery_boot_evidence.sh. Needs Secure Boot ON.
#   gate0-stability DIR1 DIR2 DIR3 [DIR...] [--expect-secure-boot 0|1 (default 1)]
#                   [--expect-pcr7 HEX] [--expect-firmware VERSION]
#       Gate 0 cold-boot PCR stability: three or more capture folders made by
#       scripts/tpm_measurement_campaign.sh capture. The operator must give
#       cold boots only (a warm restart legitimately moves PCR1); this tool
#       cannot tell the difference.
#   gate2-receipt RECEIPT.json --before DIR --after DIR --post-rollback DIR
#                 [--expect-baseline-sha SHA] [--expect-variable NAME]
#       Gate 2 per-experiment receipt written by tpm_measurement_campaign.sh
#       receipt. The three capture folders are required; their digests must match
#       the receipt (a missing folder is a partial record and is rejected).
#   gate3 PUBLIC_DIR --expect-manifest-sha SHA
#       Gate 3 key ceremony public folder (ceremony_record.txt, manifest).
#       Runs scripts/trust1_key_ceremony.sh verify when openssl is usable.
#
# Output: "HOST VALIDATION ONLY" banner, REJECT/NOTE lines, and
#   TRUST1_ATTENDED_EVIDENCE <gate>: ACCEPT | REJECT (n reasons)
# Exit: 0 ACCEPT, 1 REJECT, 2 usage error.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REASONS=0
GATE="?"

banner() { echo "HOST VALIDATION ONLY: checks recorded files, does not prove the physical event happened"; }
usage() { sed -n '/^# Subcommands/,/^# Exit/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
rej() { echo "REJECT  $*"; REASONS=$((REASONS + 1)); }
note() { echo "NOTE    $*"; }
is_sha() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
verdict() {
    if [[ "${REASONS}" -eq 0 ]]; then
        echo "TRUST1_ATTENDED_EVIDENCE ${GATE}: ACCEPT (host validation only)"
        exit 0
    fi
    echo "TRUST1_ATTENDED_EVIDENCE ${GATE}: REJECT (${REASONS} reason(s))"
    exit 1
}
need_sha_arg() { # name value
    [[ -n "$2" ]] || { echo "usage: $1 is required" >&2; exit 2; }
    is_sha "$2" || { echo "usage: $1 must be 64 lowercase hex characters" >&2; exit 2; }
}

# ------------------------------------------------------------------ gate 1
cmd_gate1() {
    GATE="gate1"
    local log="${1:-}" test_sha="" loader_sha=""
    [[ -n "${log}" ]] || usage
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --expect-test-sha) test_sha="${2:-}"; shift 2 ;;
            --expect-loader-sha) loader_sha="${2:-}"; shift 2 ;;
            *) echo "usage: unknown option $1" >&2; exit 2 ;;
        esac
    done
    need_sha_arg --expect-test-sha "${test_sha}"
    [[ -z "${loader_sha}" ]] || need_sha_arg --expect-loader-sha "${loader_sha}"
    banner
    if [[ ! -s "${log}" ]]; then rej "collector log missing or empty: ${log}"; verdict; fi

    local pass_n fail_n
    pass_n="$(grep -c '^RECOVERY_BOOT_GATE: PASS$' "${log}")"
    fail_n="$(grep -c '^RECOVERY_BOOT_GATE: FAIL$' "${log}")"
    [[ "${fail_n}" -eq 0 ]] || rej "log contains RECOVERY_BOOT_GATE: FAIL"
    [[ "${pass_n}" -eq 1 ]] || rej "log has ${pass_n} 'RECOVERY_BOOT_GATE: PASS' lines (need exactly 1; a cut-off log has none)"
    if grep -q '^FAIL  ' "${log}"; then rej "log contains failing checks: $(grep '^FAIL  ' "${log}" | head -n 3 | tr '\n' ';')"; fi
    local c
    for c in booted_from_removable_media secure_boot_state_recorded nvme_root_mounted pcrs_read \
        event_log_recorded esp_loaders_hashed recovery_unlock_readonly test_artifact_round_trip; do
        grep -q "^PASS  ${c}:" "${log}" || rej "required check '${c}' has no PASS line (missing or partial record)"
    done
    if grep -q '^recovery_unlock: not authorized' "${log}"; then rej "recovery unlock was not run (partial record)"; fi
    grep -qx 'secure_boot_byte: 1' "${log}" || rej "Secure Boot was not recorded ON (need 'secure_boot_byte: 1'; Gate 1 requires Secure Boot ON)"
    local got
    got="$(sed -n 's/^test_artifact: .* sha256=\([0-9a-f]\{64\}\)$/\1/p' "${log}" | head -n 1)"
    if [[ -z "${got}" ]]; then
        rej "no 'test_artifact: ... sha256=' line (test file not read back)"
    elif [[ "${got}" != "${test_sha}" ]]; then
        rej "test file digest mismatch: log ${got}, expected ${test_sha}"
    fi
    if [[ -n "${loader_sha}" ]] && ! grep -q "^efi_image: .* sha256=${loader_sha}\$" "${log}"; then
        rej "no efi_image line with expected loader digest ${loader_sha} (wrong candidate loader)"
    fi
    verdict
}

# -------------------------------------------------------- gate 0 stability
env_get() { sed -n "s/^$2=//p" "$1/capture.env" | head -n 1; }
pcr_get() { awk -v n="$2" '$1 == n { print $2 }' "$1/pcr_sha256.norm"; }

# Prints the reason to stdout; returns 0 if the capture folder is intact.
capture_intact() {
    local d="$1" f listed present
    for f in capture.env pcr_sha256.norm SHA256SUMS; do
        [[ -f "${d}/${f}" ]] || { echo "${d}: missing ${f} (partial capture)"; return 1; }
    done
    if ! (cd "${d}" && sha256sum --quiet -c SHA256SUMS >/dev/null 2>&1); then
        echo "${d}: files do not match its SHA256SUMS (tampered or damaged)"; return 1
    fi
    listed="$(sed 's/^[0-9a-f]*  //' "${d}/SHA256SUMS" | sort)"
    present="$(cd "${d}" && find . -type f ! -name SHA256SUMS | sort)"
    [[ "${listed}" == "${present}" ]] || { echo "${d}: files added or removed since capture"; return 1; }
    [[ "$(wc -l <"${d}/pcr_sha256.norm")" -ge 8 ]] || { echo "${d}: fewer than 8 SHA-256 PCRs (partial capture)"; return 1; }
    return 0
}

cmd_gate0_stability() {
    GATE="gate0-stability"
    local dirs=() sb=1 want7="" want_fw=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --expect-secure-boot) sb="${2:-}"; shift 2 ;;
            --expect-pcr7) want7="${2:-}"; shift 2 ;;
            --expect-firmware) want_fw="${2:-}"; shift 2 ;;
            --*) echo "usage: unknown option $1" >&2; exit 2 ;;
            *) dirs+=("$1"); shift ;;
        esac
    done
    [[ "${sb}" == 0 || "${sb}" == 1 ]] || { echo "usage: --expect-secure-boot is 0 or 1" >&2; exit 2; }
    [[ ${#dirs[@]} -ge 1 ]] || usage
    banner
    [[ ${#dirs[@]} -ge 3 ]] || rej "${#dirs[@]} capture folder(s) given; stability needs at least 3 boots"
    local d msg bid ok=() ids=""
    for d in "${dirs[@]}"; do
        if msg="$(capture_intact "${d}")"; then
            ok+=("${d}")
        else
            rej "${msg}"; continue
        fi
        [[ "$(env_get "${d}" eventlog_replay)" == "match" ]] || rej "${d}: event log replay is '$(env_get "${d}" eventlog_replay)', not 'match'"
        [[ "$(env_get "${d}" secure_boot)" == "${sb}" ]] || rej "${d}: secure_boot=$(env_get "${d}" secure_boot), expected ${sb}"
        [[ "$(env_get "${d}" setup_mode)" == "0" ]] || rej "${d}: setup_mode=$(env_get "${d}" setup_mode), expected 0"
        bid="$(env_get "${d}" boot_id)"
        if [[ -z "${bid}" || "${bid}" == unknown ]]; then rej "${d}: no usable boot_id"
        elif grep -qx "${bid}" <<<"${ids}"; then rej "${d}: boot_id ${bid} repeats an earlier folder (same boot counted twice)"
        else ids+="${bid}"$'\n'; fi
        [[ -z "${want_fw}" || "$(env_get "${d}" firmware_version)" == "${want_fw}" ]] \
            || rej "${d}: firmware_version=$(env_get "${d}" firmware_version), expected ${want_fw}"
        [[ -z "${want7}" || "$(pcr_get "${d}" 7)" == "0x${want7#0x}" ]] \
            || rej "${d}: PCR7 $(pcr_get "${d}" 7) differs from expected ${want7} (wrong candidate state)"
    done
    # Compare every intact folder with the first intact one.
    if [[ ${#ok[@]} -ge 2 ]]; then
        local ref="${ok[0]}" k va vb
        for d in "${ok[@]:1}"; do
            for k in 0 1 2 3 4 5 6 7; do
                va="$(pcr_get "${ref}" "${k}")"; vb="$(pcr_get "${d}" "${k}")"
                [[ "${va}" == "${vb}" ]] || rej "PCR${k} changed between ${ref} and ${d} (not stable; variation must be explained, not accepted)"
            done
            for k in PK_efivar_sha256 KEK_efivar_sha256 db_efivar_sha256 dbx_efivar_sha256 firmware_version; do
                [[ "$(env_get "${ref}" "${k}")" == "$(env_get "${d}" "${k}")" ]] || rej "${k} changed between ${ref} and ${d}"
                [[ "$(env_get "${d}" "${k}")" != "unreadable" ]] || rej "${d}: ${k} unreadable (partial capture)"
            done
        done
    fi
    note "cannot tell cold from warm restarts; the operator must supply cold boots only"
    verdict
}

# ------------------------------------------------------------- gate 2 receipt
cmd_gate2_receipt() {
    GATE="gate2-receipt"
    local rc="${1:-}" base="" var="" before="" after="" post=""
    [[ -n "${rc}" ]] || usage
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --expect-baseline-sha) base="${2:-}"; shift 2 ;;
            --expect-variable) var="${2:-}"; shift 2 ;;
            --before) before="${2:-}"; shift 2 ;;
            --after) after="${2:-}"; shift 2 ;;
            --post-rollback) post="${2:-}"; shift 2 ;;
            *) echo "usage: unknown option $1" >&2; exit 2 ;;
        esac
    done
    [[ -z "${base}" ]] || need_sha_arg --expect-baseline-sha "${base}"
    command -v jq >/dev/null || { echo "usage: jq is required" >&2; exit 2; }
    banner
    if [[ ! -s "${rc}" ]]; then rej "receipt missing or empty: ${rc}"; verdict; fi
    if ! jq -e . "${rc}" >/dev/null 2>&1; then rej "receipt is not valid JSON"; verdict; fi
    local f
    for f in receipt_type variable before after post_rollback changed_by_mutation not_restored_after_rollback \
        rollback_restored previous_receipt_sha256 baseline_receipt_sha256 result; do
        jq -e "has(\"${f}\")" "${rc}" >/dev/null 2>&1 || rej "receipt lacks field '${f}' (partial record)"
    done
    [[ "$(jq -r '.receipt_type // ""' "${rc}")" == "trust1_gate2_measurement" ]] || rej "receipt_type is not trust1_gate2_measurement"
    [[ "$(jq -r '.result // ""' "${rc}")" == "RECORDED" ]] || rej "result is '$(jq -r '.result // "absent"' "${rc}")', not RECORDED (failing record)"
    [[ "$(jq -r '.rollback_restored // ""' "${rc}")" == "true" ]] || rej "rollback_restored is not true"
    [[ "$(jq -r '(.not_restored_after_rollback // ["x"]) | length' "${rc}")" == "0" ]] || rej "items not restored after rollback"
    [[ -z "${var}" || "$(jq -r '.variable // ""' "${rc}")" == "${var}" ]] || rej "variable is '$(jq -r '.variable // ""' "${rc}")', expected '${var}'"
    local rb
    rb="$(jq -r '.baseline_receipt_sha256 // ""' "${rc}")"
    if [[ -n "${base}" && "${rb}" != "${base}" ]]; then rej "baseline_receipt_sha256 '${rb}' does not match expected ${base} (wrong chain)"; fi
    local pair key dir want got msg
    for pair in "before:${before}" "after:${after}" "post_rollback:${post}"; do
        key="${pair%%:*}"; dir="${pair#*:}"
        if [[ -z "${dir}" ]]; then rej "${key}: capture folder not given (--${key/_/-}); its digest cannot be checked (partial evidence)"; continue; fi
        if [[ ! -f "${dir}/SHA256SUMS" ]]; then rej "${key}: folder ${dir} has no SHA256SUMS"; continue; fi
        want="$(jq -r ".${key}.capture_digest // \"\"" "${rc}")"
        got="$(sha256sum "${dir}/SHA256SUMS" | cut -d' ' -f1)"
        [[ "${want}" == "${got}" ]] || rej "${key}: receipt digest '${want:-absent}' does not match folder digest ${got}"
        if ! msg="$(capture_intact "${dir}")"; then rej "${msg}"; fi
    done
    verdict
}

# ------------------------------------------------------------------ gate 3
cmd_gate3() {
    GATE="gate3"
    local pub="${1:-}" want=""
    [[ -n "${pub}" ]] || usage
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --expect-manifest-sha) want="${2:-}"; shift 2 ;;
            *) echo "usage: unknown option $1" >&2; exit 2 ;;
        esac
    done
    need_sha_arg --expect-manifest-sha "${want}"
    banner
    local rec="${pub}/ceremony_record.txt" man="${pub}/authority_manifest.txt"
    if [[ ! -f "${rec}" ]]; then rej "ceremony_record.txt missing in ${pub}"; verdict; fi
    if [[ ! -f "${man}" ]]; then rej "authority_manifest.txt missing in ${pub}"; verdict; fi
    grep -qx 'aienos_key_ceremony_record=1' "${rec}" || rej "record header 'aienos_key_ceremony_record=1' missing"
    local rv actual r ra ma n sig out
    rv="$(sed -n 's/^manifest_sha256=//p' "${rec}" | head -n 1)"
    actual="$(sha256sum "${man}" | cut -d' ' -f1)"
    [[ "${rv}" == "${actual}" ]] || rej "record manifest_sha256 '${rv:-absent}' does not match the manifest file ${actual} (altered after the record)"
    [[ "${actual}" == "${want}" ]] || rej "manifest digest ${actual} does not match expected ${want} (wrong candidate)"
    if grep -q 'PRIVATE KEY' "${rec}" "${man}"; then rej "private key material found in the public record"; fi
    for r in owner_root boot_signer release_signer operator_approval; do
        ra="$(sed -n "s/^role\\.${r}\\.pub_sha256=//p" "${rec}" | head -n 1)"
        ma="$(sed -n "s/^role\\.${r}\\.pub_sha256=//p" "${man}" | head -n 1)"
        if [[ -z "${ra}" ]]; then rej "record has no fingerprint line for role ${r} (partial record)"
        elif [[ "${ra}" != "${ma}" ]]; then rej "role ${r} fingerprint in the record differs from the manifest"; fi
    done
    n="$(sed -n 's/^backup_count=//p' "${rec}" | head -n 1)"
    if ! [[ "${n:-}" =~ ^[0-9]+$ ]] || [[ "${n}" -lt 2 ]]; then rej "backup_count '${n:-absent}' is below 2 (Gate 3 needs two verified backups)"; fi
    [[ "$(grep -c '^backup ' "${rec}")" -ge 2 ]] || rej "fewer than two 'backup ' lines in the record"
    grep -qx 'firmware_changed=no' "${rec}" || rej "'firmware_changed=no' missing (Gate 3 must not touch firmware)"
    sig="$(sed -n 's/^operator_signature=//p' "${rec}" | head -n 1)"
    if [[ -z "${sig}" || "${sig}" == "<operator signs here"* ]]; then rej "operator signature not filled in (still the placeholder)"; fi
    if command -v openssl >/dev/null 2>&1 && [[ -f "${repo_root}/scripts/trust1_key_ceremony.sh" ]]; then
        if ! out="$(bash "${repo_root}/scripts/trust1_key_ceremony.sh" verify "${pub}" 2>&1)"; then
            rej "trust1_key_ceremony.sh verify failed: $(tail -n 2 <<<"${out}" | tr '\n' ' ')"
        fi
    else
        note "openssl not available: manifest signature NOT re-verified"
    fi
    verdict
}

sub="${1:-}"
[[ -n "${sub}" ]] || usage
shift
case "${sub}" in
    gate1) cmd_gate1 "$@" ;;
    gate0-stability) cmd_gate0_stability "$@" ;;
    gate2-receipt) cmd_gate2_receipt "$@" ;;
    gate3) cmd_gate3 "$@" ;;
    -h|--help|help) usage ;;
    *) echo "usage: unknown subcommand ${sub}" >&2; usage ;;
esac
