#!/usr/bin/env bash
# tpm_measurement_campaign.sh: TRUST-1 Gate 0 / Gate 2 measurement tool.
#
# Read-only on the machine. It never writes efivars, never changes boot
# entries, never touches TPM objects, never reads secrets. It only reads PCR
# banks, the firmware event log, Secure Boot variables (public certificate
# lists), boot entries and version strings, and writes them into OUT_DIR.
#
# Subcommands:
#   capture OUT_DIR [LABEL]       one snapshot of the measured boot state
#   compare DIR_A DIR_B           item-by-item diff of two snapshots
#                                 exit 0 = identical, 3 = differences found
#   receipt --variable NAME --before DIR --after DIR --post-rollback DIR
#           [--prev RECEIPT] [--baseline RECEIPT] [--explain TEXT] --out FILE
#                                 Gate 2 per-experiment receipt (JSON)
#   OUT_DIR                       legacy form, same as `capture OUT_DIR`
#
# FLAG(sovereignty): requires tpm2-tools (outside dep), Linux host only; replace with in-house C tool.
# Requirements: tpm2-tools (tpm2_pcrread, tpm2_eventlog), read access to
# /dev/tpmrm0 and the event log (member of group tss), sha256sum.
# TPM2TOOLS_TCTI may point at a software TPM for host testing.

set -euo pipefail

die() { echo "Error: $*" >&2; exit 2; }

sb_vars=(PK KEK db dbx)
efi_global=8be4df61-93ca-11d2-aa0d-00e098032b8c
efi_imgsec=d719b2cb-3d3a-4596-a3bc-dad00e67656f
efivars_dir="${AIENOS_EFIVARS_DIR:-/sys/firmware/efi/efivars}"
eventlog_path="${AIENOS_EVENTLOG:-/sys/kernel/security/tpm0/binary_bios_measurements}"

var_guid() {
    case "$1" in
        PK|KEK|SecureBoot|SetupMode|BootOrder|BootCurrent) echo "${efi_global}" ;;
        db|dbx) echo "${efi_imgsec}" ;;
        *) die "unknown variable $1" ;;
    esac
}

# Normalize `tpm2_pcrread <bank>` or the `pcrs:` block of tpm2_eventlog into
# "INDEX HEX" lines, lowercase, sorted as text (the order `join` needs).
# Both tools print "  7 : 0x.." for one-digit and "  10: 0x.." (or "10 :")
# for two-digit indices.
normalize_pcrs() {
    local bank="$1"
    awk -v bank="${bank}" '
        $1 == bank":" { inb = 1; next }
        inb && /^ *[a-z0-9]+:$/ { inb = 0; next }
        inb && match($0, /^ *[0-9]+ *: *0x[0-9A-Fa-f]+/) {
            line = $0; gsub(/[ :]+/, " ", line); sub(/^ /, "", line)
            split(line, f, " "); printf "%d %s\n", f[1], tolower(f[2])
        }
    ' | sort -k1,1
}

efivar_byte() {
    # Last byte of a one-byte efivar (4 attribute bytes + value).
    local f="${efivars_dir}/$1-$(var_guid "$1")"
    [[ -r "${f}" ]] || { echo "unreadable"; return; }
    od -An -tu1 -j4 -N1 "${f}" | tr -d ' '
}

cmd_capture() {
    local out="${1:?capture needs OUT_DIR}" label="${2:-unlabelled}"
    [[ "${label}" =~ ^[A-Za-z0-9._-]+$ ]] || die "label must match [A-Za-z0-9._-]+"
    [[ ! -e "${out}" ]] || die "${out} already exists; captures are never overwritten"
    # FLAG(sovereignty): tpm2_pcrread/tpm2_eventlog (outside dep), Linux host only; replace with in-house C PCR reader and event-log parser.
    command -v tpm2_pcrread >/dev/null || die "tpm2_pcrread not installed"
    command -v tpm2_eventlog >/dev/null || die "tpm2_eventlog not installed"
    mkdir -p "${out}/efivars"

    # PCR banks. SHA-256 is mandatory; SHA-1/SHA-384 are recorded if present.
    tpm2_pcrread sha256 >"${out}/pcr_sha256.txt" || die "tpm2_pcrread sha256 failed"
    normalize_pcrs sha256 <"${out}/pcr_sha256.txt" >"${out}/pcr_sha256.norm"
    [[ "$(wc -l <"${out}/pcr_sha256.norm")" -ge 8 ]] || die "fewer than 8 SHA-256 PCRs read"
    local bank
    for bank in sha1 sha384; do
        if tpm2_pcrread "${bank}" >"${out}/pcr_${bank}.txt" 2>"${out}/pcr_${bank}.err"; then
            normalize_pcrs "${bank}" <"${out}/pcr_${bank}.txt" >"${out}/pcr_${bank}.norm"
            rm -f "${out}/pcr_${bank}.err"
            [[ -s "${out}/pcr_${bank}.norm" ]] || rm -f "${out}/pcr_${bank}.norm"
        fi
    done

    # Event log: copy, digest, parse, and replay. Parser correctness check:
    # every PCR the log replays must equal the live PCR value.
    local ev_sha="absent" ev_size=0 replay_result="no_eventlog"
    if [[ -r "${eventlog_path}" ]]; then
        cat "${eventlog_path}" >"${out}/eventlog.bin"
        ev_sha="$(sha256sum "${out}/eventlog.bin" | cut -d' ' -f1)"
        ev_size="$(wc -c <"${out}/eventlog.bin")"
        tpm2_eventlog "${out}/eventlog.bin" >"${out}/eventlog_parsed.yaml" \
            || die "tpm2_eventlog could not parse the event log"
        sed -n '/^pcrs:/,$p' "${out}/eventlog_parsed.yaml" | normalize_pcrs sha256 \
            >"${out}/eventlog_replay_sha256.norm"
        [[ -s "${out}/eventlog_replay_sha256.norm" ]] || die "event log replay produced no SHA-256 PCRs"
        if join "${out}/eventlog_replay_sha256.norm" "${out}/pcr_sha256.norm" \
            | awk '{ print $1, ($2 == $3 ? "match" : "MISMATCH") }' >"${out}/eventlog_replay_check.txt" \
            && ! grep -q MISMATCH "${out}/eventlog_replay_check.txt"; then
            replay_result="match"
        else
            replay_result="mismatch"
        fi
    fi

    # Secure Boot variables: public certificate/hash lists. The digest covers
    # the efivarfs file bytes (4 attribute bytes + EFI_SIGNATURE_LIST data).
    local v f sums=""
    for v in "${sb_vars[@]}"; do
        f="${efivars_dir}/${v}-$(var_guid "${v}")"
        if [[ -r "${f}" ]]; then
            cat "${f}" >"${out}/efivars/${v}.efivar"
            sums+="${v}_efivar_sha256=$(sha256sum "${out}/efivars/${v}.efivar" | cut -d' ' -f1)"$'\n'
        else
            sums+="${v}_efivar_sha256=unreadable"$'\n'
        fi
    done

    efibootmgr -v >"${out}/boot_entries.txt" 2>&1 || echo "efibootmgr failed" >>"${out}/boot_entries.txt"
    if command -v mokutil >/dev/null; then
        mokutil --list-enrolled 2>/dev/null | grep -E 'SHA1 Fingerprint|Subject:' >"${out}/mok_enrolled.txt" || true
    fi

    {
        echo "capture_label=${label}"
        echo "capture_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "host=$(uname -n)"
        echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
        echo "uptime_s=$(cut -d' ' -f1 /proc/uptime 2>/dev/null || echo unknown)"
        echo "kernel_release=$(uname -r)"
        echo "firmware_version=$(cat /sys/class/dmi/id/bios_version 2>/dev/null || echo unknown)"
        echo "firmware_date=$(cat /sys/class/dmi/id/bios_date 2>/dev/null || echo unknown)"
        echo "secure_boot=$(efivar_byte SecureBoot)"
        echo "setup_mode=$(efivar_byte SetupMode)"
        printf '%s' "${sums}"
        echo "eventlog_sha256=${ev_sha}"
        echo "eventlog_size=${ev_size}"
        echo "eventlog_replay=${replay_result}"
        echo "boot_current=$(awk '/^BootCurrent:/ {print $2}' "${out}/boot_entries.txt")"
        echo "boot_order=$(awk '/^BootOrder:/ {print $2}' "${out}/boot_entries.txt")"
        echo "boot_next=$(awk '/^BootNext:/ {print $2}' "${out}/boot_entries.txt")"
        # FLAG(sovereignty): systemctl (systemd) queried on Linux host; remove, read fwupd state another way or drop the line.
        echo "fwupd_refresh_timer=$(systemctl is-enabled fwupd-refresh.timer 2>/dev/null || echo unknown)"
        echo "pcr_banks_with_values=$(cd "${out}" && ls pcr_*.norm | sed "s/pcr_//; s/.norm//" | paste -sd, -)"
        # FLAG(sovereignty): tpm2_pcrread --version used only to record tool version; drop with tpm2-tools.
        echo "tpm2_tools=$(tpm2_pcrread --version 2>/dev/null | sed -n 's/.*version="\([^"]*\)".*/\1/p')"
    } >"${out}/capture.env"

    (cd "${out}" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
    echo "capture_digest=$(sha256sum "${out}/SHA256SUMS" | cut -d' ' -f1)"
    echo "eventlog_replay=${replay_result}"
    echo "TPM measurement capture saved to ${out}"
    [[ "${replay_result}" != "mismatch" ]] || { echo "STOP: event log replay does not match live PCRs" >&2; exit 4; }
}

env_get() { sed -n "s/^$2=//p" "$1/capture.env"; }

# Prints one line per compared item: "SAME item" or "CHANGED item old -> new".
diff_items() {
    local a="$1" b="$2" k
    join -a1 -a2 -e missing -o 0,1.2,2.2 "${a}/pcr_sha256.norm" "${b}/pcr_sha256.norm" \
        | awk '{ if ($2 == $3) print "SAME pcr_sha256_" $1; else print "CHANGED pcr_sha256_" $1, $2, "->", $3 }'
    for k in PK_efivar_sha256 KEK_efivar_sha256 db_efivar_sha256 dbx_efivar_sha256 \
        secure_boot setup_mode eventlog_sha256 boot_order firmware_version kernel_release fwupd_refresh_timer; do
        local va vb
        va="$(env_get "${a}" "${k}")"; vb="$(env_get "${b}" "${k}")"
        if [[ "${va}" == "${vb}" ]]; then echo "SAME ${k}"; else echo "CHANGED ${k} ${va:-empty} -> ${vb:-empty}"; fi
    done
}

check_capture() {
    [[ -f "$1/capture.env" && -f "$1/pcr_sha256.norm" && -f "$1/SHA256SUMS" ]] || die "$1 is not a capture directory"
    (cd "$1" && sha256sum --quiet -c SHA256SUMS) || die "$1 failed its own SHA256SUMS check"
    local listed present
    listed="$(sed "s/^[0-9a-f]*  //" "$1/SHA256SUMS" | sort)"
    present="$(cd "$1" && find . -type f ! -name SHA256SUMS | sort)"
    [[ "${listed}" == "${present}" ]] || die "$1 has files added or removed since capture"
}

cmd_compare() {
    local a="${1:?compare needs DIR_A}" b="${2:?compare needs DIR_B}"
    check_capture "${a}"; check_capture "${b}"
    echo "A: $(env_get "${a}" capture_label) boot_id=$(env_get "${a}" boot_id)"
    echo "B: $(env_get "${b}" capture_label) boot_id=$(env_get "${b}" boot_id)"
    local lines
    lines="$(diff_items "${a}" "${b}")"
    grep '^CHANGED' <<<"${lines}" || true
    local changed
    changed="$(grep -c '^CHANGED' <<<"${lines}" || true)"
    echo "compared=$(wc -l <<<"${lines}") changed=${changed}"
    [[ "${changed}" -eq 0 ]] || exit 3
}

json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r\t')"; }

capture_json() {
    printf '{"label":%s,"boot_id":%s,"capture_utc":%s,"capture_digest":%s}' \
        "$(json_str "$(env_get "$1" capture_label)")" "$(json_str "$(env_get "$1" boot_id)")" \
        "$(json_str "$(env_get "$1" capture_utc)")" \
        "$(json_str "$(sha256sum "$1/SHA256SUMS" | cut -d' ' -f1)")"
}

changed_json() {
    local first=1 line
    printf '['
    while IFS= read -r line; do
        [[ "${line}" == CHANGED* ]] || continue
        [[ ${first} -eq 1 ]] || printf ','
        first=0
        json_str "${line#CHANGED }"
    done <<<"$(diff_items "$1" "$2")"
    printf ']'
}

cmd_receipt() {
    local variable="" before="" after="" post="" prev="" baseline="" explain="" out=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --variable) variable="$2"; shift 2 ;;
            --before) before="$2"; shift 2 ;;
            --after) after="$2"; shift 2 ;;
            --post-rollback) post="$2"; shift 2 ;;
            --prev) prev="$2"; shift 2 ;;
            --baseline) baseline="$2"; shift 2 ;;
            --explain) explain="$2"; shift 2 ;;
            --out) out="$2"; shift 2 ;;
            *) die "unknown receipt option $1" ;;
        esac
    done
    [[ -n "${variable}" && -n "${before}" && -n "${after}" && -n "${post}" && -n "${out}" ]] \
        || die "receipt needs --variable --before --after --post-rollback --out"
    [[ ! -e "${out}" ]] || die "${out} already exists; receipts are never overwritten"
    check_capture "${before}"; check_capture "${after}"; check_capture "${post}"
    local prev_sha="none" base_sha="none"
    [[ -z "${prev}" ]] || prev_sha="$(sha256sum "${prev}" | cut -d' ' -f1)"
    [[ -z "${baseline}" ]] || base_sha="$(sha256sum "${baseline}" | cut -d' ' -f1)"

    local restored=true result=RECORDED
    local rollback_diff
    rollback_diff="$(diff_items "${before}" "${post}")"
    if grep -q '^CHANGED' <<<"${rollback_diff}"; then
        restored=false
        result=STOP_UNEXPECTED_STATE
    fi
    {
        printf '{\n  "schema_version": "1.0.0",\n  "receipt_type": "trust1_gate2_measurement",\n'
        printf '  "variable": %s,\n' "$(json_str "${variable}")"
        printf '  "explanation": %s,\n' "$(json_str "${explain}")"
        printf '  "before": %s,\n' "$(capture_json "${before}")"
        printf '  "after": %s,\n' "$(capture_json "${after}")"
        printf '  "post_rollback": %s,\n' "$(capture_json "${post}")"
        printf '  "changed_by_mutation": %s,\n' "$(changed_json "${before}" "${after}")"
        printf '  "not_restored_after_rollback": %s,\n' "$(changed_json "${before}" "${post}")"
        printf '  "rollback_restored": %s,\n' "${restored}"
        printf '  "previous_receipt_sha256": %s,\n' "$(json_str "${prev_sha}")"
        printf '  "baseline_receipt_sha256": %s,\n' "$(json_str "${base_sha}")"
        printf '  "result": %s\n}\n' "$(json_str "${result}")"
    } >"${out}"
    echo "receipt=${out} sha256=$(sha256sum "${out}" | cut -d' ' -f1) result=${result}"
    [[ "${result}" == RECORDED ]] || exit 4
}

case "${1:-}" in
    capture) shift; cmd_capture "$@" ;;
    compare) shift; cmd_compare "$@" ;;
    receipt) shift; cmd_receipt "$@" ;;
    ""|-h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) cmd_capture "$1" "${2:-unlabelled}" ;;
esac
