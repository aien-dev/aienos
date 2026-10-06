#!/usr/bin/env bash
# native_boot_preflight.sh -- READ-ONLY preflight before an attended one-time
# native AIENOS boot on the Spark (docs/native/PREFLIGHT-AND-RECOVERY.md
# section 2). It only reads: `efibootmgr` with no arguments, the SecureBoot
# EFI variable file, findmnt, git status, the image file and the quiet flag.
# It never writes a variable, never stages, never reboots, needs no sudo.
#
# Usage: bash scripts/native_boot_preflight.sh [--image EFI [--expect-sha256 HEX]]
#        bash scripts/native_boot_preflight.sh --self-test   (canned inputs, no machine state)
#
# Checks, one line each (PASS / STOP / INFO); the last line is
#   NATIVE_PREFLIGHT: READY        every STOP-class check passed
#   NATIVE_PREFLIGHT: NOT_READY    at least one STOP line (exit 1)
# Items Drake does in person (at the machine, display and keyboard attached,
# fresh go-ahead for this boot) cannot be read by a script: they are printed
# as ASK lines and never counted as passed.
#
# Environment (for the self-test and for reading a saved capture):
#   AIENOS_PREFLIGHT_EFIBOOTMGR  file holding saved `efibootmgr` output
#   AIENOS_PREFLIGHT_SECUREBOOT  path of the SecureBoot variable file
#   AIENOS_PREFLIGHT_ESP         ESP mount point (default /boot/efi)
#   AIENOS_QUIET_FLAG            quiet flag path (default ~/workspace/.spark-quiet)
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
default_entry="0001"
recov_entry="0004"
recov_label="AIENOSRECOV"
sb_default="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

# preflight EFIBOOTMGR_TEXT SB_FILE ESP QUIET_FLAG TREE_STATUS IMAGE EXPECT
# Prints the check lines; returns 0 READY, 1 NOT_READY.
preflight() {
    local boot="$1" sb="$2" esp="$3" quiet="$4" tree="$5" image="$6" expect="$7" stops=0
    stop() { echo "STOP  $*"; stops=$((stops + 1)); }
    ok() { echo "PASS  $*"; }
    echo "ASK   Drake is at the machine with a display and keyboard attached, and gave a fresh go-ahead for this boot"
    if [[ -z "${boot}" ]]; then
        stop "efibootmgr gave no output (not a UEFI Linux host, or efibootmgr missing)"
    else
        local order next current recov
        order="$(sed -n 's/^BootOrder: //p' <<<"${boot}")"
        next="$(sed -n 's/^BootNext: //p' <<<"${boot}")"
        current="$(sed -n 's/^BootCurrent: //p' <<<"${boot}")"
        recov="$(grep -E "^Boot${recov_entry}\*? " <<<"${boot}" || true)"
        echo "INFO  BootCurrent=${current:-?} BootOrder=${order:-?}"
        [[ "${recov}" == *"${recov_label}"* ]] && ok "recovery stick: Boot${recov_entry} ${recov_label} listed" \
            || stop "recovery stick: Boot${recov_entry} ${recov_label} not listed (got '${recov:-none}'); plug it in, see docs/RECOVERY_MEDIA_MACHINE1.md"
        [[ "${order%%,*}" == "${default_entry}" ]] && ok "BootOrder starts with ${default_entry} (Linux, the permanent default)" \
            || stop "BootOrder does not start with ${default_entry} (got '${order:-none}')"
        [[ -z "${next}" ]] && ok "BootNext is not set (no other one-time boot pending)" \
            || stop "BootNext is already set (${next}); another staging is pending"
        [[ "${current}" == "${default_entry}" ]] && ok "running from Boot${default_entry} (Linux)" \
            || stop "BootCurrent is '${current:-?}', not ${default_entry}: not booted from the default entry"
    fi
    if [[ -r "${sb}" ]]; then
        local b; b="$(od -An -t u1 -j 4 -N 1 "${sb}" | tr -d ' ')"
        case "${b}" in
            0) echo "INFO  Secure Boot: off (recorded only; development decision 2026-10-01; a release needs it on; never flip it here)" ;;
            1) stop "Secure Boot: on; the unsigned C image would be refused (Secure Boot Violation); do not turn it off as part of this procedure" ;;
            *) stop "Secure Boot variable unreadable (byte 4 = '${b}')" ;;
        esac
    else
        stop "Secure Boot variable ${sb} not readable"
    fi
    if [[ -n "$(findmnt -no SOURCE "${esp}" 2>/dev/null)" ]]; then ok "ESP mounted at ${esp}"; else stop "ESP not mounted at ${esp}"; fi
    if [[ -e "${quiet}" ]]; then stop "quiet flag ${quiet} is held: $(head -c 120 "${quiet}" 2>/dev/null)"; else ok "no quiet flag held (no other hardware run)"; fi
    if [[ -z "${tree}" ]]; then ok "working tree clean"; else stop "working tree not clean ($(wc -l <<<"${tree}") entries): the image must map to one commit"; fi
    if [[ -n "${image}" ]]; then
        if [[ -r "${image}" ]]; then
            local d; d="$(sha256sum "${image}" | cut -c1-64)"
            echo "INFO  image ${image} sha256=${d}"
            if [[ -n "${expect}" ]]; then
                [[ "${d}" == "${expect,,}" ]] && ok "image digest equals the expected digest (from scripts/ck_repro_build.sh)" \
                    || stop "image digest ${d} differs from the expected ${expect}"
            else
                echo "ASK   compare this digest with the CK_REPRO_BUILD line for this commit (--expect-sha256 checks it)"
            fi
        else
            stop "image ${image} not readable"
        fi
    fi
    echo "ASK   the candidate is the one-time BootNext entry; Linux (Boot${default_entry}) stays first in BootOrder; the stage script makes the pre-boot capture itself"
    if [[ ${stops} == 0 ]]; then echo "NATIVE_PREFLIGHT: READY (read-only checks only; the ASK lines are Drake's)"; return 0; fi
    echo "NATIVE_PREFLIGHT: NOT_READY (${stops} STOP)"
    return 1
}

if [[ "${1:-}" == --self-test ]]; then
    st=0; t="$(mktemp -d)"; trap 'rm -rf "${t}"' EXIT
    good=$'BootCurrent: 0001\nTimeout: 5 seconds\nBootOrder: 0001,0003\nBoot0001* ubuntu\nBoot0003* UEFI PXE\nBoot0004* AIENOSRECOV'
    printf '\0\0\0\0\0' >"${t}/sb_off"; printf '\0\0\0\0\1' >"${t}/sb_on"
    esp="/"   # any mounted path stands in for the ESP in the self-test
    printf 'img' >"${t}/img"; dig="$(sha256sum "${t}/img" | cut -c1-64)"
    case_() { # label want(0|1) boot sb quiet tree image expect
        local rc=0; preflight "$3" "$4" "${esp}" "$5" "$6" "$7" "$8" >"${t}/out" 2>&1 || rc=1
        if [[ "${rc}" == "$2" ]]; then echo "PASS  $1"; else echo "FAIL  $1 (wanted $2, got ${rc})"; cat "${t}/out"; st=1; fi
    }
    case_ "good state is READY" 0 "${good}" "${t}/sb_off" "${t}/noflag" "" "${t}/img" "${dig}"
    case_ "BootNext pending -> NOT_READY" 1 "${good}"$'\nBootNext: 0000' "${t}/sb_off" "${t}/noflag" "" "" ""
    case_ "recovery stick absent -> NOT_READY" 1 "${good/Boot0004\* AIENOSRECOV/}" "${t}/sb_off" "${t}/noflag" "" "" ""
    case_ "BootOrder not Linux first -> NOT_READY" 1 "${good/BootOrder: 0001,0003/BootOrder: 0000,0001}" "${t}/sb_off" "${t}/noflag" "" "" ""
    case_ "booted from another entry -> NOT_READY" 1 "${good/BootCurrent: 0001/BootCurrent: 0004}" "${t}/sb_off" "${t}/noflag" "" "" ""
    case_ "Secure Boot on -> NOT_READY" 1 "${good}" "${t}/sb_on" "${t}/noflag" "" "" ""
    case_ "Secure Boot variable missing -> NOT_READY" 1 "${good}" "${t}/nosb" "${t}/noflag" "" "" ""
    touch "${t}/flag"
    case_ "quiet flag held -> NOT_READY" 1 "${good}" "${t}/sb_off" "${t}/flag" "" "" ""
    case_ "dirty tree -> NOT_READY" 1 "${good}" "${t}/sb_off" "${t}/noflag" " M x" "" ""
    case_ "image digest mismatch -> NOT_READY" 1 "${good}" "${t}/sb_off" "${t}/noflag" "" "${t}/img" "00${dig:2}"
    case_ "no efibootmgr output -> NOT_READY" 1 "" "${t}/sb_off" "${t}/noflag" "" "" ""
    # The script must stay read-only: no variable-writing efibootmgr flag, no sudo, no reboot.
    if grep -nE '(^|[^#]*)(efibootmgr +-[a-zA-Z]|--bootnext|--bootorder|--create|sudo |reboot|systemctl|chattr|dd |mkfs)' "${BASH_SOURCE[0]}" \
        | grep -vE "^[0-9]+: *#|grep -nE|^[0-9]+: *echo " >/dev/null; then
        echo "FAIL  script contains a writing command"; st=1
    else
        echo "PASS  script contains no writing command (efibootmgr flags, sudo, reboot, chattr, dd, mkfs)"
    fi
    if [[ ${st} == 0 ]]; then echo "NATIVE_PREFLIGHT_SELF_TEST: PASS"; exit 0; fi
    echo "NATIVE_PREFLIGHT_SELF_TEST: FAIL"; exit 1
fi

image="" expect=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) image="${2:-}"; shift 2 ;;
        --expect-sha256) expect="${2:-}"; shift 2 ;;
        *) echo "usage: $0 [--image EFI [--expect-sha256 HEX]] | --self-test"; exit 2 ;;
    esac
done
if [[ -n "${AIENOS_PREFLIGHT_EFIBOOTMGR:-}" ]]; then
    boot="$(cat "${AIENOS_PREFLIGHT_EFIBOOTMGR}" 2>/dev/null || true)"
else
    boot="$(efibootmgr 2>/dev/null || true)"
fi
tree="$(git -C "${repo_root}" status --porcelain --untracked-files=normal 2>/dev/null || echo '?? not a git checkout')"
echo "commit: $(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || echo unknown)"
preflight "${boot}" "${AIENOS_PREFLIGHT_SECUREBOOT:-${sb_default}}" "${AIENOS_PREFLIGHT_ESP:-/boot/efi}" \
    "${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}" "${tree}" "${image}" "${expect}"
