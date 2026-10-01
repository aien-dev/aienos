#!/usr/bin/env bash
# trust1_credential_policy.sh: show which TPM policy seals a systemd credential.
#
# TRUST-1 Gate 0 (G7) and Gate 6. Reads only the public header of an
# encrypted systemd credential file (`systemd-creds encrypt` output, raw or
# base64). It never decrypts, never contacts the TPM and never prints the
# sealed blob or ciphertext. Output per file: sealing type, PCR mask and the
# PCR indices it names, PCR bank, TPM primary key algorithm, and the policy
# digest the TPM will demand (a public hash, not a secret).
#
# Header layout (systemd src/shared/creds-util.c, struct
# encrypted_credential_header then tpm2_credential_header):
#   0x00 id[16]  0x10 key_size u32  0x14 block_size u32  0x18 iv_size u32
#   0x1c tag_size u32  0x20 iv[iv_size] padded to 8 bytes
#   then pcr_mask u64, pcr_bank u16, primary_alg u16, blob_size u32,
#   policy_hash_size u32, blob[blob_size] padded to 8, policy_hash[...]
#
# With --live, it also recomputes the TPM2 PolicyPCR digest from the PCR
# values the TPM reports now (tpm2_pcrread, read-only) and prints
# policy_matches_live_pcrs=yes|no: "yes" means this credential would unseal
# with the current boot state, "no" means it would refuse.
#
# Usage: trust1_credential_policy.sh [--live] FILE...   (root may be needed to
# read /etc/credstore.encrypted; reading a header changes nothing.)

set -euo pipefail

live=0
if [[ "${1:-}" == "--live" ]]; then live=1; shift; fi
[[ $# -ge 1 ]] || { sed -n "2,24p" "$0"; exit 2; }

hexdump_file() {
    # Whole file as one lowercase hex string. Base64 credentials are decoded
    # first; systemd writes them with line breaks.
    local f="$1"
    if LC_ALL=C grep -qv '^[A-Za-z0-9+/=]*$' "${f}"; then
        od -An -v -tx1 "${f}"
    else
        base64 -d "${f}" | od -An -v -tx1
    fi | tr -d ' \n'
}

# Little-endian unsigned integer of N bytes at byte offset O.
le() {
    local hex="$1" off="$2" n="$3" out="" i
    for ((i = n - 1; i >= 0; i--)); do out+="${hex:$(((off + i) * 2)):2}"; done
    echo $((16#${out}))
}

align8() { echo $((($1 + 7) / 8 * 8)); }

type_name() {
    case "$1" in
        0c7cc07b-1176-4591-9c4b-0bea08bc20fe) echo "tpm2-only" ;;
        93a89409-4874-4490-90ca-f2fc93cab553) echo "host+tpm2" ;;
        *) echo "unknown" ;;
    esac
}

bank_name() {
    case "$1" in 4) echo sha1 ;; 11) echo sha256 ;; 12) echo sha384 ;; 13) echo sha512 ;; *) echo "alg-$1" ;; esac
}

alg_name() {
    case "$1" in 1) echo rsa ;; 35) echo ecc ;; *) echo "alg-$1" ;; esac
}

hex_to_bin() { xxd -r -p; }

# TPM2 PolicyPCR digest for a fresh session:
#   SHA256(00*32 || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || SHA256(PCR values))
# with TPML_PCR_SELECTION = count(1) || hashAlg || sizeofSelect(3) || bitmap.
live_policy_digest() {
    local mask="$1" bank="$2" bankname values="" i sel
    bankname="$(bank_name "${bank}")"
    for ((i = 0; i < 24; i++)); do
        if (((mask >> i) & 1)); then
            values+="$(tpm2_pcrread "${bankname}:${i}" | awk -v i="${i}" '$1 == i && $2 == ":" { sub(/^0x/, "", $3); print tolower($3) }')"
        fi
    done
    [[ -n "${values}" ]] || return 1
    sel="$(printf '%02x%02x%02x' $((mask & 255)) $(((mask >> 8) & 255)) $(((mask >> 16) & 255)))"
    local pcr_digest
    pcr_digest="$(printf '%s' "${values}" | hex_to_bin | sha256sum | cut -d' ' -f1)"
    printf '%064d%s%s%04x%s%s%s' 0 0000017f 00000001 "${bank}" 03 "${sel}" "${pcr_digest}" \
        | hex_to_bin | sha256sum | cut -d' ' -f1
}

status=0
for f in "$@"; do
    hex="$(hexdump_file "${f}")"
    if [[ ${#hex} -lt 128 ]]; then
        echo "file=${f} error=too_short"; status=1; continue
    fi
    id="${hex:0:8}-${hex:8:4}-${hex:12:4}-${hex:16:4}-${hex:20:12}"
    kind="$(type_name "${id}")"
    iv_size="$(le "${hex}" 24 4)"
    echo "file=${f}"
    echo "  file_sha256=$(sha256sum "${f}" | cut -d' ' -f1)"
    echo "  type_id=${id}"
    echo "  type=${kind}"
    if [[ "${kind}" == unknown ]]; then
        echo "  error=unknown_type_id (not decoded; add the id only after checking systemd source)"
        status=1
        continue
    fi
    t=$((32 + $(align8 "${iv_size}")))
    mask="$(le "${hex}" "${t}" 8)"
    bank="$(le "${hex}" $((t + 8)) 2)"
    palg="$(le "${hex}" $((t + 10)) 2)"
    blob="$(le "${hex}" $((t + 12)) 4)"
    phs="$(le "${hex}" $((t + 16)) 4)"
    pcrs=""
    for ((i = 0; i < 24; i++)); do
        if (((mask >> i) & 1)); then pcrs+="${pcrs:+,}${i}"; fi
    done
    pol_off=$((t + 20 + $(align8 "${blob}")))
    printf '  pcr_mask=0x%x\n' "${mask}"
    echo "  pcrs=${pcrs:-none}"
    echo "  pcr_bank=$(bank_name "${bank}")"
    echo "  primary_alg=$(alg_name "${palg}")"
    echo "  sealed_blob_bytes=${blob}"
    echo "  policy_hash_bytes=${phs}"
    if [[ "${phs}" -gt 0 && "${phs}" -le 64 ]]; then
        policy="${hex:$((pol_off * 2)):$((phs * 2))}"
        echo "  policy_hash=${policy}"
        if [[ ${live} -eq 1 ]]; then
            expect="$(live_policy_digest "${mask}" "${bank}")" || expect="unavailable"
            echo "  live_policy_digest=${expect}"
            if [[ "${expect}" == "${policy}" ]]; then
                echo "  policy_matches_live_pcrs=yes"
            else
                echo "  policy_matches_live_pcrs=no"
                status=1
            fi
        fi
    fi
done
exit "${status}"
