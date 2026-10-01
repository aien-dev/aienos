#!/usr/bin/env bash
# trust1_key_ceremony.sh: TRUST-1 Gate 3 owner key ceremony tool.
#
# Run ONLY on the offline ceremony machine the operator chose, never on the
# Spark. Creates the generation-1 owner hierarchy:
#   owner_root         Ed25519  signs the authority manifest; never on the Spark
#   boot_signer        RSA-2048 self-signed X.509 (the cert UEFI db will hold
#                      later, at Gate 6; nothing is enrolled here)
#   release_signer     Ed25519  signs kernels/manifests under the loader
#   operator_approval  Ed25519  approves boundary changes; never boots
#
# Private keys are written ENCRYPTED from the start (openssl genpkey with a
# passphrase): no plaintext private key file is ever created. Public halves,
# the signed authority manifest and the ceremony record contain no private
# material and are the only things that leave the machine.
#
# Subcommands:
#   preflight [--allow-online]          tool versions; refuses if a network route exists
#   generate OUT_DIR [--allow-online]   create keys + signed manifest (OUT_DIR must not exist)
#   backup OUT_DIR DEST_DIR LABEL       copy encrypted keys to backup media, then
#                                       prove every key decrypts FROM THE COPY
#   verify PUBLIC_DIR [MIN_GEN]         check manifest signature, fingerprints and
#                                       that generation >= MIN_GEN (anti-rollback)
#   record OUT_DIR                      write public/ceremony_record.txt
#   rotate OUT_DIR ROLE add|revoke      rotate release_signer or operator_approval:
#                                       'add' signs a manifest trusting old AND new;
#                                       exercise recovery; then 'revoke' signs one
#                                       trusting only new (old key quarantined,
#                                       never deleted). Each step is a new generation.
#
# Passphrase: asked twice on the terminal, or from AIENOS_CEREMONY_PASS_FILE
# (self-test only). Works with OpenSSL 3 on Linux or macOS (set AIENOS_OPENSSL
# to a Homebrew openssl@3 binary; the macOS system LibreSSL is refused).
# Exit: 0 ok, 1 check failed, 2 usage or environment problem.

set -euo pipefail

OPENSSL="${AIENOS_OPENSSL:-openssl}"
ROLES="owner_root boot_signer release_signer operator_approval"

die() { echo "Error: $*" >&2; exit 2; }
sha256() { "${OPENSSL}" dgst -sha256 -r "$1" | cut -d' ' -f1; }
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

check_tools() {
    command -v "${OPENSSL}" >/dev/null || die "openssl not found"
    local v
    v="$("${OPENSSL}" version)"
    case "${v}" in
        "OpenSSL 3."*) ;;
        *) die "need OpenSSL 3 (found: ${v}); on macOS: brew install openssl@3 and set AIENOS_OPENSSL" ;;
    esac
}

network_route() {
    if command -v ip >/dev/null 2>&1; then
        ip route show default 2>/dev/null | grep -q . && return 0
        ip -6 route show default 2>/dev/null | grep -q . && return 0
        return 1
    fi
    if command -v route >/dev/null 2>&1; then
        route -n get default >/dev/null 2>&1 && return 0
        return 1
    fi
    return 0 # cannot tell: treat as online
}

preflight() {
    local allow_online="${1:-}"
    check_tools
    echo "openssl: $("${OPENSSL}" version)"
    echo "host: $(uname -s) $(uname -m)"
    if network_route; then
        if [[ "${allow_online}" == "--allow-online" ]]; then
            echo "network: ONLINE (allowed for a test run only)"
        else
            die "a network route exists; disconnect Wi-Fi and cables first (ceremony must be offline)"
        fi
    else
        echo "network: offline"
    fi
}

get_pass() {
    if [[ -n "${AIENOS_CEREMONY_PASS_FILE:-}" ]]; then
        AIENOS_CEREMONY_PASS="$(cat "${AIENOS_CEREMONY_PASS_FILE}")"
    else
        local a b
        read -r -s -p "Ceremony passphrase: " a; echo
        read -r -s -p "Again: " b; echo
        [[ "${a}" == "${b}" ]] || die "passphrases differ"
        AIENOS_CEREMONY_PASS="${a}"
    fi
    [[ ${#AIENOS_CEREMONY_PASS} -ge 12 ]] || die "passphrase shorter than 12 characters"
    export AIENOS_CEREMONY_PASS
}

pub_fingerprint() { # role public_dir
    if [[ "$1" == boot_signer ]]; then
        sha256 "$2/boot_signer.crt.der"
    else
        "${OPENSSL}" pkey -pubin -in "$2/$1.pub.pem" -outform DER 2>/dev/null \
            | "${OPENSSL}" dgst -sha256 -r | cut -d' ' -f1
    fi
}

generate() {
    local out="$1" allow="${2:-}"
    [[ ! -e "${out}" ]] || die "${out} already exists; never overwrite a ceremony"
    preflight "${allow}"
    get_pass
    umask 077
    mkdir -p "${out}/private" "${out}/public"
    local r
    for r in owner_root release_signer operator_approval; do
        "${OPENSSL}" genpkey -algorithm ed25519 -aes-256-cbc -pass env:AIENOS_CEREMONY_PASS \
            -out "${out}/private/${r}.key.pem"
        "${OPENSSL}" pkey -in "${out}/private/${r}.key.pem" -passin env:AIENOS_CEREMONY_PASS \
            -pubout -out "${out}/public/${r}.pub.pem"
    done
    "${OPENSSL}" genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc \
        -pass env:AIENOS_CEREMONY_PASS -out "${out}/private/boot_signer.key.pem"
    "${OPENSSL}" req -new -x509 -sha256 -days 3650 -key "${out}/private/boot_signer.key.pem" \
        -passin env:AIENOS_CEREMONY_PASS -subj "/CN=AIENOS Owner Boot Signer gen1/O=AIEN/" \
        -addext "extendedKeyUsage=codeSigning" -out "${out}/public/boot_signer.crt.pem"
    "${OPENSSL}" x509 -in "${out}/public/boot_signer.crt.pem" -outform DER \
        -out "${out}/public/boot_signer.crt.der"

    local m="${out}/public/authority_manifest.txt"
    {
        echo "aienos_authority_manifest=1"
        echo "generation=1"
        echo "created_utc=$(now_utc)"
        echo "tool=$("${OPENSSL}" version)"
        echo "rotation_rule=add new key, verify, exercise recovery, then revoke old; never delete first"
        echo "root_replacement=special recovery ceremony only"
        echo "role.owner_root.alg=ed25519"
        echo "role.owner_root.duty=signs authority manifests; never on the Spark"
        echo "role.boot_signer.alg=rsa2048-x509"
        echo "role.boot_signer.duty=signs the small stable loader; firmware db will trust this cert"
        echo "role.release_signer.alg=ed25519"
        echo "role.release_signer.duty=signs kernels and manifests under the loader; replaceable by a root-signed manifest"
        echo "role.operator_approval.alg=ed25519"
        echo "role.operator_approval.duty=approves boundary changes; never boots"
        for r in ${ROLES}; do
            echo "role.${r}.pub_sha256=$(pub_fingerprint "${r}" "${out}/public")"
        done
    } >"${m}"
    "${OPENSSL}" pkeyutl -sign -rawin -inkey "${out}/private/owner_root.key.pem" \
        -passin env:AIENOS_CEREMONY_PASS -in "${m}" -out "${out}/public/authority_manifest.sig"
    cp "${m}" "${out}/public/authority_manifest.gen1.txt"
    cp "${out}/public/authority_manifest.sig" "${out}/public/authority_manifest.gen1.sig"
    chmod 644 "${out}/public/"*
    verify "${out}/public"
    echo "generated: ${out} (private/ stays offline; public/ may be copied out)"
}

verify() {
    local pub="$1" min_gen="${2:-1}" r want got gen status=0
    check_tools
    local m="${pub}/authority_manifest.txt"
    [[ -f "${m}" && -f "${pub}/authority_manifest.sig" ]] || { echo "FAIL  manifest or signature missing"; return 1; }
    if "${OPENSSL}" pkeyutl -verify -rawin -pubin -inkey "${pub}/owner_root.pub.pem" \
        -in "${m}" -sigfile "${pub}/authority_manifest.sig" >/dev/null 2>&1; then
        echo "PASS  authority manifest signature verifies with owner_root"
    else
        echo "FAIL  authority manifest signature does not verify"; return 1
    fi
    for r in ${ROLES}; do
        want="$(sed -n "s/^role\.${r}\.pub_sha256=//p" "${m}")"
        got="$(pub_fingerprint "${r}" "${pub}" || true)"
        if [[ -n "${want}" && "${want}" == "${got}" ]]; then
            echo "PASS  ${r} public key matches manifest (${got})"
        else
            echo "FAIL  ${r} public key does not match manifest"; status=1
        fi
        want="$(sed -n "s/^role\.${r}\.next\.pub_sha256=//p" "${m}")"
        if [[ -n "${want}" ]]; then
            got="$(pub_fingerprint "${r}.next" "${pub}" || true)"
            if [[ "${want}" == "${got}" ]]; then
                echo "PASS  ${r} next key (transition) matches manifest (${got})"
            else
                echo "FAIL  ${r} next key does not match manifest"; status=1
            fi
        fi
    done
    gen="$(sed -n 's/^generation=//p' "${m}")"
    if [[ "${gen}" =~ ^[0-9]+$ && "${gen}" -ge "${min_gen}" ]]; then
        echo "PASS  generation ${gen} (minimum accepted ${min_gen})"
    else
        echo "FAIL  generation ${gen:-missing} is older than the minimum ${min_gen} (rollback refused)"; status=1
    fi
    if grep -l "PRIVATE KEY" "${pub}"/* >/dev/null 2>&1; then
        echo "FAIL  private key material found in public folder"; status=1
    fi
    echo "manifest_sha256=$(sha256 "${m}")"
    return "${status}"
}

backup() {
    local out="$1" dest="$2" label="$3" r ok=1
    [[ -d "${out}/private" ]] || die "${out}/private not found"
    [[ -d "${dest}" ]] || die "backup destination ${dest} is not a folder (mount the backup medium first)"
    local b="${dest}/aienos-owner-keys-gen1"
    [[ ! -e "${b}" ]] || die "${b} already exists on this medium"
    get_pass
    umask 077
    mkdir -p "${b}"
    cp "${out}/private/"*.key.pem "${out}/public/"* "${b}/"
    sync
    for r in ${ROLES}; do
        if "${OPENSSL}" pkey -in "${b}/${r}.key.pem" -passin env:AIENOS_CEREMONY_PASS -noout 2>/dev/null; then
            echo "PASS  ${label}: ${r} decrypts from the backup copy"
        else
            echo "FAIL  ${label}: ${r} does not decrypt from the backup copy"; ok=0
        fi
    done
    [[ "${ok}" == 1 ]] || return 1
    local digest
    digest="$(cat "${b}"/*.key.pem | "${OPENSSL}" dgst -sha256 -r | cut -d' ' -f1)"
    echo "backup label=${label} encrypted_keys_sha256=${digest} verified_utc=$(now_utc)" \
        >>"${out}/public/backups.txt"
    echo "recorded backup ${label}"
}

record() {
    local out="$1" pub="$1/public"
    verify "${pub}" >/dev/null || { echo "FAIL  verify failed; no record written"; return 1; }
    local n=0
    [[ -f "${pub}/backups.txt" ]] && n="$(grep -c '^backup ' "${pub}/backups.txt")"
    {
        echo "aienos_key_ceremony_record=1"
        echo "recorded_utc=$(now_utc)"
        echo "tool=$("${OPENSSL}" version)"
        echo "host=$(uname -s) $(uname -m)"
        echo "procedure=docs/TRUST-1-OPERATOR-STEPS.md (Gate 3)"
        echo "manifest_sha256=$(sha256 "${pub}/authority_manifest.txt")"
        grep '^role\..*\.pub_sha256=' "${pub}/authority_manifest.txt"
        echo "backup_count=${n}"
        [[ -f "${pub}/backups.txt" ]] && cat "${pub}/backups.txt"
        echo "firmware_changed=no"
        echo "operator_signature=<operator signs here by hand or with operator_approval>"
    } >"${pub}/ceremony_record.txt"
    if grep -q "PRIVATE KEY" "${pub}/ceremony_record.txt"; then
        echo "FAIL  record contains private material"; return 1
    fi
    [[ "${n}" -ge 2 ]] || echo "NOTE  only ${n} verified backup(s); Gate 3 needs 2 in separate places"
    echo "wrote ${pub}/ceremony_record.txt"
}

# Rotation (Gate 3 acceptance: add -> verify -> exercise recovery -> revoke;
# never delete first). Only release_signer and operator_approval rotate here:
# boot_signer rotation touches firmware db (a Gate 7 style attended step) and
# owner_root replacement is a special recovery ceremony.
write_manifest() { # out generation extra_lines_file
    local out="$1" gen="$2" extra="$3" m="$1/public/authority_manifest.txt" r
    {
        echo "aienos_authority_manifest=1"
        echo "generation=${gen}"
        echo "created_utc=$(now_utc)"
        echo "tool=$("${OPENSSL}" version)"
        sed -n '/^rotation_rule=/p;/^root_replacement=/p;/^role\.[a-z_]*\.alg=/p;/^role\.[a-z_]*\.duty=/p' \
            "${out}/public/authority_manifest.gen1.txt" 2>/dev/null || true
        for r in ${ROLES}; do
            echo "role.${r}.pub_sha256=$(pub_fingerprint "${r}" "${out}/public")"
        done
        cat "${extra}"
    } >"${m}"
    "${OPENSSL}" pkeyutl -sign -rawin -inkey "${out}/private/owner_root.key.pem" \
        -passin env:AIENOS_CEREMONY_PASS -in "${m}" -out "${out}/public/authority_manifest.sig"
    cp "${m}" "${out}/public/authority_manifest.gen${gen}.txt"
    cp "${out}/public/authority_manifest.sig" "${out}/public/authority_manifest.gen${gen}.sig"
    chmod 644 "${out}/public/"*
}

rotate() {
    local out="$1" role="$2" stage="$3" gen m="$1/public/authority_manifest.txt"
    case "${role}" in release_signer|operator_approval) ;; *) die "rotate supports release_signer or operator_approval only" ;; esac
    verify "${out}/public" >/dev/null || die "current manifest does not verify; fix that first"
    gen="$(sed -n 's/^generation=//p' "${m}")"
    [[ -f "${out}/public/authority_manifest.gen${gen}.txt" ]] || {
        cp "${m}" "${out}/public/authority_manifest.gen${gen}.txt"
        cp "${out}/public/authority_manifest.sig" "${out}/public/authority_manifest.gen${gen}.sig"; }
    get_pass
    umask 077
    local extra; extra="$(mktemp)"
    case "${stage}" in
        add)
            [[ ! -e "${out}/private/${role}.next.key.pem" ]] || die "a next ${role} already exists"
            "${OPENSSL}" genpkey -algorithm ed25519 -aes-256-cbc -pass env:AIENOS_CEREMONY_PASS \
                -out "${out}/private/${role}.next.key.pem"
            "${OPENSSL}" pkey -in "${out}/private/${role}.next.key.pem" -passin env:AIENOS_CEREMONY_PASS \
                -pubout -out "${out}/public/${role}.next.pub.pem"
            grep '^role\..*\.revoked_pub_sha256=' "${m}" >"${extra}" || true
            echo "role.${role}.next.pub_sha256=$(pub_fingerprint "${role}.next" "${out}/public")" >>"${extra}"
            echo "role.${role}.state=transition (current and next both accepted)" >>"${extra}"
            ;;
        revoke)
            [[ -f "${out}/private/${role}.next.key.pem" ]] || die "run 'rotate ${out} ${role} add' first"
            grep '^role\..*\.revoked_pub_sha256=' "${m}" >"${extra}" || true
            echo "role.${role}.revoked_pub_sha256=$(pub_fingerprint "${role}" "${out}/public")" >>"${extra}"
            # Old key is quarantined, never deleted: kept encrypted for audit.
            mv "${out}/private/${role}.key.pem" "${out}/private/${role}.gen${gen}.revoked.key.pem"
            mv "${out}/public/${role}.pub.pem" "${out}/public/${role}.gen${gen}.revoked.pub.pem"
            mv "${out}/private/${role}.next.key.pem" "${out}/private/${role}.key.pem"
            mv "${out}/public/${role}.next.pub.pem" "${out}/public/${role}.pub.pem"
            ;;
        *) rm -f "${extra}"; die "stage must be add or revoke" ;;
    esac
    write_manifest "${out}" "$((gen + 1))" "${extra}"
    rm -f "${extra}"
    verify "${out}/public"
    echo "rotation ${role} ${stage}: generation $((gen + 1)) signed by owner_root"
}

cmd="${1:-}"; shift || true
case "${cmd}" in
    preflight) preflight "${1:-}" ;;
    generate) [[ $# -ge 1 ]] || die "usage: generate OUT_DIR [--allow-online]"; generate "$1" "${2:-}" ;;
    backup) [[ $# -eq 3 ]] || die "usage: backup OUT_DIR DEST_DIR LABEL"; backup "$1" "$2" "$3" ;;
    verify) [[ $# -ge 1 ]] || die "usage: verify PUBLIC_DIR [MIN_GENERATION]"; verify "$1" "${2:-1}" ;;
    rotate) [[ $# -eq 3 ]] || die "usage: rotate OUT_DIR ROLE add|revoke"; rotate "$1" "$2" "$3" ;;
    record) [[ $# -eq 1 ]] || die "usage: record OUT_DIR"; record "$1" ;;
    *) sed -n '2,/^# Exit:/p' "$0"; exit 2 ;;
esac
