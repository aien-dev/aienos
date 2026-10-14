#!/usr/bin/env bash
# owner_ceremony.sh -- PI5-8 Q2: the AIENOS owner-key ceremony on Drake's YubiKey (PIV, Ed25519, slot 9c).
#
#   owner_ceremony.sh --dry-run [--out DIR]        rehearsal with a SOFTWARE key (openssl). Labelled TEST. Never touches a YubiKey.
#   owner_ceremony.sh --real [--out DIR]           the ceremony. Writes to the YubiKey. Run it only when the Spark is offline.
#   owner_ceremony.sh --sign-manifest MANIFEST SIGOUT OWNERFILE
#                                                  after the ceremony: the YubiKey signs the statement that binds MANIFEST
#                                                  (PIN once, then touch). Checks the signature against OWNERFILE before it finishes.
#   owner_ceremony.sh --check-network              exit 0 only if the machine looks offline (what --real checks first)
#
# Decisions (PI5-8 Q2, Drake): the owner key is an Ed25519 key generated ON the YubiKey (PIV, slot 9c, touch policy always, PIN
# policy once). The private key never leaves the device. The Spark is offline while the key is made. Drake types the PIV PIN,
# PUK and management key himself; this script never receives, echoes, stores or logs them: the YubiKey tools ask for them on
# the terminal. The owner key is NOT the public-release signing key (that one is generated only at the first public release).
#
# What is signed: a small fixed statement that binds the manifest (ck_manifest_sig.c, docs/native/PI5-8-OWNER-CEREMONY.md).
# Real mode writes (and only ever reads from the YubiKey the public parts): slot 9c key, PIN, PUK, management key.
# It refuses to run if slot 9c is already occupied. Output folder (default ~/aienos-owner-ceremony/<UTC time>) holds PUBLIC
# files only: slot-9c-public.pem, owner-pubkeys.txt, owner-pubkeys.txt.sha256, ceremony-statement, ceremony-signature,
# ceremony-report.txt.
set -euo pipefail
export LC_ALL=C
case $- in *x*) echo "REFUSED: shell tracing (set -x) would print secrets and commands; run without it" >&2; exit 2;; esac
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${here}/../.." && pwd)"
PIV="${AIENOS_PIV_TOOL:-${HOME}/.local/yubico-piv-tool/bin/yubico-piv-tool}"
YKMAN="${AIENOS_YKMAN:-${HOME}/.local/ykman-venv/bin/ykman}"
export LD_LIBRARY_PATH="$(dirname "$(dirname "${PIV}")")/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
SLOT=9c
mode="" out="" tmp=""
say() { printf '%s\n' "$*"; }
die() { printf 'REFUSED: %s\n' "$*" >&2; exit "${2:-1}"; }
cleanup() { [ -z "${tmp}" ] || rm -rf "${tmp}"; }
trap cleanup EXIT

# ---- network check (real mode): refuse unless the machine is offline ----------------------------------------------
network_state() { # prints reasons the machine is online, nothing when offline (refuses to guess without ip)
    command -v ip >/dev/null || { echo "cannot check: the ip tool is missing"; return 0; }
    ip -o route show default 2>/dev/null | sed 's/^/default route: /'
    ip -o -6 route show default 2>/dev/null | sed 's/^/default route (v6): /'
    local d n
    for d in "${AIENOS_SYSFS_NET:-/sys/class/net}"/*; do
        n="$(basename "${d}")"
        case "$(readlink -f "${d}")" in /sys/devices/virtual/*) continue;; esac
        [ "$(cat "${d}/operstate" 2>/dev/null || echo unknown)" = up ] && echo "network card ${n} is up"
    done
    return 0
}
require_offline() {
    local s; s="$(network_state)"
    if [ -n "${s}" ]; then
        printf '%s\n' "${s}" >&2
        die "the Spark is still online. Unplug the network cable and turn Wi-Fi off, wait ten seconds, run this again." 3
    fi
}

# ---- tools -------------------------------------------------------------------------------------------------------------
vge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]; } # vge A B: A >= B
need_tools() {
    [ -x "${PIV}" ] || die "yubico-piv-tool not found at ${PIV}; run scripts/pi5-8/install_owner_tools.sh" 2
    [ -x "${YKMAN}" ] || die "ykman not found at ${YKMAN}; run scripts/pi5-8/install_owner_tools.sh" 2
    local v; v="$("${PIV}" --version 2>&1 | awk '{print $2}')"
    vge "${v}" 2.5.0 || die "yubico-piv-tool ${v} is too old for PIV Ed25519 (needs 2.5.0 or newer; installed script builds 2.7.3)" 2
}
build_host_tools() { # in-tree verifier and owner-file checker, built from the repo
    cc -std=gnu11 -O1 -Wall -Wextra -Werror -I"${root}/native/sig" -I"${root}/native/argus" -o "${tmp}/ck_manifest_sig" \
        "${root}/native/kernel/tools/ck_manifest_sig.c" "${root}/native/sig/ed25519.c" "${root}/native/sig/sha512.c" \
        "${root}/native/sig/ct.c" "${root}/native/argus/sha256.c"
    cc -std=gnu11 -O1 -Wall -Wextra -Werror -o "${tmp}/ck_owner_gen" "${root}/native/kernel/tools/ck_owner_gen.c"
}

# ---- backends: software (dry run) and YubiKey (real) --------------------------------------------------------------------
sw_generate() { # PUBPEM
    openssl genpkey -algorithm ED25519 -out "${tmp}/TEST-software-key.pem" 2>/dev/null
    openssl pkey -in "${tmp}/TEST-software-key.pem" -pubout -out "$1"
}
sw_sign() { openssl pkeyutl -sign -rawin -inkey "${tmp}/TEST-software-key.pem" -in "$1" -out "$2"; }
yk_info() {
    say "YubiKey seen by the smart card service:"
    "${PIV}" -a list-readers
    local n; n="$("${PIV}" -a list-readers | grep -ci yubikey || true)"
    [ "${n}" = 1 ] || die "need exactly one YubiKey plugged in, found ${n}" 2
    "${YKMAN}" info | grep -E '^(Device type|Serial number|Firmware version|Form factor)'
    local fw; fw="$("${PIV}" -a version 2>&1 | sed -n 's/^Firmware version \([0-9.]*\) found.*/\1/p')"
    vge "${fw:-0}" 5.7.0 || die "firmware ${fw:-unknown} cannot hold PIV Ed25519 keys (needs 5.7.0 or newer)" 2
}
yk_slot_must_be_empty() {
    if "${PIV}" -a status 2>/dev/null | grep -qi "^Slot ${SLOT}"; then die "slot ${SLOT} already holds a key; this script never overwrites a key" 2; fi
    say "Slot ${SLOT} is empty."
}
yk_is_default() { "${YKMAN}" piv info 2>/dev/null | grep -q "WARNING: Using default $1"; } # $1: PIN | PUK | Management key
yk_set_secrets() {
    # The YubiKey tool asks for each new secret twice, so a typing slip cannot lock you out. Factory values are public
    # (PIN 123456, PUK 12345678, management key 0102...08 x3) and are passed only while the device still reports them.
    local ok
    if yk_is_default PIN; then
        say "STEP 3a: choose your new PIV PIN (6 to 8 characters). Type it, then type it again."
        "${PIV}" -a change-pin -P 123456
    else
        say "The PIN is no longer the factory PIN. Change it again only if you want to."
        read -r -p "Change the PIN now? [y/N] " ok; if [ "${ok}" = y ]; then "${PIV}" -a change-pin; fi
    fi
    if yk_is_default PUK; then
        say "STEP 3b: choose your new PUK (6 to 8 characters). It unblocks the PIN if the PIN gets blocked. Type it, then again."
        "${PIV}" -a change-puk -P 12345678
    else
        say "The PUK is no longer the factory PUK; keeping it."
    fi
    if yk_is_default "Management key"; then
        say "STEP 3c: choose your new management key: 64 hexadecimal characters (0-9, a-f), the one you wrote on paper. Type it, then again."
        "${PIV}" -a set-mgm-key -m AES256
    else
        say "The management key is no longer the factory one; keeping it."
    fi
    "${YKMAN}" piv info | grep -E 'tries remaining|Management key algorithm' || true
    if "${YKMAN}" piv info | grep -q "WARNING: Using default"; then die "something is still set to the factory value; stopping" 1; fi
}
yk_generate() { # PUBPEM
    say "STEP: the YubiKey now makes the owner key inside itself (Ed25519, slot ${SLOT}, touch always, PIN once). Type the management key when asked."
    "${PIV}" -k -a generate -s "${SLOT}" -A ED25519 --pin-policy=once --touch-policy=always -o "$1"
}
yk_sign() { # IN OUT
    say "STEP: the YubiKey signs. Type the PIN when asked, then TOUCH the metal contact on the key when it blinks."
    "${PIV}" -a verify-pin --sign -s "${SLOT}" -A ED25519 -i "$1" -o "$2"
}
yk_check_policy() {
    local info; info="$("${YKMAN}" piv keys info "${SLOT}")"
    say "${info}"
    grep -qi "Algorithm:.*ED25519" <<<"${info}" || die "slot ${SLOT} is not an Ed25519 key" 1
    grep -qi "Origin:.*GENERATED" <<<"${info}" || die "slot ${SLOT} key was not generated on the YubiKey" 1
    grep -qi "PIN required for use:.*ONCE" <<<"${info}" || die "PIN policy is not ONCE" 1
    grep -qi "Touch required for use:.*ALWAYS" <<<"${info}" || die "touch policy is not ALWAYS" 1
}

# ---- shared steps ------------------------------------------------------------------------------------------------------
write_and_check_owner_file() { # PUBPEM OUTDIR LABEL
    local hex
    hex="$("${here}/owner_pubkey_file.sh" "$1" "$2/owner-pubkeys.txt" "$3")" || die "could not convert the public key" 1
    ( cd "$2" && sha256sum owner-pubkeys.txt > owner-pubkeys.txt.sha256 )
    # ck_owner_gen is the same checker the image build uses; it also refuses RFC 8032 TEST keys and all-equal keys.
    printf 'machine_id %s\nstore_uuid %s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 16)" > "${tmp}/placeholder-machine.txt" # random placeholder, only checks the owner line
    "${tmp}/ck_owner_gen" "$2/owner-pubkeys.txt" "${tmp}/placeholder-machine.txt" "${tmp}/owner_prov.h" || die "the image build would refuse this owner file" 1
    OWNER_HEX="${hex}"
    say "Owner public key (PUBLIC): ${hex}"
    say "Owner file sha256:         $(cut -d' ' -f1 "$2/owner-pubkeys.txt.sha256")"
}
sign_and_verify() { # SIGN_FN MANIFEST SIGOUT HEX LABEL
    local fn="$1" man="$2" sig="$3" hex="$4" st="${tmp}/statement"
    "${tmp}/ck_manifest_sig" statement "${man}" "${st}"
    "${fn}" "${st}" "${sig}"
    [ "$(wc -c < "${sig}")" = 64 ] || die "signature is not 64 bytes" 1
    "${tmp}/ck_manifest_sig" verify "${man}" "${sig}" "${hex}" || die "the signature does not verify with the in-tree Ed25519" 1
    # second, independent verifier: openssl over the same statement bytes (plain Ed25519, no hashing wrapper)
    local pem="${tmp}/v.pem"
    # SPKI DER = fixed 12-byte prefix + the 32 key bytes, written as raw bytes (not through $(...), which drops NUL)
    printf "$(printf '%s' "302a300506032b6570032100${hex}" | sed 's/../\\x&/g')" | openssl pkey -pubin -inform DER -out "${pem}" 2>/dev/null \
        || die "could not rebuild the public key for the second check" 1
    openssl pkeyutl -verify -rawin -pubin -inkey "${pem}" -in "${st}" -sigfile "${sig}" >/dev/null || die "openssl does not verify the signature" 1
    say "Signature verified two ways (in-tree Ed25519 and openssl)."
    cp "${man}" "${tmp}/m.bad"; printf 'X' | dd of="${tmp}/m.bad" bs=1 seek=3 conv=notrunc 2>/dev/null
    if "${tmp}/ck_manifest_sig" verify "${tmp}/m.bad" "${sig}" "${hex}" >/dev/null; then die "a changed manifest still verified" 1; fi
    say "A changed manifest is refused, as it must be."
}
test_manifest() { printf 'AIENOS-OWNER-CEREMONY-TEST-MANIFEST-V1\nthis is a fixed test text, not a receipts manifest\n' > "$1"; }

ceremony() { # dry|real
    local kind="$1" label
    if [ -z "${out}" ]; then if [ "${kind}" = real ]; then out="${HOME}/aienos-owner-ceremony/$(date -u +%Y%m%dT%H%M%SZ)"; else out="$(mktemp -d /tmp/aienos-owner-dryrun.XXXXXX)"; fi; fi
    build_host_tools
    if [ "${kind}" = dry ]; then
        say "DRY RUN (TEST): a software key stands in for the YubiKey. No YubiKey is touched, nothing real is created."
        say "Steps 1 to 4 of the real ceremony (offline check, YubiKey, PIN/PUK/management key, key generation) are replaced by a software key."
        label="TEST software key (dry run), not an owner key"
        mkdir -p "${out}"; chmod 700 "${out}"
        sw_generate "${out}/slot-9c-public.pem"
    else
        [ -t 0 ] && [ -t 1 ] || die "run this at the keyboard of the Spark (it asks you to type secrets)" 2
        say "STEP 1: checking the Spark is offline."; require_offline; say "Offline: OK."
        say "STEP 2: checking the tools and the YubiKey."; need_tools; yk_info
        read -r -p "Does that serial number match your YubiKey (type YES to go on)? " ans; [ "${ans}" = YES ] || die "stopped by you" 1
        yk_slot_must_be_empty
        mkdir -p "${out}"; chmod 700 "${out}"
        say "STEP 3: PIN, PUK and management key (typed by you, never shown here)."; yk_set_secrets
        say "STEP 4: making the owner key inside the YubiKey."; yk_generate "${out}/slot-9c-public.pem"
        "${PIV}" -a read-public-key -s "${SLOT}" -o "${tmp}/read-back.pem"
        cmp -s "${tmp}/read-back.pem" "${out}/slot-9c-public.pem" || die "the key read back from slot ${SLOT} differs from the generated one" 1
        yk_check_policy
        label="Ed25519 key generated on YubiKey serial $("${YKMAN}" info | sed -n 's/^Serial number: *//p'), PIV slot ${SLOT}"
    fi
    say "STEP 5: owner public key file."; write_and_check_owner_file "${out}/slot-9c-public.pem" "${out}" "${label}"
    test_manifest "${out}/ceremony-test-manifest"
    say "STEP 6: signing and checking a fixed test statement."
    if [ "${kind}" = dry ]; then sign_and_verify sw_sign "${out}/ceremony-test-manifest" "${out}/ceremony-signature" "${OWNER_HEX}" TEST
    else sign_and_verify yk_sign "${out}/ceremony-test-manifest" "${out}/ceremony-signature" "${OWNER_HEX}" real; fi
    cp "${tmp}/statement" "${out}/ceremony-statement"
    {
        echo "AIENOS owner ceremony report (${kind}); PUBLIC data only"
        echo "kind: $([ "${kind}" = dry ] && echo 'DRY RUN, TEST software key, not an owner key' || echo 'REAL, key generated on the YubiKey')"
        echo "utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "key: ${label}"
        echo "owner_root_ed25519: ${OWNER_HEX}"
        echo "owner_file_sha256: $(cut -d' ' -f1 "${out}/owner-pubkeys.txt.sha256")"
        echo "signed_statement_sha256: $(sha256sum < "${out}/ceremony-statement" | cut -d' ' -f1)"
        echo "checks: network offline $([ "${kind}" = dry ] && echo n/a || echo ok); owner file accepted by ck_owner_gen; signature verified by in-tree Ed25519 and openssl; changed manifest refused"
    } > "${out}/ceremony-report.txt"
    say ""
    if [ "${kind}" = dry ]; then say "DRY RUN COMPLETE (TEST). Files in ${out}"; say "CEREMONY_DRY_RUN: PASS"
    else say "CEREMONY COMPLETE. Public files in ${out}. You may reconnect the network now."; say "CEREMONY_REAL: PASS"; fi
}

sign_manifest() { # MANIFEST SIGOUT OWNERFILE   (real YubiKey)
    local man="$1" sigout="$2" ofile="$3" hex
    [ -r "${man}" ] || die "cannot read manifest ${man}" 2
    hex="$(sed -n 's/^owner_root_ed25519 \([0-9a-f]\{64\}\)$/\1/p' "${ofile}")"; [ -n "${hex}" ] || die "no owner_root_ed25519 line in ${ofile}" 2
    need_tools; build_host_tools
    "${PIV}" -a read-public-key -s "${SLOT}" -o "${tmp}/slot.pem" || die "cannot read the public key of slot ${SLOT}" 1
    "${here}/owner_pubkey_file.sh" "${tmp}/slot.pem" "${tmp}/slot-owner.txt" >/dev/null 2>&1 || die "slot ${SLOT} does not hold an Ed25519 key" 1
    grep -qx "owner_root_ed25519 ${hex}" "${tmp}/slot-owner.txt" || die "the key in slot ${SLOT} is not the owner key in ${ofile}" 1
    sign_and_verify yk_sign "${man}" "${tmp}/sig.out" "${hex}" real
    cp "${tmp}/sig.out" "${sigout}"
    say "Wrote ${sigout}. MANIFEST_OWNER_SIGNED: PASS"
}

tmp="$(mktemp -d)"
case "${1:-}" in
    --dry-run) mode=dry; shift;;
    --real) mode=real; shift;;
    --check-network) s="$(network_state)"; if [ -n "${s}" ]; then printf '%s\n' "${s}"; echo "ONLINE"; exit 1; fi; echo "OFFLINE"; exit 0;;
    --sign-manifest) [ $# = 4 ] || die "usage: --sign-manifest MANIFEST SIGOUT OWNERFILE" 2; sign_manifest "$2" "$3" "$4"; exit 0;;
    *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2;;
esac
while [ $# -gt 0 ]; do case "$1" in --out) out="${2:?--out DIR}"; shift 2;; *) die "unknown argument $1" 2;; esac; done
ceremony "${mode}"
