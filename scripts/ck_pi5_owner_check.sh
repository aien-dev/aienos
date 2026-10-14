#!/usr/bin/env bash
# ck_pi5_owner_check.sh -- PI5-8 Q2 gate: the owner-key ceremony tooling, proven with SOFTWARE keys only (TEST).
#   1. PIV public key (PEM) -> CK_OWNER_PUBKEYS file conversion is exact; anything that is not an Ed25519 key is refused;
#   2. the ceremony dry run (software key, labelled TEST) runs end to end and never calls a YubiKey tool (tripwire);
#   3. real mode refuses when the machine looks online, and with no terminal, before any YubiKey tool is called;
#   4. an image built with that owner file (make full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=<file>) carries the owner key
#      and none of the TEST anchors (no "seed0b-test ... TEST ONLY" banner, no TEST Store identity); the TEST-anchor image
#      is the positive control (it has the banner and not the owner key); Pi image flags are refused with CK_HARDWARE_STAGING.
# No YubiKey is touched. No owner or release key is generated: every key here is a throw-away openssl key.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
fail=0
ok() { echo "PASS $*"; }
bad() { echo "FAIL $*"; fail=1; }
C="${root}/scripts/pi5-8/owner_ceremony.sh"; CONV="${root}/scripts/pi5-8/owner_pubkey_file.sh"
hexof() { od -An -v -tx1 "$1" | tr -d ' \n'; }

# 1. conversion
openssl genpkey -algorithm ED25519 -out "${tmp}/k.pem" 2>/dev/null
openssl pkey -in "${tmp}/k.pem" -pubout -out "${tmp}/k.pub"
want="$(openssl pkey -in "${tmp}/k.pem" -pubout -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n')"
got="$("${CONV}" "${tmp}/k.pub" "${tmp}/owner.txt" "TEST conversion" 2>/dev/null)"
if [ "${got}" = "${want}" ] && grep -qx "owner_root_ed25519 ${want}" "${tmp}/owner.txt" && [ "$(grep -vc '^#' "${tmp}/owner.txt")" = 1 ]; then ok "conversion gives the 32 raw key bytes in the CK_OWNER_PUBKEYS format"; else bad "conversion"; fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${tmp}/rsa.pem" 2>/dev/null; openssl pkey -in "${tmp}/rsa.pem" -pubout -out "${tmp}/rsa.pub"
openssl genpkey -algorithm X25519 -out "${tmp}/x.pem" 2>/dev/null; openssl pkey -in "${tmp}/x.pem" -pubout -out "${tmp}/x.pub"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${tmp}/ec.pem" 2>/dev/null; openssl pkey -in "${tmp}/ec.pem" -pubout -out "${tmp}/ec.pub"
printf 'not a key\n' > "${tmp}/junk.pub"
{ echo "-----BEGIN PUBLIC KEY-----"; { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; head -c 32 /dev/zero | tr '\0' '\021'; } | base64; echo "-----END PUBLIC KEY-----"; } > "${tmp}/same.pub"
for b in rsa x ec junk same; do
    if "${CONV}" "${tmp}/${b}.pub" "${tmp}/o.${b}" >/dev/null 2>&1; then bad "conversion accepted ${b}"; else ok "conversion refuses ${b} (not a plain Ed25519 key)"; fi
done
for b in rsa x ec junk same; do [ ! -e "${tmp}/o.${b}" ] || bad "refused input ${b} still wrote a file"; done

# 2. dry run with a tripwire in place of both YubiKey tools
printf '#!/bin/sh\necho "$0" >> "%s/tripwire"\nexit 99\n' "${tmp}" > "${tmp}/trip"; chmod +x "${tmp}/trip"
AIENOS_PIV_TOOL="${tmp}/trip" AIENOS_YKMAN="${tmp}/trip" "${C}" --dry-run --out "${tmp}/dry" > "${tmp}/dry.log" 2>&1 || { cat "${tmp}/dry.log"; bad "dry run failed"; }
if grep -q "^CEREMONY_DRY_RUN: PASS" "${tmp}/dry.log"; then ok "dry run passes end to end"; else bad "dry run verdict"; fi
[ ! -e "${tmp}/tripwire" ] && ok "dry run called no YubiKey tool" || bad "dry run called a YubiKey tool"
for f in slot-9c-public.pem owner-pubkeys.txt owner-pubkeys.txt.sha256 ceremony-statement ceremony-signature ceremony-report.txt; do
    [ -s "${tmp}/dry/${f}" ] || bad "dry run output lacks ${f}"
done
grep -q "DRY RUN, TEST software key, not an owner key" "${tmp}/dry/ceremony-report.txt" && ok "dry run report is labelled TEST" || bad "dry run label"
( cd "${tmp}/dry" && sha256sum -c owner-pubkeys.txt.sha256 >/dev/null ) && ok "owner file sha256 file matches" || bad "owner sha256"
if grep -rqE "PRIVATE KEY|TEST-software-key" "${tmp}/dry"; then bad "dry run output holds a private key"; else ok "dry run output holds public material only"; fi

# 3. real mode refusals (a pseudo-terminal is needed to get past the terminal check)
mkdir -p "${tmp}/fakebin" "${tmp}/net/eth0" "${tmp}/offline/eth0"
printf '#!/bin/sh\n[ "$*" = "-o route show default" ] && echo "default via 192.0.2.1 dev eth0"\nexit 0\n' > "${tmp}/fakebin/ip-online"
printf '#!/bin/sh\nexit 0\n' > "${tmp}/fakebin/ip-offline"; chmod +x "${tmp}/fakebin/ip-"*
echo up > "${tmp}/net/eth0/operstate"; echo down > "${tmp}/offline/eth0/operstate"
shimdir() { mkdir -p "${tmp}/p-$1"; cp "${tmp}/fakebin/ip-$1" "${tmp}/p-$1/ip"; for t in bash env sed cat sort head grep readlink basename dirname date cc mktemp rm; do ln -sf "$(command -v ${t})" "${tmp}/p-$1/${t}" 2>/dev/null || true; done; echo "${tmp}/p-$1"; }
online_path="$(shimdir online)"; offline_path="$(shimdir offline)"
run_pty() { script -qec "$1" /dev/null </dev/null; }
set +e
out_on="$(PATH="${online_path}:${PATH}" AIENOS_SYSFS_NET="${tmp}/offline" AIENOS_PIV_TOOL="${tmp}/trip" AIENOS_YKMAN="${tmp}/trip" run_pty "PATH='${online_path}':\$PATH '${C}' --real --out '${tmp}/real1'" 2>&1)"; rc_on=$?
out_nic="$(AIENOS_SYSFS_NET="${tmp}/net" AIENOS_PIV_TOOL="${tmp}/trip" AIENOS_YKMAN="${tmp}/trip" run_pty "PATH='${offline_path}':\$PATH '${C}' --real --out '${tmp}/real2'" 2>&1)"; rc_nic=$?
out_tty="$(PATH="${offline_path}:${PATH}" AIENOS_SYSFS_NET="${tmp}/offline" AIENOS_PIV_TOOL="${tmp}/trip" AIENOS_YKMAN="${tmp}/trip" "${C}" --real --out "${tmp}/real3" </dev/null 2>&1)"; rc_tty=$?
PATH="${offline_path}:${PATH}" AIENOS_SYSFS_NET="${tmp}/offline" "${C}" --check-network > "${tmp}/cn.off" 2>&1; rc_cn_off=$?
PATH="${online_path}:${PATH}" AIENOS_SYSFS_NET="${tmp}/offline" "${C}" --check-network > "${tmp}/cn.on" 2>&1; rc_cn_on=$?
set -e
if [ "${rc_on}" != 0 ] && grep -q "still online" <<<"${out_on}"; then ok "real mode refuses with a default route (online)"; else bad "real mode online refusal (rc=${rc_on})"; fi
if [ "${rc_nic}" != 0 ] && grep -q "network card eth0 is up" <<<"${out_nic}"; then ok "real mode refuses with a physical network card up"; else bad "real mode nic refusal (rc=${rc_nic})"; fi
if [ "${rc_tty}" = 2 ] && grep -q "keyboard of the Spark" <<<"${out_tty}"; then ok "real mode refuses without a terminal"; else bad "real mode tty refusal (rc=${rc_tty})"; fi
if [ "${rc_cn_off}" = 0 ] && grep -q OFFLINE "${tmp}/cn.off" && [ "${rc_cn_on}" = 1 ] && grep -q ONLINE "${tmp}/cn.on"; then ok "network check: offline passes, online fails"; else bad "network check controls (${rc_cn_off} ${rc_cn_on})"; fi
[ ! -e "${tmp}/tripwire" ] && ok "no refused real run called a YubiKey tool" || bad "a refused real run called a YubiKey tool"
[ ! -e "${tmp}/real1" ] && [ ! -e "${tmp}/real2" ] && [ ! -e "${tmp}/real3" ] && ok "refused real runs wrote nothing" || bad "refused real run wrote output"

# 4. images
own="${tmp}/dry/owner-pubkeys.txt"; ohex="$(sed -n 's/^owner_root_ed25519 //p' "${own}")"
printf 'machine_id %s\nstore_uuid %s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 16)" > "${tmp}/machine.txt"
K="${root}/native/kernel"
make -s -C "${K}" OUT="${tmp}/img-own" full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own}" CK_MACHINE_ID="${tmp}/machine.txt" > "${tmp}/img-own.log" 2>&1 || { tail -5 "${tmp}/img-own.log"; bad "owner image build"; }
make -s -C "${K}" OUT="${tmp}/img-test" full CK_SEED0B_TEST_ANCHOR=1 > "${tmp}/img-test.log" 2>&1 || { tail -5 "${tmp}/img-test.log"; bad "TEST-anchor image build"; }
eo="${tmp}/img-own/full-hardware-staging/aienos-ck.elf"; et="${tmp}/img-test/aienos-ck.elf"
[ -s "${eo}" ] || eo="$(find "${tmp}/img-own" -name aienos-ck.elf | head -n 1)"
[ -s "${et}" ] || et="$(find "${tmp}/img-test" -name aienos-ck.elf | head -n 1)"
if hexof "${eo}" | grep -q "${ohex}"; then ok "owner image carries the owner public key"; else bad "owner image lacks the owner key"; fi
if hexof "${et}" | grep -q "${ohex}"; then bad "TEST-anchor image carries the owner key"; else ok "TEST-anchor control image has no owner key"; fi
so="$(strings -a "${eo}")"; st="$(strings -a "${et}")"
if grep -q "seed0b-test qualification build" <<<"${st}"; then ok "control: TEST-anchor image carries the TEST ONLY artifact_trust banner"; else bad "control banner missing, the check below would prove nothing"; fi
if grep -qE "seed0b-test qualification build|TEST ONLY|TEST-ONLY|AIEN-TEST-BOOT|LANE18-TEST-KVOL|TEST machine id" <<<"${so}"; then bad "owner image carries a TEST anchor/banner: $(grep -E 'seed0b-test qualification build|TEST ONLY|TEST-ONLY|AIEN-TEST-BOOT|LANE18-TEST-KVOL|TEST machine id' <<<"${so}" | head -n 3)"; else ok "owner image has no TEST anchor banner, TEST Store label or TEST machine id"; fi
if grep -q "no TEST Store label, uuid or key code" "${tmp}/img-own.log" || make -s -C "${K}" -n OUT="${tmp}/x" full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own}" CK_MACHINE_ID="${tmp}/machine.txt" >/dev/null 2>&1; then ok "Makefile owner_check accepts the owner image"; else bad "owner_check"; fi
for flag in CK_PI5=1 CK_PI5_ARTIFACT=1 CK_SEED0B_TEST_ANCHOR=1; do
    if make -n -C "${K}" ${flag} full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own}" CK_MACHINE_ID="${tmp}/machine.txt" >/dev/null 2>&1; then bad "Makefile accepts ${flag} with CK_HARDWARE_STAGING"; else ok "Makefile refuses ${flag} with CK_HARDWARE_STAGING (TEST tier and owner image never mix)"; fi
done
if make -n -C "${K}" full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${own}" CK_MACHINE_ID="${tmp}/machine.txt" >/dev/null 2>&1; then ok "positive control: owner image build is accepted"; else bad "positive control"; fi
cp "${tmp}/machine.txt" "${tmp}/machine.copy"; printf 'owner_root_ed25519 d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\n' > "${tmp}/t1.txt"
if make -n -C "${K}" OUT="${tmp}/x2" full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${tmp}/t1.txt" CK_MACHINE_ID="${tmp}/machine.txt" >/dev/null 2>&1 && make -s -C "${K}" OUT="${tmp}/x2" full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="${tmp}/t1.txt" CK_MACHINE_ID="${tmp}/machine.txt" >/dev/null 2>&1; then bad "an RFC 8032 TEST key was accepted as owner key"; else ok "an RFC 8032 TEST key is refused as owner key"; fi
[ "${fail}" = 0 ] && echo "PASS ck_pi5_owner_check" || { echo "FAIL ck_pi5_owner_check"; exit 1; }
