#!/usr/bin/env bash
# ck_pi5_manifest_check.sh -- PI5-8 Q6 gate: the receipts manifest tool and its TEST-key signature round trip.
#   1. synthetic run folders -> manifest; second run gives identical bytes; order of arguments does not matter;
#   2. a missing run folder, an absent verdict line and an unknown run tag each make the tool fail with no output;
#   3. the owner signs a fixed statement binding the manifest length and sha256 (PIV Ed25519 takes a small message only);
#      sign with the public RFC 8032 TEST 1 key (TEST ONLY) and verify with the in-tree Ed25519; a flipped manifest byte,
#      a flipped signature byte, a different public key and a signature over the raw manifest must all fail to verify;
#   4. an openssl Ed25519 SOFTWARE key (TEST, stands in for the YubiKey) signs the statement and the tool verifies it.
# No owner or release key is generated or used. Set PI5_RUNS=<dir> to also build the manifest of real runs.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
fail=0
ok() { echo "PASS $*"; }
bad() { echo "FAIL $*"; fail=1; }
cc -std=gnu11 -O1 -Wall -Wextra -Werror -I"${root}/native/sig" -I"${root}/native/argus" -o "${tmp}/sig" \
    "${root}/native/kernel/tools/ck_manifest_sig.c" "${root}/native/sig/ed25519.c" "${root}/native/sig/sha512.c" "${root}/native/sig/ct.c" "${root}/native/argus/sha256.c"
mk() { # tag efi commit log-lines...
    local t="$1" e="$2" c="$3"; shift 3
    mkdir -p "${tmp}/runs/${t}"
    echo "[00:00:00Z] run ${t}: efi=/x/BOOTAA64.EFI sha256=${e}" > "${tmp}/runs/${t}/run.log"
    { echo "aienos_commit: ${c}"; printf '%s\r\n' "$@"; } > "${tmp}/runs/${t}/kernel.log"
}
e1=$(printf 'a%.0s' $(seq 64)); e2=$(printf 'b%.0s' $(seq 64)); c1=$(printf '1%.0s' $(seq 40))
printf 'pi5-x1\tT first\t^good: \npi5-x1\tT first\t^also=[0-9]+$\npi5-x2\tT second\t^other ok$\n' > "${tmp}/t.tsv"
mk pi5-x1 "${e1}" "${c1}" "good: yes" "noise" "also=42"
mk pi5-x2 "${e2}" "${c1}" "other ok"
M="${root}/scripts/pi5_receipts_manifest.sh"
"${M}" -t "${tmp}/t.tsv" "${tmp}/runs/pi5-x2" "${tmp}/runs/pi5-x1" > "${tmp}/m1"
"${M}" -t "${tmp}/t.tsv" "${tmp}/runs/pi5-x1" "${tmp}/runs/pi5-x2" > "${tmp}/m2"
if cmp -s "${tmp}/m1" "${tmp}/m2" && [ -s "${tmp}/m1" ]; then ok "manifest is deterministic and independent of argument order"; else bad "manifest not deterministic"; fi
grep -q "^efi_sha256 ${e1}$" "${tmp}/m1" && grep -q "^aienos_commit ${c1}$" "${tmp}/m1" && grep -q "^  | good: yes$" "${tmp}/m1" && grep -q "^runs 2$" "${tmp}/m1" \
    && ok "manifest carries efi sha256, commit, verdict lines (CR stripped)" || bad "manifest content"
if ! grep -q $'\r' "${tmp}/m1"; then ok "manifest has no carriage returns"; else bad "CR in manifest"; fi
if "${M}" -t "${tmp}/t.tsv" "${tmp}/runs/pi5-x1" "${tmp}/runs/pi5-nope" > "${tmp}/o" 2>"${tmp}/e"; then bad "missing run folder accepted"; elif [ ! -s "${tmp}/o" ] && grep -q MISSING "${tmp}/e"; then ok "missing run folder refused, no manifest"; else bad "missing run folder handling"; fi
printf 'pi5-x1\tT first\t^never matches$\n' > "${tmp}/t2.tsv"
if "${M}" -t "${tmp}/t2.tsv" "${tmp}/runs/pi5-x1" > "${tmp}/o" 2>"${tmp}/e"; then bad "absent verdict line accepted"; elif [ ! -s "${tmp}/o" ]; then ok "absent verdict line refused, no manifest"; else bad "absent verdict output"; fi
if "${M}" -t "${tmp}/t.tsv" "${tmp}/runs/pi5-x1" "${tmp}/runs/pi5-x2" "${tmp}/runs/pi5-x1" > "${tmp}/o3" 2>/dev/null && cmp -s "${tmp}/o3" "${tmp}/m1"; then ok "duplicate folder argument is folded"; else bad "duplicate folder"; fi
mkdir -p "${tmp}/runs/pi5-x3"; cp "${tmp}/runs/pi5-x1/"* "${tmp}/runs/pi5-x3/"
if "${M}" -t "${tmp}/t.tsv" "${tmp}/runs/pi5-x3" > "${tmp}/o" 2>/dev/null; then bad "run tag without table rows accepted"; else ok "run tag without table rows refused"; fi
# TEST-key signature round trip over the statement that binds the manifest
TPK=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
# the statement is exactly four LF lines and agrees with an independent sha256sum
"${tmp}/sig" statement "${tmp}/m1" "${tmp}/m1.st"
want="$(printf 'AIENOS-OWNER-STATEMENT-V1\npurpose pi5-8-receipts-manifest\nmanifest_bytes %s\nmanifest_sha256 %s\n' "$(wc -c < "${tmp}/m1")" "$(sha256sum < "${tmp}/m1" | cut -d' ' -f1)"; echo x)"
got="$(cat "${tmp}/m1.st"; echo x)"
if [ "${want}" = "${got}" ] && [ "$(wc -l < "${tmp}/m1.st")" = 4 ]; then ok "statement bytes match the spec and sha256sum"; else bad "statement bytes"; fi
"${tmp}/sig" sign-test "${tmp}/m1" "${tmp}/m1.sig" | tee "${tmp}/s.out"
grep -q "TEST ONLY" "${tmp}/s.out" && ok "sign-test says TEST ONLY" || bad "sign-test label"
"${tmp}/sig" verify "${tmp}/m1" "${tmp}/m1.sig" "${TPK}" | tee "${tmp}/v.out" && grep -q "^MANIFEST_SIG: PASS" "${tmp}/v.out" && ok "signature verifies with the in-tree Ed25519" || bad "verify"
cp "${tmp}/m1" "${tmp}/m1.bad"; printf 'X' | dd of="${tmp}/m1.bad" bs=1 seek=40 conv=notrunc 2>/dev/null
if "${tmp}/sig" verify "${tmp}/m1.bad" "${tmp}/m1.sig" "${TPK}" >/dev/null; then bad "tampered manifest verified"; else ok "tampered manifest fails to verify"; fi
cp "${tmp}/m1.sig" "${tmp}/s.bad"; printf 'Z' | dd of="${tmp}/s.bad" bs=1 seek=10 conv=notrunc 2>/dev/null
if "${tmp}/sig" verify "${tmp}/m1" "${tmp}/s.bad" "${TPK}" >/dev/null; then bad "tampered signature verified"; else ok "tampered signature fails to verify"; fi
if "${tmp}/sig" verify "${tmp}/m1" "${tmp}/m1.sig" 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c >/dev/null; then bad "wrong key verified"; else ok "wrong public key fails to verify"; fi
# a signature over the raw manifest (the old, pre-statement scheme) must not verify
openssl genpkey -algorithm ED25519 -out "${tmp}/sw.pem" 2>/dev/null
SWPK="$(openssl pkey -in "${tmp}/sw.pem" -pubout -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n')"
openssl pkeyutl -sign -rawin -inkey "${tmp}/sw.pem" -in "${tmp}/m1" -out "${tmp}/raw.sig"
if "${tmp}/sig" verify "${tmp}/m1" "${tmp}/raw.sig" "${SWPK}" >/dev/null; then bad "raw-manifest signature verified"; else ok "signature over the raw manifest is refused"; fi
# TEST software key standing in for the YubiKey: sign the statement bytes, verify through the tool
openssl pkeyutl -sign -rawin -inkey "${tmp}/sw.pem" -in "${tmp}/m1.st" -out "${tmp}/sw.sig"
"${tmp}/sig" verify "${tmp}/m1" "${tmp}/sw.sig" "${SWPK}" | tee "${tmp}/sv.out"
grep -q "^MANIFEST_SIG: PASS" "${tmp}/sv.out" && ok "openssl software key (TEST) signature over the statement verifies" || bad "software key verify"
if "${tmp}/sig" verify "${tmp}/m1.bad" "${tmp}/sw.sig" "${SWPK}" >/dev/null; then bad "software signature verified a tampered manifest"; else ok "software signature fails on a tampered manifest"; fi
if [ -n "${PI5_RUNS:-}" ]; then
    "${M}" --all "${PI5_RUNS}" > "${tmp}/real" && echo "real manifest: $(grep -c '^run ' "${tmp}/real") runs, $(wc -c < "${tmp}/real") bytes, sha256 $(sha256sum < "${tmp}/real" | cut -d' ' -f1)" || bad "real runs manifest"
fi
[ "${fail}" = 0 ] && echo "PASS ck_pi5_manifest_check" || { echo "FAIL ck_pi5_manifest_check"; exit 1; }
