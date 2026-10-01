#!/usr/bin/env bash
# m5_migsig tool test: build, sign and verify an owner-signed migration
# record with FRESHLY GENERATED TEST KEYS (random, labelled TEST-ONLY, deleted
# afterwards; never an owner key), then check every refusal end to end.
# If openssl is installed, also cross-checks the public key and the signature
# against it (an independent Ed25519); otherwise that part is reported skipped.
# Usage: m5_migsig_tool_test.sh TOOL WORK_DIR
# Last line: M5_MIGSIG_TOOL: PASS (exit 0) or M5_MIGSIG_TOOL: FAIL (exit 1).
set -u
tool="$(realpath "$1")"; work="$2"
umask 077
rm -rf "${work}"; mkdir -p "${work}"; cd "${work}" || exit 1
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
# expect RC DESCRIPTION -- command...
expect() {
    local want="$1" what="$2"; shift 3
    "$@" >out.log 2>&1; local rc=$?
    if [[ ${rc} == "${want}" ]]; then ok "${what}"; else bad "${what} (exit ${rc}, want ${want}): $(head -c 300 out.log)"; fi
}
flip_byte() { # FILE OFFSET
    local v; v=$(od -An -tu1 -j "$2" -N1 "$1" | tr -d ' ')
    printf "\\x$(printf %02x $((v ^ 1)))" | dd of="$1" bs=1 seek="$2" conv=notrunc status=none
}

head -c 32 /dev/urandom > TEST-ONLY-owner-key-1.sk
head -c 32 /dev/urandom > TEST-ONLY-owner-key-2.sk
expect 0 "pubkey (TEST key 1)" -- "${tool}" pubkey TEST-ONLY-owner-key-1.sk TEST-ONLY-owner-key-1.pub
expect 0 "pubkey (TEST key 2)" -- "${tool}" pubkey TEST-ONLY-owner-key-2.sk TEST-ONLY-owner-key-2.pub
[[ $(wc -c < TEST-ONLY-owner-key-1.pub) == 65 ]] && ok "public key file is 64 hex + newline" || bad "public key file size"

man=$(printf 'AIENOS TEST-ONLY manifest' | sha256sum | cut -d' ' -f1)
cat > spec.txt <<SPEC
# TEST-ONLY migration spec
class=test
agent_root=$(printf '32%.0s' $(seq 32))
source_store=$(printf 'a0%.0s' $(seq 16))
dest_store=$(printf 'd0%.0s' $(seq 16))
source_store_generation=9
store_format_version=1
envelope=$(printf '30%.0s' $(seq 32))
envelope=$(printf '10%.0s' $(seq 32))
envelope=$(printf '20%.0s' $(seq 32))
migration_manifest_digest=${man}
migration_counter=4
owner_hierarchy_generation=1
SPEC
expect 0 "body from spec" -- "${tool}" body spec.txt TEST-ONLY-owner-key-1.pub body.bin
[[ $(wc -c < body.bin) == 272 ]] && ok "body is 272 bytes" || bad "body size"
expect 0 "sign with TEST key 1" -- "${tool}" sign TEST-ONLY-owner-key-1.sk body.bin rec.bin
expect 0 "verify (last counter 3)" -- "${tool}" verify TEST-ONLY-owner-key-1.pub rec.bin spec.txt 3
grep -q '^M5_OWNER_MIGRATION_VERIFY: OK$' out.log && grep -q '^envelope_count=3$' out.log && ok "verify output" || bad "verify output"

# Refusals
expect 1 "wrong public key refused" -- "${tool}" verify TEST-ONLY-owner-key-2.pub rec.bin spec.txt 3
grep -q 'REFUSED AUTH' out.log && ok "wrong key reported as AUTH" || bad "wrong key reason"
expect 1 "replayed counter (last 4) refused" -- "${tool}" verify TEST-ONLY-owner-key-1.pub rec.bin spec.txt 4
grep -q 'REFUSED REPLAY' out.log && ok "replay reported as REPLAY" || bad "replay reason"
expect 1 "older counter (last 9) refused" -- "${tool}" verify TEST-ONLY-owner-key-1.pub rec.bin spec.txt 9
expect 1 "unsigned body refused" -- "${tool}" verify TEST-ONLY-owner-key-1.pub body.bin spec.txt 3
for off in 0 12 20 90 100 112 124 140 170 195 205 210 271; do
    cp rec.bin t.bin; flip_byte t.bin "${off}"
    expect 1 "tampered byte ${off} refused" -- "${tool}" verify TEST-ONLY-owner-key-1.pub t.bin spec.txt 3
done
for n in 0 1 207 208 271; do
    head -c "${n}" rec.bin > t.bin
    expect 1 "truncated to ${n} bytes refused" -- "${tool}" verify TEST-ONLY-owner-key-1.pub t.bin spec.txt 3
done
{ cat rec.bin; printf 'x'; } > t.bin
expect 1 "extended record refused" -- "${tool}" verify TEST-ONLY-owner-key-1.pub t.bin spec.txt 3
sed 's/^source_store_generation=9$/source_store_generation=8/' spec.txt > spec_gen.txt
expect 1 "verifier expecting another store generation refuses" -- "${tool}" verify TEST-ONLY-owner-key-1.pub rec.bin spec_gen.txt 3
grep -v "^envelope=$(printf '20%.0s' $(seq 32))\$" spec.txt > spec_env.txt
expect 1 "verifier expecting another envelope set refuses" -- "${tool}" verify TEST-ONLY-owner-key-1.pub rec.bin spec_env.txt 3
sed 's/^class=test$/class=production/' spec.txt > spec_cls.txt
expect 1 "TEST-class record refused in production mode" -- "${tool}" verify TEST-ONLY-owner-key-1.pub rec.bin spec_cls.txt 3
expect 1 "signing a body that names another key refused" -- "${tool}" sign TEST-ONLY-owner-key-2.sk body.bin rec2.bin
[[ ! -e rec2.bin ]] && ok "no output after refused signing" || bad "output left after refused signing"
expect 1 "re-signing a signed record refused" -- "${tool}" sign TEST-ONLY-owner-key-1.sk rec.bin rec3.bin
expect 2 "existing output not overwritten" -- "${tool}" sign TEST-ONLY-owner-key-1.sk body.bin rec.bin
cp TEST-ONLY-owner-key-1.sk loose.sk; chmod 644 loose.sk
expect 2 "group/world-readable secret key refused" -- "${tool}" sign loose.sk body.bin rec4.bin
head -c 31 TEST-ONLY-owner-key-1.sk > short.sk
expect 2 "31-byte secret key refused" -- "${tool}" sign short.sk body.bin rec5.bin
{ cat spec.txt; echo "envelope=$(printf '10%.0s' $(seq 32))"; } > spec_dup.txt
expect 2 "duplicate envelope in spec refused" -- "${tool}" body spec_dup.txt TEST-ONLY-owner-key-1.pub b2.bin
grep -v '^migration_counter=' spec.txt > spec_miss.txt
expect 2 "spec missing a key refused" -- "${tool}" body spec_miss.txt TEST-ONLY-owner-key-1.pub b3.bin
{ cat spec.txt; echo "migration_counter=5"; } > spec_twice.txt
expect 2 "spec key given twice refused" -- "${tool}" body spec_twice.txt TEST-ONLY-owner-key-1.pub b4.bin

# Key file formats: hex secret key and PKCS#8 DER give the same signature.
od -An -tx1 -v TEST-ONLY-owner-key-1.sk | tr -d ' \n' > TEST-ONLY-owner-key-1.hex; echo >> TEST-ONLY-owner-key-1.hex
expect 0 "hex secret key accepted" -- "${tool}" sign TEST-ONLY-owner-key-1.hex body.bin rec_hex.bin
cmp -s rec.bin rec_hex.bin && ok "hex key gives the identical record" || bad "hex key record differs"
{ printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'; cat TEST-ONLY-owner-key-1.sk; } > TEST-ONLY-owner-key-1.p8.der
expect 0 "PKCS#8 DER secret key accepted" -- "${tool}" sign TEST-ONLY-owner-key-1.p8.der body.bin rec_der.bin
cmp -s rec.bin rec_der.bin && ok "DER key gives the identical record" || bad "DER key record differs"

# Independent cross-check with openssl (outside tool used only as a test oracle).
if command -v openssl >/dev/null && openssl pkey -inform DER -in TEST-ONLY-owner-key-1.p8.der -pubout -outform DER -out spki.der 2>/dev/null; then
    [[ "$(tail -c 32 spki.der | od -An -tx1 -v | tr -d ' \n')" == "$(head -c 64 TEST-ONLY-owner-key-1.pub)" ]] \
        && ok "public key matches openssl" || bad "public key differs from openssl"
    expect 0 "SPKI DER public key accepted" -- "${tool}" verify spki.der rec.bin spec.txt 3
    { printf 'AIENOS-M5-OWNER-MIGRATION-V1\0'; head -c 208 rec.bin; } > msg.bin
    tail -c 64 rec.bin > sig.bin
    if openssl pkeyutl -verify -pubin -inkey spki.der -keyform DER -rawin -in msg.bin -sigfile sig.bin >/dev/null 2>&1; then
        ok "openssl verifies the record signature"
    else bad "openssl does not verify the record signature"; fi
    flip_byte msg.bin 150
    if openssl pkeyutl -verify -pubin -inkey spki.der -keyform DER -rawin -in msg.bin -sigfile sig.bin >/dev/null 2>&1; then
        bad "openssl accepted a tampered message"
    else ok "openssl refuses the tampered message"; fi
else
    echo "skip openssl cross-check (openssl with Ed25519 not available)"
fi

rm -f ./*.sk ./*.hex ./*.p8.der
if [[ ${fail} == 0 ]]; then echo "M5_MIGSIG_TOOL: PASS"; else echo "M5_MIGSIG_TOOL: FAIL"; exit 1; fi
