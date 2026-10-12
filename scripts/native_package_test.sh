#!/usr/bin/env bash
# native_package_test.sh -- self-test of scripts/native_package.sh (P11 cut 1b).
# Build-only; nothing is booted. Uses the RFC 8032 TEST 1 signer (never for
# hardware) and the labelled TEST-FIXTURE owner files. Every row prints PASS or
# FAIL; the last line is NATIVE_PACKAGE_TEST: PASS|FAIL (n checks).
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)
np="$here/native_package.sh"
fix="$repo/native/kernel/tests/fixtures/owner"
T=$(mktemp -d "${TMPDIR:-/tmp}/native-package-test.XXXXXX")
trap 'rm -rf "$T"' EXIT
export NATIVE_PACKAGE_TOOL_OUT="$T/tool"
checks=0; fails=0
pass() { checks=$((checks+1)); echo "PASS: $1"; }
fail() { checks=$((checks+1)); fails=$((fails+1)); echo "FAIL: $1"; }
expect_ok() { local what="$1"; shift; if out=$("$@" 2>&1); then pass "$what"; else fail "$what: $(echo "$out" | tail -1)"; fi; }
expect_refused() { # what, needle, cmd...
    local what="$1" needle="$2"; shift 2
    if out=$("$@" 2>&1); then fail "$what: accepted"; return; fi
    if echo "$out" | /usr/bin/grep -q -- "$needle"; then pass "$what"; else fail "$what: wrong reason: $(echo "$out" | /usr/bin/grep '^refused' | tail -1)"; fi
}
dirty=()
[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ] || dirty=(--allow-dirty)

printf 'aien-dev/omega 781e98d8224b5bf229991f54722d2dc7c415d79f\naien-dev/physics 57aafa0d69d5d768e46164ff0963ffd87355ab0d\n' >"$T/pins.txt"
head -c 4096 /dev/urandom >"$T/model.bin"
head -c 1024 /dev/urandom >"$T/fw1.bin"

# 1. build a full package with pins, model and firmware digests
expect_ok "build full package (two clean builds identical)" "$np" build --out "$T/p1" --generation 7 --policy-generation 5 --pins "$T/pins.txt" --model "$T/model.bin" --firmware "$T/fw1.bin" "${dirty[@]}"
for k in "commit " "image_sha256 " "reproducible two_clean_builds_identical" "pin aien-dev/omega 781e98d8" "model_sha256 $(sha256sum "$T/model.bin" | cut -c1-64)" "firmware fw1.bin 1024 "; do
    if /usr/bin/grep -q "^$k" "$T/p1/PACKAGE.txt"; then pass "PACKAGE.txt has $k"; else fail "PACKAGE.txt lacks $k"; fi
done
[ "$(stat -c %s "$T/p1/slot/MANIFEST.tbs")" = 448 ] && pass "tbs is 448 bytes" || fail "tbs size"
expect_refused "build refuses an existing --out" "already exists" "$np" build --out "$T/p1" --generation 7 "${dirty[@]}"
echo "aien-dev/omega notahash" >"$T/badpins.txt"
expect_refused "build refuses a bad pins line" "40 hex" "$np" build --out "$T/px" --generation 7 --pins "$T/badpins.txt" "${dirty[@]}"
expect_refused "build refuses owner files without hardware-staging" "only with --variant hardware-staging" "$np" build --out "$T/py" --generation 7 --owner-pubkeys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --machine-id "$fix/TEST-FIXTURE-machine-id.txt" "${dirty[@]}"

# 2. unsigned
expect_refused "verify refuses an unsigned package" "UNSIGNED" "$np" verify --package "$T/p1" --test-key
expect_ok "verify --allow-unsigned accepts the consistent unsigned package" "$np" verify --package "$T/p1" --test-key --allow-unsigned

# 3. test-signed, verify, wrong key
expect_ok "sign-test" "$np" sign-test --package "$T/p1"
expect_refused "sign-test refuses to sign twice" "already signed" "$np" sign-test --package "$T/p1"
expect_ok "verify PASS with the TEST key" "$np" verify --package "$T/p1" --test-key
expect_refused "verify refuses under the fixture owner key" "no trusted key" "$np" verify --package "$T/p1" --keys "$fix/TEST-FIXTURE-owner-pubkeys.txt"
expect_refused "verify needs a key source" "needs --keys" "$np" verify --package "$T/p1"

# 4. tampering (each on a fresh copy)
cp -r "$T/p1" "$T/t1"; chmod u+w "$T/t1/image/BOOTAA64.EFI"; printf '\xff' | dd of="$T/t1/image/BOOTAA64.EFI" bs=1 seek=100 conv=notrunc status=none
expect_refused "tampered image byte" "SHA256SUMS does not match" "$np" verify --package "$T/t1" --test-key
cp -r "$T/p1" "$T/t2"; sed -i 's/^generation 7$/generation 9/' "$T/t2/PACKAGE.txt"
expect_refused "tampered PACKAGE.txt" "SHA256SUMS does not match" "$np" verify --package "$T/t2" --test-key
cp -r "$T/p1" "$T/t3"; sed -i 's/^generation 7$/generation 9/' "$T/t3/PACKAGE.txt"; (cd "$T/t3" && sha256sum image/BOOTAA64.EFI PACKAGE.txt >SHA256SUMS)
expect_refused "tampered PACKAGE.txt with re-made SHA256SUMS" "provenance does not bind" "$np" verify --package "$T/t3" --test-key
cp -r "$T/p1" "$T/t4"; printf '\x01' | dd of="$T/t4/slot/MANIFEST.signed.bin" bs=1 seek=460 conv=notrunc status=none
expect_refused "flipped signature byte" "signature or digest" "$np" verify --package "$T/t4" --test-key
cp -r "$T/p1" "$T/t5"; rm "$T/t5/SHA256SUMS"
expect_refused "missing SHA256SUMS" "missing SHA256SUMS" "$np" verify --package "$T/t5" --test-key

# 5. a signed manifest from another package does not verify here
expect_ok "build core package generation 8" "$np" build --out "$T/p2" --generation 8 --variant core "${dirty[@]}"
expect_ok "sign-test p2" "$np" sign-test --package "$T/p2"
cp -r "$T/p1" "$T/t6"; cp "$T/p2/slot/MANIFEST.signed.bin" "$T/t6/slot/MANIFEST.signed.bin"
expect_refused "signed manifest of another package" "provenance does not bind" "$np" verify --package "$T/t6" --test-key

# 6. non-reproducible build is refused
expect_refused "non-reproducible build refused (test hook)" "not reproducible, not signable" env NATIVE_PACKAGE_TEST_CORRUPT_SECOND=1 "$np" build --out "$T/p3" --generation 7 --variant core "${dirty[@]}"
[ ! -e "$T/p3" ] && pass "no package directory left behind" || fail "refused build left a package"

# 7. hardware-staging variant with the labelled fixtures
expect_ok "build hardware-staging package (fixture owner files)" "$np" build --out "$T/p4" --generation 7 --variant hardware-staging --owner-pubkeys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --machine-id "$fix/TEST-FIXTURE-machine-id.txt" "${dirty[@]}"
/usr/bin/grep -q "^owner_pubkeys_sha256 " "$T/p4/PACKAGE.txt" && pass "staging PACKAGE.txt records owner_pubkeys_sha256" || fail "staging owner digest missing"
/usr/bin/grep -q "^variant hardware-staging$" "$T/p4/PACKAGE.txt" && pass "staging variant recorded" || fail "staging variant"
expect_refused "staging variant needs both owner files" "needs --owner-pubkeys" "$np" build --out "$T/p5" --generation 7 --variant hardware-staging "${dirty[@]}"

echo "NATIVE_PACKAGE_TEST: $([ "$fails" = 0 ] && echo PASS || echo FAIL) ($checks checks, $fails failures)"
[ "$fails" = 0 ]
