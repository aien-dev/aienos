#!/usr/bin/env bash
# native_package_test.sh -- self-test of scripts/native_package.sh (P11 cut 1b and
# its provenance record). Build-only; nothing is booted. Uses the RFC 8032 TEST 1
# signer (never for hardware), the labelled TEST-FIXTURE owner files, and one
# throwaway Ed25519 key made here with OpenSSL for the offline-signing round trip.
# Every row prints PASS or FAIL; the last line is NATIVE_PACKAGE_TEST: PASS|FAIL (n checks).
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)
np="$here/native_package.sh"
fix="$repo/native/kernel/tests/fixtures/owner"
T=$(mktemp -d "${TMPDIR:-/tmp}/native-package-test.XXXXXX")
cleanup() { rm -rf "$T"; }
trap cleanup EXIT
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
has_line() { # what, file, regex
    if /usr/bin/grep -qE -- "$3" "$2"; then pass "$1"; else fail "$1"; fi
}
remake_sums() {
    (cd "$1" && sha256sum image/BOOTAA64.EFI loader/SLOTLDR.EFI PACKAGE.txt >SHA256SUMS
     if [ -f inputs/libaienos_infer_kernel.a ]; then sha256sum inputs/libaienos_infer_kernel.a >>SHA256SUMS; fi)
}
remake_all() { remake_sums "$1"; echo "package_sha256 $(sha256sum "$1/SHA256SUMS" | cut -c1-64)" >"$1/PROVENANCE.txt"; }
dirty=()
tree_clean=yes
if [ -n "$(git -C "$repo" status --porcelain --untracked-files=no)" ]; then dirty=(--allow-dirty); tree_clean=no; fi
# The cross prefix the kernel Makefile picks when CROSS is not set (native/kernel/Makefile).
if [ -n "${CROSS+x}" ]; then want_cross="${CROSS:-none}"; elif [ "$(uname -m)" = aarch64 ]; then want_cross=none; else want_cross=aarch64-linux-gnu-; fi
wc_=""; [ "$want_cross" = none ] || wc_="$want_cross"

printf 'aien-dev/omega 781e98d8224b5bf229991f54722d2dc7c415d79f\naien-dev/physics 57aafa0d69d5d768e46164ff0963ffd87355ab0d\n' >"$T/pins.txt"
head -c 4096 /dev/urandom >"$T/model.bin"
head -c 1024 /dev/urandom >"$T/fw1.bin"

# 1. build a full package with pins, model and firmware digests
expect_ok "build full package (two clean builds identical)" "$np" build --out "$T/p1" --generation 7 --policy-generation 5 --pins "$T/pins.txt" --model "$T/model.bin" --firmware "$T/fw1.bin" "${dirty[@]}"
P="$T/p1/PACKAGE.txt"
for k in "commit " "image_sha256 " "reproducible two_clean_builds_identical" "pin aien-dev/omega 781e98d8" "model_sha256 $(sha256sum "$T/model.bin" | cut -c1-64)" "firmware fw1.bin 1024 "; do
    if /usr/bin/grep -q "^$k" "$P"; then pass "PACKAGE.txt has $k"; else fail "PACKAGE.txt lacks $k"; fi
done
[ "$(stat -c %s "$T/p1/slot/MANIFEST.bin")" = 4096 ] && pass "manifest is 4096 bytes" || fail "manifest size"
# 1b. the provenance record: source revision, toolchain, inputs, resulting digest
has_line "record: format 3" "$P" "^format 3$"
has_line "record: commit is HEAD" "$P" "^commit $(git -C "$repo" rev-parse HEAD)$"
has_line "record: commit_time is HEAD's" "$P" "^commit_time $(git -C "$repo" log -1 --format=%ct)$"
has_line "record: tree_clean $tree_clean" "$P" "^tree_clean $tree_clean$"
has_line "record: toolchain_cross $want_cross" "$P" "^toolchain_cross $want_cross$"
has_line "record: toolchain_cc = ${wc_}gcc --version" "$P" "^toolchain_cc $(${wc_}gcc --version | head -1 | sed 's/[][\.*^$()+?{}|]/\\&/g')$"
has_line "record: toolchain_ld = ${wc_}ld --version" "$P" "^toolchain_ld $(${wc_}ld --version | head -1 | sed 's/[][\.*^$()+?{}|]/\\&/g')$"
has_line "record: toolchain_objcopy = ${wc_}objcopy --version" "$P" "^toolchain_objcopy $(${wc_}objcopy --version | head -1 | sed 's/[][\.*^$()+?{}|]/\\&/g')$"
has_line "record: toolchain_make" "$P" "^toolchain_make GNU Make "
has_line "record: build_host_arch" "$P" "^build_host_arch $(uname -m)$"
has_line "record: input_make_goal full" "$P" "^input_make_goal full$"
has_line "record: input_make_vars none" "$P" "^input_make_vars none$"
has_line "record: input_env_ck none" "$P" "^input_env_ck none$"
has_line "record: input_makefile_sha256" "$P" "^input_makefile_sha256 $(sha256sum "$repo/native/kernel/Makefile" | cut -c1-64)$"
has_line "record: input_image_ld_sha256" "$P" "^input_image_ld_sha256 $(sha256sum "$repo/native/boot/image.ld" | cut -c1-64)$"
has_line "record: image_bytes" "$P" "^image_bytes $(stat -c %s "$T/p1/image/BOOTAA64.EFI")$"
has_line "record: image_sha512" "$P" "^image_sha512 $(sha512sum "$T/p1/image/BOOTAA64.EFI" | cut -c1-128)$"
has_line "PROVENANCE.txt package_sha256 = sha256(SHA256SUMS)" "$T/p1/PROVENANCE.txt" "^package_sha256 $(sha256sum "$T/p1/SHA256SUMS" | cut -c1-64)$"
"$NATIVE_PACKAGE_TOOL_OUT/host/ck_slot_tool" show "$T/p1/slot/MANIFEST.bin" | /usr/bin/grep -q "provenance=$(sha256sum "$T/p1/SHA256SUMS" | cut -c1-64)" \
    && pass "manifest provenance = package_sha256" || fail "manifest provenance"
# 1c. the slot loader in the package (P11 cut 3): TEST-key loader for a full package
has_line "record: loader path" "$P" "^loader loader/SLOTLDR.EFI$"
has_line "record: loader_keys test (full package)" "$P" "^loader_keys test$"
has_line "record: loader_sha256" "$P" "^loader_sha256 $(sha256sum "$T/p1/loader/SLOTLDR.EFI" | cut -c1-64)$"
has_line "record: loader_reproducible" "$P" "^loader_reproducible two_clean_builds_identical$"
has_line "SHA256SUMS covers the loader" "$T/p1/SHA256SUMS" " loader/SLOTLDR.EFI$"
LC_ALL=C /usr/bin/grep -aqF "TEST-ONLY key" "$T/p1/loader/SLOTLDR.EFI" && pass "full package loader carries its TEST-ONLY key note" || fail "full package loader lacks the TEST-ONLY note"
cp -r "$T/p1" "$T/p1o"   # unsigned copy for the offline-signing round trip (section 8)
expect_refused "build refuses an existing --out" "already exists" "$np" build --out "$T/p1" --generation 7 "${dirty[@]}"
echo "aien-dev/omega notahash" >"$T/badpins.txt"
expect_refused "build refuses a bad pins line" "40 hex" "$np" build --out "$T/px" --generation 7 --pins "$T/badpins.txt" "${dirty[@]}"
expect_refused "build refuses owner files without hardware-staging" "only with --variant hardware-staging" "$np" build --out "$T/py" --generation 7 --owner-pubkeys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --machine-id "$fix/TEST-FIXTURE-machine-id.txt" "${dirty[@]}"
expect_refused "build refuses CK_* in the environment" "CK_EXTRA_CFLAGS" env CK_EXTRA_CFLAGS=-DX "$np" build --out "$T/pz" --generation 7 "${dirty[@]}"
expect_refused "build refuses CK_* passed down in MAKEFLAGS" "CK_SERVICE" env MAKEFLAGS=" -- CK_SERVICE=1" "$np" build --out "$T/pz" --generation 7 "${dirty[@]}"
# A dirty tree is refused: a scratch clone of HEAD with this script and one changed tracked
# file (the real checkout is never touched). A plain clone into $T, not a worktree: a
# worktree writes the repository's own git dir, which the local sandbox keeps read-only.
if git -c core.hooksPath=/dev/null clone -q --no-hardlinks "$repo" "$T/wt" >/dev/null 2>&1; then
    cp "$np" "$T/wt/scripts/native_package.sh"
    echo "# dirty" >>"$T/wt/native/kernel/Makefile"
    expect_refused "build refuses a dirty tree" "working tree is dirty" "$T/wt/scripts/native_package.sh" build --out "$T/pd" --generation 7 --variant core
    [ ! -e "$T/pd" ] && pass "dirty refusal leaves no package" || fail "dirty refusal left a package"
    printf 'fn main() {}\n' >"$T/wt/crates/aienos-infer-kernel/build.rs"
    expect_refused "service refuses automatically discovered untracked Rust build script" "untracked inference build inputs" "$T/wt/scripts/native_package.sh" build --out "$T/untracked-service" --generation 1 --variant service-hardware-staging --owner-pubkeys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --machine-id "$fix/TEST-FIXTURE-machine-id.txt" --model "$T/model.bin" --allow-dirty
else
    fail "could not make a scratch worktree for the dirty-tree check"; fail "dirty refusal leaves no package (not run)"
fi

# 2. unsigned
expect_refused "verify refuses an unsigned package" "UNSIGNED" "$np" verify --package "$T/p1" --test-key "${dirty[@]}"
expect_ok "verify --allow-unsigned accepts the consistent unsigned package" "$np" verify --package "$T/p1" --test-key --allow-unsigned "${dirty[@]}"

# 3. test-signed, verify, wrong key
expect_ok "sign-test" "$np" sign-test --package "$T/p1"
expect_refused "sign-test refuses to sign twice" "already signed" "$np" sign-test --package "$T/p1"
expect_ok "verify PASS with the TEST key" "$np" verify --package "$T/p1" --test-key "${dirty[@]}"
expect_refused "verify refuses under the fixture owner key" "no trusted key" "$np" verify --package "$T/p1" --keys "$fix/TEST-FIXTURE-owner-pubkeys.txt" "${dirty[@]}"
expect_refused "verify needs a key source" "needs --keys" "$np" verify --package "$T/p1"
out=$("$np" verify --package "$T/p1" --test-key "${dirty[@]}" 2>&1)
echo "$out" | /usr/bin/grep -q "^  recorded toolchain_cc " && pass "verify prints toolchain lines as recorded" || fail "verify toolchain recorded lines"
echo "$out" | /usr/bin/grep -q "^  checked  input_makefile_sha256 " && pass "verify recomputes the Makefile digest" || fail "verify Makefile digest line"
out=$("$np" verify --package "$T/p1" --test-key --same-host "${dirty[@]}" 2>&1)
echo "$out" | /usr/bin/grep -q "^  checked  toolchain_cc " && pass "verify --same-host checks the toolchain" || fail "verify --same-host: $(echo "$out" | tail -1)"

# 4. tampering (each on a fresh copy)
cp -r "$T/p1" "$T/t1"; chmod u+w "$T/t1/image/BOOTAA64.EFI"; printf '\xff' | dd of="$T/t1/image/BOOTAA64.EFI" bs=1 seek=100 conv=notrunc status=none
expect_refused "tampered image byte" "SHA256SUMS does not match" "$np" verify --package "$T/t1" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t1l"; chmod u+w "$T/t1l/loader/SLOTLDR.EFI"; printf '\xff' | dd of="$T/t1l/loader/SLOTLDR.EFI" bs=1 seek=100 conv=notrunc status=none
expect_refused "tampered loader byte" "SHA256SUMS does not match" "$np" verify --package "$T/t1l" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t1m"; rm -f "$T/t1m/loader/SLOTLDR.EFI"
expect_refused "missing loader" "missing loader/SLOTLDR.EFI" "$np" verify --package "$T/t1m" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t2"; sed -i 's/^generation 7$/generation 9/' "$T/t2/PACKAGE.txt"
expect_refused "tampered PACKAGE.txt" "SHA256SUMS does not match" "$np" verify --package "$T/t2" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t3"; sed -i 's/^generation 7$/generation 9/' "$T/t3/PACKAGE.txt"; remake_sums "$T/t3"
expect_refused "tampered PACKAGE.txt with re-made SHA256SUMS" "PROVENANCE.txt package_sha256" "$np" verify --package "$T/t3" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t3b"; sed -i 's/^generation 7$/generation 9/' "$T/t3b/PACKAGE.txt"; remake_all "$T/t3b"
expect_refused "tampered PACKAGE.txt with re-made SHA256SUMS and PROVENANCE.txt" "provenance does not bind" "$np" verify --package "$T/t3b" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t4"; b=$(od -An -tu1 -j460 -N1 "$T/t4/slot/MANIFEST.signed.bin" | tr -d " "); printf "\\$(printf %o $(( b ^ 0xff )))" | dd of="$T/t4/slot/MANIFEST.signed.bin" bs=1 seek=460 conv=notrunc status=none
expect_refused "flipped signature byte" "signature or digest" "$np" verify --package "$T/t4" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t5"; rm "$T/t5/SHA256SUMS"
expect_refused "missing SHA256SUMS" "missing SHA256SUMS" "$np" verify --package "$T/t5" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t5b"; rm "$T/t5b/PROVENANCE.txt"
expect_refused "missing PROVENANCE.txt" "missing PROVENANCE.txt" "$np" verify --package "$T/t5b" --test-key "${dirty[@]}"
cp -r "$T/p1" "$T/t5c"; echo "package_sha256 $(printf '0%.0s' $(seq 64))" >"$T/t5c/PROVENANCE.txt"
expect_refused "tampered PROVENANCE.txt" "PROVENANCE.txt package_sha256" "$np" verify --package "$T/t5c" --test-key "${dirty[@]}"
# 4b. record lines that verify recomputes, each with re-made sums so only the record check can catch it
tamper() { # name, sed expression, needle, extra verify args...
    local name="$1" d="$T/r-$1" e="$2" needle="$3"; shift 3
    cp -r "$T/p1" "$d"; sed -i "$e" "$d/PACKAGE.txt"; remake_all "$d"
    expect_refused "record check: $name" "$needle" "$np" verify --package "$d" --test-key "$@"
}
# digest tampers flip the first hex digit to a different one (f becomes 0), so they never leave the record unchanged
tamper tree-clean-no 's/^tree_clean .*/tree_clean no/' "dirty tree (tree_clean no)"
tamper makefile-digest 's/^input_makefile_sha256 f/input_makefile_sha256 0/;t;s/^input_makefile_sha256 ./input_makefile_sha256 f/' "input_makefile_sha256 does not match" "${dirty[@]}"
tamper image-ld-digest 's/^input_image_ld_sha256 f/input_image_ld_sha256 0/;t;s/^input_image_ld_sha256 ./input_image_ld_sha256 f/' "input_image_ld_sha256 does not match" "${dirty[@]}"
tamper commit-time 's/^commit_time .*/commit_time 1/' "commit_time does not match" "${dirty[@]}"
tamper image-sha512 's/^image_sha512 f/image_sha512 0/;t;s/^image_sha512 ./image_sha512 f/' "image_sha512 does not match" "${dirty[@]}"
tamper image-bytes 's/^image_bytes .*/image_bytes 1/' "image_bytes does not match" "${dirty[@]}"
tamper make-vars 's/^input_make_vars .*/input_make_vars CK_SERVICE=1/' "input_make_vars does not match" "${dirty[@]}"
tamper make-goal 's/^input_make_goal .*/input_make_goal all/' "input_make_goal does not match" "${dirty[@]}"
tamper env-ck 's/^input_env_ck .*/input_env_ck CK_EXTRA_CFLAGS/' "input_env_ck is not none" "${dirty[@]}"
tamper missing-toolchain '/^toolchain_objcopy /d' "exactly one toolchain_objcopy" "${dirty[@]}"
tamper duplicate-commit '/^commit /p' "exactly one commit" "${dirty[@]}"
tamper toolchain-same-host 's/^toolchain_cc .*/toolchain_cc gcc 0.0/' "toolchain_cc differs from this host" --same-host "${dirty[@]}"
tamper loader-sha256 's/^loader_sha256 f/loader_sha256 0/;t;s/^loader_sha256 ./loader_sha256 f/' "loader_sha256 does not match" "${dirty[@]}"
tamper loader-keys 's/^loader_keys .*/loader_keys owner/' "loader_keys does not match the variant" "${dirty[@]}"
tamper missing-loader-line '/^loader_bytes /d' "exactly one loader_bytes" "${dirty[@]}"

# 5. a signed manifest from another package does not verify here
expect_ok "build core package generation 8" "$np" build --out "$T/p2" --generation 8 --variant core "${dirty[@]}"
has_line "core record: input_make_goal all" "$T/p2/PACKAGE.txt" "^input_make_goal all$"
expect_ok "sign-test p2" "$np" sign-test --package "$T/p2"
cp -r "$T/p1" "$T/t6"; cp "$T/p2/slot/MANIFEST.signed.bin" "$T/t6/slot/MANIFEST.signed.bin"
expect_refused "signed manifest of another package" "provenance does not bind" "$np" verify --package "$T/t6" --test-key "${dirty[@]}"

# 6. non-reproducible build is refused
expect_refused "non-reproducible build refused (test hook)" "not reproducible, not signable" env NATIVE_PACKAGE_TEST_CORRUPT_SECOND=1 "$np" build --out "$T/p3" --generation 7 --variant core "${dirty[@]}"
[ ! -e "$T/p3" ] && pass "no package directory left behind" || fail "refused build left a package"

# 7. hardware-staging variant with the labelled fixtures
expect_ok "build hardware-staging package (fixture owner files)" "$np" build --out "$T/p4" --generation 7 --variant hardware-staging --owner-pubkeys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --machine-id "$fix/TEST-FIXTURE-machine-id.txt" "${dirty[@]}"
/usr/bin/grep -q "^owner_pubkeys_sha256 " "$T/p4/PACKAGE.txt" && pass "staging PACKAGE.txt records owner_pubkeys_sha256" || fail "staging owner digest missing"
/usr/bin/grep -q "^variant hardware-staging$" "$T/p4/PACKAGE.txt" && pass "staging variant recorded" || fail "staging variant"
has_line "staging record: loader_keys owner" "$T/p4/PACKAGE.txt" "^loader_keys owner$"
LC_ALL=C /usr/bin/grep -aqF "TEST-ONLY" "$T/p4/loader/SLOTLDR.EFI" && fail "staging loader carries a TEST-ONLY note" || pass "staging loader carries no TEST-ONLY note (owner keys only)"
has_line "staging record: input_make_vars names the owner files by digest" "$T/p4/PACKAGE.txt" \
    "^input_make_vars CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=sha256:$(sha256sum "$fix/TEST-FIXTURE-owner-pubkeys.txt" | cut -c1-64) CK_MACHINE_ID=sha256:$(sha256sum "$fix/TEST-FIXTURE-machine-id.txt" | cut -c1-64)$"
expect_refused "staging variant needs both owner files" "needs --owner-pubkeys" "$np" build --out "$T/p5" --generation 7 --variant hardware-staging "${dirty[@]}"

# 8. offline signing round trip with a throwaway key and OpenSSL, as the owner will do it
#    (docs/OWNER_KEY_CEREMONY.md part 3 step 9): tbs --pubkey, openssl pkeyutl -sign -rawin,
#    sign --sig --pubkey, verify --keys. Only the public key reaches native_package.sh.
O="$T/p1o"
if openssl genpkey -algorithm ed25519 -out "$T/throwaway.key.pem" 2>/dev/null; then
    pk=$(openssl pkey -in "$T/throwaway.key.pem" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')
    printf 'owner_root_ed25519 %s\n' "$pk" >"$T/throwaway-keys.txt"
    expect_refused "tbs needs --pubkey" "needs --package DIR and --pubkey" "$np" tbs --package "$O"
    expect_refused "tbs refuses the TEST 1 key" "known TEST key" "$np" tbs --package "$O" --pubkey d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    # the old way: signing the manifest's own first 448 bytes (signer_id still zero) cannot attach
    head -c 448 "$O/slot/MANIFEST.bin" >"$T/old.tbs"
    openssl pkeyutl -sign -rawin -inkey "$T/throwaway.key.pem" -in "$T/old.tbs" -out "$T/old.sig"
    expect_refused "signature over signer-less bytes is not attached" "signature not attached" "$np" sign --package "$O" --sig "$T/old.sig" --pubkey "$pk" "${dirty[@]}"
    expect_ok "tbs --pubkey" "$np" tbs --package "$O" --pubkey "$pk"
    [ "$(stat -c %s "$O/slot/MANIFEST.tbs")" = 448 ] && pass "tbs is 448 bytes" || fail "tbs size"
    openssl pkeyutl -sign -rawin -inkey "$T/throwaway.key.pem" -in "$O/slot/MANIFEST.tbs" -out "$T/owner.sig"
    cp -r "$O" "$T/Od"; sed -i "s/^tree_clean .*/tree_clean no/" "$T/Od/PACKAGE.txt"; remake_all "$T/Od"
    expect_refused "sign refuses a dirty-tree package without --allow-dirty" "dirty tree" "$np" sign --package "$T/Od" --sig "$T/owner.sig" --pubkey "$pk"
    expect_ok "sign attaches the OpenSSL signature" "$np" sign --package "$O" --sig "$T/owner.sig" --pubkey "$pk" "${dirty[@]}"
    expect_ok "verify PASS under the throwaway owner keys file" "$np" verify --package "$O" --keys "$T/throwaway-keys.txt" "${dirty[@]}"
    sid=$(openssl pkey -in "$T/throwaway.key.pem" -pubout -outform DER | tail -c 32 | openssl dgst -sha256 -r | cut -c1-64)
    "$NATIVE_PACKAGE_TOOL_OUT/host/ck_slot_tool" show "$O/slot/MANIFEST.signed.bin" | /usr/bin/grep -q "signer_id=$sid" \
        && pass "signer_id = SHA-256 of the raw 32-byte public key (OpenSSL agrees)" || fail "signer_id derivation"
    expect_refused "verify refuses the OpenSSL-signed package under the TEST key" "no trusted key" "$np" verify --package "$O" --test-key "${dirty[@]}"
else
    fail "openssl genpkey ed25519 unavailable: offline signing round trip not run"
fi

# 9. The integrated production CPU service uses disk-only inference and owner
# keys. Public fixtures exercise the recipe; nothing is signed for deployment or booted.
S="$T/service"
service_args=(--generation 8 --variant service-hardware-staging --owner-pubkeys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --machine-id "$fix/TEST-FIXTURE-machine-id.txt")
expect_refused "service needs model identity" "needs --model" "$np" build --out "$S" "${service_args[@]}" "${dirty[@]}"
expect_refused "service needs owner provisioning" "needs --owner-pubkeys" "$np" build --out "$S" --generation 8 --variant service-hardware-staging --model "$T/model.bin" "${dirty[@]}"
expect_refused "service refuses externally supplied test flags" "CK_SERVICE_TEST_KEYS" env CK_SERVICE_TEST_KEYS=1 "$np" build --out "$S" "${service_args[@]}" --model "$T/model.bin" "${dirty[@]}"
expect_refused "service refuses non-reproducible inference archive" "two clean inference library builds differ" env NATIVE_PACKAGE_TEST_CORRUPT_INFER_SECOND=1 "$np" build --out "$S" "${service_args[@]}" --model "$T/model.bin" "${dirty[@]}"
[ ! -e "$S" ] && pass "inference reproducibility refusal leaves no package" || fail "inference reproducibility refusal left a package"
mkdir -p "$T/hostile/.cargo"
printf '[build]\nrustflags = ["--invalid-ancestor-config-flag"]\n' >"$T/hostile/.cargo/config.toml"
expect_refused "service refuses scratch ancestor Cargo config" "unrecorded Cargo configuration" env TMPDIR="$T/hostile" "$np" build --out "$S" "${service_args[@]}" --model "$T/model.bin" "${dirty[@]}"
# Rust environment overrides must not reach the recorded fixed build recipe.
mkdir -p "$T/caller/.cargo"
printf '[build]\nrustflags = ["--invalid-caller-config-flag"]\n' >"$T/caller/.cargo/config.toml"
service_from_external_cwd() { (cd "$T/caller" && env RUSTFLAGS=--invalid-package-test-flag "$np" "$@"); }
expect_ok "build production service package with isolated Rust environment and caller config" service_from_external_cwd build --out "$S" "${service_args[@]}" --model "$T/model.bin" "${dirty[@]}"
SP="$S/PACKAGE.txt"
has_line "service profile recorded" "$SP" '^variant service-hardware-staging$'
has_line "service uses owner slot keys" "$SP" '^loader_keys owner$'
has_line "service fixed offline inference recipe recorded" "$SP" '^input_infer_build offline_locked_release_aarch64-unknown-none$'
has_line "service make variables bind inference archive" "$SP" '^input_make_vars CK_SERVICE=1 .* CK_INFER_LIB=sha256:[0-9a-f]{64}$'
has_line "service archive is signed through package checksum" "$S/SHA256SUMS" ' inputs/libaienos_infer_kernel.a$'
has_line "service Rust toolchain recorded" "$SP" '^toolchain_rustc rustc '
has_line "service Cargo lock recorded" "$SP" "^input_infer_lock_sha256 $(sha256sum "$repo/crates/aienos-infer-kernel/Cargo.lock" | cut -c1-64)$"
expect_ok "verify complete unsigned service package on same host" "$np" verify --package "$S" --keys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --allow-unsigned --same-host "${dirty[@]}"
cp -r "$S" "$T/service-bad"
chmod u+w "$T/service-bad/inputs/libaienos_infer_kernel.a"
printf X >>"$T/service-bad/inputs/libaienos_infer_kernel.a"
expect_refused "service rejects changed archive" "SHA256SUMS" "$np" verify --package "$T/service-bad" --keys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --allow-unsigned "${dirty[@]}"
remake_all "$T/service-bad"
expect_refused "service rejects rechecksummed archive with stale record" "infer_library_sha256" "$np" verify --package "$T/service-bad" --keys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --allow-unsigned "${dirty[@]}"
rm -rf "$T/service-bad"
cp -r "$S" "$T/service-bad"
sed -i '/^input_infer_lock_sha256 /d' "$T/service-bad/PACKAGE.txt"
remake_all "$T/service-bad"
expect_refused "service rejects missing inference lock record" "exactly one input_infer_lock_sha256" "$np" verify --package "$T/service-bad" --keys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --allow-unsigned "${dirty[@]}"
rm -rf "$T/service-bad"
cp -r "$S" "$T/service-bad"
sed -i '/ inputs\/libaienos_infer_kernel.a$/d' "$T/service-bad/SHA256SUMS"
echo "package_sha256 $(sha256sum "$T/service-bad/SHA256SUMS" | cut -c1-64)" >"$T/service-bad/PROVENANCE.txt"
expect_refused "service archive cannot be omitted from signed checksum" "must cover inputs" "$np" verify --package "$T/service-bad" --keys "$fix/TEST-FIXTURE-owner-pubkeys.txt" --allow-unsigned "${dirty[@]}"

echo "NATIVE_PACKAGE_TEST: $([ "$fails" = 0 ] && echo PASS || echo FAIL) ($checks checks, $fails failures)"
[ "$fails" = 0 ]
