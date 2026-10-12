#!/usr/bin/env bash
# native_package.sh -- reproducible AIENOS native package with exact manifests
# and owner-signed verification (AIEN native v1 plan, P11 cut 1b, gate N7).
#
# A package is a directory:
#   image/BOOTAA64.EFI     the image, built twice from a clean tree; the two
#                          builds must be byte-identical or the package is
#                          refused as not signable (TRUST-1 Q24)
#   PACKAGE.txt            "key value" lines: format, commit, variant, image
#                          digests, toolchain, component pins, model digest,
#                          firmware digests (see write_package_txt)
#   SHA256SUMS             sha256sum lines over image/BOOTAA64.EFI and PACKAGE.txt
#   slot/MANIFEST.bin      unsigned slot manifest (native/boot/slot_format.h);
#                          its provenance field is the 64 hex characters of
#                          sha256(SHA256SUMS), so the owner's one signature
#                          over the manifest binds the whole package
#   slot/MANIFEST.tbs      the 448 bytes the owner signs offline:
#                          openssl pkeyutl -sign -inkey owner_root.pem -rawin \
#                              -in MANIFEST.tbs -out MANIFEST.sig
#   slot/MANIFEST.signed.bin  after `sign` (or `sign-test`, TEST key only)
#
#   native_package.sh build --out DIR --generation N [--variant core|full|hardware-staging]
#       [--owner-pubkeys F --machine-id F]   (hardware-staging only)
#       [--policy-generation N] [--min-rollback N] [--pins FILE] [--model FILE]
#       [--firmware FILE]... [--allow-dirty]
#   native_package.sh sign --package DIR --sig FILE --pubkey HEX64
#   native_package.sh sign-test --package DIR          RFC 8032 TEST 1 key, tests only
#   native_package.sh verify --package DIR (--keys FILE | --test-key) [--allow-unsigned]
#
# --pins FILE: lines "<repo> <40 hex>" copied into PACKAGE.txt after validation.
# --model FILE: its sha256 and size are recorded (the frozen model of P09/P12).
# --firmware FILE: each file's sha256 and size are recorded (GB10 firmware blobs
#   of docs/GB10_FIRMWARE_INVENTORY.md). Nothing is loaded or booted.
# Build-only. Never writes outside DIR and the scratch build directories.
# Every refusal prints "refused: <reason>" and exits 1.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)
kdir="$repo/native/kernel"
FORMAT=1

refuse() { echo "refused: $*"; exit 1; }
hex40() { [[ "$1" =~ ^[0-9a-f]{40}$ ]]; }
hex64() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
sha512_of() { sha512sum "$1" | cut -d' ' -f1; }
size_of() { stat -c %s "$1"; }

slot_tool() {
    local out="${NATIVE_PACKAGE_TOOL_OUT:-$repo/target/native-kernel}"
    make -s -C "$kdir" OUT="$out" slot-tool >/dev/null
    echo "$out/host/ck_slot_tool"
}

# ---- build ---------------------------------------------------------------------
build_once() {
    # $1 = OUT dir, $2 = variant, $3 = owner pubkeys, $4 = machine id
    local out="$1" variant="$2" own="$3" mid="$4"
    case "$variant" in
    core) make -s -C "$kdir" OUT="$out" >"$out.log" 2>&1 || refuse "build failed (see $out.log)"; echo "$out/BOOTAA64.EFI";;
    full) make -s -C "$kdir" OUT="$out" full >"$out.log" 2>&1 || refuse "build failed (see $out.log)"; echo "$out/full/BOOTAA64.EFI";;
    hardware-staging)
        make -s -C "$kdir" OUT="$out" full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS="$own" CK_MACHINE_ID="$mid" >"$out.log" 2>&1 || refuse "build failed (see $out.log)"
        echo "$out/full-hardware-staging/BOOTAA64.EFI";;
    *) refuse "unknown variant $variant";;
    esac
}

write_package_txt() {
    # $1 = package dir, then named globals
    local dir="$1"
    {
        echo "format $FORMAT"
        echo "repo aien-dev/aienos"
        echo "commit $commit"
        echo "commit_time $commit_time"
        echo "tree clean"
        echo "variant $variant"
        echo "generation $generation"
        echo "policy_generation $policy_generation"
        echo "min_rollback_generation $min_rollback"
        echo "image image/BOOTAA64.EFI"
        echo "image_bytes $(size_of "$dir/image/BOOTAA64.EFI")"
        echo "image_sha256 $(sha256_of "$dir/image/BOOTAA64.EFI")"
        echo "image_sha512 $(sha512_of "$dir/image/BOOTAA64.EFI")"
        echo "reproducible two_clean_builds_identical"
        echo "toolchain_cc $(gcc --version | head -1)"
        echo "toolchain_ld $(ld --version | head -1)"
        echo "toolchain_make $(make --version | head -1)"
        echo "build_host_arch $(uname -m)"
        if [ -n "$pins" ]; then
            while read -r r s; do
                [ -z "$r" ] && continue
                case "$r" in \#*) continue;; esac
                echo "pin $r $s"
            done <"$pins"
        fi
        if [ -n "$model" ]; then
            echo "model_bytes $(size_of "$model")"
            echo "model_sha256 $(sha256_of "$model")"
        fi
        for f in "${firmware[@]}"; do
            echo "firmware $(basename "$f") $(size_of "$f") $(sha256_of "$f")"
        done
        if [ -n "$own" ]; then
            echo "owner_pubkeys_sha256 $(sha256_of "$own")"
            echo "machine_id_sha256 $(sha256_of "$mid")"
        fi
    } >"$dir/PACKAGE.txt"
}

cmd_build() {
    local out="" generation="" variant="full" own="" mid="" policy_generation=0 min_rollback=0
    local pins="" model="" allow_dirty=0
    local -a firmware=()
    while [ $# -gt 0 ]; do
        case "$1" in
        --out) out="$2"; shift 2;;
        --generation) generation="$2"; shift 2;;
        --variant) variant="$2"; shift 2;;
        --owner-pubkeys) own="$2"; shift 2;;
        --machine-id) mid="$2"; shift 2;;
        --policy-generation) policy_generation="$2"; shift 2;;
        --min-rollback) min_rollback="$2"; shift 2;;
        --pins) pins="$2"; shift 2;;
        --model) model="$2"; shift 2;;
        --firmware) firmware+=("$2"); shift 2;;
        --allow-dirty) allow_dirty=1; shift;;
        *) refuse "build: unknown argument $1";;
        esac
    done
    [ -n "$out" ] || refuse "build needs --out DIR"
    [[ "$generation" =~ ^[1-9][0-9]*$ ]] || refuse "build needs --generation N (positive integer)"
    [[ "$policy_generation" =~ ^[0-9]+$ ]] || refuse "--policy-generation must be an integer"
    [[ "$min_rollback" =~ ^[0-9]+$ ]] || refuse "--min-rollback must be an integer"
    [ -e "$out" ] && refuse "--out $out already exists (packages are never overwritten)"
    if [ "$variant" = hardware-staging ]; then
        [ -n "$own" ] && [ -n "$mid" ] || refuse "hardware-staging needs --owner-pubkeys and --machine-id"
        [ -f "$own" ] && [ -f "$mid" ] || refuse "owner pubkeys or machine id file missing"
    else
        [ -z "$own" ] && [ -z "$mid" ] || refuse "--owner-pubkeys/--machine-id only with --variant hardware-staging"
    fi
    [ -z "$pins" ] || [ -f "$pins" ] || refuse "pins file missing"
    if [ -n "$pins" ]; then
        while read -r r s; do
            [ -z "$r" ] && continue
            case "$r" in \#*) continue;; esac
            hex40 "$s" || refuse "pins file: $r is not followed by 40 hex characters"
        done <"$pins"
    fi
    [ -z "$model" ] || [ -f "$model" ] || refuse "model file missing"
    for f in "${firmware[@]}"; do [ -f "$f" ] || refuse "firmware file missing: $f"; done

    local dirty
    dirty=$(git -C "$repo" status --porcelain --untracked-files=no)
    if [ -n "$dirty" ] && [ "$allow_dirty" = 0 ]; then
        refuse "working tree is dirty; a package is built from a committed tree only (or --allow-dirty for tests)"
    fi
    local commit commit_time
    commit=$(git -C "$repo" rev-parse HEAD)
    commit_time=$(git -C "$repo" log -1 --format=%ct)
    hex40 "$commit" || refuse "cannot read the commit"

    local scratch
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/native-package.XXXXXX")
    local img_a img_b
    img_a=$(build_once "$scratch/a" "$variant" "$own" "$mid")
    img_b=$(build_once "$scratch/b" "$variant" "$own" "$mid")
    if [ -n "${NATIVE_PACKAGE_TEST_CORRUPT_SECOND:-}" ]; then
        printf '\0' >>"$img_b"   # test hook: make the second build differ
    fi
    local da db
    da=$(sha256_of "$img_a"); db=$(sha256_of "$img_b")
    if [ "$da" != "$db" ]; then
        rm -rf "$scratch"
        refuse "two clean builds differ ($da vs $db): not reproducible, not signable"
    fi

    mkdir -p "$out/image" "$out/slot"
    cp "$img_a" "$out/image/BOOTAA64.EFI"
    chmod 444 "$out/image/BOOTAA64.EFI"
    rm -rf "$scratch"
    write_package_txt "$out"
    (cd "$out" && sha256sum image/BOOTAA64.EFI PACKAGE.txt >SHA256SUMS)
    local prov tool
    prov=$(sha256_of "$out/SHA256SUMS")
    tool=$(slot_tool)
    "$tool" make-manifest --image "$out/image/BOOTAA64.EFI" --generation "$generation" \
        --policy-generation "$policy_generation" --min-rollback "$min_rollback" \
        --commit "$commit" --provenance "$prov" --timestamp "$commit_time" \
        --out "$out/slot/MANIFEST.bin" >/dev/null || refuse "slot manifest not built"
    "$tool" tbs "$out/slot/MANIFEST.bin" --out "$out/slot/MANIFEST.tbs" >/dev/null
    echo "package built: $out"
    echo "  commit $commit variant $variant generation $generation"
    echo "  image sha256 $da ($(size_of "$out/image/BOOTAA64.EFI") bytes), two clean builds identical"
    echo "  provenance (sha256 of SHA256SUMS) $prov"
    echo "  sign offline: openssl pkeyutl -sign -inkey owner_root.pem -rawin -in $out/slot/MANIFEST.tbs -out MANIFEST.sig"
    echo "  then: $0 sign --package $out --sig MANIFEST.sig --pubkey <64 hex>"
}

# ---- package integrity (shared by sign and verify) ---------------------------------
check_package_files() {
    local dir="$1"
    [ -d "$dir" ] || refuse "package directory missing"
    for f in image/BOOTAA64.EFI PACKAGE.txt SHA256SUMS slot/MANIFEST.bin; do
        [ -f "$dir/$f" ] || refuse "package is missing $f"
    done
    (cd "$dir" && sha256sum -c --quiet --strict SHA256SUMS >/dev/null 2>&1) || refuse "SHA256SUMS does not match the package files"
    local fmt
    fmt=$(awk '$1=="format"{print $2}' "$dir/PACKAGE.txt")
    [ "$fmt" = "$FORMAT" ] || refuse "PACKAGE.txt format $fmt is not $FORMAT"
    local want_sha have_sha
    want_sha=$(awk '$1=="image_sha256"{print $2}' "$dir/PACKAGE.txt")
    have_sha=$(sha256_of "$dir/image/BOOTAA64.EFI")
    [ "$want_sha" = "$have_sha" ] || refuse "PACKAGE.txt image_sha256 does not match the image"
    local repro
    repro=$(awk '$1=="reproducible"{print $2}' "$dir/PACKAGE.txt")
    [ "$repro" = two_clean_builds_identical ] || refuse "PACKAGE.txt does not record a reproducible build"
}

manifest_provenance_check() {
    # $1 = dir, $2 = manifest file. The manifest's provenance must be sha256(SHA256SUMS)
    # and its commit must be PACKAGE.txt's commit. Read via the tool's print lines.
    local dir="$1" mf="$2" tool="$3"
    local line prov commit want_prov want_commit
    line=$("$tool" show "$mf" 2>/dev/null | /usr/bin/grep -m1 '^  commit=' || true)
    commit=$(echo "$line" | sed -n 's/^  commit=\([0-9a-f]\{40\}\) provenance=.*/\1/p')
    prov=$(echo "$line" | sed -n 's/^  commit=[0-9a-f]\{40\} provenance=\([0-9a-f]\{64\}\).*/\1/p')
    want_prov=$(sha256_of "$dir/SHA256SUMS")
    want_commit=$(awk '$1=="commit"{print $2}' "$dir/PACKAGE.txt")
    [ "$prov" = "$want_prov" ] || refuse "manifest provenance does not bind this package's SHA256SUMS"
    [ "$commit" = "$want_commit" ] || refuse "manifest commit does not match PACKAGE.txt"
}

cmd_sign() {
    local dir="" sig="" pk="" test_key=0
    while [ $# -gt 0 ]; do
        case "$1" in
        --package) dir="$2"; shift 2;;
        --sig) sig="$2"; shift 2;;
        --pubkey) pk="$2"; shift 2;;
        --test) test_key=1; shift;;
        *) refuse "sign: unknown argument $1";;
        esac
    done
    [ -n "$dir" ] || refuse "sign needs --package DIR"
    check_package_files "$dir"
    local tool
    tool=$(slot_tool)
    manifest_provenance_check "$dir" "$dir/slot/MANIFEST.bin" "$tool"
    [ -e "$dir/slot/MANIFEST.signed.bin" ] && refuse "package is already signed (never re-signed in place)"
    if [ "$test_key" = 1 ]; then
        "$tool" sign-test "$dir/slot/MANIFEST.bin" --out "$dir/slot/MANIFEST.signed.bin" | tail -1
        echo "TEST-SIGNED package (never for hardware): $dir"
        return 0
    fi
    [ -n "$sig" ] && [ -n "$pk" ] || refuse "sign needs --sig FILE and --pubkey HEX64"
    hex64 "$pk" || refuse "--pubkey must be 64 hex characters"
    "$tool" attach-sig "$dir/slot/MANIFEST.bin" --sig "$sig" --pubkey "$pk" --out "$dir/slot/MANIFEST.signed.bin" | tail -1
    echo "signed package: $dir"
}

cmd_verify() {
    local dir="" keys="" test_key=0 allow_unsigned=0
    while [ $# -gt 0 ]; do
        case "$1" in
        --package) dir="$2"; shift 2;;
        --keys) keys="$2"; shift 2;;
        --test-key) test_key=1; shift;;
        --allow-unsigned) allow_unsigned=1; shift;;
        *) refuse "verify: unknown argument $1";;
        esac
    done
    [ -n "$dir" ] || refuse "verify needs --package DIR"
    [ -n "$keys" ] || [ "$test_key" = 1 ] || refuse "verify needs --keys FILE or --test-key"
    check_package_files "$dir"
    local tool
    tool=$(slot_tool)
    local mf="$dir/slot/MANIFEST.signed.bin"
    if [ ! -f "$mf" ]; then
        [ "$allow_unsigned" = 1 ] || refuse "package is UNSIGNED (slot/MANIFEST.signed.bin missing)"
        manifest_provenance_check "$dir" "$dir/slot/MANIFEST.bin" "$tool"
        echo "VERIFY: UNSIGNED package is internally consistent (not installable)"
        return 0
    fi
    manifest_provenance_check "$dir" "$mf" "$tool"
    local -a karg
    if [ "$test_key" = 1 ]; then karg=(--test-key); else karg=(--keys "$keys"); fi
    local vout
    if ! vout=$("$tool" verify "$mf" --image "$dir/image/BOOTAA64.EFI" "${karg[@]}" 2>&1); then
        echo "$vout" | /usr/bin/grep '^refused:' || true
        refuse "slot manifest signature or digest check failed"
    fi
    # The unsigned manifest must equal the signed one in every field but signer/signature.
    cmp -s <(head -c 184 "$dir/slot/MANIFEST.bin") <(head -c 184 "$mf") || refuse "signed manifest differs from the built manifest"
    echo "VERIFY: PASS $dir"
    echo "$vout" | /usr/bin/grep -E '^(verify:|manifest:|keys:)'
    awk '$1=="commit"||$1=="variant"||$1=="generation"||$1=="image_sha256"||$1=="model_sha256"||$1=="pin"{print "  " $0}' "$dir/PACKAGE.txt"
}

case "${1:-}" in
build) shift; cmd_build "$@";;
sign) shift; cmd_sign "$@";;
sign-test) shift; cmd_sign --test "$@";;
verify) shift; cmd_verify "$@";;
*) refuse "usage: native_package.sh build|sign|sign-test|verify ... (see the header)";;
esac
