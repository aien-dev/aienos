#!/usr/bin/env bash
# native_package.sh -- reproducible AIENOS native package with exact manifests
# and owner-signed verification (AIEN native v1 plan, P11 cut 1b, gate N7).
#
# A package is a directory:
#   image/BOOTAA64.EFI     the image, built twice from a clean tree; the two
#                          builds must be byte-identical or the package is
#                          refused as not signable (TRUST-1 Q24)
#   PACKAGE.txt            the provenance record, "key value" lines (format 2):
#                          source revision (commit, commit time, tree_clean),
#                          toolchain (cross prefix, gcc/ld/objcopy/make version
#                          lines, build host arch), inputs (make goal and
#                          variables, Makefile and image.ld digests, component
#                          pins, model and firmware digests, owner file digests)
#                          and the resulting image (bytes, SHA-256, SHA-512).
#                          See write_package_txt and docs/NATIVE_PACKAGE.md.
#   SHA256SUMS             sha256sum lines over image/BOOTAA64.EFI and PACKAGE.txt
#   PROVENANCE.txt         "package_sha256 <sha256(SHA256SUMS)>": the resulting
#                          package digest, which is also the slot manifest's
#                          provenance field (it cannot live in PACKAGE.txt,
#                          which SHA256SUMS covers)
#   slot/MANIFEST.bin      unsigned slot manifest (native/boot/slot_format.h);
#                          its provenance field is package_sha256, so the
#                          owner's one signature over the manifest binds the
#                          whole package
#   slot/MANIFEST.tbs      the 448 bytes the owner signs offline, written by
#                          `tbs --pubkey` (or `build --pubkey`): signer_id =
#                          SHA-256(pubkey) is inside the signed bytes.
#                          openssl pkeyutl -sign -inkey owner_root.key.pem -rawin \
#                              -in MANIFEST.tbs -out MANIFEST.sig
#   slot/MANIFEST.signed.bin  after `sign` (or `sign-test`, TEST key only)
#
#   native_package.sh build --out DIR --generation N [--variant core|full|hardware-staging]
#       [--owner-pubkeys F --machine-id F]   (hardware-staging only)
#       [--policy-generation N] [--min-rollback N] [--pins FILE] [--model FILE]
#       [--firmware FILE]... [--pubkey HEX64] [--allow-dirty]
#   native_package.sh tbs --package DIR --pubkey HEX64
#   native_package.sh sign --package DIR --sig FILE --pubkey HEX64 [--allow-dirty]
#   native_package.sh sign-test --package DIR          RFC 8032 TEST 1 key, tests only
#   native_package.sh verify --package DIR (--keys FILE | --test-key) [--allow-unsigned]
#       [--same-host] [--allow-dirty]
#
# --pins FILE: lines "<repo> <40 hex>" copied into PACKAGE.txt after validation.
# --model FILE: its sha256 and size are recorded (the frozen model of P09/P12).
# --firmware FILE: each file's sha256 and size are recorded (GB10 firmware blobs
#   of docs/GB10_FIRMWARE_INVENTORY.md). Nothing is loaded or booted.
# --allow-dirty (tests only): build from a dirty tree, recorded as tree_clean no;
#   verify and sign refuse such a package unless given --allow-dirty too
#   (sign-test does not refuse it: the TEST key is never for hardware).
# --same-host: verify compares the recorded toolchain lines with the toolchain
#   running here; without it they are printed as "recorded".
# Any CK_* variable in the environment is refused: every make variable that
# selects the image is passed explicitly and recorded.
# Build-only. Never writes outside DIR and the scratch build directories.
# Every refusal prints "refused: <reason>" and exits 1.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)
kdir="$repo/native/kernel"
FORMAT=2
MAKEFILE_REL=native/kernel/Makefile
IMAGE_LD_REL=native/boot/image.ld

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

# ---- toolchain and inputs (what the record says and verify recomputes) -------------
# The cross prefix exactly as the kernel Makefile resolves it (CROSS ?= ..., by host
# arch, environment and MAKEFLAGS included), asked from make itself.
cross_prefix() {
    make -s --no-print-directory -C "$kdir" --eval 'np-print-cross: ; @echo "[$(CROSS)]"' np-print-cross \
        | sed -n 's/^\[\(.*\)\]$/\1/p'
}
cross_name() { if [ -n "$1" ]; then echo "$1"; else echo none; fi; }
cross_value() { if [ "$1" = none ]; then echo ""; else echo "$1"; fi; }
first_line() { "$@" 2>/dev/null | head -1; }
# toolchain_lines CROSS: the toolchain lines of PACKAGE.txt, in order.
toolchain_lines() {
    local c="$1"
    echo "toolchain_cross $(cross_name "$c")"
    echo "toolchain_cc $(first_line "${c}gcc" --version)"
    echo "toolchain_ld $(first_line "${c}ld" --version)"
    echo "toolchain_objcopy $(first_line "${c}objcopy" --version)"
    echo "toolchain_make $(first_line make --version)"
    echo "build_host_arch $(uname -m)"
}
# The make goal and variables build_once passes for a variant ($2/$3: owner file digests).
make_goal_of() { case "$1" in core) echo all;; *) echo full;; esac; }
make_vars_of() {
    if [ "$1" = hardware-staging ]; then
        echo "CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=sha256:$2 CK_MACHINE_ID=sha256:$3"
    else
        echo none
    fi
}
ck_env() { # CK_* in the environment, or passed down from an outer make in MAKEFLAGS
    { env | sed -n 's/^\(CK_[A-Za-z0-9_]*\)=.*/\1/p'; echo "${MAKEFLAGS:-}" | tr ' ' '\n' | sed -n 's/^\(CK_[A-Za-z0-9_]*\)=.*/\1/p'; } | sort -u | tr '\n' ' ' | sed 's/ $//'
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
    # $1 = package dir, then named globals of cmd_build
    local dir="$1" own_sha="" mid_sha=""
    if [ -n "$own" ]; then own_sha=$(sha256_of "$own"); mid_sha=$(sha256_of "$mid"); fi
    {
        echo "format $FORMAT"
        # source revision
        echo "repo aien-dev/aienos"
        echo "commit $commit"
        echo "commit_time $commit_time"
        echo "tree_clean $tree_clean"
        # what was asked for
        echo "variant $variant"
        echo "generation $generation"
        echo "policy_generation $policy_generation"
        echo "min_rollback_generation $min_rollback"
        # toolchain (the one make used: CROSS-prefixed tools)
        toolchain_lines "$cross"
        # inputs that select the image
        echo "input_make_goal $(make_goal_of "$variant")"
        echo "input_make_vars $(make_vars_of "$variant" "$own_sha" "$mid_sha")"
        echo "input_env_ck none"
        echo "input_makefile_sha256 $(sha256_of "$repo/$MAKEFILE_REL")"
        echo "input_image_ld_sha256 $(sha256_of "$repo/$IMAGE_LD_REL")"
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
            echo "owner_pubkeys_sha256 $own_sha"
            echo "machine_id_sha256 $mid_sha"
        fi
        # resulting image
        echo "image image/BOOTAA64.EFI"
        echo "image_bytes $(size_of "$dir/image/BOOTAA64.EFI")"
        echo "image_sha256 $(sha256_of "$dir/image/BOOTAA64.EFI")"
        echo "image_sha512 $(sha512_of "$dir/image/BOOTAA64.EFI")"
        echo "reproducible two_clean_builds_identical"
    } >"$dir/PACKAGE.txt"
}

write_tbs() {
    # $1 = package dir, $2 = pubkey hex, $3 = tool
    hex64 "$2" || refuse "--pubkey must be 64 hex characters"
    local tout
    tout=$("$3" tbs "$1/slot/MANIFEST.bin" --pubkey "$2" --out "$1/slot/MANIFEST.tbs" 2>&1) || {
        echo "$tout" | /usr/bin/grep '^refused:' || true
        refuse "to-be-signed bytes not written"; }
}

cmd_build() {
    local out="" generation="" variant="full" own="" mid="" policy_generation=0 min_rollback=0
    local pins="" model="" allow_dirty=0 pubkey=""
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
        --pubkey) pubkey="$2"; shift 2;;
        --allow-dirty) allow_dirty=1; shift;;
        *) refuse "build: unknown argument $1";;
        esac
    done
    [ -n "$out" ] || refuse "build needs --out DIR"
    [[ "$generation" =~ ^[1-9][0-9]*$ ]] || refuse "build needs --generation N (positive integer)"
    [[ "$policy_generation" =~ ^[0-9]+$ ]] || refuse "--policy-generation must be an integer"
    [[ "$min_rollback" =~ ^[0-9]+$ ]] || refuse "--min-rollback must be an integer"
    [ -z "$pubkey" ] || hex64 "$pubkey" || refuse "--pubkey must be 64 hex characters"
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
    local envck
    envck=$(ck_env)
    [ -z "$envck" ] || refuse "CK_* variables in the environment change the image without being recorded: $envck"

    local dirty tree_clean=yes
    dirty=$(git -C "$repo" status --porcelain --untracked-files=no)
    if [ -n "$dirty" ]; then
        [ "$allow_dirty" = 1 ] || refuse "working tree is dirty; a package is built from a committed tree only (or --allow-dirty for tests)"
        tree_clean=no
    fi
    local commit commit_time cross
    commit=$(git -C "$repo" rev-parse HEAD)
    commit_time=$(git -C "$repo" log -1 --format=%ct)
    hex40 "$commit" || refuse "cannot read the commit"
    cross=$(cross_prefix)

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
    echo "package_sha256 $prov" >"$out/PROVENANCE.txt"
    tool=$(slot_tool)
    "$tool" make-manifest --image "$out/image/BOOTAA64.EFI" --generation "$generation" \
        --policy-generation "$policy_generation" --min-rollback "$min_rollback" \
        --commit "$commit" --provenance "$prov" --timestamp "$commit_time" \
        --out "$out/slot/MANIFEST.bin" >/dev/null || refuse "slot manifest not built"
    [ -z "$pubkey" ] || write_tbs "$out" "$pubkey" "$tool"
    echo "package built: $out"
    echo "  commit $commit (tree_clean $tree_clean) variant $variant generation $generation"
    echo "  image sha256 $da ($(size_of "$out/image/BOOTAA64.EFI") bytes), two clean builds identical"
    echo "  package_sha256 (sha256 of SHA256SUMS, the slot provenance) $prov"
    if [ -z "$pubkey" ]; then
        echo "  next: $0 tbs --package $out --pubkey <owner public key, 64 hex>"
    fi
    echo "  sign offline: openssl pkeyutl -sign -inkey owner_root.key.pem -rawin -in $out/slot/MANIFEST.tbs -out MANIFEST.sig"
    echo "  then: $0 sign --package $out --sig MANIFEST.sig --pubkey <64 hex>"
}

# ---- package integrity (shared by tbs, sign and verify) -----------------------------
rec() { awk -v k="$2" '$1==k{sub(/^[^ ]+ /,""); print}' "$1/PACKAGE.txt"; }

check_package_files() {
    local dir="$1"
    [ -d "$dir" ] || refuse "package directory missing"
    for f in image/BOOTAA64.EFI PACKAGE.txt SHA256SUMS PROVENANCE.txt slot/MANIFEST.bin; do
        [ -f "$dir/$f" ] || refuse "package is missing $f"
    done
    (cd "$dir" && sha256sum -c --quiet --strict SHA256SUMS >/dev/null 2>&1) || refuse "SHA256SUMS does not match the package files"
    local fmt
    fmt=$(rec "$dir" format)
    [ "$fmt" = "$FORMAT" ] || refuse "PACKAGE.txt format $fmt is not $FORMAT"
    local want have
    want=$(awk '$1=="package_sha256"{print $2}' "$dir/PROVENANCE.txt")
    have=$(sha256_of "$dir/SHA256SUMS")
    [ "$want" = "$have" ] || refuse "PROVENANCE.txt package_sha256 is not the SHA-256 of SHA256SUMS"
}

# check_record DIR SAME_HOST ALLOW_DIRTY: every PACKAGE.txt line that can be recomputed
# here must match; the rest are printed as recorded. Prints "  checked|recorded key value".
check_record() {
    local dir="$1" same_host="$2" allow_dirty="$3" k
    local -a required=(format repo commit commit_time tree_clean variant generation policy_generation
        min_rollback_generation toolchain_cross toolchain_cc toolchain_ld toolchain_objcopy toolchain_make
        build_host_arch input_make_goal input_make_vars input_env_ck input_makefile_sha256
        input_image_ld_sha256 image image_bytes image_sha256 image_sha512 reproducible)
    for k in "${required[@]}"; do
        [ "$(awk -v k="$k" '$1==k' "$dir/PACKAGE.txt" | wc -l)" = 1 ] || refuse "PACKAGE.txt must hold exactly one $k line"
    done
    local img="$dir/image/BOOTAA64.EFI"
    [ "$(rec "$dir" image)" = image/BOOTAA64.EFI ] || refuse "PACKAGE.txt image is not image/BOOTAA64.EFI"
    [ "$(rec "$dir" image_bytes)" = "$(size_of "$img")" ] || refuse "PACKAGE.txt image_bytes does not match the image"
    [ "$(rec "$dir" image_sha256)" = "$(sha256_of "$img")" ] || refuse "PACKAGE.txt image_sha256 does not match the image"
    [ "$(rec "$dir" image_sha512)" = "$(sha512_of "$img")" ] || refuse "PACKAGE.txt image_sha512 does not match the image"
    [ "$(rec "$dir" reproducible)" = two_clean_builds_identical ] || refuse "PACKAGE.txt does not record a reproducible build"
    local tc; tc=$(rec "$dir" tree_clean)
    case "$tc" in
    yes) ;;
    no) [ "$allow_dirty" = 1 ] || refuse "package was built from a dirty tree (tree_clean no): not a release candidate";;
    *) refuse "PACKAGE.txt tree_clean is neither yes nor no";;
    esac
    [ "$(rec "$dir" input_env_ck)" = none ] || refuse "PACKAGE.txt input_env_ck is not none"
    local variant own_sha mid_sha
    variant=$(rec "$dir" variant)
    case "$variant" in core|full|hardware-staging) ;; *) refuse "PACKAGE.txt variant $variant is unknown";; esac
    own_sha=$(rec "$dir" owner_pubkeys_sha256); mid_sha=$(rec "$dir" machine_id_sha256)
    if [ "$variant" = hardware-staging ]; then
        hex64 "$own_sha" && hex64 "$mid_sha" || refuse "hardware-staging PACKAGE.txt lacks the owner file digests"
    else
        [ -z "$own_sha$mid_sha" ] || refuse "PACKAGE.txt has owner file digests on a $variant package"
    fi
    [ "$(rec "$dir" input_make_goal)" = "$(make_goal_of "$variant")" ] || refuse "PACKAGE.txt input_make_goal does not match variant $variant"
    [ "$(rec "$dir" input_make_vars)" = "$(make_vars_of "$variant" "$own_sha" "$mid_sha")" ] || refuse "PACKAGE.txt input_make_vars does not match variant $variant"
    echo "record:"
    for k in image image_bytes image_sha256 image_sha512 reproducible tree_clean input_env_ck variant input_make_goal input_make_vars; do
        echo "  checked  $k $(rec "$dir" "$k")"
    done

    # Source revision and source inputs: recomputed from the commit when this repository
    # has it (clean package) or from the working tree (dirty package, tests only).
    local commit; commit=$(rec "$dir" commit)
    hex40 "$commit" || refuse "PACKAGE.txt commit is not 40 hex characters"
    if git -C "$repo" cat-file -e "$commit^{commit}" 2>/dev/null; then
        [ "$(rec "$dir" commit_time)" = "$(git -C "$repo" log -1 --format=%ct "$commit")" ] || refuse "PACKAGE.txt commit_time does not match commit $commit"
        echo "  checked  commit $commit"
        echo "  checked  commit_time $(rec "$dir" commit_time)"
        local f key have
        for f in "$MAKEFILE_REL:input_makefile_sha256" "$IMAGE_LD_REL:input_image_ld_sha256"; do
            key=${f#*:}; f=${f%%:*}
            if [ "$tc" = yes ]; then
                have=$(git -C "$repo" show "$commit:$f" | sha256sum | cut -d' ' -f1)
            else
                have=$(sha256_of "$repo/$f")
            fi
            [ "$(rec "$dir" "$key")" = "$have" ] || refuse "PACKAGE.txt $key does not match $f at $([ "$tc" = yes ] && echo "commit $commit" || echo "the working tree")"
            echo "  checked  $key $have"
        done
    else
        for k in commit commit_time input_makefile_sha256 input_image_ld_sha256; do
            echo "  recorded $k $(rec "$dir" "$k") (commit not in this repository)"
        done
    fi

    # Toolchain: compared with the running toolchain only when asked (--same-host).
    if [ "$same_host" = 1 ]; then
        local c line
        c=$(cross_value "$(rec "$dir" toolchain_cross)")
        [ "$(cross_name "$(cross_prefix)")" = "$(rec "$dir" toolchain_cross)" ] || refuse "toolchain_cross differs from this host's ($(cross_name "$(cross_prefix)"))"
        while read -r line; do
            k=${line%% *}
            [ "$(rec "$dir" "$k")" = "${line#* }" ] || refuse "$k differs from this host (recorded '$(rec "$dir" "$k")', here '${line#* }')"
            echo "  checked  $line"
        done < <(toolchain_lines "$c")
    else
        for k in toolchain_cross toolchain_cc toolchain_ld toolchain_objcopy toolchain_make build_host_arch; do
            echo "  recorded $k $(rec "$dir" "$k")"
        done
    fi
    # Not recomputable from the package alone: generations are checked through the
    # manifest; pins, model and firmware are the digests of files the package does not carry.
    awk '$1=="generation"||$1=="policy_generation"||$1=="min_rollback_generation"||$1=="pin"||$1=="model_bytes"||$1=="model_sha256"||$1=="firmware"||$1=="owner_pubkeys_sha256"||$1=="machine_id_sha256"{print "  recorded " $0}' "$dir/PACKAGE.txt"
    echo "  checked  package_sha256 $(sha256_of "$dir/SHA256SUMS")"
}

manifest_provenance_check() {
    # $1 = dir, $2 = manifest file. The manifest's provenance must be package_sha256
    # and its commit must be PACKAGE.txt's commit. Read via the tool's print lines.
    local dir="$1" mf="$2" tool="$3"
    local line prov commit want_prov want_commit
    line=$("$tool" show "$mf" 2>/dev/null | /usr/bin/grep -m1 '^  commit=' || true)
    commit=$(echo "$line" | sed -n 's/^  commit=\([0-9a-f]\{40\}\) provenance=.*/\1/p')
    prov=$(echo "$line" | sed -n 's/^  commit=[0-9a-f]\{40\} provenance=\([0-9a-f]\{64\}\).*/\1/p')
    want_prov=$(sha256_of "$dir/SHA256SUMS")
    want_commit=$(rec "$dir" commit)
    [ "$prov" = "$want_prov" ] || refuse "manifest provenance does not bind this package's SHA256SUMS"
    [ "$commit" = "$want_commit" ] || refuse "manifest commit does not match PACKAGE.txt"
}

cmd_tbs() {
    local dir="" pk=""
    while [ $# -gt 0 ]; do
        case "$1" in
        --package) dir="$2"; shift 2;;
        --pubkey) pk="$2"; shift 2;;
        *) refuse "tbs: unknown argument $1";;
        esac
    done
    [ -n "$dir" ] && [ -n "$pk" ] || refuse "tbs needs --package DIR and --pubkey HEX64"
    check_package_files "$dir"
    local tool
    tool=$(slot_tool)
    manifest_provenance_check "$dir" "$dir/slot/MANIFEST.bin" "$tool"
    write_tbs "$dir" "$pk" "$tool"
    echo "to-be-signed bytes for signer $pk: $dir/slot/MANIFEST.tbs"
}

cmd_sign() {
    local dir="" sig="" pk="" test_key=0 allow_dirty=0
    while [ $# -gt 0 ]; do
        case "$1" in
        --package) dir="$2"; shift 2;;
        --sig) sig="$2"; shift 2;;
        --pubkey) pk="$2"; shift 2;;
        --test) test_key=1; shift;;
        --allow-dirty) allow_dirty=1; shift;;
        *) refuse "sign: unknown argument $1";;
        esac
    done
    [ -n "$dir" ] || refuse "sign needs --package DIR"
    check_package_files "$dir"
    # A real signature never goes on a dirty-tree package (--allow-dirty: tests only);
    # TEST signing may.
    local rout
    [ "$test_key" = 1 ] && allow_dirty=1
    rout=$(check_record "$dir" 0 "$allow_dirty") || { echo "$rout" | /usr/bin/grep '^refused:'; exit 1; }
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
    local aout
    if ! aout=$("$tool" attach-sig "$dir/slot/MANIFEST.bin" --sig "$sig" --pubkey "$pk" --out "$dir/slot/MANIFEST.signed.bin" 2>&1); then
        echo "$aout" | /usr/bin/grep '^refused:' || true
        refuse "signature not attached"
    fi
    echo "$aout" | tail -1
    echo "signed package: $dir"
}

cmd_verify() {
    local dir="" keys="" test_key=0 allow_unsigned=0 same_host=0 allow_dirty=0
    while [ $# -gt 0 ]; do
        case "$1" in
        --package) dir="$2"; shift 2;;
        --keys) keys="$2"; shift 2;;
        --test-key) test_key=1; shift;;
        --allow-unsigned) allow_unsigned=1; shift;;
        --same-host) same_host=1; shift;;
        --allow-dirty) allow_dirty=1; shift;;
        *) refuse "verify: unknown argument $1";;
        esac
    done
    [ -n "$dir" ] || refuse "verify needs --package DIR"
    [ -n "$keys" ] || [ "$test_key" = 1 ] || refuse "verify needs --keys FILE or --test-key"
    check_package_files "$dir"
    local record
    record=$(check_record "$dir" "$same_host" "$allow_dirty") || { echo "$record" | /usr/bin/grep '^refused:'; exit 1; }
    local tool
    tool=$(slot_tool)
    local mf="$dir/slot/MANIFEST.signed.bin"
    if [ ! -f "$mf" ]; then
        [ "$allow_unsigned" = 1 ] || refuse "package is UNSIGNED (slot/MANIFEST.signed.bin missing)"
        manifest_provenance_check "$dir" "$dir/slot/MANIFEST.bin" "$tool"
        echo "VERIFY: UNSIGNED package is internally consistent (not installable)"
        echo "$record"
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
    echo "$record"
}

case "${1:-}" in
build) shift; cmd_build "$@";;
tbs) shift; cmd_tbs "$@";;
sign) shift; cmd_sign "$@";;
sign-test) shift; cmd_sign --test "$@";;
verify) shift; cmd_verify "$@";;
*) refuse "usage: native_package.sh build|tbs|sign|sign-test|verify ... (see the header)";;
esac
