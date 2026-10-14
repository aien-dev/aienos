#!/bin/bash
# make-receipts.sh: build the Omega realization receipt fixtures (receipt v1, omega spec/one-layer-receipts.md)
# for OSC unit admission (aienos#383) with omega's own checker2. Usage:
#   make-receipts.sh OMEGA_DIR [OUT_DIR]          write the fixtures to OUT_DIR (default: this directory)
#   make-receipts.sh --check OMEGA_DIR            rebuild into a temporary directory and require every committed
#                                                 fixture and expected.txt to be byte-identical (Ed25519 is
#                                                 deterministic, so the same checker2 gives the same bytes)
# OMEGA_DIR is a checkout of aien-dev/omega with src/checker2 (omega#448). checker2 and checker2_other are built
# from it into a temporary OUT_DIR (omega's own build/ is not touched). Every receipt is minted by
# `checker2 receipt issue` with the checker2 TEST key (class TEST); nothing here signs anything itself.
# Altered bytes (n_altered: one flipped byte; n_length: one extra byte) are copies of a minted receipt.
# Needs bash, make, cc, od, dd, sha256sum, cmp. No Python.
set -eu
export LC_ALL=C
mydir=$(cd "$(dirname "$0")" && pwd)
check=0
if [ "${1:-}" = --check ]; then check=1; shift; fi
OMEGA=$(cd "${1:?OMEGA_DIR}" && pwd)
OUT=${2:-$mydir}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ "$check" = 1 ]; then OUT=$work/out; fi
mkdir -p "$OUT"

fix=$(cd "$mydir/.." && pwd)
TARGET=aienos-ck-aarch64-el0 # the kernel's target name (osc_receipt.h OSC_RCPT_TARGET_NAME)
FLOOR=10                      # kernel qualification policy (core/osc_admit.c): epoch floor 10, current epoch 20
NOW=20

make -s -C "$OMEGA" OUT_DIR="$work/c2" "$work/c2/checker2/checker2" "$work/c2/checker2/checker2_other" >/dev/null
C2=$work/c2/checker2/checker2
C2O=$work/c2/checker2/checker2_other
omega_commit=$(git -C "$OMEGA" rev-parse HEAD 2>/dev/null || echo unknown)
omega_dirty=$(git -C "$OMEGA" status --porcelain -- src/checker2 mk/checker2.mk 2>/dev/null | head -1)
[ -z "$omega_dirty" ] || { echo "omega checker2 sources are modified; refusing (fixtures must come from a commit)" >&2; exit 1; }
checker_id=$("$C2" version | sed -n 's/^checker_id=//p')
other_id=$("$C2O" version | sed -n 's/^checker_id=//p')

# Section 1 (IR) and section 2 (code) of an OSCUNIT container: section table at 128, 48 bytes per entry,
# offset u32 at +4, length u32 at +8, SHA-256 at +16 (OSC_UNIT_ARTIFACT.md section 4). The extracted bytes must
# hash to the table's hash, so a wrong offset cannot go unnoticed.
u32() { od -An -tu4 -j "$2" -N4 "$1" | tr -d ' '; }
hexat() { od -An -tx1 -j "$2" -N "$3" "$1" | tr -d ' \n'; }
extract() { # unit-file short-name
    local u=$1 b=$2 k off len ent
    for k in 1 2; do
        ent=$((128 + (k - 1) * 48))
        off=$(u32 "$u" $((ent + 4)))
        len=$(u32 "$u" $((ent + 8)))
        dd if="$u" of="$work/$b.s$k" bs=1 skip="$off" count="$len" status=none
        [ "$(sha256sum "$work/$b.s$k" | cut -c1-64)" = "$(hexat "$u" $((ent + 16)) 32)" ] \
            || { echo "$u: section $k does not hash to its table entry" >&2; exit 1; }
    done
    mv "$work/$b.s1" "$work/$b.ir"
    mv "$work/$b.s2" "$work/$b.code"
}
extract "$fix/osc_unit/vectors/a01_valid_min.unit" a01
extract "$fix/osc_unit/launch/l01_launch_fns.unit" l01
extract "$fix/osh/osh_lex.unit" osh_lex
extract "$fix/osh/osh_parse.unit" osh_parse
extract "$fix/osh/osh_expand.unit" osh_expand
printf 'not a firmware image (receipt fixture)\n' >"$work/firmware.bin"
printf 'stand-in producer identity (receipt fixture)\n' >"$work/producer.bin"

# issue NAME CHECKER IR CODE EPOCH EXPIRY [extra issue options]
issue() {
    local name=$1 c=$2 ir=$3 code=$4 ep=$5 ex=$6 line path
    shift 6
    rm -rf "$work/store"; mkdir -p "$work/store"
    line=$("$c" receipt issue "$work/$ir.ir" "$work/$code.code" --target "${TGT:-$TARGET}" --epoch "$ep" --expiry "$ex" \
        --out-dir "$work/store" "$@")
    path=${line#receipt=}
    [ -f "$path" ] || { echo "issue $name: $line" >&2; exit 1; }
    cat "$path" >"$OUT/$name.rcpt"
}
id_of() { sha256sum "$OUT/$1.rcpt" | cut -c1-64; }

# valid receipts, one per launched program+code pair. A receipt binds the IR and the code, not the container
# manifest: l02_stack_over.unit has l01's IR and code (l01.rcpt covers it) and a06_valid_limits_at_max.unit has
# a01's (a01.rcpt covers it; checker2 gives byte-identical receipts for them).
issue a01 "$C2" a01 a01 10 1000
issue l01 "$C2" l01 l01 10 1000
issue osh_lex "$C2" osh_lex osh_lex 10 1000
issue osh_parse "$C2" osh_parse osh_parse 10 1000
issue osh_expand "$C2" osh_expand osh_expand 10 1000
# negative receipts, all for a01_valid_min.unit
issue n_stale "$C2" a01 a01 5 1000           # issued under epoch 5, below the floor 10: replay
issue n_revoked_id "$C2" a01 a01 11 1000     # valid except that its id is on the kernel's revoked list
issue n_expired "$C2" a01 a01 10 15          # last fresh epoch 15, kernel is at 20
issue n_future "$C2" a01 a01 30 1000         # issued under epoch 30, kernel is at 20
TGT=aarch64-linux-host issue n_target "$C2" a01 a01 10 1000
issue n_program "$C2" osh_lex a01 10 1000    # another (checker2-accepted) program with a01's code
issue n_firmware "$C2" a01 a01 10 1000 --firmware "$work/firmware.bin"
issue n_producer "$C2" a01 a01 10 1000 --producer "$work/producer.bin"
issue n_deps "$C2" a01 a01 10 1000 --dep "$(id_of a01)"
issue n_checker "$C2O" a01 a01 10 1000       # minted by a checker2 build with another identity
# copies with altered bytes
cat "$OUT/a01.rcpt" >"$OUT/n_altered.rcpt"
b=$(od -An -tu1 -j80 -N1 "$OUT/a01.rcpt" | tr -d ' ')
printf "\\$(printf '%03o' $((b ^ 1)))" | dd of="$OUT/n_altered.rcpt" bs=1 seek=80 conv=notrunc status=none
{ cat "$OUT/a01.rcpt"; printf '\0'; } >"$OUT/n_length.rcpt"

test_fp=$(hexat "$OUT/a01.rcpt" 320 32)
revoked_id=$(id_of n_revoked_id)
# The same policy for checker2 verify (the oracle) as the kernel's qualification policy: TEST key allowed,
# floor 10, epoch 20, target aienos-ck-aarch64-el0, no firmware, no dependencies, revoked id n_revoked_id.
# Both checker2 and the kernel compare the producer (none = all zero unless the policy names one).
qual=(--allow-test-key --floor "$FLOOR" --epoch "$NOW" --target "$TARGET" --revoked-id "$revoked_id")
# oracle NAME UNIT VARIANT KERNEL-VERDICT [extra verify options]
oracle() {
    local name=$1 unit=$2 variant=$3 kv=$4 v opts
    shift 4
    case $variant in
    qual) opts=("${qual[@]}") ;;
    release) opts=(--production --floor "$FLOOR" --epoch "$NOW" --target "$TARGET" --revoked-id "$revoked_id") ;;
    revoke_key) opts=("${qual[@]}" --revoked-key "$test_fp") ;;
    producer) opts=("${qual[@]}" --producer "$work/producer.bin") ;;
    esac
    v=$("$C2" receipt verify "$OUT/$name.rcpt" "$work/$unit.ir" "$work/$unit.code" "${opts[@]}" "$@" 2>&1 || true)
    v=${v#receipt=}
    echo "$name.rcpt unit=$unit variant=$variant checker2=$v kernel=$kv id=$(id_of "$name")"
}
{
    echo "# Receipt fixtures for aienos#383, minted by omega checker2 (TEST key). Generated by make-receipts.sh."
    echo "# omega=$omega_commit checker_id=$checker_id other_checker_id=$other_id"
    echo "# test_key_fingerprint=$test_fp target=$TARGET floor=$FLOOR epoch=$NOW revoked_id=$revoked_id"
    echo "# columns: receipt unit variant checker2-verify-verdict kernel-verdict receipt-id"
    echo "# variant: qual = kernel qualification policy; release = the same with release=1 (TEST refused);"
    echo "#          revoke_key = qual plus the TEST key fingerprint on the revoked-key list;"
    echo "#          producer = qual plus an expected producer (qual expects none = all zero)"
    oracle a01 a01 qual VALID
    oracle l01 l01 qual VALID
    oracle osh_lex osh_lex qual VALID
    oracle osh_parse osh_parse qual VALID
    oracle osh_expand osh_expand qual VALID
    oracle a01 a01 release TEST_SIGNER_IN_PRODUCTION
    oracle a01 a01 revoke_key REVOKED
    oracle n_altered a01 qual BAD_SIGNATURE
    oracle n_length a01 qual SIZE
    oracle n_stale a01 qual STALE_EPOCH
    oracle n_revoked_id a01 qual REVOKED
    oracle n_expired a01 qual EXPIRED
    oracle n_future a01 qual NOT_YET_VALID
    oracle n_target a01 qual WRONG_TARGET
    oracle n_firmware a01 qual WRONG_FIRMWARE
    oracle n_program a01 qual PROGRAM_MISMATCH
    oracle l01 a01 qual EXECUTABLE_MISMATCH
    oracle n_deps a01 qual DEPENDENCIES_MISMATCH
    oracle n_checker a01 qual UNTRUSTED_CHECKER
    oracle n_producer a01 qual WRONG_PRODUCER
    oracle n_producer a01 producer VALID
    oracle a01 a01 producer WRONG_PRODUCER
} >"$OUT/expected.txt"
# The oracle must agree with the kernel column everywhere except where the kernel deliberately does not check:
# n_producer under qual (checker2 compares an all-zero producer; the kernel policy has no producer).
bad=$(awk '!/^#/ { split($4, c, "="); split($5, k, "="); if (c[2] != k[2] && !($1 == "n_producer.rcpt" && $3 == "variant=qual")) print }' "$OUT/expected.txt")
[ -z "$bad" ] || { echo "checker2 and the expected kernel verdict disagree:" >&2; echo "$bad" >&2; exit 1; }

if [ "$check" = 1 ]; then
    rc=0
    for f in "$OUT"/*; do
        cmp -s "$f" "$mydir/$(basename "$f")" || { echo "differs from the committed fixture: $(basename "$f")" >&2; rc=1; }
    done
    [ "$rc" = 0 ] && echo "receipt fixtures reproduced byte for byte ($(ls "$OUT" | wc -l) files, omega $omega_commit)"
    exit "$rc"
fi
echo "wrote $(ls "$OUT"/*.rcpt | wc -l) receipts and expected.txt to $OUT (omega $omega_commit, checker_id $checker_id)"
