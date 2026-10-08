#!/bin/bash
# make-l01.sh: build the C3-3a launch test unit l01_launch_fns.unit with the spec's own generator
# helpers. Usage: make-l01.sh SPEC_DIR OUT_DIR
#   SPEC_DIR  a checkout of aien-protocols specs/osc-unit-artifact (needs tools/make-vectors.sh, src/min.ir)
#   OUT_DIR   receives l01_launch_fns.unit and l01.code
# Needs as, objcopy, nm, xxd, sha256sum, openssl (Ed25519), bash. No Python.
# The helper functions (u8, le16, entry, caps_none, build, resign, the throwaway TEST key "test1") are
# taken from SPEC_DIR/tools/make-vectors.sh unchanged: everything before its line `cp "$SRC/min.ir"`.
# HONEST LIMIT: the code is hand-assembled (l01.S), not compiled by oscc. The IR section is min.ir
# (the spec's compiled vector), so the IR does not describe this code. The IR is attested by the
# signer, never checked against the code (spec section 10); the container is valid and the TEST
# signer vouches for a mismatch. program_id therefore equals min.osc's. Test fixture only.
set -eu
export LC_ALL=C
mydir=$(cd "$(dirname "$0")" && pwd)
SPEC=${1:?SPEC_DIR}
OUT=${2:?OUT_DIR}
mkdir -p "$OUT"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
n=$(grep -n '^cp "\$SRC/min.ir"' "$SPEC/tools/make-vectors.sh" | head -1 | cut -d: -f1)
{ echo 'here='"$SPEC/tools"; sed -n "1,$((n - 1))p" "$SPEC/tools/make-vectors.sh" | sed '/^here=/d'; } >"$work/helpers.sh"
OUT_UNIT=$OUT
set -- "$work/keys-out" "$work/keys-out"   # helpers read OUT_DIR=$1, KEYS_DIR=$2
mkdir -p "$work/keys-out"
SRC=$SPEC/src
# shellcheck disable=SC1090
. "$work/helpers.sh"
OUT=$OUT_UNIT
cmp -s "$KEYS/test1.pub" "$SPEC/keys/test1.pub" || { echo "TEST key mismatch: generator is not the frozen one" >&2; exit 1; }

as -o "$work/l01.o" "$mydir/l01.S"
objcopy -O binary -j .text "$work/l01.o" "$work/code"
off() { printf '%d' 0x"$(nm "$work/l01.o" | awk -v s="$1" '$3 == s {print $1}')"; }
cp "$SRC/min.ir" "$work/ir"
{
    entry 0 1 5 5 0 0 0 0 0 "$(off trap)" trap
    entry 1 0 5 0 0 0 0 0 0 "$(off spin)" spin
    entry 2 0 5 0 0 0 0 0 0 "$(off peek0)" peek0
    entry 3 0 5 0 0 0 0 0 0 "$(off poke_rt)" poke_rt
    entry 4 0 5 0 0 0 0 0 0 "$(off bare_brk)" bare_brk
    entry 5 0 5 0 0 0 0 0 0 "$(off exec_stack)" exec_stack
    entry 6 0 5 0 0 0 0 0 0 "$(off overflow)" overflow
    entry 7 2 5 12 5 0 0 0 0 "$(off counter)" counter
} >"$work/ent"
caps_none >"$work/caps0"
build "$OUT/l01_launch_fns.unit" test1 1 5 1 8 "$work/ir" "$work/code" "$work/ent" "$work/caps0"
cp "$work/code" "$OUT/l01.code"
echo "built $OUT/l01_launch_fns.unit"
