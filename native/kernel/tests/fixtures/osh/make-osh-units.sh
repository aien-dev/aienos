#!/bin/bash
# make-osh-units.sh: pack the three compiled OSH shell-core units (lex_run, parse_run, expand_run; OSH-AIENOS-0)
# into TEST-signed OSC unit containers with the spec's own generator helpers. Usage:
#   make-osh-units.sh SPEC_DIR OSCC_OUT_DIR OUT_DIR
#   SPEC_DIR      a checkout of aien-protocols specs/osc-unit-artifact (tools/make-vectors.sh, keys/test1.pub)
#   OSCC_OUT_DIR  holds osh_{lex,parse,expand}.{ir,code,entries} written by `oscc src/osh/osh_X.osc OUT` (omega)
#   OUT_DIR       receives osh_lex.unit osh_parse.unit osh_expand.unit
# Unlike make-l01.sh the IR and the code are REAL compiler output (oscc), not hand-assembled, and every function
# gets its entry record from OUT.entries (lines: fn_index nregs ret_kind k0..k5 code_offset name).
# One container per unit, TEST signer (the spec's throwaway key test1), no caps, max_stack_bytes 16384,
# cpu_ticks 1000 (1 tick = 10 ms, so 10 s per call, QEMU TCG).
# QEMU (aarch64 virt), TEST signer, not physical. Needs xxd, sha256sum, openssl (Ed25519), bash. No Python.
set -eu
export LC_ALL=C
SPEC=${1:?SPEC_DIR}
OSCC=${2:?OSCC_OUT_DIR}
OUT=${3:?OUT_DIR}
STACK=16384
TICKS=1000
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

for u in lex parse expand; do
    b=$OSCC/osh_$u
    nfn=$(wc -l <"$b.entries")
    {
        while read -r idx nregs ret k0 k1 k2 k3 k4 k5 off name; do
            entry "$idx" "$nregs" "$ret" "$k0" "$k1" "$k2" "$k3" "$k4" "$k5" "$off" "$name"
        done <"$b.entries"
    } >"$work/ent_$u"
    caps_none >"$work/caps0"
    build "$OUT/osh_$u.unit" test1 1 5 1 "$nfn" "$b.ir" "$b.code" "$work/ent_$u" "$work/caps0"
    # header offset 36: max_stack_bytes (u32 LE), offset 40: cpu_ticks (u64 LE); both are signed, so re-sign
    s=$(printf '%08x' "$STACK"); t=$(printf '%016x' "$TICKS")
    le() { echo "$1" | sed -E 's/(..)/\1 /g' | awk '{for(i=NF;i>0;i--) printf "%s ", $i}'; }
    # shellcheck disable=SC2046
    patch "$OUT/osh_$u.unit" 36 $(le "$s") $(le "$t") >"$OUT/osh_$u.unit.new"
    mv "$OUT/osh_$u.unit.new" "$OUT/osh_$u.unit"
    resign "$OUT/osh_$u.unit" test1
    echo "built $OUT/osh_$u.unit ($nfn functions)"
done
