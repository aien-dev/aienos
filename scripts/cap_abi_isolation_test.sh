#!/usr/bin/env bash
# The native C capability authority and the Rust capability crates are two
# separate implementations with incompatible layouts:
#
#   native/capability (production ABI)   AienosCapRef 16 bytes, u64 generation,
#                                        symbols aienos_cap_*
#   crates/aienos-capability-ffi         AienosCapRef 8 bytes, u32 generation,
#                                        symbols aienos_cap32_*
#
# This test proves they cannot be swapped by accident. It builds both archives
# and checks, with nm and the linker:
#   1 both archives define their expected entry points (non-empty, positive)
#   2 no aienos_cap* text symbol is defined by both archives
#   3 the C archive defines no aienos_cap32_*; the Rust one no aienos_cap_*
#   4 a C program compiled against aienos_capability.h links and runs against
#     the C archive, and FAILS TO LINK against the Rust archive with an
#     undefined reference to aienos_cap_*
#   5 control: a C caller of the cap32 ABI links against the Rust archive with
#     the same link line, and aienos_cap32_abi_layout reports 8/4/4/64, v1
#   6 the C layout asserts reject a drifted header: a narrowed generation, and
#     an equal-size reorder of AienosCapRef
# Any build failure, or any check that cannot run, fails the test (exit 1).
# No Python. Needs cc, ar, nm, cargo.
#
#   bash scripts/cap_abi_isolation_test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
CC="${CC:-cc}"
CFLAGS="-std=gnu11 -O2 -Wall -Wextra -Werror"
fails=0

die() { echo "cap-abi-isolation FAIL: $*" >&2; echo "AIENOS_CAP_ABI_ISOLATION: FAIL"; exit 1; }
check() { # name, then a command that must succeed
    local name="$1"; shift
    if "$@"; then echo "ok   $name"; else echo "FAIL $name"; fails=$((fails + 1)); fi
}

for tool in "$CC" ar nm cargo; do
    command -v "$tool" > /dev/null || die "missing tool: $tool"
done

# ---- build both archives (any failure here is a test failure) -------------
make -s -C "$ROOT/native/capability" OUT="$WORK/c" "$WORK/c/libaienos_capability.a" \
    > "$WORK/c-build.log" 2>&1 || { tail -20 "$WORK/c-build.log"; die "native C library build"; }
C_LIB="$WORK/c/libaienos_capability.a"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
(cd "$ROOT" && cargo build --locked -p aienos-capability-ffi) \
    > "$WORK/rust-build.log" 2>&1 || { tail -20 "$WORK/rust-build.log"; die "Rust staticlib build"; }
R_LIB="$TARGET_DIR/debug/libaienos_capability_ffi.a"
[ -s "$C_LIB" ] || die "C archive missing: $C_LIB"
[ -s "$R_LIB" ] || die "Rust archive missing: $R_LIB"

# ---- symbol sets ------------------------------------------------------------
syms() { # defined global text symbols starting with aienos_cap
    nm --defined-only -g "$1" 2> /dev/null | awk '$2 == "T" {print $3}' |
        grep '^aienos_cap' | sort -u || true
}
syms "$C_LIB" > "$WORK/c.syms"
syms "$R_LIB" > "$WORK/r.syms"
echo "C archive:    $(wc -l < "$WORK/c.syms") aienos_cap* text symbols"
echo "Rust archive: $(wc -l < "$WORK/r.syms") aienos_cap* text symbols"

has() { grep -qx "$2" "$1"; }
for s in aienos_cap_start aienos_cap_stop aienos_cap_mint aienos_cap_validate aienos_cap_restart; do
    check "C archive defines $s" has "$WORK/c.syms" "$s"
done
for s in aienos_cap32_start aienos_cap32_stop aienos_cap32_mint aienos_cap32_validate \
    aienos_cap32_restart aienos_cap32_abi_layout; do
    check "Rust archive defines $s" has "$WORK/r.syms" "$s"
done

comm -12 "$WORK/c.syms" "$WORK/r.syms" > "$WORK/common.syms"
check "no aienos_cap* symbol defined by both archives" test ! -s "$WORK/common.syms"
[ -s "$WORK/common.syms" ] && sed 's/^/     shared: /' "$WORK/common.syms"
check "C archive defines no aienos_cap32_*" bash -c "! grep -q '^aienos_cap32_' '$WORK/c.syms'"
check "Rust archive defines no aienos_cap_*" bash -c "! grep -q '^aienos_cap_' '$WORK/r.syms'"

# ---- link probe: a caller of the production C ABI ---------------------------
cat > "$WORK/probe.c" << 'C'
#include <stdio.h>
#include "aienos_capability.h"
int main(void) {
    AienosCapAdmin *admin = NULL;
    AienosCapView *view = NULL;
    if (aienos_cap_start(&admin, &view) != AIENOS_CAP_OK) return 2;
    AienosCapRef office;
    if (aienos_cap_office(admin, &office) != AIENOS_CAP_OK) return 3;
    int rc = aienos_cap_validate(view, office, 0, AIENOS_CAP_RES_AUTHORITY,
                                 AIENOS_CAP_RIGHT_MINT, NULL);
    aienos_cap_stop(admin, view);
    printf("probe sizeof(AienosCapRef)=%zu validate=%d\n", sizeof(AienosCapRef), rc);
    return rc == AIENOS_CAP_OK && sizeof(AienosCapRef) == 16 ? 0 : 4;
}
C
"$CC" $CFLAGS -I "$ROOT/native/capability" -c -o "$WORK/probe.o" "$WORK/probe.c" ||
    die "probe compile against aienos_capability.h"

RLINK="-lpthread -ldl -lm"
check "C-ABI probe links against the C archive" \
    "$CC" -o "$WORK/probe_c" "$WORK/probe.o" "$C_LIB" -pthread
check "C-ABI probe runs against the C archive" "$WORK/probe_c"

# shellcheck disable=SC2086
if "$CC" -o "$WORK/probe_r" "$WORK/probe.o" "$R_LIB" $RLINK > "$WORK/probe_r.log" 2>&1; then
    echo "FAIL C-ABI probe LINKED against the Rust archive (layouts would be misread)"
    fails=$((fails + 1))
elif grep -q "undefined reference to .aienos_cap_start" "$WORK/probe_r.log" &&
    grep -q "undefined reference to .aienos_cap_validate" "$WORK/probe_r.log"; then
    echo "ok   C-ABI probe fails to link against the Rust archive (undefined aienos_cap_*)"
else
    echo "FAIL C-ABI probe did not link against the Rust archive, but not for the expected reason:"
    tail -5 "$WORK/probe_r.log"
    fails=$((fails + 1))
fi

# ---- control: the same link line works for a real cap32 caller -------------
cat > "$WORK/probe32.c" << 'C'
#include <stdint.h>
#include <stdio.h>
uint32_t aienos_cap32_abi_layout(uint32_t *out);
int main(void) {
    uint32_t w[4] = {0, 0, 0, 0};
    uint32_t v = aienos_cap32_abi_layout(w);
    printf("cap32 abi v%u ref=%u gen_off=%u gen_size=%u entry=%u\n", v, w[0], w[1], w[2], w[3]);
    return v == 1 && w[0] == 8 && w[1] == 4 && w[2] == 4 && w[3] == 64 ? 0 : 1;
}
C
"$CC" $CFLAGS -c -o "$WORK/probe32.o" "$WORK/probe32.c" || die "cap32 probe compile"
# shellcheck disable=SC2086
check "control: cap32 caller links against the Rust archive" \
    "$CC" -o "$WORK/probe32" "$WORK/probe32.o" "$R_LIB" $RLINK
check "control: aienos_cap32_abi_layout reports v1 8/4/4/64" "$WORK/probe32"
check "control: cap32 caller does not link against the C archive" \
    bash -c "! '$CC' -o '$WORK/probe32_c' '$WORK/probe32.o' '$C_LIB' -pthread > /dev/null 2>&1"

# ---- the C layout asserts reject a drifted header ----------------------------
drift() { # name, perl substitution on the header; the copy must NOT compile
    local name="$1" expr="$2" d="$WORK/drift-$1"
    mkdir -p "$d"
    cp "$ROOT/native/capability/aienos_capability.c" "$ROOT/native/capability/aienos_capability.h" "$d/"
    perl -0pi -e "$expr" "$d/aienos_capability.h"
    if cmp -s "$d/aienos_capability.h" "$ROOT/native/capability/aienos_capability.h"; then
        echo "FAIL drift $name: substitution did not apply"; fails=$((fails + 1)); return
    fi
    if "$CC" $CFLAGS -c -o "$d/x.o" "$d/aienos_capability.c" > "$d/log" 2>&1; then
        echo "FAIL drift $name: compiled, layout asserts did not fire"; fails=$((fails + 1))
    elif grep -q 'static assertion failed' "$d/log"; then
        echo "ok   drift $name rejected by _Static_assert"
    else
        echo "FAIL drift $name: build failed for another reason"; tail -3 "$d/log"; fails=$((fails + 1))
    fi
}
drift narrowed-generation \
    's/typedef struct \{\n    uint32_t cap_id;\n    uint64_t generation;\n\} AienosCapRef;/typedef struct {\n    uint32_t cap_id;\n    uint32_t generation;\n} AienosCapRef;/'
drift reordered-same-size \
    's/typedef struct \{\n    uint32_t cap_id;\n    uint64_t generation;\n\} AienosCapRef;/typedef struct {\n    uint64_t generation;\n    uint32_t cap_id;\n} AienosCapRef;/'

if [ "$fails" -ne 0 ]; then
    echo "AIENOS_CAP_ABI_ISOLATION: FAIL ($fails checks failed)"
    exit 1
fi
echo "AIENOS_CAP_ABI_ISOLATION: PASS"
