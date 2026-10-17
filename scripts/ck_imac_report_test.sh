#!/bin/sh
# ck_imac_report_test.sh -- host test of the iMac kernel's network report:
# the frames x86/report_x86.c builds (Ethernet broadcast, IPv4, UDP with a
# checksum, part headers) and the receiver tools/ck_imac_report_listen.c,
# which must rebuild the report byte for byte from parts sent out of order
# and repeated. Hosted only; the BCM57766 itself cannot be emulated.
# Ends with "AIENOS_IMAC_REPORT: PASS" or "AIENOS_IMAC_REPORT: FAIL <why>".
set -u
cd "$(dirname "$0")/.."
K=native/kernel
W=$(mktemp -d "${TMPDIR:-/tmp}/ck_imac_report.XXXXXX")
trap 'kill $LP 2>/dev/null; rm -rf "$W"' EXIT
LP=
fail() { echo "AIENOS_IMAC_REPORT: FAIL $*"; exit 1; }
CC=${HOSTCC:-cc}
CF="-std=gnu11 -O2 -Wall -Wextra -Werror"
$CC $CF -o "$W/listen" $K/tools/ck_imac_report_listen.c || fail "listener does not build"
$CC $CF -DCK_X86_REPORT_HOST -I$K/x86 -I$K/tests -Inative/net -o "$W/test" \
    $K/tests/test_imac_report.c $K/x86/report_x86.c native/net/aienos_net.c || fail "test does not build"
"$W/test" || fail "frame checks"
PORT=$((47100 + $$ % 800))
mkdir -p "$W/out"
"$W/listen" $PORT "$W/out" 20 &
LP=$!
i=0
until grep -q "^ready port=$PORT" "$W/out/listen.log" 2>/dev/null; do
    i=$((i + 1)); [ $i -gt 50 ] && fail "listener not ready: $(cat "$W/out/listen.log" 2>/dev/null)"
    sleep 0.1
done
"$W/test" send $PORT "$W/sent.txt" >/dev/null || fail "send"
i=0
until grep -q "^complete run=0123456789abcdef " "$W/out/listen.log"; do
    i=$((i + 1)); [ $i -gt 50 ] && fail "report not completed: $(cat "$W/out/listen.log")"
    sleep 0.1
done
cmp -s "$W/sent.txt" "$W/out/imac-0123456789abcdef.txt" || fail "rebuilt report differs"
[ "$(grep -c '^complete ' "$W/out/listen.log")" = 1 ] || fail "report written more than once"
grep -q '^ignored' "$W/out/listen.log" && fail "listener ignored a valid part"
echo "AIENOS_IMAC_REPORT: PASS"
