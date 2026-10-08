#!/usr/bin/env bash
# Self-test of scripts/lib_gate_hold.sh, the one way QEMU gate scripts treat
# the machine quiet flag and the QEMU gate lock (aienos#278).
#
# Runs only in a temp folder: AIENOS_QUIET_FLAG and AIENOS_GATE_LOCK point
# there, never at ~/workspace. No QEMU, no build, no GPU.
#
# Cases:
#   1 two competing gates: the second refuses (exit 3) and names the holder
#   2 a gate killed mid-run (SIGKILL, no trap): another gate does not remove
#     that dead hold before its expected_end; the same gate removes its own
#     dead hold and runs; a dead hold past expected_end is stale for any gate
#   3 a record without a readable pid (old "<name> <pid>" or "lane tag" form)
#     is held and never removed, in the gate lock and in the quiet flag
#   4 the quiet flag held by a live owner: the gate refuses by name, the flag
#     is unchanged
#   5 the quiet flag of the caller's own quietlock hold (hold=<id> equal to
#     QUIETLOCK_HOLD): the gate runs and leaves the flag alone
#   6 release removes only this run's own record
#   7 the gate lock record is in the quietlock record format (holder, start=,
#     expected_end=, pid=, hold=); when quietlock is installed it reads the
#     holder as alive
#   8 no script under scripts/ writes or removes the machine quiet flag
#   9 a "*" in a record is not globbed; a reused pid (other start time) is
#     dead; no date or no flock: the gate refuses and writes nothing
# Exit 0 when every case passes, 1 otherwise.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lib="${here}/lib_gate_hold.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
export AIENOS_QUIET_FLAG="${tmp}/spark-quiet"
export AIENOS_GATE_LOCK="${tmp}/qemu-gate-lock"
unset QUIETLOCK_HOLD
case "${AIENOS_QUIET_FLAG}${AIENOS_GATE_LOCK}" in
    *"${HOME}/workspace/"*) echo "gate_hold_selftest: refusing to run on the real flag paths" >&2; exit 1 ;;
esac

pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# A fake gate: takes the quiet check and the gate lock like a real gate, then
# runs its body ("sleep N" or "true"). Exit 3 + "NOT_RUN <why>" when refused.
gate="${tmp}/fake_gate.sh"
cat >"${gate}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
. "${lib}"
name="\$1"; shift
if ! gh_quiet_check || ! gh_lock_take "\${name}" "\${GATE_MINUTES:-30}"; then
    echo "NOT_RUN  \${gh_why}"
    exit 3
fi
trap gh_lock_release EXIT
"\$@"
EOF
chmod +x "${gate}"

dead_pid() { sleep 0 & local p=$!; wait "${p}" 2>/dev/null; echo "${p}"; }
iso() { date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ; }
wait_lock() { local i; for i in $(seq 1 100); do [[ -s "${AIENOS_GATE_LOCK}" ]] && return 0; sleep 0.05; done; return 1; }

if [[ ! -r "${lib}" ]]; then
    bad "lib_gate_hold.sh exists"
fi

# ---- 1: two competing gates
"${gate}" gateA sleep 30 >"${tmp}/a.out" 2>&1 & a=$!
wait_lock
out="$("${gate}" gateB true 2>&1)"; rc=$?
check "1 second gate refuses (exit 3)" '[[ ${rc} == 3 ]]'
check "1 refusal names the holder" '[[ ${out} == *"gateA"* ]]'
out="$("${gate}" gateA true 2>&1)"; rc=$?
check "1 same gate name, live holder: refuses" '[[ ${rc} == 3 && ${out} == *"gateA"* ]]'

# ---- 2: kill mid-gate, then cleanup removes only its own dead hold
kill -KILL "${a}" 2>/dev/null; wait "${a}" 2>/dev/null
check "2 SIGKILL leaves the hold behind" '[[ -s ${AIENOS_GATE_LOCK} ]]'
before="$(cat "${AIENOS_GATE_LOCK}" 2>/dev/null)"
out="$("${gate}" gateB true 2>&1)"; rc=$?
check "2 another gate does not remove a dead hold before expected_end" \
    '[[ ${rc} == 3 && "$(cat "${AIENOS_GATE_LOCK}" 2>/dev/null)" == "${before}" ]]'
out="$("${gate}" gateA true 2>&1)"; rc=$?
check "2 the same gate removes its own dead hold and runs" '[[ ${rc} == 0 ]]'
check "2 and releases it at exit" '[[ ! -e ${AIENOS_GATE_LOCK} ]]'
p="$(dead_pid)"
printf 'aienos qemu-gate gateX start=%s expected_end=%s pid=%s hold=old\n' \
    "$(iso '-2 hours')" "$(iso '-1 hour')" "${p}" >"${AIENOS_GATE_LOCK}"
out="$("${gate}" gateA true 2>&1)"; rc=$?
check "2 dead hold past expected_end is stale for any gate" '[[ ${rc} == 0 && ! -e ${AIENOS_GATE_LOCK} ]]'

# ---- 3: unreadable records are held, never removed
for rec in "qemu_ck_boot_test 12345" "lane11 qemu_native_nvme_test" "garbage"; do
    printf '%s\n' "${rec}" >"${AIENOS_GATE_LOCK}"
    out="$("${gate}" gateA true 2>&1)"; rc=$?
    check "3 gate lock '${rec}' is held" '[[ ${rc} == 3 ]]'
    check "3 gate lock '${rec}' is not removed" '[[ "$(cat "${AIENOS_GATE_LOCK}")" == "${rec}" ]]'
done
rm -f "${AIENOS_GATE_LOCK}"
printf 'qemu_ck_boot_test 12345\n' >"${AIENOS_QUIET_FLAG}"
out="$("${gate}" gateA true 2>&1)"; rc=$?
check "3 unreadable quiet flag is held" '[[ ${rc} == 3 && -e ${AIENOS_QUIET_FLAG} ]]'
rm -f "${AIENOS_QUIET_FLAG}"

# ---- 4: quiet flag of a live owner
printf 'gb10 t4fix measure start=%s expected_end=%s pid=%s hold=q-1\n' \
    "$(iso 'now')" "$(iso '+20 minutes')" "$$" >"${AIENOS_QUIET_FLAG}"
before="$(cat "${AIENOS_QUIET_FLAG}")"
out="$("${gate}" gateA true 2>&1)"; rc=$?
check "4 gate refuses while a live owner holds the machine" '[[ ${rc} == 3 ]]'
check "4 refusal names the machine holder" '[[ ${out} == *"gb10 t4fix measure"* ]]'
check "4 quiet flag unchanged" '[[ "$(cat "${AIENOS_QUIET_FLAG}")" == "${before}" && ! -e ${AIENOS_GATE_LOCK} ]]'

# ---- 5: inside the caller's own quietlock hold
out="$(QUIETLOCK_HOLD=q-1 "${gate}" gateA true 2>&1)"; rc=$?
check "5 gate runs inside the caller's quietlock hold" '[[ ${rc} == 0 ]]'
check "5 quiet flag left alone" '[[ "$(cat "${AIENOS_QUIET_FLAG}")" == "${before}" ]]'
out="$(QUIETLOCK_HOLD=q-2 "${gate}" gateA true 2>&1)"; rc=$?
check "5 a different hold id does not count" '[[ ${rc} == 3 ]]'
rm -f "${AIENOS_QUIET_FLAG}"

# ---- 6: release removes only this run's own record
"${gate}" gateA sleep 1 >"${tmp}/a6.out" 2>&1 & a=$!
wait_lock
other="aienos qemu-gate gateZ start=$(iso now) expected_end=$(iso '+5 minutes') pid=$$ hold=z"
printf '%s\n' "${other}" >"${AIENOS_GATE_LOCK}"
wait "${a}"
check "6 a replaced record is left alone at exit" '[[ "$(cat "${AIENOS_GATE_LOCK}" 2>/dev/null)" == "${other}" ]]'
rm -f "${AIENOS_GATE_LOCK}"

# ---- 7: record format
"${gate}" gateA sleep 30 >/dev/null 2>&1 & a=$!
wait_lock
rec="$(head -n1 "${AIENOS_GATE_LOCK}")"
check "7 record names holder, start, expected_end, pid and hold" \
    '[[ ${rec} =~ ^aienos\ qemu-gate\ gateA\ start=[0-9TZ:-]+\ expected_end=[0-9TZ:-]+\ pid=[0-9]+\ .*hold=[A-Za-z0-9._-]+ ]]'
if command -v quietlock >/dev/null 2>&1; then
    mkdir -p "${tmp}/ql"
    cp "${AIENOS_GATE_LOCK}" "${tmp}/ql/.spark-quiet"
    qout="$(QUIETLOCK_DIR="${tmp}/ql" quietlock check 2>&1)"
    check "7 quietlock reads the record as alive" '[[ ${qout} == *"pid="[0-9]* && ${qout} == *"alive=yes"* ]]'
else
    echo "skip 7 quietlock not installed"
fi
kill -TERM "${a}" 2>/dev/null; wait "${a}" 2>/dev/null
check "7 SIGTERM releases the hold" '[[ ! -e ${AIENOS_GATE_LOCK} ]]'

# ---- 9: review hardening (aienos#281 review)
# 9a a "*" in a record is a literal token, never a filename glob
mkdir -p "${tmp}/globdir" && touch "${tmp}/globdir/gateA"
p="$(dead_pid)"
printf 'aienos qemu-gate * start=%s expected_end=%s pid=%s hold=g\n' "$(iso '-1 minute')" "$(iso '+30 minutes')" "${p}" >"${AIENOS_GATE_LOCK}"
before="$(cat "${AIENOS_GATE_LOCK}")"
out="$(cd "${tmp}/globdir" && "${gate}" gateA true 2>&1)"; rc=$?
check "9a holder '*' is not read as a filename (dead, before expected_end: held)" \
    '[[ ${rc} == 3 && "$(cat "${AIENOS_GATE_LOCK}")" == "${before}" ]]'
rm -f "${AIENOS_GATE_LOCK}"
# 9b pid reused: the recorded start time differs from the live pid's, so the
#    holder is dead (removed by the same gate name)
printf 'aienos qemu-gate gateA start=%s expected_end=%s pid=%s pidstart=1 hold=g\n' "$(iso now)" "$(iso '+30 minutes')" "$$" >"${AIENOS_GATE_LOCK}"
out="$("${gate}" gateA true 2>&1)"; rc=$?
check "9b live pid with a different start time counts as dead" '[[ ${rc} == 0 && ! -e ${AIENOS_GATE_LOCK} ]]'
printf 'aienos qemu-gate gateA start=%s expected_end=%s pid=%s pidstart=1 hold=g\n' "$(iso now)" "$(iso '+30 minutes')" "$$" >"${AIENOS_GATE_LOCK}"
out="$("${gate}" gateB true 2>&1)"; rc=$?
check "9b and another gate still waits for its expected_end" '[[ ${rc} == 3 && -e ${AIENOS_GATE_LOCK} ]]'
rm -f "${AIENOS_GATE_LOCK}"
# 9c no clock or no flock: refuse, write nothing
mkdir -p "${tmp}/nodate" "${tmp}/noflock"
for t in bash cat flock mkdir dirname rm sleep true; do ln -sf "$(command -v "${t}")" "${tmp}/nodate/${t}"; done
for t in bash cat date mkdir dirname rm sleep true; do ln -sf "$(command -v "${t}")" "${tmp}/noflock/${t}"; done
out="$(PATH="${tmp}/nodate" "${gate}" gateA true 2>&1)"; rc=$?
check "9c no date: refuses and writes no record" '[[ ${rc} == 3 && ${out} == *"clock"* && ! -e ${AIENOS_GATE_LOCK} ]]'
out="$(PATH="${tmp}/noflock" "${gate}" gateA true 2>&1)"; rc=$?
check "9c no flock: refuses by name and writes no record" '[[ ${rc} == 3 && ${out} == *"flock not found"* && ! -e ${AIENOS_GATE_LOCK} ]]'

# ---- 8: no script writes or removes the machine quiet flag
# trust1_m5_qualify.sh is left out of the grep: it writes and removes a flag
# only in --self-test, after pointing QUIET_FLAG at a temp file; 8b checks that
# every reassignment of its QUIET_FLAG is such a temp file or a restore.
writers="$(grep -n -E '(>|rm -f) *"?\$\{?(quiet_flag|quiet|QUIET_FLAG)\}?"' "${here}"/*.sh 2>/dev/null \
    | grep -v -E '/(gate_hold_selftest|trust1_m5_qualify)\.sh:' | cut -d: -f1,2 || true)"
check "8 no script writes or removes the quiet flag" '[[ -z ${writers} ]]'
[[ -n ${writers} ]] && printf '     %s\n' ${writers}
reassign="$(grep -n -E '(^|[ ;])QUIET_FLAG=' "${here}/trust1_m5_qualify.sh" \
    | grep -v -E 'QUIET_FLAG="(\$\{AIENOS_QUIET_FLAG:-\$\{HOME\}/workspace/\.spark-quiet\}|\$\{tmp\}/[A-Za-z0-9_]+|\$\{saved_quiet2?\})"' || true)"
check "8b trust1_m5_qualify.sh points QUIET_FLAG only at the default, temp files or a restore" '[[ -z ${reassign} ]]'
[[ -n ${reassign} ]] && printf '     %s\n' "${reassign}"

echo "gate_hold_selftest: ${pass} passed, ${fail} failed"
[[ ${fail} == 0 ]]
