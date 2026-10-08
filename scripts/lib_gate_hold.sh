# shellcheck shell=bash
# lib_gate_hold.sh: how a QEMU gate script treats the machine quiet flag and
# the QEMU gate lock (aienos#278). Sourced; sets no shell options.
#
# The machine quiet flag (AIENOS_QUIET_FLAG, default ~/workspace/.spark-quiet)
# belongs to quietlock: gates only READ it (no agent raises it without
# Drake's approval; holds are taken with `quietlock hold`). A gate refuses
# while the flag exists, except inside the caller's own quietlock hold (the
# flag's hold=<id> equals $QUIETLOCK_HOLD, which `quietlock hold` exports to
# its command).
#
# One QEMU gate at a time: the gate lock (AIENOS_GATE_LOCK, default
# ~/workspace/.qemu-gate-lock) holds one record in the quietlock record format
#   aienos qemu-gate <name> start=<iso> expected_end=<iso> pid=<n> pidstart=<n> hold=<id>
# (holder = the first three fields), so `quietlock check`-style readers see
# the holder and whether it is alive. Taking, clearing and releasing run under
# flock on "<lock>.mutex", and the record is created by exclusive create.
#
# Rules (the quietlock rules, gate side):
#  - a live holder is never removed;
#  - a record without a readable holder, pid= or expected_end= is HELD and is
#    never removed (nothing here can prove its holder dead);
#  - a dead holder's record is removed by the same gate (same <name>) at once,
#    or by any gate once its expected_end has passed (quietlock's stale rule);
#  - a gate removes only its own record at exit (exact line match).
# A holder is dead when /proc/<pid> is gone, is a zombie, or started at a
# different time than pidstart= records (pid reused).
#
# API: gh_quiet_check; gh_lock_take NAME MINUTES; gh_lock_release.
# The first two return 0 (go) or 3 (refused; $gh_why says why and names the
# holder). gh_lock_release is safe to call more than once (EXIT trap).

gh_quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
gh_gate_lock="${AIENOS_GATE_LOCK:-${HOME}/workspace/.qemu-gate-lock}"
gh_why=""
gh_line=""

_gh_iso() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }

# Start time (clock ticks since boot, /proc/<pid>/stat field 22) of a pid.
_gh_pidstart() {
    local s
    s="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
    s="${s##*) }"
    # shellcheck disable=SC2086
    set -- ${s}
    [[ $# -ge 20 ]] || return 1
    printf '%s\n' "${20}"
}

_gh_alive() { # pid [pidstart]
    local s st
    s="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
    st="${s##*) }"; st="${st%% *}"
    [[ "${st}" != Z ]] || return 1
    [[ -z "${2:-}" || "$(_gh_pidstart "$1")" == "$2" ]]
}

# Parse the first line of a record file into _gh_holder _gh_name _gh_pid
# _gh_pidstart _gh_end _gh_end_text _gh_hold. Return 0 when holder (three
# plain fields), pid= and expected_end= are all readable, else 1.
_gh_parse() {
    local line tok n=0
    _gh_holder="" _gh_name="" _gh_pid="" _gh_pidstart="" _gh_end="" _gh_end_text="" _gh_hold=""
    IFS= read -r line <"$1" 2>/dev/null || [[ -n "${line:-}" ]] || return 1
    _gh_first="${line:0:200}"
    for tok in ${line}; do
        case "${tok}" in
            pid=*) [[ -z "${_gh_pid}" ]] && _gh_pid="${tok#pid=}" ;;
            pidstart=*) [[ -z "${_gh_pidstart}" ]] && _gh_pidstart="${tok#pidstart=}" ;;
            expected_end=*) [[ -z "${_gh_end_text}" ]] && _gh_end_text="${tok#expected_end=}" ;;
            hold=*) [[ -z "${_gh_hold}" ]] && _gh_hold="${tok#hold=}" ;;
            *=*) ;;
            *) if [[ ${n} -lt 3 ]]; then
                   n=$((n + 1)); _gh_holder="${_gh_holder:+${_gh_holder} }${tok}"; [[ ${n} == 3 ]] && _gh_name="${tok}"
               fi ;;
        esac
    done
    [[ ${n} == 3 && "${_gh_pid}" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -n "${_gh_end_text}" ]] && _gh_end="$(date -u -d "${_gh_end_text}" +%s 2>/dev/null)" || return 1
    [[ "${_gh_pidstart}" =~ ^[0-9]*$ ]] || _gh_pidstart=""
    return 0
}

_gh_describe() { # file -> "holder='...' pid=... alive=... expected_end=..." or the raw line
    if _gh_parse "$1"; then
        local alive=no
        _gh_alive "${_gh_pid}" "${_gh_pidstart}" && alive=yes
        printf "holder='%s' pid=%s alive=%s expected_end=%s" "${_gh_holder}" "${_gh_pid}" "${alive}" "${_gh_end_text}"
    else
        printf "unreadable record, treated as held: %s" "${_gh_first:-?}"
    fi
}

# 0 = the machine is not held for this gate; 3 = refused.
gh_quiet_check() {
    gh_why=""
    [[ -e "${gh_quiet_flag}" ]] || return 0
    if _gh_parse "${gh_quiet_flag}" && [[ -n "${_gh_hold}" && "${_gh_hold}" == "${QUIETLOCK_HOLD:-}" ]]; then
        echo "gate_hold: running inside the caller's quietlock hold ${_gh_hold} (quiet flag left alone)" >&2
        return 0
    fi
    gh_why="quiet flag ${gh_quiet_flag} is held ($(_gh_describe "${gh_quiet_flag}"))"
    return 3
}

gh_lock_take() { # NAME MINUTES
    local name="$1" minutes="$2" fd now line rc=0
    gh_why=""
    if [[ ! "${name}" =~ ^[A-Za-z0-9._-]{1,64}$ || ! "${minutes}" =~ ^[1-9][0-9]*$ ]]; then
        gh_why="gate_hold: bad gate name or minutes ('${name}', '${minutes}')"
        return 3
    fi
    mkdir -p "$(dirname "${gh_gate_lock}")" 2>/dev/null || true
    if ! exec {fd}>>"${gh_gate_lock}.mutex"; then
        gh_why="QEMU gate lock mutex ${gh_gate_lock}.mutex cannot be opened"
        return 3
    fi
    if ! flock -x -w 30 "${fd}"; then
        exec {fd}>&-
        gh_why="QEMU gate lock mutex ${gh_gate_lock}.mutex busy for 30 s"
        return 3
    fi
    now="$(date +%s)"
    if [[ -e "${gh_gate_lock}" ]]; then
        if ! _gh_parse "${gh_gate_lock}"; then
            gh_why="QEMU gate lock ${gh_gate_lock} is held (unreadable record, treated as held and never removed: ${_gh_first:-?})"
            rc=3
        elif _gh_alive "${_gh_pid}" "${_gh_pidstart}"; then
            gh_why="QEMU gate lock ${gh_gate_lock} is held ($(_gh_describe "${gh_gate_lock}"))"
            rc=3
        elif [[ "${_gh_name}" == "${name}" || ${now} -gt ${_gh_end} ]]; then
            echo "gate_hold: removing dead QEMU gate lock record ($(_gh_describe "${gh_gate_lock}"); $([[ "${_gh_name}" == "${name}" ]] && echo "this gate's own" || echo "past expected_end"))" >&2
            rm -f "${gh_gate_lock}"
        else
            gh_why="QEMU gate lock ${gh_gate_lock} is held by a dead gate before its expected_end ($(_gh_describe "${gh_gate_lock}")); only that gate, or any gate after expected_end, removes it"
            rc=3
        fi
    fi
    if [[ ${rc} == 0 ]]; then
        line="aienos qemu-gate ${name} start=$(_gh_iso "${now}") expected_end=$(_gh_iso $((now + minutes * 60))) pid=$$ pidstart=$(_gh_pidstart $$) hold=gate-$$-${now}"
        if ( set -C; printf '%s\n' "${line}" >"${gh_gate_lock}" ) 2>/dev/null; then
            gh_line="${line}"
        else
            gh_why="QEMU gate lock ${gh_gate_lock} appeared while taking it ($(_gh_describe "${gh_gate_lock}"))"
            rc=3
        fi
    fi
    flock -u "${fd}"
    exec {fd}>&-
    return ${rc}
}

gh_lock_release() {
    local fd cur
    [[ -n "${gh_line}" ]] || return 0
    if exec {fd}>>"${gh_gate_lock}.mutex" && flock -x -w 30 "${fd}"; then
        IFS= read -r cur <"${gh_gate_lock}" 2>/dev/null || true
        [[ "${cur:-}" == "${gh_line}" ]] && rm -f "${gh_gate_lock}"
        flock -u "${fd}"
        exec {fd}>&-
    fi
    gh_line=""
    return 0
}
