#!/usr/bin/env bash
# Store crash gate for the AIENOS C kernel: CK gate M4_STORE_CRASH.
# C-kernel port of the Rust campaigns scripts/qemu_store_crash_test.sh
# (4096-byte LBA) and scripts/qemu_store_512b_crash_test.sh (512-byte LBA).
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# Images (native/kernel/Makefile):
#  - make full                     default image: every setup and verify boot
#  - make full CK_TEST_STORE_CRASH=1
#                                  TEST-ONLY crash hook image (svc/store_crash.h):
#                                  only the crash boots. Never counts toward a
#                                  PASS of M4_STORE; refused with
#                                  CK_HARDWARE_STAGING and CK_QEMU_UNSAFE_DMA.
#
# Power-cut model. The host writes a crash plan into the last 4096-byte unit
# of the AIENOS partition (the rw-probe scratch unit, restored by the devices
# stage; the kernel sees only that partition, dev/disk_part.h):
# "AIENCRSH v1 cp=<checkpoint> policy=<drop|all|newest|torn>". The TEST image
# then runs the Store on a volatile write cache: nothing reaches the disk until
# the Store flushes. At the planned checkpoint it lands, per policy, none / all
# / only the newest write call / the first half of the blocks of the newest
# write call of the unflushed writes, flushes, prints "store_crash: HALT at"
# and stops; the host kills QEMU (SIGKILL). policy=all is the Rust tier 1
# model (QEMU killed, every accepted write is in the host file); drop, newest
# and torn model a lost or reordered volatile cache and a root write cut
# between sectors, which the Rust campaign does not boot.
#
# Commit stages of one boot commit (native/store/store_engine.c st_transact and
# store_sealed.c ss_commit_prepared), checkpoint name -> what it models:
#   before_first_write .. after_commit_record   before the data flush
#   after_first_flush                           after data, before the root
#   after_inactive_superblock                   during/after the root write,
#                                               before the root flush
#   after_final_flush, before_anchor            root durable, anchor behind
#   after_anchor                                commit and anchor durable
#
# Campaign, per geometry (512 B and 4096 B namespaces, fresh 64 MiB GPT image
# from native/kernel/tools/ck_gpt_image.c, AIENOS partition [9,57) MiB, as in
# scripts/qemu_ck_store_test.sh; all Store offsets below are partition offsets
# plus the partition start) and
# per settle (0: the crash boot formats a blank disk; 3: three default boots
# first, as the Rust settle 3): every checkpoint with policy=all, plus
# after_commit_record/newest and after_inactive_superblock drop/newest/torn.
# Each case: crash boot (TEST image), plan cleared, verify boot (default
# image). N = the generation the crash boot opened (must be 1 + settle).
# The verify boot must pass the M1 checks, exit 0, print "stage store: ok", no
# "store: REFUSED", no reformat, and open:
#   N        before the root write landed (Rust: "N")
#   N + 1    after the final flush (Rust: "NP1"), and for policy=all at
#            after_inactive_superblock (QEMU kill: the root write is in the file)
#   N or N+1 newest/torn at after_inactive_superblock (Rust: "N_NP1")
# with boot_count and prev_commit of that generation, anchor
# prepared-advance while the anchor is behind (native/store/README.md "Commit
# order"), then commit generation + 1.
# Root tear closure (Rust tier 2a, here on the QEMU images): for settle 3 the
# after_inactive_superblock/all crash changes exactly one superblock slot,
# that slot then holds generation N + 1, and every changed byte lies in the
# slot's first 512 bytes, so any sector-granular tear of the root write
# leaves either the old or the new slot bytes.
# Injected root (Rust tier 2b, one case): that crash image with one byte of the
# new root's CRC flipped must not open generation N + 1: Store refused, nothing
# committed, disk left as found (image sha256 unchanged).
# Hardware refusal: make must refuse CK_TEST_STORE_CRASH with
# CK_HARDWARE_STAGING and with CK_QEMU_UNSAFE_DMA; the default image must
# carry no crash hook string; the TEST image must announce itself.
# Not covered: Rust STORE_SLOT_REUSE_QEMU (the C Store is append-only, no
# reclaim) is printed NOT_RUN and is not part of this gate.
#
# Usage: bash scripts/qemu_ck_store_crash_test.sh             the gate
#        bash scripts/qemu_ck_store_crash_test.sh --self-test host only, no QEMU:
#             judges, expectation table, plan bytes, tear-closure check and
#             make refusals against canned inputs and counterexamples
#        bash scripts/qemu_ck_store_crash_test.sh --mutant skip_root_flush
#        bash scripts/qemu_ck_store_crash_test.sh --mutant accept_bad_root_crc
#             builds the TEST-ONLY broken Store (CK_TEST_STORE_CRASH_MUTANT) and
#             runs the cases that must catch it, on that image only. Prints
#             AIENOS_CK_STORE_CRASH_MUTANT_<NAME>: KILLED (exit 0) when the
#             gate's checks FAIL on it, SURVIVED (exit 1) otherwise. Never
#             prints the AIENOS_CK_M4_STORE_CRASH line.
# Takes the machine quiet flag like qemu_ck_store_test.sh (not in --self-test).
# Final line (gate): AIENOS_CK_M4_STORE_CRASH: PASS|FAIL|NOT_RUN.
# Exit: 0 PASS, 1 FAIL, 2 missing tools/build failure, 3 quiet flag held.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

mode=gate; mutant=""
case "${1:-}" in
    "") ;;
    --self-test) mode=selftest ;;
    --mutant)
        mode=mutant; mutant="${2:-}"
        [[ "${mutant}" == skip_root_flush || "${mutant}" == accept_bad_root_crc ]] \
            || { echo "usage: $0 [--self-test | --mutant skip_root_flush|accept_bad_root_crc]" >&2; exit 2; } ;;
    *) echo "usage: $0 [--self-test | --mutant skip_root_flush|accept_bad_root_crc]" >&2; exit 2 ;;
esac

verdict() {
    if [[ "${mode}" == mutant ]]; then
        echo "AIENOS_CK_STORE_CRASH_MUTANT_${mutant^^}: $1"
    else
        echo "AIENOS_CK_M4_STORE_CRASH: $1"
    fi
}

img_bytes=67108864
unit=4096
units=$(( img_bytes / unit ))
plan_unit=$(( units - 1 ))
store_off=16384            # 4 anchor units (dev/disk_layout.h; qemu_ck_store_test.sh checks it)
# set_part BS FIRST_LBA LAST_LBA: the AIENOS partition of a GPT image. Sets
# sb_base (image byte offset of the Store region: partition start + store_off)
# and plan_unit (the last 4096-byte unit of the partition). Default: the whole
# image is the partition (self-test synthetic images).
sb_base=${store_off}
set_part() {
    sb_base=$(( $2 * $1 + store_off ))
    plan_unit=$(( ($3 + 1) * $1 / unit - 1 ))
}
sb_gen_off=56              # superblock generation (native/store/store_engine.c st_open gen_of)
sb_crc_off=168             # SV1_SB_CRC_OFFSET (native/store/store_v1.h)
cps=(before_first_write after_payload_objects after_catalog after_commit_record after_first_flush
     after_inactive_superblock after_final_flush before_anchor after_anchor)
# Gate cases beyond "every checkpoint, policy all" (per geometry and settle).
gate_extra=("after_commit_record newest" "after_inactive_superblock drop" "after_inactive_superblock newest" "after_inactive_superblock torn")
gate_geos=(512 4096); gate_settles=(0 3)
# Result rows a complete gate campaign prints: 2 x 2 x (9 + 4) = 52.
gate_rows_want=$(( ${#gate_geos[@]} * ${#gate_settles[@]} * (${#cps[@]} + ${#gate_extra[@]}) ))
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

# rows_all_ok FILE WANT: port of rows_all_ok in scripts/qemu_store_crash_test.sh
# lines 19-31 (main e4f1513 and later). True only when FILE holds exactly WANT
# result rows (lines with " -> ") and every one ends in "-> OK". A missing
# file, an empty or short campaign, an extra row or any BAD row is false, so a
# loop that never ran (or stopped early) cannot read as PASS.
rows_all_ok() {
    local f="$1" want="$2" total=0 ok=0
    rows_why=""
    [[ -f "${f}" ]] || { rows_why="results file ${f##*/} missing (want ${want} OK rows)"; return 1; }
    total=$(grep -c ' -> ' "${f}" || true)
    ok=$(grep -c ' -> OK$' "${f}" || true)
    if [[ "${want}" -gt 0 && "${total}" == "${want}" && "${ok}" == "${want}" ]]; then return 0; fi
    rows_why="${f##*/} has ${total} rows, ${ok} OK; want exactly ${want} OK"
    return 1
}

# --------------------------------------------------------------- pure logic
# expect_for CHECKPOINT POLICY -> N | NP1 | N_NP1 (generation the verify boot opens)
expect_for() {
    case "$1" in
        after_inactive_superblock)
            case "$2" in all) echo NP1 ;; drop) echo N ;; *) echo N_NP1 ;; esac ;;
        after_final_flush|before_anchor|after_anchor) echo NP1 ;;
        *) echo N ;;
    esac
}
# anchor_ok CHECKPOINT OPENED_GEN N ANCHOR -> 0 if the anchor state fits
anchor_ok() {
    local cp="$1" g="$2" n="$3" a="$4"
    if [[ "${g}" == "${n}" ]]; then [[ "${a}" == valid-resume || "${a}" == genesis ]]; return; fi
    case "${cp}" in
        after_anchor) [[ "${a}" == valid-resume ]] ;;
        *) [[ "${a}" == prepared-advance ]] ;;
    esac
}

# plan_bytes CP POLICY: the 4096-byte plan unit on stdout.
plan_bytes() {
    { printf 'AIENCRSH v1 cp=%s policy=%s\n' "$1" "$2"; head -c "${unit}" /dev/zero; } | head -c "${unit}"
}
write_plan() { plan_bytes "$2" "$3" | dd of="$1" bs="${unit}" seek="${plan_unit}" conv=notrunc status=none; }
clear_plan() { head -c "${unit}" /dev/zero | dd of="$1" bs="${unit}" seek="${plan_unit}" conv=notrunc status=none; }

# judge_crash SERIAL CP POLICY SETTLE: sets crash_n and crash_why; returns 0 if
# the crash boot halted exactly at CP with the planned policy.
judge_crash() {
    local s="$1" cp="$2" pol="$3" settle="$4" re seq want="" c
    crash_n=""; crash_why=""
    grep -qF "store_crash: TEST-ONLY Store crash hook image (CK_TEST_STORE_CRASH=1)" "${s}" || { crash_why="no TEST-ONLY banner"; return 1; }
    grep -qxF "store_crash: plan halt_at=${cp} policy=${pol}; Store runs on a volatile write cache" "${s}" \
        || { crash_why="plan not armed"; return 1; }
    re="^store_crash: HALT at ${cp} policy=${pol} generation_open=([0-9]+) target=([0-9]+) pending_writes=[0-9]+ pending_blocks=[0-9]+ landed_blocks=[0-9]+ rc=0 "
    local line; line="$(grep -E "^store_crash: HALT at " "${s}" || true)"
    [[ "$(grep -c . <<<"${line}")" == 1 && "${line}" =~ ${re} ]] || { crash_why="no single HALT at ${cp} with rc=0"; return 1; }
    crash_n="${BASH_REMATCH[1]}"
    [[ "${BASH_REMATCH[2]}" == $(( crash_n + 1 )) ]] || { crash_why="target is not generation_open + 1"; return 1; }
    [[ "${crash_n}" == $(( 1 + settle )) ]] || { crash_why="opened generation ${crash_n}, expected $(( 1 + settle ))"; return 1; }
    seq="$(sed -nE 's/^store_crash: checkpoint ([a-z_]+) generation_open=([0-9]+) .*/\1:\2/p' "${s}" | paste -sd' ' -)"
    for c in "${cps[@]}"; do want+="${want:+ }${c}:${crash_n}"; [[ "${c}" == "${cp}" ]] && break; done
    [[ "${seq}" == "${want}" ]] || { crash_why="checkpoint order '${seq}', expected '${want}'"; return 1; }
    grep -q "^store: committed" "${s}" && { crash_why="Store reported a commit before the halt"; return 1; }
    return 0
}

# judge_verify SERIAL CP POLICY SETTLE N: sets v_gen and v_why; 0 if the
# verify boot opened the right committed generation and committed on top.
judge_verify() {
    local s="$1" cp="$2" pol="$3" settle="$4" n="$5" exp ore cre oline cline g bc prev anc cg cbc
    v_gen=""; v_why=""
    exp="$(expect_for "${cp}" "${pol}")"
    grep -q "^stage store: ok" "${s}" || { v_why="stage store not ok"; return 1; }
    grep -q "store: REFUSED" "${s}" && { v_why="Store refused"; return 1; }
    grep -q "formatted TEST store" "${s}" && { v_why="Store reformatted after the crash"; return 1; }
    grep -q "^store_crash: HALT" "${s}" && { v_why="verify boot halted"; return 1; }
    ore='^store: opened generation=([0-9]+) boot_count=([0-9]+) prev_commit=([^ ]+) anchor=([a-z?-]+)$'
    cre='^store: committed generation=([0-9]+) boot_count=([0-9]+)$'
    oline="$(grep -E "${ore}" "${s}" || true)"; cline="$(grep -E "${cre}" "${s}" || true)"
    [[ "$(grep -c . <<<"${oline}")" == 1 && "${oline}" =~ ${ore} ]] || { v_why="no single opened line"; return 1; }
    g="${BASH_REMATCH[1]}"; bc="${BASH_REMATCH[2]}"; prev="${BASH_REMATCH[3]}"; anc="${BASH_REMATCH[4]}"
    v_gen="${g}"
    [[ "$(grep -c . <<<"${cline}")" == 1 && "${cline}" =~ ${cre} ]] || { v_why="no single committed line"; return 1; }
    cg="${BASH_REMATCH[1]}"; cbc="${BASH_REMATCH[2]}"
    case "${exp}" in
        N)     [[ "${g}" == "${n}" ]] ;;
        NP1)   [[ "${g}" == $(( n + 1 )) ]] ;;
        N_NP1) [[ "${g}" == "${n}" || "${g}" == $(( n + 1 )) ]] ;;
    esac || { v_why="opened generation ${g}, expected ${exp} (N=${n})"; return 1; }
    local want_bc=$(( settle + (g == n + 1 ? 1 : 0) ))
    [[ "${bc}" == "${want_bc}" ]] || { v_why="boot_count ${bc} at generation ${g}, expected ${want_bc}"; return 1; }
    if [[ "${bc}" == 0 ]]; then [[ "${prev}" == none ]]; else [[ "${prev}" == "${commit}" ]]; fi \
        || { v_why="prev_commit ${prev}"; return 1; }
    anchor_ok "${cp}" "${g}" "${n}" "${anc}" || { v_why="anchor ${anc} at generation ${g} (cp ${cp})"; return 1; }
    [[ "${cg}" == $(( g + 1 )) && "${cbc}" == $(( bc + 1 )) ]] \
        || { v_why="committed generation ${cg} boot_count ${cbc} after opening ${g}/${bc}"; return 1; }
    return 0
}

# judge_injected SERIAL N: 0 if the bad-CRC root (generation N+1) was not
# opened and nothing was committed (the image hash is checked by the caller).
judge_injected() {
    local s="$1" n="$2"
    inj_why=""
    grep -q "^store: opened generation=$(( n + 1 )) " "${s}" && { inj_why="opened the corrupt root generation $(( n + 1 ))"; return 1; }
    grep -q "^store: committed" "${s}" && { inj_why="committed on top of a corrupt root"; return 1; }
    grep -q "^store: REFUSED " "${s}" || { inj_why="no Store refusal"; return 1; }
    grep -q "disk left as found, not reformatted" "${s}" || { inj_why="no 'disk left as found'"; return 1; }
    grep -q "formatted TEST store" "${s}" && { inj_why="reformatted"; return 1; }
    return 0
}

u64_at() { od --endian=little -An -tu8 -j "$2" -N 8 "$1" | tr -d ' '; }

# tear_closure BEFORE AFTER N: 0 if exactly one superblock slot changed, it
# holds generation N+1 and every changed byte is in its first 512 bytes.
tear_closure() {
    local b="$1" a="$2" n="$3" diffs slots s off
    tc_why=""; tc_slot=""
    diffs="$(cmp -l "${b}" "${a}" 2>/dev/null | awk -v lo="${sb_base}" -v hi="$(( sb_base + 2 * unit ))" '$1-1 >= lo && $1-1 < hi {print $1-1}')"
    [[ -n "${diffs}" ]] || { tc_why="no superblock slot changed"; return 1; }
    slots="$(awk -v lo="${sb_base}" -v u="${unit}" '{print int(($1 - lo) / u)}' <<<"${diffs}" | sort -u)"
    [[ "$(grep -c . <<<"${slots}")" == 1 ]] || { tc_why="both superblock slots changed"; return 1; }
    s="${slots}"; off=$(( sb_base + s * unit ))
    awk -v o="${off}" '$1 - o >= 512 {bad=1} END {exit bad}' <<<"${diffs}" \
        || { tc_why="slot ${s} changed beyond its first 512-byte sector"; return 1; }
    [[ "$(u64_at "${a}" $(( off + sb_gen_off )))" == $(( n + 1 )) ]] \
        || { tc_why="changed slot ${s} does not hold generation $(( n + 1 ))"; return 1; }
    tc_slot="${s}"
    return 0
}

# make_refusals: the TEST hook must be refused with hardware staging and the
# unsafe DMA build; a mutant needs the hook; unknown mutants refused. Parse
# only (make -n): nothing is built.
make_refusals() {
    local out f=0
    mk() { make -n -s -C native/kernel OUT="${1}" full "${@:2}" 2>&1; }
    local tmpo; tmpo="$(mktemp -d)"
    out="$(mk "${tmpo}" CK_TEST_STORE_CRASH=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=/dev/null CK_MACHINE_ID=/dev/null)"
    grep -q "CK_TEST_STORE_CRASH (TEST-ONLY Store crash hook) cannot be combined with CK_HARDWARE_STAGING" <<<"${out}" \
        && echo "PASS  make refuses the crash hook with CK_HARDWARE_STAGING" || { echo "FAIL  hardware staging accepted the crash hook"; f=1; }
    out="$(mk "${tmpo}" CK_TEST_STORE_CRASH=1 CK_QEMU_UNSAFE_DMA=1)"
    grep -q "cannot be combined with CK_QEMU_UNSAFE_DMA" <<<"${out}" \
        && echo "PASS  make refuses the crash hook with CK_QEMU_UNSAFE_DMA" || { echo "FAIL  unsafe DMA build accepted the crash hook"; f=1; }
    out="$(mk "${tmpo}" CK_TEST_STORE_CRASH_MUTANT=skip_root_flush)"
    grep -q "CK_TEST_STORE_CRASH_MUTANT needs CK_TEST_STORE_CRASH=1" <<<"${out}" \
        && echo "PASS  make refuses a mutant without the TEST hook" || { echo "FAIL  mutant built without the TEST hook"; f=1; }
    out="$(mk "${tmpo}" CK_TEST_STORE_CRASH=1 CK_TEST_STORE_CRASH_MUTANT=bogus)"
    grep -q "CK_TEST_STORE_CRASH_MUTANT must be skip_root_flush or accept_bad_root_crc" <<<"${out}" \
        && echo "PASS  make refuses an unknown mutant" || { echo "FAIL  unknown mutant accepted"; f=1; }
    out="$(mk "${tmpo}" CK_TEST_STORE_CRASH=1)"
    grep -qE "^\*\*\*|Error|error:" <<<"${out}" && { echo "FAIL  plain TEST crash build refused: $(head -3 <<<"${out}")"; f=1; } \
        || echo "PASS  make accepts the plain TEST crash build (control)"
    rm -rf "${tmpo}"
    return "${f}"
}

# ----------------------------------------------------------------- self-test
self_test() {
    local st=0 t s n
    t="$(mktemp -d)"; trap 'rm -rf "${t}"' RETURN
    ok() { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; st=1; }
    [[ "$(expect_for after_commit_record all)" == N && "$(expect_for after_first_flush all)" == N \
       && "$(expect_for after_inactive_superblock all)" == NP1 && "$(expect_for after_inactive_superblock drop)" == N \
       && "$(expect_for after_inactive_superblock torn)" == N_NP1 && "$(expect_for after_final_flush all)" == NP1 \
       && "$(expect_for before_anchor all)" == NP1 && "$(expect_for after_anchor all)" == NP1 \
       && "$(expect_for before_first_write newest)" == N ]] && ok "expectation table" || bad "expectation table"

    # plan bytes: exact line, zero padded to one unit
    plan_bytes after_catalog torn >"${t}/plan"
    [[ "$(stat -c %s "${t}/plan")" == "${unit}" && "$(head -c 40 "${t}/plan")" == "AIENCRSH v1 cp=after_catalog policy=torn" \
       && "$(tail -c +41 "${t}/plan" | tr -d '\0' | od -An -c | tr -d ' ')" == '\n' ]] && ok "plan unit bytes" || bad "plan unit bytes"
    truncate -s "${img_bytes}" "${t}/img"; write_plan "${t}/img" after_anchor all
    cmp -s <(dd if="${t}/img" bs="${unit}" skip="${plan_unit}" count=1 status=none) <(plan_bytes after_anchor all) \
        && [[ "$(stat -c %s "${t}/img")" == "${img_bytes}" ]] && ok "plan written into the last unit only" || bad "plan placement"
    clear_plan "${t}/img"; cmp -s "${t}/img" <(head -c "${img_bytes}" /dev/zero) && ok "plan cleared" || bad "plan clear"
    # GPT disks: the plan goes into the last unit of the AIENOS partition
    # [9,57) MiB and the Store region starts store_off into it.
    ( set_part 512 18432 116735; [[ "${plan_unit}" == 14591 && "${sb_base}" == $(( 9 * 1048576 + store_off )) ]] ) \
        && ( set_part 4096 2304 14591; [[ "${plan_unit}" == 14591 && "${sb_base}" == $(( 9 * 1048576 + store_off )) ]] ) \
        && ok "partition plan unit and Store base (512 B and 4096 B GPT layouts)" || bad "set_part offsets"

    # crash judge
    n=4; s="${t}/crash.txt"
    { echo "store_crash: TEST-ONLY Store crash hook image (CK_TEST_STORE_CRASH=1); never counts toward a PASS of M4_STORE"
      echo "store_crash: plan halt_at=after_catalog policy=newest; Store runs on a volatile write cache"
      for c in before_first_write after_payload_objects after_catalog; do echo "store_crash: checkpoint ${c} generation_open=${n} pending_writes=1"; done
      echo "store_crash: HALT at after_catalog policy=newest generation_open=${n} target=5 pending_writes=2 pending_blocks=2 landed_blocks=1 rc=0 (power cut: the host kills QEMU now)"; } >"${s}"
    judge_crash "${s}" after_catalog newest 3 && ok "crash judge accepts a halt at the planned checkpoint" || bad "crash judge: ${crash_why}"
    judge_crash "${s}" after_catalog newest 0 && bad "crash judge accepted the wrong settle" || ok "crash judge refuses N != 1 + settle (${crash_why})"
    judge_crash "${s}" after_commit_record newest 3 && bad "crash judge accepted another checkpoint" || ok "crash judge refuses a halt elsewhere (${crash_why})"
    grep -v "checkpoint after_payload_objects" "${s}" >"${t}/c2"
    judge_crash "${t}/c2" after_catalog newest 3 && bad "crash judge accepted a skipped checkpoint" || ok "crash judge refuses a gap in the checkpoint order (${crash_why})"
    sed 's/rc=0/rc=-1/' "${s}" >"${t}/c3"
    judge_crash "${t}/c3" after_catalog newest 3 && bad "crash judge accepted rc!=0" || ok "crash judge refuses a failed landing (${crash_why})"
    grep -v "TEST-ONLY Store crash hook image" "${s}" >"${t}/c4"
    judge_crash "${t}/c4" after_catalog newest 3 && bad "crash judge accepted no banner" || ok "crash judge refuses an image without the banner"

    # verify judge
    vf() { # file gen bc prev anchor cgen cbc [extra line]
        { echo "stage store: ok"; echo "store: opened generation=$2 boot_count=$3 prev_commit=$4 anchor=$5"
          echo "store: committed generation=$6 boot_count=$7"; [[ -z "${8:-}" ]] || echo "$8"; } >"$1"; }
    vf "${t}/v1" 4 3 "${commit}" valid-resume 5 4
    judge_verify "${t}/v1" after_catalog all 3 4 && ok "verify judge: N at after_catalog" || bad "verify judge N: ${v_why}"
    judge_verify "${t}/v1" after_final_flush all 3 4 && bad "verify judge accepted N where N+1 is required" || ok "verify judge refuses N after the final flush (${v_why})"
    vf "${t}/v2" 5 4 "${commit}" prepared-advance 6 5
    judge_verify "${t}/v2" after_final_flush all 3 4 && ok "verify judge: N+1 prepared-advance after the final flush" || bad "verify judge NP1: ${v_why}"
    judge_verify "${t}/v2" after_first_flush all 3 4 && bad "verify judge accepted N+1 before the root write" || ok "verify judge refuses N+1 before the root (${v_why})"
    judge_verify "${t}/v2" after_inactive_superblock torn 3 4 && ok "verify judge: N+1 allowed for a torn root" || bad "verify judge torn: ${v_why}"
    judge_verify "${t}/v2" after_anchor all 3 4 && bad "verify judge accepted prepared-advance after the anchor" || ok "verify judge refuses an anchor behind after_anchor (${v_why})"
    vf "${t}/v3" 5 3 "${commit}" prepared-advance 6 4
    judge_verify "${t}/v3" after_final_flush all 3 4 && bad "verify judge accepted a wrong boot_count" || ok "verify judge refuses a wrong boot_count (${v_why})"
    vf "${t}/v4" 4 3 "${commit}" valid-resume 5 4 "store: blank disk (all-zero anchor + Store head): formatted TEST store"
    judge_verify "${t}/v4" after_catalog all 3 4 && bad "verify judge accepted a reformat" || ok "verify judge refuses a reformat (${v_why})"
    vf "${t}/v5" 1 0 none valid-resume 2 1
    judge_verify "${t}/v5" before_first_write all 0 1 && ok "verify judge: settle 0, prev_commit none" || bad "verify judge settle 0: ${v_why}"
    vf "${t}/v6" 4 3 "${commit}" valid-resume 6 4
    judge_verify "${t}/v6" after_catalog all 3 4 && bad "verify judge accepted a commit that skipped a generation" || ok "verify judge refuses a skipped commit generation (${v_why})"
    { echo "stage store: FAIL"; echo "store: REFUSED proof=commit step=\"ss_transact\" rc=-203 (x); disk left as found, not reformatted"; } >"${t}/v7"
    judge_verify "${t}/v7" after_catalog all 3 4 && bad "verify judge accepted a refused Store" || ok "verify judge refuses a refused Store (${v_why})"

    # injected-root judge
    judge_injected "${t}/v7" 4 && ok "injected judge: refusal accepted" || bad "injected judge: ${inj_why}"
    judge_injected "${t}/v2" 4 && bad "injected judge accepted the corrupt root" || ok "injected judge refuses an opened corrupt root (${inj_why})"

    # tear closure on synthetic images
    truncate -s 65536 "${t}/b"; cp "${t}/b" "${t}/a"
    printf 'SBMAGIC!' | dd of="${t}/a" bs=1 seek=$(( store_off + unit )) conv=notrunc status=none
    printf '\005\0\0\0\0\0\0\0' | dd of="${t}/a" bs=1 seek=$(( store_off + unit + sb_gen_off )) conv=notrunc status=none
    tear_closure "${t}/b" "${t}/a" 4 && [[ "${tc_slot}" == 1 ]] && ok "tear closure: one slot, sector 0, generation N+1" || bad "tear closure: ${tc_why}"
    tear_closure "${t}/b" "${t}/a" 3 && bad "tear closure accepted the wrong generation" || ok "tear closure refuses the wrong generation (${tc_why})"
    cp "${t}/a" "${t}/a2"; printf 'x' | dd of="${t}/a2" bs=1 seek=$(( store_off + unit + 600 )) conv=notrunc status=none
    tear_closure "${t}/b" "${t}/a2" 4 && bad "tear closure accepted a change past sector 0" || ok "tear closure refuses a change past sector 0 (${tc_why})"
    cp "${t}/a" "${t}/a3"; printf 'x' | dd of="${t}/a3" bs=1 seek=$(( store_off + 3 )) conv=notrunc status=none
    tear_closure "${t}/b" "${t}/a3" 4 && bad "tear closure accepted two changed slots" || ok "tear closure refuses two changed slots (${tc_why})"

    # Row tally (mirrors the Rust --verdict-self-test, scripts/qemu_store_crash_test.sh
    # lines 33-53): only a complete all-OK table passes.
    [[ "${gate_rows_want}" == 52 ]] && ok "gate campaign wants 52 rows (2 geometries x 2 settles x 13 cases)" \
        || bad "gate campaign row count ${gate_rows_want}, expected 52"
    want_rows() { # NAME WANT EXPECT(0 pass|1 fail) LINES...
        local name="$1" want="$2" expect="$3" got=0; shift 3
        : >"${t}/rows"; for l in "$@"; do printf '%s\n' "${l}" >>"${t}/rows"; done
        rows_all_ok "${t}/rows" "${want}" || got=1
        [[ "${got}" == "${expect}" ]] && ok "row tally: ${name} -> $([[ ${got} == 0 ]] && echo PASS || echo FAIL)" \
            || bad "row tally: ${name} gave the wrong verdict"
    }
    want_rows "empty campaign" 3 1
    want_rows "one row short" 3 1 "a -> OK" "b -> OK"
    want_rows "one BAD row" 3 1 "a -> OK" "b -> BAD (x)" "c -> OK"
    want_rows "one extra row" 3 1 "a -> OK" "b -> OK" "c -> OK" "d -> OK"
    want_rows "zero rows wanted is never a pass" 0 1
    want_rows "complete, all OK" 3 0 "a -> OK" "b -> OK" "c -> OK"
    rm -f "${t}/rows"; rows_all_ok "${t}/rows" 3 && bad "row tally: missing file read as PASS" || ok "row tally: missing results file -> FAIL"
    # The gate's own row format: a real OK and BAD line from run_case's printf.
    printf 'bs=%-4s settle=%s cp=%-26s policy=%-6s saw=%s N=%-2s opened=%-3s expect=%-5s -> %s%s\n' \
        512 0 after_catalog all 1 1 1 N OK "" 4096 3 after_anchor all 1 4 5 NP1 BAD " (verify: x)" >"${t}/rows"
    rows_all_ok "${t}/rows" 2 && bad "row tally: a BAD gate row passed" || ok "row tally: gate-format BAD row -> FAIL (${rows_why})"
    rows_all_ok "${t}/rows" 1 && bad "row tally: over-full gate rows passed" || ok "row tally: gate-format extra row -> FAIL"

    if command -v make >/dev/null; then
        make_refusals || st=1
    else
        bad "make not installed: refusal checks not run"
    fi
    [[ "${st}" == 0 ]] && echo "CK_STORE_CRASH_SELFTEST: PASS" || echo "CK_STORE_CRASH_SELFTEST: FAIL"
    return "${st}"
}

if [[ "${mode}" == selftest ]]; then
    self_test; exit $?
fi

# ------------------------------------------------------------------ QEMU run
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; verdict NOT_RUN; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; verdict NOT_RUN; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
out="${repo_root}/target/native-kernel"
mk_full() { make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" full "$@" >/dev/null; }
if [[ "${mode}" == mutant ]]; then
    mk_full CK_TEST_STORE_CRASH=1 CK_TEST_STORE_CRASH_MUTANT="${mutant}" || { echo "mutant build failed"; verdict NOT_RUN; exit 2; }
    crash_efi="${out}/full-test-store-crash-mutant-${mutant}/BOOTAA64.EFI"
    plain_efi="${crash_efi}"   # every boot of a mutant run uses the broken Store
else
    mk_full || { echo "build failed"; verdict NOT_RUN; exit 2; }
    mk_full CK_TEST_STORE_CRASH=1 || { echo "TEST crash build failed"; verdict NOT_RUN; exit 2; }
    crash_efi="${out}/full-test-store-crash/BOOTAA64.EFI"
    plain_efi="${out}/full/BOOTAA64.EFI"
fi
# GPT boot disk tool (native/kernel/tools/ck_gpt_image.c): the kernel binds
# NVMe only when it finds exactly one AIENOS partition (dev/disk_part.h).
if ! make -s -C native/kernel OUT="${out}" gpt-image >/dev/null; then
    echo "GPT image tool build failed"; verdict NOT_RUN; exit 2
fi

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_store_crash_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    verdict NOT_RUN
    exit 3
fi
own_flag=1
release_flag() {
    if [[ "${own_flag}" == 1 ]]; then
        own_flag=0
        if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
    fi
}
top="$(mktemp -d)"
qemu_pid=""
cleanup() { [[ -n "${qemu_pid}" ]] && kill -9 "${qemu_pid}" 2>/dev/null; rm -rf "${top}"; release_flag; }
trap cleanup EXIT

# shellcheck source=scripts/lib_ck_m1_checks.sh
source "${repo_root}/scripts/lib_ck_m1_checks.sh"
sha() { sha256sum "$1" | cut -d' ' -f1; }
fail=0; m1_fail=0

qemu_args() { # efi-dir image bs
    local nvme_dev="nvme,drive=nvme0,serial=aienos-store-crash"
    [[ "$3" == 512 ]] || nvme_dev="${nvme_dev},logical_block_size=$3,physical_block_size=$3"
    qargs=(-M "virt,virtualization=on,gic-version=3,iommu=smmuv3" -accel tcg,thread=single -cpu max -smp 4 -m 2048
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}"
        -drive if=pflash,format=raw,file="${work}/vars.fd"
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp"
        -device virtio-blk-pci,drive=esp
        -drive if=none,id=nvme0,format=raw,file="$2"
        -device "${nvme_dev}"
        -device ramfb -display none -nic none
        -serial file:"${work}/serial.log" -no-reboot)
}
prep() { # name efi
    work="${top}/$1"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$2" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
}
# boot_full NAME EFI IMAGE BS: a boot that runs to its end (setup/verify).
boot_full() {
    prep "$1" "$2"; qemu_args "$1" "$3" "$4"
    timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 "${qargs[@]}"
    qemu_status=$?
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_store_crash_$1.log"
    failed=0
    ck_m1_checks >"${work}/m1.txt"
    if [[ "${failed}" != 0 || "${qemu_status}" != 0 ]]; then
        echo "FAIL  boot $1: M1 checks or QEMU exit ${qemu_status}"; grep '^FAIL' "${work}/m1.txt" | sed 's/^/      /'
        m1_fail=1; return 1
    fi
    if [[ "${mode}" == gate ]] && grep -q "store_crash:" "${work}/serial.txt"; then
        echo "FAIL  boot $1: the default image printed crash hook lines"; m1_fail=1; return 1
    fi
    return 0
}
# boot_crash NAME EFI IMAGE BS: runs until the HALT line, then SIGKILL.
boot_crash() {
    prep "$1" "$2"; qemu_args "$1" "$3" "$4"
    : >"${work}/serial.log"
    qemu-system-aarch64 "${qargs[@]}" &
    qemu_pid=$!
    local deadline=$(( $(date +%s) + ${AIENOS_QEMU_TIMEOUT:-180} ))
    while (( $(date +%s) < deadline )); do
        grep -qE '^store_crash: (HALT at |plan REFUSED)' "${work}/serial.log" 2>/dev/null && break
        kill -0 "${qemu_pid}" 2>/dev/null || break
        sleep 0.1
    done
    kill -9 "${qemu_pid}" 2>/dev/null
    wait "${qemu_pid}" 2>/dev/null
    qemu_pid=""
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_store_crash_$1.log"
}

results="${top}/results.txt"; : >"${results}"
closure_ok=1; inject_ok=1; inject_ran=0; control_ok=1
declare -A geo_ok=([512]=1 [4096]=1)

# run_case BS SETTLE CP POLICY BASE_IMAGE: one crash + verify; leaves the
# crashed image in ${top}/crashed.img.
run_case() {
    local bs="$1" settle="$2" cp="$3" pol="$4" base="$5" name="${1}-s${2}-${3}-${4}" img saw=0 ok=0 why=""
    img="${top}/case.img"; cp "${base}" "${img}"
    write_plan "${img}" "${cp}" "${pol}"
    boot_crash "${name}-crash" "${crash_efi}" "${img}" "${bs}"
    if judge_crash "${work}/serial.txt" "${cp}" "${pol}" "${settle}"; then saw=1; else why="crash: ${crash_why}"; fi
    grep -q "^kernel: alive" "${work}/serial.txt" && grep -qF "aienos_commit: ${commit}" "${work}/serial.txt" \
        || { saw=0; why="crash boot is not this commit's kernel"; }
    clear_plan "${img}"
    cp "${img}" "${top}/crashed.img"
    local n="${crash_n:-0}"
    v_gen=""
    if boot_full "${name}-verify" "${plain_efi}" "${img}" "${bs}"; then
        if [[ "${saw}" == 1 ]]; then
            judge_verify "${work}/serial.txt" "${cp}" "${pol}" "${settle}" "${n}" && ok=1 || why="verify: ${v_why}"
        fi
    else
        why="${why:+${why}; }verify boot failed M1/exit"
    fi
    printf 'bs=%-4s settle=%s cp=%-26s policy=%-6s saw=%s N=%-2s opened=%-3s expect=%-5s -> %s%s\n' \
        "${bs}" "${settle}" "${cp}" "${pol}" "${saw}" "${n}" "${v_gen:-none}" "$(expect_for "${cp}" "${pol}")" \
        "$([[ "${ok}" == 1 ]] && echo OK || echo BAD)" "${why:+ (${why})}" | tee -a "${results}"
    case_saw="${saw}"; case_ok="${ok}"; case_n="${n}"
    [[ "${ok}" == 1 ]] || { fail=1; geo_ok[${bs}]=0; }
}

# new_disk BS: the fresh GPT template image for geometry BS (sentinel-a, AIENOS
# all zero, sentinel-b), and set_part from the range the tool WROTE.
new_disk() {
    local l re='^gpt_image bs=[0-9]+ blocks=[0-9]+ aienos_first_lba=([0-9]+) aienos_last_lba=([0-9]+)$'
    gpt_tmpl="${top}/gpt-$1.img"
    l=$("${out}/host/ck_gpt_image" create "${gpt_tmpl}" "$1" $(( img_bytes / 1048576 )) aienos-middle) || l=""
    if [[ "${l}" =~ ${re} ]]; then set_part "$1" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"; return 0; fi
    echo "FAIL  GPT boot disk image not created (bs $1: ${l})"; fail=1; geo_ok[$1]=0; return 1
}
# setup_image BS SETTLE -> path of an image after SETTLE default-image boots
setup_image() {
    local bs="$1" settle="$2" img="${top}/setup-${1}-${2}.img" k
    cp "${gpt_tmpl}" "${img}"
    for (( k = 1; k <= settle; k++ )); do
        if ! boot_full "${bs}-setup${settle}-${k}" "${plain_efi}" "${img}" "${bs}" \
            || ! grep -q "^store: committed generation=$(( k + 1 )) boot_count=${k}$" "${work}/serial.txt"; then
            echo "FAIL  setup boot ${k} (bs ${bs}) did not commit generation $(( k + 1 ))"; fail=1; geo_ok[${bs}]=0
        fi
    done
    echo "${img}"
}

# injected_case BS BASE_SETUP CRASHED N: tear closure + bad-CRC root.
injected_case() {
    local bs="$1" before="$2" crashed="$3" n="$4" img off s0 s1
    if tear_closure "${before}" "${crashed}" "${n}"; then
        echo "PASS  bs=${bs} root tear closure: only slot ${tc_slot} changed, inside its first 512 bytes, generation $(( n + 1 ))"
    else
        echo "FAIL  bs=${bs} root tear closure: ${tc_why}"; closure_ok=0
        return
    fi
    img="${top}/inject.img"; cp "${crashed}" "${img}"
    off=$(( sb_base + tc_slot * unit + sb_crc_off ))
    printf "\\$(printf '%03o' $(( $(od -An -tu1 -j "${off}" -N 1 "${img}") ^ 0x01 )))" \
        | dd of="${img}" bs=1 seek="${off}" conv=notrunc status=none
    cmp -s "${img}" "${crashed}" && { echo "FAIL  bs=${bs} CRC byte flip did not change the image"; inject_ok=0; return; }
    s0="$(sha "${img}")"
    inject_ran=1
    if boot_full "${bs}-inject-bad-crc" "${plain_efi}" "${img}" "${bs}"; then
        s1="$(sha "${img}")"
        if judge_injected "${work}/serial.txt" "${n}" && [[ "${s1}" == "${s0}" ]]; then
            echo "PASS  bs=${bs} root with a bad CRC (generation $(( n + 1 ))) not opened, nothing committed, image unchanged"
        else
            echo "FAIL  bs=${bs} bad-CRC root: ${inj_why:-image changed by the boot}"; inject_ok=0
            grep -E '^store: ' "${work}/serial.txt" | sed 's/^/      /'
        fi
    else
        echo "FAIL  bs=${bs} bad-CRC root boot failed M1/exit"; inject_ok=0
    fi
}

hw_ok=1
if [[ "${mode}" == gate ]]; then
    make_refusals || hw_ok=0
    grep -aqF "store_crash:" "${plain_efi}" && { echo "FAIL  default image carries crash hook strings"; hw_ok=0; } \
        || echo "PASS  default image carries no crash hook strings"
    grep -aqF "TEST-ONLY Store crash hook image" "${crash_efi}" && echo "PASS  TEST crash image announces itself" \
        || { echo "FAIL  TEST crash image lacks its announcement"; hw_ok=0; }
fi

mutant_hit=0; mutant_cases=0
for bs in "${gate_geos[@]}"; do
    echo "=== ${bs}-byte LBA ==="
    new_disk "${bs}" || continue
    for settle in "${gate_settles[@]}"; do
        if [[ "${mode}" == mutant && "${mutant}" == accept_bad_root_crc && "${settle}" == 0 ]]; then continue; fi
        base="$(setup_image "${bs}" "${settle}")"
        plan=()
        if [[ "${mode}" == gate ]]; then
            for cp in "${cps[@]}"; do plan+=("${cp} all"); done
            plan+=("${gate_extra[@]}")
        elif [[ "${mutant}" == skip_root_flush ]]; then
            plan=("after_inactive_superblock newest" "after_inactive_superblock torn")
        else
            plan=("after_inactive_superblock all")
        fi
        for p in "${plan[@]}"; do
            read -r cp pol <<<"${p}"
            run_case "${bs}" "${settle}" "${cp}" "${pol}" "${base}"
            if [[ "${mode}" == mutant ]]; then
                mutant_cases=$(( mutant_cases + 1 ))
                [[ "${mutant}" == skip_root_flush && "${case_saw}" == 1 && "${case_ok}" == 0 ]] && mutant_hit=1
                # accept_bad_root_crc: the uninjected crash case is the control; it must pass.
                [[ "${mutant}" == accept_bad_root_crc && "${case_ok}" != 1 ]] && control_ok=0
            fi
            if [[ "${settle}" == 3 && "${cp}" == after_inactive_superblock && "${pol}" == all \
                  && ( "${mode}" == gate || "${mutant}" == accept_bad_root_crc ) && "${case_saw}" == 1 ]]; then
                injected_case "${bs}" "${base}" "${top}/crashed.img" "${case_n}"
            fi
        done
    done
done
release_flag

echo "---- crash campaign results ----"
cat "${results}"
if [[ "${fail}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for s in "${top}"/*/serial.txt; do
        echo "---- serial $(basename "$(dirname "${s}")") (store lines) ----"
        grep -E '^(stage store|store:|store_crash:)' "${s}" | head -30 || true
    done
fi

if [[ "${mode}" == mutant ]]; then
    if [[ "${mutant}" == skip_root_flush ]]; then
        [[ "${mutant_hit}" == 1 ]] && { verdict "KILLED (a crash case after the root write recovered wrong on the Store without its pre-root flush)"; exit 0; }
        verdict "SURVIVED (${mutant_cases} cases, none failed)"; exit 1
    fi
    if [[ "${control_ok}" != 1 || "${inject_ran}" != 1 || "${closure_ok}" != 1 ]]; then
        verdict "SURVIVED (inconclusive: control crash case or tear closure failed, injection ran=${inject_ran})"; exit 1
    fi
    [[ "${inject_ok}" == 0 ]] && { verdict "KILLED (the bad-CRC root was opened)"; exit 0; }
    verdict "SURVIVED (bad-CRC root still refused)"; exit 1
fi

pf() { [[ "$1" == 1 && "${m1_fail}" == 0 ]] && echo PASS || echo FAIL; }
echo
echo "CK_STORE_CRASH_512B_QEMU: $(pf "${geo_ok[512]}")"
echo "CK_STORE_CRASH_4096_QEMU: $(pf "${geo_ok[4096]}")"
echo "CK_STORE_ROOT_TEAR_CLOSURE_QEMU: $(pf "${closure_ok}")"
echo "CK_STORE_INJECTED_ROOT_QEMU: $(pf "$(( inject_ok & inject_ran ))")"
echo "CK_STORE_CRASH_HOOK_REFUSED_ON_HARDWARE: $(pf "${hw_ok}")"
echo "CK_STORE_SLOT_REUSE: NOT_RUN (MISSING_IMPLEMENTATION: the C Store is append-only, no reclaim/slot reuse)"
[[ "${m1_fail}" != 0 ]] && echo "M1 checks or QEMU exit failed on at least one setup/verify boot: no verdict can pass"
# Complete campaign: exactly gate_rows_want rows, all OK (rows_all_ok, as in
# the Rust scripts); an empty, short or over-full table is FAIL.
rows_ok=0
if rows_all_ok "${results}" "${gate_rows_want}"; then
    rows_ok=1; echo "CK_STORE_CRASH_ROWS: PASS (${gate_rows_want} of ${gate_rows_want} rows OK)"
else
    echo "CK_STORE_CRASH_ROWS: FAIL (${rows_why})"
fi
if [[ "${rows_ok}" == 1 && "${fail}" == 0 && "${m1_fail}" == 0 && "${closure_ok}" == 1 && "${inject_ok}" == 1 && "${inject_ran}" == 1 \
      && "${hw_ok}" == 1 && "${geo_ok[512]}" == 1 && "${geo_ok[4096]}" == 1 ]]; then
    verdict PASS; exit 0
fi
verdict FAIL
exit 1
