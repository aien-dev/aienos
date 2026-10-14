#!/usr/bin/env bash
# pi5_receipts_manifest.sh -- PI5-8 Q6: canonical, deterministic manifest of Pi run evidence.
#
#   scripts/pi5_receipts_manifest.sh [-t verdicts.tsv] <run-folder>...      (folders like ~/workspace/pi5-runs/<tag>)
#   scripts/pi5_receipts_manifest.sh [-t verdicts.tsv] --all <runs-root>   (every tag in the table)
#
# Each run folder holds kernel.log and run.log (written by the Pi run harness). The manifest has, per run tag
# (sorted bytewise): the image EFI sha256 (run.log first line), aienos_commit (kernel.log), the sha256 of
# kernel.log, and the verdict lines picked by the checked-in table (scripts/pi5_receipts_verdicts.tsv).
# Output is plain ASCII, LF line endings, no timestamps, no absolute paths: same inputs, same bytes.
#
# SIGNING (not done here): the manifest bytes on stdout are the message. A signature is an Ed25519 detached
# signature over exactly those bytes (RFC 8032 pure Ed25519), checked with the in-tree verifier
# (native/sig/ed25519.c) by native/kernel/tools/ck_manifest_sig.c ("verify MANIFEST SIG PUBKEYHEX").
# No owner or release key exists yet; scripts/ck_pi5_manifest_check.sh proves sign+verify with the public
# RFC 8032 TEST 1 key only.
#
# Exit 0 and a manifest on stdout only when every run folder exists, every field was found and every table
# row matched at least one line. Otherwise nothing goes to stdout; problems go to stderr (exit 1 evidence
# missing, exit 2 usage or missing run folder).
set -euo pipefail
export LC_ALL=C
here="$(cd "$(dirname "$0")" && pwd)"
table="${here}/pi5_receipts_verdicts.tsv"
if [ "${1:-}" = "-t" ]; then table="${2:?table}"; shift 2; fi
[ -r "${table}" ] || { echo "no verdict table ${table}" >&2; exit 2; }
rows="$(grep -v '^#' "${table}" | grep -v '^$')"
dirs=()
if [ "${1:-}" = "--all" ]; then
    root="${2:?runs root}"
    while IFS= read -r t; do dirs+=("${root}/${t}"); done < <(cut -f1 <<<"${rows}" | sort -u)
else
    [ $# -ge 1 ] || { echo "usage: $0 [-t table] <run-folder>... | --all <runs-root>" >&2; exit 2; }
    dirs=("$@")
fi
# sorted unique tags, tag -> folder
declare -A folder
tags=""
for d in "${dirs[@]}"; do
    d="${d%/}"; t="${d##*/}"
    folder[$t]="$d"; tags="${tags}${t}"$'\n'
done
tags="$(printf '%s' "${tags}" | sort -u)"
missing=0
while IFS= read -r t; do
    d="${folder[$t]}"
    for f in kernel.log run.log; do
        [ -r "${d}/${f}" ] || { echo "MISSING ${d}/${f}" >&2; missing=1; }
    done
done <<<"${tags}"
[ "${missing}" = 0 ] || exit 2
bad=0
out="AIENOS-PI5-RECEIPTS-MANIFEST-V1"$'\n'
out+="verdict_table_sha256 $(grep -v '^#' "${table}" | grep -v '^$' | sha256sum | cut -d' ' -f1)"$'\n'
out+="runs $(grep -c . <<<"${tags}")"$'\n'
while IFS= read -r t; do
    d="${folder[$t]}"
    efi="$(head -n 1 "${d}/run.log" | grep -ao 'sha256=[0-9a-f]\{64\}' | head -n 1 | cut -d= -f2 || true)"
    commit="$(grep -a -m1 '^aienos_commit: [0-9a-f]\{40\}' "${d}/kernel.log" | cut -d' ' -f2 || true)"
    [ -n "${efi}" ] || { echo "no image sha256 in ${d}/run.log first line" >&2; bad=1; }
    [ -n "${commit}" ] || { echo "no aienos_commit in ${d}/kernel.log" >&2; bad=1; }
    out+="run ${t}"$'\n'
    out+="efi_sha256 ${efi:-NONE}"$'\n'
    out+="aienos_commit ${commit:-NONE}"$'\n'
    out+="kernel_log_sha256 $(sha256sum < "${d}/kernel.log" | cut -d' ' -f1)"$'\n'
    nrow=0
    while IFS=$'\t' read -r rt ms pat; do
        [ "${rt}" = "${t}" ] || continue
        nrow=$((nrow + 1))
        m="$(tr -d '\r' < "${d}/kernel.log" | grep -aE -e "${pat}" | tr -c '\11\12\40-\176' '?' || true)"
        if [ -z "${m}" ]; then n=0; h="NONE"; echo "no line matches [${ms}] /${pat}/ in ${t}" >&2; bad=1
        else n="$(grep -c '' <<<"${m}")"; h="$(printf '%s\n' "${m}" | sha256sum | cut -d' ' -f1)"; fi
        out+="verdict ${ms} | /${pat}/ | lines=${n} sha256=${h}"$'\n'
        [ "${n}" = 0 ] || out+="$(sed 's/^/  | /' <<<"${m}")"$'\n'
    done <<<"${rows}"
    [ "${nrow}" -gt 0 ] || { echo "run ${t} has no row in the verdict table" >&2; bad=1; }
done <<<"${tags}"
out+="end"$'\n'
[ "${bad}" = 0 ] || exit 1
printf '%s' "${out}"
