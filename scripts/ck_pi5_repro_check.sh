#!/usr/bin/env bash
# ck_pi5_repro_check.sh -- PI5-8 Q1, reproducible builds of every Raspberry Pi 5 image.
#
#   scripts/ck_pi5_repro_check.sh [commit]        (default: HEAD of this checkout)
#
# Makes two clean detached worktrees of the SAME commit at two DIFFERENT paths (so build-directory
# paths that leak into an image show up as a difference), builds every Pi image in each with the same
# toolchain, and compares the sha256 of each BOOTAA64.EFI and aienos-ck.elf byte for byte. Prints a
# table and PASS/FAIL (exit 0 only when every BOOTAA64.EFI and every stripped ELF matches; a raw ELF may differ only in Rust symbol-name hash suffixes, see below). Records the toolchain versions used.
# Env: REPRO_KEEP=1 keeps the worktrees; REPRO_TMP=<dir> sets where they go (default: mktemp -d).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
commit="$(git -C "${root}" rev-parse "${1:-HEAD}")"
tmp="${REPRO_TMP:-$(mktemp -d "${TMPDIR:-/tmp}/aienos-repro.XXXXXX")}"
mkdir -p "${tmp}"
cleanup() {
    if [ "${REPRO_KEEP:-}" != 1 ]; then
        for d in a/aienos-repro b/aienos-repro; do
            git -C "${root}" worktree remove --force "${tmp}/${d}" 2>/dev/null || true
        done
        rm -rf "${tmp}"
    fi
}
trap cleanup EXIT
# target name -> output directory (relative to the worktree) that holds BOOTAA64.EFI and aienos-ck.elf
images="pi5:target/native-kernel-pi5
pi5-store:target/native-kernel-pi5-store/full-pi5-store
pi5-unlock:target/native-kernel-pi5-unlock/full-pi5-unlock
pi5-unlock-card:target/native-kernel-pi5-unlock-card/full-pi5-unlock-card
pi5-fact:target/native-kernel-pi5-unlock-card-fact/full-pi5-unlock-card-fact
pi5-infer:target/native-kernel-pi5-infer
pi5-agent:target/native-kernel-pi5-unlock-card-agent/full-pi5-unlock-card-agent
pi5-lifecycle:target/native-kernel-pi5-unlock-card-lifecycle/full-pi5-unlock-card-lifecycle
pi5-artifact:target/native-kernel-pi5-artifact
pi5-pcie:target/native-kernel-pi5-pcie
pi5-net:target/native-kernel-pi5-net"

echo "commit: ${commit}"
echo "toolchain:"
for c in "make --version" "cc --version" "ld --version" "objcopy --version" "rustc -Vv" "cargo -V"; do
    out="$(${c} 2>&1)"; printf "  %s: %s\n" "${c%% *}" "${out%%$'\n'*}"
done
git -C "${root}" worktree prune
for d in a b; do
    mkdir -p "${tmp}/${d}"
    git -C "${root}" worktree add -q --detach "${tmp}/${d}/aienos-repro" "${commit}"
done
for d in a b; do
    echo "== build set ${d} (${tmp}/${d}/aienos-repro)"
    while IFS=: read -r tgt _; do
        make -C "${tmp}/${d}/aienos-repro/native/kernel" "${tgt}" >"${tmp}/${d}.${tgt}.log" 2>&1 \
            || { echo "FAIL build ${tgt} in set ${d}; see ${tmp}/${d}.${tgt}.log"; REPRO_KEEP=1; tail -20 "${tmp}/${d}.${tgt}.log"; exit 2; }
    done <<<"${images}"
done
fail=0
printf '%-16s %-10s %-64s %s\n' IMAGE FILE SHA256 RESULT
while IFS=: read -r tgt dir; do
    for f in BOOTAA64.EFI aienos-ck.elf; do
        pa="${tmp}/a/aienos-repro/${dir}/${f}"; pb="${tmp}/b/aienos-repro/${dir}/${f}"
        if [ ! -s "${pa}" ] || [ ! -s "${pb}" ]; then printf '%-16s %-10s %-64s %s\n' "${tgt}" "${f}" "-" "MISSING"; fail=1; continue; fi
        ha="$(sha256sum "${pa}" | cut -d' ' -f1)"; hb="$(sha256sum "${pb}" | cut -d' ' -f1)"
        if [ "${ha}" = "${hb}" ]; then printf '%-16s %-10s %-64s %s\n' "${tgt}" "${f}" "${ha}" "match"
        elif [ "${f}" = aienos-ck.elf ] && strip -s -o "${tmp}/sa.elf" "${pa}" && strip -s -o "${tmp}/sb.elf" "${pb}" && cmp -s "${tmp}/sa.elf" "${tmp}/sb.elf"; then
            # Rust crate-hash suffixes in symbol NAMES (cargo hashes the absolute path of a path dependency outside the crate's
            # own workspace). Symbols are not in BOOTAA64.EFI; the stripped ELF (all code and data) is byte-identical.
            printf '%-16s %-10s %-64s %s\n' "${tgt}" "${f}" "${ha}/${hb}" "match-stripped (symbol-name hash suffix only)"
        else printf '%-16s %-10s %-64s %s\n' "${tgt}" "${f}" "${ha}/${hb}" "DIFFER"; fail=1; fi
    done
done <<<"${images}"
if [ "${fail}" = 0 ]; then echo "PASS ck_pi5_repro_check: every Pi image built twice from ${commit} is byte-identical (EFI exact; Rust-linked ELFs exact once stripped)"; else echo "FAIL ck_pi5_repro_check"; exit 1; fi
