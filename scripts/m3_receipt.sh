#!/usr/bin/env bash
# m3_receipt.sh: produce one reproducible M3 evidence receipt for the commit
# that is checked out.
#
# It refuses to run on a dirty tree, records the commit and the toolchain,
# runs `AIENOS_STRICT=1 bash scripts/verify_all.sh` (so no step may be
# skipped) with every serial log captured, and writes
# evidence/m3_receipt_<YYYY-MM-DD>.md with the PASS lines grouped by proof,
# the sha256 and line count of every raw log, the limitations, and an operator
# sign-off line that stays "pending" until the operator writes "M3 accepted".
#
# Raw logs are kept outside the tree (printed at the end) and are never
# committed; the receipt carries only their hashes and line counts.
#
# Usage: bash scripts/m3_receipt.sh [--allow-missing]
#   --allow-missing  write the receipt and exit 0 even when some proofs have
#                    no PASS line yet (they are listed as MISSING).
# Environment:
#   AIENOS_RECEIPT_LOG_DIR  where raw logs go (default: a new mktemp dir).
#   AIENOS_QEMU_TIMEOUT     passed through to the QEMU scripts.
#
# Exit status: 0 all proofs present (or --allow-missing), 1 verification
# failed or the run changed tracked files, 2 usage or dirty tree, 3 proofs
# MISSING without --allow-missing.
set -euo pipefail

allow_missing=0
for arg in "$@"; do
    case "${arg}" in
        --allow-missing) allow_missing=1 ;;
        -h|--help) sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
    esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Resolve a caller-supplied log dir against the caller's directory, before cd.
requested_log_dir=""
if [[ -n "${AIENOS_RECEIPT_LOG_DIR:-}" ]]; then
    requested_log_dir="$(realpath -m -- "${AIENOS_RECEIPT_LOG_DIR}")"
    case "${requested_log_dir}/" in
        "$(realpath -m -- "${repo_root}")/"*)
            echo "m3_receipt: AIENOS_RECEIPT_LOG_DIR must be outside the tree: ${requested_log_dir}" >&2
            exit 2 ;;
    esac
fi
cd "${repo_root}"

# 1. The receipt must describe exactly one commit: refuse a dirty tree,
# including untracked files that a build could pick up.
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "m3_receipt: refusing to run on a dirty tree. Commit, stash or remove these first:" >&2
    git status --short --untracked-files=normal >&2
    exit 2
fi

head_sha="$(git rev-parse HEAD)"
head_subject="$(git log -1 --format=%s HEAD)"
branch="$(git rev-parse --abbrev-ref HEAD)"
origin_main_local="$(git rev-parse --verify -q refs/remotes/origin/main || echo unknown)"
origin_main_live="$(timeout 20 git ls-remote origin refs/heads/main 2>/dev/null | awk '{print $1}' || true)"
[[ -n "${origin_main_live}" ]] || origin_main_live="unreachable"
equals() { [[ "$1" == "${head_sha}" ]] && echo yes || echo no; }

date_utc="$(date -u +%F)"
started_utc="$(date -u +%FT%TZ)"
receipt="evidence/m3_receipt_${date_utc}.md"

log_dir="${requested_log_dir:-$(mktemp -d "${TMPDIR:-/tmp}/aienos-m3-receipt.XXXXXX")}"
mkdir -p "${log_dir}/serial" "${log_dir}/shim"
log_dir="$(cd "${log_dir}" && pwd)"
if [[ -n "$(ls -A "${log_dir}/serial")" ]]; then
    echo "m3_receipt: ${log_dir}/serial is not empty; use a fresh AIENOS_RECEIPT_LOG_DIR" >&2
    exit 2
fi
: >"${log_dir}/commands.log"

# 2. Record every cargo and qemu-system-aarch64 invocation with its exact
# arguments. A thin wrapper on PATH logs the argv, plus the build-time
# AIENOS_* variables the image embeds (option_env!), then execs the real tool.
make_shim() { # tool name
    local real
    real="$(command -v "$1" || true)"
    [[ -n "${real}" ]] || return 0
    cat >"${log_dir}/shim/$1" <<EOF
#!/usr/bin/env bash
{
    env | grep -E '^AIENOS_(COMMIT|RESTART_SECS|KEYBOARD_SECS)=' | sort | tr '\\n' ' '
    printf '%q ' "$1" "\$@"
    echo
} >>"${log_dir}/commands.log"
exec "${real}" "\$@"
EOF
    chmod +x "${log_dir}/shim/$1"
}
make_shim cargo
make_shim qemu-system-aarch64

first_line() { "$@" 2>/dev/null | head -n 1 || true; }
sha_of() { [[ -r "$1" ]] && sha256sum "$1" | awk '{print $1}' || echo "not readable"; }
os_name="$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}") || echo unknown)"
rustc_v="$(first_line rustc -V)"
cargo_v="$(first_line cargo -V)"
qemu_v="$(first_line qemu-system-aarch64 --version)"
swtpm_v="$(first_line swtpm --version)"
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"

harness_cmd="AIENOS_STRICT=1 AIENOS_LOG_DIR=${log_dir}/serial bash scripts/verify_all.sh"
[[ -z "${AIENOS_QEMU_TIMEOUT:-}" ]] || harness_cmd="AIENOS_QEMU_TIMEOUT=${AIENOS_QEMU_TIMEOUT} ${harness_cmd}"

# 3. Run the strict harness.
echo "m3_receipt: commit ${head_sha}"
echo "m3_receipt: raw logs in ${log_dir}"
echo "m3_receipt: running ${harness_cmd}"
set +e
PATH="${log_dir}/shim:${PATH}" AIENOS_STRICT=1 AIENOS_LOG_DIR="${log_dir}/serial" \
    bash scripts/verify_all.sh 2>&1 | tee "${log_dir}/verify_all.log"
verify_status=${PIPESTATUS[0]}
set -e
finished_utc="$(date -u +%FT%TZ)"

tree_after="clean"
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    tree_after="DIRTY (the run changed the tree)"
fi

# 4. Collect PASS lines with the verify_all.sh section they came from.
pass_tsv="${log_dir}/pass_lines.tsv"
awk '
    { sub(/\r$/, "") }
    /^--- \[.*\] ---$/ { sec = $0; sub(/^--- \[/, "", sec); sub(/\] ---$/, "", sec); next }
    /^PASS[[:space:]]|: PASS|ALL TESTS PASS/ { print sec "\t" $0 }
' "${log_dir}/verify_all.log" >"${pass_tsv}"

results="${log_dir}/results.md"
claimed="${log_dir}/claimed.tsv"
: >"${results}"
: >"${claimed}"
missing=()
# proof name, section regex, PASS line regex (both matched lower-cased).
proof() {
    local name="$1" sec_re="$2" line_re="$3" hits
    hits="$(awk -F '\t' -v s="${sec_re}" -v l="${line_re}" \
        'tolower($1) ~ s && tolower($2) ~ l' "${pass_tsv}")"
    {
        echo "### ${name}"
        echo ""
        if [[ -z "${hits}" ]]; then
            echo "    MISSING"
        else
            printf '%s\n' "${hits}" | awk -F '\t' '{ printf "    [%s] %s\n", $1, $2 }'
        fi
        echo ""
    } >>"${results}"
    if [[ -z "${hits}" ]]; then
        missing+=("${name}")
    else
        printf '%s\n' "${hits}" >>"${claimed}"
    fi
}
boot_sec="^qemu aarch64 uefi boot"
smmu_sec="smmu"
proof "Formatting" "^formatting" "formatting"
proof "Host tests" "^host component" "host tests"
proof "Clippy" "^clippy" "clippy"
proof "AArch64 build" "bare-metal|aarch64 uefi image" "aarch64 build"
proof "QEMU boot" "${boot_sec}" "pre-exit report|image is this commit|entered the kernel|kernel entered el1h|final report|qemu_boot: pass"
proof "MMU" "${boot_sec}" "page table"
proof "GIC/timer" "${boot_sec}" "gic|timer irq"
proof "Preemption" "${boot_sec}" "preempt|placement"
proof "EL0 isolation" "." "el0"
proof "Capability" "${boot_sec}" "capabilit"
proof "IPC" "." "(^|[^a-z])ipc([^a-z]|$)"
proof "SMMU positive DMA" "${smmu_sec}" "iort stream|dma window translated|typed text echoed"
proof "SMMU negative DMA" "${smmu_sec}" "negative|(dma|stream).*(block|denied|deny|fault|reject|abort)|(block|denied|deny|fault|reject|abort).*dma"
proof "Device revocation" "." "revok|revoc"
proof "Recovery/security regressions" "^trust-1 gate 4|^trust-1 gate 1|^recovery media tooling" "."
proof "ABI conformance" "." "(^|[^a-z])abi([^a-z]|$)"

other="$(grep -vxF -f "${claimed}" "${pass_tsv}" || true)"

# 5. Hash every raw log.
hashes="${log_dir}/hashes.txt"
: >"${hashes}"
for f in "${log_dir}/verify_all.log" "${log_dir}/commands.log" "${log_dir}"/serial/*.log; do
    [[ -f "${f}" ]] || continue
    printf '%s  %s  (%s lines)\n' "$(sha256sum "${f}" | awk '{print $1}')" \
        "${f#"${log_dir}/"}" "$(wc -l <"${f}" | tr -d ' ')" >>"${hashes}"
done
serial_count="$(find "${log_dir}/serial" -name '*.log' | wc -l | tr -d ' ')"

# Debug-only build features seen in the recorded commands.
debug_features="$(grep -oE -- '--features [^ ]+' "${log_dir}/commands.log" | tr ',' '\n' \
    | grep -oE 'debug[a-z0-9_-]*' | sort -u | tr '\n' ' ' || true)"

if [[ "${verify_status}" != 0 || "${tree_after}" != "clean" ]]; then
    overall="FAIL (verify_all.sh exit ${verify_status}, tree after run: ${tree_after})"
    exit_code=1
elif [[ "${#missing[@]}" -gt 0 ]]; then
    if [[ "${allow_missing}" == 1 ]]; then
        overall="INCOMPLETE: ${#missing[@]} proof(s) MISSING, accepted only because --allow-missing was given"
        exit_code=0
    else
        overall="INCOMPLETE: ${#missing[@]} proof(s) MISSING"
        exit_code=3
    fi
else
    overall="PASS: every listed proof has at least one PASS line"
    exit_code=0
fi

# 6. Write the receipt.
{
    echo "# M3 receipt ${date_utc}"
    echo ""
    echo "Generated by scripts/m3_receipt.sh$([[ "${allow_missing}" == 1 ]] && echo " --allow-missing")."
    echo "Overall: ${overall}"
    echo ""
    echo "## Commit"
    echo ""
    echo "- HEAD: ${head_sha}"
    echo "- Subject: ${head_subject}"
    echo "- Branch: ${branch}"
    echo "- Tree before run: clean (checked with git status --porcelain)"
    echo "- Tree after run: ${tree_after}"
    echo "- origin/main (local tracking ref): ${origin_main_local} (HEAD equal: $(equals "${origin_main_local}"))"
    echo "- origin/main (live, git ls-remote): ${origin_main_live} (HEAD equal: $(equals "${origin_main_live}"))"
    echo "- Run: ${started_utc} to ${finished_utc}"
    echo ""
    echo "## Environment"
    echo ""
    echo "- Host: $(uname -n)"
    echo "- Arch: $(uname -m)"
    echo "- OS: ${os_name}, kernel $(uname -r)"
    echo "- rustc: ${rustc_v:-not found}"
    echo "- cargo: ${cargo_v:-not found}"
    echo "- QEMU: ${qemu_v:-not found}"
    echo "- swtpm: ${swtpm_v:-not found}"
    echo "- AAVMF code: ${code_fd} sha256 $(sha_of "${code_fd}")"
    echo "- AAVMF vars: ${vars_fd} sha256 $(sha_of "${vars_fd}")"
    echo ""
    echo "## Commands"
    echo ""
    echo "Harness (exit ${verify_status}):"
    echo ""
    echo "    ${harness_cmd}"
    echo ""
    echo "Every cargo invocation, in first-use order, with the build-time AIENOS_*"
    echo "variables that were set (recorded by a PATH wrapper, not reconstructed):"
    echo ""
    grep -E "(^| )cargo " "${log_dir}/commands.log" | sed 's/ *$//' | awk '!seen[$0]++' | sed 's/^/    /' || true
    echo ""
    echo "Every qemu-system-aarch64 invocation (temporary paths differ per run):"
    echo ""
    grep -E "(^| )qemu-system-aarch64 " "${log_dir}/commands.log" | sed 's/ *$//' | sed 's/^/    /' || true
    echo ""
    echo "## Results"
    echo ""
    echo "PASS lines from the harness output, grouped by proof. Each line shows the"
    echo "verify_all.sh section it came from. One line may support more than one proof."
    echo ""
    cat "${results}"
    echo "### Other PASS lines"
    echo ""
    if [[ -n "${other}" ]]; then
        printf '%s\n' "${other}" | awk -F '\t' '{ printf "    [%s] %s\n", $1, $2 }'
    else
        echo "    none"
    fi
    echo ""
    echo "## Log hashes"
    echo ""
    echo "Raw logs are not committed. They were kept on the run host in ${log_dir}"
    echo "(${serial_count} serial logs)."
    echo ""
    sed 's/^/    /' "${hashes}"
    echo ""
    echo "## Limitations"
    echo ""
    echo "- QEMU only (virt machine, TCG). Nothing here is proven on Machine 1 (GB10) hardware."
    echo "- One SMMUv3 instance (QEMU virt iommu=smmuv3) guarding one device stream (xHCI)."
    echo "  Machine 1 has several SMMUs; none of them is exercised here."
    if [[ -n "${debug_features}" ]]; then
        echo "- Debug-only build features used by some test images: ${debug_features% }."
        echo "  The QEMU keyboard test (no SMMU) enables identity xHCI DMA through a debug bypass;"
        echo "  the confined path is the separate SMMU run."
    else
        echo "- No debug-only build features were used."
    fi
    echo "- The recovery boots run the host's Linux kernel from /boot with the AIENOS recovery"
    echo "  initrd; they are not AIENOS kernel boots."
    if [[ "${#missing[@]}" -gt 0 ]]; then
        echo "- Not yet implemented or not yet reported by any test (MISSING above):"
        for m in "${missing[@]}"; do echo "  - ${m}"; done
    fi
    if [[ "$(equals "${origin_main_live}")" != yes ]]; then
        echo "- HEAD is not the live origin/main tip, so this receipt is not for main."
    fi
    echo ""
    echo "## Operator sign-off"
    echo ""
    echo "Operator sign-off: pending"
} >"${receipt}"

echo ""
echo "m3_receipt: wrote ${receipt}"
echo "m3_receipt: ${overall}"
if [[ "${#missing[@]}" -gt 0 ]]; then
    echo "m3_receipt: MISSING proofs: ${missing[*]}"
fi
exit "${exit_code}"
