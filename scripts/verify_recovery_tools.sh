#!/usr/bin/env bash
# verify_recovery_tools.sh: Verify that the standalone recovery initrd ships
# the tooling issue #17 requires: mount the NVMe root, repair /boot/efi, and
# restore boot entries. Host-side, static check only: extracts the built
# initrd and greps for files and init hooks. No real devices, no root, no
# QEMU boot (qemu_verify_recovery_media.sh already covers the boot itself).
# Verdict: PASS only when every check ran and passed; FAIL on any failed check
# (exit 1); NOT_RUN (exit 3) when a check class was skipped (readelf missing, or
# the test-only no-gocryptfs allowance in use). A skip is never a PASS.
# bash scripts/verify_recovery_tools.sh --self-test   negative controls, no build.
# Zero Disk Secrets and Unslop compliant.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# --self-test: negative controls on a synthetic image. No build, no QEMU, no
# root. Proves the verdict follows the checks: a missing tool is FAIL, a
# skipped check class (no gocryptfs allowed, no readelf) is NOT_RUN (exit 3),
# and only a complete, unskipped image is PASS.
if [[ "${1:-}" == --self-test ]]; then
    self="${REPO_ROOT}/scripts/verify_recovery_tools.sh"
    command -v readelf >/dev/null || { echo "NOT_RUN  self-test needs readelf on this host"; echo "RECOVERY_TOOLS_SELF_TEST: NOT_RUN"; exit 3; }
    t="$(mktemp -d)"; trap 'rm -rf "${t}"' EXIT
    st=0
    mk_root() { # dir: a complete synthetic recovery root
        local d="$1" f
        mkdir -p "${d}/bin" "${d}/etc" "${d}/usr/local/sbin" "${d}/lib/aarch64-linux-gnu"
        for f in busybox mount lsblk blkid cryptsetup fsck.vfat mkfs.vfat fsck.ext4 efibootmgr chroot findmnt \
                 tpm2_pcrread sbverify age gocryptfs fusermount3; do
            : >"${d}/bin/${f}"; chmod +x "${d}/bin/${f}"
        done
        : >"${d}/usr/local/sbin/collect_recovery_boot_evidence"
        : >"${d}/lib/aarch64-linux-gnu/libtss2-tcti-device.so.0"
        printf 'nvme.ko\ndm-crypt.ko\n' >"${d}/etc/aienos-modules.order"
        printf '#!/bin/sh\n# aienos.test=1\n# efibootmgr\nexec /bin/sh\n' >"${d}/init"; chmod +x "${d}/init"
    }
    mk_img() { (cd "$1" && find . | cpio -o -H newc --quiet 2>/dev/null) | gzip -c >"$2"; }
    # expect NAME RC MARKER IMAGE [PATH_OVERRIDE] [ALLOW_NO_GOCRYPTFS]
    expect() {
        local name="$1" want_rc="$2" want="$3" img="$4" path="${5:-${PATH}}" allow="${6:-0}" rc=0 out
        out="$(PATH="${path}" AIENOS_RECOVERY_ALLOW_NO_GOCRYPTFS="${allow}" /bin/bash "${self}" "${img}" 2>&1)" || rc=$?
        if [[ "${rc}" == "${want_rc}" ]] && grep -q "^RECOVERY_TOOLS: ${want}" <<<"${out}"; then
            echo "PASS  ${name} -> ${want} (exit ${rc})"
        else
            echo "FAIL  ${name}: want ${want} exit ${want_rc}, got exit ${rc}: $(grep '^RECOVERY_TOOLS:' <<<"${out}" || echo 'no verdict line')"; st=1
        fi
    }
    mk_root "${t}/full"; mk_img "${t}/full" "${t}/full.img"
    expect "complete image" 0 PASS "${t}/full.img"
    mk_root "${t}/noage"; rm "${t}/noage/bin/age"; mk_img "${t}/noage" "${t}/noage.img"
    expect "mutant: age deleted from the image" 1 FAIL "${t}/noage.img"
    mk_root "${t}/nogo"; rm "${t}/nogo/bin/gocryptfs"; mk_img "${t}/nogo" "${t}/nogo.img"
    expect "mutant: gocryptfs missing, not allowed" 1 FAIL "${t}/nogo.img"
    expect "gocryptfs missing, test-only allowance -> check skipped" 3 NOT_RUN "${t}/nogo.img" "${PATH}" 1
    # A PATH with the tools the script needs but no readelf: the closure check cannot run.
    mkdir -p "${t}/nopath"
    for c in gzip cpio sed grep mktemp rm mkdir readlink head cat dirname basename sort wc tr; do
        ln -s "$(command -v "${c}")" "${t}/nopath/${c}"
    done
    expect "readelf absent -> library closure checks skipped" 3 NOT_RUN "${t}/full.img" "${t}/nopath"
    if [[ ${st} == 0 ]]; then echo "RECOVERY_TOOLS_SELF_TEST: PASS"; exit 0; fi
    echo "RECOVERY_TOOLS_SELF_TEST: FAIL"; exit 1
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

# With an argument: inspect exactly that image, and fail if it is missing
# (never substitute a freshly built one). Without: build a private copy in
# WORK_DIR, so parallel runs never share a fixed /tmp path and no stale
# user-owned file is left where a root build would later collide with it.
if [[ $# -ge 1 ]]; then
    INITRD_IMG="$1"
    if [[ ! -f "${INITRD_IMG}" ]]; then
        echo "FAIL  initrd image not found: ${INITRD_IMG}" >&2
        exit 1
    fi
else
    INITRD_IMG="${WORK_DIR}/aienos-recovery-standalone-initrd.img"
# Repo checks run on hosts without gocryptfs (CI, laptops). Only there, and
# visibly, allow a test image without it. The real stick build
# (build_recovery_media.sh) never sets this.
if ! command -v gocryptfs >/dev/null 2>&1 && [[ ! -f /home/atlas/atlas-forgejo-setup-20260904/runtime/usr/bin/gocryptfs && -z "${AIENOS_GOCRYPTFS:-}" ]]; then
    echo "SKIP  gocryptfs not on this host; building a TEST-ONLY image without it"
    export AIENOS_RECOVERY_ALLOW_NO_GOCRYPTFS=1
fi

    echo "Building standalone recovery initrd..."
    bash "${REPO_ROOT}/scripts/build_standalone_recovery_initrd.sh" "${INITRD_IMG}"
fi

ROOT_DIR="${WORK_DIR}/root"
mkdir -p "${ROOT_DIR}"

echo "Extracting ${INITRD_IMG}..."
gzip -dc "${INITRD_IMG}" | (cd "${ROOT_DIR}" && cpio -idm --quiet)

FAILED=0
SKIPS=()
check() {
    if [[ "$2" == 1 ]]; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        FAILED=1
    fi
}

have_file() { [[ -f "${ROOT_DIR}/$1" || -x "${ROOT_DIR}/$1" || -L "${ROOT_DIR}/$1" ]] && echo 1 || echo 0; }
init_has() { grep -q -- "$1" "${ROOT_DIR}/init" 2>/dev/null && echo 1 || echo 0; }
module_packaged() { grep -qxF "$1.ko" "${ROOT_DIR}/etc/aienos-modules.order" 2>/dev/null && echo 1 || echo 0; }

echo ""
echo "-- required tools for NVMe root mount --"
check "busybox present" "$(have_file bin/busybox)"
check "mount present" "$(have_file bin/mount)"
check "lsblk present" "$(have_file bin/lsblk)"
check "blkid present" "$(have_file bin/blkid)"
check "cryptsetup present" "$(have_file bin/cryptsetup)"
check "nvme kernel module packaged" "$(module_packaged nvme)"
check "dm-crypt kernel module packaged" "$(module_packaged dm-crypt)"

echo ""
echo "-- required tools for /boot/efi repair --"
check "fsck.vfat present" "$(have_file bin/fsck.vfat)"
check "mkfs.vfat present" "$(have_file bin/mkfs.vfat)"
check "fsck.ext4 present" "$(have_file bin/fsck.ext4)"
check "efibootmgr present" "$(have_file bin/efibootmgr)"

echo ""
echo "-- required tools for boot-entry restore --"
check "efibootmgr present (boot entries)" "$(have_file bin/efibootmgr)"
check "chroot present" "$(have_file bin/chroot)"
check "findmnt present for attended evidence collector" "$(have_file bin/findmnt)"
check "attended evidence collector packaged on media" "$(have_file usr/local/sbin/collect_recovery_boot_evidence)"

echo ""
echo "-- TRUST-1 Gate 1 items 8, 10, 11-12: TPM, signatures, recovery unlock --"
# FLAG(sovereignty): tpm2_pcrread expected in the recovery image (outside dep); replace with in-house C PCR reader.
check "tpm2_pcrread present" "$(have_file bin/tpm2_pcrread)"
check "tpm2 device transport library packaged (dlopen, not seen by ldd)" \
    "$(compgen -G "${ROOT_DIR}/lib/*-linux-gnu/libtss2-tcti-device.so.0*" >/dev/null && echo 1 || echo 0)"
check "sbverify present" "$(have_file bin/sbverify)"
check "age present" "$(have_file bin/age)"
if [[ "${AIENOS_RECOVERY_ALLOW_NO_GOCRYPTFS:-0}" == 1 ]]; then
    echo "SKIP  gocryptfs present (TEST-ONLY image built on a host without gocryptfs)"; SKIPS+=("gocryptfs present (TEST-ONLY image without gocryptfs)")
else
    check "gocryptfs present" "$(have_file bin/gocryptfs)"
fi
check "fusermount3 present" "$(have_file bin/fusermount3)"

# Every shared library each recovery tool needs (and what those need in
# turn) must be inside the image itself, or the tool fails only later, in the
# rescue shell. Static check with readelf: no root, no execution.
lib_in_image() {
    local d
    for d in lib lib64 usr/lib lib/aarch64-linux-gnu usr/lib/aarch64-linux-gnu lib/x86_64-linux-gnu usr/lib/x86_64-linux-gnu; do
        [[ -e "${ROOT_DIR}/${d}/$1" ]] && { echo "${ROOT_DIR}/${d}/$1"; return 0; }
    done
    return 1
}
closure_ok() { # binary path inside image
    local queue=("$1") seen=" " f lib p
    while [[ ${#queue[@]} -gt 0 ]]; do
        f="${queue[0]}"; queue=("${queue[@]:1}")
        while read -r lib; do
            [[ "${seen}" == *" ${lib} "* ]] && continue
            seen+="${lib} "
            p="$(lib_in_image "${lib}")" || { echo "missing ${lib} (needed by ${f##*/})" >&2; echo 0; return; }
            queue+=("$(readlink -f "${p}")")
        done < <(readelf -d "${f}" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
    done
    echo 1
}
if command -v readelf >/dev/null; then
    # FLAG(sovereignty): tpm2_pcrread expected in the recovery image; follows the in-house C replacement.
    for t in gocryptfs age sbverify tpm2_pcrread cryptsetup fusermount3 efibootmgr; do
        [[ -e "${ROOT_DIR}/bin/${t}" ]] || continue
        check "${t}: every shared library it needs is inside the image" "$(closure_ok "${ROOT_DIR}/bin/${t}")"
    done
    tcti="$(compgen -G "${ROOT_DIR}/lib/*-linux-gnu/libtss2-tcti-device.so.0" | head -n 1 || true)"
    [[ -z "${tcti}" ]] || check "tpm2 device transport: its libraries are inside the image" "$(closure_ok "$(readlink -f "${tcti}")")"
else
    echo "SKIP  library closure checks (readelf not installed)"; SKIPS+=("library closure checks (readelf not installed)")
fi

echo ""
echo "-- init hooks --"
check "init is executable" "$([[ -x "${ROOT_DIR}/init" ]] && echo 1 || echo 0)"
check "init keeps zero-disk test mode (aienos.test=1)" "$(init_has 'aienos.test=1')"
check "init reports EFI boot entries (efibootmgr)" "$(init_has 'efibootmgr')"
check "init drops into an interactive maintenance shell" "$(init_has 'exec /bin/sh')"

echo ""
if [[ "${FAILED}" != 0 ]]; then
    echo "RECOVERY_TOOLS: FAIL"
    exit 1
fi
# A skipped check is not a passed check: say NOT_RUN and exit 3, never PASS.
if [[ ${#SKIPS[@]} -gt 0 ]]; then
    printf 'NOT_RUN  skipped check: %s\n' "${SKIPS[@]}"
    echo "RECOVERY_TOOLS: NOT_RUN (${#SKIPS[@]} check(s) skipped; every other check passed)"
    exit 3
fi
echo "RECOVERY_TOOLS: PASS (initrd ships mount, EFI repair, and boot-entry restore capability)"
