#!/usr/bin/env bash
# test_recovery_unlock_chroot.sh: TRUST-1 Gate 1 items 11-12, host rehearsal.
#
# Proves the recovery image's OWN binaries can do the recovery unlock path:
# age decrypts a passfile spare, and gocryptfs mounts a gocryptfs store with
# it (read-only), exactly as the rescue shell would. Everything is a
# throwaway made here in a private temp folder: a test age identity, a test
# gocryptfs store, a test file. No owner key, no real store, no hardware,
# no USB stick. The real Spark stores and spares are never read.
#
# Runs the image's binaries inside a chroot of the extracted initrd, which
# needs root (sudo). Without passwordless sudo it SKIPs (exit 0). MANUAL
# ONLY: not part of verify_all, because it needs root.
#
# Usage: test_recovery_unlock_chroot.sh [INITRD_IMG]
# Exit 0 = PASS or SKIP, 1 = FAIL, 2 = missing tools.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for t in age age-keygen gocryptfs gzip cpio; do
    command -v "${t}" >/dev/null || { echo "Error: ${t} not installed" >&2; exit 2; }
done
if ! sudo -n true 2>/dev/null; then
    echo "SKIP  recovery unlock rehearsal needs passwordless sudo for chroot"
    exit 0
fi

work="$(mktemp -d)"
root="${work}/root"
cleanup() {
    # SAFETY: never delete across a mount. Unmount everything under the
    # temp folder (lazy detach as a fallback), then refuse to delete at all
    # if any mount is still there. rm also stays on one filesystem.
    local m
    for m in "${root}/mnt/plain" "${root}/proc" "${root}/dev"; do
        if findmnt "${m}" >/dev/null 2>&1; then
            sudo -n umount "${m}" 2>/dev/null || sudo -n umount -l "${m}" 2>/dev/null || true
        fi
    done
    if findmnt -rn -o TARGET | grep -qF "${work}"; then
        echo "WARNING: mounts remain under ${work}; NOT deleting it" >&2
        return
    fi
    sudo -n rm -rf --one-file-system "${work}"
}
trap cleanup EXIT

img="${1:-${work}/initrd.img}"
if [[ $# -lt 1 ]]; then
    bash "${repo_root}/scripts/build_standalone_recovery_initrd.sh" "${img}" >/dev/null
fi
[[ -f "${img}" ]] || { echo "FAIL  initrd not found: ${img}"; exit 1; }
mkdir -p "${root}"
gzip -dc "${img}" | (cd "${root}" && cpio -idm --quiet)

# Throwaway material, built with the HOST tools (stands in for the spares
# made on the Spark): a test identity, a test store, an age-wrapped passfile.
age-keygen -o "${work}/test-identity.txt" 2>/dev/null
recipient="$(age-keygen -y "${work}/test-identity.txt")"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"${work}/pass"
mkdir -p "${work}/cipher" "${work}/plain-host"
gocryptfs -q -init -passfile "${work}/pass" "${work}/cipher"
gocryptfs -q -passfile "${work}/pass" "${work}/cipher" "${work}/plain-host"
head -c 4096 /dev/urandom >"${work}/plain-host/known-file"
want="$(sha256sum "${work}/plain-host/known-file" | cut -d' ' -f1)"
fusermount3 -u "${work}/plain-host"
age -r "${recipient}" -o "${work}/pass.age" "${work}/pass"
rm -f "${work}/pass"

# Stage into the image root as the operator would bring them on the
# second medium: the store, the spare, and the identity.
mkdir -p "${root}/media/test"
cp -a "${work}/cipher" "${root}/mnt/cipher/store"
cp "${work}/pass.age" "${work}/test-identity.txt" "${root}/media/test/"

# A private, throwaway /dev for the chroot (never a bind of the host /dev):
# only the nodes the recipe needs.
sudo -n mount -t tmpfs -o mode=0755,size=1m aienos-test-dev "${root}/dev"
sudo -n mknod -m 0666 "${root}/dev/null" c 1 3
sudo -n mknod -m 0666 "${root}/dev/zero" c 1 5
sudo -n mknod -m 0666 "${root}/dev/urandom" c 1 9
sudo -n mknod -m 0666 "${root}/dev/random" c 1 8
sudo -n mknod -m 0666 "${root}/dev/fuse" c 10 229
sudo -n mount -t proc proc "${root}/proc"

fail() { echo "FAIL  $*"; exit 1; }

# The rescue-shell recipe, run only with the image's binaries. The passfile
# is decrypted into RAM (tmpfs in the real shell) and removed after mount.
sudo -n chroot "${root}" /bin/sh -c '
    set -e
    /bin/busybox --install -s /bin
    /bin/age -d -i /media/test/test-identity.txt -o /tmp/pass /media/test/pass.age
    /bin/gocryptfs -q -nosyslog -ro -passfile /tmp/pass /mnt/cipher/store /mnt/plain
    rm -f /tmp/pass
' || fail "image age + gocryptfs could not open the test store"

got="$(sudo -n chroot "${root}" /bin/sha256sum /mnt/plain/known-file | cut -d' ' -f1)"
[[ "${got}" == "${want}" ]] || fail "known file digest differs (${got} != ${want})"
echo "PASS  image age decrypted the spare passfile; image gocryptfs mounted the store read-only"
echo "PASS  known test file read back intact (sha256 ${want})"

if sudo -n chroot "${root}" /bin/sh -c 'echo x > /mnt/plain/write-probe' 2>/dev/null; then
    fail "store was writable; recovery mount must be read-only"
fi
echo "PASS  recovery mount refuses writes"

sudo -n umount "${root}/mnt/plain"
echo "TRUST-1 Gate 1 recovery unlock rehearsal (throwaway keys, chroot): ALL PASS"
