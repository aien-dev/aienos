#!/bin/sh
# PROBE, not a gate. Boots the Lane 18 stages three times on QEMU virt with
# one 64 MiB NVMe image (blank at boot 1) and prints the stage lines.
# QEMU is an emulator: this qualifies nothing physical. Takes the shared
# quiet flag for the run (waits while another session holds it).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="${PROBE_OUT:-/tmp/aienos-ck-probe-$(id -u)}"
quiet="${HOME}/workspace/.spark-quiet"
make -s -C "$here" PROBE_OUT="$out" >/dev/null
img="$out/nvme.img"
rm -f "$img"
dd if=/dev/zero of="$img" bs=1M count=64 status=none
until ( set -C; echo "lane18 stage qemu" > "$quiet" ) 2>/dev/null; do sleep 60; done
release() { if grep -q "lane18 stage" "$quiet" 2>/dev/null; then rm -f "$quiet"; fi; }
trap release EXIT INT TERM
for n in 1 2 3; do
    echo "=== probe boot $n ==="
    timeout --kill-after=5 120 qemu-system-aarch64 \
        -M virt,highmem=off -cpu max -m 512M -smp 1 -nographic -no-reboot \
        -kernel "$out/ck_probe.elf" \
        -drive "file=$img,if=none,id=nvm0,format=raw" \
        -device nvme,drive=nvm0,serial=aienos-lane18,logical_block_size=512,physical_block_size=512 \
        -netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on 2>&1 | tr -d '\r' || echo "probe boot $n: qemu exit $?"
done
release
