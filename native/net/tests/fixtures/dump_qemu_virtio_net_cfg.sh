#!/bin/sh
# Re-dump the 256-byte PCI config space of a real QEMU virtio-net-pci device,
# with no guest: QEMU's qtest protocol reads the ECAM window directly while the
# CPU stays paused (-S). Recorded with QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18),
# machine "virt", device at 00:01.0, highmem ECAM base 0x4010000000.
#   transitional: default on the virt root bus (device id 0x1000)
#   modern:       disable-legacy=on (device id 0x1041)
# Single instance, nice'd; refuses to start if another QEMU runs.
# Usage: sh dump_qemu_virtio_net_cfg.sh transitional|modern > out.cfg
set -eu
case "${1:-}" in
transitional) extra="" ;;
modern) extra=",disable-legacy=on" ;;
*) echo "usage: $0 transitional|modern" >&2; exit 2 ;;
esac
if pgrep -x 'qemu-system-.*' >/dev/null 2>&1 || pgrep -f '^qemu-system' >/dev/null 2>&1; then
    echo "another QEMU is running; wait for it" >&2; exit 3
fi
o=0
cmds=$(while [ $o -lt 256 ]; do printf 'readl 0x%x\n' $((0x4010008000 + o)); o=$((o + 4)); done)
printf '%s\n' "$cmds" |
timeout 30 nice -n 19 qemu-system-aarch64 -machine virt -accel tcg -S -qtest stdio \
    -display none -nodefaults -netdev user,id=n0 \
    -device "virtio-net-pci,addr=1,netdev=n0$extra" 2>/dev/null |
grep '^OK 0x' | while read -r _ h; do
    x=$((h))
    printf "$(printf '\\%03o\\%03o\\%03o\\%03o' $((x & 255)) $((x >> 8 & 255)) $((x >> 16 & 255)) $((x >> 24 & 255)))"
done
