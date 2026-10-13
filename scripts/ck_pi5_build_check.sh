#!/usr/bin/env bash
# ck_pi5_build_check.sh -- AIENOS-PI5 step 1, build only.
#
# Builds the Raspberry Pi 5 kernel image (make -C native/kernel pi5) and checks:
#   1. the Pi image defines the board glue: watchdog, SD host, card log slot;
#   2. the default image (make -C native/kernel all) defines none of it, so the
#      Spark and QEMU builds carry no Pi code (the hooks are weak and absent).
# The Pi image cannot boot in QEMU (its SD host and PM watchdog addresses are
# Pi 5 only); it is run on the hub Pi with the one-shot tryboot runner.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
make -C "${root}/native/kernel" all >/dev/null
make -C "${root}/native/kernel" pi5 >/dev/null
def="${root}/target/native-kernel/aienos-ck.elf"
pi5="${root}/target/native-kernel-pi5/aienos-ck.elf"
syms="ck_pi5_start ck_pi5_stage ck_pi5_before_reset ck_pi5_wdt_arm ck_pi5_wdt_pet ck_boot_klog_find sdhci_init ck_klog_put ck_klog_hdr_match ck_pi5_marker_run"
fail=0
defined() { nm "$1" | awk -v s="$2" '$3==s && $2 ~ /^[TtDdBbRrW]$/ {f=1} END {exit !f}'; }
for s in ${syms}; do
    if defined "${pi5}" "${s}"; then echo "PASS pi5 image defines ${s}"; else echo "FAIL pi5 image lacks ${s}"; fail=1; fi
    if defined "${def}" "${s}"; then echo "FAIL default image defines ${s}"; fail=1; else echo "PASS default image has no ${s}"; fi
done
test -s "${root}/target/native-kernel-pi5/BOOTAA64.EFI" || { echo "FAIL no Pi BOOTAA64.EFI"; fail=1; }
if [[ ${fail} == 0 ]]; then echo "CK_PI5_BUILD: PASS"; else echo "CK_PI5_BUILD: FAIL"; exit 1; fi
