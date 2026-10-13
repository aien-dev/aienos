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
syms="ck_pi5_start ck_pi5_stage ck_pi5_before_reset ck_pi5_wdt_arm ck_pi5_wdt_pet ck_boot_klog_find sdhci_init ck_klog_put ck_klog_hdr_match ck_pi5_marker_run ck_pi5_rng_ops ck_rng200_read"
fail=0
defined() { nm "$1" | awk -v s="$2" '$3==s && $2 ~ /^[TtDdBbRrW]$/ {f=1} END {exit !f}'; }
for s in ${syms}; do
    if defined "${pi5}" "${s}"; then echo "PASS pi5 image defines ${s}"; else echo "FAIL pi5 image lacks ${s}"; fail=1; fi
    if defined "${def}" "${s}"; then echo "FAIL default image defines ${s}"; fail=1; else echo "PASS default image has no ${s}"; fi
done
test -s "${root}/target/native-kernel-pi5/BOOTAA64.EFI" || { echo "FAIL no Pi BOOTAA64.EFI"; fail=1; }

# CPU feature printout (PI5-6 cut 1) is on every arm64 image, not Pi only.
for img in "${def}" "${pi5}"; do
    if defined "${img}" ck_cpufeat_decode; then echo "PASS ${img##*/../} defines ck_cpufeat_decode"; else echo "FAIL ${img} lacks ck_cpufeat_decode"; fail=1; fi
done

# Step 3b: the Pi image with the sealed Store stage in the TEST-key tier (SEED-0B-PI5).
make -C "${root}/native/kernel" pi5-store >/dev/null
ps="${root}/target/native-kernel-pi5-store/full-pi5-store/aienos-ck.elf"
for s in ck_stage_store ck_dev_boot_disk ck_store_test_keys; do
    if defined "${ps}" "${s}"; then echo "PASS pi5-store image defines ${s}"; else echo "FAIL pi5-store image lacks ${s}"; fail=1; fi
    if defined "${pi5}" "${s}"; then echo "FAIL plain pi5 image defines ${s}"; fail=1; else echo "PASS plain pi5 image has no ${s}"; fi
done
ps_strings="$(strings -a "${ps}")" # no early-exit pipe (SIGPIPE under pipefail)
if grep -q "SEED-0B-PI5" <<<"${ps_strings}" && ! grep -q "SEED-0B-QEMU" <<<"${ps_strings}"; then echo "PASS pi5-store image carries the SEED-0B-PI5 tier label only"; else echo "FAIL pi5-store tier label"; fail=1; fi
test -s "${root}/target/native-kernel-pi5-store/full-pi5-store/BOOTAA64.EFI" || { echo "FAIL no pi5-store BOOTAA64.EFI"; fail=1; }

# PI5-6 cut 2: the Pi image with the inference unit linked (make pi5-infer). Model source is the boot disk
# (MODEL.MAP) only: no fw_cfg code, and the Rust unit is present only here.
make -C "${root}/native/kernel" pi5-infer >/dev/null
pinf="${root}/target/native-kernel-pi5-infer/aienos-ck.elf"
for s in aienos_infer_session_open aienos_infer_run aienos_infer_heap_init ck_infer_run ck_pi5_start ck_cpufeat_decode; do
    if defined "${pinf}" "${s}"; then echo "PASS pi5-infer image defines ${s}"; else echo "FAIL pi5-infer image lacks ${s}"; fail=1; fi
done
for s in aienos_infer_session_open aienos_infer_run aienos_infer_heap_init; do
    if defined "${pi5}" "${s}" || defined "${ps}" "${s}" || defined "${def}" "${s}"; then echo "FAIL a non-inference image defines ${s}"; fail=1; else echo "PASS plain pi5, pi5-store and default images have no ${s}"; fi
done
pinf_strings="$(strings -a "${pinf}")"
if grep -q "infer_source_mode: boot-disk model" <<<"${pinf_strings}"; then echo "PASS pi5-infer image carries the boot-disk model source line"; else echo "FAIL pi5-infer boot-disk source line"; fail=1; fi
if grep -qE "opt/aienos/model|TEST-ONLY QEMU fw_cfg|fw_cfg" <<<"${pinf_strings}"; then echo "FAIL pi5-infer image carries fw_cfg code or strings"; fail=1; else echo "PASS pi5-infer image has no fw_cfg model ingest"; fi
if defined "${pinf}" ck_stage_store; then echo "FAIL pi5-infer image defines ck_stage_store"; fail=1; else echo "PASS pi5-infer image has no Store stage"; fi
test -s "${root}/target/native-kernel-pi5-infer/BOOTAA64.EFI" || { echo "FAIL no pi5-infer BOOTAA64.EFI"; fail=1; }

if [[ ${fail} == 0 ]]; then echo "CK_PI5_BUILD: PASS"; else echo "CK_PI5_BUILD: FAIL"; exit 1; fi
