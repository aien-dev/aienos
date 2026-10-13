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

# AIENOS-PI5 network lane step 1: the Pi image with the PCIe2 / RP1 enumerator (make pi5-pcie). Read-only boot
# report; the plain pi5, pi5-store, pi5-infer and default images must carry none of it.
make -C "${root}/native/kernel" pi5-pcie >/dev/null
ppc="${root}/target/native-kernel-pi5-pcie/aienos-ck.elf"
for s in ck_pi5pcie_report ck_pi5pcie_cfg_read32 ck_pi5pcie_ib_verdict ck_dmaw_init ck_pi5_start; do
    if defined "${ppc}" "${s}"; then echo "PASS pi5-pcie image defines ${s}"; else echo "FAIL pi5-pcie image lacks ${s}"; fail=1; fi
done
for s in ck_pi5pcie_report ck_pi5pcie_cfg_read32 ck_pi5pcie_ib_verdict ck_dmaw_init; do
    if defined "${pi5}" "${s}" || defined "${ps}" "${s}" || defined "${pinf}" "${s}" || defined "${def}" "${s}"; then echo "FAIL a non-pcie image defines ${s}"; fail=1; else echo "PASS plain pi5, pi5-store, pi5-infer and default images have no ${s}"; fi
done
if grep -q "software-only DMA confinement (Pi 5, weaker than the Spark)" <<<"$(strings -a "${ppc}")"; then echo "PASS pi5-pcie image carries the ADR 0020 label"; else echo "FAIL pi5-pcie image lacks the ADR 0020 label"; fail=1; fi
test -s "${root}/target/native-kernel-pi5-pcie/BOOTAA64.EFI" || { echo "FAIL no pi5-pcie BOOTAA64.EFI"; fail=1; }

# AIENOS-PI5 network lane cut 2: the Pi image that narrows the inbound DMA window and reads the PHY ID (make pi5-net).
# No other image may carry it, and it must refuse every other Pi image flag.
make -C "${root}/native/kernel" pi5-net >/dev/null
pnet="${root}/target/native-kernel-pi5-net/aienos-ck.elf"
for s in ck_pi5net_run ck_pi5net_ib_plan ck_pi5net_ib_apply ck_rp1_phy_reset ck_gem_mdio_read ck_pi5pcie_ib_verdict ck_pi5_start; do
    if defined "${pnet}" "${s}"; then echo "PASS pi5-net image defines ${s}"; else echo "FAIL pi5-net image lacks ${s}"; fail=1; fi
done
for s in ck_pi5net_run ck_pi5net_ib_plan ck_pi5net_ib_apply ck_rp1_phy_reset ck_gem_mdio_read; do
    if defined "${pi5}" "${s}" || defined "${ps}" "${s}" || defined "${pinf}" "${s}" || defined "${def}" "${s}" || defined "${ppc}" "${s}"; then echo "FAIL a non-net image defines ${s}"; fail=1; else echo "PASS plain pi5, pi5-store, pi5-infer, pi5-pcie and default images have no ${s}"; fi
done
if grep -q "pi5_dma: hw_window %s=%s" <<<"$(strings -a "${pnet}")"; then echo "PASS pi5-net image carries the verdict line"; else echo "FAIL pi5-net image lacks the verdict line"; fail=1; fi
test -s "${root}/target/native-kernel-pi5-net/BOOTAA64.EFI" || { echo "FAIL no pi5-net BOOTAA64.EFI"; fail=1; }
for other in CK_PI5_STORE=1 CK_PI5_INFER=1 CK_PI5_PCIE=1 CK_PI5_UNLOCK=1 CK_PI5_AGENT=1 CK_PI5_FACT=1 CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_PI5_NET=2; do
    if make -n -C "${root}/native/kernel" CK_PI5_NET=1 ${other} full >/dev/null 2>&1; then echo "FAIL Makefile accepts CK_PI5_NET=1 with ${other}"; fail=1; else echo "PASS Makefile refuses CK_PI5_NET=1 with ${other}"; fi
done

# PI5-4 cut 1: the Pi unlock image opens the Store only through the Slot 1 recovery-secret path.
make -C "${root}/native/kernel" pi5-unlock >/dev/null
uo="${root}/target/native-kernel-pi5-unlock/full-pi5-unlock/aienos-ck.elf"
for s in ck_stage_store ck_dev_boot_disk ck_store_unlock_boot ck_store_pi5_unlock_run ck_pi5_unlock_secret; do
    if defined "${uo}" "${s}"; then echo "PASS pi5-unlock image defines ${s}"; else echo "FAIL pi5-unlock image lacks ${s}"; fail=1; fi
done
for s in ck_store_test_keys ck_store_test_uuid; do
    if defined "${uo}" "${s}"; then echo "FAIL pi5-unlock image defines ${s}"; fail=1; else echo "PASS pi5-unlock image has no ${s}"; fi
done
uo_strings="$(strings -a "${uo}")"
if grep -q "AIEN-TEST-BOOT" <<<"${uo_strings}" || grep -q "LANE18-TEST-KVOL" <<<"${uo_strings}" || grep -q "SEED-0B-PI5" <<<"${uo_strings}" || grep -q "SEED-0B-QEMU" <<<"${uo_strings}"; then
    echo "FAIL pi5-unlock image carries a TEST uuid, TEST key label or TEST tier label"; fail=1
else
    echo "PASS pi5-unlock image carries no TEST uuid, TEST key label or TEST tier label"
fi
if defined "${ps}" ck_pi5_unlock_secret; then echo "FAIL pi5-store image defines ck_pi5_unlock_secret"; fail=1; else echo "PASS pi5-store image has no unlock secret source"; fi
# The tier flags are mutually exclusive: the Makefile must refuse each combination.
for combo in CK_PI5_STORE=1 CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_TEST_STORE_CRASH=1 CK_SERVICE_TEST_KEYS=1; do
    if make -n -C "${root}/native/kernel" CK_PI5_UNLOCK=1 "${combo}" full >/dev/null 2>&1; then echo "FAIL Makefile accepts CK_PI5_UNLOCK=1 with ${combo}"; fail=1; else echo "PASS Makefile refuses CK_PI5_UNLOCK=1 with ${combo}"; fi
done
test -s "${root}/target/native-kernel-pi5-unlock/full-pi5-unlock/BOOTAA64.EFI" || { echo "FAIL no pi5-unlock BOOTAA64.EFI"; fail=1; }
# PI5-4 cut 2: the card request source (QUALIFICATION ONLY) exists only in its own image.
make -C "${root}/native/kernel" pi5-unlock-card >/dev/null
uc="${root}/target/native-kernel-pi5-unlock-card/full-pi5-unlock-card/aienos-ck.elf"
for s in ck_boot_unlock_req_find ck_unlock_req_take ck_unlock_req_check; do
    if defined "${uc}" "${s}"; then echo "PASS pi5-unlock-card image defines ${s}"; else echo "FAIL pi5-unlock-card image lacks ${s}"; fail=1; fi
    for other in "${uo}" "${ps}" "${pi5}" "${def}"; do
        if defined "${other}" "${s}"; then echo "FAIL ${other} defines ${s}"; fail=1; fi
    done
done
echo "PASS no other image (pi5-unlock, pi5-store, pi5, default) defines the card request reader"
for s in ck_store_test_keys ck_store_test_uuid; do
    if defined "${uc}" "${s}"; then echo "FAIL pi5-unlock-card image defines ${s}"; fail=1; else echo "PASS pi5-unlock-card image has no ${s}"; fi
done
uc_strings="$(strings -a "${uc}")"
if grep -q "QUALIFICATION ONLY, throwaway secret" <<<"${uc_strings}" && ! grep -q "QUALIFICATION ONLY, throwaway secret" <<<"${uo_strings}"; then echo "PASS the loud unlock_source label is in the card image only"; else echo "FAIL unlock_source label placement"; fail=1; fi
if grep -q "AIEN-TEST-BOOT\|LANE18-TEST-KVOL\|SEED-0B-" <<<"${uc_strings}"; then echo "FAIL pi5-unlock-card image carries a TEST label"; fail=1; else echo "PASS pi5-unlock-card image carries no TEST label"; fi
if make -n -C "${root}/native/kernel" CK_PI5_UNLOCK_CARD=1 full >/dev/null 2>&1; then echo "FAIL Makefile accepts CK_PI5_UNLOCK_CARD=1 without CK_PI5_UNLOCK=1"; fail=1; else echo "PASS Makefile refuses CK_PI5_UNLOCK_CARD=1 without CK_PI5_UNLOCK=1"; fi
for combo in "CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_PRODUCTION=1" "CK_PI5_UNLOCK=1 CK_PI5_PRODUCTION=1" "CK_PI5_PRODUCTION=1" "CK_PI5_STORE=1 CK_PI5_UNLOCK_CARD=1"; do
    # shellcheck disable=SC2086
    if make -n -C "${root}/native/kernel" ${combo} full >/dev/null 2>&1; then echo "FAIL Makefile accepts ${combo}"; fail=1; else echo "PASS Makefile refuses ${combo}"; fi
done
test -s "${root}/target/native-kernel-pi5-unlock-card/full-pi5-unlock-card/BOOTAA64.EFI" || { echo "FAIL no pi5-unlock-card BOOTAA64.EFI"; fail=1; }
# PI5-5: the Cortex fact stage and the FACT.REQ reader exist only in the pi5-fact image.
make -C "${root}/native/kernel" pi5-fact >/dev/null
uf="${root}/target/native-kernel-pi5-unlock-card-fact/full-pi5-unlock-card-fact/aienos-ck.elf"
for s in ck_pi5_fact_run ck_store_pi5_fact_stage ck_boot_fact_req_find ck_fact_req_check ck_store_pi5_unlock_run cx_open_with; do
    if defined "${uf}" "${s}"; then echo "PASS pi5-fact image defines ${s}"; else echo "FAIL pi5-fact image lacks ${s}"; fail=1; fi
done
for s in ck_pi5_fact_run ck_store_pi5_fact_stage ck_boot_fact_req_find ck_fact_req_check cx_open_with; do
    for other in "${uc}" "${uo}" "${ps}" "${pi5}" "${def}"; do
        if defined "${other}" "${s}"; then echo "FAIL ${other} defines ${s}"; fail=1; fi
    done
done
echo "PASS no other image (pi5-unlock-card, pi5-unlock, pi5-store, pi5, default) defines the fact stage or its request reader"
for s in ck_store_test_keys ck_store_test_uuid; do
    if defined "${uf}" "${s}"; then echo "FAIL pi5-fact image defines ${s}"; fail=1; else echo "PASS pi5-fact image has no ${s}"; fi
done
uf_strings="$(strings -a "${uf}")"
if grep -q "AIEN-TEST-BOOT\|LANE18-TEST-KVOL\|SEED-0B-" <<<"${uf_strings}"; then echo "FAIL pi5-fact image carries a TEST label"; fail=1; else echo "PASS pi5-fact image carries no TEST label (production-class Store)"; fi
for combo in "CK_PI5_FACT=1" "CK_PI5_UNLOCK=1 CK_PI5_FACT=1" "CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_FACT=1 CK_PI5_STORE=1" "CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_FACT=1 CK_PI5_INFER=1" "CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_FACT=1 CK_PI5_PCIE=1" "CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_FACT=2"; do
    # shellcheck disable=SC2086
    if make -n -C "${root}/native/kernel" ${combo} full >/dev/null 2>&1; then echo "FAIL Makefile accepts ${combo}"; fail=1; else echo "PASS Makefile refuses ${combo}"; fi
done
for combo in CK_PI5_FACT=1; do
    for other in CK_PI5_STORE=1 CK_PI5_INFER=1 CK_PI5_PCIE=1; do
        # shellcheck disable=SC2086
        if make -n -C "${root}/native/kernel" ${other} ${combo} full >/dev/null 2>&1; then echo "FAIL Makefile accepts ${other} ${combo}"; fail=1; else echo "PASS Makefile refuses ${other} ${combo}"; fi
    done
done
test -s "${root}/target/native-kernel-pi5-unlock-card-fact/full-pi5-unlock-card-fact/BOOTAA64.EFI" || { echo "FAIL no pi5-fact BOOTAA64.EFI"; fail=1; }
# PI5-6 final cut: the agent stage (Store plus resident inference plus the persisted reply) exists only in the pi5-agent image.
make -C "${root}/native/kernel" pi5-agent >/dev/null
ua="${root}/target/native-kernel-pi5-unlock-card-agent/full-pi5-unlock-card-agent/aienos-ck.elf"
for s in ck_pi5_agent_run ck_store_pi5_agent_stage ck_infer_prompt ck_infer_resident_close ck_infer_model_sha256 ck_store_pi5_unlock_run ck_boot_unlock_req_find; do
    if defined "${ua}" "${s}"; then echo "PASS pi5-agent image defines ${s}"; else echo "FAIL pi5-agent image lacks ${s}"; fail=1; fi
done
for s in ck_pi5_agent_run ck_store_pi5_agent_stage; do
    for other in "${uf}" "${uc}" "${uo}" "${ps}" "${pi5}" "${pinf}" "${def}"; do
        if defined "${other}" "${s}"; then echo "FAIL ${other} defines ${s}"; fail=1; fi
    done
done
echo "PASS no other image (pi5-fact, pi5-unlock-card, pi5-unlock, pi5-store, pi5, pi5-infer, default) defines the agent stage"
for s in ck_store_test_keys ck_store_test_uuid ck_pi5_fact_run ck_boot_fact_req_find fw_dma_read fwcfg_from_dsdt; do
    if defined "${ua}" "${s}"; then echo "FAIL pi5-agent image defines ${s}"; fail=1; else echo "PASS pi5-agent image has no ${s}"; fi
done
ua_strings="$(strings -a "${ua}")"
if grep -q "AIEN-TEST-BOOT\|LANE18-TEST-KVOL\|SEED-0B-" <<<"${ua_strings}"; then echo "FAIL pi5-agent image carries a TEST label"; fail=1; else echo "PASS pi5-agent image carries no TEST label (production-class Store)"; fi
if grep -q "infer_source_mode: boot-disk model" <<<"${ua_strings}" && ! grep -q "opt/aienos/model\|TEST-ONLY QEMU fw_cfg" <<<"${ua_strings}"; then echo "PASS pi5-agent image reads the model from the boot disk only (no fw_cfg source)"; else echo "FAIL pi5-agent image model source"; fail=1; fi
if grep -q "QUALIFICATION ONLY, throwaway secret" <<<"${ua_strings}"; then echo "PASS the loud unlock_source label is in the pi5-agent image"; else echo "FAIL pi5-agent image lacks the unlock_source label"; fail=1; fi
# the positive control: the flag set the image is built with is accepted (a dry run), so the refusals below are the flag under test.
if make -n -C "${root}/native/kernel" CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_AGENT=1 CK_INFER_LIB=/nonexistent/lib.a full >/dev/null 2>&1; then echo "PASS Makefile accepts CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_AGENT=1 CK_INFER_LIB=<lib>"; else echo "FAIL Makefile refuses the pi5-agent flag set"; fail=1; fi
for combo in "CK_PI5_AGENT=1" "CK_PI5_UNLOCK=1 CK_PI5_AGENT=1 CK_INFER_LIB=/x/l.a" "CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_AGENT=1" "CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_AGENT=2 CK_INFER_LIB=/x/l.a" "CK_PI5_UNLOCK_CARD=1 CK_PI5_AGENT=1 CK_INFER_LIB=/x/l.a"; do
    # shellcheck disable=SC2086
    if make -n -C "${root}/native/kernel" ${combo} full >/dev/null 2>&1; then echo "FAIL Makefile accepts ${combo}"; fail=1; else echo "PASS Makefile refuses ${combo}"; fi
done
for other in CK_PI5_STORE=1 CK_PI5_INFER=1 CK_PI5_PCIE=1 CK_PI5_FACT=1 CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_TEST_FWCFG_ARTIFACTS=1; do
    # shellcheck disable=SC2086
    if make -n -C "${root}/native/kernel" ${other} CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_AGENT=1 CK_INFER_LIB=/x/l.a full >/dev/null 2>&1; then echo "FAIL Makefile accepts ${other} with CK_PI5_AGENT=1"; fail=1; else echo "PASS Makefile refuses ${other} with CK_PI5_AGENT=1"; fi
done
# the other direction: the older Pi tiers refuse the agent flag too.
for tier in CK_PI5_INFER=1 CK_PI5_PCIE=1 CK_PI5_FACT=1; do
    # shellcheck disable=SC2086
    if make -n -C "${root}/native/kernel" ${tier} CK_PI5_AGENT=1 CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_INFER_LIB=/x/l.a full >/dev/null 2>&1; then echo "FAIL Makefile accepts ${tier} with CK_PI5_AGENT=1"; fail=1; fi
done
test -s "${root}/target/native-kernel-pi5-unlock-card-agent/full-pi5-unlock-card-agent/BOOTAA64.EFI" || { echo "FAIL no pi5-agent BOOTAA64.EFI"; fail=1; }
if [[ ${fail} == 0 ]]; then echo "CK_PI5_BUILD: PASS"; else echo "CK_PI5_BUILD: FAIL"; exit 1; fi
