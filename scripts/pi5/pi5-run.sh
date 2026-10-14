#!/usr/bin/env bash
# Runs from the Spark against the hub Pi 5 over ssh (host alias "hub"); never run it on the hub itself. Run folders go under $PI5_RUNS_DIR (default ~/workspace/pi5-runs).
# pi5-run.sh -- one remote, one-shot AIENOS test run on the hub Raspberry Pi 5.
#
#   pi5-run.sh <EFI file> <tag> [wait-file]
#
# 1. Puts <EFI file> on the AIENOS test microSD (mmcblk0p1, label AIENOSPI5) as
#    EFI/BOOT/BOOTAA64.EFI and removes the old report, so a report after the run
#    proves this run wrote it.
# 2. Makes sure the Pi 5 UEFI firmware from the card is also on the USB stick's
#    boot partition under aienos/ (the Pi bootloader reads config from the stick).
# 3. Appends a [tryboot]-only block to the stick's config.txt (backup kept on the
#    hub and here) and reboots with reboot '0 tryboot'. Raspberry Pi docs
#    (bootflow-eeprom.adoc): the flag "is cleared before starting the firmware, a
#    crash or reset will cause the original config.txt file to be loaded on the
#    next reboot". Normal boots never read the block.
# 4. Waits for the hub to come back on normal Linux (ping every 30 s, ssh only
#    after ping answers; hub stick is fragile: one ssh at a time, no fast retries).
# 5. Removes the block (restores the backup, checks it), copies the card's
#    EFI/AIENOS tree to ~/workspace/pi5-runs/<tag>/, unmounts.
# If the hub is not back after 15 min: notify Drake (power-cycle the Pi; it comes
# back on normal Linux because the flag is already cleared).
set -euo pipefail
efi="${1:?EFI file}"; tag="${2:?tag}"
hub=hub
runs="${PI5_RUNS_DIR:-$HOME/workspace/pi5-runs}/${tag}"
mkdir -p "${runs}"
log() { echo "[$(date -u +%H:%M:%SZ)] $*" | tee -a "${runs}/run.log"; }
hs() { ssh -o BatchMode=yes -o ConnectTimeout=15 "${hub}" "$@"; }
mark_begin='# >>> AIENOS-PI5 one-shot tryboot block (pi5-run.sh adds it before a run, removes it after)'
mark_end='# <<< AIENOS-PI5'

[[ -r "${efi}" ]] || { echo "no EFI file ${efi}"; exit 2; }
sha=$(sha256sum "${efi}" | cut -d' ' -f1)
log "run ${tag}: efi=${efi} sha256=${sha}"

# ---- which source commit does this EFI claim? (the kernel prints the same string as aienos_commit) ----
# A Pi build made from a tree with uncommitted changes to tracked files ends in
# -dirty (native/kernel/Makefile); such a run is not tied to any GitHub commit.
stamp_rc=0
commit_stamp=$("$(dirname "$0")/efi-commit.sh" "${efi}" 2>&1) || stamp_rc=$?
log "efi aienos_commit: ${commit_stamp}"
if [[ ${stamp_rc} != 0 ]]; then
    log "!!! NOT commit-bound (no single commit stamp found in the EFI)"
elif [[ ${commit_stamp} == *-dirty ]]; then
    log "!!! NOT commit-bound (dirty build): ${commit_stamp%-dirty} is only the commit the build started from; this EFI also holds uncommitted changes"
fi

# ---- preflight on the hub ----
hs 'set -e
test "$(cat /proc/device-tree/chosen/bootloader/tryboot | od -An -tx1 | tr -d " ")" = 00000000
test ! -e /boot/firmware/new || { echo "REFUSE: /boot/firmware/new exists (pending Ubuntu tryboot update)"; exit 1; }
grep -qF "AIENOS-PI5 one-shot" /boot/firmware/config.txt && { echo "REFUSE: block already in config.txt"; exit 1; } || true
lsblk -no LABEL /dev/mmcblk0p1 | grep -qx AIENOSPI5
findmnt /dev/mmcblk0p1 >/dev/null && { echo "REFUSE: card mounted"; exit 1; } || true
echo "users: $(who | wc -l)"' 2>&1 | tee -a "${runs}/run.log"
[[ ${PIPESTATUS[0]} == 0 ]] || { log "preflight FAILED"; exit 1; }

# ---- card: install EFI, clear old report; stick: firmware copy ----
scp -q -o BatchMode=yes "${efi}" "${hub}:/tmp/aienos-run.efi"
hs "set -e
sudo mkdir -p /mnt/aienos
sudo mount /dev/mmcblk0p1 /mnt/aienos
trap 'sudo umount /mnt/aienos' EXIT
sudo cp /tmp/aienos-run.efi /mnt/aienos/EFI/BOOT/BOOTAA64.EFI
sudo rm -rf /mnt/aienos/EFI/AIENOS
test \"\$(sha256sum /mnt/aienos/EFI/BOOT/BOOTAA64.EFI | cut -d' ' -f1)\" = ${sha}
sudo mkdir -p /boot/firmware/aienos/overlays
for f in RPI_EFI.fd RPI_NV0.bin RPI_NV1.bin bcm2712-rpi-5-b.dtb overlays/bcm2712d0.dtbo; do
  if ! cmp -s /mnt/aienos/\$f /boot/firmware/aienos/\$f; then sudo cp /mnt/aienos/\$f /boot/firmware/aienos/\$f; fi
done
test -e /boot/firmware/aienos/overlays/README || echo 'AIENOS-PI5 tryboot overlays (only bcm2712d0)' | sudo tee /boot/firmware/aienos/overlays/README >/dev/null
sync
echo card+stick ready" 2>&1 | tee -a "${runs}/run.log"

# ---- optional: KLOG slot for a kernel run (KLOG=1) ----
# A 2 MiB contiguous file on the card plus \EFI\AIENOS\KLOG.MAP naming its
# absolute first sector and a fresh nonce (aienos core/klog_slot.h). The raw
# card sector is read back and compared before the map is written, so the
# kernel is never told a position that is not the file.
if [[ "${KLOG:-0}" == 1 ]]; then
    . "$(dirname "$0")/klog-lib.sh"
    slot_secs=4096
    ext=$(hs "set -e
sudo mount /dev/mmcblk0p1 /mnt/aienos; trap 'sudo umount /mnt/aienos' EXIT
sudo mkdir -p /mnt/aienos/EFI/AIENOS
sudo dd if=/dev/zero of=/mnt/aienos/EFI/AIENOS/KLOG.BIN bs=512 count=${slot_secs} conv=fsync status=none
sync
sudo hdparm --fibmap /mnt/aienos/EFI/AIENOS/KLOG.BIN")
    echo "${ext}" >> "${runs}/run.log"
    # hdparm --fibmap rows: byte_offset begin_LBA end_LBA sectors (absolute card LBAs)
    rows=$(echo "${ext}" | awk '$1 ~ /^[0-9]+$/ && NF==4')
    nexts=$(echo -n "${rows}" | grep -c . || true)
    read -r poff klog_lba pend plen <<<"${rows}"
    if [[ "${nexts}" != 1 || "${poff}" != 0 || "${plen}" != "${slot_secs}" || $((pend - klog_lba + 1)) != "${slot_secs}" ]]; then
        log "KLOG.BIN is not one ${slot_secs}-sector extent (rows=${nexts} lba=${klog_lba} len=${plen}); stopping"; exit 1
    fi
    nonce=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
    klog_hdr_empty "${klog_lba}" "${slot_secs}" "${nonce}" "${runs}/klog-hdr.bin"
    klog_map "${klog_lba}" "${slot_secs}" "${nonce}" "${runs}/KLOG.MAP"
    scp -q -o BatchMode=yes "${runs}/klog-hdr.bin" "${runs}/KLOG.MAP" "${hub}:/tmp/"
    if ! hs "set -e
sudo mount /dev/mmcblk0p1 /mnt/aienos; trap 'sudo umount /mnt/aienos' EXIT
sudo dd if=/tmp/klog-hdr.bin of=/mnt/aienos/EFI/AIENOS/KLOG.BIN bs=512 count=1 conv=notrunc,fsync status=none
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
sudo dd if=/dev/mmcblk0 bs=512 skip=${klog_lba} count=1 iflag=direct status=none | cmp - /tmp/klog-hdr.bin
sudo cp /tmp/KLOG.MAP /mnt/aienos/EFI/AIENOS/KLOG.MAP; sync
echo klog_slot_ready" 2>&1 | tee -a "${runs}/run.log"; then :; fi
    if ! grep -q klog_slot_ready "${runs}/run.log"; then log "klog slot raw read-back FAILED; stopping before any reboot"; exit 1; fi
    log "klog slot lba=${klog_lba} sectors=${slot_secs} nonce=${nonce} (raw card sector matches)"
fi
if [[ "${DRY:-0}" == 1 ]]; then log "DRY=1: card prepared, stopping before any config change or reboot"; exit 0; fi

# ---- config.txt: backup, append the tryboot-only block, check ----
hs "sudo cp -p /boot/firmware/config.txt /boot/firmware/config.txt.pre-aienos" 
hs "cat /boot/firmware/config.txt" > "${runs}/config.txt.before"
{
cat <<BLOCK

${mark_begin}
[tryboot]
armstub=aienos/RPI_EFI.fd
device_tree=aienos/bcm2712-rpi-5-b.dtb
overlay_prefix=aienos/overlays/
device_tree_address=0x1f0000
device_tree_end=0x210000
framebuffer_depth=32
disable_overscan=1
usb_max_current_enable=1
force_turbo=1
initramfs aienos/RPI_NV0.bin,aienos/RPI_NV1.bin 0x04000000
[all]
${mark_end}
BLOCK
} > "${runs}/block.txt"
scp -q -o BatchMode=yes "${runs}/block.txt" "${hub}:/tmp/aienos-block.txt"
hs "set -e; sudo sh -c 'cat /tmp/aienos-block.txt >> /boot/firmware/config.txt'; sync
diff /boot/firmware/config.txt.pre-aienos /boot/firmware/config.txt | grep -c '^>' "
hs "cat /boot/firmware/config.txt" > "${runs}/config.txt.during"
if ! diff <(cat "${runs}/config.txt.before" "${runs}/block.txt") "${runs}/config.txt.during" >/dev/null; then
    log "config.txt is not exactly before+block: restoring and stopping"
    hs "sudo cp -p /boot/firmware/config.txt.pre-aienos /boot/firmware/config.txt; sync"
    exit 1
fi
log "block appended; rebooting the hub with tryboot"
t0=$(date +%s)
hs "sudo reboot '0 tryboot'" >/dev/null 2>&1 || true

# ---- wait: down, then back ----
sleep 20
down=0; back=0
for i in $(seq 1 30); do
    if ping -c1 -W3 192.168.1.192 >/dev/null 2>&1; then
        [[ ${down} == 1 ]] && { back=1; break; }
    else
        down=1
    fi
    sleep 30
done
if [[ ${back} != 1 ]]; then
    log "hub NOT back after ~15 min (down_seen=${down})"
    exit 4
fi
log "hub answers ping again after $(( $(date +%s) - t0 )) s; waiting 60 s for ssh"
sleep 60
for i in 1 2 3 4 5; do hs true 2>/dev/null && break; sleep 60; done

# ---- cleanup + evidence ----
hs "set -e
tb=\$(od -An -tx1 /proc/device-tree/chosen/bootloader/tryboot | tr -d ' ')
echo tryboot_flag_now=\$tb
sudo cp -p /boot/firmware/config.txt.pre-aienos /boot/firmware/config.txt; sync
grep -qF 'AIENOS-PI5 one-shot' /boot/firmware/config.txt && echo BLOCK_STILL_THERE || echo block_removed
uptime" 2>&1 | tee -a "${runs}/run.log"
hs "cat /boot/firmware/config.txt" > "${runs}/config.txt.after"
cmp -s "${runs}/config.txt.before" "${runs}/config.txt.after" && log "config.txt restored byte for byte" || log "WARNING config.txt differs from before"
hs "set -e; sudo mount -o ro /dev/mmcblk0p1 /mnt/aienos; trap 'sudo umount /mnt/aienos' EXIT
if [ -d /mnt/aienos/EFI/AIENOS ]; then sudo tar -C /mnt/aienos/EFI -cf - AIENOS; fi" > "${runs}/aienos.tar"
if [[ -s "${runs}/aienos.tar" ]]; then
    tar -C "${runs}" -xf "${runs}/aienos.tar" && rm "${runs}/aienos.tar"
    log "report copied: $(ls -R "${runs}/AIENOS" | tr '\n' ' ' | head -c 400)"
    if [[ "${KLOG:-0}" == 1 ]]; then
        if [[ -f "${runs}/AIENOS/KLOG.BIN" ]] && klog_extract "${runs}/AIENOS/KLOG.BIN" "${runs}/kernel.log" | tee -a "${runs}/run.log"; then
            log "kernel log: $(wc -l < "${runs}/kernel.log") lines in ${runs}/kernel.log"
        else
            log "kernel log NOT written (slot still empty or missing)"
        fi
    fi
else
    log "NO report on the card: the AIENOS image did not run or did not write"
    exit 5
fi
log "run ${tag} done"
