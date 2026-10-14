#!/usr/bin/env bash
# PI5-8: put one model on the card's raw AIENOS-MODEL partition (p3), run the measurement image once, clean up.
#   pi_run.sh MODEL.gguf MODEL.MAP BOOTAA64.EFI TAG [--no-write | --write-only]
#   --no-write: p3 already holds the model (only verify it); --write-only: write and verify p3, do not run.
# Steps: wait until no other Pi run is going (hold file + pi5-run processes), write the model to /dev/mmcblk0p3 on
# the hub and read it back (sha256 must equal the model's), run ~/workspace/pi5/pi5-run.sh with KLOG=1 and the
# map, then remove MODEL.MAP from the ESP (the harness does not). Evidence: ~/workspace/pi5-runs/TAG/.
# The hub is the house server: one ssh at a time, no fast retries, never `find /` on it.
set -euo pipefail
model="${1:?model}"; map="${2:?map}"; efi="${3:?efi}"; tag="${4:?tag}"; nowrite="${5:-}"
hold=/home/drakestapleton/.claude/jobs/9974574d/tmp/pi-hold
hs() { ssh -o BatchMode=yes -o ConnectTimeout=15 hub "$@"; }
until [[ ! -e "$hold" ]] && [[ -z "$(ps -eo pid,args | grep -E ' bash [^ ]*/pi5-run[^ ]*\.sh' | grep -v grep || true)" ]]; do sleep 30; done
size=$(stat -c %s "$model"); sha=$(sha256sum "$model" | cut -d' ' -f1)
if [[ "$nowrite" != --no-write ]]; then
    echo "[$(date -u +%H:%M:%SZ)] writing $size bytes to p3"
    hs 'sudo dd of=/dev/mmcblk0p3 bs=4M conv=fsync status=none' < "$model"
    hs 'sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null'
fi
got=$(hs "sudo dd if=/dev/mmcblk0p3 bs=4M status=none | head -c ${size} | sha256sum" | cut -d' ' -f1)
echo "[$(date -u +%H:%M:%SZ)] p3 readback sha256=$got want=$sha"
[[ "$got" == "$sha" ]] || { echo "p3 readback MISMATCH; stopping"; exit 1; }
[[ "$nowrite" == --write-only ]] && { echo "write-only: p3 verified, no run"; exit 0; }
KLOG=1 MODEL_MAP="$map" "$HOME/workspace/pi5/pi5-run.sh" "$efi" "$tag"
hs 'set -e; sudo mount /dev/mmcblk0p1 /mnt/aienos; trap "sudo umount /mnt/aienos" EXIT; sudo rm -f /mnt/aienos/EFI/AIENOS/MODEL.MAP; sync; test ! -e /mnt/aienos/EFI/AIENOS/MODEL.MAP; echo model_map_removed'
echo "[$(date -u +%H:%M:%SZ)] done $tag"
