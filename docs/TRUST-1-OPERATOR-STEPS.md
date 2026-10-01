# TRUST-1: the steps only the operator can do

This is the hands-on companion to [TRUST-1-IMPLEMENTATION-PLAN.md](TRUST-1-IMPLEMENTATION-PLAN.md).
The plan says *what* each gate must prove. This page says *what you physically
do*, in order: what to type, where to type it, what it changes, and what you
should see. Agents have already built and tested every script used here.

Ground rules for every step:

- Nothing here changes firmware settings, Secure Boot keys, or the TPM. If a
  step ever asks you to, stop: that belongs to Gate 6 or Gate 7 and gets its
  own written approval first.
- "Terminal" means a terminal window on the Spark, logged in as yourself,
  unless a step says otherwise.
- Every command that starts with `sudo` will ask for your Spark password.
- If anything prints `FAIL` or looks different from "What you should see",
  stop and hand the output to the orchestrator. Do not retry or improvise.

All commands below assume this folder (the Spark's copy of the AIENOS repository):

```bash
cd ~/workspace/aienos-recovery-gate
git pull --ff-only
```

*What it does:* moves into the repository and downloads the latest scripts.
*Changes:* only the script files in that folder. *You should see:* a list of
updated files, or `Already up to date.`

---

## Step 1. Restart the Spark once, with a snapshot before and after (Gate 2, first baseline boot)

Why: Gate 2 needs proof that the security measurements the Spark makes at
startup come out the same on every normal boot. This restart also rebuilds the
Spark's device list cleanly after the 2026-09-30 incident in which a test
script wiped and an agent rebuilt it by hand.

1. Take the "before" snapshot:

   ```bash
   mkdir -p ~/trust1-evidence
   bash scripts/tpm_measurement_campaign.sh capture ~/trust1-evidence/boot0-before baseline-before-restart
   ```

   *What it does:* reads the startup measurements, Secure Boot state and boot
   menu entries, and saves them in a folder. *Changes:* nothing on the
   machine; it only writes the new folder. *You should see:* a short summary
   ending without any `FAIL`.

2. Restart: save your work, then type `sudo reboot`. Do not touch the
   keyboard during startup. Ubuntu should come back as normal.

3. Take the "after" snapshot and compare:

   ```bash
   cd ~/workspace/aienos-recovery-gate
   bash scripts/tpm_measurement_campaign.sh capture ~/trust1-evidence/boot1-after baseline-after-restart
   bash scripts/tpm_measurement_campaign.sh compare ~/trust1-evidence/boot0-before ~/trust1-evidence/boot1-after
   ```

   *Changes:* nothing on the machine. *You should see:* one `SAME` or `CHANGED`
   line per item and a last line `compared=... changed=...`. `changed=0` means
   identical. Either result is useful evidence; differences
   are what Gate 2 exists to explain. Tell the orchestrator which you got.

## Step 2. Pause automatic firmware-update checks during the measurement campaign (recommended)

Why: the plan forbids a firmware update while measurements are being
collected, because an update changes the measurements and would spoil the
comparison.

```bash
sudo systemctl disable --now fwupd-refresh.timer
```

*What it does:* stops Ubuntu's background check for new firmware. *Changes:*
one Ubuntu setting; no firmware is touched. *You should see:* a line saying a
link was removed, or nothing. *To undo later (after Gate 2 ends):*
`sudo systemctl enable --now fwupd-refresh.timer`.

## Step 3. Create the harmless test file (Gate 1 round trip, part 1)

Why: Gate 1 must prove the recovery stick can open the encrypted private
storage *without* Ubuntu, using the offline spare. We prove it with a
throwaway file whose fingerprint we know, never with real data.

```bash
sudo -u atlas sh -c 'date -u > /home/atlas/atlas-runtime-setup-20260905/private-data/trust1-roundtrip-test.txt'
sudo -u atlas sha256sum /home/atlas/atlas-runtime-setup-20260905/private-data/trust1-roundtrip-test.txt
```

The commands run as the `atlas` account because that account opened the
private storage, and only it may write there (even the administrator is
refused). *Changes:* adds one small text file to the private storage. *You should see:*
the date, then a long fingerprint (64 letters and digits). Write the
fingerprint down or paste it to the orchestrator; Step 6 checks it.

## Step 4. Rebuild the recovery stick with the new image (needs your approval)

Why: the stick in use today was built before the Gate 1 fixes. It lacks the
tools that open the encrypted storage, read the startup measurements through
the TPM, and check loader signatures. Rebuilding replaces the recovery files on
the stick (it is not reformatted); it does not
touch the Spark's internal drive. (What the stick contains, and how it was
first proven, is recorded in
[RECOVERY_MEDIA_MACHINE1.md](RECOVERY_MEDIA_MACHINE1.md).)

1. Plug in the recovery stick (label `AIENOSRECOV`). Run `lsblk -f` and find
   the line with that label. Note its name, for example `sdb1`. If Ubuntu
   opened it automatically (a folder path shows in the last column), close it
   first with `udisksctl unmount -b /dev/sdX1` (your name in place of `sdX1`).
2. Run (replace `sdX1` with the name you found):

   ```bash
   bash scripts/verify_recovery_tools.sh
   sudo -v
   aien-proof hold --resource machine-1 --job build-recovery-media -- \
       sudo bash scripts/build_recovery_media.sh /dev/sdX1
   ```

   *What it does:* checks the new image, then writes it to the stick. The
   builder refuses the internal drive and the old `ATLAS_RECOV` stick on its
   own. *Changes:* replaces the recovery files on the stick only. *You should see:*
   `RECOVERY_TOOLS: PASS`, then the builder copying files and unmounting the
   stick with no error.

## Step 5. Decide where the recovery key lives (decision for you)

**Where we are.** The stick can now open the encrypted storage on its own. To
do that it needs two things: the *spare* (a locked copy of the storage
password, already kept on the Spark at
`~/.config/atlas/offline-spares/atlas-private-storage.passfile.age`) and the
*identity* (the private key that unlocks the spare). The identity is **not**
on the Spark, on purpose; it is kept on the MacBook. The orchestrator will
confirm which MacBook file opens this spare before you copy it. If that file
is itself passphrase-protected, the recovery prompt will ask for that
passphrase during Step 6. The spare is useless without the identity, so where
the identity sits during the test matters.

**The decision.** Where should the identity be when the stick boots?

- **Option A: on a second, separate small USB stick (recommended).**
  You copy the identity file onto a spare USB stick, plug it in only for the
  test, then put it away somewhere separate.
  *Upside:* the recovery stick itself stays secret-free (it is rebuilt from a
  public repository, and the builder forbids secrets on it); losing one stick
  never exposes the storage. *Downside:* one more stick to keep track of.
  *If you pick it:* about 5 extra minutes; fully reversible (wipe the stick).
- **Option B: on the recovery stick.**
  *Upside:* one object to carry. *Downside:* anyone holding that stick plus
  the Spark's drive can open the storage, and it breaks the stick's
  "no secrets" rule; agents would have to change the builder. *If you pick
  it:* not recommended; it would need a new rule decision first.
- **Option C: type it in by hand at the recovery prompt.**
  *Upside:* nothing to carry. *Downside:* an identity is a long random string;
  a typo means the test fails, and there is no screen copy-paste in the
  recovery shell. *If you pick it:* expect several tries.

**Recommendation:** Option A, because it keeps the stick and the key apart,
which is the whole point of an offline recovery path.

*(Reminder, mentioned once: the identity and the spares should also have a
second copy somewhere physically separate from the Spark.)*

**Question: Option A (second USB stick), or do you prefer B or C?**

## Step 6. Boot the recovery stick with Secure Boot ON and prove the unlock (Gate 1, attended)

The recovery prompt is a small, separate system on the stick. It has only
the tools listed in
[RECOVERY_MEDIA_MACHINE1.md, "What ships"](RECOVERY_MEDIA_MACHINE1.md#what-ships).
`aien-proof` is not one of them, so type the commands below exactly as shown,
with nothing in front.

1. Both sticks plugged in (Option A). In the terminal:

   ```bash
   efibootmgr
   ```

   Find the line for the USB stick (last time it was `Boot0004* UEFI: USB ...`)
   and use its number below:

   ```bash
   sudo efibootmgr --bootnext 0004
   sudo reboot
   ```

   *What it does:* tells the firmware to start from the stick **once only**.
   *Changes:* a one-time setting that the firmware erases itself after use;
   the normal boot order stays as it is. *You should see:* the AIENOS menu,
   then the banner `AIENOS Standalone Hardware Recovery Core`.

2. At the recovery prompt, open the internal drive read-only and the key stick:

   ```sh
   mkdir -p /mnt/root /mnt/esp /mnt/key
   mount -o ro /dev/nvme0n1p2 /mnt/root
   mount -o ro /dev/nvme0n1p1 /mnt/esp
   lsblk -f
   mount -o ro /dev/sdY1 /mnt/key
   ```

   Replace `sdY1` with the key stick's name from the `lsblk` list (the one
   that is not `AIENOSRECOV`). *Changes:* nothing; everything is read-only.

3. Run the evidence collector with the unlock switched on. Replace
   `IDENTITY-FILE` with the identity's file name on the key stick and
   `FINGERPRINT` with the value from Step 3:

   ```sh
   env AIENOS_ESP_MNT=/mnt/esp \
       AIENOS_UNLOCK_CIPHER=/mnt/root/home/atlas/atlas-runtime-setup-20260905/private-cipher \
       AIENOS_UNLOCK_SPARE=/mnt/root/home/drakestapleton/.config/atlas/offline-spares/atlas-private-storage.passfile.age \
       AIENOS_UNLOCK_IDENTITY=/mnt/key/IDENTITY-FILE \
       AIENOS_UNLOCK_EXPECT="trust1-roundtrip-test.txt FINGERPRINT" \
     /usr/local/sbin/collect_recovery_boot_evidence /mnt/root
   ```

   *What it does:* records Secure Boot state, the startup measurements, the
   disks, the encrypted stores, every loader's fingerprint and signer; then
   opens the private storage **read-only**, checks the test file, and closes
   it. The unlocked password exists only in memory and is deleted straight
   away. *Changes:* nothing on any disk. *You should see:*
   `PASS  recovery_unlock_readonly`, `PASS  test_artifact_round_trip`, and
   finally `RECOVERY_BOOT_GATE: PASS`. Photograph the screen or save the
   output to the key stick if you can.

4. Return to Ubuntu: type `umount /mnt/key /mnt/esp /mnt/root`, remove both
   sticks, then `reboot -f`. *You should see:* Ubuntu start normally. Then
   in a terminal run `mokutil --sb-state` and expect `SecureBoot enabled`.
   That is the "return to Linux" proof.

## Step 7. Two more normal restarts, fully powered off (Gate 2 baseline)

Repeat Step 1 twice, but instead of `sudo reboot` use `sudo poweroff`, wait 30
seconds, then press the power button. Use new folder names each time
(`boot2-before`/`boot2-after`, `boot3-before`/`boot3-after`). Hand the compare
results to the orchestrator. Agents then prepare the one-change-at-a-time
experiments (each with its own written steps and undo) and write the Gate 2
report.

## Step 8. The offline key ceremony (Gate 3; after Steps 1-7)

**Where we are.** The tool that creates your owner keys
(`scripts/trust1_key_ceremony.sh`) is written and tested with throwaway keys.
It creates four keys: the Owner Root (the master key that never touches the
Spark), the Boot Signer (signs the small startup loader), the Release Signer
(signs each AIENOS release) and the Operator Approval key (signs your
approvals). Every private key is locked with a passphrase from the moment it
is created. Nothing is installed into the Spark's firmware at this gate.

**The decision.** Which machine runs the ceremony? It must be disconnected
from every network while it runs; the tool refuses to start if it sees a
network connection.

- **Option A: the MacBook, with Wi-Fi off (recommended for now).**
  *Upside:* you already have it; nothing to buy. *Downside:* it is a daily,
  internet-connected machine, so the keys are only as safe as the MacBook
  was before the ceremony. It needs OpenSSL 3 installed first (one command
  while still online: `brew install openssl@3`).
  *If you pick it:* about 30 minutes; the keys can later be replaced through
  the rotation steps.
- **Option B: a spare computer (or a fresh live USB system) used only for
  this.** *Upside:* strongest protection for the master key. *Downside:*
  needs a spare machine or a new stick and some setup time.

**Recommendation:** Option A for generation 1, with the plan to rotate to a
dedicated machine later if one becomes available. The rotation path is
already built and tested.

**Question: MacBook with Wi-Fi off, or a dedicated machine?**

What you will do, once you choose (the orchestrator will walk you through it
live):

1. Copy `scripts/trust1_key_ceremony.sh` to the ceremony machine while it is
   still online. Turn off Wi-Fi and unplug network cables.
2. `bash trust1_key_ceremony.sh preflight` (add
   `AIENOS_OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl ` in front on a
   Mac). *You should see:* `OpenSSL 3...` and `network: offline`.
3. `bash trust1_key_ceremony.sh generate ~/aienos-ceremony-gen1`. It asks
   for a passphrase twice: choose a long one and write it on paper stored with
   the backups. *Changes:* creates that folder only. *You should see:* four
   `PASS ... matches manifest` lines and a `generated:` line.
4. Plug in backup stick 1, then
   `bash trust1_key_ceremony.sh backup ~/aienos-ceremony-gen1 /Volumes/STICK1 backup-A`
   (use the stick's real name). *You should see:* four `PASS ... decrypts from
   the backup copy`. Repeat with backup stick 2 as `backup-B`. Store the two
   sticks in two different places.
5. `bash trust1_key_ceremony.sh record ~/aienos-ceremony-gen1` writes the
   ceremony record. Only the `public` folder (public keys, the signed
   manifest, the record) goes back to the Spark. The `private` folder stays
   on the ceremony machine and the two backups.

## Known hardware risk: do not boot the C kernel on a disk that holds data

**Do not boot the C kernel on a disk holding data until CK gate `DISK_LAYOUT`
is PASS on a forge receipt.** Today that gate is **NOT_RUN
(MISSING_IMPLEMENTATION, fix in progress)**. Nothing in this document's steps
boots the C kernel, and none of them may be extended to do so before the gate
passes.

Why: the C kernel treats the whole NVMe disk as its own and knows nothing about
partitions. On a real GPT disk such as Machine 1's, that overlaps the disk's
own partition table:

- It writes the last 4 KiB of the whole disk at every boot (a write, read-back
  and restore probe), `native/kernel/dev/nvme_bind.c:93-127` (called at line
  224), sized by `native/kernel/dev/disk_layout.h:6-7`. The last sectors of a GPT
  disk hold the backup partition table. A power cut during the probe leaves
  that area with probe data.
- It uses the first 16 KiB (4 units) as the anti-rollback anchor,
  `native/kernel/dev/disk_layout.h:3,12` and
  `native/kernel/svc/store_boot.c:164-170` (`anchor_lba = 0`). Sector 0 is the
  protective MBR and the next sectors hold the primary GPT.
- The Store region is everything between those two ends
  (`native/kernel/dev/disk_layout.h:4`, `store_boot.c:169-170`), so a format
  of the Store would cover every partition on the disk.

Source: `~/handoffs/2026-10-01-review/track4-aienos-trust.md`, row R2.
This entry is documentation only. It was not tested, and no hardware result is
claimed. Host, QEMU and hardware status of the fix: all NOT_RUN.

## Later gates (no action from you yet)

- **Gate 4** (agents): sign the loader with your Boot Signer in the emulator
  and add the remaining emulator tests.
- **Gate 5** (agents): the TPM approval rules, tested in a software TPM only.
- **Gate 6** (you + agents): add a second way to unlock the storage next to
  the current one. Gets its own written steps and approval.
- **Gate 7** (you): the single attended hardware boot with Secure Boot on.
  Gets its own written checklist and approval; nothing above prepares it
  silently. Before that checklist, an agent or you can run the pre-flight
  check in a normal terminal:

  ```bash
  bash scripts/trust1_gate7_preflight.sh
  ```

  *What it does:* checks the things that can be checked before any restart:
  the TPM and Secure Boot state can be read, every tool the stick and the
  snapshot steps need is present, the locked spare and the encrypted storage
  folder are where this page says, no secret key sits next to the spare, and
  the recovery image (on the stick if it is plugged in and open, otherwise a
  private test copy) has every tool. *Changes:* nothing; it needs no
  password and cleans up its own temporary folder. Takes about 5 seconds.
  *You should see:* a list of `PASS` lines, a `NOT CHECKED` list (things only
  your restarts or later gates can prove), and last
  `GATE7_PREFLIGHT: PASS`. Any `FAIL` line: stop and hand the output to the
  orchestrator.
- **Gates 8-9**: observation period, then retiring the old rules only with
  your approval.
