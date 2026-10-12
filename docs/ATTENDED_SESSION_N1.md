# ATTENDED_SESSION_N1: the first attended service session on the physical DGX Spark

Status: PLAN (2026-10-12). Nothing in this document has run on hardware. Every
hardware row is **NOT_RUN**. Writing it changed nothing on the machine: no
reboot, no staging, no boot-variable change, no partition change, no root
command. The only commands run on the Spark while writing it were read-only
(`lsblk`, reads of `/sys/block/nvme0n1/*`), quoted where used.

Owner's words (2026-10-12): "Prepare one attended hardware session with
explicit prerequisites, stop conditions, and a known-good native recovery
path. My earlier approval of a window does not mean I am currently present."
The milestone he set: "boot the candidate, unlock it, run bounded CPU
inference, approve and remember something, restart, and recover the saved
state." Native GPU and update/rollback qualification are separate proofs.

**Verdict today: NO-GO.** Four prerequisites in section 2.2 are not met and
three of them need desk-side code first. This page says what each one is and
where it stands, so that the session can be run as written once they close.
The B7b window (`docs/campaigns/B7B-PHYSICAL-BOOT-PREP.md`) is a different,
smaller session and does not depend on them.

Related, read first: `docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md`,
`docs/BOOT_HANDOFF_CONTRACT.md` section 7, `docs/campaigns/B7B-PHYSICAL-BOOT-PREP.md`,
`docs/native/PREFLIGHT-AND-RECOVERY.md`, `docs/RECOVERY_MEDIA_MACHINE1.md`,
`docs/NATIVE_IMAGE_SLOTS.md`, `native/kernel/GATES.md` LIFECYCLE and INFER
sections, aien-architecture `CURRENT_EXECUTION_PLAN.md` (native v1 addendum,
gates N1 to N7).

## 1. Purpose and the exact proof

One attended window, two native boots of the same release-candidate image on
the same disk, with Linux returning between them by the firmware's one-time
`BootNext` rule.

| step | what is proved | gate it feeds (aien-architecture N1 to N7 ledger) |
|---|---|---|
| boot the candidate | the service image starts on the Spark, its console is readable and takes operator input | N1 ("boot is observable and recoverable; operator input and abort work") |
| unlock | `unlock <64-hex recovery secret>` formats a production Store on a blank AIENOS partition (genesis) and opens it | N1 (operator input), N2 (real owner state) |
| bounded CPU inference | `prompt <text>` generates at most 16 tokens on the CPU from the model read off the boot disk; a second prompt is cancelled between steps | N3 ("supplies a new prompt, sees bounded generated output ... cancels another request") |
| approve and remember | `approve` commits the reply as one sealed Store object; `remember <text>` appends one fact to the Omega Cortex journal on the Store | N3 ("approves a useful local artifact"), N2 ("committed Store objects") |
| restart | `shutdown` runs the stop order and resets; Linux comes up (BootNext consumed); `BootNext` is armed once more and the machine reboots into the same image | N1 (rollback evidence), N2 (one physical cold start) |
| recover the saved state | after `unlock`, `recall` returns the approved reply and `facts` returns the fact from the disk; the fact is never typed in this boot | N3 ("cold-boots to recover the approved artifact and a memory-only fact") |

What this session does **not** prove, stated so nobody reads more into it:

- N1 also needs "bounded B7b result" (the SMMU probe window, a separate
  session). This session gives N1 its operator-input and rollback part only.
- N2 also needs "the declared fault cases" (power loss mid-commit, corrupt and
  stale state). One clean cold start is not those.
- N3 is the gate this session can close, and only if every expected line in
  section 3 is seen and the verifier agrees (N6 rule).
- Nothing about N4 (GB10), N5, N6 or N7. The return path in this session is
  the Linux `BootOrder`, which N7 says is insufficient.

## 2. Prerequisites

### 2.1 Pins and the image

| # | prerequisite | state on 2026-10-12 | source |
|---|---|---|---|
| R1 | One release candidate pinned: aienos, omega, physics, aien-sovereign-core, aien-architecture commits recorded as RC-1 in aien-architecture `CURRENT_EXECUTION_PLAN.md`. The session boots exactly that aienos commit. | being recorded (aien-architecture branch `native-v1/gates-ledger-2026-10-12`) | Drake decision 3, 2026-10-12 |
| R2 | The service image built from the RC-1 aienos commit twice, byte-identical, digests written to a `SHA256SUMS` kept with the RC-1 record, together with source revision, toolchain and inputs (Drake decision 7) | NOT BUILT: no build recipe exists yet (R2 depends on B2) | `scripts/native_package.sh` (aienos#322) does this for the slot package; the staging scripts each build twice and compare (`scripts/stage_one_time_boot_ck_b7b.sh` header) |
| R3 | The model file pinned and immutable: `Llama-3.2-1B-Instruct-Q4_K_M.gguf`, sha256 `3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1`, `chattr +i` before `MODEL.MAP` is made | procedure exists for the one-shot inference image | `scripts/stage_one_time_boot_ck.sh` lines 2-40 and `pinned_sha` |
| R4 | Owner files for a hardware staging image (`CK_OWNER_PUBKEYS`, `CK_MACHINE_ID`); the TEST-FIXTURE files are refused for a boot | NOT DONE: the owner key ceremony is decided (MacBook, Wi-Fi off) but the key is generated only when Drake says he is present | `native/kernel/Makefile` lines 13-18; Drake decision 1; `docs/OWNER_KEY_CEREMONY.md` (in preparation by another worker, not merged) |
| R5 | The 64-hex recovery secret written on paper, generated offline, never typed into any chat, file or terminal on the Spark except the AIENOS console | NOT DONE; how it is generated and backed up must be written down before the window (if the ceremony document does not cover it, this is an open item) | ADR 0017 Slot 1 (`docs/adr/`), `native/kernel/GATES.md` row 170 (secret hygiene) |

### 2.2 Blocking prerequisites (each one alone makes today a NO-GO)

**B1. Operator input on the Spark's console.** Half solved at the desk
(aienos#328); the other half is an operator step that needs a cable.

Verified on the Spark on 2026-10-12 (read-only, Linux running, no write):
the ACPI SPCR (80 bytes, revision 2) names interface type **0x01** (16550
subset, Linux `ACPI_DBG2_16550_SUBSET`), a memory-mapped UART at
**0x16A00000** with 32-bit dword-spaced registers (GAS access size 3),
interrupt GSIV 878, baud byte 7 (115200). Linux drives the same port as
`ttyS0` (`console=ttyS0,921600`, device `MTKI0511:00`, ACPI `\_SB_.COM1`,
`io_type=3` 32-bit MMIO, `iomem_reg_shift=2`, `uartclk=26000000`).
Before aienos#328 the kernel accepted SPCR types 0x00 and 0x12 only, so by
the code (not observed on the machine) it had no serial console on the
Spark at all, and the lifecycle would have stopped with `REFUSED no
operator input`.

Implemented by aienos#328 (desk, host-tested; `native/kernel/GATES.md`
rows 167c-167f): the kernel selects that 16550 from the SPCR for output and
for operator input, reads it with 32-bit accesses, polls it (no
interrupts) between lifecycle steps and between generation steps (so
`cancel` works), refuses overlong lines and lines with a receive error
(overrun, parity, framing, break) whole, and prints `lifecycle: ready ...
(operator input: serial 16550 at 0x16a00000, polled)`. With no supported
UART it prints `lifecycle: REFUSED console input unsupported on this
platform` and stops. QEMU cannot run the 16550 path (QEMU virt has only a
PL011); the PL011 path passes the full lifecycle QEMU gate.

Still an operator step and UNVERIFIED: (1) whether the Spark's 16550 is
wired to a connector you can reach (no documented external serial port;
`docs/HARDWARE_TEST_RIG.md` plans the hub Pi's 3.3 V GPIO UART); (2) the
line speed AIENOS inherits, because the kernel never reprograms the UART
(try 115200 from the SPCR first, then 921600, 8N1, no flow control).
**A prompt on the screen does not prove input.** What proves it: the bytes
you type echo back on the serial terminal, `status` is answered with a
`lifecycle: state=... store=...` line, and `shutdown` is answered with
`lifecycle: shutdown accepted`, the `lifecycle: stop order ...` line and
the final report. If no reachable serial connector exists, the remaining
path is the local USB keyboard bound to the service lifecycle (the keyboard
and xHCI code exist in `native/kernel/dev/usb_kbd.c`, CONSOLE gate, in a
TEST-only image), which is a separate desk cut not done yet.

**B2. A hardware service image with resident CPU inference.** The milestone
image is `make full CK_SERVICE=1 CK_HARDWARE_STAGING=1 CK_INFER_LIB=...`.
The Makefile refuses it: "CK_INFER_LIB (inference probe, QEMU gate only)
cannot be combined with CK_HARDWARE_STAGING" (`native/kernel/Makefile` lines
264-266). `native/kernel/GATES.md` INFER section says the same: "the hardware
service image has no inference yet (the MODEL.MAP boot-disk source is the
hardware path)". The kernel code already reads the model from the boot disk
when the stub found `MODEL.MAP` (`native/kernel/core/infer.c` ck_infer_run,
source 1; aienos#254, merge `25836ba`), but the resident session in a service
image has only run on the TEST-ONLY fw_cfg source with TEST keys (LIFECYCLE
rows 174-176). No staging script stages a `CK_SERVICE` image (only
`scripts/qemu_ck_lifecycle_test.sh` names `CK_SERVICE`). Needed, desk-side:
lift the refusal for the `CK_SERVICE` + `MODEL.MAP` combination only (fw_cfg
stays refused in hardware images), a QEMU gate that runs this session's
script end to end on the production service image with the model on the
disk (two boots, same disk), and a staging variant
(`stage_one_time_boot_ck_service.sh`, same shape as the B7b variant) that
builds twice, makes `MODEL.MAP`, stages once and sets `BootNext` once.

**B3. An AIENOS partition on the Spark's NVMe.** The kernel writes only
inside the one GPT partition of type `38DAAC89-5EAD-4B40-8B1E-3687A7418061`;
otherwise it prints `disk: no AIENOS partition, refusing writes` and the
Store reports `no boot disk` (`native/kernel/README.md` lines 439-450). The
Spark has one NVMe, `nvme0n1`, with exactly two partitions: the ESP
(`nvme0n1p1`, start 2048, 610304 sectors) and the Linux root ext4
(`nvme0n1p2`, start 612352, 8000961167 sectors). The disk has 8001573552
sectors, so after the root partition only the 33 sectors of the backup GPT
remain (read 2026-10-12 from `/sys/block/nvme0n1/`). There is no room for an
AIENOS partition without shrinking the Linux root filesystem, which can only
be done with it unmounted (ext4 does not shrink online; whether the recovery stick carries the tools is not checked), and which changes the
Linux disk. That conflicts with "Linux side left untouched" and needs its
own owner decision and its own attended window, with a verified backup
first. Whether the Spark has a free slot for a second NVMe is UNKNOWN. Until
B3 is decided and done, `unlock` cannot open anything on the Spark.

**B4. Owner files (R4) and the recovery secret (R5).** Both are owner steps
with Drake present.

### 2.3 Machine and people

| # | prerequisite | how it is checked |
|---|---|---|
| M1 | Drake at the machine for the whole window, display and USB keyboard attached, with a fresh "go" given in the window (an earlier yes does not carry over) | said aloud and written in the notes with the time |
| M2 | Window: two hours, start time written in advance; nothing else uses the machine | the notes |
| M3 | Quiet flag held for the window, raised only with Drake's OK: `quietlock hold --owner attended-n1 --minutes 150 --reason "attended N1 session" -- <the staging command>`; `quietlock check` clear before it | `quietlock check` output saved |
| M4 | Recovery stick `AIENOSRECOV` plugged in and listed (`Boot0004`), verified (section 5) | `efibootmgr` output; it is NOT plugged in on 2026-10-12 (`/dev/disk/by-label` shows only `EFI` and `root`) |
| M5 | Console capture: one phone or camera on the screen for both boots (the screen is the observation channel); serial capture only if B1 is solved by a wired serial link; a witness or a time-stamped recording; paper for times and exact words | the recording and the notes |
| M6 | Linux side untouched apart from the one-time boot: the staging script writes only `\EFI\AIENOS` on the ESP, creates one boot entry outside `BootOrder` and sets `BootNext` once; `BootOrder` unchanged (`docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md` sections 3.2 and 5) | `scripts/verify_native_rollback.sh --capture-pre/--capture-post/--verify` |
| M7 | Secure Boot recorded, never changed (OFF since 2026-10-01, owner decision) | `scripts/native_boot_preflight.sh` records it |
| M8 | Preflight P1 to P13 of `docs/campaigns/B7B-PHYSICAL-BOOT-PREP.md` section 3 passed within 24 hours on the RC-1 commit, with the service staging script's `--dry-run` in place of P12, plus `bash scripts/qemu_ck_lifecycle_test.sh` and the new B2 gate PASS at RC-1 | outputs saved with the commit and digests |

## 3. The session, step by step

Drake (or the witness) reads each step aloud. "Expected" lines are taken from
the QEMU gate regexes in `scripts/qemu_ck_lifecycle_test.sh` (rows named) and
`native/kernel/GATES.md`; they are **expected, not observed** on hardware.
Generation numbers hold only if the verbs are typed in exactly this order.
The secret is echoed as 64 `*` (row 170); `<S>` below is the paper secret.

### Boot 1 (genesis)

| # | do | expected on screen | row |
|---|---|---|---|
| 1 | In Linux: `sudo scripts/stage_one_time_boot_ck_service.sh --apply` (B2; does not exist yet). Read its output aloud. | ends with `BootNext` set to the new entry, `Boot0004 AIENOSRECOV` still listed, `BootOrder` unchanged, two equal image digests equal to the RC-1 `SHA256SUMS` | M6 |
| 2 | `sudo reboot`. Start the clock. | firmware, then `model_map: ok len=807694368 extents=<n> sector=512 disk=<guid>` (stub, before ExitBootServices; length per aienos#254), then `kernel: alive` | INFER disk mode |
| 3 | wait | `disk: gpt ok primary+backup crc32 ... aienos_index=<n> first_lba=<n> ...` (B3); `store: REFUSED proof=keyed step="production Store key source" rc=-2002 (service image stays LOCKED ...`; `store: service lifetime: Store LOCKED, NVMe stays bound for ...`; `infer: resident open rc=0 tensors=147 vocab=128256 layers=16 kv_capacity=64 max_new=16 max_prompt_bytes=256 heap_reserve_kib=64 ...`; `lifecycle: ready state=locked store=locked (operator input: <source>)` and the `> ` prompt | 160, 174 |
| 4 | type `status` | `lifecycle: state=locked store=locked pending=- requests=1 continuity=none` | 161 |
| 5 | type `unlock <S>` | `> unlock ****...` (64 stars); `store: blank disk (all-zero anchor + Store head): formatted production store`; `store: key source=recovery-keyslot genesis=1 ...`; `store: committed generation=2 boot_count=1`; `store: security manifest sequence=1 generation=2 keyslot=bound previous=genesis`; `store: unlock ok source=recovery-keyslot slot=1 genesis=1 generation=2 boot_count=1`; `continuity: PROVISIONED agent=<64 hex> incarnation=1 sequence=1 ...`; `allen: GENESIS subject=<64 hex> sequence=1 ...`; `lifecycle: unlock ok state=ready` | 168, 171, 183 |
| 6 | write down the first 16 hex of `agent=` | (the notes) | 172 |
| 7 | type `prompt What is the capital of France?` | `lifecycle: generating prompt="What is the capital of France?" (cancel stops it between steps)`; then `lifecycle: reply ids=791 6864 315 9822 374 12366 13 128009 tokens=8 prompt_ids=17 steps=25 us=<n>`; `lifecycle: reply pending state=serve proposed="reply: The capital of France is Paris." (approve | deny | cancel)` | 174 |
| 8 | type `approve` | `lifecycle: approve committed gen=4 id=<8 hex> state=ready` | 164, 174 |
| 9 | type `prompt Say hello.` then, as soon as `generating` appears, `cancel` | `lifecycle: generation cancelled steps=<n> prompt_ids=<n> produced=0 us=<n> state=ready`, or, if the reply was already complete before `cancel` arrived (the Spark CPU may be fast enough), `lifecycle: cancelled state=ready` (the pending reply dropped, `native/kernel/core/lifecycle_fsm.c` CK_LC_V_CANCEL); both are a cancelled request, write down which one | 165, 175 |
| 10 | type `remember prefer short notes` | `lifecycle: cortex open records=0 chunks=1 journal_bytes=32 store_gen=5 ... chain=ok`; `lifecycle: remembered id=1 t=1 store_gen=6 bytes=18 text="prefer short notes"` | 180 |
| 11 | type `facts`, then `recall`, then `evidence` | `lifecycle: facts records=1 shown=1 journal_bytes=192 chain=ok`; `lifecycle: recall gen=4 kind=reply ...text="aienos.reply.v1 ... The capital of France is Paris."`; one `lifecycle: evidence ...` line with `approved=1`, `prompts=2 replies=1 gen_cancelled=1`, `remembers=1 facts=1` | 175, 176, 180 |
| 12 | type `shutdown` | `lifecycle: shutdown accepted ...`; `lifecycle: cortex closed ...`; `infer: resident close rc=0 ...`; `lifecycle: stop order store=closed nvme=released state=stop requests=<n>`; `stage lifecycle: ok rc=0`; `report_kind: final`; the screen hold; reset | 167, 176 |
| 13 | do nothing | Linux comes up (BootNext was consumed, `BootOrder` unchanged) | M0 rule |

### Between the boots (Linux)

| # | do | expected |
|---|---|---|
| 14 | `sudo scripts/verify_native_rollback.sh --capture-post evidence/<session>/post_boot1.json`, then `--verify` against the pre capture | the ten invariants PASS; `BootNext` absent; `BootOrder` as before |
| 15 | Arm the same entry once: `sudo efibootmgr --bootnext <entry printed in step 1>` (the only boot-variable write; never `--bootorder`). Do not rebuild or restage: the image and `MODEL.MAP` stay as staged, the model stays immutable. | `efibootmgr` shows `BootNext: <entry>` |
| 16 | `sudo reboot` | |

### Boot 2 (cold resume)

| # | do | expected | row |
|---|---|---|---|
| 17 | wait | as steps 2 and 3, `lifecycle: ready state=locked store=locked`; no `store: blank disk` line | 169 |
| 18 | type `unlock <S>` | `store: opened generation=6 boot_count=1 prev_commit=<hex> anchor=valid-resume`; `store: committed generation=7 boot_count=2`; `store: security manifest sequence=2 generation=7 keyslot=bound previous=linked`; `store: unlock ok source=recovery-keyslot slot=1 genesis=0 generation=7 boot_count=2`; `allen: RESTORED subject=<hex> sequence=1 ...`; `continuity: RESUMED agent=<same as step 6> incarnation=2 sequence=2 ...`; `lifecycle: unlock ok state=ready` | 169, 172, 183 |
| 19 | type `status` | `... continuity=resumed agent=<first 16 hex from step 6> incarnation=2 subject_seq=1` | 172 |
| 20 | type `recall` | `lifecycle: recall gen=4 kind=reply id=<same id as step 8> ...The capital of France is Paris.` | 175 |
| 21 | type `facts` (never `remember` in this boot) | `lifecycle: cortex open records=1 chunks=2 journal_bytes=192 store_gen=8 ... chain=ok`; `lifecycle: fact id=1 t=1 store_gen=6 text="prefer short notes"`; `lifecycle: facts records=1 shown=1 journal_bytes=192 chain=ok` | 181 |
| 22 | type `evidence`, then `shutdown` | evidence with `recalls=1 facts=1 remembers=0`; the stop order as step 12; reset; Linux returns | 167, 181 |
| 23 | In Linux: capture post, `--verify` | ten invariants PASS | M6 |

Timing on hardware is UNKNOWN for every step. QEMU under TCG needs about 15
minutes for step 7; the Spark's CPU is expected to be far faster, not measured.

## 4. Stop conditions

Two kinds. **Soft stop**: the console still answers; type `shutdown`, let
the stop order finish, do not continue to the next step, go to section 6.
**Abort**: the console does not answer or the screen shows a panic; act as
below. Any one of these stops the session:

| # | condition | kind |
|---|---|---|
| S1 | no `kernel: alive` within 300 s of the firmware leaving its own screen (the stub reads about 0.8 GB through firmware Block I/O first; its duration on the Spark is UNKNOWN) | abort |
| S2 | nothing new on screen for 60 s at any time outside generation; during generation (after `lifecycle: generating`), nothing for 600 s | abort |
| S3 | `Secure Boot Violation` or any firmware refusal | firmware returns to `BootOrder` by itself; record, never bypass |
| S4 | any `report_kind: panic` or `report_kind: fault`, any `panic:` line, any handoff refusal line of `docs/BOOT_HANDOFF_CONTRACT.md` section 6 | abort (the kernel resets itself) |
| S5 | `lifecycle: REFUSED console input unsupported on this platform` or `REFUSED console input not ready`, or no echo / no answer to `status` on the serial terminal | a refusal: soft (the image already stopped); no echo or no answer: abort. Either way B1 is not solved |
| S6 | `disk: no AIENOS partition, refusing writes` or `store: ... no boot disk` | soft: B3 is not solved |
| S7 | any `store: ... REFUSED` or `store: unlock REFUSED` line after `unlock <S>` (wrong secret, keyslot, SecurityManifest, rollback anchor), any `continuity: REFUSED`, `degraded` or `RESUMED_READONLY` | soft; never retype a different secret in the same window |
| S8 | `store: blank disk ... formatted` in boot 2 (the Store did not survive) | soft; a finding against N2 |
| S9 | `infer: ingest FAIL`, `infer: resident open rc=` not 0, a model sha256 mismatch, or `infer_source_mode: TEST-ONLY` in a hardware image | soft |
| S10 | a reply whose ids differ from step 7, or `recall`/`facts` text that differs from what was approved/remembered | soft; record verbatim (a finding, not a retry) |
| S11 | any line not in the tables of section 3, or a number that differs from them | soft; write the time and the exact words |
| S12 | anyone says "stop", or less than 30 minutes of the window are left before boot 2 | soft |

**What abort means physically** (from `docs/campaigns/B7B-PHYSICAL-BOOT-PREP.md`
section 7): touch nothing for 60 s, then hold the chassis power button until
the machine is off, wait ten seconds, press it again. `BootNext` was consumed
before the image started, so the firmware boots `BootOrder` (Linux, `0001`).
Nothing on the Linux side and no boot variable is changed by the candidate
(`docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md` section 5). Plainly: the AIENOS
partition may hold Store generations committed before the abort; that is by
design (every commit is durable when the line prints) and is recorded, not
repaired. A power cut during a commit is one of N2's declared fault cases and
is not claimed by this session. Never during the window: run `--apply` a
second time, change `BootOrder`, change firmware settings or Secure Boot, or
"fix" anything without a new, separate go from Drake.

## 5. Recovery path for this session

**What exists today.**

1. The firmware's one-time `BootNext` rule back to the unchanged Linux
   install (`docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md`; C kernel as the BootNext
   candidate, QEMU gate M0_ROLLBACK rows 42-46 PASS, aienos#273 merge
   `61bd76a`; log `evidence/ck_rollback_qemu_5deb3971...log`). On hardware
   NOT_RUN for the C kernel.
2. The recovery stick `AIENOSRECOV` (1 GB, vfat UUID `3511-E686`, firmware
   entry `Boot0004`): a Linux-based recovery environment that runs from RAM,
   mounts the internal root and ESP read-only and collects evidence
   (`docs/RECOVERY_MEDIA_MACHINE1.md`). Last physical boot recorded
   2026-09-25 with Secure Boot ON (`evidence/recovery_boot_machine1.md`); it
   has not been booted since Secure Boot was turned OFF on 2026-10-01
   (UNVERIFIED that it still boots; preflight P13). It is not a key backup.

**What does not exist yet.** The known-good AIENOS recovery image (P11 cut 4
in `docs/NATIVE_IMAGE_SLOTS.md` section 6, item 4: "the same loader plus a slot
image on recovery media built by our tools, for the dual-invalid case") is
not built, and the slot loader (cut 2a) is not merged.

**So, for this session, the recovery path is the firmware BootNext rule back
to the unchanged Linux install, plus the Linux recovery stick if Linux does
not come up.** That is a Linux recovery path. It is acceptable as the safety
net of a development session and it is explicitly insufficient for N7. If
Linux does not come up: firmware boot menu, pick `AIENOSRECOV`, mount root
and ESP read-only, run the collector exactly as in
`docs/RECOVERY_MEDIA_MACHINE1.md`; any repair needs a new go from Drake.

## 6. Evidence and where it goes

| evidence | where |
|---|---|
| camera recording and photos of both boots | offline only, `~/aienos-private-evidence/` (phone photos carry location data; never committed) |
| witness notes with times and exact screen words; the transcript of every screen line from section 3 | `evidence/attended_n1_<date>/notes.md` in aienos |
| staging script output, `efibootmgr` before and after each boot, `pre`/`post` captures and both `--verify` verdicts | `evidence/attended_n1_<date>/` |
| RC-1 pins, image `SHA256SUMS`, toolchain and inputs record | the same folder, and the RC-1 entry in aien-architecture `CURRENT_EXECUTION_PLAN.md` |
| physical rows (new rows beside LIFECYCLE 160-185, labelled "Machine 1", never replacing the QEMU status) | `native/kernel/GATES.md`, after the session, by whoever records it |
| one result note per gate touched, observed facts with limits | aienos#34 (N3 inference), #35 (memory across reboot), #31 (storage), #32 (unlock); ledger update on aien-architecture#190 |

A physical PASS is claimed only for lines that were seen. Anything not seen
stays NOT_RUN; any deviation is a finding.

## 7. Pre-flight checklist for Drake (plain words)

Before the day:

1. The four missing pieces are done and merged: typing commands into AIENOS
   (B1), the AIENOS build that has the language model and the safe-box
   together (B2), a separate area on the drive for AIENOS's safe-box (B3,
   your decision first, because it means shrinking Linux's area), and your
   owner key plus the long unlock code on paper (B4).
2. One frozen set of versions ("RC-1") is written down, and the AIENOS build
   made from it twice came out identical.
3. The recovery stick has been booted once since Secure Boot was turned off,
   and Linux came back.

On the day, before anything is touched:

4. You are at the Spark with screen and keyboard, a camera on the screen, and
   paper. You have two free hours.
5. The recovery stick is plugged in.
6. The unlock code is on paper in front of you and nowhere else.
7. The pre-checks have all passed today; nobody else is using the machine.
8. Everyone can say the stop rule: if the screen freezes for a minute or
   shows a crash, wait one more minute, hold the power button until it turns
   off, wait ten seconds, turn it back on. Linux comes back by itself.
9. You say "go" out loud and the time is written down. Without that, nothing
   starts.
