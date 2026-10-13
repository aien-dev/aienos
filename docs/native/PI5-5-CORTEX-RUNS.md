# PI5-5 Cortex memory on the Raspberry Pi 5 (qualification record)

Tier: PI5-CORTEX-QUALIFICATION. Image: `make pi5-fact` (the PI5-4 `pi5-unlock-card` image, production-class
Store opened by the Slot 1 recovery secret, plus the Cortex fact stage). It never builds on the TEST-key
store tier. Hardware runs F1 to F3 are NOT_RUN in this document until the Pi is free; the host proof is below.

## What is reused

- Cortex store: the canonical Omega store (`third_party/omega/rx_cortex.c`, wrapper `svc/cortex_store.c`) over
  the sealed Store journal (`svc/cortex_journal.c`, chunks of kind `CJ`, one record = one sealed transaction).
  This is the path the service lifecycle's `remember` and `facts` verbs use (`core/lifecycle.c`, QEMU rows 179
  to 181 of `native/kernel/GATES.md`). The record is the same: one `CX_CLAIM` about subject 0 (the owner), text
  packed into 64-bit words, tag = byte length, `t` = record count + 1, generation = the Store generation the
  append commits. The two shared constants (`CK_CX_SUBJECTS`, `CK_CX_FACT_SUBJECT`) now live in
  `svc/cortex_journal.h` so the lifecycle and the Pi stage cannot drift.
- Store open: PI5-4 (`ck_store_pi5_unlock_run`, recovery secret from `\EFI\AIENOS\UNLOCK.REQ`).

## What is new

- `core/fact_req.[ch]`, `native/boot/efi_fact.c`: the labelled card request `\EFI\AIENOS\FACT.REQ`
  (QUALIFICATION ONLY, 512 bytes, magic `AIENFCT1`, tag `QUALIF-FACT-DATA`, one fact of 1 to 48 printable
  ASCII characters). The UEFI stub reads it before ExitBootServices; the run tool deletes it after the run.
  `scripts/pi5_fact_req.sh <out> "<fact>"` writes one.
- `svc/pi5_fact.[ch]`, hook `ck_store_pi5_fact_stage` in `svc/store_boot.c`, run right after the Store stage:
  - request present: open or create the journal (one sealed header transaction), append the fact (one sealed
    transaction), print `fact_stage: remembered id=.. t=.. store_gen=.. bytes=.. text="..."`, then read it back
    (`fact_stage: readback ...`, digest and chain checked).
  - no request: replay the journal; print `fact_stage: recalled id=.. t=.. store_gen=.. text="..."` for each fact,
    then `fact_stage: recall records=N shown=N newest_id=.. newest_store_gen=.. chain=ok`. No journal on the disk:
    `fact_stage: recall none cortex=none records=0`, nothing is created.
  - Store refused (wrong recovery secret): `fact_stage: NOTHING RECALLED: the Store is not open ...`; the journal is
    not read and a fact request in the same boot is dropped, nothing is written.
- `make pi5-fact` = `CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_FACT=1`; the Makefile refuses CK_PI5_FACT
  without both unlock flags and with CK_PI5_STORE, CK_PI5_INFER or CK_PI5_PCIE.

## Host proof (file-backed card, `dev/tests/pi5_fact_test.c`, run by `stage-test` and `stage-sanitize`)

77 checks, ASan + UBSan clean. Every boot reopens the file and starts from a cold C state. Boot 1 (card fact)
remembers `prefer short notes` and prints its Store generation; boot 2 (no request) recalls the same text at the
same generation, adds no record, chain ok; the wrong secret recalls nothing, prints no fact text and leaves the
card byte-identical (also when a fact request comes with it); the right secret afterwards recalls again; a second
fact keeps both in order; a card with no journal says `none` and creates none; the request checker refuses every
malformed layout. Mutation proof (`make -f stage.mk pi5-fact-mutants`): `CK_FACT_MUTANT_NO_APPEND` (the commit
skipped, success still reported) and `CK_FACT_MUTANT_RECALL_BLIND` (recall never reads the journal) both make the
test fail (mutants killed).

## Pi runs (PASS, 2026-10-13, Raspberry Pi 5, main dd99eda, `make pi5-fact`)

Each run is one tryboot of the hub (`~/workspace/pi5/pi5-run-fact.sh`, KLOG=1): a soft reboot into AIENOS and back, NOT a power cut. The Store partition head was zeroed before F1 (the PI5-4 Store's throwaway secret no longer exists). Secrets S and W are throwaway QUALIFICATION ONLY request files, kept outside git and deleted from the card after each run.

F1 remember (UNLOCK.REQ S, FACT.REQ "prefer short notes"):
```
store: opened generation=1 boot_count=0 prev_commit=none anchor=valid-resume
store: committed generation=2 boot_count=1
fact_stage: remembered id=1 t=1 store_gen=4 bytes=18 text="prefer short notes"
fact_stage: readback id=1 t=1 store_gen=4 text="prefer short notes"
```
F2 recall on the next boot (UNLOCK.REQ S, no FACT.REQ):
```
store: opened generation=4 boot_count=1 prev_commit=dd99eda1ec2d3e6b097bfb71a9583b153e3face7 anchor=valid-resume
fact_stage: recalled id=1 t=1 store_gen=4 text="prefer short notes"
```
F3 wrong secret W:
```
store: REFUSED proof=keyed step="recovery secret rejected (K_vol unwrap tag failed); disk not opened" rc=-2004 (RecoverySecretRejected); disk left as found, not reformatted
fact_stage: NOTHING RECALLED: the Store is not open (recovery secret missing or rejected, or the disk was refused); no Cortex was read, nothing was written
```
Limits: tryboot reset, not a power cut (a power-cut recall run is owed, done by hand); secret from the card, no TPM; the anchor shares the disk, so a whole-disk rollback is not detectable; single runs.
