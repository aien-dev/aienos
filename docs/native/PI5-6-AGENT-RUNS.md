# PI5-6 final cut: a resident model's bounded reply, persisted in the sealed Store, recovered after a reboot (Raspberry Pi 5)

Tier: PI5-AGENT-QUALIFICATION, QUALIFICATION ONLY while the recovery secret comes from the card request file
(`\EFI\AIENOS\UNLOCK.REQ`, a throwaway secret, PI5-4 cut 2). Image: `make pi5-agent`
(`CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_PI5_AGENT=1 CK_INFER_LIB=...`). Hardware runs G1 to G3 are NOT_RUN in this document
(the Pi was busy with another job); the host proof and the QEMU regressions are below.

## What is reused (no parallel format)

- Store object: the lifecycle's approved-reply object, kind `0x5231` ('R1'), `aienos.reply.v1\nprompt: <prompt>\nreply: <text>\n`
  (core/lifecycle.c `commit_task`, QEMU rows 174 to 176 and 205 to 206 of native/kernel/GATES.md). The builder now lives in
  `core/reply_obj.h` and `core/lifecycle.c` calls it; the host test pins its output to the literal the lifecycle wrote before.
  The agent object adds a trailer after the reply: `model: <64 hex sha256>\nids: <token ids>\n`. A lifecycle reply has no trailer.
- Inference: the resident path of core/infer.c (`ck_infer_run` ingest + SHA-256 + `resident_open`, `ck_infer_prompt`,
  `ck_infer_resident_close`), the same functions the QEMU service image uses. `CK_INFER_RESIDENT` is now also set by the Pi agent image.
- Model source: MODEL.MAP on the ESP naming the raw partition `AIENOS-MODEL` (PI5-6 cut 3), read by the UEFI stub. SDOT path, 1.20 tok/s.
- Store open: PI5-4 (`ck_store_pi5_unlock_run`, Slot 1 recovery secret from UNLOCK.REQ). Hook shape: PI5-5 (`ck_store_pi5_fact_stage`).

## What is new

- `svc/pi5_agent.[ch]`, hook `ck_store_pi5_agent_stage` in svc/store_boot.c, run right after the Store stage and before the Store is released:
  - Store not open (wrong secret): `agent: NOTHING RECOVERED ...`, `AIENOS_PI5_AGENT: NOSTORE`. The model is not hashed, no session is opened,
    nothing is written.
  - The Store holds an agent reply for the fixed prompt: RECOVER. The object is read back through the sealed Store (`ss_read`), parsed
    from its end, and checked against the golden token ids, golden text and golden model digest. It never uses the model, even when MODEL.MAP is on the card.
  - No reply yet: GENERATE. Prompt `What is the capital of France?`, cap N = 16 tokens (`SESS_MAX_NEW`; the reply is 8 tokens ending at EOT).
    The reply is committed only if the chat-template head is 128000,128006,882,128007, the 8 ids equal llama.cpp's
    (791 6864 315 9822 374 12366 13 128009), the text is `The capital of France is Paris.` and the model digest is the golden one. The session is
    closed (all 256 MiB of heap returned) before the commit. The reply is read back from the Store the way a cold boot reads it.
  - Both ways print the same line: `agent: reply store_gen=G object_sha256=H model_sha256=M tokens=N ids=... text="..."`, so G2's line must equal G1's.
- Prompt-token check restored (it was dropped on the Pi when the one-shot probe was skipped): the new Rust call
  `aienos_infer_session_prompt_ids` (crates/aienos-infer-kernel/src/session.rs) gives the kernel the prompt ids; `session_request` in core/infer.c checks the
  first four against `expect_ids` (`infer: session prompt=2 prompt_head=... expect=match`), so `make pi5-infer` and the QEMU infer gate judge it,
  and `ck_infer_prompt` fills `prompt_head` for the agent. scripts/qemu_ck_infer_test.sh checks the new line and has three new self-test mutations.
- The watchdog is petted after every generation step in `ck_infer_prompt` (no-op on every board except the Pi).
- Makefile: `CK_PI5_AGENT=1` needs `CK_PI5_UNLOCK=1 CK_PI5_UNLOCK_CARD=1 CK_INFER_LIB`, refuses CK_PI5_STORE, CK_PI5_INFER, CK_PI5_PCIE, CK_PI5_FACT,
  CK_SERVICE, CK_HARDWARE_STAGING and CK_TEST_FWCFG_ARTIFACTS (and CK_PI5_INFER, CK_PI5_PCIE, CK_PI5_FACT refuse it). Own OUT
  `target/native-kernel-pi5-unlock-card-agent`. scripts/ck_pi5_build_check.sh covers all of it.

## Order: unlock the Store BEFORE the model is hashed and run

Decision: Store first, model second, commit last.
- A wrong or missing secret fails in milliseconds, before the 5.1 s model hash, the 0.3 s session open, the 256 MiB heap and the 17 s of generation. Nothing
  slow ever runs for a boot that could not keep its result. The host test counts the calls: wrong secret = zero model calls.
- The boot that only needs to recover (G2) never touches the model. It needs no heap and no hash: the boot is the Store open plus one object read.
- The mode (recover or generate) is decided from what the Store holds, never from whether the model is on the card, so a leftover MODEL.MAP cannot cause a second reply.
- Watchdog (15 s PM watchdog, petted at boot stages, every 16 MiB hashed and every generation step): the unlock is one short stage; the only
  long stretches are the hash (pet per 16 MiB) and the steps (pet per step, the longest step is the 0.9 s of a token). Nothing waits on the SD card for long.
- Failure modes. Power loss during generation: the Store is open but no transaction is in flight, so the card holds exactly what it held. A reply that is not golden, a refused or cancelled prompt, a
  missing model, or a digest mismatch: nothing is committed (host test: the next boot still says NOTHING GENERATED). Power loss during the commit: one sealed transaction (the Store's own crash rule), the
  object is either whole or absent. The cost of this order: the Store (about 2 MiB of heap and its 1.1 MiB image) is resident during generation, and the SD card is idle for about 30 s between the unlock and the commit.
- The other order (model first, as the QEMU service image does after its Store stage, or as `make pi5-infer` does before it) would spend the 30 s and the 256 MiB, then learn the secret was wrong.

## Memory budget (Pi 5, 8 GB class board)

Measured values are from the PI5-4 and PI5-6 runs; the agent image's own run is G1 (NOT_RUN).
| item | MiB | source |
| --- | --- | --- |
| free after boot, no model on the card | 7033.6 (7375265792 B) | pi5-unlock-a `memory:` line |
| model, reserved by the stub (807694368 B, plus rounding) | 770.6 | pi5-infer-b: 6567268352 B free with it, 807997440 B less |
| free with the model, at the start of the agent stage | 6263.0 | pi5-infer-b `memory:` line |
| inference heap (65536 frames), returned at close | 256.0 | core/infer.c HEAP_BYTES, `frames_returned=65536` |
| inside the heap: session open / peak | 22.4 / 24.1 | pi5-infer-b `heap_used_kib=22900`, `heap_peak_kib=24695` |
| Store stage heap use (64 MiB kernel heap, peak) | 2.0 | pi5-unlock-a `mm_usage heap_min_free` |
| agent image .bss (all static buffers, 32 KiB of them the agent's) | 1.1 | `size` of aienos-ck.elf |
| free during generation (6263.0 - 256.0 - 2.0 - 1.1) | about 6004 | arithmetic |
| free on the recovery boot (no model on the card, no heap) | about 7030 | arithmetic |
Model + heap + Store = about 1030 MiB, 14.6 percent of the memory the kernel owns. The 256 MiB heap is 10 times the 24.1 MiB the session peaks at (a deliberate margin, unchanged from the proven pi5-infer image).

## Host proof

`make -C native/kernel -f stage.mk pi5-agent-test pi5-agent-sanitize pi5-agent-mutants` (run by `stage-test`, `stage-sanitize`): dev/tests/pi5_agent_test.c, 120 checks,
ASan and UBSan clean. A file stands in for the card, every boot starts from a cold C state, the inference unit is a stub (a real model cannot run on the host); the stage code under test is the real svc/pi5_agent.c.
It proves: the reply object equals the lifecycle's bytes and adds only the trailer; boot 1 generates, closes, commits once and reads back; boot 2 (same secret, no model) prints exactly boot 1's `agent: reply` line (same Store generation, same object digest) with
zero model calls, also when the model is present; wrong secret: nothing recovered, zero model calls, card byte-identical, and the right secret afterwards recovers again; eight non-golden generations (wrong id, wrong head, wrong text, wrong model digest, refused prompt, cancelled prompt,
model vanished, too many tokens) commit nothing; no reply and no model is NOMODEL; a lifecycle reply for the same prompt and a reply for another prompt are ignored; a stored non-golden reply is reported FAIL and is never regenerated over.
Mutation proof (each TEST-ONLY mutant must make the test fail; all six killed): NO_COMMIT (commit skipped, success reported), RECOVER_BLIND (recovery never reads the Store), NO_GOLDEN_CHECK, NO_PROMPT_CHECK, RECOVER_NO_CHECK, MODEL_FIRST (model touched before the Store check).
Regressions: `make -C native/kernel test`; `scripts/ck_pi5_build_check.sh`; the QEMU infer gate (`scripts/qemu_ck_infer_test.sh`, PASS, includes the restored prompt-head check) and the QEMU lifecycle gate (`scripts/qemu_ck_lifecycle_test.sh`, the reply object path).

## Pi runs (PASS, 2026-10-13, Raspberry Pi 5, main 5429602, `make pi5-agent`)

Each run is one tryboot of the hub (`~/workspace/pi5/pi5-run.sh`, KLOG=1): a soft reboot, NOT a power cut. Same card and secret S as the PI5-5 runs (Store generation continues). MODEL.MAP was placed for G1 and G3 and removed from the ESP after each (every image's stub reads it).

G1 generate, check golden, commit:
```
store: opened generation=5 boot_count=2 prev_commit=dd99eda1ec2d3e6b097bfb71a9583b153e3face7 anchor=valid-resume
agent: generated tokens=8 prompt_ids=17 steps=25 us=16946950 prompt_head=128000,128006,882,128007
agent: reply store_gen=7 object_sha256=07d15b3d26726090494b0d033f6a955d88e4b9a1ae4322130459297db952989c model_sha256=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1 tokens=8 ids=791 6864 315 9822 374 12366 13 128009 text="The capital of France is Paris."
agent: committed store_gen=7
AIENOS_PI5_AGENT: GENERATED PASS
```
G2 recover on the next boot (no MODEL.MAP; no `model:` or `infer:` line in the log):
```
store: opened generation=7 boot_count=3 prev_commit=5429602193cfc5ab79b05c0111b0cbad36e74fed anchor=valid-resume
agent: reply store_gen=7 object_sha256=07d15b3d26726090494b0d033f6a955d88e4b9a1ae4322130459297db952989c model_sha256=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1 tokens=8 ids=791 6864 315 9822 374 12366 13 128009 text="The capital of France is Paris."
AIENOS_PI5_AGENT: RECOVERED PASS
```
G3 wrong secret W (MODEL.MAP placed; the UEFI stub still read the model bytes before the kernel ran, the kernel never hashed or used them: no `infer: sha256=` line):
```
store: REFUSED proof=keyed step="recovery secret rejected (K_vol unwrap tag failed); disk not opened" rc=-2004 (RecoverySecretRejected); disk left as found, not reformatted
agent: NOTHING RECOVERED: the Store is not open (recovery secret missing or rejected, or the disk was refused); the model was not read or hashed, nothing was generated, nothing was written
AIENOS_PI5_AGENT: NOSTORE
```
Limits: tryboot reset, not a power cut; the AIENOS partition was not hashed around G3 (PI5-4 run C proved the same refusal path leaves the partition byte-identical); one golden prompt; 1.20 tok/s; single runs; secret from the card, no TPM.
