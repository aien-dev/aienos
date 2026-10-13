# PI5-6 cut 3: first real inference on the Raspberry Pi 5

Image: `make pi5-infer` (core/infer.c, model from MODEL.MAP read by the UEFI stub through firmware Block I/O).
Model: Llama-3.2-1B-Instruct-Q4_K_M.gguf, 807694368 bytes, sha256 `3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1`
(the host sha256, and the one in crates/aienos-infer/tests/fixtures/PROVENANCE.md). Internal yardstick only (Llama licence); the file is not in the repo.
Runs: `~/workspace/pi5-runs/pi5-infer-a` (before #361, scalar) and `pi5-infer-b` (after #361 merged, SDOT). Harness: `~/workspace/pi5/pi5-run.sh`, KLOG=1, tryboot, per-run nonce.

## Route chosen: a raw model partition, MODEL.MAP on the ESP

The ESP (512 MiB) is smaller than the model, but MODEL.MAP (native/boot/model_map.h:1-20) names the model as extents of absolute LBAs on the whole
disk, found by the GPT disk GUID; the stub (native/boot/efi_model.c, read_map / find_disk) only needs the 4 KiB map on the ESP volume the image was loaded from.
So the ESP is not enlarged and p1/p2 are not touched. A third GPT partition `AIENOS-MODEL` (784 MiB, type Linux filesystem, no file system) was appended
in the free space after p2, the GGUF was written to it raw, and the map has one extent (LBA 9439232, 1577529 sectors).
Written with `sfdisk --append`; read back through p3 and checked to equal the host sha256 before any reboot.
The AIENOS Store finder matches its own type GUID, so p3 is invisible to it (kernel.log: `pi5_part: ... entries_used=` line).

### Card layout, before (`sudo sfdisk -d /dev/mmcblk0`)
```
label-id: 2DB4CE29-B3E1-4564-B340-924422EBCAE3
/dev/mmcblk0p1 : start=        2048, size=     1048576, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=87E06D0B-EB85-4266-B3DD-3958E0671C3E, name="AIENOSPI5-ESP"
/dev/mmcblk0p2 : start=     1050624, size=     8388608, type=38DAAC89-5EAD-4B40-8B1E-3687A7418061, uuid=AEC31319-DDBA-4108-AE6C-972E76E3B770, name="AIENOS"
```
### After
```
/dev/mmcblk0p1    2048 1050623 1048576  512M EFI System
/dev/mmcblk0p2 1050624 9439231 8388608    4G unknown
/dev/mmcblk0p3: Created a new partition 3 of type 'Linux filesystem' and of size 784 MiB.
/dev/mmcblk0p4: Done.
/dev/mmcblk0p1    2048  1050623 1048576  512M EFI System
/dev/mmcblk0p2 1050624  9439231 8388608    4G unknown
/dev/mmcblk0p3 9439232 11044863 1605632  784M Linux filesystem
label-id: 2DB4CE29-B3E1-4564-B340-924422EBCAE3
/dev/mmcblk0p1 : start=        2048, size=     1048576, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=87E06D0B-EB85-4266-B3DD-3958E0671C3E, name="AIENOSPI5-ESP"
/dev/mmcblk0p2 : start=     1050624, size=     8388608, type=38DAAC89-5EAD-4B40-8B1E-3687A7418061, uuid=AEC31319-DDBA-4108-AE6C-972E76E3B770, name="AIENOS"
/dev/mmcblk0p3 : start=     9439232, size=     1605632, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, uuid=585D37FF-6C68-4130-8D88-BDED7AE8721A, name="AIENOS-MODEL"
```
p1 and p2 are byte-for-byte the same entries (same uuids); the disk GUID is unchanged (`2DB4CE29-...`, raw `29ceb42d...` in the map). The hub USB stick was not touched.

## Kernel changes needed for a long run (native/kernel/core/infer.c)
The Pi PM watchdog is 15 s and is petted only at boot stages (core/pi5.c); hashing 770 MiB and generating tokens are longer. Changes:
the SHA-256 runs in 16 MiB pieces with a pet between them; the session loop pets after every step; the one-shot probe (one call, interrupts masked,
cannot pet) is skipped on `CK_PI5_INFER` and the step-by-step session (same prompt, same expected llama.cpp tokens) is the judged run. No other image changes.
RAM log note: the log is written only on the orderly reset path (core/pi5.c:9), so a watchdog expiry would have lost it; both runs ended orderly.

## Harness
`pi5-run.sh` got an optional `MODEL_MAP=<4096-byte map>` hook (copies the map to `\EFI\AIENOS\MODEL.MAP`, checks sha256 on the card, refuses a non-AIENMDL1 file). Backup of the original: `~/workspace/pi5/pi5-run.sh.pre-modelmap`. The script lives outside this repo.

## Evidence, run B (SDOT path, after #361), `kernel.log` lines
```
model_map: ok len=807694368 extents=1 sector=512 disk=29ceb42de1b36445b340924422ebcae3
model: reading 807694368 bytes in 1 extents, block_size=512 last_block=250347519 -> 0xc081000
model: base=0xc081000 len=807694368 extents=1 read_us=8399660 declared_sha256=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1
cpu_features: dotprod=1 i8mm=0 bf16=0 fhm=0 fp16=1 sve=0 rndr=0
infer_source_mode: boot-disk model (MODEL.MAP read by the UEFI stub through the firmware's Block I/O before ExitBootServices); the path that exists on hardware
infer: disk base=0xc081000 size=807694368 extents=1 read_us=8399660 block_size=512
infer: sha256=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1 sha_us=5082431
infer: one-shot probe skipped on the Pi image (watchdog); the session below runs the golden prompt step by step
infer: dot_path=sdot cpu_dotprod=1
infer: session open rc=0 tensors=147 vocab=128256 layers=16 kv_capacity=64 max_new=16 max_prompt_bytes=256 heap_reserve_kib=64 heap_used_kib=22900 open_us=274985
infer: session refusals open_twice=-12 prompt_bytes=-16 step_idle=0
infer: session prompt=1 ids=13 cancel_after_steps=3 steps=3 prefill=3 produced=0 idle_step=done heap_used_kib=22900 rc=1
infer: session prompt=2 ids=17 steps=25 prefill=17 produced=8 last=yes prefill_us=11141714 mean_tok_us=833129 tokens=791 6864 315 9822 374 12366 13 128009 text=The capital of France is Paris. heap_used_kib=22901 request_us=16974445 rc=3
infer: session prompt=3 ids=13 cancel_after_steps=1 steps=1 prefill=1 produced=0 idle_step=done heap_used_kib=22902 rc=1
infer: session close rc=0 heap_used_kib=22902 heap_peak_kib=24695 frames_free_before=1603320 frames_free_after=1603320 rc=0
infer: unloaded heap_live_kib=0 frames_free_before=1603320 frames_free_after=1603320 frames_returned=65536 rc=0,0
```

- Loaded: 807694368 bytes, one extent, read by the firmware in 8.40 s (about 96 MB/s).
- sha256 computed by the kernel over the received bytes equals the declared and the host sha256 (5.08 s).
- First generated token 791 (" The") and all 8 (791 6864 315 9822 374 12366 13 128009) equal the llama.cpp golden (`expect_gen`, crates/aienos-infer/tests/fixtures/ref_fr.txt); text "The capital of France is Paris."
- Speed, 7 timed decode tokens: mean 833129 us per token = 1.20 tok/s. Prefill of 17 prompt tokens 11.1 s. Whole request 16.97 s.
- First proof of dotprod on the A76: `cpu_features: dotprod=1`, `infer: dot_path=sdot cpu_dotprod=1`.

## Run A (before #361, scalar f32 path), same card, same map
```
cpu_features: dotprod=1 i8mm=0 bf16=0 fhm=0 fp16=1 sve=0 rndr=0
infer: sha256=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1 sha_us=5076260
infer: session prompt=2 ids=17 steps=25 prefill=17 produced=8 last=yes prefill_us=62198378 mean_tok_us=4564997 tokens=791 6864 315 9822 374 12366 13 128009 text=The capital of France is Paris. heap_used_kib=22892 request_us=94154192 rc=3
```
Scalar: 4564997 us per token = 0.22 tok/s, so SDOT is 5.5 times faster on the same model and the same 8 tokens.

## Not verified / limits
- The remaining kernel.log lines (boot, SD, entropy) are in the run directories, not reproduced here.
- Time-to-first-token includes prefill of the chat template (17 ids); no larger prompt was run (KV capacity 64 in this probe).
- Both runs are single runs; no variance measured.
