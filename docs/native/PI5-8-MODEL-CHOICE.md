# PI5-8: choosing the open release model for the Pi 5 (decision PD4, settled by measurement)

Scope: which Apache-2.0 or MIT model the AIENOS Pi 5 image should ship, measured on the same engine (`crates/aienos-infer`,
image `make pi5-infer`) and the same card that produced the PI5-6 numbers (docs/native/PI5-6-INFER-RUNS.md).
The Llama model used by PI5-6 stays an internal yardstick (Llama licence). It is not a candidate and is not named as the release model.

## Result in one paragraph

Of the three open candidates, **TinyLlama-1.1B-Chat-v1.0 (Apache-2.0)** and **h2o-danube3-500m-chat (Apache-2.0)** run on the
Pi with the engine's forward pass unchanged, match llama.cpp token for token on the short prompt, and fit the 784 MiB model partition.
**SmolLM2-1.7B-Instruct (Apache-2.0)** runs on the host but its Q4_K_M file (1,055,609,536 bytes) does not fit the partition (822,083,584 bytes), so it was not run on the Pi.
Recommendation: **TinyLlama-1.1B-Chat-v1.0 Q4_K_M** as the Pi release model (1.46 tok/s on the Pi), with
h2o-danube3-500m-chat as the fast fallback (3.23 tok/s, official GGUF from the publisher). **Neither runs end to end yet**: the engine's tokenizer, chat
template and stop token are Llama-3 only, so a small tokenizer change is needed before any open model can answer a typed prompt (section "What this does not prove").

## Ground truth read first

| Fact | Where |
|---|---|
| Engine accepts only `general.architecture = llama` | `crates/aienos-infer/src/gguf.rs` `llama_params` |
| Weight types accepted: Q4_K, Q6_K, F32, F16, BF16; a weight row must be a multiple of 256 columns (K-quant block) | `crates/aienos-infer/src/model.rs` `Weight::bind` |
| Tokenizer: GPT-2 byte-level BPE with the Llama-3 pre-tokenizer only; chat template is Llama-3 only; stop token is the constant 128009 | `crates/aienos-infer/src/tokenizer.rs`, `crates/aienos-infer-kernel/src/lib.rs` (`EOT`) |
| Pi image fixes the golden prompt, the Llama-3 ids and the 64-position cache | `native/kernel/core/infer.c` (`expect_ids`, `expect_gen`, `SESS_KV`) |
| PI5-6 golden tokens came from llama.cpp 4a89937 via `crates/aienos-infer/tests/ref/llama_ref.c` (CPU, one thread, prints ids and greedy steps, writes first logits) | `crates/aienos-infer/tests/fixtures/PROVENANCE.md`, `docs/qualification/INT8-ACTIVATION-QUAL-v1.md` |
| llama.cpp on this Spark: `~/llama.cpp-build` (commit 4a89937, the same build), linked by `llama_ref.c` | measured here |
| Model partition `AIENOS-MODEL` (p3): 1,605,632 sectors = 822,083,584 bytes (784 MiB), raw, found through MODEL.MAP | PI5-6 doc; `lsblk` on the Pi |
| Why SmolLM2 "failed qualification" earlier | aien-architecture `CURRENT_EXECUTION_PLAN.md` lines 838 to 840 and 903: campaign v1 on the Linux host path (GB10), T2 wrong path, T3 cut at the 64-token limit, a daemon crash at warm-up (sovereign-core #236, not reproduced). That was a task-quality and daemon test of a different pipeline, not an engine load failure. Here SmolLM2 loads and matches llama.cpp on the host |

Consequence: with the engine as it is, **no open model runs end to end**. Every open model needs its own tokenizer behaviour (TinyLlama and danube3 use
a SentencePiece vocabulary, SmolLM2 a different BPE pre-tokenizer) and its own chat template and stop token. The arithmetic part (loader, Q4_K and Q6_K
dot products, attention, RoPE, tied or separate output weights) is already generic across `llama`-architecture files. So the measurements below feed token ids
produced by llama.cpp's own tokenizer into the engine and judge only that part.

## Shortlist

All three are `llama` architecture and use only Q4_K, Q6_K and F32 tensors, so they need **no engine architecture work**.
Each needs the tokenizer and template work described above (shared between TinyLlama and danube3, which both use a 32000-entry SentencePiece vocabulary).

| Model (file) | Licence (from the card I read) | Publisher of the file | Size bytes | Fits p3 (822,083,584) | Shape |
|---|---|---|---|---|---|
| TinyLlama-1.1B-Chat-v1.0, `tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` | Apache-2.0 | TheBloke (well-known quantizer); base model by the TinyLlama project | 668,788,096 | yes (81 %) | 22 layers, embd 2048, 32 heads, 4 kv heads, ff 5632, vocab 32000, separate output weight |
| h2o-danube3-500m-chat, `h2o-danube3-500m-chat-Q4_K_M.gguf` | Apache-2.0 | h2oai (the model's own publisher) | 317,877,408 | yes (39 %) | 16 layers, embd 1536, 16 heads, 8 kv heads, ff 4096, vocab 32000, rope base 100000 |
| SmolLM2-1.7B-Instruct, `smollm2-1.7b-instruct-q4_k_m.gguf` | Apache-2.0 | HuggingFaceTB (the model's own publisher) | 1,055,609,536 | **no** (128 %) | 24 layers, embd 2048, 32 heads, 32 kv heads, ff 8192, vocab 49152, tied output weight |

The one candidate that would need a **small, well-scoped engine change** is SmolLM2 (a different BPE pre-tokenizer, a ChatML template, stop token `<|im_end|>`,
and a model partition of at least 1.1 GiB). It was not built here. Models skipped on purpose (not run, reasons from memory and not checked here): SmolLM2-360M, SmolLM2-135M and Qwen2.5-0.5B, whose embedding widths (960, 576, 896 as I recall them)
are not multiples of 256, which the engine's K-quant blocks require; Qwen3-0.6B, whose publisher lists only `Qwen3-0.6B-Q8_0.gguf` (a type the engine rejects) and whose architecture, as I recall, adds per-head norms (a real engine change). The Qwen3-0.6B card also says `license: apache-2.0` and the repository has a LICENSE file (listing seen, file not read).

### Licence evidence (the YAML header of each model card, read on 2026-10-13; none of these repositories ships a separate LICENSE file)
- TinyLlama base card: https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0 : `license: apache-2.0`
- TinyLlama GGUF card: https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF : `license: apache-2.0` (a third-party conversion of the Apache-2.0 model; the TinyLlama project publishes no GGUF of its own)
- danube3 base card: https://huggingface.co/h2oai/h2o-danube3-500m-chat : `license: apache-2.0`
- danube3 GGUF card: https://huggingface.co/h2oai/h2o-danube3-500m-chat-GGUF : `license: apache-2.0`
- SmolLM2 base card: https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct : `license: apache-2.0`
- SmolLM2 GGUF card: https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct-GGUF : `license: apache-2.0`

### Downloads (kept outside git, in `~/models/pi5-8-candidates/`; sha256 equals the LFS object id the publisher's file listing reports)
| File | URL | sha256 |
|---|---|---|
| tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf | https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf | `9fecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0` |
| h2o-danube3-500m-chat-Q4_K_M.gguf | https://huggingface.co/h2oai/h2o-danube3-500m-chat-GGUF/resolve/main/h2o-danube3-500m-chat-Q4_K_M.gguf | `021f78849c5670ecb2aa4cd7c5972eee0a3c9e41e33e5902c408a2ab989f0b43` |
| smollm2-1.7b-instruct-q4_k_m.gguf | https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct-GGUF/resolve/main/smollm2-1.7b-instruct-q4_k_m.gguf | `decd2598bc2c8ed08c19adc3c8fdd461ee19ed5708679d1c54ef54a5a30d4f33` |

Evidence excerpts: `docs/native/pi5-8/pi-kernel-log-lines.txt` (the kernel log lines of the three Pi boots). The measurement patch: `docs/native/pi5-8/measure-ids.patch` (applies cleanly to main with `git apply`).

## Method

- Prompts: the PI5-6 prompt ("What is the capital of France?") plus two longer ones (`scripts/pi5-8/prompt-long1.txt`, 35 to 45 ids, and `prompt-long2.txt`, 108 to 119 ids), wrapped in each model's chat template as I wrote it (TinyLlama: Zephyr style; danube3: `<|prompt|>...</s><|answer|>`; SmolLM2: ChatML without a system turn).
  The TinyLlama GGUF carries no embedded template, so its Zephyr style template comes from the model card. 16 greedy tokens, stop at the stop token.
- Reference: `llama_ref` from `crates/aienos-infer/tests/ref/llama_ref.c`, linked to llama.cpp 4a89937, CPU only (`CUDA_VISIBLE_DEVICES` hidden), one thread. Its token ids are the prompt given to the engine.
- Host check: `scripts/pi5-8/host_golden.sh MODEL TEMPLATE EOS [N] [sdot]` runs the engine's own forward pass (`crates/aienos-infer/examples/model_probe.rs`) on the Spark in both arithmetic paths (f32, and the SDOT int8 path the Pi uses), and compares tokens and the first-position logits.
- Pi check: `docs/native/pi5-8/measure-ids.patch` (applied to a scratch copy, not to main) lets the Pi image take prompt ids and a stop token instead of text, raises the cache to 192 positions and runs five requests in one boot (short prompt three times for variance, then the two long prompts). `scripts/pi5-8/gen_measure_header.sh` turns the llama.cpp output into the header the image compiles in; `scripts/pi5-8/pi_run.sh` writes the model to p3, reads it back, runs `~/workspace/pi5/pi5-run.sh` with `KLOG=1` and a MODEL.MAP, then removes MODEL.MAP from the ESP. MODEL.MAP: one extent at LBA 9439232, same disk GUID as PI5-6.
- Scoring rule for the host table: exact token match is PASS. A mismatch counts as NOISE when, at the first differing step, llama.cpp's own top-1 minus top-2 logit gap is below 1.0 (the largest single-logit difference between the engine and llama.cpp on the Llama control was 0.90); a larger gap would be FAIL. The 1.0 threshold is my choice, not a published standard.

## Host golden results (engine vs llama.cpp 4a89937, 16 tokens; Spark, 2026-10-13)

Control: the PI5-6 Llama file on the same scripts gives PASS, PASS, PASS in SDOT (and PASS, NOISE, PASS in f32, first divergence at gap 0.039), with first-position logit rms difference 0.09 to 0.17.
That is the baseline noise level of this engine against llama.cpp.

| Model | Path | short (id count) | long1 | long2 | logit rms diff vs llama.cpp (3 prompts) |
|---|---|---|---|---|---|
| TinyLlama | f32 | PASS (24) | NOISE (step 2, gap 0.0006) | NOISE (step 13, gap 0.118) | 0.099, 0.099, 0.149 |
| TinyLlama | SDOT | PASS | NOISE (step 10, gap 0.035) | NOISE (step 13, gap 0.118) | 0.104, 0.115, 0.134 |
| danube3-500m | f32 | PASS (20) | NOISE (step 0, gap 0.065) | NOISE (step 0, gap 0.110) | 0.180, 0.181, 0.326 |
| danube3-500m | SDOT | PASS | NOISE (step 0, gap 0.065) | PASS | 0.158, 0.222, 0.188 |
| SmolLM2-1.7B | f32 | PASS (16) | PASS | NOISE (step 8, gap 0.94) | 0.650, 0.506, 0.469 |
| SmolLM2-1.7B | SDOT | PASS | PASS | NOISE (step 1, gap 0.044) | 0.263, 0.262, 0.339 |

Reading: TinyLlama is as close to llama.cpp as the Llama control is. danube3 is slightly further (rms 0.16 to 0.33). SmolLM2 in the f32 path is 3 to 6 times further than the control
(rms up to 0.65, one divergence at a gap of 0.94, just under my 1.0 line); the SDOT path is closer. I did not find the cause (UNKNOWN); it does not affect the Pi, which runs SDOT, but it is why SmolLM2 would need a closer look before it is trusted.
No FAIL under the scoring rule. Raw files: `/tmp/pi58-golden/<model>[-sdot]/` on the Spark (not kept in git).

## Pi results (real Raspberry Pi 5, SDOT path, `make pi5-infer` image plus the measurement patch)

Each row is one boot. The three short requests are the variance sample (same prompt, same boot); long prompts are single requests. `mean_tok_us` is the kernel's per-token time exactly as PI5-6 defined it (decode steps after the first token).

| | TinyLlama-1.1B-Chat Q4_K_M | danube3-500m-chat Q4_K_M | (internal yardstick, PI5-6 definition, re-run today) |
|---|---|---|---|
| Model bytes / sha256 matches the declared one | 668,788,096 / yes | 317,877,408 / yes | 807,694,368 / yes |
| p3 read back through Linux before the boot, sha256 equals the file | yes | yes | yes |
| Load (firmware reads p3) | 6.96 s | 3.31 s | 8.40 s |
| sha256 inside the kernel | 4.20 s | 2.07 s | 5.08 s |
| Short prompt, 3 requests, us per token | 683,917 / 684,024 / 683,980 | 309,842 / 309,893 / 309,866 | 832,559 (one request) |
| Short prompt tok/s, mean of 3 (spread) | **1.462** (1.4620 to 1.4622, 0.01 %) | **3.227** (3.2268 to 3.2274, 0.02 %) | 1.201 |
| Short prompt prefill | 15.30 s for 24 ids (0.64 s per id) | 5.51 s for 20 ids (0.28 s per id) | 11.14 s for 17 ids |
| long1 (ids), tok/s, prefill | 45 ids, 1.456, 28.69 s | 41 ids, 3.210, 11.29 s | |
| long2 (ids), tok/s, prefill | 119 ids, 1.438, 76.32 s | 113 ids, 3.159, 31.32 s | |
| Tokens equal to llama.cpp, short x3 | 3 of 3 match | 3 of 3 match | 3 of 3 (kernel's own check) |
| Tokens equal to llama.cpp, long1 / long2 | MISMATCH at step 10 (host SDOT NOISE, same tokens) / match | MISMATCH at step 0 (host SDOT NOISE, same tokens) / match | |
| Heap used by the session | 11.7 MiB | 19.8 MiB | 22.4 MiB |
| Evidence | `~/workspace/pi5-runs/pi5-8-tinyllama-a/kernel.log` | `~/workspace/pi5-runs/pi5-8-danube3-a/kernel.log` | `~/workspace/pi5-runs/pi5-8-restore/kernel.log` |

On both models the Pi produced exactly the same token lists as the host SDOT run for all five requests, including the two near-tie mismatches (compare `golden=MISMATCH` lines with the host table): the Pi's arithmetic is the same as the host's SDOT arithmetic.
Variance between the three in-boot requests is under 0.03 %; I did not repeat whole boots (UNVERIFIED across boots: the PI5-6 load time of 8.4 s reproduced to 8.40 s on a second boot, a hint that load time is stable).

Cost of a long prompt: prefill is the same per-token speed as decoding in this engine (no batching), so a 119-token prompt waits 76 s on TinyLlama and 31 s on danube3 before the first word.

Log excerpt (TinyLlama, one request line):
```
infer: measure req=0 name=short ids=24 prefill=24 prefill_us=15296424 produced=8 mean_tok_us=683917 tokens=1576 7483 310 3444 338 3681 29889 2 golden=match request_us=20084557 rc=3
```

## Recommendation

**TinyLlama-1.1B-Chat-v1.0 (Q4_K_M, Apache-2.0).** Engineering reasons:
1. It is faster on the Pi than the internal yardstick (1.46 against 1.20 tok/s) because it has fewer weights per token, loads in 7.0 s, and uses 81 % of the model partition, so nothing about the card layout changes.
2. Its forward pass on the Pi is as faithful to llama.cpp as the yardstick's (first-position logit rms difference 0.10 to 0.15 against 0.09 to 0.17), and the only mismatches are near-ties that the host reproduces exactly.
3. It needs no architecture work, only the tokenizer, template and stop-token work that every open model needs.
4. Its weakness is quality and age (1.1B, trained in 2023, Zephyr style chat tuning): expect plain, short answers. If quality matters more than speed, SmolLM2 is the next candidate, but it needs a larger partition (at least 1.1 GiB) and a tokenizer change.

Fallback: **h2o-danube3-500m-chat**, 2.2 times faster again (3.23 tok/s), 318 MB, and its GGUF comes from the publisher itself (TinyLlama's comes from a third-party quantizer). Its first token differed from llama.cpp on one long prompt at a logit gap of 0.065, which is why I rank it second on fidelity, and the card gives no benchmark numbers I could use here.

## What this does not prove (limits)
- The engine's own tokenizer was not run on any open model. Token ids came from llama.cpp. The release needs a SentencePiece tokenizer (shared by TinyLlama and danube3), a per-model chat template, and a per-model stop token in `aienos-infer` and `aienos-infer-kernel`. Not built in this task.
- Quality was not evaluated: only that the engine computes what llama.cpp computes. I did not read generated text for usefulness.
- Pi numbers are one boot per model; variance is in-boot only. The measurement patch changed the session limits (cache 192 positions, five requests) so absolute tok/s can differ slightly from a production image.
- SmolLM2 on the Pi: not run (does not fit p3). SmolLM2's f32 host path being further from llama.cpp than the control is unexplained (UNKNOWN).
- The cards state Apache-2.0; no separate LICENSE file exists in those repositories. Whether the training data (SlimPajama, StarCoderData, UltraChat, UltraFeedback for TinyLlama) carries obligations was not assessed.
- The SDOT int8 path was not compared bitwise with llama.cpp; only tokens and logits as above.

## State left behind
p3 holds the PI5-6 yardstick again: written back at 02:18Z and read back through Linux, sha256 `3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1` equals the file. Because the restore command also launched one run with the unchanged PI5-6 image (my script had no write-only switch at that moment; the switch is in the committed script), the yardstick was re-measured the same day: 8 tokens identical to the golden list, 832,559 us per token (1.201 tok/s), `AIENOS_CK_INFER_SESSION: PASS`.
MODEL.MAP was removed from the ESP after every run (`model_map_removed` in each run output). The three downloaded GGUF files stay in `~/models/pi5-8-candidates/`, outside the repository.
