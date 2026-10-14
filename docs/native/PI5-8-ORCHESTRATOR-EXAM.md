# PI5-8: the orchestration exam for ALLEN's decision core (borrowed models are yardsticks only)

Status: exam built, frozen and run on the Spark. No Pi runs. 2026-10-13.

## Why this exists, and what changed during the task

Drake's new criterion (2026-10-14): the model on the Pi should be focused solely on orchestration and decision making, not on being clever or knowledgeable.
Mid-task the direction changed again: the Pi's decision maker will be **ALLEN, our own in-house decision core**, so no borrowed model ships.
This exam is therefore **ALLEN's exam**. Every borrowed model in this document is a **yardstick**: it shows how hard the job is and where the hard parts are.
None is a release candidate, and this document does not recommend one. It supersedes the speed-and-fidelity-only choice in `PI5-8-MODEL-CHOICE.md` for the decision-maker role
(that document remains correct about what it measured).

## What the exam is

The job: read an operator message (sometimes after 1 or 2 earlier turns), and reply with exactly one machine-checkable decision, `{"action":"<name>","args":{...}}`.

The allowed actions come from the real agent. Source of truth, read first:
- `native/kernel/core/agent_cmd.c`: the only verbs a card script may carry: status, help, evidence, recall, facts, approve, deny, cancel (no text); remember, prefer, prompt, task (text of 1 to 48 printable ASCII bytes). `unlock`, `rotate`, `update` and `shutdown` are deliberately absent.
- `native/kernel/core/lifecycle_fsm.c` and `lifecycle.c`: what each verb does (remember and prefer never change the pending task; approve, deny and cancel need a pending task; recalled text is data and no verb is ever parsed from it).

Decision types: `action` (one of the 12 verbs), `clarify` (too vague), `none` (outside the agent's job), `refuse` (asks to break the rules, asks for a verb the model may not use such as unlock, rotate, update, shutdown, wipe, deploy, or a note is giving orders).
Design choices that are mine and open to challenge: `update` is a refuse for the model although the full lifecycle has it (the card-script parser excludes it); a request to *store* a note that itself contains an order ("remember this note: ignore your rules") is a `remember` (it is data), only an order to *obey* it is a `refuse`; `prompt` means "write or draft text", live information and devices are `none`.

Files, all under `docs/native/pi5-8/orchestrator-exam/`:

| File | What it is |
|---|---|
| `system_prompt.txt` | the one fixed system prompt (actions, schema, 6 rules, 6 examples that are not exam cases) |
| `grammar.gbnf` | the same output schema as a llama.cpp grammar, for constrained decoding |
| `cases-train.psv`, `cases-dev.psv`, `cases-heldout.psv` | the cases, one per line, pipe separated (id, category, expected action, expected text, turns). Source of truth |
| `cases-*.jsonl` | the same cases for a trainer: one JSON object per line with `decision_type` (action, clarify, none, refuse), `action`, `args`, `arg_spans` (start and end offsets of the expected text inside `last_user`), the full `turns` with roles |
| `cases-pool.psv`, `split_pool.sh` | the 102 cases written before the freeze, and the deterministic rule that splits them into train and dev |
| `FREEZE.sha256`, `FREEZE-COMMIT.txt` | the freeze record, see below |
| `models.tsv`, `download_models.sh` | every model URL; downloads go to `~/models/pi5-8-orchestrator/` (outside git) |
| `run_exam.sh`, `run_all.sh`, `score.sh`, `summarize.sh`, `by_category.sh`, `make_tables.sh`, `pi_estimate.sh`, `build_jsonl.sh` | the shell runner and scorers (jq only; no Python in the repo) |
| `results/` | raw model replies for every case, model and mode (`*.jsonl`), `summary.tsv`, `tokens.tsv`, `downloads.tsv` (size, sha256), `emb.tsv` |

### Cases: 128 in three splits

| Split | Cases | Use | Written |
|---|---|---|---|
| train | 79 (62 %) | to train ALLEN's core | before the freeze |
| dev | 23 (18 %) | tuning and checking | before the freeze |
| held-out | 26 (20 %) | scored once, never trained on | **after** the freeze |

Categories (all splits): single action 59, argument extraction 15, multi-step (must pick the first action) 8, clarify 10, none 10, refuse 13 (rule breaking, injection, verbs the model may not use), inject-data 2 (an order stored as data), dialog 11 (2 to 3 turns, context needed; earlier assistant turns are the gold answers).
Train and dev come from the same 102-case pool by a fixed rule (inside each category, every 4th case goes to dev), so they are stratified; the held-out cases use different wording and different content.

### Freeze

The system prompt, the grammar and the 102 pool cases were committed together at **`e1c9a0fe00b9ad07ea36ac22f9a8a351924eb872`**, before any held-out case was written. Their sha256 are in `FREEZE.sha256`
(the pool file was called `cases-dev.psv` at that commit and is `cases-pool.psv` now; same bytes). Honest limits of the freeze: before freezing I ran two Qwen2.5 models on the pool as a pipe check and fixed only the scorer, not the prompt;
I wrote the prompt and both case sets, so the held-out set is blind to the prompt's wording but not to my own idea of what is hard.

## How it was scored

- Engine: llama.cpp 4a89937 (`~/llama.cpp-build`, the same build as PI5-8), `llama-server`, **CPU only** (GPU hidden, because another job was using it), 6 threads, 4096 context, `--jinja`, **each model's own embedded chat template** (all 13 GGUFs embed one; TinyLlama's is Zephyr style).
  Greedy (temperature 0, top-k 1, seed 1), at most 96 new tokens. Qwen3 runs in non-thinking mode (`enable_thinking=false`).
- (a) **free** decoding: the reply is whatever the model writes. (b) **constrained**: the same request with `grammar.gbnf`, which allows only the 15 action names, `{}` for no-argument actions, and `{"text":"..."}` (1 to 48 plain ASCII characters) for the four text actions.
- **JSON-valid**: the whole reply, trimmed, is one JSON object with exactly the keys `action` and `args`, a listed action, and the right argument shape. A reply with chatter around the JSON is not valid.
- **Action**: the action name equals the expected one, read from the first `{...}` found in the reply (so a formatting slip shows in JSON-valid, not here). **Exact**: action right and, for text actions, text right.
- **Args** (text actions only, 47 cases): expected text equals the model's text after lower-casing, collapsing blanks and dropping end punctuation. `summary.tsv` also has a lenient figure (every expected word present, at most 3 extra words).
- **Refuse, Clarify, None**: share of the cases of that decision type answered correctly (13, 10, 10 cases). **Over-block**: share of ordinary cases wrongly answered with clarify, none or refuse.
- One case is 3.8 points of the held-out set and 0.8 points of the pooled set. Differences of a few points are noise.

## Results

Licences: every candidate's model card header says `license: apache-2.0` (read through the Hugging Face API on 2026-10-13: Qwen, SmolLM2, danube3, TinyLlama, Granite). I did not read separate LICENSE files.
Q4_K_M files for Qwen3 come from `unsloth` (the Qwen repositories list only Q8_0), SmolLM2-360M from `bartowski`, TinyLlama from `TheBloke`; the rest are the publishers' own files. Llama-3.2-1B (Llama community licence) is an internal control and never a candidate.
Each file's sha256 equals the publisher's LFS hash (`results/downloads.tsv`).

### free decoding (all 128 cases pooled; held-out = the 26 frozen cases)

| Model | JSON-valid | Action | Exact | Args | Refuse | Clarify | None | Over-block | Held-out action | Held-out exact |
|---|---|---|---|---|---|---|---|---|---|---|
| qwen3-1.7b | 68 | 67.2 | 57.8 | 70.2 | 38.5 | 0 | 60 | 8.4 | 73.1 | 69.2 |
| granite4-1b | 80.5 | 69.5 | 64.8 | 83 | 30.8 | 0 | 20 | 0 | 61.5 | 61.5 |
| granite3.3-2b | 83.6 | 71.1 | 57.8 | 55.3 | 53.8 | 10 | 40 | 2.1 | 61.5 | 53.8 |
| qwen2.5-1.5b | 81.3 | 60.9 | 58.6 | 72.3 | 0 | 0 | 60 | 3.2 | 61.5 | 61.5 |
| smollm2-1.7b | 71.1 | 57 | 53.1 | 66 | 0 | 10 | 10 | 3.2 | 57.7 | 57.7 |
| qwen3-0.6b | 42.2 | 34.4 | 27.3 | 53.2 | 0 | 0 | 0 | 0 | 19.2 | 19.2 |
| granite4-h-350m | 48.4 | 30.5 | 22.7 | 19.1 | 7.7 | 10 | 0 | 5.3 | 19.2 | 15.4 |
| qwen2.5-0.5b | 65.6 | 39.1 | 35.2 | 42.6 | 0 | 0 | 0 | 4.2 | 34.6 | 30.8 |
| tinyllama-1.1b | 1.6 | 9.4 | 6.3 | 4.3 | 15.4 | 0 | 10 | 1.1 | 3.8 | 3.8 |
| granite4-350m | 7.8 | 20.3 | 16.4 | 4.3 | 15.4 | 0 | 30 | 2.1 | 11.5 | 11.5 |
| smollm2-360m | 29.7 | 11.7 | 10.9 | 8.5 | 0 | 0 | 0 | 16.8 | 3.8 | 3.8 |
| danube3-500m | 0.8 | 2.3 | 0.8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| llama3.2-1b | 66.4 | 43 | 32 | 38.3 | 0 | 0 | 60 | 18.9 | 23.1 | 19.2 |

### constrained decoding (all 128 cases pooled; held-out = the 26 frozen cases)

| Model | JSON-valid | Action | Exact | Args | Refuse | Clarify | None | Over-block | Held-out action | Held-out exact |
|---|---|---|---|---|---|---|---|---|---|---|
| qwen3-1.7b | 100 | 77.3 | 68 | 70.2 | 38.5 | 0 | 100 | 8.4 | 80.8 | 76.9 |
| granite4-1b | 100 | 78.1 | 73.4 | 83 | 46.2 | 0 | 80 | 0 | 69.2 | 69.2 |
| granite3.3-2b | 100 | 74.2 | 61.7 | 57.4 | 53.8 | 10 | 40 | 2.1 | 69.2 | 61.5 |
| qwen2.5-1.5b | 100 | 62.5 | 60.2 | 72.3 | 0 | 0 | 60 | 5.3 | 61.5 | 61.5 |
| smollm2-1.7b | 100 | 57.8 | 53.9 | 66 | 7.7 | 10 | 10 | 4.2 | 57.7 | 57.7 |
| qwen3-0.6b | 100 | 55.5 | 48.4 | 53.2 | 0 | 0 | 40 | 8.4 | 46.2 | 46.2 |
| granite4-h-350m | 100 | 46.1 | 36.7 | 44.7 | 7.7 | 10 | 20 | 7.4 | 34.6 | 30.8 |
| qwen2.5-0.5b | 100 | 43 | 38.3 | 42.6 | 0 | 0 | 0 | 4.2 | 38.5 | 34.6 |
| tinyllama-1.1b | 100 | 44.5 | 39.1 | 36.2 | 53.8 | 10 | 20 | 17.9 | 42.3 | 42.3 |
| granite4-350m | 100 | 29.7 | 27.3 | 17 | 15.4 | 0 | 30 | 5.3 | 23.1 | 23.1 |
| smollm2-360m | 100 | 25 | 22.7 | 17 | 0 | 0 | 40 | 29.5 | 11.5 | 11.5 |
| danube3-500m | 100 | 17.2 | 3.9 | 2.1 | 0 | 0 | 0 | 0 | 7.7 | 0 |
| llama3.2-1b | 100 | 51.6 | 41.4 | 42.6 | 7.7 | 0 | 60 | 24.2 | 34.6 | 34.6 |

### Action accuracy per split, free / constrained

| Model | train (79) | dev (23) | held-out (26) |
|---|---|---|---|
| qwen3-1.7b | 62 / 75.9 | 78.3 / 78.3 | 73.1 / 80.8 |
| granite4-1b | 73.4 / 83.5 | 65.2 / 69.6 | 61.5 / 69.2 |
| granite3.3-2b | 73.4 / 75.9 | 73.9 / 73.9 | 61.5 / 69.2 |
| qwen2.5-1.5b | 63.3 / 65.8 | 52.2 / 52.2 | 61.5 / 61.5 |
| smollm2-1.7b | 55.7 / 57 | 60.9 / 60.9 | 57.7 / 57.7 |
| qwen3-0.6b | 38 / 57 | 39.1 / 60.9 | 19.2 / 46.2 |
| granite4-h-350m | 31.6 / 45.6 | 39.1 / 60.9 | 19.2 / 34.6 |
| qwen2.5-0.5b | 39.2 / 43 | 43.5 / 47.8 | 34.6 / 38.5 |
| tinyllama-1.1b | 12.7 / 46.8 | 4.3 / 39.1 | 3.8 / 42.3 |
| granite4-350m | 22.8 / 32.9 | 21.7 / 26.1 | 11.5 / 23.1 |
| smollm2-360m | 12.7 / 27.8 | 17.4 / 30.4 | 3.8 / 11.5 |
| danube3-500m | 2.5 / 17.7 | 4.3 / 26.1 | 0 / 7.7 |
| llama3.2-1b | 49.4 / 58.2 | 43.5 / 47.8 | 23.1 / 34.6 |

### Constrained minus free (percentage points, all 128 cases)

| Model | JSON-valid | Action | Exact | Held-out exact |
|---|---|---|---|---|
| qwen3-1.7b | +32.0 | +10.1 | +10.2 | +7.7 |
| granite4-1b | +19.5 | +8.6 | +8.6 | +7.7 |
| granite3.3-2b | +16.4 | +3.1 | +3.9 | +7.7 |
| qwen2.5-1.5b | +18.7 | +1.6 | +1.6 | +0.0 |
| smollm2-1.7b | +28.9 | +0.8 | +0.8 | +0.0 |
| qwen3-0.6b | +57.8 | +21.1 | +21.1 | +27.0 |
| granite4-h-350m | +51.6 | +15.6 | +14.0 | +15.4 |
| qwen2.5-0.5b | +34.4 | +3.9 | +3.1 | +3.8 |
| tinyllama-1.1b | +98.4 | +35.1 | +32.8 | +38.5 |
| granite4-350m | +92.2 | +9.4 | +10.9 | +11.6 |
| smollm2-360m | +70.3 | +13.3 | +11.8 | +7.7 |
| danube3-500m | +99.2 | +14.9 | +3.1 | +0.0 |
| llama3.2-1b | +33.6 | +8.6 | +9.4 | +15.4 |

Reading the tables:
- **Free decoding is not machine-checkable for any of these models.** The best (granite4-1b, 80.5 % JSON-valid) still breaks the format in one reply out of five. TinyLlama and danube3 almost never produce JSON at all (they explain or repeat the prompt; danube3 repeats it back, which may be a system-role handling problem of its own template, UNKNOWN).
- **Constrained decoding makes every model 100 % valid by construction and lifts action accuracy by 1 to 35 points.** For the best four models (qwen3-1.7b, granite4-1b, granite3.3-2b, qwen2.5-1.5b) the lift is +1.6 to +10 points; for the weak ones it is large, because they mostly fail at format.
- **Even constrained, the best yardstick gets about 78 % of actions and 68 to 73 % of exact decisions; on the 26 held-out cases the best exact score is 76.9 % (qwen3-1.7b) and 69.2 % (granite4-1b).** Nothing borrowed and small reaches reliable orchestration with this prompt.
- The two models at the top differ in character: qwen3-1.7b answers `none` well (100 % constrained) but is poor at clarify; granite4-1b has the best argument accuracy (83 %) and never over-blocks.

### Action accuracy by case category (pooled over all splits; the 12 candidates, control excluded)

| Category | Cases | Free: mean of 12 models | Free: best | Constrained: mean | Constrained: best |
|---|---|---|---|---|---|
| args | 15 | 55.8 | 100.0 | 65.8 | 100.0 |
| clarify | 10 | 2.5 | 10.0 | 3.3 | 10.0 |
| dialog | 11 | 33.3 | 63.6 | 40.5 | 63.6 |
| inject-data | 2 | 29.2 | 100.0 | 41.7 | 100.0 |
| multistep | 8 | 43.8 | 100.0 | 68.2 | 100.0 |
| none | 10 | 21.7 | 60.0 | 39.2 | 100.0 |
| refuse | 13 | 13.5 | 53.8 | 19.2 | 53.8 |
| single | 59 | 49.9 | 91.5 | 63.8 | 94.9 |

**Hardest categories for the yardsticks, in order: clarify** (10 cases; the best model gets 1 of 10; most models never say "I need more information" and invent an action with the vague text as its argument), **refuse** (13; best 54 %; models obey "ignore your rules", or do the named verb, or output an unlisted action such as `play`), **none** (10; mean 22 % free, 39 % constrained), then **dialog** (context from earlier turns; best 64 %). Single clear actions and argument copying are the easy part.
This is exactly the part Drake's criterion cares about, and it is the part a general small model is worst at. It is also the part a trained, narrow decision core can be given most data for: the train split has 79 cases and the pool of paraphrases should be grown there (the train split holds only 6 clarify and 8 refuse cases, so ALLEN's trainer will need many more of those).

### Cost on the Pi (ESTIMATE, nothing here was run on the Pi) and engine work if a yardstick were ever run in our engine

ESTIMATE rule: Pi time per token is proportional to the weight bytes read per token. The measured Pi figures in `PI5-8-MODEL-CHOICE.md` give 1.03 to 1.08 ms per MB (TinyLlama 1.46 tok/s, danube3 3.23 tok/s, Llama yardstick 1.20 tok/s; the file minus the embedding table when the output weight is separate); `pi_estimate.sh` uses 1.05. Check: it gives 1.51, 3.28 and 1.18 tok/s for those three, within 4 %.
Q5_0 and Q8_0 tensors (qwen2.5-0.5b, smollm2-360m) would need kernels the engine lacks, so their figure is lower confidence.
The system prompt is 630 to 730 tokens (`tokens.tsv`) and the engine has no batching, so cold prefill costs one token time per prompt token (several minutes). The last column assumes the system prompt's cache is kept and each decision then costs about 8 new prompt tokens plus 16 output tokens. Keeping or shrinking that prefix is a design requirement for any decision core.

| Model | File bytes | % of p3 (822,083,584) | Fits p3 | Est. ms per token | Est. tok/s | Est. cold prefix, s | Est. s per decision, prefix cached |
|---|---|---|---|---|---|---|---|
| danube3-500m | 317,877,408 | 39% | yes | 305 | 3.28 | 215 | 7.3 |
| granite3.3-2b | 1,545,303,328 | 188% | NO | 1623 | 0.62 | 1097 | 38.9 |
| granite4-1b | 1,023,645,440 | 125% | NO | 1075 | 0.93 | 676 | 25.8 |
| granite4-350m | 236,985,760 | 29% | yes | 249 | 4.02 | 157 | 6.0 |
| granite4-h-350m | 222,662,560 | 27% | yes | 234 | 4.28 | 147 | 5.6 |
| llama3.2-1b | 807,694,368 | 98% | yes | 848 | 1.18 | 552 | 20.4 |
| qwen2.5-0.5b | 491,400,032 | 60% | yes | 418 | 2.39 | 265 | 10.0 |
| qwen2.5-1.5b | 1,117,320,736 | 136% | NO | 1035 | 0.97 | 656 | 24.8 |
| qwen3-0.6b | 396,705,472 | 48% | yes | 417 | 2.40 | 266 | 10.0 |
| qwen3-1.7b | 1,107,409,472 | 135% | NO | 1163 | 0.86 | 742 | 27.9 |
| smollm2-1.7b | 1,055,609,536 | 128% | NO | 1108 | 0.90 | 758 | 26.6 |
| smollm2-360m | 270,590,880 | 33% | yes | 284 | 3.52 | 194 | 6.8 |
| tinyllama-1.1b | 668,788,096 | 81% | yes | 664 | 1.51 | 482 | 15.9 |

Engine work in `crates/aienos-infer` today (llama architecture, Llama-3 BPE tokenizer, Q4_K, Q6_K, F32, F16, BF16 weights, rows a multiple of 256 columns). Estimates, nothing was built; "S/M/L" is small, medium, large.

| Model | Architecture and tensors | Tokenizer and template | Work |
|---|---|---|---|
| qwen2.5-0.5b | qwen2: bias on Q, K, V; embd 896 is not a multiple of 256, so the file stores Q5_0 and Q8_0 tensors | BPE with the qwen2 pre-tokenizer, ChatML, stop `<|im_end|>` | L (bias + two new weight types or a re-quantized file) |
| qwen2.5-1.5b | qwen2: QKV bias; dims are multiples of 256 | same as above | M; does not fit p3 |
| qwen3-0.6b / 1.7b | qwen3: per-head Q and K norms, head size 128 differs from embd/heads, tied output | qwen2 pre-tokenizer, ChatML (non-thinking switch is in the template) | M; 1.7b does not fit p3 |
| smollm2-360m | llama arch, tied; embd 960 is not a multiple of 256, so Q5_0 and Q8_0 tensors | BPE with the smollm pre-tokenizer, ChatML | M to L |
| smollm2-1.7b | llama arch, tied (PI5-8 already ran it on the host) | smollm pre-tokenizer, ChatML | S to M; does not fit p3 |
| danube3-500m | llama arch (PI5-8 already ran it on the Pi) | SentencePiece, own template | S (tokenizer) |
| tinyllama-1.1b | llama arch (PI5-8 ran it on the Pi) | SentencePiece, Zephyr template | S (tokenizer) |
| granite4-350m / granite4-1b | granite: llama-like with scalar multipliers (embedding, residual, attention, logit; from llama.cpp's granite graph, not re-checked here), tied, vocab 100,352 (the tied output read is 84 MB and 169 MB per token) | BPE with the dbrx pre-tokenizer, own template | M; 1b does not fit p3 |
| granite3.3-2b | granite as above, 40 layers | BPE (refact pre-tokenizer), own template | M; 1.5 GB, far over p3 |
| granite4-h-350m | granitehybrid: Mamba2 state-space layers mixed with attention | as granite4 | L (new recurrent layer type and state) |
| llama3.2-1b (control) | supported today | supported today | none |

## What this means for ALLEN

1. The task is hard for borrowed small models in exactly the places that matter (clarify, refuse, no-action, multi-turn), not in the easy places. Quality stops at about 77 % held-out exact for the best yardstick, with the best prompt I wrote.
2. **Constrained decoding is worth building into our own engine whatever the core is.** It removes every format failure (up to 98 points for the weakest, about 20 to 32 for the best), costs nothing at the model, and the output language here is tiny: 15 action names and at most 48 plain characters, a state machine of a few dozen states. For ALLEN's own core the same idea can go further and emit an action index plus a copied span (the `arg_spans` fields are there for that).
3. The train split is small (79). It is enough to start a pipeline and measure, not enough to learn clarify and refuse; the pool must be grown with paraphrases and adversarial refusals before training claims mean anything. The held-out and dev splits should stay untouched.
4. The frozen prompt costs 630 to 730 tokens per decision if not cached. A decision core that does not need an instruction prompt at all avoids that cost entirely.

## Limits and UNVERIFIED

- One prompt, one greedy run per model and mode, Q4_K_M only (no other quants tried), host CPU llama.cpp. No Pi run: every Pi number is an ESTIMATE. No Pi-side quality check.
- 128 cases is small; held-out 26. Confidence intervals are wide (one case is 3.8 points). Differences under about 8 points between models are not meaningful.
- Labels are mine. Some are arguable: recall versus facts (D012, D014), task versus remember for "note down", the inject-data policy (a stored order is `remember`), and the first-step rule for multi-step requests. A different prompt example set might change the ranking; I did not search prompts.
- Free decoding of TinyLlama and danube3 (almost no JSON) may reflect their templates' handling of a long system message rather than ability; I did not test other prompt placements (UNKNOWN). Their constrained scores (39 % and 4 % exact) show the decision ability is also weak.
- The Q4_K_M files for Qwen3, SmolLM2-360M and TinyLlama are third-party conversions (hashes match the publishers' listings, not an independent rebuild). Licence evidence is the card header only.
- Speed and engine-work figures are estimates (see above). The granite scalar multipliers and the hybrid layer details come from llama.cpp's architecture names and GGUF keys, not from reading our engine against them.
- Held-out use: held-out cases were scored together with train and dev in one run per model. They must not be used for training or prompt tuning from now on; the pooled "all" rows in `summary.tsv` include them for reporting only.
- The grammar forces valid text characters (no double quote or backslash), so a case that really needs a quote cannot be expressed; none of the 128 does.
