# PI5-8: ALLEN REFLEX v0, ALLEN's own decision core

Status: in progress. This file starts with the evaluation protocol, written and committed before any model code (plan amendment 14).

## Evaluation protocol (frozen before building)

1. The exam is the frozen orchestration exam in `docs/native/pi5-8/orchestrator-exam/` (freeze `e1c9a0f`, cases from `59b8888`). The scorer `score.sh` is reused unchanged.
   REFLEX writes `results/allen-reflex.<split>.<mode>.jsonl` in `run_exam.sh`'s record format; `raw` is the decision JSON only. Explanations go to a separate file.
2. Modes: `reflex` (hypervector core), `nearest` (nearest exemplar over the same features, no hypervectors), `perceptron` (linear classifier over the same features).
   All three share the same front end (turn roles, pending-task state, request ordering, policy layer, span copy, output check) and differ only in the label scorer.
3. Inference sees only the turns of a case. Ids, categories, expected actions and expected texts are read by the host harness for the record, never passed to the core.
4. Training data: `cases-train.psv` plus `cases-reflex-extra.psv` (cases we write ourselves from the action contract and the train split, each tagged with a paraphrase family and its source). Nothing is written from dev or held-out.
5. Tuning (feature weights, k, thresholds, retraining passes, zero band) uses dev and a leave-one-family-out check on the training pool. Every dev-driven change is logged in this file.
6. The held-out files (`cases-heldout.*`, any `results/*heldout*`) are not opened, searched or printed until code, data, thresholds and seeds are committed and that commit is recorded here.
   Then held-out is scored exactly once with learning disabled, and the number is reported as it comes out. After that, only documentation changes.
7. The learning-curve experiment runs on dev with the frozen thresholds: each case is predicted and scored before its correction is revealed; memory is reset between experiments.
