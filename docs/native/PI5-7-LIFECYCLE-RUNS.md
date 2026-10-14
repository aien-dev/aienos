# PI5-7 agent runtime on the Raspberry Pi 5: run evidence

QUALIFICATION ONLY. Image `make pi5-lifecycle` (CK_PI5_LIFECYCLE=1, PI5-7 cut 2, #370): the resident agent
lifecycle runs on the Pi, driven by a command script on the card (`\EFI\AIENOS\AGENT.CMD`). The Store secret
comes from the card `UNLOCK.REQ` (a throwaway qualification secret, never committed). All four runs used the
same image (EFI sha256 `282507650d85d5e38a55f50663efc004a9aa1df9522fe01394516ccd43174641`, built from the #370
branch on top of `073554361dd5`). Harness: `pi5-run-lifecycle.sh` (pi5-run.sh plus `AGENT_CMD=`), KLOG=1.

| Run | Restart before it | Secret | Model | Result |
|---|---|---|---|---|
| L1 | tryboot soft reset | right | loaded (MODEL.MAP) | preference stored gen 11; reply approved and committed gen 12 id `e69ceb6d` |
| L2 | tryboot soft reset | right | none | recall gen 12 id `e69ceb6d` 356 bytes; preference "short notes"; continuity resumed incarnation 2 |
| L3 | tryboot soft reset | wrong | none | Store refused (RecoverySecretRejected), disk left as found; every memory verb refused |
| P1 | **full power cut**: clean OS shutdown, power unplugged 10 s, cold boot (Linux uptime 6 min when the run started) | right | none | recall gen 12 id `e69ceb6d` 356 bytes; preference "short notes"; continuity resumed incarnation 3 |

The full `recall gen=12` line (stored prompt, reply, context digest, model digest) has the same sha256
(`8c82ce42ea0f33f9...`) in L1, L2 and P1: what the kernel prints from the persisted object is identical after a soft reset and after a
real power loss. The generation steps are consistent with each successful boot committing two Store records (boot count and
continuity incarnation; inferred, not logged separately): the
Store opened at generation 12 in L2 and at 14 in P1 (L3 wrote nothing), while the reply object stays at generation 12.

## Kernel log lines (verbatim, long lines cut at 230 characters)

```
--- l1
store: opened generation=8 boot_count=4 prev_commit=5429602193cfc5ab79b05c0111b0cbad36e74fed anchor=valid-resume
lifecycle: preferred id=2 t=2 store_gen=11 bytes=11 permitted=context agent=937b377ef64bae1f safe=yes text="short notes"
lifecycle: state=ready store=open pending=- requests=2 continuity=provisioned agent=937b377ef64bae1f incarnation=1 subject_seq=1
lifecycle: recall gen=7 kind=reply id=748380ef bytes=209 text="aienos.reply.v1?prompt: What is the capital of France??reply: The capital of France is Paris.?model: 3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1?i
lifecycle: context memory=used selected=1 eligible=1 omitted=0 legacy=1 unpermitted=0 unsafe=0 other=0 records=2 prompt_bytes=116 limit=752 sha256=9de8ebddce5c8a3e agent=937b377ef64bae1f
lifecycle: reply pending state=serve proposed="reply: The capital of France is Paris." (approve | deny | cancel)
lifecycle: approve committed gen=12 id=e69ceb6d state=ready
lifecycle: recall gen=12 kind=reply id=e69ceb6d bytes=356 text="aienos.reply.v1?prompt: What is the capital of France??reply: The capital of France is Paris.?context: sha256=9de8ebddce5c8a3e972fbf582776a2ed64d5f066f7b6bb7979c0ba7e
lifecycle: preference id=2 t=2 store_gen=11 agent=937b377ef64bae1f permitted=context text="short notes"
lifecycle: evidence requests=8 refused=0 invalid=0 tasks=0 approved=1 denied=0 cancelled=0 overlong=0 last_commit_gen=12 last_id=e69ceb6d prompts=1 replies=1 gen_cancelled=0 gen_failed=0 recalls=2 inference=resident remembers=0 fa
--- l2
store: opened generation=12 boot_count=5 prev_commit=073554361dd508f809c4b474ad66579104bd633f anchor=valid-resume
lifecycle: state=ready store=open pending=- requests=1 continuity=resumed agent=937b377ef64bae1f incarnation=2 subject_seq=1
lifecycle: recall gen=12 kind=reply id=e69ceb6d bytes=356 text="aienos.reply.v1?prompt: What is the capital of France??reply: The capital of France is Paris.?context: sha256=9de8ebddce5c8a3e972fbf582776a2ed64d5f066f7b6bb7979c0ba7e
lifecycle: preference id=2 t=2 store_gen=11 agent=937b377ef64bae1f permitted=context text="short notes"
lifecycle: evidence requests=4 refused=0 invalid=0 tasks=0 approved=0 denied=0 cancelled=0 overlong=0 last_commit_gen=0 last_id=00000000 prompts=0 replies=0 gen_cancelled=0 gen_failed=0 recalls=1 inference=none remembers=0 facts=1
--- l3
store: REFUSED proof=keyed step="recovery secret rejected (K_vol unwrap tag failed); disk not opened" rc=-2004 (RecoverySecretRejected); disk left as found, not reformatted
lifecycle: REFUSED verb=prefer state=locked reason="locked: no production Store"
lifecycle: state=locked store=locked pending=- requests=2 continuity=none
lifecycle: REFUSED verb=recall state=locked reason="locked: no production Store"
lifecycle: REFUSED verb=prompt state=locked reason="locked: no production Store"
lifecycle: REFUSED verb=approve state=locked reason="nothing pending"
lifecycle: REFUSED verb=recall state=locked reason="locked: no production Store"
lifecycle: REFUSED verb=facts state=locked reason="locked: no production Store"
lifecycle: evidence requests=8 refused=6 invalid=0 tasks=0 approved=0 denied=0 cancelled=0 overlong=0 last_commit_gen=0 last_id=00000000 prompts=0 replies=0 gen_cancelled=0 gen_failed=0 recalls=0 inference=none remembers=0 facts=0
--- powercut
store: opened generation=14 boot_count=6 prev_commit=073554361dd508f809c4b474ad66579104bd633f anchor=valid-resume
lifecycle: state=ready store=open pending=- requests=1 continuity=resumed agent=937b377ef64bae1f incarnation=3 subject_seq=1
lifecycle: recall gen=12 kind=reply id=e69ceb6d bytes=356 text="aienos.reply.v1?prompt: What is the capital of France??reply: The capital of France is Paris.?context: sha256=9de8ebddce5c8a3e972fbf582776a2ed64d5f066f7b6bb7979c0ba7e
lifecycle: preference id=2 t=2 store_gen=11 agent=937b377ef64bae1f permitted=context text="short notes"
lifecycle: evidence requests=4 refused=0 invalid=0 tasks=0 approved=0 denied=0 cancelled=0 overlong=0 last_commit_gen=0 last_id=00000000 prompts=0 replies=0 gen_cancelled=0 gen_failed=0 recalls=1 inference=none remembers=0 facts=1
```

Raw logs: `~/workspace/pi5-runs/pi5-lifecycle-{l1,l2,l3,powercut}/kernel.log` on the Spark.

## Not verified

- The image was built before #370 was rebased onto #369; the rebased image was not re-run on the Pi.
- P1 is one power cut while the Pi was idle (after a clean shutdown). A power cut in the middle of a Store
  commit is covered only by the QEMU crash gates, not on hardware.
- L3 had no model loaded, so it does not exercise a refusal on the inference path.
