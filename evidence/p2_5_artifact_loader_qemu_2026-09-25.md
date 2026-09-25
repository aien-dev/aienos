# P2-5 evidence: Binary Artifact loader, exact-byte EL0 execution, W^X (QEMU)

Date: 2026-09-25 · Commit: `e9defa69f4df472262cd1aadedeb396d8af9d936` (read back from the image: `aienos_commit:` line) · Host: DGX Spark (aarch64), QEMU `virt`, AAVMF, TCG single-thread · Scope: QEMU only. Machine 1 is P2-9.

## Claim

A cryptographically admitted external program executes as an isolated EL0
principal from the exact bytes AIENOS authenticated:

```text
identified bytes = verified bytes = admitted bytes = mapped bytes = executed bytes
```

## Pipeline under test (`crates/aienos-kernel/src/artifact_loader.rs`)

Firmware reads `\EFI\AIENOS\ARTIFACTS\*.AIEN` into LOADER_DATA pages and does
not interpret them. After firmware exit the kernel:

1. Stages the bytes into contiguous NX kernel frames. These are never mapped into the task.
2. Parses them, computes the ArtifactId, and checks Ed25519 against the local anchors. This is the `Verified` state.
3. Applies the deterministic admission policy: READ on SEED object 1 only, no IPC. This is `Authorized`.
4. Reserves the scheduler slot, every content and table frame, and the shadow table frames, all before mapping anything. This is `Reserved`.
5. Builds a private L0 (a copy of the kernel root) and a private L1/L2/L3 window laid out as guard | code | guard | data | guard | stack | guard. It copies the exact code and data through the RW+NX identity alias.
6. Hashes the code and data bytes read back from the private frames (SHA-256 of code‖data) and requires it to equal the admitted payload digest. This is `Hashed`.
7. Seals the task. It syncs the I-cache and maps code EL0 RX (PXN). In the task root's private shadow of the identity map, it marks each code frame's EL1 alias read-only+PXN+UXN. It then runs a fail-closed audit of the whole window and every code alias (`audit_wx`). This is `Sealed`.
8. Installs exactly the policy grants in the task's own M3 `CapTable`, with the resource value set to the grant index. It also writes the handle array at the stack top.
9. Produces a `LoadedTask`, hands it to the scheduler (`tick`), and runs it at EL0 through `task_runtime::run`. EL0 starts with zeroed GPRs and SIMD registers, TTBR0 set to the task root with ASID 2, and a timer enforcing min(cpu_ticks, elapsed_ticks). The runtime also enforces the syscall budget.
10. On any ending, it re-hashes the code frames (executed bytes), revokes every handle, scrubs and releases every frame, and frees the slot.

## Artifacts (deterministic: two independent packs are byte-identical)

| File | ArtifactId | File SHA-256 |
|---|---|---|
| P25EXEC.AIEN | `19429f616c5b531594a3495f6bb7dccf0b55f1cd497d748fe31a5a4abad8f26f` | `49c3621c190bf3fa8ea9ee4b7cd7f7b65472edc2a790d81aa4a29b43ffa56244` |
| P25WX.AIEN | `aa57bd141cf88fd07256bcf2233f8785e63b66692ab76e6d5c84bed3d8c1a09a` | `54a749077cdaf862b0d1410713529890c2bb7b0052f634809eee9129c31f2eb7` |
| P25SPIN.AIEN | `a683f56212ca600d21b529b8d336aad4674dc6a2bcb52d70359fca3959ca09ac` | `5589ef4256f29a2bf96d58a02f5d28c86ca49ba2fb3499bc6937eaf2cdcb9ff9` |
| P25TAMP.AIEN | (P25EXEC with one payload bit flipped after signing) | `069e10eda35bef104a8ff877cdb956724f0ccf8b2ecada3926bf89a61ffb3852` |

The probe sources, code and data binaries, and manifests are in `crates/aienos-artifact-tool/fixtures/p2_5/`. `code.bin` is checked byte-for-byte against `probe.S` on every run. The signer is the SEED-0B test key (RFC 8032 TEST 1), used only in a debug host tool.

## Raw serial: qualification build (`--features seed0b-qualification`)

```text
aienos_commit: e9defa69f4df472262cd1aadedeb396d8af9d936
artifact_candidates: 4
artifact: P25EXEC.AIEN admitted id=19429f616c5b5315 tier=seed0b-test exec=exited:0x0 bytes=identified=verified=admitted=mapped=executed wx=enforced caps=1 revoked=yes reclaimed=yes frames=10 syscalls=3 reads=1 denials=1
artifact: P25SPIN.AIEN admitted id=a683f56212ca600d tier=seed0b-test exec=timeout bytes=identified=verified=admitted=mapped=executed wx=enforced caps=0 revoked=yes reclaimed=yes frames=10 syscalls=0 reads=0 denials=0
artifact: P25TAMP.AIEN rejected stage=verified reason=BadSignature reclaimed=yes
artifact: P25WX.AIEN admitted id=aa57bd141cf88fd0 tier=seed0b-test exec=fault:code-write bytes=identified=verified=admitted=mapped=executed wx=enforced caps=0 revoked=yes reclaimed=yes frames=10 syscalls=0 reads=0 denials=0
artifacts: candidates=4 admitted=3 rejected=1
artifact_trust: SEED-0B QUALIFICATION BUILD — TEST ONLY TRUST ANCHOR
artifact_trust: seed0b-test qualification build — TEST ONLY
```

- **P25EXEC:** exit 0 means every check in `probe.S` passed:
  - exactly one handle;
  - its authenticated data word read back at EL0;
  - data and stack are writable;
  - `OBJECT_READ` through the granted handle returned the SEED word;
  - a forged-generation handle was denied.

  The runtime counters agree: 3 syscalls (read, forged read, exit), 1 successful read, 1 denial.
- **P25WX:** it stored to its own code page and got an EL0 write permission fault with FAR inside the code range. It was terminated, not resumed.
- **P25SPIN:** `b .` forever. It was killed by the timer IRQ from EL0 at its 6,250,000-tick budget.
- **P25TAMP:** the ArtifactId changed, so the signature failed before any task frame was reserved.
- **frames=10:** 3 content pages (1 code, 1 data, 1 stack), 4 window tables, and 3 shadow tables (a private L1, L2 and L3 on the path to the code frame). Every candidate reported `reclaimed=yes`, meaning allocator free count before equals free count after, and no live capability remained.

## Raw serial: ordinary build (empty production trust)

```text
artifact_candidates: 4
artifact: P25EXEC.AIEN rejected stage=verified reason=UntrustedSigner reclaimed=yes
artifact: P25SPIN.AIEN rejected stage=verified reason=UntrustedSigner reclaimed=yes
artifact: P25TAMP.AIEN rejected stage=verified reason=UntrustedSigner reclaimed=yes
artifact: P25WX.AIEN rejected stage=verified reason=UntrustedSigner reclaimed=yes
artifacts: candidates=4 admitted=0 rejected=4
artifact_trust: no production anchors enrolled
```

## Mutation control (audit is live)

I temporarily removed `AP_READ_ONLY` from the shadow alias leaf, leaving the code frames' EL1 alias writable in the task root. The same QEMU run then produced:

```text
artifact: P25EXEC.AIEN rejected stage=sealed reason=WxAudit reclaimed=yes
artifact: P25SPIN.AIEN rejected stage=sealed reason=WxAudit reclaimed=yes
artifact: P25TAMP.AIEN rejected stage=verified reason=BadSignature reclaimed=yes
artifact: P25WX.AIEN rejected stage=sealed reason=WxAudit reclaimed=yes
```

No task ran, and everything was reclaimed. The change was reverted before commit.

## Gates run at this commit

- `AIENOS_STRICT=1 ./scripts/verify_all.sh` exited 0 with 0 FAIL and 0 SKIPPED. That covers:
  - fmt, 370 host tests, and `clippy -D warnings`;
  - the aarch64 kernel build and both EFI images;
  - `QEMU_BOOT: PASS` (M3 el0/ipc/preempt unchanged);
  - `QEMU_KEYBOARD: PASS` (smmu + fail-closed) and the SMMU confinement run;
  - `QEMU_ARTIFACT: PASS`;
  - recovery tools.
- The host loader suite (`artifact_loader_tests.rs`, 19 tests) runs over a mock physical memory on three kernel-map shapes (1 GiB block, 2 MiB blocks, 4 KiB pages). It covers:
  - every rejection stage and error, with full reclaim;
  - kernel tables byte-identical after each load;
  - zeroed frames;
  - grants ⊆ requests;
  - audit tamper detection;
  - an executed-digest mismatch path.

## Not covered here

- Admission Receipt v0 encoding and signing is separate work, needed from P2-6 on.
- P2-6's first SEED-0B capability artifact, with a WRITE attempt through a READ handle and a receipt.
- The P2-7 full hostile-input matrix.
- Machine 1 (P2-9).
- The kernel root keeps its RW+NX alias of code frames; it is used only before sealing and after the task has left the CPU. While the task lives, the only active translation regime is the task root, where the alias is read-only.
