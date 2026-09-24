# Instructions for coding agents working on AIENOS

Read `CONTRIBUTING.md`, `CONTEXT.md` (domain language) and `docs/MILESTONES.md`
(gate order and escalation triggers) before starting. They are binding. This
file adds what agents most often get wrong here.

## Finish line for every pull request

1. `bash scripts/verify_all.sh` passes. Paste the command and the tail of its
   output (the PASS/FAIL lines) at the top of the PR description.
2. On an x86 runner some steps print `SKIPPED` (AArch64-only recovery tests,
   KVM). Say which steps skipped; never describe a skipped step as passing.
3. The PR description ends with one line `SECURITY_IMPACT: <class>`, one of
   NONE, BOUNDARY, ROOT_OF_TRUST, AUTHORITY, RECOVERY, PERSISTENT_FORMAT.
   Anything in the kernel privilege path, capabilities, AEGIS, storage unlock,
   crypto or recovery is not NONE.
4. One concern per PR, and keep it reviewable: aim for under 600 changed
   lines. Split larger work into a series and say what comes next.

## Hard rules

- Rust only (small AArch64 assembly where hardware demands it). No Python, no
  shell scripts that fetch from the network, no CUDA or CUDA-shaped APIs.
- No systemd anywhere: no units, no systemd-creds, no journald, no emulation
  of them. AIENOS has its own init and supervision.
- No new crates in the kernel, boot or trusted-base crates unless the issue
  asks for one. Elsewhere, justify each new dependency in the PR.
- The kernel must work with no AI model loaded. Models never run in the
  kernel and never hold authority.
- Never claim hardware behavior. Only QEMU and host-test results can be
  claimed; Machine 1 (DGX Spark) evidence is produced by maintainers.
- Do not edit existing files in `evidence/`, the recovery scripts
  (`scripts/build_recovery_media.sh`, `scripts/build_standalone_recovery_initrd.sh`,
  `scripts/qemu_verify_recovery_media.sh`), signing or key tooling, or
  `.github/workflows/`, unless the issue explicitly asks for it.
- No secrets, keys, personal data or photos in the repository.
- Docs and comments: plain language, no em dashes or en dashes.

## Kernel ordering (Milestone 3)

ADR 0009 is accepted: the kernel moves from EL2 to EL1h before anything else in
M3. Until that change is on `main`, do not implement MMU page tables, exception
vector changes, interrupt or timer bring-up, task switching or EL0 entry, even
if an issue seems to ask. Host-testable logic (pure Rust with unit tests, no
system registers) is fine and preferred: build it so the EL1 kernel can adopt
it later.

## ADRs

Check `docs/adr/` **and open pull requests** for the next free ADR number
before writing one, update `docs/adr/README.md`, and start with
`Status: Proposed.` Only the operator accepts ADRs.

## Useful commands

```bash
rustup target add aarch64-unknown-uefi aarch64-unknown-none
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p aienos-kernel --target aarch64-unknown-none --no-default-features
bash scripts/qemu_boot_test.sh     # UEFI boot in QEMU, needs qemu-system-aarch64 + AAVMF
bash scripts/verify_all.sh         # everything
```
