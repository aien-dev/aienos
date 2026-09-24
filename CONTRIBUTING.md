# Contributing to AIENOS

Thank you for considering it. AIENOS is experimental and pre-alpha; we welcome
contributions of code, review, design and testing.

## Find something to work on

- [ROADMAP.md](ROADMAP.md) shows the gates and links every open issue.
- Issues labelled `good first issue` are small and self-contained.
- Issues labelled `emulator-ok` need no special hardware: everything runs in
  QEMU on an ordinary machine.
- Comment on an issue before starting larger work so effort is not duplicated.
  Questions and ideas belong in GitHub Discussions.

## Build and verify

You need a Rust toolchain with two extra targets:

```bash
rustup target add aarch64-unknown-uefi aarch64-unknown-none
bash scripts/verify_all.sh
```

`verify_all.sh` runs every workspace test, `clippy -D warnings`, the bare-metal
kernel build, and a format check of both UEFI images. It must pass before a
pull request is reviewed.

For boot work, install QEMU for AArch64 and the AAVMF UEFI firmware (on Ubuntu:
`qemu-system-arm` and `qemu-efi-aarch64`). An automated emulator boot is being
added in [#18](https://github.com/aien-dev/aienos/issues/18); once it lands it
becomes part of `verify_all.sh`.

## Rules for code

- **Rust.** Small AArch64 assembly is fine where the hardware requires it.
- **No Python, no CUDA, no CUDA-shaped APIs** anywhere in the repository.
- **Sovereign trusted base.** Boot, kernel, memory management, scheduling,
  storage, cryptography, identity, AEGIS and recovery build from inspectable
  source, offline. Do not add proprietary binaries, cloud services or network
  fetches to the build.
- **Dependencies are rare.** Prefer small in-house code for the trusted base
  (the kernel carries its own SHA-256 and HMAC). Explain any new crate in the
  pull request.
- **Tests.** New behaviour comes with host tests; anything that touches the
  boot path must build for `aarch64-unknown-uefi` and `aarch64-unknown-none`.

## Pull requests

- One concern per pull request.
- Lead the description with proof: the commands you ran and their output.
- Claims about speed or hardware behaviour need recorded evidence.
- House style for docs and comments: plain language, no em dashes or en dashes.
- Changes that touch the root of trust, security boundaries, persistent
  identity, irreversible data formats or recovery guarantees need maintainer
  and operator sign-off; see the escalation triggers in
  [docs/MILESTONES.md](docs/MILESTONES.md).

## Hardware

Machine 1 is an NVIDIA DGX Spark. Work that needs it is labelled
`needs-hardware`; maintainers run those boots under the `aien-proof`
hardware-test ledger and publish the evidence in `evidence/`. You can still
design and review that work, and most of it can be prototyped in QEMU first.

## Security

Report vulnerabilities privately through GitHub's "Report a vulnerability"
(Security advisories) on this repository, not in public issues.

## License

AIENOS is licensed under Apache-2.0 WITH LLVM-exception. By submitting a
contribution you agree that it is licensed under the same terms.
