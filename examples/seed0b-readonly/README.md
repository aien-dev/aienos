# SEED-0B read-only canary artifact

This fixture is the first intended external Binary Artifact v0 payload. Its
entry ABI passes the first granted capability handle in `x0`. The artifact
requests one READ-only object capability (resource ID `0x49504f42`, the M3
kernel object resource), reads word zero, checks the qualification value
`0xc0ffee01`, attempts a write through the same handle, and exits with:

| Exit status | Meaning |
| --- | --- |
| `0` | Read matched and write was denied |
| `1` | Read failed or returned another value |
| `2` | Write unexpectedly succeeded |

The only capability request has READ (`rights: 1`), one object-word range, and
no device, DMA, network, filesystem, or firmware authority. The data section
is intentionally non-empty because Binary Artifact v0 requires a code and a
data section.

Build the signed qualification artifact from the repository root:

```sh
bash examples/seed0b-readonly/build.sh
```

The generated external artifact is `readonly-canary.aien` beside these
sources. Its qualification build identities are:

```text
file SHA-256: 71df7d565bbe87b5e6abd93d8493cadcfd071a35e6a2ce3a0091c68e0ea33020
ArtifactId:   8a345c9f1049e714e5795ec936db638a32ccf5d7ccb962c66e781ce69f304791
payload SHA:  330583512ec8701c937fe09db722dd5200139330ca10222817bf925ddfa2199a
signer:       21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9
```

The script requires GNU AArch64 binutils and uses only the explicit
`seed0b-test-signing` RFC 8032 test identity. The private test vector is public
and is not suitable for production. The script prints the artifact SHA-256,
ArtifactId, payload SHA-256, and test signer fingerprint. It creates no
production trust root and makes no platform trust changes.

This is a qualification input fixture. It does not claim that the current
kernel dynamically loads or executes this artifact yet.
