# aienos-artifact-tool

Host CLI for Binary Artifact v0. The CLI calls the same `aienos-artifact`
parser and identity code used by the kernel.

```text
aienos-artifact-tool pack MANIFEST.json CODE.bin DATA.bin OUTPUT.aien
aienos-artifact-tool inspect FILE.aien
aienos-artifact-tool id FILE.aien
aienos-artifact-tool sign INPUT.aien OUTPUT.aien
aienos-artifact-tool verify FILE.aien
```

`pack` accepts UTF-8 JSON with exactly these top-level fields:

```json
{
  "entry_offset": 0,
  "capabilities": [
    {
      "resource_kind": 3,
      "resource_id": 7,
      "rights": 1,
      "bounds_kind": 1,
      "max_operations": 4,
      "max_bytes": 4,
      "byte_offset": 0,
      "byte_length": 4
    }
  ],
  "resources": {
    "code_pages": 1,
    "data_pages": 1,
    "stack_pages": 1,
    "max_capabilities": 1,
    "ipc_messages": 2,
    "ipc_bytes": 16,
    "cpu_ticks": 1000,
    "elapsed_ticks": 2000,
    "syscall_count": 16
  }
}
```

`pack` rejects unknown JSON fields and validates its output with the shared
parser. Repeating `pack` with the same manifest and code/data bytes produces
identical bytes. The initial signature block is structurally valid but
unauthenticated until signed.

Qualification signing is deliberately opt-in:

```text
cargo run -p aienos-artifact-tool --features seed0b-test-signing -- sign INPUT.aien OUTPUT.aien
cargo run -p aienos-artifact-tool --features seed0b-test-signing -- verify OUTPUT.aien
```

That feature uses only the public RFC 8032 test-vector identity. It is not a
production key or production signing facility. Without the feature, the
verification trust-anchor set is empty and signing returns an error.
