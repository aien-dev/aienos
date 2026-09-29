#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output="${1:-${repo_root}/examples/seed0b-readonly/readonly-canary.aien}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/seed0b-artifact.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

for tool in aarch64-linux-gnu-as aarch64-linux-gnu-objcopy; do
    command -v "$tool" >/dev/null || {
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 2
    }
done

mkdir -p "$(dirname "$output")"
aarch64-linux-gnu-as -o "$tmp/readonly_canary.o" \
    "$repo_root/examples/seed0b-readonly/readonly_canary.S"
aarch64-linux-gnu-objcopy --only-section=.text -O binary \
    "$tmp/readonly_canary.o" "$tmp/code.bin"
aarch64-linux-gnu-objcopy --only-section=.data -O binary \
    "$tmp/readonly_canary.o" "$tmp/data.bin"

cargo run --quiet --offline -p aienos-artifact-tool \
    --features seed0b-test-signing -- pack \
    "$repo_root/examples/seed0b-readonly/manifest.json" \
    "$tmp/code.bin" "$tmp/data.bin" "$tmp/unsigned.aien"
cargo run --quiet --offline -p aienos-artifact-tool \
    --features seed0b-test-signing -- sign \
    "$tmp/unsigned.aien" "$output"
cargo run --quiet --offline -p aienos-artifact-tool \
    --features seed0b-test-signing -- verify "$output"
sha256sum "$output"
