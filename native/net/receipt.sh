#!/bin/sh
# receipt.sh: one content-addressed M6-A host receipt for the current commit.
# Refuses a dirty tree. Runs make test + make sanitize from clean, records the
# commit, toolchain, source hashes and verdict lines, and writes
# receipts/m6a_net_host_<sha256 of the receipt body>.txt. Never overwrites.
#
# Optional: RUSTDIFF=/path/to/driver runs an external driver built from the
# UNMODIFIED Rust reference (kept outside this repo: no Rust in AIENOS) on the
# same corpus and records a live comparison; otherwise that line is NOT_RUN and
# only the pinned digest is checked.
set -eu
cd "$(dirname "$0")"
top=$(git rev-parse --show-toplevel)
if [ -n "$(git -C "$top" status --porcelain --untracked-files=normal)" ]; then
    echo "receipt: refusing to run on a dirty tree:" >&2
    git -C "$top" status --short >&2
    exit 2
fi
commit=$(git rev-parse HEAD)
log=$(mktemp -d "${TMPDIR:-/tmp}/m6a-net-receipt.XXXXXX")
make clean >/dev/null
status=PASS
make test > "$log/test.txt" 2>&1 || status=FAIL
make sanitize > "$log/sanitize.txt" 2>&1 || status=FAIL
live="NET_RUST_DIFFERENTIAL_LIVE: NOT_RUN (no RUSTDIFF driver given; pinned digest checked)"
if [ -n "${RUSTDIFF:-}" ]; then
    if "$RUSTDIFF" < out/diff_corpus.bin > "$log/rust.txt" && cmp -s "$log/rust.txt" out/diff_c.txt; then
        live="NET_RUST_DIFFERENTIAL_LIVE: PASS (driver sha256 $(sha256sum "$RUSTDIFF" | cut -d' ' -f1))"
    else
        live="NET_RUST_DIFFERENTIAL_LIVE: FAIL"; status=FAIL
    fi
fi
if [ -n "$(git -C "$top" status --porcelain --untracked-files=normal)" ]; then
    echo "receipt: the run changed tracked files" >&2; status=FAIL
fi
body="$log/body.txt"
{
    echo "AIENOS M6-A hosted C network stack receipt"
    echo "commit: $commit"
    echo "host: $(uname -srm)"
    echo "cc: $(${CC:-cc} --version 2>/dev/null | head -1)"
    echo "scope: host tests only (no QEMU, no hardware, no native binding, TEST identity only)"
    echo "sources:"
    for f in aienos_net.c aienos_net.h aienos_virtio_pci.c aienos_virtio_pci.h aienos_ctl.c aienos_ctl.h \
             ../argus/sha256.c tests/net_test.c tests/ctl_test.c tests/net_diff.c Makefile receipt.sh; do
        echo "  $(sha256sum "$f" | cut -d' ' -f1)  native/net/$f"
    done
    echo "rust reference (spec, unmodified):"
    for f in "$top/crates/aienos-kernel/src/net.rs" "$top/crates/aienos-kernel/src/virtio_net.rs"; do
        echo "  $(sha256sum "$f" | cut -d' ' -f1)  ${f#$top/}"
    done
    echo "differential corpus: $(sha256sum out/diff_corpus.bin | cut -d' ' -f1)"
    echo "results:"
    grep -hE '^(net_test|ctl_test|lib-checks|NET_|CTL_|  [a-z+0-9-]+ +(done|link_down))' "$log/test.txt" "$log/sanitize.txt" | sed 's/^/  /'
    echo "  $live"
    echo "deferred (not claimed): native binding -> needs a C kernel (no-Rust rule; port order open);"
    echo "  production identity and keys, secure transport -> needs M5 key hierarchy (TRUST-1);"
    echo "  physical NIC qualification -> needs Machine 1 wave after TRUST-1 Gate 7."
    echo "M6A_NET_HOST: $status"
} > "$body"
digest=$(sha256sum "$body" | cut -d' ' -f1)
mkdir -p receipts
out="receipts/m6a_net_host_${digest}.txt"
[ -e "$out" ] || cp "$body" "$out"
cat "$out"
echo "receipt: native/net/$out (raw logs in $log)"
[ "$status" = PASS ]
