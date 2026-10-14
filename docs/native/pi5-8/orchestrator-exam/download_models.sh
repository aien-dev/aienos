#!/bin/bash
# Download every model in models.tsv to ~/models/pi5-8-orchestrator/<name>/ and record sha256.
# Also records the publisher's own LFS hash (x-linked-etag) so the two can be compared.
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=${MODELS_DIR:-$HOME/models/pi5-8-orchestrator}
mkdir -p "$root"
grep -v '^#' "$here/models.tsv" | while IFS=$'\t' read -r name role repo url file; do
  d="$root/$name"; mkdir -p "$d"
  [ -f "$d/$file" ] || curl -sS -L -o "$d/$file.part" "$url" && mv -f "$d/$file.part" "$d/$file" 2>/dev/null
  sum=$(sha256sum "$d/$file" | cut -d' ' -f1)
  etag=$(curl -sSI -L "$url" | tr -d '\r' | grep -i '^x-linked-etag:' | tail -1 | tr -d '"' | awk '{print $2}')
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$(stat -c %s "$d/$file")" "$sum" "$etag" "$file"
done | tee "$root/downloads.tsv"
