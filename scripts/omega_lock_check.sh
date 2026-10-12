#!/usr/bin/env bash
# omega_lock_check.sh -- the vendored Omega sources (native/kernel/third_party/omega)
# are byte for byte the files of the omega commit named in omega.lock.
#
# omega.lock: line 1 is the full omega commit sha; every further line is
#   sha256 <hex> <vendored path> <path in omega>
# Always: each vendored file's sha256 equals the recorded one (offline).
# When possible: the recorded sha256 equals the blob at that commit in omega
# (OMEGA_LOCK_REPO=<local omega checkout>, else a shallow fetch of the commit
# from GitHub; skipped with a NOTE when neither works, never a PASS for it).
# Exit 0 only when every check that ran passed. No Python.
set -u
cd "$(dirname "$0")/.." || exit 2
lock=omega.lock
[ -r "$lock" ] || { echo "OMEGA_LOCK: FAIL $lock missing"; exit 1; }
sha=$(sed -n 1p "$lock")
case "$sha" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) echo "OMEGA_LOCK: FAIL line 1 is not a commit sha"; exit 1 ;;
esac
[ ${#sha} -eq 40 ] || { echo "OMEGA_LOCK: FAIL line 1 is not a full sha"; exit 1; }
fail=0
n=0
while read -r tag hex path opath; do
    [ "$tag" = sha256 ] || continue
    n=$((n + 1))
    if [ ! -r "$path" ]; then echo "FAIL $path missing"; fail=1; continue; fi
    have=$(sha256sum "$path" | cut -d' ' -f1)
    if [ "$have" = "$hex" ]; then echo "PASS $path sha256 matches omega.lock"; else echo "FAIL $path sha256 $have, omega.lock says $hex"; fail=1; fi
done < "$lock"
[ "$n" -gt 0 ] || { echo "OMEGA_LOCK: FAIL no sha256 lines"; exit 1; }

# upstream check
repo="${OMEGA_LOCK_REPO:-}"
tmp=""
if [ -z "$repo" ] && command -v git >/dev/null 2>&1; then
    tmp=$(mktemp -d)
    if git -C "$tmp" init -q 2>/dev/null && git -C "$tmp" fetch -q --depth=1 https://github.com/aien-dev/omega.git "$sha" 2>/dev/null; then
        repo="$tmp"
        up=FETCH_HEAD
    fi
fi
[ -n "${up:-}" ] || up="$sha"
if [ -n "$repo" ] && git -C "$repo" cat-file -e "$up^{commit}" 2>/dev/null; then
    while read -r tag hex path opath; do
        [ "$tag" = sha256 ] || continue
        blob=$(git -C "$repo" show "$up:$opath" 2>/dev/null | sha256sum | cut -d' ' -f1)
        if [ "$blob" = "$hex" ]; then echo "PASS omega $opath at ${sha:0:12} matches omega.lock"; else echo "FAIL omega $opath at ${sha:0:12} is $blob, omega.lock says $hex"; fail=1; fi
    done < "$lock"
else
    echo "NOTE upstream check not run (no OMEGA_LOCK_REPO and no fetch of $sha); offline sha256 check only"
fi
[ -n "$tmp" ] && rm -rf "$tmp"
if [ "$fail" = 0 ]; then echo "OMEGA_LOCK: PASS commit=$sha files=$n"; exit 0; fi
echo "OMEGA_LOCK: FAIL commit=$sha"
exit 1
