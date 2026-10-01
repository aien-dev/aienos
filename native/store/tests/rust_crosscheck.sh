#!/bin/sh
# C -> Rust cross-check: the Rust aienos-store-tool works on images written
# by the C Store engine, and the C engine classifies images the Rust tool has
# changed the same way the Rust engine does.
#
#   rust_crosscheck.sh XCHECK_BIN OUT_DIR
#
# The Rust tool is found at $RUST_STORE_TOOL, else <repo>/target/release/
# aienos-store-tool. If it is missing the verdict is NOT_RUN (never PASS).
# Rust -> C: no Rust-written image is used here; that direction is covered by
# the golden vectors (byte-exact) and by the Rust-rechecksummed bytes that
# "inject" writes into C images.
set -u
xc=$1
out=$2
here=$(cd "$(dirname "$0")/../../.." && pwd)
tool=${RUST_STORE_TOOL:-$here/target/release/aienos-store-tool}
if [ ! -x "$tool" ]; then
  echo "rust cross-check: Rust store tool not found at $tool"
  echo "STORE_RUST_CROSSCHECK: NOT_RUN"
  exit 0
fi
echo "rust cross-check: tool $tool"
fail=0
n=0
units=64
expect() { # name got want
  n=$((n + 1))
  if [ "$2" = "$3" ]; then echo "  ok   $1: $2"; else echo "  FAIL $1: got [$2] want [$3]"; fail=1; fi
}
# Rust's own opinion of an image: corrupt-kind with a kind no image holds
# mounts (Rust Store::open) and then stops without writing.
rust_mount() { # img off
  r=$("$tool" corrupt-kind "$1" "$2" $units 999 2>&1)
  case "$r" in
    *"no catalog object of kind 999"*) echo MOUNT ;;
    *"store does not mount: "*) echo "REFUSE MountError::${r##*store does not mount: }" ;;
    *) echo "UNEXPECTED $r" ;;
  esac
}
c_mount() { "$xc" classify "$1" "$bs" "$base" $units | sed 's/^MOUNT .*/MOUNT/'; }

for bs in 512 4096; do
  base=$((2 * 4096 / bs)) # store starts 2 units into the device
  off=$((base * bs))
  d=$out/xcheck_$bs
  rm -rf "$d"; mkdir -p "$d"
  echo "geometry $bs-byte blocks, store at byte $off:"
  "$xc" mkpair "$d/old.img" "$d/new.img" $bs $base $units >/dev/null || { echo "  FAIL C image build"; fail=1; continue; }
  expect "C reads its own gen 3" "$("$xc" classify "$d/new.img" $bs $base $units)" "MOUNT state=Valid peer=Valid gen=3 objects_ok=3/3"
  expect "Rust mounts the C image" "$(rust_mount "$d/new.img" $off)" "MOUNT"
  for sector in 512 4096; do
    r=$("$tool" tear-closure "$d/old.img" "$d/new.img" $off $sector 2>&1)
    echo "    $r"
    case "$r" in STORE_ROOT_TEAR_CLOSURE:\ PASS*) expect "tear-closure sector $sector" PASS PASS ;;
      *) expect "tear-closure sector $sector" FAIL PASS ;; esac
  done
  # corrupt-kind on an object both roots hold: both refuse the same way
  cp "$d/new.img" "$d/c7.img"
  r=$("$tool" corrupt-kind "$d/c7.img" $off $units 7 2>&1); echo "    $r"
  expect "corrupt kind 7 (both roots): C" "$("$xc" classify "$d/c7.img" $bs $base $units)" "REFUSE MountError::CorruptRecoveryRequired"
  expect "corrupt kind 7 (both roots): Rust" "$(rust_mount "$d/c7.img" $off)" "REFUSE MountError::CorruptRecoveryRequired"
  # corrupt-kind on an object only the newest root holds: both mount the older root
  cp "$d/new.img" "$d/c9.img"
  r=$("$tool" corrupt-kind "$d/c9.img" $off $units 9 2>&1); echo "    $r"
  expect "corrupt kind 9 (newest only): C" "$("$xc" classify "$d/c9.img" $bs $base $units)" "MOUNT state=DegradedRecovery peer=GraphBadNewer gen=2 objects_ok=2/2"
  expect "corrupt kind 9 (newest only): Rust" "$(rust_mount "$d/c9.img" $off)" "MOUNT"
  # inject into the inactive slot (slot 1 holds gen 2; slot 0 holds gen 3)
  cp "$d/new.img" "$d/gen4.img"
  "$xc" advance "$d/gen4.img" $bs $base $units >/dev/null
  for case in bad_crc wrong_magic nonzero_reserved wrong_slot_id region_mismatch unsupported_version seeded_garbage new_root; do
    img=$d/inj_$case.img
    cp "$d/new.img" "$img"
    src=$d/new.img
    [ $case = new_root ] && src=$d/gen4.img
    r=$("$tool" inject "$img" $off inactive $case "$src" 2>&1); echo "    $r"
    case $case in
      unsupported_version) want="REFUSE MountError::UnsupportedVersion" ;;
      new_root) want="MOUNT state=DegradedRecovery peer=GraphBadNewer gen=3 objects_ok=3/3" ;;
      *) want="MOUNT state=DegradedRecovery peer=Malformed gen=3 objects_ok=3/3" ;;
    esac
    got=$("$xc" classify "$img" $bs $base $units)
    expect "inject $case: C" "$got" "$want"
    rw=$(echo "$want" | sed 's/^MOUNT .*/MOUNT/')
    expect "inject $case: Rust agrees" "$(rust_mount "$img" $off)" "$rw"
  done
done
echo "rust cross-check: $n checks"
if [ $fail -eq 0 ]; then echo "STORE_RUST_CROSSCHECK: PASS"; else echo "STORE_RUST_CROSSCHECK: FAIL"; exit 1; fi
