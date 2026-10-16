#!/usr/bin/env bash
# allen_route_mutants.sh -- red before green for the interactive routing layer (aienos#399).
#
# Runs crates/allen-reflex/tests/route.rs once as is (must PASS) and once per host-only mutant feature of
# crates/allen-reflex (must FAIL, else the tests do not catch that mutation):
#   route-mutant-grant           an approval phrase runs directly instead of going to the owner desk
#   route-mutant-dialog-pending  pending state taken from the conversation (injectable) instead of the lifecycle
#   route-mutant-guest-memory    a guest reads owner memory
# Usage: scripts/allen_route_mutants.sh [cargo target dir]. Prints ALLEN_ROUTE_MUTANTS: PASS or FAIL.
set -uo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
tgt=${1:-${CARGO_TARGET_DIR:-$repo/target}}
fail=0
run() { CARGO_TARGET_DIR="$tgt" cargo test -q --locked --manifest-path "$repo/Cargo.toml" -p allen-reflex --test route "$@" >"$tgt/route-mutant.log" 2>&1; }
if run; then echo "route tests (no mutant): PASS"; else echo "route tests (no mutant): FAIL"; tail -20 "$tgt/route-mutant.log"; fail=1; fi
for m in route-mutant-grant route-mutant-dialog-pending route-mutant-guest-memory; do
    if run --features "$m"; then echo "mutant $m: tests PASSED, the mutation is not caught"; fail=1
    else echo "mutant $m: caught ($(grep -cE -- '--- FAILED$' "$tgt/route-mutant.log") tests failed)"; [ "$(grep -cE -- "--- FAILED$" "$tgt/route-mutant.log")" -gt 0 ] || { echo "  ...but no test failed (build error?)"; fail=1; }; fi
done
if [ $fail = 0 ]; then echo "ALLEN_ROUTE_MUTANTS: PASS"; else echo "ALLEN_ROUTE_MUTANTS: FAIL"; exit 1; fi
