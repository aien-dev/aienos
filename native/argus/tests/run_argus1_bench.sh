#!/usr/bin/env bash
set -euo pipefail

bench_bin=$1
mode=$2
integration_bin=$3
lane_out=$4
quiet_file="${HOME}/workspace/.spark-quiet"
lock_file="${HOME}/workspace/.argus-bench.lock"

if [[ -e "$quiet_file" ]]; then
    echo "ARGUS-1 benchmark blocked: .spark-quiet is present" >&2
    exit 2
fi
if ! command -v taskset >/dev/null || ! command -v flock >/dev/null; then
    echo "ARGUS-1 benchmark needs taskset and flock on the Spark host" >&2
    exit 2
fi

flock -n "$lock_file" bash -c '
    set -euo pipefail
    taskset -c 7 "$1"
    if [[ "$2" == full ]]; then
        taskset -c 7 make -f lane_b.mk LANE_B_OUT="$4" bench-ring
        taskset -c 7 "$3" --bench
    fi
' bash "$bench_bin" "$mode" "$integration_bin" "$lane_out"
