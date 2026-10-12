#!/bin/sh
# Fail when GitHub refused any workflow file on a commit.
#
# A workflow file GitHub cannot parse (for example an unquoted ": " inside a
# step name) produces a run that is recorded as "failure" with zero jobs, and
# that run never appears in a pull request's checks list, so the job it was
# supposed to run silently never runs. 2026-10-12: .github/workflows/
# ck-kernel.yml was in that state for four hours (aienos#318). This script
# runs from an always-on workflow and turns that silence into a red check.
#
#   scripts/workflow_files_check.sh <commit sha>
# Needs: gh with a token that can read Actions (GITHUB_TOKEN in CI), and
# GITHUB_REPOSITORY (owner/name; defaults to aien-dev/aienos). POSIX sh, no
# Python. Exit 0 when every workflow run on the commit has at least one job,
# 1 when one does not, 2 on usage or API error.
set -eu
sha="${1:-}"
[ -n "$sha" ] || { echo "usage: $0 <commit sha>" >&2; exit 2; }
repo="${GITHUB_REPOSITORY:-aien-dev/aienos}"
settle="${WORKFLOW_FILES_SETTLE_SECONDS:-20}"
[ "$settle" -gt 0 ] && sleep "$settle"   # let GitHub record the push-event runs
runs=$(gh api "repos/$repo/actions/runs?head_sha=$sha&per_page=100" \
       --jq '.workflow_runs[] | select(.conclusion == "failure") | "\(.id) \(.path)"') \
  || { echo "WORKFLOW_FILES: ERROR cannot list runs for $sha" >&2; exit 2; }
bad=0
for id in $(printf '%s\n' "$runs" | awk 'NF {print $1}'); do
  path=$(printf '%s\n' "$runs" | awk -v i="$id" '$1 == i {print $2}')
  n=$(gh api "repos/$repo/actions/runs/$id/jobs" --jq '.total_count') \
    || { echo "WORKFLOW_FILES: ERROR cannot read jobs of run $id" >&2; exit 2; }
  if [ "$n" = 0 ]; then
    echo "WORKFLOW_FILES: REFUSED $path (run $id failed with no jobs: GitHub did not accept the file)"
    bad=1
  fi
done
[ "$bad" = 0 ] && echo "WORKFLOW_FILES: OK (every workflow run on $sha has jobs)"
exit "$bad"
