#!/bin/bash
# Deterministic split of the frozen pool (cases-pool.psv, 102 cases written before the prompt freeze) into
# cases-train.psv and cases-dev.psv. Within each category, in file order, every 4th case (positions 4, 8, ...) goes to dev, the rest to train.
# The held-out set (cases-heldout.psv) was written after the freeze and is never part of this split.
here=$(cd "$(dirname "$0")" && pwd)
hdr='# id|category|expected_action|expected_text|turns (user ~~ assistant ~~ user ...; the last turn is the one scored)'
echo "$hdr" > "$here/cases-train.psv"; echo "$hdr" > "$here/cases-dev.psv"
grep -v '^#' "$here/cases-pool.psv" | awk -F'|' -v d="$here/cases-dev.psv" -v t="$here/cases-train.psv" '{c[$2]++; if (c[$2]%4==0) print >> d; else print >> t}'
