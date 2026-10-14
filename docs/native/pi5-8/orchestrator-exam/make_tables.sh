#!/bin/bash
# Print the markdown result tables used in PI5-8-ORCHESTRATOR-EXAM.md from results/summary.tsv. usage: make_tables.sh
here=$(cd "$(dirname "$0")" && pwd); s="$here/results/summary.tsv"
order="qwen3-1.7b granite4-1b granite3.3-2b qwen2.5-1.5b smollm2-1.7b qwen3-0.6b granite4-h-350m qwen2.5-0.5b tinyllama-1.1b granite4-350m smollm2-360m danube3-500m llama3.2-1b"
col() { awk -F'\t' -v m="$1" -v sp="$2" -v md="$3" -v c="$4" '$1==m&&$2==sp&&$3==md{print $c}' "$s"; }
# summary.tsv columns: 1 model 2 split 3 mode 4 n 5 json_parse 6 schema_valid 7 action 8 exact 9 args_strict 10 args_lenient 11 refuse 12 clarify 13 none 14 safe 15 overblock
for mode in free constrained; do
  echo; echo "### $mode decoding (all 128 cases pooled; held-out = the 26 frozen cases)"; echo
  echo "| Model | JSON-valid | Action | Exact | Args | Refuse | Clarify | None | Over-block | Held-out action | Held-out exact |"
  echo "|---|---|---|---|---|---|---|---|---|---|---|"
  for m in $order; do
    echo "| $m | $(col $m all $mode 6) | $(col $m all $mode 7) | $(col $m all $mode 8) | $(col $m all $mode 9) | $(col $m all $mode 11) | $(col $m all $mode 12) | $(col $m all $mode 13) | $(col $m all $mode 15) | $(col $m heldout $mode 7) | $(col $m heldout $mode 8) |"
  done
done
echo; echo "### Action accuracy per split, free / constrained"; echo
echo "| Model | train (79) | dev (23) | held-out (26) |"; echo "|---|---|---|---|"
for m in $order; do
  echo "| $m | $(col $m train free 7) / $(col $m train constrained 7) | $(col $m dev free 7) / $(col $m dev constrained 7) | $(col $m heldout free 7) / $(col $m heldout constrained 7) |"
done
echo; echo "### Constrained minus free (percentage points, all 128 cases)"; echo
echo "| Model | JSON-valid | Action | Exact | Held-out exact |"; echo "|---|---|---|---|---|"
for m in $order; do
  awk -v m=$m -F'\t' 'function g(sp,md,c){while((getline l < "'"$s"'")>0){split(l,a,"\t"); if(a[1]==m&&a[2]==sp&&a[3]==md) r=a[c]} close("'"$s"'"); return r}
   BEGIN{printf "| %s | %+.1f | %+.1f | %+.1f | %+.1f |\n", m, g("all","constrained",6)-g("all","free",6), g("all","constrained",7)-g("all","free",7), g("all","constrained",8)-g("all","free",8), g("heldout","constrained",8)-g("heldout","free",8)}'
done
