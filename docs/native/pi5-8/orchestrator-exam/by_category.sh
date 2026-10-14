#!/bin/bash
# Action accuracy per case category, pooled over train+dev+heldout. Columns: category, n cases, then per mode:
# mean over the borrowed yardstick models (control excluded) and the best single model.
# usage: by_category.sh   (reads results/*.jsonl, writes TSV to stdout)
here=$(cd "$(dirname "$0")" && pwd)
for mode in free constrained; do
  for f in "$here"/results/*.$mode.jsonl; do
    n=$(basename "$f"); n=${n%%.*}; [ "$n" = llama3.2-1b ] && continue
    jq -r --arg n "$n" --arg mode "$mode" '
      def acts: ["status","help","evidence","recall","facts","remember","prefer","task","prompt","approve","deny","cancel","none","clarify","refuse"];
      ((.raw|sub("^\\s+";"")|sub("\\s+$";"")) as $r
       | ((try ($r|fromjson) catch null) // ([try (($r|capture("(?<j>\\{.*\\})";"s")|.j)|fromjson) catch empty]|first // null)) as $o
       | [$n,$mode,.cat,(if (($o|type)=="object") and ($o.action==.exp_action) then 1 else 0 end)]|@tsv)' "$f"
  done
done | awk -F'\t' '{k=$2"\t"$3; a[$1"\t"k]+=$4; c[$1"\t"k]++; cat[$3]=1}
 END{ for(x in a){split(x,p,"\t"); m=p[2]; g=p[3]; acc=a[x]/c[x]*100; sum[m"\t"g]+=acc; nn[m"\t"g]++; if(acc>best[m"\t"g]) best[m"\t"g]=acc; n[g]=c[x]}
      printf "category\tn\tfree_mean\tfree_best\tconstrained_mean\tconstrained_best\n";
      for(g in cat) printf "%s\t%d\t%.1f\t%.1f\t%.1f\t%.1f\n", g, n[g], sum["free\t"g]/nn["free\t"g], best["free\t"g], sum["constrained\t"g]/nn["constrained\t"g], best["constrained\t"g] }' | sort
