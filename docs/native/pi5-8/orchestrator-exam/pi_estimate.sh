#!/bin/bash
# ESTIMATE of Pi 5 speed, scaled from the measured Pi numbers in PI5-8-MODEL-CHOICE.md (SDOT path, per-token time is proportional to the weight bytes read per token).
# Calibration (measured): TinyLlama 631.9 MB read per token (file minus the unread embedding table) -> 683,917 us; danube3 290.2 MB -> 309,842 us; Llama yardstick 807.7 MB -> 832,559 us.
# That is 1.03 to 1.08 ms per MB; this script uses 1.05 ms per MB. Not measured for any model here. Q5_0/Q8_0 tensors would use kernels the engine does not have, so their speed is unknown.
# usage: pi_estimate.sh <downloads.tsv> <emb.tsv> <tokens.tsv>
P3=822083584
join -t$'\t' <(sort "$1" | cut -f1,2) <(sort "$2" | cut -f1,2,3) | join -t$'\t' - <(tail -n +2 "$3" | sort | cut -f1,2) |
awk -F'\t' -v p3=$P3 'BEGIN{print "model\tfile_bytes\tpct_of_p3\tfits\tactive_MB\test_ms_per_tok\test_tok_s\test_cold_prefix_s\test_s_per_decision_cached"}
 {act=($4=="untied")?$2-$3:$2; ms=act/1e6*1.05; printf "%s\t%d\t%.0f\t%s\t%.0f\t%.0f\t%.2f\t%.0f\t%.1f\n",$1,$2,$2*100/p3,($2<=p3)?"yes":"NO",act/1e6,ms,1000/ms,$5*ms/1000,(8+16)*ms/1000}' | sort
