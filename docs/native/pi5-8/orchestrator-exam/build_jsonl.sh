#!/bin/bash
# Derive machine-readable cases-<split>.jsonl (one JSON object per line) from the .psv sources, for the trainer and other readers.
# Fields: id, split, category, decision_type (action|clarify|none|refuse), action, args ({"text":..} or {}),
#   arg_spans (for "text": start/end byte offsets into last_user, end exclusive, from a case-insensitive match; match=exact|case|none;
#   a text that is a shortened form of the request has no span and match=none), turns (all turns with roles), last_user.
here=$(cd "$(dirname "$0")" && pwd)
for split in train dev heldout; do
  grep -v '^#' "$here/cases-$split.psv" | while IFS='|' read -r id cat act text turns; do
    jq -cn --arg id "$id" --arg split "$split" --arg cat "$cat" --arg act "$act" --arg text "$text" --arg turns "$turns" '
      ($turns|split(" ~~ ")) as $t | ($t|last) as $last
      | (if $text=="" then null else ($last|index($text)) end) as $ex
      | (if $text=="" then null else ($last|ascii_downcase|index($text|ascii_downcase)) end) as $ci
      | {id:$id, split:$split, category:$cat,
         decision_type:(if $act=="clarify" or $act=="none" or $act=="refuse" then $act else "action" end),
         action:$act,
         args:(if $text=="" then {} else {text:$text} end),
         arg_spans:(if $text=="" then [] else [{arg:"text", start:($ex // $ci), end:(($ex // $ci) | if .==null then null else .+($text|length) end), match:(if $ex!=null then "exact" elif $ci!=null then "case" else "none" end)}] end),
         turns:($t|to_entries|map({role:(if .key%2==0 then "user" else "assistant" end),content:.value})),
         last_user:$last}' 
  done > "$here/cases-$split.jsonl"
done
