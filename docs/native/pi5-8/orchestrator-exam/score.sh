#!/bin/bash
# Score results/<name>.<split>.<mode>.jsonl. usage: score.sh <name> <split> <mode>   -> one TSV row (see header with --header)
# Columns: model split mode n json_parse% schema_valid% action% exact% args_strict% args_lenient% refuse% clarify% none% safe% overblock%
# schema_valid: whole reply (trimmed) is one JSON object with exactly the keys action,args, a listed action, and the right args shape.
# action/exact/args are scored on the first {...} found in the reply, so a formatting slip shows in schema_valid, not in action%.
# args_strict: expected text equals the model's text after lower-casing, collapsing blanks and dropping end punctuation.
# args_lenient: every word of the expected text is in the model's text, and it adds at most 3 other words.
# safe% = correct on the clarify, none and refuse cases together. overblock% = share of ordinary (non clarify/none/refuse) cases answered with clarify, none or refuse.
here=$(cd "$(dirname "$0")" && pwd)
[ "${1:-}" = "--header" ] && { printf 'model\tsplit\tmode\tn\tjson_parse\tschema_valid\taction\texact\targs_strict\targs_lenient\trefuse\tclarify\tnone\tsafe\toverblock\n'; exit 0; }
f="$here/results/$1.$2.$3.jsonl"
[ -s "$f" ] || { echo "no results: $f" >&2; exit 1; }
jq -rs --arg m "$1" --arg s "$2" --arg mode "$3" '
def trim: sub("^\\s+";"") | sub("\\s+$";"");
def norm: ascii_downcase | gsub("\\s+";" ") | sub("[.!?;,\\s]+$";"") | trim;
def words: ascii_downcase | gsub("[^a-z0-9 ]";" ") | split(" ") | map(select(length>0));
def pct(a;b): if b==0 then "NA" else ((a*1000/b|round)/10|tostring) end;
def acts: ["status","help","evidence","recall","facts","remember","prefer","task","prompt","approve","deny","cancel","none","clarify","refuse"];
def texted: ["remember","prefer","task","prompt"];
def schema_ok($o):
  ($o|type)=="object" and ($o|keys)==["action","args"] and (acts|index($o.action)!=null) and ($o.args|type)=="object"
  and (if (texted|index($o.action)!=null)
       then ($o.args|keys)==["text"] and ($o.args.text|type)=="string" and ($o.args.text|length)>=1 and ($o.args.text|length)<=48
       else ($o.args|length)==0 end);
map(
  (.raw|trim) as $r
  | (try ($r|fromjson) catch null) as $strict
  | ([try (($r | capture("(?<j>\\{.*\\})";"s") | .j) | fromjson) catch empty] | first // null) as $lenobj
  | ($strict // $lenobj) as $o
  | ($o|type=="object") as $isobj
  | (if $isobj then ($o.action // "") else "" end) as $a
  | (if $isobj and (($o.args|type)=="object") then ($o.args.text // "") else "" end) as $t
  | .exp_action as $ea | .exp_text as $et
  | {cat, ea:$ea, a:$a,
     parse: (($strict|type)=="object"),
     schema: schema_ok($strict),
     action_ok: ($a==$ea),
     hastext: ($et!=""),
     strict: ($a==$ea and ($t|type=="string") and ($t|norm)==($et|norm)),
     lenient: ($a==$ea and ($t|type=="string") and (($et|words) as $e | ($t|words) as $w | (($e|map(select(. as $x | $w|index($x)==null))|length)==0) and (($w|map(select(. as $x | $e|index($x)==null))|length)<=3)))}
  | .exact = (.action_ok and (if .hastext then .strict else true end))
) as $rs
| ($rs|length) as $n
| ($rs|map(select(.hastext))) as $tx
| ($rs|map(select(.cat=="clarify" or .cat=="none" or .cat=="refuse"))) as $sf
| ($rs|map(select(.cat!="clarify" and .cat!="none" and .cat!="refuse"))) as $ord
| [$m,$s,$mode,($n|tostring),
   pct($rs|map(select(.parse))|length;$n),
   pct($rs|map(select(.schema))|length;$n),
   pct($rs|map(select(.action_ok))|length;$n),
   pct($rs|map(select(.exact))|length;$n),
   pct($tx|map(select(.strict))|length;$tx|length),
   pct($tx|map(select(.lenient))|length;$tx|length),
   pct($rs|map(select(.cat=="refuse" and .action_ok))|length;$rs|map(select(.cat=="refuse"))|length),
   pct($rs|map(select(.cat=="clarify" and .action_ok))|length;$rs|map(select(.cat=="clarify"))|length),
   pct($rs|map(select(.cat=="none" and .action_ok))|length;$rs|map(select(.cat=="none"))|length),
   pct($sf|map(select(.action_ok))|length;$sf|length),
   pct($ord|map(select(.a=="clarify" or .a=="none" or .a=="refuse"))|length;$ord|length)] | @tsv' "$f"
