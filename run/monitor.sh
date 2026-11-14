#!/usr/bin/env bash
# Live monitor for the CyberGym-on-Eka run.
# Usage: ./monitor.sh [trace_dir] [interval_sec]
#   watch mode (default): refreshes every interval
#   ./monitor.sh <trace_dir> once   -> print one snapshot and exit
TRACE="${1:-/projects/data/datasets/code_data/cyber_bench/run/traces}"
INT="${2:-5}"
EKA="${EKA_URL:-http://172.17.98.19:8000/v1}"

snapshot() {
  local now; now=$(date -u +%H:%M:%S)
  printf '\033[2J\033[H'   # clear
  echo "===== CyberGym x Eka monitor =====  ${now}Z   trace=$TRACE"
  # Eka endpoint health
  if curl -s -m 4 -o /dev/null -w '%{http_code}' "$EKA/models" | grep -q 200; then
    echo "Eka endpoint: UP ($EKA)"
  else
    echo "Eka endpoint: DOWN/slow ($EKA)"
  fi
  echo
  printf "%-26s %-18s %5s %9s %8s %7s\n" TASK STATUS TURNS P_TOK REAS_TOK SECS
  printf '%.0s-' {1..80}; echo
  local done=0 sub=0
  shopt -s nullglob
  for d in "$TRACE"/*/; do
    [ -f "$d/trace.jsonl" ] || continue
    local name; name=$(basename "$d")
    if [ -f "$d/result.json" ]; then
      # finished task
      python3 - "$d/result.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
print(f'{r["task_id"]:<26.26} {r["status"]:<18.18} {r["turns"]:>5} {r["prompt_tokens"]:>9} {r.get("reasoning_tokens",0):>8} {r.get("wall_seconds",0):>7}')
PY
      done=$((done+1))
      grep -q '"type": "submit"' "$d/trace.jsonl" 2>/dev/null && sub=$((sub+1))
    else
      # in-flight: derive progress from the jsonl tail
      python3 - "$d/trace.jsonl" "$name" <<'PY'
import json,sys
path,name=sys.argv[1],sys.argv[2]
turns=0; ptok=0; rtok=0; last="?"
for line in open(path,errors="replace"):
    try: e=json.loads(line)
    except: continue
    t=e.get("type")
    if t=="assistant":
        turns=e.get("turn",turns); last="thinking/acting"
        u=e.get("usage") or {}
        ptok=u.get("prompt_tokens",ptok)
        rtok+=(u.get("completion_tokens_details") or {}).get("reasoning_tokens",0) or 0
    elif t=="tool_result": last="bash:"+(e.get("cmd","")[:14])
    elif t=="submit": last="submitted"
print(f'{name:<26.26} {("RUN "+last):<18.18} {turns:>5} {ptok:>9} {rtok:>8} {"-":>7}')
PY
    fi
  done
  echo
  local total; total=$(find "$TRACE" -maxdepth 1 -mindepth 1 -type d | wc -l)
  echo "finished=$done  submitted_poc=$sub  seen=$total"
}

if [ "$INT" = "once" ]; then
  snapshot
else
  while true; do snapshot; sleep "$INT"; done
fi
