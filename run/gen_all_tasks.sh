#!/usr/bin/env bash
# Build the full 1507-task mask map, then generate all task bundles (level1) in
# parallel. Bundles carry the submit metadata (agent_id/checksum) needed to grade.
set -uo pipefail
ROOT=/projects/data/datasets/code_data/cyber_bench
PY=$ROOT/cybergym/.venv/bin/python
DATA=$ROOT/run/data/cybergym_data/data
OUT=$ROOT/run/tasks_all
MASK=$ROOT/run/data/mask_map_all.json
SERVER="${CYBERGYM_SERVER:-http://cybergym-server:8666}"   # real URL applied at grading time
mkdir -p "$OUT"

# 1) full mask map from all task ids
PYTHONPATH=$ROOT/cybergym/src "$PY" - "$ROOT/run/data/tasks.json" "$MASK" <<'PY'
import json, sys
from pathlib import Path
from cybergym.task.mask import generate_mask_map
ids=[t["task_id"] for t in json.load(open(sys.argv[1]))]
generate_mask_map(ids, Path(sys.argv[2]))
print("mask map entries:", len(json.load(open(sys.argv[2]))))
PY

# 2) parallel gen_task (mask map is read-only here)
gen_one() {
  t="$1"; org="${t%%:*}"; id="${t##*:}"; name="${org}_${id}"; dst="$OUT/$name"
  [ -s "$dst/submit.sh" ] && { echo "skip $t"; return; }
  mkdir -p "$dst"
  "$PY" -m cybergym.task.gen_task --task-id "$t" --out-dir "$dst" --data-dir "$DATA" \
      --server "$SERVER" --mask-map "$MASK" --difficulty level1 \
      >/dev/null 2>>"$ROOT/run/logs/gen_all.err" || echo "GENFAIL $t" >>"$ROOT/run/logs/gen_fail.txt"
}
export -f gen_one; export OUT DATA MASK SERVER PY ROOT
"$PY" -c "import json;[print(t['task_id']) for t in json.load(open('$ROOT/run/data/tasks.json'))]" \
  | xargs -P 24 -I{} bash -c 'gen_one "$@"' _ {}

echo "GEN ALL COMPLETE"
ls "$OUT" | wc -l | xargs echo "bundles:"
wc -l "$ROOT/run/logs/gen_fail.txt" 2>/dev/null || echo "no gen failures"
