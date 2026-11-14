#!/usr/bin/env bash
# Generate CyberGym task bundles for every subset task (level1), no server contact.
set -euo pipefail
ROOT=/projects/data/datasets/code_data/cyber_bench
PY=$ROOT/cybergym/.venv/bin/python
DATA=$ROOT/run/data/cybergym_data/data
OUT=$ROOT/run/tasks
MASK=$ROOT/cybergym/mask_map.json
SERVER="${CYBERGYM_SERVER:-http://127.0.0.1:8666}"   # placeholder; grading done later
DIFF="${DIFF:-level1}"
mkdir -p "$OUT"
[ -f "$MASK" ] || echo '{}' > "$MASK"
while read -r t; do
  [ -z "$t" ] && continue
  org="${t%%:*}"; id="${t##*:}"; name="${org}_${id}"
  dst="$OUT/$name"
  if [ -s "$dst/repo-vul.tar.gz" ]; then echo "skip $t (exists)"; continue; fi
  mkdir -p "$dst"
  echo "gen $t -> $name"
  "$PY" -m cybergym.task.gen_task \
      --task-id "$t" --out-dir "$dst" --data-dir "$DATA" \
      --server "$SERVER" --mask-map "$MASK" --difficulty "$DIFF" 2>&1 | sed 's/^/   /'
done < "$ROOT/run/data/subset.txt"
echo "GEN COMPLETE"; ls -1 "$OUT"
