#!/usr/bin/env bash
# CyberGym smoke runner. Reads loop_runners/smoke_tasks.txt (comments ignored)
# and drives the selected tasks through cybergym_loop.py.
#
# Usage:
#   TASKS_DIR=tasks OUT_DIR=runs/cybergym-smoke \
#   PROVIDER=openai MODEL=gpt-5.5 \
#       bash loop_runners/run_smoke.sh
#
# Options via env:
#   TASKS_DIR       directory containing task bundles (default: tasks)
#   OUT_DIR         where to dump per-task results   (default: runs/cybergym-smoke)
#   PROVIDER        loop provider id                 (default: openai)
#   MODEL           loop model id                    (default: gpt-5.5)
#   CONCURRENCY     parallel tasks                   (default: 2)
#   DEADLINE        per-task timeout, seconds        (default: 1800)
#   TIER            easy | hard | all                (default: easy)
#   NO_GRADE        1 to skip submit.sh              (default: unset)

set -euo pipefail

TASKS_DIR="${TASKS_DIR:-tasks}"
OUT_DIR="${OUT_DIR:-runs/cybergym-smoke}"
PROVIDER="${PROVIDER:-openai}"
MODEL="${MODEL:-gpt-5.5}"
CONCURRENCY="${CONCURRENCY:-2}"
DEADLINE="${DEADLINE:-1800}"
TIER="${TIER:-easy}"

LIST_FILE="$(dirname "$0")/smoke_tasks.txt"
if [ ! -f "$LIST_FILE" ]; then
  echo "missing $LIST_FILE" >&2
  exit 2
fi

awk_filter=''
case "$TIER" in
  easy) awk_filter='NR<=5' ;;
  hard) awk_filter='NR>5' ;;
  all)  awk_filter='1' ;;
  *) echo "TIER must be easy|hard|all (got $TIER)" >&2; exit 2 ;;
esac

ONLY=$(
  grep -v -E '^\s*(#|$)' "$LIST_FILE" |
  awk "$awk_filter" |
  paste -sd, -
)

echo "tasks: $ONLY"
echo "out:   $OUT_DIR"
echo "model: $PROVIDER/$MODEL"

extra=()
[ "${NO_GRADE:-}" = "1" ] && extra+=(--no-grade)

python3 "$(dirname "$0")/cybergym_loop.py" \
  --tasks-dir "$TASKS_DIR" \
  --out-dir   "$OUT_DIR" \
  --provider  "$PROVIDER" \
  --model     "$MODEL" \
  --only      "$ONLY" \
  --concurrency "$CONCURRENCY" \
  --task-deadline "$DEADLINE" \
  "${extra[@]}"
