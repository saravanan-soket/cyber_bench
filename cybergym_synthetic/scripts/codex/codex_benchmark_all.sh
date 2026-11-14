#!/bin/bash
# Run all (or a filtered subset of) bench-v8 bugs through Codex with
# per-(bug, seed) isolation + concurrency control. Each run is capped
# at 300 model turns via the patched codex fork's --max-turns flag.
#
# Usage:
#   codex_benchmark_all.sh [yaml] [results_root] [concurrency] [seeds]
#
# Defaults:
#   yaml          = ~/exploitbench/benchmarks/v8.yaml
#   results_root  = /home/admin/codex-bench
#   concurrency   = 2
#   seeds         = "1"          # comma-separated, e.g. "1,2,3"
#
# Environment overrides (passed through to per-bug runner):
#   MAX_TURNS     - per-run turn cap (default 300)
#   MODEL         - codex model (default gpt-5.5)
#   EFFORT        - reasoning effort (default xhigh)
#   FILTER        - regex to filter bug ids (e.g. "cve-2024-")

set -uo pipefail

YAML="${1:-${HOME}/exploitbench/benchmarks/v8.yaml}"
RESULTS_ROOT="${2:-/home/admin/codex-bench}"
CONCURRENCY="${3:-2}"
SEEDS="${4:-1}"
FILTER="${FILTER:-}"

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
RUNNER="${SCRIPT_DIR}/codex_run_bug.sh"

if [ ! -x "$RUNNER" ]; then
  echo "ERROR: $RUNNER not found or not executable" >&2
  exit 1
fi

mkdir -p "$RESULTS_ROOT"

# Parse seeds (comma-separated) into array.
IFS=',' read -ra SEED_ARR <<< "$SEEDS"

# Extract bug list from v8.yaml — every env id starting with v8-*
mapfile -t BUGS < <(python3 -c "
import yaml, sys, re
flt = sys.argv[2] if len(sys.argv) > 2 else None
with open(sys.argv[1]) as f:
    cfg = yaml.safe_load(f)
for env in cfg.get('envs', []):
    bid = env.get('id', '')
    if not bid.startswith('v8-'): continue
    if flt and not re.search(flt, bid): continue
    print(bid)
" "$YAML" "$FILTER")

NUM_BUGS=${#BUGS[@]}
TOTAL_CELLS=$((NUM_BUGS * ${#SEED_ARR[@]}))

echo "[bench_all] yaml=${YAML}  filter='${FILTER}'"
echo "[bench_all] bugs=${NUM_BUGS}  seeds=${SEEDS} (${#SEED_ARR[@]} values)  total_cells=${TOTAL_CELLS}"
echo "[bench_all] results_root=${RESULTS_ROOT}  concurrency=${CONCURRENCY}"
echo "[bench_all] env: MAX_TURNS=${MAX_TURNS:-300} MODEL=${MODEL:-gpt-5.5} EFFORT=${EFFORT:-xhigh}"

count_active() {
  tmux ls 2>/dev/null | grep -c '^codex-bench-' || true
}

LAUNCHED=0
SKIPPED=0

for BUG in "${BUGS[@]}"; do
  for SEED in "${SEED_ARR[@]}"; do
    CELL_DIR="${RESULTS_ROOT}/${BUG}/seed${SEED}"

    # Skip if already completed
    if [ -f "${CELL_DIR}/caps.json" ]; then
      echo "[bench_all] SKIP ${BUG}/seed${SEED} — caps.json exists"
      SKIPPED=$((SKIPPED + 1))
      continue
    fi

    # Wait until below concurrency cap
    while [ "$(count_active)" -ge "$CONCURRENCY" ]; do
      sleep 30
    done

    SESSION="codex-bench-${BUG}-s${SEED}"
    # tmux session names can't have '.'; use _
    SESSION="${SESSION//./_}"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
      echo "[bench_all] SKIP ${BUG}/seed${SEED} — tmux session ${SESSION} already running"
      SKIPPED=$((SKIPPED + 1))
      continue
    fi

    echo "[bench_all] LAUNCH ${BUG}/seed${SEED} (session=${SESSION}) at $(date -u +%FT%TZ)"
    tmux new -d -s "$SESSION" "${RUNNER} ${BUG} ${SEED} ${RESULTS_ROOT}; sleep 2"
    LAUNCHED=$((LAUNCHED + 1))
    sleep 5  # stagger launches
  done
done

echo "[bench_all] all cells queued. launched=${LAUNCHED} skipped=${SKIPPED} total=${TOTAL_CELLS}"
echo "[bench_all] waiting for active sessions to finish..."

while [ "$(count_active)" -gt 0 ]; do
  ACTIVE=$(tmux ls 2>/dev/null | grep '^codex-bench-' | wc -l)
  echo "[bench_all] $(date -u +%FT%TZ)  active=${ACTIVE}/${TOTAL_CELLS}"
  sleep 60
done

echo "[bench_all] all sessions complete"
echo ""
echo "=== results summary ==="
python3 "${SCRIPT_DIR}/codex_aggregate.py" "$RESULTS_ROOT"
