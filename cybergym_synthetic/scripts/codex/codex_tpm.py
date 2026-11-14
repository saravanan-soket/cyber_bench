"""Compute current OpenAI TPM consumption from running codex rollouts.

Walks all <root>/<bug>/seed<N>/.codex/sessions/.../rollout-*.jsonl,
sums input + output tokens for each model call made in the last 60s,
buckets by tier (normal-pool vs long-context-pool at 272K threshold).
"""
import json
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

LONG_CTX_THRESHOLD = 272_000   # gpt-5.5 long-context routing boundary
NORMAL_LIMIT = 20_000_000      # gpt-5.5 normal pool TPM
LONG_LIMIT   = 2_000_000       # gpt-5.5 long-context pool TPM

root = Path(sys.argv[1] if len(sys.argv) > 1 else "/home/admin/codex-bench")
now = datetime.now(timezone.utc)
cutoff = now - timedelta(seconds=60)

norm_in = norm_out = 0
long_in = long_out = 0
n_norm = n_long = 0
per_cell = []

for rollout in root.glob("*/seed*/.codex/sessions/*/*/*/rollout-*.jsonl"):
    # path: <root>/<bug>/seed<N>/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl
    parts = rollout.parts
    cell = f"{parts[-8]}/{parts[-7]}"  # <bug>/seed<N>
    cell_in = cell_out = cell_calls = 0
    for line in rollout.open(errors="ignore"):
        try:
            o = json.loads(line)
        except Exception:
            continue
        ts = o.get("timestamp", "")
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            continue
        if t < cutoff:
            continue
        payload = o.get("payload") or {}
        info = payload.get("info") or {}
        u = info.get("last_token_usage") if isinstance(info, dict) else None
        if not isinstance(u, dict):
            continue
        in_t = int(u.get("input_tokens", 0) or 0)
        out_t = int(u.get("output_tokens", 0) or 0)
        cell_in += in_t; cell_out += out_t; cell_calls += 1
        if in_t >= LONG_CTX_THRESHOLD:
            long_in += in_t; long_out += out_t; n_long += 1
        else:
            norm_in += in_t; norm_out += out_t; n_norm += 1
    if cell_calls:
        per_cell.append((cell, cell_calls, cell_in, cell_out))

print(f"=== last 60s, OpenAI TPM consumption ===")
print(f"now: {now.isoformat(timespec='seconds')}")
print()
print(f"  normal pool  calls={n_norm:>3}  in={norm_in:>10,}  out={norm_out:>7,}  → "
      f"{(norm_in + norm_out) / NORMAL_LIMIT * 100:>5.2f}% of {NORMAL_LIMIT/1_000_000:.0f}M TPM")
print(f"  long-context calls={n_long:>3}  in={long_in:>10,}  out={long_out:>7,}  → "
      f"{(long_in + long_out) / LONG_LIMIT * 100:>5.2f}% of {LONG_LIMIT/1_000_000:.0f}M TPM")
print()
if per_cell:
    print(f"=== per-cell (last 60s) ===")
    for cell, n, ci, co in sorted(per_cell):
        print(f"  {cell:<32}  calls={n}  in={ci:,}  out={co:,}")
